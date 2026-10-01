import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from exposure_manager.analytics import build_analytics
from exposure_manager.campaigns import CampaignManager
from exposure_manager.importers import load_findings
from exposure_manager.integrations import finding_ticket_payload
from exposure_manager.intel import enrich_findings
from exposure_manager.service import ExposureManager


class PlatformFeatureTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.manager = ExposureManager(self.root / "exposure.db")

    def tearDown(self):
        self.tempdir.cleanup()

    def test_nessus_import(self):
        path = self.root / "scan.nessus"
        path.write_text(
            """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="test">
    <ReportHost name="server.example.test">
      <HostProperties>
        <tag name="host-ip">192.0.2.50</tag>
        <tag name="host-fqdn">server.example.test</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="www" protocol="tcp" severity="3"
                  pluginID="12345" pluginName="Example TLS finding" pluginFamily="General">
        <synopsis>Example issue</synopsis>
        <solution>Update the service.</solution>
        <cve>CVE-2026-1111</cve>
        <cvss3_base_score>8.1</cvss3_base_score>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
""",
            encoding="utf-8",
        )
        selected, findings = load_findings(path, "auto")
        self.assertEqual(selected, "nessus")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].asset, "server.example.test")
        self.assertEqual(findings[0].port, 443)
        self.assertEqual(findings[0].severity, "high")

    def test_zap_import(self):
        path = self.root / "zap.json"
        path.write_text(
            json.dumps(
                {
                    "site": [
                        {
                            "@name": "https://app.example.test",
                            "alerts": [
                                {
                                    "pluginid": "10021",
                                    "riskcode": "2",
                                    "alert": "Missing Header",
                                    "desc": "Header missing",
                                    "solution": "Add the header",
                                    "instances": [{"uri": "https://app.example.test/login"}],
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        selected, findings = load_findings(path, "auto")
        self.assertEqual(selected, "zap")
        self.assertEqual(findings[0].asset, "app.example.test")
        self.assertEqual(findings[0].severity, "medium")

    def test_semgrep_import(self):
        path = self.root / "semgrep.json"
        path.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "check_id": "python.lang.security.example",
                            "path": "app/auth.py",
                            "start": {"line": 10},
                            "end": {"line": 10},
                            "extra": {
                                "message": "Example code finding",
                                "severity": "ERROR",
                                "fix": "Use a safer API",
                            },
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        selected, findings = load_findings(path, "auto")
        self.assertEqual(selected, "semgrep")
        self.assertEqual(findings[0].asset, "app/auth.py")
        self.assertEqual(findings[0].severity, "high")

    def test_kev_and_epss_enrichment(self):
        scan = self.root / "generic.json"
        scan.write_text(
            json.dumps(
                [
                    {
                        "asset": "vpn.example.test",
                        "title": "Example CVE",
                        "external_id": "CVE-2026-2222",
                        "severity": "high",
                        "cvss": 8.0,
                    }
                ]
            ),
            encoding="utf-8",
        )
        self.manager.import_scan(scan, fmt="generic", source="scanner", scope="edge")
        finding = self.manager.remediation_queue()[0]
        before = finding["risk_score"]

        kev = self.root / "kev.json"
        kev.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2026-2222",
                            "dateAdded": "2026-01-01",
                            "dueDate": "2026-01-20",
                            "knownRansomwareCampaignUse": "Unknown",
                            "requiredAction": "Apply updates",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        epss = self.root / "epss.csv"
        epss.write_text(
            "cve,epss,percentile\nCVE-2026-2222,0.95,0.99\n",
            encoding="utf-8",
        )

        result = enrich_findings(self.manager.db, kev_path=kev, epss_path=epss)
        after = self.manager.db.get_finding(int(finding["id"]))
        self.assertEqual(result["updated_findings"], 1)
        self.assertEqual(after["known_exploited"], 1)
        self.assertGreater(after["risk_score"], before)
        metadata = json.loads(after["metadata_json"])
        self.assertIn("cisa_kev", metadata["threat_intel"])
        self.assertEqual(metadata["threat_intel"]["epss"]["score"], 0.95)

    def test_campaign_groups_active_findings(self):
        scan = self.root / "findings.json"
        scan.write_text(
            json.dumps(
                [
                    {"asset": "a.example.test", "title": "High A", "severity": "high"},
                    {"asset": "b.example.test", "title": "Low B", "severity": "low"},
                ]
            ),
            encoding="utf-8",
        )
        self.manager.import_scan(scan, fmt="generic", source="scanner", scope="prod")
        campaigns = CampaignManager(self.manager.db)
        campaign = campaigns.create("High risk sprint", owner="security", min_risk=70)
        self.assertEqual(campaign["finding_count"], 1)
        self.assertEqual(campaign["findings"][0]["title"], "High A")

    def test_analytics_and_ticket_payload(self):
        scan = self.root / "finding.json"
        scan.write_text(
            json.dumps([{"asset": "api.example.test", "title": "API issue", "severity": "medium"}]),
            encoding="utf-8",
        )
        self.manager.import_scan(scan, fmt="generic", source="scanner", scope="prod")
        finding = self.manager.remediation_queue()[0]
        analytics = build_analytics(self.manager.db)
        ticket = finding_ticket_payload(finding)

        self.assertEqual(analytics["active_findings"], 1)
        self.assertIn("API issue", ticket["summary"])
        self.assertIn("api.example.test", ticket["description"])


if __name__ == "__main__":
    unittest.main()
