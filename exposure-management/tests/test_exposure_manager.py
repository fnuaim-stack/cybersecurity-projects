import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from exposure_manager.importers import load_findings
from exposure_manager.service import ExposureManager


class ExposureManagerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.db = self.root / "exposure.db"
        self.manager = ExposureManager(self.db)

    def tearDown(self):
        self.tempdir.cleanup()

    def write_json(self, name, payload):
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_generic_import_deduplicates(self):
        scan = self.write_json(
            "scan.json",
            [
                {
                    "asset": "app.example.test",
                    "title": "Outdated web server",
                    "external_id": "CVE-2026-0001",
                    "severity": "high",
                    "cvss": 8.1,
                    "port": 443,
                    "protocol": "tcp",
                }
            ],
        )

        first = self.manager.import_scan(scan, fmt="generic", source="scanner", scope="prod")
        second = self.manager.import_scan(scan, fmt="generic", source="scanner", scope="prod")

        self.assertEqual(first["created"], 1)
        self.assertEqual(second["created"], 0)
        self.assertEqual(second["updated"], 1)
        self.assertEqual(self.manager.summary()["findings"], 1)

    def test_asset_context_changes_risk(self):
        scan = self.write_json(
            "scan.json",
            [{"asset": "vpn.example.test", "title": "Weak setting", "severity": "medium"}],
        )
        self.manager.import_scan(scan, fmt="generic", source="scanner", scope="edge")
        before = self.manager.remediation_queue()[0]["risk_score"]

        self.manager.set_asset_context(
            "vpn.example.test",
            criticality=5,
            internet_exposed=True,
            owner="security",
            environment="production",
        )
        after = self.manager.remediation_queue()[0]["risk_score"]

        self.assertGreater(after, before)
        asset = self.manager.db.get_asset("vpn.example.test")
        self.assertEqual(asset["owner"], "security")
        self.assertEqual(asset["environment"], "production")

    def test_two_clean_scans_verify_resolution_and_reappearance_reopens(self):
        finding_scan = self.write_json(
            "finding.json",
            [{"asset": "10.0.0.10", "title": "Example finding", "severity": "high"}],
        )
        clean_scan = self.write_json("clean.json", [])

        self.manager.import_scan(finding_scan, fmt="generic", source="scanner", scope="prod")
        finding_id = self.manager.remediation_queue()[0]["id"]

        first_clean = self.manager.import_scan(clean_scan, fmt="generic", source="scanner", scope="prod")
        self.assertEqual(first_clean["verified_resolved"], 0)
        self.assertEqual(self.manager.db.get_finding(finding_id)["status"], "open")

        second_clean = self.manager.import_scan(clean_scan, fmt="generic", source="scanner", scope="prod")
        self.assertEqual(second_clean["verified_resolved"], 1)
        self.assertEqual(self.manager.db.get_finding(finding_id)["status"], "resolved")

        returned = self.manager.import_scan(finding_scan, fmt="generic", source="scanner", scope="prod")
        self.assertEqual(returned["reopened"], 1)
        self.assertEqual(self.manager.db.get_finding(finding_id)["status"], "open")

    def test_risk_exception_is_time_limited(self):
        scan = self.write_json(
            "scan.json",
            [{"asset": "db.example.test", "title": "Legacy protocol", "severity": "medium"}],
        )
        self.manager.import_scan(scan, fmt="generic", source="scanner", scope="prod")
        finding_id = self.manager.remediation_queue()[0]["id"]

        self.manager.accept_risk(finding_id, "2099-12-31", "Vendor migration pending")
        self.assertEqual(self.manager.db.get_finding(finding_id)["status"], "accepted_risk")
        self.assertEqual(self.manager.remediation_queue(), [])

        self.manager.db.update_finding(finding_id, {"exception_until": "2000-01-01"})
        queue = self.manager.remediation_queue()
        self.assertEqual(queue[0]["status"], "open")
        actions = [item["action"] for item in self.manager.db.history(finding_id)]
        self.assertIn("risk_exception_expired", actions)

    def test_nuclei_jsonl_import(self):
        path = self.root / "nuclei.jsonl"
        path.write_text(
            json.dumps(
                {
                    "template-id": "missing-header",
                    "host": "https://app.example.test",
                    "ip": "192.0.2.10",
                    "port": 443,
                    "type": "http",
                    "info": {
                        "name": "Missing security header",
                        "severity": "medium",
                        "description": "Header was not present.",
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )

        selected, findings = load_findings(path, "auto")
        self.assertEqual(selected, "nuclei")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].asset, "app.example.test")
        self.assertEqual(findings[0].port, 443)

    def test_pretty_nuclei_json_import(self):
        path = self.root / "nuclei.json"
        path.write_text(
            json.dumps(
                {
                    "template-id": "tls-version",
                    "host": "https://gateway.example.test",
                    "info": {
                        "name": "Legacy TLS version",
                        "severity": "medium",
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        selected, findings = load_findings(path, "auto")
        self.assertEqual(selected, "nuclei")
        self.assertEqual(findings[0].asset, "gateway.example.test")

    def test_trivy_import(self):
        scan = self.write_json(
            "trivy.json",
            {
                "Results": [
                    {
                        "Target": "python:3.11",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-1234",
                                "PkgName": "example",
                                "InstalledVersion": "1.0",
                                "FixedVersion": "1.1",
                                "Severity": "HIGH",
                                "Title": "Example package issue",
                            }
                        ],
                    }
                ]
            },
        )

        selected, findings = load_findings(scan, "auto")
        self.assertEqual(selected, "trivy")
        self.assertEqual(findings[0].external_id, "CVE-2026-1234")
        self.assertIn("1.1", findings[0].remediation)

    def test_nmap_open_service_import(self):
        path = self.root / "nmap.xml"
        path.write_text(
            """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.20" addrtype="ipv4"/>
    <hostnames><hostname name="server.example.test"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.25"/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
            encoding="utf-8",
        )

        selected, findings = load_findings(path, "auto")
        self.assertEqual(selected, "nmap")
        self.assertEqual(findings[0].asset, "server.example.test")
        self.assertEqual(findings[0].port, 443)
        self.assertEqual(findings[0].severity, "info")


if __name__ == "__main__":
    unittest.main()
