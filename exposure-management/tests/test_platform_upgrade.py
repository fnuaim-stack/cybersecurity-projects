import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from exposure_manager.intel import fetch_epss, fetch_kev
from exposure_manager.notifications import NotificationService
from exposure_manager.scheduler import ScanScheduler
from exposure_manager.service import ExposureManager
from webapp import create_app


class _FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class _FakeScanner:
    def __init__(self):
        self.calls = []

    def start(self, **kwargs):
        self.calls.append(kwargs)
        return {"id": f"job-{len(self.calls)}"}


class PlatformUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.manager = ExposureManager(self.root / "platform.db")

    def tearDown(self):
        self.tempdir.cleanup()

    def write_json(self, name, payload):
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_profiles_schedules_and_scheduler(self):
        profile = self.manager.platform.create_profile(
            name="Hourly local scan",
            provider="builtin-network",
            target="127.0.0.1",
            scope="lab",
            ports="5055",
            partial=False,
        )
        schedule = self.manager.platform.create_schedule(
            profile["id"],
            interval_hours=1,
            run_immediately=True,
        )

        fake = _FakeScanner()
        scheduler = ScanScheduler(fake, self.manager.platform, poll_seconds=5)
        launched = scheduler.run_due_once()

        self.assertEqual(len(launched), 1)
        self.assertEqual(fake.calls[0]["target"], "127.0.0.1")
        updated = self.manager.platform.get_schedule(schedule["id"])
        self.assertEqual(updated["last_job_id"], "job-1")
        self.assertIsNotNone(updated["last_run_at"])

    def test_suppression_is_applied_during_import(self):
        self.manager.platform.create_suppression(
            name="Ignore expected demo signal",
            source_pattern="scanner",
            asset_pattern="lab-*",
            title_pattern="*expected*",
            reason="Known lab condition.",
        )
        scan = self.write_json(
            "scan.json",
            [
                {
                    "asset": "lab-host",
                    "title": "Expected lab finding",
                    "severity": "high",
                }
            ],
        )
        self.manager.import_scan(scan, fmt="generic", source="scanner", scope="lab")
        finding = self.manager.db.list_findings(limit=1)[0]
        self.assertEqual(finding["status"], "false_positive")
        actions = [item["action"] for item in self.manager.db.history(finding["id"])]
        self.assertIn("suppressed_by_rule", actions)

    def test_notes_and_asset_tags(self):
        scan = self.write_json(
            "finding.json",
            [{"asset": "app.example.test", "title": "Example issue", "severity": "medium"}],
        )
        self.manager.import_scan(scan, fmt="generic", source="scanner", scope="prod")
        finding = self.manager.db.list_findings(limit=1)[0]

        self.manager.platform.add_note(finding["id"], "Validated by app team.", "tester")
        self.manager.platform.add_asset_tag("app.example.test", "customer-facing")
        self.manager.platform.add_asset_tag("app.example.test", "production")

        self.assertEqual(self.manager.platform.notes(finding["id"])[0]["author"], "tester")
        self.assertEqual(
            self.manager.platform.tags_for_asset("app.example.test"),
            ["customer-facing", "production"],
        )

    def test_finding_search(self):
        scan = self.write_json(
            "findings.json",
            [
                {"asset": "vpn.example.test", "title": "VPN TLS issue", "severity": "high"},
                {"asset": "db.example.test", "title": "Database issue", "severity": "medium"},
            ],
        )
        self.manager.import_scan(scan, fmt="generic", source="scanner", scope="prod")
        rows = self.manager.db.list_findings(query="VPN", limit=10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["asset_key"], "vpn.example.test")

    @patch("exposure_manager.intel.urllib.request.urlopen")
    def test_online_intel_fetch_parsers(self, urlopen):
        urlopen.side_effect = [
            _FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2099-0001",
                            "vendorProject": "Demo",
                            "product": "Demo",
                        }
                    ]
                }
            ),
            _FakeResponse(
                {
                    "data": [
                        {
                            "cve": "CVE-2099-0001",
                            "epss": "0.91",
                            "percentile": "0.98",
                        }
                    ]
                }
            ),
        ]

        kev = fetch_kev()
        epss = fetch_epss({"CVE-2099-0001"})

        self.assertIn("CVE-2099-0001", kev)
        self.assertEqual(epss["CVE-2099-0001"]["epss"], 0.91)

    def test_new_ui_pages_and_local_api(self):
        app = create_app(self.root / "web.db", start_scheduler=False)
        app.config.update(TESTING=True)
        client = app.test_client()

        for path in ["/automation", "/triage", "/settings", "/api/v1/summary", "/api/v1/assets", "/api/v1/scans"]:
            response = client.get(path)
            self.assertEqual(response.status_code, 200, path)

        profile = client.post(
            "/automation/profiles",
            data={
                "name": "Local web",
                "provider": "builtin-web",
                "target": "http://127.0.0.1:5055",
                "scope": "local",
                "ports": "quick",
            },
            follow_redirects=True,
        )
        self.assertEqual(profile.status_code, 200)
        self.assertIn(b"Local web", profile.data)

        unauthorized_scan = client.post(
            "/api/v1/scans",
            json={
                "provider": "builtin-network",
                "target": "127.0.0.1",
                "ports": "5055",
            },
        )
        self.assertEqual(unauthorized_scan.status_code, 400)

    @patch("exposure_manager.notifications.send_slack")
    def test_scan_notifications_use_threshold_and_env_secret(self, send_slack):
        scan = self.write_json(
            "notify.json",
            [{"asset": "vpn.example.test", "title": "Critical issue", "severity": "critical"}],
        )
        summary = self.manager.import_scan(scan, fmt="generic", source="scanner", scope="prod")
        self.manager.platform.set_setting("notifications_enabled", True)
        self.manager.platform.set_setting("notification_min_risk", 70)

        with patch.dict("os.environ", {"EXPOSURE_SLACK_WEBHOOK": "https://example.invalid/hook"}):
            result = NotificationService(self.manager, self.manager.platform).notify_scan(summary)

        self.assertEqual(result["sent"], 1)
        self.assertEqual(result["finding_count"], 1)
        send_slack.assert_called_once()


if __name__ == "__main__":
    unittest.main()
