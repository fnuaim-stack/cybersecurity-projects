import io
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from webapp import create_app


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.app = create_app(self.root / "ui-test.db")
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_main_pages_load(self):
        for path in ["/", "/scan", "/import", "/findings", "/assets", "/campaigns", "/analytics", "/intel", "/health"]:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)

    def test_import_to_dashboard_flow(self):
        payload = b'''[
          {
            "asset": "vpn.example.test",
            "title": "Example VPN finding",
            "severity": "high",
            "external_id": "CVE-2026-9000",
            "cvss": 8.4
          }
        ]'''

        response = self.client.post(
            "/import",
            data={
                "scan_file": (io.BytesIO(payload), "scan.json"),
                "format": "generic",
                "scope": "prod",
                "verify_misses": "2",
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Example VPN finding", response.data)

        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"vpn.example.test", dashboard.data)

    def test_finding_asset_and_report_actions(self):
        manager = self.app.config["MANAGER"]
        path = self.root / "finding.json"
        path.write_text(
            """[{"asset":"api.example.test","title":"API issue","severity":"medium"}]""",
            encoding="utf-8",
        )
        manager.import_scan(path, fmt="generic", source="scanner", scope="prod")
        finding = manager.remediation_queue()[0]

        detail = self.client.get(f"/findings/{finding['id']}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b"API issue", detail.data)

        update = self.client.post(
            f"/findings/{finding['id']}/update",
            data={"status": "in_progress", "owner": "security"},
            follow_redirects=True,
        )
        self.assertEqual(update.status_code, 200)
        self.assertIn(b"security", update.data)

        asset_update = self.client.post(
            "/assets/update",
            data={
                "asset": "api.example.test",
                "criticality": "5",
                "internet_exposed": "on",
                "owner": "platform",
                "environment": "production",
            },
            follow_redirects=True,
        )
        self.assertEqual(asset_update.status_code, 200)
        self.assertIn(b"production", asset_update.data)

        report = self.client.get("/reports/csv")
        self.assertEqual(report.status_code, 200)
        self.assertIn(b"API issue", report.data)


if __name__ == "__main__":
    unittest.main()
