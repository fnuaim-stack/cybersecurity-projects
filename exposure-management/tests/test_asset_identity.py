import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from exposure_manager.service import ExposureManager


class AssetIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.manager = ExposureManager(self.root / "exposure.db")

    def tearDown(self):
        self.tempdir.cleanup()

    def write_scan(self, name, rows):
        path = self.root / name
        path.write_text(json.dumps(rows), encoding="utf-8")
        return path

    def test_alias_reconciles_scanner_names_to_one_asset(self):
        first = self.write_scan(
            "first.json",
            [{"asset": "server.example.test", "title": "Finding A", "severity": "high"}],
        )
        second = self.write_scan(
            "second.json",
            [{"asset": "192.0.2.70", "title": "Finding B", "severity": "medium"}],
        )

        self.manager.import_scan(first, fmt="generic", source="scanner-a", scope="prod")
        self.manager.assets.add_alias("server.example.test", "192.0.2.70")
        self.manager.import_scan(second, fmt="generic", source="scanner-b", scope="prod")

        assets = self.manager.db.list_assets()
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["asset_key"], "server.example.test")
        self.assertEqual(assets[0]["finding_count"], 2)

    def test_partial_scan_does_not_verify_missing_findings(self):
        finding_scan = self.write_scan(
            "finding.json",
            [{"asset": "app.example.test", "title": "Finding A", "severity": "high"}],
        )
        partial_scan = self.write_scan("partial.json", [])

        self.manager.import_scan(finding_scan, fmt="generic", source="scanner", scope="prod")
        finding_id = self.manager.remediation_queue()[0]["id"]

        for _ in range(3):
            result = self.manager.import_scan(
                partial_scan,
                fmt="generic",
                source="scanner",
                scope="prod",
                verification_misses=2,
                verify_missing=False,
            )
            self.assertFalse(result["verification_applied"])

        finding = self.manager.db.get_finding(finding_id)
        self.assertEqual(finding["status"], "open")
        self.assertEqual(finding["consecutive_misses"], 0)

    def test_asset_context_csv_import(self):
        csv_path = self.root / "assets.csv"
        csv_path.write_text(
            "asset,name,criticality,internet_exposed,owner,environment,aliases\n"
            "vpn.example.test,VPN,5,yes,network,production,192.0.2.80;vpn01\n",
            encoding="utf-8",
        )

        result = self.manager.assets.import_context_csv(csv_path)
        asset = self.manager.db.get_asset("vpn.example.test")

        self.assertEqual(result["created_assets"], 1)
        self.assertEqual(result["aliases"], 2)
        self.assertEqual(asset["criticality"], 5)
        self.assertEqual(asset["internet_exposed"], 1)
        self.assertEqual(self.manager.assets.resolve("192.0.2.80"), "vpn.example.test")
        self.assertEqual(self.manager.assets.resolve("vpn01"), "vpn.example.test")


if __name__ == "__main__":
    unittest.main()
