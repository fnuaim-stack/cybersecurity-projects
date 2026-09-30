import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hardening_audit", ROOT / "hardening_audit.py")
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
assert SPEC.loader is not None
SPEC.loader.exec_module(AUDIT)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.system = {
            "hostname": "test-host",
            "platform": "Linux",
            "platform_release": "test",
            "platform_version": "test",
            "architecture": "x86_64",
            "python": "3.x",
            "audit_time_utc": "2026-01-01T00:00:00+00:00",
        }
        self.results = [
            AUDIT.CheckResult(
                "TEST-001",
                "Passing control",
                "Test",
                "Low",
                AUDIT.PASS,
                "secure",
                "secure",
                "none",
            ),
            AUDIT.CheckResult(
                "TEST-002",
                "Failing control",
                "Test",
                "High",
                AUDIT.FAIL,
                "insecure",
                "secure",
                "fix the setting",
            ),
            AUDIT.CheckResult(
                "TEST-003",
                "Warning control",
                "Test",
                "Medium",
                AUDIT.WARN,
                "unknown",
                "reviewed",
                "review manually",
            ),
        ]

    def test_summary_score_excludes_warning(self):
        summary = AUDIT.summarize(self.results)
        self.assertEqual(summary["counts"][AUDIT.PASS], 1)
        self.assertEqual(summary["counts"][AUDIT.FAIL], 1)
        self.assertEqual(summary["counts"][AUDIT.WARN], 1)
        self.assertEqual(summary["score_percent"], 50.0)

    def test_markdown_contains_remediation(self):
        report = AUDIT.markdown_report(self.system, self.results)
        self.assertIn("System Hardening Audit Report", report)
        self.assertIn("TEST-002", report)
        self.assertIn("fix the setting", report)

    def test_html_escapes_observed_values(self):
        results = [
            AUDIT.CheckResult(
                "TEST-XSS",
                "HTML escaping",
                "Test",
                "Low",
                AUDIT.FAIL,
                "<script>alert(1)</script>",
                "safe text",
                "none",
            )
        ]
        report = AUDIT.html_report(self.system, results)
        self.assertNotIn("<script>alert(1)</script>", report)
        self.assertIn("&lt;script&gt;", report)


if __name__ == "__main__":
    unittest.main()
