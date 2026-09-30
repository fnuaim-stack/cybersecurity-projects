import importlib.util
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("socket_leak_guard", ROOT / "socket_leak_guard.py")
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
assert SPEC.loader is not None
SPEC.loader.exec_module(MOD)


class TrendTests(unittest.TestCase):
    def test_high_growth_is_flagged(self):
        trend = MOD.evaluate_trend(10, "demo.exe", [10, 18, 27, 40], min_growth=10, min_percent=25)
        self.assertEqual(trend.severity, "HIGH")
        self.assertEqual(trend.growth, 30)

    def test_flat_is_stable(self):
        trend = MOD.evaluate_trend(10, "demo.exe", [10, 10, 10, 10], min_growth=5, min_percent=20)
        self.assertEqual(trend.severity, "STABLE")


class ClassificationTests(unittest.TestCase):
    def test_protected_process(self):
        importance, action, reason = MOD.classify_process(4, "System", r"C:\\Windows\\System32\\ntoskrnl.exe")
        self.assertEqual(importance, "critical")
        self.assertIn("keep", action)
        self.assertIn("do not terminate", reason.lower())

    def test_program_files_app(self):
        importance, action, _ = MOD.classify_process(900, "vendor.exe", r"C:\\Program Files\\Vendor\\vendor.exe")
        self.assertEqual(importance, "normal")
        self.assertIn("update", action)


class ProtectionTests(unittest.TestCase):
    def test_self_is_protected(self):
        with mock.patch.object(MOD.os, "getpid", return_value=1234):
            protected, _ = MOD.protected_target(1234)
        self.assertTrue(protected)


if __name__ == "__main__":
    unittest.main()
