import importlib.util
import tempfile
import unittest
from email.message import Message
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


network = load_module("network_scanner", "network-scanner/scanner.py")
headers = load_module("http_checker", "http-security-checker/check_headers.py")
logs = load_module("log_analyzer", "log-analyzer/analyzer.py")
integrity = load_module("integrity_monitor", "file-integrity-monitor/monitor.py")
packets = load_module("packet_analyzer", "packet-analyzer/analyzer.py")


class NetworkScannerTests(unittest.TestCase):
    def test_subnet_and_port_parsing(self):
        target = network.parse_target("192.168.1.0/30")
        self.assertEqual(target["mode"], "subnet")
        self.assertEqual(target["hosts"], ["192.168.1.1", "192.168.1.2"])
        self.assertEqual(network.parse_ports("80,443,8000-8002"), [80, 443, 8000, 8001, 8002])

    def test_host_rows_include_names(self):
        rows = network.build_host_rows(
            ["10.0.0.2"],
            {"10.0.0.2"},
            {"10.0.0.2": [{"port": 443, "service": "https"}]},
            {},
            {"10.0.0.2": "lab-host"},
        )
        self.assertEqual(rows[0]["hostname"], "lab-host")
        self.assertEqual(rows[0]["status"], "up")


class HttpCheckerTests(unittest.TestCase):
    def test_cookie_flag_review(self):
        message = Message()
        message.add_header("Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Lax")
        message.add_header("Set-Cookie", "prefs=dark")

        cookies, issues = headers.analyze_cookies(message)

        self.assertEqual(len(cookies), 2)
        self.assertEqual(len(issues), 3)
        self.assertTrue(any(item["cookie"] == "prefs" for item in issues))

    def test_url_normalization(self):
        self.assertEqual(
            headers.normalize_url("example.com"),
            "https://example.com",
        )


class LogAnalyzerTests(unittest.TestCase):
    def test_auth_and_web_events(self):
        lines = [
            "Failed password for invalid user admin from 192.168.1.9 port 22 ssh2",
            "Failed password for admin from 192.168.1.9 port 22 ssh2",
            '192.168.1.8 - - "GET /missing HTTP/1.1" 404 10',
            "Accepted publickey for student from 2001:db8::10 port 4444 ssh2",
        ]

        result = logs.analyze(lines, threshold=2)

        self.assertEqual(result["flagged_ips"]["192.168.1.9"], 2)
        self.assertEqual(result["event_counts"]["failed_login"], 2)
        self.assertEqual(result["http_statuses"]["404"], 1)
        self.assertIn("student", result["user_activity"])
        self.assertIn("2001:db8::10", result["ip_activity"])


class FileIntegrityTests(unittest.TestCase):
    def test_baseline_excludes_and_detects_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            baseline = root / "baseline.json"
            keep = root / "keep.txt"
            ignored = root / "debug.log"

            keep.write_text("one", encoding="utf-8")
            ignored.write_text("ignore me", encoding="utf-8")

            data = integrity.save_baseline(
                root,
                baseline,
                exclude_patterns=["*.log"],
            )
            self.assertEqual(data["file_count"], 1)

            keep.write_text("two", encoding="utf-8")
            ignored.write_text("changed too", encoding="utf-8")

            result = integrity.compare_baseline(root, baseline)
            self.assertEqual(result["modified"], ["keep.txt"])
            self.assertEqual(result["changed_count"], 1)
            self.assertIn("keep.txt", result["changed_details"])


class PacketAnalyzerTests(unittest.TestCase):
    def test_richer_packet_summary(self):
        sample = [
            IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=50000, dport=443),
            IP(src="10.0.0.2", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com")),
        ]

        result = packets.summarize_packets(sample)

        self.assertEqual(result["packet_count"], 2)
        self.assertEqual(result["protocol_counts"]["TCP"], 1)
        self.assertEqual(result["protocol_counts"]["UDP"], 1)
        self.assertEqual(result["top_talkers"][0]["ip"], "10.0.0.2")
        self.assertEqual(result["dns_queries"][0]["query"], "example.com")


if __name__ == "__main__":
    unittest.main()
