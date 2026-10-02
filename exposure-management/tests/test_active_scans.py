import http.server
import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from exposure_manager.active_scans import ScannerService
from exposure_manager.service import ExposureManager


class ActiveScanTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.manager = ExposureManager(self.root / "scan-test.db")
        self.scanner = ScannerService(self.manager)

    def tearDown(self):
        self.tempdir.cleanup()

    def wait_for_job(self, job_id, timeout=8):
        deadline = time.time() + timeout
        while time.time() < deadline:
            job = self.scanner.store.get(job_id)
            if job["status"] in {"completed", "failed", "cancelled"}:
                return job
            time.sleep(0.05)
        self.fail(f"scan job {job_id} did not finish")

    def test_builtin_network_scan_detects_local_open_port_and_imports_it(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        stop = threading.Event()

        def accept_loop():
            server.settimeout(0.2)
            while not stop.is_set():
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    continue
                connection.close()

        thread = threading.Thread(target=accept_loop, daemon=True)
        thread.start()
        try:
            job = self.scanner.start(
                provider="builtin-network",
                target="127.0.0.1",
                scope="local-test",
                ports=str(port),
            )
            finished = self.wait_for_job(job["id"])
        finally:
            stop.set()
            server.close()
            thread.join(timeout=1)

        self.assertEqual(finished["status"], "completed", finished["error"])
        self.assertEqual(finished["result_count"], 1)
        findings = self.manager.db.list_findings(source="builtin-network", limit=10)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["port"], port)

    def test_builtin_web_scan_creates_header_findings(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            job = self.scanner.start(
                provider="builtin-web",
                target=url,
                scope="local-web",
            )
            finished = self.wait_for_job(job["id"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

        self.assertEqual(finished["status"], "completed", finished["error"])
        self.assertGreaterEqual(finished["result_count"], 4)
        findings = self.manager.db.list_findings(source="builtin-web", limit=20)
        titles = {item["title"] for item in findings}
        self.assertIn("Web target uses unencrypted HTTP", titles)
        self.assertIn("Missing Content-Security-Policy", titles)

    def test_scan_validation_limits_large_subnets(self):
        with self.assertRaises(ValueError):
            self.scanner.start(
                provider="builtin-network",
                target="10.0.0.0/16",
                scope="test",
            )

    def test_web_scan_requires_full_url(self):
        with self.assertRaises(ValueError):
            self.scanner.start(
                provider="builtin-web",
                target="example.test",
                scope="test",
            )


if __name__ == "__main__":
    unittest.main()
