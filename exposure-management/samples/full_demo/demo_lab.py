from __future__ import annotations

import argparse
import http.server
import json
import socket
import sys
import threading
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from exposure_manager.active_scans import ScannerService
from exposure_manager.campaigns import CampaignManager
from exposure_manager.intel import enrich_findings
from exposure_manager.service import ExposureManager


HERE = Path(__file__).resolve().parent


class DemoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"Exposure Management safe local demo target"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        # Deliberately omit common security headers so the built-in web checker has safe findings.
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def start_tcp_service(port: int, stop: threading.Event) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen()
    server.settimeout(0.25)

    def loop():
        while not stop.is_set():
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            connection.sendall(b"DEMO\n")
            connection.close()

    threading.Thread(target=loop, daemon=True, name="demo-tcp").start()
    return server


def wait_job(scanner: ScannerService, job_id: str, timeout: int = 20) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = scanner.store.get(job_id)
        if job["status"] in {"completed", "failed", "cancelled"}:
            return job
        time.sleep(0.1)
    raise RuntimeError(f"demo scan {job_id} timed out")


def seed_demo(manager: ExposureManager, scanner: ScannerService) -> None:
    manager.import_scan(
        HERE / "demo_findings.json",
        fmt="generic",
        source="demo-import",
        scope="demo",
        verify_missing=False,
    )
    manager.assets.import_context_csv(HERE / "assets.csv")

    manager.set_asset_context(
        "demo-vpn.local",
        criticality=5,
        internet_exposed=True,
        owner="network-team",
        environment="production",
    )
    manager.set_asset_context(
        "demo-app.local",
        criticality=4,
        internet_exposed=True,
        owner="app-team",
        environment="production",
    )

    manager.platform.add_asset_tag("demo-vpn.local", "internet-facing")
    manager.platform.add_asset_tag("demo-vpn.local", "tier-0")
    manager.platform.add_asset_tag("demo-app.local", "customer-facing")

    top = manager.db.list_findings(query="Demo critical VPN", limit=1)[0]
    manager.platform.add_note(
        int(top["id"]),
        "Validated in the safe demo. Assign remediation to the network team.",
        "demo-user",
    )

    manager.platform.create_suppression(
        name="Suppress expected demo finding",
        source_pattern="demo-import",
        asset_pattern="demo-printer.local",
        title_pattern="*expected informational*",
        reason="Expected low-value demo signal used to test noise handling.",
    )
    manager.platform.apply_suppressions()

    enrich_findings(
        manager.db,
        kev_path=HERE / "demo_kev.json",
        epss_path=HERE / "demo_epss.csv",
    )

    CampaignManager(manager.db).create(
        "Demo critical fixes",
        owner="security",
        min_risk=70,
        notes="Safe demo campaign.",
    )

    try:
        profile = manager.platform.create_profile(
            name="Demo TCP service scan",
            provider="builtin-network",
            target="127.0.0.1",
            scope="demo-local",
            ports="9099",
            partial=False,
        )
        schedule = manager.platform.create_schedule(
            profile["id"],
            interval_hours=24,
            run_immediately=False,
        )
        manager.platform.set_schedule_enabled(schedule["id"], False)
    except Exception:
        pass

    for provider, target, ports in [
        ("builtin-network", "127.0.0.1", "9099"),
        ("builtin-web", "http://127.0.0.1:8088", "quick"),
    ]:
        job = scanner.start(
            provider=provider,
            target=target,
            scope="demo-local",
            ports=ports,
            partial=True,
        )
        result = wait_job(scanner, job["id"])
        if result["status"] != "completed":
            raise RuntimeError(result["error"] or f"{provider} demo scan failed")


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe local Exposure Management demo lab.")
    parser.add_argument("--db", default=str(HERE / "demo-exposure.db"))
    args = parser.parse_args()

    db_path = Path(args.db).resolve()
    stop = threading.Event()
    tcp_server = start_tcp_service(9099, stop)
    web_server = http.server.ThreadingHTTPServer(("127.0.0.1", 8088), DemoHandler)
    web_thread = threading.Thread(target=web_server.serve_forever, daemon=True, name="demo-web")
    web_thread.start()

    try:
        manager = ExposureManager(db_path)
        scanner = ScannerService(manager)
        seed_demo(manager, scanner)

        print("")
        print("Exposure Management full demo is ready.")
        print(f"Database: {db_path}")
        print("Demo web target: http://127.0.0.1:8088")
        print("Demo TCP target: 127.0.0.1:9099")
        print("")
        print("In another PowerShell window run:")
        print(f'$env:EXPOSURE_DB="{db_path}"')
        print("py webapp.py")
        print("")
        print("Try Dashboard, Findings, Triage, Assets, Campaigns, Automation, Analytics and Scan.")
        print("Press Ctrl+C here when you are finished.")

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        stop.set()
        tcp_server.close()
        web_server.shutdown()
        web_server.server_close()
        web_thread.join(timeout=1)


if __name__ == "__main__":
    raise SystemExit(main())
