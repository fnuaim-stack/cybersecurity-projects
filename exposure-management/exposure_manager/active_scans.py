from __future__ import annotations

import ipaddress
import json
import re
import shutil
import socket
import sqlite3
import subprocess
import threading
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445,
    587, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 9200, 27017,
]
WEB_PORTS = [80, 443, 8000, 8080, 8081, 8443]
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanCancelled(RuntimeError):
    pass


class ScanJobStore:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS active_scan_jobs (
        id TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        target TEXT NOT NULL,
        scope TEXT NOT NULL,
        ports TEXT NOT NULL DEFAULT 'quick',
        partial INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL,
        progress INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT,
        result_count INTEGER NOT NULL DEFAULT 0,
        output_path TEXT NOT NULL DEFAULT '',
        import_summary_json TEXT NOT NULL DEFAULT '{}',
        log_text TEXT NOT NULL DEFAULT '',
        error TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_active_scan_jobs_created
        ON active_scan_jobs(created_at DESC);
    """

    def __init__(self, db) -> None:
        self.db = db
        with self.db.connect() as conn:
            conn.executescript(self.SCHEMA)
            conn.execute(
                """
                UPDATE active_scan_jobs
                SET status='failed',
                    finished_at=?,
                    error='Application stopped before this scan completed.'
                WHERE status IN ('queued','running','cancel_requested')
                """,
                (utc_now(),),
            )

    def create(self, *, provider: str, target: str, scope: str, ports: str, partial: bool) -> dict:
        job_id = uuid.uuid4().hex[:12]
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO active_scan_jobs(
                    id,provider,target,scope,ports,partial,status,progress,created_at
                ) VALUES(?,?,?,?,?,?,?,0,?)
                """,
                (job_id, provider, target, scope, ports, int(partial), "queued", now),
            )
        return self.get(job_id)

    def update(self, job_id: str, **values) -> None:
        if not values:
            return
        allowed = {
            "status", "progress", "started_at", "finished_at", "result_count",
            "output_path", "import_summary_json", "log_text", "error",
        }
        invalid = set(values) - allowed
        if invalid:
            raise ValueError(f"invalid scan job fields: {sorted(invalid)}")
        keys = list(values)
        assignments = ",".join(f"{key}=?" for key in keys)
        with self.db.connect() as conn:
            conn.execute(
                f"UPDATE active_scan_jobs SET {assignments} WHERE id=?",
                [values[key] for key in keys] + [job_id],
            )

    def append_log(self, job_id: str, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {message.strip()}\n"
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE active_scan_jobs
                SET log_text=substr(log_text || ?, -12000)
                WHERE id=?
                """,
                (line, job_id),
            )

    def get(self, job_id: str) -> dict:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM active_scan_jobs WHERE id=?",
                (job_id,),
            ).fetchone()
        if not row:
            raise KeyError(f"scan job not found: {job_id}")
        result = dict(row)
        try:
            result["import_summary"] = json.loads(result.get("import_summary_json") or "{}")
        except json.JSONDecodeError:
            result["import_summary"] = {}
        return result

    def list(self, limit: int = 30) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM active_scan_jobs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]


class ScannerService:
    PROVIDER_NAMES = {
        "builtin-network": "Built-in network scan",
        "builtin-web": "Built-in web check",
        "nmap": "Nmap service scan",
        "nuclei": "Nuclei web scan",
        "trivy": "Trivy filesystem scan",
    }

    def __init__(self, manager) -> None:
        self.manager = manager
        self.store = ScanJobStore(manager.db)
        self.result_dir = manager.db.path.parent / "scan-results"
        self.result_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._cancel_events: dict[str, threading.Event] = {}
        self._processes: dict[str, subprocess.Popen] = {}

    def providers(self) -> list[dict]:
        return [
            {
                "id": "builtin-network",
                "name": self.PROVIDER_NAMES["builtin-network"],
                "available": True,
                "detail": "TCP service discovery for a host, IP, or small subnet.",
                "target_hint": "192.168.1.0/24 or server.local",
            },
            {
                "id": "builtin-web",
                "name": self.PROVIDER_NAMES["builtin-web"],
                "available": True,
                "detail": "HTTP/HTTPS reachability and common response security headers.",
                "target_hint": "https://app.example.com",
            },
            {
                "id": "nmap",
                "name": self.PROVIDER_NAMES["nmap"],
                "available": bool(shutil.which("nmap")),
                "detail": "Richer TCP service/version discovery when Nmap is installed.",
                "target_hint": "192.168.1.10 or 192.168.1.0/24",
            },
            {
                "id": "nuclei",
                "name": self.PROVIDER_NAMES["nuclei"],
                "available": bool(shutil.which("nuclei")),
                "detail": "Template-based web checks with intrusive/fuzz/DoS tags excluded.",
                "target_hint": "https://app.example.com",
            },
            {
                "id": "trivy",
                "name": self.PROVIDER_NAMES["trivy"],
                "available": bool(shutil.which("trivy")),
                "detail": "Local dependency vulnerability scan for a file or folder.",
                "target_hint": r"C:\path\to\project",
            },
        ]

    def start(
        self,
        *,
        provider: str,
        target: str,
        scope: str = "default",
        ports: str = "quick",
        partial: bool = False,
    ) -> dict:
        provider = provider.strip().lower()
        if provider not in self.PROVIDER_NAMES:
            raise ValueError("Unknown scan provider.")

        target = target.strip()
        scope = scope.strip() or "default"
        ports = ports.strip() or "quick"

        self._validate(provider, target, ports)
        availability = {item["id"]: item["available"] for item in self.providers()}
        if not availability.get(provider):
            raise ValueError(f"{self.PROVIDER_NAMES[provider]} is not installed or available.")

        job = self.store.create(
            provider=provider,
            target=target,
            scope=scope,
            ports=ports,
            partial=partial,
        )
        cancel_event = threading.Event()
        with self._lock:
            self._cancel_events[job["id"]] = cancel_event

        thread = threading.Thread(
            target=self._run,
            args=(job["id"], cancel_event),
            daemon=True,
            name=f"exposure-scan-{job['id']}",
        )
        thread.start()
        return job

    def cancel(self, job_id: str) -> dict:
        job = self.store.get(job_id)
        if job["status"] not in {"queued", "running"}:
            return job

        self.store.update(job_id, status="cancel_requested")
        self.store.append_log(job_id, "Cancellation requested.")
        with self._lock:
            event = self._cancel_events.get(job_id)
            process = self._processes.get(job_id)
        if event:
            event.set()
        if process and process.poll() is None:
            process.terminate()
        return self.store.get(job_id)

    def _validate(self, provider: str, target: str, ports: str) -> None:
        if not target:
            raise ValueError("A scan target is required.")

        if provider in {"builtin-network", "nmap"}:
            self._network_targets(target)
            self._parse_ports(ports)
        elif provider in {"builtin-web", "nuclei"}:
            parsed = urlparse(target)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("Web scans require a full http:// or https:// URL.")
        elif provider == "trivy":
            path = Path(target).expanduser()
            if not path.exists():
                raise ValueError("The Trivy target path does not exist.")

    def _network_targets(self, target: str) -> list[str]:
        if "://" in target or "/" in target and not self._looks_like_network(target):
            raise ValueError("Network scans accept a hostname, IP address, or CIDR subnet.")

        if self._looks_like_network(target):
            network = ipaddress.ip_network(target, strict=False)
            if network.num_addresses > 256:
                raise ValueError("Limit subnet scans to 256 addresses (/24 for IPv4) per job.")
            if network.num_addresses <= 2:
                return [str(address) for address in network]
            return [str(address) for address in network.hosts()]

        try:
            ipaddress.ip_address(target)
            return [target]
        except ValueError:
            pass

        if not HOSTNAME_RE.fullmatch(target):
            raise ValueError("Invalid hostname or network target.")
        return [target]

    @staticmethod
    def _looks_like_network(value: str) -> bool:
        if "/" not in value:
            return False
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False

    def _parse_ports(self, value: str) -> list[int]:
        text = value.strip().lower()
        if text == "quick":
            return list(COMMON_PORTS)
        if text == "web":
            return list(WEB_PORTS)

        ports: set[int] = set()
        for part in text.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start_text, end_text = part.split("-", 1)
                if not start_text.isdigit() or not end_text.isdigit():
                    raise ValueError("Custom ports must look like 22,80,443 or 8000-8010.")
                start, end = int(start_text), int(end_text)
                if start > end:
                    start, end = end, start
                if end - start > 1023:
                    raise ValueError("A custom port range may contain at most 1024 ports.")
                ports.update(range(start, end + 1))
            else:
                if not part.isdigit():
                    raise ValueError("Custom ports must look like 22,80,443 or 8000-8010.")
                ports.add(int(part))

        if not ports:
            raise ValueError("Choose quick, web, or enter at least one custom port.")
        if len(ports) > 1024:
            raise ValueError("Limit a scan to 1024 ports per host.")
        if min(ports) < 1 or max(ports) > 65535:
            raise ValueError("Ports must be between 1 and 65535.")
        return sorted(ports)

    def _run(self, job_id: str, cancel_event: threading.Event) -> None:
        job = self.store.get(job_id)
        self.store.update(job_id, status="running", started_at=utc_now(), progress=1)
        self.store.append_log(job_id, f"Starting {self.PROVIDER_NAMES[job['provider']]}.")
        output_path: Path | None = None

        try:
            provider = job["provider"]
            if provider == "builtin-network":
                output_path, fmt, source = self._run_builtin_network(job, cancel_event)
            elif provider == "builtin-web":
                output_path, fmt, source = self._run_builtin_web(job, cancel_event)
            elif provider == "nmap":
                output_path, fmt, source = self._run_nmap(job, cancel_event)
            elif provider == "nuclei":
                output_path, fmt, source = self._run_nuclei(job, cancel_event)
            elif provider == "trivy":
                output_path, fmt, source = self._run_trivy(job, cancel_event)
            else:
                raise ValueError("Unsupported scan provider.")

            if cancel_event.is_set():
                raise ScanCancelled("Scan cancelled.")

            self.store.update(job_id, progress=92, output_path=str(output_path))
            self.store.append_log(job_id, "Scan finished. Importing results into Exposure Management.")
            summary = self.manager.import_scan(
                output_path,
                fmt=fmt,
                source=source,
                scope=job["scope"],
                verification_misses=2,
                verify_missing=not bool(job["partial"]),
            )
            self.store.update(
                job_id,
                status="completed",
                progress=100,
                finished_at=utc_now(),
                result_count=int(summary.get("imported", 0)),
                import_summary_json=json.dumps(summary, default=str),
                output_path=str(output_path),
                error="",
            )
            self.store.append_log(
                job_id,
                f"Imported {summary.get('imported', 0)} results; "
                f"{summary.get('created', 0)} new and {summary.get('updated', 0)} updated.",
            )
        except ScanCancelled as error:
            self.store.update(
                job_id,
                status="cancelled",
                finished_at=utc_now(),
                error=str(error),
            )
            self.store.append_log(job_id, "Scan cancelled.")
        except Exception as error:
            self.store.update(
                job_id,
                status="failed",
                finished_at=utc_now(),
                error=str(error),
            )
            self.store.append_log(job_id, f"Scan failed: {error}")
        finally:
            with self._lock:
                self._cancel_events.pop(job_id, None)
                process = self._processes.pop(job_id, None)
            if process and process.poll() is None:
                process.kill()

    def _job_path(self, job_id: str, suffix: str) -> Path:
        folder = self.result_dir / job_id
        folder.mkdir(parents=True, exist_ok=True)
        return folder / f"result{suffix}"

    def _run_builtin_network(self, job: dict, cancel_event: threading.Event):
        hosts = self._network_targets(job["target"])
        ports = self._parse_ports(job["ports"])
        total = max(1, len(hosts) * len(ports))
        self.store.append_log(
            job["id"],
            f"Scanning {len(hosts)} host(s) across {len(ports)} TCP port(s).",
        )

        findings: list[dict] = []
        completed = 0

        def check(host: str, port: int):
            if cancel_event.is_set():
                return None
            try:
                with socket.create_connection((host, port), timeout=0.45):
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except OSError:
                        service = "unknown"
                    return {
                        "asset": host,
                        "title": f"Open TCP service: {port} ({service})",
                        "external_id": f"builtin-tcp:{port}",
                        "severity": "info",
                        "port": port,
                        "protocol": "tcp",
                        "service": service,
                        "description": "The built-in TCP scanner connected successfully to this port.",
                        "remediation": "Confirm the service is required, patched, and limited to the networks that need it.",
                    }
            except (OSError, TimeoutError):
                return None

        with ThreadPoolExecutor(max_workers=min(96, max(8, len(ports) * 2))) as executor:
            futures = {
                executor.submit(check, host, port): (host, port)
                for host in hosts
                for port in ports
            }
            for future in as_completed(futures):
                if cancel_event.is_set():
                    for pending in futures:
                        pending.cancel()
                    raise ScanCancelled("Scan cancelled.")
                result = future.result()
                if result:
                    findings.append(result)
                    self.store.append_log(
                        job["id"],
                        f"Open: {result['asset']}:{result['port']}/{result['protocol']} ({result['service']})",
                    )
                completed += 1
                if completed % 25 == 0 or completed == total:
                    progress = min(88, 5 + int((completed / total) * 83))
                    self.store.update(job["id"], progress=progress)

        path = self._job_path(job["id"], ".json")
        path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        return path, "generic", "builtin-network"

    def _run_builtin_web(self, job: dict, cancel_event: threading.Event):
        if cancel_event.is_set():
            raise ScanCancelled("Scan cancelled.")

        target = job["target"]
        self.store.append_log(job["id"], f"Requesting {target}.")
        request = urllib.request.Request(
            target,
            headers={"User-Agent": "ExposureManagement/0.3"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
                effective_url = response.geturl()
                status = response.status
        except urllib.error.HTTPError as error:
            headers = {key.lower(): value for key, value in error.headers.items()}
            effective_url = error.geturl()
            status = error.code
        except urllib.error.URLError as error:
            raise RuntimeError(f"Could not reach target: {error.reason}") from error

        parsed = urlparse(effective_url)
        asset = parsed.hostname or effective_url
        findings: list[dict] = []

        checks = [
            ("content-security-policy", "Missing Content-Security-Policy", "medium",
             "Add a suitable Content-Security-Policy for the application."),
            ("x-content-type-options", "Missing X-Content-Type-Options", "low",
             "Set X-Content-Type-Options: nosniff."),
            ("x-frame-options", "Missing clickjacking protection header", "medium",
             "Use frame-ancestors in CSP or an appropriate X-Frame-Options header."),
            ("referrer-policy", "Missing Referrer-Policy", "low",
             "Set an appropriate Referrer-Policy."),
        ]
        if parsed.scheme == "https":
            checks.append(
                ("strict-transport-security", "Missing HTTP Strict-Transport-Security", "medium",
                 "Enable HSTS after confirming HTTPS is correctly deployed.")
            )
        else:
            findings.append({
                "asset": asset,
                "title": "Web target uses unencrypted HTTP",
                "external_id": "builtin-web:http",
                "severity": "medium",
                "description": f"The effective URL uses HTTP (status {status}).",
                "remediation": "Serve the application over HTTPS and redirect HTTP to HTTPS.",
            })

        for header, title, severity, remediation in checks:
            if header not in headers:
                findings.append({
                    "asset": asset,
                    "title": title,
                    "external_id": f"builtin-web:{header}",
                    "severity": severity,
                    "description": f"The {header} response header was not present (HTTP {status}).",
                    "remediation": remediation,
                })

        self.store.update(job["id"], progress=88)
        self.store.append_log(
            job["id"],
            f"HTTP {status}; generated {len(findings)} security-header finding(s).",
        )
        path = self._job_path(job["id"], ".json")
        path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        return path, "generic", "builtin-web"

    def _run_nmap(self, job: dict, cancel_event: threading.Event):
        executable = shutil.which("nmap")
        if not executable:
            raise RuntimeError("Nmap is not installed or not in PATH.")

        output = self._job_path(job["id"], ".xml")
        ports = job["ports"].strip().lower()
        command = [
            executable,
            "-sT",
            "-sV",
            "--version-light",
            "--open",
            "-T3",
            "-oX",
            str(output),
        ]
        if ports == "quick":
            command += ["--top-ports", "100"]
        elif ports == "web":
            command += ["-p", ",".join(map(str, WEB_PORTS))]
        else:
            command += ["-p", ",".join(map(str, self._parse_ports(ports)))]
        command.append(job["target"])

        self._run_process(job["id"], command, cancel_event, timeout=900)
        return output, "nmap", "nmap"

    def _run_nuclei(self, job: dict, cancel_event: threading.Event):
        executable = shutil.which("nuclei")
        if not executable:
            raise RuntimeError("Nuclei is not installed or not in PATH.")

        output = self._job_path(job["id"], ".jsonl")
        output.touch()
        command = [
            executable,
            "-u",
            job["target"],
            "-jsonl",
            "-o",
            str(output),
            "-silent",
            "-exclude-tags",
            "intrusive,fuzz,dos",
            "-rate-limit",
            "50",
            "-timeout",
            "10",
        ]
        self._run_process(job["id"], command, cancel_event, timeout=1200)
        return output, "nuclei", "nuclei"

    def _run_trivy(self, job: dict, cancel_event: threading.Event):
        executable = shutil.which("trivy")
        if not executable:
            raise RuntimeError("Trivy is not installed or not in PATH.")

        output = self._job_path(job["id"], ".json")
        target = str(Path(job["target"]).expanduser().resolve())
        command = [
            executable,
            "fs",
            "--format",
            "json",
            "--output",
            str(output),
            "--scanners",
            "vuln",
            target,
        ]
        self._run_process(job["id"], command, cancel_event, timeout=1200)
        return output, "trivy", "trivy"

    def _run_process(
        self,
        job_id: str,
        command: list[str],
        cancel_event: threading.Event,
        *,
        timeout: int,
    ) -> None:
        self.store.append_log(job_id, f"Launching {Path(command[0]).name}.")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
        with self._lock:
            self._processes[job_id] = process

        timer = threading.Timer(timeout, process.kill)
        timer.start()
        try:
            while True:
                if cancel_event.is_set():
                    process.terminate()
                    raise ScanCancelled("Scan cancelled.")

                line = process.stdout.readline() if process.stdout else ""
                if line:
                    self.store.append_log(job_id, line[:500])
                code = process.poll()
                if code is not None:
                    remainder = process.stdout.read() if process.stdout else ""
                    if remainder:
                        for extra in remainder.splitlines()[-20:]:
                            self.store.append_log(job_id, extra[:500])
                    if code != 0:
                        raise RuntimeError(f"Scanner exited with code {code}. Check the scan log.")
                    break
                self.store.update(job_id, progress=min(85, self.store.get(job_id)["progress"] + 1))
        finally:
            timer.cancel()
            with self._lock:
                self._processes.pop(job_id, None)
