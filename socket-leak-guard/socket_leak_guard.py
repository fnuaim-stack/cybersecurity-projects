#!/usr/bin/env python3
"""Socket Leak Guard - inspect and safely remediate runaway socket usage."""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import os
import platform
import shlex
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

try:
    import psutil
except ImportError:  # pragma: no cover - friendly CLI path
    psutil = None


PROTECTED_PROCESS_NAMES = {
    "system",
    "system idle process",
    "registry",
    "memory compression",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "kernel_task",
    "launchd",
    "systemd",
    "init",
}

WINDOWS_DIR = os.environ.get("WINDIR", r"C:\Windows")


@dataclass
class SocketSummary:
    pid: int
    name: str = "<unknown>"
    sockets: int = 0
    tcp: int = 0
    udp: int = 0
    listening: int = 0
    established: int = 0
    time_wait: int = 0
    close_wait: int = 0
    other_tcp: int = 0
    start_time: str = "unknown"
    runtime: str = "unknown"
    username: str = "unknown"
    exe: str = "unknown"
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    importance: str = "review"
    action: str = "review"
    reason: str = ""


@dataclass
class LeakTrend:
    pid: int
    name: str
    first: int
    last: int
    maximum: int
    minimum: int
    growth: int
    growth_percent: float
    rising_steps: int
    samples: int
    severity: str


def require_psutil() -> None:
    if psutil is None:
        raise SystemExit("Missing dependency: pip install psutil")


def utc_iso(timestamp: float | None) -> str:
    if not timestamp:
        return "unknown"
    return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def format_duration(seconds: float) -> str:
    if seconds < 0:
        return "unknown"
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    chunks = []
    if days:
        chunks.append(f"{days}d")
    if hours or days:
        chunks.append(f"{hours}h")
    if minutes or hours or days:
        chunks.append(f"{minutes}m")
    chunks.append(f"{seconds}s")
    return " ".join(chunks)


def _normalize_path(value: str) -> str:
    try:
        return str(Path(value).resolve()).lower()
    except Exception:
        return value.lower()


def is_system_path(exe: str) -> bool:
    if not exe or exe == "unknown":
        return False
    normalized = _normalize_path(exe)
    if platform.system() == "Windows":
        return normalized.startswith(_normalize_path(WINDOWS_DIR))
    return normalized.startswith(("/usr/", "/bin/", "/sbin/", "/lib/", "/system/"))


def is_user_temp_path(exe: str) -> bool:
    if not exe or exe == "unknown":
        return False
    low = exe.lower().replace("/", "\\")
    return any(part in low for part in ("\\appdata\\local\\temp\\", "\\temp\\", "\\downloads\\"))


def classify_process(pid: int, name: str, exe: str, username: str = "unknown", signer: str | None = None) -> tuple[str, str, str]:
    lname = (name or "").lower()
    signer_low = (signer or "").lower()

    if pid in {0, 1, 4} or lname in PROTECTED_PROCESS_NAMES:
        return "critical", "keep / update OS", "Protected operating-system process; do not terminate or delete it."

    if is_system_path(exe) or "microsoft" in signer_low:
        return "high", "keep / update OS", "Operating-system or Microsoft component; update through Windows Update/vendor servicing."

    if "program files" in (exe or "").lower() or signer:
        return "normal", "update / review", "Installed application. Update from the vendor; uninstall normally if you no longer need it."

    if is_user_temp_path(exe):
        return "review", "review / uninstall if unwanted", "Runs from a user temp/download location; verify publisher and purpose before keeping it."

    if exe and exe != "unknown":
        return "review", "review / update", "Non-system executable. Verify publisher and whether you intentionally installed it."

    return "review", "review", "Process metadata could not be fully read; run elevated for a more complete assessment."


def authenticode_signer(exe: str) -> tuple[str, str]:
    """Return (signature_status, signer_subject) on Windows without extra modules."""
    if platform.system() != "Windows" or not exe or exe == "unknown" or not Path(exe).exists():
        return "not-checked", ""
    quoted = exe.replace("'", "''")
    script = (
        f"$s=Get-AuthenticodeSignature -LiteralPath '{quoted}'; "
        "$o=[PSCustomObject]@{Status=[string]$s.Status;Signer=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''}}; "
        "$o|ConvertTo-Json -Compress"
    )
    try:
        cp = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if cp.returncode == 0 and cp.stdout.strip():
            payload = json.loads(cp.stdout)
            return str(payload.get("Status", "unknown")), str(payload.get("Signer", ""))
    except Exception:
        pass
    return "unknown", ""


def _safe_process_metadata(pid: int) -> dict[str, object]:
    now = time.time()
    data: dict[str, object] = {
        "name": "<unknown>",
        "start_time": "unknown",
        "runtime": "unknown",
        "username": "unknown",
        "exe": "unknown",
        "cpu_percent": 0.0,
        "memory_mb": 0.0,
    }
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            data["name"] = proc.name() or "<unknown>"
            created = proc.create_time()
            data["start_time"] = utc_iso(created)
            data["runtime"] = format_duration(now - created)
            try:
                data["username"] = proc.username() or "unknown"
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
            try:
                data["exe"] = proc.exe() or "unknown"
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
            try:
                data["memory_mb"] = round(proc.memory_info().rss / (1024 * 1024), 1)
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
            try:
                data["cpu_percent"] = round(proc.cpu_percent(interval=None), 1)
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return data


def collect_socket_summaries() -> tuple[list[SocketSummary], list[str]]:
    require_psutil()
    warnings: list[str] = []
    grouped: dict[int, list[object]] = collections.defaultdict(list)
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        raise SystemExit("Access denied while reading sockets. Re-run as Administrator/root for a complete view.")

    for conn in connections:
        if conn.pid is not None:
            grouped[int(conn.pid)].append(conn)

    summaries: list[SocketSummary] = []
    import socket

    for pid, conns in grouped.items():
        meta = _safe_process_metadata(pid)
        s = SocketSummary(pid=pid, name=str(meta["name"]), sockets=len(conns))
        s.start_time = str(meta["start_time"])
        s.runtime = str(meta["runtime"])
        s.username = str(meta["username"])
        s.exe = str(meta["exe"])
        s.cpu_percent = float(meta["cpu_percent"])
        s.memory_mb = float(meta["memory_mb"])

        for conn in conns:
            if conn.type == socket.SOCK_DGRAM:
                s.udp += 1
                continue
            s.tcp += 1
            status = str(conn.status or "").upper()
            if status == "LISTEN":
                s.listening += 1
            elif status == "ESTABLISHED":
                s.established += 1
            elif status == "TIME_WAIT":
                s.time_wait += 1
            elif status == "CLOSE_WAIT":
                s.close_wait += 1
            else:
                s.other_tcp += 1

        s.importance, s.action, s.reason = classify_process(s.pid, s.name, s.exe, s.username)
        summaries.append(s)

    summaries.sort(key=lambda x: (x.sockets, x.established, x.close_wait), reverse=True)
    if platform.system() == "Windows" and not _is_elevated_windows():
        warnings.append("Not running as Administrator; some system-process metadata/sockets may be hidden.")
    return summaries, warnings


def _is_elevated_windows() -> bool:
    if platform.system() != "Windows":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def print_table(rows: Iterable[SocketSummary], limit: int) -> None:
    selected = list(rows)[:limit]
    headers = ("PID", "PROCESS", "SOCKETS", "EST", "LISTEN", "CLOSE_WAIT", "STARTED", "ACTION")
    print(f"{headers[0]:>7}  {headers[1]:<24} {headers[2]:>7} {headers[3]:>5} {headers[4]:>6} {headers[5]:>10}  {headers[6]:<25} {headers[7]}")
    print("-" * 118)
    for s in selected:
        print(f"{s.pid:>7}  {s.name[:24]:<24} {s.sockets:>7} {s.established:>5} {s.listening:>6} {s.close_wait:>10}  {s.start_time[:25]:<25} {s.action}")


def cmd_top(args: argparse.Namespace) -> int:
    summaries, warnings = collect_socket_summaries()
    if args.json:
        print(json.dumps({"generated_at": utc_iso(time.time()), "processes": [asdict(x) for x in summaries[: args.limit]], "warnings": warnings}, indent=2))
    else:
        print_table(summaries, args.limit)
        for warning in warnings:
            print(f"WARNING: {warning}", file=sys.stderr)
    return 0


def _snapshot_counts() -> dict[int, tuple[str, int]]:
    summaries, _ = collect_socket_summaries()
    return {s.pid: (s.name, s.sockets) for s in summaries}


def evaluate_trend(pid: int, name: str, values: list[int], min_growth: int, min_percent: float) -> LeakTrend:
    first = values[0]
    last = values[-1]
    growth = last - first
    base = max(first, 1)
    pct = round((growth / base) * 100, 1)
    rising = sum(1 for a, b in zip(values, values[1:]) if b > a)
    enough_steps = rising >= max(2, (len(values) - 1) // 2)

    if growth >= min_growth * 2 and pct >= min_percent * 2 and enough_steps:
        severity = "HIGH"
    elif growth >= min_growth and pct >= min_percent and enough_steps:
        severity = "MEDIUM"
    elif growth > 0:
        severity = "LOW"
    else:
        severity = "STABLE"

    return LeakTrend(pid, name, first, last, max(values), min(values), growth, pct, rising, len(values), severity)


def cmd_watch(args: argparse.Namespace) -> int:
    history: dict[int, list[int]] = collections.defaultdict(list)
    names: dict[int, str] = {}
    for index in range(args.samples):
        snapshot = _snapshot_counts()
        all_pids = set(history) | set(snapshot)
        for pid in all_pids:
            name, count = snapshot.get(pid, (names.get(pid, "<ended>"), 0))
            names[pid] = name
            history[pid].append(count)
        if not args.quiet:
            leaders = sorted(snapshot.items(), key=lambda item: item[1][1], reverse=True)[:5]
            compact = ", ".join(f"{name}({pid})={count}" for pid, (name, count) in leaders)
            print(f"Sample {index + 1}/{args.samples}: {compact}")
        if index + 1 < args.samples:
            time.sleep(args.interval)

    trends = [evaluate_trend(pid, names.get(pid, "<unknown>"), values, args.min_growth, args.min_percent) for pid, values in history.items() if values]
    severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "STABLE": 0}
    trends.sort(key=lambda x: (severity_rank[x.severity], x.growth, x.maximum), reverse=True)
    flagged = [t for t in trends if t.severity in {"HIGH", "MEDIUM"}]

    payload = {"generated_at": utc_iso(time.time()), "interval_seconds": args.interval, "samples": args.samples, "flagged": [asdict(t) for t in flagged]}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print("\nPotential socket-leak trends:")
        if not flagged:
            print("No medium/high growth trend detected in this sampling window.")
        for t in flagged:
            print(f"{t.severity:<6} PID {t.pid:<7} {t.name:<24} {t.first} -> {t.last} (+{t.growth}, {t.growth_percent}%, rising {t.rising_steps}/{t.samples - 1})")
    return 0


def _connections_for_pid(pid: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.pid != pid:
            continue
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
        rows.append({"family": str(conn.family), "type": str(conn.type), "local": laddr, "remote": raddr, "status": str(conn.status)})
    return rows


def inspect_payload(pid: int, include_signer: bool = True) -> dict[str, object]:
    require_psutil()
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            name = proc.name()
            exe = "unknown"
            username = "unknown"
            cmdline: list[str] = []
            try:
                exe = proc.exe() or "unknown"
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
            try:
                username = proc.username() or "unknown"
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
            try:
                cmdline = proc.cmdline()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
            created = proc.create_time()
    except psutil.NoSuchProcess:
        raise SystemExit(f"PID {pid} no longer exists.")
    except psutil.AccessDenied:
        raise SystemExit(f"Access denied reading PID {pid}; re-run elevated.")

    sig_status, signer = authenticode_signer(exe) if include_signer else ("not-checked", "")
    importance, action, reason = classify_process(pid, name, exe, username, signer)
    conns = _connections_for_pid(pid)
    states = collections.Counter(row["status"] for row in conns)
    return {
        "pid": pid,
        "name": name,
        "exe": exe,
        "username": username,
        "command_line": shlex.join(cmdline) if cmdline else "unknown",
        "start_time": utc_iso(created),
        "runtime": format_duration(time.time() - created),
        "socket_count": len(conns),
        "socket_states": dict(states),
        "signature_status": sig_status,
        "signer": signer,
        "importance": importance,
        "recommended_action": action,
        "reason": reason,
        "connections": conns,
    }


def cmd_inspect(args: argparse.Namespace) -> int:
    payload = inspect_payload(args.pid, include_signer=not args.no_signer)
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0
    print(f"Process: {payload['name']} (PID {payload['pid']})")
    print(f"Started: {payload['start_time']}  Runtime: {payload['runtime']}")
    print(f"Path: {payload['exe']}")
    print(f"User: {payload['username']}")
    print(f"Signer: {payload['signature_status']} {payload['signer']}")
    print(f"Sockets: {payload['socket_count']}  States: {payload['socket_states']}")
    print(f"Assessment: {payload['importance']} | {payload['recommended_action']}")
    print(f"Reason: {payload['reason']}")
    if args.connections:
        print("\nConnections:")
        for row in payload["connections"]:
            print(f"  {row['status']:<13} {row['local']:<24} -> {row['remote']}")
    return 0


def protected_target(pid: int) -> tuple[bool, str]:
    if pid in {0, 1, 4}:
        return True, "protected operating-system PID"
    if pid == os.getpid():
        return True, "Socket Leak Guard refuses to terminate itself"
    try:
        name = psutil.Process(pid).name().lower()
    except psutil.NoSuchProcess:
        return False, "process no longer exists"
    except psutil.AccessDenied:
        return True, "cannot safely identify this process without elevated access"
    if name in PROTECTED_PROCESS_NAMES:
        return True, f"protected operating-system process: {name}"
    return False, ""


def cmd_release(args: argparse.Namespace) -> int:
    require_psutil()
    protected, reason = protected_target(args.pid)
    if protected:
        print(f"REFUSED: {reason}", file=sys.stderr)
        return 3
    try:
        proc = psutil.Process(args.pid)
        name = proc.name()
        before = len(_connections_for_pid(args.pid))
    except psutil.NoSuchProcess:
        print(f"PID {args.pid} already exited; its sockets are already released.")
        return 0

    if not args.yes:
        print(f"Dry run: would gracefully terminate {name} (PID {args.pid}), which currently owns {before} inet socket(s).")
        print("Re-run with --yes to proceed. Add --force only if you want a kill after the graceful timeout.")
        return 0

    print(f"Terminating {name} (PID {args.pid}) to release {before} socket(s)...")
    try:
        proc.terminate()
        proc.wait(timeout=args.timeout)
        print("Released: process exited and the OS reclaimed its sockets.")
        return 0
    except psutil.TimeoutExpired:
        if not args.force:
            print("Process did not exit before timeout. No forced kill performed. Re-run with --force if appropriate.", file=sys.stderr)
            return 4
        print("Graceful termination timed out; forcing process exit because --force was supplied.")
        proc.kill()
        proc.wait(timeout=args.timeout)
        print("Released: process was killed and the OS reclaimed its sockets.")
        return 0
    except psutil.AccessDenied:
        print("Access denied. Re-run as Administrator/root if this is a non-critical process you intend to stop.", file=sys.stderr)
        return 5


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Find socket-heavy processes, detect socket leaks, inspect ownership, and safely release sockets by stopping a selected non-critical process."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    top = sub.add_parser("top", help="Rank processes by current inet socket count")
    top.add_argument("--limit", type=int, default=15)
    top.add_argument("--json", action="store_true")
    top.set_defaults(func=cmd_top)

    watch = sub.add_parser("watch", help="Sample socket counts over time and flag growth trends")
    watch.add_argument("--samples", type=int, default=8)
    watch.add_argument("--interval", type=float, default=2.0)
    watch.add_argument("--min-growth", type=int, default=10, help="Minimum absolute growth to flag")
    watch.add_argument("--min-percent", type=float, default=25.0, help="Minimum percent growth to flag")
    watch.add_argument("--quiet", action="store_true")
    watch.add_argument("--json", action="store_true")
    watch.set_defaults(func=cmd_watch)

    inspect = sub.add_parser("inspect", help="Show process, start time, signer, recommendation, and sockets")
    inspect.add_argument("pid", type=int)
    inspect.add_argument("--connections", action="store_true")
    inspect.add_argument("--no-signer", action="store_true", help="Skip Windows Authenticode lookup")
    inspect.add_argument("--json", action="store_true")
    inspect.set_defaults(func=cmd_inspect)

    release = sub.add_parser("release", help="Release a process's sockets by stopping that selected process")
    release.add_argument("pid", type=int)
    release.add_argument("--yes", action="store_true", help="Actually terminate; without this the command is dry-run only")
    release.add_argument("--force", action="store_true", help="Kill only if graceful termination times out")
    release.add_argument("--timeout", type=float, default=8.0)
    release.set_defaults(func=cmd_release)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    if getattr(args, "samples", 2) < 2:
        raise SystemExit("--samples must be at least 2")
    if getattr(args, "interval", 0) < 0:
        raise SystemExit("--interval must be >= 0")
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
