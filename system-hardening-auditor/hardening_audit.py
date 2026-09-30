#!/usr/bin/env python3
"""
System Hardening Auditor
Read-only local configuration audit for Windows and Linux.

The checks are intentionally CIS-inspired / vendor-guidance-aligned rather than
a verbatim implementation of any copyrighted benchmark. The tool does not
change system settings; it generates remediation guidance for review.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable


PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
INFO = "INFO"
ERROR = "ERROR"


@dataclass
class CheckResult:
    check_id: str
    title: str
    category: str
    severity: str
    status: str
    observed: str
    expected: str
    remediation: str
    evidence: str = ""


def run(command: list[str], timeout: int = 15) -> tuple[int, str, str]:
    """Run a local command without invoking a shell."""
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


def result(
    check_id: str,
    title: str,
    category: str,
    severity: str,
    status: str,
    observed: object,
    expected: str,
    remediation: str,
    evidence: str = "",
) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        title=title,
        category=category,
        severity=severity,
        status=status,
        observed=str(observed),
        expected=expected,
        remediation=remediation,
        evidence=evidence,
    )


def powershell(script: str) -> tuple[int, str, str]:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return 127, "", "PowerShell was not found"
    return run([exe, "-NoProfile", "-NonInteractive", "-Command", script], timeout=20)


def ps_scalar(script: str) -> tuple[int, str]:
    code, out, err = powershell(script)
    return code, (out if out else err)


def windows_checks() -> list[CheckResult]:
    checks: list[CheckResult] = []

    # Firewall profiles
    code, out, err = powershell(
        "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
    )
    if code == 0 and out:
        try:
            profiles = json.loads(out)
            if isinstance(profiles, dict):
                profiles = [profiles]
            disabled = [str(p.get("Name")) for p in profiles if not bool(p.get("Enabled"))]
            checks.append(
                result(
                    "WIN-FW-001",
                    "Windows Firewall enabled on all profiles",
                    "Network",
                    "High",
                    FAIL if disabled else PASS,
                    "Disabled: " + ", ".join(disabled) if disabled else "All profiles enabled",
                    "Domain, Private, and Public firewall profiles enabled",
                    "Enable Windows Defender Firewall for every profile with Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True.",
                    out,
                )
            )
        except json.JSONDecodeError:
            checks.append(result("WIN-FW-001", "Windows Firewall enabled on all profiles", "Network", "High", ERROR, out, "All profiles enabled", "Review Windows Firewall profile state manually.", err))
    else:
        checks.append(result("WIN-FW-001", "Windows Firewall enabled on all profiles", "Network", "High", ERROR, err or out, "All profiles enabled", "Run the audit from a PowerShell-capable Windows session and review Get-NetFirewallProfile."))

    # Defender real-time protection
    code, out = ps_scalar("(Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled")
    normalized = out.strip().lower()
    if code == 0 and normalized in {"true", "false"}:
        checks.append(
            result(
                "WIN-AV-001",
                "Microsoft Defender real-time protection",
                "Endpoint Protection",
                "High",
                PASS if normalized == "true" else FAIL,
                out,
                "Real-time protection enabled",
                "Enable Microsoft Defender real-time protection, or verify that an approved third-party endpoint protection product is active.",
            )
        )
    else:
        checks.append(result("WIN-AV-001", "Microsoft Defender real-time protection", "Endpoint Protection", "High", WARN, out, "Real-time protection enabled", "Verify the active endpoint protection product and real-time scanning state."))

    # UAC
    code, out = ps_scalar("(Get-ItemPropertyValue 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -ErrorAction Stop)")
    if code == 0 and out.strip() in {"0", "1"}:
        checks.append(
            result(
                "WIN-UAC-001",
                "User Account Control enabled",
                "Accounts",
                "High",
                PASS if out.strip() == "1" else FAIL,
                f"EnableLUA={out.strip()}",
                "EnableLUA=1",
                "Enable UAC in Windows security policy or set EnableLUA to 1, then restart as required.",
            )
        )
    else:
        checks.append(result("WIN-UAC-001", "User Account Control enabled", "Accounts", "High", WARN, out, "EnableLUA=1", "Review UAC policy manually."))

    # SMBv1 server support
    code, out = ps_scalar("(Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol")
    if code == 0 and out.strip().lower() in {"true", "false"}:
        checks.append(
            result(
                "WIN-SMB-001",
                "SMBv1 server protocol disabled",
                "Network",
                "Critical",
                PASS if out.strip().lower() == "false" else FAIL,
                f"EnableSMB1Protocol={out.strip()}",
                "SMBv1 disabled",
                "Disable SMBv1 unless a documented legacy dependency requires it. Prefer SMBv2/SMBv3.",
            )
        )
    else:
        checks.append(result("WIN-SMB-001", "SMBv1 server protocol disabled", "Network", "Critical", WARN, out, "SMBv1 disabled", "Review SMB server protocol configuration manually."))

    # Guest account
    code, out = ps_scalar("(Get-LocalUser -Name 'Guest' -ErrorAction Stop).Enabled")
    if code == 0 and out.strip().lower() in {"true", "false"}:
        checks.append(
            result(
                "WIN-ACC-001",
                "Built-in Guest account disabled",
                "Accounts",
                "Medium",
                PASS if out.strip().lower() == "false" else FAIL,
                f"Guest.Enabled={out.strip()}",
                "Guest account disabled",
                "Disable the built-in Guest account unless there is a documented operational requirement.",
            )
        )
    else:
        checks.append(result("WIN-ACC-001", "Built-in Guest account disabled", "Accounts", "Medium", WARN, out, "Guest account disabled", "Confirm the local Guest account is disabled."))

    # RDP and NLA
    code1, rdp = ps_scalar("(Get-ItemPropertyValue 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop)")
    if code1 == 0 and rdp.strip() == "1":
        checks.append(result("WIN-RDP-001", "Remote Desktop protected by NLA", "Remote Access", "High", PASS, "RDP disabled", "RDP disabled, or NLA required when enabled", "No change required while RDP remains disabled."))
    elif code1 == 0 and rdp.strip() == "0":
        code2, nla = ps_scalar("(Get-ItemPropertyValue 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -ErrorAction Stop)")
        if code2 == 0 and nla.strip() in {"0", "1"}:
            checks.append(result("WIN-RDP-001", "Remote Desktop protected by NLA", "Remote Access", "High", PASS if nla.strip() == "1" else FAIL, f"RDP enabled; UserAuthentication={nla.strip()}", "NLA required when RDP is enabled", "Require Network Level Authentication for RDP, and restrict RDP exposure with firewall rules or a trusted access path."))
        else:
            checks.append(result("WIN-RDP-001", "Remote Desktop protected by NLA", "Remote Access", "High", WARN, nla, "NLA required when RDP is enabled", "Verify NLA is required for Remote Desktop."))
    else:
        checks.append(result("WIN-RDP-001", "Remote Desktop protected by NLA", "Remote Access", "High", WARN, rdp, "RDP disabled, or NLA required when enabled", "Review Remote Desktop and NLA settings."))

    # Anonymous SAM/share enumeration restriction
    code, out = ps_scalar("(Get-ItemPropertyValue 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RestrictAnonymous -ErrorAction Stop)")
    if code == 0 and out.strip().isdigit():
        checks.append(
            result(
                "WIN-LSA-001",
                "Anonymous enumeration restricted",
                "Accounts",
                "Medium",
                PASS if int(out.strip()) >= 1 else FAIL,
                f"RestrictAnonymous={out.strip()}",
                "RestrictAnonymous >= 1",
                "Use Local Security Policy / Group Policy to restrict anonymous enumeration of SAM accounts and shares.",
            )
        )
    else:
        checks.append(result("WIN-LSA-001", "Anonymous enumeration restricted", "Accounts", "Medium", WARN, out, "RestrictAnonymous >= 1", "Review anonymous access restrictions in Local Security Policy."))

    # Minimum password length (best effort; output can be localized)
    code, out, err = run(["net", "accounts"])
    match = re.search(r"Minimum password length\s*:\s*(\d+)", out, re.IGNORECASE)
    if code == 0 and match:
        length = int(match.group(1))
        checks.append(
            result(
                "WIN-PASS-001",
                "Minimum password length",
                "Authentication",
                "Medium",
                PASS if length >= 14 else FAIL,
                f"{length} characters",
                "At least 14 characters for local password policy",
                "Set an organization-appropriate minimum password length (14+ is used by this baseline) and prefer long passphrases with MFA where available.",
                out,
            )
        )
    else:
        checks.append(result("WIN-PASS-001", "Minimum password length", "Authentication", "Medium", WARN, err or "Could not parse local policy", "At least 14 characters", "Review effective local/domain password policy. Domain policy may override local settings."))

    return checks


def read_sshd_effective() -> dict[str, str]:
    settings: dict[str, str] = {}
    exe = shutil.which("sshd")
    if exe:
        code, out, _ = run([exe, "-T"], timeout=10)
        if code == 0:
            for line in out.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    settings[parts[0].lower()] = parts[1].strip()
            return settings

    path = Path("/etc/ssh/sshd_config")
    if path.exists():
        try:
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    settings[parts[0].lower()] = parts[1].strip()
        except OSError:
            pass
    return settings


def sysctl_value(name: str) -> str | None:
    proc_path = Path("/proc/sys") / Path(name.replace(".", "/"))
    try:
        return proc_path.read_text().strip()
    except OSError:
        code, out, _ = run(["sysctl", "-n", name])
        return out.strip() if code == 0 else None


def systemd_active(service: str) -> bool:
    if not shutil.which("systemctl"):
        return False
    code, out, _ = run(["systemctl", "is-active", service], timeout=5)
    return code == 0 and out.strip() == "active"


def linux_checks() -> list[CheckResult]:
    checks: list[CheckResult] = []
    ssh = read_sshd_effective()

    root_login = ssh.get("permitrootlogin")
    if root_login:
        checks.append(
            result(
                "LNX-SSH-001",
                "SSH direct root login restricted",
                "Remote Access",
                "High",
                PASS if root_login.lower() in {"no", "prohibit-password", "without-password"} else FAIL,
                f"PermitRootLogin {root_login}",
                "PermitRootLogin no (or key-only root access where explicitly required)",
                "Set PermitRootLogin no in the effective SSH server configuration where operationally possible, then validate and reload sshd.",
            )
        )
    else:
        checks.append(result("LNX-SSH-001", "SSH direct root login restricted", "Remote Access", "High", INFO, "OpenSSH server configuration not detected", "Root login restricted when SSH server is installed", "If SSH server is used, explicitly restrict direct root login."))

    password_auth = ssh.get("passwordauthentication")
    if password_auth:
        checks.append(
            result(
                "LNX-SSH-002",
                "SSH password authentication disabled",
                "Remote Access",
                "Medium",
                PASS if password_auth.lower() == "no" else WARN,
                f"PasswordAuthentication {password_auth}",
                "PasswordAuthentication no when key-based authentication is operational",
                "Prefer key-based SSH authentication and disable password authentication after confirming recovery/admin access.",
            )
        )
    else:
        checks.append(result("LNX-SSH-002", "SSH password authentication disabled", "Remote Access", "Medium", INFO, "OpenSSH server configuration not detected", "Key-based authentication preferred", "If SSH server is used, consider key-based authentication and MFA where supported."))

    # Firewall
    firewall_observed: list[str] = []
    active = False
    for service in ("ufw", "firewalld"):
        if systemd_active(service):
            active = True
            firewall_observed.append(f"{service}=active")
    if shutil.which("nft"):
        code, out, _ = run(["nft", "list", "ruleset"], timeout=8)
        if code == 0 and re.search(r"\b(chain|table)\b", out):
            active = True
            firewall_observed.append("nftables rules present")
    checks.append(
        result(
            "LNX-FW-001",
            "Host firewall active",
            "Network",
            "High",
            PASS if active else FAIL,
            ", ".join(firewall_observed) if firewall_observed else "No active ufw/firewalld or nftables rules detected",
            "Active host firewall with an explicit policy",
            "Enable and configure the host firewall appropriate to the distribution (for example ufw, firewalld, or nftables) and allow only required services.",
        )
    )

    # Automatic updates
    update_active = any(
        systemd_active(service)
        for service in (
            "unattended-upgrades",
            "dnf-automatic.timer",
            "dnf5-automatic.timer",
            "yum-cron",
        )
    )
    checks.append(
        result(
            "LNX-UPD-001",
            "Automatic security update mechanism",
            "Patching",
            "Medium",
            PASS if update_active else WARN,
            "Active" if update_active else "No supported automatic-update service detected",
            "Security updates automatically applied or centrally managed",
            "Enable the distribution's automatic security-update mechanism, or document the centralized patch-management process.",
        )
    )

    # /etc/shadow permissions
    shadow = Path("/etc/shadow")
    if shadow.exists():
        try:
            mode = stat.S_IMODE(shadow.stat().st_mode)
            secure = (mode & 0o007) == 0 and (mode & 0o020) == 0 and (mode & 0o004) == 0
            checks.append(
                result(
                    "LNX-FILE-001",
                    "/etc/shadow permissions restricted",
                    "File Permissions",
                    "Critical",
                    PASS if secure else FAIL,
                    oct(mode),
                    "No permissions for other users; tightly restricted group access",
                    "Restrict /etc/shadow to root and the distribution-approved shadow group/mode. Do not broaden read access.",
                )
            )
        except OSError as exc:
            checks.append(result("LNX-FILE-001", "/etc/shadow permissions restricted", "File Permissions", "Critical", ERROR, exc, "Restricted permissions", "Review /etc/shadow ownership and mode."))
    else:
        checks.append(result("LNX-FILE-001", "/etc/shadow permissions restricted", "File Permissions", "Critical", INFO, "/etc/shadow not present", "Restricted permissions on Linux systems using shadow passwords", "No action if the platform legitimately does not use /etc/shadow."))

    # IP forwarding
    ipf = sysctl_value("net.ipv4.ip_forward")
    if ipf is not None:
        checks.append(
            result(
                "LNX-NET-001",
                "IPv4 forwarding disabled on non-router hosts",
                "Kernel",
                "Medium",
                PASS if ipf == "0" else WARN,
                f"net.ipv4.ip_forward={ipf}",
                "0 unless the host is intentionally routing traffic",
                "If this system is not a router, set net.ipv4.ip_forward=0 persistently. If routing is intentional, document the exception and firewall policy.",
            )
        )

    # ICMP redirects
    redirect_keys = [
        "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.default.accept_redirects",
    ]
    redirect_values = {k: sysctl_value(k) for k in redirect_keys}
    present = {k: v for k, v in redirect_values.items() if v is not None}
    if present:
        bad = {k: v for k, v in present.items() if v != "0"}
        checks.append(
            result(
                "LNX-NET-002",
                "ICMP redirects not accepted",
                "Kernel",
                "Medium",
                FAIL if bad else PASS,
                ", ".join(f"{k}={v}" for k, v in present.items()),
                "accept_redirects=0 for all/default",
                "Set IPv4 accept_redirects to 0 unless a documented network requirement exists, and persist the setting through sysctl configuration.",
            )
        )

    # SUID core dumps
    suid_dump = sysctl_value("fs.suid_dumpable")
    if suid_dump is not None:
        checks.append(
            result(
                "LNX-KERN-001",
                "SUID core dumps disabled",
                "Kernel",
                "Medium",
                PASS if suid_dump == "0" else FAIL,
                f"fs.suid_dumpable={suid_dump}",
                "0",
                "Set fs.suid_dumpable=0 persistently unless there is a documented debugging requirement.",
            )
        )

    # Password aging
    login_defs = Path("/etc/login.defs")
    max_days = None
    if login_defs.exists():
        try:
            for line in login_defs.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.match(r"^\s*PASS_MAX_DAYS\s+(\d+)", line)
                if m:
                    max_days = int(m.group(1))
                    break
        except OSError:
            pass
    if max_days is not None:
        checks.append(
            result(
                "LNX-PASS-001",
                "Password maximum age policy",
                "Authentication",
                "Low",
                PASS if max_days <= 90 else WARN,
                f"PASS_MAX_DAYS={max_days}",
                "90 days or less for password-only local accounts (organization policy may differ)",
                "Align password aging with organizational policy. Prefer MFA and strong passphrases; avoid forced rotation without a policy reason.",
            )
        )
    else:
        checks.append(result("LNX-PASS-001", "Password maximum age policy", "Authentication", "Low", INFO, "PASS_MAX_DAYS not found", "Defined local password-aging policy", "Review local authentication policy if password-based local accounts are used."))

    # auditd
    audit_active = systemd_active("auditd")
    checks.append(
        result(
            "LNX-AUD-001",
            "Linux auditing service active",
            "Logging",
            "Medium",
            PASS if audit_active else WARN,
            "auditd active" if audit_active else "auditd not active or not installed",
            "Host auditing enabled or centrally provided",
            "Enable and configure auditd, or document the approved equivalent endpoint/audit telemetry source.",
        )
    )

    return checks


def collect_system_info() -> dict[str, str]:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "audit_time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def summarize(results: Iterable[CheckResult]) -> dict[str, object]:
    items = list(results)
    counts = {key: sum(1 for r in items if r.status == key) for key in (PASS, FAIL, WARN, INFO, ERROR)}
    scored = counts[PASS] + counts[FAIL]
    score = round((counts[PASS] / scored) * 100, 1) if scored else 0.0
    return {"counts": counts, "score_percent": score, "total_checks": len(items)}


def markdown_report(system: dict[str, str], results: list[CheckResult]) -> str:
    summary = summarize(results)
    counts = summary["counts"]
    lines = [
        "# System Hardening Audit Report",
        "",
        f"- **Host:** {system['hostname']}",
        f"- **Platform:** {system['platform']} {system['platform_release']}",
        f"- **Architecture:** {system['architecture']}",
        f"- **Audit time (UTC):** {system['audit_time_utc']}",
        "- **Baseline:** Local Security Hardening Baseline v1 (CIS-inspired / vendor-guidance-aligned; not an official CIS benchmark)",
        f"- **Score:** {summary['score_percent']}% (PASS vs FAIL checks)",
        f"- **Results:** PASS {counts[PASS]} | FAIL {counts[FAIL]} | WARN {counts[WARN]} | INFO {counts[INFO]} | ERROR {counts[ERROR]}",
        "",
        "## Results",
        "",
        "| ID | Severity | Status | Control | Observed |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        observed = r.observed.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {r.check_id} | {r.severity} | {r.status} | {r.title} | {observed} |")

    actionable = [r for r in results if r.status in {FAIL, WARN, ERROR}]
    lines.extend(["", "## Remediation", ""])
    if not actionable:
        lines.append("No failed or warning checks were detected.")
    else:
        for r in actionable:
            lines.extend(
                [
                    f"### {r.check_id} — {r.title}",
                    "",
                    f"- **Severity:** {r.severity}",
                    f"- **Status:** {r.status}",
                    f"- **Observed:** {r.observed}",
                    f"- **Expected:** {r.expected}",
                    f"- **Remediation:** {r.remediation}",
                    "",
                ]
            )
    lines.extend(
        [
            "## Notes",
            "",
            "- This audit is read-only and does not modify the host.",
            "- WARN/INFO can represent environment-specific exceptions or checks that require manual validation.",
            "- Domain policy, MDM, EDR, cloud security policy, containers, and distribution-specific defaults can affect the effective state.",
            "",
        ]
    )
    return "\n".join(lines)


def html_report(system: dict[str, str], results: list[CheckResult]) -> str:
    summary = summarize(results)
    counts = summary["counts"]
    rows = []
    for r in results:
        rows.append(
            "<tr>"
            f"<td>{html.escape(r.check_id)}</td>"
            f"<td>{html.escape(r.severity)}</td>"
            f"<td><span class='status {html.escape(r.status.lower())}'>{html.escape(r.status)}</span></td>"
            f"<td>{html.escape(r.title)}</td>"
            f"<td>{html.escape(r.observed)}</td>"
            "</tr>"
        )

    remediation = []
    for r in results:
        if r.status in {FAIL, WARN, ERROR}:
            remediation.append(
                "<section class='finding'>"
                f"<h3>{html.escape(r.check_id)} — {html.escape(r.title)}</h3>"
                f"<p><b>Severity:</b> {html.escape(r.severity)} &nbsp; <b>Status:</b> {html.escape(r.status)}</p>"
                f"<p><b>Observed:</b> {html.escape(r.observed)}</p>"
                f"<p><b>Expected:</b> {html.escape(r.expected)}</p>"
                f"<p><b>Remediation:</b> {html.escape(r.remediation)}</p>"
                "</section>"
            )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>System Hardening Audit - {html.escape(system['hostname'])}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 0; background: #0b1020; color: #e6edf7; }}
main {{ max-width: 1180px; margin: 0 auto; padding: 32px; }}
.card, .finding {{ background: #131a2d; border: 1px solid #26304b; border-radius: 12px; padding: 18px; margin: 14px 0; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(150px,1fr)); gap: 12px; }}
.metric {{ font-size: 1.65rem; font-weight: 700; }}
table {{ width: 100%; border-collapse: collapse; background: #131a2d; }}
th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #26304b; vertical-align: top; }}
th {{ background: #18223a; }}
.status {{ font-weight: 700; }}
.pass {{ color: #6ee7a8; }} .fail {{ color: #ff7b7b; }} .warn {{ color: #ffd166; }}
.info {{ color: #8ec5ff; }} .error {{ color: #ff9bd2; }}
small {{ color: #aab6cf; }}
</style>
</head>
<body><main>
<h1>System Hardening Audit Report</h1>
<p><small>{html.escape(system['hostname'])} · {html.escape(system['platform'])} {html.escape(system['platform_release'])} · {html.escape(system['audit_time_utc'])}</small></p>
<div class="grid">
  <div class="card"><div class="metric">{summary['score_percent']}%</div><div>PASS vs FAIL score</div></div>
  <div class="card"><div class="metric">{counts[PASS]}</div><div>Passed</div></div>
  <div class="card"><div class="metric">{counts[FAIL]}</div><div>Failed</div></div>
  <div class="card"><div class="metric">{counts[WARN]}</div><div>Warnings</div></div>
</div>
<div class="card"><b>Baseline:</b> Local Security Hardening Baseline v1 — CIS-inspired / vendor-guidance-aligned; not an official CIS benchmark. This audit is read-only.</div>
<h2>Results</h2>
<table><thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Control</th><th>Observed</th></tr></thead><tbody>
{''.join(rows)}
</tbody></table>
<h2>Remediation</h2>
{''.join(remediation) if remediation else '<div class="card">No failed or warning checks were detected.</div>'}
</main></body></html>"""


def write_reports(output_dir: Path, formats: set[str], system: dict[str, str], results: list[CheckResult]) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_host = re.sub(r"[^A-Za-z0-9_.-]+", "_", system["hostname"])
    base = output_dir / f"hardening-audit-{safe_host}-{stamp}"
    written: list[Path] = []

    payload = {
        "tool": "System Hardening Auditor",
        "baseline": "Local Security Hardening Baseline v1",
        "system": system,
        "summary": summarize(results),
        "results": [asdict(r) for r in results],
    }

    if "json" in formats:
        path = base.with_suffix(".json")
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        written.append(path)
    if "md" in formats:
        path = base.with_suffix(".md")
        path.write_text(markdown_report(system, results), encoding="utf-8")
        written.append(path)
    if "html" in formats:
        path = base.with_suffix(".html")
        path.write_text(html_report(system, results), encoding="utf-8")
        written.append(path)
    return written


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit local Windows/Linux hardening controls and generate remediation reports."
    )
    parser.add_argument(
        "--format",
        choices=["all", "json", "md", "html"],
        default="all",
        help="Report format (default: all)",
    )
    parser.add_argument(
        "--output",
        default="reports",
        help="Directory for generated reports (default: reports)",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with code 2 when one or more FAIL results are found (useful for CI/labs).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    system = collect_system_info()
    os_name = platform.system().lower()

    if os_name == "windows":
        results = windows_checks()
    elif os_name == "linux":
        results = linux_checks()
    else:
        print(f"Unsupported platform: {platform.system()}", file=sys.stderr)
        return 1

    formats = {"json", "md", "html"} if args.format == "all" else {args.format}
    written = write_reports(Path(args.output), formats, system, results)
    summary = summarize(results)

    print(f"System Hardening Auditor — {system['hostname']}")
    print(
        f"PASS={summary['counts'][PASS]} FAIL={summary['counts'][FAIL]} "
        f"WARN={summary['counts'][WARN]} INFO={summary['counts'][INFO]} "
        f"ERROR={summary['counts'][ERROR]} SCORE={summary['score_percent']}%"
    )
    for path in written:
        print(f"Report: {path}")

    if args.fail_on_findings and summary["counts"][FAIL] > 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
