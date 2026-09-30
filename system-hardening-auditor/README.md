# System Hardening Auditor

A read-only Windows/Linux hardening audit tool for a cybersecurity portfolio. It checks local security configuration against a practical baseline and generates a remediation report without changing the host.

## What it audits

### Windows

- Windows Defender Firewall profiles
- Microsoft Defender real-time protection
- User Account Control (UAC)
- SMBv1 server protocol
- Built-in Guest account
- Remote Desktop / Network Level Authentication (NLA)
- Anonymous account/share enumeration restrictions
- Minimum local password length

### Linux

- SSH root-login policy
- SSH password-authentication policy
- Host firewall state (ufw, firewalld, nftables)
- Automatic security-update service
- `/etc/shadow` permissions
- IPv4 forwarding
- ICMP redirect acceptance
- SUID core-dump setting
- Password-age policy
- auditd state

## Reports

Each run can generate:

- **JSON** for machine-readable results
- **Markdown** for GitHub / assessment notes
- **HTML** for a clean human-readable remediation report

Every finding contains a control ID, category, severity, status, observed state, expected state, and remediation guidance.

## Run

No third-party Python packages are required.

```bash
cd system-hardening-auditor
python hardening_audit.py
```

Reports are written to `./reports/`.

Choose one format:

```bash
python hardening_audit.py --format html
python hardening_audit.py --format md
python hardening_audit.py --format json
```

Choose another output directory:

```bash
python hardening_audit.py --output ./my-reports
```

For CI or lab automation, return exit code `2` if a failed hardening control is found:

```bash
python hardening_audit.py --fail-on-findings
```

## Windows notes

Run from a normal PowerShell/CMD terminal first. Most checks are readable without elevation, but some Windows builds or enterprise policies may limit access to individual security settings. Those checks are reported as `WARN` or `ERROR` instead of silently passing.

## Linux notes

The tool uses read-only local commands and files such as `sshd -T`, `systemctl`, `nft`, `/proc/sys`, `/etc/login.defs`, and file metadata. Some checks may require elevated read access depending on the distribution.

## Status meanings

| Status | Meaning |
|---|---|
| PASS | The observed configuration matches the baseline |
| FAIL | The observed configuration does not match the baseline |
| WARN | Review is recommended, or the setting may be environment-dependent |
| INFO | Informational / not applicable / service not detected |
| ERROR | The check could not be completed reliably |

The score is calculated from PASS and FAIL checks only. WARN, INFO, and ERROR results remain visible but are not treated as automatic failures.

## Baseline statement

The built-in **Local Security Hardening Baseline v1** is a practical, CIS-inspired and vendor-guidance-aligned set of controls created for this project. It is **not an official CIS Benchmark implementation or certification**, and it does not reproduce proprietary benchmark text.

The baseline intentionally leaves room for environment-specific exceptions. For example, IP forwarding can be valid on a router, and SSH password authentication may be temporarily required during a migration.

## Safety

The auditor is read-only. It does not automatically apply remediation commands, disable services, change firewall rules, edit the registry, or rewrite Linux configuration files. Review remediation guidance before changing a real system.
