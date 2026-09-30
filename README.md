# Cybersecurity Projects

This repo is where I keep my cybersecurity projects and slowly connect them into one usable toolkit.

The main project is the **Pentest Workbench**. The smaller tools still work by themselves, but they also plug into the same local UI and findings database.

## Projects

| Project | What it does |
|---|---|
| [Pentest Workbench](./pentest-workbench/) | Local UI that connects the tools, stores findings, tracks status, and builds reports |
| [Network Scanner](./network-scanner/) | Fast single-host and subnet TCP scanning with service names and optional hostname lookup |
| [HTTP Security Checker](./http-security-checker/) | Passive HTTP, redirect, cookie, security-header, and TLS checks |
| [Packet Analyzer](./packet-analyzer/) | Live packet capture or offline PCAP analysis with protocol, DNS, port, and talker summaries |
| [Log Analyzer](./log-analyzer/) | Parses authentication and basic web events, IPs, users, and repeated failed logins |
| [File Integrity Monitor](./file-integrity-monitor/) | SHA-256 baselines with file metadata, excludes, and detailed change reports |
| [System Hardening Auditor](./system-hardening-auditor/) | Read-only Windows/Linux baseline audit with JSON, Markdown, and HTML remediation reports |

## Folder structure

```text
cybersecurity-projects/
├── pentest-workbench/
├── network-scanner/
├── http-security-checker/
├── packet-analyzer/
├── log-analyzer/
├── file-integrity-monitor/
├── system-hardening-auditor/
└── tests/
```

The old standalone vulnerability dashboard was removed because the Workbench now handles findings and reporting in one place.

## Run the UI

```bash
cd pentest-workbench
pip install -r requirements.txt
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

Each tool also has its own README and CLI.

Anything that scans, captures traffic, or supports penetration testing is meant for labs, CTF-style environments, and systems or networks I own or have permission to test.
