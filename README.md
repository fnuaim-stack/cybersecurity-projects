# Cybersecurity Projects

This repo is where I keep my cybersecurity projects and slowly connect them into one usable toolkit.

The main app is the **Pentest Workbench**, but the repo now also has a bigger red-team/PT side with scope checking, scan-result parsing, endpoint inventory, CTF helpers, wordlist utilities, and evidence organization.

## Main toolkit

| Project | What it does |
|---|---|
| [Pentest Workbench](./pentest-workbench/) | Local UI that connects the core tools, stores findings, tracks status, and builds reports |
| [Network Scanner](./network-scanner/) | Fast single-host and subnet TCP scanning |
| [HTTP Security Checker](./http-security-checker/) | Passive HTTP, redirect, cookie, header, and TLS checks |
| [Packet Analyzer](./packet-analyzer/) | Live capture or offline PCAP analysis |
| [Log Analyzer](./log-analyzer/) | Authentication/basic web log analysis |
| [File Integrity Monitor](./file-integrity-monitor/) | SHA-256 baselines and change reports |
| [System Hardening Auditor](./system-hardening-auditor/) | Read-only Windows/Linux baseline audit with JSON, Markdown, and HTML remediation reports |

## Red-team / PT projects

| Project | What it does |
|---|---|
| [Scope Guard](./scope-guard/) | Checks targets against an authorized scope before testing |
| [Nmap Result Explorer](./nmap-result-explorer/) | Parses saved Nmap XML into clean console, JSON, or Markdown output |
| [Web Endpoint Inventory](./web-endpoint-inventory/) | Builds an endpoint map from HAR files or URL lists |
| [CTF Toolbox](./ctf-toolbox/) | Local base64/hex/URL/JWT decode and hash-format helpers |
| [Wordlist Lab](./wordlist-lab/) | Cleans, filters, deduplicates, and transforms local wordlists |
| [Evidence Organizer](./evidence-organizer/) | Stores assessment evidence with SHA-256 hashes and a Markdown index |

See [RED_TEAM.md](./RED_TEAM.md) for how these pieces fit together.

## Run the Workbench

```bash
cd pentest-workbench
pip install -r requirements.txt
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

Every project has its own README and CLI examples.

Anything that scans, captures traffic, or supports penetration testing is meant for labs, CTF-style environments, and systems or networks I own or have permission to test.
