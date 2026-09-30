# Cybersecurity Projects

This repo started as a place for small cybersecurity projects and I am slowly turning it into a mix of red-team, penetration-testing, defensive, and vulnerability-management work.

I still want the code to stay readable instead of making every project complicated for no reason.

## Projects

| Project | What it does |
|---|---|
| [Pentest Workbench](./pentest-workbench/) | Local SQLite workbench for findings, tool imports, status tracking, and Markdown reports |
| [Network Scanner](./network-scanner/) | Checks a host for open TCP ports |
| [HTTP Security Header Checker](./http-security-checker/) | Checks a site for a few common browser security headers |
| [Packet Analyzer](./packet-analyzer/) | Captures packets and gives a small traffic summary |
| [Log Analyzer](./log-analyzer/) | Checks logs for repeated failed logins and IP activity |
| [File Integrity Monitor](./file-integrity-monitor/) | Uses SHA-256 hashes to notice changed, added, or deleted files |
| [Vulnerability Dashboard](./vulnerability-dashboard/) | Small browser dashboard for tracking vulnerability findings and their status |

## Folder structure

```text
cybersecurity-projects/
├── pentest-workbench/
├── network-scanner/
├── http-security-checker/
├── packet-analyzer/
├── log-analyzer/
├── file-integrity-monitor/
└── vulnerability-dashboard/
```

The newer direction is to make the projects work together where it makes sense. For example, the Pentest Workbench can already import JSON results from the Network Scanner and HTTP Security Header Checker instead of treating every folder like a completely separate demo.

Every project has its own README with the commands needed to run it.

There is also a [roadmap](./ROADMAP.md) for things I want to build or improve next.

Anything that scans, captures traffic, or supports penetration testing is meant for labs, CTF-style environments, and systems I own or have permission to test.
