# Cybersecurity Projects

Just a collection of small cybersecurity projects I am building for practice.

I wanted to keep them in one repo instead of making a new repo for every small idea.

## Projects

| Project | What it does |
|---|---|
| [Network Scanner](./network-scanner/) | Checks a host for open TCP ports |
| [Packet Analyzer](./packet-analyzer/) | Captures packets and gives a small traffic summary |
| [Log Analyzer](./log-analyzer/) | Checks logs for repeated failed logins and IP activity |
| [File Integrity Monitor](./file-integrity-monitor/) | Uses SHA-256 hashes to notice changed, added, or deleted files |
| [Vulnerability Dashboard](./vulnerability-dashboard/) | Small browser dashboard for tracking vulnerability findings and their status |
| [HTTP Security Header Checker](./http-security-checker/) | Checks a site for a few common browser security headers |

## Folder structure

```text
cybersecurity-projects/
├── network-scanner/
├── packet-analyzer/
├── log-analyzer/
├── file-integrity-monitor/
├── vulnerability-dashboard/
└── http-security-checker/
```

Every project has its own README with the commands needed to run it.

I also added a small [roadmap](./ROADMAP.md) so there is always a list of things worth improving instead of making random changes just for the sake of commits.

These are learning projects, so I am keeping the code readable and not trying to turn every project into something huge.

Anything that scans or captures network traffic should only be used on systems and networks you own or have permission to test.
