# Roadmap

No strict schedule. I use this to keep the repo moving in a useful direction instead of adding random scripts.

## Current direction

The main goal is one practical PT/security workbench with small tools that can still run by themselves.

The standalone vulnerability dashboard is gone. Findings, status tracking, and reports now live in the Pentest Workbench.

## Next upgrades

### Pentest Workbench

- assessment scope and notes
- tags and CVE/reference fields
- evidence file attachments
- JSON/CSV report export
- better history view for previous tool runs
- reusable assessment profiles

### Network Scanner

- optional scan presets
- better service fingerprints without turning it into a full Nmap clone
- export cleaner host inventories

### HTTP Security Checker

- more useful CSP parsing
- certificate-chain details
- optional HTML report output

### Packet Analyzer

- PCAP timeline view
- more DNS and TCP conversation detail
- export filtered packet summaries

### Log Analyzer

- presets for SSH/auth.log, Apache/Nginx, and Windows-style exports
- time-window filtering
- small rule system for custom detections

### File Integrity Monitor

- baseline labels
- multiple saved baselines
- optional allowlist for expected changes

## Project ideas

- DNS/domain recon helper
- web endpoint inventory tool
- wordlist cleanup/mutation utilities
- CTF notes/evidence organizer
- offline hash identification and lab password-audit helper
- assessment evidence organizer

Everything that touches a target stays scoped to systems I own, labs, CTFs, or environments where I have permission to test.
