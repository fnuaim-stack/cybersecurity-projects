# Roadmap

No strict schedule here. This is the list I use when deciding what is actually worth building next.

## Current direction

I want the repo to have both offensive-security and defensive projects, with more focus on penetration testing and red-team learning.

The goal is not to dump random scripts into folders. I would rather have projects that connect together and slowly become useful tools.

## In progress / next improvements

### Pentest Workbench

- import more result formats
- add tags and CVE/reference fields
- attach evidence paths to findings
- add assessment scope and notes
- export JSON as well as Markdown
- add a small local web UI when the CLI/data model is stable

### Network Scanner

- add safe concurrency so larger lab scans are faster
- improve service information
- make its JSON output richer for the workbench

### HTTP Security Header Checker

- add response metadata and redirect history
- make findings easier to import into the workbench
- avoid treating every missing header as automatically serious

### Packet Analyzer

- add capture filters
- improve protocol summaries
- add PCAP-only analysis mode so saved captures can be reviewed without live sniffing

### Defensive projects

- support more real log formats in the log analyzer
- let the file integrity monitor save a proper change report
- connect the vulnerability dashboard to a small backend instead of browser-only storage

## New project ideas

- DNS and domain reconnaissance helper
- service-enumeration notes helper for lab targets
- web endpoint inventory tool
- wordlist cleanup and mutation utilities
- CTF notes/evidence organizer
- offline hash identification and lab password-audit helper
- PCAP investigation toolkit
- assessment report templates and evidence management

Everything that touches a target should stay scoped to systems I own, labs, CTFs, or environments where I have permission to test.
