# Roadmap

No strict schedule. I use this to keep the repo moving in a useful direction instead of adding random scripts.

## Current direction

The repo now has two connected sides:

- the Pentest Workbench and core security tools
- standalone red-team/PT helpers for scope, recon results, web inventory, CTF work, wordlists, and evidence

The next step is making these projects share data more cleanly instead of duplicating inputs.

## Next upgrades

### Pentest Workbench

- import Nmap XML directly
- import endpoint inventories
- assessment scope and notes
- tags and CVE/reference fields
- evidence file attachments
- JSON/CSV report export
- better history view

### Red-team projects

- connect Scope Guard to active tools as an optional pre-check
- add a local recon workspace that combines Nmap XML + endpoint inventory
- add better URL/parameter grouping
- add CTF note templates and challenge folders
- let Evidence Organizer link directly to Workbench finding IDs

### Existing tools

- network scan presets and cleaner inventory export
- better CSP parsing in HTTP checker
- PCAP timeline/conversation views
- log-format presets and time-window filtering
- multiple named FIM baselines

## Possible future projects

- DNS/domain recon helper for authorized targets
- local service-enumeration note builder
- web technology inventory from saved response data
- offline hash-audit helper using user-provided hashes and wordlists
- assessment report/evidence bundle exporter

Everything that touches a target stays scoped to systems I own, labs, CTFs, or environments where I have permission to test.
