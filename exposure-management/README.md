# Exposure Management

This project turns scanner results into a remediation queue instead of leaving them as separate files.

It keeps an asset inventory, removes duplicate findings, adds asset context to risk, tracks owners and status, applies remediation due dates, and verifies fixes across rescans.

## Supported imports

- Nuclei JSON/JSONL
- Trivy JSON
- Nmap XML
- OpenVAS CSV
- SARIF
- Generic JSON, JSONL, or CSV

## Run

No extra Python packages are required.

~~~bash
cd exposure-management
python exposure.py import scan.jsonl --format nuclei --scope prod
python exposure.py summary
python exposure.py queue
~~~

Set asset context:

~~~bash
python exposure.py asset-set app.example.com --criticality 5 --internet-exposed yes --owner security
~~~

Update a finding:

~~~bash
python exposure.py finding-set 12 --status in_progress --owner faisal
~~~

Accept a risk for a limited time:

~~~bash
python exposure.py accept-risk 12 --until 2026-12-31 --reason "Upgrade is scheduled"
~~~

Export a report:

~~~bash
python exposure.py report --format markdown --output report.md
~~~

By default the database is stored at `~/.exposure-management/exposure.db`. Use `--db` if you want another location.

A finding is not automatically considered fixed after one clean scan. By default it must be absent from two complete scans from the same source and scope before it is marked resolved.
