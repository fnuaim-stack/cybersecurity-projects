# Exposure Management

A local vulnerability and exposure management app.

It can run scans, import results from other tools, prioritize findings, track remediation, verify fixes across rescans, and keep asset context in one place.

## Run on Windows

~~~powershell
cd exposure-management
py -m pip install -r requirements.txt
py webapp.py
~~~

Open:

~~~text
http://127.0.0.1:5055
~~~

## Main features

- Built-in network and web scans
- Optional Nmap, Nuclei, and Trivy scans
- Nuclei, Trivy, Nmap, Nessus, OpenVAS, ZAP, Semgrep and SARIF imports
- Asset owners, criticality, aliases and tags
- Risk prioritization with CVSS, exposure, CISA KEV and EPSS
- Finding search, notes, risk acceptance and suppression rules
- Remediation campaigns and SLA tracking
- Scan profiles and recurring schedules
- Scan-to-scan new, reopened and resolved counts
- Analytics, CSV/JSON/Markdown reports
- Jira, Slack and webhook support from the CLI
- Local REST API for automation

The app stays on `127.0.0.1` by default.

## Full demo

For a safe test of most features:

~~~powershell
powershell -ExecutionPolicy Bypass -File samples\full_demo\run_demo.ps1
~~~

This creates only local demo targets and synthetic findings. See `samples/full_demo/README.md`.

## CLI

~~~powershell
py exposure.py summary
py exposure.py queue
~~~

By default the database is stored at `~/.exposure-management/exposure.db`.

Use `--partial` for incomplete scan imports so missing findings are not treated as proof that a vulnerability was fixed.
