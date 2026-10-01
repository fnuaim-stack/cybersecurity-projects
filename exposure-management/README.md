# Exposure Management

This project turns scanner results into one remediation workflow.

It keeps an asset inventory, removes duplicate findings, adds asset context to risk, tracks owners and due dates, verifies fixes across rescans, and shows which work should be handled first.

## Supported imports

- Nuclei
- Trivy
- Nmap
- Nessus
- OpenVAS
- OWASP ZAP
- Semgrep
- SARIF
- Generic JSON, JSONL, or CSV

## Run the UI

On Windows:

~~~powershell
cd exposure-management
py -m pip install -r requirements.txt
py webapp.py
~~~

The browser opens at `http://127.0.0.1:5055`.

For a quick test, import `samples/demo_findings.json` from the **Import scans** page and choose `generic`.

## CLI

~~~bash
python exposure.py import scan.jsonl --format nuclei --scope prod
python exposure.py summary
python exposure.py queue
~~~

Add asset context:

~~~bash
python exposure.py asset-set app.example.com --criticality 5 --internet-exposed yes --owner security
python exposure.py asset-alias app.example.com 192.0.2.10
~~~

Bulk asset context can also be imported from CSV with `asset-import`.

See MTTR, SLA, aging, recurrence, and top-risk assets:

~~~bash
python exposure.py analytics
~~~

Enrich CVE findings with local CISA KEV and EPSS files:

~~~bash
python exposure.py intel-enrich --kev kev.json --epss epss.csv
~~~

Create a remediation campaign:

~~~bash
python exposure.py campaign-create "Critical fixes" --min-risk 90 --owner security
python exposure.py campaigns
~~~

Export the queue:

~~~bash
python exposure.py report --format markdown --output report.md
~~~

Optional Jira, Slack, and generic webhook commands are available for sending findings to other systems. Secrets are read from environment variables.

By default the database is stored at `~/.exposure-management/exposure.db`.

A finding is not considered fixed after one clean scan. By default it must be absent from two complete scans from the same source and scope before it is verified resolved. Use `--partial` when importing incomplete scan results so missing findings are not counted as fixed.
