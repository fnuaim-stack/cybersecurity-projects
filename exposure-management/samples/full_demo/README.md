# Full demo

This is a safe local test for the Exposure Management app.

It starts:
- a local web target on `127.0.0.1:8088`
- a local TCP service on `127.0.0.1:9099`
- a fresh demo database with sample findings, tags, notes, threat intel, a suppression rule, a campaign, and a saved scan profile

On Windows:

~~~powershell
cd exposure-management
py -m pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File samples\full_demo\run_demo.ps1
~~~

The app opens normally. Check:

- Dashboard for scan changes
- Findings for risk and threat-intel context
- Triage for the suppression rule
- Assets for owners and tags
- Campaigns for the demo remediation campaign
- Automation for the saved profile and paused schedule
- Scan for the local built-in scanner

Everything in this demo is local and synthetic. No external target is scanned.
