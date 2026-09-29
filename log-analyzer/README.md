# Log Analyzer

A simple Python script for checking text logs and finding repeated failed logins.

I made it mostly to practice parsing logs, regex, counters, and basic security detection.

## What it checks

- IP addresses seen in the log
- lines that look like failed logins
- how many failed attempts came from each IP
- IPs that pass a threshold you choose

There is a small `sample.log` file in the folder so it can be tested right away.

## Run it

```bash
python analyzer.py sample.log
```

Change the failed-login threshold:

```bash
python analyzer.py sample.log --threshold 3
```

Save the report as JSON:

```bash
python analyzer.py sample.log --json report.json
```

It is intentionally basic. Real logs come in a lot of different formats, so I can add support for more formats later.
