# Log Analyzer

A small defensive parser for authentication and basic web log activity.

## What it looks for

- IPv4 and IPv6 addresses
- failed logins
- successful logins
- privilege-related activity
- usernames
- HTTP 4xx/5xx statuses
- repeated failed-login IPs
- top IP and user activity

## Run it

```bash
python analyzer.py sample.log
```

Change the threshold:

```bash
python analyzer.py sample.log --threshold 3
```

Keep more top rows:

```bash
python analyzer.py sample.log --top 25
```

Save JSON:

```bash
python analyzer.py sample.log --json report.json
```

The parser is intentionally generic. It catches useful patterns without pretending every log format is identical.
