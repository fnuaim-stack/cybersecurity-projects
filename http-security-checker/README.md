# HTTP Security Header Checker

A small passive web-security checker.

It sends a normal request to a website and checks whether a few common security headers are there. It does not try to exploit anything or send attack payloads.

## Run it

```bash
python check_headers.py example.com
```

Or use a full URL:

```bash
python check_headers.py https://example.com
```

Save the result:

```bash
python check_headers.py https://example.com --json result.json
```

## What it checks

- Strict-Transport-Security
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy

Missing a header does not automatically mean a site is vulnerable. This is just a quick checklist and a way to practice working with HTTP responses in Python.
