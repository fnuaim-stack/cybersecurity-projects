# HTTP Security Checker

A small passive web checker. It sends a normal request and inspects the response instead of trying to exploit anything.

## What it checks

- common browser security headers
- final URL and redirect chain
- basic response metadata
- cookie flags: Secure, HttpOnly, SameSite
- HTTPS certificate issuer/subject
- TLS version and cipher
- certificate expiry

## Run it

```bash
python check_headers.py https://example.com
```

Save JSON:

```bash
python check_headers.py https://example.com --json result.json
```

Missing headers or cookie flags are review items, not automatic proof that a site is vulnerable. Context still matters.

The Workbench can run this checker and save review items into the shared findings database.
