# Web Endpoint Inventory

This tool turns local web traffic exports into a clean endpoint list.

I can export a HAR file from a browser/devtools or use a text file of URLs, then get a deduplicated inventory of paths, methods, parameters, hosts, extensions, and response statuses.

It does **not** crawl or attack a website by itself.

## HAR file

```bash
python endpoint_inventory.py traffic.har
```

## URL list

```text
GET https://app.example.test/
GET https://app.example.test/login?next=/admin
POST https://app.example.test/api/session
```

Then:

```bash
python endpoint_inventory.py urls.txt
```

## Hide static assets

```bash
python endpoint_inventory.py traffic.har --no-static
```

## Export

```bash
python endpoint_inventory.py traffic.har \
  --json endpoints.json \
  --markdown endpoints.md
```

## What it tracks

- host
- method
- path
- query parameter names
- body parameter names from HAR
- response status codes
- file extensions
- static/non-static classification
- duplicate request count

This is useful after browsing an authorized lab app through Burp, ZAP, or browser devtools.
