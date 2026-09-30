# Nmap Result Explorer

This project reads **saved Nmap XML** and turns it into cleaner JSON or Markdown.

It does not run Nmap or scan a target. I wanted something I could use after a lab scan to quickly see hosts, ports, services, OS guesses, and script output without digging through XML.

## Make an XML result with Nmap

On a system you are allowed to test:

```bash
nmap -sV -oX scan.xml 192.168.56.10
```

Then parse it:

```bash
python nmap_explorer.py scan.xml
```

## JSON

```bash
python nmap_explorer.py scan.xml --json parsed.json
```

## Markdown summary

```bash
python nmap_explorer.py scan.xml --markdown notes.md
```

## What it extracts

- host status
- IPv4 / IPv6 / MAC addresses
- hostnames
- TCP/UDP ports
- state and reason
- service name
- product/version/extrainfo
- Nmap script output
- OS guesses
- service counts

This is mainly a result-parsing/reporting helper for authorized assessments and labs.
