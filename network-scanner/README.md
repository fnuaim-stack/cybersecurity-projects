# Network Scanner

I made this as a small Python project to practice sockets and basic port scanning.

It scans one host at a time and tells you which TCP ports are open. I kept it simple on purpose so the code is easy to read and change later.

## What it does

- scans common TCP ports
- lets you choose your own ports
- shows the service name when Python knows it
- can save the results to a JSON file
- accepts an IP address or hostname

It only uses Python's built-in libraries, so there is nothing extra to install.

## Run it

```bash
python scanner.py 192.168.1.1
```

Scan specific ports:

```bash
python scanner.py 192.168.1.1 --ports 22,80,443
```

Scan a small range:

```bash
python scanner.py 192.168.1.1 --ports 1-100
```

Save the result:

```bash
python scanner.py 192.168.1.1 --ports 1-100 --json result.json
```

You can also scan a hostname:

```bash
python scanner.py example.com --ports 80,443
```

## Example output

```text
Target: 192.168.1.1 (192.168.1.1)
Scanning 3 TCP ports...

[OPEN] 80    http
[OPEN] 443   https

Finished in 0.42 seconds.
```

## Notes

This is a basic TCP connect scanner, not something meant to replace Nmap.

Use it on your own devices, lab machines, or systems you have permission to test.
