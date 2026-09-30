# Network Scanner

This is a fast TCP scanner for my own lab and local-network practice.

It handles one host or a small IPv4 subnet, and the Workbench uses the same scanner underneath.

## What it does

- single host or CIDR subnet
- fast TCP host sweep
- open-port checks
- common service names
- optional reverse-DNS hostnames
- source-IP/interface binding
- concurrent workers
- JSON output
- sweep-only mode

## Examples

Single host:

```bash
python scanner.py 192.168.0.181 --ports 1-1000
```

Subnet:

```bash
python scanner.py 192.168.0.0/24 --ports 22,80,443,445,3389,5000
```

Fast host sweep:

```bash
python scanner.py 192.168.0.0/24 --sweep-only
```

Try reverse-DNS names:

```bash
python scanner.py 192.168.0.0/24 --sweep-only --resolve-names
```

Force a local interface by its IPv4 address:

```bash
python scanner.py 192.168.0.0/24 --source-ip 192.168.0.181
```

## Speed

Default:

- timeout: 0.25 seconds
- workers: 128
- max workers: 256

A bigger worker number is not always faster, especially over Wi-Fi.

## Host status

**UP** means the target replied to one of the TCP probes.

A real device can still show **NO RESPONSE** if a firewall silently drops all of those probes.

This is a learning scanner, not a replacement for Nmap. Use it only on networks and systems you are allowed to test.
