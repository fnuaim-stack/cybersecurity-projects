# Network Scanner

This started as a tiny TCP scanner and now it can do both single-host scans and fast local subnet sweeps.

It still only uses Python's built-in libraries.

## What it does

- scans one host or an IPv4 CIDR subnet
- shows whether a host replied to TCP discovery probes
- finds open TCP ports
- shows the normal service name for open ports when Python knows it
- uses concurrent workers so LAN scans are much faster
- can bind to a local source IP so I can choose which network interface is used
- supports a fast sweep-only mode
- saves JSON for the Pentest Workbench

## Single host

```bash
python scanner.py 192.168.0.181 --ports 1-1000
```

You can also test localhost:

```bash
python scanner.py 127.0.0.1 --ports 5000
```

## Scan a subnet

For a normal /24 home or lab network:

```bash
python scanner.py 192.168.0.0/24 --ports 22,80,443,445,3389,5000,8080
```

That first does a quick host sweep and then scans the selected ports on hosts that replied.

## Fast sweep only

If I only want to see which hosts reply:

```bash
python scanner.py 192.168.0.0/24 --sweep-only
```

## Choose a network interface

The scanner selects the interface automatically through the operating system routing table.

To force a specific local interface, bind to that interface's IPv4 address:

```bash
python scanner.py 192.168.0.0/24 --source-ip 192.168.0.181
```

This is the same source-IP selector shown in the Pentest Workbench UI.

## Speed

Default concurrency is 128 workers:

```bash
python scanner.py 192.168.0.0/24 --workers 128
```

The maximum is 256. More workers are not always faster, especially over Wi-Fi.

The default timeout is 0.25 seconds because this project is mainly aimed at local networks. If a lab network is slow, increase it.

## Host status note

**UP** means the host replied to at least one TCP discovery probe.

A real device can still appear as **NO RESPONSE** if its firewall silently drops all of the discovery probes. This scanner does not pretend that TCP discovery is perfect host detection.

## Limits

To keep accidental scans under control:

- single host: up to 2000 selected ports
- subnet scan: up to 200 selected ports
- subnet size: up to 1024 hosts
- total TCP checks are capped

This is still a learning scanner, not a replacement for Nmap.

Use it only on devices, labs, and networks you own or have permission to test.
