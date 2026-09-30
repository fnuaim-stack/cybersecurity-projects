# Packet Analyzer

A Scapy-based traffic analyzer for live captures and saved PCAP files.

## Setup

```bash
pip install -r requirements.txt
```

On Windows, live capture may need Administrator privileges and Npcap.

## Live capture

```bash
python analyzer.py --count 50
```

Capture for 10 seconds:

```bash
python analyzer.py --timeout 10
```

Use a BPF filter:

```bash
python analyzer.py --timeout 10 --filter "tcp port 443"
```

Save the live capture:

```bash
python analyzer.py --timeout 10 --save capture.pcap
```

## Offline PCAP analysis

```bash
python analyzer.py --pcap capture.pcap
```

## Summary data

It reports:

- protocol counts
- packet source/destination
- TCP/UDP ports
- packet lengths
- top talkers
- top conversations
- common destination ports
- DNS query names

The Workbench can also upload a PCAP and show the same summary in the browser.
