# Packet Analyzer

This one is a small Scapy project I made to practice looking at live network traffic.

It captures packets, shows the source and destination, guesses the main protocol, and gives a small summary at the end.

## Setup

```bash
pip install -r requirements.txt
```

On Windows, run the terminal as Administrator if Scapy cannot capture packets.

## Run it

Capture 20 packets:

```bash
python analyzer.py --count 20
```

Capture for 10 seconds:

```bash
python analyzer.py --timeout 10
```

Save the capture too:

```bash
python analyzer.py --timeout 10 --save capture.pcap
```

You can also choose an interface:

```bash
python analyzer.py --interface "Wi-Fi" --count 30
```

This is mainly for learning and checking traffic on networks you are allowed to monitor.
