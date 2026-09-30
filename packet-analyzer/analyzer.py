import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from scapy.all import ICMP, IP, IPv6, TCP, UDP, sniff, wrpcap


def packet_info(packet):
    protocol = "OTHER"
    src = "-"
    dst = "-"

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
    elif IPv6 in packet:
        src = packet[IPv6].src
        dst = packet[IPv6].dst

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"
    elif IP in packet:
        protocol = "IP"
    elif IPv6 in packet:
        protocol = "IPv6"

    return protocol, src, dst


def summarize_packets(packets):
    counts = Counter()
    rows = []

    for number, packet in enumerate(packets, start=1):
        protocol, src, dst = packet_info(packet)
        counts[protocol] += 1
        rows.append(
            {
                "number": number,
                "protocol": protocol,
                "source": src,
                "destination": dst,
            }
        )

    return {
        "captured_at": datetime.now().isoformat(timespec="seconds"),
        "packet_count": len(rows),
        "protocol_counts": dict(counts),
        "packets": rows,
    }


def main():
    parser = argparse.ArgumentParser(description="Small packet capture and summary tool.")
    parser.add_argument("--interface", help="Network interface to capture from")
    parser.add_argument("--count", type=int, default=20, help="Number of packets to capture")
    parser.add_argument("--timeout", type=int, help="Stop after this many seconds")
    parser.add_argument("--save", help="Optional .pcap file to save the capture")
    parser.add_argument("--json", dest="json_path", help="Save the summary as JSON")
    args = parser.parse_args()

    if args.count < 1 or args.count > 500:
        parser.error("--count must be between 1 and 500")
    if args.timeout is not None and (args.timeout < 1 or args.timeout > 60):
        parser.error("--timeout must be between 1 and 60 seconds")

    print("Starting capture...")
    packets = sniff(
        iface=args.interface,
        count=args.count if not args.timeout else 0,
        timeout=args.timeout,
        store=True,
    )

    result = summarize_packets(packets)

    print("\nPackets:")
    for item in result["packets"]:
        print(
            f"{item['number']:>3}. {item['protocol']:<6} "
            f"{item['source']} -> {item['destination']}"
        )

    print("\nSummary:")
    for protocol, total in sorted(
        result["protocol_counts"].items(),
        key=lambda item: item[1],
        reverse=True,
    ):
        print(f"{protocol:<6} {total}")

    if args.save:
        wrpcap(args.save, packets)
        print(f"\nSaved capture to {args.save}")

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(result, indent=2),
            encoding="utf-8",
        )
        print(f"Saved JSON result to: {args.json_path}")


if __name__ == "__main__":
    main()
