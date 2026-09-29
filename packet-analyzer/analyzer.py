import argparse
from collections import Counter
from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP


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


def main():
    parser = argparse.ArgumentParser(description="Small packet capture and summary tool.")
    parser.add_argument("--interface", help="Network interface to capture from")
    parser.add_argument("--count", type=int, default=20, help="Number of packets to capture")
    parser.add_argument("--timeout", type=int, help="Stop after this many seconds")
    parser.add_argument("--save", help="Optional .pcap file to save the capture")
    args = parser.parse_args()

    print("Starting capture...")
    packets = sniff(
        iface=args.interface,
        count=args.count if not args.timeout else 0,
        timeout=args.timeout,
        store=True,
    )

    counts = Counter()

    print("\nPackets:")
    for number, packet in enumerate(packets, start=1):
        protocol, src, dst = packet_info(packet)
        counts[protocol] += 1
        print(f"{number:>3}. {protocol:<6} {src} -> {dst}")

    print("\nSummary:")
    for protocol, total in counts.most_common():
        print(f"{protocol:<6} {total}")

    if args.save:
        wrpcap(args.save, packets)
        print(f"\nSaved capture to {args.save}")


if __name__ == "__main__":
    main()
