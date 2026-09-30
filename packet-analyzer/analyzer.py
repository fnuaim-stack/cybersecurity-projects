import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from scapy.all import DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, rdpcap, sniff, wrpcap


def packet_info(packet):
    protocol = "OTHER"
    src = "-"
    dst = "-"
    sport = None
    dport = None

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
    elif IPv6 in packet:
        src = packet[IPv6].src
        dst = packet[IPv6].dst

    if TCP in packet:
        protocol = "TCP"
        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)
    elif UDP in packet:
        protocol = "UDP"
        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)
    elif ICMP in packet:
        protocol = "ICMP"
    elif IP in packet:
        protocol = "IP"
    elif IPv6 in packet:
        protocol = "IPv6"

    dns_query = None
    if DNS in packet and packet[DNS].qr == 0 and DNSQR in packet:
        qname = packet[DNSQR].qname
        if isinstance(qname, bytes):
            qname = qname.decode("utf-8", errors="replace")
        dns_query = str(qname).rstrip(".")

    return {
        "protocol": protocol,
        "source": src,
        "destination": dst,
        "source_port": sport,
        "destination_port": dport,
        "length": len(packet),
        "dns_query": dns_query,
    }


def summarize_packets(packets, top=10):
    protocol_counts = Counter()
    talkers = Counter()
    conversations = Counter()
    tcp_ports = Counter()
    udp_ports = Counter()
    dns_queries = Counter()
    rows = []

    for number, packet in enumerate(packets, start=1):
        info = packet_info(packet)
        protocol_counts[info["protocol"]] += 1

        if info["source"] != "-":
            talkers[info["source"]] += 1

        if info["source"] != "-" and info["destination"] != "-":
            conversations[(info["source"], info["destination"])] += 1

        if info["protocol"] == "TCP" and info["destination_port"] is not None:
            tcp_ports[info["destination_port"]] += 1
        elif info["protocol"] == "UDP" and info["destination_port"] is not None:
            udp_ports[info["destination_port"]] += 1

        if info["dns_query"]:
            dns_queries[info["dns_query"]] += 1

        rows.append({"number": number, **info})

    return {
        "analyzed_at": datetime.now().isoformat(timespec="seconds"),
        "packet_count": len(rows),
        "protocol_counts": dict(protocol_counts.most_common()),
        "top_talkers": [
            {"ip": ip, "packets": count}
            for ip, count in talkers.most_common(top)
        ],
        "top_conversations": [
            {"source": src, "destination": dst, "packets": count}
            for (src, dst), count in conversations.most_common(top)
        ],
        "top_tcp_destination_ports": [
            {"port": port, "packets": count}
            for port, count in tcp_ports.most_common(top)
        ],
        "top_udp_destination_ports": [
            {"port": port, "packets": count}
            for port, count in udp_ports.most_common(top)
        ],
        "dns_queries": [
            {"query": query, "count": count}
            for query, count in dns_queries.most_common(top)
        ],
        "packets": rows,
    }


def capture_packets(interface, count, timeout, capture_filter):
    kwargs = {
        "iface": interface or None,
        "count": count if not timeout else 0,
        "timeout": timeout,
        "store": True,
    }

    if capture_filter:
        kwargs["filter"] = capture_filter

    return sniff(**kwargs)


def load_pcap(path):
    pcap_path = Path(path)
    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
    return rdpcap(str(pcap_path))


def main():
    parser = argparse.ArgumentParser(
        description="Packet capture and offline PCAP summary tool."
    )
    parser.add_argument("--interface", help="Network interface to capture from")
    parser.add_argument("--count", type=int, default=20, help="Number of packets to capture")
    parser.add_argument("--timeout", type=int, help="Stop live capture after this many seconds")
    parser.add_argument("--filter", dest="capture_filter", help="Optional BPF capture filter")
    parser.add_argument("--pcap", help="Analyze an existing PCAP instead of live capture")
    parser.add_argument("--save", help="Optional .pcap file to save a live capture")
    parser.add_argument("--top", type=int, default=10, help="Top summary rows to keep")
    parser.add_argument("--json", dest="json_path", help="Save the summary as JSON")
    args = parser.parse_args()

    if args.count < 1 or args.count > 5000:
        parser.error("--count must be between 1 and 5000")
    if args.timeout is not None and (args.timeout < 1 or args.timeout > 300):
        parser.error("--timeout must be between 1 and 300 seconds")
    if args.top < 1 or args.top > 100:
        parser.error("--top must be between 1 and 100")
    if args.pcap and args.save:
        parser.error("--save only applies to live captures")

    try:
        if args.pcap:
            print(f"Loading PCAP: {args.pcap}")
            packets = load_pcap(args.pcap)
            source = {"mode": "pcap", "path": str(Path(args.pcap))}
        else:
            print("Starting capture...")
            packets = capture_packets(
                args.interface,
                args.count,
                args.timeout,
                args.capture_filter,
            )
            source = {
                "mode": "live",
                "interface": args.interface or "default",
                "filter": args.capture_filter or "",
            }
    except (OSError, FileNotFoundError) as error:
        parser.error(str(error))

    result = summarize_packets(packets, args.top)
    result["source"] = source

    print("\nPackets:")
    for item in result["packets"][:50]:
        ports = ""
        if item["source_port"] is not None or item["destination_port"] is not None:
            ports = f" {item['source_port']} -> {item['destination_port']}"
        print(
            f"{item['number']:>4}. {item['protocol']:<6} "
            f"{item['source']} -> {item['destination']}{ports}"
        )

    if len(result["packets"]) > 50:
        print(f"... {len(result['packets']) - 50} more packet rows")

    print("\nProtocol summary:")
    for protocol, total in result["protocol_counts"].items():
        print(f"{protocol:<8} {total}")

    if result["top_talkers"]:
        print("\nTop talkers:")
        for item in result["top_talkers"]:
            print(f"{item['ip']:<39} {item['packets']}")

    if result["dns_queries"]:
        print("\nDNS queries:")
        for item in result["dns_queries"]:
            print(f"{item['query']:<50} {item['count']}")

    if args.save and not args.pcap:
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
