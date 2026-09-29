import argparse
import json
import socket
import time
from datetime import datetime

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139,
    143, 443, 445, 3306, 3389, 5432, 8080
]


def parse_ports(value):
    ports = set()

    for part in value.split(","):
        part = part.strip()

        if not part:
            continue

        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = int(start_text)
            end = int(end_text)

            if start > end:
                start, end = end, start

            for port in range(start, end + 1):
                ports.add(port)
        else:
            ports.add(int(part))

    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError("Ports must be between 1 and 65535.")

    if len(ports) > 2000:
        raise ValueError("Please scan 2000 ports or fewer at a time.")

    return sorted(ports)


def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    finally:
        sock.close()


def save_json(path, result):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Simple TCP port scanner for a single host."
    )
    parser.add_argument("host", help="IP address or hostname to scan")
    parser.add_argument(
        "--ports",
        default=",".join(str(port) for port in DEFAULT_PORTS),
        help='Ports to scan, for example "22,80,443" or "1-100"',
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.4,
        help="Timeout for each connection in seconds (default: 0.4)",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        help="Optional path to save the result as JSON",
    )
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    try:
        ports = parse_ports(args.ports)
    except ValueError as error:
        parser.error(str(error))

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        parser.error(f"Could not resolve host: {args.host}")

    print(f"\nTarget: {args.host} ({ip})")
    print(f"Scanning {len(ports)} TCP ports...\n")

    started = time.time()
    open_ports = []

    for port in ports:
        if scan_port(ip, port, args.timeout):
            service = get_service_name(port)
            open_ports.append({"port": port, "service": service})
            print(f"[OPEN] {port:<5} {service}")

    elapsed = round(time.time() - started, 2)

    if not open_ports:
        print("No open ports found in the selected list.")

    print(f"\nFinished in {elapsed} seconds.")

    result = {
        "target": args.host,
        "ip": ip,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "elapsed_seconds": elapsed,
    }

    if args.json_path:
        save_json(args.json_path, result)
        print(f"Saved JSON result to: {args.json_path}")


if __name__ == "__main__":
    main()
