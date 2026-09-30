import argparse
import errno
import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139,
    143, 443, 445, 3306, 3389, 5432, 5000, 8080
]
DISCOVERY_PORTS = [22, 53, 80, 135, 139, 443, 445, 3389, 5000, 8080]
MAX_PORTS_SINGLE = 2000
MAX_PORTS_SUBNET = 200
MAX_HOSTS = 1024
MAX_TOTAL_PORT_CHECKS = 75000
DEFAULT_WORKERS = 128

RESPONDED_CODES = {
    0,
    errno.ECONNREFUSED,
    getattr(errno, "ECONNRESET", 104),
    10054,  # Windows: connection reset
    10061,  # Windows: connection refused
}


def parse_ports(value, *, limit=MAX_PORTS_SINGLE):
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

            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    if not ports:
        raise ValueError("Choose at least one port.")

    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError("Ports must be between 1 and 65535.")

    if len(ports) > limit:
        raise ValueError(f"Please scan {limit} ports or fewer at a time.")

    return sorted(ports)


def parse_target(value):
    value = value.strip()

    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as error:
            raise ValueError(f"Invalid subnet: {value}") from error

        if network.version != 4:
            raise ValueError("Only IPv4 subnets are supported right now.")

        hosts = [str(host) for host in network.hosts()]
        if len(hosts) > MAX_HOSTS:
            raise ValueError(
                f"Subnet is too large. Use {MAX_HOSTS} hosts or fewer per scan."
            )

        return {
            "mode": "subnet",
            "target": value,
            "network": str(network),
            "hosts": hosts,
        }

    try:
        ip = socket.gethostbyname(value)
    except socket.gaierror as error:
        raise ValueError(f"Could not resolve host: {value}") from error

    return {
        "mode": "host",
        "target": value,
        "network": None,
        "hosts": [ip],
    }


def validate_source_ip(source_ip):
    if not source_ip:
        return None

    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError as error:
        raise ValueError(f"Invalid source IP: {source_ip}") from error

    if address.version != 4:
        raise ValueError("Only IPv4 source addresses are supported right now.")

    return str(address)


def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def connect_result(ip, port, timeout, source_ip=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        if source_ip:
            sock.bind((source_ip, 0))
        code = sock.connect_ex((ip, port))
        return {
            "ip": ip,
            "port": port,
            "open": code == 0,
            "responded": code in RESPONDED_CODES,
            "code": code,
        }
    except OSError as error:
        return {
            "ip": ip,
            "port": port,
            "open": False,
            "responded": False,
            "code": getattr(error, "errno", None),
        }
    finally:
        sock.close()


def run_checks(hosts, ports, timeout, workers, source_ip=None):
    results = []
    total = len(hosts) * len(ports)

    if total > MAX_TOTAL_PORT_CHECKS:
        raise ValueError(
            f"This would make {total:,} TCP checks. Reduce the subnet or port list "
            f"to stay under {MAX_TOTAL_PORT_CHECKS:,} checks."
        )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(connect_result, ip, port, timeout, source_ip)
            for ip in hosts
            for port in ports
        ]

        for future in as_completed(futures):
            results.append(future.result())

    return results


def discovery_port_list(selected_ports):
    ports = list(DISCOVERY_PORTS)

    if len(selected_ports) <= 32:
        ports.extend(selected_ports)
    else:
        ports.extend(selected_ports[:16])

    return sorted(set(ports))


def discover_hosts(hosts, selected_ports, timeout, workers, source_ip=None):
    probes = run_checks(
        hosts,
        discovery_port_list(selected_ports),
        timeout,
        workers,
        source_ip,
    )

    up = set()
    discovery_open = {}

    for item in probes:
        if item["responded"]:
            up.add(item["ip"])
        if item["open"]:
            discovery_open.setdefault(item["ip"], set()).add(item["port"])

    return up, discovery_open


def scan_hosts(hosts, ports, timeout, workers, source_ip=None):
    checks = run_checks(hosts, ports, timeout, workers, source_ip)
    grouped = {ip: [] for ip in hosts}

    for item in checks:
        if item["open"]:
            grouped[item["ip"]].append(
                {
                    "port": item["port"],
                    "service": get_service_name(item["port"]),
                }
            )

    for open_ports in grouped.values():
        open_ports.sort(key=lambda item: item["port"])

    return grouped


def reverse_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def resolve_hostnames(hosts, workers=32):
    names = {}

    with ThreadPoolExecutor(max_workers=min(workers, 32)) as executor:
        future_map = {
            executor.submit(reverse_lookup, ip): ip
            for ip in hosts
        }

        for future in as_completed(future_map):
            ip = future_map[future]
            name = future.result()
            if name:
                names[ip] = name

    return names


def build_host_rows(all_hosts, up_hosts, port_results, discovery_open, hostnames=None):
    rows = []
    hostnames = hostnames or {}

    for ip in all_hosts:
        open_ports = port_results.get(ip, [])
        discovery_ports = sorted(discovery_open.get(ip, set()))

        rows.append(
            {
                "ip": ip,
                "hostname": hostnames.get(ip),
                "status": "up" if ip in up_hosts else "down",
                "open_ports": open_ports,
                "discovery_open_ports": discovery_ports,
            }
        )

    return rows


def scan_target(
    target,
    ports,
    *,
    timeout=0.25,
    workers=DEFAULT_WORKERS,
    source_ip=None,
    sweep_only=False,
    resolve_names=False,
):
    parsed = parse_target(target)
    source_ip = validate_source_ip(source_ip)

    if timeout <= 0 or timeout > 10:
        raise ValueError("Timeout must be greater than 0 and at most 10 seconds.")

    if workers < 1 or workers > 256:
        raise ValueError("Workers must be between 1 and 256.")

    port_limit = MAX_PORTS_SUBNET if parsed["mode"] == "subnet" else MAX_PORTS_SINGLE
    selected_ports = parse_ports(ports, limit=port_limit)

    started = time.time()

    up_hosts, discovery_open = discover_hosts(
        parsed["hosts"],
        selected_ports,
        timeout,
        workers,
        source_ip,
    )

    if parsed["mode"] == "host":
        # A single host should still get the requested port scan even if discovery
        # probes were filtered.
        scan_list = parsed["hosts"]
    elif sweep_only:
        scan_list = []
    else:
        scan_list = sorted(up_hosts, key=ipaddress.ip_address)

    port_results = {}
    if scan_list:
        port_results = scan_hosts(
            scan_list,
            selected_ports,
            timeout,
            workers,
            source_ip,
        )

        # An open selected port is also proof the host is reachable.
        up_hosts.update(ip for ip, items in port_results.items() if items)

    hostnames = resolve_hostnames(up_hosts) if resolve_names and up_hosts else {}

    rows = build_host_rows(
        parsed["hosts"],
        up_hosts,
        port_results,
        discovery_open,
        hostnames,
    )

    elapsed = round(time.time() - started, 2)
    up_count = sum(row["status"] == "up" for row in rows)

    result = {
        "mode": parsed["mode"],
        "target": parsed["target"],
        "network": parsed["network"],
        "source_ip": source_ip or "automatic",
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "timeout_seconds": timeout,
        "workers": workers,
        "sweep_only": sweep_only,
        "resolve_names": resolve_names,
        "ports_scanned": 0 if sweep_only else len(selected_ports),
        "selected_ports": selected_ports,
        "hosts_total": len(rows),
        "hosts_up": up_count,
        "hosts_down": len(rows) - up_count,
        "hosts": rows,
        "elapsed_seconds": elapsed,
    }

    if parsed["mode"] == "host":
        row = rows[0]
        result.update(
            {
                "ip": row["ip"],
                "host_up": row["status"] == "up",
                "open_ports": row["open_ports"],
            }
        )

    return result


def save_json(path, result):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=2)


def print_result(result):
    if result["mode"] == "host":
        status = "UP" if result["host_up"] else "NO RESPONSE"
        print(f"\nTarget: {result['target']} ({result['ip']})")
        print(f"Status: {status}")
        print(f"Source IP: {result['source_ip']}")

        if result["open_ports"]:
            print("\nOpen ports:")
            for item in result["open_ports"]:
                print(f"[OPEN] {item['port']:<5} {item['service']}")
        else:
            print("\nNo open ports found in the selected list.")
    else:
        print(f"\nSubnet: {result['network']}")
        print(
            f"Hosts up: {result['hosts_up']} / {result['hosts_total']} "
            f"(source: {result['source_ip']})"
        )

        for host in result["hosts"]:
            if host["status"] != "up":
                continue

            services = ", ".join(
                f"{item['port']}/{item['service']}"
                for item in host["open_ports"]
            )
            if not services and host["discovery_open_ports"]:
                services = ", ".join(
                    f"{port}/{get_service_name(port)}"
                    for port in host["discovery_open_ports"]
                )

            label = host["ip"]
            if host.get("hostname"):
                label += f" ({host['hostname']})"
            print(f"[UP] {label:<35} {services or 'no selected open ports'}")

    print(f"\nFinished in {result['elapsed_seconds']} seconds.")


def main():
    parser = argparse.ArgumentParser(
        description="Fast TCP host and subnet scanner for authorized networks."
    )
    parser.add_argument(
        "target",
        help="Hostname, IPv4 address, or CIDR subnet such as 192.168.1.0/24",
    )
    parser.add_argument(
        "--ports",
        default=",".join(str(port) for port in DEFAULT_PORTS),
        help='Ports to scan, for example "22,80,443" or "1-100"',
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.25,
        help="TCP timeout in seconds (default: 0.25)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Concurrent TCP workers, 1-256 (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "--source-ip",
        help="Bind scans to a local IPv4 address/interface",
    )
    parser.add_argument(
        "--sweep-only",
        action="store_true",
        help="Discover responsive hosts without the full selected-port scan",
    )
    parser.add_argument(
        "--resolve-names",
        action="store_true",
        help="Try reverse-DNS lookups for responsive hosts",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        help="Optional path to save the result as JSON",
    )
    args = parser.parse_args()

    try:
        result = scan_target(
            args.target,
            args.ports,
            timeout=args.timeout,
            workers=args.workers,
            source_ip=args.source_ip,
            sweep_only=args.sweep_only,
            resolve_names=args.resolve_names,
        )
    except ValueError as error:
        parser.error(str(error))

    print_result(result)

    if args.json_path:
        save_json(args.json_path, result)
        print(f"Saved JSON result to: {args.json_path}")


if __name__ == "__main__":
    main()
