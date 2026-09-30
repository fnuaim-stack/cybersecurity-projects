import argparse
import json
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path


def attr(element, name, default=""):
    return element.attrib.get(name, default) if element is not None else default


def parse_script_elements(parent):
    scripts = []

    if parent is None:
        return scripts

    for script in parent.findall("script"):
        scripts.append(
            {
                "id": attr(script, "id"),
                "output": attr(script, "output"),
            }
        )

    return scripts


def parse_host(host):
    status = host.find("status")
    addresses = {
        item.attrib.get("addrtype", "unknown"): item.attrib.get("addr", "")
        for item in host.findall("address")
    }

    hostnames = [
        item.attrib.get("name", "")
        for item in host.findall("./hostnames/hostname")
        if item.attrib.get("name")
    ]

    ports = []
    for port in host.findall("./ports/port"):
        state = port.find("state")
        service = port.find("service")

        ports.append(
            {
                "protocol": attr(port, "protocol"),
                "port": int(attr(port, "portid", "0")),
                "state": attr(state, "state"),
                "reason": attr(state, "reason"),
                "service": {
                    "name": attr(service, "name"),
                    "product": attr(service, "product"),
                    "version": attr(service, "version"),
                    "extra": attr(service, "extrainfo"),
                    "tunnel": attr(service, "tunnel"),
                },
                "scripts": parse_script_elements(port),
            }
        )

    os_matches = []
    for match in host.findall("./os/osmatch"):
        os_matches.append(
            {
                "name": attr(match, "name"),
                "accuracy": int(attr(match, "accuracy", "0") or 0),
            }
        )

    return {
        "status": attr(status, "state", "unknown"),
        "addresses": addresses,
        "hostnames": hostnames,
        "ports": ports,
        "host_scripts": parse_script_elements(host.find("hostscript")),
        "os_matches": sorted(os_matches, key=lambda item: item["accuracy"], reverse=True),
    }


def parse_nmap_xml(path):
    tree = ET.parse(path)
    root = tree.getroot()

    hosts = [parse_host(host) for host in root.findall("host")]

    up_hosts = [host for host in hosts if host["status"] == "up"]
    open_ports = [
        port
        for host in up_hosts
        for port in host["ports"]
        if port["state"] == "open"
    ]

    services = Counter(
        port["service"]["name"] or "unknown"
        for port in open_ports
    )

    return {
        "scanner": root.attrib.get("scanner", "nmap"),
        "args": root.attrib.get("args", ""),
        "version": root.attrib.get("version", ""),
        "summary": {
            "hosts_total": len(hosts),
            "hosts_up": len(up_hosts),
            "open_ports": len(open_ports),
            "services": dict(services.most_common()),
        },
        "hosts": hosts,
    }


def host_label(host):
    if host["hostnames"]:
        return f"{host['hostnames'][0]} ({host['addresses'].get('ipv4') or host['addresses'].get('ipv6') or '?'})"

    return (
        host["addresses"].get("ipv4")
        or host["addresses"].get("ipv6")
        or host["addresses"].get("mac")
        or "unknown"
    )


def build_markdown(result):
    lines = [
        "# Nmap Result Summary",
        "",
        f"- Hosts in file: {result['summary']['hosts_total']}",
        f"- Hosts up: {result['summary']['hosts_up']}",
        f"- Open ports: {result['summary']['open_ports']}",
        "",
    ]

    if result["summary"]["services"]:
        lines.extend(["## Services", ""])
        for service, count in result["summary"]["services"].items():
            lines.append(f"- {service}: {count}")
        lines.append("")

    lines.extend(["## Hosts", ""])

    for host in result["hosts"]:
        lines.append(f"### {host_label(host)}")
        lines.append("")
        lines.append(f"- Status: {host['status']}")

        if host["os_matches"]:
            best = host["os_matches"][0]
            lines.append(f"- OS guess: {best['name']} ({best['accuracy']}%)")

        open_ports = [port for port in host["ports"] if port["state"] == "open"]
        if open_ports:
            lines.extend(["", "| Port | Service | Product | Version |", "|---:|---|---|---|"])
            for port in open_ports:
                service = port["service"]
                lines.append(
                    f"| {port['port']}/{port['protocol']} | "
                    f"{service['name'] or '-'} | "
                    f"{service['product'] or '-'} | "
                    f"{service['version'] or '-'} |"
                )
        else:
            lines.extend(["", "No open ports in this result."])

        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Explore a saved Nmap XML file without running a scan."
    )
    parser.add_argument("xml_file", help="Nmap XML file")
    parser.add_argument("--json", dest="json_path", help="Save parsed data as JSON")
    parser.add_argument("--markdown", help="Save a Markdown summary")
    parser.add_argument(
        "--open-only",
        action="store_true",
        help="Console output only shows hosts with open ports",
    )
    args = parser.parse_args()

    try:
        result = parse_nmap_xml(args.xml_file)
    except (OSError, ET.ParseError, ValueError) as error:
        parser.error(str(error))

    print(
        f"Hosts: {result['summary']['hosts_up']} up / "
        f"{result['summary']['hosts_total']} total"
    )
    print(f"Open ports: {result['summary']['open_ports']}")

    for host in result["hosts"]:
        open_ports = [port for port in host["ports"] if port["state"] == "open"]
        if args.open_only and not open_ports:
            continue

        print(f"\n{host_label(host)} - {host['status']}")
        for port in open_ports:
            service = port["service"]
            detail = " ".join(
                item
                for item in (service["name"], service["product"], service["version"])
                if item
            )
            print(f"  {port['port']}/{port['protocol']} open  {detail or 'unknown'}")

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(result, indent=2),
            encoding="utf-8",
        )

    if args.markdown:
        Path(args.markdown).write_text(
            build_markdown(result),
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
