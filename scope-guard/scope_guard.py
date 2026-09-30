import argparse
import ipaddress
import json
import socket
from pathlib import Path
from urllib.parse import urlparse


def load_scope(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        "networks": [ipaddress.ip_network(item, strict=False) for item in data.get("networks", [])],
        "hosts": {item.lower().rstrip(".") for item in data.get("hosts", [])},
        "domains": {item.lower().lstrip("*.").rstrip(".") for item in data.get("domains", [])},
        "exclude_networks": [
            ipaddress.ip_network(item, strict=False)
            for item in data.get("exclude_networks", [])
        ],
        "exclude_hosts": {item.lower().rstrip(".") for item in data.get("exclude_hosts", [])},
    }


def normalize_target(value):
    value = value.strip()

    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or value

    return value.strip("[]").rstrip(".")


def is_domain_match(hostname, domains):
    hostname = hostname.lower().rstrip(".")
    return any(
        hostname == domain or hostname.endswith("." + domain)
        for domain in domains
    )


def classify_target(target, scope):
    raw = target
    target = normalize_target(target)

    if not target:
        return {"target": raw, "normalized": target, "allowed": False, "reason": "empty target"}

    lowered = target.lower()

    if lowered in scope["exclude_hosts"]:
        return {
            "target": raw,
            "normalized": target,
            "allowed": False,
            "reason": "explicitly excluded host",
        }

    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        ip = None

    if ip:
        if any(ip in network for network in scope["exclude_networks"]):
            return {
                "target": raw,
                "normalized": str(ip),
                "allowed": False,
                "reason": "inside excluded network",
            }

        if any(ip in network for network in scope["networks"]):
            return {
                "target": raw,
                "normalized": str(ip),
                "allowed": True,
                "reason": "inside allowed network",
            }

        return {
            "target": raw,
            "normalized": str(ip),
            "allowed": False,
            "reason": "IP is outside allowed networks",
        }

    if lowered in scope["hosts"]:
        return {
            "target": raw,
            "normalized": lowered,
            "allowed": True,
            "reason": "explicitly allowed host",
        }

    if is_domain_match(lowered, scope["domains"]):
        return {
            "target": raw,
            "normalized": lowered,
            "allowed": True,
            "reason": "inside allowed domain scope",
        }

    return {
        "target": raw,
        "normalized": lowered,
        "allowed": False,
        "reason": "host/domain is not in scope",
    }


def resolve_target(target):
    normalized = normalize_target(target)
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(normalized, None)})
    except socket.gaierror:
        return []


def validate_targets(targets, scope, resolve=False):
    results = []

    for target in targets:
        result = classify_target(target, scope)

        if resolve and result["allowed"] and not result["normalized"].replace(".", "").isdigit():
            result["resolved_ips"] = resolve_target(result["normalized"])

        results.append(result)

    return results


def read_targets(values, file_path=None):
    targets = list(values or [])

    if file_path:
        targets.extend(
            line.strip()
            for line in Path(file_path).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )

    return targets


def main():
    parser = argparse.ArgumentParser(
        description="Check a target list against an authorized scope file before testing."
    )
    parser.add_argument("--scope", required=True, help="JSON scope file")
    parser.add_argument("--target", action="append", default=[], help="Target to check; repeatable")
    parser.add_argument("--targets-file", help="Text file with one target per line")
    parser.add_argument("--resolve", action="store_true", help="Resolve allowed hostnames for reference")
    parser.add_argument("--json", dest="json_path", help="Save results as JSON")
    parser.add_argument(
        "--allowed-output",
        help="Write only allowed normalized targets to this text file",
    )
    args = parser.parse_args()

    try:
        scope = load_scope(args.scope)
        targets = read_targets(args.target, args.targets_file)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))

    if not targets:
        parser.error("Provide at least one --target or --targets-file")

    results = validate_targets(targets, scope, resolve=args.resolve)
    allowed = [item for item in results if item["allowed"]]
    denied = [item for item in results if not item["allowed"]]

    print(f"Targets checked: {len(results)}")
    print(f"Allowed: {len(allowed)}")
    print(f"Denied: {len(denied)}")

    for item in results:
        status = "ALLOW" if item["allowed"] else "DENY"
        print(f"[{status}] {item['normalized'] or item['target']} - {item['reason']}")

    if args.allowed_output:
        Path(args.allowed_output).write_text(
            "\n".join(item["normalized"] for item in allowed) + ("\n" if allowed else ""),
            encoding="utf-8",
        )

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(
                {
                    "summary": {
                        "checked": len(results),
                        "allowed": len(allowed),
                        "denied": len(denied),
                    },
                    "results": results,
                },
                indent=2,
            ),
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
