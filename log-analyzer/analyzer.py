import argparse
import json
import re
from collections import Counter
from pathlib import Path

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FAILED_WORDS = (
    "failed password",
    "authentication failure",
    "login failed",
    "invalid user",
    "failed login",
)


def valid_ip(ip):
    try:
        return all(0 <= int(part) <= 255 for part in ip.split("."))
    except ValueError:
        return False


def analyze(lines, threshold):
    ip_counts = Counter()
    failed_by_ip = Counter()
    failed_lines = []

    for number, line in enumerate(lines, start=1):
        lowered = line.lower()
        ips = [ip for ip in IP_PATTERN.findall(line) if valid_ip(ip)]

        for ip in ips:
            ip_counts[ip] += 1

        if any(word in lowered for word in FAILED_WORDS):
            failed_lines.append({"line": number, "text": line.rstrip()})
            for ip in ips:
                failed_by_ip[ip] += 1

    suspicious = {
        ip: count
        for ip, count in failed_by_ip.items()
        if count >= threshold
    }

    return {
        "total_lines": len(lines),
        "ip_activity": dict(ip_counts.most_common()),
        "failed_login_lines": failed_lines,
        "failed_logins_by_ip": dict(failed_by_ip.most_common()),
        "flagged_ips": suspicious,
    }


def main():
    parser = argparse.ArgumentParser(description="Simple defensive log analyzer.")
    parser.add_argument("logfile", help="Log file to analyze")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Flag an IP after this many failed-login lines",
    )
    parser.add_argument("--json", dest="json_path", help="Save the report as JSON")
    args = parser.parse_args()

    path = Path(args.logfile)

    if not path.exists():
        parser.error(f"File not found: {path}")

    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    result = analyze(lines, args.threshold)

    print(f"Lines checked: {result['total_lines']}")
    print(f"Failed-login lines: {len(result['failed_login_lines'])}")

    print("\nTop IPs:")
    for ip, count in list(result["ip_activity"].items())[:10]:
        print(f"{ip:<15} {count}")

    print("\nFlagged IPs:")
    if result["flagged_ips"]:
        for ip, count in result["flagged_ips"].items():
            print(f"{ip:<15} {count} failed attempts")
    else:
        print("None")

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(result, indent=2),
            encoding="utf-8",
        )
        print(f"\nSaved report to {args.json_path}")


if __name__ == "__main__":
    main()
