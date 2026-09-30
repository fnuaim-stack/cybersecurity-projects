import argparse
import ipaddress
import json
import re
from collections import Counter
from pathlib import Path

FAILED_WORDS = (
    "failed password",
    "authentication failure",
    "login failed",
    "invalid user",
    "failed login",
    "authentication failed",
)
SUCCESS_WORDS = (
    "accepted password",
    "accepted publickey",
    "login successful",
    "session opened",
)
PRIVILEGE_WORDS = (
    "sudo",
    "su:",
    "privilege",
)

IP_CANDIDATE = re.compile(r"[0-9A-Fa-f:.]{3,}")
USERNAME_PATTERNS = (
    re.compile(r"failed password for (?:invalid user )?(?P<user>[^ ]+)", re.I),
    re.compile(r"accepted (?:password|publickey) for (?P<user>[^ ]+)", re.I),
    re.compile(r"invalid user (?P<user>[^ ]+)", re.I),
    re.compile(r"user[=: ]+(?P<user>[A-Za-z0-9_.@-]+)", re.I),
)
HTTP_STATUS_PATTERN = re.compile(r'[" ](?P<status>[45][0-9]{2})[" ]')


def extract_ips(line):
    found = []

    for candidate in IP_CANDIDATE.findall(line):
        candidate = candidate.strip("[](),;")
        try:
            ip = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue

        if ip not in found:
            found.append(ip)

    return found


def extract_usernames(line):
    users = []

    for pattern in USERNAME_PATTERNS:
        match = pattern.search(line)
        if match:
            user = match.group("user").strip("[](),;:")
            if user and user not in users:
                users.append(user)

    return users


def classify_line(line):
    lowered = line.lower()
    events = []

    if any(word in lowered for word in FAILED_WORDS):
        events.append("failed_login")

    if any(word in lowered for word in SUCCESS_WORDS):
        events.append("successful_login")

    if any(word in lowered for word in PRIVILEGE_WORDS):
        events.append("privilege_activity")

    status_match = HTTP_STATUS_PATTERN.search(line)
    if status_match:
        status = int(status_match.group("status"))
        events.append("http_client_error" if status < 500 else "http_server_error")

    return events


def analyze(lines, threshold, top=10):
    ip_counts = Counter()
    failed_by_ip = Counter()
    usernames = Counter()
    event_counts = Counter()
    http_statuses = Counter()
    failed_lines = []
    event_lines = []

    for number, line in enumerate(lines, start=1):
        ips = extract_ips(line)
        users = extract_usernames(line)
        events = classify_line(line)

        ip_counts.update(ips)
        usernames.update(users)
        event_counts.update(events)

        status_match = HTTP_STATUS_PATTERN.search(line)
        if status_match:
            http_statuses[status_match.group("status")] += 1

        if "failed_login" in events:
            failed_lines.append({"line": number, "text": line.rstrip()})
            failed_by_ip.update(ips)

        if events:
            event_lines.append(
                {
                    "line": number,
                    "events": events,
                    "ips": ips,
                    "users": users,
                    "text": line.rstrip(),
                }
            )

    suspicious = {
        ip: count
        for ip, count in failed_by_ip.items()
        if count >= threshold
    }

    return {
        "total_lines": len(lines),
        "event_counts": dict(event_counts.most_common()),
        "ip_activity": dict(ip_counts.most_common(top)),
        "user_activity": dict(usernames.most_common(top)),
        "http_statuses": dict(http_statuses.most_common()),
        "failed_login_lines": failed_lines,
        "failed_logins_by_ip": dict(failed_by_ip.most_common()),
        "flagged_ips": suspicious,
        "events": event_lines[:200],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Small defensive log analyzer for auth and basic web activity."
    )
    parser.add_argument("logfile", help="Log file to analyze")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Flag an IP after this many failed-login lines",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="How many top IP/user rows to keep (default: 10)",
    )
    parser.add_argument("--json", dest="json_path", help="Save the report as JSON")
    args = parser.parse_args()

    path = Path(args.logfile)

    if not path.exists():
        parser.error(f"File not found: {path}")
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if args.top < 1 or args.top > 100:
        parser.error("--top must be between 1 and 100")

    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    result = analyze(lines, args.threshold, args.top)

    print(f"Lines checked: {result['total_lines']}")

    print("\nEvents:")
    if result["event_counts"]:
        for event, count in result["event_counts"].items():
            print(f"{event:<22} {count}")
    else:
        print("None from the current rules.")

    print("\nTop IPs:")
    for ip, count in result["ip_activity"].items():
        print(f"{ip:<39} {count}")

    print("\nFlagged failed-login IPs:")
    if result["flagged_ips"]:
        for ip, count in result["flagged_ips"].items():
            print(f"{ip:<39} {count} failed attempts")
    else:
        print("None")

    if result["user_activity"]:
        print("\nUsernames seen:")
        for user, count in result["user_activity"].items():
            print(f"{user:<24} {count}")

    if result["http_statuses"]:
        print("\nHTTP error statuses:")
        for status, count in result["http_statuses"].items():
            print(f"{status:<4} {count}")

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(result, indent=2),
            encoding="utf-8",
        )
        print(f"\nSaved report to {args.json_path}")


if __name__ == "__main__":
    main()
