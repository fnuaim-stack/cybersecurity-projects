import argparse
import json
import posixpath
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urlparse, urlunparse


STATIC_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".webp",
}


def normalize_url(url):
    parsed = urlparse(url.strip())

    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Not a full URL: {url}")

    path = parsed.path or "/"
    path = posixpath.normpath(path)
    if not path.startswith("/"):
        path = "/" + path

    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        path=path,
        fragment="",
    )
    return urlunparse(normalized)


def endpoint_key(method, url):
    parsed = urlparse(url)
    return f"{method.upper()} {parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"


def parse_url_entry(url, method="GET", status=None, source="text"):
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    query_names = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
    extension = Path(parsed.path).suffix.lower()

    return {
        "url": normalized,
        "method": method.upper(),
        "status": status,
        "host": parsed.netloc,
        "path": parsed.path or "/",
        "query_parameters": query_names,
        "extension": extension,
        "static": extension in STATIC_EXTENSIONS,
        "source": source,
    }


def parse_har(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = []

    for item in data.get("log", {}).get("entries", []):
        request = item.get("request", {})
        response = item.get("response", {})
        url = request.get("url")

        if not url:
            continue

        try:
            entry = parse_url_entry(
                url,
                method=request.get("method", "GET"),
                status=response.get("status"),
                source="har",
            )
        except ValueError:
            continue

        post_names = []
        for param in request.get("postData", {}).get("params", []) or []:
            name = param.get("name")
            if name:
                post_names.append(name)

        entry["body_parameters"] = sorted(set(post_names))
        entries.append(entry)

    return entries


def parse_text(path):
    entries = []

    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        method = "GET"
        url = line

        if " " in line:
            first, rest = line.split(None, 1)
            if first.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
                method = first.upper()
                url = rest.strip()

        try:
            entries.append(parse_url_entry(url, method=method, source="text"))
        except ValueError:
            continue

    return entries


def dedupe_entries(entries):
    merged = {}

    for entry in entries:
        key = endpoint_key(entry["method"], entry["url"])

        if key not in merged:
            merged[key] = {
                **entry,
                "query_parameters": set(entry.get("query_parameters", [])),
                "body_parameters": set(entry.get("body_parameters", [])),
                "statuses": set(
                    [entry["status"]]
                    if entry.get("status") is not None
                    else []
                ),
                "sources": {entry.get("source", "unknown")},
                "seen": 1,
            }
            continue

        current = merged[key]
        current["query_parameters"].update(entry.get("query_parameters", []))
        current["body_parameters"].update(entry.get("body_parameters", []))
        if entry.get("status") is not None:
            current["statuses"].add(entry["status"])
        current["sources"].add(entry.get("source", "unknown"))
        current["seen"] += 1

    output = []
    for item in merged.values():
        item["query_parameters"] = sorted(item["query_parameters"])
        item["body_parameters"] = sorted(item["body_parameters"])
        item["statuses"] = sorted(item["statuses"])
        item["sources"] = sorted(item["sources"])
        item.pop("status", None)
        output.append(item)

    return sorted(output, key=lambda item: (item["host"], item["path"], item["method"]))


def build_report(entries, include_static=True):
    if not include_static:
        entries = [item for item in entries if not item["static"]]

    hosts = Counter(item["host"] for item in entries)
    methods = Counter(item["method"] for item in entries)
    extensions = Counter(item["extension"] or "(none)" for item in entries)
    statuses = Counter(
        status
        for item in entries
        for status in item.get("statuses", [])
    )

    parameters = Counter()
    for item in entries:
        parameters.update(item.get("query_parameters", []))
        parameters.update(item.get("body_parameters", []))

    by_host = defaultdict(list)
    for item in entries:
        by_host[item["host"]].append(item)

    return {
        "summary": {
            "endpoints": len(entries),
            "hosts": dict(hosts.most_common()),
            "methods": dict(methods.most_common()),
            "statuses": {str(key): value for key, value in statuses.most_common()},
            "extensions": dict(extensions.most_common()),
            "parameters": dict(parameters.most_common()),
        },
        "hosts": {
            host: items
            for host, items in sorted(by_host.items())
        },
        "endpoints": entries,
    }


def build_markdown(report):
    lines = [
        "# Web Endpoint Inventory",
        "",
        f"- Endpoints: {report['summary']['endpoints']}",
        f"- Hosts: {len(report['summary']['hosts'])}",
        "",
        "## Hosts",
        "",
    ]

    for host, count in report["summary"]["hosts"].items():
        lines.append(f"- {host}: {count}")

    lines.extend(["", "## Endpoints", ""])

    for host, items in report["hosts"].items():
        lines.extend([f"### {host}", "", "| Method | Path | Params | Status |", "|---|---|---|---|"])
        for item in items:
            params = sorted(
                set(item.get("query_parameters", []))
                | set(item.get("body_parameters", []))
            )
            statuses = ", ".join(str(value) for value in item.get("statuses", [])) or "-"
            lines.append(
                f"| {item['method']} | {item['path']} | "
                f"{', '.join(params) or '-'} | {statuses} |"
            )
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Build a local web endpoint inventory from HAR files or URL lists."
    )
    parser.add_argument("inputs", nargs="+", help=".har/.json HAR files or text URL lists")
    parser.add_argument("--no-static", action="store_true", help="Hide common static assets")
    parser.add_argument("--json", dest="json_path", help="Save inventory as JSON")
    parser.add_argument("--markdown", help="Save inventory as Markdown")
    args = parser.parse_args()

    entries = []

    for item in args.inputs:
        path = Path(item)

        try:
            if path.suffix.lower() in {".har", ".json"}:
                entries.extend(parse_har(path))
            else:
                entries.extend(parse_text(path))
        except (OSError, json.JSONDecodeError) as error:
            parser.error(f"{path}: {error}")

    deduped = dedupe_entries(entries)
    report = build_report(deduped, include_static=not args.no_static)

    print(f"Endpoints: {report['summary']['endpoints']}")
    print(f"Hosts: {len(report['summary']['hosts'])}")

    for host, items in report["hosts"].items():
        print(f"\n{host}")
        for endpoint in items:
            params = sorted(
                set(endpoint.get("query_parameters", []))
                | set(endpoint.get("body_parameters", []))
            )
            param_text = f" params={','.join(params)}" if params else ""
            print(f"  {endpoint['method']:<7} {endpoint['path']}{param_text}")

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

    if args.markdown:
        Path(args.markdown).write_text(
            build_markdown(report),
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
