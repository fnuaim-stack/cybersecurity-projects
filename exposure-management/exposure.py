from __future__ import annotations

import argparse
import json
from pathlib import Path

from exposure_manager.models import VALID_STATUSES
from exposure_manager.reporting import to_csv, to_json, to_markdown
from exposure_manager.service import ExposureManager


DEFAULT_DB = Path.home() / ".exposure-management" / "exposure.db"


def yes_no(value: str) -> bool:
    text = value.strip().lower()
    if text in {"yes", "true", "1", "on"}:
        return True
    if text in {"no", "false", "0", "off"}:
        return False
    raise argparse.ArgumentTypeError("use yes or no")


def print_rows(rows: list[dict], columns: list[tuple[str, str]]) -> None:
    if not rows:
        print("No results.")
        return

    widths = {}
    for key, label in columns:
        values = [str(row.get(key, "") or "") for row in rows]
        widths[key] = min(42, max(len(label), *(len(value) for value in values)))

    print("  ".join(label.ljust(widths[key]) for key, label in columns))
    print("  ".join("-" * widths[key] for key, _ in columns))

    for row in rows:
        cells = []
        for key, _ in columns:
            value = str(row.get(key, "") or "")
            if len(value) > widths[key]:
                value = value[: max(1, widths[key] - 1)] + "…"
            cells.append(value.ljust(widths[key]))
        print("  ".join(cells))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Normalize security findings and turn them into a remediation queue."
    )
    parser.add_argument("--db", default=str(DEFAULT_DB), help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)

    imp = sub.add_parser("import", help="Import a completed scanner result")
    imp.add_argument("path")
    imp.add_argument(
        "--format",
        default="auto",
        choices=["auto", "nuclei", "trivy", "nmap", "openvas-csv", "sarif", "generic"],
    )
    imp.add_argument("--source", help="Scanner/source name; defaults to detected format")
    imp.add_argument("--scope", default="default", help="Stable scan scope, such as prod-dmz")
    imp.add_argument(
        "--verify-misses",
        type=int,
        default=2,
        help="Consecutive complete scans that must miss a finding before it is verified resolved",
    )

    summary = sub.add_parser("summary", help="Show current exposure summary")
    summary.add_argument("--json", action="store_true")

    findings = sub.add_parser("findings", help="List findings")
    findings.add_argument("--status", choices=sorted(VALID_STATUSES))
    findings.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"])
    findings.add_argument("--source")
    findings.add_argument("--owner")
    findings.add_argument("--min-risk", type=int)
    findings.add_argument("--limit", type=int, default=100)
    findings.add_argument("--json", action="store_true")

    queue = sub.add_parser("queue", help="Show the prioritized remediation queue")
    queue.add_argument("--limit", type=int, default=100)
    queue.add_argument("--json", action="store_true")

    show = sub.add_parser("show", help="Show one finding and its history")
    show.add_argument("id", type=int)

    assets = sub.add_parser("assets", help="List known assets")
    assets.add_argument("--json", action="store_true")

    asset_set = sub.add_parser("asset-set", help="Set business context for an asset")
    asset_set.add_argument("asset")
    asset_set.add_argument("--criticality", type=int, choices=range(1, 6))
    asset_set.add_argument("--internet-exposed", type=yes_no)
    asset_set.add_argument("--owner")
    asset_set.add_argument("--environment")

    finding_set = sub.add_parser("finding-set", help="Update finding workflow state")
    finding_set.add_argument("id", type=int)
    finding_set.add_argument(
        "--status",
        choices=sorted(VALID_STATUSES - {"accepted_risk"}),
    )
    finding_set.add_argument("--owner")

    accept = sub.add_parser("accept-risk", help="Create a time-limited risk exception")
    accept.add_argument("id", type=int)
    accept.add_argument("--until", required=True, help="YYYY-MM-DD")
    accept.add_argument("--reason", required=True)

    scans = sub.add_parser("scans", help="Show recent imports")
    scans.add_argument("--limit", type=int, default=30)
    scans.add_argument("--json", action="store_true")

    report = sub.add_parser("report", help="Export the active remediation queue")
    report.add_argument("--format", choices=["markdown", "json", "csv"], default="markdown")
    report.add_argument("--output")
    report.add_argument("--limit", type=int, default=1000)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    manager = ExposureManager(args.db)

    if args.command == "import":
        result = manager.import_scan(
            args.path,
            fmt=args.format,
            source=args.source,
            scope=args.scope,
            verification_misses=args.verify_misses,
        )
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "summary":
        data = manager.summary()
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print(f"Assets: {data['assets']}")
            print(f"Findings: {data['findings']}")
            print(f"Active: {data['active']}")
            print(f"Overdue: {data['overdue']}")
            print("Active by risk:", data.get("active_by_risk", {}))
        return 0

    if args.command == "findings":
        rows = manager.db.list_findings(
            status=args.status,
            severity=args.severity,
            source=args.source,
            owner=args.owner,
            min_risk=args.min_risk,
            limit=args.limit,
        )
        if args.json:
            print(json.dumps(rows, indent=2, default=str))
        else:
            print_rows(
                rows,
                [
                    ("id", "ID"),
                    ("risk_score", "Risk"),
                    ("status", "Status"),
                    ("asset_key", "Asset"),
                    ("title", "Finding"),
                    ("source", "Source"),
                ],
            )
        return 0

    if args.command == "queue":
        rows = manager.remediation_queue(args.limit)
        if args.json:
            print(json.dumps(rows, indent=2, default=str))
        else:
            print_rows(
                rows,
                [
                    ("id", "ID"),
                    ("risk_score", "Risk"),
                    ("overdue", "Overdue"),
                    ("asset_key", "Asset"),
                    ("title", "Finding"),
                    ("due_at", "Due"),
                ],
            )
        return 0

    if args.command == "show":
        print(json.dumps(manager.export_finding(args.id), indent=2, default=str))
        return 0

    if args.command == "assets":
        rows = manager.db.list_assets()
        if args.json:
            print(json.dumps(rows, indent=2, default=str))
        else:
            print_rows(
                rows,
                [
                    ("asset_key", "Asset"),
                    ("criticality", "Criticality"),
                    ("internet_exposed", "Internet"),
                    ("environment", "Environment"),
                    ("active_findings", "Active"),
                    ("owner", "Owner"),
                ],
            )
        return 0

    if args.command == "asset-set":
        result = manager.set_asset_context(
            args.asset,
            criticality=args.criticality,
            internet_exposed=args.internet_exposed,
            owner=args.owner,
            environment=args.environment,
        )
        print(json.dumps(result, indent=2, default=str))
        return 0

    if args.command == "finding-set":
        result = manager.set_finding(
            args.id,
            status=args.status,
            owner=args.owner,
        )
        print(json.dumps(result, indent=2, default=str))
        return 0

    if args.command == "accept-risk":
        result = manager.accept_risk(args.id, args.until, args.reason)
        print(json.dumps(result, indent=2, default=str))
        return 0

    if args.command == "scans":
        rows = manager.db.list_scans(args.limit)
        if args.json:
            print(json.dumps(rows, indent=2, default=str))
        else:
            print_rows(
                rows,
                [
                    ("started_at", "Started"),
                    ("source", "Source"),
                    ("scope", "Scope"),
                    ("imported_count", "Imported"),
                    ("status", "Status"),
                ],
            )
        return 0

    if args.command == "report":
        findings = manager.remediation_queue(args.limit)
        summary = manager.summary()
        if args.format == "json":
            content = to_json(summary, findings)
        elif args.format == "csv":
            content = to_csv(findings)
        else:
            content = to_markdown(summary, findings)

        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content, encoding="utf-8")
            print(f"Saved {output}")
        else:
            print(content, end="")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
