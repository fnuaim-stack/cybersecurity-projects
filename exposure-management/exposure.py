from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from exposure_manager.analytics import build_analytics
from exposure_manager.campaigns import CampaignManager
from exposure_manager.integrations import create_jira_issue, send_slack, send_webhook
from exposure_manager.intel import enrich_findings
from exposure_manager.models import VALID_STATUSES
from exposure_manager.reporting import to_csv, to_json, to_markdown
from exposure_manager.service import ExposureManager


DEFAULT_DB = Path.home() / ".exposure-management" / "exposure.db"
FORMATS = [
    "auto",
    "nuclei",
    "trivy",
    "nmap",
    "nessus",
    "openvas-csv",
    "sarif",
    "zap",
    "semgrep",
    "generic",
]


def yes_no(value: str) -> bool:
    text = value.strip().lower()
    if text in {"yes", "true", "1", "on"}:
        return True
    if text in {"no", "false", "0", "off"}:
        return False
    raise argparse.ArgumentTypeError("use yes or no")


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Missing environment variable: {name}")
    return value


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
        description="Normalize security findings and turn them into a remediation workflow."
    )
    parser.add_argument("--db", default=str(DEFAULT_DB), help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)

    imp = sub.add_parser("import", help="Import a completed scanner result")
    imp.add_argument("path")
    imp.add_argument("--format", default="auto", choices=FORMATS)
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

    analytics = sub.add_parser("analytics", help="Show MTTR, aging, SLA and recurrence metrics")
    analytics.add_argument("--json", action="store_true")

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
    finding_set.add_argument("--status", choices=sorted(VALID_STATUSES - {"accepted_risk"}))
    finding_set.add_argument("--owner")

    accept = sub.add_parser("accept-risk", help="Create a time-limited risk exception")
    accept.add_argument("id", type=int)
    accept.add_argument("--until", required=True, help="YYYY-MM-DD")
    accept.add_argument("--reason", required=True)

    scans = sub.add_parser("scans", help="Show recent imports")
    scans.add_argument("--limit", type=int, default=30)
    scans.add_argument("--json", action="store_true")

    intel = sub.add_parser("intel-enrich", help="Enrich findings from local CISA KEV and EPSS files")
    intel.add_argument("--kev", help="CISA KEV JSON file")
    intel.add_argument("--epss", help="EPSS CSV file")

    campaign_create = sub.add_parser("campaign-create", help="Create a remediation campaign")
    campaign_create.add_argument("name")
    campaign_create.add_argument("--owner", default="")
    campaign_create.add_argument("--due")
    campaign_create.add_argument("--notes", default="")
    campaign_create.add_argument("--min-risk", type=int)
    campaign_create.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"])
    campaign_create.add_argument("--source")
    campaign_create.add_argument("--finding-owner")
    campaign_create.add_argument("--limit", type=int, default=1000)

    campaigns = sub.add_parser("campaigns", help="List remediation campaigns")
    campaigns.add_argument("--json", action="store_true")

    campaign_show = sub.add_parser("campaign-show", help="Show a remediation campaign")
    campaign_show.add_argument("id")

    campaign_sync = sub.add_parser("campaign-sync", help="Refresh campaign completion status")
    campaign_sync.add_argument("id")

    report = sub.add_parser("report", help="Export the active remediation queue")
    report.add_argument("--format", choices=["markdown", "json", "csv"], default="markdown")
    report.add_argument("--output")
    report.add_argument("--limit", type=int, default=1000)

    slack = sub.add_parser("slack", help="Send the top remediation items to a Slack webhook")
    slack.add_argument("--webhook-env", default="EXPOSURE_SLACK_WEBHOOK")
    slack.add_argument("--title", default="Exposure Management Queue")
    slack.add_argument("--limit", type=int, default=10)

    webhook = sub.add_parser("webhook", help="POST the current summary and queue to a generic webhook")
    webhook.add_argument("--url-env", default="EXPOSURE_WEBHOOK_URL")
    webhook.add_argument("--token-env", default="EXPOSURE_WEBHOOK_TOKEN")
    webhook.add_argument("--limit", type=int, default=100)

    jira = sub.add_parser("jira-create", help="Create a Jira issue for one finding")
    jira.add_argument("id", type=int)
    jira.add_argument("--base-url", required=True)
    jira.add_argument("--project", required=True)
    jira.add_argument("--email", required=True)
    jira.add_argument("--token-env", default="JIRA_API_TOKEN")
    jira.add_argument("--issue-type", default="Task")

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

    if args.command == "analytics":
        data = build_analytics(manager.db)
        if args.json:
            print(json.dumps(data, indent=2, default=str))
        else:
            print(f"Active findings: {data['active_findings']}")
            print(f"Resolved findings: {data['resolved_findings']}")
            print(f"Overdue active: {data['overdue_active']}")
            print(f"SLA compliance: {data['sla_compliance_percent']}")
            print(f"MTTR average hours: {data['mttr_hours']['average']}")
            print(f"Recurring findings: {data['recurrence']['findings_that_recurred']}")
            print("Age buckets:", data["age_buckets"])
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
        result = manager.set_finding(args.id, status=args.status, owner=args.owner)
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

    if args.command == "intel-enrich":
        if not args.kev and not args.epss:
            raise SystemExit("Provide --kev, --epss, or both.")
        result = enrich_findings(manager.db, kev_path=args.kev, epss_path=args.epss)
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "campaign-create":
        campaigns = CampaignManager(manager.db)
        result = campaigns.create(
            args.name,
            owner=args.owner,
            due_at=args.due,
            notes=args.notes,
            min_risk=args.min_risk,
            severity=args.severity,
            source=args.source,
            finding_owner=args.finding_owner,
            limit=args.limit,
        )
        print(json.dumps(result, indent=2, default=str))
        return 0

    if args.command == "campaigns":
        rows = CampaignManager(manager.db).list()
        if args.json:
            print(json.dumps(rows, indent=2, default=str))
        else:
            print_rows(
                rows,
                [
                    ("id", "ID"),
                    ("name", "Campaign"),
                    ("owner", "Owner"),
                    ("status", "Status"),
                    ("finding_count", "Findings"),
                    ("active_findings", "Active"),
                    ("due_at", "Due"),
                ],
            )
        return 0

    if args.command == "campaign-show":
        print(json.dumps(CampaignManager(manager.db).get(args.id), indent=2, default=str))
        return 0

    if args.command == "campaign-sync":
        print(json.dumps(CampaignManager(manager.db).sync_status(args.id), indent=2, default=str))
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

    if args.command == "slack":
        result = send_slack(
            required_env(args.webhook_env),
            title=args.title,
            findings=manager.remediation_queue(args.limit),
        )
        print(json.dumps(result, indent=2, default=str))
        return 0

    if args.command == "webhook":
        token = os.environ.get(args.token_env)
        payload = {
            "summary": manager.summary(),
            "analytics": build_analytics(manager.db),
            "queue": manager.remediation_queue(args.limit),
        }
        result = send_webhook(required_env(args.url_env), payload, bearer_token=token)
        print(json.dumps(result, indent=2, default=str))
        return 0

    if args.command == "jira-create":
        finding = manager.db.get_finding(args.id)
        if not finding:
            raise SystemExit(f"Finding not found: {args.id}")
        result = create_jira_issue(
            base_url=args.base_url,
            project_key=args.project,
            email=args.email,
            api_token=required_env(args.token_env),
            finding=finding,
            issue_type=args.issue_type,
        )
        print(json.dumps(result, indent=2, default=str))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
