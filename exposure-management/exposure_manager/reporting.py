from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone


def to_json(summary: dict, findings: list[dict]) -> str:
    return json.dumps(
        {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "findings": findings,
        },
        indent=2,
        default=str,
    )


def to_csv(findings: list[dict]) -> str:
    fields = [
        "id",
        "asset_key",
        "title",
        "source",
        "severity",
        "risk_score",
        "risk_band",
        "status",
        "owner",
        "due_at",
        "last_seen",
        "external_id",
        "port",
        "protocol",
        "service",
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(findings)
    return output.getvalue()


def to_markdown(summary: dict, findings: list[dict]) -> str:
    lines = [
        "# Exposure Management Report",
        "",
        f"Assets: {summary.get('assets', 0)}",
        f"Findings: {summary.get('findings', 0)}",
        f"Active remediation items: {summary.get('active', 0)}",
        f"Overdue: {summary.get('overdue', 0)}",
        "",
        "## Remediation queue",
        "",
        "| Risk | Asset | Finding | Status | Due |",
        "| ---: | --- | --- | --- | --- |",
    ]

    for item in findings:
        title = str(item.get("title", "")).replace("|", "\\|")
        asset = str(item.get("asset_key", "")).replace("|", "\\|")
        lines.append(
            f"| {item.get('risk_score', 0)} | {asset} | {title} | "
            f"{item.get('status', '')} | {item.get('due_at') or '-'} |"
        )

    if not findings:
        lines.append("| - | - | No active findings | - | - |")

    return "\n".join(lines) + "\n"
