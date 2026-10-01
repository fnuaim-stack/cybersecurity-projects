from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from statistics import mean, median


ACTIVE = {"open", "in_progress"}


def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def build_analytics(db) -> dict:
    findings = db.list_findings(limit=100000)
    scans = db.list_scans(limit=200)
    now = datetime.now(timezone.utc)

    active = [item for item in findings if item["status"] in ACTIVE]
    resolved = [item for item in findings if item["status"] == "resolved"]

    ages = {"0-7d": 0, "8-30d": 0, "31-90d": 0, "90d+": 0}
    overdue = 0
    active_with_due = 0
    mttr_hours: list[float] = []
    recurrence_total = 0
    recurring_findings = 0

    by_owner = Counter()
    by_source = Counter()
    by_environment = Counter()
    asset_risk = defaultdict(int)

    for item in active:
        first_seen = _dt(item.get("first_seen"))
        if first_seen:
            days = max(0, (now - first_seen).days)
            if days <= 7:
                ages["0-7d"] += 1
            elif days <= 30:
                ages["8-30d"] += 1
            elif days <= 90:
                ages["31-90d"] += 1
            else:
                ages["90d+"] += 1

        due = _dt(item.get("due_at"))
        if due:
            active_with_due += 1
            if due < now:
                overdue += 1

        by_owner[item.get("owner") or item.get("asset_owner") or "unassigned"] += 1
        by_source[item.get("source") or "unknown"] += 1
        by_environment[item.get("environment") or "unknown"] += 1
        asset_risk[item.get("asset_key") or "unknown"] += int(item.get("risk_score") or 0)

    for item in resolved:
        first_seen = _dt(item.get("first_seen"))
        verified = _dt(item.get("verified_at"))
        if first_seen and verified and verified >= first_seen:
            mttr_hours.append((verified - first_seen).total_seconds() / 3600)

    for item in findings:
        history = db.history(int(item["id"]))
        recurrences = sum(1 for entry in history if entry["action"] == "reopened")
        recurrence_total += recurrences
        if recurrences:
            recurring_findings += 1

    compliance = None
    if active_with_due:
        compliance = round(((active_with_due - overdue) / active_with_due) * 100, 1)

    recent_scans = [
        {
            "id": scan["id"],
            "source": scan["source"],
            "scope": scan["scope"],
            "started_at": scan["started_at"],
            "imported_count": scan["imported_count"],
            "status": scan["status"],
        }
        for scan in scans[:20]
    ]

    return {
        "generated_at": now.isoformat(),
        "total_findings": len(findings),
        "active_findings": len(active),
        "resolved_findings": len(resolved),
        "overdue_active": overdue,
        "sla_compliance_percent": compliance,
        "age_buckets": ages,
        "mttr_hours": {
            "count": len(mttr_hours),
            "average": round(mean(mttr_hours), 2) if mttr_hours else None,
            "median": round(median(mttr_hours), 2) if mttr_hours else None,
        },
        "recurrence": {
            "reopened_events": recurrence_total,
            "findings_that_recurred": recurring_findings,
        },
        "active_by_owner": dict(by_owner.most_common()),
        "active_by_source": dict(by_source.most_common()),
        "active_by_environment": dict(by_environment.most_common()),
        "top_assets_by_risk": [
            {"asset": asset, "aggregate_risk": score}
            for asset, score in sorted(asset_risk.items(), key=lambda pair: pair[1], reverse=True)[:10]
        ],
        "recent_scans": recent_scans,
    }
