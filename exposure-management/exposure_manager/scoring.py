from __future__ import annotations

from datetime import datetime, timedelta, timezone


SEVERITY_BASE = {
    "info": 5,
    "low": 20,
    "medium": 45,
    "high": 70,
    "critical": 90,
}

CRITICALITY_ADJUSTMENT = {
    1: -8,
    2: -4,
    3: 0,
    4: 6,
    5: 12,
}

SLA_DAYS = {
    "critical": 7,
    "high": 14,
    "medium": 30,
    "low": 90,
    "info": 180,
}


def normalize_severity(value: str | None) -> str:
    text = (value or "info").strip().lower()
    aliases = {
        "informational": "info",
        "none": "info",
        "moderate": "medium",
        "important": "high",
        "severe": "critical",
    }
    text = aliases.get(text, text)
    return text if text in SEVERITY_BASE else "info"


def calculate_risk(
    severity: str,
    *,
    cvss: float | None = None,
    criticality: int = 3,
    internet_exposed: bool = False,
    exploit_available: bool = False,
    known_exploited: bool = False,
) -> tuple[int, str]:
    severity = normalize_severity(severity)
    score = SEVERITY_BASE[severity]

    if cvss is not None:
        score = max(score, round(max(0.0, min(float(cvss), 10.0)) * 10))

    score += CRITICALITY_ADJUSTMENT.get(max(1, min(int(criticality), 5)), 0)

    if internet_exposed:
        score += 10
    if exploit_available:
        score += 8
    if known_exploited:
        score += 15

    score = max(0, min(score, 100))

    if score >= 90:
        band = "critical"
    elif score >= 70:
        band = "high"
    elif score >= 40:
        band = "medium"
    elif score >= 15:
        band = "low"
    else:
        band = "info"

    return score, band


def due_date(first_seen: str, risk_band: str) -> str:
    try:
        started = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
    except ValueError:
        started = datetime.now(timezone.utc)

    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)

    return (started + timedelta(days=SLA_DAYS.get(risk_band, 30))).isoformat()
