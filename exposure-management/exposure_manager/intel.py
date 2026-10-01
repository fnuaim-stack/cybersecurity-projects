from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from .scoring import calculate_risk


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _band(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def _extract_cves(finding: dict) -> set[str]:
    values = [
        str(finding.get("external_id") or ""),
        str(finding.get("title") or ""),
        str(finding.get("description") or ""),
        str(finding.get("metadata_json") or ""),
    ]
    found: set[str] = set()
    for value in values:
        for match in CVE_RE.findall(value):
            found.add(match.upper())
    return found


def load_kev(path: str | Path) -> dict[str, dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = data.get("vulnerabilities", data if isinstance(data, list) else [])
    result = {}
    for row in rows:
        cve = str(row.get("cveID") or row.get("cve") or "").upper()
        if cve:
            result[cve] = row
    return result


def load_epss(path: str | Path) -> dict[str, dict]:
    result: dict[str, dict] = {}
    with Path(path).open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        filtered = (line for line in handle if not line.startswith("#"))
        for row in csv.DictReader(filtered):
            cve = str(row.get("cve") or row.get("CVE") or "").upper()
            if not cve:
                continue
            try:
                epss = float(row.get("epss") or 0)
            except (TypeError, ValueError):
                epss = 0.0
            try:
                percentile = float(row.get("percentile") or 0)
            except (TypeError, ValueError):
                percentile = 0.0
            result[cve] = {"epss": epss, "percentile": percentile}
    return result


def enrich_findings(db, *, kev_path: str | Path | None = None, epss_path: str | Path | None = None) -> dict:
    kev = load_kev(kev_path) if kev_path else {}
    epss = load_epss(epss_path) if epss_path else {}
    changed = 0
    kev_matches = 0
    epss_matches = 0

    for finding in db.list_findings(limit=100000):
        cves = _extract_cves(finding)
        if not cves:
            continue

        matched_kev = [cve for cve in cves if cve in kev]
        matched_epss = [(cve, epss[cve]) for cve in cves if cve in epss]
        if not matched_kev and not matched_epss:
            continue

        metadata = {}
        try:
            metadata = json.loads(finding.get("metadata_json") or "{}")
        except json.JSONDecodeError:
            metadata = {}

        intel = metadata.setdefault("threat_intel", {})
        if matched_kev:
            intel["cisa_kev"] = [
                {
                    "cve": cve,
                    "date_added": kev[cve].get("dateAdded"),
                    "due_date": kev[cve].get("dueDate"),
                    "ransomware_use": kev[cve].get("knownRansomwareCampaignUse"),
                    "required_action": kev[cve].get("requiredAction"),
                }
                for cve in matched_kev
            ]
            kev_matches += 1

        max_epss = None
        if matched_epss:
            best_cve, best = max(matched_epss, key=lambda pair: pair[1]["epss"])
            max_epss = float(best["epss"])
            intel["epss"] = {
                "cve": best_cve,
                "score": max_epss,
                "percentile": float(best["percentile"]),
            }
            epss_matches += 1

        score, band = calculate_risk(
            finding["severity"],
            cvss=finding["cvss"],
            criticality=int(finding["criticality"]),
            internet_exposed=bool(finding["internet_exposed"]),
            exploit_available=bool(finding["exploit_available"]),
            known_exploited=bool(matched_kev) or bool(finding["known_exploited"]),
        )

        if max_epss is not None:
            if max_epss >= 0.9:
                score += 12
            elif max_epss >= 0.5:
                score += 8
            elif max_epss >= 0.1:
                score += 4
            score = min(score, 100)
            band = _band(score)

        db.update_finding(
            int(finding["id"]),
            {
                "known_exploited": int(bool(matched_kev) or bool(finding["known_exploited"])),
                "risk_score": score,
                "risk_band": band,
                "metadata_json": db.metadata_json(metadata),
            },
        )
        db.add_history(
            int(finding["id"]),
            __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "threat_intel_enriched",
            f"KEV={bool(matched_kev)} EPSS={max_epss if max_epss is not None else 'n/a'}",
        )
        changed += 1

    return {
        "updated_findings": changed,
        "kev_matches": kev_matches,
        "epss_matches": epss_matches,
    }
