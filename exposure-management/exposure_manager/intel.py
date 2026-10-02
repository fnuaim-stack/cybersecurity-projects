from __future__ import annotations

import csv
import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .scoring import calculate_risk, due_date


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CISA_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_API_URL = "https://api.first.org/data/v1/epss"


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


def fetch_kev(*, timeout: int = 25) -> dict[str, dict]:
    request = urllib.request.Request(
        CISA_KEV_JSON_URL,
        headers={"User-Agent": "ExposureManagement/0.4"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8"))
    result = {}
    for row in data.get("vulnerabilities", []):
        cve = str(row.get("cveID") or "").upper()
        if cve:
            result[cve] = row
    return result


def fetch_epss(cves: set[str], *, timeout: int = 25) -> dict[str, dict]:
    ordered = sorted({cve.upper() for cve in cves if CVE_RE.fullmatch(cve)})
    result: dict[str, dict] = {}
    batch: list[str] = []
    length = 0

    def flush(values: list[str]) -> None:
        if not values:
            return
        query = urllib.parse.urlencode({"cve": ",".join(values)})
        request = urllib.request.Request(
            f"{FIRST_EPSS_API_URL}?{query}",
            headers={"User-Agent": "ExposureManagement/0.4"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        for row in payload.get("data", []):
            cve = str(row.get("cve") or "").upper()
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

    for cve in ordered:
        extra = len(cve) + (1 if batch else 0)
        if batch and length + extra > 1800:
            flush(batch)
            batch = []
            length = 0
        batch.append(cve)
        length += extra
    flush(batch)
    return result


def _enrich_from_maps(db, kev: dict[str, dict], epss: dict[str, dict]) -> dict:
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

        try:
            metadata = json.loads(finding.get("metadata_json") or "{}")
        except json.JSONDecodeError:
            metadata = {}

        intel = metadata.setdefault("threat_intel", {})
        intel["updated_at"] = datetime.now(timezone.utc).isoformat()

        if matched_kev:
            intel["cisa_kev"] = [
                {
                    "cve": cve,
                    "date_added": kev[cve].get("dateAdded"),
                    "due_date": kev[cve].get("dueDate"),
                    "ransomware_use": kev[cve].get("knownRansomwareCampaignUse"),
                    "required_action": kev[cve].get("requiredAction"),
                    "vendor": kev[cve].get("vendorProject"),
                    "product": kev[cve].get("product"),
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

        candidate_due = due_date(finding["first_seen"], band)
        current_due = finding.get("due_at")
        if current_due and current_due < candidate_due:
            candidate_due = current_due

        db.update_finding(
            int(finding["id"]),
            {
                "known_exploited": int(bool(matched_kev) or bool(finding["known_exploited"])),
                "risk_score": score,
                "risk_band": band,
                "due_at": candidate_due,
                "metadata_json": db.metadata_json(metadata),
            },
        )
        db.add_history(
            int(finding["id"]),
            datetime.now(timezone.utc).isoformat(),
            "threat_intel_enriched",
            f"KEV={bool(matched_kev)} EPSS={max_epss if max_epss is not None else 'n/a'}",
        )
        changed += 1

    return {
        "updated_findings": changed,
        "kev_matches": kev_matches,
        "epss_matches": epss_matches,
    }


def enrich_findings(db, *, kev_path: str | Path | None = None, epss_path: str | Path | None = None) -> dict:
    kev = load_kev(kev_path) if kev_path else {}
    epss = load_epss(epss_path) if epss_path else {}
    return _enrich_from_maps(db, kev, epss)


def enrich_findings_online(db, *, timeout: int = 25) -> dict:
    all_cves: set[str] = set()
    for finding in db.list_findings(limit=100000):
        all_cves.update(_extract_cves(finding))

    if not all_cves:
        return {
            "updated_findings": 0,
            "kev_matches": 0,
            "epss_matches": 0,
            "cves_checked": 0,
        }

    kev = fetch_kev(timeout=timeout)
    epss = fetch_epss(all_cves, timeout=timeout)
    result = _enrich_from_maps(db, kev, epss)
    result["cves_checked"] = len(all_cves)
    return result
