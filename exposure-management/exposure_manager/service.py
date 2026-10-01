from __future__ import annotations

import hashlib
import json
import uuid
from datetime import date, datetime, timezone
from pathlib import Path

from .database import Database
from .importers import load_findings
from .models import VALID_STATUSES, NormalizedFinding
from .scoring import calculate_risk, due_date, normalize_severity


ACTIVE_STATUSES = {"open", "in_progress"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _exception_active(until: str | None) -> bool:
    if not until:
        return False
    try:
        return date.fromisoformat(until) >= date.today()
    except ValueError:
        return False


class ExposureManager:
    def __init__(self, database_path: str | Path) -> None:
        self.db = Database(database_path)

    @staticmethod
    def fingerprint(source: str, scope: str, item: NormalizedFinding) -> str:
        identity = item.external_id.strip() or item.title.strip().lower()
        payload = "|".join(
            [
                source.strip().lower(),
                scope.strip().lower(),
                item.asset.strip().lower(),
                identity,
                str(item.port or ""),
                item.protocol.strip().lower(),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def import_scan(
        self,
        path: str | Path,
        *,
        fmt: str = "auto",
        source: str | None = None,
        scope: str = "default",
        verification_misses: int = 2,
    ) -> dict:
        if verification_misses < 1:
            raise ValueError("verification_misses must be at least 1")

        selected_format, items = load_findings(path, fmt)
        source_name = (source or selected_format).strip().lower()
        scope_name = scope.strip() or "default"
        scan_id = uuid.uuid4().hex
        started = utc_now()
        self.db.create_scan(scan_id, source_name, scope_name, started)

        seen: set[str] = set()
        created = 0
        updated = 0
        reopened = 0

        try:
            for item in items:
                if not item.asset.strip():
                    item.asset = "unknown"
                item.severity = normalize_severity(item.severity)

                asset = self.db.upsert_asset(
                    item.asset.strip(),
                    started,
                    name=item.hostname or item.asset,
                    address=item.address,
                    hostname=item.hostname,
                )
                score, band = calculate_risk(
                    item.severity,
                    cvss=item.cvss,
                    criticality=int(asset["criticality"]),
                    internet_exposed=bool(asset["internet_exposed"]),
                    exploit_available=item.exploit_available,
                    known_exploited=item.known_exploited,
                )
                fingerprint = self.fingerprint(source_name, scope_name, item)
                seen.add(fingerprint)
                existing = self.db.finding_by_fingerprint(fingerprint)

                if existing:
                    status = existing["status"]
                    verified_at = existing["verified_at"]
                    action = "seen_again"

                    if status == "resolved":
                        status = "open"
                        verified_at = None
                        reopened += 1
                        action = "reopened"
                    elif status == "accepted_risk" and not _exception_active(existing["exception_until"]):
                        status = "open"
                        action = "risk_exception_expired"
                    elif status == "false_positive":
                        status = "false_positive"

                    candidate_due = due_date(existing["first_seen"], band)
                    current_due = existing["due_at"]
                    if current_due and current_due < candidate_due:
                        candidate_due = current_due

                    self.db.update_finding(
                        int(existing["id"]),
                        {
                            "asset_id": asset["id"],
                            "external_id": item.external_id,
                            "title": item.title,
                            "severity": item.severity,
                            "cvss": item.cvss,
                            "description": item.description,
                            "remediation": item.remediation,
                            "port": item.port,
                            "protocol": item.protocol,
                            "service": item.service,
                            "status": status,
                            "risk_score": score,
                            "risk_band": band,
                            "last_seen": started,
                            "due_at": candidate_due,
                            "verified_at": verified_at,
                            "exploit_available": int(item.exploit_available),
                            "known_exploited": int(item.known_exploited),
                            "consecutive_misses": 0,
                            "last_scan_id": scan_id,
                            "metadata_json": self.db.metadata_json(item.metadata),
                        },
                    )
                    self.db.add_history(
                        int(existing["id"]),
                        started,
                        action,
                        f"Observed in scan {scan_id}",
                    )
                    updated += 1
                else:
                    finding_id = self.db.insert_finding(
                        {
                            "fingerprint": fingerprint,
                            "asset_id": asset["id"],
                            "source": source_name,
                            "scope": scope_name,
                            "external_id": item.external_id,
                            "title": item.title,
                            "severity": item.severity,
                            "cvss": item.cvss,
                            "description": item.description,
                            "remediation": item.remediation,
                            "port": item.port,
                            "protocol": item.protocol,
                            "service": item.service,
                            "status": "open",
                            "risk_score": score,
                            "risk_band": band,
                            "owner": "",
                            "first_seen": started,
                            "last_seen": started,
                            "due_at": due_date(started, band),
                            "verified_at": None,
                            "exception_until": None,
                            "exception_reason": "",
                            "exploit_available": int(item.exploit_available),
                            "known_exploited": int(item.known_exploited),
                            "consecutive_misses": 0,
                            "last_scan_id": scan_id,
                            "metadata_json": self.db.metadata_json(item.metadata),
                        }
                    )
                    self.db.add_history(
                        finding_id,
                        started,
                        "created",
                        f"Imported from {source_name} scan {scan_id}",
                    )
                    created += 1

            verified = self._apply_rescan_verification(
                source_name,
                scope_name,
                scan_id,
                seen,
                verification_misses,
                started,
            )
            self.db.finish_scan(scan_id, utc_now(), len(items), "completed")
        except Exception:
            self.db.finish_scan(scan_id, utc_now(), 0, "failed")
            raise

        return {
            "scan_id": scan_id,
            "format": selected_format,
            "source": source_name,
            "scope": scope_name,
            "imported": len(items),
            "created": created,
            "updated": updated,
            "reopened": reopened,
            "verified_resolved": verified,
        }

    def _apply_rescan_verification(
        self,
        source: str,
        scope: str,
        scan_id: str,
        seen: set[str],
        verification_misses: int,
        now: str,
    ) -> int:
        verified = 0

        for finding in self.db.findings_for_source_scope(source, scope):
            if finding["fingerprint"] in seen:
                continue

            status = finding["status"]
            if status == "accepted_risk" and _exception_active(finding["exception_until"]):
                continue
            if status in {"resolved", "false_positive"}:
                continue

            misses = int(finding["consecutive_misses"] or 0) + 1
            values = {"consecutive_misses": misses}

            if misses >= verification_misses:
                values.update(
                    {
                        "status": "resolved",
                        "verified_at": now,
                    }
                )
                self.db.add_history(
                    int(finding["id"]),
                    now,
                    "verified_resolved",
                    f"Not observed in {misses} consecutive complete {source} scans for scope {scope}",
                )
                verified += 1
            else:
                self.db.add_history(
                    int(finding["id"]),
                    now,
                    "verification_miss",
                    f"Not observed in scan {scan_id}; miss {misses}/{verification_misses}",
                )

            self.db.update_finding(int(finding["id"]), values)

        return verified

    def set_asset_context(
        self,
        asset_key: str,
        *,
        criticality: int | None = None,
        internet_exposed: bool | None = None,
        owner: str | None = None,
        environment: str | None = None,
    ) -> dict:
        asset = self.db.set_asset_context(
            asset_key,
            criticality=criticality,
            internet_exposed=internet_exposed,
            owner=owner,
            environment=environment,
        )
        self._recalculate_asset_findings(asset)
        return self.db.get_asset(asset_key) or asset

    def _recalculate_asset_findings(self, asset: dict) -> None:
        now = utc_now()
        for finding in self.db.findings_for_asset(int(asset["id"])):
            score, band = calculate_risk(
                finding["severity"],
                cvss=finding["cvss"],
                criticality=int(asset["criticality"]),
                internet_exposed=bool(asset["internet_exposed"]),
                exploit_available=bool(finding["exploit_available"]),
                known_exploited=bool(finding["known_exploited"]),
            )
            candidate_due = due_date(finding["first_seen"], band)
            current_due = finding["due_at"]
            if current_due and current_due < candidate_due:
                candidate_due = current_due

            self.db.update_finding(
                int(finding["id"]),
                {
                    "risk_score": score,
                    "risk_band": band,
                    "due_at": candidate_due,
                },
            )
            self.db.add_history(
                int(finding["id"]),
                now,
                "risk_recalculated",
                f"Asset context changed; risk={score} ({band})",
            )

    def set_finding(
        self,
        finding_id: int,
        *,
        status: str | None = None,
        owner: str | None = None,
    ) -> dict:
        finding = self.db.get_finding(finding_id)
        if not finding:
            raise KeyError(f"finding not found: {finding_id}")

        values = {}
        action_bits = []

        if status is not None:
            if status not in VALID_STATUSES:
                raise ValueError(f"invalid status: {status}")
            if status == "accepted_risk":
                raise ValueError("use accept_risk to set an exception expiry and reason")
            values["status"] = status
            if status != "resolved":
                values["verified_at"] = None
            action_bits.append(f"status={status}")

        if owner is not None:
            values["owner"] = owner
            action_bits.append(f"owner={owner}")

        if not values:
            raise ValueError("no finding fields were supplied")

        self.db.update_finding(finding_id, values)
        self.db.add_history(finding_id, utc_now(), "updated", ", ".join(action_bits))
        return self.db.get_finding(finding_id) or {}

    def accept_risk(self, finding_id: int, until: str, reason: str) -> dict:
        try:
            expiry = date.fromisoformat(until)
        except ValueError as error:
            raise ValueError("until must use YYYY-MM-DD") from error

        if expiry < date.today():
            raise ValueError("risk exception expiry cannot be in the past")
        if not reason.strip():
            raise ValueError("risk exception requires a reason")
        if not self.db.get_finding(finding_id):
            raise KeyError(f"finding not found: {finding_id}")

        self.db.update_finding(
            finding_id,
            {
                "status": "accepted_risk",
                "exception_until": until,
                "exception_reason": reason.strip(),
                "verified_at": None,
            },
        )
        self.db.add_history(
            finding_id,
            utc_now(),
            "risk_accepted",
            f"Until {until}: {reason.strip()}",
        )
        return self.db.get_finding(finding_id) or {}

    def remediation_queue(self, limit: int = 100) -> list[dict]:
        now = utc_now()
        findings = self.db.list_findings(limit=5000)
        queue = []

        for finding in findings:
            status = finding["status"]
            if status not in ACTIVE_STATUSES:
                if status == "accepted_risk" and not _exception_active(finding["exception_until"]):
                    pass
                else:
                    continue

            item = dict(finding)
            due_at = item.get("due_at") or ""
            item["overdue"] = bool(due_at and due_at < now)
            queue.append(item)

        queue.sort(
            key=lambda row: (
                int(bool(row["overdue"])),
                int(row["risk_score"]),
                row["last_seen"],
            ),
            reverse=True,
        )
        return queue[:limit]

    def summary(self) -> dict:
        summary = self.db.summary()
        queue = self.remediation_queue(limit=5000)
        summary["active"] = len(queue)
        summary["overdue"] = sum(1 for item in queue if item["overdue"])
        summary["top_risk"] = [
            {
                "id": item["id"],
                "asset": item["asset_key"],
                "title": item["title"],
                "risk_score": item["risk_score"],
                "risk_band": item["risk_band"],
            }
            for item in queue[:5]
        ]
        return summary

    def export_finding(self, finding_id: int) -> dict:
        finding = self.db.get_finding(finding_id)
        if not finding:
            raise KeyError(f"finding not found: {finding_id}")

        payload = dict(finding)
        try:
            payload["metadata"] = json.loads(payload.pop("metadata_json") or "{}")
        except json.JSONDecodeError:
            payload["metadata"] = {}
        payload["history"] = self.db.history(finding_id)
        return payload
