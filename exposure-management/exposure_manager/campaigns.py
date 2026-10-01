from __future__ import annotations

import uuid
from datetime import datetime, timezone


CAMPAIGN_SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    due_at TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS campaign_findings (
    campaign_id TEXT NOT NULL,
    finding_id INTEGER NOT NULL,
    added_at TEXT NOT NULL,
    PRIMARY KEY(campaign_id, finding_id),
    FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
    FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
);
"""


class CampaignManager:
    def __init__(self, db) -> None:
        self.db = db
        with self.db.connect() as conn:
            conn.executescript(CAMPAIGN_SCHEMA)

    def create(
        self,
        name: str,
        *,
        owner: str = "",
        due_at: str | None = None,
        notes: str = "",
        min_risk: int | None = None,
        severity: str | None = None,
        source: str | None = None,
        finding_owner: str | None = None,
        limit: int = 1000,
    ) -> dict:
        if not name.strip():
            raise ValueError("campaign name is required")

        campaign_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        findings = self.db.list_findings(
            severity=severity,
            source=source,
            owner=finding_owner,
            min_risk=min_risk,
            limit=limit,
        )
        findings = [item for item in findings if item["status"] in {"open", "in_progress"}]

        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO campaigns(id,name,owner,due_at,status,created_at,notes) VALUES(?,?,?,?,?,?,?)",
                (campaign_id, name.strip(), owner, due_at, "open", now, notes),
            )
            conn.executemany(
                "INSERT OR IGNORE INTO campaign_findings(campaign_id,finding_id,added_at) VALUES(?,?,?)",
                [(campaign_id, int(item["id"]), now) for item in findings],
            )

        return self.get(campaign_id)

    def list(self) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT c.*,
                       COUNT(cf.finding_id) AS finding_count,
                       SUM(CASE WHEN f.status IN ('open','in_progress') THEN 1 ELSE 0 END) AS active_findings,
                       SUM(CASE WHEN f.status='resolved' THEN 1 ELSE 0 END) AS resolved_findings
                FROM campaigns c
                LEFT JOIN campaign_findings cf ON cf.campaign_id=c.id
                LEFT JOIN findings f ON f.id=cf.finding_id
                GROUP BY c.id
                ORDER BY c.created_at DESC
                """
            ).fetchall()
            return [dict(row) for row in rows]

    def get(self, campaign_id: str) -> dict:
        with self.db.connect() as conn:
            campaign = conn.execute(
                "SELECT * FROM campaigns WHERE id=?",
                (campaign_id,),
            ).fetchone()
            if not campaign:
                raise KeyError(f"campaign not found: {campaign_id}")

            findings = conn.execute(
                """
                SELECT f.id, f.title, f.status, f.risk_score, f.risk_band,
                       f.owner, f.due_at, a.asset_key
                FROM campaign_findings cf
                JOIN findings f ON f.id=cf.finding_id
                JOIN assets a ON a.id=f.asset_id
                WHERE cf.campaign_id=?
                ORDER BY f.risk_score DESC, f.id
                """,
                (campaign_id,),
            ).fetchall()

        payload = dict(campaign)
        payload["findings"] = [dict(row) for row in findings]
        payload["finding_count"] = len(payload["findings"])
        payload["active_findings"] = sum(
            1 for item in payload["findings"] if item["status"] in {"open", "in_progress"}
        )
        payload["resolved_findings"] = sum(
            1 for item in payload["findings"] if item["status"] == "resolved"
        )
        return payload

    def sync_status(self, campaign_id: str) -> dict:
        campaign = self.get(campaign_id)
        status = "completed" if campaign["finding_count"] and campaign["active_findings"] == 0 else "in_progress"
        if campaign["finding_count"] == 0:
            status = "open"

        with self.db.connect() as conn:
            conn.execute("UPDATE campaigns SET status=? WHERE id=?", (status, campaign_id))

        return self.get(campaign_id)
