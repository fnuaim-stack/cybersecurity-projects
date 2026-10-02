from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT 'unknown',
    criticality INTEGER NOT NULL DEFAULT 3,
    internet_exposed INTEGER NOT NULL DEFAULT 0,
    owner TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    scope TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    imported_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    asset_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    scope TEXT NOT NULL,
    external_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss REAL,
    description TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    port INTEGER,
    protocol TEXT NOT NULL DEFAULT '',
    service TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_band TEXT NOT NULL DEFAULT 'info',
    owner TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    due_at TEXT,
    verified_at TEXT,
    exception_until TEXT,
    exception_reason TEXT NOT NULL DEFAULT '',
    exploit_available INTEGER NOT NULL DEFAULT 0,
    known_exploited INTEGER NOT NULL DEFAULT 0,
    consecutive_misses INTEGER NOT NULL DEFAULT 0,
    last_scan_id TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(asset_id) REFERENCES assets(id),
    FOREIGN KEY(last_scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS finding_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(finding_id) REFERENCES findings(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_source_scope ON findings(source, scope);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_history_finding ON finding_history(finding_id);
"""


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def create_scan(self, scan_id: str, source: str, scope: str, started_at: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO scans(id, source, scope, started_at) VALUES(?,?,?,?)",
                (scan_id, source, scope, started_at),
            )

    def finish_scan(self, scan_id: str, completed_at: str, imported_count: int, status: str = "completed") -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE scans SET completed_at=?, imported_count=?, status=? WHERE id=?",
                (completed_at, imported_count, status, scan_id),
            )

    def upsert_asset(
        self,
        asset_key: str,
        now: str,
        *,
        name: str = "",
        address: str = "",
        hostname: str = "",
    ) -> dict:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO assets(asset_key, name, address, hostname, first_seen, last_seen)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(asset_key) DO UPDATE SET
                    name=CASE WHEN excluded.name <> '' THEN excluded.name ELSE assets.name END,
                    address=CASE WHEN excluded.address <> '' THEN excluded.address ELSE assets.address END,
                    hostname=CASE WHEN excluded.hostname <> '' THEN excluded.hostname ELSE assets.hostname END,
                    last_seen=excluded.last_seen
                """,
                (asset_key, name, address, hostname, now, now),
            )
            row = conn.execute(
                "SELECT * FROM assets WHERE asset_key=?",
                (asset_key,),
            ).fetchone()
            return dict(row)

    def set_asset_context(
        self,
        asset_key: str,
        *,
        criticality: int | None = None,
        internet_exposed: bool | None = None,
        owner: str | None = None,
        environment: str | None = None,
    ) -> dict:
        fields = []
        values = []

        if criticality is not None:
            if criticality < 1 or criticality > 5:
                raise ValueError("criticality must be between 1 and 5")
            fields.append("criticality=?")
            values.append(criticality)
        if internet_exposed is not None:
            fields.append("internet_exposed=?")
            values.append(int(bool(internet_exposed)))
        if owner is not None:
            fields.append("owner=?")
            values.append(owner)
        if environment is not None:
            fields.append("environment=?")
            values.append(environment)

        if not fields:
            raise ValueError("no asset fields were supplied")

        with self.connect() as conn:
            row = conn.execute(
                "SELECT id FROM assets WHERE asset_key=?",
                (asset_key,),
            ).fetchone()
            if not row:
                raise KeyError(f"asset not found: {asset_key}")

            values.append(asset_key)
            conn.execute(
                f"UPDATE assets SET {', '.join(fields)} WHERE asset_key=?",
                values,
            )
            updated = conn.execute(
                "SELECT * FROM assets WHERE asset_key=?",
                (asset_key,),
            ).fetchone()
            return dict(updated)

    def get_asset(self, asset_key: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM assets WHERE asset_key=?",
                (asset_key,),
            ).fetchone()
            return dict(row) if row else None

    def list_assets(self) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT a.*,
                       COUNT(f.id) AS finding_count,
                       SUM(CASE WHEN f.status IN ('open','in_progress') THEN 1 ELSE 0 END) AS active_findings
                FROM assets a
                LEFT JOIN findings f ON f.asset_id=a.id
                GROUP BY a.id
                ORDER BY active_findings DESC, a.asset_key
                """
            ).fetchall()
            return [dict(row) for row in rows]

    def finding_by_fingerprint(self, fingerprint: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE fingerprint=?",
                (fingerprint,),
            ).fetchone()
            return dict(row) if row else None

    def get_finding(self, finding_id: int) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT f.*, a.asset_key, a.name AS asset_name, a.address,
                       a.hostname, a.environment, a.criticality,
                       a.internet_exposed, a.owner AS asset_owner
                FROM findings f
                JOIN assets a ON a.id=f.asset_id
                WHERE f.id=?
                """,
                (finding_id,),
            ).fetchone()
            return dict(row) if row else None

    def insert_finding(self, values: dict) -> int:
        columns = list(values)
        placeholders = ",".join("?" for _ in columns)
        with self.connect() as conn:
            cur = conn.execute(
                f"INSERT INTO findings({','.join(columns)}) VALUES({placeholders})",
                [values[column] for column in columns],
            )
            return int(cur.lastrowid)

    def update_finding(self, finding_id: int, values: dict) -> None:
        if not values:
            return
        columns = list(values)
        assignments = ",".join(f"{column}=?" for column in columns)
        with self.connect() as conn:
            conn.execute(
                f"UPDATE findings SET {assignments} WHERE id=?",
                [values[column] for column in columns] + [finding_id],
            )

    def add_history(self, finding_id: int, timestamp: str, action: str, details: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO finding_history(finding_id,timestamp,action,details) VALUES(?,?,?,?)",
                (finding_id, timestamp, action, details),
            )

    def history(self, finding_id: int) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM finding_history WHERE finding_id=? ORDER BY id",
                (finding_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def findings_for_source_scope(self, source: str, scope: str) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE source=? AND scope=?",
                (source, scope),
            ).fetchall()
            return [dict(row) for row in rows]

    def findings_for_asset(self, asset_id: int) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE asset_id=?",
                (asset_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def list_findings(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        source: str | None = None,
        owner: str | None = None,
        min_risk: int | None = None,
        query: str | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> list[dict]:
        where = []
        args: list[object] = []

        filters = {
            "f.status": status,
            "f.severity": severity,
            "f.source": source,
            "f.owner": owner,
        }
        for column, value in filters.items():
            if value:
                where.append(f"{column}=?")
                args.append(value)

        if min_risk is not None:
            where.append("f.risk_score>=?")
            args.append(min_risk)

        if query:
            needle = f"%{query.strip()}%"
            where.append(
                "(f.title LIKE ? OR f.external_id LIKE ? OR f.description LIKE ? "
                "OR a.asset_key LIKE ? OR a.hostname LIKE ? OR f.owner LIKE ?)"
            )
            args.extend([needle] * 6)

        clause = " WHERE " + " AND ".join(where) if where else ""
        args.extend([limit, max(0, offset)])

        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT f.*, a.asset_key, a.name AS asset_name, a.address,
                       a.hostname, a.environment, a.criticality,
                       a.internet_exposed, a.owner AS asset_owner
                FROM findings f
                JOIN assets a ON a.id=f.asset_id
                {clause}
                ORDER BY f.risk_score DESC, f.last_seen DESC
                LIMIT ? OFFSET ?
                """,
                args,
            ).fetchall()
            return [dict(row) for row in rows]

    def list_scans(self, limit: int = 50) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]

    def summary(self) -> dict:
        with self.connect() as conn:
            status_rows = conn.execute(
                "SELECT status, COUNT(*) AS count FROM findings GROUP BY status"
            ).fetchall()
            band_rows = conn.execute(
                """
                SELECT risk_band, COUNT(*) AS count
                FROM findings
                WHERE status IN ('open','in_progress')
                GROUP BY risk_band
                """
            ).fetchall()
            source_rows = conn.execute(
                "SELECT source, COUNT(*) AS count FROM findings GROUP BY source"
            ).fetchall()
            asset_count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            finding_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

        return {
            "assets": asset_count,
            "findings": finding_count,
            "by_status": {row["status"]: row["count"] for row in status_rows},
            "active_by_risk": {row["risk_band"]: row["count"] for row in band_rows},
            "by_source": {row["source"]: row["count"] for row in source_rows},
        }

    @staticmethod
    def metadata_json(value: dict) -> str:
        return json.dumps(value or {}, sort_keys=True, default=str)
