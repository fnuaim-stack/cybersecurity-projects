from __future__ import annotations

import fnmatch
import json
import uuid
from datetime import datetime, timedelta, timezone


SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL,
    target TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'default',
    ports TEXT NOT NULL DEFAULT 'quick',
    partial INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_schedules (
    id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    interval_hours INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    next_run_at TEXT NOT NULL,
    last_run_at TEXT,
    last_job_id TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(profile_id) REFERENCES scan_profiles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS finding_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    author TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS suppression_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_pattern TEXT NOT NULL DEFAULT '*',
    asset_pattern TEXT NOT NULL DEFAULT '*',
    title_pattern TEXT NOT NULL DEFAULT '*',
    external_id_pattern TEXT NOT NULL DEFAULT '*',
    reason TEXT NOT NULL,
    expires_at TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_tags (
    asset_key TEXT NOT NULL,
    tag TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(asset_key, tag)
);

CREATE TABLE IF NOT EXISTS platform_settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _active_expiry(value: str | None) -> bool:
    if not value:
        return True
    try:
        expiry = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry >= datetime.now(timezone.utc)


class PlatformStore:
    def __init__(self, db) -> None:
        self.db = db
        with self.db.connect() as conn:
            conn.executescript(SCHEMA)

    # Scan profiles and schedules
    def create_profile(self, *, name: str, provider: str, target: str, scope: str, ports: str, partial: bool) -> dict:
        if not name.strip():
            raise ValueError("Profile name is required.")
        profile_id = uuid.uuid4().hex[:12]
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_profiles(id,name,provider,target,scope,ports,partial,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (profile_id, name.strip(), provider, target, scope or "default", ports or "quick", int(partial), now, now),
            )
        return self.get_profile(profile_id)

    def update_profile(self, profile_id: str, *, name: str, provider: str, target: str, scope: str, ports: str, partial: bool) -> dict:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE scan_profiles
                SET name=?,provider=?,target=?,scope=?,ports=?,partial=?,updated_at=?
                WHERE id=?
                """,
                (name.strip(), provider, target, scope or "default", ports or "quick", int(partial), utc_now(), profile_id),
            )
        return self.get_profile(profile_id)

    def delete_profile(self, profile_id: str) -> None:
        with self.db.connect() as conn:
            conn.execute("DELETE FROM scan_profiles WHERE id=?", (profile_id,))

    def get_profile(self, profile_id: str) -> dict:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM scan_profiles WHERE id=?", (profile_id,)).fetchone()
        if not row:
            raise KeyError(f"profile not found: {profile_id}")
        return dict(row)

    def list_profiles(self) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT p.*,
                       COUNT(s.id) AS schedule_count,
                       SUM(CASE WHEN s.enabled=1 THEN 1 ELSE 0 END) AS enabled_schedules
                FROM scan_profiles p
                LEFT JOIN scan_schedules s ON s.profile_id=p.id
                GROUP BY p.id
                ORDER BY p.name
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def create_schedule(self, profile_id: str, *, interval_hours: int, run_immediately: bool = False) -> dict:
        if interval_hours < 1 or interval_hours > 24 * 30:
            raise ValueError("Schedule interval must be between 1 hour and 30 days.")
        self.get_profile(profile_id)
        now = datetime.now(timezone.utc)
        next_run = now if run_immediately else now + timedelta(hours=interval_hours)
        schedule_id = uuid.uuid4().hex[:12]
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_schedules(id,profile_id,interval_hours,enabled,next_run_at,created_at)
                VALUES(?,?,?,?,?,?)
                """,
                (schedule_id, profile_id, interval_hours, 1, next_run.isoformat(), now.isoformat()),
            )
        return self.get_schedule(schedule_id)

    def get_schedule(self, schedule_id: str) -> dict:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT s.*,p.name AS profile_name,p.provider,p.target,p.scope,p.ports,p.partial
                FROM scan_schedules s
                JOIN scan_profiles p ON p.id=s.profile_id
                WHERE s.id=?
                """,
                (schedule_id,),
            ).fetchone()
        if not row:
            raise KeyError(f"schedule not found: {schedule_id}")
        return dict(row)

    def list_schedules(self) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT s.*,p.name AS profile_name,p.provider,p.target,p.scope,p.ports,p.partial
                FROM scan_schedules s
                JOIN scan_profiles p ON p.id=s.profile_id
                ORDER BY s.enabled DESC,s.next_run_at
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def due_schedules(self) -> list[dict]:
        now = utc_now()
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT s.*,p.name AS profile_name,p.provider,p.target,p.scope,p.ports,p.partial
                FROM scan_schedules s
                JOIN scan_profiles p ON p.id=s.profile_id
                WHERE s.enabled=1 AND s.next_run_at<=?
                ORDER BY s.next_run_at
                """,
                (now,),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_schedule_run(self, schedule_id: str, job_id: str) -> dict:
        schedule = self.get_schedule(schedule_id)
        now = datetime.now(timezone.utc)
        next_run = now + timedelta(hours=int(schedule["interval_hours"]))
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE scan_schedules
                SET last_run_at=?,last_job_id=?,next_run_at=?
                WHERE id=?
                """,
                (now.isoformat(), job_id, next_run.isoformat(), schedule_id),
            )
        return self.get_schedule(schedule_id)

    def set_schedule_enabled(self, schedule_id: str, enabled: bool) -> dict:
        with self.db.connect() as conn:
            conn.execute("UPDATE scan_schedules SET enabled=? WHERE id=?", (int(enabled), schedule_id))
        return self.get_schedule(schedule_id)

    def delete_schedule(self, schedule_id: str) -> None:
        with self.db.connect() as conn:
            conn.execute("DELETE FROM scan_schedules WHERE id=?", (schedule_id,))

    # Notes
    def add_note(self, finding_id: int, note: str, author: str = "") -> dict:
        if not note.strip():
            raise ValueError("Note cannot be empty.")
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                "INSERT INTO finding_notes(finding_id,author,note,created_at) VALUES(?,?,?,?)",
                (finding_id, author.strip(), note.strip(), now),
            )
            row = conn.execute("SELECT * FROM finding_notes WHERE id=?", (cur.lastrowid,)).fetchone()
        self.db.add_history(finding_id, now, "note_added", note.strip()[:240])
        return dict(row)

    def notes(self, finding_id: int) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM finding_notes WHERE finding_id=? ORDER BY id DESC",
                (finding_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    # Suppression rules
    def create_suppression(
        self,
        *,
        name: str,
        source_pattern: str = "*",
        asset_pattern: str = "*",
        title_pattern: str = "*",
        external_id_pattern: str = "*",
        reason: str,
        expires_at: str | None = None,
    ) -> dict:
        if not name.strip() or not reason.strip():
            raise ValueError("Suppression name and reason are required.")
        rule_id = uuid.uuid4().hex[:12]
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO suppression_rules(
                    id,name,source_pattern,asset_pattern,title_pattern,external_id_pattern,
                    reason,expires_at,enabled,created_at
                ) VALUES(?,?,?,?,?,?,?,?,1,?)
                """,
                (
                    rule_id, name.strip(), source_pattern or "*", asset_pattern or "*",
                    title_pattern or "*", external_id_pattern or "*", reason.strip(),
                    expires_at or None, utc_now(),
                ),
            )
        return self.get_suppression(rule_id)

    def get_suppression(self, rule_id: str) -> dict:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM suppression_rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            raise KeyError(f"suppression rule not found: {rule_id}")
        return dict(row)

    def list_suppressions(self) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM suppression_rules ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]

    def set_suppression_enabled(self, rule_id: str, enabled: bool) -> dict:
        with self.db.connect() as conn:
            conn.execute("UPDATE suppression_rules SET enabled=? WHERE id=?", (int(enabled), rule_id))
        return self.get_suppression(rule_id)

    def matching_suppression(self, finding: dict) -> dict | None:
        source = str(finding.get("source") or "").lower()
        asset = str(finding.get("asset_key") or "").lower()
        title = str(finding.get("title") or "").lower()
        external_id = str(finding.get("external_id") or "").lower()
        for rule in self.list_suppressions():
            if not rule["enabled"] or not _active_expiry(rule["expires_at"]):
                continue
            checks = (
                (source, rule["source_pattern"]),
                (asset, rule["asset_pattern"]),
                (title, rule["title_pattern"]),
                (external_id, rule["external_id_pattern"]),
            )
            if all(fnmatch.fnmatch(value, str(pattern or "*").lower()) for value, pattern in checks):
                return rule
        return None

    def apply_suppression_to_finding(self, finding_id: int) -> dict | None:
        finding = self.db.get_finding(finding_id)
        if not finding or finding["status"] not in {"open", "in_progress"}:
            return None
        rule = self.matching_suppression(finding)
        if not rule:
            return None
        self.db.update_finding(finding_id, {"status": "false_positive", "verified_at": None})
        self.db.add_history(
            finding_id,
            utc_now(),
            "suppressed_by_rule",
            f"{rule['name']}: {rule['reason']}",
        )
        return rule

    def apply_suppressions(self) -> dict:
        matched = 0
        for finding in self.db.list_findings(limit=100000):
            if self.apply_suppression_to_finding(int(finding["id"])):
                matched += 1
        return {"suppressed_findings": matched}

    # Asset tags
    def add_asset_tag(self, asset_key: str, tag: str) -> None:
        value = tag.strip().lower()
        if not value:
            raise ValueError("Tag cannot be empty.")
        if not self.db.get_asset(asset_key):
            raise KeyError(f"asset not found: {asset_key}")
        with self.db.connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO asset_tags(asset_key,tag,created_at) VALUES(?,?,?)",
                (asset_key, value, utc_now()),
            )

    def remove_asset_tag(self, asset_key: str, tag: str) -> None:
        with self.db.connect() as conn:
            conn.execute("DELETE FROM asset_tags WHERE asset_key=? AND tag=?", (asset_key, tag.strip().lower()))

    def tags_for_asset(self, asset_key: str) -> list[str]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT tag FROM asset_tags WHERE asset_key=? ORDER BY tag",
                (asset_key,),
            ).fetchall()
        return [str(row["tag"]) for row in rows]

    def asset_tags_map(self) -> dict[str, list[str]]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT asset_key,tag FROM asset_tags ORDER BY asset_key,tag").fetchall()
        result: dict[str, list[str]] = {}
        for row in rows:
            result.setdefault(str(row["asset_key"]), []).append(str(row["tag"]))
        return result

    # Simple settings
    def set_setting(self, key: str, value) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO platform_settings(key,value_json) VALUES(?,?)
                ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json
                """,
                (key, json.dumps(value)),
            )

    def get_setting(self, key: str, default=None):
        with self.db.connect() as conn:
            row = conn.execute("SELECT value_json FROM platform_settings WHERE key=?", (key,)).fetchone()
        if not row:
            return default
        try:
            return json.loads(row["value_json"])
        except json.JSONDecodeError:
            return default
