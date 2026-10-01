from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path


ASSET_SCHEMA = """
CREATE TABLE IF NOT EXISTS asset_aliases (
    alias TEXT PRIMARY KEY,
    asset_key TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asset_aliases_asset ON asset_aliases(asset_key);
"""


def _bool(value: str | bool | None) -> bool | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    raise ValueError(f"invalid boolean value: {value}")


class AssetResolver:
    def __init__(self, db) -> None:
        self.db = db
        with self.db.connect() as conn:
            conn.executescript(ASSET_SCHEMA)

    def resolve(self, asset_key: str) -> str:
        key = asset_key.strip()
        if not key:
            return "unknown"
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT asset_key FROM asset_aliases WHERE lower(alias)=lower(?)",
                (key,),
            ).fetchone()
        return str(row["asset_key"]) if row else key

    def add_alias(self, asset_key: str, alias: str) -> dict:
        canonical = asset_key.strip()
        alias_value = alias.strip()
        if not canonical or not alias_value:
            raise ValueError("asset and alias are required")

        now = datetime.now(timezone.utc).isoformat()
        with self.db.connect() as conn:
            existing = conn.execute(
                "SELECT asset_key FROM assets WHERE asset_key=?",
                (canonical,),
            ).fetchone()
            if not existing:
                raise KeyError(f"asset not found: {canonical}")
            conn.execute(
                """
                INSERT INTO asset_aliases(alias,asset_key,created_at)
                VALUES(?,?,?)
                ON CONFLICT(alias) DO UPDATE SET asset_key=excluded.asset_key
                """,
                (alias_value, canonical, now),
            )
        return {"alias": alias_value, "asset_key": canonical}

    def list_aliases(self) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT alias,asset_key,created_at FROM asset_aliases ORDER BY asset_key,alias"
            ).fetchall()
            return [dict(row) for row in rows]

    def import_context_csv(self, path: str | Path) -> dict:
        created = 0
        updated = 0
        aliases = 0
        now = datetime.now(timezone.utc).isoformat()

        with Path(path).open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            for row in csv.DictReader(handle):
                asset = str(row.get("asset") or row.get("asset_key") or "").strip()
                if not asset:
                    continue

                existed = self.db.get_asset(asset) is not None
                self.db.upsert_asset(
                    asset,
                    now,
                    name=str(row.get("name") or asset),
                    address=str(row.get("address") or row.get("ip") or ""),
                    hostname=str(row.get("hostname") or ""),
                )

                kwargs = {}
                if row.get("criticality"):
                    kwargs["criticality"] = int(row["criticality"])
                exposed = _bool(row.get("internet_exposed"))
                if exposed is not None:
                    kwargs["internet_exposed"] = exposed
                if row.get("owner") is not None and row.get("owner") != "":
                    kwargs["owner"] = str(row["owner"])
                if row.get("environment") is not None and row.get("environment") != "":
                    kwargs["environment"] = str(row["environment"])
                if kwargs:
                    self.db.set_asset_context(asset, **kwargs)

                for alias in str(row.get("aliases") or "").split(";"):
                    alias = alias.strip()
                    if alias:
                        self.add_alias(asset, alias)
                        aliases += 1

                if existed:
                    updated += 1
                else:
                    created += 1

        return {"created_assets": created, "updated_assets": updated, "aliases": aliases}
