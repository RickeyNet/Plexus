"""
Migration 0066: Cato Networks accounts in the topology.

Adds:
  - meraki_orgs.provider - which integration an entry belongs to: "meraki"
    (a Dashboard organization, the default for every existing row) or "cato"
    (a Cato account). A Cato account is stored, collected and merged into the
    map exactly like an organization, so it shares the organization and
    snapshot tables; only the collector that runs differs.
"""

from __future__ import annotations

import os

VERSION = 66
DESCRIPTION = "Add meraki_orgs.provider for Cato Networks accounts"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _column_exists_sqlite(db) -> bool:
    cursor = await db.execute("PRAGMA table_info(meraki_orgs)")
    rows = await cursor.fetchall()
    return any(row[1] == "provider" for row in rows)


async def _up_sqlite(db) -> None:
    if await _column_exists_sqlite(db):
        return
    await db.execute("ALTER TABLE meraki_orgs ADD COLUMN provider TEXT NOT NULL DEFAULT 'meraki'")
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute("ALTER TABLE meraki_orgs ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'meraki'")
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
