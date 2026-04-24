"""
Migration 0019: add per-source IPAM push toggle.

Adds:
  - ipam_sources.push_enabled (default off)
"""

from __future__ import annotations

import os

VERSION = 19
DESCRIPTION = "Add per-source IPAM push toggle"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    cursor = await db.execute("PRAGMA table_info(ipam_sources)")
    rows = await cursor.fetchall()
    cols = {str(r[1]) for r in rows}
    if "push_enabled" not in cols:
        await db.execute(
            "ALTER TABLE ipam_sources ADD COLUMN push_enabled INTEGER NOT NULL DEFAULT 0"
        )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        ALTER TABLE ipam_sources
        ADD COLUMN IF NOT EXISTS push_enabled INTEGER NOT NULL DEFAULT 0
        """
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
