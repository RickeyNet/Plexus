"""
Migration 0022: Add scheduled_at column to upgrade_campaigns table.

Persists the target activation time for scheduled upgrade campaigns so that
tasks can be rehydrated after a server restart instead of being silently lost.
"""

from __future__ import annotations

import os

VERSION = 22
DESCRIPTION = "Add scheduled_at to upgrade_campaigns"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        "ALTER TABLE upgrade_campaigns ADD COLUMN scheduled_at TEXT"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        "ALTER TABLE upgrade_campaigns ADD COLUMN scheduled_at TIMESTAMPTZ"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
