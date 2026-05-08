"""
Migration 0035: Add is_service flag to credentials.

Service credentials are used by Plexus itself (monitoring polls, scheduled
SNMP discovery, anything running outside an interactive user request) and
are administratively shared rather than owned by a single user. They are
exposed under /api/credentials/service and are admin-only for both read
and write. User credentials remain strictly per-owner (see
netcontrol/routes/credentials.py).

Existing rows default to is_service = 0, preserving prior per-user
behavior. Admins explicitly mark a credential as a service credential
through Settings.
"""

from __future__ import annotations

import os

VERSION = 35
DESCRIPTION = "Add credentials.is_service flag for service-account credentials"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _column_exists_sqlite(db) -> bool:
    cursor = await db.execute("PRAGMA table_info(credentials)")
    rows = await cursor.fetchall()
    return any(row[1] == "is_service" for row in rows)


async def _up_sqlite(db) -> None:
    if await _column_exists_sqlite(db):
        return
    await db.execute(
        "ALTER TABLE credentials ADD COLUMN is_service INTEGER NOT NULL DEFAULT 0"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        "ALTER TABLE credentials ADD COLUMN IF NOT EXISTS is_service INTEGER NOT NULL DEFAULT 0"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
