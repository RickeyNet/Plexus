"""
Migration 0033: Per-user "session never expires" flag for kiosk/display accounts.

Adds:
  - users.session_never_expires — when 1, that user's sessions bypass the
    global idle-timeout enforcement and the absolute lifetime cap. Intended
    for read-only display accounts (smart boards, NOC walls) that need to
    stay logged in indefinitely.
"""

from __future__ import annotations

import os

VERSION = 33
DESCRIPTION = "Add users.session_never_expires for kiosk/display accounts"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _column_exists_sqlite(db) -> bool:
    cursor = await db.execute("PRAGMA table_info(users)")
    rows = await cursor.fetchall()
    return any(row[1] == "session_never_expires" for row in rows)


async def _up_sqlite(db) -> None:
    # SQLite has no IF NOT EXISTS on ADD COLUMN. Fresh deploys created the
    # column from SCHEMA already; only existing v1.0.0 DBs need the alter.
    if await _column_exists_sqlite(db):
        return
    await db.execute(
        "ALTER TABLE users ADD COLUMN session_never_expires INTEGER NOT NULL DEFAULT 0"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS session_never_expires INTEGER NOT NULL DEFAULT 0"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
