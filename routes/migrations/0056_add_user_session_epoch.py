"""
Migration 0056: Add session_epoch to users for server-side session revocation.

Sessions are stateless signed cookies, so before this there was no way to
invalidate an outstanding token: logout only dropped the client cookie, and a
password change / admin reset / role change left captured tokens valid until
the 24h absolute cap. ``session_epoch`` is a per-user counter embedded in each
issued token; ``require_auth`` (and the WebSocket auth path) reject a token
whose epoch is older than the user's current value. Bumping the column
(password change, admin password reset, privilege change) invalidates every
previously-issued session for that user at once.

Existing tokens carry no epoch and are treated as epoch 0; existing rows
default to 0, so no one is logged out by the migration itself - only by a
subsequent revocation event.
"""

from __future__ import annotations

import os

VERSION = 56
DESCRIPTION = "Add session_epoch to users for session revocation"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"

_COLUMN = ("session_epoch", "INTEGER NOT NULL DEFAULT 0")


async def _column_exists_sqlite(db, name: str) -> bool:
    cursor = await db.execute("PRAGMA table_info(users)")
    rows = await cursor.fetchall()
    return any(row[1] == name for row in rows)


async def _up_sqlite(db) -> None:
    name, decl = _COLUMN
    if not await _column_exists_sqlite(db, name):
        await db.execute(f"ALTER TABLE users ADD COLUMN {name} {decl}")
    await db.commit()


async def _up_postgres(db) -> None:
    name, decl = _COLUMN
    await db.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {name} {decl}")
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
