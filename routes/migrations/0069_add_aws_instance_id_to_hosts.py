"""
Migration 0069: Add an explicit AWS instance ID to hosts.

The AWS topology recognises an inventory host as an EC2 instance by its
addresses. ``aws_instance_id`` names the instance outright (``i-0abc...``)
and is checked before any address match, for hosts whose inventory address
is not one AWS records (a NAT or load-balanced address, a DNS name's IP).

Existing rows default to ``''`` (no override).
"""

from __future__ import annotations

import os

VERSION = 69
DESCRIPTION = "Add aws_instance_id to hosts"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"

_COLUMN = "aws_instance_id"
_DECL = "TEXT NOT NULL DEFAULT ''"


async def _column_exists_sqlite(db, name: str) -> bool:
    cursor = await db.execute("PRAGMA table_info(hosts)")
    rows = await cursor.fetchall()
    return any(row[1] == name for row in rows)


async def _up_sqlite(db) -> None:
    if not await _column_exists_sqlite(db, _COLUMN):
        await db.execute(f"ALTER TABLE hosts ADD COLUMN {_COLUMN} {_DECL}")
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(f"ALTER TABLE hosts ADD COLUMN IF NOT EXISTS {_COLUMN} {_DECL}")
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
