"""
Migration 0021: Add serial_number column to hosts table.

Stores the device serial number collected on-demand via SSH
(show version | include System Serial Number).  Column is empty
until populated by the POST /api/hosts/{id}/fetch-serial endpoint.
"""

from __future__ import annotations

import os

VERSION = 21
DESCRIPTION = "Add serial_number to hosts"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        "ALTER TABLE hosts ADD COLUMN serial_number TEXT NOT NULL DEFAULT ''"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        "ALTER TABLE hosts ADD COLUMN serial_number TEXT NOT NULL DEFAULT ''"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
