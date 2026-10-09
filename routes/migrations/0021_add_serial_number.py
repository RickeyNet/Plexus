"""
Migration 0021: Add serial_number column to hosts table.

Stores the device serial number collected on-demand via SSH
(show version | include System Serial Number).  Column is empty
until populated by the POST /api/hosts/{id}/fetch-serial endpoint.
"""

from __future__ import annotations

VERSION = 21
DESCRIPTION = "Add serial_number to hosts"


async def up(db) -> None:
    await db.execute("ALTER TABLE hosts ADD COLUMN serial_number TEXT NOT NULL DEFAULT ''")
    await db.commit()
