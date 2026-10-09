"""
Migration 0022: Add scheduled_at column to upgrade_campaigns table.

Persists the target activation time for scheduled upgrade campaigns so that
tasks can be rehydrated after a server restart instead of being silently lost.
"""

from __future__ import annotations

VERSION = 22
DESCRIPTION = "Add scheduled_at to upgrade_campaigns"


async def up(db) -> None:
    await db.execute("ALTER TABLE upgrade_campaigns ADD COLUMN scheduled_at TIMESTAMPTZ")
    await db.commit()
