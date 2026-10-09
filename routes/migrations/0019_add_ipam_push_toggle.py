"""
Migration 0019: add per-source IPAM push toggle.

Adds:
  - ipam_sources.push_enabled (default off)
"""

from __future__ import annotations

VERSION = 19
DESCRIPTION = "Add per-source IPAM push toggle"


async def up(db) -> None:
    await db.execute(
        """
        ALTER TABLE ipam_sources
        ADD COLUMN IF NOT EXISTS push_enabled INTEGER NOT NULL DEFAULT 0
        """
    )
    await db.commit()
