"""
Migration 0004: Add configuration backup search indexes.

Adds a GIN full-text index on config_backups.config_text.

Also adds helper btree indexes used by backup search ordering/filtering.
"""

from __future__ import annotations

VERSION = 4
DESCRIPTION = "Add config backup full-text search indexes"


async def up(db) -> None:
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_config_backups_fts
        ON config_backups
        USING GIN (to_tsvector('simple', COALESCE(config_text, '')))
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_config_backups_host_captured
        ON config_backups(host_id, captured_at DESC)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_config_backups_status_captured
        ON config_backups(status, captured_at DESC)
        """
    )
    await db.commit()
