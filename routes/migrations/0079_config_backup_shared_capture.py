"""
Migration 0079: one stored configuration per device capture.

Every feature that reads a device's running configuration now goes through
one capture path that stores what it read in ``config_backups``. A capture
reads the plain configuration and, where the platform has it, the form with
default settings included (``show running-config all``), over one session.

  - config_text_full - the configuration with defaults included, or ``''``
    when the platform has no such form. Backup search reads it; restore,
    diffs, drift, compliance and the path trace read ``config_text``.
  - checked_at - when the device last returned this exact configuration.
    A capture that matches the newest backup updates it instead of writing
    a duplicate row, and features that accept a recent configuration (up
    to 15 minutes old) measure age from it.

The search index moves to the column search now reads. It was created both
by migration 0004 and at schema init; both copies are dropped.
"""

from __future__ import annotations

VERSION = 79
DESCRIPTION = "Store the config with defaults and a last-checked time on config backups"


async def up(db) -> None:
    await db.execute("ALTER TABLE config_backups ADD COLUMN IF NOT EXISTS config_text_full TEXT NOT NULL DEFAULT ''")
    await db.execute("ALTER TABLE config_backups ADD COLUMN IF NOT EXISTS checked_at TEXT")
    await db.execute("UPDATE config_backups SET checked_at = captured_at WHERE checked_at IS NULL")
    await db.execute("DROP INDEX IF EXISTS idx_config_backups_fts")
    await db.execute("DROP INDEX IF EXISTS idx_config_backups_search_tsv")
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_config_backups_search_full_tsv
        ON config_backups
        USING GIN (to_tsvector('simple', COALESCE(NULLIF(config_text_full, ''), config_text, '')))
        """
    )
    await db.commit()
