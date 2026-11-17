"""
Migration 0097: dynamic groups (saved host filters).

Adds:

  - dynamic_groups - a named, saved host filter that resolves to the hosts
    matching it whenever it is used: ``name`` (unique ignoring case),
    ``description``, ``object_type`` (``host``; the only type for now),
    ``filter`` (the validated filter definition as JSONB, see
    ``netcontrol.dynamic_groups``), ``created_by`` and the ``created_at`` /
    ``updated_at`` / ``updated_by`` stamps.
  - jobs gain ``dynamic_group_id``: a job launched against a dynamic group
    resolves its hosts when the queue starts it, not at launch. Deleting the
    dynamic group clears the column, so a queued job that targeted it fails
    with "no hosts" instead of running against something else.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 97
DESCRIPTION = "Add dynamic groups (saved host filters) and job targeting by dynamic group"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS dynamic_groups (
            id          SERIAL PRIMARY KEY,
            name        TEXT  NOT NULL,
            description TEXT  NOT NULL DEFAULT '',
            object_type TEXT  NOT NULL DEFAULT 'host',
            filter      JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_by  TEXT  NOT NULL DEFAULT '',
            created_at  TEXT  NOT NULL DEFAULT '',
            updated_at  TEXT  NOT NULL DEFAULT '',
            updated_by  TEXT  NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_dynamic_groups_name_lower ON dynamic_groups (lower(name))")
    await db.execute(
        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS dynamic_group_id INTEGER "
        "REFERENCES dynamic_groups(id) ON DELETE SET NULL"
    )
    await db.commit()
