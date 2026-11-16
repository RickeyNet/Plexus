"""
Migration 0093: Git repositories as data sources.

Adds:

  - git_sources - one Git repository Plexus clones and imports from: a
    ``name`` (unique ignoring case), the ``remote_url`` (https or ssh, never
    with credentials in it), the ``branch``, an optional service credential
    (``credential_id``, cleared when the credential is deleted), the content
    types it ``provides`` (a JSON list of ``templates``, ``playbooks`` and
    ``config_contexts``), ``sync_interval_minutes`` (``0``: only on demand),
    ``enabled``, and the outcome of the newest sync: ``status`` (``never``,
    ``syncing``, ``ok``, ``warning``, ``error``), ``error``,
    ``last_commit`` (the HEAD SHA imported), ``last_attempt_at``,
    ``last_synced_at`` (the newest successful sync) and ``summary`` (JSON
    counts and per-file warnings).
  - templates / playbooks / config_contexts gain ``git_source_id`` (the
    source that owns the record; NULL for records written in Plexus),
    ``git_path`` (the file in the repository) and ``git_commit`` (the commit
    it was last imported from). A record a source owns is read-only in the
    API and removed when its file leaves the repository.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 93
DESCRIPTION = "Add Git data sources and source ownership of templates, playbooks and config contexts"

_OWNED_TABLES = ("templates", "playbooks", "config_contexts")


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS git_sources (
            id                    SERIAL PRIMARY KEY,
            name                  TEXT    NOT NULL,
            remote_url            TEXT    NOT NULL,
            branch                TEXT    NOT NULL DEFAULT 'main',
            credential_id         INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
            provides              TEXT    NOT NULL DEFAULT '[]',
            sync_interval_minutes INTEGER NOT NULL DEFAULT 0,
            enabled               INTEGER NOT NULL DEFAULT 1,
            status                TEXT    NOT NULL DEFAULT 'never',
            error                 TEXT    NOT NULL DEFAULT '',
            last_commit           TEXT    NOT NULL DEFAULT '',
            last_attempt_at       TEXT    NOT NULL DEFAULT '',
            last_synced_at        TEXT    NOT NULL DEFAULT '',
            summary               TEXT    NOT NULL DEFAULT '{}',
            created_at            TEXT    NOT NULL DEFAULT '',
            updated_at            TEXT    NOT NULL DEFAULT '',
            updated_by            TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_git_sources_name_lower ON git_sources (lower(name))")
    for table in _OWNED_TABLES:
        await db.execute(
            f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS git_source_id INTEGER "
            "REFERENCES git_sources(id) ON DELETE SET NULL"
        )
        await db.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS git_path TEXT NOT NULL DEFAULT ''")
        await db.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS git_commit TEXT NOT NULL DEFAULT ''")
        await db.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_git_source ON {table} (git_source_id)")
    await db.commit()
