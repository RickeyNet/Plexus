"""
Migration 0064: Meraki topology - organizations and built snapshots.

Adds:
  - meraki_orgs - one row per Meraki Dashboard organization Plexus can map.
    Holds the (encrypted) Dashboard API key, the API base URL for regional
    clouds, per-org build options, and the outcome of the last build.
  - meraki_topology_snapshots - one row per completed topology build. The
    full positioned node/edge snapshot is stored as JSON so a map can be
    re-opened or re-exported to HTML later without calling Meraki again;
    summary_json duplicates the headline counts so listings never have to
    load the (multi-megabyte) snapshot body.
"""

from __future__ import annotations

import os

VERSION = 64
DESCRIPTION = "Add Meraki topology organization and snapshot tables"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS meraki_orgs (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            name                TEXT    NOT NULL UNIQUE,
            org_id              TEXT    NOT NULL DEFAULT '',
            base_url            TEXT    NOT NULL DEFAULT 'https://api.meraki.com/api/v1',
            api_key_enc         TEXT    NOT NULL DEFAULT '',
            options_json        TEXT    NOT NULL DEFAULT '{}',
            last_build_at       TEXT,
            last_build_status   TEXT    NOT NULL DEFAULT 'never',
            last_build_message  TEXT    NOT NULL DEFAULT '',
            created_by          TEXT    NOT NULL DEFAULT '',
            created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at          TEXT
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS meraki_topology_snapshots (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            org_ref         INTEGER NOT NULL REFERENCES meraki_orgs(id) ON DELETE CASCADE,
            summary_json    TEXT    NOT NULL DEFAULT '{}',
            snapshot_json   TEXT    NOT NULL DEFAULT '{}',
            warning_count   INTEGER NOT NULL DEFAULT 0,
            duration_seconds REAL   NOT NULL DEFAULT 0,
            built_by        TEXT    NOT NULL DEFAULT '',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_meraki_snapshots_org ON meraki_topology_snapshots (org_ref, id)")
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS meraki_orgs (
            id                  SERIAL PRIMARY KEY,
            name                TEXT    NOT NULL UNIQUE,
            org_id              TEXT    NOT NULL DEFAULT '',
            base_url            TEXT    NOT NULL DEFAULT 'https://api.meraki.com/api/v1',
            api_key_enc         TEXT    NOT NULL DEFAULT '',
            options_json        TEXT    NOT NULL DEFAULT '{}',
            last_build_at       TIMESTAMPTZ,
            last_build_status   TEXT    NOT NULL DEFAULT 'never',
            last_build_message  TEXT    NOT NULL DEFAULT '',
            created_by          TEXT    NOT NULL DEFAULT '',
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at          TIMESTAMPTZ
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS meraki_topology_snapshots (
            id              SERIAL PRIMARY KEY,
            org_ref         INTEGER NOT NULL REFERENCES meraki_orgs(id) ON DELETE CASCADE,
            summary_json    TEXT    NOT NULL DEFAULT '{}',
            snapshot_json   TEXT    NOT NULL DEFAULT '{}',
            warning_count   INTEGER NOT NULL DEFAULT 0,
            duration_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
            built_by        TEXT    NOT NULL DEFAULT '',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_meraki_snapshots_org ON meraki_topology_snapshots (org_ref, id)")
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
