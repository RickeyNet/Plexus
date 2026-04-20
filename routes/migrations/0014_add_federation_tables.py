"""Migration 0014 — Add multi-instance federation tables.

Creates:
  federation_peers     — registry of remote Plexus instances
  federation_snapshots — cached aggregate data pulled from peers
"""

from __future__ import annotations

import os

VERSION = 14
DESCRIPTION = "Add federation_peers and federation_snapshots tables"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"

_SQLITE_PEERS = """\
CREATE TABLE IF NOT EXISTS federation_peers (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT    NOT NULL,
    url                 TEXT    NOT NULL,
    api_token_enc       TEXT    NOT NULL DEFAULT '',
    description         TEXT    NOT NULL DEFAULT '',
    enabled             INTEGER NOT NULL DEFAULT 1,
    last_sync_at        TEXT,
    last_sync_status    TEXT    NOT NULL DEFAULT 'never',
    last_sync_message   TEXT    NOT NULL DEFAULT '',
    created_by          TEXT    NOT NULL DEFAULT '',
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT
);
"""

_SQLITE_SNAPSHOTS = """\
CREATE TABLE IF NOT EXISTS federation_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id     INTEGER NOT NULL REFERENCES federation_peers(id) ON DELETE CASCADE,
    category    TEXT    NOT NULL,
    data_json   TEXT    NOT NULL DEFAULT '{}',
    captured_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""

_POSTGRES_PEERS = """\
CREATE TABLE IF NOT EXISTS federation_peers (
    id                  SERIAL PRIMARY KEY,
    name                TEXT    NOT NULL,
    url                 TEXT    NOT NULL,
    api_token_enc       TEXT    NOT NULL DEFAULT '',
    description         TEXT    NOT NULL DEFAULT '',
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    last_sync_at        TIMESTAMPTZ,
    last_sync_status    TEXT    NOT NULL DEFAULT 'never',
    last_sync_message   TEXT    NOT NULL DEFAULT '',
    created_by          TEXT    NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ
);
"""

_POSTGRES_SNAPSHOTS = """\
CREATE TABLE IF NOT EXISTS federation_snapshots (
    id          SERIAL PRIMARY KEY,
    peer_id     INTEGER NOT NULL REFERENCES federation_peers(id) ON DELETE CASCADE,
    category    TEXT    NOT NULL,
    data_json   TEXT    NOT NULL DEFAULT '{}',
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


async def _up_sqlite(db) -> None:
    await db.execute(_SQLITE_PEERS)
    await db.execute(_SQLITE_SNAPSHOTS)
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(_POSTGRES_PEERS)
    await db.execute(_POSTGRES_SNAPSHOTS)
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
