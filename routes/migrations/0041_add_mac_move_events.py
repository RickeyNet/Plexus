"""
Migration 0041: Add MAC move event tracking tables.

Mirrors the config-drift model for MAC/ARP tracking: `mac_move_events`
records one row each time a MAC relocates (switch / port / VLAN / IP binding
change) instead of writing history every poll, and `mac_move_event_history`
is the append-only lifecycle timeline (detected, acknowledged) per event.
"""

from __future__ import annotations

import os

VERSION = 41
DESCRIPTION = "Add mac_move_events and mac_move_event_history tables"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS mac_move_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address     TEXT    NOT NULL,
            status          TEXT    NOT NULL DEFAULT 'open',
            change_kind     TEXT    NOT NULL DEFAULT '',
            from_host_id    INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            from_port       TEXT    NOT NULL DEFAULT '',
            from_vlan       INTEGER DEFAULT 0,
            from_ip         TEXT    NOT NULL DEFAULT '',
            to_host_id      INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            to_port         TEXT    NOT NULL DEFAULT '',
            to_vlan         INTEGER DEFAULT 0,
            to_ip           TEXT    NOT NULL DEFAULT '',
            detected_at     TEXT    NOT NULL DEFAULT (datetime('now')),
            acknowledged_at TEXT,
            acknowledged_by TEXT    DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_mac_move_events_mac "
        "ON mac_move_events(mac_address, detected_at)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_mac_move_events_status "
        "ON mac_move_events(status, detected_at)"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS mac_move_event_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id        INTEGER NOT NULL REFERENCES mac_move_events(id) ON DELETE CASCADE,
            mac_address     TEXT    NOT NULL,
            action          TEXT    NOT NULL DEFAULT '',
            from_status     TEXT    NOT NULL DEFAULT '',
            to_status       TEXT    NOT NULL DEFAULT '',
            actor           TEXT    NOT NULL DEFAULT '',
            details         TEXT    NOT NULL DEFAULT '',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_mac_move_event_history_event_created "
        "ON mac_move_event_history(event_id, created_at DESC)"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS mac_move_events (
            id              BIGSERIAL PRIMARY KEY,
            mac_address     TEXT    NOT NULL,
            status          TEXT    NOT NULL DEFAULT 'open',
            change_kind     TEXT    NOT NULL DEFAULT '',
            from_host_id    INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            from_port       TEXT    NOT NULL DEFAULT '',
            from_vlan       INTEGER DEFAULT 0,
            from_ip         TEXT    NOT NULL DEFAULT '',
            to_host_id      INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            to_port         TEXT    NOT NULL DEFAULT '',
            to_vlan         INTEGER DEFAULT 0,
            to_ip           TEXT    NOT NULL DEFAULT '',
            detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            acknowledged_at TIMESTAMPTZ,
            acknowledged_by TEXT    DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_mac_move_events_mac "
        "ON mac_move_events(mac_address, detected_at)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_mac_move_events_status "
        "ON mac_move_events(status, detected_at)"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS mac_move_event_history (
            id              BIGSERIAL PRIMARY KEY,
            event_id        INTEGER NOT NULL REFERENCES mac_move_events(id) ON DELETE CASCADE,
            mac_address     TEXT    NOT NULL,
            action          TEXT    NOT NULL DEFAULT '',
            from_status     TEXT    NOT NULL DEFAULT '',
            to_status       TEXT    NOT NULL DEFAULT '',
            actor           TEXT    NOT NULL DEFAULT '',
            details         TEXT    NOT NULL DEFAULT '',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_mac_move_event_history_event_created "
        "ON mac_move_event_history(event_id, created_at DESC)"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
