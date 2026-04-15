"""
Migration 0008: Add interface error/discard tracking tables.

Adds:
  - interface_error_stats: current + previous error counters per interface for delta calculation.
  - interface_error_events: detected error spike events with root-cause correlation hints.
"""

from __future__ import annotations

import os

VERSION = 8
DESCRIPTION = "Add interface error/discard tracking tables"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS interface_error_stats (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id             INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            if_index            INTEGER NOT NULL,
            if_name             TEXT    NOT NULL DEFAULT '',
            in_errors           INTEGER DEFAULT 0,
            out_errors          INTEGER DEFAULT 0,
            in_discards         INTEGER DEFAULT 0,
            out_discards        INTEGER DEFAULT 0,
            prev_in_errors      INTEGER DEFAULT 0,
            prev_out_errors     INTEGER DEFAULT 0,
            prev_in_discards    INTEGER DEFAULT 0,
            prev_out_discards   INTEGER DEFAULT 0,
            polled_at           TEXT    NOT NULL DEFAULT (datetime('now')),
            prev_polled_at      TEXT    DEFAULT NULL,
            UNIQUE(host_id, if_index)
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_interface_error_stats_host
        ON interface_error_stats(host_id, if_index)
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS interface_error_events (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id             INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            if_index            INTEGER NOT NULL,
            if_name             TEXT    NOT NULL DEFAULT '',
            event_type          TEXT    NOT NULL DEFAULT 'spike',
            metric_name         TEXT    NOT NULL DEFAULT '',
            severity            TEXT    NOT NULL DEFAULT 'warning',
            current_rate        REAL    DEFAULT 0,
            baseline_rate       REAL    DEFAULT 0,
            spike_factor        REAL    DEFAULT 0,
            root_cause_hint     TEXT    NOT NULL DEFAULT '',
            root_cause_category TEXT    NOT NULL DEFAULT 'unknown',
            correlation_details TEXT    NOT NULL DEFAULT '{}',
            acknowledged        INTEGER NOT NULL DEFAULT 0,
            acknowledged_by     TEXT    DEFAULT NULL,
            created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
            resolved_at         TEXT    DEFAULT NULL
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_interface_error_events_host
        ON interface_error_events(host_id, created_at DESC)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_interface_error_events_unresolved
        ON interface_error_events(resolved_at, severity)
        """
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS interface_error_stats (
            id                  BIGSERIAL PRIMARY KEY,
            host_id             INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            if_index            INTEGER NOT NULL,
            if_name             TEXT    NOT NULL DEFAULT '',
            in_errors           BIGINT  DEFAULT 0,
            out_errors          BIGINT  DEFAULT 0,
            in_discards         BIGINT  DEFAULT 0,
            out_discards        BIGINT  DEFAULT 0,
            prev_in_errors      BIGINT  DEFAULT 0,
            prev_out_errors     BIGINT  DEFAULT 0,
            prev_in_discards    BIGINT  DEFAULT 0,
            prev_out_discards   BIGINT  DEFAULT 0,
            polled_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            prev_polled_at      TIMESTAMPTZ DEFAULT NULL,
            UNIQUE(host_id, if_index)
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_interface_error_stats_host
        ON interface_error_stats(host_id, if_index)
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS interface_error_events (
            id                  BIGSERIAL PRIMARY KEY,
            host_id             INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            if_index            INTEGER NOT NULL,
            if_name             TEXT    NOT NULL DEFAULT '',
            event_type          TEXT    NOT NULL DEFAULT 'spike',
            metric_name         TEXT    NOT NULL DEFAULT '',
            severity            TEXT    NOT NULL DEFAULT 'warning',
            current_rate        DOUBLE PRECISION DEFAULT 0,
            baseline_rate       DOUBLE PRECISION DEFAULT 0,
            spike_factor        DOUBLE PRECISION DEFAULT 0,
            root_cause_hint     TEXT    NOT NULL DEFAULT '',
            root_cause_category TEXT    NOT NULL DEFAULT 'unknown',
            correlation_details TEXT    NOT NULL DEFAULT '{}',
            acknowledged        INTEGER NOT NULL DEFAULT 0,
            acknowledged_by     TEXT    DEFAULT NULL,
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            resolved_at         TIMESTAMPTZ DEFAULT NULL
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_interface_error_events_host
        ON interface_error_events(host_id, created_at DESC)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_interface_error_events_unresolved
        ON interface_error_events(resolved_at, severity)
        """
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
