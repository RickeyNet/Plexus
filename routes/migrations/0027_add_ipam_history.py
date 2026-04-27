"""
Migration 0027: Historical IP allocation tracking (Phase I).

Adds:
  - ipam_ip_history — append-only per-IP assignment timeline. Each row records
    a single assignment lifespan: started_at when an IP was assigned to a
    hostname/source, ended_at when it was released. NULL ended_at = currently
    assigned. Supports forensics ("who had this IP on date X") and per-IP audit.
  - ipam_subnet_utilization — periodic snapshots of subnet utilization
    (total/used/reserved/pending/free + utilization_pct) for time-series
    charting and exhaustion forecasting.
"""

from __future__ import annotations

import os

VERSION = 27
DESCRIPTION = "Add ipam_ip_history and ipam_subnet_utilization for historical tracking"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_ip_history (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            address       TEXT    NOT NULL,
            vrf_name      TEXT    NOT NULL DEFAULT '',
            hostname      TEXT    NOT NULL DEFAULT '',
            source_type   TEXT    NOT NULL DEFAULT '',
            source_ref    TEXT    NOT NULL DEFAULT '',
            started_at    TEXT    NOT NULL DEFAULT (datetime('now')),
            ended_at      TEXT,
            recorded_by   TEXT    NOT NULL DEFAULT '',
            note          TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipam_history_address "
        "ON ipam_ip_history (address, vrf_name, started_at)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipam_history_open "
        "ON ipam_ip_history (address, vrf_name) WHERE ended_at IS NULL"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_subnet_utilization (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            subnet           TEXT    NOT NULL,
            vrf_name         TEXT    NOT NULL DEFAULT '',
            total            INTEGER NOT NULL DEFAULT 0,
            used             INTEGER NOT NULL DEFAULT 0,
            reserved         INTEGER NOT NULL DEFAULT 0,
            pending          INTEGER NOT NULL DEFAULT 0,
            free             INTEGER NOT NULL DEFAULT 0,
            utilization_pct  REAL    NOT NULL DEFAULT 0,
            captured_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipam_util_subnet_time "
        "ON ipam_subnet_utilization (subnet, vrf_name, captured_at)"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_ip_history (
            id            SERIAL PRIMARY KEY,
            address       TEXT    NOT NULL,
            vrf_name      TEXT    NOT NULL DEFAULT '',
            hostname      TEXT    NOT NULL DEFAULT '',
            source_type   TEXT    NOT NULL DEFAULT '',
            source_ref    TEXT    NOT NULL DEFAULT '',
            started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            ended_at      TIMESTAMPTZ,
            recorded_by   TEXT    NOT NULL DEFAULT '',
            note          TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipam_history_address "
        "ON ipam_ip_history (address, vrf_name, started_at)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipam_history_open "
        "ON ipam_ip_history (address, vrf_name) WHERE ended_at IS NULL"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_subnet_utilization (
            id               SERIAL PRIMARY KEY,
            subnet           TEXT    NOT NULL,
            vrf_name         TEXT    NOT NULL DEFAULT '',
            total            INTEGER NOT NULL DEFAULT 0,
            used             INTEGER NOT NULL DEFAULT 0,
            reserved         INTEGER NOT NULL DEFAULT 0,
            pending          INTEGER NOT NULL DEFAULT 0,
            free             INTEGER NOT NULL DEFAULT 0,
            utilization_pct  REAL    NOT NULL DEFAULT 0,
            captured_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipam_util_subnet_time "
        "ON ipam_subnet_utilization (subnet, vrf_name, captured_at)"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
