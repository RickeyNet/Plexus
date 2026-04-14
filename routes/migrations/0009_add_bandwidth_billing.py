"""
Migration 0009: Add bandwidth billing and 95th percentile reports.

Creates tables for:
  - billing_circuits: define billable circuits (interface + customer + commit rate)
  - billing_periods: generated billing period reports with 95th percentile results
"""

from __future__ import annotations

import os

VERSION = 9
DESCRIPTION = "Add bandwidth billing and 95th percentile reports"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS billing_circuits (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    NOT NULL DEFAULT '',
            description     TEXT    NOT NULL DEFAULT '',
            customer        TEXT    NOT NULL DEFAULT '',
            host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            if_index        INTEGER NOT NULL,
            if_name         TEXT    NOT NULL DEFAULT '',
            commit_rate_bps REAL    NOT NULL DEFAULT 0,
            burst_limit_bps REAL    NOT NULL DEFAULT 0,
            billing_day     INTEGER NOT NULL DEFAULT 1,
            billing_cycle   TEXT    NOT NULL DEFAULT 'monthly',
            cost_per_mbps   REAL    NOT NULL DEFAULT 0,
            currency        TEXT    NOT NULL DEFAULT 'USD',
            overage_enabled INTEGER NOT NULL DEFAULT 1,
            enabled         INTEGER NOT NULL DEFAULT 1,
            created_by      TEXT    NOT NULL DEFAULT '',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_billing_circuits_host
        ON billing_circuits (host_id, if_index)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_billing_circuits_customer
        ON billing_circuits (customer)
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS billing_periods (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            circuit_id      INTEGER NOT NULL REFERENCES billing_circuits(id) ON DELETE CASCADE,
            period_start    TEXT    NOT NULL,
            period_end      TEXT    NOT NULL,
            total_samples   INTEGER NOT NULL DEFAULT 0,
            p95_in_bps      REAL    NOT NULL DEFAULT 0,
            p95_out_bps     REAL    NOT NULL DEFAULT 0,
            p95_billing_bps REAL    NOT NULL DEFAULT 0,
            max_in_bps      REAL    NOT NULL DEFAULT 0,
            max_out_bps     REAL    NOT NULL DEFAULT 0,
            avg_in_bps      REAL    NOT NULL DEFAULT 0,
            avg_out_bps     REAL    NOT NULL DEFAULT 0,
            commit_rate_bps REAL    NOT NULL DEFAULT 0,
            overage_bps     REAL    NOT NULL DEFAULT 0,
            overage_cost    REAL    NOT NULL DEFAULT 0,
            total_cost      REAL    NOT NULL DEFAULT 0,
            status          TEXT    NOT NULL DEFAULT 'generated',
            generated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_billing_periods_circuit
        ON billing_periods (circuit_id, period_start)
        """
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS billing_circuits (
            id              SERIAL PRIMARY KEY,
            name            TEXT    NOT NULL DEFAULT '',
            description     TEXT    NOT NULL DEFAULT '',
            customer        TEXT    NOT NULL DEFAULT '',
            host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            if_index        INTEGER NOT NULL,
            if_name         TEXT    NOT NULL DEFAULT '',
            commit_rate_bps DOUBLE PRECISION NOT NULL DEFAULT 0,
            burst_limit_bps DOUBLE PRECISION NOT NULL DEFAULT 0,
            billing_day     INTEGER NOT NULL DEFAULT 1,
            billing_cycle   TEXT    NOT NULL DEFAULT 'monthly',
            cost_per_mbps   DOUBLE PRECISION NOT NULL DEFAULT 0,
            currency        TEXT    NOT NULL DEFAULT 'USD',
            overage_enabled INTEGER NOT NULL DEFAULT 1,
            enabled         INTEGER NOT NULL DEFAULT 1,
            created_by      TEXT    NOT NULL DEFAULT '',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_billing_circuits_host
        ON billing_circuits (host_id, if_index)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_billing_circuits_customer
        ON billing_circuits (customer)
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS billing_periods (
            id              SERIAL PRIMARY KEY,
            circuit_id      INTEGER NOT NULL REFERENCES billing_circuits(id) ON DELETE CASCADE,
            period_start    TEXT    NOT NULL,
            period_end      TEXT    NOT NULL,
            total_samples   INTEGER NOT NULL DEFAULT 0,
            p95_in_bps      DOUBLE PRECISION NOT NULL DEFAULT 0,
            p95_out_bps     DOUBLE PRECISION NOT NULL DEFAULT 0,
            p95_billing_bps DOUBLE PRECISION NOT NULL DEFAULT 0,
            max_in_bps      DOUBLE PRECISION NOT NULL DEFAULT 0,
            max_out_bps     DOUBLE PRECISION NOT NULL DEFAULT 0,
            avg_in_bps      DOUBLE PRECISION NOT NULL DEFAULT 0,
            avg_out_bps     DOUBLE PRECISION NOT NULL DEFAULT 0,
            commit_rate_bps DOUBLE PRECISION NOT NULL DEFAULT 0,
            overage_bps     DOUBLE PRECISION NOT NULL DEFAULT 0,
            overage_cost    DOUBLE PRECISION NOT NULL DEFAULT 0,
            total_cost      DOUBLE PRECISION NOT NULL DEFAULT 0,
            status          TEXT    NOT NULL DEFAULT 'generated',
            generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_billing_periods_circuit
        ON billing_periods (circuit_id, period_start)
        """
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
