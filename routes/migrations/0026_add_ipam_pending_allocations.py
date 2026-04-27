"""
Migration 0026: IPAM-driven provisioning (Phase H).

Adds:
  - ipam_pending_allocations — tracks reserved-but-not-committed IP allocations
    issued via POST /api/ipam/allocate. Each row holds subnet, address, vrf,
    intended hostname, optional external IPAM source/ref, expiry, and state
    ('pending' | 'committed' | 'released'). Pending rows participate in
    next-IP selection so concurrent allocates can't hand out the same address.
"""

from __future__ import annotations

import os

VERSION = 26
DESCRIPTION = "Add ipam_pending_allocations table for IPAM-driven provisioning"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_pending_allocations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            subnet          TEXT    NOT NULL,
            address         TEXT    NOT NULL,
            vrf_name        TEXT    NOT NULL DEFAULT '',
            hostname        TEXT    NOT NULL DEFAULT '',
            description     TEXT    NOT NULL DEFAULT '',
            source_id       INTEGER,
            external_ref    TEXT    NOT NULL DEFAULT '',
            state           TEXT    NOT NULL DEFAULT 'pending',
            expires_at      TEXT    NOT NULL,
            created_by      TEXT    NOT NULL DEFAULT '',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            committed_at    TEXT,
            released_at     TEXT
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipam_pending_subnet_state "
        "ON ipam_pending_allocations (subnet, state)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipam_pending_vrf_address "
        "ON ipam_pending_allocations (vrf_name, address, state)"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_pending_allocations (
            id              SERIAL PRIMARY KEY,
            subnet          TEXT    NOT NULL,
            address         TEXT    NOT NULL,
            vrf_name        TEXT    NOT NULL DEFAULT '',
            hostname        TEXT    NOT NULL DEFAULT '',
            description     TEXT    NOT NULL DEFAULT '',
            source_id       INTEGER,
            external_ref    TEXT    NOT NULL DEFAULT '',
            state           TEXT    NOT NULL DEFAULT 'pending',
            expires_at      TIMESTAMPTZ NOT NULL,
            created_by      TEXT    NOT NULL DEFAULT '',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            committed_at    TIMESTAMPTZ,
            released_at     TIMESTAMPTZ
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipam_pending_subnet_state "
        "ON ipam_pending_allocations (subnet, state)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipam_pending_vrf_address "
        "ON ipam_pending_allocations (vrf_name, address, state)"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
