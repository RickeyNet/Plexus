"""
Migration 0007: Add STP root-bridge policy table.

Adds:
  - stp_root_policies: expected STP root bridge by inventory group and VLAN.
"""

from __future__ import annotations

import os

VERSION = 7
DESCRIPTION = "Add STP root-bridge policy table"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS stp_root_policies (
            id                       INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id                 INTEGER NOT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
            vlan_id                  INTEGER NOT NULL DEFAULT 1,
            expected_root_bridge_id  TEXT    NOT NULL DEFAULT '',
            expected_root_hostname   TEXT    NOT NULL DEFAULT '',
            enabled                  INTEGER NOT NULL DEFAULT 1,
            created_at               TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at               TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(group_id, vlan_id)
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_stp_root_policies_group_vlan
        ON stp_root_policies(group_id, vlan_id)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_stp_root_policies_enabled
        ON stp_root_policies(enabled, group_id, vlan_id)
        """
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS stp_root_policies (
            id                       BIGSERIAL PRIMARY KEY,
            group_id                 INTEGER NOT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
            vlan_id                  INTEGER NOT NULL DEFAULT 1,
            expected_root_bridge_id  TEXT    NOT NULL DEFAULT '',
            expected_root_hostname   TEXT    NOT NULL DEFAULT '',
            enabled                  INTEGER NOT NULL DEFAULT 1,
            created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(group_id, vlan_id)
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_stp_root_policies_group_vlan
        ON stp_root_policies(group_id, vlan_id)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_stp_root_policies_enabled
        ON stp_root_policies(enabled, group_id, vlan_id)
        """
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
