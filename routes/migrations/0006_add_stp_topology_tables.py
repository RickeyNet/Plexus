"""
Migration 0006: Add STP topology state + event tables.

Adds:
  - stp_port_states: latest per-port STP state/role snapshot by host/VLAN.
  - stp_topology_events: root-change / topology-change / port-state-change events.
"""

from __future__ import annotations

import os

VERSION = 6
DESCRIPTION = "Add STP topology state and event tables"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS stp_port_states (
            id                         INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id                    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            vlan_id                    INTEGER NOT NULL DEFAULT 1,
            bridge_port                INTEGER NOT NULL DEFAULT 0,
            if_index                   INTEGER NOT NULL DEFAULT 0,
            interface_name             TEXT    NOT NULL DEFAULT '',
            port_state                 TEXT    NOT NULL DEFAULT '',
            port_role                  TEXT    NOT NULL DEFAULT '',
            designated_bridge_id       TEXT    NOT NULL DEFAULT '',
            root_bridge_id             TEXT    NOT NULL DEFAULT '',
            root_port                  INTEGER NOT NULL DEFAULT 0,
            topology_change_count      INTEGER NOT NULL DEFAULT 0,
            time_since_topology_change INTEGER NOT NULL DEFAULT 0,
            is_root_bridge             INTEGER NOT NULL DEFAULT 0,
            collected_at               TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(host_id, vlan_id, bridge_port)
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_stp_port_states_host_vlan
        ON stp_port_states(host_id, vlan_id, collected_at DESC)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_stp_port_states_state
        ON stp_port_states(vlan_id, port_state)
        """
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS stp_topology_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            vlan_id         INTEGER NOT NULL DEFAULT 1,
            event_type      TEXT    NOT NULL DEFAULT '',
            severity        TEXT    NOT NULL DEFAULT 'warning',
            interface_name  TEXT    NOT NULL DEFAULT '',
            details         TEXT    NOT NULL DEFAULT '',
            old_value       TEXT    NOT NULL DEFAULT '',
            new_value       TEXT    NOT NULL DEFAULT '',
            acknowledged    INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_stp_events_ack_created
        ON stp_topology_events(acknowledged, created_at DESC)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_stp_events_host_created
        ON stp_topology_events(host_id, created_at DESC)
        """
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS stp_port_states (
            id                         BIGSERIAL PRIMARY KEY,
            host_id                    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            vlan_id                    INTEGER NOT NULL DEFAULT 1,
            bridge_port                INTEGER NOT NULL DEFAULT 0,
            if_index                   INTEGER NOT NULL DEFAULT 0,
            interface_name             TEXT    NOT NULL DEFAULT '',
            port_state                 TEXT    NOT NULL DEFAULT '',
            port_role                  TEXT    NOT NULL DEFAULT '',
            designated_bridge_id       TEXT    NOT NULL DEFAULT '',
            root_bridge_id             TEXT    NOT NULL DEFAULT '',
            root_port                  INTEGER NOT NULL DEFAULT 0,
            topology_change_count      INTEGER NOT NULL DEFAULT 0,
            time_since_topology_change INTEGER NOT NULL DEFAULT 0,
            is_root_bridge             INTEGER NOT NULL DEFAULT 0,
            collected_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(host_id, vlan_id, bridge_port)
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_stp_port_states_host_vlan
        ON stp_port_states(host_id, vlan_id, collected_at DESC)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_stp_port_states_state
        ON stp_port_states(vlan_id, port_state)
        """
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS stp_topology_events (
            id              BIGSERIAL PRIMARY KEY,
            host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            vlan_id         INTEGER NOT NULL DEFAULT 1,
            event_type      TEXT    NOT NULL DEFAULT '',
            severity        TEXT    NOT NULL DEFAULT 'warning',
            interface_name  TEXT    NOT NULL DEFAULT '',
            details         TEXT    NOT NULL DEFAULT '',
            old_value       TEXT    NOT NULL DEFAULT '',
            new_value       TEXT    NOT NULL DEFAULT '',
            acknowledged    INTEGER NOT NULL DEFAULT 0,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_stp_events_ack_created
        ON stp_topology_events(acknowledged, created_at DESC)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_stp_events_host_created
        ON stp_topology_events(host_id, created_at DESC)
        """
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
