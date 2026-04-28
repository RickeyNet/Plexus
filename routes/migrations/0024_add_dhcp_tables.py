"""
Migration 0024: Add DHCP scope/lease integration tables.

Adds:
  - dhcp_servers (one row per DHCP source: ISC DHCP, Windows DHCP, Infoblox)
  - dhcp_scopes (per-server cached scope/pool inventory with utilization)
  - dhcp_leases (per-server cached active leases)
"""

from __future__ import annotations

import os

VERSION = 24
DESCRIPTION = "Add DHCP servers, scopes, and leases tables"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS dhcp_servers (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            provider            TEXT    NOT NULL,
            name                TEXT    NOT NULL,
            base_url            TEXT    NOT NULL DEFAULT '',
            auth_type           TEXT    NOT NULL DEFAULT 'token',
            auth_config_enc     TEXT    NOT NULL DEFAULT '',
            notes               TEXT    NOT NULL DEFAULT '',
            enabled             INTEGER NOT NULL DEFAULT 1,
            verify_tls          INTEGER NOT NULL DEFAULT 1,
            last_sync_at        TEXT,
            last_sync_status    TEXT    NOT NULL DEFAULT 'never',
            last_sync_message   TEXT    NOT NULL DEFAULT '',
            created_by          TEXT    NOT NULL DEFAULT '',
            created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at          TEXT
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS dhcp_scopes (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id           INTEGER NOT NULL REFERENCES dhcp_servers(id) ON DELETE CASCADE,
            external_id         TEXT    NOT NULL DEFAULT '',
            subnet              TEXT    NOT NULL,
            name                TEXT    NOT NULL DEFAULT '',
            range_start         TEXT    NOT NULL DEFAULT '',
            range_end           TEXT    NOT NULL DEFAULT '',
            total_addresses     INTEGER NOT NULL DEFAULT 0,
            used_addresses      INTEGER NOT NULL DEFAULT 0,
            free_addresses      INTEGER NOT NULL DEFAULT 0,
            state               TEXT    NOT NULL DEFAULT '',
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            discovered_at       TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(server_id, subnet, external_id)
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS dhcp_leases (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id           INTEGER NOT NULL REFERENCES dhcp_servers(id) ON DELETE CASCADE,
            scope_subnet        TEXT    NOT NULL DEFAULT '',
            address             TEXT    NOT NULL,
            mac_address         TEXT    NOT NULL DEFAULT '',
            hostname            TEXT    NOT NULL DEFAULT '',
            client_id           TEXT    NOT NULL DEFAULT '',
            state               TEXT    NOT NULL DEFAULT '',
            starts_at           TEXT,
            ends_at             TEXT,
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            discovered_at       TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(server_id, address)
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_dhcp_scopes_server_subnet
        ON dhcp_scopes (server_id, subnet)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_dhcp_leases_server_address
        ON dhcp_leases (server_id, address)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_dhcp_leases_mac
        ON dhcp_leases (mac_address)
        """
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS dhcp_servers (
            id                  SERIAL PRIMARY KEY,
            provider            TEXT    NOT NULL,
            name                TEXT    NOT NULL,
            base_url            TEXT    NOT NULL DEFAULT '',
            auth_type           TEXT    NOT NULL DEFAULT 'token',
            auth_config_enc     TEXT    NOT NULL DEFAULT '',
            notes               TEXT    NOT NULL DEFAULT '',
            enabled             INTEGER NOT NULL DEFAULT 1,
            verify_tls          INTEGER NOT NULL DEFAULT 1,
            last_sync_at        TIMESTAMPTZ,
            last_sync_status    TEXT    NOT NULL DEFAULT 'never',
            last_sync_message   TEXT    NOT NULL DEFAULT '',
            created_by          TEXT    NOT NULL DEFAULT '',
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at          TIMESTAMPTZ
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS dhcp_scopes (
            id                  SERIAL PRIMARY KEY,
            server_id           INTEGER NOT NULL REFERENCES dhcp_servers(id) ON DELETE CASCADE,
            external_id         TEXT    NOT NULL DEFAULT '',
            subnet              TEXT    NOT NULL,
            name                TEXT    NOT NULL DEFAULT '',
            range_start         TEXT    NOT NULL DEFAULT '',
            range_end           TEXT    NOT NULL DEFAULT '',
            total_addresses     INTEGER NOT NULL DEFAULT 0,
            used_addresses      INTEGER NOT NULL DEFAULT 0,
            free_addresses      INTEGER NOT NULL DEFAULT 0,
            state               TEXT    NOT NULL DEFAULT '',
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(server_id, subnet, external_id)
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS dhcp_leases (
            id                  SERIAL PRIMARY KEY,
            server_id           INTEGER NOT NULL REFERENCES dhcp_servers(id) ON DELETE CASCADE,
            scope_subnet        TEXT    NOT NULL DEFAULT '',
            address             TEXT    NOT NULL,
            mac_address         TEXT    NOT NULL DEFAULT '',
            hostname            TEXT    NOT NULL DEFAULT '',
            client_id           TEXT    NOT NULL DEFAULT '',
            state               TEXT    NOT NULL DEFAULT '',
            starts_at           TIMESTAMPTZ,
            ends_at             TIMESTAMPTZ,
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(server_id, address)
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_dhcp_scopes_server_subnet
        ON dhcp_scopes (server_id, subnet)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_dhcp_leases_server_address
        ON dhcp_leases (server_id, address)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_dhcp_leases_mac
        ON dhcp_leases (mac_address)
        """
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
