"""
Migration 0018: Add IPAM sync sources, prefix/allocation cache, and reservations.

Adds:
  - ipam_sources (external IPAM provider configs and sync status)
  - ipam_prefixes (synced external subnet inventory)
  - ipam_allocations (synced external address allocations)
  - ipam_reservations (local reserved address ranges per subnet)
"""

from __future__ import annotations

import os

VERSION = 18
DESCRIPTION = "Add IPAM sync sources, allocations, and reservation tables"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_sources (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            provider            TEXT    NOT NULL,
            name                TEXT    NOT NULL,
            base_url            TEXT    NOT NULL DEFAULT '',
            auth_type           TEXT    NOT NULL DEFAULT 'token',
            auth_config_enc     TEXT    NOT NULL DEFAULT '',
            sync_scope          TEXT    NOT NULL DEFAULT '',
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
        CREATE TABLE IF NOT EXISTS ipam_prefixes (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id           INTEGER NOT NULL REFERENCES ipam_sources(id) ON DELETE CASCADE,
            external_id         TEXT    NOT NULL,
            subnet              TEXT    NOT NULL,
            description         TEXT    NOT NULL DEFAULT '',
            status              TEXT    NOT NULL DEFAULT '',
            vrf                 TEXT    NOT NULL DEFAULT '',
            tenant              TEXT    NOT NULL DEFAULT '',
            site                TEXT    NOT NULL DEFAULT '',
            vlan                TEXT    NOT NULL DEFAULT '',
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            discovered_at       TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at          TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(source_id, external_id, subnet)
        )
        """
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_allocations (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id           INTEGER NOT NULL REFERENCES ipam_sources(id) ON DELETE CASCADE,
            prefix_subnet       TEXT    NOT NULL DEFAULT '',
            address             TEXT    NOT NULL,
            dns_name            TEXT    NOT NULL DEFAULT '',
            status              TEXT    NOT NULL DEFAULT '',
            description         TEXT    NOT NULL DEFAULT '',
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            discovered_at       TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(source_id, address)
        )
        """
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_reservations (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            subnet              TEXT    NOT NULL,
            start_ip            TEXT    NOT NULL,
            end_ip              TEXT    NOT NULL,
            reason              TEXT    NOT NULL DEFAULT '',
            created_by          TEXT    NOT NULL DEFAULT '',
            created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )

    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ipam_sources_provider_enabled
        ON ipam_sources (provider, enabled)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ipam_prefixes_source_subnet
        ON ipam_prefixes (source_id, subnet)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ipam_allocations_source_prefix
        ON ipam_allocations (source_id, prefix_subnet, address)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ipam_reservations_subnet
        ON ipam_reservations (subnet, start_ip, end_ip)
        """
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_sources (
            id                  SERIAL PRIMARY KEY,
            provider            TEXT    NOT NULL,
            name                TEXT    NOT NULL,
            base_url            TEXT    NOT NULL DEFAULT '',
            auth_type           TEXT    NOT NULL DEFAULT 'token',
            auth_config_enc     TEXT    NOT NULL DEFAULT '',
            sync_scope          TEXT    NOT NULL DEFAULT '',
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
        CREATE TABLE IF NOT EXISTS ipam_prefixes (
            id                  SERIAL PRIMARY KEY,
            source_id           INTEGER NOT NULL REFERENCES ipam_sources(id) ON DELETE CASCADE,
            external_id         TEXT    NOT NULL,
            subnet              TEXT    NOT NULL,
            description         TEXT    NOT NULL DEFAULT '',
            status              TEXT    NOT NULL DEFAULT '',
            vrf                 TEXT    NOT NULL DEFAULT '',
            tenant              TEXT    NOT NULL DEFAULT '',
            site                TEXT    NOT NULL DEFAULT '',
            vlan                TEXT    NOT NULL DEFAULT '',
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(source_id, external_id, subnet)
        )
        """
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_allocations (
            id                  SERIAL PRIMARY KEY,
            source_id           INTEGER NOT NULL REFERENCES ipam_sources(id) ON DELETE CASCADE,
            prefix_subnet       TEXT    NOT NULL DEFAULT '',
            address             TEXT    NOT NULL,
            dns_name            TEXT    NOT NULL DEFAULT '',
            status              TEXT    NOT NULL DEFAULT '',
            description         TEXT    NOT NULL DEFAULT '',
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(source_id, address)
        )
        """
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_reservations (
            id                  SERIAL PRIMARY KEY,
            subnet              TEXT    NOT NULL,
            start_ip            TEXT    NOT NULL,
            end_ip              TEXT    NOT NULL,
            reason              TEXT    NOT NULL DEFAULT '',
            created_by          TEXT    NOT NULL DEFAULT '',
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )

    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ipam_sources_provider_enabled
        ON ipam_sources (provider, enabled)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ipam_prefixes_source_subnet
        ON ipam_prefixes (source_id, subnet)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ipam_allocations_source_prefix
        ON ipam_allocations (source_id, prefix_subnet, address)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ipam_reservations_subnet
        ON ipam_reservations (subnet, start_ip, end_ip)
        """
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)