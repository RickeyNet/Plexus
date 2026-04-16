"""
Migration 0011: Add cloud visibility inventory/topology tables.

Adds:
  - cloud_accounts (provider account definitions and sync status)
  - cloud_resources (VPC/VNet/TransitGW/CloudRouter/etc discovered objects)
  - cloud_connections (cloud-to-cloud connectivity edges)
  - cloud_hybrid_links (on-prem host to cloud resource connectivity)
"""

from __future__ import annotations

import os

VERSION = 11
DESCRIPTION = "Add cloud visibility accounts and topology tables"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_accounts (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            provider            TEXT    NOT NULL,
            name                TEXT    NOT NULL,
            account_identifier  TEXT    NOT NULL DEFAULT '',
            region_scope        TEXT    NOT NULL DEFAULT '',
            auth_type           TEXT    NOT NULL DEFAULT 'manual',
            auth_config_json    TEXT    NOT NULL DEFAULT '{}',
            notes               TEXT    NOT NULL DEFAULT '',
            enabled             INTEGER NOT NULL DEFAULT 1,
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
        CREATE TABLE IF NOT EXISTS cloud_resources (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id          INTEGER NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
            provider            TEXT    NOT NULL,
            resource_uid        TEXT    NOT NULL,
            resource_type       TEXT    NOT NULL,
            name                TEXT    NOT NULL DEFAULT '',
            region              TEXT    NOT NULL DEFAULT '',
            cidr                TEXT    NOT NULL DEFAULT '',
            status              TEXT    NOT NULL DEFAULT '',
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            discovered_at       TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at          TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(account_id, resource_uid)
        )
        """
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_connections (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id          INTEGER NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
            provider            TEXT    NOT NULL,
            source_resource_uid TEXT    NOT NULL,
            target_resource_uid TEXT    NOT NULL,
            connection_type     TEXT    NOT NULL DEFAULT 'peering',
            state               TEXT    NOT NULL DEFAULT '',
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            discovered_at       TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(account_id, source_resource_uid, target_resource_uid, connection_type)
        )
        """
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_hybrid_links (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id          INTEGER NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
            provider            TEXT    NOT NULL,
            host_id             INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            host_label          TEXT    NOT NULL DEFAULT '',
            cloud_resource_uid  TEXT    NOT NULL,
            connection_type     TEXT    NOT NULL DEFAULT 'vpn',
            state               TEXT    NOT NULL DEFAULT '',
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            discovered_at       TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )

    await db.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_hybrid_links_unique
        ON cloud_hybrid_links (account_id, host_id, cloud_resource_uid, connection_type)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cloud_accounts_provider_enabled
        ON cloud_accounts (provider, enabled)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cloud_resources_account_type
        ON cloud_resources (account_id, resource_type)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cloud_connections_account
        ON cloud_connections (account_id, source_resource_uid, target_resource_uid)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cloud_hybrid_links_account
        ON cloud_hybrid_links (account_id, host_id, cloud_resource_uid)
        """
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_accounts (
            id                  SERIAL PRIMARY KEY,
            provider            TEXT    NOT NULL,
            name                TEXT    NOT NULL,
            account_identifier  TEXT    NOT NULL DEFAULT '',
            region_scope        TEXT    NOT NULL DEFAULT '',
            auth_type           TEXT    NOT NULL DEFAULT 'manual',
            auth_config_json    TEXT    NOT NULL DEFAULT '{}',
            notes               TEXT    NOT NULL DEFAULT '',
            enabled             INTEGER NOT NULL DEFAULT 1,
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
        CREATE TABLE IF NOT EXISTS cloud_resources (
            id                  SERIAL PRIMARY KEY,
            account_id          INTEGER NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
            provider            TEXT    NOT NULL,
            resource_uid        TEXT    NOT NULL,
            resource_type       TEXT    NOT NULL,
            name                TEXT    NOT NULL DEFAULT '',
            region              TEXT    NOT NULL DEFAULT '',
            cidr                TEXT    NOT NULL DEFAULT '',
            status              TEXT    NOT NULL DEFAULT '',
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(account_id, resource_uid)
        )
        """
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_connections (
            id                  SERIAL PRIMARY KEY,
            account_id          INTEGER NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
            provider            TEXT    NOT NULL,
            source_resource_uid TEXT    NOT NULL,
            target_resource_uid TEXT    NOT NULL,
            connection_type     TEXT    NOT NULL DEFAULT 'peering',
            state               TEXT    NOT NULL DEFAULT '',
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(account_id, source_resource_uid, target_resource_uid, connection_type)
        )
        """
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_hybrid_links (
            id                  SERIAL PRIMARY KEY,
            account_id          INTEGER NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
            provider            TEXT    NOT NULL,
            host_id             INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            host_label          TEXT    NOT NULL DEFAULT '',
            cloud_resource_uid  TEXT    NOT NULL,
            connection_type     TEXT    NOT NULL DEFAULT 'vpn',
            state               TEXT    NOT NULL DEFAULT '',
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )

    await db.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_hybrid_links_unique
        ON cloud_hybrid_links (account_id, host_id, cloud_resource_uid, connection_type)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cloud_accounts_provider_enabled
        ON cloud_accounts (provider, enabled)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cloud_resources_account_type
        ON cloud_resources (account_id, resource_type)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cloud_connections_account
        ON cloud_connections (account_id, source_resource_uid, target_resource_uid)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cloud_hybrid_links_account
        ON cloud_hybrid_links (account_id, host_id, cloud_resource_uid)
        """
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
