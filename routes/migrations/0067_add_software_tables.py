"""
Migration 0067: software version tracking and vulnerability alerts.

Adds:
  - software_versions - one row per device whose software version Plexus
    knows: inventory hosts (SNMP/SSH), and the devices of the latest
    topology collection of every Meraki organization, Cato account and
    AnyConnect FMC. Keeps the previous version and when it changed.
  - software_version_history - every version a device has been seen on,
    with the period it was seen, so upgrades and downgrades can be listed
    after the fact.
  - software_advisories - security advisories to check versions against:
    entered by hand, imported, or synced from Cisco PSIRT. Affected
    versions are a JSON list of version specifications.
  - software_alerts - one row per (device, advisory) that currently (or
    previously) matched, with acknowledgement and resolution.
  - software_settings - key/value settings of the tracker (refresh
    interval, Cisco PSIRT credentials, notification floor).

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

VERSION = 67
DESCRIPTION = "Add software version tracking and vulnerability alert tables"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS software_versions (
            id               SERIAL PRIMARY KEY,
            device_key       TEXT    NOT NULL UNIQUE,
            source           TEXT    NOT NULL DEFAULT 'inventory',
            org_ref          INTEGER NOT NULL DEFAULT 0,
            host_id          INTEGER,
            name             TEXT    NOT NULL DEFAULT '',
            model            TEXT    NOT NULL DEFAULT '',
            serial           TEXT    NOT NULL DEFAULT '',
            site             TEXT    NOT NULL DEFAULT '',
            org_name         TEXT    NOT NULL DEFAULT '',
            platform         TEXT    NOT NULL DEFAULT '',
            version          TEXT    NOT NULL DEFAULT '',
            raw_version      TEXT    NOT NULL DEFAULT '',
            previous_version TEXT    NOT NULL DEFAULT '',
            changed_at       TEXT    NOT NULL DEFAULT '',
            first_seen       TEXT    NOT NULL DEFAULT '',
            last_seen        TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_software_versions_platform ON software_versions (platform)")
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS software_version_history (
            id          SERIAL PRIMARY KEY,
            device_key  TEXT NOT NULL,
            name        TEXT NOT NULL DEFAULT '',
            platform    TEXT NOT NULL DEFAULT '',
            version     TEXT NOT NULL DEFAULT '',
            seen_from   TEXT NOT NULL DEFAULT '',
            seen_until  TEXT NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_software_history_device ON software_version_history (device_key, seen_from)"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS software_advisories (
            id                     SERIAL PRIMARY KEY,
            advisory_id            TEXT    NOT NULL UNIQUE,
            source                 TEXT    NOT NULL DEFAULT 'manual',
            title                  TEXT    NOT NULL DEFAULT '',
            severity               TEXT    NOT NULL DEFAULT 'medium',
            cvss                   REAL,
            platform               TEXT    NOT NULL DEFAULT '',
            product_match          TEXT    NOT NULL DEFAULT '',
            affected_versions_json TEXT    NOT NULL DEFAULT '[]',
            fixed_versions_json    TEXT    NOT NULL DEFAULT '[]',
            cves_json              TEXT    NOT NULL DEFAULT '[]',
            url                    TEXT    NOT NULL DEFAULT '',
            published              TEXT    NOT NULL DEFAULT '',
            summary                TEXT    NOT NULL DEFAULT '',
            enabled                INTEGER NOT NULL DEFAULT 1,
            created_at             TEXT    NOT NULL DEFAULT '',
            updated_at             TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS software_alerts (
            id              SERIAL PRIMARY KEY,
            device_key      TEXT NOT NULL,
            advisory_id     TEXT NOT NULL,
            severity        TEXT NOT NULL DEFAULT 'medium',
            first_seen      TEXT NOT NULL DEFAULT '',
            last_seen       TEXT NOT NULL DEFAULT '',
            acknowledged_at TEXT NOT NULL DEFAULT '',
            acknowledged_by TEXT NOT NULL DEFAULT '',
            resolved_at     TEXT NOT NULL DEFAULT '',
            UNIQUE(device_key, advisory_id)
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_software_alerts_open ON software_alerts (resolved_at, severity)")
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS software_settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        )
        """
    )
    await db.commit()
