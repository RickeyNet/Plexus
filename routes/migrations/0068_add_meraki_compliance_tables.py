"""
Migration 0068: Meraki security compliance.

Compliance profiles can carry Meraki rules (``"type": "meraki"``) that name a
check against the Dashboard API configuration of an organization - the
Meraki equivalents of DHCP snooping, port security, BPDU guard, storm
control, IPS/AMP, SSID security, dashboard login security and so on. Hosts
in the inventory are not involved, so these scans have their own tables:

  - meraki_compliance_assignments - a profile bound to a Meraki organization
    on a schedule (the organization's stored API key is used, read-only)
  - meraki_compliance_results - one row per scanned *target* (the
    organization, a network, or a switch) with the per-check findings as JSON.
    ``scan_id`` groups the rows of one scan.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import os

VERSION = 68
DESCRIPTION = "Add Meraki compliance assignment and result tables"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def up(db) -> None:
    primary_key = "SERIAL PRIMARY KEY" if DB_ENGINE == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT"
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS meraki_compliance_assignments (
            id               {primary_key},
            profile_id       INTEGER NOT NULL REFERENCES compliance_profiles(id) ON DELETE CASCADE,
            org_ref          INTEGER NOT NULL REFERENCES meraki_orgs(id) ON DELETE CASCADE,
            enabled          INTEGER NOT NULL DEFAULT 1,
            interval_seconds INTEGER NOT NULL DEFAULT 86400,
            last_scan_at     TEXT,
            last_scan_status TEXT    NOT NULL DEFAULT '',
            last_scan_message TEXT   NOT NULL DEFAULT '',
            assigned_at      TEXT    NOT NULL DEFAULT '',
            assigned_by      TEXT    NOT NULL DEFAULT '',
            UNIQUE(profile_id, org_ref)
        )
        """
    )
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS meraki_compliance_results (
            id               {primary_key},
            scan_id          TEXT    NOT NULL DEFAULT '',
            assignment_id    INTEGER REFERENCES meraki_compliance_assignments(id) ON DELETE SET NULL,
            profile_id       INTEGER NOT NULL REFERENCES compliance_profiles(id) ON DELETE CASCADE,
            org_ref          INTEGER NOT NULL REFERENCES meraki_orgs(id) ON DELETE CASCADE,
            target_kind      TEXT    NOT NULL DEFAULT 'network',
            target_id        TEXT    NOT NULL DEFAULT '',
            target_name      TEXT    NOT NULL DEFAULT '',
            network_id       TEXT    NOT NULL DEFAULT '',
            network_name     TEXT    NOT NULL DEFAULT '',
            model            TEXT    NOT NULL DEFAULT '',
            serial           TEXT    NOT NULL DEFAULT '',
            status           TEXT    NOT NULL DEFAULT 'compliant',
            total_rules      INTEGER NOT NULL DEFAULT 0,
            passed_rules     INTEGER NOT NULL DEFAULT 0,
            failed_rules     INTEGER NOT NULL DEFAULT 0,
            unreadable_rules INTEGER NOT NULL DEFAULT 0,
            findings         TEXT    NOT NULL DEFAULT '[]',
            scanned_at       TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_meraki_compliance_results_org ON meraki_compliance_results (org_ref, scanned_at)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_meraki_compliance_results_profile ON meraki_compliance_results (profile_id)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_meraki_compliance_results_target "
        "ON meraki_compliance_results (target_kind, target_id, profile_id)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_meraki_compliance_results_scan ON meraki_compliance_results (scan_id)"
    )
    await db.commit()
