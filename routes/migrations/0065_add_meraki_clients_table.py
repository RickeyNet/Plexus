"""
Migration 0065: Meraki clients - MAC addresses seen on Meraki devices.

Adds:
  - meraki_clients - one row per (organization, network, MAC). Filled from the
    per-network client list of every Meraki collection, so the MAC tracking
    search covers Meraki devices as well as SNMP/SSH-polled inventory hosts.
    Rows outlive the snapshot they were collected with: first_seen / last_seen
    keep a client findable after it drops out of Meraki's one-day window.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text (the
format mac_address_table uses), so results of both tables sort together.
"""

from __future__ import annotations

VERSION = 65
DESCRIPTION = "Add Meraki clients table for MAC tracking"

_COLUMNS = """
            org_ref         INTEGER NOT NULL REFERENCES meraki_orgs(id) ON DELETE CASCADE,
            network_id      TEXT    NOT NULL DEFAULT '',
            network_name    TEXT    NOT NULL DEFAULT '',
            mac_address     TEXT    NOT NULL,
            ip_address      TEXT    NOT NULL DEFAULT '',
            vlan            INTEGER NOT NULL DEFAULT 0,
            device_serial   TEXT    NOT NULL DEFAULT '',
            device_name     TEXT    NOT NULL DEFAULT '',
            port_name       TEXT    NOT NULL DEFAULT '',
            description     TEXT    NOT NULL DEFAULT '',
            manufacturer    TEXT    NOT NULL DEFAULT '',
            ssid            TEXT    NOT NULL DEFAULT '',
            status          TEXT    NOT NULL DEFAULT '',
            first_seen      TEXT    NOT NULL DEFAULT '',
            last_seen       TEXT    NOT NULL DEFAULT '',
            UNIQUE(org_ref, network_id, mac_address)
"""


async def up(db) -> None:
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS meraki_clients (
            id              SERIAL PRIMARY KEY,{_COLUMNS}
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_meraki_clients_mac ON meraki_clients (mac_address)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_meraki_clients_last_seen ON meraki_clients (last_seen)")
    await db.commit()
