"""
Migration 0075: availability tracking of topology (API-collected) entities.

Devices, sites, uplinks, tunnels, VPN connections, circuits, peerings and HA
links that Plexus knows only from an integration's collection (Meraki, Cato,
Cisco FMC, Palo Alto Panorama, Appgate SDP, AWS, Azure, GCP) never reach the
SNMP/ICMP poller, so ``availability_transitions`` (keyed by inventory host)
cannot hold them. Adds:

  - topology_entity_state - the current state of every tracked entity
    (``up`` / ``degraded`` / ``down`` / ``unknown``), since when, when it
    was last seen in a collection, and which alert is open for it.
  - topology_availability_transitions - every state change, with the
    collection it was seen in. Uptime and outages are computed from it.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

VERSION = 75
DESCRIPTION = "Add topology availability tracking tables"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS topology_entity_state (
            id           SERIAL PRIMARY KEY,
            provider     TEXT    NOT NULL,
            org_ref      INTEGER NOT NULL DEFAULT 0,
            org_name     TEXT    NOT NULL DEFAULT '',
            entity_type  TEXT    NOT NULL,
            entity_id    TEXT    NOT NULL,
            name         TEXT    NOT NULL DEFAULT '',
            site         TEXT    NOT NULL DEFAULT '',
            model        TEXT    NOT NULL DEFAULT '',
            host_id      INTEGER,
            state        TEXT    NOT NULL DEFAULT 'unknown',
            raw_status   TEXT    NOT NULL DEFAULT '',
            state_since  TEXT    NOT NULL DEFAULT '',
            first_seen   TEXT    NOT NULL DEFAULT '',
            last_seen    TEXT    NOT NULL DEFAULT '',
            missing      INTEGER NOT NULL DEFAULT 0,
            alert_state  TEXT    NOT NULL DEFAULT '',
            meta_json    TEXT    NOT NULL DEFAULT '{}',
            UNIQUE (provider, org_ref, entity_type, entity_id)
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS topology_availability_transitions (
            id            SERIAL PRIMARY KEY,
            provider      TEXT    NOT NULL,
            org_ref       INTEGER NOT NULL DEFAULT 0,
            entity_type   TEXT    NOT NULL,
            entity_id     TEXT    NOT NULL,
            name          TEXT    NOT NULL DEFAULT '',
            site          TEXT    NOT NULL DEFAULT '',
            host_id       INTEGER,
            old_state     TEXT    NOT NULL DEFAULT 'unknown',
            new_state     TEXT    NOT NULL DEFAULT 'unknown',
            transition_at TEXT    NOT NULL DEFAULT '',
            snapshot_ref  TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_topo_avail_transitions_entity "
        "ON topology_availability_transitions (provider, org_ref, entity_type, entity_id)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_topo_avail_transitions_at ON topology_availability_transitions (transition_at)"
    )
    await db.commit()
