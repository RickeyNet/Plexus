"""
Migration 0125: the last byte counter reading of each tunnel.

Adds the store the traffic rates of topology entities are computed from
(``netcontrol.integrations.traffic``, ``routes.db.topology_traffic``):

  - topology_traffic_counters - one row per source (``provider``,
    ``org_ref``) and traffic key (the entity at the vendor, e.g. an
    OPNsense IPsec connection or WireGuard peer): the tracked entity it
    belongs to (``entity_type``, ``entity_id``, as the last collection
    named it), its counters at the last reading (``counters_json``, NULL
    when they were not known) and when they were read (``read_at``).

A stored collection and a monitoring poll of the firewall each compute the
rate since this reading and then replace it. Rows go with their source,
when a collection no longer reports the key, and with the monitoring
retention. Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS``
text. Every step is idempotent.
"""

from __future__ import annotations

VERSION = 125
DESCRIPTION = "Add the topology traffic counter store"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS topology_traffic_counters (
            id            SERIAL PRIMARY KEY,
            provider      TEXT    NOT NULL,
            org_ref       INTEGER NOT NULL DEFAULT 0,
            traffic_key   TEXT    NOT NULL,
            entity_type   TEXT    NOT NULL DEFAULT '',
            entity_id     TEXT    NOT NULL DEFAULT '',
            counters_json TEXT,
            read_at       TEXT    NOT NULL DEFAULT '',
            UNIQUE (provider, org_ref, traffic_key)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_topology_traffic_counters_read ON topology_traffic_counters (read_at)"
    )
    await db.commit()
