"""
Migration 0121: flow interface names.

Adds:

  - flow_interface_names - the name of each interface index a host's flow
    records carry in ``input_if`` / ``output_if`` (``flow_records`` keep the
    number only), written by an integration that knows the device's
    interface table without SNMP: the OPNsense collection reads the
    FreeBSD kernel index of each interface off the ``link#N`` gateways of
    its routing table (``device``: ``igb0``, ``vlan0.10``; ``name``: the
    OPNsense name, ``LAN``, ``WAN``). ``source`` names the writer, which
    replaces only its own rows. A host polled over SNMP needs no row: its
    ``interface_stats`` already name the SNMP ifIndex its flows carry.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 121
DESCRIPTION = "Add flow interface names"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS flow_interface_names (
            host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            if_index    INTEGER NOT NULL,
            device      TEXT    NOT NULL DEFAULT '',
            name        TEXT    NOT NULL DEFAULT '',
            source      TEXT    NOT NULL DEFAULT '',
            updated_at  TEXT    NOT NULL DEFAULT '',
            PRIMARY KEY (host_id, if_index)
        )
        """
    )
    await db.commit()
