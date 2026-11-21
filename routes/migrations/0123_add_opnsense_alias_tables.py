"""
Migration 0123: OPNsense alias tables.

Adds:

  - opnsense_alias_tables - the contents of the pf tables behind the
    aliases of an OPNsense firewall that its config.xml cannot resolve
    (URL tables, GeoIP, ASN, host names, dynamic IPv6 hosts...), read by
    the OPNsense collection (``firewall/alias_util/list/{alias}``) for the
    firewall's inventory host. One row per alias table: its name, the
    entries read (``entries``: one per line, as pf lists them, ``!`` for a
    negated entry), how many were read (``entry_count``) and how many the
    table held (``total``), whether the entries are cut short
    (``truncated``) and when they were read (``read_at``). Each collection
    replaces a host's rows as a whole; the path trace resolves those
    aliases from them (``netcontrol.integrations.pathtrace.opnsense_config``).

Rows are removed with their host. Timestamps are written by Plexus as UTC
``YYYY-MM-DD HH:MM:SS`` text. Every step is idempotent.
"""

from __future__ import annotations

VERSION = 123
DESCRIPTION = "Add OPNsense alias tables"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS opnsense_alias_tables (
            host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            name         TEXT    NOT NULL,
            entries      TEXT    NOT NULL DEFAULT '',
            entry_count  INTEGER NOT NULL DEFAULT 0,
            total        INTEGER NOT NULL DEFAULT 0,
            truncated    INTEGER NOT NULL DEFAULT 0,
            read_at      TEXT    NOT NULL DEFAULT '',
            PRIMARY KEY (host_id, name)
        )
        """
    )
    await db.commit()
