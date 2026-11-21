"""
Migration 0127: OPNsense rule counter history.

Adds:

  - opnsense_rule_counters - the filter rule counters of an OPNsense
    firewall (``firewall/filter_util/rule_stats``) kept across collections
    for the firewall's inventory host, so "unused" can mean "matched
    nothing for 90 days" and not only "nothing since the last reboot or
    filter reload" (pf resets the counters then). One row per rule label
    (the pf label the counters are keyed by): when the label was first and
    last reported (``first_seen_at``, ``last_seen_at``), the counters as
    last read (``evaluations``, ``packets``, ``bytes``, ``states``,
    ``pf_rules``; NULL when the firewall did not report one), when the
    packet counter was last seen to grow (``last_hit_at``, '' when never)
    and the packets and bytes counted since the first read
    (``total_packets``, ``total_bytes``), which survive counter resets.
    Written by the OPNsense collection
    (``netcontrol.routes.opnsense_collection.attach_rule_stats``); a label
    the firewall no longer reports is removed once it has not been seen for
    the retention of ``routes.db.opnsense_rule_counters``.

Rows are removed with their host. Timestamps are written by Plexus as UTC
``YYYY-MM-DD HH:MM:SS`` text. Every step is idempotent.
"""

from __future__ import annotations

VERSION = 127
DESCRIPTION = "Add OPNsense rule counter history"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS opnsense_rule_counters (
            host_id        INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            label          TEXT    NOT NULL,
            evaluations    BIGINT,
            packets        BIGINT,
            bytes          BIGINT,
            states         BIGINT,
            pf_rules       BIGINT,
            total_packets  BIGINT  NOT NULL DEFAULT 0,
            total_bytes    BIGINT  NOT NULL DEFAULT 0,
            first_seen_at  TEXT    NOT NULL DEFAULT '',
            last_seen_at   TEXT    NOT NULL DEFAULT '',
            last_hit_at    TEXT    NOT NULL DEFAULT '',
            PRIMARY KEY (host_id, label)
        )
        """
    )
    await db.commit()
