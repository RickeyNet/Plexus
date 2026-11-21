"""
Migration 0120: OPNsense firewall log evidence.

Adds the per-rule aggregate of the ``filterlog`` lines OPNsense firewalls
send to the syslog receiver (``netcontrol.integrations.opnsense.filterlog``).
Raw lines are never stored:

  - opnsense_filterlog_hits - hits per time bucket (``bucket``: its start,
    ``filterlog.BUCKET_SECONDS`` wide) of each inventory host, rule
    (``rule_key``: the pf label the line names, else ``rulenr:N``), action
    (pass, block), interface and direction, with when the last one was
    received (``last_seen``).
  - opnsense_filterlog_flows - a few recent distinct flows per host, rule
    and action (source, destination, protocol, destination port; 0 when
    the protocol has none) with their hits and ``last_seen``, so a path
    trace can tell whether the flow it traced was logged.

Both are kept for ``EVIDENCE_RETENTION_DAYS`` by the metrics retention
cleanup and removed with their host. Timestamps are written by Plexus as
UTC ``YYYY-MM-DD HH:MM:SS`` text. Every step is idempotent.
"""

from __future__ import annotations

VERSION = 120
DESCRIPTION = "Add OPNsense firewall log evidence"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS opnsense_filterlog_hits (
            id          SERIAL PRIMARY KEY,
            host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            bucket      TEXT    NOT NULL,
            rule_key    TEXT    NOT NULL,
            action      TEXT    NOT NULL,
            interface   TEXT    NOT NULL DEFAULT '',
            direction   TEXT    NOT NULL DEFAULT '',
            hits        BIGINT  NOT NULL DEFAULT 0,
            last_seen   TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_opnsense_filterlog_hits_key "
        "ON opnsense_filterlog_hits (host_id, bucket, rule_key, action, interface, direction)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_opnsense_filterlog_hits_bucket ON opnsense_filterlog_hits (bucket)"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS opnsense_filterlog_flows (
            id               SERIAL PRIMARY KEY,
            host_id          INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            rule_key         TEXT    NOT NULL,
            action           TEXT    NOT NULL,
            source           TEXT    NOT NULL,
            destination      TEXT    NOT NULL,
            protocol         TEXT    NOT NULL DEFAULT '',
            destination_port INTEGER NOT NULL DEFAULT 0,
            hits             BIGINT  NOT NULL DEFAULT 0,
            last_seen        TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_opnsense_filterlog_flows_key "
        "ON opnsense_filterlog_flows (host_id, rule_key, action, source, destination, protocol, destination_port)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_opnsense_filterlog_flows_seen ON opnsense_filterlog_flows (last_seen)"
    )
    await db.commit()
