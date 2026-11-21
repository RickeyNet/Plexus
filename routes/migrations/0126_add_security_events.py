"""
Migration 0126: security events.

Adds a vendor-neutral store of security events, the first producer being
the intrusion detection (Suricata) alerts of an OPNsense firewall
(``netcontrol.routes.opnsense_ids``, ``routes.db.security_events``):

  - security_events - one row per event: the source that reported it
    (``provider``, ``org_ref``: a topology source; ``source_name`` as it
    was named then), the inventory host it is about when there is one
    (``host_id``, NULL otherwise or once the host is deleted), the kind of
    event (``kind``: ``ids_alert``), a key unique per source and kind
    (``event_key``: the same event read twice is stored once), when it
    happened at the vendor (``occurred_at``) and when Plexus stored it
    (``received_at``), its ``severity`` (critical / warning / info /
    unknown) and the vendor's ``priority``, the signature (``signature_id``,
    ``signature``, ``category``), what the device did (``action``: allowed
    or blocked) and the flow (``protocol``, ``src_ip``, ``src_port``,
    ``dest_ip``, ``dest_port``, ``interface``, ``flow_id``, ``app_proto``).

Rows go with their source, with the monitoring retention, and beyond a cap
per source (oldest first). Text comes from network traffic and rule files
and is bounded before it is written. Timestamps are written by Plexus as
UTC ``YYYY-MM-DD HH:MM:SS`` text. Every step is idempotent.
"""

from __future__ import annotations

VERSION = 126
DESCRIPTION = "Add the security event store"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS security_events (
            id            SERIAL PRIMARY KEY,
            provider      TEXT    NOT NULL,
            org_ref       INTEGER NOT NULL DEFAULT 0,
            source_name   TEXT    NOT NULL DEFAULT '',
            host_id       INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            kind          TEXT    NOT NULL,
            event_key     TEXT    NOT NULL,
            occurred_at   TEXT    NOT NULL,
            received_at   TEXT    NOT NULL DEFAULT '',
            severity      TEXT    NOT NULL DEFAULT 'unknown',
            priority      INTEGER,
            signature_id  BIGINT,
            signature     TEXT    NOT NULL DEFAULT '',
            category      TEXT    NOT NULL DEFAULT '',
            action        TEXT    NOT NULL DEFAULT '',
            protocol      TEXT    NOT NULL DEFAULT '',
            src_ip        TEXT    NOT NULL DEFAULT '',
            src_port      INTEGER,
            dest_ip       TEXT    NOT NULL DEFAULT '',
            dest_port     INTEGER,
            interface     TEXT    NOT NULL DEFAULT '',
            flow_id       TEXT    NOT NULL DEFAULT '',
            app_proto     TEXT    NOT NULL DEFAULT '',
            UNIQUE (provider, org_ref, kind, event_key)
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_security_events_occurred ON security_events (occurred_at)")
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_security_events_source ON security_events (provider, org_ref, kind, occurred_at)"
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_security_events_host ON security_events (host_id, occurred_at)")
    await db.commit()
