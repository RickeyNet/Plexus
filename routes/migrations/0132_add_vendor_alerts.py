"""
Migration 0132: vendor alert feeds.

A vendor-neutral store for alerts a vendor API pushes or lets Plexus read as
a feed (``netcontrol.routes.vendor_alerts``, ``routes.db.vendor_alerts``).
The Cato events feed is the first provider; AWS and Azure alert feeds are to
use the same tables. (The Meraki feed keeps its own ``meraki_alerts`` table,
migration 0081.) Adds:

  - vendor_alerts - one row per alert key (``provider`` and a key the
    provider builds from the source, the entity and the condition): the
    entity it is about (``entity_type`` / ``entity_id`` as the topology
    availability tracker names them, ``entity_name``, ``site``,
    ``serial``), what happened (``condition``, the vendor's
    ``event_type`` / ``event_sub_type``, ``title``, ``message``,
    ``severity``), whether it is open or resolved, whether it closes on
    its own (``auto_expire``: a one-shot event with no recovery event),
    which tracker entities it covers (``tracker_scope``), the vendor's
    event id, a bounded ``detail_json``, and the alert Plexus raised for it
    (``alert_state``, ``alert_via``, ``host_id``) so it alerts once and is
    cleared when the condition clears.
  - vendor_alert_feeds - one row per source and feed: the vendor's cursor
    (``feed_cursor``: Cato's events feed marker) so a restart neither replays
    nor skips, the poll lease (``lease_owner`` / ``lease_until``: one app
    worker polls a source at a time), the back-off (``failures``,
    ``next_poll_at``) and the status of the last poll (``last_poll_at``,
    ``last_ok_at``, ``last_error``, ``feed_status``, ``last_event_at``,
    ``events_read``), shared by every worker.

Resolved alerts go with the monitoring retention. Timestamps are written by
Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text. Every step is idempotent.
"""

from __future__ import annotations

VERSION = 132
DESCRIPTION = "Add the vendor alert feed store"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS vendor_alerts (
            id              SERIAL PRIMARY KEY,
            provider        TEXT    NOT NULL,
            org_ref         INTEGER NOT NULL DEFAULT 0,
            alert_key       TEXT    NOT NULL,
            org_name        TEXT    NOT NULL DEFAULT '',
            entity_type     TEXT    NOT NULL DEFAULT '',
            entity_id       TEXT    NOT NULL DEFAULT '',
            entity_name     TEXT    NOT NULL DEFAULT '',
            site            TEXT    NOT NULL DEFAULT '',
            serial          TEXT    NOT NULL DEFAULT '',
            condition       TEXT    NOT NULL DEFAULT '',
            event_type      TEXT    NOT NULL DEFAULT '',
            event_sub_type  TEXT    NOT NULL DEFAULT '',
            title           TEXT    NOT NULL DEFAULT '',
            message         TEXT    NOT NULL DEFAULT '',
            severity        TEXT    NOT NULL DEFAULT 'warning',
            status          TEXT    NOT NULL DEFAULT 'open',
            auto_expire     INTEGER NOT NULL DEFAULT 0,
            tracker_scope   TEXT    NOT NULL DEFAULT '',
            started_at      TEXT    NOT NULL DEFAULT '',
            resolved_at     TEXT    NOT NULL DEFAULT '',
            first_seen      TEXT    NOT NULL DEFAULT '',
            last_seen       TEXT    NOT NULL DEFAULT '',
            vendor_event_id TEXT    NOT NULL DEFAULT '',
            occurrences     INTEGER NOT NULL DEFAULT 1,
            detail_json     TEXT    NOT NULL DEFAULT '{}',
            host_id         INTEGER,
            alert_state     TEXT    NOT NULL DEFAULT '',
            alert_via       TEXT    NOT NULL DEFAULT '',
            UNIQUE (provider, alert_key)
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_vendor_alerts_status ON vendor_alerts (provider, status, severity)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_vendor_alerts_org ON vendor_alerts (provider, org_ref, status)")
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_vendor_alerts_entity ON vendor_alerts (provider, org_ref, entity_type, entity_id)"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS vendor_alert_feeds (
            provider      TEXT    NOT NULL,
            org_ref       INTEGER NOT NULL,
            feed          TEXT    NOT NULL,
            feed_cursor   TEXT    NOT NULL DEFAULT '',
            cursor_at     TEXT    NOT NULL DEFAULT '',
            lease_owner   TEXT    NOT NULL DEFAULT '',
            lease_until   TEXT    NOT NULL DEFAULT '',
            failures      INTEGER NOT NULL DEFAULT 0,
            next_poll_at  TEXT    NOT NULL DEFAULT '',
            last_poll_at  TEXT    NOT NULL DEFAULT '',
            last_ok_at    TEXT    NOT NULL DEFAULT '',
            last_error    TEXT    NOT NULL DEFAULT '',
            feed_status   TEXT    NOT NULL DEFAULT '',
            last_event_at TEXT    NOT NULL DEFAULT '',
            events_read   BIGINT  NOT NULL DEFAULT 0,
            PRIMARY KEY (provider, org_ref, feed)
        )
        """
    )
    await db.commit()
