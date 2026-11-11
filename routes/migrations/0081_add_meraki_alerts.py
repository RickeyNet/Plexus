"""
Migration 0081: near-real-time Meraki alerts.

Alerts arrive from a short poll of every Meraki organization's assurance
alerts and from an optional webhook receiver
(``netcontrol.routes.meraki_alerts``). Both paths are normalised to one
shape (``netcontrol.integrations.meraki.alerts``) and deduplicated by
``alert_key`` (source, device or network, condition). Most alerts are about
Meraki devices that are not inventory hosts, so ``monitoring_alerts``
(keyed by host) cannot hold them. Adds:

  - meraki_alerts - one row per alert key: where and what it is, its
    severity, whether it is open or resolved, which paths reported it
    (``seen_via``), and the alert Plexus raised for it (``alert_state``,
    ``alert_via``, ``host_id``) so it alerts once and is cleared when the
    condition clears.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

VERSION = 81
DESCRIPTION = "Add Meraki alerts table"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS meraki_alerts (
            id              SERIAL PRIMARY KEY,
            alert_key       TEXT    NOT NULL UNIQUE,
            org_ref         INTEGER NOT NULL DEFAULT 0,
            org_id          TEXT    NOT NULL DEFAULT '',
            org_name        TEXT    NOT NULL DEFAULT '',
            network_id      TEXT    NOT NULL DEFAULT '',
            network_name    TEXT    NOT NULL DEFAULT '',
            device_serial   TEXT    NOT NULL DEFAULT '',
            device_name     TEXT    NOT NULL DEFAULT '',
            device_model    TEXT    NOT NULL DEFAULT '',
            product_type    TEXT    NOT NULL DEFAULT '',
            alert_type      TEXT    NOT NULL DEFAULT '',
            condition       TEXT    NOT NULL DEFAULT '',
            category        TEXT    NOT NULL DEFAULT '',
            title           TEXT    NOT NULL DEFAULT '',
            message         TEXT    NOT NULL DEFAULT '',
            severity        TEXT    NOT NULL DEFAULT 'warning',
            status          TEXT    NOT NULL DEFAULT 'open',
            started_at      TEXT    NOT NULL DEFAULT '',
            resolved_at     TEXT    NOT NULL DEFAULT '',
            first_seen      TEXT    NOT NULL DEFAULT '',
            last_seen       TEXT    NOT NULL DEFAULT '',
            seen_via        TEXT    NOT NULL DEFAULT '',
            last_source     TEXT    NOT NULL DEFAULT '',
            meraki_alert_id TEXT    NOT NULL DEFAULT '',
            occurrences     INTEGER NOT NULL DEFAULT 1,
            detail_json     TEXT    NOT NULL DEFAULT '{}',
            host_id         INTEGER,
            alert_state     TEXT    NOT NULL DEFAULT '',
            alert_via       TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_meraki_alerts_status ON meraki_alerts (status, severity)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_meraki_alerts_org ON meraki_alerts (org_ref, status)")
    await db.commit()
