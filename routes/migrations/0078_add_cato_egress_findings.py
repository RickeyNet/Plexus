"""
Migration 0078: findings of the Cato egress vs cloud allow-list check.

The check (``netcontrol.integrations.cato.egress_check``) compares the
inbound cloud filter rules that name a Cato account's allocated IPs with the
Cato network rule a flow to the protected public address matches. Its
findings are about pairs of cloud rules and Cato rules, not inventory hosts,
so neither ``monitoring_alerts`` (keyed by host) nor the compliance tables
fit. Adds:

  - cato_egress_findings - one row per (Cato account, resource, public
    address, ports, cloud rule), or per Cato account for an account note:
    its kind, severity and message, whether it is open or resolved, and the
    alert raised for it (``alert_state``, ``alert_via``) so it alerts once
    and is cleared when the condition clears.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

VERSION = 78
DESCRIPTION = "Add Cato egress check findings table"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS cato_egress_findings (
            id            SERIAL PRIMARY KEY,
            finding_key   TEXT    NOT NULL UNIQUE,
            cato_org_ref  INTEGER NOT NULL DEFAULT 0,
            cato_org_name TEXT    NOT NULL DEFAULT '',
            provider      TEXT    NOT NULL DEFAULT '',
            resource_id   TEXT    NOT NULL DEFAULT '',
            resource_name TEXT    NOT NULL DEFAULT '',
            public_ip     TEXT    NOT NULL DEFAULT '',
            private_ip    TEXT    NOT NULL DEFAULT '',
            protocol      TEXT    NOT NULL DEFAULT '',
            ports         TEXT    NOT NULL DEFAULT '',
            filter_name   TEXT    NOT NULL DEFAULT '',
            rule_name     TEXT    NOT NULL DEFAULT '',
            rule_id       TEXT    NOT NULL DEFAULT '',
            kind          TEXT    NOT NULL DEFAULT '',
            severity      TEXT    NOT NULL DEFAULT 'info',
            message       TEXT    NOT NULL DEFAULT '',
            detail_json   TEXT    NOT NULL DEFAULT '{}',
            status        TEXT    NOT NULL DEFAULT 'open',
            first_seen    TEXT    NOT NULL DEFAULT '',
            last_seen     TEXT    NOT NULL DEFAULT '',
            resolved_at   TEXT    NOT NULL DEFAULT '',
            alert_state   TEXT    NOT NULL DEFAULT '',
            alert_via     TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_cato_egress_findings_status ON cato_egress_findings (status, severity)"
    )
    await db.commit()
