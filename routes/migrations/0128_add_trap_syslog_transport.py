"""
Migration 0128: how a received syslog message arrived.

The syslog receiver listens on UDP and, when turned on, on TCP and TLS
(``netcontrol.syslog_stream``). A UDP source address can be forged; a TCP
or TLS one cannot. Adds:

  - trap_syslog_events.transport - ``udp`` (the default, so existing rows
    and every SNMP trap stay UDP), ``tcp`` or ``tls``. With the receiver's
    ``syslog_udp_actions`` switch off, messages that arrived over UDP are
    stored and never acted on (``metrics_engine._evaluate_syslog_rules``,
    the restore at startup), and the rule activity counts the messages per
    transport (``netcontrol.syslog_activity``).

Every step is idempotent.
"""

from __future__ import annotations

VERSION = 128
DESCRIPTION = "Add transport to trap_syslog_events"


async def up(db) -> None:
    await db.execute("ALTER TABLE trap_syslog_events ADD COLUMN IF NOT EXISTS transport TEXT NOT NULL DEFAULT 'udp'")
    await db.commit()
