"""
Migration 0138: custom SNMP trap rules in syslog_alert_rules.

Adds:

  - syslog_alert_rules.source - the message source a row belongs to:
    ``syslog`` (the default, so every existing custom rule stays a syslog
    rule) or ``trap``. A custom trap rule (``netcontrol/trap_rules.py``) is
    a row with an empty ``builtin_key`` and ``source`` ``trap``: its
    ``pattern`` is the trap (OID, ``<OID>.*`` prefix or registry name) that
    raises it, its ``clear_pattern`` the optional clearing trap, and
    ``match_type`` is ``trap``. The existing overrides of the built-in trap
    rules (``builtin_key`` ``trap_<key>``) are marked ``trap``.
  - syslog_alert_rules.trap_match - JSON text: a custom trap rule's varbind
    conditions (raise and clear) and the varbind that names its instance.
    ``''`` for every other row.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 138
DESCRIPTION = "Add custom SNMP trap rules to syslog_alert_rules"


async def up(db) -> None:
    await db.execute("ALTER TABLE syslog_alert_rules ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'syslog'")
    await db.execute("ALTER TABLE syslog_alert_rules ADD COLUMN IF NOT EXISTS trap_match TEXT NOT NULL DEFAULT ''")
    await db.execute("UPDATE syslog_alert_rules SET source = 'trap' WHERE LEFT(builtin_key, 5) = 'trap_'")
    await db.commit()
