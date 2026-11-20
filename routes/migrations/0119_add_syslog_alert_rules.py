"""
Migration 0119: syslog alert rules.

Adds:

  - syslog_alert_rules - the operator's own rules that turn received syslog
    messages into monitoring alerts, and the overrides of the built-in
    rules (``netcontrol/syslog_rules.py``). A row with an empty
    ``builtin_key`` is a custom rule: ``match_type`` (``tag``, ``contains``
    or ``regex``), the ``pattern`` that raises it and the optional
    ``clear_pattern`` that resolves it, ``severity`` (info, warning,
    critical), ``threshold_count`` matches within
    ``threshold_window_seconds`` (per host and instance) before it raises,
    and ``auto_resolve_minutes`` (0: only a clear message resolves it). A
    row with a ``builtin_key`` only overrides ``enabled`` and ``severity``
    of that built-in rule (one row per built-in).

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 119
DESCRIPTION = "Add syslog alert rules"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS syslog_alert_rules (
            id                       SERIAL PRIMARY KEY,
            name                     TEXT    NOT NULL DEFAULT '',
            enabled                  INTEGER NOT NULL DEFAULT 1,
            builtin_key              TEXT    NOT NULL DEFAULT '',
            match_type               TEXT    NOT NULL DEFAULT 'contains',
            pattern                  TEXT    NOT NULL DEFAULT '',
            clear_pattern            TEXT    NOT NULL DEFAULT '',
            severity                 TEXT    NOT NULL DEFAULT 'warning',
            threshold_count          INTEGER NOT NULL DEFAULT 1,
            threshold_window_seconds INTEGER NOT NULL DEFAULT 300,
            auto_resolve_minutes     INTEGER NOT NULL DEFAULT 0,
            created_by               TEXT    NOT NULL DEFAULT '',
            created_at               TEXT    NOT NULL DEFAULT '',
            updated_at               TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_syslog_alert_rules_builtin "
        "ON syslog_alert_rules (builtin_key) WHERE builtin_key <> ''"
    )
    await db.commit()
