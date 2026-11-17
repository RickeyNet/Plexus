"""
Migration 0096: admin-defined data validation rules.

Adds:

  - validation_rules - one row per rule: a unique ``name`` (ignoring case),
    the ``object_type`` it applies to (host, group, prefix, ip_address,
    vlan, vrf), the ``field`` it checks (a column such as ``hostname``, or
    ``cf.<key>`` for a custom field), the ``rule_type`` (regex, length,
    numeric, required) with its parameters (``params_json``, a JSON object:
    ``pattern`` for regex, ``min``/``max`` for length and numeric), the
    ``error_message`` shown when a value breaks it (empty: a generated
    one), an ``enabled`` flag and a ``description``.

Rules are enforced by ``netcontrol.data_validation`` on the REST create and
update routes of those objects and on custom field value saves. Timestamps
are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text. Every step is
idempotent.
"""

from __future__ import annotations

VERSION = 96
DESCRIPTION = "Add data validation rules"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS validation_rules (
            id            SERIAL PRIMARY KEY,
            name          TEXT    NOT NULL,
            object_type   TEXT    NOT NULL,
            field         TEXT    NOT NULL,
            rule_type     TEXT    NOT NULL,
            params_json   TEXT    NOT NULL DEFAULT '{}',
            error_message TEXT    NOT NULL DEFAULT '',
            description   TEXT    NOT NULL DEFAULT '',
            enabled       INTEGER NOT NULL DEFAULT 1,
            created_by    TEXT    NOT NULL DEFAULT '',
            created_at    TEXT    NOT NULL DEFAULT '',
            updated_by    TEXT    NOT NULL DEFAULT '',
            updated_at    TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_validation_rules_name ON validation_rules (lower(name))")
    await db.execute(
        "CREATE INDEX IF NOT EXISTS ix_validation_rules_object_type ON validation_rules (object_type, enabled)"
    )
    await db.commit()
