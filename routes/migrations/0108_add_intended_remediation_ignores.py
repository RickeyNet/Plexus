"""
Migration 0108: intended configuration remediation ignore rules.

Adds:

  - intended_remediation_ignores - lines that remediation of intended
    configuration leaves alone (``netcontrol.intended_remediation``):
    ``kind`` (``exact``, ``prefix`` or ``regex``, a regex is matched with
    RE2), ``pattern`` (compared with each stripped configuration line; a
    matching line is dropped with its block from both the intended and the
    running configuration), ``device_type`` (a driver key, ``''`` for every
    driver), ``description``, ``enabled`` (0/1) and the create and update
    stamps.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 108
DESCRIPTION = "Add intended configuration remediation ignore rules"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS intended_remediation_ignores (
            id          SERIAL  PRIMARY KEY,
            kind        TEXT    NOT NULL DEFAULT 'exact',
            pattern     TEXT    NOT NULL,
            device_type TEXT    NOT NULL DEFAULT '',
            description TEXT    NOT NULL DEFAULT '',
            enabled     INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT    NOT NULL DEFAULT '',
            updated_at  TEXT    NOT NULL DEFAULT '',
            updated_by  TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.commit()
