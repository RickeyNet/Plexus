"""
Migration 0090: Add a per-host SNMP profile to hosts.

``snmp_profile_id`` names an SNMP profile (``auth_settings``
``snmp_profiles``) that a host is polled with instead of its group's SNMP
config. Existing rows default to ``''`` (inherit the group's config).
"""

from __future__ import annotations

VERSION = 90
DESCRIPTION = "Add snmp_profile_id to hosts"

_COLUMN = "snmp_profile_id"
_DECL = "TEXT NOT NULL DEFAULT ''"


async def up(db) -> None:
    await db.execute(f"ALTER TABLE hosts ADD COLUMN IF NOT EXISTS {_COLUMN} {_DECL}")
    await db.commit()
