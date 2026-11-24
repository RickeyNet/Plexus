"""
Migration 0134: a host's address is confirmed by an admin.

Adds:

  - hosts.address_confirmed - 1 when the host's address (``ip_address``)
    was set or confirmed by an admin or the server API token, 0 when a
    non-admin caller (or a run nobody configured) determined it. Shared
    secrets (the Plexus service credential, the default credential and
    the shared SNMP profiles) go only to a confirmed address
    (``netcontrol.managed_targets``).

Every host stored before this release keeps working: the column is added
with the default 1, so each existing host counts as confirmed. New hosts
are written with an explicit value by ``routes.db.inventory.add_host``.

Every step is idempotent.
"""

from __future__ import annotations

VERSION = 134
DESCRIPTION = "Record whether an admin confirmed a host's address"


async def up(db) -> None:
    await db.execute("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS address_confirmed INTEGER NOT NULL DEFAULT 1")
    await db.commit()
