"""
Migration 0141: record who last set a host's address.

Adds:
  - hosts.address_set_by - the id of the user who last wrote the host's
    address (``ip_address``), or NULL when no signed-in user did (the
    server API token, a discovery or sync run with no acting user, or a
    host stored before this release). Work that runs later with a stored
    owner's personal credential (a backup policy, a compliance assignment,
    a queued job, a deployment run by someone else) sends that credential
    only to a confirmed address or to one its owner set
    (``netcontrol.managed_targets``).

Existing rows stay NULL: an existing host whose address is not confirmed
gets no deferred run with a personal credential until an admin confirms
its address or the credential's owner writes it.

Every step is idempotent.
"""

from __future__ import annotations

VERSION = 141
DESCRIPTION = "Record which user last set a host's address"


async def up(db) -> None:
    await db.execute("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS address_set_by INTEGER")
    await db.commit()
