"""
Migration 0084: mutes of topology (API-collected) entities.

An operator can mute one entity tracked in ``topology_entity_state`` (a
device that is down on purpose) or every entity at one site (a site not
installed yet). A muted entity is not a problem on the Dashboard and raises
no notification from the availability tracker or the Meraki alerts; it is
still listed, marked muted, under Monitoring > Availability. Adds:

  - topology_mutes - one row per mute: the source (provider, org_ref), the
    scope (``entity`` with entity_type / entity_id, or ``site`` with the
    site name as stored on the state rows), the reason, who and when.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

VERSION = 84
DESCRIPTION = "Add topology entity mutes"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS topology_mutes (
            id           SERIAL PRIMARY KEY,
            provider     TEXT    NOT NULL,
            org_ref      INTEGER NOT NULL DEFAULT 0,
            scope        TEXT    NOT NULL,
            entity_type  TEXT    NOT NULL DEFAULT '',
            entity_id    TEXT    NOT NULL DEFAULT '',
            site         TEXT    NOT NULL DEFAULT '',
            reason       TEXT    NOT NULL DEFAULT '',
            created_by   TEXT    NOT NULL DEFAULT '',
            created_at   TEXT    NOT NULL DEFAULT '',
            UNIQUE (provider, org_ref, scope, entity_type, entity_id, site)
        )
        """
    )
    await db.commit()
