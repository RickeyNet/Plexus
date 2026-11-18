"""
Migration 0117: the SSH credential an inventory group's discovery remembers.

Adds ``inventory_groups.discovery_credential_id``: the stored credential the
last discovery scan or sync of the group was explicitly run with (NULL: the
Plexus service credential, the default). A scan or sync with no credential
uses it before the service credential when the caller may use it; the
scheduled discovery sync uses it only when it is a service credential.

The foreign key clears the column when the credential is deleted
(``ON DELETE SET NULL``); deleting the group deletes the row and with it the
remembered credential. As with ``parent_id`` (migration 0072) the baseline
SCHEMA declares the column but not the foreign key: SCHEMA runs before
migrations on every start, and an existing database has no column until
this migration adds it. Every step is idempotent.
"""

from __future__ import annotations

VERSION = 117
DESCRIPTION = "Add inventory_groups.discovery_credential_id"


async def up(db) -> None:
    await db.execute(
        "ALTER TABLE inventory_groups ADD COLUMN IF NOT EXISTS discovery_credential_id INTEGER DEFAULT NULL"
    )
    await db.execute(
        "DO $$ BEGIN "
        "ALTER TABLE inventory_groups ADD CONSTRAINT fk_inventory_groups_discovery_credential_id_credentials "
        "FOREIGN KEY (discovery_credential_id) REFERENCES credentials(id) ON DELETE SET NULL; "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
    )
    await db.commit()
