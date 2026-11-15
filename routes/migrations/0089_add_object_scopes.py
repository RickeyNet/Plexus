"""
Migration 0089: object-level permissions on inventory groups.

Adds:

  - access_groups.object_scope - ``all`` (the default: the group's members
    see every device, as before) or ``groups`` (they see only the inventory
    groups the access group grants).
  - access_group_inventory_scopes - the grants of an access group whose
    ``object_scope`` is ``groups``: one row per inventory group, with
    ``can_write`` (0: read only, 1: read and write). A grant covers the
    inventory group and all of its sub-groups. Deleted with either parent.
"""

from __future__ import annotations

VERSION = 89
DESCRIPTION = "Add access group object scopes on inventory groups"


async def up(db) -> None:
    await db.execute("ALTER TABLE access_groups ADD COLUMN IF NOT EXISTS object_scope TEXT NOT NULL DEFAULT 'all'")
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS access_group_inventory_scopes (
            access_group_id    INTEGER NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
            inventory_group_id INTEGER NOT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
            can_write          INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (access_group_id, inventory_group_id)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_group_inventory_scopes_group "
        "ON access_group_inventory_scopes (inventory_group_id)"
    )
    await db.commit()
