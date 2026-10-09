"""
Migration 0028: Per-user custom ordering of inventory groups.

Adds:
  - user_inventory_group_order - stores a user's preferred display order for
    inventory groups. Each row pins a (user_id, group_id) pair to a position.
    Groups without a row for the current user fall to the bottom alphabetically.
"""

from __future__ import annotations

VERSION = 28
DESCRIPTION = "Add user_inventory_group_order for per-user group ordering"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS user_inventory_group_order (
            user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            group_id  INTEGER NOT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
            position  INTEGER NOT NULL,
            PRIMARY KEY (user_id, group_id)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_user_inv_group_order_user ON user_inventory_group_order (user_id, position)"
    )
    await db.commit()
