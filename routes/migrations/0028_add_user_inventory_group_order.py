"""
Migration 0028: Per-user custom ordering of inventory groups.

Adds:
  - user_inventory_group_order — stores a user's preferred display order for
    inventory groups. Each row pins a (user_id, group_id) pair to a position.
    Groups without a row for the current user fall to the bottom alphabetically.
"""

from __future__ import annotations

import os

VERSION = 28
DESCRIPTION = "Add user_inventory_group_order for per-user group ordering"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS user_inventory_group_order (
            user_id   INTEGER NOT NULL,
            group_id  INTEGER NOT NULL,
            position  INTEGER NOT NULL,
            PRIMARY KEY (user_id, group_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES inventory_groups(id) ON DELETE CASCADE
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_user_inv_group_order_user "
        "ON user_inventory_group_order (user_id, position)"
    )
    await db.commit()


async def _up_postgres(db) -> None:
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
        "CREATE INDEX IF NOT EXISTS idx_user_inv_group_order_user "
        "ON user_inventory_group_order (user_id, position)"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
