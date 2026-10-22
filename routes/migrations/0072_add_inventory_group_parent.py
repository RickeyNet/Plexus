"""
Migration 0072: Inventory group hierarchy (parent and sub-groups).

Adds ``inventory_groups.parent_id`` (NULL for a top-level group) so a group
can hold sub-groups, e.g. ``Meraki`` with one sub-group per Meraki network.
A host still belongs to exactly one group; a parent's hosts are its direct
hosts only.

Names were globally unique (``name TEXT NOT NULL UNIQUE``, auto-named
``inventory_groups_name_key`` by Postgres). They become unique among
siblings: a unique index on ``(COALESCE(parent_id, 0), name)`` keeps
top-level names unique among top-level groups and lets two parents each
have a sub-group of the same name.

The baseline SCHEMA declares the column (for fresh installs) but not the
foreign key or the indexes: SCHEMA runs before migrations on every start,
and an existing database has no ``parent_id`` until this migration adds it.
Every step is idempotent, so a fresh database (which runs this migration
too) ends in the same shape as a migrated one.
"""

from __future__ import annotations

VERSION = 72
DESCRIPTION = "Add inventory_groups.parent_id; group names unique among siblings"


async def up(db) -> None:
    await db.execute("ALTER TABLE inventory_groups ADD COLUMN IF NOT EXISTS parent_id INTEGER DEFAULT NULL")
    # Named like the FKs routes.database._extract_postgres_fks adds; no
    # ON DELETE action, so a parent with sub-groups cannot be deleted.
    await db.execute(
        "DO $$ BEGIN "
        "ALTER TABLE inventory_groups ADD CONSTRAINT fk_inventory_groups_parent_id_inventory_groups "
        "FOREIGN KEY (parent_id) REFERENCES inventory_groups(id); "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_inventory_groups_parent_id ON inventory_groups (parent_id)")
    await db.execute("ALTER TABLE inventory_groups DROP CONSTRAINT IF EXISTS inventory_groups_name_key")
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_inventory_groups_sibling_name "
        "ON inventory_groups ((COALESCE(parent_id, 0)), name)"
    )
    await db.commit()
