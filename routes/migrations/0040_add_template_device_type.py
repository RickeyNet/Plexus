"""
Migration 0040: Add device_type to templates; key uniqueness on (name, device_type).

Phase 12 of the multi-vendor driver framework lets a single logical
template (e.g. "SNMPv3 Standard") carry vendor-specific command bodies.
A template row gains a ``device_type`` column:

  * ``''`` (empty) - the generic/default body, applied to any host
    whose device_type has no vendor-specific variant.  Every template
    that existed before this migration is generic, so the column
    defaults to ``''`` and prior behaviour is preserved exactly.
  * a non-empty Netmiko device_type string (e.g. ``paloalto_panos``,
    ``fortinet``, ``cisco_nxos``) - a vendor-specific variant of the
    same ``name``.

The old schema had a column-level ``name TEXT NOT NULL UNIQUE``.  That
constraint must become composite ``UNIQUE(name, device_type)`` so two
rows can share a name while differing only by vendor.  SQLite cannot
drop a column-level UNIQUE in place, so the table is rebuilt; Postgres
drops the auto-named unique constraint and adds the composite one.

Job-time resolution (see ``routes.database.resolve_template_for_device_type``)
prefers the ``(name, host.device_type)`` row and falls back to the
``(name, '')`` generic row, so a mixed-vendor inventory group runs the
right command body per host without the operator picking N templates.
"""

from __future__ import annotations

import os

VERSION = 40
DESCRIPTION = "Add templates.device_type; uniqueness on (name, device_type)"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _column_exists_sqlite(db) -> bool:
    cursor = await db.execute("PRAGMA table_info(templates)")
    rows = await cursor.fetchall()
    return any(row[1] == "device_type" for row in rows)


async def _up_sqlite(db) -> None:
    if await _column_exists_sqlite(db):
        return
    # SQLite can't drop the column-level UNIQUE(name) in place, so
    # rebuild the table with the composite key, copy the data, swap.
    await db.execute(
        """
        CREATE TABLE templates_new (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            device_type TEXT    NOT NULL DEFAULT '',
            content     TEXT    NOT NULL DEFAULT '',
            description TEXT    DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(name, device_type)
        )
        """
    )
    await db.execute(
        """
        INSERT INTO templates_new
            (id, name, device_type, content, description, created_at, updated_at)
        SELECT id, name, '', content, description, created_at, updated_at
        FROM templates
        """
    )
    await db.execute("DROP TABLE templates")
    await db.execute("ALTER TABLE templates_new RENAME TO templates")
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        "ALTER TABLE templates ADD COLUMN IF NOT EXISTS "
        "device_type TEXT NOT NULL DEFAULT ''"
    )
    # The original column-level UNIQUE was auto-named templates_name_key
    # by Postgres.  Drop it (IF EXISTS so a re-run is a no-op) and add
    # the composite constraint in its place.
    await db.execute(
        "ALTER TABLE templates DROP CONSTRAINT IF EXISTS templates_name_key"
    )
    await db.execute(
        "ALTER TABLE templates DROP CONSTRAINT IF EXISTS templates_name_device_type_key"
    )
    await db.execute(
        "ALTER TABLE templates ADD CONSTRAINT templates_name_device_type_key "
        "UNIQUE (name, device_type)"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
