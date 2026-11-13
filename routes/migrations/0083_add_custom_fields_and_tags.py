"""
Migration 0083: custom fields and tags.

Admins define extra fields and tags; users who can edit an object fill them
in. Data is keyed by ``(object_type, object_key)`` so one set of tables
serves every object type: ``host`` and ``group`` use the row id as text,
``prefix`` uses ``subnet|vrf`` (``routes.db.custom_fields.prefix_key``) so a
prefix keeps its data across IPAM source resyncs. Adds:

  - tags - name (unique ignoring case), palette color slot, description.
  - tag_assignments - which objects carry which tag.
  - custom_fields - field definitions: key and type (fixed once created),
    label, choices for ``select`` and the object types a field applies to
    (JSON lists), required flag, default, help text and display order.
  - custom_field_values - one canonical text value per field and object
    (``netcontrol.custom_fields.canonical_value``); an empty value is never
    stored.

Assignments and values cascade when their tag or field is deleted.
Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

VERSION = 83
DESCRIPTION = "Add custom fields and tags tables"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS tags (
            id          SERIAL PRIMARY KEY,
            name        TEXT    NOT NULL,
            color       TEXT    NOT NULL DEFAULT 'gray',
            description TEXT    NOT NULL DEFAULT '',
            created_by  TEXT    NOT NULL DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_tags_name_lower ON tags (lower(name))")
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS tag_assignments (
            id          SERIAL PRIMARY KEY,
            tag_id      INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
            object_type TEXT    NOT NULL,
            object_key  TEXT    NOT NULL,
            UNIQUE (tag_id, object_type, object_key)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_tag_assignments_object ON tag_assignments (object_type, object_key)"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS custom_fields (
            id                SERIAL PRIMARY KEY,
            key               TEXT    NOT NULL UNIQUE,
            label             TEXT    NOT NULL,
            field_type        TEXT    NOT NULL,
            choices_json      TEXT    NOT NULL DEFAULT '[]',
            object_types_json TEXT    NOT NULL DEFAULT '[]',
            required          INTEGER NOT NULL DEFAULT 0,
            default_value     TEXT    NOT NULL DEFAULT '',
            description       TEXT    NOT NULL DEFAULT '',
            sort_order        INTEGER NOT NULL DEFAULT 0,
            created_by        TEXT    NOT NULL DEFAULT '',
            created_at        TEXT    NOT NULL DEFAULT '',
            updated_at        TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS custom_field_values (
            id          SERIAL PRIMARY KEY,
            field_id    INTEGER NOT NULL REFERENCES custom_fields(id) ON DELETE CASCADE,
            object_type TEXT    NOT NULL,
            object_key  TEXT    NOT NULL,
            value       TEXT    NOT NULL,
            UNIQUE (field_id, object_type, object_key)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_custom_field_values_object ON custom_field_values (object_type, object_key)"
    )
    await db.commit()
