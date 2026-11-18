"""
Migration 0109: custom data on every object type, computed fields and
relationships.

Custom fields and tags (migration 0083) are keyed by ``(object_type,
object_key)``, so new object types need no new value tables: the registry in
``netcontrol.custom_fields`` names them. Adds:

  - computed_fields - read-only fields an admin defines per object type,
    rendered from a Jinja2 template over the object's attributes: ``key``
    (unique per object type), ``label``, ``object_type``, ``template``,
    ``description``, ``sort_order`` and the stamps.
  - relationships - a link kind an admin defines between two object types:
    ``key`` (unique), ``label``, ``source_type``, ``destination_type``,
    ``cardinality`` (``one-to-one``, ``one-to-many``, ``many-to-many``),
    ``description`` and the stamps.
  - relationship_links - one association: ``relationship_id`` (deleted with
    the relationship), the source and destination object (type and key),
    unique per relationship and pair. Cardinality is checked by Plexus when a
    link is added.
  - plexus_purge_object_data(type, id column) - a trigger function that
    deletes an object's tags, custom field values and relationship links
    when its row is deleted, and an AFTER DELETE trigger calling it on the
    table of every registered object type keyed by id (every delete path
    and cascade alike).

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

from netcontrol.custom_fields import OBJECT_TYPE_SPECS, purge_trigger_sql

VERSION = 109
DESCRIPTION = "Add custom data on every object type, computed fields and relationships"

_STAMPS = """
            created_by  TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT ''
"""

# The object types whose rows get the purge trigger (prefixes are keyed by
# subnet|vrf, not by row id, and keep their data across IPAM resyncs).
_TRIGGER_TYPES: tuple[str, ...] = (
    "host",
    "group",
    "vrf",
    "vlan",
    "region",
    "site",
    "tenant",
    "manufacturer",
    "device_type",
    "device_role",
    "circuit_provider",
    "circuit",
    "cluster",
    "virtual_machine",
    "autonomous_system",
    "bgp_peering",
    "rack",
    "cable",
)

_PURGE_FUNCTION = """
CREATE OR REPLACE FUNCTION plexus_purge_object_data() RETURNS trigger AS $$
DECLARE
    obj_key TEXT := to_jsonb(OLD) ->> TG_ARGV[1];
BEGIN
    DELETE FROM tag_assignments WHERE object_type = TG_ARGV[0] AND object_key = obj_key;
    DELETE FROM custom_field_values WHERE object_type = TG_ARGV[0] AND object_key = obj_key;
    DELETE FROM relationship_links
        WHERE (source_type = TG_ARGV[0] AND source_key = obj_key)
           OR (destination_type = TG_ARGV[0] AND destination_key = obj_key);
    RETURN OLD;
END
$$ LANGUAGE plpgsql
"""


async def up(db) -> None:
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS computed_fields (
            id          SERIAL  PRIMARY KEY,
            key         TEXT    NOT NULL,
            label       TEXT    NOT NULL,
            object_type TEXT    NOT NULL,
            template    TEXT    NOT NULL DEFAULT '',
            description TEXT    NOT NULL DEFAULT '',
            sort_order  INTEGER NOT NULL DEFAULT 0,
            {_STAMPS}
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_computed_fields_type_key ON computed_fields (object_type, key)"
    )
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS relationships (
            id               SERIAL PRIMARY KEY,
            key              TEXT   NOT NULL UNIQUE,
            label            TEXT   NOT NULL,
            source_type      TEXT   NOT NULL,
            destination_type TEXT   NOT NULL,
            cardinality      TEXT   NOT NULL DEFAULT 'many-to-many',
            description      TEXT   NOT NULL DEFAULT '',
            {_STAMPS}
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS relationship_links (
            id               SERIAL  PRIMARY KEY,
            relationship_id  INTEGER NOT NULL REFERENCES relationships(id) ON DELETE CASCADE,
            source_type      TEXT    NOT NULL,
            source_key       TEXT    NOT NULL,
            destination_type TEXT    NOT NULL,
            destination_key  TEXT    NOT NULL,
            created_by       TEXT    NOT NULL DEFAULT '',
            created_at       TEXT    NOT NULL DEFAULT '',
            UNIQUE (relationship_id, source_key, destination_key)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_relationship_links_source ON relationship_links (source_type, source_key)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_relationship_links_destination "
        "ON relationship_links (destination_type, destination_key)"
    )
    await db.execute(_PURGE_FUNCTION)
    for object_type in _TRIGGER_TYPES:
        for statement in purge_trigger_sql(OBJECT_TYPE_SPECS[object_type]):
            await db.execute(statement)
    await db.commit()
