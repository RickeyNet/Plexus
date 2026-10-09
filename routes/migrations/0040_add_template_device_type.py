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
rows can share a name while differing only by vendor.  The migration
drops the auto-named unique constraint and adds the composite one.

Job-time resolution (see ``routes.database.resolve_template_for_device_type``)
prefers the ``(name, host.device_type)`` row and falls back to the
``(name, '')`` generic row, so a mixed-vendor inventory group runs the
right command body per host without the operator picking N templates.
"""

from __future__ import annotations

VERSION = 40
DESCRIPTION = "Add templates.device_type; uniqueness on (name, device_type)"


async def up(db) -> None:
    await db.execute("ALTER TABLE templates ADD COLUMN IF NOT EXISTS device_type TEXT NOT NULL DEFAULT ''")
    # The original column-level UNIQUE was auto-named templates_name_key
    # by Postgres.  Drop it (IF EXISTS so a re-run is a no-op) and add
    # the composite constraint in its place.
    await db.execute("ALTER TABLE templates DROP CONSTRAINT IF EXISTS templates_name_key")
    await db.execute("ALTER TABLE templates DROP CONSTRAINT IF EXISTS templates_name_device_type_key")
    await db.execute("ALTER TABLE templates ADD CONSTRAINT templates_name_device_type_key UNIQUE (name, device_type)")
    await db.commit()
