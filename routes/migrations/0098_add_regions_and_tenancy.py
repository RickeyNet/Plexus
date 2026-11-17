"""
Migration 0098: location hierarchy and tenancy.

The location tree is region > region ... > site (``geo_sites``) > floor or
area (``geo_floors``). Adds:

  - regions - a named area that holds sites and other regions:
    ``parent_id`` (another region, NULL for a top-level one; a region with
    child regions or sites cannot be deleted), ``name`` (unique among its
    siblings, ignoring case), ``description`` and the stamps.
  - geo_sites gain ``region_id`` (cleared when the region goes), ``status``
    (``active``, ``planned``, ``staging``, ``decommissioning``, ``retired``),
    ``facility``, ``time_zone`` and ``tenant_id``.
  - tenant_groups - a tree of groups (``parent_id``) to file tenants under.
  - tenants - who an object belongs to or serves: ``name`` (unique ignoring
    case), ``group_id`` (cleared when the group goes), ``description``,
    ``comments`` and the stamps.
  - ``tenant_id`` on hosts, ipam_prefixes, ipam_allocations, vlans and vrfs,
    cleared when the tenant is deleted.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 98
DESCRIPTION = "Add regions (location hierarchy) and tenants"

_STAMPS = """
            created_by  TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT '',
            updated_by  TEXT NOT NULL DEFAULT ''
"""

_TENANT_TABLES = ("hosts", "ipam_prefixes", "ipam_allocations", "vlans", "vrfs", "geo_sites")


async def up(db) -> None:
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS regions (
            id          SERIAL PRIMARY KEY,
            parent_id   INTEGER REFERENCES regions(id) ON DELETE RESTRICT,
            name        TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_regions_parent_name "
        "ON regions (COALESCE(parent_id, 0), lower(name))"
    )
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS tenant_groups (
            id          SERIAL PRIMARY KEY,
            parent_id   INTEGER REFERENCES tenant_groups(id) ON DELETE RESTRICT,
            name        TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        )
        """
    )
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_groups_name ON tenant_groups (lower(name))")
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS tenants (
            id          SERIAL PRIMARY KEY,
            group_id    INTEGER REFERENCES tenant_groups(id) ON DELETE SET NULL,
            name        TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            comments    TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        )
        """
    )
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_name ON tenants (lower(name))")

    await db.execute(
        "ALTER TABLE geo_sites ADD COLUMN IF NOT EXISTS region_id INTEGER REFERENCES regions(id) ON DELETE SET NULL"
    )
    await db.execute("ALTER TABLE geo_sites ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'")
    await db.execute("ALTER TABLE geo_sites ADD COLUMN IF NOT EXISTS facility TEXT NOT NULL DEFAULT ''")
    await db.execute("ALTER TABLE geo_sites ADD COLUMN IF NOT EXISTS time_zone TEXT NOT NULL DEFAULT ''")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_geo_sites_region ON geo_sites (region_id)")

    for table in _TENANT_TABLES:
        await db.execute(
            f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS tenant_id INTEGER "  # nosec B608 - fixed table names
            "REFERENCES tenants(id) ON DELETE SET NULL"
        )
        await db.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_tenant ON {table} (tenant_id)")
    await db.commit()
