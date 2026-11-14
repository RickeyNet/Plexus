"""
Migration 0086: VRF and VLAN records, and the addresses of device interfaces.

Adds:

  - vrfs - a VRF by name (unique; ``""``, the global VRF, has no record),
    route distinguisher, description, origin (``manual`` or
    ``discovered``). The text columns that hold VRF names elsewhere
    (``hosts.vrf_name``, ``ipam_prefixes.vrf``...) stay and are matched to a
    record by exact name; no foreign keys point here.
  - vlans - a VLAN id (1 to 4094) of a site (``geo_sites``, deleted with
    it) or of no site, name, description, origin. One record per site and
    VLAN id.
  - interface_addresses - the addresses a device's interfaces carry, read
    from its stored running configuration, with the network, the VRF, the
    role (primary, secondary, virtual) and, on a VLAN interface, the VLAN
    id. Replaced per host each time a configuration is stored.
  - host_vrfs - the VRFs a device has an interface or a static route in.

The backfill is set-based and safe to run twice: a ``discovered`` VRF for
every name the hosts and IPAM tables hold, and a ``discovered`` VLAN for
every VLAN a device defines, at the device's site (none: no site), named as
the device with the lowest id names it. Interface addresses are not filled
here (that needs the configuration parsers): the app parses the stored
configurations once, in the background, after its first start on 0086.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

VERSION = 86
DESCRIPTION = "Add VRF and VLAN records and interface addresses"

_NAME_MAX = 64
_NOW = "to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')"


async def _create_tables(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS vrfs (
            id          SERIAL PRIMARY KEY,
            name        TEXT    NOT NULL UNIQUE,
            rd          TEXT    NOT NULL DEFAULT '',
            description TEXT    NOT NULL DEFAULT '',
            origin      TEXT    NOT NULL DEFAULT 'manual',
            created_at  TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_vrfs_name_lower ON vrfs (lower(name))")
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS vlans (
            id          SERIAL PRIMARY KEY,
            vid         INTEGER NOT NULL CHECK (vid BETWEEN 1 AND 4094),
            name        TEXT    NOT NULL DEFAULT '',
            site_id     INTEGER REFERENCES geo_sites(id) ON DELETE CASCADE,
            description TEXT    NOT NULL DEFAULT '',
            origin      TEXT    NOT NULL DEFAULT 'manual',
            created_at  TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_vlans_site_vid ON vlans (COALESCE(site_id, 0), vid)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_vlans_vid ON vlans (vid)")
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS interface_addresses (
            id            SERIAL PRIMARY KEY,
            host_id       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            interface     TEXT    NOT NULL,
            interface_key TEXT    NOT NULL DEFAULT '',
            address       TEXT    NOT NULL,
            prefix_length INTEGER NOT NULL DEFAULT 0,
            network       TEXT    NOT NULL DEFAULT '',
            vrf_name      TEXT    NOT NULL DEFAULT '',
            role          TEXT    NOT NULL DEFAULT 'primary',
            protocol      TEXT    NOT NULL DEFAULT '',
            svi_vid       INTEGER NOT NULL DEFAULT 0,
            collected_at  TEXT    NOT NULL DEFAULT '',
            UNIQUE (host_id, interface, address)
        )
        """
    )
    for column in ("address", "network", "vrf_name"):
        await db.execute(
            f"CREATE INDEX IF NOT EXISTS idx_interface_addresses_{column} ON interface_addresses ({column})"
        )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS host_vrfs (
            host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            vrf_name        TEXT    NOT NULL,
            interface_count INTEGER NOT NULL DEFAULT 0,
            collected_at    TEXT    NOT NULL DEFAULT '',
            PRIMARY KEY (host_id, vrf_name)
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_host_vrfs_vrf_name ON host_vrfs (vrf_name)")


async def backfill(db) -> None:
    """Create the records the stored data names; existing records are left
    alone, so running it again changes nothing. Does not commit."""
    await db.execute(
        f"""INSERT INTO vrfs (name, origin, created_at)
            SELECT DISTINCT trim(n), 'discovered', {_NOW}
            FROM (SELECT vrf_name AS n FROM hosts
                  UNION SELECT vrf FROM ipam_prefixes
                  UNION SELECT vrf_name FROM ipam_allocations) names
            WHERE trim(n) <> '' AND length(trim(n)) <= {_NAME_MAX}
            ON CONFLICT DO NOTHING"""  # nosec B608 - fixed clauses, no values
    )
    await db.execute(
        f"""INSERT INTO vlans (vid, name, site_id, origin, created_at)
            SELECT DISTINCT ON (COALESCE(h.site_id, 0), d.vlan_id)
                   d.vlan_id, left(trim(d.name), {_NAME_MAX}), h.site_id, 'discovered', {_NOW}
            FROM vlan_definitions d JOIN hosts h ON h.id = d.host_id
            WHERE d.vlan_id BETWEEN 1 AND 4094
            ORDER BY COALESCE(h.site_id, 0), d.vlan_id, d.host_id
            ON CONFLICT DO NOTHING"""  # nosec B608 - fixed clauses, no values
    )


async def up(db) -> None:
    await _create_tables(db)
    await backfill(db)
    await db.commit()
