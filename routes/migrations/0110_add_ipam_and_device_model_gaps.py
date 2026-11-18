"""
Migration 0110: IPAM namespaces, route targets, VLAN groups, RIRs and
aggregates; console ports; device type component templates.

Adds:

  - ipam_namespaces - a namespace groups VRFs and prefixes so the same
    address space may exist once per namespace: name (unique ignoring
    case), description and the stamps. Row 1 is "Global", which cannot be
    deleted.
  - vrfs and ipam_prefixes gain ``namespace_id`` (default 1, Global; a
    namespace in use cannot be deleted). Every existing VRF and prefix lands
    in Global, so nothing about the data changes.
  - route_targets - a BGP extended community: name (``65000:100``,
    ``4200000000:1`` or ``192.0.2.1:100``, unique ignoring case), tenant
    (cleared when it goes), description and the stamps.
  - vrf_route_targets - which route targets a VRF imports and exports
    (``direction`` ``import`` or ``export``), deleted with either side.
  - vlan_groups - a named pool of VLAN ids ``min_vid`` to ``max_vid``
    (1 to 4094), scoped to a site or a region or neither (cleared when
    it goes), description and the stamps; name unique ignoring case.
  - vlans gain ``vlan_group_id`` (cleared when the group goes); a VLAN id
    is unique within a group.
  - rirs - a regional internet registry or private allocator: name (unique
    ignoring case), ``is_private``, description and the stamps.
  - aggregates - a top-level block of address space: ``prefix`` (CIDR,
    unique), RIR (a RIR with aggregates cannot be deleted), ``date_added``
    (``YYYY-MM-DD`` or ``''``), tenant (cleared), description and the stamps.
  - console_ports - the console ports of a host (name unique per host
    ignoring case), connector type and description; deleted with the host.
  - device_component_templates - the components every device of a device
    type has: ``component_type`` (``interface``, ``console_port``,
    ``power_port``, ``rear_port``, ``front_port``, ``module_bay``), name
    (unique per device type and component type ignoring case), connector or
    interface ``type``, ``positions`` (rear port), the rear port template
    and position a front port maps to, the power draws, description and the
    stamps. Deleted with the device type.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 110
DESCRIPTION = "Add IPAM namespaces, route targets, VLAN groups, RIRs, aggregates and device type component templates"

_STAMPS = """
            created_by  TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT '',
            updated_by  TEXT NOT NULL DEFAULT ''
"""

_TABLES: tuple[tuple[str, str], ...] = (
    (
        "ipam_namespaces",
        f"""
            id          SERIAL PRIMARY KEY,
            name        TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "route_targets",
        f"""
            id          SERIAL PRIMARY KEY,
            name        TEXT NOT NULL,
            tenant_id   INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "vrf_route_targets",
        """
            vrf_id          INTEGER NOT NULL REFERENCES vrfs(id) ON DELETE CASCADE,
            route_target_id INTEGER NOT NULL REFERENCES route_targets(id) ON DELETE CASCADE,
            direction       TEXT NOT NULL CHECK (direction IN ('import', 'export')),
            PRIMARY KEY (vrf_id, route_target_id, direction)
        """,
    ),
    (
        "vlan_groups",
        f"""
            id          SERIAL PRIMARY KEY,
            name        TEXT NOT NULL,
            site_id     INTEGER REFERENCES geo_sites(id) ON DELETE SET NULL,
            region_id   INTEGER REFERENCES regions(id) ON DELETE SET NULL,
            min_vid     INTEGER NOT NULL DEFAULT 1 CHECK (min_vid BETWEEN 1 AND 4094),
            max_vid     INTEGER NOT NULL DEFAULT 4094 CHECK (max_vid BETWEEN 1 AND 4094),
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS},
            CHECK (min_vid <= max_vid),
            CHECK (site_id IS NULL OR region_id IS NULL)
        """,
    ),
    (
        "rirs",
        f"""
            id          SERIAL PRIMARY KEY,
            name        TEXT NOT NULL,
            is_private  INTEGER NOT NULL DEFAULT 0,
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "aggregates",
        f"""
            id          SERIAL PRIMARY KEY,
            prefix      TEXT NOT NULL,
            rir_id      INTEGER NOT NULL REFERENCES rirs(id) ON DELETE RESTRICT,
            date_added  TEXT NOT NULL DEFAULT '',
            tenant_id   INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "console_ports",
        f"""
            id          SERIAL PRIMARY KEY,
            host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            name        TEXT NOT NULL,
            type        TEXT NOT NULL DEFAULT 'rj-45',
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "device_component_templates",
        f"""
            id                    SERIAL PRIMARY KEY,
            device_type_id        INTEGER NOT NULL REFERENCES device_types(id) ON DELETE CASCADE,
            component_type        TEXT NOT NULL CHECK (component_type IN
                                    ('interface', 'console_port', 'power_port', 'rear_port', 'front_port', 'module_bay')),
            name                  TEXT NOT NULL,
            type                  TEXT NOT NULL DEFAULT '',
            positions             INTEGER NOT NULL DEFAULT 1 CHECK (positions BETWEEN 1 AND 1024),
            rear_port_template_id INTEGER REFERENCES device_component_templates(id) ON DELETE RESTRICT,
            rear_port_position    INTEGER NOT NULL DEFAULT 1 CHECK (rear_port_position BETWEEN 1 AND 1024),
            maximum_draw          INTEGER,
            allocated_draw        INTEGER,
            description           TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
)

_COLUMNS: tuple[str, ...] = (
    "ALTER TABLE vrfs ADD COLUMN IF NOT EXISTS namespace_id INTEGER NOT NULL DEFAULT 1 "
    "REFERENCES ipam_namespaces(id) ON DELETE RESTRICT",
    "ALTER TABLE ipam_prefixes ADD COLUMN IF NOT EXISTS namespace_id INTEGER NOT NULL DEFAULT 1 "
    "REFERENCES ipam_namespaces(id) ON DELETE RESTRICT",
    "ALTER TABLE vlans ADD COLUMN IF NOT EXISTS vlan_group_id INTEGER REFERENCES vlan_groups(id) ON DELETE SET NULL",
)

_INDEXES: tuple[str, ...] = (
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_ipam_namespaces_name ON ipam_namespaces (lower(name))",
    "CREATE INDEX IF NOT EXISTS idx_vrfs_namespace ON vrfs (namespace_id)",
    "CREATE INDEX IF NOT EXISTS idx_ipam_prefixes_namespace ON ipam_prefixes (namespace_id, vrf, subnet)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_route_targets_name ON route_targets (lower(name))",
    "CREATE INDEX IF NOT EXISTS idx_route_targets_tenant ON route_targets (tenant_id)",
    "CREATE INDEX IF NOT EXISTS idx_vrf_route_targets_rt ON vrf_route_targets (route_target_id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_vlan_groups_name ON vlan_groups (lower(name))",
    "CREATE INDEX IF NOT EXISTS idx_vlan_groups_site ON vlan_groups (site_id)",
    "CREATE INDEX IF NOT EXISTS idx_vlan_groups_region ON vlan_groups (region_id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_vlans_group_vid ON vlans (vlan_group_id, vid) WHERE vlan_group_id IS NOT NULL",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_rirs_name ON rirs (lower(name))",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_aggregates_prefix ON aggregates (prefix)",
    "CREATE INDEX IF NOT EXISTS idx_aggregates_rir ON aggregates (rir_id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_console_ports_host_name ON console_ports (host_id, lower(name))",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_component_templates_name "
    "ON device_component_templates (device_type_id, component_type, lower(name))",
    "CREATE INDEX IF NOT EXISTS idx_component_templates_rear ON device_component_templates (rear_port_template_id)",
)


async def up(db) -> None:
    for table, columns in _TABLES:
        await db.execute(f"CREATE TABLE IF NOT EXISTS {table} ({columns})")  # nosec B608 - fixed DDL
    # The Global namespace is row 1, the default of every namespace column.
    await db.execute(
        "INSERT INTO ipam_namespaces (id, name, description, created_by, created_at, updated_at) "
        "VALUES (1, 'Global', 'The default namespace', 'system', "
        "to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'), "
        "to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')) ON CONFLICT DO NOTHING"
    )
    await db.execute(
        "SELECT setval(pg_get_serial_sequence('ipam_namespaces', 'id'), "
        "(SELECT COALESCE(MAX(id), 1) FROM ipam_namespaces))"
    )
    for statement in _COLUMNS:
        await db.execute(statement)
    for statement in _INDEXES:
        await db.execute(statement)
    await db.commit()
