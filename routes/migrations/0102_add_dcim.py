"""
Migration 0102: physical DCIM - racks, device placement, patch panel ports,
modules, power and cables.

Adds:

  - rack_roles - name (unique ignoring case), palette color slot,
    description and the stamps.
  - racks - a rack of a site (``geo_sites``; a site with racks cannot be
    deleted) on an optional floor (``geo_floors``, cleared when it goes):
    name (unique per site ignoring case), facility id, status (``active``,
    ``planned``, ``reserved``, ``available``, ``deprecated``), role
    (``rack_roles``, cleared when it goes), tenant (``tenants``, cleared),
    height in units (1 to 100, default 42), ``desc_units`` (1: unit 1 at the
    top), width (19 or 23 inches), serial, asset tag, description,
    comments and the stamps.
  - rack_reservations - units of a rack (a JSON list of unit numbers)
    held for someone, deleted with the rack: user, description, tenant.
  - hosts gain ``rack_id`` (cleared when the rack goes), ``rack_position``
    (the lowest unit the device occupies, NULL: in the rack but not mounted)
    and ``rack_face`` (``front`` or ``rear``, ``''`` when not mounted).
  - rear_ports / front_ports - the ports of a patch panel (a host): name
    (unique per host ignoring case), connector type, description; a rear
    port has ``positions`` (1 to 1024), a front port maps to one position of
    a rear port of the same host (``rear_port_id``, ``rear_port_position``,
    one front port per rear port position). Deleted with their host.
  - modules - a module installed in a bay of a host (bay unique per host
    ignoring case): module type, part number, serial, asset tag, status,
    description.
  - power_panels - a power panel of a site (a site with panels cannot be
    deleted) on an optional floor; name unique per site ignoring case.
  - power_feeds - a circuit of a panel (deleted with it) to an optional
    rack (cleared when it goes): name unique per panel ignoring case,
    status, type (``primary``, ``redundant``), supply (``ac``, ``dc``),
    phase (``single``, ``three``), voltage, amperage and the maximum
    utilisation in percent.
  - power_ports - the power inlets of a host (name unique per host ignoring
    case) with the maximum and the allocated draw in watts.
  - power_outlets - the outlets of a host (a PDU), each optionally fed by
    one of the host's power ports (cleared when it goes) on feed leg
    ``A``, ``B`` or ``C``.
  - cables - a cable between two endpoints: ``a_type``/``b_type`` (one of
    ``interface``, ``front_port``, ``rear_port``, ``power_port``,
    ``power_outlet``, ``power_feed``, ``circuit_termination``), ``a_id``
    (the record id; NULL for an interface), ``a_host_id`` (the host of an
    interface or port; the cable is deleted with the host) and ``a_name``
    (the interface name), the same for B; status (``connected``,
    ``planned``, ``decommissioning``), type, label, color (hex), length
    and unit, tenant, description and the stamps. A circuit termination is
    referenced by id with no foreign key (``circuit_terminations`` is
    another migration's table); the API checks it exists.
  - cable_endpoints - one row per end of a cable with a unique endpoint key
    (``front_port:12``, ``interface:7:Gi1/0/1``), so an endpoint carries at
    most one cable whichever end it is on. Deleted with the cable.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 102
DESCRIPTION = "Add DCIM: racks, placement, ports, modules, power and cables"

_STAMPS = """
            created_by  TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT '',
            updated_by  TEXT NOT NULL DEFAULT ''
"""

_TABLES: tuple[tuple[str, str], ...] = (
    (
        "rack_roles",
        f"""
            id          SERIAL PRIMARY KEY,
            name        TEXT NOT NULL,
            color       TEXT NOT NULL DEFAULT 'gray',
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "racks",
        f"""
            id          SERIAL PRIMARY KEY,
            site_id     INTEGER NOT NULL REFERENCES geo_sites(id) ON DELETE RESTRICT,
            floor_id    INTEGER REFERENCES geo_floors(id) ON DELETE SET NULL,
            name        TEXT NOT NULL,
            facility_id TEXT NOT NULL DEFAULT '',
            status      TEXT NOT NULL DEFAULT 'active',
            role_id     INTEGER REFERENCES rack_roles(id) ON DELETE SET NULL,
            tenant_id   INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
            u_height    INTEGER NOT NULL DEFAULT 42 CHECK (u_height BETWEEN 1 AND 100),
            desc_units  INTEGER NOT NULL DEFAULT 0,
            width       INTEGER NOT NULL DEFAULT 19 CHECK (width IN (19, 23)),
            serial      TEXT NOT NULL DEFAULT '',
            asset_tag   TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            comments    TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "rack_reservations",
        f"""
            id          SERIAL PRIMARY KEY,
            rack_id     INTEGER NOT NULL REFERENCES racks(id) ON DELETE CASCADE,
            units       TEXT NOT NULL DEFAULT '[]',
            user_name   TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            tenant_id   INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
            {_STAMPS}
        """,
    ),
    (
        "rear_ports",
        f"""
            id          SERIAL PRIMARY KEY,
            host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            name        TEXT NOT NULL,
            type        TEXT NOT NULL DEFAULT '8p8c',
            positions   INTEGER NOT NULL DEFAULT 1 CHECK (positions BETWEEN 1 AND 1024),
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "front_ports",
        f"""
            id                 SERIAL PRIMARY KEY,
            host_id            INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            name               TEXT NOT NULL,
            type               TEXT NOT NULL DEFAULT '8p8c',
            rear_port_id       INTEGER NOT NULL REFERENCES rear_ports(id),
            rear_port_position INTEGER NOT NULL DEFAULT 1 CHECK (rear_port_position BETWEEN 1 AND 1024),
            description        TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "modules",
        f"""
            id          SERIAL PRIMARY KEY,
            host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            bay         TEXT NOT NULL,
            module_type TEXT NOT NULL DEFAULT '',
            part_number TEXT NOT NULL DEFAULT '',
            serial      TEXT NOT NULL DEFAULT '',
            asset_tag   TEXT NOT NULL DEFAULT '',
            status      TEXT NOT NULL DEFAULT 'active',
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "power_panels",
        f"""
            id          SERIAL PRIMARY KEY,
            site_id     INTEGER NOT NULL REFERENCES geo_sites(id) ON DELETE RESTRICT,
            floor_id    INTEGER REFERENCES geo_floors(id) ON DELETE SET NULL,
            name        TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "power_feeds",
        f"""
            id              SERIAL PRIMARY KEY,
            power_panel_id  INTEGER NOT NULL REFERENCES power_panels(id) ON DELETE CASCADE,
            rack_id         INTEGER REFERENCES racks(id) ON DELETE SET NULL,
            name            TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'active',
            type            TEXT NOT NULL DEFAULT 'primary',
            supply          TEXT NOT NULL DEFAULT 'ac',
            phase           TEXT NOT NULL DEFAULT 'single',
            voltage         INTEGER NOT NULL DEFAULT 230,
            amperage        INTEGER NOT NULL DEFAULT 16,
            max_utilization INTEGER NOT NULL DEFAULT 80 CHECK (max_utilization BETWEEN 1 AND 100),
            description     TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "power_ports",
        f"""
            id             SERIAL PRIMARY KEY,
            host_id        INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            name           TEXT NOT NULL,
            maximum_draw   INTEGER,
            allocated_draw INTEGER,
            description    TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "power_outlets",
        f"""
            id            SERIAL PRIMARY KEY,
            host_id       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            name          TEXT NOT NULL,
            power_port_id INTEGER REFERENCES power_ports(id) ON DELETE SET NULL,
            feed_leg      TEXT NOT NULL DEFAULT '',
            description   TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "cables",
        f"""
            id          SERIAL PRIMARY KEY,
            a_type      TEXT NOT NULL,
            a_id        INTEGER,
            a_host_id   INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
            a_name      TEXT NOT NULL DEFAULT '',
            b_type      TEXT NOT NULL,
            b_id        INTEGER,
            b_host_id   INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
            b_name      TEXT NOT NULL DEFAULT '',
            status      TEXT NOT NULL DEFAULT 'connected',
            type        TEXT NOT NULL DEFAULT '',
            label       TEXT NOT NULL DEFAULT '',
            color       TEXT NOT NULL DEFAULT '',
            length      DOUBLE PRECISION,
            length_unit TEXT NOT NULL DEFAULT '',
            tenant_id   INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "cable_endpoints",
        """
            cable_id     INTEGER NOT NULL REFERENCES cables(id) ON DELETE CASCADE,
            side         TEXT NOT NULL CHECK (side IN ('a', 'b')),
            endpoint_key TEXT NOT NULL UNIQUE,
            PRIMARY KEY (cable_id, side)
        """,
    ),
)

_INDEXES: tuple[str, ...] = (
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_rack_roles_name ON rack_roles (lower(name))",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_racks_site_name ON racks (site_id, lower(name))",
    "CREATE INDEX IF NOT EXISTS idx_racks_floor ON racks (floor_id)",
    "CREATE INDEX IF NOT EXISTS idx_racks_role ON racks (role_id)",
    "CREATE INDEX IF NOT EXISTS idx_racks_tenant ON racks (tenant_id)",
    "CREATE INDEX IF NOT EXISTS idx_rack_reservations_rack ON rack_reservations (rack_id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_rear_ports_host_name ON rear_ports (host_id, lower(name))",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_front_ports_host_name ON front_ports (host_id, lower(name))",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_front_ports_rear_position ON front_ports (rear_port_id, rear_port_position)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_modules_host_bay ON modules (host_id, lower(bay))",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_power_panels_site_name ON power_panels (site_id, lower(name))",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_power_feeds_panel_name ON power_feeds (power_panel_id, lower(name))",
    "CREATE INDEX IF NOT EXISTS idx_power_feeds_rack ON power_feeds (rack_id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_power_ports_host_name ON power_ports (host_id, lower(name))",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_power_outlets_host_name ON power_outlets (host_id, lower(name))",
    "CREATE INDEX IF NOT EXISTS idx_power_outlets_port ON power_outlets (power_port_id)",
    "CREATE INDEX IF NOT EXISTS idx_cables_a_host ON cables (a_host_id)",
    "CREATE INDEX IF NOT EXISTS idx_cables_b_host ON cables (b_host_id)",
    "CREATE INDEX IF NOT EXISTS idx_cables_tenant ON cables (tenant_id)",
    "CREATE INDEX IF NOT EXISTS idx_hosts_rack ON hosts (rack_id)",
)


async def up(db) -> None:
    for table, columns in _TABLES:
        await db.execute(f"CREATE TABLE IF NOT EXISTS {table} ({columns})")  # nosec B608 - fixed DDL
    await db.execute(
        "ALTER TABLE hosts ADD COLUMN IF NOT EXISTS rack_id INTEGER REFERENCES racks(id) ON DELETE SET NULL"
    )
    await db.execute("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS rack_position INTEGER")
    await db.execute("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS rack_face TEXT NOT NULL DEFAULT ''")
    for statement in _INDEXES:
        await db.execute(statement)
    await db.commit()
