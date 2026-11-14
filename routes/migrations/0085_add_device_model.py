"""
Migration 0085: device model for hosts.

A host points at managed records instead of loose strings. Adds:

  - manufacturers - name (unique ignoring case), description.
  - device_types - a hardware model of one manufacturer (unique per
    manufacturer ignoring case), part number, rack units, description.
    Deleted with their manufacturer.
  - device_roles - name (unique ignoring case), palette color slot,
    description. Seeded with the categories SNMP discovery guesses.
  - host_statuses - lifecycle statuses, like roles plus ``is_default``
    (at most one row is 1). Seeded; Active is the default.
  - hosts.device_type_id, role_id, lifecycle_status_id, site_id (set to
    NULL when the record goes), location_detail (rack, room), and the
    ``hardware_locked`` / ``role_locked`` flags that stop discovery
    overwriting a value a person set.

``hosts.device_type`` (the SSH driver key), ``hosts.status`` (reachability),
``hosts.model`` and ``hosts.device_category`` keep their meaning.

The backfill is set-based and safe to run twice: each host with a model
gets a manufacturer (from its driver key) and a device type, a role from its
category, the Active status, and the site of the floor it is placed on (the
lowest site id when floors of several sites hold it).

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

VERSION = 85
DESCRIPTION = "Add device model: manufacturers, device types, roles, lifecycle statuses"

# Driver key prefix to manufacturer, first match wins. A copy of
# netcontrol.device_model.MANUFACTURER_PREFIXES: a migration must not import
# runtime code that can change later.
_MANUFACTURER_PREFIXES: tuple[tuple[str, str], ...] = (
    ("meraki", "Cisco Meraki"),
    ("cisco", "Cisco"),
    ("juniper", "Juniper"),
    ("arista", "Arista"),
    ("fortinet", "Fortinet"),
    ("paloalto", "Palo Alto Networks"),
    ("aruba", "Aruba"),
    ("hp", "HPE"),
    ("dell", "Dell"),
    ("extreme", "Extreme Networks"),
    ("huawei", "Huawei"),
    ("mikrotik", "MikroTik"),
    ("checkpoint", "Check Point"),
    ("f5", "F5"),
    ("ubiquiti", "Ubiquiti"),
    ("vyos", "VyOS"),
)

_ROLES: tuple[tuple[str, str], ...] = (
    ("Router", "blue"),
    ("Switch", "teal"),
    ("Firewall", "red"),
    ("Wireless", "purple"),
    ("WLC", "purple"),
    ("Phone", "gray"),
    ("Server", "orange"),
    ("Unknown", "gray"),
)

_STATUSES: tuple[tuple[str, str], ...] = (
    ("Active", "green"),
    ("Planned", "blue"),
    ("Staged", "teal"),
    ("Maintenance", "yellow"),
    ("Decommissioning", "orange"),
    ("Retired", "gray"),
)

_DEFAULT_STATUS = "Active"
_MODEL_MAX = 100


def _manufacturer_case() -> tuple[str, tuple[str, ...]]:
    """A SQL ``CASE`` naming the manufacturer of host ``h`` from its driver
    key, and its parameters."""
    whens = " ".join("WHEN lower(h.device_type) LIKE ? THEN ?" for _ in _MANUFACTURER_PREFIXES)
    params: list[str] = []
    for prefix, name in _MANUFACTURER_PREFIXES:
        params.extend((prefix + "%", name))
    return f"(CASE {whens} ELSE 'Unknown' END)", tuple(params)


async def _create_tables(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS manufacturers (
            id          SERIAL PRIMARY KEY,
            name        TEXT    NOT NULL,
            description TEXT    NOT NULL DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_manufacturers_name_lower ON manufacturers (lower(name))")
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS device_types (
            id              SERIAL PRIMARY KEY,
            manufacturer_id INTEGER NOT NULL REFERENCES manufacturers(id) ON DELETE CASCADE,
            model           TEXT    NOT NULL,
            part_number     TEXT    NOT NULL DEFAULT '',
            u_height        INTEGER NOT NULL DEFAULT 0,
            description     TEXT    NOT NULL DEFAULT '',
            created_at      TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_device_types_model_lower ON device_types (manufacturer_id, lower(model))"
    )
    for table in ("device_roles", "host_statuses"):
        extra = "is_default  INTEGER NOT NULL DEFAULT 0," if table == "host_statuses" else ""
        await db.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {table} (
                id          SERIAL PRIMARY KEY,
                name        TEXT    NOT NULL,
                color       TEXT    NOT NULL DEFAULT 'gray',
                description TEXT    NOT NULL DEFAULT '',
                {extra}
                created_at  TEXT    NOT NULL DEFAULT ''
            )
            """  # nosec B608 - fixed table names
        )
        await db.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS idx_{table}_name_lower ON {table} (lower(name))")
    # At most one default status.
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_host_statuses_one_default ON host_statuses (is_default) "
        "WHERE is_default = 1"
    )


async def _add_host_columns(db) -> None:
    for column, target in (
        ("device_type_id", "device_types"),
        ("role_id", "device_roles"),
        ("lifecycle_status_id", "host_statuses"),
        ("site_id", "geo_sites"),
    ):
        await db.execute(
            f"ALTER TABLE hosts ADD COLUMN IF NOT EXISTS {column} INTEGER REFERENCES {target}(id) ON DELETE SET NULL"
        )
        await db.execute(f"CREATE INDEX IF NOT EXISTS idx_hosts_{column} ON hosts ({column})")
    await db.execute("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS location_detail TEXT NOT NULL DEFAULT ''")
    await db.execute("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS hardware_locked INTEGER NOT NULL DEFAULT 0")
    await db.execute("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS role_locked INTEGER NOT NULL DEFAULT 0")


async def _seed(db) -> None:
    for name, color in _ROLES:
        await db.execute(
            "INSERT INTO device_roles (name, color, created_at) VALUES (?, ?, '') ON CONFLICT DO NOTHING",
            (name, color),
        )
    for name, color in _STATUSES:
        await db.execute(
            "INSERT INTO host_statuses (name, color, created_at) VALUES (?, ?, '') ON CONFLICT DO NOTHING",
            (name, color),
        )
    await db.execute(
        """UPDATE host_statuses SET is_default = 1
           WHERE lower(name) = lower(?) AND NOT EXISTS (SELECT 1 FROM host_statuses WHERE is_default = 1)""",
        (_DEFAULT_STATUS,),
    )


async def backfill(db) -> None:
    """Link existing hosts to the catalogues; touches only hosts whose value
    is still NULL, so running it again changes nothing. Does not commit."""
    case_sql, case_params = _manufacturer_case()
    model = f"left(trim(h.model), {_MODEL_MAX})"
    await db.execute(
        f"""INSERT INTO manufacturers (name, created_at)
            SELECT DISTINCT {case_sql}, '' FROM hosts h
            WHERE trim(h.model) <> '' AND h.device_type_id IS NULL
            ON CONFLICT DO NOTHING""",  # nosec B608 - fixed clauses, placeholders only
        case_params,
    )
    await db.execute(
        f"""INSERT INTO device_types (manufacturer_id, model, created_at)
            SELECT DISTINCT ON (m.id, lower({model})) m.id, {model}, ''
            FROM hosts h JOIN manufacturers m ON lower(m.name) = lower({case_sql})
            WHERE trim(h.model) <> '' AND h.device_type_id IS NULL
            ORDER BY m.id, lower({model}), {model}
            ON CONFLICT DO NOTHING""",  # nosec B608 - fixed clauses, placeholders only
        case_params,
    )
    await db.execute(
        f"""UPDATE hosts AS h SET device_type_id = dt.id
            FROM device_types dt JOIN manufacturers m ON m.id = dt.manufacturer_id
            WHERE h.device_type_id IS NULL AND trim(h.model) <> ''
              AND lower(dt.model) = lower({model}) AND lower(m.name) = lower({case_sql})""",  # nosec B608 - fixed clauses, placeholders only
        case_params,
    )
    await db.execute(
        """UPDATE hosts AS h SET role_id = r.id FROM device_roles r
           WHERE h.role_id IS NULL AND trim(h.device_category) <> ''
             AND lower(r.name) = lower(trim(h.device_category))"""
    )
    await db.execute(
        """UPDATE hosts SET lifecycle_status_id = (SELECT id FROM host_statuses WHERE lower(name) = lower(?))
           WHERE lifecycle_status_id IS NULL""",
        (_DEFAULT_STATUS,),
    )
    await db.execute(
        """UPDATE hosts AS h SET site_id = s.site_id
           FROM (SELECT p.host_id, MIN(f.site_id) AS site_id
                 FROM geo_placements p JOIN geo_floors f ON f.id = p.floor_id
                 GROUP BY p.host_id) s
           WHERE h.id = s.host_id AND h.site_id IS NULL"""
    )


async def up(db) -> None:
    await _create_tables(db)
    await _add_host_columns(db)
    await _seed(db)
    await backfill(db)
    await db.commit()
