"""VRF and VLAN records, and the addresses device interfaces carry.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables: migration 0086. A VRF record is matched to the VRF text columns
(``hosts.vrf_name``, ``ipam_prefixes.vrf``, ``ipam_allocations.vrf_name``,
``interface_addresses.vrf_name``, ``host_vrfs.vrf_name``) by exact name; no
foreign key points at it. A device's VLAN ``v`` (a ``vlan_definitions`` row)
belongs to the record of the device's site and ``v`` when there is one,
otherwise to the record of no site and ``v``; this is resolved when read.

Discovery (``ensure_vrfs``, ``ensure_vlans_for_host``, the bindings sync)
only creates missing records; it never changes or deletes one.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from netcontrol.drivers import parse_vlan_ranges
from netcontrol.network_objects import VRF_NAME_MAX, port_vlan_modes, vlans_of_port

import routes.database as _dbcore
from routes.database import _LOGGER, _is_unique_violation, _safe_dynamic_update, rows_to_list
from routes.db.custom_fields import _chunks, _marks, _now

__all__ = [
    "create_vlan",
    "create_vrf",
    "delete_vlan",
    "delete_vrf",
    "ensure_vlans_for_host",
    "ensure_vrfs",
    "find_interface_addresses",
    "find_interface_addresses_in_subnet",
    "get_host_vlans_for_hosts",
    "get_interface_addresses_for_host",
    "get_interface_addresses_for_hosts",
    "get_vlan",
    "get_vlan_detail",
    "get_vrf",
    "get_vrf_detail",
    "list_binding_hosts",
    "list_vlan_ports",
    "list_vlans",
    "list_vrfs",
    "replace_host_bindings",
    "update_vlan",
    "update_vrf",
    "vrf_usage",
]

# The VLAN record a ``vlan_definitions`` row ``d`` of host ``h`` resolves to:
# its site's record, else the record of no site. ``{vid}`` is the column that
# holds the VLAN id.
_RESOLVE_VLAN = """COALESCE(
    (SELECT vl.id FROM vlans vl WHERE vl.site_id = h.site_id AND vl.vid = {vid}),
    (SELECT vl.id FROM vlans vl WHERE vl.site_id IS NULL AND vl.vid = {vid}))"""

# Every device VLAN with the record it resolves to (``record_id``, NULL: none).
_RESOLVED = f"""
    SELECT d.host_id, h.hostname, d.vlan_id AS vid, d.name, d.state,
           {_RESOLVE_VLAN.format(vid="d.vlan_id")} AS record_id
    FROM vlan_definitions d JOIN hosts h ON h.id = d.host_id
"""  # nosec B608 - fixed clauses

_ADDRESS_COLUMNS = (
    "host_id",
    "hostname",
    "interface",
    "address",
    "prefix_length",
    "network",
    "vrf_name",
    "role",
    "protocol",
    "svi_vid",
    "collected_at",
)
from routes.db.change_events import tracks_changes
from routes.db.organization import TENANT_UNCHANGED, TenantArg, _Unchanged

_ADDRESS_SELECT = """
    SELECT a.host_id, h.hostname, a.interface, a.address, a.prefix_length, a.network, a.vrf_name,
           a.role, a.protocol, a.svi_vid, a.collected_at
    FROM interface_addresses a JOIN hosts h ON h.id = a.host_id
"""
_ADDRESS_ORDER = " ORDER BY lower(h.hostname), a.host_id, a.interface, a.id"


async def _select(sql: str, params: tuple = ()) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(sql, params)
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


def _address(row: dict) -> dict:
    out = {key: row.get(key) for key in _ADDRESS_COLUMNS}
    out["host_id"] = int(row["host_id"])
    out["hostname"] = row.get("hostname") or ""
    out["prefix_length"] = int(row.get("prefix_length") or 0)
    out["svi_vid"] = int(row.get("svi_vid") or 0)
    out["protocol"] = row.get("protocol") or ""
    out["vrf_name"] = row.get("vrf_name") or ""
    out["collected_at"] = row.get("collected_at") or ""
    return out


def _limited(rows: list[dict], limit: int) -> tuple[list[dict], bool]:
    return rows[:limit], len(rows) > limit


# ── VRFs ─────────────────────────────────────────────────────────────────────

_VRF_SELECT = """
    SELECT v.id, v.name, v.rd, v.description, v.origin, v.created_at, v.tenant_id, tn.name AS tenant_name,
           v.namespace_id, ns.name AS namespace_name,
           COALESCE(hc.n, 0) AS host_count, COALESCE(dc.n, 0) AS device_count,
           COALESCE(pc.n, 0) + COALESCE(ic.n, 0) AS prefix_count, COALESCE(ac.n, 0) AS address_count
    FROM vrfs v
    LEFT JOIN tenants tn ON tn.id = v.tenant_id
    LEFT JOIN ipam_namespaces ns ON ns.id = v.namespace_id
    LEFT JOIN (SELECT vrf_name, COUNT(*) AS n FROM hosts GROUP BY vrf_name) hc ON hc.vrf_name = v.name
    LEFT JOIN (SELECT vrf_name, COUNT(*) AS n FROM host_vrfs GROUP BY vrf_name) dc ON dc.vrf_name = v.name
    LEFT JOIN (SELECT vrf, COUNT(*) AS n FROM ipam_prefixes GROUP BY vrf) pc ON pc.vrf = v.name
    LEFT JOIN (SELECT a.vrf_name, COUNT(DISTINCT a.network) AS n FROM interface_addresses a
               WHERE NOT EXISTS (SELECT 1 FROM ipam_prefixes p WHERE p.vrf = a.vrf_name AND p.subnet = a.network)
               GROUP BY a.vrf_name) ic ON ic.vrf_name = v.name
    LEFT JOIN (SELECT vrf_name, COUNT(*) AS n FROM interface_addresses GROUP BY vrf_name) ac ON ac.vrf_name = v.name
"""


def _tenant_of(row: dict) -> dict:
    tenant = row.get("tenant_id")
    return {"tenant_id": int(tenant) if tenant is not None else None, "tenant_name": row.get("tenant_name")}


def _tenant_set(exprs: list[str], params: list, tenant_id: TenantArg, column: str = "tenant_id") -> None:
    """Add ``column = ?`` (the tenant, or another nullable reference) to an
    update unless the value is left alone (``TENANT_UNCHANGED``)."""
    if not isinstance(tenant_id, _Unchanged):
        exprs.append(f"{column} = ?")
        params.append(tenant_id)


def _vrf(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "rd": row["rd"] or "",
        "description": row["description"] or "",
        "origin": row["origin"],
        "created_at": row["created_at"] or "",
        **_tenant_of(row),
        "namespace_id": int(row["namespace_id"]),
        "namespace_name": row.get("namespace_name") or "",
        "host_count": int(row["host_count"]),
        "device_count": int(row["device_count"]),
        "prefix_count": int(row["prefix_count"]),
        "address_count": int(row["address_count"]),
    }


def _host_ids_condition(column: str, host_ids: Iterable[int] | None) -> tuple[str, tuple[int, ...]]:
    """``column IN (host_ids)`` (``("", ())`` for ``None``; an empty set
    matches nothing). ``column`` is a fixed identifier."""
    if host_ids is None:
        return "", ()
    ids = tuple(sorted({int(h) for h in host_ids}))
    if not ids:
        return "1 = 0", ()
    return f"{column} IN ({_marks(ids)})", ids


async def _scoped_vrf_counts(
    vrfs: list[dict], host_ids: Iterable[int] | None, prefix_scope: tuple[str, tuple] | None
) -> list[dict]:
    """``vrfs`` with their counts limited to the hosts ``host_ids`` and the
    prefixes the SQL condition ``prefix_scope`` (alias ``p``) keeps (object
    scope); unchanged when both are ``None``."""
    if (host_ids is None and prefix_scope is None) or not vrfs:
        return vrfs
    h_sql, h_params = _host_ids_condition("h.id", host_ids)
    hv_sql, _ = _host_ids_condition("hv.host_id", host_ids)
    a_sql, _ = _host_ids_condition("a.host_id", host_ids)
    p_sql, p_params = prefix_scope or ("", ())

    def where(sql: str) -> str:
        return f" WHERE {sql}" if sql else ""

    async def counts(sql: str, params: tuple) -> dict[str, int]:
        return {str(r["k"] or ""): int(r["n"]) for r in await _select(sql, params)}

    hosts = await counts(
        f"SELECT h.vrf_name AS k, COUNT(*) AS n FROM hosts h{where(h_sql)} GROUP BY h.vrf_name",  # nosec B608
        h_params,
    )
    devices = await counts(
        f"SELECT hv.vrf_name AS k, COUNT(*) AS n FROM host_vrfs hv{where(hv_sql)} GROUP BY hv.vrf_name",  # nosec B608
        h_params,
    )
    prefixes = await counts(
        f"SELECT p.vrf AS k, COUNT(*) AS n FROM ipam_prefixes p{where(p_sql)} GROUP BY p.vrf",  # nosec B608
        tuple(p_params),
    )
    networks = await counts(
        "SELECT a.vrf_name AS k, COUNT(DISTINCT a.network) AS n FROM interface_addresses a "
        "WHERE NOT EXISTS (SELECT 1 FROM ipam_prefixes p WHERE p.vrf = a.vrf_name AND p.subnet = a.network)"
        + (f" AND {a_sql}" if a_sql else "")
        + " GROUP BY a.vrf_name",  # nosec B608 - placeholders only
        h_params,
    )
    addresses = await counts(
        f"SELECT a.vrf_name AS k, COUNT(*) AS n FROM interface_addresses a{where(a_sql)} GROUP BY a.vrf_name",  # nosec B608
        h_params,
    )
    for vrf in vrfs:
        name = vrf["name"]
        vrf["host_count"] = hosts.get(name, 0)
        vrf["device_count"] = devices.get(name, 0)
        vrf["prefix_count"] = prefixes.get(name, 0) + networks.get(name, 0)
        vrf["address_count"] = addresses.get(name, 0)
    return vrfs


async def list_vrfs(
    *, host_ids: Iterable[int] | None = None, prefix_scope: tuple[str, tuple] | None = None
) -> list[dict]:
    """Every VRF by name, with its counts (see ``docs/vrfs-and-vlans.md``).
    ``host_ids`` / ``prefix_scope`` (object scope; ``None``: all) count
    only those hosts and the prefixes that SQL condition (alias ``p``)
    keeps."""
    rows = [_vrf(r) for r in await _select(_VRF_SELECT + " ORDER BY lower(v.name), v.name, v.id")]
    return await _scoped_vrf_counts(rows, host_ids, prefix_scope)


async def get_vrf(
    vrf_id: int, *, host_ids: Iterable[int] | None = None, prefix_scope: tuple[str, tuple] | None = None
) -> dict | None:
    rows = await _select(_VRF_SELECT + " WHERE v.id = ?", (int(vrf_id),))
    return (await _scoped_vrf_counts([_vrf(rows[0])], host_ids, prefix_scope))[0] if rows else None


@tracks_changes("vrf", "create")
async def create_vrf(
    *,
    name: str,
    rd: str = "",
    description: str = "",
    origin: str = "manual",
    tenant_id: int | None = None,
    namespace_id: int = 1,
) -> dict:
    """Raises ``ValueError`` when a VRF has the name, ignoring case."""
    taken = ValueError(f"A VRF named '{name}' already exists.")
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT 1 FROM vrfs WHERE lower(name) = lower(?)", (name,))
        if await cursor.fetchone() is not None:
            raise taken
        cursor = await db.execute(
            "INSERT INTO vrfs (name, rd, description, origin, created_at, tenant_id, namespace_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
            (name, rd, description, origin, _now(), tenant_id, int(namespace_id)),
        )
        new_id = int(cursor.lastrowid)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise taken from exc
        raise
    finally:
        await db.close()
    return await _must(get_vrf(new_id))


@tracks_changes("vrf", "update", id_arg="vrf_id")
async def update_vrf(
    vrf_id: int,
    *,
    rd: str,
    description: str,
    tenant_id: TenantArg = TENANT_UNCHANGED,
    namespace_id: int | None = None,
) -> dict | None:
    """Change the route distinguisher, description and (when given) tenant
    and namespace; the name never changes. ``None`` when the VRF does not
    exist."""
    exprs, values = ["rd = ?", "description = ?"], [rd, description]
    _tenant_set(exprs, values, tenant_id)
    if namespace_id is not None:
        exprs.append("namespace_id = ?")
        values.append(int(namespace_id))
    sql, params = _safe_dynamic_update("vrfs", exprs, values, "id = ?", int(vrf_id))
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        found = (cursor.rowcount or 0) > 0
    finally:
        await db.close()
    return await get_vrf(vrf_id) if found else None


# What may use a VRF name: (key, table, column).
_VRF_USERS: tuple[tuple[str, str, str], ...] = (
    ("hosts", "hosts", "vrf_name"),
    ("prefixes", "ipam_prefixes", "vrf"),
    ("allocations", "ipam_allocations", "vrf_name"),
    ("interface_addresses", "interface_addresses", "vrf_name"),
    ("device_vrfs", "host_vrfs", "vrf_name"),
)


async def vrf_usage(name: str) -> dict[str, int]:
    """How many rows of each kind use the VRF name (exact match)."""
    parts = " UNION ALL ".join(
        f"SELECT '{key}' AS kind, COUNT(*) AS n FROM {table} WHERE {column} = ?" for key, table, column in _VRF_USERS
    )
    rows = await _select(parts, tuple(name for _ in _VRF_USERS))  # nosec B608 - fixed tables and columns
    return {str(r["kind"]): int(r["n"]) for r in rows}


@tracks_changes("vrf", "delete", id_arg="vrf_id")
async def delete_vrf(vrf_id: int) -> bool:
    """Delete the record (the caller checks ``vrf_usage`` first)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM vrfs WHERE id = ?", (int(vrf_id),))
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


async def get_vrf_detail(
    vrf_id: int,
    limit: int = 2000,
    *,
    host_ids: Iterable[int] | None = None,
    prefix_scope: tuple[str, tuple] | None = None,
) -> dict | None:
    """The VRF with its ``devices``, ``interfaces`` (at most ``limit``,
    ``truncated`` when more exist) and ``prefixes`` (``source``: the IPAM
    source's provider, or ``interface`` for a network only an interface
    address names). ``host_ids`` / ``prefix_scope`` (object scope;
    ``None``: all) keep only those hosts' rows and the prefixes that SQL
    condition (alias ``p``) keeps."""
    vrf = await get_vrf(vrf_id, host_ids=host_ids, prefix_scope=prefix_scope)
    if vrf is None:
        return None
    name = vrf["name"]
    ids = None if host_ids is None else sorted({int(h) for h in host_ids})
    hv_sql, hv_params = _host_ids_condition("hv.host_id", ids)
    a_sql, a_params = _host_ids_condition("a.host_id", ids)
    p_sql, p_params = prefix_scope or ("", ())
    devices = await _select(
        """SELECT hv.host_id, h.hostname, hv.interface_count FROM host_vrfs hv JOIN hosts h ON h.id = hv.host_id
           WHERE hv.vrf_name = ?"""
        + (f" AND {hv_sql}" if hv_sql else "")
        + " ORDER BY lower(h.hostname), hv.host_id",  # nosec B608 - placeholders only
        (name, *hv_params),
    )
    rows = await _select(
        _ADDRESS_SELECT + " WHERE a.vrf_name = ?" + (f" AND {a_sql}" if a_sql else "") + _ADDRESS_ORDER + " LIMIT ?",
        (name, *a_params, limit + 1),
    )
    interfaces, truncated = _limited([_address(r) for r in rows], limit)
    prefixes = await _select(
        """SELECT subnet, source FROM (
               SELECT p.subnet, s.provider AS source FROM ipam_prefixes p JOIN ipam_sources s ON s.id = p.source_id
               WHERE p.vrf = ?"""
        + (f" AND {p_sql}" if p_sql else "")
        + """
               UNION
               SELECT DISTINCT a.network AS subnet, 'interface' AS source FROM interface_addresses a
               WHERE a.vrf_name = ?"""
        + (f" AND {a_sql}" if a_sql else "")
        + """
                 AND NOT EXISTS (SELECT 1 FROM ipam_prefixes p WHERE p.vrf = a.vrf_name AND p.subnet = a.network)
           ) found ORDER BY subnet, source""",  # nosec B608 - scope conditions, placeholders only
        (name, *p_params, name, *a_params),
    )
    return {
        **vrf,
        "devices": [
            {
                "host_id": int(d["host_id"]),
                "hostname": d["hostname"] or "",
                "interface_count": int(d["interface_count"]),
            }
            for d in devices
        ],
        "interfaces": interfaces,
        "truncated": truncated,
        "prefixes": [{"subnet": p["subnet"], "source": p["source"] or ""} for p in prefixes],
    }


async def _insert_vrfs(db, names: Iterable[str], origin: str) -> int:
    """Insert the missing VRF names on an open connection; names that are
    empty or too long are skipped. Returns how many were created."""
    wanted = sorted({n.strip() for n in names if isinstance(n, str) and 0 < len(n.strip()) <= VRF_NAME_MAX})
    created = 0
    for name in wanted:
        cursor = await db.execute(
            "INSERT INTO vrfs (name, origin, created_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
            (name, origin, _now()),
        )
        created += int(cursor.rowcount or 0)
    return created


async def ensure_vrfs(names: Iterable[str], origin: str = "discovered") -> int:
    """Create a record for every VRF name in ``names`` that has none (an
    existing record is never changed). Never raises: a failure is logged.
    Returns how many were created."""
    names = [n for n in names if isinstance(n, str) and n.strip()]
    if not names:
        return 0
    try:
        db = await _dbcore.get_db()
        try:
            created = await _insert_vrfs(db, names, origin)
            await db.commit()
            return created
        except Exception:
            await db.rollback()
            raise
        finally:
            await db.close()
    except Exception as exc:
        _LOGGER.warning("network objects: could not record VRFs: %s", exc)
        return 0


# ── VLANs ────────────────────────────────────────────────────────────────────

_VLAN_SELECT = """
    SELECT v.id, v.vid, v.name, v.site_id, s.name AS site_name, v.description, v.origin, v.created_at,
           v.tenant_id, tn.name AS tenant_name, v.vlan_group_id, g.name AS vlan_group_name
    FROM vlans v LEFT JOIN geo_sites s ON s.id = v.site_id LEFT JOIN tenants tn ON tn.id = v.tenant_id
    LEFT JOIN vlan_groups g ON g.id = v.vlan_group_id
"""
_VLAN_ORDER = " ORDER BY lower(s.name) ASC NULLS FIRST, v.site_id NULLS FIRST, v.vid, v.id"


async def _vlan_counts(record_ids: list[int], host_ids: Iterable[int] | None = None) -> dict[int, dict]:
    """``record id -> {device_count, interface_count, prefix_count,
    name_mismatch}`` for the given VLAN records; ``host_ids`` (object
    scope; ``None``: all) counts only those hosts."""
    counts = {
        rid: {"device_count": 0, "interface_count": 0, "prefix_count": 0, "name_mismatch": False} for rid in record_ids
    }
    if not record_ids:
        return counts
    wanted = set(record_ids)
    allowed = None if host_ids is None else {int(h) for h in host_ids}
    resolved = [
        r
        for r in await _select(
            f"SELECT r.host_id, r.vid, r.name, r.record_id, v.name AS record_name FROM ({_RESOLVED}) r "
            "JOIN vlans v ON v.id = r.record_id"  # nosec B608 - fixed clauses
        )
        if int(r["record_id"]) in wanted and (allowed is None or int(r["host_id"]) in allowed)
    ]
    host_vids: dict[int, set[int]] = {}
    for r in resolved:
        entry = counts[int(r["record_id"])]
        entry["device_count"] += 1
        if _mismatch(r["name"], r["record_name"]):
            entry["name_mismatch"] = True
        host_vids.setdefault(int(r["host_id"]), set()).add(int(r["vid"]))
    # Ports per (host, VLAN id), counting a port once whatever its mode.
    carried: dict[tuple[int, int], int] = {}
    parsed: dict[str, set[int]] = {}
    for chunk in _chunks(sorted(host_vids)):
        ports = await _select(
            f"""SELECT host_id, access_vlan, trunk_vlans FROM interface_inventory
                WHERE host_id IN ({_marks(chunk)}) AND (access_vlan > 0 OR trunk_vlans <> '')""",  # nosec B608 - placeholders only
            tuple(chunk),
        )
        for port in ports:
            host = int(port["host_id"])
            text = str(port["trunk_vlans"] or "")
            trunk = parsed.setdefault(text, parse_vlan_ranges(text) if text else set())
            for vid in vlans_of_port(int(port["access_vlan"] or 0), trunk, host_vids[host]):
                carried[(host, vid)] = carried.get((host, vid), 0) + 1
    for r in resolved:
        counts[int(r["record_id"])]["interface_count"] += carried.get((int(r["host_id"]), int(r["vid"])), 0)
    if allowed is not None:
        found: dict[int, set[str]] = {}
        for row in await _select(
            f"""SELECT DISTINCT r.record_id, r.host_id, a.network FROM ({_RESOLVED}) r
                JOIN interface_addresses a ON a.host_id = r.host_id AND a.svi_vid = r.vid
                WHERE r.record_id IS NOT NULL"""  # nosec B608 - fixed clauses
        ):
            if int(row["record_id"]) in wanted and int(row["host_id"]) in allowed:
                found.setdefault(int(row["record_id"]), set()).add(str(row["network"]))
        for rid, nets in found.items():
            counts[rid]["prefix_count"] = len(nets)
        return counts
    networks = await _select(
        f"""SELECT r.record_id, COUNT(DISTINCT a.network) AS n FROM ({_RESOLVED}) r
            JOIN interface_addresses a ON a.host_id = r.host_id AND a.svi_vid = r.vid
            WHERE r.record_id IS NOT NULL GROUP BY r.record_id"""  # nosec B608 - fixed clauses
    )
    for row in networks:
        if int(row["record_id"]) in wanted:
            counts[int(row["record_id"])]["prefix_count"] = int(row["n"])
    return counts


def _mismatch(device_name: object, record_name: object) -> bool:
    """A device names the VLAN differently from the record (case ignored; a
    device that gives no name never differs)."""
    name = str(device_name or "").strip()
    return bool(name) and name.lower() != str(record_name or "").strip().lower()


def _vlan(row: dict, counts: dict) -> dict:
    site_id = row["site_id"]
    group_id = row.get("vlan_group_id")
    return {
        "id": int(row["id"]),
        "vid": int(row["vid"]),
        "name": row["name"] or "",
        "site_id": int(site_id) if site_id is not None else None,
        "site": {"id": int(site_id), "name": row["site_name"]} if site_id is not None else None,
        "vlan_group_id": int(group_id) if group_id is not None else None,
        "vlan_group": {"id": int(group_id), "name": row["vlan_group_name"]} if group_id is not None else None,
        "description": row["description"] or "",
        "origin": row["origin"],
        "created_at": row["created_at"] or "",
        **_tenant_of(row),
        **counts,
    }


async def list_vlans(
    *,
    site_id: int | None = None,
    no_site: bool = False,
    vid: int | None = None,
    vlan_group_id: int | None = None,
    host_ids: Iterable[int] | None = None,
) -> list[dict]:
    """VLAN records by site name (no site first) then VLAN id; ``site_id``
    keeps one site's, ``no_site`` those of no site, ``vid`` one VLAN id,
    ``vlan_group_id`` one VLAN group's. ``host_ids`` (object scope;
    ``None``: all) counts only those hosts."""
    clauses: list[str] = []
    params: list[int] = []
    if no_site:
        clauses.append("v.site_id IS NULL")
    elif site_id is not None:
        clauses.append("v.site_id = ?")
        params.append(int(site_id))
    if vid is not None:
        clauses.append("v.vid = ?")
        params.append(int(vid))
    if vlan_group_id is not None:
        clauses.append("v.vlan_group_id = ?")
        params.append(int(vlan_group_id))
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = await _select(_VLAN_SELECT + where + _VLAN_ORDER, tuple(params))
    counts = await _vlan_counts([int(r["id"]) for r in rows], host_ids)
    return [_vlan(r, counts[int(r["id"])]) for r in rows]


async def get_vlan(vlan_id: int, *, host_ids: Iterable[int] | None = None) -> dict | None:
    rows = await _select(_VLAN_SELECT + " WHERE v.id = ?", (int(vlan_id),))
    if not rows:
        return None
    counts = await _vlan_counts([int(rows[0]["id"])], host_ids)
    return _vlan(rows[0], counts[int(rows[0]["id"])])


def _vlan_taken(vid: int, exc: Exception | None = None) -> ValueError:
    if exc is not None and "idx_vlans_group_vid" in str(exc):
        return ValueError(f"VLAN {vid} already exists in this VLAN group.")
    return ValueError(f"VLAN {vid} already exists at this site.")


@tracks_changes("vlan", "create")
async def create_vlan(
    *,
    vid: int,
    name: str = "",
    site_id: int | None = None,
    description: str = "",
    origin: str = "manual",
    tenant_id: int | None = None,
    vlan_group_id: int | None = None,
) -> dict:
    """Raises ``ValueError`` when the site (or no site), or the VLAN group,
    has the VLAN id. The caller checks that the site and group exist and
    that the VLAN fits the group (``vlan_group_problem``)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO vlans (vid, name, site_id, description, origin, created_at, tenant_id, vlan_group_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id""",
            (int(vid), name, site_id, description, origin, _now(), tenant_id, vlan_group_id),
        )
        new_id = int(cursor.lastrowid)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise _vlan_taken(vid, exc) from exc
        raise
    finally:
        await db.close()
    return await _must(get_vlan(new_id))


@tracks_changes("vlan", "update", id_arg="vlan_id")
async def update_vlan(
    vlan_id: int,
    *,
    name: str,
    site_id: int | None,
    description: str,
    tenant_id: TenantArg = TENANT_UNCHANGED,
    vlan_group_id: TenantArg = TENANT_UNCHANGED,
) -> dict | None:
    """Change the name, site, description and (when given) tenant and VLAN
    group (the VLAN id never changes). ``None`` when it does not exist;
    ``ValueError`` when the new site or group has the VLAN id already."""
    exprs, values = ["name = ?", "site_id = ?", "description = ?"], [name, site_id, description]
    _tenant_set(exprs, values, tenant_id)
    _tenant_set(exprs, values, vlan_group_id, "vlan_group_id")
    sql, params = _safe_dynamic_update("vlans", exprs, values, "id = ?", int(vlan_id))
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        found = (cursor.rowcount or 0) > 0
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            current = await _select("SELECT vid FROM vlans WHERE id = ?", (int(vlan_id),))
            raise _vlan_taken(int(current[0]["vid"]) if current else 0, exc) from exc
        raise
    finally:
        await db.close()
    return await get_vlan(vlan_id) if found else None


@tracks_changes("vlan", "delete", id_arg="vlan_id")
async def delete_vlan(vlan_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM vlans WHERE id = ?", (int(vlan_id),))
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


async def list_vlan_ports(vid: int, host_ids: Iterable[int] | None = None) -> list[dict]:
    """The ports that carry VLAN ``vid`` (``interface_inventory``): its
    access ports, then its trunk ports, as ``{host_id, hostname, interface,
    mode}``. A port that has the VLAN both ways is listed twice. With
    ``host_ids``, only those hosts' ports. Shared by the topology VLAN search
    and the VLAN records."""
    sql = """SELECT i.host_id, h.hostname, i.name, i.access_vlan, i.trunk_vlans
             FROM interface_inventory i LEFT JOIN hosts h ON h.id = i.host_id
             WHERE (i.access_vlan = ? OR (i.trunk_vlans IS NOT NULL AND i.trunk_vlans <> ''))"""
    batches: list[tuple] = []
    if host_ids is None:
        batches.append((sql + " ORDER BY i.id", (int(vid),)))
    else:
        ids = sorted({int(h) for h in host_ids})
        for chunk in _chunks(ids):
            batches.append((f"{sql} AND i.host_id IN ({_marks(chunk)}) ORDER BY i.id", (int(vid), *chunk)))
    by_mode: dict[str, list[dict]] = {"access": [], "trunk": []}
    for query, params in batches:
        for row in await _select(query, params):  # nosec B608 - fixed clauses, placeholders only
            trunk = parse_vlan_ranges(row["trunk_vlans"] or "") if row["trunk_vlans"] else set()
            for mode in port_vlan_modes(int(row["access_vlan"] or 0), trunk, int(vid)):
                by_mode[mode].append(
                    {"host_id": row["host_id"], "hostname": row["hostname"], "interface": row["name"], "mode": mode}
                )
    return by_mode["access"] + by_mode["trunk"]


async def get_vlan_detail(vlan_id: int, limit: int = 2000, *, host_ids: Iterable[int] | None = None) -> dict | None:
    """The VLAN with the ``devices`` that resolve to it (their own name for
    it), their ``interfaces`` in it (at most ``limit``, ``truncated`` when
    more exist) and the ``prefixes`` of their VLAN interfaces. ``host_ids``
    (object scope; ``None``: all) keeps only those devices."""
    vlan = await get_vlan(vlan_id, host_ids=host_ids)
    if vlan is None:
        return None
    allowed = None if host_ids is None else {int(h) for h in host_ids}
    devices = [
        d
        for d in await _select(
            f"SELECT r.host_id, r.hostname, r.name, r.state FROM ({_RESOLVED}) r WHERE r.record_id = ? "
            "ORDER BY lower(r.hostname), r.host_id",  # nosec B608 - fixed clauses, placeholders only
            (int(vlan_id),),
        )
        if allowed is None or int(d["host_id"]) in allowed
    ]
    host_ids = [int(d["host_id"]) for d in devices]
    ports = await list_vlan_ports(vlan["vid"], host_ids) if host_ids else []
    ports.sort(key=lambda p: (str(p["hostname"] or "").lower(), int(p["host_id"]), str(p["interface"] or "")))
    interfaces, truncated = _limited(
        [{**p, "host_id": int(p["host_id"]), "hostname": p["hostname"] or ""} for p in ports], limit
    )
    prefixes: list[dict] = []
    for chunk in _chunks(host_ids):
        prefixes.extend(
            await _select(
                f"""SELECT a.network, a.vrf_name, a.host_id, h.hostname, a.interface, a.address
                    FROM interface_addresses a JOIN hosts h ON h.id = a.host_id
                    WHERE a.svi_vid = ? AND a.role <> 'virtual' AND a.host_id IN ({_marks(chunk)})""",  # nosec B608 - placeholders only
                (vlan["vid"], *chunk),
            )
        )
    prefixes.sort(key=lambda p: (p["network"], str(p["hostname"] or "").lower(), p["interface"], p["address"]))
    return {
        **vlan,
        "devices": [
            {
                "host_id": int(d["host_id"]),
                "hostname": d["hostname"] or "",
                "name": d["name"] or "",
                "state": d["state"] or "",
                "name_matches": not _mismatch(d["name"], vlan["name"]),
            }
            for d in devices
        ],
        "interfaces": interfaces,
        "truncated": truncated,
        "prefixes": [
            {
                "network": p["network"],
                "vrf_name": p["vrf_name"] or "",
                "host_id": int(p["host_id"]),
                "hostname": p["hostname"] or "",
                "interface": p["interface"],
                "address": p["address"],
            }
            for p in prefixes
        ],
    }


async def ensure_vlans_for_host(host_id: int) -> int:
    """Create a record, at the host's site (none: no site) and named as the
    device names it, for each VLAN the host defines that resolves to no
    record. Never raises: a failure is logged. Returns how many were made."""
    try:
        db = await _dbcore.get_db()
        try:
            cursor = await db.execute(
                """INSERT INTO vlans (vid, name, site_id, description, origin, created_at)
                   SELECT d.vlan_id, left(trim(d.name), 64), h.site_id, '', 'discovered', ?
                   FROM vlan_definitions d JOIN hosts h ON h.id = d.host_id
                   WHERE d.host_id = ? AND d.vlan_id BETWEEN 1 AND 4094
                     AND NOT EXISTS (SELECT 1 FROM vlans v WHERE v.vid = d.vlan_id
                                     AND (v.site_id IS NULL OR v.site_id = h.site_id))
                   ON CONFLICT DO NOTHING""",
                (_now(), int(host_id)),
            )
            await db.commit()
            return int(cursor.rowcount or 0)
        except Exception:
            await db.rollback()
            raise
        finally:
            await db.close()
    except Exception as exc:
        _LOGGER.warning("network objects: could not record the VLANs of host %s: %s", host_id, exc)
        return 0


# ── Interface addresses ──────────────────────────────────────────────────────


async def replace_host_bindings(host_id: int, rows: list[dict], vrfs: dict[str, int]) -> bool:
    """Replace the host's interface addresses and device VRFs in one
    transaction and create a ``discovered`` record for each VRF name found.
    ``False`` (nothing written) when the host does not exist."""
    now = _now()
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT 1 FROM hosts WHERE id = ?", (int(host_id),))
        if await cursor.fetchone() is None:
            return False
        await db.execute("DELETE FROM interface_addresses WHERE host_id = ?", (int(host_id),))
        await db.execute("DELETE FROM host_vrfs WHERE host_id = ?", (int(host_id),))
        # One executemany per table rather than a statement per address; rows
        # keep their order, so ids (the read-back tiebreak) are unchanged.
        if rows:
            await db.executemany(
                """INSERT INTO interface_addresses
                   (host_id, interface, interface_key, address, prefix_length, network, vrf_name, role,
                    protocol, svi_vid, collected_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING""",
                [
                    (
                        int(host_id),
                        row["interface"],
                        row["interface_key"],
                        row["address"],
                        int(row["prefix_length"]),
                        row["network"],
                        row["vrf_name"],
                        row["role"],
                        row["protocol"],
                        int(row["svi_vid"]),
                        now,
                    )
                    for row in rows
                ],
            )
        if vrfs:
            await db.executemany(
                "INSERT INTO host_vrfs (host_id, vrf_name, interface_count, collected_at) VALUES (?, ?, ?, ?)",
                [(int(host_id), name, int(count), now) for name, count in vrfs.items()],
            )
        await _insert_vrfs(db, [*vrfs, *(r["vrf_name"] for r in rows)], "discovered")
        await db.commit()
        return True
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def get_interface_addresses_for_hosts(host_ids: Iterable[int]) -> dict[int, list[dict]]:
    """``host_id -> interface addresses`` (by interface) for many hosts, a
    few queries whatever their number; each address carries the id of its
    VRF record (``vrf_id``) and of the VLAN record its VLAN interface
    resolves to (``vlan_id``), ``None`` when there is none. A host with no
    address maps to ``[]``."""
    found: dict[int, list[dict]] = {int(h): [] for h in host_ids}
    for chunk in _chunks(sorted(found)):
        rows = await _select(
            f"""SELECT a.host_id, h.hostname, a.interface, a.address, a.prefix_length, a.network, a.vrf_name,
                       a.role, a.protocol, a.svi_vid, a.collected_at, vr.id AS vrf_id,
                       CASE WHEN a.svi_vid > 0 THEN {_RESOLVE_VLAN.format(vid="a.svi_vid")} END AS vlan_id
                FROM interface_addresses a JOIN hosts h ON h.id = a.host_id
                LEFT JOIN vrfs vr ON vr.name = a.vrf_name AND a.vrf_name <> ''
                WHERE a.host_id IN ({_marks(chunk)})
                ORDER BY a.host_id, a.interface, a.id""",  # nosec B608 - fixed clauses, placeholders only
            tuple(chunk),
        )
        for r in rows:
            found[int(r["host_id"])].append(
                {
                    **_address(r),
                    "vrf_id": int(r["vrf_id"]) if r["vrf_id"] is not None else None,
                    "vlan_id": int(r["vlan_id"]) if r["vlan_id"] is not None else None,
                }
            )
    return found


async def get_host_vlans_for_hosts(host_ids: Iterable[int]) -> dict[int, list[dict]]:
    """``host_id -> the VLANs the device defines`` (``vid``, ``name``,
    ``state`` and ``record_id``, the VLAN record it resolves to or ``None``),
    by VLAN id. A host with none maps to ``[]``."""
    found: dict[int, list[dict]] = {int(h): [] for h in host_ids}
    for chunk in _chunks(sorted(found)):
        rows = await _select(
            f"SELECT r.* FROM ({_RESOLVED}) r WHERE r.host_id IN ({_marks(chunk)}) "  # nosec B608 - placeholders only
            "ORDER BY r.host_id, r.vid",
            tuple(chunk),
        )
        for r in rows:
            found[int(r["host_id"])].append(
                {
                    "vid": int(r["vid"]),
                    "name": r.get("name") or "",
                    "state": r.get("state") or "",
                    "record_id": int(r["record_id"]) if r["record_id"] is not None else None,
                }
            )
    return found


async def get_interface_addresses_for_host(host_id: int) -> dict:
    """``{"addresses": [...], "vrfs": [...]}``: the host's interface
    addresses with the id of their VRF record (``vrf_id``) and of the VLAN
    record their VLAN interface resolves to (``vlan_id``), ``None`` when
    there is none; and the host's VRFs with their record id and interface
    count."""
    addresses = (await get_interface_addresses_for_hosts([int(host_id)]))[int(host_id)]
    vrfs = await _select(
        """SELECT hv.vrf_name AS name, vr.id AS vrf_id, hv.interface_count FROM host_vrfs hv
           LEFT JOIN vrfs vr ON vr.name = hv.vrf_name WHERE hv.host_id = ? ORDER BY lower(hv.vrf_name), hv.vrf_name""",
        (int(host_id),),
    )
    return {
        "addresses": addresses,
        "vrfs": [
            {
                "name": v["name"],
                "vrf_id": int(v["vrf_id"]) if v["vrf_id"] is not None else None,
                "interface_count": int(v["interface_count"]),
            }
            for v in vrfs
        ],
    }


async def find_interface_addresses(
    address: str, vrf: str | None = None, *, host_ids: Iterable[int] | None = None
) -> list[dict]:
    """The interface addresses equal to ``address`` (any spelling of it),
    only those of VRF ``vrf`` when it is given and of the hosts ``host_ids``
    (object scope) when that is not ``None``. ``[]`` when ``address`` is
    not an IP address."""
    try:
        canonical = str(ipaddress.ip_address(str(address).strip()))
    except ValueError:
        return []
    where, params = " WHERE a.address = ?", [canonical]
    if vrf is not None:
        where += " AND a.vrf_name = ?"
        params.append(vrf)
    host_sql, host_params = _host_ids_condition("a.host_id", host_ids)
    if host_sql:
        where += f" AND {host_sql}"
        params.extend(host_params)
    rows = await _select(_ADDRESS_SELECT + where + _ADDRESS_ORDER, tuple(params))
    return [_address(r) for r in rows]


async def find_interface_addresses_in_subnet(
    subnet: str, vrf: str | None = None, limit: int = 1024, *, host_ids: Iterable[int] | None = None
) -> list[dict]:
    """The interface addresses inside ``subnet`` (at most ``limit``), only
    those of VRF ``vrf`` when it is given and of the hosts ``host_ids``
    (object scope) when that is not ``None``. ``[]`` when ``subnet`` is not
    a network."""
    try:
        network = str(ipaddress.ip_network(str(subnet).strip(), strict=False))
    except ValueError:
        return []
    where, params = " WHERE CAST(a.address AS inet) <<= CAST(CAST(? AS TEXT) AS inet)", [network]
    if vrf is not None:
        where += " AND a.vrf_name = ?"
        params.append(vrf)
    host_sql, host_params = _host_ids_condition("a.host_id", host_ids)
    if host_sql:
        where += f" AND {host_sql}"
        params.extend(host_params)
    rows = await _select(_ADDRESS_SELECT + where + _ADDRESS_ORDER + " LIMIT ?", (*params, int(limit)))
    return [_address(r) for r in rows]


async def list_binding_hosts() -> list[dict]:
    """The hosts with a stored configuration (``id``, ``device_type``), by id."""
    rows = await _select(
        """SELECT h.id, h.device_type FROM hosts h
           WHERE EXISTS (SELECT 1 FROM config_backups b WHERE b.host_id = h.id AND b.status = 'success')
           ORDER BY h.id"""
    )
    return [{"id": int(r["id"]), "device_type": r["device_type"] or ""} for r in rows]


async def _must(coro) -> dict:
    record = await coro
    if record is None:  # pragma: no cover - the row was just written
        raise RuntimeError("record vanished after write")
    return record
