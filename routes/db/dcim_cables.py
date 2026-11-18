"""Cables, cable traces and rack power for the physical DCIM.

Star re-exported by routes/database.py. Tables: migration 0102. A cable
keeps both endpoints on its own row (``a_type``, ``a_id``, ``a_host_id``,
``a_name`` and the same for B) and one ``cable_endpoints`` row per end whose
unique key stops an endpoint carrying two cables. The trace walk and the
power maths are ``netcontrol.dcim``; this module loads what they read.

A ``circuit_termination`` endpoint is an id into ``circuit_terminations``
(another migration's table, possibly absent): it is checked here and never
a foreign key.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from netcontrol.dcim import CableGraph, endpoint_key, rack_power_summary, trace

import routes.database as _dbcore
from routes.database import _is_unique_violation, _safe_dynamic_update, rows_to_list
from routes.db.change_events import tracks_changes
from routes.db.custom_fields import _marks, _now
from routes.db.dcim import LIST_MAX, get_host_placement

__all__ = [
    "create_cable",
    "delete_cable",
    "get_cable",
    "get_host_dcim_summary",
    "get_rack_power",
    "list_cables",
    "list_host_interface_names",
    "resolve_cable_endpoint",
    "trace_cable_endpoint",
    "update_cable",
]

_SIDES = ("a", "b")
_ENDPOINT_COLUMNS = ("type", "id", "host_id", "name")
# Endpoint type -> (table, name column) for the records that have a row.
_ENDPOINT_TABLES: dict[str, tuple[str, str]] = {
    "front_port": ("front_ports", "name"),
    "rear_port": ("rear_ports", "name"),
    "power_port": ("power_ports", "name"),
    "power_outlet": ("power_outlets", "name"),
    "power_feed": ("power_feeds", "name"),
}
CIRCUIT_TERMINATIONS = "circuit_terminations"


async def _select(sql: str, params: tuple = ()) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(sql, params)
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def _table_exists(name: str) -> bool:
    rows = await _select("SELECT to_regclass(?) IS NOT NULL AS present", (name,))
    return bool(rows and rows[0]["present"])


# ── Endpoints ────────────────────────────────────────────────────────────────


async def resolve_cable_endpoint(endpoint: dict) -> dict | None:
    """The stored form of an endpoint (``type``, ``id``, ``host_id``,
    ``name``) when it names a record that exists, else ``None``. An
    interface needs its host only (interfaces have no rows); a circuit
    termination needs the ``circuit_terminations`` table and the row."""
    kind = endpoint.get("type")
    if kind == "interface":
        host_id = endpoint.get("host_id")
        name = str(endpoint.get("name") or "")
        if host_id is None or not name:
            return None
        if not await _select("SELECT 1 FROM hosts WHERE id = ?", (int(host_id),)):
            return None
        return {"type": "interface", "id": None, "host_id": int(host_id), "name": name}
    record_id = endpoint.get("id")
    if record_id is None:
        return None
    if kind == "circuit_termination":
        if not await _table_exists(CIRCUIT_TERMINATIONS):
            return None
        rows = await _select(f"SELECT 1 FROM {CIRCUIT_TERMINATIONS} WHERE id = ?", (int(record_id),))  # nosec B608 - fixed table name
        return {"type": kind, "id": int(record_id), "host_id": None, "name": ""} if rows else None
    if kind not in _ENDPOINT_TABLES:
        return None
    table, _name = _ENDPOINT_TABLES[kind]
    has_host = kind != "power_feed"
    rows = await _select(
        f"SELECT {'host_id' if has_host else 'NULL AS host_id'} FROM {table} WHERE id = ?",  # nosec B608 - fixed table names
        (int(record_id),),
    )
    if not rows:
        return None
    host_id = rows[0]["host_id"]
    return {"type": kind, "id": int(record_id), "host_id": int(host_id) if host_id is not None else None, "name": ""}


def _side_columns(side: str, endpoint: dict) -> dict:
    return {f"{side}_{column}": endpoint.get(column) for column in _ENDPOINT_COLUMNS}


def _side_key(row: dict, side: str) -> str:
    return endpoint_key(
        row[f"{side}_type"], row.get(f"{side}_id"), row.get(f"{side}_host_id"), row.get(f"{side}_name") or ""
    )


class CableEndpointTaken(ValueError):
    """An endpoint already carries another cable (the API's 409)."""


async def _write_cable(cable_id: int | None, values: dict, user: str) -> int | None:
    stored = dict(values)
    for side in _SIDES:
        endpoint = stored.pop(side, None)
        if endpoint is not None:
            stored.update(_side_columns(side, endpoint))
    now = _now()
    db = await _dbcore.get_db()
    try:
        if cable_id is None:
            stored = {**stored, "created_by": user, "created_at": now, "updated_by": user, "updated_at": now}
            columns = list(stored)
            cursor = await db.execute(
                f"INSERT INTO cables ({', '.join(columns)}) VALUES ({_marks(columns)}) RETURNING id",  # nosec B608 - fixed column names
                tuple(stored.values()),
            )
            result = int(cursor.lastrowid)
        else:
            stored = {**stored, "updated_by": user, "updated_at": now}
            sql, params = _safe_dynamic_update(
                "cables", [f"{c} = ?" for c in stored], list(stored.values()), "id = ?", int(cable_id)
            )
            cursor = await db.execute(sql, params)
            if not (cursor.rowcount or 0):
                await db.rollback()
                return None
            result = int(cable_id)
        cursor = await db.execute("SELECT * FROM cables WHERE id = ?", (result,))
        row = dict((await cursor.fetchone()) or {})
        await db.execute("DELETE FROM cable_endpoints WHERE cable_id = ?", (result,))
        for side in _SIDES:
            await db.execute(
                "INSERT INTO cable_endpoints (cable_id, side, endpoint_key) VALUES (?, ?, ?)",
                (result, side, _side_key(row, side)),
            )
        await db.commit()
        return result
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise CableEndpointTaken("An endpoint of this cable already has another cable.") from exc
        raise
    finally:
        await db.close()


@tracks_changes("cable", "create")
async def create_cable(values: dict, user: str = "") -> int:
    """Insert a cable: ``values`` holds ``a`` and ``b`` (resolved endpoints,
    see ``resolve_cable_endpoint``) and the cable columns. Returns its id;
    ``CableEndpointTaken`` when an endpoint has a cable."""
    return int(await _write_cable(None, values, user) or 0)


@tracks_changes("cable", "update", id_arg="cable_id")
async def update_cable(cable_id: int, values: dict, user: str = "") -> bool:
    """Change a cable's columns and, with ``a``/``b``, its endpoints."""
    return await _write_cable(int(cable_id), values, user) is not None


@tracks_changes("cable", "delete", id_arg="cable_id")
async def delete_cable(cable_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM cables WHERE id = ?", (int(cable_id),))
        await db.commit()
        return (cursor.rowcount or 0) > 0
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


# ── Labels ───────────────────────────────────────────────────────────────────


async def _endpoint_labels(endpoints: list[dict]) -> dict[str, dict]:
    """endpoint key -> display fields (``host_name``, ``name``, ``label``,
    and for a feed its panel) for every endpoint given."""
    wanted: dict[str, set[int]] = {}
    hosts: set[int] = set()
    for ep in endpoints:
        if ep.get("host_id") is not None:
            hosts.add(int(ep["host_id"]))
        if ep["type"] != "interface" and ep.get("id") is not None:
            wanted.setdefault(ep["type"], set()).add(int(ep["id"]))
    names: dict[str, dict[int, dict]] = {}
    for kind, ids in wanted.items():
        id_list = sorted(ids)[:LIST_MAX]
        if kind in _ENDPOINT_TABLES:
            table, _col = _ENDPOINT_TABLES[kind]
            extra = (
                ", t.power_panel_id, (SELECT name FROM power_panels pp WHERE pp.id = t.power_panel_id) AS power_panel_name"
                if kind == "power_feed"
                else ""
            )
            rows = await _select(
                f"SELECT t.id, t.name{extra} FROM {table} t WHERE t.id IN ({_marks(id_list)})",  # nosec B608 - fixed table names, placeholders only
                tuple(id_list),
            )
            names[kind] = {int(r["id"]): r for r in rows}
        elif kind == "circuit_termination" and await _table_exists(CIRCUIT_TERMINATIONS):
            rows = await _select(
                f"SELECT * FROM {CIRCUIT_TERMINATIONS} WHERE id IN ({_marks(id_list)})",  # nosec B608 - fixed table name, placeholders only
                tuple(id_list),
            )
            names[kind] = {int(r["id"]): r for r in rows}
    host_names: dict[int, str] = {}
    if hosts:
        host_list = sorted(hosts)[:LIST_MAX]
        for row in await _select(
            f"SELECT id, hostname FROM hosts WHERE id IN ({_marks(host_list)})",  # nosec B608 - placeholders only
            tuple(host_list),
        ):
            host_names[int(row["id"])] = row["hostname"]
    out: dict[str, dict] = {}
    for ep in endpoints:
        key = endpoint_key(ep["type"], ep.get("id"), ep.get("host_id"), ep.get("name") or "")
        host_name = host_names.get(int(ep["host_id"])) if ep.get("host_id") is not None else None
        fields: dict[str, Any] = {"host_name": host_name or ""}
        if ep["type"] == "interface":
            name = ep.get("name") or ""
        elif ep["type"] == "circuit_termination":
            row = names.get(ep["type"], {}).get(int(ep.get("id") or 0)) or {}
            side = row.get("term_side") or row.get("side") or ""
            name = f"Circuit termination {ep.get('id')}" + (f" ({side})" if side else "")
            if row.get("circuit_id") is not None:
                fields["circuit_id"] = row.get("circuit_id")
        else:
            row = names.get(ep["type"], {}).get(int(ep.get("id") or 0)) or {}
            name = row.get("name") or ""
            if ep["type"] == "power_feed" and row:
                fields["power_panel_id"] = row.get("power_panel_id")
                fields["power_panel_name"] = row.get("power_panel_name") or ""
        fields["name"] = name
        fields["label"] = (
            f"{host_name} / {name}"
            if host_name
            else (f"{fields.get('power_panel_name')} / {name}" if fields.get("power_panel_name") else name)
        )
        out[key] = fields
    return out


def _endpoint(row: dict, side: str) -> dict:
    return {column: row.get(f"{side}_{column}") for column in _ENDPOINT_COLUMNS}


async def _with_labels(rows: list[dict]) -> list[dict]:
    endpoints = [_endpoint(r, side) for r in rows for side in _SIDES]
    labels = await _endpoint_labels(endpoints)
    out = []
    for row in rows:
        item = dict(row)
        for side in _SIDES:
            ep = _endpoint(row, side)
            ep["name"] = ep["name"] or ""
            key = endpoint_key(ep["type"], ep["id"], ep["host_id"], ep["name"])
            item[side] = {**ep, **labels.get(key, {})}
        out.append(item)
    return out


_CABLE_SELECT = "SELECT c.*, t.name AS tenant_name FROM cables c LEFT JOIN tenants t ON t.id = c.tenant_id"


async def list_cables(
    filters: dict[str, Any] | None = None, q: str = "", limit: int = LIST_MAX, host_ids: Iterable[int] | None = None
) -> list[dict]:
    """Cables with both endpoints described (``a``, ``b``), filtered by
    ``host_id`` (either end), ``type``, ``status``, ``tenant_id``,
    ``endpoint_type`` (either end) and the text ``q`` (label,
    description). ``host_ids`` keeps the cables with either end on one of
    those hosts, every one of them (no ``limit``)."""
    filters = filters or {}
    clauses: list[str] = []
    params: list[Any] = []
    if filters.get("host_id") is not None:
        clauses.append("(c.a_host_id = ? OR c.b_host_id = ?)")
        params.extend([int(filters["host_id"])] * 2)
    if host_ids is not None:
        ids = sorted({int(h) for h in host_ids})
        if not ids:
            return []
        clauses.append(f"(c.a_host_id IN ({_marks(ids)}) OR c.b_host_id IN ({_marks(ids)}))")
        params.extend(ids * 2)
    if filters.get("endpoint_type"):
        clauses.append("(c.a_type = ? OR c.b_type = ?)")
        params.extend([filters["endpoint_type"]] * 2)
    for key in ("type", "status", "tenant_id"):
        if filters.get(key) is not None:
            clauses.append(f"c.{key} = ?")
            params.append(filters[key])
    if q:
        clauses.append("(lower(c.label) LIKE ? OR lower(c.description) LIKE ?)")
        params.extend([f"%{q.lower()}%"] * 2)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"{_CABLE_SELECT}{where} ORDER BY c.id"
    if host_ids is None:
        sql += " LIMIT ?"
        params.append(max(1, min(int(limit), LIST_MAX)))
    rows = await _select(sql, tuple(params))  # nosec B608 - fixed clauses, placeholders only
    return await _with_labels(rows)


async def get_cable(cable_id: int) -> dict | None:
    rows = await _select(f"{_CABLE_SELECT} WHERE c.id = ?", (int(cable_id),))  # nosec B608 - fixed clauses
    return (await _with_labels(rows))[0] if rows else None


# ── Trace ────────────────────────────────────────────────────────────────────


async def _load_graph() -> CableGraph:
    """Every cable, patch panel port mapping, outlet and feed, with the keys
    of the records that exist and display labels for each endpoint."""
    cables = {int(r["id"]): r for r in await _select("SELECT * FROM cables")}
    front = {
        int(r["id"]): r
        for r in await _select("SELECT id, host_id, name, rear_port_id, rear_port_position FROM front_ports")
    }
    rear = {int(r["id"]): r for r in await _select("SELECT id, host_id, name, positions FROM rear_ports")}
    outlets = {int(r["id"]): r for r in await _select("SELECT id, host_id, name, power_port_id FROM power_outlets")}
    feeds = {
        int(r["id"]): r
        for r in await _select(
            "SELECT pf.id, pf.name, pf.power_panel_id, pp.name AS power_panel_name "
            "FROM power_feeds pf JOIN power_panels pp ON pp.id = pf.power_panel_id"
        )
    }
    power_ports = await _select("SELECT id, host_id, name FROM power_ports")
    existing: set[str] = set()
    endpoints: list[dict] = []
    for kind, rows in (
        ("front_port", front.values()),
        ("rear_port", rear.values()),
        ("power_outlet", outlets.values()),
        ("power_feed", feeds.values()),
        ("power_port", power_ports),
    ):
        for row in rows:
            existing.add(endpoint_key(kind, row["id"]))
            endpoints.append({"type": kind, "id": row["id"], "host_id": row.get("host_id"), "name": ""})
    ct_ids = sorted(
        {int(c[f"{s}_id"]) for c in cables.values() for s in _SIDES if c[f"{s}_type"] == "circuit_termination"}
    )
    if ct_ids and await _table_exists(CIRCUIT_TERMINATIONS):
        for chunk_start in range(0, len(ct_ids), 1000):
            chunk = ct_ids[chunk_start : chunk_start + 1000]
            for row in await _select(
                f"SELECT id FROM {CIRCUIT_TERMINATIONS} WHERE id IN ({_marks(chunk)})",  # nosec B608 - fixed table name, placeholders only
                tuple(chunk),
            ):
                existing.add(endpoint_key("circuit_termination", row["id"]))
    for cable in cables.values():
        endpoints.extend(_endpoint(cable, side) for side in _SIDES)
    labels = await _endpoint_labels(endpoints)
    return CableGraph(
        cables=cables,
        front_ports=front,
        rear_ports=rear,
        power_outlets=outlets,
        power_feeds=feeds,
        existing=existing,
        labels=labels,
    )


async def trace_cable_endpoint(endpoint: dict) -> dict:
    """The trace from a resolved endpoint (``netcontrol.dcim.trace``)."""
    return trace(await _load_graph(), endpoint)


# ── Rack power ───────────────────────────────────────────────────────────────


async def get_rack_power(rack_id: int) -> dict:
    """The rack's feeds and the draw of the device power ports in it (PDU
    inlets, the ports that feed outlets, are left out: the devices behind
    them count), each port traced to the feed it ends at."""
    feeds = await _select(
        "SELECT id, name, type, status, supply, phase, voltage, amperage, max_utilization "
        "FROM power_feeds WHERE rack_id = ? ORDER BY lower(name), id",
        (int(rack_id),),
    )
    ports = await _select(
        """SELECT p.id, p.host_id, h.hostname AS host_name, p.name, p.maximum_draw, p.allocated_draw
           FROM power_ports p JOIN hosts h ON h.id = p.host_id
           WHERE h.rack_id = ?
             AND NOT EXISTS (SELECT 1 FROM power_outlets o WHERE o.power_port_id = p.id)
           ORDER BY lower(h.hostname), lower(p.name), p.id""",
        (int(rack_id),),
    )
    graph = await _load_graph() if ports else CableGraph()
    for port in ports:
        result = trace(graph, {"type": "power_port", "id": port["id"], "host_id": port["host_id"], "name": ""})
        destination = result.get("destination") or {}
        port["feed_id"] = destination.get("id") if destination.get("type") == "power_feed" else None
        port["feed_name"] = destination.get("name") if port["feed_id"] is not None else ""
    summary = rack_power_summary(feeds, ports)
    summary["ports"] = ports
    return summary


# ── A host's DCIM data ───────────────────────────────────────────────────────


async def list_host_interface_names(host_id: int) -> list[str]:
    """The interface names known for a host: its collected interface
    inventory, its polled interface statistics and the names its cables
    use, sorted and without repeats."""
    names: set[str] = set()
    for row in await _dbcore.get_interface_inventory_for_host(int(host_id)):
        if row.get("name"):
            names.add(str(row["name"]))
    for row in await _dbcore.get_interface_stats_for_host(int(host_id)):
        if row.get("if_name"):
            names.add(str(row["if_name"]))
    for row in await _select(
        "SELECT a_name AS name FROM cables WHERE a_type = 'interface' AND a_host_id = ? "
        "UNION SELECT b_name FROM cables WHERE b_type = 'interface' AND b_host_id = ?",
        (int(host_id), int(host_id)),
    ):
        names.add(str(row["name"]))
    return sorted(names, key=lambda n: (n.lower(), n))


async def get_host_dcim_summary(host_id: int) -> dict | None:
    """A host's rack placement, its cables (with both ends described) and
    how many patch, power and module records it has; ``None`` when the host
    does not exist."""
    placement = await get_host_placement(host_id)
    if placement is None:
        return None
    counts = (
        await _select(
            """SELECT (SELECT COUNT(*) FROM front_ports WHERE host_id = ?) AS front_ports,
                      (SELECT COUNT(*) FROM rear_ports WHERE host_id = ?) AS rear_ports,
                      (SELECT COUNT(*) FROM power_ports WHERE host_id = ?) AS power_ports,
                      (SELECT COUNT(*) FROM power_outlets WHERE host_id = ?) AS power_outlets,
                      (SELECT COUNT(*) FROM modules WHERE host_id = ?) AS modules""",
            (int(host_id),) * 5,
        )
    )[0]
    return {
        "placement": placement,
        "cables": await list_cables({"host_id": int(host_id)}),
        "counts": {k: int(v) for k, v in counts.items()},
    }
