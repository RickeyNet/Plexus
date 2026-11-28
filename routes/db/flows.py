"""Flows persistence helpers.

Split out of routes/database.py; star re-exported there so the
``routes.database`` facade keeps its full public surface.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

import asyncpg

import routes.database as _dbcore
from routes.database import (
    _LOGGER,
    _is_unique_violation,
    _minute_bucket_expr,
    rows_to_list,
)
from routes.db.inventory import group_ids_condition

__all__ = [
    "create_flow_records_batch",
    "get_flow_top_talkers",
    "get_flow_top_applications",
    "get_flow_top_conversations",
    "get_flow_timeline",
    "get_flow_overview",
    "FLOW_OVERVIEW_PARTS",
    "cleanup_old_flow_records",
    "cleanup_old_flow_summaries",
    "get_flow_top_interfaces",
    "get_exporter_host_map",
    "upsert_flow_exporter",
    "update_flow_exporter_host_id",
    "relink_flow_exporters",
    "list_flow_exporters",
    "replace_flow_interface_names",
    "get_flow_interface_names",
    "with_interface_names",
    "get_cloud_flow_summary",
    "get_cloud_flow_top_talkers",
    "get_cloud_flow_timeline",
    "get_cloud_flow_overview",
]

# ═════════════════════════════════════════════════════════════════════════════
# FLOW RECORDS  (NetFlow / sFlow / IPFIX)
# ═════════════════════════════════════════════════════════════════════════════


_FLOW_INSERT = """INSERT INTO flow_records
               (exporter_ip, host_id, flow_type, src_ip, dst_ip, src_port, dst_port,
                protocol, bytes, packets, src_as, dst_as, input_if, output_if,
                tos, tcp_flags, start_time, end_time)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""

_INT4_MAX = 2**31 - 1
_INT8_MAX = 2**63 - 1
# The integer fields of a flow row and the largest value their column takes,
# by position in the tuple ``create_flow_records_batch`` is given.
_FLOW_ROW_INT_MAX: dict[int, int] = {
    5: _INT4_MAX,  # src_port
    6: _INT4_MAX,  # dst_port
    7: _INT4_MAX,  # protocol
    8: _INT8_MAX,  # bytes
    9: _INT8_MAX,  # packets
    10: _INT8_MAX,  # src_as
    11: _INT8_MAX,  # dst_as
    12: _INT8_MAX,  # input_if
    13: _INT8_MAX,  # output_if
    14: _INT4_MAX,  # tos
    15: _INT4_MAX,  # tcp_flags
}


def _flow_row_fits(row: tuple) -> bool:
    """Whether every integer field of the flow ``row`` fits its column."""
    for index, top in _FLOW_ROW_INT_MAX.items():
        value = row[index]
        if value is None:
            continue
        if type(value) is not int or not -top - 1 <= value <= top:
            return False
    return True


async def create_flow_records_batch(rows: list[tuple]) -> int:
    """Batch insert flow records; returns how many were stored. Each tuple:
    (exporter_ip, host_id, flow_type, src_ip, dst_ip, src_port, dst_port,
     protocol, bytes, packets, src_as, dst_as, input_if, output_if,
     tos, tcp_flags, start_time, end_time)

    The integer fields come off the wire as the exporter sent them (a v9 or
    IPFIX template sets each field's width). A row with one that fits no
    column is dropped and counted in the log; the rest of the batch is
    stored. The check runs only after the driver has refused the batch, so
    it costs a well-formed batch nothing.
    """
    if not rows:
        return 0
    db = await _dbcore.get_db()
    try:
        try:
            await db.executemany(_FLOW_INSERT, rows)
        except asyncpg.DataError:
            await db.rollback()
            kept = [row for row in rows if _flow_row_fits(row)]
            if len(kept) == len(rows):
                raise
            _LOGGER.warning(
                "flows: dropped %d of %d flow records holding a number too large for its column",
                len(rows) - len(kept),
                len(rows),
            )
            if not kept:
                return 0
            await db.executemany(_FLOW_INSERT, kept)
            rows = kept
        await db.commit()
        return len(rows)
    finally:
        await db.close()


def _with_host_scope(where: str, params: list, group_ids: Iterable[int] | None) -> str:
    """``where`` keeping only the records of exporters that are hosts of the
    inventory groups ``group_ids`` (``None``: unchanged); appends the
    parameters to ``params``."""
    if group_ids is None:
        return where
    scope_sql, scope_params = group_ids_condition("group_id", group_ids)
    params.extend(scope_params)
    return f"{where} AND host_id IN (SELECT id FROM hosts WHERE {scope_sql})"


def _flow_where(hours: int, host_id: int | None, group_ids: Iterable[int] | None) -> tuple[str, list]:
    """The ``WHERE`` clause and its parameters of the flow views: the records
    received in the last ``hours`` hours, of ``host_id`` when given, of the
    exporters in the inventory groups ``group_ids`` when given."""
    where = "WHERE received_at >= datetime('now', ? || ' hours')"
    params: list = [f"-{max(1, int(hours))}"]
    if host_id is not None:
        where += " AND host_id = ?"
        params.append(host_id)
    return _with_host_scope(where, params, group_ids), params


# The aggregates the flow views show, each one grouping set over the records:
# name -> (column, name of the column in the result rows), in grouping order.
_FLOW_SETS: dict[str, tuple[tuple[str, str], ...]] = {
    "total": (),
    "top_src": (("src_ip", "ip"),),
    "top_dst": (("dst_ip", "ip"),),
    "top_applications": (("dst_port", "port"), ("protocol", "protocol")),
    "top_conversations": (("src_ip", "src_ip"), ("dst_ip", "dst_ip")),
    "if_in": (("host_id", "host_id"), ("exporter_ip", "exporter_ip"), ("input_if", "if_index")),
    "if_out": (("host_id", "host_id"), ("exporter_ip", "exporter_ip"), ("output_if", "if_index")),
    "timeline": (("bucket", "bucket"),),
}
# The sets cut to their ``limit`` biggest groups by bytes; the others are whole.
_RANKED_SETS = frozenset({"top_src", "top_dst", "top_applications", "top_conversations"})


async def _flow_aggregates(
    where: str, params: list, sets: Iterable[str], limit: int = 20, bucket_minutes: int = 5
) -> tuple[dict[str, list[dict]], dict[str, int]]:
    """The grouping sets ``sets`` (names of ``_FLOW_SETS``) of the flow
    records ``where`` selects, all from one scan of ``flow_records``
    (``GROUPING SETS``), as ``({name: rows}, {name: number of groups})``.

    Each row holds its set's columns (by their result name) and
    ``total_bytes``, ``total_packets`` and ``flow_count``; ``total`` also
    ``first_seen`` and ``last_seen``. A ranked set is cut to its ``limit``
    biggest groups by bytes (ties by the grouping columns), each with its own
    top-N sort; ``timeline`` (``bucket_minutes`` buckets) is in bucket order.
    The group counts (of the whole set, before the cut) are read only with
    ``total``: for ``top_src`` and ``top_dst``, ``0`` for the others."""
    wanted = set(sets)
    names = [name for name in _FLOW_SETS if name in wanted]
    columns = list(dict.fromkeys(col for name in names for col, _ in _FLOW_SETS[name]))
    source = [col for col in columns if col != "bucket"]
    if "bucket" in columns:
        source.append(f"{_minute_bucket_expr('received_at', max(1, min(int(bucket_minutes), 60)))} AS bucket")
    source += ["bytes", "packets", "received_at"] if "total" in names else ["bytes", "packets"]
    # GROUPING(...) has one bit per column, the first the highest, set when
    # the row's set does not group by that column: the set's fingerprint.
    masks = {
        name: sum(
            1 << (len(columns) - 1 - i) for i, col in enumerate(columns) if col not in {c for c, _ in _FLOW_SETS[name]}
        )
        for name in names
    }
    gset = f"GROUPING({', '.join(columns)})" if columns else "0"
    grouping_sets = ", ".join(f"({', '.join(col for col, _ in _FLOW_SETS[name])})" for name in names)
    seen, last = ("MIN(received_at)", "MAX(received_at)") if "total" in names else ("NULL", "NULL")
    fields = ["gset", *columns, "total_bytes", "total_packets", "flow_count", "first_seen", "last_seen"]
    branches = []
    for name in names:
        branch = f"SELECT {', '.join(fields)}, 0 AS set_rows, 'r' AS kind FROM g WHERE gset = {masks[name]}"
        if name in _RANKED_SETS:
            order = "".join(f", {col}" for col, _ in _FLOW_SETS[name])
            branch += f" ORDER BY total_bytes DESC{order} LIMIT {max(1, int(limit))}"
        branches.append(f"({branch})")
        if "total" in names and name in {"top_src", "top_dst"}:
            nulls = ", ".join("NULL" for _ in fields[1:])
            branches.append(f"(SELECT {masks[name]}, {nulls}, COUNT(*), 'c' FROM g WHERE gset = {masks[name]})")
    aggregate = f"""SELECT {gset} AS gset, {"".join(f"{col}, " for col in columns)}
                          CAST(SUM(bytes) AS BIGINT) AS total_bytes,
                          CAST(SUM(packets) AS BIGINT) AS total_packets, COUNT(*) AS flow_count,
                          {seen} AS first_seen, {last} AS last_seen
                   FROM (SELECT {", ".join(source)} FROM flow_records {where}) f"""
    if len(branches) == 1 and columns:
        # One set: a plain GROUP BY (``g`` is read once, so it is inlined),
        # as cheap as the query of one view was.
        one = aggregate.replace(gset, str(masks[names[0]]), 1)
        sql = f"WITH g AS ({one} GROUP BY {', '.join(columns)}) {branches[0][1:-1]}"
    else:
        # ``g`` is read by every branch, so it is computed once (one scan
        # of the records); each ranked branch keeps only its top N.
        sql = f"WITH g AS ({aggregate} GROUP BY GROUPING SETS ({grouping_sets})) " + " UNION ALL ".join(branches)
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(sql, params)
        rows = rows_to_list(await cursor.fetchall())
    finally:
        await db.close()
    by_mask = {mask: name for name, mask in masks.items()}
    found: dict[str, list[dict]] = {name: [] for name in names}
    sizes: dict[str, int] = dict.fromkeys(names, 0)
    for row in rows:
        name = by_mask.get(row["gset"])
        if name is None:
            continue
        if row["kind"] == "c":
            sizes[name] = int(row["set_rows"])
            continue
        item = {label: row[col] for col, label in _FLOW_SETS[name]}
        item.update(total_bytes=row["total_bytes"], total_packets=row["total_packets"], flow_count=row["flow_count"])
        if name == "total":
            item.update(first_seen=row["first_seen"], last_seen=row["last_seen"])
        found[name].append(item)
    for name in _RANKED_SETS & set(found):
        # Each branch comes in its own order; a stable sort keeps the ties
        # in it (by the grouping columns).
        found[name].sort(key=lambda r: -(r["total_bytes"] or 0))
    if "timeline" in found:
        found["timeline"].sort(key=lambda r: r["bucket"])
    return found, sizes


def _interfaces(found: dict[str, list[dict]], limit: int) -> list[dict]:
    """The ``limit`` interfaces with the most bytes from the ``if_in`` and
    ``if_out`` sets: ``host_id``, ``exporter_ip``, ``if_index``,
    ``in_bytes``, ``out_bytes``, ``total_bytes`` and ``flow_count`` (records
    that name it either way, one that names it both ways twice)."""
    merged: dict[tuple, dict] = {}
    for name, side in (("if_in", "in_bytes"), ("if_out", "out_bytes")):
        for row in found.get(name, []):
            key = (row["host_id"], row["exporter_ip"], row["if_index"])
            entry = merged.setdefault(
                key,
                {
                    "host_id": row["host_id"],
                    "exporter_ip": row["exporter_ip"],
                    "if_index": row["if_index"],
                    "in_bytes": 0,
                    "out_bytes": 0,
                    "flow_count": 0,
                },
            )
            entry[side] += int(row["total_bytes"] or 0)
            entry["flow_count"] += int(row["flow_count"] or 0)
    for entry in merged.values():
        entry["total_bytes"] = entry["in_bytes"] + entry["out_bytes"]
    ranked = sorted(
        merged.values(),
        key=lambda r: (-r["total_bytes"], r["host_id"] is None, r["host_id"] or 0, r["exporter_ip"], r["if_index"]),
    )
    return ranked[: max(1, int(limit))]


async def get_flow_top_talkers(
    host_id: int | None = None,
    hours: int = 1,
    direction: str = "src",
    limit: int = 20,
    group_ids: Iterable[int] | None = None,
) -> list[dict]:
    """``group_ids``: over the flows of exporters in those inventory groups."""
    name = "top_src" if direction == "src" else "top_dst"
    where, params = _flow_where(hours, host_id, group_ids)
    found, _ = await _flow_aggregates(where, params, {name}, limit)
    return found[name]


async def get_flow_top_applications(
    host_id: int | None = None, hours: int = 1, limit: int = 20, group_ids: Iterable[int] | None = None
) -> list[dict]:
    """``group_ids``: over the flows of exporters in those inventory groups."""
    where, params = _flow_where(hours, host_id, group_ids)
    found, _ = await _flow_aggregates(where, params, {"top_applications"}, limit)
    return found["top_applications"]


async def get_flow_top_conversations(
    host_id: int | None = None, hours: int = 1, limit: int = 20, group_ids: Iterable[int] | None = None
) -> list[dict]:
    """``group_ids``: over the flows of exporters in those inventory groups."""
    where, params = _flow_where(hours, host_id, group_ids)
    found, _ = await _flow_aggregates(where, params, {"top_conversations"}, limit)
    return found["top_conversations"]


async def get_flow_timeline(
    host_id: int | None = None, hours: int = 6, bucket_minutes: int = 5, group_ids: Iterable[int] | None = None
) -> list[dict]:
    """Aggregate flow data into time buckets; ``group_ids``: over the flows
    of exporters in those inventory groups."""
    where, params = _flow_where(hours, host_id, group_ids)
    found, _ = await _flow_aggregates(where, params, {"timeline"}, bucket_minutes=bucket_minutes)
    return found["timeline"]


async def get_flow_top_interfaces(
    host_id: int | None = None, hours: int = 1, limit: int = 20, group_ids: Iterable[int] | None = None
) -> list[dict]:
    """The interfaces of the exporters ranked by the bytes of their flows:
    ``host_id``, ``exporter_ip``, ``if_index`` (the number the records
    carry), ``in_bytes`` (flows that entered on it: ``input_if``),
    ``out_bytes`` (flows that left on it: ``output_if``), ``total_bytes``
    and ``flow_count`` (records that name it either way). ``group_ids``:
    over the flows of exporters in those inventory groups."""
    where, params = _flow_where(hours, host_id, group_ids)
    found, _ = await _flow_aggregates(where, params, {"if_in", "if_out"})
    return _interfaces(found, limit)


async def get_flow_overview(
    host_id: int | None = None,
    hours: int = 1,
    limit: int = 20,
    bucket_minutes: int = 5,
    group_ids: Iterable[int] | None = None,
    parts: Iterable[str] | None = None,
) -> dict[str, list[dict]]:
    """The aggregates of the flow views from one scan of the records:
    ``top_src`` and ``top_dst`` (``get_flow_top_talkers``),
    ``top_applications``, ``top_conversations``, ``top_interfaces`` and
    ``timeline``, each the rows its own reader returns for the same
    arguments; ``parts`` (names of ``FLOW_OVERVIEW_PARTS``): only those
    (``None``: all). ``group_ids``: over the flows of exporters in those
    inventory groups."""
    chosen = [p for p in FLOW_OVERVIEW_PARTS if parts is None or p in set(parts)]
    sets = {s for p in chosen for s in (("if_in", "if_out") if p == "top_interfaces" else (p,))}
    if not sets:
        return {}
    where, params = _flow_where(hours, host_id, group_ids)
    found, _ = await _flow_aggregates(where, params, sets, limit, bucket_minutes)
    return {p: _interfaces(found, limit) if p == "top_interfaces" else found[p] for p in chosen}


# The parts of ``get_flow_overview``, in response order.
FLOW_OVERVIEW_PARTS = ("top_src", "top_dst", "top_applications", "top_conversations", "top_interfaces", "timeline")


async def cleanup_old_flow_records(hours: int = 48) -> int:
    return await _dbcore.chunked_delete(
        "flow_records",
        "received_at < datetime('now', ? || ' hours')",
        (f"-{hours}",),
    )


async def cleanup_old_flow_summaries(days: int = 30) -> int:
    """Delete flow summaries written more than ``days`` ago
    (``summary_retention_days``). Nothing writes the table any more (the
    flow views aggregate the raw records); this drains the rows an older
    release wrote."""
    return await _dbcore.chunked_delete(
        "flow_summaries",
        "created_at < datetime('now', '-' || ? || ' days')",
        (int(days),),
    )


async def get_exporter_host_map(hostnames: dict[int, str] | None = None) -> dict[str, int]:
    """Return ``{ip_address: host_id}`` for every host with a non-empty IP,
    plus every recorded interface address of a host (``host_ip_aliases``).
    ``hostnames``, when given, is filled from the same read with
    ``{host_id: hostname}`` of every host (the syslog TLS receiver matches a
    client certificate against it).

    Used by the flow collector at startup and on host CRUD to resolve
    incoming exporter IPs to inventory hosts without a per-packet DB hit.
    A device exports from whichever interface routes to the collector,
    which is often not the address it has in the inventory: the aliases
    (SNMP discovery's ipAddrTable, a collected configuration's or an
    OPNsense collection's interface addresses) tie that source to the host,
    as ``find_host_by_ip(include_aliases=True)`` does for syslog. A primary
    address always wins over an alias; between two aliases the lowest host
    id wins (as in ``find_host_by_ip``). Last-wins on primary collisions
    (same IP across multiple groups), which matches how the flow collector
    treats exporter identity (per IP, not per group).
    """
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT id, hostname, ip_address FROM hosts")
        rows = await cursor.fetchall()
        mapping: dict[str, int] = {}
        for r in rows:
            d = dict(r)
            if hostnames is not None:
                hostnames[int(d["id"])] = str(d.get("hostname") or "")
            ip = (d.get("ip_address") or "").strip()
            if ip:
                mapping[ip] = int(d["id"])
        cursor = await db.execute("SELECT host_id, ip_address FROM host_ip_aliases ORDER BY host_id, ip_address")
        for r in await cursor.fetchall():
            d = dict(r)
            ip = (d.get("ip_address") or "").strip()
            if ip:
                mapping.setdefault(ip, int(d["host_id"]))
        return mapping
    finally:
        await db.close()


async def upsert_flow_exporter(
    exporter_ip: str,
    flow_type: str,
    host_id: int | None,
    packets_delta: int = 1,
    sampling_rate: int = 0,
    last_record_at: str | None = None,
) -> None:
    """Insert or update a flow exporter row for ``(exporter_ip, flow_type)``.

    Increments ``packets_received`` by ``packets_delta`` and refreshes
    ``last_seen`` and ``last_record_at`` on every call. ``host_id`` is
    overwritten on conflict so a freshly-resolved exporter becomes linked
    immediately after the corresponding host is added to inventory.
    """
    if not exporter_ip or not flow_type:
        return
    now_expr = "NOW()"
    last_record_expr = "COALESCE(EXCLUDED.last_record_at, flow_exporters.last_record_at)"
    db = await _dbcore.get_db()
    try:
        await db.execute(
            f"""
            INSERT INTO flow_exporters
                (exporter_ip, host_id, flow_type, packets_received,
                 sampling_rate, first_seen, last_seen, last_record_at)
            VALUES (?, ?, ?, ?, ?, {now_expr}, {now_expr}, ?)
            ON CONFLICT (exporter_ip, flow_type) DO UPDATE SET
                host_id = EXCLUDED.host_id,
                packets_received = flow_exporters.packets_received + EXCLUDED.packets_received,
                sampling_rate = CASE WHEN EXCLUDED.sampling_rate > 0
                                     THEN EXCLUDED.sampling_rate
                                     ELSE flow_exporters.sampling_rate END,
                last_seen = {now_expr},
                last_record_at = {last_record_expr}
            """,
            (
                exporter_ip,
                host_id,
                flow_type,
                int(packets_delta),
                int(sampling_rate or 0),
                last_record_at,
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def update_flow_exporter_host_id(exporter_ip: str, host_id: int | None) -> int:
    """Update host_id on every flow_exporters row matching exporter_ip.

    Called from host CRUD so a host appearing/disappearing in inventory
    is reflected in the exporter view without waiting for the next packet.
    """
    if not exporter_ip:
        return 0
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "UPDATE flow_exporters SET host_id = ? WHERE exporter_ip = ?",
            (host_id, exporter_ip),
        )
        await db.commit()
        return cursor.rowcount or 0
    finally:
        await db.close()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


async def relink_flow_exporters(mapping: dict[str, int]) -> int:
    """Set ``host_id`` of every ``flow_exporters`` row whose exporter address
    resolves to another host than the one it is linked to (``mapping``: the
    exporter cache, ``get_exporter_host_map``); an address that resolves to
    none is unlinked. Rows whose exporter is no IP address are left alone.
    Returns the number of rows changed."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT DISTINCT exporter_ip, host_id FROM flow_exporters")
        changed = 0
        for r in await cursor.fetchall():
            d = dict(r)
            ip = str(d.get("exporter_ip") or "")
            if not _is_ip(ip):
                continue
            current = d.get("host_id")
            expected = mapping.get(ip)
            if (int(current) if current is not None else None) == expected:
                continue
            update = await db.execute("UPDATE flow_exporters SET host_id = ? WHERE exporter_ip = ?", (expected, ip))
            changed += update.rowcount or 0
        await db.commit()
        return changed
    finally:
        await db.close()


async def replace_flow_interface_names(host_id: int, source: str, entries: list[dict]) -> int:
    """Replace the interface names ``source`` recorded for the flows of
    ``host_id``: ``entries`` of ``{if_index, device, name}``. Rows another
    source wrote stay. Returns the number of rows written."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    clean: dict[int, tuple[str, str]] = {}
    for entry in entries:
        try:
            index = int(entry.get("if_index"))
        except TypeError, ValueError:
            continue
        if index > 0:
            clean[index] = (str(entry.get("device") or "")[:128], str(entry.get("name") or "")[:128])
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM flow_interface_names WHERE host_id = ? AND source = ?", (host_id, source))
        for index, (device, name) in sorted(clean.items()):
            await db.execute(
                """INSERT INTO flow_interface_names (host_id, if_index, device, name, source, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT (host_id, if_index) DO UPDATE SET
                       device = EXCLUDED.device, name = EXCLUDED.name,
                       source = EXCLUDED.source, updated_at = EXCLUDED.updated_at""",
                (host_id, index, device, name, source, now),
            )
        await db.commit()
        return len(clean)
    finally:
        await db.close()


async def get_flow_interface_names(host_ids: Iterable[int | None]) -> dict[int, dict[int, dict[str, str]]]:
    """``{host_id: {if_index: {"name", "device"}}}`` for the interface
    indexes flow records carry: the SNMP-polled interfaces of a host
    (``interface_stats``: NetFlow names the SNMP ifIndex), overridden by
    what an integration recorded (``flow_interface_names``). A host with
    neither is missing."""
    ids = sorted({int(h) for h in host_ids if h is not None})
    if not ids:
        return {}
    placeholders = ",".join("?" * len(ids))
    found: dict[int, dict[int, dict[str, str]]] = {}
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT host_id, if_index, if_name FROM interface_stats WHERE host_id IN ({placeholders})",
            tuple(ids),
        )
        for r in await cursor.fetchall():
            d = dict(r)
            name = str(d.get("if_name") or "")
            if name:
                found.setdefault(int(d["host_id"]), {})[int(d["if_index"])] = {"name": name, "device": name}
        cursor = await db.execute(
            f"SELECT host_id, if_index, device, name FROM flow_interface_names WHERE host_id IN ({placeholders})",
            tuple(ids),
        )
        for r in await cursor.fetchall():
            d = dict(r)
            device = str(d.get("device") or "")
            found.setdefault(int(d["host_id"]), {})[int(d["if_index"])] = {
                "name": str(d.get("name") or "") or device,
                "device": device,
            }
        return found
    finally:
        await db.close()


async def with_interface_names(rows: list[dict]) -> list[dict]:
    """``rows`` (each with ``host_id`` and ``if_index``) with ``if_name``
    and ``if_device`` of the index added (``None`` when the host has no
    name for it: the index alone is shown, as before)."""
    names = await get_flow_interface_names(r.get("host_id") for r in rows)
    for row in rows:
        host_id, index = row.get("host_id"), row.get("if_index")
        known = names.get(int(host_id), {}).get(int(index)) if host_id is not None and index is not None else None
        row["if_name"] = known["name"] if known else None
        row["if_device"] = known["device"] if known else None
    return rows


async def list_flow_exporters() -> list[dict]:
    """Return all flow exporters joined with host hostname when known."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """
            SELECT
                e.id,
                e.exporter_ip,
                e.host_id,
                h.hostname AS hostname,
                e.flow_type,
                e.packets_received,
                e.sampling_rate,
                e.first_seen,
                e.last_seen,
                e.last_record_at
            FROM flow_exporters e
            LEFT JOIN hosts h ON h.id = e.host_id
            ORDER BY e.last_seen DESC, e.exporter_ip ASC
            """
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


def _cloud_flow_type(provider: str) -> str:
    normalized = str(provider or "").strip().lower()
    if normalized not in {"aws", "azure", "gcp"}:
        raise ValueError("invalid_provider")
    return f"cloud_{normalized}_flow"


def _cloud_flow_exporter(account_id: int) -> str:
    return f"cloud-account-{int(account_id)}"


def _cloud_flow_where(account_id: int | None, provider: str | None, hours: int) -> tuple[str, list]:
    """The ``WHERE`` clause and its parameters of the cloud flow views: the
    cloud flow records received in the last ``hours`` hours, of one account
    and one provider when given."""
    clauses = [
        "received_at >= datetime('now', ? || ' hours')",
        "flow_type LIKE 'cloud_%'",
    ]
    params: list = [f"-{max(1, int(hours))}"]
    if account_id is not None:
        clauses.append("exporter_ip = ?")
        params.append(_cloud_flow_exporter(account_id))
    if provider:
        clauses.append("flow_type = ?")
        params.append(_cloud_flow_type(provider))
    return "WHERE " + " AND ".join(clauses), params


def _cloud_summary(found: dict[str, list[dict]], sizes: dict[str, int]) -> dict:
    """The cloud flow summary from the ``total``, ``top_src`` and ``top_dst``
    sets of ``_flow_aggregates`` (the distinct addresses are their group
    counts)."""
    total = (found.get("total") or [{}])[0]
    return {
        "flow_count": int(total.get("flow_count") or 0),
        "total_bytes": total.get("total_bytes") or 0,
        "total_packets": total.get("total_packets") or 0,
        "unique_sources": sizes.get("top_src", 0),
        "unique_destinations": sizes.get("top_dst", 0),
        "first_seen": total.get("first_seen"),
        "last_seen": total.get("last_seen"),
    }


async def get_cloud_flow_summary(
    account_id: int | None = None,
    provider: str | None = None,
    hours: int = 24,
) -> dict:
    where, params = _cloud_flow_where(account_id, provider, hours)
    found, sizes = await _flow_aggregates(where, params, {"total", "top_src", "top_dst"}, limit=1)
    return _cloud_summary(found, sizes)


async def get_cloud_flow_top_talkers(
    account_id: int | None = None,
    provider: str | None = None,
    hours: int = 24,
    direction: str = "src",
    limit: int = 20,
) -> list[dict]:
    name = "top_src" if direction == "src" else "top_dst"
    where, params = _cloud_flow_where(account_id, provider, hours)
    found, _ = await _flow_aggregates(where, params, {name}, limit)
    return found[name]


async def get_cloud_flow_timeline(
    account_id: int | None = None,
    provider: str | None = None,
    hours: int = 24,
    bucket_minutes: int = 5,
) -> list[dict]:
    where, params = _cloud_flow_where(account_id, provider, hours)
    found, _ = await _flow_aggregates(where, params, {"timeline"}, bucket_minutes=bucket_minutes)
    return found["timeline"]


async def get_cloud_flow_overview(
    account_id: int | None = None,
    provider: str | None = None,
    hours: int = 24,
    limit: int = 20,
    bucket_minutes: int = 5,
) -> dict:
    """The cloud flow view from one scan of the records: ``summary``
    (``get_cloud_flow_summary``), ``top_src`` and ``top_dst``
    (``get_cloud_flow_top_talkers``) and ``timeline``
    (``get_cloud_flow_timeline``) for the same arguments."""
    where, params = _cloud_flow_where(account_id, provider, hours)
    found, sizes = await _flow_aggregates(
        where, params, {"total", "top_src", "top_dst", "timeline"}, limit, bucket_minutes
    )
    return {
        "summary": _cloud_summary(found, sizes),
        "top_src": found["top_src"],
        "top_dst": found["top_dst"],
        "timeline": found["timeline"],
    }
