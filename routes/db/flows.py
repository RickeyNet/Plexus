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

import routes.database as _dbcore
from routes.database import (
    _LOGGER,
    _is_unique_violation,
    _minute_bucket_expr,
    row_to_dict,
    rows_to_list,
)
from routes.db.inventory import group_ids_condition

__all__ = [
    "create_flow_records_batch",
    "get_flow_top_talkers",
    "get_flow_top_applications",
    "get_flow_top_conversations",
    "get_flow_timeline",
    "create_flow_summary",
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
]

# ═════════════════════════════════════════════════════════════════════════════
# FLOW RECORDS  (NetFlow / sFlow / IPFIX)
# ═════════════════════════════════════════════════════════════════════════════


async def create_flow_records_batch(rows: list[tuple]) -> int:
    """Batch insert flow records.  Each tuple:
    (exporter_ip, host_id, flow_type, src_ip, dst_ip, src_port, dst_port,
     protocol, bytes, packets, src_as, dst_as, input_if, output_if,
     tos, tcp_flags, start_time, end_time)
    """
    if not rows:
        return 0
    db = await _dbcore.get_db()
    try:
        await db.executemany(
            """INSERT INTO flow_records
               (exporter_ip, host_id, flow_type, src_ip, dst_ip, src_port, dst_port,
                protocol, bytes, packets, src_as, dst_as, input_if, output_if,
                tos, tcp_flags, start_time, end_time)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
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


async def get_flow_top_talkers(
    host_id: int | None = None,
    hours: int = 1,
    direction: str = "src",
    limit: int = 20,
    group_ids: Iterable[int] | None = None,
) -> list[dict]:
    """``group_ids``: over the flows of exporters in those inventory groups."""
    db = await _dbcore.get_db(read_only=True)
    try:
        col = "src_ip" if direction == "src" else "dst_ip"
        where = "WHERE received_at >= datetime('now', ? || ' hours')"
        params: list = [f"-{hours}"]
        if host_id is not None:
            where += " AND host_id = ?"
            params.append(host_id)
        where = _with_host_scope(where, params, group_ids)
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT {col} as ip, SUM(bytes) as total_bytes, SUM(packets) as total_packets,
                       COUNT(*) as flow_count
               FROM flow_records {where}
               GROUP BY {col} ORDER BY total_bytes DESC LIMIT ?""",
            params,
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_flow_top_applications(
    host_id: int | None = None, hours: int = 1, limit: int = 20, group_ids: Iterable[int] | None = None
) -> list[dict]:
    """``group_ids``: over the flows of exporters in those inventory groups."""
    db = await _dbcore.get_db(read_only=True)
    try:
        where = "WHERE received_at >= datetime('now', ? || ' hours')"
        params: list = [f"-{hours}"]
        if host_id is not None:
            where += " AND host_id = ?"
            params.append(host_id)
        where = _with_host_scope(where, params, group_ids)
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT dst_port as port, protocol, SUM(bytes) as total_bytes,
                       SUM(packets) as total_packets, COUNT(*) as flow_count
               FROM flow_records {where}
               GROUP BY dst_port, protocol ORDER BY total_bytes DESC LIMIT ?""",
            params,
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_flow_top_conversations(
    host_id: int | None = None, hours: int = 1, limit: int = 20, group_ids: Iterable[int] | None = None
) -> list[dict]:
    """``group_ids``: over the flows of exporters in those inventory groups."""
    db = await _dbcore.get_db(read_only=True)
    try:
        where = "WHERE received_at >= datetime('now', ? || ' hours')"
        params: list = [f"-{hours}"]
        if host_id is not None:
            where += " AND host_id = ?"
            params.append(host_id)
        where = _with_host_scope(where, params, group_ids)
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT src_ip, dst_ip, SUM(bytes) as total_bytes,
                       SUM(packets) as total_packets, COUNT(*) as flow_count
               FROM flow_records {where}
               GROUP BY src_ip, dst_ip ORDER BY total_bytes DESC LIMIT ?""",
            params,
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_flow_timeline(
    host_id: int | None = None, hours: int = 6, bucket_minutes: int = 5, group_ids: Iterable[int] | None = None
) -> list[dict]:
    """Aggregate flow data into time buckets; ``group_ids``: over the flows
    of exporters in those inventory groups."""
    # Validate bucket_minutes to prevent SQL injection via f-string
    bucket_minutes = max(1, min(int(bucket_minutes), 60))
    db = await _dbcore.get_db(read_only=True)
    try:
        where = "WHERE received_at >= datetime('now', ? || ' hours')"
        params: list = [f"-{max(1, int(hours))}"]
        if host_id is not None:
            where += " AND host_id = ?"
            params.append(host_id)
        where = _with_host_scope(where, params, group_ids)
        bucket_expr = _minute_bucket_expr("received_at", bucket_minutes)
        cursor = await db.execute(
            f"""SELECT
                   {bucket_expr} as bucket,
                   SUM(bytes) as total_bytes,
                   SUM(packets) as total_packets,
                   COUNT(*) as flow_count
               FROM flow_records {where}
               GROUP BY bucket ORDER BY bucket""",
            params,
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_flow_top_interfaces(
    host_id: int | None = None, hours: int = 1, limit: int = 20, group_ids: Iterable[int] | None = None
) -> list[dict]:
    """The interfaces of the exporters ranked by the bytes of their flows:
    ``host_id``, ``exporter_ip``, ``if_index`` (the number the records
    carry), ``in_bytes`` (flows that entered on it: ``input_if``),
    ``out_bytes`` (flows that left on it: ``output_if``), ``total_bytes``
    and ``flow_count`` (records that name it either way). ``group_ids``:
    over the flows of exporters in those inventory groups."""
    db = await _dbcore.get_db(read_only=True)
    try:
        where = "WHERE received_at >= datetime('now', ? || ' hours')"
        params: list = [f"-{hours}"]
        if host_id is not None:
            where += " AND host_id = ?"
            params.append(host_id)
        where = _with_host_scope(where, params, group_ids)
        cursor = await db.execute(
            f"""SELECT host_id, exporter_ip, if_index,
                       SUM(in_bytes) as in_bytes, SUM(out_bytes) as out_bytes,
                       SUM(in_bytes) + SUM(out_bytes) as total_bytes, COUNT(*) as flow_count
               FROM (
                   SELECT host_id, exporter_ip, input_if as if_index, bytes as in_bytes, 0 as out_bytes
                   FROM flow_records {where}
                   UNION ALL
                   SELECT host_id, exporter_ip, output_if as if_index, 0 as in_bytes, bytes as out_bytes
                   FROM flow_records {where}
               ) sides
               GROUP BY host_id, exporter_ip, if_index ORDER BY total_bytes DESC LIMIT ?""",
            [*params, *params, limit],
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def create_flow_summary(
    host_id: int | None, summary_type: str, time_window: str, period_start: str, period_end: str, data_json: str
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO flow_summaries
               (host_id, summary_type, time_window, period_start, period_end, data_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (host_id, summary_type, time_window, period_start, period_end, data_json),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def cleanup_old_flow_records(hours: int = 48) -> int:
    return await _dbcore.chunked_delete(
        "flow_records",
        "received_at < datetime('now', ? || ' hours')",
        (f"-{hours}",),
    )


async def cleanup_old_flow_summaries(days: int = 30) -> int:
    """Delete hourly flow summaries written more than ``days`` ago
    (``summary_retention_days``)."""
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


async def get_cloud_flow_summary(
    account_id: int | None = None,
    provider: str | None = None,
    hours: int = 24,
) -> dict:
    db = await _dbcore.get_db(read_only=True)
    try:
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
        where = " AND ".join(clauses)
        cursor = await db.execute(
            f"""SELECT COUNT(*) as flow_count,
                       COALESCE(SUM(bytes), 0) as total_bytes,
                       COALESCE(SUM(packets), 0) as total_packets,
                       COUNT(DISTINCT src_ip) as unique_sources,
                       COUNT(DISTINCT dst_ip) as unique_destinations,
                       MIN(received_at) as first_seen,
                       MAX(received_at) as last_seen
               FROM flow_records
               WHERE {where}""",
            tuple(params),
        )
        return row_to_dict(await cursor.fetchone()) or {
            "flow_count": 0,
            "total_bytes": 0,
            "total_packets": 0,
            "unique_sources": 0,
            "unique_destinations": 0,
            "first_seen": None,
            "last_seen": None,
        }
    finally:
        await db.close()


async def get_cloud_flow_top_talkers(
    account_id: int | None = None,
    provider: str | None = None,
    hours: int = 24,
    direction: str = "src",
    limit: int = 20,
) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        col = "src_ip" if direction == "src" else "dst_ip"
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
        params.append(max(1, int(limit)))
        where = " AND ".join(clauses)
        cursor = await db.execute(
            f"""SELECT {col} as ip,
                       SUM(bytes) as total_bytes,
                       SUM(packets) as total_packets,
                       COUNT(*) as flow_count
                FROM flow_records
                WHERE {where}
                GROUP BY {col}
                ORDER BY total_bytes DESC
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_flow_timeline(
    account_id: int | None = None,
    provider: str | None = None,
    hours: int = 24,
    bucket_minutes: int = 5,
) -> list[dict]:
    bucket_minutes = max(1, min(int(bucket_minutes), 60))
    db = await _dbcore.get_db(read_only=True)
    try:
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
        where = " AND ".join(clauses)
        bucket_expr = _minute_bucket_expr("received_at", bucket_minutes)
        cursor = await db.execute(
            f"""SELECT
                   {bucket_expr} as bucket,
                   SUM(bytes) as total_bytes,
                   SUM(packets) as total_packets,
                   COUNT(*) as flow_count
               FROM flow_records
               WHERE {where}
               GROUP BY bucket
               ORDER BY bucket""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()
