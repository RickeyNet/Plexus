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
from datetime import UTC, datetime, timedelta

import aiosqlite

import routes.database as _dbcore
from routes.database import (
    _LOGGER,
    _is_unique_violation,
    row_to_dict,
    rows_to_list,
)

__all__ = [
    "create_flow_records_batch",
    "get_flow_top_talkers",
    "get_flow_top_applications",
    "get_flow_top_conversations",
    "get_flow_timeline",
    "create_flow_summary",
    "cleanup_old_flow_records",
    "get_exporter_host_map",
    "upsert_flow_exporter",
    "update_flow_exporter_host_id",
    "list_flow_exporters",
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


async def get_flow_top_talkers(host_id: int | None = None, hours: int = 1,
                                direction: str = "src", limit: int = 20) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        col = "src_ip" if direction == "src" else "dst_ip"
        where = "WHERE received_at >= datetime('now', ? || ' hours')"
        params: list = [f"-{hours}"]
        if host_id is not None:
            where += " AND host_id = ?"
            params.append(host_id)
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


async def get_flow_top_applications(host_id: int | None = None, hours: int = 1,
                                     limit: int = 20) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        where = "WHERE received_at >= datetime('now', ? || ' hours')"
        params: list = [f"-{hours}"]
        if host_id is not None:
            where += " AND host_id = ?"
            params.append(host_id)
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


async def get_flow_top_conversations(host_id: int | None = None, hours: int = 1,
                                      limit: int = 20) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        where = "WHERE received_at >= datetime('now', ? || ' hours')"
        params: list = [f"-{hours}"]
        if host_id is not None:
            where += " AND host_id = ?"
            params.append(host_id)
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


async def get_flow_timeline(host_id: int | None = None, hours: int = 6,
                             bucket_minutes: int = 5) -> list[dict]:
    """Aggregate flow data into time buckets."""
    # Validate bucket_minutes to prevent SQL injection via f-string
    bucket_minutes = max(1, min(int(bucket_minutes), 60))
    db = await _dbcore.get_db()
    try:
        where = "WHERE received_at >= datetime('now', ? || ' hours')"
        params: list = [f"-{max(1, int(hours))}"]
        if host_id is not None:
            where += " AND host_id = ?"
            params.append(host_id)
        cursor = await db.execute(
            f"""SELECT
                   strftime('%Y-%m-%dT%H:', received_at) ||
                   printf('%02d', (CAST(strftime('%M', received_at) AS INTEGER) / {bucket_minutes}) * {bucket_minutes}) ||
                   ':00' as bucket,
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


async def create_flow_summary(host_id: int | None, summary_type: str,
                               time_window: str, period_start: str,
                               period_end: str, data_json: str) -> int:
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
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM flow_records WHERE received_at < datetime('now', ? || ' hours')",
            (f"-{hours}",),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def get_exporter_host_map() -> dict[str, int]:
    """Return ``{ip_address: host_id}`` for every host with a non-empty IP.

    Used by the flow collector at startup and on host CRUD to resolve
    incoming exporter IPs to inventory hosts without a per-packet DB hit.
    Last-wins on collisions (same IP across multiple groups), which matches
    how the flow collector treats exporter identity (per IP, not per group).
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT id, ip_address FROM hosts WHERE ip_address IS NOT NULL AND ip_address != ''"
        )
        rows = await cursor.fetchall()
        mapping: dict[str, int] = {}
        for r in rows:
            d = dict(r)
            ip = (d.get("ip_address") or "").strip()
            if ip:
                mapping[ip] = int(d["id"])
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
    if _dbcore.DB_ENGINE == "postgres":
        now_expr = "NOW()"
        last_record_expr = "COALESCE(EXCLUDED.last_record_at, flow_exporters.last_record_at)"
    else:
        now_expr = "datetime('now')"
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


async def list_flow_exporters() -> list[dict]:
    """Return all flow exporters joined with host hostname when known."""
    db = await _dbcore.get_db()
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
    db = await _dbcore.get_db()
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
    db = await _dbcore.get_db()
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
    db = await _dbcore.get_db()
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
            f"""SELECT
                   strftime('%Y-%m-%dT%H:', received_at) ||
                   printf('%02d', (CAST(strftime('%M', received_at) AS INTEGER) / {bucket_minutes}) * {bucket_minutes}) ||
                   ':00' as bucket,
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


