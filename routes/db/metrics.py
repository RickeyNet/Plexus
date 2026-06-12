"""Metrics persistence helpers.

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
    _safe_dynamic_update,
    row_to_dict,
    rows_to_list,
)

__all__ = [
    "create_metric_sample",
    "create_metric_samples_batch",
    "query_metric_samples",
    "delete_old_metric_samples",
    "create_metric_rollup",
    "query_metric_rollups",
    "get_raw_samples_for_rollup",
    "delete_old_metric_rollups",
    "create_interface_ts_sample",
    "create_interface_ts_batch",
    "get_top_interfaces_by_bandwidth",
    "query_interface_ts",
    "delete_old_interface_ts",
    "get_interface_error_stats_for_host",
    "upsert_interface_error_stat",
    "upsert_interface_error_stats_batch",
    "create_interface_error_event",
    "get_interface_error_events",
    "get_interface_error_event",
    "acknowledge_interface_error_event",
    "resolve_interface_error_event",
    "get_interface_error_summary",
    "get_interface_error_trending",
    "delete_old_interface_error_events",
    "get_trap_syslog_events_in_range",
    "get_topology_changes_in_range",
    "get_vendor_oid_entries",
    "get_vendor_oid_for_host",
    "upsert_vendor_oid",
    "delete_vendor_oid",
    "create_trap_syslog_event",
    "get_trap_syslog_events",
    "delete_old_trap_syslog_events",
    "list_dashboards",
    "get_dashboard",
    "create_dashboard",
    "update_dashboard",
    "delete_dashboard",
    "create_dashboard_panel",
    "update_dashboard_panel",
    "delete_dashboard_panel",
    "get_annotations_in_range",
    "get_config_drift_events_in_range",
    "get_monitoring_alerts_in_range",
    "get_deployments_for_host_in_range",
    "get_audit_events_for_deployment",
    "record_availability_transition",
    "get_last_availability_state",
    "get_last_availability_states",
    "record_availability_transitions_batch",
    "get_availability_transitions",
    "get_availability_summary",
    "get_outage_history",
    "get_interface_utilization_summary",
    "get_port_detail_ts",
    "get_custom_oid_profiles",
    "get_custom_oid_profile",
    "create_custom_oid_profile",
    "update_custom_oid_profile",
    "delete_custom_oid_profile",
]

# ═════════════════════════════════════════════════════════════════════════════
# Metric Samples  (Prometheus-style flexible metric storage)
# ═════════════════════════════════════════════════════════════════════════════


async def create_metric_sample(
    host_id: int, metric_name: str, value: float,
    labels_json: str = "{}",
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO metric_samples (host_id, metric_name, labels_json, value)
               VALUES (?, ?, ?, ?)""",
            (host_id, metric_name, labels_json, value),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def create_metric_samples_batch(rows: list[tuple]) -> int:
    """Insert many metric samples at once.  Each tuple:
    (host_id, metric_name, labels_json, value)
    """
    if not rows:
        return 0
    db = await _dbcore.get_db()
    try:
        await db.executemany(
            """INSERT INTO metric_samples (host_id, metric_name, labels_json, value)
               VALUES (?, ?, ?, ?)""",
            rows,
        )
        await db.commit()
        return len(rows)
    finally:
        await db.close()


async def query_metric_samples(
    metric_name: str,
    host_ids: list[int] | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 5000,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses = ["metric_name = ?"]
        params: list = [metric_name]
        if host_ids:
            placeholders = ",".join("?" for _ in host_ids)
            clauses.append(f"host_id IN ({placeholders})")
            params.extend(host_ids)
        if start:
            clauses.append("sampled_at >= ?")
            params.append(start)
        if end:
            clauses.append("sampled_at <= ?")
            params.append(end)
        where = " AND ".join(clauses)
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT ms.*, h.hostname, h.ip_address
                FROM metric_samples ms
                JOIN hosts h ON h.id = ms.host_id
                WHERE {where}
                ORDER BY ms.sampled_at DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_old_metric_samples(hours: int = 48) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM metric_samples WHERE sampled_at < datetime('now', '-' || ? || ' hours')",
            (hours,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Metric Rollups  (downsampled aggregates: hourly / daily)
# ═════════════════════════════════════════════════════════════════════════════


async def create_metric_rollup(
    host_id: int, metric_name: str, time_window: str,
    period_start: str, period_end: str,
    val_min: float, val_avg: float, val_max: float, val_p95: float,
    sample_count: int, labels_json: str = "{}",
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO metric_rollups
               (host_id, metric_name, labels_json, time_window,
                period_start, period_end,
                val_min, val_avg, val_max, val_p95, sample_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, metric_name, labels_json, time_window,
             period_start, period_end,
             val_min, val_avg, val_max, val_p95, sample_count),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def query_metric_rollups(
    metric_name: str,
    time_window: str = "hourly",
    host_ids: list[int] | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 5000,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses = ["metric_name = ?", "time_window = ?"]
        params: list = [metric_name, time_window]
        if host_ids:
            placeholders = ",".join("?" for _ in host_ids)
            clauses.append(f"host_id IN ({placeholders})")
            params.extend(host_ids)
        if start:
            clauses.append("period_start >= ?")
            params.append(start)
        if end:
            clauses.append("period_end <= ?")
            params.append(end)
        where = " AND ".join(clauses)
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT mr.*, h.hostname, h.ip_address
                FROM metric_rollups mr
                JOIN hosts h ON h.id = mr.host_id
                WHERE {where}
                ORDER BY mr.period_start DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_raw_samples_for_rollup(
    metric_name: str, period_start: str, period_end: str,
) -> list[dict]:
    """Fetch raw samples in a time range, grouped by host+labels,
    for the downsampling engine to aggregate."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT host_id, labels_json, value
               FROM metric_samples
               WHERE metric_name = ? AND sampled_at >= ? AND sampled_at < ?
               ORDER BY host_id, labels_json""",
            (metric_name, period_start, period_end),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_old_metric_rollups(time_window: str, retention_days: int) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM metric_rollups WHERE time_window = ? AND period_start < datetime('now', '-' || ? || ' days')",
            (time_window, retention_days),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Interface Time-Series
# ═════════════════════════════════════════════════════════════════════════════


async def create_interface_ts_sample(
    host_id: int, if_index: int, if_name: str, if_speed_mbps: int,
    in_octets: int, out_octets: int,
    in_rate_bps: float | None = None, out_rate_bps: float | None = None,
    utilization_pct: float | None = None,
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO interface_ts
               (host_id, if_index, if_name, if_speed_mbps,
                in_octets, out_octets, in_rate_bps, out_rate_bps, utilization_pct)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, if_index, if_name, if_speed_mbps,
             in_octets, out_octets, in_rate_bps, out_rate_bps, utilization_pct),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def create_interface_ts_batch(rows: list[tuple]) -> int:
    """Batch insert interface time-series samples.  Each tuple:
    (host_id, if_index, if_name, if_speed_mbps,
     in_octets, out_octets, in_rate_bps, out_rate_bps, utilization_pct)
    """
    if not rows:
        return 0
    db = await _dbcore.get_db()
    try:
        await db.executemany(
            """INSERT INTO interface_ts
               (host_id, if_index, if_name, if_speed_mbps,
                in_octets, out_octets, in_rate_bps, out_rate_bps, utilization_pct)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        await db.commit()
        return len(rows)
    finally:
        await db.close()


async def get_top_interfaces_by_bandwidth(
    start: str,
    limit: int = 5,
) -> list[dict]:
    """Return top-N interfaces network-wide by peak bandwidth over [start, now).

    Used by the dashboard bandwidth-trend panel to pick which interfaces to chart.
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT t.host_id,
                      t.if_index,
                      MAX(t.if_name) AS if_name,
                      MAX(t.if_speed_mbps) AS if_speed_mbps,
                      MAX(h.hostname) AS hostname,
                      MAX(GREATEST(COALESCE(t.in_rate_bps, 0),
                                   COALESCE(t.out_rate_bps, 0))) AS peak_bps
               FROM interface_ts t
               JOIN hosts h ON h.id = t.host_id
               WHERE t.sampled_at >= ?
                 AND (t.in_rate_bps IS NOT NULL OR t.out_rate_bps IS NOT NULL)
               GROUP BY t.host_id, t.if_index
               ORDER BY peak_bps DESC
               LIMIT ?""",
            (start, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def query_interface_ts(
    host_id: int,
    if_index: int | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 2000,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses = ["host_id = ?"]
        params: list = [host_id]
        if if_index is not None:
            clauses.append("if_index = ?")
            params.append(if_index)
        if start:
            clauses.append("sampled_at >= ?")
            params.append(start)
        if end:
            clauses.append("sampled_at <= ?")
            params.append(end)
        where = " AND ".join(clauses)
        params.append(limit)
        cursor = await db.execute(
            f"SELECT * FROM interface_ts WHERE {where} ORDER BY sampled_at DESC LIMIT ?",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_old_interface_ts(retention_days: int = 30) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM interface_ts WHERE sampled_at < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Interface Error/Discard Tracking
# ═════════════════════════════════════════════════════════════════════════════


async def get_interface_error_stats_for_host(host_id: int) -> list[dict]:
    """Fetch current error counter state for all interfaces on a host."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM interface_error_stats WHERE host_id = ?",
            (host_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def upsert_interface_error_stat(
    host_id: int,
    if_index: int,
    if_name: str,
    in_errors: int,
    out_errors: int,
    in_discards: int,
    out_discards: int,
) -> int:
    """Update or insert interface error counters, shifting current to prev."""
    return await upsert_interface_error_stats_batch(host_id, [
        (if_index, if_name, in_errors, out_errors, in_discards, out_discards),
    ])


async def upsert_interface_error_stats_batch(
    host_id: int,
    rows: list[tuple],
) -> int:
    """Batch upsert interface error counters for one host."""
    if not rows:
        return 0
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT if_index FROM interface_error_stats WHERE host_id = ?",
            (host_id,),
        )
        existing = {
            row_to_dict(row)["if_index"]
            for row in await cursor.fetchall()
        }
        update_params: list[tuple] = []
        insert_params: list[tuple] = []
        for if_index, if_name, in_errors, out_errors, in_discards, out_discards in rows:
            if if_index in existing:
                update_params.append(
                    (if_name, in_errors, out_errors, in_discards, out_discards,
                     host_id, if_index))
            else:
                insert_params.append(
                    (host_id, if_index, if_name, in_errors, out_errors,
                     in_discards, out_discards))
                existing.add(if_index)
        if update_params:
            await db.executemany(
                """UPDATE interface_error_stats
                   SET if_name = ?,
                       prev_in_errors = in_errors, prev_out_errors = out_errors,
                       prev_in_discards = in_discards, prev_out_discards = out_discards,
                       prev_polled_at = polled_at,
                       in_errors = ?, out_errors = ?,
                       in_discards = ?, out_discards = ?,
                       polled_at = datetime('now')
                   WHERE host_id = ? AND if_index = ?""",
                update_params,
            )
        if insert_params:
            await db.executemany(
                """INSERT INTO interface_error_stats
                   (host_id, if_index, if_name, in_errors, out_errors,
                    in_discards, out_discards)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                insert_params,
            )
        await db.commit()
        return len(rows)
    finally:
        await db.close()


async def create_interface_error_event(
    host_id: int,
    if_index: int,
    if_name: str,
    event_type: str,
    metric_name: str,
    severity: str,
    current_rate: float,
    baseline_rate: float,
    spike_factor: float,
    root_cause_hint: str,
    root_cause_category: str,
    correlation_details: str = "{}",
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO interface_error_events
               (host_id, if_index, if_name, event_type, metric_name, severity,
                current_rate, baseline_rate, spike_factor,
                root_cause_hint, root_cause_category, correlation_details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, if_index, if_name, event_type, metric_name, severity,
             current_rate, baseline_rate, spike_factor,
             root_cause_hint, root_cause_category, correlation_details),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_interface_error_events(
    host_id: int | None = None,
    severity: str | None = None,
    unresolved_only: bool = False,
    limit: int = 200,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if host_id is not None:
            clauses.append("e.host_id = ?")
            params.append(host_id)
        if severity:
            clauses.append("e.severity = ?")
            params.append(severity)
        if unresolved_only:
            clauses.append("e.resolved_at IS NULL")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT e.*, h.hostname, h.ip_address
                FROM interface_error_events e
                LEFT JOIN hosts h ON h.id = e.host_id
                {where}
                ORDER BY e.created_at DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_interface_error_event(event_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT e.*, h.hostname, h.ip_address
               FROM interface_error_events e
               LEFT JOIN hosts h ON h.id = e.host_id
               WHERE e.id = ?""",
            (event_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def acknowledge_interface_error_event(event_id: int, user: str) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "UPDATE interface_error_events SET acknowledged = 1, acknowledged_by = ? WHERE id = ?",
            (user, event_id),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def resolve_interface_error_event(event_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "UPDATE interface_error_events SET resolved_at = datetime('now') WHERE id = ?",
            (event_id,),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_interface_error_summary(
    host_id: int,
    days: int = 1,
) -> list[dict]:
    """Per-interface error/discard rate summary with totals."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT ms.host_id, ms.labels_json, ms.metric_name,
                      COUNT(*) AS sample_count,
                      AVG(ms.value) AS avg_value,
                      MAX(ms.value) AS max_value,
                      MIN(ms.value) AS min_value
               FROM metric_samples ms
               WHERE ms.host_id = ?
                 AND ms.metric_name IN ('if_in_errors', 'if_out_errors',
                                        'if_in_discards', 'if_out_discards')
                 AND ms.sampled_at >= datetime('now', '-' || ? || ' days')
               GROUP BY ms.host_id, ms.metric_name, ms.labels_json
               ORDER BY ms.metric_name, ms.labels_json""",
            (host_id, days),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_interface_error_trending(
    host_id: int,
    if_index: int | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 5000,
) -> list[dict]:
    """Query error/discard metric_samples for a host, optionally filtered by interface."""
    db = await _dbcore.get_db()
    try:
        clauses = [
            "host_id = ?",
            "metric_name IN ('if_in_errors', 'if_out_errors', 'if_in_discards', 'if_out_discards')",
        ]
        params: list = [host_id]
        if if_index is not None:
            clauses.append("labels_json LIKE ?")
            params.append(f'%"if_index": {if_index}%')
        if start:
            clauses.append("sampled_at >= ?")
            params.append(start)
        if end:
            clauses.append("sampled_at <= ?")
            params.append(end)
        where = " AND ".join(clauses)
        params.append(limit)
        cursor = await db.execute(
            f"SELECT * FROM metric_samples WHERE {where} ORDER BY sampled_at ASC LIMIT ?",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_old_interface_error_events(retention_days: int = 90) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM interface_error_events WHERE created_at < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def get_trap_syslog_events_in_range(
    host_id: int,
    start: str,
    end: str,
    limit: int = 100,
) -> list[dict]:
    """Return trap/syslog events for a host within a time range (for error correlation)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM trap_syslog_events
               WHERE host_id = ? AND received_at >= ? AND received_at <= ?
               ORDER BY received_at DESC LIMIT ?""",
            (host_id, start, end, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_topology_changes_in_range(
    host_id: int,
    start: str,
    end: str,
    limit: int = 50,
) -> list[dict]:
    """Return topology changes for a host within a time range."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM topology_changes
               WHERE source_host_id = ? AND detected_at >= ? AND detected_at <= ?
               ORDER BY detected_at DESC LIMIT ?""",
            (host_id, start, end, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Vendor OID Registry
# ═════════════════════════════════════════════════════════════════════════════


async def get_vendor_oid_entries() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM vendor_oid_registry ORDER BY vendor, device_type")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_vendor_oid_for_host(device_type: str) -> dict | None:
    """Lookup OIDs by matching device_type substring (case-insensitive)."""
    db = await _dbcore.get_db()
    try:
        # COLLATE NOCASE is sqlite-only; postgres has no built-in case-folding
        # collation by that name. Lowercasing both sides works on every engine
        # without needing CITEXT or per-engine branches.
        cursor = await db.execute(
            """SELECT * FROM vendor_oid_registry
               WHERE LOWER(?) LIKE '%' || LOWER(device_type) || '%'
               ORDER BY LENGTH(device_type) DESC LIMIT 1""",
            (device_type,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def upsert_vendor_oid(
    vendor: str, device_type: str, cpu_oid: str = "",
    cpu_walk: int = 1, mem_used_oid: str = "", mem_free_oid: str = "",
    mem_total_oid: str = "", uptime_oid: str = "1.3.6.1.2.1.1.3",
    notes: str = "",
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO vendor_oid_registry
               (vendor, device_type, cpu_oid, cpu_walk, mem_used_oid, mem_free_oid, mem_total_oid, uptime_oid, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(vendor, device_type) DO UPDATE SET
                   cpu_oid=excluded.cpu_oid, cpu_walk=excluded.cpu_walk,
                   mem_used_oid=excluded.mem_used_oid, mem_free_oid=excluded.mem_free_oid,
                   mem_total_oid=excluded.mem_total_oid, uptime_oid=excluded.uptime_oid,
                   notes=excluded.notes""",
            (vendor, device_type, cpu_oid, cpu_walk, mem_used_oid, mem_free_oid, mem_total_oid, uptime_oid, notes),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def delete_vendor_oid(entry_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM vendor_oid_registry WHERE id = ?", (entry_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Trap / Syslog Events
# ═════════════════════════════════════════════════════════════════════════════


async def create_trap_syslog_event(
    source_ip: str, event_type: str = "trap", facility: str = "",
    severity: str = "info", oid: str = "", message: str = "",
    raw_data: str = "", host_id: int | None = None,
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO trap_syslog_events
               (source_ip, host_id, event_type, facility, severity, oid, message, raw_data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (source_ip, host_id, event_type, facility, severity, oid, message, raw_data),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_trap_syslog_events(
    event_type: str | None = None,
    host_id: int | None = None,
    severity: str | None = None,
    limit: int = 200,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if event_type:
            clauses.append("e.event_type = ?")
            params.append(event_type)
        if host_id is not None:
            clauses.append("e.host_id = ?")
            params.append(host_id)
        if severity:
            clauses.append("e.severity = ?")
            params.append(severity)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT e.*, h.hostname, h.ip_address
                FROM trap_syslog_events e
                LEFT JOIN hosts h ON h.id = e.host_id
                {where}
                ORDER BY e.received_at DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_old_trap_syslog_events(retention_days: int = 30) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM trap_syslog_events WHERE received_at < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ── Dashboards ─────────────────────────────────────────────────────────────────

async def list_dashboards(owner: str | None = None) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        if owner:
            cursor = await db.execute(
                "SELECT * FROM dashboards WHERE owner = ? ORDER BY updated_at DESC", (owner,)
            )
        else:
            cursor = await db.execute("SELECT * FROM dashboards ORDER BY updated_at DESC")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_dashboard(dashboard_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM dashboards WHERE id = ?", (dashboard_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        dashboard = dict(row)
        cursor2 = await db.execute(
            "SELECT * FROM dashboard_panels WHERE dashboard_id = ? ORDER BY grid_y, grid_x",
            (dashboard_id,),
        )
        dashboard["panels"] = rows_to_list(await cursor2.fetchall())
        return dashboard
    finally:
        await db.close()


async def create_dashboard(
    name: str, description: str = "", owner: str = "",
    layout_json: str = "{}", variables_json: str = "[]",
) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO dashboards (name, description, owner, layout_json, variables_json)
               VALUES (?, ?, ?, ?, ?)""",
            (name, description, owner, layout_json, variables_json),
        )
        await db.commit()
        new_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM dashboards WHERE id = ?", (new_id,))
        return dict(await cursor2.fetchone())
    finally:
        await db.close()


async def update_dashboard(dashboard_id: int, **kwargs) -> dict | None:
    allowed = {"name", "description", "layout_json", "variables_json", "is_default"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return await get_dashboard(dashboard_id)
    sets = ", ".join(f"{k} = ?" for k in updates)
    vals = list(updates.values())
    vals.append(dashboard_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(
            f"UPDATE dashboards SET {sets}, updated_at = datetime('now') WHERE id = ?",
            tuple(vals),
        )
        await db.commit()
        return await get_dashboard(dashboard_id)
    finally:
        await db.close()


async def delete_dashboard(dashboard_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM dashboards WHERE id = ?", (dashboard_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def create_dashboard_panel(
    dashboard_id: int, title: str = "", chart_type: str = "line",
    metric_query_json: str = "{}", grid_x: int = 0, grid_y: int = 0,
    grid_w: int = 6, grid_h: int = 4, options_json: str = "{}",
) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO dashboard_panels
               (dashboard_id, title, chart_type, metric_query_json, grid_x, grid_y, grid_w, grid_h, options_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (dashboard_id, title, chart_type, metric_query_json, grid_x, grid_y, grid_w, grid_h, options_json),
        )
        # Update dashboard timestamp in same transaction
        await db.execute("UPDATE dashboards SET updated_at = datetime('now') WHERE id = ?", (dashboard_id,))
        await db.commit()
        new_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM dashboard_panels WHERE id = ?", (new_id,))
        return dict(await cursor2.fetchone())
    finally:
        await db.close()


async def update_dashboard_panel(panel_id: int, **kwargs) -> dict | None:
    allowed = {"title", "chart_type", "metric_query_json", "grid_x", "grid_y", "grid_w", "grid_h", "options_json"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return None
    set_exprs = [f"{k} = ?" for k in updates]
    sql, sql_params = _safe_dynamic_update("dashboard_panels", set_exprs, list(updates.values()), "id = ?", panel_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, sql_params)
        cursor = await db.execute("SELECT * FROM dashboard_panels WHERE id = ?", (panel_id,))
        row = await cursor.fetchone()
        if row:
            # Update parent dashboard timestamp in same transaction
            await db.execute(
                "UPDATE dashboards SET updated_at = datetime('now') WHERE id = ?",
                (dict(row)["dashboard_id"],),
            )
        await db.commit()
        return dict(row) if row else None
    finally:
        await db.close()


async def delete_dashboard_panel(panel_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        # Get dashboard_id first to update timestamp
        cursor = await db.execute("SELECT dashboard_id FROM dashboard_panels WHERE id = ?", (panel_id,))
        row = await cursor.fetchone()
        cursor2 = await db.execute("DELETE FROM dashboard_panels WHERE id = ?", (panel_id,))
        if row:
            await db.execute(
                "UPDATE dashboards SET updated_at = datetime('now') WHERE id = ?",
                (dict(row)["dashboard_id"],),
            )
        await db.commit()
        return cursor2.rowcount > 0
    finally:
        await db.close()


# ── Annotations ────────────────────────────────────────────────────────────────

async def get_annotations_in_range(
    host_id: int | None = None,
    start: str | None = None,
    end: str | None = None,
    categories: list[str] | None = None,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        results = []
        cats = categories or ["deployment", "config", "alert"]

        # When host_id is provided, find deployment IDs that involve this host
        # so we can filter deployment annotations to only relevant ones.
        host_deployment_ids: set[int] | None = None
        if host_id is not None and "deployment" in cats:
            dep_cursor = await db.execute(
                "SELECT id, host_ids FROM deployments",
            )
            host_deployment_ids = set()
            for dep_row in await dep_cursor.fetchall():
                dep = dict(dep_row)
                try:
                    ids = json.loads(dep.get("host_ids") or "[]")
                    if host_id in ids:
                        host_deployment_ids.add(dep["id"])
                except (json.JSONDecodeError, TypeError) as exc:
                    _LOGGER.debug("skipping deployment %s: bad host_ids JSON: %s", dep.get("id"), exc)

        # Audit events
        if any(c in cats for c in ["deployment", "config", "alert"]):
            where = ["1=1"]
            params: list = []
            if start:
                where.append("timestamp >= ?")
                params.append(start)
            if end:
                where.append("timestamp <= ?")
                params.append(end)
            cat_filter = []
            if "deployment" in cats:
                cat_filter.append("category LIKE '%deploy%'")
            if "config" in cats:
                cat_filter.append("category LIKE '%config%'")
            if "alert" in cats:
                cat_filter.append("category LIKE '%alert%'")
            if cat_filter:
                where.append(f"({' OR '.join(cat_filter)})")

            cursor = await db.execute(
                f"SELECT * FROM audit_events WHERE {' AND '.join(where)} ORDER BY timestamp DESC LIMIT 500",
                tuple(params),
            )
            for row in await cursor.fetchall():
                r = dict(row)
                cat = "deployment" if "deploy" in (r.get("category") or "") else \
                      "config" if "config" in (r.get("category") or "") else \
                      "alert" if "alert" in (r.get("category") or "") else "other"

                # Filter by host_id when provided
                if host_id is not None:
                    detail = r.get("detail", "")
                    if cat == "deployment" and host_deployment_ids is not None:
                        # Check if this event references a deployment that involves the host
                        dep_id_match = re.search(r"id=(\d+)", detail)
                        if dep_id_match:
                            dep_id = int(dep_id_match.group(1))
                            if dep_id not in host_deployment_ids:
                                continue
                        else:
                            continue
                    elif cat in ("config", "alert"):
                        # Check if detail references this host_id
                        if f"host_id={host_id}" not in detail and f"host={host_id}" not in detail:
                            continue

                results.append({
                    "timestamp": r.get("timestamp"),
                    "title": r.get("action", ""),
                    "description": r.get("detail", ""),
                    "category": cat,
                    "user": r.get("user", ""),
                })

        return results
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Correlation Queries
# ═════════════════════════════════════════════════════════════════════════════


async def get_config_drift_events_in_range(
    host_ids: list[int],
    start: str,
    end: str,
) -> list[dict]:
    """Return config drift events for the given hosts within a time range."""
    if not host_ids:
        return []
    db = await _dbcore.get_db()
    try:
        placeholders = ",".join("?" for _ in host_ids)
        cursor = await db.execute(
            f"""SELECT d.*, h.hostname, h.ip_address
                FROM config_drift_events d
                LEFT JOIN hosts h ON h.id = d.host_id
                WHERE d.host_id IN ({placeholders})
                  AND d.detected_at >= ? AND d.detected_at <= ?
                ORDER BY d.detected_at DESC LIMIT 200""",
            (*host_ids, start, end),
        )
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_monitoring_alerts_in_range(
    host_ids: list[int],
    start: str,
    end: str,
) -> list[dict]:
    """Return monitoring alerts for the given hosts within a time range."""
    if not host_ids:
        return []
    db = await _dbcore.get_db()
    try:
        placeholders = ",".join("?" for _ in host_ids)
        cursor = await db.execute(
            f"""SELECT a.*, h.hostname, h.ip_address
                FROM monitoring_alerts a
                LEFT JOIN hosts h ON h.id = a.host_id
                WHERE a.host_id IN ({placeholders})
                  AND a.created_at >= ? AND a.created_at <= ?
                ORDER BY a.created_at DESC LIMIT 200""",
            (*host_ids, start, end),
        )
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_deployments_for_host_in_range(
    host_id: int,
    start: str,
    end: str,
) -> list[dict]:
    """Return deployments that include the given host within a time range."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM deployments
               WHERE started_at >= ? AND started_at <= ?
               ORDER BY started_at DESC LIMIT 50""",
            (start, end),
        )
        results = []
        for row in await cursor.fetchall():
            dep = dict(row)
            try:
                ids = json.loads(dep.get("host_ids") or "[]")
                if host_id in ids:
                    results.append(dep)
            except (json.JSONDecodeError, TypeError) as exc:
                _LOGGER.debug("skipping deployment %s: bad host_ids JSON: %s", dep.get("id"), exc)
        return results
    finally:
        await db.close()


async def get_audit_events_for_deployment(
    deployment_id: int,
    start: str,
    end: str,
) -> list[dict]:
    """Return audit events related to a deployment within a time range."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM audit_events
               WHERE timestamp >= ? AND timestamp <= ?
                 AND detail LIKE ?
               ORDER BY timestamp DESC LIMIT 200""",
            (start, end, f"%id={deployment_id}%"),
        )
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Availability Tracking
# ═════════════════════════════════════════════════════════════════════════════


async def record_availability_transition(
    host_id: int,
    entity_type: str,
    entity_id: str,
    old_state: str,
    new_state: str,
    poll_id: int | None = None,
) -> int:
    """Record a state transition (up/down) for a host or interface."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO availability_transitions
               (host_id, entity_type, entity_id, old_state, new_state, poll_id)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (host_id, entity_type, entity_id, old_state, new_state, poll_id),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_last_availability_state(
    host_id: int, entity_type: str = "host", entity_id: str = "",
) -> dict | None:
    """Get the most recent availability transition for an entity."""
    states = await get_last_availability_states(host_id, entity_type)
    if entity_id not in states:
        return None
    return {"entity_id": entity_id, "new_state": states[entity_id]}


async def get_last_availability_states(
    host_id: int, entity_type: str,
) -> dict[str, str]:
    """Return the latest new_state keyed by entity_id for one host + type."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT a.entity_id, a.new_state
               FROM availability_transitions a
               INNER JOIN (
                   SELECT entity_id, MAX(id) AS max_id
                   FROM availability_transitions
                   WHERE host_id = ? AND entity_type = ?
                   GROUP BY entity_id
               ) latest ON a.id = latest.max_id
               WHERE a.host_id = ? AND a.entity_type = ?""",
            (host_id, entity_type, host_id, entity_type),
        )
        return {
            row["entity_id"]: row["new_state"]
            for row in rows_to_list(await cursor.fetchall())
        }
    finally:
        await db.close()


async def record_availability_transitions_batch(
    transitions: list[tuple],
) -> int:
    """Insert multiple availability transitions in one transaction."""
    if not transitions:
        return 0
    db = await _dbcore.get_db()
    try:
        await db.executemany(
            """INSERT INTO availability_transitions
               (host_id, entity_type, entity_id, old_state, new_state, poll_id)
               VALUES (?, ?, ?, ?, ?, ?)""",
            transitions,
        )
        await db.commit()
        return len(transitions)
    finally:
        await db.close()


async def get_availability_transitions(
    host_id: int | None = None,
    entity_type: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 500,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses = ["1=1"]
        params: list = []
        if host_id is not None:
            clauses.append("a.host_id = ?")
            params.append(host_id)
        if entity_type:
            clauses.append("a.entity_type = ?")
            params.append(entity_type)
        if start:
            clauses.append("a.transition_at >= ?")
            params.append(start)
        if end:
            clauses.append("a.transition_at <= ?")
            params.append(end)
        where = " AND ".join(clauses)
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT a.*, h.hostname, h.ip_address
                FROM availability_transitions a
                JOIN hosts h ON h.id = a.host_id
                WHERE {where}
                ORDER BY a.transition_at DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_availability_summary(
    group_id: int | None = None,
    days: int = 30,
) -> dict:
    """Compute availability summary with outage counts and uptime % from transitions."""
    db = await _dbcore.get_db()
    try:
        group_filter = ""
        params: list = [days]
        if group_id is not None:
            group_filter = "AND h.group_id = ?"
            params.append(group_id)

        # Get all hosts and their transitions in the window
        cursor = await db.execute(
            f"""SELECT h.id AS host_id, h.hostname, h.ip_address, h.status,
                       h.group_id,
                       (SELECT COUNT(*) FROM availability_transitions t
                        WHERE t.host_id = h.id AND t.entity_type = 'host'
                          AND t.new_state = 'down'
                          AND t.transition_at >= datetime('now', '-' || ? || ' days')
                       ) AS outage_count
                FROM hosts h
                WHERE 1=1 {group_filter}
                ORDER BY h.hostname""",
            tuple(params),
        )
        hosts_raw = rows_to_list(await cursor.fetchall())

        hosts = []
        for h in hosts_raw:
            # Compute uptime from transitions
            tcursor = await db.execute(
                """SELECT transition_at, new_state FROM availability_transitions
                   WHERE host_id = ? AND entity_type = 'host'
                     AND transition_at >= datetime('now', '-' || ? || ' days')
                   ORDER BY transition_at ASC""",
                (h["host_id"], days),
            )
            transitions = rows_to_list(await tcursor.fetchall())

            # Also get the state before the window started
            pcursor = await db.execute(
                """SELECT new_state FROM availability_transitions
                   WHERE host_id = ? AND entity_type = 'host'
                     AND transition_at < datetime('now', '-' || ? || ' days')
                   ORDER BY transition_at DESC LIMIT 1""",
                (h["host_id"], days),
            )
            prev = await pcursor.fetchone()
            initial_state = dict(prev)["new_state"] if prev else "up"

            # Calculate downtime seconds in window
            total_seconds = days * 86400
            down_seconds = 0
            current_state = initial_state
            window_start = None  # We'll approximate with relative positions

            if transitions:
                # Walk through transitions accumulating down time
                last_ts = None
                for t in transitions:
                    ts = t["transition_at"]
                    if current_state == "down" and last_ts is not None:
                        # Approximate duration between transitions
                        try:
                            from datetime import datetime as dt
                            fmt = "%Y-%m-%d %H:%M:%S"
                            t1 = dt.strptime(last_ts[:19], fmt)
                            t2 = dt.strptime(ts[:19], fmt)
                            down_seconds += (t2 - t1).total_seconds()
                        except Exception as exc:
                            _LOGGER.warning("uptime: failed to parse transition timestamps '%s' / '%s': %s", last_ts, ts, exc)
                    current_state = t["new_state"]
                    last_ts = ts

                # If still down at end of window, add remaining time
                if current_state == "down" and last_ts:
                    try:
                        from datetime import datetime as dt
                        fmt = "%Y-%m-%d %H:%M:%S"
                        t1 = dt.strptime(last_ts[:19], fmt)
                        now = dt.utcnow()
                        down_seconds += (now - t1).total_seconds()
                    except Exception as exc:
                        _LOGGER.warning("uptime: failed to parse transition timestamp '%s': %s", last_ts, exc)
            elif initial_state == "down":
                down_seconds = total_seconds

            uptime_pct = round(max(0, (1 - down_seconds / max(total_seconds, 1))) * 100, 3)

            # Get last outage duration
            last_outage = None
            ocursor = await db.execute(
                """SELECT t1.transition_at AS down_at,
                          (SELECT MIN(t2.transition_at) FROM availability_transitions t2
                           WHERE t2.host_id = t1.host_id AND t2.entity_type = 'host'
                             AND t2.new_state = 'up' AND t2.transition_at > t1.transition_at
                          ) AS up_at
                   FROM availability_transitions t1
                   WHERE t1.host_id = ? AND t1.entity_type = 'host' AND t1.new_state = 'down'
                   ORDER BY t1.transition_at DESC LIMIT 1""",
                (h["host_id"],),
            )
            orow = await ocursor.fetchone()
            if orow:
                odict = dict(orow)
                last_outage = {
                    "down_at": odict.get("down_at"),
                    "up_at": odict.get("up_at"),
                }

            hosts.append({
                "host_id": h["host_id"],
                "hostname": h["hostname"],
                "ip_address": h["ip_address"],
                "group_id": h["group_id"],
                "current_state": h["status"],
                "uptime_pct": uptime_pct,
                "outage_count": h["outage_count"] or 0,
                "down_seconds": round(down_seconds),
                "last_outage": last_outage,
            })

        total_hosts = len(hosts) or 1
        avg_uptime = round(sum(h["uptime_pct"] for h in hosts) / total_hosts, 3)
        total_outages = sum(h["outage_count"] for h in hosts)
        currently_down = sum(1 for h in hosts if h["current_state"] in ("down", "error", "unreachable"))

        return {
            "period_days": days,
            "host_count": len(hosts),
            "avg_uptime_pct": avg_uptime,
            "total_outages": total_outages,
            "currently_down": currently_down,
            "hosts": hosts,
        }
    finally:
        await db.close()


async def get_outage_history(
    host_id: int | None = None,
    group_id: int | None = None,
    days: int = 30,
    limit: int = 200,
) -> list[dict]:
    """Get outage records (down transitions paired with recovery)."""
    db = await _dbcore.get_db()
    try:
        group_filter = ""
        params: list = [days]
        if host_id is not None:
            group_filter += " AND t1.host_id = ?"
            params.append(host_id)
        if group_id is not None:
            group_filter += " AND h.group_id = ?"
            params.append(group_id)
        params.append(limit)

        cursor = await db.execute(
            f"""SELECT t1.id, t1.host_id, h.hostname, h.ip_address,
                       t1.entity_type, t1.entity_id,
                       t1.transition_at AS down_at,
                       (SELECT MIN(t2.transition_at) FROM availability_transitions t2
                        WHERE t2.host_id = t1.host_id AND t2.entity_type = t1.entity_type
                          AND t2.entity_id = t1.entity_id
                          AND t2.new_state = 'up' AND t2.transition_at > t1.transition_at
                       ) AS up_at
                FROM availability_transitions t1
                JOIN hosts h ON h.id = t1.host_id
                WHERE t1.new_state = 'down'
                  AND t1.transition_at >= datetime('now', '-' || ? || ' days')
                  {group_filter}
                ORDER BY t1.transition_at DESC LIMIT ?""",
            tuple(params),
        )
        rows = rows_to_list(await cursor.fetchall())
        for r in rows:
            if r.get("down_at") and r.get("up_at"):
                try:
                    from datetime import datetime as dt
                    fmt = "%Y-%m-%d %H:%M:%S"
                    d = dt.strptime(r["down_at"][:19], fmt)
                    u = dt.strptime(r["up_at"][:19], fmt)
                    r["duration_seconds"] = int((u - d).total_seconds())
                except Exception:
                    r["duration_seconds"] = None
            else:
                r["duration_seconds"] = None
                if r.get("down_at") and not r.get("up_at"):
                    r["ongoing"] = True
        return rows
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Per-Port Utilization (95th Percentile)
# ═════════════════════════════════════════════════════════════════════════════


async def get_interface_utilization_summary(
    host_id: int,
    days: int = 1,
) -> list[dict]:
    """Per-interface utilization summary with avg, peak, and 95th percentile."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT if_index, if_name, if_speed_mbps,
                      COUNT(*) AS sample_count,
                      AVG(in_rate_bps) AS avg_in_bps,
                      AVG(out_rate_bps) AS avg_out_bps,
                      MAX(in_rate_bps) AS peak_in_bps,
                      MAX(out_rate_bps) AS peak_out_bps,
                      AVG(utilization_pct) AS avg_util,
                      MAX(utilization_pct) AS peak_util
               FROM interface_ts
               WHERE host_id = ?
                 AND sampled_at >= datetime('now', '-' || ? || ' days')
                 AND in_rate_bps IS NOT NULL
               GROUP BY if_index
               ORDER BY if_name""",
            (host_id, days),
        )
        interfaces = rows_to_list(await cursor.fetchall())

        # Compute 95th percentile per interface
        for iface in interfaces:
            pcursor = await db.execute(
                """SELECT utilization_pct FROM interface_ts
                   WHERE host_id = ? AND if_index = ?
                     AND sampled_at >= datetime('now', '-' || ? || ' days')
                     AND utilization_pct IS NOT NULL
                   ORDER BY utilization_pct ASC""",
                (host_id, iface["if_index"], days),
            )
            values = [r[0] for r in await pcursor.fetchall() if r[0] is not None]
            if values:
                idx = int(len(values) * 0.95)
                idx = min(idx, len(values) - 1)
                iface["p95_util"] = round(values[idx], 2)

                # Also 95th for in/out bps
                for direction in ("in", "out"):
                    bcursor = await db.execute(
                        f"""SELECT {direction}_rate_bps FROM interface_ts
                            WHERE host_id = ? AND if_index = ?
                              AND sampled_at >= datetime('now', '-' || ? || ' days')
                              AND {direction}_rate_bps IS NOT NULL
                            ORDER BY {direction}_rate_bps ASC""",
                        (host_id, iface["if_index"], days),
                    )
                    bvals = [r[0] for r in await bcursor.fetchall() if r[0] is not None]
                    if bvals:
                        bidx = int(len(bvals) * 0.95)
                        bidx = min(bidx, len(bvals) - 1)
                        iface[f"p95_{direction}_bps"] = round(bvals[bidx], 2)
                    else:
                        iface[f"p95_{direction}_bps"] = None
            else:
                iface["p95_util"] = None
                iface["p95_in_bps"] = None
                iface["p95_out_bps"] = None

            # Round numeric fields
            for k in ("avg_in_bps", "avg_out_bps", "peak_in_bps", "peak_out_bps", "avg_util", "peak_util"):
                if iface.get(k) is not None:
                    iface[k] = round(iface[k], 2)

        return interfaces
    finally:
        await db.close()


async def get_port_detail_ts(
    host_id: int,
    if_index: int,
    start: str | None = None,
    end: str | None = None,
    limit: int = 5000,
) -> dict:
    """Detailed time-series for a single port with summary stats."""
    db = await _dbcore.get_db()
    try:
        clauses = ["host_id = ?", "if_index = ?"]
        params: list = [host_id, if_index]
        if start:
            clauses.append("sampled_at >= ?")
            params.append(start)
        if end:
            clauses.append("sampled_at <= ?")
            params.append(end)
        where = " AND ".join(clauses)
        params.append(limit)
        cursor = await db.execute(
            f"SELECT * FROM interface_ts WHERE {where} ORDER BY sampled_at ASC LIMIT ?",
            tuple(params),
        )
        samples = rows_to_list(await cursor.fetchall())

        # Compute summary
        in_rates = [s["in_rate_bps"] for s in samples if s.get("in_rate_bps") is not None]
        out_rates = [s["out_rate_bps"] for s in samples if s.get("out_rate_bps") is not None]
        utils = [s["utilization_pct"] for s in samples if s.get("utilization_pct") is not None]

        def percentile(vals, pct):
            if not vals:
                return None
            sorted_v = sorted(vals)
            idx = min(int(len(sorted_v) * pct / 100), len(sorted_v) - 1)
            return round(sorted_v[idx], 2)

        summary = {
            "sample_count": len(samples),
            "avg_in_bps": round(sum(in_rates) / len(in_rates), 2) if in_rates else None,
            "avg_out_bps": round(sum(out_rates) / len(out_rates), 2) if out_rates else None,
            "peak_in_bps": round(max(in_rates), 2) if in_rates else None,
            "peak_out_bps": round(max(out_rates), 2) if out_rates else None,
            "p95_in_bps": percentile(in_rates, 95),
            "p95_out_bps": percentile(out_rates, 95),
            "avg_util": round(sum(utils) / len(utils), 2) if utils else None,
            "peak_util": round(max(utils), 2) if utils else None,
            "p95_util": percentile(utils, 95),
        }
        if samples:
            summary["if_name"] = samples[0].get("if_name", "")
            summary["if_speed_mbps"] = samples[0].get("if_speed_mbps", 0)

        return {"summary": summary, "samples": samples}
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Custom OID Profiles
# ═════════════════════════════════════════════════════════════════════════════


async def get_custom_oid_profiles(
    vendor: str | None = None,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        if vendor:
            cursor = await db.execute(
                "SELECT * FROM custom_oid_profiles WHERE vendor = ? ORDER BY name",
                (vendor,),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM custom_oid_profiles ORDER BY vendor, name"
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_custom_oid_profile(profile_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM custom_oid_profiles WHERE id = ?", (profile_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def create_custom_oid_profile(
    name: str, vendor: str = "", device_type: str = "",
    description: str = "", oids_json: str = "[]",
    is_default: int = 0, created_by: str = "",
) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO custom_oid_profiles
               (name, vendor, device_type, description, oids_json, is_default, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (name, vendor, device_type, description, oids_json, is_default, created_by),
        )
        await db.commit()
        return await get_custom_oid_profile(cursor.lastrowid) or {}
    finally:
        await db.close()


async def update_custom_oid_profile(profile_id: int, **kwargs) -> dict | None:
    db = await _dbcore.get_db()
    try:
        existing = await get_custom_oid_profile(profile_id)
        if not existing:
            return None
        fields = []
        params: list = []
        for key in ("name", "vendor", "device_type", "description", "oids_json", "is_default"):
            if key in kwargs and kwargs[key] is not None:
                fields.append(f"{key} = ?")
                params.append(kwargs[key])
        if not fields:
            return existing
        fields.append("updated_at = datetime('now')")
        sql, sql_params = _safe_dynamic_update("custom_oid_profiles", fields, params, "id = ?", profile_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_custom_oid_profile(profile_id)
    finally:
        await db.close()


async def delete_custom_oid_profile(profile_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM custom_oid_profiles WHERE id = ?", (profile_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


