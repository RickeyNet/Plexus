"""Monitoring persistence helpers.

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
    "set_alert_created_hook",
    "create_monitoring_poll",
    "get_latest_monitoring_polls",
    "get_monitoring_poll_history",
    "delete_old_monitoring_polls",
    "get_monitoring_summary",
    "create_monitoring_alert",
    "get_monitoring_alerts",
    "get_monitoring_alert",
    "acknowledge_monitoring_alert",
    "delete_old_monitoring_alerts",
    "create_route_snapshot",
    "get_route_snapshots",
    "get_latest_route_snapshot",
    "delete_old_route_snapshots",
    "create_alert_rule",
    "get_alert_rules",
    "get_alert_rule",
    "update_alert_rule",
    "delete_alert_rule",
    "create_alert_suppression",
    "get_alert_suppressions",
    "is_alert_suppressed",
    "delete_alert_suppression",
    "delete_expired_suppressions",
    "get_alerts_for_escalation",
    "escalate_alert",
    "bulk_acknowledge_alerts",
    "get_sla_targets",
    "get_sla_target",
    "create_sla_target",
    "update_sla_target",
    "delete_sla_target",
    "get_sla_summary",
    "get_sla_host_detail",
    "delete_old_sla_metrics",
]

# The notification-channel engine registers itself here via
# ``set_alert_created_hook`` at app startup. It is fired by
# ``create_monitoring_alert`` ONLY when a brand-new alert row is inserted (not
# when an existing alert is deduplicated), so a flapping condition does not
# generate a notification storm. Fire-and-forget: exceptions never propagate.
_alert_created_hook = None  # type: ignore[var-annotated]


def set_alert_created_hook(hook) -> None:
    """Register a coroutine fn(alert: dict) -> None called after a NEW
    monitoring alert is created. Pass ``None`` to clear."""
    global _alert_created_hook
    _alert_created_hook = hook


# ═════════════════════════════════════════════════════════════════════════════
# Monitoring Polls
# ═════════════════════════════════════════════════════════════════════════════


async def create_monitoring_poll(
    host_id: int,
    cpu_percent: float | None = None,
    memory_percent: float | None = None,
    memory_used_mb: float | None = None,
    memory_total_mb: float | None = None,
    uptime_seconds: int | None = None,
    if_up_count: int = 0,
    if_down_count: int = 0,
    if_admin_down: int = 0,
    if_details: str = "[]",
    vpn_tunnels_up: int = 0,
    vpn_tunnels_down: int = 0,
    vpn_details: str = "[]",
    route_count: int = 0,
    route_snapshot: str = "",
    poll_status: str = "ok",
    poll_error: str = "",
    response_time_ms: float | None = None,
    packet_loss_pct: float | None = None,
    icmp_alive: bool | None = None,
    icmp_rtt_ms: float | None = None,
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO monitoring_polls
               (host_id, cpu_percent, memory_percent, memory_used_mb, memory_total_mb,
                uptime_seconds, if_up_count, if_down_count, if_admin_down, if_details,
                vpn_tunnels_up, vpn_tunnels_down, vpn_details,
                route_count, route_snapshot, poll_status, poll_error,
                response_time_ms, packet_loss_pct, icmp_alive, icmp_rtt_ms, polled_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (host_id, cpu_percent, memory_percent, memory_used_mb, memory_total_mb,
             uptime_seconds, if_up_count, if_down_count, if_admin_down, if_details,
             vpn_tunnels_up, vpn_tunnels_down, vpn_details,
             route_count, route_snapshot, poll_status, poll_error,
             response_time_ms, packet_loss_pct,
             None if icmp_alive is None else int(bool(icmp_alive)),
             icmp_rtt_ms),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_latest_monitoring_polls(
    group_id: int | None = None, limit: int = 200,
    include_details: bool = False,
) -> list[dict]:
    """Return the most recent poll per host, with host info joined."""
    detail_cols = ", p.if_details, p.vpn_details, p.route_snapshot" if include_details else ""
    db = await _dbcore.get_db()
    try:
        group_filter = ""
        params: list = []
        if group_id is not None:
            group_filter = "AND h.group_id = ?"
            params.append(group_id)
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT p.id, p.host_id, p.cpu_percent, p.memory_percent,
                       p.memory_used_mb, p.memory_total_mb, p.uptime_seconds,
                       p.if_up_count, p.if_down_count, p.if_admin_down,
                       p.vpn_tunnels_up, p.vpn_tunnels_down, p.route_count,
                       p.poll_status, p.poll_error, p.response_time_ms,
                       p.packet_loss_pct, p.icmp_alive, p.icmp_rtt_ms, p.polled_at
                       {detail_cols},
                       h.hostname, h.ip_address, h.device_type, h.group_id,
                       h.model, h.software_version, h.status AS host_status,
                       h.last_seen, g.name AS group_name
                FROM monitoring_polls p
                INNER JOIN (
                    SELECT host_id, MAX(id) AS max_id
                    FROM monitoring_polls
                    GROUP BY host_id
                ) latest ON p.id = latest.max_id
                JOIN hosts h ON h.id = p.host_id
                LEFT JOIN inventory_groups g ON g.id = h.group_id
                WHERE 1=1 {group_filter}
                ORDER BY h.hostname
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_monitoring_poll_history(
    host_id: int, limit: int = 100,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT p.*, h.hostname, h.ip_address
               FROM monitoring_polls p
               JOIN hosts h ON h.id = p.host_id
               WHERE p.host_id = ?
               ORDER BY p.polled_at DESC
               LIMIT ?""",
            (host_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_old_monitoring_polls(retention_days: int) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM monitoring_polls WHERE polled_at < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def get_monitoring_summary(group_id: int | None = None) -> dict:
    db = await _dbcore.get_db()
    try:
        group_filter = ""
        params: list = []
        if group_id is not None:
            group_filter = "AND h.group_id = ?"
            params.append(group_id)

        cursor = await db.execute(
            f"""SELECT COUNT(DISTINCT p.host_id) FROM monitoring_polls p
                JOIN hosts h ON h.id = p.host_id WHERE 1=1 {group_filter}""",
            tuple(params),
        )
        monitored_hosts = (await cursor.fetchone())[0]

        cursor = await db.execute(
            f"""SELECT p.id, p.host_id, p.cpu_percent, p.memory_percent,
                       p.memory_used_mb, p.memory_total_mb, p.uptime_seconds,
                       p.if_up_count, p.if_down_count, p.if_admin_down,
                       p.vpn_tunnels_up, p.vpn_tunnels_down, p.route_count,
                       p.poll_status, p.poll_error, p.response_time_ms,
                       p.packet_loss_pct, p.icmp_alive, p.icmp_rtt_ms, p.polled_at
                FROM monitoring_polls p
                INNER JOIN (
                    SELECT host_id, MAX(id) AS max_id
                    FROM monitoring_polls
                    GROUP BY host_id
                ) latest ON p.id = latest.max_id
                JOIN hosts h ON h.id = p.host_id
                WHERE 1=1 {group_filter}""",
            tuple(params),
        )
        latest_polls = rows_to_list(await cursor.fetchall())

        total_cpu = 0.0
        cpu_count = 0
        total_mem = 0.0
        mem_count = 0
        total_if_up = 0
        total_if_down = 0
        total_vpn_up = 0
        total_vpn_down = 0
        total_routes = 0
        error_hosts = 0
        high_cpu_hosts = 0
        high_mem_hosts = 0

        for p in latest_polls:
            if p.get("cpu_percent") is not None:
                total_cpu += p["cpu_percent"]
                cpu_count += 1
                if p["cpu_percent"] >= 80:
                    high_cpu_hosts += 1
            if p.get("memory_percent") is not None:
                total_mem += p["memory_percent"]
                mem_count += 1
                if p["memory_percent"] >= 80:
                    high_mem_hosts += 1
            total_if_up += p.get("if_up_count", 0)
            total_if_down += p.get("if_down_count", 0)
            total_vpn_up += p.get("vpn_tunnels_up", 0)
            total_vpn_down += p.get("vpn_tunnels_down", 0)
            total_routes += p.get("route_count", 0)
            if p.get("poll_status") == "error":
                error_hosts += 1

        a_params = list(params)
        cursor = await db.execute(
            f"""SELECT COUNT(*) FROM monitoring_alerts a
                JOIN hosts h ON h.id = a.host_id
                WHERE a.acknowledged = 0 {group_filter}""",
            tuple(a_params),
        )
        open_alerts = (await cursor.fetchone())[0]

        cursor = await db.execute(
            f"""SELECT MAX(p.polled_at) FROM monitoring_polls p
                JOIN hosts h ON h.id = p.host_id WHERE 1=1 {group_filter}""",
            tuple(params),
        )
        row = await cursor.fetchone()
        last_poll_at = row[0] if row else None

        return {
            "monitored_hosts": monitored_hosts,
            "avg_cpu": round(total_cpu / cpu_count, 1) if cpu_count else None,
            "avg_memory": round(total_mem / mem_count, 1) if mem_count else None,
            "high_cpu_hosts": high_cpu_hosts,
            "high_mem_hosts": high_mem_hosts,
            "interfaces_up": total_if_up,
            "interfaces_down": total_if_down,
            "vpn_tunnels_up": total_vpn_up,
            "vpn_tunnels_down": total_vpn_down,
            "total_routes": total_routes,
            "error_hosts": error_hosts,
            "open_alerts": open_alerts,
            "last_poll_at": last_poll_at,
        }
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Monitoring Alerts
# ═════════════════════════════════════════════════════════════════════════════


async def create_monitoring_alert(
    host_id: int,
    poll_id: int | None,
    alert_type: str,
    metric: str,
    message: str,
    severity: str = "warning",
    value: float | None = None,
    threshold: float | None = None,
    rule_id: int | None = None,
    dedup_key: str = "",
    channel_ids: str = "",
    hostname: str = "",
) -> int:
    """Create or deduplicate a monitoring alert.

    If dedup_key is provided and an unacknowledged alert with the same key exists,
    bump its occurrence_count and update last_seen_at instead of creating a new one.
    Returns the alert ID (existing or new).

    ``channel_ids`` (the owning rule's notification-channel assignment, if any)
    and ``hostname`` are not persisted on the alert row; they are forwarded to
    the alert-created hook so the notification engine can route the alert. The
    hook fires ONLY on a genuinely new insert, never on a dedup bump.
    """
    db = await _dbcore.get_db()
    try:
        # Dedup check
        if dedup_key:
            cursor = await db.execute(
                """SELECT id, occurrence_count FROM monitoring_alerts
                   WHERE dedup_key = ? AND acknowledged = 0
                   ORDER BY id DESC LIMIT 1""",
                (dedup_key,),
            )
            existing = await cursor.fetchone()
            if existing:
                eid = existing[0] if isinstance(existing, (list, tuple)) else existing["id"]
                cnt = (existing[1] if isinstance(existing, (list, tuple)) else existing["occurrence_count"]) + 1
                await db.execute(
                    """UPDATE monitoring_alerts
                       SET occurrence_count = ?, last_seen_at = datetime('now'),
                           value = ?, poll_id = ?, message = ?
                       WHERE id = ?""",
                    (cnt, value, poll_id, message, eid),
                )
                await db.commit()
                return eid

        if not dedup_key:
            dedup_key = f"{host_id}:{metric}:{alert_type}"

        cursor = await db.execute(
            """INSERT INTO monitoring_alerts
               (host_id, poll_id, rule_id, alert_type, metric, message,
                severity, original_severity, value, threshold,
                dedup_key, occurrence_count, last_seen_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'))""",
            (host_id, poll_id, rule_id, alert_type, metric, message,
             severity, severity, value, threshold, dedup_key),
        )
        await db.commit()
        new_id = cursor.lastrowid
    finally:
        await db.close()

    # Fan the new alert out to notification channels (best-effort). Done after
    # the row is committed and the connection closed so a slow/wedged channel
    # cannot hold a DB handle. Only fires for genuinely new alerts.
    if _alert_created_hook is not None:
        alert_event = {
            "alert_id": new_id,
            "host_id": host_id,
            "hostname": hostname,
            "poll_id": poll_id,
            "rule_id": rule_id,
            "alert_type": alert_type,
            "metric": metric,
            "message": message,
            "severity": severity,
            "value": value,
            "threshold": threshold,
            "dedup_key": dedup_key,
            "channel_ids": channel_ids,
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        try:
            await _alert_created_hook(alert_event)
        except Exception as exc:
            # Notification delivery must never break alert ingestion.
            _LOGGER.warning(
                "Notification delivery failed for alert %s (rule %s, host %s): %s",
                new_id, rule_id, host_id, exc,
            )
    return new_id


async def get_monitoring_alerts(
    host_id: int | None = None,
    acknowledged: bool | None = None,
    severity: str | None = None,
    limit: int = 200,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses = []
        params: list = []
        if host_id is not None:
            clauses.append("a.host_id = ?")
            params.append(host_id)
        if acknowledged is not None:
            clauses.append("a.acknowledged = ?")
            params.append(1 if acknowledged else 0)
        if severity:
            clauses.append("a.severity = ?")
            params.append(severity)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT a.*, h.hostname, h.ip_address, h.device_type
                FROM monitoring_alerts a
                JOIN hosts h ON h.id = a.host_id
                {where}
                ORDER BY a.created_at DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_monitoring_alert(alert_id: int) -> dict | None:
    """Return a single monitoring alert by ID."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT a.*, h.hostname, h.ip_address
               FROM monitoring_alerts a
               LEFT JOIN hosts h ON h.id = a.host_id
               WHERE a.id = ?""",
            (alert_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def acknowledge_monitoring_alert(
    alert_id: int, acknowledged_by: str,
) -> None:
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """UPDATE monitoring_alerts
               SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = datetime('now')
               WHERE id = ?""",
            (acknowledged_by, alert_id),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_old_monitoring_alerts(retention_days: int) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM monitoring_alerts WHERE created_at < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Route Snapshots (churn detection)
# ═════════════════════════════════════════════════════════════════════════════


async def create_route_snapshot(
    host_id: int, route_count: int, routes_text: str, routes_hash: str,
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO route_snapshots
               (host_id, route_count, routes_text, routes_hash, captured_at)
               VALUES (?, ?, ?, ?, datetime('now'))""",
            (host_id, route_count, routes_text, routes_hash),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_route_snapshots(
    host_id: int, limit: int = 50,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT r.*, h.hostname, h.ip_address
               FROM route_snapshots r
               JOIN hosts h ON h.id = r.host_id
               WHERE r.host_id = ?
               ORDER BY r.captured_at DESC LIMIT ?""",
            (host_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_latest_route_snapshot(host_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM route_snapshots WHERE host_id = ? ORDER BY id DESC LIMIT 1",
            (host_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def delete_old_route_snapshots(retention_days: int) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM route_snapshots WHERE captured_at < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Alert Rules
# ═════════════════════════════════════════════════════════════════════════════


async def create_alert_rule(
    name: str,
    metric: str,
    rule_type: str = "threshold",
    operator: str = ">=",
    value: float = 0,
    severity: str = "warning",
    consecutive: int = 1,
    cooldown_minutes: int = 15,
    escalate_after_minutes: int = 0,
    escalate_to: str = "critical",
    host_id: int | None = None,
    group_id: int | None = None,
    description: str = "",
    created_by: str = "",
    channel_ids: str = "",
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO alert_rules
               (name, description, metric, rule_type, operator, value, severity,
                consecutive, cooldown_minutes, escalate_after_minutes, escalate_to,
                host_id, group_id, channel_ids, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
            (name, description, metric, rule_type, operator, value, severity,
             consecutive, cooldown_minutes, escalate_after_minutes, escalate_to,
             host_id, group_id, channel_ids, created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_alert_rules(enabled_only: bool = False) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        where = "WHERE r.enabled = 1" if enabled_only else ""
        cursor = await db.execute(
            f"""SELECT r.*, h.hostname, h.ip_address, g.name as group_name
                FROM alert_rules r
                LEFT JOIN hosts h ON h.id = r.host_id
                LEFT JOIN inventory_groups g ON g.id = r.group_id
                {where}
                ORDER BY r.created_at DESC""",
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_alert_rule(rule_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT r.*, h.hostname, h.ip_address, g.name as group_name
               FROM alert_rules r
               LEFT JOIN hosts h ON h.id = r.host_id
               LEFT JOIN inventory_groups g ON g.id = r.group_id
               WHERE r.id = ?""",
            (rule_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_alert_rule(rule_id: int, **kwargs) -> None:
    allowed = {"name", "description", "metric", "rule_type", "operator", "value",
               "severity", "enabled", "consecutive", "cooldown_minutes",
               "escalate_after_minutes", "escalate_to", "host_id", "group_id",
               "channel_ids"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return
    sets = []
    params: list = []
    for k, v in updates.items():
        sets.append(f"{k} = ?")
        params.append(v)
    sets.append("updated_at = datetime('now')")
    sql, sql_params = _safe_dynamic_update("alert_rules", sets, params, "id = ?", rule_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
    finally:
        await db.close()


async def delete_alert_rule(rule_id: int) -> None:
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
        await db.commit()
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Alert Suppressions
# ═════════════════════════════════════════════════════════════════════════════


async def create_alert_suppression(
    name: str,
    ends_at: str,
    host_id: int | None = None,
    group_id: int | None = None,
    metric: str = "",
    reason: str = "",
    starts_at: str = "",
    created_by: str = "",
) -> int:
    db = await _dbcore.get_db()
    try:
        starts = starts_at if starts_at else "datetime('now')"
        if starts_at:
            cursor = await db.execute(
                """INSERT INTO alert_suppressions
                   (name, host_id, group_id, metric, reason, starts_at, ends_at, created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
                (name, host_id, group_id, metric, reason, starts_at, ends_at, created_by),
            )
        else:
            cursor = await db.execute(
                """INSERT INTO alert_suppressions
                   (name, host_id, group_id, metric, reason, starts_at, ends_at, created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, datetime('now'), ?, ?, datetime('now'))""",
                (name, host_id, group_id, metric, reason, ends_at, created_by),
            )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_alert_suppressions(active_only: bool = False) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        where = "WHERE s.ends_at > datetime('now')" if active_only else ""
        cursor = await db.execute(
            f"""SELECT s.*, h.hostname, h.ip_address, g.name as group_name
                FROM alert_suppressions s
                LEFT JOIN hosts h ON h.id = s.host_id
                LEFT JOIN inventory_groups g ON g.id = s.group_id
                {where}
                ORDER BY s.ends_at DESC""",
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def is_alert_suppressed(
    host_id: int, metric: str, group_id: int | None = None,
) -> bool:
    """Check if alerts for this host+metric are currently suppressed."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT COUNT(*) FROM alert_suppressions
               WHERE starts_at <= datetime('now')
                 AND ends_at > datetime('now')
                 AND (
                     (host_id IS NULL AND group_id IS NULL AND metric = '')
                     OR (host_id = ? AND (metric = '' OR metric = ?))
                     OR (group_id = ? AND (metric = '' OR metric = ?))
                     OR (host_id IS NULL AND group_id IS NULL AND metric = ?)
                 )""",
            (host_id, metric, group_id or 0, metric, metric),
        )
        count = (await cursor.fetchone())[0]
        return count > 0
    finally:
        await db.close()


async def delete_alert_suppression(suppression_id: int) -> None:
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM alert_suppressions WHERE id = ?", (suppression_id,))
        await db.commit()
    finally:
        await db.close()


async def delete_expired_suppressions() -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM alert_suppressions WHERE ends_at < datetime('now', '-7 days')",
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Alert Escalation Queries
# ═════════════════════════════════════════════════════════════════════════════


async def get_alerts_for_escalation(escalate_after_minutes: int) -> list[dict]:
    """Return unacknowledged, non-escalated alerts older than the escalation threshold."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT a.*, h.hostname, h.ip_address
               FROM monitoring_alerts a
               JOIN hosts h ON h.id = a.host_id
               WHERE a.acknowledged = 0
                 AND a.escalated = 0
                 AND a.severity != 'critical'
                 AND a.created_at < datetime('now', '-' || ? || ' minutes')
               ORDER BY a.created_at ASC""",
            (str(int(escalate_after_minutes)),),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def escalate_alert(alert_id: int, new_severity: str) -> None:
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """UPDATE monitoring_alerts
               SET severity = ?, escalated = 1,
                   escalation_count = escalation_count + 1,
                   escalated_at = datetime('now')
               WHERE id = ?""",
            (new_severity, alert_id),
        )
        await db.commit()
    finally:
        await db.close()


async def bulk_acknowledge_alerts(alert_ids: list[int], acknowledged_by: str) -> int:
    """Acknowledge multiple alerts at once. Returns count updated."""
    if not alert_ids:
        return 0
    db = await _dbcore.get_db()
    try:
        placeholders = ",".join("?" for _ in alert_ids)
        cursor = await db.execute(
            f"""UPDATE monitoring_alerts
                SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = datetime('now')
                WHERE id IN ({placeholders}) AND acknowledged = 0""",
            (acknowledged_by, *alert_ids),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ── SLA Targets ──────────────────────────────────────────────────────────────


async def get_sla_targets(
    host_id: int | None = None,
    group_id: int | None = None,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        where = ["1=1"]
        params: list = []
        if host_id is not None:
            where.append("t.host_id = ?")
            params.append(host_id)
        if group_id is not None:
            where.append("t.group_id = ?")
            params.append(group_id)
        cursor = await db.execute(
            f"""SELECT t.*,
                       h.hostname AS host_name,
                       g.name AS group_name
                FROM sla_targets t
                LEFT JOIN hosts h ON h.id = t.host_id
                LEFT JOIN inventory_groups g ON g.id = t.group_id
                WHERE {' AND '.join(where)}
                ORDER BY t.name""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_sla_target(target_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT t.*, h.hostname AS host_name, g.name AS group_name
               FROM sla_targets t
               LEFT JOIN hosts h ON h.id = t.host_id
               LEFT JOIN inventory_groups g ON g.id = t.group_id
               WHERE t.id = ?""",
            (target_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def create_sla_target(
    name: str,
    metric: str,
    target_value: float,
    warning_value: float,
    host_id: int | None = None,
    group_id: int | None = None,
    created_by: str = "",
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO sla_targets
               (name, metric, target_value, warning_value, host_id, group_id, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (name, metric, target_value, warning_value, host_id, group_id, created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_sla_target(target_id: int, **kwargs) -> None:
    allowed = {"name", "metric", "target_value", "warning_value", "enabled", "host_id", "group_id"}
    fields = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not fields:
        return
    fields["updated_at"] = datetime.now(UTC).isoformat()
    sets = [f"{k} = ?" for k in fields]
    sql, sql_params = _safe_dynamic_update("sla_targets", sets, list(fields.values()), "id = ?", target_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
    finally:
        await db.close()


async def delete_sla_target(target_id: int) -> None:
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM sla_targets WHERE id = ?", (target_id,))
        await db.commit()
    finally:
        await db.close()


# ── SLA Summary & Host Detail ────────────────────────────────────────────────


async def get_sla_summary(
    group_id: int | None = None,
    days: int = 30,
) -> dict:
    """Compute SLA summary from monitoring_polls data directly."""
    db = await _dbcore.get_db()
    try:
        group_filter = ""
        params: list = [days]
        if group_id is not None:
            group_filter = "AND h.group_id = ?"
            params.append(group_id)

        # Per-host uptime (% of polls with status='ok'), latency, packet loss
        cursor = await db.execute(
            f"""SELECT h.id AS host_id, h.hostname, h.ip_address, h.group_id,
                       COUNT(*) AS total_polls,
                       SUM(CASE WHEN p.poll_status = 'ok' THEN 1 ELSE 0 END) AS ok_polls,
                       AVG(p.response_time_ms) AS avg_latency,
                       AVG(p.response_time_ms * p.response_time_ms) AS mean_sq_rt,
                       AVG(p.packet_loss_pct) AS avg_packet_loss
                FROM monitoring_polls p
                JOIN hosts h ON h.id = p.host_id
                WHERE p.polled_at >= datetime('now', '-' || ? || ' days')
                {group_filter}
                GROUP BY h.id
                ORDER BY h.hostname""",
            tuple(params),
        )
        rows = rows_to_list(await cursor.fetchall())

        hosts = []
        total_uptime = 0.0
        total_latency = 0.0
        total_packet_loss = 0.0
        latency_count = 0
        pkt_count = 0

        for r in rows:
            total = r["total_polls"] or 1
            ok = r["ok_polls"] or 0
            uptime_pct = round(ok / total * 100, 3)
            lat = round(r["avg_latency"], 2) if r["avg_latency"] is not None else None
            pkt = round(r["avg_packet_loss"], 2) if r["avg_packet_loss"] is not None else None

            # Jitter = stddev of response time, derived from the same grouped
            # aggregate (mean and mean-of-squares) rather than a per-host query.
            mean_rt = r["avg_latency"]
            mean_sq = r["mean_sq_rt"]
            if mean_rt is not None and mean_sq is not None:
                variance = mean_sq - (mean_rt ** 2)
                jitter = round(max(0.0, variance) ** 0.5, 2)
            else:
                jitter = None

            total_uptime += uptime_pct
            if lat is not None:
                total_latency += lat
                latency_count += 1
            if pkt is not None:
                total_packet_loss += pkt
                pkt_count += 1

            hosts.append({
                "host_id": r["host_id"],
                "hostname": r["hostname"],
                "ip_address": r["ip_address"],
                "group_id": r["group_id"],
                "total_polls": total,
                "ok_polls": ok,
                "uptime_pct": uptime_pct,
                "avg_latency_ms": lat,
                "avg_packet_loss_pct": pkt,
                "jitter_ms": jitter,
            })

        host_count = len(hosts) or 1

        # MTTR / MTTD from alerts
        cursor = await db.execute(
            f"""SELECT
                   AVG(CASE WHEN a.acknowledged = 1 AND a.acknowledged_at IS NOT NULL
                        THEN (julianday(a.acknowledged_at) - julianday(a.created_at)) * 1440
                        ELSE NULL END) AS avg_mttr_minutes,
                   COUNT(CASE WHEN a.acknowledged = 1 THEN 1 END) AS resolved_alerts,
                   COUNT(*) AS total_alerts
                FROM monitoring_alerts a
                JOIN hosts h ON h.id = a.host_id
                WHERE a.created_at >= datetime('now', '-' || ? || ' days')
                {group_filter}""",
            tuple(params),
        )
        alert_row = await cursor.fetchone()
        mttr = round(alert_row[0], 1) if alert_row and alert_row[0] is not None else None
        resolved_alerts = alert_row[1] if alert_row else 0
        total_alerts = alert_row[2] if alert_row else 0

        # MTTD: time from first failed poll to alert creation
        cursor = await db.execute(
            f"""SELECT AVG(
                    (julianday(a.created_at) -
                     julianday(COALESCE(
                        (SELECT MIN(p2.polled_at) FROM monitoring_polls p2
                         WHERE p2.host_id = a.host_id AND p2.poll_status = 'error'
                           AND p2.polled_at <= a.created_at
                           AND p2.polled_at >= datetime(a.created_at, '-1 day')),
                        a.created_at))
                    ) * 1440) AS avg_mttd_minutes
                FROM monitoring_alerts a
                JOIN hosts h ON h.id = a.host_id
                WHERE a.created_at >= datetime('now', '-' || ? || ' days')
                {group_filter}""",
            tuple(params),
        )
        mttd_row = await cursor.fetchone()
        mttd = round(mttd_row[0], 1) if mttd_row and mttd_row[0] is not None else None

        avg_jitter_vals = [h["jitter_ms"] for h in hosts if h["jitter_ms"] is not None]
        avg_jitter = round(sum(avg_jitter_vals) / len(avg_jitter_vals), 2) if avg_jitter_vals else None

        return {
            "period_days": days,
            "host_count": len(hosts),
            "avg_uptime_pct": round(total_uptime / host_count, 3),
            "avg_latency_ms": round(total_latency / latency_count, 2) if latency_count else None,
            "avg_jitter_ms": avg_jitter,
            "avg_packet_loss_pct": round(total_packet_loss / pkt_count, 2) if pkt_count else None,
            "mttr_minutes": mttr,
            "mttd_minutes": mttd,
            "total_alerts": total_alerts,
            "resolved_alerts": resolved_alerts,
            "hosts": hosts,
        }
    finally:
        await db.close()


async def get_sla_host_detail(
    host_id: int,
    days: int = 30,
) -> dict:
    """Detailed SLA metrics for a single host over time."""
    db = await _dbcore.get_db()
    try:
        # Daily uptime/latency/packet_loss trend
        cursor = await db.execute(
            """SELECT date(p.polled_at) AS day,
                      COUNT(*) AS total_polls,
                      SUM(CASE WHEN p.poll_status = 'ok' THEN 1 ELSE 0 END) AS ok_polls,
                      AVG(p.response_time_ms) AS avg_latency,
                      AVG(p.packet_loss_pct) AS avg_packet_loss,
                      AVG(p.response_time_ms * p.response_time_ms) AS mean_sq_rt,
                      AVG(p.response_time_ms) AS mean_rt
               FROM monitoring_polls p
               WHERE p.host_id = ?
                 AND p.polled_at >= datetime('now', '-' || ? || ' days')
               GROUP BY date(p.polled_at)
               ORDER BY day ASC""",
            (host_id, days),
        )
        daily = []
        for r in rows_to_list(await cursor.fetchall()):
            total = r["total_polls"] or 1
            ok = r["ok_polls"] or 0
            mean = r["mean_rt"]
            mean_sq = r["mean_sq_rt"]
            jitter = None
            if mean is not None and mean_sq is not None:
                variance = mean_sq - (mean ** 2)
                jitter = round(max(0, variance) ** 0.5, 2)
            daily.append({
                "day": r["day"],
                "uptime_pct": round(ok / total * 100, 3),
                "avg_latency_ms": round(r["avg_latency"], 2) if r["avg_latency"] is not None else None,
                "avg_packet_loss_pct": round(r["avg_packet_loss"], 2) if r["avg_packet_loss"] is not None else None,
                "jitter_ms": jitter,
                "total_polls": total,
                "ok_polls": ok,
            })

        # MTTR for this host
        cursor = await db.execute(
            """SELECT
                   AVG(CASE WHEN a.acknowledged = 1 AND a.acknowledged_at IS NOT NULL
                        THEN (julianday(a.acknowledged_at) - julianday(a.created_at)) * 1440
                        ELSE NULL END) AS avg_mttr_minutes,
                   COUNT(CASE WHEN a.acknowledged = 1 THEN 1 END) AS resolved,
                   COUNT(*) AS total
               FROM monitoring_alerts a
               WHERE a.host_id = ?
                 AND a.created_at >= datetime('now', '-' || ? || ' days')""",
            (host_id, days),
        )
        ar = await cursor.fetchone()

        # Host info
        cursor = await db.execute(
            "SELECT hostname, ip_address, device_type, group_id FROM hosts WHERE id = ?",
            (host_id,),
        )
        host_row = await cursor.fetchone()

        return {
            "host_id": host_id,
            "hostname": host_row[0] if host_row else "",
            "ip_address": host_row[1] if host_row else "",
            "device_type": host_row[2] if host_row else "",
            "group_id": host_row[3] if host_row else None,
            "period_days": days,
            "daily": daily,
            "mttr_minutes": round(ar[0], 1) if ar and ar[0] is not None else None,
            "resolved_alerts": ar[1] if ar else 0,
            "total_alerts": ar[2] if ar else 0,
        }
    finally:
        await db.close()


async def delete_old_sla_metrics(retention_days: int) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM sla_metrics WHERE period_start < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


