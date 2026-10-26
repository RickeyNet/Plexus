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

import routes.database as _dbcore
from routes.database import (
    _LOGGER,
    _is_unique_violation,
    _safe_dynamic_update,
    row_to_dict,
    rows_to_list,
)
from routes.db.inventory import GROUP_SUBTREE_SQL as _GROUP_SUBTREE_SQL

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
    "get_latest_route_snapshots_for_hosts",
    "delete_old_route_snapshots",
    "create_alert_rule",
    "get_alert_rules",
    "get_alert_rule",
    "update_alert_rule",
    "delete_alert_rule",
    "create_alert_suppression",
    "get_alert_suppressions",
    "get_active_alert_suppressions",
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
    "SLA_METRIC_NAMES",
    "get_sla_host_metrics",
    "rollup_sla_metrics",
    "get_sla_target_hosts",
    "record_sla_target_statuses",
    "get_sla_compliance",
    "get_sla_compliance_history",
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
            (
                host_id,
                cpu_percent,
                memory_percent,
                memory_used_mb,
                memory_total_mb,
                uptime_seconds,
                if_up_count,
                if_down_count,
                if_admin_down,
                if_details,
                vpn_tunnels_up,
                vpn_tunnels_down,
                vpn_details,
                route_count,
                route_snapshot,
                poll_status,
                poll_error,
                response_time_ms,
                packet_loss_pct,
                None if icmp_alive is None else int(bool(icmp_alive)),
                icmp_rtt_ms,
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_latest_monitoring_polls(
    group_id: int | None = None,
    limit: int = 200,
    include_details: bool = False,
) -> list[dict]:
    """Return the most recent poll per host, with host info joined."""
    detail_cols = ", p.if_details, p.vpn_details, p.route_snapshot" if include_details else ""
    db = await _dbcore.get_db(read_only=True)
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
    host_id: int,
    limit: int = 100,
    include_details: bool = False,
) -> list[dict]:
    """Poll history for a host, newest first. The large per-poll blobs
    (if_details, vpn_details, route_snapshot) are only selected when
    include_details is set — history tables just need the lean columns."""
    detail_cols = ", p.if_details, p.vpn_details, p.route_snapshot" if include_details else ""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT p.id, p.host_id, p.cpu_percent, p.memory_percent,
                       p.memory_used_mb, p.memory_total_mb, p.uptime_seconds,
                       p.if_up_count, p.if_down_count, p.if_admin_down,
                       p.vpn_tunnels_up, p.vpn_tunnels_down, p.route_count,
                       p.poll_status, p.poll_error, p.response_time_ms,
                       p.packet_loss_pct, p.icmp_alive, p.icmp_rtt_ms, p.polled_at
                       {detail_cols},
                       h.hostname, h.ip_address
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
    db = await _dbcore.get_db(read_only=True)
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
            (host_id, poll_id, rule_id, alert_type, metric, message, severity, severity, value, threshold, dedup_key),
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
                new_id,
                rule_id,
                host_id,
                exc,
            )
    return new_id


async def get_monitoring_alerts(
    host_id: int | None = None,
    acknowledged: bool | None = None,
    severity: str | None = None,
    limit: int = 200,
) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
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
    db = await _dbcore.get_db(read_only=True)
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
    alert_id: int,
    acknowledged_by: str,
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
    host_id: int,
    route_count: int,
    routes_text: str,
    routes_hash: str,
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
    host_id: int,
    limit: int = 50,
) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
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
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT * FROM route_snapshots WHERE host_id = ? ORDER BY id DESC LIMIT 1",
            (host_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def get_latest_route_snapshots_for_hosts(host_ids: list[int]) -> dict[int, dict]:
    """``host_id -> newest route snapshot`` for many hosts in one query.
    A host with no capture is left out."""
    wanted = sorted({int(h) for h in host_ids})
    if not wanted:
        return {}
    db = await _dbcore.get_db(read_only=True)
    try:
        placeholders = ",".join("?" * len(wanted))
        cursor = await db.execute(
            f"""SELECT r.* FROM route_snapshots r
                JOIN (SELECT host_id, MAX(id) AS id FROM route_snapshots
                      WHERE host_id IN ({placeholders}) GROUP BY host_id) newest
                  ON newest.id = r.id""",
            tuple(wanted),
        )
        return {int(row["host_id"]): row for row in rows_to_list(await cursor.fetchall())}
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
            (
                name,
                description,
                metric,
                rule_type,
                operator,
                value,
                severity,
                consecutive,
                cooldown_minutes,
                escalate_after_minutes,
                escalate_to,
                host_id,
                group_id,
                channel_ids,
                created_by,
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_alert_rules(enabled_only: bool = False) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
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
    db = await _dbcore.get_db(read_only=True)
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
    allowed = {
        "name",
        "description",
        "metric",
        "rule_type",
        "operator",
        "value",
        "severity",
        "enabled",
        "consecutive",
        "cooldown_minutes",
        "escalate_after_minutes",
        "escalate_to",
        "host_id",
        "group_id",
        "channel_ids",
    }
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
    db = await _dbcore.get_db(read_only=True)
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


async def get_active_alert_suppressions() -> list[dict]:
    """Return the currently-active suppression rows (starts_at <= now < ends_at).

    Lean projection (host_id, group_id, metric) for in-memory matching by the
    monitoring poll loop, which preloads these once per cycle instead of issuing
    one is_alert_suppressed() query per firing check per host.
    """
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """SELECT host_id, group_id, metric FROM alert_suppressions
               WHERE starts_at <= datetime('now') AND ends_at > datetime('now')"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def is_alert_suppressed(
    host_id: int,
    metric: str,
    group_id: int | None = None,
) -> bool:
    """Check if alerts for this host+metric are currently suppressed."""
    db = await _dbcore.get_db(read_only=True)
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
    db = await _dbcore.get_db(read_only=True)
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

# The metrics an SLA target can track, and the rollup rows written for them.
SLA_METRIC_NAMES = ("uptime", "latency", "jitter", "packet_loss")

# Worst first: a host's SLA status is the worst status of its targets.
_SLA_STATUS_RANK = {"breach": 3, "warn": 2, "met": 1, "no_data": 0}


async def get_sla_targets(
    host_id: int | None = None,
    group_id: int | None = None,
) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
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
                WHERE {" AND ".join(where)}
                ORDER BY t.name""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_sla_target(target_id: int) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
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
    window_days: int = 30,
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO sla_targets
               (name, metric, target_value, warning_value, host_id, group_id, created_by, window_days)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, metric, target_value, warning_value, host_id, group_id, created_by, window_days),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_sla_target(target_id: int, **kwargs) -> None:
    allowed = {"name", "metric", "target_value", "warning_value", "enabled", "host_id", "group_id", "window_days"}
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


# ── SLA windows: raw polls + hourly/daily rollups ────────────────────────────
#
# Raw ``monitoring_polls`` are purged after ``retention_days`` (default 30),
# so a longer SLA window cannot be computed from them. The SLA rollup job
# (``rollup_sla_metrics``) writes one ``sla_metrics`` row per host, metric and
# completed hour, then one per completed day from the hourly rows. Each row
# carries the sums needed to recombine it exactly:
#
#   uptime       sample_count = polls,            sum_value = ok polls
#   latency      sample_count = response samples, sum_value = sum, sum_sq = sum of squares
#   jitter       same sums as latency; value = population stddev of the hour/day
#   packet_loss  sample_count = loss samples,     sum_value = sum
#
# A window [now - days, now) is then read as: daily rows for the whole days up
# to the daily watermark (the end of the last daily rollup), hourly rows for
# the hours after that (and for the partial first day) up to the hourly
# watermark, and raw polls for the rest (the partial first hour and the hours
# not rolled up yet). Without rollups this is the raw-poll computation.

_SLA_TS_FORMAT = "%Y-%m-%d %H:%M:%S"
# Hours (and days) before the watermark that a rollup pass re-reads. Rows that
# exist are kept (ON CONFLICT DO NOTHING); this only fills a period a host
# had no row for, e.g. polls committed just after the previous pass.
_SLA_HOURLY_LOOKBACK = timedelta(hours=2)
_SLA_DAILY_LOOKBACK = timedelta(days=1)


def _sla_ts(dt: datetime) -> str:
    return dt.strftime(_SLA_TS_FORMAT)


def _sla_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    return now if now.tzinfo else now.replace(tzinfo=UTC)


def _sla_parse_ts(value: str) -> datetime:
    return datetime.strptime(value[:19], _SLA_TS_FORMAT).replace(tzinfo=UTC)


def _ceil_hour(dt: datetime) -> datetime:
    floor = dt.replace(minute=0, second=0, microsecond=0)
    return floor if floor == dt else floor + timedelta(hours=1)


def _ceil_day(dt: datetime) -> datetime:
    floor = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    return floor if floor == dt else floor + timedelta(days=1)


async def _sla_watermark(db, time_window: str) -> str | None:
    """End of the newest ``time_window`` rollup period (all hosts are rolled
    up together, so every period before it is complete)."""
    cursor = await db.execute(
        "SELECT MAX(period_end) FROM sla_metrics WHERE time_window = ?",
        (time_window,),
    )
    row = await cursor.fetchone()
    return row[0] if row and row[0] else None


async def _sla_host_aggregates(
    db,
    days: int,
    now: datetime,
    *,
    host_id: int | None = None,
    group_id: int | None = None,
    by_day: bool = False,
) -> tuple[list[dict], str, str]:
    """Per-host (and per-day with ``by_day``) poll counts and sums over the
    window ``[now - days, now)``, combining raw polls and rollups (see the
    comment above). Returns ``(rows, window_start, window_end)``."""
    hourly_mark = await _sla_watermark(db, "hourly")
    daily_mark = await _sla_watermark(db, "daily")
    start = now - timedelta(days=days)
    start_s = _sla_ts(start)
    start_hour = _sla_ts(_ceil_hour(start))
    start_day = _sla_ts(_ceil_day(start))
    # Raw polls: the partial first hour, then everything after the hourly
    # watermark (everything at all when nothing is rolled up yet).
    raw_from = max(hourly_mark, start_hour) if hourly_mark else start_s
    # Hourly rows: the partial first day, then the hours after the daily
    # watermark; daily rows cover the whole days in between.
    hourly_after = max(daily_mark, start_day) if daily_mark else start_day

    raw_filter = ""
    roll_filter = ""
    filter_params: list = []
    if host_id is not None:
        raw_filter += " AND p.host_id = ?"
        roll_filter += " AND m.host_id = ?"
        filter_params.append(host_id)
    if group_id is not None:
        raw_filter += " AND p.host_id IN (SELECT id FROM hosts WHERE group_id = ?)"
        roll_filter += " AND m.host_id IN (SELECT id FROM hosts WHERE group_id = ?)"
        filter_params.append(group_id)

    raw_day = "substr(p.polled_at, 1, 10) AS day," if by_day else ""
    raw_day_group = ", substr(p.polled_at, 1, 10)" if by_day else ""
    roll_day = "substr(m.period_start, 1, 10) AS day," if by_day else ""
    roll_day_group = ", substr(m.period_start, 1, 10)" if by_day else ""
    outer_day = "x.day," if by_day else ""
    outer_day_group = ", x.day" if by_day else ""

    cursor = await db.execute(
        f"""SELECT h.id AS host_id, h.hostname, h.ip_address, h.group_id, {outer_day}
                   SUM(x.total) AS total_polls,
                   SUM(x.ok) AS ok_polls,
                   SUM(x.rt_n) AS rt_n,
                   SUM(x.rt_sum) AS rt_sum,
                   SUM(x.rt_sq) AS rt_sq,
                   SUM(x.pl_n) AS pl_n,
                   SUM(x.pl_sum) AS pl_sum
            FROM (
                SELECT p.host_id, {raw_day}
                       COUNT(*) AS total,
                       SUM(CASE WHEN p.poll_status = 'ok' THEN 1 ELSE 0 END) AS ok,
                       COUNT(p.response_time_ms) AS rt_n,
                       COALESCE(SUM(p.response_time_ms), 0) AS rt_sum,
                       COALESCE(SUM(p.response_time_ms * p.response_time_ms), 0) AS rt_sq,
                       COUNT(p.packet_loss_pct) AS pl_n,
                       COALESCE(SUM(p.packet_loss_pct), 0) AS pl_sum
                FROM monitoring_polls p
                WHERE p.polled_at >= ? AND (p.polled_at < ? OR p.polled_at >= ?){raw_filter}
                GROUP BY p.host_id{raw_day_group}
                UNION ALL
                SELECT m.host_id, {roll_day}
                       SUM(CASE WHEN m.metric = 'uptime' THEN m.sample_count ELSE 0 END) AS total,
                       SUM(CASE WHEN m.metric = 'uptime' THEN m.sum_value ELSE 0 END) AS ok,
                       SUM(CASE WHEN m.metric = 'latency' THEN m.sample_count ELSE 0 END) AS rt_n,
                       SUM(CASE WHEN m.metric = 'latency' THEN m.sum_value ELSE 0 END) AS rt_sum,
                       SUM(CASE WHEN m.metric = 'latency' THEN m.sum_sq ELSE 0 END) AS rt_sq,
                       SUM(CASE WHEN m.metric = 'packet_loss' THEN m.sample_count ELSE 0 END) AS pl_n,
                       SUM(CASE WHEN m.metric = 'packet_loss' THEN m.sum_value ELSE 0 END) AS pl_sum
                FROM sla_metrics m
                WHERE m.metric IN ('uptime', 'latency', 'packet_loss')
                  AND ((m.time_window = 'hourly' AND m.period_start >= ? AND m.period_end <= ?
                        AND (m.period_start < ? OR m.period_start >= ?))
                    OR (m.time_window = 'daily' AND m.period_start >= ? AND m.period_end <= ?)){roll_filter}
                GROUP BY m.host_id{roll_day_group}
            ) x
            JOIN hosts h ON h.id = x.host_id
            GROUP BY h.id{outer_day_group}
            HAVING SUM(x.total) > 0
            ORDER BY h.hostname{outer_day_group}""",
        (
            start_s,
            start_hour,
            raw_from,
            *filter_params,
            start_hour,
            hourly_mark or "",
            start_day,
            hourly_after,
            start_day,
            daily_mark or "",
            *filter_params,
        ),
    )
    return rows_to_list(await cursor.fetchall()), start_s, _sla_ts(now)


def _sla_values(r: dict) -> dict:
    """Uptime %, mean latency, jitter (population stddev of the response
    time) and mean packet loss from one aggregate row's counts and sums."""
    total = int(r.get("total_polls") or 0)
    ok = int(round(float(r.get("ok_polls") or 0)))
    rt_n = int(r.get("rt_n") or 0)
    pl_n = int(r.get("pl_n") or 0)
    latency = jitter = packet_loss = None
    if rt_n:
        mean = float(r.get("rt_sum") or 0) / rt_n
        variance = float(r.get("rt_sq") or 0) / rt_n - mean * mean
        latency = round(mean, 2)
        jitter = round(max(0.0, variance) ** 0.5, 2)
    if pl_n:
        packet_loss = round(float(r.get("pl_sum") or 0) / pl_n, 2)
    return {
        "total_polls": total,
        "ok_polls": ok,
        "uptime_pct": round(ok / total * 100, 3) if total else None,
        "avg_latency_ms": latency,
        "jitter_ms": jitter,
        "avg_packet_loss_pct": packet_loss,
        "latency_samples": rt_n,
        "packet_loss_samples": pl_n,
    }


async def get_sla_host_metrics(
    days: int = 30,
    *,
    now: datetime | None = None,
    host_id: int | None = None,
    group_id: int | None = None,
) -> dict:
    """SLA values of every host with data in the window ``[now - days, now)``:
    ``{"window_start", "window_end", "hosts": {host_id: values}}``."""
    db = await _dbcore.get_db(read_only=True)
    try:
        rows, window_start, window_end = await _sla_host_aggregates(
            db, days, _sla_now(now), host_id=host_id, group_id=group_id
        )
    finally:
        await db.close()
    return {
        "window_start": window_start,
        "window_end": window_end,
        "hosts": {int(r["host_id"]): {**_sla_values(r), "hostname": r["hostname"]} for r in rows},
    }


# ── SLA Summary & Host Detail ────────────────────────────────────────────────


def _worst_sla_status(statuses: list[str]) -> str | None:
    if not statuses:
        return None
    return max(statuses, key=lambda s: _SLA_STATUS_RANK.get(s, 0))


async def get_sla_summary(
    group_id: int | None = None,
    days: int = 30,
    now: datetime | None = None,
) -> dict:
    """SLA summary over the last ``days``: raw polls combined with the SLA
    rollups (so windows longer than the poll retention are complete), with
    the latest server-side target evaluation per host."""
    db = await _dbcore.get_db(read_only=True)
    try:
        group_filter = ""
        params: list = [days]
        if group_id is not None:
            group_filter = "AND h.group_id = ?"
            params.append(group_id)

        rows, _start, _end = await _sla_host_aggregates(db, days, _sla_now(now), group_id=group_id)

        # Latest target evaluation per host (worst status across its targets).
        cursor = await db.execute(
            f"""SELECT s.host_id, s.status, s.evaluated_at
                FROM sla_target_status s
                JOIN hosts h ON h.id = s.host_id
                WHERE 1=1 {group_filter}""",
            tuple(params[1:]),
        )
        host_statuses: dict[int, list[str]] = {}
        evaluated_at = None
        for srow in rows_to_list(await cursor.fetchall()):
            host_statuses.setdefault(int(srow["host_id"]), []).append(srow["status"])
            if srow["evaluated_at"] and (evaluated_at is None or srow["evaluated_at"] > evaluated_at):
                evaluated_at = srow["evaluated_at"]
        worst_by_host = {hid: _worst_sla_status(sts) for hid, sts in host_statuses.items()}
        compliance = {"met": 0, "warn": 0, "breach": 0, "no_data": 0}
        for status in worst_by_host.values():
            if status in compliance:
                compliance[status] += 1

        hosts = []
        total_uptime = 0.0
        total_latency = 0.0
        total_packet_loss = 0.0
        latency_count = 0
        pkt_count = 0

        for r in rows:
            values = _sla_values(r)
            uptime_pct = values["uptime_pct"] or 0.0
            lat = values["avg_latency_ms"]
            pkt = values["avg_packet_loss_pct"]
            total_uptime += uptime_pct
            if lat is not None:
                total_latency += lat
                latency_count += 1
            if pkt is not None:
                total_packet_loss += pkt
                pkt_count += 1

            hosts.append(
                {
                    "host_id": r["host_id"],
                    "hostname": r["hostname"],
                    "ip_address": r["ip_address"],
                    "group_id": r["group_id"],
                    "total_polls": values["total_polls"],
                    "ok_polls": values["ok_polls"],
                    "uptime_pct": uptime_pct,
                    "avg_latency_ms": lat,
                    "avg_packet_loss_pct": pkt,
                    "jitter_ms": values["jitter_ms"],
                    "sla_status": worst_by_host.get(int(r["host_id"])),
                }
            )

        host_count = len(hosts) or 1

        # MTTR / MTTD from alerts
        mttr_expr = _dbcore._minutes_between_expr("a.acknowledged_at", "a.created_at")
        cursor = await db.execute(
            f"""SELECT
                   AVG(CASE WHEN a.acknowledged = 1 AND a.acknowledged_at IS NOT NULL
                        THEN {mttr_expr}
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
        mttd_earlier = (
            "COALESCE("
            "(SELECT MIN(p2.polled_at) FROM monitoring_polls p2 "
            "WHERE p2.host_id = a.host_id AND p2.poll_status = 'error' "
            "AND p2.polled_at <= a.created_at "
            "AND p2.polled_at >= datetime(a.created_at, '-1 day')), "
            "a.created_at)"
        )
        mttd_expr = _dbcore._minutes_between_expr("a.created_at", mttd_earlier)
        cursor = await db.execute(
            f"""SELECT AVG({mttd_expr}) AS avg_mttd_minutes
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
            "compliance": {**compliance, "hosts": len(worst_by_host), "evaluated_at": evaluated_at},
            "hosts": hosts,
        }
    finally:
        await db.close()


async def get_sla_host_detail(
    host_id: int,
    days: int = 30,
    now: datetime | None = None,
) -> dict:
    """Detailed SLA metrics for a single host over time (one point per day,
    from raw polls and the SLA rollups)."""
    db = await _dbcore.get_db(read_only=True)
    try:
        rows, _start, _end = await _sla_host_aggregates(db, days, _sla_now(now), host_id=host_id, by_day=True)
        daily = []
        for r in rows:
            values = _sla_values(r)
            daily.append(
                {
                    "day": r["day"],
                    "uptime_pct": values["uptime_pct"],
                    "avg_latency_ms": values["avg_latency_ms"],
                    "avg_packet_loss_pct": values["avg_packet_loss_pct"],
                    "jitter_ms": values["jitter_ms"],
                    "total_polls": values["total_polls"],
                    "ok_polls": values["ok_polls"],
                }
            )

        # MTTR for this host
        host_mttr_expr = _dbcore._minutes_between_expr("a.acknowledged_at", "a.created_at")
        cursor = await db.execute(
            f"""SELECT
                   AVG(CASE WHEN a.acknowledged = 1 AND a.acknowledged_at IS NOT NULL
                        THEN {host_mttr_expr}
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


# ── SLA Rollups ──────────────────────────────────────────────────────────────

# One row per host, metric and completed hour of raw polls. ``to_char`` of the
# truncated hour writes the same ``YYYY-MM-DD HH:MM:SS`` text the window
# reader compares against (the session time zone is UTC).
_SLA_HOURLY_ROLLUP_SQL = """
INSERT INTO sla_metrics
    (host_id, metric, time_window, value, sample_count, sum_value, sum_sq, period_start, period_end)
SELECT a.host_id, m.metric, 'hourly',
       CASE m.metric
           WHEN 'uptime' THEN 100.0 * a.ok / a.total
           WHEN 'latency' THEN a.rt_sum / a.rt_n
           WHEN 'jitter' THEN sqrt(GREATEST(0, a.rt_sq / a.rt_n - (a.rt_sum / a.rt_n) * (a.rt_sum / a.rt_n)))
           ELSE a.pl_sum / a.pl_n
       END,
       CASE m.metric WHEN 'uptime' THEN a.total WHEN 'packet_loss' THEN a.pl_n ELSE a.rt_n END,
       CASE m.metric WHEN 'uptime' THEN a.ok WHEN 'packet_loss' THEN a.pl_sum ELSE a.rt_sum END,
       CASE WHEN m.metric IN ('latency', 'jitter') THEN a.rt_sq ELSE 0 END,
       a.period_start, a.period_end
FROM (
    SELECT p.host_id,
           to_char(date_trunc('hour', p.polled_at::timestamptz), 'YYYY-MM-DD HH24:MI:SS') AS period_start,
           to_char(date_trunc('hour', p.polled_at::timestamptz) + INTERVAL '1 hour', 'YYYY-MM-DD HH24:MI:SS')
               AS period_end,
           COUNT(*) AS total,
           SUM(CASE WHEN p.poll_status = 'ok' THEN 1 ELSE 0 END) AS ok,
           COUNT(p.response_time_ms) AS rt_n,
           COALESCE(SUM(p.response_time_ms), 0) AS rt_sum,
           COALESCE(SUM(p.response_time_ms * p.response_time_ms), 0) AS rt_sq,
           COUNT(p.packet_loss_pct) AS pl_n,
           COALESCE(SUM(p.packet_loss_pct), 0) AS pl_sum
    FROM monitoring_polls p
    WHERE p.polled_at >= ? AND p.polled_at < ?
    GROUP BY p.host_id, 2, 3
) a
CROSS JOIN (VALUES ('uptime'), ('latency'), ('jitter'), ('packet_loss')) AS m (metric)
WHERE m.metric = 'uptime'
   OR (m.metric IN ('latency', 'jitter') AND a.rt_n > 0)
   OR (m.metric = 'packet_loss' AND a.pl_n > 0)
ON CONFLICT (host_id, metric, time_window, period_start) DO NOTHING
"""

# One row per host, metric and completed day, recombined from the hourly rows.
_SLA_DAILY_ROLLUP_SQL = """
INSERT INTO sla_metrics
    (host_id, metric, time_window, value, sample_count, sum_value, sum_sq, period_start, period_end)
SELECT d.host_id, d.metric, 'daily',
       CASE d.metric
           WHEN 'uptime' THEN 100.0 * d.s / d.n
           WHEN 'jitter' THEN sqrt(GREATEST(0, d.q / d.n - (d.s / d.n) * (d.s / d.n)))
           ELSE d.s / d.n
       END,
       d.n, d.s, d.q,
       d.day || ' 00:00:00',
       to_char(d.day::date + 1, 'YYYY-MM-DD') || ' 00:00:00'
FROM (
    SELECT host_id, metric, substr(period_start, 1, 10) AS day,
           SUM(sample_count) AS n, SUM(sum_value) AS s, SUM(sum_sq) AS q
    FROM sla_metrics
    WHERE time_window = 'hourly' AND period_start >= ? AND period_start < ?
    GROUP BY host_id, metric, substr(period_start, 1, 10)
) d
WHERE d.n > 0
ON CONFLICT (host_id, metric, time_window, period_start) DO NOTHING
"""


async def rollup_sla_metrics(now: datetime | None = None) -> dict:
    """Write the SLA rollups for every completed hour and day not rolled up
    yet. Idempotent: a (host, metric, window, period_start) is never written
    twice. The first pass rolls up every raw poll still retained."""
    current = _sla_now(now)
    hour_end = current.replace(minute=0, second=0, microsecond=0)
    day_end = current.replace(hour=0, minute=0, second=0, microsecond=0)
    db = await _dbcore.get_db()
    try:
        mark = await _sla_watermark(db, "hourly")
        hourly_from = _sla_ts(min(_sla_parse_ts(mark) - _SLA_HOURLY_LOOKBACK, hour_end)) if mark else ""
        cursor = await db.execute(_SLA_HOURLY_ROLLUP_SQL, (hourly_from, _sla_ts(hour_end)))
        hourly = cursor.rowcount

        mark = await _sla_watermark(db, "daily")
        daily_from = _sla_ts(min(_sla_parse_ts(mark) - _SLA_DAILY_LOOKBACK, day_end)) if mark else ""
        cursor = await db.execute(_SLA_DAILY_ROLLUP_SQL, (daily_from, _sla_ts(day_end)))
        daily = cursor.rowcount
        await db.commit()
    finally:
        await db.close()
    return {"hourly_rows": hourly, "daily_rows": daily}


async def delete_old_sla_metrics(retention_days: int) -> int:
    """Drop SLA rollups (and SLA status history) older than ``retention_days``.
    Returns the number of rollup rows deleted."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM sla_metrics WHERE period_start < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        deleted = cursor.rowcount
        await db.execute(
            "DELETE FROM sla_target_status_history WHERE evaluated_at < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return deleted
    finally:
        await db.close()


# ── SLA Target Evaluation ────────────────────────────────────────────────────


async def get_sla_target_hosts(host_id: int | None = None, group_id: int | None = None) -> list[dict]:
    """The hosts a target scoped to ``host_id`` / ``group_id`` applies to: the
    host, every host of the group and of its sub-groups, or (neither set)
    every host."""
    if host_id is not None:
        where, params = "h.id = ?", (host_id,)
    elif group_id is not None:
        where, params = f"h.group_id IN {_GROUP_SUBTREE_SQL}", (group_id,)
    else:
        where, params = "1=1", ()
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT h.id AS host_id, h.hostname, h.group_id FROM hosts h WHERE {where} ORDER BY h.hostname",
            params,
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


_SLA_STATUS_COLUMNS = (
    "target_id",
    "host_id",
    "metric",
    "value",
    "target_value",
    "warning_value",
    "status",
    "sample_count",
    "window_days",
    "window_start",
    "window_end",
)


async def record_sla_target_statuses(results: list[dict], evaluated_at: str) -> list[dict]:
    """Store one evaluation pass: upsert the latest status of every
    (target, host), append a history row where the status changed (or was
    never recorded), and drop the latest-status rows this pass did not
    evaluate (a disabled or deleted target, a host that left the group).

    Returns ``results`` with ``previous_status`` ('' when new) on each."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT target_id, host_id, status, status_since FROM sla_target_status")
        previous = {(int(r["target_id"]), int(r["host_id"])): r for r in rows_to_list(await cursor.fetchall())}
        upserts = []
        history = []
        out = []
        for res in results:
            prev = previous.get((int(res["target_id"]), int(res["host_id"])))
            prev_status = prev["status"] if prev else ""
            changed = prev_status != res["status"]
            since = evaluated_at if changed or not prev or not prev["status_since"] else prev["status_since"]
            upserts.append((*(res[c] for c in _SLA_STATUS_COLUMNS), evaluated_at, since))
            if changed:
                history.append(
                    (
                        res["target_id"],
                        res["host_id"],
                        res["metric"],
                        res["value"],
                        res["status"],
                        prev_status,
                        res["window_start"],
                        res["window_end"],
                        evaluated_at,
                    )
                )
            out.append({**res, "previous_status": prev_status, "status_since": since})
        if upserts:
            await db.executemany(
                f"""INSERT INTO sla_target_status
                    ({", ".join(_SLA_STATUS_COLUMNS)}, evaluated_at, status_since)
                    VALUES ({", ".join("?" for _ in range(len(_SLA_STATUS_COLUMNS) + 2))})
                    ON CONFLICT (target_id, host_id) DO UPDATE SET
                        metric = excluded.metric,
                        value = excluded.value,
                        target_value = excluded.target_value,
                        warning_value = excluded.warning_value,
                        status = excluded.status,
                        sample_count = excluded.sample_count,
                        window_days = excluded.window_days,
                        window_start = excluded.window_start,
                        window_end = excluded.window_end,
                        evaluated_at = excluded.evaluated_at,
                        status_since = excluded.status_since""",
                upserts,
            )
        if history:
            await db.executemany(
                """INSERT INTO sla_target_status_history
                   (target_id, host_id, metric, value, status, previous_status,
                    window_start, window_end, evaluated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                history,
            )
        current = {(int(res["target_id"]), int(res["host_id"])) for res in results}
        stale = [key for key in previous if key not in current]
        if stale:
            await db.executemany("DELETE FROM sla_target_status WHERE target_id = ? AND host_id = ?", stale)
        await db.commit()
    finally:
        await db.close()
    return out


async def get_sla_compliance(
    group_id: int | None = None,
    host_id: int | None = None,
    target_id: int | None = None,
) -> list[dict]:
    """Latest evaluation of every (target, host). ``group_id`` keeps the hosts
    of the group and of its sub-groups."""
    where = ["1=1"]
    params: list = []
    if group_id is not None:
        where.append(f"h.group_id IN {_GROUP_SUBTREE_SQL}")
        params.append(group_id)
    if host_id is not None:
        where.append("s.host_id = ?")
        params.append(host_id)
    if target_id is not None:
        where.append("s.target_id = ?")
        params.append(target_id)
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT s.*, t.name AS target_name,
                       h.hostname, h.ip_address, h.group_id
                FROM sla_target_status s
                JOIN sla_targets t ON t.id = s.target_id
                JOIN hosts h ON h.id = s.host_id
                WHERE {" AND ".join(where)}
                ORDER BY h.hostname, t.name""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_sla_compliance_history(
    target_id: int | None = None,
    host_id: int | None = None,
    limit: int = 100,
) -> list[dict]:
    """Status changes of SLA targets, newest first."""
    where = ["1=1"]
    params: list = []
    if target_id is not None:
        where.append("x.target_id = ?")
        params.append(target_id)
    if host_id is not None:
        where.append("x.host_id = ?")
        params.append(host_id)
    params.append(limit)
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT x.*, t.name AS target_name, h.hostname
                FROM sla_target_status_history x
                JOIN sla_targets t ON t.id = x.target_id
                JOIN hosts h ON h.id = x.host_id
                WHERE {" AND ".join(where)}
                ORDER BY x.id DESC
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()
