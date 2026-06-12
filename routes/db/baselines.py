"""Baselines persistence helpers.

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
    "upsert_metric_baseline",
    "get_metric_baseline",
    "get_baselines_for_host",
    "list_baseline_alert_rules",
    "get_baseline_alert_rule",
    "create_baseline_alert_rule",
    "update_baseline_alert_rule",
    "delete_baseline_alert_rule",
    "create_upgrade_image",
    "get_all_upgrade_images",
    "get_upgrade_image",
    "get_upgrade_image_by_filename",
    "update_upgrade_image",
    "delete_upgrade_image",
    "create_upgrade_campaign",
    "get_all_upgrade_campaigns",
    "get_upgrade_campaign",
    "update_upgrade_campaign",
    "delete_upgrade_campaign",
    "delete_upgrade_devices_by_campaign",
    "create_upgrade_operation",
    "update_upgrade_operation",
    "get_upgrade_operations",
    "get_latest_upgrade_operation",
    "add_upgrade_device",
    "get_upgrade_devices",
    "get_upgrade_device_counts",
    "get_upgrade_device",
    "update_upgrade_device",
    "add_upgrade_event",
    "get_upgrade_events",
]

# ═════════════════════════════════════════════════════════════════════════════
# METRIC BASELINES  (statistical learning for baseline deviation alerting)
# ═════════════════════════════════════════════════════════════════════════════


async def upsert_metric_baseline(host_id: int, metric_name: str,
                                   day_of_week: int, hour_of_day: int,
                                   baseline_avg: float, baseline_stddev: float,
                                   baseline_min: float, baseline_max: float,
                                   baseline_p95: float, sample_count: int,
                                   labels_json: str = "{}",
                                   learning_window_days: int = 14) -> int:
    """Atomic upsert using INSERT ... ON CONFLICT DO UPDATE (SQLite 3.24+)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO metric_baselines
               (host_id, metric_name, labels_json, day_of_week, hour_of_day,
                baseline_avg, baseline_stddev, baseline_min, baseline_max,
                baseline_p95, sample_count, learning_window_days)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(host_id, metric_name, labels_json, day_of_week, hour_of_day) DO UPDATE SET
                baseline_avg = excluded.baseline_avg,
                baseline_stddev = excluded.baseline_stddev,
                baseline_min = excluded.baseline_min,
                baseline_max = excluded.baseline_max,
                baseline_p95 = excluded.baseline_p95,
                sample_count = excluded.sample_count,
                learning_window_days = excluded.learning_window_days,
                last_computed = datetime('now')
               RETURNING id""",
            (host_id, metric_name, labels_json, day_of_week, hour_of_day,
             baseline_avg, baseline_stddev, baseline_min, baseline_max,
             baseline_p95, sample_count, learning_window_days),
        )
        row = await cursor.fetchone()
        await db.commit()
        return int(row[0])
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def get_metric_baseline(host_id: int, metric_name: str,
                                day_of_week: int, hour_of_day: int,
                                labels_json: str = "{}") -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM metric_baselines
               WHERE host_id = ? AND metric_name = ? AND labels_json = ?
                     AND day_of_week = ? AND hour_of_day = ?""",
            (host_id, metric_name, labels_json, day_of_week, hour_of_day),
        )
        row = await cursor.fetchone()
        return row_to_dict(row) if row else None
    finally:
        await db.close()


async def get_baselines_for_host(host_id: int, metric_name: str | None = None) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        if metric_name:
            cursor = await db.execute(
                "SELECT * FROM metric_baselines WHERE host_id = ? AND metric_name = ? ORDER BY day_of_week, hour_of_day",
                (host_id, metric_name),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM metric_baselines WHERE host_id = ? ORDER BY metric_name, day_of_week, hour_of_day",
                (host_id,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ── Baseline Alert Rules ──

async def list_baseline_alert_rules(enabled_only: bool = False) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        q = "SELECT * FROM baseline_alert_rules"
        if enabled_only:
            q += " WHERE enabled = 1"
        q += " ORDER BY name"
        cursor = await db.execute(q)
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_baseline_alert_rule(rule_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM baseline_alert_rules WHERE id = ?", (rule_id,))
        row = await cursor.fetchone()
        return row_to_dict(row) if row else None
    finally:
        await db.close()


async def create_baseline_alert_rule(**kwargs) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO baseline_alert_rules
               (name, description, metric_name, host_id, group_id,
                sensitivity, min_samples, learning_days, enabled,
                severity, cooldown_minutes, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (kwargs.get("name", ""), kwargs.get("description", ""),
             kwargs.get("metric_name", ""), kwargs.get("host_id"),
             kwargs.get("group_id"), kwargs.get("sensitivity", 2.0),
             kwargs.get("min_samples", 100), kwargs.get("learning_days", 14),
             kwargs.get("enabled", 1), kwargs.get("severity", "warning"),
             kwargs.get("cooldown_minutes", 30), kwargs.get("created_by", "")),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_baseline_alert_rule(rule_id: int, **kwargs) -> bool:
    db = await _dbcore.get_db()
    try:
        sets = []
        vals = []
        allowed = ("name", "description", "metric_name", "host_id", "group_id",
                    "sensitivity", "min_samples", "learning_days", "enabled",
                    "severity", "cooldown_minutes")
        for k, v in kwargs.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        sets.append("updated_at = datetime('now')")
        sql, sql_params = _safe_dynamic_update("baseline_alert_rules", sets, vals, "id = ?", rule_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_baseline_alert_rule(rule_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM baseline_alert_rules WHERE id = ?", (rule_id,))
        await db.commit()
        return True
    finally:
        await db.close()


# ── IOS-XE Upgrade System ──────────────────────────────────────────────────


async def create_upgrade_image(filename, original_name, file_size, md5_hash,
                               model_pattern, version, platform, notes, uploaded_by):
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO upgrade_images (filename, original_name, file_size, md5_hash, "
            "model_pattern, version, platform, notes, uploaded_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (filename, original_name, file_size, md5_hash,
             model_pattern, version, platform, notes, uploaded_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_all_upgrade_images():
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM upgrade_images ORDER BY created_at DESC")
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_upgrade_image(image_id):
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM upgrade_images WHERE id = ?", (image_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def get_upgrade_image_by_filename(filename):
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM upgrade_images WHERE filename = ?",
            (filename,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def update_upgrade_image(image_id, **kwargs):
    db = await _dbcore.get_db()
    try:
        sets, vals = [], []
        for k, v in kwargs.items():
            if k in ("model_pattern", "version", "platform", "notes"):
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        sql, sql_params = _safe_dynamic_update("upgrade_images", sets, vals, "id = ?", image_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_upgrade_image(image_id):
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM upgrade_images WHERE id = ?", (image_id,))
        await db.commit()
        return True
    finally:
        await db.close()


async def create_upgrade_campaign(name, description, image_map, options, created_by):
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO upgrade_campaigns (name, description, image_map, options, created_by) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, description, json.dumps(image_map), json.dumps(options), created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_all_upgrade_campaigns():
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM upgrade_campaigns ORDER BY created_at DESC")
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_upgrade_campaign(campaign_id):
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM upgrade_campaigns WHERE id = ?", (campaign_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def update_upgrade_campaign(campaign_id, **kwargs):
    db = await _dbcore.get_db()
    try:
        sets, vals = [], []
        for k, v in kwargs.items():
            if k in ("name", "description", "status", "image_map", "options", "scheduled_at"):
                if k in ("image_map", "options"):
                    v = json.dumps(v)
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        sets.append("updated_at = datetime('now')")
        sql, sql_params = _safe_dynamic_update("upgrade_campaigns", sets, vals, "id = ?", campaign_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_upgrade_campaign(campaign_id):
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM upgrade_campaigns WHERE id = ?", (campaign_id,))
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_upgrade_devices_by_campaign(campaign_id):
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "DELETE FROM upgrade_devices WHERE campaign_id = ? "
            "AND COALESCE(phase, 'pending') != 'running' "
            "AND COALESCE(prestage_status, 'pending') != 'running' "
            "AND COALESCE(transfer_status, 'pending') != 'running' "
            "AND COALESCE(activate_status, 'pending') != 'running' "
            "AND COALESCE(verify_status, 'pending') != 'running'",
            (campaign_id,),
        )
        await db.commit()
        return True
    finally:
        await db.close()


async def create_upgrade_operation(
    campaign_id,
    phase,
    status,
    requested_by="",
    device_count=0,
    scheduled_at=None,
    started_at=None,
):
    db = await _dbcore.get_db()
    try:
        now = datetime.now(UTC).isoformat()
        cursor = await db.execute(
            "INSERT INTO upgrade_operations "
            "(campaign_id, phase, status, requested_by, device_count, scheduled_at, started_at, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                campaign_id,
                phase,
                status,
                requested_by,
                device_count,
                scheduled_at,
                started_at,
                now,
                now,
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_upgrade_operation(operation_id, **kwargs):
    db = await _dbcore.get_db()
    try:
        allowed = {
            "status",
            "device_count",
            "succeeded",
            "failed",
            "cancelled",
            "scheduled_at",
            "started_at",
            "completed_at",
            "error_message",
        }
        sets, vals = [], []
        for k, v in kwargs.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        sets.append("updated_at = ?")
        vals.append(datetime.now(UTC).isoformat())
        sql, sql_params = _safe_dynamic_update(
            "upgrade_operations", sets, vals, "id = ?", operation_id
        )
        await db.execute(sql, sql_params)
        await db.commit()
        return True
    finally:
        await db.close()


async def get_upgrade_operations(campaign_id, limit=20):
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM upgrade_operations WHERE campaign_id = ? "
            "ORDER BY COALESCE(started_at, scheduled_at, created_at) DESC, id DESC LIMIT ?",
            (campaign_id, limit),
        )
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_latest_upgrade_operation(campaign_id, phase=None, statuses=None):
    db = await _dbcore.get_db()
    try:
        clauses = ["campaign_id = ?"]
        params = [campaign_id]
        if phase is not None:
            clauses.append("phase = ?")
            params.append(phase)
        if statuses:
            placeholders = ", ".join("?" for _ in statuses)
            clauses.append(f"status IN ({placeholders})")
            params.extend(statuses)
        cursor = await db.execute(
            "SELECT * FROM upgrade_operations WHERE "
            + " AND ".join(clauses)
            + " ORDER BY COALESCE(started_at, scheduled_at, created_at) DESC, id DESC LIMIT 1",
            tuple(params),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def add_upgrade_device(campaign_id, host_id, ip_address, hostname):
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO upgrade_devices (campaign_id, host_id, ip_address, hostname) "
            "VALUES (?, ?, ?, ?)",
            (campaign_id, host_id, ip_address, hostname),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_upgrade_devices(campaign_id):
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM upgrade_devices WHERE campaign_id = ? ORDER BY hostname, ip_address",
            (campaign_id,),
        )
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_upgrade_device_counts():
    """Per-campaign device tallies via a single grouped query.

    Lets the campaigns list compute device_count / devices_completed /
    devices_failed without an N+1 over get_upgrade_devices (which fetched and
    materialized every device row of every campaign just to count them).
    Returns ``{campaign_id: {device_count, devices_completed, devices_failed}}``.
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT campaign_id, "
            "COUNT(*) AS device_count, "
            "SUM(CASE WHEN phase = 'completed' THEN 1 ELSE 0 END) AS devices_completed, "
            "SUM(CASE WHEN phase = 'failed' THEN 1 ELSE 0 END) AS devices_failed "
            "FROM upgrade_devices GROUP BY campaign_id"
        )
        out = {}
        for r in await cursor.fetchall():
            row = dict(r)
            out[row["campaign_id"]] = {
                "device_count": row["device_count"] or 0,
                "devices_completed": row["devices_completed"] or 0,
                "devices_failed": row["devices_failed"] or 0,
            }
        return out
    finally:
        await db.close()


async def get_upgrade_device(device_id):
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM upgrade_devices WHERE id = ?", (device_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def update_upgrade_device(device_id, **kwargs):
    db = await _dbcore.get_db()
    try:
        allowed = {
            "model", "current_version", "target_image", "phase", "phase_detail",
            "health_status", "prestage_status", "transfer_status", "activate_status",
            "verify_status", "error_message", "started_at", "completed_at",
        }
        sets, vals = [], []
        for k, v in kwargs.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        sql, sql_params = _safe_dynamic_update("upgrade_devices", sets, vals, "id = ?", device_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return True
    finally:
        await db.close()


async def add_upgrade_event(campaign_id, device_id, level, message, host=""):
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO upgrade_events (campaign_id, device_id, level, message, host) "
            "VALUES (?, ?, ?, ?, ?)",
            (campaign_id, device_id, level, message, host),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_upgrade_events(campaign_id, device_id=None, limit=1000):
    """Return up to ``limit`` of the most recent events, oldest-first.

    Takes the newest ``limit`` rows (tail) then re-sorts ascending for display.
    Long-running campaigns can emit far more events than any viewer needs, so
    capping the tail keeps the payload and the DB scan bounded while still
    showing the latest activity. ``id`` breaks ties on same-second timestamps.
    """
    db = await _dbcore.get_db()
    try:
        if device_id:
            cursor = await db.execute(
                "SELECT * FROM ("
                "SELECT * FROM upgrade_events WHERE campaign_id = ? AND device_id = ? "
                "ORDER BY timestamp DESC, id DESC LIMIT ?"
                ") AS recent ORDER BY timestamp ASC, id ASC",
                (campaign_id, device_id, limit),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM ("
                "SELECT * FROM upgrade_events WHERE campaign_id = ? "
                "ORDER BY timestamp DESC, id DESC LIMIT ?"
                ") AS recent ORDER BY timestamp ASC, id ASC",
                (campaign_id, limit),
            )
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


