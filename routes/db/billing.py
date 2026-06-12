"""Billing persistence helpers.

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
    "create_billing_circuit",
    "get_billing_circuit",
    "list_billing_circuits",
    "update_billing_circuit",
    "delete_billing_circuit",
    "create_billing_period",
    "get_billing_period",
    "list_billing_periods",
    "delete_billing_period",
    "get_billing_samples_for_period",
    "get_billing_rollups_for_period",
    "get_billing_customers",
]

# ═════════════════════════════════════════════════════════════════════════════
# Bandwidth Billing – Circuits & 95th Percentile Reports
# ═════════════════════════════════════════════════════════════════════════════


async def create_billing_circuit(
    name: str,
    host_id: int,
    if_index: int,
    if_name: str = "",
    customer: str = "",
    description: str = "",
    commit_rate_bps: float = 0,
    burst_limit_bps: float = 0,
    billing_day: int = 1,
    billing_cycle: str = "monthly",
    cost_per_mbps: float = 0,
    currency: str = "USD",
    overage_enabled: int = 1,
    created_by: str = "",
) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO billing_circuits
               (name, description, customer, host_id, if_index, if_name,
                commit_rate_bps, burst_limit_bps, billing_day, billing_cycle,
                cost_per_mbps, currency, overage_enabled, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, description, customer, host_id, if_index, if_name,
             commit_rate_bps, burst_limit_bps, billing_day, billing_cycle,
             cost_per_mbps, currency, overage_enabled, created_by),
        )
        await db.commit()
        return await get_billing_circuit(cursor.lastrowid)
    finally:
        await db.close()


async def get_billing_circuit(circuit_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM billing_circuits WHERE id = ?", (circuit_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def list_billing_circuits(
    customer: str | None = None,
    host_id: int | None = None,
    enabled_only: bool = False,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if customer:
            clauses.append("bc.customer = ?")
            params.append(customer)
        if host_id is not None:
            clauses.append("bc.host_id = ?")
            params.append(host_id)
        if enabled_only:
            clauses.append("bc.enabled = 1")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT bc.*, h.hostname, h.ip_address
                FROM billing_circuits bc
                LEFT JOIN hosts h ON h.id = bc.host_id
                {where}
                ORDER BY bc.customer, bc.name""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def update_billing_circuit(circuit_id: int, **kwargs) -> dict | None:
    db = await _dbcore.get_db()
    try:
        allowed = {
            "name", "description", "customer", "if_name",
            "commit_rate_bps", "burst_limit_bps", "billing_day",
            "billing_cycle", "cost_per_mbps", "currency",
            "overage_enabled", "enabled",
        }
        sets = []
        vals = []
        for k, v in kwargs.items():
            if k in allowed and v is not None:
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return await get_billing_circuit(circuit_id)
        sets.append("updated_at = datetime('now')")
        sql, sql_params = _safe_dynamic_update("billing_circuits", sets, vals, "id = ?", circuit_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_billing_circuit(circuit_id)
    finally:
        await db.close()


async def delete_billing_circuit(circuit_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM billing_circuits WHERE id = ?", (circuit_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def create_billing_period(
    circuit_id: int,
    period_start: str,
    period_end: str,
    total_samples: int = 0,
    p95_in_bps: float = 0,
    p95_out_bps: float = 0,
    p95_billing_bps: float = 0,
    max_in_bps: float = 0,
    max_out_bps: float = 0,
    avg_in_bps: float = 0,
    avg_out_bps: float = 0,
    commit_rate_bps: float = 0,
    overage_bps: float = 0,
    overage_cost: float = 0,
    total_cost: float = 0,
    status: str = "generated",
) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO billing_periods
               (circuit_id, period_start, period_end, total_samples,
                p95_in_bps, p95_out_bps, p95_billing_bps,
                max_in_bps, max_out_bps, avg_in_bps, avg_out_bps,
                commit_rate_bps, overage_bps, overage_cost, total_cost, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (circuit_id, period_start, period_end, total_samples,
             p95_in_bps, p95_out_bps, p95_billing_bps,
             max_in_bps, max_out_bps, avg_in_bps, avg_out_bps,
             commit_rate_bps, overage_bps, overage_cost, total_cost, status),
        )
        await db.commit()
        return await get_billing_period(cursor.lastrowid)
    finally:
        await db.close()


async def get_billing_period(period_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT bp.*, bc.name AS circuit_name, bc.customer,
                      bc.if_name, h.hostname
               FROM billing_periods bp
               JOIN billing_circuits bc ON bc.id = bp.circuit_id
               LEFT JOIN hosts h ON h.id = bc.host_id
               WHERE bp.id = ?""",
            (period_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def list_billing_periods(
    circuit_id: int | None = None,
    customer: str | None = None,
    start_after: str | None = None,
    limit: int = 100,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if circuit_id is not None:
            clauses.append("bp.circuit_id = ?")
            params.append(circuit_id)
        if customer:
            clauses.append("bc.customer = ?")
            params.append(customer)
        if start_after:
            clauses.append("bp.period_start >= ?")
            params.append(start_after)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT bp.*, bc.name AS circuit_name, bc.customer,
                       bc.if_name, h.hostname
                FROM billing_periods bp
                JOIN billing_circuits bc ON bc.id = bp.circuit_id
                LEFT JOIN hosts h ON h.id = bc.host_id
                {where}
                ORDER BY bp.period_start DESC
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_billing_period(period_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM billing_periods WHERE id = ?", (period_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_billing_samples_for_period(
    host_id: int,
    if_index: int,
    period_start: str,
    period_end: str,
) -> list[dict]:
    """Fetch raw interface_ts samples for 95th percentile billing calculation."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT in_rate_bps, out_rate_bps, sampled_at
               FROM interface_ts
               WHERE host_id = ? AND if_index = ?
                 AND sampled_at >= ? AND sampled_at < ?
                 AND in_rate_bps IS NOT NULL
               ORDER BY sampled_at ASC""",
            (host_id, if_index, period_start, period_end),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_billing_rollups_for_period(
    host_id: int,
    if_index: int,
    period_start: str,
    period_end: str,
) -> list[dict]:
    """Fetch hourly rollups for longer billing periods (falls back from raw)."""
    db = await _dbcore.get_db()
    try:
        labels_pattern = f'%"if_index": {if_index}%'
        cursor = await db.execute(
            """SELECT val_min, val_avg, val_max, val_p95, sample_count,
                      period_start, period_end
               FROM metric_rollups
               WHERE host_id = ?
                 AND metric_name IN ('if_in_octets', 'if_out_octets')
                 AND labels_json LIKE ?
                 AND time_window = 'hourly'
                 AND period_start >= ? AND period_start < ?
               ORDER BY period_start ASC""",
            (host_id, labels_pattern, period_start, period_end),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_billing_customers() -> list[str]:
    """Get distinct customer names from billing circuits."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT DISTINCT customer FROM billing_circuits WHERE customer != '' ORDER BY customer"
        )
        return [r[0] for r in await cursor.fetchall()]
    finally:
        await db.close()


