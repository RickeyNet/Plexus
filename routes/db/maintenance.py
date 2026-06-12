"""Maintenance persistence helpers.

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
    "VALID_RECURRENCE",
    "VALID_WINDOW_POLICY",
    "VALID_APPROVAL_STATUS",
    "create_maintenance_window",
    "update_maintenance_window",
    "delete_maintenance_window",
    "get_maintenance_window",
    "list_maintenance_windows",
    "get_windows_for_groups",
    "set_group_environment",
    "set_deployment_approval",
]

# ═════════════════════════════════════════════════════════════════════════════
# Maintenance windows + deployment approval gates
# ═════════════════════════════════════════════════════════════════════════════

VALID_RECURRENCE = ("none", "daily", "weekly")
VALID_WINDOW_POLICY = ("allow_changes", "block_outside_window", "warn_outside_window")
VALID_APPROVAL_STATUS = ("not_required", "pending", "approved", "rejected")


async def create_maintenance_window(
    name: str,
    start_at: str,
    end_at: str,
    *,
    description: str = "",
    recurrence: str = "none",
    weekday_mask: int = 0,
    policy: str = "block_outside_window",
    enabled: bool = True,
    created_by: str = "",
    group_ids: list[int] | None = None,
) -> int:
    if recurrence not in VALID_RECURRENCE:
        raise ValueError(f"invalid recurrence '{recurrence}'")
    if policy not in VALID_WINDOW_POLICY:
        raise ValueError(f"invalid policy '{policy}'")
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO maintenance_windows
               (name, description, start_at, end_at, recurrence, weekday_mask,
                policy, enabled, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (name, description, start_at, end_at, recurrence, int(weekday_mask),
             policy, 1 if enabled else 0, created_by),
        )
        window_id = cursor.lastrowid
        for gid in group_ids or []:
            await db.execute(
                "INSERT OR IGNORE INTO maintenance_window_scopes (window_id, group_id) VALUES (?, ?)",
                (window_id, gid),
            )
        await db.commit()
        return window_id
    finally:
        await db.close()


async def update_maintenance_window(
    window_id: int,
    *,
    name: str | None = None,
    description: str | None = None,
    start_at: str | None = None,
    end_at: str | None = None,
    recurrence: str | None = None,
    weekday_mask: int | None = None,
    policy: str | None = None,
    enabled: bool | None = None,
    group_ids: list[int] | None = None,
) -> None:
    if recurrence is not None and recurrence not in VALID_RECURRENCE:
        raise ValueError(f"invalid recurrence '{recurrence}'")
    if policy is not None and policy not in VALID_WINDOW_POLICY:
        raise ValueError(f"invalid policy '{policy}'")
    sets: list[str] = []
    params: list = []
    for col, val in (
        ("name", name),
        ("description", description),
        ("start_at", start_at),
        ("end_at", end_at),
        ("recurrence", recurrence),
        ("weekday_mask", weekday_mask),
        ("policy", policy),
    ):
        if val is not None:
            sets.append(f"{col} = ?")
            params.append(val)
    if enabled is not None:
        sets.append("enabled = ?")
        params.append(1 if enabled else 0)
    db = await _dbcore.get_db()
    try:
        if sets:
            params.append(window_id)
            await db.execute(
                f"UPDATE maintenance_windows SET {', '.join(sets)} WHERE id = ?",
                tuple(params),
            )
        if group_ids is not None:
            await db.execute("DELETE FROM maintenance_window_scopes WHERE window_id = ?", (window_id,))
            for gid in group_ids:
                await db.execute(
                    "INSERT OR IGNORE INTO maintenance_window_scopes (window_id, group_id) VALUES (?, ?)",
                    (window_id, gid),
                )
        await db.commit()
    finally:
        await db.close()


async def delete_maintenance_window(window_id: int) -> None:
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM maintenance_windows WHERE id = ?", (window_id,))
        await db.commit()
    finally:
        await db.close()


async def get_maintenance_window(window_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM maintenance_windows WHERE id = ?", (window_id,)
        )
        row = row_to_dict(await cursor.fetchone())
        if not row:
            return None
        cursor = await db.execute(
            "SELECT group_id FROM maintenance_window_scopes WHERE window_id = ?",
            (window_id,),
        )
        row["group_ids"] = [r["group_id"] for r in await cursor.fetchall()]
        return row
    finally:
        await db.close()


async def list_maintenance_windows() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM maintenance_windows ORDER BY start_at DESC"
        )
        windows = rows_to_list(await cursor.fetchall())
        cursor = await db.execute(
            """SELECT s.window_id, s.group_id, g.name AS group_name
               FROM maintenance_window_scopes s
               LEFT JOIN inventory_groups g ON g.id = s.group_id"""
        )
        scopes = rows_to_list(await cursor.fetchall())
        by_window: dict[int, list[dict]] = {}
        for s in scopes:
            by_window.setdefault(s["window_id"], []).append(
                {"group_id": s["group_id"], "group_name": s["group_name"]}
            )
        for w in windows:
            w["scopes"] = by_window.get(w["id"], [])
            w["group_ids"] = [sc["group_id"] for sc in w["scopes"]]
        return windows
    finally:
        await db.close()


async def get_windows_for_groups(group_ids: list[int]) -> list[dict]:
    """Return enabled windows whose scope covers any of `group_ids`, plus
    windows with no scope (global). Used to decide if a change is allowed
    right now.
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT w.* FROM maintenance_windows w
               WHERE w.enabled = 1
                 AND NOT EXISTS (SELECT 1 FROM maintenance_window_scopes s WHERE s.window_id = w.id)"""
        )
        global_windows = rows_to_list(await cursor.fetchall())
        scoped_windows: list[dict] = []
        if group_ids:
            placeholders = ",".join("?" for _ in group_ids)
            cursor = await db.execute(
                f"""SELECT DISTINCT w.* FROM maintenance_windows w
                    JOIN maintenance_window_scopes s ON s.window_id = w.id
                    WHERE w.enabled = 1 AND s.group_id IN ({placeholders})""",
                tuple(group_ids),
            )
            scoped_windows = rows_to_list(await cursor.fetchall())
        # de-dup by id
        seen: set[int] = set()
        out: list[dict] = []
        for w in global_windows + scoped_windows:
            if w["id"] in seen:
                continue
            seen.add(w["id"])
            out.append(w)
        return out
    finally:
        await db.close()


async def set_group_environment(group_id: int, environment: str | None) -> None:
    """Set the production/staging/lab marker on an inventory group. Pass
    None to clear. Caller is responsible for validating the value if a
    closed vocabulary is desired -- the column is free-form text.
    """
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE inventory_groups SET environment = ? WHERE id = ?",
            (environment, group_id),
        )
        await db.commit()
    finally:
        await db.close()


async def set_deployment_approval(
    deployment_id: int,
    *,
    requires_approval: bool | None = None,
    approval_status: str | None = None,
    approved_by: str | None = None,
    approval_comment: str | None = None,
    request: bool = False,
) -> None:
    """Mutate approval state on a deployment.

    request=True stamps approval_requested_at=now and sets status to
    'pending'. When approval_status is 'approved' or 'rejected' the
    approved_at timestamp is stamped and approved_by stored.
    """
    if approval_status is not None and approval_status not in VALID_APPROVAL_STATUS:
        raise ValueError(f"invalid approval_status '{approval_status}'")
    sets: list[str] = []
    params: list = []
    if requires_approval is not None:
        sets.append("requires_approval = ?")
        params.append(1 if requires_approval else 0)
    if approval_status is not None:
        sets.append("approval_status = ?")
        params.append(approval_status)
    if approved_by is not None:
        sets.append("approved_by = ?")
        params.append(approved_by)
    if approval_comment is not None:
        sets.append("approval_comment = ?")
        params.append(approval_comment)
    if request:
        sets.append("approval_requested_at = datetime('now')")
    if approval_status in ("approved", "rejected"):
        sets.append("approved_at = datetime('now')")
    if not sets:
        return
    params.append(deployment_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(
            f"UPDATE deployments SET {', '.join(sets)} WHERE id = ?",
            tuple(params),
        )
        await db.commit()
    finally:
        await db.close()
