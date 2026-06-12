"""Lab persistence helpers.

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
    "create_lab_environment",
    "list_lab_environments",
    "get_lab_environment",
    "update_lab_environment",
    "delete_lab_environment",
    "create_lab_device",
    "list_lab_devices",
    "get_lab_device",
    "update_lab_device",
    "delete_lab_device",
    "create_lab_run",
    "list_lab_runs",
    "get_lab_run",
    "update_lab_run_status",
    "update_lab_device_runtime",
    "add_lab_runtime_event",
    "list_lab_runtime_events",
    "list_running_lab_devices",
    "create_lab_topology",
    "list_lab_topologies",
    "get_lab_topology",
    "update_lab_topology_status",
    "delete_lab_topology",
    "set_lab_device_topology",
    "list_topology_devices",
    "create_lab_topology_link",
    "list_topology_links",
    "delete_lab_topology_link",
    "list_running_lab_topologies",
    "create_lab_drift_run",
    "list_lab_drift_runs",
    "get_lab_drift_run",
    "get_latest_lab_drift_run",
    "list_drift_eligible_devices",
]

# ═════════════════════════════════════════════════════════════════════════════
# Digital Twin / Lab Mode (migration 0029)
# ═════════════════════════════════════════════════════════════════════════════

async def create_lab_environment(
    name: str,
    description: str = "",
    owner_id: int | None = None,
    shared: bool = False,
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO lab_environments (name, description, owner_id, shared, active)
               VALUES (?,?,?,?,1)""",
            (name, description, owner_id, 1 if shared else 0),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_lab_environments(user_id: int | None = None, is_admin: bool = False) -> list[dict]:
    """List visible environments. Admins see all; non-admins see their own + shared."""
    db = await _dbcore.get_db()
    try:
        if is_admin or user_id is None:
            cursor = await db.execute(
                """SELECT e.*, COUNT(d.id) AS device_count
                   FROM lab_environments e
                   LEFT JOIN lab_devices d ON d.environment_id = e.id
                   GROUP BY e.id
                   ORDER BY e.name"""
            )
        else:
            cursor = await db.execute(
                """SELECT e.*, COUNT(d.id) AS device_count
                   FROM lab_environments e
                   LEFT JOIN lab_devices d ON d.environment_id = e.id
                   WHERE e.owner_id = ? OR e.shared = 1 OR e.owner_id IS NULL
                   GROUP BY e.id
                   ORDER BY e.name""",
                (user_id,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_lab_environment(env_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM lab_environments WHERE id = ?", (env_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_lab_environment(
    env_id: int,
    name: str | None = None,
    description: str | None = None,
    shared: bool | None = None,
    active: bool | None = None,
) -> bool:
    fields = []
    values: list = []
    if name is not None:
        fields.append("name = ?")
        values.append(name)
    if description is not None:
        fields.append("description = ?")
        values.append(description)
    if shared is not None:
        fields.append("shared = ?")
        values.append(1 if shared else 0)
    if active is not None:
        fields.append("active = ?")
        values.append(1 if active else 0)
    if not fields:
        return False
    fields.append("updated_at = ?")
    values.append(datetime.now(UTC).isoformat())
    sql, params = _safe_dynamic_update(
        "lab_environments", fields, values, "id = ?", env_id,
    )
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def delete_lab_environment(env_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM lab_environments WHERE id = ?", (env_id,),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def create_lab_device(
    environment_id: int,
    hostname: str,
    ip_address: str = "",
    device_type: str = "cisco_ios",
    model: str = "",
    source_host_id: int | None = None,
    running_config: str = "",
    notes: str = "",
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO lab_devices
               (environment_id, hostname, ip_address, device_type, model,
                source_host_id, running_config, notes)
               VALUES (?,?,?,?,?,?,?,?)""",
            (environment_id, hostname, ip_address, device_type, model,
             source_host_id, running_config, notes),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_lab_devices(environment_id: int) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT d.id, d.environment_id, d.hostname, d.ip_address,
                      d.device_type, d.model, d.source_host_id, d.notes,
                      d.created_at, d.updated_at,
                      LENGTH(d.running_config) AS config_size,
                      d.runtime_kind, d.runtime_status, d.runtime_mgmt_address,
                      d.runtime_node_kind, d.runtime_image,
                      (SELECT COUNT(*) FROM lab_runs r WHERE r.lab_device_id = d.id) AS run_count
               FROM lab_devices d
               WHERE d.environment_id = ?
               ORDER BY d.hostname""",
            (environment_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_lab_device(device_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM lab_devices WHERE id = ?", (device_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_lab_device(
    device_id: int,
    hostname: str | None = None,
    ip_address: str | None = None,
    device_type: str | None = None,
    model: str | None = None,
    running_config: str | None = None,
    notes: str | None = None,
) -> bool:
    fields = []
    values: list = []
    if hostname is not None:
        fields.append("hostname = ?")
        values.append(hostname)
    if ip_address is not None:
        fields.append("ip_address = ?")
        values.append(ip_address)
    if device_type is not None:
        fields.append("device_type = ?")
        values.append(device_type)
    if model is not None:
        fields.append("model = ?")
        values.append(model)
    if running_config is not None:
        fields.append("running_config = ?")
        values.append(running_config)
    if notes is not None:
        fields.append("notes = ?")
        values.append(notes)
    if not fields:
        return False
    fields.append("updated_at = ?")
    values.append(datetime.now(UTC).isoformat())
    sql, params = _safe_dynamic_update(
        "lab_devices", fields, values, "id = ?", device_id,
    )
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def delete_lab_device(device_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM lab_devices WHERE id = ?", (device_id,),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def create_lab_run(
    lab_device_id: int,
    submitted_by: str,
    commands: list[str],
    pre_config: str,
    post_config: str,
    diff_text: str,
    diff_added: int,
    diff_removed: int,
    risk_score: float = 0.0,
    risk_level: str = "",
    risk_detail: dict | None = None,
    status: str = "simulated",
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO lab_runs
               (lab_device_id, submitted_by, commands, pre_config, post_config,
                diff_text, diff_added, diff_removed, risk_score, risk_level,
                risk_detail, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                lab_device_id, submitted_by,
                json.dumps(commands or []),
                pre_config, post_config, diff_text, diff_added, diff_removed,
                float(risk_score), risk_level,
                json.dumps(risk_detail or {}),
                status,
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_lab_runs(lab_device_id: int, limit: int = 50) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT id, lab_device_id, submitted_by, diff_added, diff_removed,
                      risk_score, risk_level, status, promoted_deployment_id,
                      created_at
               FROM lab_runs
               WHERE lab_device_id = ?
               ORDER BY id DESC LIMIT ?""",
            (lab_device_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_lab_run(run_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM lab_runs WHERE id = ?", (run_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_lab_run_status(
    run_id: int,
    status: str,
    promoted_deployment_id: int | None = None,
) -> bool:
    db = await _dbcore.get_db()
    try:
        if promoted_deployment_id is not None:
            cursor = await db.execute(
                "UPDATE lab_runs SET status = ?, promoted_deployment_id = ? WHERE id = ?",
                (status, promoted_deployment_id, run_id),
            )
        else:
            cursor = await db.execute(
                "UPDATE lab_runs SET status = ? WHERE id = ?",
                (status, run_id),
            )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ── Phase B-1: containerlab runtime helpers ──────────────────────────────────


async def update_lab_device_runtime(
    device_id: int,
    *,
    runtime_kind: str | None = None,
    runtime_node_kind: str | None = None,
    runtime_image: str | None = None,
    runtime_status: str | None = None,
    runtime_lab_name: str | None = None,
    runtime_node_name: str | None = None,
    runtime_mgmt_address: str | None = None,
    runtime_credential_id: int | None | object = ...,
    runtime_error: str | None = None,
    runtime_workdir: str | None = None,
    runtime_started_at: str | None | object = ...,
) -> bool:
    """Update runtime fields on a lab device. Skips fields left as the default sentinel."""
    fields: list[str] = []
    values: list = []
    if runtime_kind is not None:
        fields.append("runtime_kind = ?")
        values.append(runtime_kind)
    if runtime_node_kind is not None:
        fields.append("runtime_node_kind = ?")
        values.append(runtime_node_kind)
    if runtime_image is not None:
        fields.append("runtime_image = ?")
        values.append(runtime_image)
    if runtime_status is not None:
        fields.append("runtime_status = ?")
        values.append(runtime_status)
    if runtime_lab_name is not None:
        fields.append("runtime_lab_name = ?")
        values.append(runtime_lab_name)
    if runtime_node_name is not None:
        fields.append("runtime_node_name = ?")
        values.append(runtime_node_name)
    if runtime_mgmt_address is not None:
        fields.append("runtime_mgmt_address = ?")
        values.append(runtime_mgmt_address)
    if runtime_credential_id is not ...:
        fields.append("runtime_credential_id = ?")
        values.append(runtime_credential_id)
    if runtime_error is not None:
        fields.append("runtime_error = ?")
        values.append(runtime_error)
    if runtime_workdir is not None:
        fields.append("runtime_workdir = ?")
        values.append(runtime_workdir)
    if runtime_started_at is not ...:
        fields.append("runtime_started_at = ?")
        values.append(runtime_started_at)
    if not fields:
        return False
    fields.append("updated_at = ?")
    values.append(datetime.now(UTC).isoformat())
    sql, params = _safe_dynamic_update(
        "lab_devices", fields, values, "id = ?", device_id,
    )
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def add_lab_runtime_event(
    lab_device_id: int,
    action: str,
    status: str = "ok",
    actor: str = "",
    detail: str = "",
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO lab_runtime_events
               (lab_device_id, action, status, actor, detail)
               VALUES (?,?,?,?,?)""",
            (lab_device_id, action, status, actor, detail),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_lab_runtime_events(lab_device_id: int, limit: int = 50) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT id, lab_device_id, action, status, actor, detail, created_at
               FROM lab_runtime_events
               WHERE lab_device_id = ?
               ORDER BY id DESC LIMIT ?""",
            (lab_device_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def list_running_lab_devices() -> list[dict]:
    """Return all lab devices currently in `provisioning` or `running` state.

    Used at startup to reconcile in-memory state with whatever containerlab is
    actually still running (or to surface stale rows after a crash).
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM lab_devices
               WHERE runtime_kind = 'containerlab'
                 AND runtime_status IN ('provisioning','running')"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ── Phase B-2: lab topologies (multi-device) ────────────────────────────────


async def create_lab_topology(
    environment_id: int,
    name: str,
    description: str = "",
    mgmt_subnet: str = "",
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO lab_topologies
               (environment_id, name, description, mgmt_subnet)
               VALUES (?, ?, ?, ?)""",
            (environment_id, name, description, mgmt_subnet),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_lab_topologies(environment_id: int) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT t.*,
                      (SELECT COUNT(*) FROM lab_devices d WHERE d.topology_id = t.id) AS device_count,
                      (SELECT COUNT(*) FROM lab_topology_links l WHERE l.topology_id = t.id) AS link_count
               FROM lab_topologies t
               WHERE t.environment_id = ?
               ORDER BY t.name""",
            (environment_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_lab_topology(topology_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM lab_topologies WHERE id = ?", (topology_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_lab_topology_status(
    topology_id: int,
    *,
    status: str | None = None,
    lab_name: str | None = None,
    workdir: str | None = None,
    error: str | None = None,
    started_at: str | None | object = ...,
) -> bool:
    fields: list[str] = []
    values: list = []
    if status is not None:
        fields.append("status = ?")
        values.append(status)
    if lab_name is not None:
        fields.append("lab_name = ?")
        values.append(lab_name)
    if workdir is not None:
        fields.append("workdir = ?")
        values.append(workdir)
    if error is not None:
        fields.append("error = ?")
        values.append(error)
    if started_at is not ...:
        fields.append("started_at = ?")
        values.append(started_at)
    if not fields:
        return False
    fields.append("updated_at = ?")
    values.append(datetime.now(UTC).isoformat())
    sql, params = _safe_dynamic_update(
        "lab_topologies", fields, values, "id = ?", topology_id,
    )
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def delete_lab_topology(topology_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM lab_topologies WHERE id = ?", (topology_id,),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def set_lab_device_topology(device_id: int, topology_id: int | None) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "UPDATE lab_devices SET topology_id = ?, updated_at = ? WHERE id = ?",
            (topology_id, datetime.now(UTC).isoformat(), device_id),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def list_topology_devices(topology_id: int) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM lab_devices
               WHERE topology_id = ?
               ORDER BY hostname""",
            (topology_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def create_lab_topology_link(
    topology_id: int,
    a_device_id: int,
    a_endpoint: str,
    b_device_id: int,
    b_endpoint: str,
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO lab_topology_links
               (topology_id, a_device_id, a_endpoint, b_device_id, b_endpoint)
               VALUES (?, ?, ?, ?, ?)""",
            (topology_id, a_device_id, a_endpoint, b_device_id, b_endpoint),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_topology_links(topology_id: int) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM lab_topology_links WHERE topology_id = ? ORDER BY id",
            (topology_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_lab_topology_link(link_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM lab_topology_links WHERE id = ?", (link_id,),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def list_running_lab_topologies() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM lab_topologies
               WHERE status IN ('provisioning','running')"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ── Phase B-3a: drift-from-twin ─────────────────────────────────────────────


async def create_lab_drift_run(
    lab_device_id: int,
    source_host_id: int | None,
    status: str,
    diff_text: str = "",
    diff_added: int = 0,
    diff_removed: int = 0,
    twin_bytes: int = 0,
    prod_bytes: int = 0,
    actor: str = "",
    error: str = "",
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO lab_drift_runs
               (lab_device_id, source_host_id, status, diff_text,
                diff_added, diff_removed, twin_bytes, prod_bytes, actor, error)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (lab_device_id, source_host_id, status, diff_text,
             diff_added, diff_removed, twin_bytes, prod_bytes, actor, error),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_lab_drift_runs(lab_device_id: int, limit: int = 50) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT id, lab_device_id, source_host_id, status,
                      diff_added, diff_removed, twin_bytes, prod_bytes,
                      actor, error, checked_at
               FROM lab_drift_runs
               WHERE lab_device_id = ?
               ORDER BY id DESC LIMIT ?""",
            (lab_device_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_lab_drift_run(run_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM lab_drift_runs WHERE id = ?", (run_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def get_latest_lab_drift_run(lab_device_id: int) -> dict | None:
    """Return the most recent drift run for a lab device, sans diff_text."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT id, lab_device_id, source_host_id, status,
                      diff_added, diff_removed, twin_bytes, prod_bytes,
                      actor, error, checked_at
               FROM lab_drift_runs
               WHERE lab_device_id = ?
               ORDER BY id DESC LIMIT 1""",
            (lab_device_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def list_drift_eligible_devices() -> list[dict]:
    """Lab devices with a source host attached - the only ones drift checks
    can compare. Used by the scheduler to decide what to walk each tick.
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT id, environment_id, hostname, source_host_id, running_config
               FROM lab_devices
               WHERE source_host_id IS NOT NULL"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


