"""Jobs persistence helpers.

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
    "get_all_jobs",
    "get_job",
    "create_job",
    "finish_job",
    "add_job_event",
    "add_job_events",
    "get_job_events",
    "delete_expired_jobs",
    "start_job",
    "cancel_job",
    "update_job_priority",
    "get_job_queue",
    "get_next_queued_job",
    "check_job_dependencies_met",
    "get_running_job_count",
    "reap_orphaned_running_jobs",
    "get_dashboard_stats",
]

# ═════════════════════════════════════════════════════════════════════════════
# Jobs
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_jobs(limit: int = 50) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("""
            SELECT j.*, p.name AS playbook_name, g.name AS group_name
            FROM jobs j
            JOIN playbooks p ON p.id = j.playbook_id
            LEFT JOIN inventory_groups g ON g.id = j.inventory_group_id
            ORDER BY j.id DESC LIMIT ?
        """, (limit,))
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_job(job_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("""
            SELECT j.*, p.name AS playbook_name, g.name AS group_name
            FROM jobs j
            JOIN playbooks p ON p.id = j.playbook_id
            LEFT JOIN inventory_groups g ON g.id = j.inventory_group_id
            WHERE j.id = ?
        """, (job_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_job(playbook_id: int, inventory_group_id: int | None,
                     credential_id: int | None = None,
                     template_id: int | None = None,
                     dry_run: bool = True,
                     launched_by: str = "admin",
                     priority: int = 2,
                     depends_on: list[int] | None = None,
                     host_ids: list[int] | None = None,
                     ad_hoc_ips: list[str] | None = None,
                     parameters: dict | None = None) -> int:
    db = await _dbcore.get_db()
    try:
        deps_json = json.dumps(depends_on or [])
        host_ids_json = json.dumps(host_ids) if host_ids else None
        ad_hoc_json = json.dumps(ad_hoc_ips) if ad_hoc_ips else None
        params_json = json.dumps(parameters) if parameters else None
        now = datetime.now(UTC).isoformat()
        cursor = await db.execute(
            """INSERT INTO jobs
               (playbook_id, inventory_group_id, credential_id, template_id,
                dry_run, status, priority, depends_on, queued_at, launched_by,
                host_ids, ad_hoc_ips, parameters)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (playbook_id, inventory_group_id, credential_id, template_id,
             1 if dry_run else 0, "queued", priority, deps_json, now, launched_by,
             host_ids_json, ad_hoc_json, params_json),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def finish_job(job_id: int, status: str, hosts_ok: int = 0,
                     hosts_failed: int = 0, hosts_skipped: int = 0):
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """UPDATE jobs SET status=?, finished_at=?, hosts_ok=?,
               hosts_failed=?, hosts_skipped=? WHERE id=?""",
            (status, datetime.now(UTC).isoformat(),
             hosts_ok, hosts_failed, hosts_skipped, job_id),
        )
        await db.commit()
    finally:
        await db.close()


async def add_job_event(job_id: int, level: str, message: str, host: str = ""):
    await add_job_events(job_id, [(level, message, host)])


async def add_job_events(job_id: int, events: list[tuple[str, str, str]]) -> None:
    """Persist multiple ordered job events in one transaction."""
    if not events:
        return
    db = await _dbcore.get_db()
    try:
        await db.executemany(
            "INSERT INTO job_events (job_id, level, host, message) VALUES (?,?,?,?)",
            [(job_id, level, host, message) for level, message, host in events],
        )
        await db.commit()
    finally:
        await db.close()


async def get_job_events(job_id: int, limit: int = 10000) -> list[dict]:
    """Return job events in chronological order, capped to the most recent
    ``limit``. A verbose multi-host job can emit tens of thousands of lines;
    both the REST endpoint and the WebSocket history replay bound the payload
    so a reconnect can't stream the whole unbounded log.
    """
    db = await _dbcore.get_db()
    try:
        safe_limit = max(1, int(limit))
        cursor = await db.execute(
            "SELECT * FROM (SELECT * FROM job_events WHERE job_id = ? "
            "ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
            (job_id, safe_limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_expired_jobs(retention_days: int) -> int:
    """Delete completed jobs older than retention_days and return deleted row count."""
    db = await _dbcore.get_db()
    try:
        safe_days = max(1, int(retention_days))
        if _dbcore.DB_ENGINE == "postgres":
            cursor = await db.execute(
                """
                DELETE FROM jobs
                WHERE status IN ('success', 'failed', 'cancelled')
                  AND COALESCE(finished_at, started_at, queued_at) IS NOT NULL
                  AND COALESCE(finished_at, started_at, queued_at)::timestamp <= (NOW() - (?::int * INTERVAL '1 day'))
                """,
                (safe_days,),
            )
        else:
            cursor = await db.execute(
                """
                DELETE FROM jobs
                WHERE status IN ('success', 'failed', 'cancelled')
                  AND COALESCE(finished_at, started_at, queued_at) IS NOT NULL
                  AND julianday(COALESCE(finished_at, started_at, queued_at)) <= julianday('now') - ?
                """,
                (safe_days,),
            )
        await db.commit()
        return cursor.rowcount or 0
    finally:
        await db.close()


async def start_job(job_id: int) -> None:
    """Transition a queued job to running status with started_at timestamp."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE jobs SET status = 'running', started_at = ? WHERE id = ? AND status = 'queued'",
            (datetime.now(UTC).isoformat(), job_id),
        )
        await db.commit()
    finally:
        await db.close()


async def cancel_job(job_id: int, cancelled_by: str = "") -> bool:
    """Cancel a queued or running job. Returns True if the job was updated."""
    db = await _dbcore.get_db()
    try:
        now = datetime.now(UTC).isoformat()
        cursor = await db.execute(
            """UPDATE jobs SET status = 'cancelled', cancelled_at = ?, cancelled_by = ?,
               finished_at = COALESCE(finished_at, ?)
               WHERE id = ? AND status IN ('queued', 'running')""",
            (now, cancelled_by, now, job_id),
        )
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


async def update_job_priority(job_id: int, priority: int) -> bool:
    """Update the priority of a queued job."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "UPDATE jobs SET priority = ? WHERE id = ? AND status = 'queued'",
            (max(0, min(4, priority)), job_id),
        )
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


async def get_job_queue() -> list[dict]:
    """Get all queued and running jobs ordered by priority (desc) then queued_at (asc)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT j.*, p.name AS playbook_name, g.name AS group_name
               FROM jobs j
               JOIN playbooks p ON p.id = j.playbook_id
               LEFT JOIN inventory_groups g ON g.id = j.inventory_group_id
               WHERE j.status IN ('queued', 'running')
               ORDER BY j.status = 'running' DESC, j.priority DESC, j.queued_at ASC"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_next_queued_job() -> dict | None:
    """Get the next job to run: highest priority first, then earliest queued."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT j.* FROM jobs j
               WHERE j.status = 'queued'
               ORDER BY j.priority DESC, j.queued_at ASC
               LIMIT 1"""
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def check_job_dependencies_met(job_id: int) -> bool:
    """Check if all dependency jobs have completed successfully."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT depends_on FROM jobs WHERE id = ?", (job_id,))
        row = await cursor.fetchone()
        if not row:
            return True
        deps = json.loads(row[0] or "[]")
        if not deps:
            return True
        placeholders = ",".join("?" for _ in deps)
        cursor = await db.execute(
            f"""SELECT COUNT(*) FROM jobs
                WHERE id IN ({placeholders}) AND status != 'success'""",
            tuple(deps),
        )
        unmet = (await cursor.fetchone())[0]
        return unmet == 0
    finally:
        await db.close()


async def get_running_job_count() -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM jobs WHERE status = 'running'")
        return (await cursor.fetchone())[0]
    finally:
        await db.close()


async def reap_orphaned_running_jobs() -> list[int]:
    """Mark jobs left in 'running' by a crashed/restarted process as 'failed'.

    A job only leaves 'running' when its in-process asyncio task calls
    finish_job. If the process died mid-run, the row stays 'running' forever
    and keeps counting against the concurrency gate (get_running_job_count),
    which can permanently wedge the queue after a restart. Called once at
    startup. Re-queuing is deliberately avoided: an interrupted config/
    firmware push must not silently re-execute - the operator re-runs it.

    Returns the affected job ids so the caller can emit job events.
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT id FROM jobs WHERE status = 'running'")
        ids = [row[0] for row in await cursor.fetchall()]
        if ids:
            await db.execute(
                "UPDATE jobs SET status = 'failed', finished_at = ? WHERE status = 'running'",
                (datetime.now(UTC).isoformat(),),
            )
            await db.commit()
        return ids
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Dashboard Stats
# ═════════════════════════════════════════════════════════════════════════════

async def get_dashboard_stats() -> dict:
    db = await _dbcore.get_db()
    try:
        total_hosts = (await (await db.execute("SELECT COUNT(*) FROM hosts")).fetchone())[0]
        total_groups = (await (await db.execute("SELECT COUNT(*) FROM inventory_groups")).fetchone())[0]
        total_playbooks = (await (await db.execute("SELECT COUNT(*) FROM playbooks")).fetchone())[0]
        total_jobs = (await (await db.execute("SELECT COUNT(*) FROM jobs")).fetchone())[0]
        running_jobs = (await (await db.execute(
            "SELECT COUNT(*) FROM jobs WHERE status='running'"
        )).fetchone())[0]
        successful_jobs = (await (await db.execute(
            "SELECT COUNT(*) FROM jobs WHERE status='success'"
        )).fetchone())[0]
        completed_jobs = (await (await db.execute(
            "SELECT COUNT(*) FROM jobs WHERE status IN ('success','failed')"
        )).fetchone())[0]
        success_rate = round(successful_jobs / completed_jobs * 100) if completed_jobs > 0 else 0

        return {
            "total_hosts": total_hosts,
            "total_groups": total_groups,
            "total_playbooks": total_playbooks,
            "total_jobs": total_jobs,
            "running_jobs": running_jobs,
            "success_rate": success_rate,
        }
    finally:
        await db.close()


