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
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

import routes.database as _dbcore
from routes.database import (
    _LOGGER,
    _is_unique_violation,
    row_to_dict,
    rows_to_list,
)
from routes.db.change_events import tracks_changes

__all__ = [
    "host_ids_json_condition",
    "job_scope_condition",
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
    "JOB_PENDING_APPROVAL",
    "JOB_DENIED",
    "decide_job_approval",
    "get_jobs_pending_approval",
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

# A job whose playbook needs approval waits here; the queue never starts it.
JOB_PENDING_APPROVAL = "pending_approval"
# A job whose approval was denied (terminal).
JOB_DENIED = "denied"


def host_ids_json_condition(column: str, group_ids: Iterable[int] | None) -> tuple[str, tuple[int, ...]]:
    """A SQL condition (and its parameters) keeping rows whose ``column`` (a
    JSON list of host ids stored as text, e.g. ``jobs.host_ids``) names only
    hosts in ``group_ids`` (object-level permissions): an unknown host or one
    in no group fails; an empty or NULL list passes. ``None``: no condition.
    ``column`` is a fixed identifier."""
    if group_ids is None:
        return "", ()
    ids = tuple(sorted({int(g) for g in group_ids}))
    if not ids:
        return "1 = 0", ()
    marks = ",".join("?" * len(ids))
    return (
        "NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text("
        f"(CASE WHEN COALESCE({column}, '') IN ('', 'null') THEN '[]' ELSE {column} END)::jsonb) AS scope_t(v)"
        " LEFT JOIN hosts scope_h ON scope_h.id = scope_t.v::bigint"
        f" WHERE scope_h.group_id IS NULL OR scope_h.group_id NOT IN ({marks}))",
        ids,
    )


def job_scope_condition(
    group_ids: Iterable[int] | None, launched_by: str | None = None, alias: str = "j"
) -> tuple[str, tuple]:
    """A SQL condition (and its parameters) keeping the jobs whose every
    target is in ``group_ids`` (object-level permissions, see
    ``netcontrol.routes.jobs.job_visible``): no ad-hoc addresses; the stored
    host selection all in those groups (an unknown host fails), else a
    dynamic group job launched by ``launched_by`` (resolved within that
    user's own scope), else the job's inventory group in those groups.
    ``None``: no condition. ``alias`` is a fixed identifier."""
    if group_ids is None:
        return "", ()
    ids = tuple(sorted({int(g) for g in group_ids}))
    if not ids:
        return "1 = 0", ()
    a = alias
    hosts_sql, hosts_params = host_ids_json_condition(f"{a}.host_ids", ids)
    sql = (
        f"(COALESCE({a}.ad_hoc_ips, '') IN ('', '[]', 'null') AND CASE"
        f" WHEN COALESCE({a}.host_ids, '') NOT IN ('', '[]', 'null') THEN {hosts_sql}"
        f" WHEN {a}.dynamic_group_id IS NOT NULL THEN {a}.launched_by = ?"
        f" ELSE {a}.inventory_group_id IN ({','.join('?' * len(ids))}) END)"
    )
    return sql, (*hosts_params, launched_by or "", *ids)


def launched_by_condition(cond: str, params: tuple, username: str | None, alias: str = "j") -> tuple[str, tuple]:
    """``cond`` (and its parameters) narrowed to the jobs ``username``
    launched; unchanged for ``None``. ``alias`` is a fixed identifier."""
    if username is None:
        return cond, params
    own = f"{alias}.launched_by = ?"
    return (f"({cond}) AND {own}" if cond else own), (*params, username)


async def get_all_jobs(
    limit: int = 50,
    *,
    group_ids: Iterable[int] | None = None,
    launched_by: str | None = None,
    only_launched_by: str | None = None,
) -> list[dict]:
    """The newest jobs. ``group_ids`` (object scope): only jobs whose every
    target is in those inventory groups (``job_scope_condition``).
    ``only_launched_by``: only the jobs that user launched."""
    cond, cond_params = launched_by_condition(*job_scope_condition(group_ids, launched_by), only_launched_by)
    where = f"WHERE {cond}" if cond else ""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""
            SELECT j.*, p.name AS playbook_name, g.name AS group_name, dg.name AS dynamic_group_name
            FROM jobs j
            JOIN playbooks p ON p.id = j.playbook_id
            LEFT JOIN inventory_groups g ON g.id = j.inventory_group_id
            LEFT JOIN dynamic_groups dg ON dg.id = j.dynamic_group_id
            {where}
            ORDER BY j.id DESC LIMIT ?
        """,  # nosec B608
            (*cond_params, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_job(job_id: int) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """
            SELECT j.*, p.name AS playbook_name, g.name AS group_name, dg.name AS dynamic_group_name
            FROM jobs j
            JOIN playbooks p ON p.id = j.playbook_id
            LEFT JOIN inventory_groups g ON g.id = j.inventory_group_id
            LEFT JOIN dynamic_groups dg ON dg.id = j.dynamic_group_id
            WHERE j.id = ?
        """,
            (job_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


@tracks_changes("job", "create")
async def create_job(
    playbook_id: int,
    inventory_group_id: int | None,
    credential_id: int | None = None,
    template_id: int | None = None,
    dry_run: bool = True,
    launched_by: str = "admin",
    priority: int = 2,
    depends_on: list[int] | None = None,
    host_ids: list[int] | None = None,
    ad_hoc_ips: list[str] | None = None,
    parameters: dict | None = None,
    dynamic_group_id: int | None = None,
    approval_required: bool = False,
) -> int:
    """Store a new job. ``approval_required``: it waits in
    ``pending_approval`` (never started by the queue) instead of ``queued``."""
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
                host_ids, ad_hoc_ips, parameters, dynamic_group_id, approval_status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                playbook_id,
                inventory_group_id,
                credential_id,
                template_id,
                1 if dry_run else 0,
                JOB_PENDING_APPROVAL if approval_required else "queued",
                priority,
                deps_json,
                now,
                launched_by,
                host_ids_json,
                ad_hoc_json,
                params_json,
                dynamic_group_id,
                "pending" if approval_required else "not_required",
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


@tracks_changes("job", "update", id_arg="job_id")
async def finish_job(job_id: int, status: str, hosts_ok: int = 0, hosts_failed: int = 0, hosts_skipped: int = 0):
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """UPDATE jobs SET status=?, finished_at=?, hosts_ok=?,
               hosts_failed=?, hosts_skipped=? WHERE id=?""",
            (status, datetime.now(UTC).isoformat(), hosts_ok, hosts_failed, hosts_skipped, job_id),
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
    db = await _dbcore.get_db(read_only=True)
    try:
        safe_limit = max(1, int(limit))
        cursor = await db.execute(
            "SELECT * FROM (SELECT * FROM job_events WHERE job_id = ? ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
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
        cursor = await db.execute(
            """
            DELETE FROM jobs
            WHERE status IN ('success', 'failed', 'cancelled', 'denied')
              AND COALESCE(finished_at, started_at, queued_at) IS NOT NULL
              AND COALESCE(finished_at, started_at, queued_at)::timestamp <= (NOW() - (?::int * INTERVAL '1 day'))
            """,
            (safe_days,),
        )
        await db.commit()
        return cursor.rowcount or 0
    finally:
        await db.close()


@tracks_changes("job", "update", id_arg="job_id")
async def start_job(job_id: int) -> bool:
    """Transition a queued job to running with started_at timestamp.

    Returns True only when this call won the queued→running transition; a
    False return means another path (a concurrent queue kick, a cancel)
    already moved the job, and the caller must NOT launch the runner."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "UPDATE jobs SET status = 'running', started_at = ? WHERE id = ? AND status = 'queued'",
            (datetime.now(UTC).isoformat(), job_id),
        )
        await db.commit()
        return cursor.rowcount == 1
    finally:
        await db.close()


@tracks_changes("job", "update", id_arg="job_id")
async def cancel_job(job_id: int, cancelled_by: str = "") -> bool:
    """Cancel a job awaiting approval, queued or running. Returns True if
    the job was updated."""
    db = await _dbcore.get_db()
    try:
        now = datetime.now(UTC).isoformat()
        cursor = await db.execute(
            """UPDATE jobs SET status = 'cancelled', cancelled_at = ?, cancelled_by = ?,
               finished_at = COALESCE(finished_at, ?)
               WHERE id = ? AND status IN ('pending_approval', 'queued', 'running')""",
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


@tracks_changes("job", "update", id_arg="job_id")
async def decide_job_approval(job_id: int, *, approve: bool, decided_by: str, comment: str = "") -> bool:
    """Record an approval decision on a job awaiting approval: approved moves
    it to ``queued`` (the queue picks it up as usual), denied to ``denied``
    (terminal). Returns False when the job was no longer awaiting approval
    (another decision or a cancel won)."""
    now = datetime.now(UTC).isoformat()
    if approve:
        sql = (
            "UPDATE jobs SET status = 'queued', approval_status = 'approved', approved_by = ?,"
            " approved_at = ?, approval_comment = ? WHERE id = ? AND status = ?"
        )
        params: tuple = (decided_by, now, comment, job_id, JOB_PENDING_APPROVAL)
    else:
        sql = (
            "UPDATE jobs SET status = ?, approval_status = 'denied', approved_by = ?,"
            " approved_at = ?, approval_comment = ?, finished_at = ? WHERE id = ? AND status = ?"
        )
        params = (JOB_DENIED, decided_by, now, comment, now, job_id, JOB_PENDING_APPROVAL)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return (cursor.rowcount or 0) == 1
    finally:
        await db.close()


async def get_jobs_pending_approval(
    *,
    group_ids: Iterable[int] | None = None,
    launched_by: str | None = None,
    exclude_launched_by: str | None = None,
    limit: int = 200,
) -> list[dict]:
    """Jobs awaiting approval, oldest first. ``group_ids`` (object scope):
    only jobs whose every target is in those inventory groups
    (``job_scope_condition``); ``exclude_launched_by``: leave out the jobs
    this user launched (they cannot approve their own)."""
    cond, cond_params = job_scope_condition(group_ids, launched_by)
    extra = f" AND {cond}" if cond else ""
    params: list = [JOB_PENDING_APPROVAL, *cond_params]
    if exclude_launched_by:
        extra += " AND COALESCE(j.launched_by, '') <> ?"
        params.append(exclude_launched_by)
    params.append(max(1, int(limit)))
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT j.*, p.name AS playbook_name, g.name AS group_name, dg.name AS dynamic_group_name
               FROM jobs j
               JOIN playbooks p ON p.id = j.playbook_id
               LEFT JOIN inventory_groups g ON g.id = j.inventory_group_id
               LEFT JOIN dynamic_groups dg ON dg.id = j.dynamic_group_id
               WHERE j.status = ?{extra}
               ORDER BY j.queued_at ASC, j.id ASC LIMIT ?""",  # nosec B608 - fixed clauses, values bound
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_job_queue(*, group_ids: Iterable[int] | None = None, launched_by: str | None = None) -> list[dict]:
    """Get all queued and running jobs ordered by priority (desc) then
    queued_at (asc). ``group_ids`` (object scope): only jobs whose every
    target is in those inventory groups (``job_scope_condition``)."""
    cond, cond_params = job_scope_condition(group_ids, launched_by)
    extra = f" AND {cond}" if cond else ""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT j.*, p.name AS playbook_name, g.name AS group_name
               FROM jobs j
               JOIN playbooks p ON p.id = j.playbook_id
               LEFT JOIN inventory_groups g ON g.id = j.inventory_group_id
               WHERE j.status IN ('queued', 'running'){extra}
               ORDER BY j.status = 'running' DESC, j.priority DESC, j.queued_at ASC""",  # nosec B608
            cond_params,
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_next_queued_job() -> dict | None:
    """Get the next job to run: highest priority first, then earliest queued."""
    db = await _dbcore.get_db(read_only=True)
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
    db = await _dbcore.get_db(read_only=True)
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
    db = await _dbcore.get_db(read_only=True)
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
    # One round-trip, one pass over jobs (was seven separate COUNT scans,
    # four of them over jobs), on a read-pool connection.
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """SELECT
                   (SELECT COUNT(*) FROM hosts),
                   (SELECT COUNT(*) FROM inventory_groups),
                   (SELECT COUNT(*) FROM playbooks),
                   COUNT(*),
                   COALESCE(SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END), 0),
                   COALESCE(SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END), 0),
                   COALESCE(SUM(CASE WHEN status IN ('success', 'failed') THEN 1 ELSE 0 END), 0)
               FROM jobs"""
        )
        row = await cursor.fetchone()
        total_hosts, total_groups, total_playbooks, total_jobs, running_jobs, successful_jobs, completed_jobs = row
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
