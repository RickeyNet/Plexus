"""Sync framework storage: connections, jobs, runs and run entries.

Tables: migration 0104. Imported directly (``import routes.db.sync``) by
``netcontrol.sync.runner`` and ``netcontrol.routes.sync``; the logic lives
there, this module only reads and writes rows. Names of connections and
jobs are unique ignoring case. A connection names a service credential by
id; the secret itself stays in ``credentials`` (encrypted).

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

import routes.database as _dbcore
from routes.database import _is_foreign_key_violation
from routes.db.custom_fields import _now
from routes.db.device_model import _insert, _select, _update

__all__ = [
    "ConnectionInUse",
    "claim_job_attempt",
    "create_connection",
    "create_job",
    "create_run",
    "delete_connection",
    "delete_job",
    "fail_stale_runs",
    "finish_run",
    "get_connection",
    "get_job",
    "get_run",
    "list_connections",
    "list_jobs",
    "list_run_entries",
    "list_runs",
    "prune_runs",
    "set_connection_test",
]

# Runs kept per job; older ones (and their entries) are pruned.
RUNS_KEPT_PER_JOB = 50
# Most entries one run stores; the summary still counts every one.
MAX_ENTRIES_PER_RUN = 20_000


class ConnectionInUse(ValueError):
    """The connection is used by sync jobs."""


def _json(text: str | None, default: Any) -> Any:
    try:
        value = json.loads(text or "")
    except ValueError:
        return default
    return value if isinstance(value, type(default)) else default


def _stamps(row: dict) -> dict:
    return {
        "created_by": row.get("created_by") or "",
        "created_at": row.get("created_at") or "",
        "updated_at": row.get("updated_at") or "",
        "updated_by": row.get("updated_by") or "",
    }


def _taken(what: str, name: str) -> ValueError:
    return ValueError(f"A sync {what} named '{name}' already exists.")


async def _name_taken(table: str, name: str, record_id: int | None) -> bool:
    rows = await _select(f"SELECT id FROM {table} WHERE lower(name) = lower(?)", (name,))  # nosec B608 - fixed table names
    return any(int(r["id"]) != record_id for r in rows)


async def _execute(sql: str, params: tuple = ()) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return int(cursor.rowcount or 0)
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


# ── Connections ──────────────────────────────────────────────────────────────

_CONNECTION_SELECT = """
    SELECT c.*, cr.name AS credential_name,
           (SELECT COUNT(*) FROM sync_jobs j WHERE j.connection_id = c.id) AS job_count
    FROM sync_connections c
    LEFT JOIN credentials cr ON cr.id = c.credential_id
"""


def _connection(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "kind": row["kind"],
        "base_url": row["base_url"],
        "auth_type": row["auth_type"],
        "credential_id": int(row["credential_id"]) if row["credential_id"] is not None else None,
        "credential_name": row["credential_name"] or "",
        "verify_tls": bool(row["verify_tls"]),
        "has_ca_pem": bool((row["ca_pem"] or "").strip()),
        "timeout_seconds": int(row["timeout_seconds"]),
        "description": row["description"] or "",
        "last_test_at": row["last_test_at"] or "",
        "last_test_ok": None if row["last_test_ok"] is None else bool(row["last_test_ok"]),
        "last_test_message": row["last_test_message"] or "",
        "job_count": int(row["job_count"]),
        **_stamps(row),
    }


def _written(values: dict, user: str, *, create: bool) -> dict:
    out = dict(values)
    for key in ("verify_tls", "enabled", "delete_missing"):
        if key in out:
            out[key] = 1 if out[key] else 0
    for key in ("object_types", "mappings", "options"):
        if key in out and not isinstance(out[key], str):
            out[key] = json.dumps(out[key])
    out["updated_at"] = _now()
    out["updated_by"] = user or ""
    if create:
        out["created_by"] = user or ""
    return out


async def list_connections() -> list[dict]:
    return [_connection(r) for r in await _select(_CONNECTION_SELECT + " ORDER BY lower(c.name), c.id")]


async def get_connection(connection_id: int, *, with_ca: bool = False) -> dict | None:
    """A connection; with ``with_ca`` also its ``ca_pem`` (for the runner)."""
    rows = await _select(_CONNECTION_SELECT + " WHERE c.id = ?", (int(connection_id),))
    if not rows:
        return None
    record = _connection(rows[0])
    if with_ca:
        record["ca_pem"] = rows[0]["ca_pem"] or ""
    return record


async def create_connection(values: dict, user: str = "") -> dict:
    """``ValueError`` when a connection has the name, ignoring case."""
    if await _name_taken("sync_connections", values["name"], None):
        raise _taken("connection", values["name"])
    new_id = await _insert(
        "sync_connections", _written(values, user, create=True), _taken("connection", values["name"])
    )
    record = await get_connection(new_id)
    if record is None:  # pragma: no cover - the row was just written
        raise RuntimeError("record vanished after write")
    return record


async def update_connection(connection_id: int, values: dict, user: str = "") -> dict | None:
    """``None`` when it does not exist; ``ValueError`` for a taken name.
    ``ca_pem`` absent from ``values`` keeps the stored bundle."""
    if "name" in values and await _name_taken("sync_connections", values["name"], int(connection_id)):
        raise _taken("connection", values["name"])
    written = _written(values, user, create=False)
    if not await _update("sync_connections", int(connection_id), written, _taken("connection", values.get("name", ""))):
        return None
    return await get_connection(connection_id)


async def delete_connection(connection_id: int) -> bool:
    """``ConnectionInUse`` while jobs use it."""
    try:
        return await _execute("DELETE FROM sync_connections WHERE id = ?", (int(connection_id),)) > 0
    except Exception as exc:
        if _is_foreign_key_violation(exc):
            raise ConnectionInUse("Sync jobs use this connection; delete or move them first.") from exc
        raise


async def set_connection_test(connection_id: int, *, ok: bool, message: str) -> None:
    await _execute(
        "UPDATE sync_connections SET last_test_at = ?, last_test_ok = ?, last_test_message = ? WHERE id = ?",
        (_now(), 1 if ok else 0, message[:1000], int(connection_id)),
    )


# ── Jobs ─────────────────────────────────────────────────────────────────────

_JOB_SELECT = """
    SELECT j.*, c.name AS connection_name, c.kind AS connection_kind
    FROM sync_jobs j JOIN sync_connections c ON c.id = j.connection_id
"""


def _job(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "connection_id": int(row["connection_id"]),
        "connection_name": row["connection_name"],
        "connection_kind": row["connection_kind"],
        "object_types": _json(row["object_types"], []),
        "direction": row["direction"],
        "conflict_policy": row["conflict_policy"],
        "delete_missing": bool(row["delete_missing"]),
        "mappings": _json(row["mappings"], {}),
        "options": _json(row["options"], {}),
        "interval_minutes": int(row["interval_minutes"]),
        "enabled": bool(row["enabled"]),
        "description": row["description"] or "",
        "last_run_id": int(row["last_run_id"]) if row["last_run_id"] is not None else None,
        "last_run_status": row["last_run_status"] or "",
        "last_run_at": row["last_run_at"] or "",
        "last_attempt_at": row["last_attempt_at"] or "",
        **_stamps(row),
    }


async def list_jobs(connection_id: int | None = None) -> list[dict]:
    where, params = ("", ()) if connection_id is None else (" WHERE j.connection_id = ?", (int(connection_id),))
    rows = await _select(_JOB_SELECT + where + " ORDER BY lower(j.name), j.id", params)
    return [_job(r) for r in rows]


async def get_job(job_id: int) -> dict | None:
    rows = await _select(_JOB_SELECT + " WHERE j.id = ?", (int(job_id),))
    return _job(rows[0]) if rows else None


async def create_job(values: dict, user: str = "") -> dict:
    if await _name_taken("sync_jobs", values["name"], None):
        raise _taken("job", values["name"])
    new_id = await _insert("sync_jobs", _written(values, user, create=True), _taken("job", values["name"]))
    record = await get_job(new_id)
    if record is None:  # pragma: no cover - the row was just written
        raise RuntimeError("record vanished after write")
    return record


async def update_job(job_id: int, values: dict, user: str = "") -> dict | None:
    if "name" in values and await _name_taken("sync_jobs", values["name"], int(job_id)):
        raise _taken("job", values["name"])
    if not await _update("sync_jobs", int(job_id), _written(values, user, create=False), _taken("job", values["name"])):
        return None
    return await get_job(job_id)


async def delete_job(job_id: int) -> bool:
    """Delete a job with its runs."""
    return await _execute("DELETE FROM sync_jobs WHERE id = ?", (int(job_id),)) > 0


async def claim_job_attempt(job_id: int) -> None:
    """Stamp ``last_attempt_at`` (the scheduler's clock)."""
    await _execute("UPDATE sync_jobs SET last_attempt_at = ? WHERE id = ?", (_now(), int(job_id)))


# ── Runs ─────────────────────────────────────────────────────────────────────

_RUN_SELECT = """
    SELECT r.*, j.name AS job_name
    FROM sync_runs r JOIN sync_jobs j ON j.id = r.job_id
"""


def _run(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "job_id": int(row["job_id"]),
        "job_name": row["job_name"],
        "dry_run": bool(row["dry_run"]),
        "trigger": row["trigger_kind"],
        "status": row["status"],
        "started_by": row["started_by"] or "",
        "started_at": row["started_at"] or "",
        "finished_at": row["finished_at"] or "",
        "summary": _json(row["summary"], {}),
        "message": row["message"] or "",
    }


async def create_run(job_id: int, *, dry_run: bool, trigger: str, user: str) -> dict:
    """A ``running`` run of the job."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO sync_runs (job_id, dry_run, trigger_kind, status, started_by, started_at) "
            "VALUES (?, ?, ?, 'running', ?, ?) RETURNING id",
            (int(job_id), 1 if dry_run else 0, trigger, user or "", _now()),
        )
        await db.commit()
        new_id = int(cursor.lastrowid)
    finally:
        await db.close()
    record = await get_run(new_id)
    if record is None:  # pragma: no cover - the row was just written
        raise RuntimeError("record vanished after write")
    return record


async def finish_run(
    run_id: int, *, status: str, summary: dict, message: str, entries: Iterable[dict] = ()
) -> dict | None:
    """Store a run's outcome and entries (at most ``MAX_ENTRIES_PER_RUN``)
    and the job's last-run columns. Entries: ``Entry.as_dict()``."""
    rows = []
    for entry in entries:
        if len(rows) >= MAX_ENTRIES_PER_RUN:
            break
        rows.append(
            (
                int(run_id),
                entry["object_type"],
                str(entry["key"])[:500],
                entry["action"],
                entry["target"],
                json.dumps(entry.get("changes") or {}),
                entry["outcome"],
                str(entry.get("message") or "")[:2000],
            )
        )
    finished = _now()
    db = await _dbcore.get_db()
    try:
        if rows:
            await db.executemany(
                "INSERT INTO sync_run_entries (run_id, object_type, object_key, action, target, changes, outcome, message)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        await db.execute(
            "UPDATE sync_runs SET status = ?, summary = ?, message = ?, finished_at = ? WHERE id = ?",
            (status, json.dumps(summary), message[:2000], finished, int(run_id)),
        )
        await db.execute(
            "UPDATE sync_jobs SET last_run_id = ?, last_run_status = ?, last_run_at = ? "
            "WHERE id = (SELECT job_id FROM sync_runs WHERE id = ?)",
            (int(run_id), status, finished, int(run_id)),
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()
    return await get_run(run_id)


async def list_runs(job_id: int | None = None, limit: int = 100) -> list[dict]:
    where, params = ("", ()) if job_id is None else (" WHERE r.job_id = ?", (int(job_id),))
    rows = await _select(_RUN_SELECT + where + " ORDER BY r.id DESC LIMIT ?", (*params, int(limit)))
    return [_run(r) for r in rows]


async def get_run(run_id: int) -> dict | None:
    rows = await _select(_RUN_SELECT + " WHERE r.id = ?", (int(run_id),))
    return _run(rows[0]) if rows else None


async def list_run_entries(
    run_id: int,
    *,
    object_type: str | None = None,
    outcome: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """A page of a run's entries (by object type order of the run, then
    id) and the number matching."""
    clauses, params = ["run_id = ?"], [int(run_id)]
    if object_type:
        clauses.append("object_type = ?")
        params.append(object_type)
    if outcome:
        clauses.append("outcome = ?")
        params.append(outcome)
    where = " WHERE " + " AND ".join(clauses)
    total = await _select("SELECT COUNT(*) AS n FROM sync_run_entries" + where, tuple(params))  # nosec B608 - fixed clauses
    rows = await _select(
        "SELECT * FROM sync_run_entries" + where + " ORDER BY id LIMIT ? OFFSET ?",  # nosec B608 - fixed clauses
        (*params, int(limit), int(offset)),
    )
    entries = [
        {
            "id": int(r["id"]),
            "object_type": r["object_type"],
            "key": r["object_key"],
            "action": r["action"],
            "target": r["target"],
            "changes": _json(r["changes"], {}),
            "outcome": r["outcome"],
            "message": r["message"] or "",
        }
        for r in rows
    ]
    return entries, int(total[0]["n"])


async def prune_runs(job_id: int, keep: int = RUNS_KEPT_PER_JOB) -> int:
    """Delete the job's runs older than its ``keep`` newest; the number gone."""
    return await _execute(
        "DELETE FROM sync_runs WHERE job_id = ? AND id NOT IN "
        "(SELECT id FROM sync_runs WHERE job_id = ? ORDER BY id DESC LIMIT ?)",
        (int(job_id), int(job_id), int(keep)),
    )


async def fail_stale_runs() -> int:
    """Mark runs left ``running`` by a stopped server as failed."""
    return await _execute(
        "UPDATE sync_runs SET status = 'failed', finished_at = ?, "
        "message = 'Interrupted: the server stopped during the run.' WHERE status = 'running'",
        (_now(),),
    )
