"""background_jobs.py - in-memory registry for fire-and-forget API jobs.

Long-running endpoints (full-CIDR discovery scans, fleet-wide MAC/ARP
collection) launch an ``asyncio`` task, register it here, and return a
``job_id`` immediately; the frontend polls the corresponding GET endpoint
until the job reaches a terminal status. This mirrors the config-drift
capture-job pattern but without WebSockets - polling only.

State is process-local and ephemeral by design (same trade-off as the
config-drift capture jobs): a restart drops job records, and a poll for an
unknown job_id should be treated by callers as "job lost, re-trigger".
Finished jobs are kept for ``_JOB_TTL_SECONDS`` so the frontend has time to
read the result, then dropped.

All functions are synchronous and must be called from the event loop thread;
single-loop access means no locking is needed.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.background_jobs")

# How long a finished job's record (and result payload) stays pollable.
_JOB_TTL_SECONDS = 300

_TERMINAL_STATUSES = {"completed", "partial", "failed"}

_jobs: dict[str, dict] = {}


def create_job(kind: str, progress: dict | None = None) -> dict:
    """Register a new running job and return its record."""
    job = {
        "job_id": uuid.uuid4().hex,
        "kind": kind,
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "finished_at": None,
        "progress": dict(progress or {}),
        "result": None,
        "error": None,
    }
    _jobs[job["job_id"]] = job
    return job


def get_job(job_id: str, kind: str | None = None) -> dict | None:
    """Look up a job, optionally requiring a specific kind."""
    job = _jobs.get(job_id)
    if job is None:
        return None
    if kind is not None and job["kind"] != kind:
        return None
    return job


def running_job(kind: str) -> dict | None:
    """Return the first still-running job of this kind, if any (overlap guard)."""
    for job in _jobs.values():
        if job["kind"] == kind and job["status"] == "running":
            return job
    return None


def update_progress(job_id: str, **fields) -> None:
    """Merge progress fields into a running job (no-op if the job is gone)."""
    job = _jobs.get(job_id)
    if job is not None:
        job["progress"].update(fields)


def finish_job(job_id: str, status: str = "completed",
               result: dict | None = None, error: str | None = None) -> None:
    """Mark a job terminal and schedule its record for cleanup."""
    job = _jobs.get(job_id)
    if job is None:
        return
    if status not in _TERMINAL_STATUSES:
        raise ValueError(f"finish_job requires a terminal status, got {status!r}")
    job["status"] = status
    job["finished_at"] = datetime.now(UTC).isoformat()
    job["result"] = result
    job["error"] = error

    async def _deferred_cleanup() -> None:
        await asyncio.sleep(_JOB_TTL_SECONDS)
        _jobs.pop(job_id, None)

    try:
        asyncio.ensure_future(_deferred_cleanup())
    except RuntimeError:
        # No running loop (sync test context) - skip cleanup; the record
        # lives until process exit, which is fine outside the server.
        LOGGER.debug("background_jobs: no event loop for deferred cleanup of %s", job_id)
