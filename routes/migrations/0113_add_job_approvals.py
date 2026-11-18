"""
Migration 0113: approval workflow for jobs.

Adds:

  - playbooks gain ``approval_required`` (0 or 1, default 0). A job launched
    from a playbook with it set (by hand, retry, re-run or a ChatOps preset)
    is created in status ``pending_approval``, which the job queue never
    starts, until someone holding ``jobs.approve`` approves it.
  - jobs gain the approval record, named like the deployment one:
    ``approval_status`` (``not_required``, ``pending``, ``approved`` or
    ``denied``; default ``not_required``), ``approved_by`` (who decided, for
    an approval or a denial), ``approved_at`` and ``approval_comment``.
    An approved job moves to ``queued``; a denied one to ``denied`` (terminal).
  - an index on ``jobs.status`` for the approvals list.

Timestamps are written by Plexus as UTC ISO 8601 text, like the other job
timestamps. Every step is idempotent.
"""

from __future__ import annotations

VERSION = 113
DESCRIPTION = "Add the job approval workflow"

_STATEMENTS: tuple[str, ...] = (
    "ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS approval_required INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'not_required'",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS approved_by TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS approved_at TEXT",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS approval_comment TEXT NOT NULL DEFAULT ''",
    "CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs (status)",
)


async def up(db) -> None:
    for statement in _STATEMENTS:
        await db.execute(statement)
    await db.commit()
