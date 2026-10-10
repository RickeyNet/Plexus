"""
Migration 0038: Add parameters JSON column to jobs.

Per-job parameters (e.g. NetFlow's collector_ip / sampling_rate) are
collected from the launch UI based on each playbook's parameters_schema
and stored as a JSON blob here. The runner deserializes them and assigns
to ``pb.parameters`` before the playbook's ``run()`` executes.

Existing rows default to NULL, which the runner treats as an empty dict
so older jobs replayed via retry continue to work.
"""

from __future__ import annotations

VERSION = 38
DESCRIPTION = "Add jobs.parameters JSON column for per-job playbook parameters"


async def up(db) -> None:
    await db.execute("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS parameters TEXT DEFAULT NULL")
    await db.commit()
