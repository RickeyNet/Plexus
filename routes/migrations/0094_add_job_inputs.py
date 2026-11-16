"""
Migration 0094: typed job input forms and per-job permissions on playbooks.

Adds to ``playbooks``:

  - input_schema - JSON list of typed input fields (name, type, label, help,
    default, required, min/max, regex, choices) the run dialog renders and
    the launch endpoint validates. ``[]`` (the default) means "use the
    schema the Python class declares in code, if any".
  - permissions - JSON ``{"run": {"roles": [], "groups": []},
    "commit": {"roles": [], "groups": []}}``: the user roles and access
    group ids allowed to run the job and to run it in commit (live) mode.
    ``{}`` (the default) leaves the job open to every user with the
    ``jobs`` feature, as before.

The validated inputs of a job are stored in the existing ``jobs.parameters``
column (secret-type values as ``{{secret.NAME}}`` references, never the
value) and the run mode in the existing ``jobs.dry_run`` column.
"""

from __future__ import annotations

VERSION = 94
DESCRIPTION = "Add playbooks.input_schema and playbooks.permissions"


async def up(db) -> None:
    await db.execute("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS input_schema TEXT NOT NULL DEFAULT '[]'")
    await db.execute("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS permissions TEXT NOT NULL DEFAULT '{}'")
    await db.commit()
