"""
Migration 0140: per-secret "usable by" rule on secret variables.

Adds:
  - secret_variables.usable_by - a JSON rule ``{"roles": [...], "groups":
    [...]}`` naming the user roles and access group ids whose jobs may have
    the secret resolved. Empty (the default) is open: every user who may run
    the job may use it, as before. Admins are always allowed. Existing rows
    stay open until an admin restricts them.
"""

from __future__ import annotations

VERSION = 140
DESCRIPTION = "Add secret_variables.usable_by to limit which users' jobs may use a secret"


async def up(db) -> None:
    await db.execute("ALTER TABLE secret_variables ADD COLUMN IF NOT EXISTS usable_by TEXT NOT NULL DEFAULT ''")
    await db.commit()
