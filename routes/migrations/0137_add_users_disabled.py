"""
Migration 0137: per-user "account disabled" flag.

Adds:
  - users.disabled - when 1, the account cannot sign in by any method, its
    sessions are refused and the AI-access (MCP) tokens it owns stop
    working. An admin sets it to cut off a person without deleting the
    account. Existing accounts stay enabled (0).
"""

from __future__ import annotations

VERSION = 137
DESCRIPTION = "Add users.disabled to switch an account off without deleting it"


async def up(db) -> None:
    await db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled INTEGER NOT NULL DEFAULT 0")
    await db.commit()
