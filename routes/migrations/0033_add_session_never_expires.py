"""
Migration 0033: Per-user "session never expires" flag for kiosk/display accounts.

Adds:
  - users.session_never_expires - when 1, that user's sessions bypass the
    global idle-timeout enforcement and the absolute lifetime cap. Intended
    for read-only display accounts (smart boards, NOC walls) that need to
    stay logged in indefinitely.
"""

from __future__ import annotations

VERSION = 33
DESCRIPTION = "Add users.session_never_expires for kiosk/display accounts"


async def up(db) -> None:
    await db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS session_never_expires INTEGER NOT NULL DEFAULT 0")
    await db.commit()
