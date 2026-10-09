"""
Migration 0056: Add session_epoch to users for server-side session revocation.

Sessions are stateless signed cookies, so before this there was no way to
invalidate an outstanding token: logout only dropped the client cookie, and a
password change / admin reset / role change left captured tokens valid until
the 24h absolute cap. ``session_epoch`` is a per-user counter embedded in each
issued token; ``require_auth`` (and the WebSocket auth path) reject a token
whose epoch is older than the user's current value. Bumping the column
(password change, admin password reset, privilege change) invalidates every
previously-issued session for that user at once.

Existing tokens carry no epoch and are treated as epoch 0; existing rows
default to 0, so no one is logged out by the migration itself - only by a
subsequent revocation event.
"""

from __future__ import annotations

VERSION = 56
DESCRIPTION = "Add session_epoch to users for session revocation"

_COLUMN = ("session_epoch", "INTEGER NOT NULL DEFAULT 0")


async def up(db) -> None:
    name, decl = _COLUMN
    await db.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {name} {decl}")
    await db.commit()
