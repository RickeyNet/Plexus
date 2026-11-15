"""
Migration 0088: Add users.external_id for OpenID Connect sign-in.

An OIDC provider identifies a person by ``sub``, a value that never changes
even when the username claim does (a renamed account, a reused email).
The first OIDC login of an account stores its ``sub`` here; a later login
for the same ``oidc``-managed account whose ``sub`` differs is refused, so
someone who takes over a username at the provider cannot take over the
Plexus account bound to the old subject (see auth.upsert_oidc_user).

Existing rows default to '' (no subject bound yet).
"""

from __future__ import annotations

VERSION = 88
DESCRIPTION = "Add users.external_id holding the OIDC subject of SSO accounts"


async def up(db) -> None:
    await db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS external_id TEXT NOT NULL DEFAULT ''")
    await db.commit()
