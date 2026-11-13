"""
Migration 0082: MCP access tokens.

The read-only AI access endpoint (``netcontrol.mcp``, served at ``/mcp``)
authenticates each request with a bearer token an admin created. Adds:

  - mcp_tokens - one row per token: its name, the SHA-256 of the token (the
    plaintext is shown once at creation and never stored), a short display
    prefix, the Plexus user it acts as, the data categories it may read
    (JSON list), an optional expiry, usage counters, and ``revoked_at``.
    Revoked rows are kept so audit history still resolves the token name.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

VERSION = 82
DESCRIPTION = "Add MCP access tokens table"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS mcp_tokens (
            id            SERIAL PRIMARY KEY,
            name          TEXT    NOT NULL UNIQUE,
            token_hash    TEXT    NOT NULL UNIQUE,
            token_prefix  TEXT    NOT NULL DEFAULT '',
            owner_user_id INTEGER NOT NULL,
            categories    TEXT    NOT NULL DEFAULT '[]',
            expires_at    TEXT    NOT NULL DEFAULT '',
            created_at    TEXT    NOT NULL DEFAULT '',
            created_by    TEXT    NOT NULL DEFAULT '',
            last_used_at  TEXT    NOT NULL DEFAULT '',
            call_count    INTEGER NOT NULL DEFAULT 0,
            revoked_at    TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.commit()
