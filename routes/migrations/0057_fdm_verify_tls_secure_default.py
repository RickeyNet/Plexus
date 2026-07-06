"""
Migration 0057: Make Cisco FDM TLS verification secure by default.

Migration 0051 shipped ``hosts.fdm_verify_tls`` defaulting to 0 (verification
OFF). Because the FDM REST API carries the firewall admin credentials on every
request, an unverified TLS session is MITM-exploitable. This migration flips
any existing rows still at 0 to 1 so already-created hosts verify certs.

Deployments that intentionally use the out-of-box self-signed FDM cert must
re-opt-out per host after upgrading. The going-forward column default is set
to 1 in the schema (CREATE TABLE) and in migration 0051 for fresh installs;
SQLite cannot alter an existing column's default in place, but the FDM feature
sets ``fdm_verify_tls`` explicitly whenever a host is configured for API
polling, so the flipped rows are what matters for live exposure.
"""

from __future__ import annotations

import os

VERSION = 57
DESCRIPTION = "Flip existing hosts.fdm_verify_tls to secure (1)"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _column_exists_sqlite(db, name: str) -> bool:
    cursor = await db.execute("PRAGMA table_info(hosts)")
    rows = await cursor.fetchall()
    return any(row[1] == name for row in rows)


async def up(db) -> None:
    # Guard: only run if the column exists (it is added by migration 0051).
    if DB_ENGINE != "postgres":
        if not await _column_exists_sqlite(db, "fdm_verify_tls"):
            return
    await db.execute("UPDATE hosts SET fdm_verify_tls = 1 WHERE fdm_verify_tls = 0")
    await db.commit()
