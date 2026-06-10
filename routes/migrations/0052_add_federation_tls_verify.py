"""
Migration 0052: Add tls_verify flag to federation peers.

Federation requests previously disabled TLS certificate verification
unconditionally (verify=False), allowing an on-path attacker to capture the
peer API token. Peers now verify certificates by default; operators using
self-signed certificates between instances can opt out per peer.

Existing rows default to tls_verify = 1 (verify). Deployments whose peers
use self-signed certs must either install trusted certs or explicitly
disable verification on that peer after upgrading.
"""

from __future__ import annotations

import os

VERSION = 52
DESCRIPTION = "Add federation_peers.tls_verify flag (verify TLS by default)"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _column_exists_sqlite(db) -> bool:
    cursor = await db.execute("PRAGMA table_info(federation_peers)")
    rows = await cursor.fetchall()
    return any(row[1] == "tls_verify" for row in rows)


async def _up_sqlite(db) -> None:
    if await _column_exists_sqlite(db):
        return
    await db.execute(
        "ALTER TABLE federation_peers ADD COLUMN tls_verify INTEGER NOT NULL DEFAULT 1"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        "ALTER TABLE federation_peers ADD COLUMN IF NOT EXISTS tls_verify INTEGER NOT NULL DEFAULT 1"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
