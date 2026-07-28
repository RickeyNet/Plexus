"""
Migration 0061: Add users.auth_provider provenance column.

Shadow accounts created by external authentication (LDAP/RADIUS) were
indistinguishable from genuine local accounts, so directory group changes
could never be re-synced: a user removed from the LDAP admin group kept
local admin forever, and a user added to it was never promoted.

auth_provider records which provider manages the account ('ldap'/'radius',
'' = local). Existing rows default to '' (unmanaged); the first external
login after this migration claims the account and enables re-sync from
then on (see auth.upsert_external_user).
"""

from __future__ import annotations

import os

VERSION = 61
DESCRIPTION = "Add users.auth_provider provenance column for external-auth role re-sync"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _column_exists_sqlite(db) -> bool:
    cursor = await db.execute("PRAGMA table_info(users)")
    rows = await cursor.fetchall()
    return any(row[1] == "auth_provider" for row in rows)


async def _up_sqlite(db) -> None:
    if await _column_exists_sqlite(db):
        return
    await db.execute("ALTER TABLE users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT ''")
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider TEXT NOT NULL DEFAULT ''")
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
