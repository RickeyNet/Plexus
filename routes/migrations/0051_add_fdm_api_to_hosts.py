"""
Migration 0051: Add Cisco FDM REST-API polling columns to hosts.

FDM-managed FTDs (device_type ``cisco_ftd``) can be polled over the on-box
Firepower Device Manager REST API instead of (or alongside) SNMP. These
per-host columns flag a host for API polling and point at the read-only API
credential:

  - ``fdm_api_enabled``    : 1 to include the host in the FDM poll cycle
  - ``fdm_credential_id``  : credentials.id of the read-only API user
  - ``fdm_port``           : HTTPS port of the FDM management interface (default 443)
  - ``fdm_verify_tls``     : 1 to verify the device cert (0 for self-signed default)

Existing rows default to disabled, so the new poll loop is a no-op until a
host is explicitly opted in.
"""

from __future__ import annotations

import os

VERSION = 51
DESCRIPTION = "Add FDM REST-API polling columns to hosts"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"

_COLUMNS = (
    ("fdm_api_enabled", "INTEGER NOT NULL DEFAULT 0"),
    ("fdm_credential_id", "INTEGER"),
    ("fdm_port", "INTEGER NOT NULL DEFAULT 443"),
    ("fdm_verify_tls", "INTEGER NOT NULL DEFAULT 0"),
)


async def _column_exists_sqlite(db, name: str) -> bool:
    cursor = await db.execute("PRAGMA table_info(hosts)")
    rows = await cursor.fetchall()
    return any(row[1] == name for row in rows)


async def _up_sqlite(db) -> None:
    for name, decl in _COLUMNS:
        if await _column_exists_sqlite(db, name):
            continue
        await db.execute(f"ALTER TABLE hosts ADD COLUMN {name} {decl}")
    await db.commit()


async def _up_postgres(db) -> None:
    for name, decl in _COLUMNS:
        await db.execute(f"ALTER TABLE hosts ADD COLUMN IF NOT EXISTS {name} {decl}")
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
