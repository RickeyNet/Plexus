"""
Migration 0045: Add ICMP liveness columns to monitoring_polls.

`icmp_alive` and `icmp_rtt_ms` are populated by the independent ICMP probe
in `_poll_host_monitoring` so the UI can surface "pings but SNMP broken"
as a distinct state (the diagnostic gap that motivated this feature for
SNMPv3-on-Cisco-FTD).  Existing rows pre-dating ICMP support stay NULL,
which the UI already treats as "no data" for the field.
"""

from __future__ import annotations

import os

VERSION = 45
DESCRIPTION = "Add icmp_alive + icmp_rtt_ms to monitoring_polls"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"

_COLUMNS = (
    ("icmp_alive", "INTEGER DEFAULT NULL"),
    ("icmp_rtt_ms", "REAL DEFAULT NULL"),
)


async def _column_exists_sqlite(db, name: str) -> bool:
    cursor = await db.execute("PRAGMA table_info(monitoring_polls)")
    rows = await cursor.fetchall()
    return any(row[1] == name for row in rows)


async def _up_sqlite(db) -> None:
    for name, decl in _COLUMNS:
        if await _column_exists_sqlite(db, name):
            continue
        await db.execute(
            f"ALTER TABLE monitoring_polls ADD COLUMN {name} {decl}"
        )
    await db.commit()


async def _up_postgres(db) -> None:
    for name, decl in _COLUMNS:
        await db.execute(
            f"ALTER TABLE monitoring_polls ADD COLUMN IF NOT EXISTS {name} {decl}"
        )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
