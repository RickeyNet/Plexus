"""
Migration 0053: Add host_ip_aliases for multi-interface device dedup.

A router/L3 switch has many IPs (one per interface). Discovery previously
keyed devices on IP, so every SNMP/ping-reachable interface IP became its own
host row — the same physical device appeared many times in inventory and in
the topology graph.

host_ip_aliases records the *secondary* interface IPs a device owns (learned
from its SNMP ipAddrTable). Discovery uses it to recognise that a freshly
probed IP belongs to a device already in inventory instead of creating a
duplicate, and topology resolves secondary IPs to the owning host through it.
The host's primary management IP stays in hosts.ip_address; only the extra
IPs live here.
"""

from __future__ import annotations

import os

VERSION = 53
DESCRIPTION = "Add host_ip_aliases table for multi-interface device dedup"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """CREATE TABLE IF NOT EXISTS host_ip_aliases (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            ip_address  TEXT    NOT NULL,
            UNIQUE(host_id, ip_address)
        )"""
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_host_ip_aliases_ip ON host_ip_aliases(ip_address)"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """CREATE TABLE IF NOT EXISTS host_ip_aliases (
            id          SERIAL PRIMARY KEY,
            host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            ip_address  TEXT    NOT NULL,
            UNIQUE(host_id, ip_address)
        )"""
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_host_ip_aliases_ip ON host_ip_aliases(ip_address)"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
