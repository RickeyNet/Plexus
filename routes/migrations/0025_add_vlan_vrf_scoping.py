"""
Migration 0025: VLAN/VRF-aware subnet scoping (IPAM Phase G).

Adds:
  - hosts.vrf_name (text, default '') — VRF context for inventory hosts
  - hosts.vlan_id  (text, default '') — VLAN ID for inventory hosts (text to allow non-numeric tags)
  - ipam_allocations.vrf_name (text, default '')
  - ipam_allocations.vlan_id  (text, default '')

Empty string is treated as the global / default VRF so existing rows remain
non-conflicting with each other. Conflict detection now keys on (vrf, ip).
"""

from __future__ import annotations

import os

VERSION = 25
DESCRIPTION = "Add vrf_name / vlan_id columns to hosts and ipam_allocations"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _column_set(db, table: str) -> set[str]:
    cursor = await db.execute(f"PRAGMA table_info({table})")
    rows = await cursor.fetchall()
    return {str(r[1]) for r in rows}


async def _up_sqlite(db) -> None:
    host_cols = await _column_set(db, "hosts")
    if "vrf_name" not in host_cols:
        await db.execute("ALTER TABLE hosts ADD COLUMN vrf_name TEXT NOT NULL DEFAULT ''")
    if "vlan_id" not in host_cols:
        await db.execute("ALTER TABLE hosts ADD COLUMN vlan_id TEXT NOT NULL DEFAULT ''")

    alloc_cols = await _column_set(db, "ipam_allocations")
    if "vrf_name" not in alloc_cols:
        await db.execute("ALTER TABLE ipam_allocations ADD COLUMN vrf_name TEXT NOT NULL DEFAULT ''")
    if "vlan_id" not in alloc_cols:
        await db.execute("ALTER TABLE ipam_allocations ADD COLUMN vlan_id TEXT NOT NULL DEFAULT ''")

    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_hosts_vrf_ip ON hosts (vrf_name, ip_address)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipam_allocations_vrf_addr ON ipam_allocations (vrf_name, address)"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS vrf_name TEXT NOT NULL DEFAULT ''")
    await db.execute("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS vlan_id TEXT NOT NULL DEFAULT ''")
    await db.execute("ALTER TABLE ipam_allocations ADD COLUMN IF NOT EXISTS vrf_name TEXT NOT NULL DEFAULT ''")
    await db.execute("ALTER TABLE ipam_allocations ADD COLUMN IF NOT EXISTS vlan_id TEXT NOT NULL DEFAULT ''")
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_hosts_vrf_ip ON hosts (vrf_name, ip_address)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipam_allocations_vrf_addr ON ipam_allocations (vrf_name, address)"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
