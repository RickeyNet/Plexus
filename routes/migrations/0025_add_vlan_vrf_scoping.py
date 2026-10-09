"""
Migration 0025: VLAN/VRF-aware subnet scoping (IPAM Phase G).

Adds:
  - hosts.vrf_name (text, default '') - VRF context for inventory hosts
  - hosts.vlan_id  (text, default '') - VLAN ID for inventory hosts (text to allow non-numeric tags)
  - ipam_allocations.vrf_name (text, default '')
  - ipam_allocations.vlan_id  (text, default '')

Empty string is treated as the global / default VRF so existing rows remain
non-conflicting with each other. Conflict detection now keys on (vrf, ip).
"""

from __future__ import annotations

VERSION = 25
DESCRIPTION = "Add vrf_name / vlan_id columns to hosts and ipam_allocations"


async def up(db) -> None:
    await db.execute("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS vrf_name TEXT NOT NULL DEFAULT ''")
    await db.execute("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS vlan_id TEXT NOT NULL DEFAULT ''")
    await db.execute("ALTER TABLE ipam_allocations ADD COLUMN IF NOT EXISTS vrf_name TEXT NOT NULL DEFAULT ''")
    await db.execute("ALTER TABLE ipam_allocations ADD COLUMN IF NOT EXISTS vlan_id TEXT NOT NULL DEFAULT ''")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_hosts_vrf_ip ON hosts (vrf_name, ip_address)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_ipam_allocations_vrf_addr ON ipam_allocations (vrf_name, address)")
    await db.commit()
