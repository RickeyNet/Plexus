"""
Migration 0066: Cato Networks accounts in the topology.

Adds:
  - meraki_orgs.provider - which integration an entry belongs to: "meraki"
    (a Dashboard organization, the default for every existing row) or "cato"
    (a Cato account). A Cato account is stored, collected and merged into the
    map exactly like an organization, so it shares the organization and
    snapshot tables; only the collector that runs differs.
"""

from __future__ import annotations

VERSION = 66
DESCRIPTION = "Add meraki_orgs.provider for Cato Networks accounts"


async def up(db) -> None:
    await db.execute("ALTER TABLE meraki_orgs ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'meraki'")
    await db.commit()
