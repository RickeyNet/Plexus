"""
Migration 0073: Record a neighbor's CDP / LLDP capabilities on topology links.

The inventory SSH collection reads the capabilities a neighbor advertises
("Host Phone", "B,T", "B,R"). The map uses them to tell an end device (a
phone, a station such as a server or a camera) from network infrastructure,
and keeps end devices off the map unless asked for them.

Existing rows default to ``''`` (unknown: the neighbor is drawn as before).
"""

from __future__ import annotations

VERSION = 73
DESCRIPTION = "Add target_capabilities to topology_links"

_COLUMN = "target_capabilities"
_DECL = "TEXT NOT NULL DEFAULT ''"


async def up(db) -> None:
    await db.execute(f"ALTER TABLE topology_links ADD COLUMN IF NOT EXISTS {_COLUMN} {_DECL}")
    await db.commit()
