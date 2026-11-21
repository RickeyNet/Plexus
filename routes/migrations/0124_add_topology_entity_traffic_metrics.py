"""
Migration 0124: traffic rates of topology (API-collected) entities.

Adds to topology_entity_metrics (migration 0091) the traffic of an entity
(an OPNsense IPsec connection, WireGuard peer, OpenVPN client or server
instance), in bits per second averaged over the time between two
collections and computed from the byte counters the vendor reports
(``netcontrol.integrations.traffic``):

  - in_bps  - received by the device through the entity;
  - out_bps - sent by the device through the entity.

Both are nullable: existing rows and the latency / jitter / loss samples of
other entities keep ``NULL``. The daily rollups need no change: they gain
the metrics ``traffic_in`` and ``traffic_out`` (one row per entity, day and
metric, as for ``latency``). Every step is idempotent.
"""

from __future__ import annotations

VERSION = 124
DESCRIPTION = "Add traffic rates to topology entity metrics"


async def up(db) -> None:
    for column in ("in_bps", "out_bps"):
        await db.execute(f"ALTER TABLE topology_entity_metrics ADD COLUMN IF NOT EXISTS {column} REAL")
    await db.commit()
