"""
Migration 0036: Add flow_exporters table.

Tracks every device seen exporting NetFlow/sFlow/IPFIX records to Plexus.
One row per (exporter_ip, flow_type) combination so the same device can
appear under multiple protocols (e.g. NetFlow v9 + sFlow) without
collapsing the per-protocol packet counters.

Populated by the flow collector on every received packet and queryable
via /api/flows/exporters so the UI can show who is exporting without
scanning the full flow_records table.
"""

from __future__ import annotations

VERSION = 36
DESCRIPTION = "Add flow_exporters table for per-device NetFlow/sFlow visibility"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS flow_exporters (
            id              SERIAL PRIMARY KEY,
            exporter_ip     TEXT    NOT NULL,
            host_id         INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            flow_type       TEXT    NOT NULL DEFAULT 'netflow',
            packets_received BIGINT NOT NULL DEFAULT 0,
            sampling_rate   INTEGER NOT NULL DEFAULT 0,
            first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_record_at  TIMESTAMPTZ,
            UNIQUE(exporter_ip, flow_type)
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_flow_exporters_host ON flow_exporters(host_id)")
    await db.commit()
