"""
Migration 0145: Widen the flow exporter counters to BIGINT.

``flow_exporters.packets_received`` counts every datagram an exporter has
ever sent, and ``sampling_rate`` is an unsigned 32-bit value on the wire.
As int4, the upsert of an exporter fails with "integer out of range" once
its count passes 2^31-1, and from then on its ``last_seen`` no longer moves.

The table has one row per exporter and flow type, so the rewrite that
``ALTER COLUMN ... TYPE`` does is instant. A column that is already BIGINT
(a database created from the current schema) is left alone.
"""

from __future__ import annotations

VERSION = 145
DESCRIPTION = "Widen flow_exporters.packets_received and sampling_rate to BIGINT"

_COLUMNS = ("packets_received", "sampling_rate")


async def up(db) -> None:
    for column in _COLUMNS:
        cursor = await db.execute(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = 'flow_exporters' AND column_name = ?",
            (column,),
        )
        row = await cursor.fetchone()
        dtype = None if row is None else (row["data_type"] if isinstance(row, dict) else row[0])
        if dtype == "integer":
            await db.execute(f"ALTER TABLE flow_exporters ALTER COLUMN {column} TYPE BIGINT")
    await db.commit()
