"""
Migration 0034: Widen interface counter columns from INTEGER to BIGINT.

SNMP Counter64 OIDs (ifHCInOctets, ifHCOutOctets) routinely exceed signed
32-bit range - real production switches push tens of billions of bytes per
interface. Postgres treats SCHEMA `INTEGER` as int4 and rejects values >2^31,
which crashes topology + monitoring writes on busy networks.

Postgres needs explicit ALTER COLUMN ... TYPE BIGINT.
"""

from __future__ import annotations

VERSION = 34
DESCRIPTION = "Widen interface_stats / interface_ts octet columns to BIGINT"


async def up(db) -> None:
    # ALTER COLUMN ... TYPE BIGINT preserves existing values.
    for table, columns in (
        ("interface_stats", ["in_octets", "out_octets", "prev_in_octets", "prev_out_octets"]),
        ("interface_ts", ["in_octets", "out_octets"]),
    ):
        for col in columns:
            await db.execute(f"ALTER TABLE {table} ALTER COLUMN {col} TYPE BIGINT")
    await db.commit()
