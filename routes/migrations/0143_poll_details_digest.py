"""
Migration 0143: Store a poll's detail blobs only where they change.

``monitoring_polls`` gets ``details_digest``: the state the poll's
``if_details`` (without the interface counters), ``vpn_details`` and
``route_snapshot`` describe. A poll in the middle of a run of polls with
the same digest has its three blobs cleared to NULL, so the three columns
lose ``NOT NULL``; each run keeps its first and its last row, and the
newest poll of a host always keeps them.

Both changes are catalog-only on PostgreSQL (a nullable column with no
default, and ``DROP NOT NULL``): no table rewrite and no backfill. Rows
written before this migration keep their blobs and a NULL digest, and are
never cleared; they age out with poll retention.

The poll no longer samples the raw interface error counters, only their
``_rate`` versions, so the built-in "Interface Errors & Discards" graph
template plots the rates. Only series still as seeded (raw counter name,
``rate`` transform) are changed; a user's edits are left alone.

Every step is idempotent.
"""

from __future__ import annotations

VERSION = 143
DESCRIPTION = "Add monitoring_polls.details_digest; allow NULL detail blobs; error template plots rates"

_BLOB_COLUMNS = ("if_details", "vpn_details", "route_snapshot")
_ERROR_COUNTERS = ("if_in_errors", "if_out_errors", "if_in_discards", "if_out_discards")


async def up(db) -> None:
    await db.execute("ALTER TABLE monitoring_polls ADD COLUMN IF NOT EXISTS details_digest TEXT DEFAULT NULL")
    for column in _BLOB_COLUMNS:
        await db.execute(f"ALTER TABLE monitoring_polls ALTER COLUMN {column} DROP NOT NULL")
    for metric in _ERROR_COUNTERS:
        await db.execute(
            """UPDATE graph_template_items SET metric_name = ?, transform = ''
               WHERE metric_name = ? AND transform = 'rate'
                 AND template_id IN (
                     SELECT id FROM graph_templates
                     WHERE built_in = 1 AND name = 'Interface Errors & Discards')""",
            (f"{metric}_rate", metric),
        )
    await db.commit()
