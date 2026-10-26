"""
Migration 0076: per-source settings of scheduled collection.

The integration sources in ``meraki_orgs`` (Meraki organizations, Cato
accounts, Cisco FMCs, Palo Alto Panoramas, Appgate SDP collectives) are now
collected on a schedule. Adds:

  - auto_collect - 1 (default) when the scheduler collects the source, 0 when
    it is only collected by hand.
  - collect_interval_seconds - the source's own interval; 0 (default) uses
    the global one (auth setting ``source_collection_sync``).
"""

from __future__ import annotations

VERSION = 76
DESCRIPTION = "Add auto_collect and collect_interval_seconds to meraki_orgs"

_COLUMNS = (
    ("auto_collect", "INTEGER NOT NULL DEFAULT 1"),
    ("collect_interval_seconds", "INTEGER NOT NULL DEFAULT 0"),
)


async def up(db) -> None:
    for column, decl in _COLUMNS:
        await db.execute(f"ALTER TABLE meraki_orgs ADD COLUMN IF NOT EXISTS {column} {decl}")
    await db.commit()
