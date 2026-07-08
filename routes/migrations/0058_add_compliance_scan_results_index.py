"""
Migration 0058: Composite index on compliance_scan_results.

The compliance dashboard reads latest-status-per-host via
``INNER JOIN (SELECT host_id, profile_id, MAX(id) ... GROUP BY host_id,
profile_id)`` (get_compliance_host_status) and the summary counts
non-compliant hosts against the same group-max subquery
(get_compliance_summary).  The table had NO index, so every compliance
dashboard/summary load full-scanned a table that grows one row per host per
scan.  The composite (host_id, profile_id, id) serves the group-max subquery
as an index-only scan and also covers the optional ``WHERE profile_id = ?``
filter.
"""

from __future__ import annotations

VERSION = 58
DESCRIPTION = "Add compliance_scan_results(host_id, profile_id, id) index"


async def up(db) -> None:
    # Identical SQL on SQLite and Postgres.
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_compliance_scan_results_host_profile_id "
        "ON compliance_scan_results(host_id, profile_id, id)"
    )
    await db.commit()
