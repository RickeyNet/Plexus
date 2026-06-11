"""
Migration 0053: Indexes for hot-path scans on suppressions, topology, alerts.

Three tables are filtered on unindexed columns in code paths that run every
poll cycle, so each grows into a progressively slower full-table scan:

- ``alert_suppressions``: ``is_alert_suppressed()`` runs per metric per host
  during monitoring polls and always filters ``ends_at > datetime('now')``.
  Expired suppressions accumulate; an ends_at index narrows every check to
  the (small) active set.
- ``topology_changes``: listed/counted with ``ORDER BY detected_at DESC``,
  retention-deleted by ``detected_at``, and bulk-acknowledged with
  ``WHERE acknowledged = 0``.
- ``monitoring_alerts``: retention-deleted by ``created_at``.
"""

from __future__ import annotations

VERSION = 53
DESCRIPTION = "Add indexes for alert_suppressions, topology_changes, monitoring_alerts hot paths"


async def up(db) -> None:
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alert_suppressions_ends_at
        ON alert_suppressions(ends_at)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_topology_changes_detected_at
        ON topology_changes(detected_at)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_topology_changes_acknowledged
        ON topology_changes(acknowledged)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_monitoring_alerts_created_at
        ON monitoring_alerts(created_at)
        """
    )
    await db.commit()
