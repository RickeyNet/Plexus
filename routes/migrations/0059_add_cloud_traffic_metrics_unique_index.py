"""
Migration 0059: Unique index for cloud_traffic_metrics idempotency.

Cloud metric ingestion was a blind INSERT with no natural key, so a manual
pull overlapping the scheduled sync loop (or a lookback window overlapping
the cursor) double-inserted identical samples and inflated
``SUM(metric_value)`` in the traffic analytics endpoints.  Deduplicate any
existing rows, then add a unique index over the sample identity so the batch
insert can use INSERT OR IGNORE / ON CONFLICT DO NOTHING.
"""

from __future__ import annotations

VERSION = 59
DESCRIPTION = "Add unique sample-identity index to cloud_traffic_metrics"


async def up(db) -> None:
    # Identical SQL on SQLite and Postgres.
    await db.execute(
        """DELETE FROM cloud_traffic_metrics WHERE id NOT IN (
               SELECT MIN(id) FROM cloud_traffic_metrics
               GROUP BY account_id, metric_name, resource_uid, statistic, interval_start
           )"""
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_traffic_metrics_sample_identity "
        "ON cloud_traffic_metrics(account_id, metric_name, resource_uid, statistic, interval_start)"
    )
    await db.commit()
