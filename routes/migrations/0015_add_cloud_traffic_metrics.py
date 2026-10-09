"""Migration 0015: Add cloud_traffic_metrics table.

Stores provider-derived cloud traffic metrics (CloudWatch / Azure Monitor /
Cloud Monitoring) normalized into a common schema for API analytics.
"""

from __future__ import annotations

VERSION = 15
DESCRIPTION = "Add cloud traffic metrics ingestion table"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_traffic_metrics (
            id                  SERIAL PRIMARY KEY,
            account_id          INTEGER NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
            provider            TEXT    NOT NULL,
            metric_name         TEXT    NOT NULL,
            metric_namespace    TEXT    NOT NULL DEFAULT '',
            resource_uid        TEXT    NOT NULL DEFAULT '',
            direction           TEXT    NOT NULL DEFAULT '',
            statistic           TEXT    NOT NULL DEFAULT '',
            unit                TEXT    NOT NULL DEFAULT '',
            metric_value        DOUBLE PRECISION NOT NULL DEFAULT 0,
            interval_start      TIMESTAMPTZ NOT NULL,
            interval_end        TIMESTAMPTZ NOT NULL,
            metadata_json       TEXT    NOT NULL DEFAULT '{}',
            source              TEXT    NOT NULL DEFAULT 'api',
            ingested_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cloud_traffic_metrics_lookup
        ON cloud_traffic_metrics (account_id, provider, metric_name, interval_end)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cloud_traffic_metrics_resource
        ON cloud_traffic_metrics (resource_uid, interval_end)
        """
    )
    await db.commit()
