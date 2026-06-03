"""
Migration 0047: Index upgrade_devices and upgrade_events for campaign lookups.

The upgrades campaigns list rolls up device counts per campaign, and opening a
campaign (websocket replay) or a device log reads its events ordered by time.
Both tables were unindexed, so every read was a full table scan that grows with
campaign and event volume. These indexes turn those into range lookups.
"""

from __future__ import annotations

import os

VERSION = 47
DESCRIPTION = "Index upgrade_devices(campaign_id) and upgrade_events for campaign/device lookups"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def up(db) -> None:
    # Per-campaign device count roll-up (campaigns list).
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_upgrade_devices_campaign
        ON upgrade_devices(campaign_id)
        """
    )
    # Campaign-wide event replay, newest-first (websocket on campaign open).
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_upgrade_events_campaign_ts
        ON upgrade_events(campaign_id, timestamp)
        """
    )
    # Per-device event log, ordered by time (device upgrade log modal).
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_upgrade_events_campaign_device_ts
        ON upgrade_events(campaign_id, device_id, timestamp)
        """
    )
    await db.commit()
