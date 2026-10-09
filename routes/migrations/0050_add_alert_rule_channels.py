"""
Migration 0050: Add notification channel assignment to alert_rules.

`channel_ids` is a TEXT column holding a JSON list (or comma-separated list) of
notification-channel ids that a rule's alerts should be delivered to (email /
PagerDuty / webhook / Teams). Empty means "use the global default channel set"
(see auth_settings `notification_channels.default_channel_ids`), which is also
what built-in threshold / baseline / route-churn alerts fall back to since they
aren't tied to a user rule.
"""

from __future__ import annotations

VERSION = 50
DESCRIPTION = "Add channel_ids to alert_rules for notification routing"


async def up(db) -> None:
    await db.execute("ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS channel_ids TEXT NOT NULL DEFAULT ''")
    await db.commit()
