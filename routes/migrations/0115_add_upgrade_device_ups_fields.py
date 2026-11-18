"""
Migration 0115: APC Smart-UPS firmware updates in upgrade campaigns.

Adds to upgrade_devices:

  - ups_id - the UPS ID the Network Management Card reports in
    ``upsabout`` (``1025``); ``''`` for other devices or before prestage.
    It selects the firmware file (``SRT1025UPS_15-0.enc``) for the UPS.
  - logic_reset_confirmed_by / logic_reset_confirmed_at - who confirmed,
    and when (UTC ISO 8601), that the manual Logic Reset a Smart-UPS Ultra
    (UPS ID 1226 / 1227) needs before its update was done. Transfer and
    Activate wait for it.

Every step is idempotent.
"""

from __future__ import annotations

VERSION = 115
DESCRIPTION = "Add UPS ID and Logic Reset confirmation to upgrade_devices"


async def up(db) -> None:
    await db.execute("ALTER TABLE upgrade_devices ADD COLUMN IF NOT EXISTS ups_id TEXT NOT NULL DEFAULT ''")
    await db.execute(
        "ALTER TABLE upgrade_devices ADD COLUMN IF NOT EXISTS logic_reset_confirmed_by TEXT NOT NULL DEFAULT ''"
    )
    await db.execute("ALTER TABLE upgrade_devices ADD COLUMN IF NOT EXISTS logic_reset_confirmed_at TEXT")
    await db.commit()
