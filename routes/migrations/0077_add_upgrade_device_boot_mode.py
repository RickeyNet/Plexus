"""
Migration 0077: record each upgrade device's boot mode.

The upgrade engine reads a Catalyst's boot mode (``show version`` Mode
column: INSTALL or BUNDLE) during prestage, transfer, activate and the
status check. Install-mode upgrades (including ISSU) cannot run on a
BUNDLE-mode switch, so the campaign table shows the mode per device.

  - boot_mode - ``install``, ``bundle``, or ``''`` (not read yet / the
    platform has no boot-mode concept / the output did not say).
"""

from __future__ import annotations

VERSION = 77
DESCRIPTION = "Add boot_mode to upgrade_devices"


async def up(db) -> None:
    await db.execute("ALTER TABLE upgrade_devices ADD COLUMN IF NOT EXISTS boot_mode TEXT NOT NULL DEFAULT ''")
    await db.commit()
