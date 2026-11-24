"""
Migration 0135: a campaign device records that it came from inventory.

Adds:

  - upgrade_devices.from_inventory - 1 when the device was added to the
    campaign as an inventory host, 0 when its address was typed into the
    campaign. ``host_id`` alone cannot tell the two apart: it becomes NULL
    when the host is deleted. A campaign that runs with a shared credential
    signs in to a device from inventory only at its host's confirmed
    address (``netcontrol.managed_targets.recorded_address_refusal``).

Existing rows with a ``host_id`` are marked 1. A row whose host was deleted
before this release has no ``host_id`` left and stays 0, like an address
typed into the campaign.

Every step is idempotent.
"""

from __future__ import annotations

VERSION = 135
DESCRIPTION = "Record whether an upgrade campaign device was added from inventory"


async def up(db) -> None:
    await db.execute("ALTER TABLE upgrade_devices ADD COLUMN IF NOT EXISTS from_inventory INTEGER NOT NULL DEFAULT 0")
    await db.execute("UPDATE upgrade_devices SET from_inventory = 1 WHERE host_id IS NOT NULL AND from_inventory = 0")
    await db.commit()
