"""
Migration 0116: the ``ups`` device category and the UPS device role.

The ``ups`` category is new (APC Smart-UPS hosts, device type ``apc_ups``).

  - The UPS role joins the seeded roles (migration 0085), unless a role of
    that name exists already.
  - An ``apc_ups`` host with no category takes ``ups``. A category someone
    set is left alone.
  - Such a host with no role takes the role named ``ups`` (ignoring case),
    as migration 0085 filled roles from categories.

Every step is idempotent.
"""

from __future__ import annotations

VERSION = 116
DESCRIPTION = "Add the ups device category and UPS role for APC Smart-UPS hosts"


async def up(db) -> None:
    await db.execute(
        """INSERT INTO device_roles (name, color, created_at)
           SELECT 'UPS', 'yellow', ''
           WHERE NOT EXISTS (SELECT 1 FROM device_roles WHERE lower(name) = 'ups')"""
    )
    await db.execute(
        """UPDATE hosts SET device_category = 'ups'
           WHERE device_type = 'apc_ups' AND trim(device_category) = ''"""
    )
    await db.execute(
        """UPDATE hosts AS h SET role_id = r.id FROM device_roles r
           WHERE h.role_id IS NULL AND h.device_type = 'apc_ups' AND h.device_category = 'ups'
             AND lower(r.name) = 'ups'"""
    )
    await db.commit()
