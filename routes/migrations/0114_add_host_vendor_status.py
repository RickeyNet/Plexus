"""
Migration 0114: vendor status of an inventory host.

Adds:

  - host_vendor_status - the newest vendor-specific state the monitoring
    poll read from a host beyond the common CPU / memory / interface
    columns of ``monitoring_polls``: one row per host (``host_id``, deleted
    with the host), ``kind`` (what the state describes, ``apc_ups`` for an
    APC Smart-UPS read over PowerNet-MIB), ``status`` (JSON text of the
    values, see ``netcontrol/integrations/apc/snmp.py``) and ``polled_at``.
    The history of the numeric values is kept in ``metric_samples`` and its
    rollups; this row is the current state the device page shows and the
    software tracker reads the UPS firmware from.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 114
DESCRIPTION = "Add the vendor status of inventory hosts"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS host_vendor_status (
            host_id   INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
            kind      TEXT    NOT NULL DEFAULT '',
            status    TEXT    NOT NULL DEFAULT '{}',
            polled_at TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.commit()
