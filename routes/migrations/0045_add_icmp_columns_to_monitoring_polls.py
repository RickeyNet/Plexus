"""
Migration 0045: Add ICMP liveness columns to monitoring_polls.

`icmp_alive` and `icmp_rtt_ms` are populated by the independent ICMP probe
in `_poll_host_monitoring` so the UI can surface "pings but SNMP broken"
as a distinct state (the diagnostic gap that motivated this feature for
SNMPv3-on-Cisco-FTD).  Existing rows pre-dating ICMP support stay NULL,
which the UI already treats as "no data" for the field.
"""

from __future__ import annotations

import os

VERSION = 45
DESCRIPTION = "Add icmp_alive + icmp_rtt_ms to monitoring_polls"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up(db) -> None:
    await db.execute(
        "ALTER TABLE monitoring_polls ADD COLUMN icmp_alive INTEGER DEFAULT NULL"
    )
    await db.execute(
        "ALTER TABLE monitoring_polls ADD COLUMN icmp_rtt_ms REAL DEFAULT NULL"
    )
    await db.commit()


async def up(db) -> None:
    await _up(db)
