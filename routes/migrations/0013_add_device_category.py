"""
Migration 0013: Add device_category column to hosts table.

Stores the inferred device role (router, switch, firewall, wireless, wlc,
phone, server, unknown) populated automatically from SNMP discovery or set
manually.  Also backfills existing hosts based on their model string.
"""

from __future__ import annotations

import os
import re

VERSION = 13
DESCRIPTION = "Add device_category to hosts for topology icons"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"

# Lightweight category inference for backfill (mirrors snmp._infer_device_category)
_CAT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"C9800|AIR-CT|WLC|C3504", re.I), "wlc"),
    (re.compile(r"AIR-AP|AIR-CAP|C9120|C9130|C9136|C9162|C9164|CW916", re.I), "wireless"),
    (re.compile(r"CP-\d|IP\s?Phone|SEP[0-9A-F]", re.I), "phone"),
    (re.compile(r"ISR\d|ASR\d|CSR1|NCS-|C8[0-9]{3}|CISCO[0-9]{4}", re.I), "router"),
    (re.compile(r"C9[0-9]{3}|C3[0-9]{3}|C2[0-9]{3}|WS-C|C1[01][0-9]{2}F?", re.I), "switch"),
    (re.compile(r"N[3579]K|N[0-9]{4}|Nexus", re.I), "switch"),
    (re.compile(r"forti", re.I), "firewall"),
    (re.compile(r"MX\d|PTX|ACX|SRX[0-9]{4}", re.I), "router"),
    (re.compile(r"EX\d|QFX", re.I), "switch"),
    (re.compile(r"SRX[0-9]{2,3}$", re.I), "firewall"),
    (re.compile(r"DCS-|CCS-", re.I), "switch"),
    (re.compile(r"PA-\d", re.I), "firewall"),
    (re.compile(r"UCS|PowerEdge|ProLiant|server", re.I), "server"),
]


def _infer_cat(model: str, device_type: str) -> str:
    for pattern, cat in _CAT_PATTERNS:
        if pattern.search(model or ""):
            return cat
    if device_type == "fortinet":
        return "firewall"
    return ""


async def _backfill(db) -> None:
    """Set device_category for existing hosts that have a model string."""
    cursor = await db.execute("SELECT id, model, device_type FROM hosts WHERE model != ''")
    rows = await cursor.fetchall()
    for row in rows:
        cat = _infer_cat(row[1], row[2])
        if cat:
            await db.execute(
                "UPDATE hosts SET device_category = ? WHERE id = ?",
                (cat, row[0]),
            )
    await db.commit()


async def _up_sqlite(db) -> None:
    await db.execute(
        "ALTER TABLE hosts ADD COLUMN device_category TEXT NOT NULL DEFAULT ''"
    )
    await db.commit()
    await _backfill(db)


async def _up_postgres(db) -> None:
    await db.execute(
        "ALTER TABLE hosts ADD COLUMN device_category TEXT NOT NULL DEFAULT ''"
    )
    await db.commit()
    await _backfill(db)


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
