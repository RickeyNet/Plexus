"""
Migration 0069: Add an explicit AWS instance ID to hosts.

The AWS topology recognises an inventory host as an EC2 instance by its
addresses. ``aws_instance_id`` names the instance outright (``i-0abc...``)
and is checked before any address match, for hosts whose inventory address
is not one AWS records (a NAT or load-balanced address, a DNS name's IP).

Existing rows default to ``''`` (no override).
"""

from __future__ import annotations

VERSION = 69
DESCRIPTION = "Add aws_instance_id to hosts"

_COLUMN = "aws_instance_id"
_DECL = "TEXT NOT NULL DEFAULT ''"


async def up(db) -> None:
    await db.execute(f"ALTER TABLE hosts ADD COLUMN IF NOT EXISTS {_COLUMN} {_DECL}")
    await db.commit()
