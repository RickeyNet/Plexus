"""
Migration 0139: the SNMP trap receiver's own SNMPv3 engine and its SNMPv3
replay record (``netcontrol.snmpv3_engine``, ``routes.db.snmp_engine``).

Adds:

  - snmp_local_engine - one row (``id`` 1): the receiver's snmpEngineID
    (``engine_id``, hex, generated once in the RFC 3411 format) and its
    snmpEngineBoots (``boots``), incremented each time the trap receiver
    starts listening. An SNMPv3 inform is authenticated against this
    engine ID, so it must not change.
  - snmpv3_replay_state - per (source address, sender engine ID): the
    highest engine boots and time accepted from a sender of SNMPv3 traps
    and the UTC time that was recorded (``seen_at``), so the time window
    survives a restart. Bounded: the receiver keeps the newest rows only
    (DATA_RETENTION.md).

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text. Every step is idempotent.
"""

from __future__ import annotations

VERSION = 139
DESCRIPTION = "Add the SNMP trap receiver's engine ID, engine boots and SNMPv3 replay record"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS snmp_local_engine (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            engine_id TEXT NOT NULL,
            boots INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS snmpv3_replay_state (
            source TEXT NOT NULL,
            engine_id TEXT NOT NULL,
            boots INTEGER NOT NULL,
            engine_time INTEGER NOT NULL,
            seen_at TEXT NOT NULL,
            PRIMARY KEY (source, engine_id)
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_snmpv3_replay_state_seen ON snmpv3_replay_state (seen_at)")
    await db.commit()
