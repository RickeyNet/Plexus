"""
Migration 0136: hardware components with a serial, per host, and their
history (``netcontrol.hardware_components``, ``routes.db.hardware_components``).

Adds:

  - hardware_components - one row per serial a host has listed: what it is
    (``category``, ``slot``, ``name``, ``description``, ``model``, the
    revisions), ``status`` (``present``, ``missing``: absent from one
    complete read, ``removed``: still absent once missing for 30 minutes,
    or replaced), ``missing_since`` (when it went missing), the
    ``source`` that read it (``snmp`` / ``ssh``), ``first_seen``,
    ``last_seen`` and ``removed_at``. Removed rows are kept. Deleted with
    their host.
  - hardware_component_events - the append-only history (``baseline``,
    ``installed``, ``removed``, ``replaced``, ``moved``, ``changed``). Kept
    when the host is deleted: ``host_id`` is set NULL and ``hostname`` is
    kept as text. Not pruned automatically (DATA_RETENTION.md).
  - hardware_collection_state - per host: the last complete read
    (``collected_at``, ``source``), the last attempt (``attempted_at``,
    ``result``, ``message``), the empty reads in a row and whether the next
    poll reads the host again (``recheck``). Deleted with its host.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text. Every step is idempotent.
"""

from __future__ import annotations

VERSION = 136
DESCRIPTION = "Add hardware components with serials and their history"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS hardware_components (
            id            SERIAL PRIMARY KEY,
            host_id       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            category      TEXT    NOT NULL DEFAULT 'other',
            slot          TEXT    NOT NULL DEFAULT '',
            name          TEXT    NOT NULL DEFAULT '',
            description   TEXT    NOT NULL DEFAULT '',
            model         TEXT    NOT NULL DEFAULT '',
            serial        TEXT    NOT NULL,
            hardware_rev  TEXT    NOT NULL DEFAULT '',
            firmware_rev  TEXT    NOT NULL DEFAULT '',
            software_rev  TEXT    NOT NULL DEFAULT '',
            status        TEXT    NOT NULL DEFAULT 'present',
            source        TEXT    NOT NULL DEFAULT '',
            first_seen    TEXT    NOT NULL DEFAULT '',
            last_seen     TEXT    NOT NULL DEFAULT '',
            removed_at    TEXT,
            missing_since TEXT,
            UNIQUE (host_id, serial)
        )
        """
    )
    await db.execute("ALTER TABLE hardware_components ADD COLUMN IF NOT EXISTS missing_since TEXT")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_hardware_components_serial ON hardware_components (UPPER(serial))")
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_hardware_components_host ON hardware_components (host_id, status, category)"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS hardware_component_events (
            id                SERIAL PRIMARY KEY,
            host_id           INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            hostname          TEXT    NOT NULL DEFAULT '',
            occurred_at       TEXT    NOT NULL DEFAULT '',
            event             TEXT    NOT NULL,
            category          TEXT    NOT NULL DEFAULT '',
            slot              TEXT    NOT NULL DEFAULT '',
            name              TEXT    NOT NULL DEFAULT '',
            model             TEXT    NOT NULL DEFAULT '',
            serial            TEXT    NOT NULL DEFAULT '',
            previous_serial   TEXT    NOT NULL DEFAULT '',
            previous_model    TEXT    NOT NULL DEFAULT '',
            previous_slot     TEXT    NOT NULL DEFAULT '',
            previous_host_id  INTEGER,
            previous_hostname TEXT    NOT NULL DEFAULT '',
            changes_json      TEXT    NOT NULL DEFAULT '{}',
            detail            TEXT    NOT NULL DEFAULT '',
            source            TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_hardware_component_events_host "
        "ON hardware_component_events (host_id, occurred_at)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_hardware_component_events_time ON hardware_component_events (occurred_at)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_hardware_component_events_serial ON hardware_component_events (UPPER(serial))"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS hardware_collection_state (
            host_id         INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
            collected_at    TEXT    NOT NULL DEFAULT '',
            attempted_at    TEXT    NOT NULL DEFAULT '',
            source          TEXT    NOT NULL DEFAULT '',
            result          TEXT    NOT NULL DEFAULT '',
            message         TEXT    NOT NULL DEFAULT '',
            empty_reads     INTEGER NOT NULL DEFAULT 0,
            recheck         INTEGER NOT NULL DEFAULT 0,
            component_count INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    await db.commit()
