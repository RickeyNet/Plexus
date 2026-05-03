"""
Migration 0030: Phase B-1 — containerlab runtime support for lab mode.

Extends `lab_devices` with runtime metadata so a single twin can optionally
back its config snapshot with a real virtual device (Arista cEOS, Nokia
SR Linux, FRR, generic Linux, …) deployed via containerlab.

Adds:
  - lab_devices.runtime_kind          'config_only' (default) | 'containerlab'
  - lab_devices.runtime_node_kind     containerlab `kind` field (ceos, srl, linux, …)
  - lab_devices.runtime_image         container image reference (e.g. 'ceos:4.30.0F')
  - lab_devices.runtime_status        '' | provisioning | running | stopped | error | destroyed
  - lab_devices.runtime_lab_name      containerlab lab name (used to destroy)
  - lab_devices.runtime_node_name     node name within the lab
  - lab_devices.runtime_mgmt_address  IP address on the management network
  - lab_devices.runtime_credential_id credential used for live SSH push
  - lab_devices.runtime_error         last error message from runtime ops
  - lab_devices.runtime_workdir       absolute path to the generated topology workdir
  - lab_devices.runtime_started_at    timestamp the container was last started

  - lab_runtime_events — append-only deploy/destroy/refresh history per device.
    Stores actor, action, status (ok/error), detail JSON, and timestamps so
    operators can audit runtime activity from the UI.
"""

from __future__ import annotations

import os

VERSION = 30
DESCRIPTION = "Add containerlab runtime fields to lab_devices and lab_runtime_events"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


# Columns to add to lab_devices, in order. Same set for both engines except
# the integer FK which is defined inline on postgres for parity.
_RUNTIME_COLUMNS = [
    ("runtime_kind", "TEXT NOT NULL DEFAULT 'config_only'"),
    ("runtime_node_kind", "TEXT NOT NULL DEFAULT ''"),
    ("runtime_image", "TEXT NOT NULL DEFAULT ''"),
    ("runtime_status", "TEXT NOT NULL DEFAULT ''"),
    ("runtime_lab_name", "TEXT NOT NULL DEFAULT ''"),
    ("runtime_node_name", "TEXT NOT NULL DEFAULT ''"),
    ("runtime_mgmt_address", "TEXT NOT NULL DEFAULT ''"),
    ("runtime_credential_id", "INTEGER"),
    ("runtime_error", "TEXT NOT NULL DEFAULT ''"),
    ("runtime_workdir", "TEXT NOT NULL DEFAULT ''"),
    ("runtime_started_at", "TEXT"),
]


async def _column_exists(db, table: str, column: str, *, engine: str) -> bool:
    if engine == "postgres":
        cur = await db.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = ? AND column_name = ?",
            (table, column),
        )
        return await cur.fetchone() is not None
    cur = await db.execute(f"PRAGMA table_info({table})")
    rows = await cur.fetchall()
    return any(
        (row[1] if not isinstance(row, dict) else row.get("name")) == column
        for row in rows
    )


async def _add_columns(db, *, engine: str) -> None:
    for name, ddl in _RUNTIME_COLUMNS:
        if await _column_exists(db, "lab_devices", name, engine=engine):
            continue
        await db.execute(f"ALTER TABLE lab_devices ADD COLUMN {name} {ddl}")


async def _up_sqlite(db) -> None:
    await _add_columns(db, engine="sqlite")
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_runtime_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            lab_device_id   INTEGER NOT NULL,
            action          TEXT    NOT NULL,
            status          TEXT    NOT NULL DEFAULT 'ok',
            actor           TEXT    NOT NULL DEFAULT '',
            detail          TEXT    NOT NULL DEFAULT '',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (lab_device_id) REFERENCES lab_devices(id) ON DELETE CASCADE
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_lab_runtime_events_device "
        "ON lab_runtime_events (lab_device_id, created_at)"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await _add_columns(db, engine="postgres")
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_runtime_events (
            id              SERIAL PRIMARY KEY,
            lab_device_id   INTEGER NOT NULL REFERENCES lab_devices(id) ON DELETE CASCADE,
            action          TEXT    NOT NULL,
            status          TEXT    NOT NULL DEFAULT 'ok',
            actor           TEXT    NOT NULL DEFAULT '',
            detail          TEXT    NOT NULL DEFAULT '',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_lab_runtime_events_device "
        "ON lab_runtime_events (lab_device_id, created_at)"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
