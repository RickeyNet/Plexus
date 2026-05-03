"""
Migration 0031: Phase B-2 — multi-device lab topologies.

Phase B-1 deployed each lab device as its own containerlab single-node lab.
Phase B-2 lets operators link N devices into one containerlab topology so
routing/STP/LACP behaviors can be exercised end-to-end against real NOS
images.

Adds:
  - lab_topologies — one row per multi-node topology. Lives inside a lab
    environment. Stores its own runtime status, lab name, workdir, and an
    optional management subnet override.
  - lab_topology_links — one row per cable between two lab devices. Stores
    the endpoint name on each side (e.g. eth1, GigabitEthernet0/1) so the
    YAML generator can emit a containerlab `links` entry verbatim.
  - lab_devices.topology_id — nullable FK so a device knows whether it's
    a free-standing twin (Phase B-1) or a member of a topology (Phase B-2).
    The two modes are mutually exclusive at deploy time.

Free-standing twins keep working unchanged; only deploy/destroy semantics
change for topology-attached devices (managed at topology level).
"""

from __future__ import annotations

import os

VERSION = 31
DESCRIPTION = "Add lab_topologies, lab_topology_links, and lab_devices.topology_id"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


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


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_topologies (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            environment_id  INTEGER NOT NULL,
            name            TEXT    NOT NULL,
            description     TEXT    NOT NULL DEFAULT '',
            lab_name        TEXT    NOT NULL DEFAULT '',
            status          TEXT    NOT NULL DEFAULT '',
            workdir         TEXT    NOT NULL DEFAULT '',
            mgmt_subnet     TEXT    NOT NULL DEFAULT '',
            error           TEXT    NOT NULL DEFAULT '',
            started_at      TEXT,
            created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (environment_id) REFERENCES lab_environments(id) ON DELETE CASCADE,
            UNIQUE (environment_id, name)
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_topology_links (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            topology_id     INTEGER NOT NULL,
            a_device_id     INTEGER NOT NULL,
            a_endpoint      TEXT    NOT NULL,
            b_device_id     INTEGER NOT NULL,
            b_endpoint      TEXT    NOT NULL,
            FOREIGN KEY (topology_id) REFERENCES lab_topologies(id) ON DELETE CASCADE,
            FOREIGN KEY (a_device_id) REFERENCES lab_devices(id) ON DELETE CASCADE,
            FOREIGN KEY (b_device_id) REFERENCES lab_devices(id) ON DELETE CASCADE
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_lab_topology_links_topo "
        "ON lab_topology_links (topology_id)"
    )
    if not await _column_exists(db, "lab_devices", "topology_id", engine="sqlite"):
        await db.execute(
            "ALTER TABLE lab_devices ADD COLUMN topology_id INTEGER "
            "REFERENCES lab_topologies(id) ON DELETE SET NULL"
        )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_lab_devices_topology "
        "ON lab_devices (topology_id)"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_topologies (
            id              SERIAL PRIMARY KEY,
            environment_id  INTEGER NOT NULL REFERENCES lab_environments(id) ON DELETE CASCADE,
            name            TEXT    NOT NULL,
            description     TEXT    NOT NULL DEFAULT '',
            lab_name        TEXT    NOT NULL DEFAULT '',
            status          TEXT    NOT NULL DEFAULT '',
            workdir         TEXT    NOT NULL DEFAULT '',
            mgmt_subnet     TEXT    NOT NULL DEFAULT '',
            error           TEXT    NOT NULL DEFAULT '',
            started_at      TIMESTAMPTZ,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (environment_id, name)
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_topology_links (
            id              SERIAL PRIMARY KEY,
            topology_id     INTEGER NOT NULL REFERENCES lab_topologies(id) ON DELETE CASCADE,
            a_device_id     INTEGER NOT NULL REFERENCES lab_devices(id) ON DELETE CASCADE,
            a_endpoint      TEXT    NOT NULL,
            b_device_id     INTEGER NOT NULL REFERENCES lab_devices(id) ON DELETE CASCADE,
            b_endpoint      TEXT    NOT NULL
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_lab_topology_links_topo "
        "ON lab_topology_links (topology_id)"
    )
    if not await _column_exists(db, "lab_devices", "topology_id", engine="postgres"):
        await db.execute(
            "ALTER TABLE lab_devices ADD COLUMN topology_id INTEGER "
            "REFERENCES lab_topologies(id) ON DELETE SET NULL"
        )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_lab_devices_topology "
        "ON lab_devices (topology_id)"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
