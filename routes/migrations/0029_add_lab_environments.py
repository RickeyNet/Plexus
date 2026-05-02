"""
Migration 0029: Digital twin / lab mode for safe pre-production change testing.

Adds:
  - lab_environments — named workspaces that group simulated devices and runs.
    A lab environment is owned by a user and can be private or shared with all
    operators. Each environment carries description and active flag for archival.
  - lab_devices — virtual or cloned-from-production devices within an
    environment. Stores a snapshot of the running config text plus metadata
    (device_type, hostname, ip_address, model). source_host_id links to the
    real inventory host the snapshot was cloned from when applicable.
  - lab_runs — record of each simulated change applied to a lab device. Stores
    the proposed commands, the resulting simulated config, the unified diff
    against the prior state, optional risk score/level, and a status indicating
    whether the run was simulated only or promoted to production via the
    deployments router.
"""

from __future__ import annotations

import os

VERSION = 29
DESCRIPTION = "Add lab_environments, lab_devices, lab_runs for digital twin mode"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_environments (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT    NOT NULL UNIQUE,
            description  TEXT    NOT NULL DEFAULT '',
            owner_id     INTEGER,
            shared       INTEGER NOT NULL DEFAULT 0,
            active       INTEGER NOT NULL DEFAULT 1,
            created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at   TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_devices (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            environment_id  INTEGER NOT NULL,
            hostname        TEXT    NOT NULL,
            ip_address      TEXT    NOT NULL DEFAULT '',
            device_type     TEXT    NOT NULL DEFAULT 'cisco_ios',
            model           TEXT    NOT NULL DEFAULT '',
            source_host_id  INTEGER,
            running_config  TEXT    NOT NULL DEFAULT '',
            notes           TEXT    NOT NULL DEFAULT '',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (environment_id) REFERENCES lab_environments(id) ON DELETE CASCADE,
            FOREIGN KEY (source_host_id) REFERENCES hosts(id) ON DELETE SET NULL
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_lab_devices_env "
        "ON lab_devices (environment_id)"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_runs (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            lab_device_id    INTEGER NOT NULL,
            submitted_by     TEXT    NOT NULL DEFAULT '',
            commands         TEXT    NOT NULL DEFAULT '',
            pre_config       TEXT    NOT NULL DEFAULT '',
            post_config      TEXT    NOT NULL DEFAULT '',
            diff_text        TEXT    NOT NULL DEFAULT '',
            diff_added       INTEGER NOT NULL DEFAULT 0,
            diff_removed     INTEGER NOT NULL DEFAULT 0,
            risk_score       REAL    NOT NULL DEFAULT 0,
            risk_level       TEXT    NOT NULL DEFAULT '',
            risk_detail      TEXT    NOT NULL DEFAULT '',
            status           TEXT    NOT NULL DEFAULT 'simulated',
            promoted_deployment_id INTEGER,
            created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (lab_device_id) REFERENCES lab_devices(id) ON DELETE CASCADE
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_lab_runs_device "
        "ON lab_runs (lab_device_id, created_at)"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_environments (
            id           SERIAL PRIMARY KEY,
            name         TEXT    NOT NULL UNIQUE,
            description  TEXT    NOT NULL DEFAULT '',
            owner_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
            shared       BOOLEAN NOT NULL DEFAULT FALSE,
            active       BOOLEAN NOT NULL DEFAULT TRUE,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_devices (
            id              SERIAL PRIMARY KEY,
            environment_id  INTEGER NOT NULL REFERENCES lab_environments(id) ON DELETE CASCADE,
            hostname        TEXT    NOT NULL,
            ip_address      TEXT    NOT NULL DEFAULT '',
            device_type     TEXT    NOT NULL DEFAULT 'cisco_ios',
            model           TEXT    NOT NULL DEFAULT '',
            source_host_id  INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            running_config  TEXT    NOT NULL DEFAULT '',
            notes           TEXT    NOT NULL DEFAULT '',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_lab_devices_env "
        "ON lab_devices (environment_id)"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_runs (
            id               SERIAL PRIMARY KEY,
            lab_device_id    INTEGER NOT NULL REFERENCES lab_devices(id) ON DELETE CASCADE,
            submitted_by     TEXT    NOT NULL DEFAULT '',
            commands         TEXT    NOT NULL DEFAULT '',
            pre_config       TEXT    NOT NULL DEFAULT '',
            post_config      TEXT    NOT NULL DEFAULT '',
            diff_text        TEXT    NOT NULL DEFAULT '',
            diff_added       INTEGER NOT NULL DEFAULT 0,
            diff_removed     INTEGER NOT NULL DEFAULT 0,
            risk_score       REAL    NOT NULL DEFAULT 0,
            risk_level       TEXT    NOT NULL DEFAULT '',
            risk_detail      TEXT    NOT NULL DEFAULT '',
            status           TEXT    NOT NULL DEFAULT 'simulated',
            promoted_deployment_id INTEGER,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_lab_runs_device "
        "ON lab_runs (lab_device_id, created_at)"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
