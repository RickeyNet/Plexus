"""
Migration 0042: Audit report subsystem tables.

Adds the schema backing Plexus's network-audit reports:

* ``interface_inventory`` -- per-port snapshot (description, admin/oper state,
  speed/duplex, last-flap time, access VLAN, trunk allowed list). Filled by
  the SNMP collector and consumed by the port-hygiene + VLAN-consistency
  rules.
* ``vlan_definitions``     -- per-device VLAN list (id, name, state).
* ``audit_runs``           -- one row per audit invocation (status, summary).
* ``audit_findings``       -- one row per rule violation with severity, CIS
  mapping, evidence blob.
* ``audit_rule_overrides`` -- per-host or per-rule mute / accept-risk records.
* ``config_templates``     -- empty in v1; v2 will store per-platform Jinja2
  golden templates. Schema is laid down now so v2 doesn't need another
  migration.
"""

from __future__ import annotations

import os

VERSION = 42
DESCRIPTION = "Add audit report tables (interfaces, VLANs, runs, findings, overrides, templates)"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


# ── SQLite ──────────────────────────────────────────────────────────────────

async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS interface_inventory (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            if_index        INTEGER NOT NULL,
            name            TEXT    NOT NULL DEFAULT '',
            description     TEXT    NOT NULL DEFAULT '',
            admin_state     TEXT    NOT NULL DEFAULT '',
            oper_state      TEXT    NOT NULL DEFAULT '',
            speed_mbps      INTEGER NOT NULL DEFAULT 0,
            duplex          TEXT    NOT NULL DEFAULT '',
            last_change     TEXT    NOT NULL DEFAULT '',
            access_vlan     INTEGER NOT NULL DEFAULT 0,
            trunk_vlans     TEXT    NOT NULL DEFAULT '',
            collected_at    TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE (host_id, if_index)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_interface_inventory_host "
        "ON interface_inventory(host_id, name)"
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS vlan_definitions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            vlan_id         INTEGER NOT NULL,
            name            TEXT    NOT NULL DEFAULT '',
            state           TEXT    NOT NULL DEFAULT '',
            collected_at    TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE (host_id, vlan_id)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_vlan_definitions_host "
        "ON vlan_definitions(host_id, vlan_id)"
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_runs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            status          TEXT    NOT NULL DEFAULT 'pending',
            trigger         TEXT    NOT NULL DEFAULT 'manual',
            started_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            finished_at     TEXT,
            host_count      INTEGER NOT NULL DEFAULT 0,
            findings_total  INTEGER NOT NULL DEFAULT 0,
            findings_critical INTEGER NOT NULL DEFAULT 0,
            findings_high   INTEGER NOT NULL DEFAULT 0,
            findings_medium INTEGER NOT NULL DEFAULT 0,
            findings_low    INTEGER NOT NULL DEFAULT 0,
            findings_info   INTEGER NOT NULL DEFAULT 0,
            summary_json    TEXT    NOT NULL DEFAULT '{}',
            error_text      TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_runs_started "
        "ON audit_runs(started_at DESC)"
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id          INTEGER NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
            host_id         INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            rule_id         TEXT    NOT NULL DEFAULT '',
            category        TEXT    NOT NULL DEFAULT '',
            severity        TEXT    NOT NULL DEFAULT 'info',
            cis_control     TEXT    NOT NULL DEFAULT '',
            title           TEXT    NOT NULL DEFAULT '',
            detail          TEXT    NOT NULL DEFAULT '',
            evidence_json   TEXT    NOT NULL DEFAULT '{}',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_findings_run "
        "ON audit_findings(run_id, severity)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_findings_host "
        "ON audit_findings(host_id, run_id)"
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_rule_overrides (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id         TEXT    NOT NULL,
            host_id         INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
            mode            TEXT    NOT NULL DEFAULT 'mute',
            reason          TEXT    NOT NULL DEFAULT '',
            created_by      TEXT    NOT NULL DEFAULT '',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            expires_at      TEXT,
            UNIQUE (rule_id, host_id)
        )
        """
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS config_templates (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    NOT NULL,
            device_type     TEXT    NOT NULL DEFAULT '',
            template_text   TEXT    NOT NULL DEFAULT '',
            description     TEXT    NOT NULL DEFAULT '',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE (name, device_type)
        )
        """
    )
    await db.commit()


# ── Postgres ────────────────────────────────────────────────────────────────

async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS interface_inventory (
            id              BIGSERIAL PRIMARY KEY,
            host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            if_index        INTEGER NOT NULL,
            name            TEXT    NOT NULL DEFAULT '',
            description     TEXT    NOT NULL DEFAULT '',
            admin_state     TEXT    NOT NULL DEFAULT '',
            oper_state      TEXT    NOT NULL DEFAULT '',
            speed_mbps      BIGINT  NOT NULL DEFAULT 0,
            duplex          TEXT    NOT NULL DEFAULT '',
            last_change     TEXT    NOT NULL DEFAULT '',
            access_vlan     INTEGER NOT NULL DEFAULT 0,
            trunk_vlans     TEXT    NOT NULL DEFAULT '',
            collected_at    TEXT NOT NULL DEFAULT (NOW()::text),
            UNIQUE (host_id, if_index)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_interface_inventory_host "
        "ON interface_inventory(host_id, name)"
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS vlan_definitions (
            id              BIGSERIAL PRIMARY KEY,
            host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            vlan_id         INTEGER NOT NULL,
            name            TEXT    NOT NULL DEFAULT '',
            state           TEXT    NOT NULL DEFAULT '',
            collected_at    TEXT NOT NULL DEFAULT (NOW()::text),
            UNIQUE (host_id, vlan_id)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_vlan_definitions_host "
        "ON vlan_definitions(host_id, vlan_id)"
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_runs (
            id                BIGSERIAL PRIMARY KEY,
            status            TEXT NOT NULL DEFAULT 'pending',
            trigger           TEXT NOT NULL DEFAULT 'manual',
            started_at        TEXT NOT NULL DEFAULT (NOW()::text),
            finished_at       TEXT,
            host_count        INTEGER NOT NULL DEFAULT 0,
            findings_total    INTEGER NOT NULL DEFAULT 0,
            findings_critical INTEGER NOT NULL DEFAULT 0,
            findings_high     INTEGER NOT NULL DEFAULT 0,
            findings_medium   INTEGER NOT NULL DEFAULT 0,
            findings_low      INTEGER NOT NULL DEFAULT 0,
            findings_info     INTEGER NOT NULL DEFAULT 0,
            summary_json      TEXT NOT NULL DEFAULT '{}',
            error_text        TEXT NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_runs_started "
        "ON audit_runs(started_at DESC)"
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_findings (
            id              BIGSERIAL PRIMARY KEY,
            run_id          INTEGER NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
            host_id         INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            rule_id         TEXT    NOT NULL DEFAULT '',
            category        TEXT    NOT NULL DEFAULT '',
            severity        TEXT    NOT NULL DEFAULT 'info',
            cis_control     TEXT    NOT NULL DEFAULT '',
            title           TEXT    NOT NULL DEFAULT '',
            detail          TEXT    NOT NULL DEFAULT '',
            evidence_json   TEXT    NOT NULL DEFAULT '{}',
            created_at      TEXT NOT NULL DEFAULT (NOW()::text)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_findings_run "
        "ON audit_findings(run_id, severity)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_findings_host "
        "ON audit_findings(host_id, run_id)"
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_rule_overrides (
            id              BIGSERIAL PRIMARY KEY,
            rule_id         TEXT    NOT NULL,
            host_id         INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
            mode            TEXT    NOT NULL DEFAULT 'mute',
            reason          TEXT    NOT NULL DEFAULT '',
            created_by      TEXT    NOT NULL DEFAULT '',
            created_at      TEXT NOT NULL DEFAULT (NOW()::text),
            expires_at      TEXT,
            UNIQUE (rule_id, host_id)
        )
        """
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS config_templates (
            id              BIGSERIAL PRIMARY KEY,
            name            TEXT NOT NULL,
            device_type     TEXT NOT NULL DEFAULT '',
            template_text   TEXT NOT NULL DEFAULT '',
            description     TEXT NOT NULL DEFAULT '',
            created_at      TEXT NOT NULL DEFAULT (NOW()::text),
            updated_at      TEXT NOT NULL DEFAULT (NOW()::text),
            UNIQUE (name, device_type)
        )
        """
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
