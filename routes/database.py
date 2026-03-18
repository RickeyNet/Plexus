"""
database.py — Async SQLite database layer for Plexus.

Tables:
    inventory_groups  — device groups (name, description)
    hosts             — individual devices linked to a group
    playbooks         — registered automation scripts
    templates         — reusable config snippets
    credentials       — encrypted SSH credentials per inventory group
    jobs              — execution history
    job_events        — per-host log lines for each job
    audit_events      — immutable audit trail for auth, CRUD, and operational actions
    topology_links    — discovered L2/L3 neighbor relationships between devices
    interface_stats   — SNMP interface counter snapshots for utilization calculation
    topology_changes  — detected topology differences between discovery runs
    config_baselines  — intended/golden configuration per host
    config_snapshots  — timestamped running-config captures per host
    config_drift_events — detected configuration drift instances
    config_backup_policies — scheduled configuration backup policies per group
    config_backups     — stored configuration backup records
    compliance_profiles — golden template compliance rule sets
    compliance_profile_assignments — profile-to-group bindings with scan schedule
    compliance_scan_results — per-host compliance scan findings
    risk_analyses          — pre-change risk analysis records
    deployments            — deployment orchestration records with rollback support
    deployment_checkpoints — pre/post deployment validation checks
    deployment_snapshots   — per-host config snapshots captured before/after deployment
    monitoring_polls       — periodic device health poll snapshots (CPU/mem/interfaces/VPN/routes)
    monitoring_alerts      — threshold violations and anomaly alerts (with dedup/escalation)
    route_snapshots        — route table captures for churn detection
    alert_rules            — user-defined threshold/anomaly alert rules
    alert_suppressions     — time-windowed alert suppression entries
"""

import json
import os
import re
from datetime import UTC, datetime

import aiosqlite

try:
    import asyncpg
except Exception:  # pragma: no cover - optional dependency for postgres mode
    asyncpg = None

from netcontrol.telemetry import configure_logging

_LOGGER = configure_logging("plexus.db")

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"
APP_DATABASE_URL = os.getenv("APP_DATABASE_URL", "").strip()
_VALID_DB_ENGINES = {"sqlite", "postgres"}

DB_PATH = os.getenv(
    "APP_DB_PATH",
    os.path.join(os.path.dirname(__file__), "netcontrol.db"),
)
SQLITE_CONNECT_TIMEOUT = float(os.getenv("APP_SQLITE_CONNECT_TIMEOUT", "30"))
SQLITE_BUSY_TIMEOUT_MS = int(os.getenv("APP_SQLITE_BUSY_TIMEOUT_MS", "5000"))

_INSERT_ID_TABLES = {
    "users",
    "access_groups",
    "inventory_groups",
    "hosts",
    "playbooks",
    "templates",
    "credentials",
    "jobs",
    "audit_events",
    "topology_links",
    "interface_stats",
    "topology_changes",
    "config_baselines",
    "config_snapshots",
    "config_drift_events",
    "config_backup_policies",
    "config_backups",
    "compliance_profiles",
    "compliance_profile_assignments",
    "compliance_scan_results",
    "risk_analyses",
    "deployments",
    "deployment_checkpoints",
    "deployment_snapshots",
    "monitoring_polls",
    "monitoring_alerts",
    "route_snapshots",
    "alert_rules",
    "alert_suppressions",
    "sla_targets",
    "sla_metrics",
}

# ── Schema ───────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE,
    password_hash TEXT  NOT NULL,
    salt        TEXT    NOT NULL,
    display_name TEXT   DEFAULT '',
    role        TEXT    NOT NULL DEFAULT 'user',
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS access_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS access_group_features (
    group_id    INTEGER NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
    feature_key TEXT    NOT NULL,
    PRIMARY KEY (group_id, feature_key)
);

CREATE TABLE IF NOT EXISTS user_group_memberships (
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id    INTEGER NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS auth_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS inventory_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id    INTEGER NOT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
    hostname    TEXT    NOT NULL,
    ip_address  TEXT    NOT NULL,
    device_type TEXT    NOT NULL DEFAULT 'cisco_ios',
    status      TEXT    NOT NULL DEFAULT 'unknown',
    last_seen   TEXT,
    UNIQUE(group_id, ip_address)
);

CREATE TABLE IF NOT EXISTS playbooks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    filename    TEXT    NOT NULL,
    type        TEXT    NOT NULL DEFAULT 'python',
    description TEXT    DEFAULT '',
    tags        TEXT    DEFAULT '[]',
    content     TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT
);

CREATE TABLE IF NOT EXISTS templates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    content     TEXT    NOT NULL DEFAULT '',
    description TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    username    TEXT    NOT NULL,
    password    TEXT    NOT NULL,
    secret      TEXT    NOT NULL DEFAULT '',
    owner_id    INTEGER REFERENCES users(id),
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id     INTEGER NOT NULL REFERENCES playbooks(id),
    inventory_group_id INTEGER NOT NULL REFERENCES inventory_groups(id),
    credential_id   INTEGER REFERENCES credentials(id),
    template_id     INTEGER REFERENCES templates(id),
    dry_run         INTEGER NOT NULL DEFAULT 1,
    status          TEXT    NOT NULL DEFAULT 'pending',
    priority        INTEGER NOT NULL DEFAULT 2,
    depends_on      TEXT    NOT NULL DEFAULT '[]',
    queued_at       TEXT,
    started_at      TEXT,
    finished_at     TEXT,
    cancelled_at    TEXT,
    cancelled_by    TEXT    DEFAULT '',
    hosts_ok        INTEGER DEFAULT 0,
    hosts_failed    INTEGER DEFAULT 0,
    hosts_skipped   INTEGER DEFAULT 0,
    launched_by     TEXT    DEFAULT 'admin'
);

CREATE TABLE IF NOT EXISTS job_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now')),
    level       TEXT    NOT NULL DEFAULT 'info',
    host        TEXT    DEFAULT '',
    message     TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL DEFAULT (datetime('now')),
    category        TEXT    NOT NULL,
    action          TEXT    NOT NULL,
    user            TEXT    NOT NULL DEFAULT '',
    detail          TEXT    DEFAULT '',
    correlation_id  TEXT    DEFAULT ''
);

CREATE TABLE IF NOT EXISTS topology_links (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    source_host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    source_ip           TEXT    NOT NULL,
    source_interface    TEXT    NOT NULL DEFAULT '',
    target_host_id      INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    target_ip           TEXT    DEFAULT '',
    target_device_name  TEXT    NOT NULL DEFAULT '',
    target_interface    TEXT    NOT NULL DEFAULT '',
    protocol            TEXT    NOT NULL DEFAULT 'cdp',
    target_platform     TEXT    DEFAULT '',
    discovered_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(source_host_id, source_interface, target_device_name, target_interface)
);

CREATE TABLE IF NOT EXISTS interface_stats (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id             INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    if_index            INTEGER NOT NULL,
    if_name             TEXT    NOT NULL DEFAULT '',
    if_speed_mbps       INTEGER DEFAULT 0,
    in_octets           INTEGER DEFAULT 0,
    out_octets          INTEGER DEFAULT 0,
    prev_in_octets      INTEGER DEFAULT 0,
    prev_out_octets     INTEGER DEFAULT 0,
    polled_at           TEXT    NOT NULL DEFAULT (datetime('now')),
    prev_polled_at      TEXT    DEFAULT NULL,
    UNIQUE(host_id, if_index)
);

CREATE TABLE IF NOT EXISTS topology_changes (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    change_type         TEXT    NOT NULL,
    source_host_id      INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    source_hostname     TEXT    DEFAULT '',
    source_interface    TEXT    DEFAULT '',
    target_device_name  TEXT    DEFAULT '',
    target_interface    TEXT    DEFAULT '',
    target_ip           TEXT    DEFAULT '',
    protocol            TEXT    DEFAULT '',
    detected_at         TEXT    NOT NULL DEFAULT (datetime('now')),
    acknowledged        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS topology_node_positions (
    node_id             TEXT    PRIMARY KEY,
    x                   REAL    NOT NULL DEFAULT 0,
    y                   REAL    NOT NULL DEFAULT 0,
    updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS config_baselines (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL DEFAULT '',
    config_text TEXT    NOT NULL DEFAULT '',
    source      TEXT    NOT NULL DEFAULT 'manual',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    created_by  TEXT    NOT NULL DEFAULT '',
    UNIQUE(host_id)
);

CREATE TABLE IF NOT EXISTS config_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    config_text     TEXT    NOT NULL DEFAULT '',
    captured_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    capture_method  TEXT    NOT NULL DEFAULT 'manual'
);

CREATE TABLE IF NOT EXISTS config_drift_events (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id            INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    snapshot_id        INTEGER NOT NULL REFERENCES config_snapshots(id) ON DELETE CASCADE,
    baseline_id        INTEGER REFERENCES config_baselines(id) ON DELETE SET NULL,
    status             TEXT    NOT NULL DEFAULT 'open',
    diff_text          TEXT    NOT NULL DEFAULT '',
    diff_lines_added   INTEGER NOT NULL DEFAULT 0,
    diff_lines_removed INTEGER NOT NULL DEFAULT 0,
    detected_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    resolved_at        TEXT,
    resolved_by        TEXT    DEFAULT ''
);

CREATE TABLE IF NOT EXISTS config_backup_policies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    group_id        INTEGER NOT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
    credential_id   INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    enabled         INTEGER NOT NULL DEFAULT 1,
    interval_seconds INTEGER NOT NULL DEFAULT 86400,
    retention_days  INTEGER NOT NULL DEFAULT 30,
    last_run_at     TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    created_by      TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS config_backups (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id       INTEGER REFERENCES config_backup_policies(id) ON DELETE SET NULL,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    config_text     TEXT    NOT NULL DEFAULT '',
    capture_method  TEXT    NOT NULL DEFAULT 'scheduled',
    status          TEXT    NOT NULL DEFAULT 'success',
    error_message   TEXT    DEFAULT '',
    captured_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS compliance_profiles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    DEFAULT '',
    rules       TEXT    NOT NULL DEFAULT '[]',
    severity    TEXT    NOT NULL DEFAULT 'medium',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    created_by  TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS compliance_profile_assignments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER NOT NULL REFERENCES compliance_profiles(id) ON DELETE CASCADE,
    group_id    INTEGER NOT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
    credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    enabled     INTEGER NOT NULL DEFAULT 1,
    interval_seconds INTEGER NOT NULL DEFAULT 86400,
    last_scan_at TEXT,
    assigned_at TEXT    NOT NULL DEFAULT (datetime('now')),
    assigned_by TEXT    NOT NULL DEFAULT '',
    UNIQUE(profile_id, group_id)
);

CREATE TABLE IF NOT EXISTS compliance_scan_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id   INTEGER REFERENCES compliance_profile_assignments(id) ON DELETE SET NULL,
    profile_id      INTEGER NOT NULL REFERENCES compliance_profiles(id) ON DELETE CASCADE,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    status          TEXT    NOT NULL DEFAULT 'compliant',
    total_rules     INTEGER NOT NULL DEFAULT 0,
    passed_rules    INTEGER NOT NULL DEFAULT 0,
    failed_rules    INTEGER NOT NULL DEFAULT 0,
    findings        TEXT    NOT NULL DEFAULT '[]',
    config_snippet  TEXT    NOT NULL DEFAULT '',
    scanned_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS risk_analyses (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    change_type         TEXT    NOT NULL DEFAULT 'template',
    host_id             INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    group_id            INTEGER REFERENCES inventory_groups(id) ON DELETE SET NULL,
    risk_level          TEXT    NOT NULL DEFAULT 'low',
    risk_score          REAL    NOT NULL DEFAULT 0.0,
    proposed_commands   TEXT    NOT NULL DEFAULT '',
    proposed_diff       TEXT    NOT NULL DEFAULT '',
    current_config      TEXT    NOT NULL DEFAULT '',
    simulated_config    TEXT    NOT NULL DEFAULT '',
    analysis            TEXT    NOT NULL DEFAULT '{}',
    compliance_impact   TEXT    NOT NULL DEFAULT '[]',
    affected_areas      TEXT    NOT NULL DEFAULT '[]',
    approved            INTEGER NOT NULL DEFAULT 0,
    approved_by         TEXT    DEFAULT '',
    approved_at         TEXT,
    created_by          TEXT    NOT NULL DEFAULT '',
    created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS deployments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    description     TEXT    DEFAULT '',
    group_id        INTEGER NOT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
    credential_id   INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    change_type     TEXT    NOT NULL DEFAULT 'template',
    proposed_commands TEXT  NOT NULL DEFAULT '',
    template_id     INTEGER REFERENCES templates(id) ON DELETE SET NULL,
    risk_analysis_id INTEGER REFERENCES risk_analyses(id) ON DELETE SET NULL,
    status          TEXT    NOT NULL DEFAULT 'planning',
    rollback_status TEXT    DEFAULT '',
    host_ids        TEXT    NOT NULL DEFAULT '[]',
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    started_at      TEXT,
    finished_at     TEXT
);

CREATE TABLE IF NOT EXISTS deployment_checkpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_id   INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    phase           TEXT    NOT NULL DEFAULT 'pre',
    check_name      TEXT    NOT NULL,
    check_type      TEXT    NOT NULL DEFAULT 'config_capture',
    status          TEXT    NOT NULL DEFAULT 'pending',
    host_id         INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    result          TEXT    NOT NULL DEFAULT '{}',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    executed_at     TEXT
);

CREATE TABLE IF NOT EXISTS deployment_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_id   INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    phase           TEXT    NOT NULL DEFAULT 'pre',
    config_text     TEXT    NOT NULL DEFAULT '',
    captured_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS monitoring_polls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    cpu_percent     REAL    DEFAULT NULL,
    memory_percent  REAL    DEFAULT NULL,
    memory_used_mb  REAL    DEFAULT NULL,
    memory_total_mb REAL    DEFAULT NULL,
    uptime_seconds  INTEGER DEFAULT NULL,
    if_up_count     INTEGER DEFAULT 0,
    if_down_count   INTEGER DEFAULT 0,
    if_admin_down   INTEGER DEFAULT 0,
    if_details      TEXT    NOT NULL DEFAULT '[]',
    vpn_tunnels_up  INTEGER DEFAULT 0,
    vpn_tunnels_down INTEGER DEFAULT 0,
    vpn_details     TEXT    NOT NULL DEFAULT '[]',
    route_count     INTEGER DEFAULT 0,
    route_snapshot  TEXT    NOT NULL DEFAULT '',
    poll_status     TEXT    NOT NULL DEFAULT 'ok',
    poll_error      TEXT    DEFAULT '',
    response_time_ms REAL   DEFAULT NULL,
    packet_loss_pct  REAL   DEFAULT NULL,
    polled_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS monitoring_alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    poll_id         INTEGER REFERENCES monitoring_polls(id) ON DELETE SET NULL,
    rule_id         INTEGER REFERENCES alert_rules(id) ON DELETE SET NULL,
    alert_type      TEXT    NOT NULL DEFAULT 'threshold',
    metric          TEXT    NOT NULL DEFAULT '',
    message         TEXT    NOT NULL DEFAULT '',
    severity        TEXT    NOT NULL DEFAULT 'warning',
    original_severity TEXT  NOT NULL DEFAULT '',
    value           REAL    DEFAULT NULL,
    threshold       REAL    DEFAULT NULL,
    dedup_key       TEXT    NOT NULL DEFAULT '',
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    last_seen_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    acknowledged    INTEGER NOT NULL DEFAULT 0,
    acknowledged_by TEXT    DEFAULT '',
    acknowledged_at TEXT,
    escalated       INTEGER NOT NULL DEFAULT 0,
    escalation_count INTEGER NOT NULL DEFAULT 0,
    escalated_at    TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS route_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    route_count     INTEGER NOT NULL DEFAULT 0,
    routes_text     TEXT    NOT NULL DEFAULT '',
    routes_hash     TEXT    NOT NULL DEFAULT '',
    captured_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alert_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL DEFAULT '',
    description     TEXT    NOT NULL DEFAULT '',
    metric          TEXT    NOT NULL DEFAULT '',
    rule_type       TEXT    NOT NULL DEFAULT 'threshold',
    operator        TEXT    NOT NULL DEFAULT '>=',
    value           REAL    NOT NULL DEFAULT 0,
    severity        TEXT    NOT NULL DEFAULT 'warning',
    enabled         INTEGER NOT NULL DEFAULT 1,
    consecutive     INTEGER NOT NULL DEFAULT 1,
    cooldown_minutes INTEGER NOT NULL DEFAULT 15,
    escalate_after_minutes INTEGER NOT NULL DEFAULT 0,
    escalate_to     TEXT    NOT NULL DEFAULT 'critical',
    host_id         INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    group_id        INTEGER REFERENCES inventory_groups(id) ON DELETE CASCADE,
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alert_suppressions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL DEFAULT '',
    host_id         INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    group_id        INTEGER REFERENCES inventory_groups(id) ON DELETE CASCADE,
    metric          TEXT    NOT NULL DEFAULT '',
    reason          TEXT    NOT NULL DEFAULT '',
    starts_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    ends_at         TEXT    NOT NULL,
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sla_targets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL DEFAULT '',
    host_id         INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    group_id        INTEGER REFERENCES inventory_groups(id) ON DELETE CASCADE,
    metric          TEXT    NOT NULL DEFAULT 'uptime',
    target_value    REAL    NOT NULL DEFAULT 99.9,
    warning_value   REAL    NOT NULL DEFAULT 99.0,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sla_metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    metric          TEXT    NOT NULL DEFAULT 'uptime',
    time_window     TEXT    NOT NULL DEFAULT 'hourly',
    value           REAL    NOT NULL DEFAULT 0,
    sample_count    INTEGER NOT NULL DEFAULT 0,
    period_start    TEXT    NOT NULL,
    period_end      TEXT    NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


def _convert_sqlite_schema_to_postgres(sqlite_schema: str) -> str:
    converted = sqlite_schema
    converted = converted.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    converted = converted.replace("DEFAULT (datetime('now'))", "DEFAULT NOW()")
    return converted


POSTGRES_SCHEMA = _convert_sqlite_schema_to_postgres(SCHEMA)


def _split_sql_statements(schema: str) -> list[str]:
    return [stmt.strip() for stmt in schema.split(";") if stmt.strip()]


def _convert_qmark_to_dollar_params(query: str) -> str:
    out: list[str] = []
    in_single_quote = False
    param_index = 1
    for ch in query:
        if ch == "'":
            in_single_quote = not in_single_quote
            out.append(ch)
            continue
        if ch == "?" and not in_single_quote:
            out.append(f"${param_index}")
            param_index += 1
            continue
        out.append(ch)
    converted = "".join(out)
    converted = converted.replace("datetime('now')", "NOW()")
    return converted


def _parse_rowcount(status: str) -> int:
    try:
        return int(status.rsplit(" ", 1)[-1])
    except Exception:
        return 0


def _is_unique_violation(exc: Exception) -> bool:
    message = str(exc).lower()
    return "unique constraint" in message or "duplicate key value violates unique constraint" in message


def _is_foreign_key_violation(exc: Exception) -> bool:
    message = str(exc).lower()
    return "foreign key constraint failed" in message or "violates foreign key constraint" in message


class _PostgresCursorCompat:
    def __init__(self, rows=None, *, lastrowid: int | None = None, rowcount: int = 0):
        self._rows = rows or []
        self._idx = 0
        self.lastrowid = lastrowid
        self.rowcount = rowcount

    async def fetchone(self):
        if self._idx >= len(self._rows):
            return None
        row = self._rows[self._idx]
        self._idx += 1
        return row

    async def fetchall(self):
        return list(self._rows)


class _PostgresConnectionCompat:
    def __init__(self, conn):
        self._conn = conn
        self.row_factory = None

    async def execute(self, query: str, params=()):
        params = tuple(params or ())
        query_stripped = query.strip()
        query_upper = query_stripped.upper()
        converted = _convert_qmark_to_dollar_params(query)

        if query_upper.startswith("SELECT") or query_upper.startswith("WITH"):
            rows = await self._conn.fetch(converted, *params)
            return _PostgresCursorCompat(rows=rows, rowcount=len(rows))

        if query_upper.startswith("INSERT"):
            m = re.match(r"^\s*INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)", query_stripped, re.IGNORECASE)
            table = m.group(1).lower() if m else ""
            if table in _INSERT_ID_TABLES and "RETURNING" not in query_upper:
                returning_query = f"{converted.rstrip()} RETURNING id"
                row = await self._conn.fetchrow(returning_query, *params)
                lastrowid = row["id"] if row is not None and "id" in row else None
                return _PostgresCursorCompat(lastrowid=lastrowid, rowcount=1 if row else 0)

            status = await self._conn.execute(converted, *params)
            return _PostgresCursorCompat(rowcount=_parse_rowcount(status))

        status = await self._conn.execute(converted, *params)
        return _PostgresCursorCompat(rowcount=_parse_rowcount(status))

    async def executescript(self, script: str):
        for stmt in _split_sql_statements(script):
            await self._conn.execute(stmt)

    async def commit(self):
        # asyncpg uses autocommit when no explicit transaction is active.
        return None

    async def close(self):
        await self._conn.close()


async def get_db():
    """Open a backend connection using APP_DB_ENGINE."""
    if DB_ENGINE not in _VALID_DB_ENGINES:
        raise RuntimeError(
            f"Unsupported APP_DB_ENGINE '{DB_ENGINE}'. Supported values: {', '.join(sorted(_VALID_DB_ENGINES))}"
        )

    if DB_ENGINE == "postgres":
        if asyncpg is None:
            raise RuntimeError("APP_DB_ENGINE=postgres requires the 'asyncpg' package")
        if not APP_DATABASE_URL:
            raise RuntimeError("APP_DB_ENGINE=postgres requires APP_DATABASE_URL")
        conn = await asyncpg.connect(APP_DATABASE_URL)
        return _PostgresConnectionCompat(conn)

    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    db = await aiosqlite.connect(DB_PATH, timeout=SQLITE_CONNECT_TIMEOUT)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
    await db.execute("PRAGMA synchronous=NORMAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db


async def _init_postgres(db) -> None:
    for stmt in _split_sql_statements(POSTGRES_SCHEMA):
        await db.execute(stmt)

    # Idempotent startup migrations for already-created databases.
    await db.execute("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS content TEXT DEFAULT ''")
    await db.execute("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS updated_at TEXT")
    await db.execute("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'python'")
    await db.execute("UPDATE playbooks SET updated_at = NOW()::text WHERE updated_at IS NULL")

    await db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT DEFAULT ''")
    await db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'")
    await db.execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password INTEGER NOT NULL DEFAULT 0"
    )

    await db.execute("ALTER TABLE credentials ADD COLUMN IF NOT EXISTS owner_id INTEGER REFERENCES users(id)")

    cursor = await db.execute("SELECT COUNT(*) FROM credentials WHERE owner_id IS NULL")
    orphan_count_row = await cursor.fetchone()
    orphan_count = orphan_count_row[0] if orphan_count_row else 0
    if orphan_count > 0:
        admin_cursor = await db.execute("SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1")
        admin_row = await admin_cursor.fetchone()
        if admin_row:
            await db.execute("UPDATE credentials SET owner_id = ? WHERE owner_id IS NULL", (admin_row[0],))
            _LOGGER.info(
                "migration(postgres): assigned %s orphaned credential(s) to admin user (id=%s)",
                orphan_count,
                admin_row[0],
            )
        else:
            _LOGGER.warning("migration(postgres): no admin user found to assign orphaned credentials")

    await db.commit()


async def init_db():
    """Create all tables if they don't exist."""
    db = await get_db()
    try:
        if DB_ENGINE == "postgres":
            await _init_postgres(db)
            return

        await db.executescript(SCHEMA)
        await db.commit()
        
        # Migration: Add content and updated_at columns to playbooks if they don't exist
        try:
            cursor = await db.execute("PRAGMA table_info(playbooks)")
            columns = [row[1] for row in await cursor.fetchall()]
            
            if 'content' not in columns:
                _LOGGER.info("migration: adding 'content' column to playbooks table")
                await db.execute("ALTER TABLE playbooks ADD COLUMN content TEXT DEFAULT ''")
                await db.commit()
                _LOGGER.info("migration: added 'content' column successfully")
            
            if 'updated_at' not in columns:
                _LOGGER.info("migration: adding 'updated_at' column to playbooks table")
                await db.execute("ALTER TABLE playbooks ADD COLUMN updated_at TEXT")
                await db.commit()
                await db.execute("UPDATE playbooks SET updated_at = datetime('now') WHERE updated_at IS NULL")
                await db.commit()
                _LOGGER.info("migration: added 'updated_at' column successfully")

            if 'type' not in columns:
                _LOGGER.info("migration: adding 'type' column to playbooks table")
                await db.execute("ALTER TABLE playbooks ADD COLUMN type TEXT NOT NULL DEFAULT 'python'")
                await db.commit()
                _LOGGER.info("migration: added 'type' column successfully")
        except Exception as e:
            _LOGGER.error("migration: playbooks migration error: %s", e, exc_info=True)

        # Migration: Add display_name and role columns to users if they don't exist
        try:
            cursor = await db.execute("PRAGMA table_info(users)")
            columns = [row[1] for row in await cursor.fetchall()]

            if 'display_name' not in columns:
                _LOGGER.info("migration: adding 'display_name' column to users table")
                await db.execute("ALTER TABLE users ADD COLUMN display_name TEXT DEFAULT ''")
                await db.commit()
                _LOGGER.info("migration: added 'display_name' column successfully")
            
            if 'role' not in columns:
                _LOGGER.info("migration: adding 'role' column to users table")
                await db.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
                await db.commit()
                _LOGGER.info("migration: added 'role' column successfully")

        except Exception as e:
            _LOGGER.error("migration: users table migration error: %s", e, exc_info=True)

        # Migration: Add owner_id column to credentials, drop UNIQUE on name
        try:
            cursor = await db.execute("PRAGMA table_info(credentials)")
            columns = [row[1] for row in await cursor.fetchall()]

            if 'owner_id' not in columns:
                _LOGGER.info("migration: migrating 'credentials' table to add 'owner_id' and drop UNIQUE on name")
                
                # 1. Rename existing table
                await db.execute("ALTER TABLE credentials RENAME TO old_credentials")
                await db.commit()

                # 2. Create new table with updated schema (no UNIQUE on name)
                await db.execute("""
                    CREATE TABLE credentials (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        name        TEXT    NOT NULL,
                        username    TEXT    NOT NULL,
                        password    TEXT    NOT NULL,
                        secret      TEXT    NOT NULL DEFAULT '',
                        owner_id    INTEGER REFERENCES users(id),
                        created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
                    )
                """)
                await db.commit()

                # 3. Copy data from old table to new table
                await db.execute("""
                    INSERT INTO credentials (id, name, username, password, secret, created_at)
                    SELECT id, name, username, password, secret, created_at FROM old_credentials
                """)
                await db.commit()

                # 4. Drop old table
                await db.execute("DROP TABLE old_credentials")
                await db.commit()
                _LOGGER.info("migration: 'credentials' table migration complete")
            else:
                _LOGGER.info("migration: 'owner_id' column already exists in 'credentials' table, skipping")


            # Assign orphaned credentials to the first admin user (newly created or existing)
            cursor2 = await db.execute("SELECT COUNT(*) FROM credentials WHERE owner_id IS NULL")
            orphan_count = (await cursor2.fetchall())[0][0]
            if orphan_count > 0:
                cursor3 = await db.execute("SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1")
                admin_row = await cursor3.fetchone()
                if admin_row:
                    admin_id = admin_row[0]
                    await db.execute("UPDATE credentials SET owner_id = ? WHERE owner_id IS NULL", (admin_id,))
                    await db.commit()
                    _LOGGER.info("migration: assigned %s orphaned credential(s) to admin user (id=%s)", orphan_count, admin_id)
                else:
                    _LOGGER.warning("migration: no admin user found to assign orphaned credentials to")
        except Exception as e:
            _LOGGER.error("migration: credentials migration error: %s", e, exc_info=True)

        # Migration: Add must_change_password column to users if it doesn't exist
        try:
            cursor = await db.execute("PRAGMA table_info(users)")
            columns = [row[1] for row in await cursor.fetchall()]
            if 'must_change_password' not in columns:
                _LOGGER.info("migration: adding 'must_change_password' column to users table")
                await db.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
                await db.commit()
                _LOGGER.info("migration: added 'must_change_password' column successfully")
        except Exception as e:
            _LOGGER.error("migration: must_change_password migration error: %s", e, exc_info=True)

        # Migration: Add missing columns to jobs table if they don't exist
        try:
            cursor = await db.execute("PRAGMA table_info(jobs)")
            columns = [row[1] for row in await cursor.fetchall()]
            for col_name, col_def in [
                ("queued_at", "TEXT"),
                ("cancelled_at", "TEXT"),
                ("cancelled_by", "TEXT DEFAULT ''"),
                ("priority", "INTEGER NOT NULL DEFAULT 2"),
                ("depends_on", "TEXT NOT NULL DEFAULT '[]'"),
                ("launched_by", "TEXT DEFAULT 'admin'"),
            ]:
                if col_name not in columns:
                    _LOGGER.info("migration: adding '%s' column to jobs table", col_name)
                    await db.execute(f"ALTER TABLE jobs ADD COLUMN {col_name} {col_def}")
                    await db.commit()
                    _LOGGER.info("migration: added '%s' column to jobs table successfully", col_name)
        except Exception as e:
            _LOGGER.error("migration: jobs table migration error: %s", e, exc_info=True)
    finally:
        await db.close()


# ── Helper: row → dict ──────────────────────────────────────────────────────

def row_to_dict(row) -> dict:
    if row is None:
        return None
    return dict(row)


def rows_to_list(rows) -> list[dict]:
    return [dict(r) for r in rows]


# ═════════════════════════════════════════════════════════════════════════════
# Users
# ═════════════════════════════════════════════════════════════════════════════

async def get_user_by_username(username: str) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM users WHERE username = ?", (username,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def get_user_by_id(user_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id, username, display_name, role, must_change_password, created_at FROM users WHERE id = ?",
            (user_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_user(username: str, password_hash: str, salt: str,
                      display_name: str = "", role: str = "user",
                      must_change_password: bool = False) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO users (username, password_hash, salt, display_name, role, must_change_password) VALUES (?,?,?,?,?,?)",
            (username, password_hash, salt, display_name, role, int(must_change_password)),
        )
        await db.commit()
        return cursor.lastrowid
    except Exception as e:
        if _is_unique_violation(e):
            raise ValueError(f"Username '{username}' already exists.")
        raise
    finally:
        await db.close()


async def update_user_password(user_id: int, password_hash: str, salt: str):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE users SET password_hash = ?, salt = ?, must_change_password = 0 WHERE id = ?",
            (password_hash, salt, user_id),
        )
        await db.commit()
    finally:
        await db.close()


async def update_user_profile(user_id: int, display_name: str = None):
    db = await get_db()
    try:
        if display_name is not None:
            await db.execute("UPDATE users SET display_name = ? WHERE id = ?", (display_name, user_id))
            await db.commit()
    finally:
        await db.close()


async def update_user_admin(user_id: int, username: str = None, display_name: str = None, role: str = None):
    db = await get_db()
    try:
        fields = []
        values = []
        if username is not None:
            fields.append("username = ?")
            values.append(username)
        if display_name is not None:
            fields.append("display_name = ?")
            values.append(display_name)
        if role is not None:
            fields.append("role = ?")
            values.append(role)
        if not fields:
            return
        values.append(user_id)
        await db.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", tuple(values))
        await db.commit()
    except Exception as e:
        if _is_unique_violation(e):
            raise ValueError("Username already exists")
        raise
    finally:
        await db.close()


async def get_all_users() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id, username, display_name, role, must_change_password, created_at FROM users ORDER BY username"
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_user(user_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM credentials WHERE owner_id = ?", (user_id,))
        await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await db.commit()
    finally:
        await db.close()


async def get_user_group_ids(user_id: int) -> list[int]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT group_id FROM user_group_memberships WHERE user_id = ? ORDER BY group_id",
            (user_id,),
        )
        rows = await cursor.fetchall()
        return [int(r[0]) for r in rows]
    finally:
        await db.close()


async def set_user_groups(user_id: int, group_ids: list[int]):
    db = await get_db()
    try:
        await db.execute("DELETE FROM user_group_memberships WHERE user_id = ?", (user_id,))
        for gid in sorted(set(group_ids)):
            await db.execute(
                "INSERT INTO user_group_memberships (user_id, group_id) VALUES (?, ?)",
                (user_id, gid),
            )
        await db.commit()
    except Exception as e:
        if _is_foreign_key_violation(e):
            raise ValueError("One or more selected groups do not exist")
        raise
    finally:
        await db.close()


async def get_all_access_groups() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            SELECT g.id, g.name, g.description, g.created_at, COUNT(m.user_id) AS member_count
            FROM access_groups g
            LEFT JOIN user_group_memberships m ON m.group_id = g.id
            GROUP BY g.id
            ORDER BY g.name
            """
        )
        groups = rows_to_list(await cursor.fetchall())

        for group in groups:
            fcur = await db.execute(
                "SELECT feature_key FROM access_group_features WHERE group_id = ? ORDER BY feature_key",
                (group["id"],),
            )
            group["feature_keys"] = [r[0] for r in await fcur.fetchall()]
        return groups
    finally:
        await db.close()


async def get_access_group(group_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id, name, description, created_at FROM access_groups WHERE id = ?",
            (group_id,),
        )
        group = row_to_dict(await cursor.fetchone())
        if not group:
            return None

        fcur = await db.execute(
            "SELECT feature_key FROM access_group_features WHERE group_id = ? ORDER BY feature_key",
            (group_id,),
        )
        mcur = await db.execute(
            "SELECT COUNT(*) FROM user_group_memberships WHERE group_id = ?",
            (group_id,),
        )
        group["feature_keys"] = [r[0] for r in await fcur.fetchall()]
        group["member_count"] = int((await mcur.fetchone())[0])
        return group
    finally:
        await db.close()


async def create_access_group(name: str, description: str, feature_keys: list[str]) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO access_groups (name, description) VALUES (?, ?)",
            (name, description),
        )
        group_id = cursor.lastrowid
        for feature in sorted(set(feature_keys)):
            await db.execute(
                "INSERT INTO access_group_features (group_id, feature_key) VALUES (?, ?)",
                (group_id, feature),
            )
        await db.commit()
        return int(group_id)
    except Exception as e:
        if _is_unique_violation(e):
            raise ValueError("Access group name already exists")
        raise
    finally:
        await db.close()


async def update_access_group(group_id: int, name: str, description: str, feature_keys: list[str]):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE access_groups SET name = ?, description = ? WHERE id = ?",
            (name, description, group_id),
        )
        await db.execute("DELETE FROM access_group_features WHERE group_id = ?", (group_id,))
        for feature in sorted(set(feature_keys)):
            await db.execute(
                "INSERT INTO access_group_features (group_id, feature_key) VALUES (?, ?)",
                (group_id, feature),
            )
        await db.commit()
    except Exception as e:
        if _is_unique_violation(e):
            raise ValueError("Access group name already exists")
        raise
    finally:
        await db.close()


async def delete_access_group(group_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM access_groups WHERE id = ?", (group_id,))
        await db.commit()
    finally:
        await db.close()


async def get_user_effective_features(user_id: int) -> list[str]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            SELECT DISTINCT f.feature_key
            FROM access_group_features f
            INNER JOIN user_group_memberships m ON m.group_id = f.group_id
            WHERE m.user_id = ?
            ORDER BY f.feature_key
            """,
            (user_id,),
        )
        rows = await cursor.fetchall()
        return [r[0] for r in rows]
    finally:
        await db.close()


async def set_auth_setting(key: str, value: dict):
    db = await get_db()
    try:
        payload = json.dumps(value)
        await db.execute(
            """
            INSERT INTO auth_settings (key, value, updated_at)
            VALUES (?, ?, datetime('now'))
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = datetime('now')
            """,
            (key, payload),
        )
        await db.commit()
    finally:
        await db.close()


async def get_auth_setting(key: str) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT value FROM auth_settings WHERE key = ?", (key,))
        row = await cursor.fetchone()
        if not row:
            return None
        return json.loads(row[0])
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Inventory Groups
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_groups() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute("""
            SELECT g.*, COUNT(h.id) AS host_count
            FROM inventory_groups g
            LEFT JOIN hosts h ON h.group_id = g.id
            GROUP BY g.id ORDER BY g.name
        """)
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_all_groups_with_hosts() -> list[dict]:
    """Return all groups with embedded host arrays using a single query."""
    db = await get_db()
    try:
        cursor = await db.execute("""
            SELECT
                g.id AS group_id,
                g.name AS group_name,
                g.description AS group_description,
                h.id AS host_id,
                h.group_id AS host_group_id,
                h.hostname AS host_hostname,
                h.ip_address AS host_ip_address,
                h.device_type AS host_device_type,
                h.status AS host_status,
                h.last_seen AS host_last_seen
            FROM inventory_groups g
            LEFT JOIN hosts h ON h.group_id = g.id
            ORDER BY g.name, h.ip_address
        """)
        rows = await cursor.fetchall()
    finally:
        await db.close()

    groups: list[dict] = []
    by_group_id: dict[int, dict] = {}
    for row in rows:
        gid = int(row["group_id"])
        group = by_group_id.get(gid)
        if group is None:
            group = {
                "id": gid,
                "name": row["group_name"],
                "description": row["group_description"] or "",
                "host_count": 0,
                "hosts": [],
            }
            by_group_id[gid] = group
            groups.append(group)

        host_id = row["host_id"]
        if host_id is None:
            continue
        group["hosts"].append({
            "id": host_id,
            "group_id": row["host_group_id"],
            "hostname": row["host_hostname"],
            "ip_address": row["host_ip_address"],
            "device_type": row["host_device_type"],
            "status": row["host_status"],
            "last_seen": row["host_last_seen"],
        })
        group["host_count"] += 1

    return groups


async def get_group(group_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM inventory_groups WHERE id = ?", (group_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_group(name: str, description: str = "") -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO inventory_groups (name, description) VALUES (?, ?)",
            (name, description),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_group(group_id: int, name: str, description: str = ""):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE inventory_groups SET name = ?, description = ? WHERE id = ?",
            (name, description, group_id),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_group(group_id: int):
    db = await get_db()
    try:
        # Delete jobs referencing this group (job_events cascade automatically)
        await db.execute("DELETE FROM jobs WHERE inventory_group_id = ?", (group_id,))
        await db.execute("DELETE FROM inventory_groups WHERE id = ?", (group_id,))
        await db.commit()
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Hosts
# ═════════════════════════════════════════════════════════════════════════════

async def get_host(host_id: int) -> dict | None:
    """Get a single host by ID."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM hosts WHERE id = ?", (host_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def get_hosts_for_group(group_id: int) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM hosts WHERE group_id = ? ORDER BY ip_address", (group_id,)
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_hosts_by_ids(host_ids: list[int]) -> list[dict]:
    """Get multiple hosts by their IDs."""
    if not host_ids:
        return []
    db = await get_db()
    try:
        placeholders = ','.join('?' * len(host_ids))
        cursor = await db.execute(
            f"SELECT * FROM hosts WHERE id IN ({placeholders}) ORDER BY ip_address",
            tuple(host_ids)
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def add_host(group_id: int, hostname: str, ip_address: str,
                   device_type: str = "cisco_ios") -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address, device_type) VALUES (?,?,?,?)",
            (group_id, hostname, ip_address, device_type),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def remove_host(host_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        await db.commit()
    finally:
        await db.close()


async def update_host(host_id: int, hostname: str, ip_address: str,
                      device_type: str = "cisco_ios"):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE hosts SET hostname=?, ip_address=?, device_type=? WHERE id=?",
            (hostname, ip_address, device_type, host_id),
        )
        await db.commit()
    finally:
        await db.close()


async def move_hosts(host_ids: list[int], target_group_id: int) -> int:
    if not host_ids:
        return 0
    db = await get_db()
    try:
        placeholders = ",".join("?" for _ in host_ids)
        cursor = await db.execute(
            f"UPDATE hosts SET group_id = ? WHERE id IN ({placeholders})",
            (target_group_id, *host_ids),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def bulk_delete_hosts(host_ids: list[int]) -> int:
    if not host_ids:
        return 0
    db = await get_db()
    try:
        placeholders = ",".join("?" for _ in host_ids)
        cursor = await db.execute(
            f"DELETE FROM hosts WHERE id IN ({placeholders})",
            tuple(host_ids),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def update_host_status(host_id: int, status: str):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE hosts SET status = ?, last_seen = ? WHERE id = ?",
            (status, datetime.now(UTC).isoformat(), host_id),
        )
        await db.commit()
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Playbooks
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_playbooks() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute("""
            SELECT p.*,
                   (SELECT j.status FROM jobs j WHERE j.playbook_id = p.id
                    ORDER BY j.id DESC LIMIT 1) AS last_status,
                   (SELECT j.started_at FROM jobs j WHERE j.playbook_id = p.id
                    ORDER BY j.id DESC LIMIT 1) AS last_run
            FROM playbooks p ORDER BY p.name
        """)
        rows = rows_to_list(await cursor.fetchall())
        for r in rows:
            r["tags"] = json.loads(r.get("tags") or "[]")
        return rows
    finally:
        await db.close()


async def get_playbook(playbook_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM playbooks WHERE id = ?", (playbook_id,))
        row = row_to_dict(await cursor.fetchone())
        if row:
            row["tags"] = json.loads(row.get("tags") or "[]")
        return row
    finally:
        await db.close()


async def create_playbook(name: str, filename: str, description: str = "",
                          tags: list[str] | None = None, content: str = "",
                          type: str = "python") -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO playbooks (name, filename, description, tags, content, type) VALUES (?,?,?,?,?,?)",
            (name, filename, description, json.dumps(tags or []), content, type),
        )
        await db.commit()
        return cursor.lastrowid
    except Exception as e:
        # If it's a unique constraint error, re-raise it
        if _is_unique_violation(e):
            raise
        raise
    finally:
        await db.close()


async def sync_playbook_filename(name: str, filename: str):
    """Update the filename for an existing playbook by name."""
    db = await get_db()
    try:
        if DB_ENGINE == "postgres":
            await db.execute(
                "UPDATE playbooks SET filename = ?, updated_at = NOW()::text WHERE name = ?",
                (filename, name),
            )
        else:
            await db.execute(
                "UPDATE playbooks SET filename = ?, updated_at = datetime('now') WHERE name = ?",
                (filename, name),
            )
        await db.commit()
    finally:
        await db.close()


async def update_playbook(playbook_id: int, name: str = None, filename: str = None,
                          description: str = None, tags: list[str] | None = None,
                          content: str = None, type: str = None):
    """Update playbook fields. None values are not updated."""
    db = await get_db()
    try:
        updates = []
        params = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if filename is not None:
            updates.append("filename = ?")
            params.append(filename)
        if description is not None:
            updates.append("description = ?")
            params.append(description)
        if tags is not None:
            updates.append("tags = ?")
            params.append(json.dumps(tags))
        if content is not None:
            updates.append("content = ?")
            params.append(content)
        if type is not None:
            updates.append("type = ?")
            params.append(type)
        
        if updates:
            updates.append("updated_at = NOW()::text" if DB_ENGINE == "postgres" else "updated_at = datetime('now')")

            params.append(playbook_id)
            await db.execute(
                f"UPDATE playbooks SET {', '.join(updates)} WHERE id = ?",
                params
            )
            await db.commit()
    finally:
        await db.close()


async def delete_playbook(playbook_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM playbooks WHERE id = ?", (playbook_id,))
        await db.commit()
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Templates
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_templates() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM templates ORDER BY name")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_template(template_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM templates WHERE id = ?", (template_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_template(name: str, content: str, description: str = "") -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO templates (name, content, description) VALUES (?,?,?)",
            (name, content, description),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_template(template_id: int, name: str, content: str,
                          description: str = ""):
    db = await get_db()
    try:
        await db.execute(
            """UPDATE templates SET name=?, content=?, description=?,
               updated_at=datetime('now') WHERE id=?""",
            (name, content, description, template_id),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_template(template_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM templates WHERE id = ?", (template_id,))
        await db.commit()
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Credentials (encrypted externally before storage)
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_credentials(owner_id: int | None = None) -> list[dict]:
    """Return credentials with passwords masked. Filter by owner if provided."""
    db = await get_db()
    try:
        if owner_id is not None:
            cursor = await db.execute(
                "SELECT id, name, username, owner_id, created_at FROM credentials WHERE owner_id = ? ORDER BY name",
                (owner_id,))
        else:
            cursor = await db.execute("SELECT id, name, username, owner_id, created_at FROM credentials ORDER BY name")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_credential_raw(cred_id: int) -> dict | None:
    """Return full credential including encrypted password/secret."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM credentials WHERE id = ?", (cred_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_credential(name: str, username: str, enc_password: str,
                            enc_secret: str = "", owner_id: int | None = None) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO credentials (name, username, password, secret, owner_id) VALUES (?,?,?,?,?)",
            (name, username, enc_password, enc_secret, owner_id),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def delete_credential(cred_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        await db.commit()
    finally:
        await db.close()


async def update_credential(
    cred_id: int,
    *,
    name: str | None = None,
    username: str | None = None,
    enc_password: str | None = None,
    enc_secret: str | None = None,
):
    """Update credential fields. Omit or None means leave unchanged."""
    updates = []
    args = []
    if name is not None:
        updates.append("name = ?")
        args.append(name)
    if username is not None:
        updates.append("username = ?")
        args.append(username)
    if enc_password is not None:
        updates.append("password = ?")
        args.append(enc_password)
    if enc_secret is not None:
        updates.append("secret = ?")
        args.append(enc_secret)
    if not updates:
        return
    args.append(cred_id)
    db = await get_db()
    try:
        await db.execute(
            f"UPDATE credentials SET {', '.join(updates)} WHERE id = ?",
            tuple(args),
        )
        await db.commit()
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Jobs
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_jobs(limit: int = 50) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute("""
            SELECT j.*, p.name AS playbook_name, g.name AS group_name
            FROM jobs j
            JOIN playbooks p ON p.id = j.playbook_id
            JOIN inventory_groups g ON g.id = j.inventory_group_id
            ORDER BY j.id DESC LIMIT ?
        """, (limit,))
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_job(job_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("""
            SELECT j.*, p.name AS playbook_name, g.name AS group_name
            FROM jobs j
            JOIN playbooks p ON p.id = j.playbook_id
            JOIN inventory_groups g ON g.id = j.inventory_group_id
            WHERE j.id = ?
        """, (job_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_job(playbook_id: int, inventory_group_id: int,
                     credential_id: int | None = None,
                     template_id: int | None = None,
                     dry_run: bool = True,
                     launched_by: str = "admin",
                     priority: int = 2,
                     depends_on: list[int] | None = None) -> int:
    db = await get_db()
    try:
        deps_json = json.dumps(depends_on or [])
        now = datetime.now(UTC).isoformat()
        cursor = await db.execute(
            """INSERT INTO jobs
               (playbook_id, inventory_group_id, credential_id, template_id,
                dry_run, status, priority, depends_on, queued_at, launched_by)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (playbook_id, inventory_group_id, credential_id, template_id,
             1 if dry_run else 0, "queued", priority, deps_json, now, launched_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def finish_job(job_id: int, status: str, hosts_ok: int = 0,
                     hosts_failed: int = 0, hosts_skipped: int = 0):
    db = await get_db()
    try:
        await db.execute(
            """UPDATE jobs SET status=?, finished_at=?, hosts_ok=?,
               hosts_failed=?, hosts_skipped=? WHERE id=?""",
            (status, datetime.now(UTC).isoformat(),
             hosts_ok, hosts_failed, hosts_skipped, job_id),
        )
        await db.commit()
    finally:
        await db.close()


async def add_job_event(job_id: int, level: str, message: str, host: str = ""):
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO job_events (job_id, level, host, message) VALUES (?,?,?,?)",
            (job_id, level, host, message),
        )
        await db.commit()
    finally:
        await db.close()


async def get_job_events(job_id: int) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM job_events WHERE job_id = ? ORDER BY id", (job_id,)
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_expired_jobs(retention_days: int) -> int:
    """Delete completed jobs older than retention_days and return deleted row count."""
    db = await get_db()
    try:
        safe_days = max(1, int(retention_days))
        if DB_ENGINE == "postgres":
            cursor = await db.execute(
                """
                DELETE FROM jobs
                WHERE status IN ('success', 'failed', 'cancelled')
                  AND COALESCE(finished_at, started_at, queued_at) IS NOT NULL
                  AND COALESCE(finished_at, started_at, queued_at)::timestamp <= (NOW() - (?::int * INTERVAL '1 day'))
                """,
                (safe_days,),
            )
        else:
            cursor = await db.execute(
                """
                DELETE FROM jobs
                WHERE status IN ('success', 'failed', 'cancelled')
                  AND COALESCE(finished_at, started_at, queued_at) IS NOT NULL
                  AND julianday(COALESCE(finished_at, started_at, queued_at)) <= julianday('now') - ?
                """,
                (safe_days,),
            )
        await db.commit()
        return cursor.rowcount or 0
    finally:
        await db.close()


async def start_job(job_id: int) -> None:
    """Transition a queued job to running status with started_at timestamp."""
    db = await get_db()
    try:
        await db.execute(
            "UPDATE jobs SET status = 'running', started_at = ? WHERE id = ? AND status = 'queued'",
            (datetime.now(UTC).isoformat(), job_id),
        )
        await db.commit()
    finally:
        await db.close()


async def cancel_job(job_id: int, cancelled_by: str = "") -> bool:
    """Cancel a queued or running job. Returns True if the job was updated."""
    db = await get_db()
    try:
        now = datetime.now(UTC).isoformat()
        cursor = await db.execute(
            """UPDATE jobs SET status = 'cancelled', cancelled_at = ?, cancelled_by = ?,
               finished_at = COALESCE(finished_at, ?)
               WHERE id = ? AND status IN ('queued', 'running')""",
            (now, cancelled_by, now, job_id),
        )
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


async def update_job_priority(job_id: int, priority: int) -> bool:
    """Update the priority of a queued job."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE jobs SET priority = ? WHERE id = ? AND status = 'queued'",
            (max(0, min(4, priority)), job_id),
        )
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


async def get_job_queue() -> list[dict]:
    """Get all queued and running jobs ordered by priority (desc) then queued_at (asc)."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT j.*, p.name AS playbook_name, g.name AS group_name
               FROM jobs j
               JOIN playbooks p ON p.id = j.playbook_id
               JOIN inventory_groups g ON g.id = j.inventory_group_id
               WHERE j.status IN ('queued', 'running')
               ORDER BY j.status = 'running' DESC, j.priority DESC, j.queued_at ASC"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_next_queued_job() -> dict | None:
    """Get the next job to run: highest priority first, then earliest queued."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT j.* FROM jobs j
               WHERE j.status = 'queued'
               ORDER BY j.priority DESC, j.queued_at ASC
               LIMIT 1"""
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def check_job_dependencies_met(job_id: int) -> bool:
    """Check if all dependency jobs have completed successfully."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT depends_on FROM jobs WHERE id = ?", (job_id,))
        row = await cursor.fetchone()
        if not row:
            return True
        deps = json.loads(row[0] or "[]")
        if not deps:
            return True
        placeholders = ",".join("?" for _ in deps)
        cursor = await db.execute(
            f"""SELECT COUNT(*) FROM jobs
                WHERE id IN ({placeholders}) AND status != 'success'""",
            tuple(deps),
        )
        unmet = (await cursor.fetchone())[0]
        return unmet == 0
    finally:
        await db.close()


async def get_running_job_count() -> int:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM jobs WHERE status = 'running'")
        return (await cursor.fetchone())[0]
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Dashboard Stats
# ═════════════════════════════════════════════════════════════════════════════

async def get_dashboard_stats() -> dict:
    db = await get_db()
    try:
        total_hosts = (await (await db.execute("SELECT COUNT(*) FROM hosts")).fetchone())[0]
        total_groups = (await (await db.execute("SELECT COUNT(*) FROM inventory_groups")).fetchone())[0]
        total_playbooks = (await (await db.execute("SELECT COUNT(*) FROM playbooks")).fetchone())[0]
        total_jobs = (await (await db.execute("SELECT COUNT(*) FROM jobs")).fetchone())[0]
        running_jobs = (await (await db.execute(
            "SELECT COUNT(*) FROM jobs WHERE status='running'"
        )).fetchone())[0]
        successful_jobs = (await (await db.execute(
            "SELECT COUNT(*) FROM jobs WHERE status='success'"
        )).fetchone())[0]
        completed_jobs = (await (await db.execute(
            "SELECT COUNT(*) FROM jobs WHERE status IN ('success','failed')"
        )).fetchone())[0]
        success_rate = round(successful_jobs / completed_jobs * 100) if completed_jobs > 0 else 0

        return {
            "total_hosts": total_hosts,
            "total_groups": total_groups,
            "total_playbooks": total_playbooks,
            "total_jobs": total_jobs,
            "running_jobs": running_jobs,
            "success_rate": success_rate,
        }
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Audit Events
# ═════════════════════════════════════════════════════════════════════════════


async def add_audit_event(
    category: str,
    action: str,
    user: str = "",
    detail: str = "",
    correlation_id: str = "",
) -> int:
    """Insert an immutable audit record and return its ID."""
    conn = await get_db()
    try:
        cursor = await conn.execute(
            """INSERT INTO audit_events (category, action, user, detail, correlation_id)
               VALUES (?, ?, ?, ?, ?)""",
            (category, action, user, detail, correlation_id),
        )
        await conn.commit()
        return cursor.lastrowid
    finally:
        await conn.close()


async def get_audit_events(
    limit: int = 100,
    category: str | None = None,
) -> list[dict]:
    """Return recent audit events, optionally filtered by category."""
    conn = await get_db()
    try:
        if category:
            cursor = await conn.execute(
                "SELECT * FROM audit_events WHERE category = ? ORDER BY id DESC LIMIT ?",
                (category, limit),
            )
        else:
            cursor = await conn.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await conn.close()


# ═════════════════════════════════════════════════════════════════════════════
# Topology Links
# ═════════════════════════════════════════════════════════════════════════════

async def upsert_topology_link(
    source_host_id: int,
    source_ip: str,
    source_interface: str,
    target_host_id: int | None,
    target_ip: str,
    target_device_name: str,
    target_interface: str,
    protocol: str = "cdp",
    target_platform: str = "",
) -> int:
    """Insert or replace a topology link (deduplicated by source+interfaces+target)."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO topology_links
               (source_host_id, source_ip, source_interface,
                target_host_id, target_ip, target_device_name,
                target_interface, protocol, target_platform, discovered_at)
               VALUES (?,?,?,?,?,?,?,?,?, datetime('now'))
               ON CONFLICT(source_host_id, source_interface, target_device_name, target_interface)
               DO UPDATE SET
                   target_host_id = excluded.target_host_id,
                   target_ip = excluded.target_ip,
                   protocol = excluded.protocol,
                   target_platform = excluded.target_platform,
                   discovered_at = excluded.discovered_at""",
            (source_host_id, source_ip, source_interface,
             target_host_id, target_ip, target_device_name,
             target_interface, protocol, target_platform),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_topology_links(group_id: int | None = None) -> list[dict]:
    """Return topology links, optionally filtered by source host group."""
    db = await get_db()
    try:
        if group_id is not None:
            cursor = await db.execute(
                """SELECT tl.*, h.hostname AS source_hostname, h.device_type AS source_device_type,
                          h.status AS source_status, h.group_id AS source_group_id
                   FROM topology_links tl
                   JOIN hosts h ON tl.source_host_id = h.id
                   WHERE h.group_id = ?
                   ORDER BY tl.source_host_id, tl.source_interface""",
                (group_id,),
            )
        else:
            cursor = await db.execute(
                """SELECT tl.*, h.hostname AS source_hostname, h.device_type AS source_device_type,
                          h.status AS source_status, h.group_id AS source_group_id
                   FROM topology_links tl
                   JOIN hosts h ON tl.source_host_id = h.id
                   ORDER BY tl.source_host_id, tl.source_interface"""
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_topology_links_for_host(host_id: int) -> list[dict]:
    """Return all topology links where the given host is source or resolved target."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT tl.*, h.hostname AS source_hostname, h.device_type AS source_device_type,
                      h.status AS source_status, h.group_id AS source_group_id
               FROM topology_links tl
               JOIN hosts h ON tl.source_host_id = h.id
               WHERE tl.source_host_id = ? OR tl.target_host_id = ?
               ORDER BY tl.source_host_id, tl.source_interface""",
            (host_id, host_id),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_topology_links_for_host(host_id: int) -> int:
    """Delete all topology links where the given host is the source."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM topology_links WHERE source_host_id = ?", (host_id,)
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def delete_all_topology_links() -> int:
    """Delete all topology links."""
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM topology_links")
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def resolve_topology_target_host_ids() -> int:
    """Match unresolved target_host_ids by looking up target_ip or target_device_name in hosts."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """UPDATE topology_links
               SET target_host_id = (
                   SELECT h.id FROM hosts h
                   WHERE h.ip_address = topology_links.target_ip
                      OR LOWER(h.hostname) = LOWER(topology_links.target_device_name)
                   LIMIT 1
               )
               WHERE target_host_id IS NULL
                 AND (target_ip != '' OR target_device_name != '')"""
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Interface Stats (utilization tracking)
# ═════════════════════════════════════════════════════════════════════════════

async def upsert_interface_stat(
    host_id: int,
    if_index: int,
    if_name: str,
    if_speed_mbps: int,
    in_octets: int,
    out_octets: int,
) -> int:
    """Insert or update interface counters, shifting current values to prev_*."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO interface_stats
               (host_id, if_index, if_name, if_speed_mbps, in_octets, out_octets, polled_at)
               VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(host_id, if_index)
               DO UPDATE SET
                   if_name = excluded.if_name,
                   if_speed_mbps = CASE WHEN excluded.if_speed_mbps > 0
                                        THEN excluded.if_speed_mbps
                                        ELSE interface_stats.if_speed_mbps END,
                   prev_in_octets = interface_stats.in_octets,
                   prev_out_octets = interface_stats.out_octets,
                   prev_polled_at = interface_stats.polled_at,
                   in_octets = excluded.in_octets,
                   out_octets = excluded.out_octets,
                   polled_at = excluded.polled_at""",
            (host_id, if_index, if_name, if_speed_mbps, in_octets, out_octets),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_interface_stats_for_host(host_id: int) -> list[dict]:
    """Return all interface stats for a host."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM interface_stats WHERE host_id = ? ORDER BY if_index",
            (host_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_interface_stats_by_hosts(host_ids: list[int]) -> list[dict]:
    """Return interface stats for multiple hosts."""
    if not host_ids:
        return []
    db = await get_db()
    try:
        placeholders = ",".join("?" for _ in host_ids)
        cursor = await db.execute(
            f"SELECT * FROM interface_stats WHERE host_id IN ({placeholders}) ORDER BY host_id, if_index",
            tuple(host_ids),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Topology Changes (diff detection)
# ═════════════════════════════════════════════════════════════════════════════

async def insert_topology_change(
    change_type: str,
    source_host_id: int | None,
    source_hostname: str = "",
    source_interface: str = "",
    target_device_name: str = "",
    target_interface: str = "",
    target_ip: str = "",
    protocol: str = "",
) -> int:
    """Record a topology change (added/removed link)."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO topology_changes
               (change_type, source_host_id, source_hostname, source_interface,
                target_device_name, target_interface, target_ip, protocol, detected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (change_type, source_host_id, source_hostname, source_interface,
             target_device_name, target_interface, target_ip, protocol),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_topology_changes(unacknowledged_only: bool = False,
                               limit: int = 100) -> list[dict]:
    """Return recent topology changes."""
    db = await get_db()
    try:
        where = "WHERE acknowledged = 0" if unacknowledged_only else ""
        cursor = await db.execute(
            f"SELECT * FROM topology_changes {where} ORDER BY detected_at DESC LIMIT ?",
            (limit,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_topology_changes_count(unacknowledged_only: bool = True) -> int:
    """Return count of topology changes."""
    db = await get_db()
    try:
        where = "WHERE acknowledged = 0" if unacknowledged_only else ""
        cursor = await db.execute(
            f"SELECT COUNT(*) FROM topology_changes {where}"
        )
        row = await cursor.fetchone()
        return row[0] if row else 0
    finally:
        await db.close()


async def acknowledge_topology_changes() -> int:
    """Mark all unacknowledged changes as acknowledged."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE topology_changes SET acknowledged = 1 WHERE acknowledged = 0"
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def delete_old_topology_changes(days: int = 30) -> int:
    """Delete topology changes older than N days."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM topology_changes WHERE detected_at < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ── Topology Node Positions ──────────────────────────────────────────────────

async def get_topology_positions() -> dict:
    """Return all saved node positions as {node_id: {x, y}}."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT node_id, x, y FROM topology_node_positions")
        rows = await cursor.fetchall()
        return {row[0]: {"x": row[1], "y": row[2]} for row in rows}
    finally:
        await db.close()


async def save_topology_positions(positions: dict) -> int:
    """Upsert node positions. positions = {node_id: {x, y}}."""
    if not positions:
        return 0
    db = await get_db()
    try:
        count = 0
        for node_id, pos in positions.items():
            await db.execute(
                """INSERT INTO topology_node_positions (node_id, x, y, updated_at)
                   VALUES (?, ?, ?, datetime('now'))
                   ON CONFLICT(node_id) DO UPDATE SET
                       x = excluded.x,
                       y = excluded.y,
                       updated_at = datetime('now')""",
                (str(node_id), pos["x"], pos["y"]),
            )
            count += 1
        await db.commit()
        return count
    finally:
        await db.close()


async def delete_topology_positions() -> int:
    """Delete all saved node positions."""
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM topology_node_positions")
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ── Config Baselines ─────────────────────────────────────────────────────────


async def create_config_baseline(
    host_id: int,
    name: str = "",
    config_text: str = "",
    source: str = "manual",
    created_by: str = "",
) -> int:
    """Create or replace a config baseline for a host."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO config_baselines
               (host_id, name, config_text, source, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
               ON CONFLICT(host_id) DO UPDATE SET
                   name = excluded.name,
                   config_text = excluded.config_text,
                   source = excluded.source,
                   updated_at = datetime('now')""",
            (host_id, name, config_text, source, created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_config_baseline(baseline_id: int) -> dict | None:
    """Return a single config baseline by ID."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM config_baselines WHERE id = ?", (baseline_id,)
        )
        row = await cursor.fetchone()
        return row_to_dict(row)
    finally:
        await db.close()


async def get_config_baseline_for_host(host_id: int) -> dict | None:
    """Return the config baseline for a specific host."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM config_baselines WHERE host_id = ?", (host_id,)
        )
        row = await cursor.fetchone()
        return row_to_dict(row)
    finally:
        await db.close()


async def get_config_baselines(
    host_id: int | None = None,
    limit: int = 200,
) -> list[dict]:
    """Return config baselines, optionally filtered by host_id."""
    db = await get_db()
    try:
        if host_id is not None:
            cursor = await db.execute(
                """SELECT b.*, h.hostname, h.ip_address
                   FROM config_baselines b
                   JOIN hosts h ON h.id = b.host_id
                   WHERE b.host_id = ?
                   ORDER BY b.updated_at DESC LIMIT ?""",
                (host_id, limit),
            )
        else:
            cursor = await db.execute(
                """SELECT b.*, h.hostname, h.ip_address
                   FROM config_baselines b
                   JOIN hosts h ON h.id = b.host_id
                   ORDER BY b.updated_at DESC LIMIT ?""",
                (limit,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def update_config_baseline(
    baseline_id: int,
    name: str | None = None,
    config_text: str | None = None,
    source: str | None = None,
) -> None:
    """Update fields on a config baseline."""
    db = await get_db()
    try:
        parts: list[str] = []
        params: list = []
        if name is not None:
            parts.append("name = ?")
            params.append(name)
        if config_text is not None:
            parts.append("config_text = ?")
            params.append(config_text)
        if source is not None:
            parts.append("source = ?")
            params.append(source)
        if not parts:
            return
        parts.append("updated_at = datetime('now')")
        params.append(baseline_id)
        await db.execute(
            f"UPDATE config_baselines SET {', '.join(parts)} WHERE id = ?",
            tuple(params),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_config_baseline(baseline_id: int) -> None:
    """Delete a config baseline."""
    db = await get_db()
    try:
        await db.execute("DELETE FROM config_baselines WHERE id = ?", (baseline_id,))
        await db.commit()
    finally:
        await db.close()


# ── Config Snapshots ─────────────────────────────────────────────────────────


async def create_config_snapshot(
    host_id: int,
    config_text: str,
    capture_method: str = "manual",
) -> int:
    """Store a running-config snapshot for a host."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO config_snapshots (host_id, config_text, capture_method, captured_at)
               VALUES (?, ?, ?, datetime('now'))""",
            (host_id, config_text, capture_method),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_config_snapshot(snapshot_id: int) -> dict | None:
    """Return a single config snapshot by ID."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM config_snapshots WHERE id = ?", (snapshot_id,)
        )
        row = await cursor.fetchone()
        return row_to_dict(row)
    finally:
        await db.close()


async def get_config_snapshots_for_host(
    host_id: int, limit: int = 50
) -> list[dict]:
    """Return config snapshots for a host, newest first."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, host_id, capture_method, captured_at,
                      LENGTH(config_text) as config_length
               FROM config_snapshots
               WHERE host_id = ?
               ORDER BY captured_at DESC LIMIT ?""",
            (host_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_latest_config_snapshot(host_id: int) -> dict | None:
    """Return the most recent snapshot for a host."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM config_snapshots
               WHERE host_id = ?
               ORDER BY id DESC LIMIT 1""",
            (host_id,),
        )
        row = await cursor.fetchone()
        return row_to_dict(row)
    finally:
        await db.close()


async def delete_config_snapshot(snapshot_id: int) -> None:
    """Delete a config snapshot."""
    db = await get_db()
    try:
        await db.execute(
            "DELETE FROM config_snapshots WHERE id = ?", (snapshot_id,)
        )
        await db.commit()
    finally:
        await db.close()


async def delete_old_config_snapshots(days: int = 90) -> int:
    """Delete config snapshots older than N days."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM config_snapshots WHERE captured_at < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ── Config Drift Events ──────────────────────────────────────────────────────


async def create_config_drift_event(
    host_id: int,
    snapshot_id: int,
    baseline_id: int | None,
    diff_text: str,
    diff_lines_added: int = 0,
    diff_lines_removed: int = 0,
) -> int:
    """Record a detected configuration drift event."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO config_drift_events
               (host_id, snapshot_id, baseline_id, diff_text,
                diff_lines_added, diff_lines_removed, detected_at)
               VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
            (host_id, snapshot_id, baseline_id, diff_text,
             diff_lines_added, diff_lines_removed),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_config_drift_event(event_id: int) -> dict | None:
    """Return a single drift event with host info."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT e.*, h.hostname, h.ip_address, h.device_type
               FROM config_drift_events e
               JOIN hosts h ON h.id = e.host_id
               WHERE e.id = ?""",
            (event_id,),
        )
        row = await cursor.fetchone()
        return row_to_dict(row)
    finally:
        await db.close()


async def get_config_drift_events(
    status: str | None = None,
    host_id: int | None = None,
    limit: int = 100,
) -> list[dict]:
    """Return drift events with optional filters."""
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if status:
            clauses.append("e.status = ?")
            params.append(status)
        if host_id is not None:
            clauses.append("e.host_id = ?")
            params.append(host_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT e.id, e.host_id, e.snapshot_id, e.baseline_id,
                       e.status, e.diff_lines_added, e.diff_lines_removed,
                       e.detected_at, e.resolved_at, e.resolved_by,
                       h.hostname, h.ip_address, h.device_type
                FROM config_drift_events e
                JOIN hosts h ON h.id = e.host_id
                {where}
                ORDER BY e.detected_at DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_config_drift_summary() -> dict:
    """Return drift summary stats."""
    db = await get_db()
    try:
        # Count hosts with baselines
        cursor = await db.execute(
            "SELECT COUNT(*) FROM config_baselines"
        )
        row = await cursor.fetchone()
        total_baselined = row[0] if row else 0

        # Count hosts with open drift events
        cursor = await db.execute(
            "SELECT COUNT(DISTINCT host_id) FROM config_drift_events WHERE status = 'open'"
        )
        row = await cursor.fetchone()
        drifted = row[0] if row else 0

        # Count open events
        cursor = await db.execute(
            "SELECT COUNT(*) FROM config_drift_events WHERE status = 'open'"
        )
        row = await cursor.fetchone()
        open_events = row[0] if row else 0

        # Count accepted events
        cursor = await db.execute(
            "SELECT COUNT(*) FROM config_drift_events WHERE status = 'accepted'"
        )
        row = await cursor.fetchone()
        accepted_events = row[0] if row else 0

        return {
            "total_baselined": total_baselined,
            "compliant": max(0, total_baselined - drifted),
            "drifted": drifted,
            "open_events": open_events,
            "accepted_events": accepted_events,
        }
    finally:
        await db.close()


async def update_config_drift_event_status(
    event_id: int, status: str, resolved_by: str = ""
) -> None:
    """Update drift event status (open/resolved/accepted)."""
    db = await get_db()
    try:
        if status in ("resolved", "accepted"):
            await db.execute(
                """UPDATE config_drift_events
                   SET status = ?, resolved_at = datetime('now'), resolved_by = ?
                   WHERE id = ?""",
                (status, resolved_by, event_id),
            )
        else:
            await db.execute(
                "UPDATE config_drift_events SET status = ? WHERE id = ?",
                (status, event_id),
            )
        await db.commit()
    finally:
        await db.close()


async def delete_old_config_drift_events(days: int = 90) -> int:
    """Delete drift events older than N days."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM config_drift_events WHERE detected_at < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ── Config Backup Policies ──────────────────────────────────────────────────


async def create_config_backup_policy(
    name: str,
    group_id: int,
    credential_id: int,
    interval_seconds: int = 86400,
    retention_days: int = 30,
    created_by: str = "",
) -> int:
    """Create a new config backup policy."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO config_backup_policies
               (name, group_id, credential_id, interval_seconds, retention_days, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
            (name, group_id, credential_id, interval_seconds, retention_days, created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_config_backup_policies(group_id: int | None = None) -> list[dict]:
    """List all backup policies, optionally filtered by group."""
    db = await get_db()
    try:
        if group_id is not None:
            cursor = await db.execute(
                """SELECT p.*, g.name as group_name,
                          (SELECT COUNT(*) FROM hosts WHERE group_id = p.group_id) as host_count
                   FROM config_backup_policies p
                   LEFT JOIN inventory_groups g ON g.id = p.group_id
                   WHERE p.group_id = ?
                   ORDER BY p.name""",
                (group_id,),
            )
        else:
            cursor = await db.execute(
                """SELECT p.*, g.name as group_name,
                          (SELECT COUNT(*) FROM hosts WHERE group_id = p.group_id) as host_count
                   FROM config_backup_policies p
                   LEFT JOIN inventory_groups g ON g.id = p.group_id
                   ORDER BY p.name"""
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_config_backup_policy(policy_id: int) -> dict | None:
    """Get a single backup policy by ID."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT p.*, g.name as group_name,
                      (SELECT COUNT(*) FROM hosts WHERE group_id = p.group_id) as host_count
               FROM config_backup_policies p
               LEFT JOIN inventory_groups g ON g.id = p.group_id
               WHERE p.id = ?""",
            (policy_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_config_backup_policy(policy_id: int, **kwargs) -> None:
    """Update a backup policy. Pass only the fields to change."""
    allowed = {"name", "enabled", "credential_id", "interval_seconds", "retention_days"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return
    updates["updated_at"] = "datetime('now')"
    sets = []
    params = []
    for k, v in updates.items():
        if k == "updated_at":
            sets.append("updated_at = datetime('now')")
        else:
            sets.append(f"{k} = ?")
            params.append(v)
    params.append(policy_id)
    db = await get_db()
    try:
        await db.execute(
            f"UPDATE config_backup_policies SET {', '.join(sets)} WHERE id = ?",
            tuple(params),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_config_backup_policy(policy_id: int) -> None:
    """Delete a backup policy."""
    db = await get_db()
    try:
        await db.execute("DELETE FROM config_backup_policies WHERE id = ?", (policy_id,))
        await db.commit()
    finally:
        await db.close()


async def get_config_backup_policies_due() -> list[dict]:
    """Get enabled policies that are due for a backup run."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT p.*, g.name as group_name
               FROM config_backup_policies p
               LEFT JOIN inventory_groups g ON g.id = p.group_id
               WHERE p.enabled = 1
                 AND (p.last_run_at IS NULL
                      OR datetime(p.last_run_at, '+' || p.interval_seconds || ' seconds') < datetime('now'))"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def update_config_backup_policy_last_run(policy_id: int) -> None:
    """Mark a policy as just having been run."""
    db = await get_db()
    try:
        await db.execute(
            "UPDATE config_backup_policies SET last_run_at = datetime('now') WHERE id = ?",
            (policy_id,),
        )
        await db.commit()
    finally:
        await db.close()


# ── Config Backups ───────────────────────────────────────────────────────────


async def create_config_backup(
    policy_id: int | None,
    host_id: int,
    config_text: str,
    capture_method: str = "scheduled",
    status: str = "success",
    error_message: str = "",
) -> int:
    """Store a config backup record."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO config_backups
               (policy_id, host_id, config_text, capture_method, status, error_message, captured_at)
               VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
            (policy_id, host_id, config_text, capture_method, status, error_message),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_config_backups(
    host_id: int | None = None,
    policy_id: int | None = None,
    limit: int = 100,
) -> list[dict]:
    """List backups with host info, optionally filtered."""
    db = await get_db()
    try:
        conditions = []
        params: list = []
        if host_id is not None:
            conditions.append("b.host_id = ?")
            params.append(host_id)
        if policy_id is not None:
            conditions.append("b.policy_id = ?")
            params.append(policy_id)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT b.id, b.policy_id, b.host_id, b.capture_method, b.status,
                       b.error_message, b.captured_at, LENGTH(b.config_text) as config_length,
                       h.hostname, h.ip_address, h.device_type
                FROM config_backups b
                LEFT JOIN hosts h ON h.id = b.host_id
                {where}
                ORDER BY b.captured_at DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_config_backup(backup_id: int) -> dict | None:
    """Get a single backup record including config text."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT b.*, h.hostname, h.ip_address, h.device_type
               FROM config_backups b
               LEFT JOIN hosts h ON h.id = b.host_id
               WHERE b.id = ?""",
            (backup_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def delete_config_backup(backup_id: int) -> None:
    """Delete a single backup."""
    db = await get_db()
    try:
        await db.execute("DELETE FROM config_backups WHERE id = ?", (backup_id,))
        await db.commit()
    finally:
        await db.close()


async def delete_old_config_backups(days: int = 30) -> int:
    """Delete backups older than N days (retention cleanup)."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM config_backups WHERE captured_at < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def get_config_backup_summary() -> dict:
    """Return summary stats for config backups."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM config_backup_policies")
        row = await cursor.fetchone()
        total_policies = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(*) FROM config_backups")
        row = await cursor.fetchone()
        total_backups = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(DISTINCT host_id) FROM config_backups WHERE status = 'success'")
        row = await cursor.fetchone()
        hosts_backed_up = row[0] if row else 0

        cursor = await db.execute("SELECT MAX(captured_at) FROM config_backups")
        row = await cursor.fetchone()
        last_backup_at = row[0] if row else None

        return {
            "total_policies": total_policies,
            "total_backups": total_backups,
            "hosts_backed_up": hosts_backed_up,
            "last_backup_at": last_backup_at,
        }
    finally:
        await db.close()


# ── Compliance Profiles ─────────────────────────────────────────────────────


async def create_compliance_profile(
    name: str,
    description: str = "",
    rules: str = "[]",
    severity: str = "medium",
    created_by: str = "",
) -> int:
    """Create a new compliance profile with rules JSON."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO compliance_profiles
               (name, description, rules, severity, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
            (name, description, rules, severity, created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_compliance_profiles() -> list[dict]:
    """List all compliance profiles."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT p.*,
                      (SELECT COUNT(*) FROM compliance_profile_assignments WHERE profile_id = p.id) as assignment_count
               FROM compliance_profiles p
               ORDER BY p.name"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_compliance_profile(profile_id: int) -> dict | None:
    """Get a single compliance profile by ID."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM compliance_profiles WHERE id = ?", (profile_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_compliance_profile(profile_id: int, **kwargs) -> None:
    """Update a compliance profile. Pass only the fields to change."""
    allowed = {"name", "description", "rules", "severity"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return
    sets = []
    params = []
    for k, v in updates.items():
        sets.append(f"{k} = ?")
        params.append(v)
    sets.append("updated_at = datetime('now')")
    params.append(profile_id)
    db = await get_db()
    try:
        await db.execute(
            f"UPDATE compliance_profiles SET {', '.join(sets)} WHERE id = ?",
            tuple(params),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_compliance_profile(profile_id: int) -> None:
    """Delete a compliance profile and its assignments/results."""
    db = await get_db()
    try:
        await db.execute("DELETE FROM compliance_profiles WHERE id = ?", (profile_id,))
        await db.commit()
    finally:
        await db.close()


# ── Compliance Profile Assignments ──────────────────────────────────────────


async def create_compliance_assignment(
    profile_id: int,
    group_id: int,
    credential_id: int,
    interval_seconds: int = 86400,
    assigned_by: str = "",
) -> int:
    """Assign a compliance profile to an inventory group."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO compliance_profile_assignments
               (profile_id, group_id, credential_id, interval_seconds, assigned_by, assigned_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'))""",
            (profile_id, group_id, credential_id, interval_seconds, assigned_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_compliance_assignments(profile_id: int | None = None, group_id: int | None = None) -> list[dict]:
    """List compliance assignments, optionally filtered."""
    db = await get_db()
    try:
        where_clauses = []
        params = []
        if profile_id is not None:
            where_clauses.append("a.profile_id = ?")
            params.append(profile_id)
        if group_id is not None:
            where_clauses.append("a.group_id = ?")
            params.append(group_id)
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        cursor = await db.execute(
            f"""SELECT a.*, p.name as profile_name, p.severity as profile_severity,
                       g.name as group_name,
                       (SELECT COUNT(*) FROM hosts WHERE group_id = a.group_id) as host_count
                FROM compliance_profile_assignments a
                LEFT JOIN compliance_profiles p ON p.id = a.profile_id
                LEFT JOIN inventory_groups g ON g.id = a.group_id
                {where_sql}
                ORDER BY a.assigned_at DESC""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_compliance_assignment(assignment_id: int) -> dict | None:
    """Get a single compliance assignment by ID."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT a.*, p.name as profile_name, g.name as group_name
               FROM compliance_profile_assignments a
               LEFT JOIN compliance_profiles p ON p.id = a.profile_id
               LEFT JOIN inventory_groups g ON g.id = a.group_id
               WHERE a.id = ?""",
            (assignment_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_compliance_assignment(assignment_id: int, **kwargs) -> None:
    """Update an assignment. Pass only the fields to change."""
    allowed = {"enabled", "credential_id", "interval_seconds"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return
    sets = []
    params = []
    for k, v in updates.items():
        sets.append(f"{k} = ?")
        params.append(v)
    params.append(assignment_id)
    db = await get_db()
    try:
        await db.execute(
            f"UPDATE compliance_profile_assignments SET {', '.join(sets)} WHERE id = ?",
            tuple(params),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_compliance_assignment(assignment_id: int) -> None:
    """Delete a compliance assignment."""
    db = await get_db()
    try:
        await db.execute("DELETE FROM compliance_profile_assignments WHERE id = ?", (assignment_id,))
        await db.commit()
    finally:
        await db.close()


async def get_compliance_assignments_due() -> list[dict]:
    """Get enabled assignments that are due for a compliance scan."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT a.*, p.name as profile_name, p.rules as profile_rules,
                      p.severity as profile_severity, g.name as group_name
               FROM compliance_profile_assignments a
               LEFT JOIN compliance_profiles p ON p.id = a.profile_id
               LEFT JOIN inventory_groups g ON g.id = a.group_id
               WHERE a.enabled = 1
                 AND (a.last_scan_at IS NULL
                      OR datetime(a.last_scan_at, '+' || a.interval_seconds || ' seconds') < datetime('now'))"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def update_compliance_assignment_last_scan(assignment_id: int) -> None:
    """Mark an assignment as just having been scanned."""
    db = await get_db()
    try:
        await db.execute(
            "UPDATE compliance_profile_assignments SET last_scan_at = datetime('now') WHERE id = ?",
            (assignment_id,),
        )
        await db.commit()
    finally:
        await db.close()


# ── Compliance Scan Results ─────────────────────────────────────────────────


async def create_compliance_scan_result(
    assignment_id: int | None,
    profile_id: int,
    host_id: int,
    status: str = "compliant",
    total_rules: int = 0,
    passed_rules: int = 0,
    failed_rules: int = 0,
    findings: str = "[]",
    config_snippet: str = "",
) -> int:
    """Store a compliance scan result for a host."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO compliance_scan_results
               (assignment_id, profile_id, host_id, status, total_rules, passed_rules,
                failed_rules, findings, config_snippet, scanned_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (assignment_id, profile_id, host_id, status, total_rules, passed_rules,
             failed_rules, findings, config_snippet),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_compliance_scan_results(
    host_id: int | None = None,
    profile_id: int | None = None,
    assignment_id: int | None = None,
    status: str | None = None,
    limit: int = 200,
) -> list[dict]:
    """List compliance scan results with optional filters."""
    db = await get_db()
    try:
        where_clauses = []
        params: list = []
        if host_id is not None:
            where_clauses.append("r.host_id = ?")
            params.append(host_id)
        if profile_id is not None:
            where_clauses.append("r.profile_id = ?")
            params.append(profile_id)
        if assignment_id is not None:
            where_clauses.append("r.assignment_id = ?")
            params.append(assignment_id)
        if status is not None:
            where_clauses.append("r.status = ?")
            params.append(status)
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT r.*, p.name as profile_name, h.hostname, h.ip_address
                FROM compliance_scan_results r
                LEFT JOIN compliance_profiles p ON p.id = r.profile_id
                LEFT JOIN hosts h ON h.id = r.host_id
                {where_sql}
                ORDER BY r.scanned_at DESC
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_compliance_scan_result(result_id: int) -> dict | None:
    """Get a single scan result by ID."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT r.*, p.name as profile_name, h.hostname, h.ip_address
               FROM compliance_scan_results r
               LEFT JOIN compliance_profiles p ON p.id = r.profile_id
               LEFT JOIN hosts h ON h.id = r.host_id
               WHERE r.id = ?""",
            (result_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def delete_compliance_scan_result(result_id: int) -> None:
    """Delete a single scan result."""
    db = await get_db()
    try:
        await db.execute("DELETE FROM compliance_scan_results WHERE id = ?", (result_id,))
        await db.commit()
    finally:
        await db.close()


async def delete_old_compliance_scan_results(days: int = 90) -> int:
    """Delete compliance scan results older than N days."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM compliance_scan_results WHERE scanned_at < datetime('now', '-' || ? || ' days')",
            (days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def get_compliance_summary() -> dict:
    """Return summary stats for compliance scanning."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM compliance_profiles")
        row = await cursor.fetchone()
        total_profiles = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(*) FROM compliance_profile_assignments WHERE enabled = 1")
        row = await cursor.fetchone()
        active_assignments = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(DISTINCT host_id) FROM compliance_scan_results")
        row = await cursor.fetchone()
        hosts_scanned = row[0] if row else 0

        cursor = await db.execute(
            """SELECT COUNT(DISTINCT host_id) FROM compliance_scan_results
               WHERE status = 'non-compliant'
                 AND id IN (SELECT MAX(id) FROM compliance_scan_results GROUP BY host_id, profile_id)"""
        )
        row = await cursor.fetchone()
        hosts_non_compliant = row[0] if row else 0

        cursor = await db.execute("SELECT MAX(scanned_at) FROM compliance_scan_results")
        row = await cursor.fetchone()
        last_scan_at = row[0] if row else None

        return {
            "total_profiles": total_profiles,
            "active_assignments": active_assignments,
            "hosts_scanned": hosts_scanned,
            "hosts_non_compliant": hosts_non_compliant,
            "last_scan_at": last_scan_at,
        }
    finally:
        await db.close()


async def get_compliance_host_status(profile_id: int | None = None) -> list[dict]:
    """Get latest compliance status per host (optionally filtered by profile)."""
    db = await get_db()
    try:
        where_clause = "WHERE r.profile_id = ?" if profile_id is not None else ""
        params = (profile_id,) if profile_id is not None else ()
        cursor = await db.execute(
            f"""SELECT r.host_id, h.hostname, h.ip_address, r.profile_id,
                       p.name as profile_name, r.status, r.total_rules,
                       r.passed_rules, r.failed_rules, r.scanned_at
                FROM compliance_scan_results r
                INNER JOIN (
                    SELECT host_id, profile_id, MAX(id) as max_id
                    FROM compliance_scan_results
                    GROUP BY host_id, profile_id
                ) latest ON r.id = latest.max_id
                LEFT JOIN hosts h ON h.id = r.host_id
                LEFT JOIN compliance_profiles p ON p.id = r.profile_id
                {where_clause}
                ORDER BY r.status DESC, h.hostname""",
            params,
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ── Risk Analyses ───────────────────────────────────────────────────────────


async def create_risk_analysis(
    change_type: str = "template",
    host_id: int | None = None,
    group_id: int | None = None,
    risk_level: str = "low",
    risk_score: float = 0.0,
    proposed_commands: str = "",
    proposed_diff: str = "",
    current_config: str = "",
    simulated_config: str = "",
    analysis: str = "{}",
    compliance_impact: str = "[]",
    affected_areas: str = "[]",
    created_by: str = "",
) -> int:
    """Create a new risk analysis record."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO risk_analyses
               (change_type, host_id, group_id, risk_level, risk_score,
                proposed_commands, proposed_diff, current_config, simulated_config,
                analysis, compliance_impact, affected_areas, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (change_type, host_id, group_id, risk_level, risk_score,
             proposed_commands, proposed_diff, current_config, simulated_config,
             analysis, compliance_impact, affected_areas, created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_risk_analyses(
    host_id: int | None = None,
    group_id: int | None = None,
    risk_level: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """List risk analyses with optional filters."""
    db = await get_db()
    try:
        where_clauses = []
        params: list = []
        if host_id is not None:
            where_clauses.append("r.host_id = ?")
            params.append(host_id)
        if group_id is not None:
            where_clauses.append("r.group_id = ?")
            params.append(group_id)
        if risk_level is not None:
            where_clauses.append("r.risk_level = ?")
            params.append(risk_level)
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT r.*, h.hostname, h.ip_address, g.name as group_name
                FROM risk_analyses r
                LEFT JOIN hosts h ON h.id = r.host_id
                LEFT JOIN inventory_groups g ON g.id = r.group_id
                {where_sql}
                ORDER BY r.created_at DESC
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_risk_analysis(analysis_id: int) -> dict | None:
    """Get a single risk analysis by ID."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT r.*, h.hostname, h.ip_address, g.name as group_name
               FROM risk_analyses r
               LEFT JOIN hosts h ON h.id = r.host_id
               LEFT JOIN inventory_groups g ON g.id = r.group_id
               WHERE r.id = ?""",
            (analysis_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def approve_risk_analysis(analysis_id: int, approved_by: str) -> None:
    """Mark a risk analysis as approved."""
    db = await get_db()
    try:
        await db.execute(
            "UPDATE risk_analyses SET approved = 1, approved_by = ?, approved_at = datetime('now') WHERE id = ?",
            (approved_by, analysis_id),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_risk_analysis(analysis_id: int) -> None:
    """Delete a risk analysis."""
    db = await get_db()
    try:
        await db.execute("DELETE FROM risk_analyses WHERE id = ?", (analysis_id,))
        await db.commit()
    finally:
        await db.close()


async def get_risk_analysis_summary() -> dict:
    """Return summary stats for risk analyses."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM risk_analyses")
        row = await cursor.fetchone()
        total = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(*) FROM risk_analyses WHERE risk_level IN ('high', 'critical')")
        row = await cursor.fetchone()
        high_risk = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(*) FROM risk_analyses WHERE approved = 1")
        row = await cursor.fetchone()
        approved = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(*) FROM risk_analyses WHERE approved = 0")
        row = await cursor.fetchone()
        pending = row[0] if row else 0

        cursor = await db.execute("SELECT MAX(created_at) FROM risk_analyses")
        row = await cursor.fetchone()
        last_analysis_at = row[0] if row else None

        return {
            "total": total,
            "high_risk": high_risk,
            "approved": approved,
            "pending": pending,
            "last_analysis_at": last_analysis_at,
        }
    finally:
        await db.close()


# ── Deployments ──────────────────────────────────────────────────────────────


async def create_deployment(
    name: str,
    group_id: int,
    credential_id: int,
    change_type: str = "template",
    proposed_commands: str = "",
    template_id: int | None = None,
    risk_analysis_id: int | None = None,
    host_ids: str = "[]",
    description: str = "",
    created_by: str = "",
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO deployments
               (name, description, group_id, credential_id, change_type,
                proposed_commands, template_id, risk_analysis_id, host_ids,
                created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (name, description, group_id, credential_id, change_type,
             proposed_commands, template_id, risk_analysis_id, host_ids,
             created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_deployments(
    status: str | None = None,
    group_id: int | None = None,
    limit: int = 100,
) -> list[dict]:
    db = await get_db()
    try:
        where_clauses = []
        params: list = []
        if status:
            where_clauses.append("d.status = ?")
            params.append(status)
        if group_id is not None:
            where_clauses.append("d.group_id = ?")
            params.append(group_id)
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT d.*, g.name as group_name
                FROM deployments d
                LEFT JOIN inventory_groups g ON g.id = d.group_id
                {where_sql}
                ORDER BY d.created_at DESC
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_deployment(deployment_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT d.*, g.name as group_name
               FROM deployments d
               LEFT JOIN inventory_groups g ON g.id = d.group_id
               WHERE d.id = ?""",
            (deployment_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_deployment_status(
    deployment_id: int, status: str,
    rollback_status: str | None = None,
) -> None:
    db = await get_db()
    try:
        if rollback_status is not None:
            await db.execute(
                "UPDATE deployments SET status = ?, rollback_status = ? WHERE id = ?",
                (status, rollback_status, deployment_id),
            )
        else:
            await db.execute(
                "UPDATE deployments SET status = ? WHERE id = ?",
                (status, deployment_id),
            )
        if status in ("executing",) :
            await db.execute(
                "UPDATE deployments SET started_at = datetime('now') WHERE id = ? AND started_at IS NULL",
                (deployment_id,),
            )
        if status in ("completed", "failed", "rolled-back"):
            await db.execute(
                "UPDATE deployments SET finished_at = datetime('now') WHERE id = ?",
                (deployment_id,),
            )
        await db.commit()
    finally:
        await db.close()


async def delete_deployment(deployment_id: int) -> None:
    db = await get_db()
    try:
        await db.execute("DELETE FROM deployments WHERE id = ?", (deployment_id,))
        await db.commit()
    finally:
        await db.close()


async def get_deployment_summary() -> dict:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM deployments")
        total = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM deployments WHERE status = 'completed'")
        completed = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM deployments WHERE status IN ('executing', 'pre-check', 'post-check')")
        active = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM deployments WHERE status = 'rolled-back'")
        rolled_back = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM deployments WHERE status = 'failed'")
        failed = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM deployments WHERE status = 'planning'")
        planning = (await cursor.fetchone())[0]

        return {
            "total": total,
            "completed": completed,
            "active": active,
            "rolled_back": rolled_back,
            "failed": failed,
            "planning": planning,
        }
    finally:
        await db.close()


# ── Deployment Checkpoints ───────────────────────────────────────────────────


async def create_deployment_checkpoint(
    deployment_id: int,
    phase: str,
    check_name: str,
    check_type: str = "config_capture",
    host_id: int | None = None,
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO deployment_checkpoints
               (deployment_id, phase, check_name, check_type, host_id, created_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'))""",
            (deployment_id, phase, check_name, check_type, host_id),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_deployment_checkpoint(
    checkpoint_id: int, status: str, result: str = "{}",
) -> None:
    db = await get_db()
    try:
        await db.execute(
            """UPDATE deployment_checkpoints
               SET status = ?, result = ?, executed_at = datetime('now')
               WHERE id = ?""",
            (status, result, checkpoint_id),
        )
        await db.commit()
    finally:
        await db.close()


async def get_deployment_checkpoints(deployment_id: int) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT c.*, h.hostname, h.ip_address
               FROM deployment_checkpoints c
               LEFT JOIN hosts h ON h.id = c.host_id
               WHERE c.deployment_id = ?
               ORDER BY c.phase, c.id""",
            (deployment_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ── Deployment Snapshots ─────────────────────────────────────────────────────


async def create_deployment_snapshot(
    deployment_id: int,
    host_id: int,
    phase: str,
    config_text: str,
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO deployment_snapshots
               (deployment_id, host_id, phase, config_text, captured_at)
               VALUES (?, ?, ?, ?, datetime('now'))""",
            (deployment_id, host_id, phase, config_text),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_deployment_snapshots(
    deployment_id: int, phase: str | None = None,
) -> list[dict]:
    db = await get_db()
    try:
        if phase:
            cursor = await db.execute(
                """SELECT s.*, h.hostname, h.ip_address
                   FROM deployment_snapshots s
                   LEFT JOIN hosts h ON h.id = s.host_id
                   WHERE s.deployment_id = ? AND s.phase = ?
                   ORDER BY s.id""",
                (deployment_id, phase),
            )
        else:
            cursor = await db.execute(
                """SELECT s.*, h.hostname, h.ip_address
                   FROM deployment_snapshots s
                   LEFT JOIN hosts h ON h.id = s.host_id
                   WHERE s.deployment_id = ?
                   ORDER BY s.phase, s.id""",
                (deployment_id,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Monitoring Polls
# ═════════════════════════════════════════════════════════════════════════════


async def create_monitoring_poll(
    host_id: int,
    cpu_percent: float | None = None,
    memory_percent: float | None = None,
    memory_used_mb: float | None = None,
    memory_total_mb: float | None = None,
    uptime_seconds: int | None = None,
    if_up_count: int = 0,
    if_down_count: int = 0,
    if_admin_down: int = 0,
    if_details: str = "[]",
    vpn_tunnels_up: int = 0,
    vpn_tunnels_down: int = 0,
    vpn_details: str = "[]",
    route_count: int = 0,
    route_snapshot: str = "",
    poll_status: str = "ok",
    poll_error: str = "",
    response_time_ms: float | None = None,
    packet_loss_pct: float | None = None,
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO monitoring_polls
               (host_id, cpu_percent, memory_percent, memory_used_mb, memory_total_mb,
                uptime_seconds, if_up_count, if_down_count, if_admin_down, if_details,
                vpn_tunnels_up, vpn_tunnels_down, vpn_details,
                route_count, route_snapshot, poll_status, poll_error,
                response_time_ms, packet_loss_pct, polled_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (host_id, cpu_percent, memory_percent, memory_used_mb, memory_total_mb,
             uptime_seconds, if_up_count, if_down_count, if_admin_down, if_details,
             vpn_tunnels_up, vpn_tunnels_down, vpn_details,
             route_count, route_snapshot, poll_status, poll_error,
             response_time_ms, packet_loss_pct),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_latest_monitoring_polls(
    group_id: int | None = None, limit: int = 200,
) -> list[dict]:
    """Return the most recent poll per host, with host info joined."""
    db = await get_db()
    try:
        if group_id is not None:
            cursor = await db.execute(
                """SELECT p.*, h.hostname, h.ip_address, h.device_type, h.group_id
                   FROM monitoring_polls p
                   JOIN hosts h ON h.id = p.host_id
                   WHERE h.group_id = ?
                     AND p.id = (SELECT MAX(p2.id) FROM monitoring_polls p2 WHERE p2.host_id = p.host_id)
                   ORDER BY h.hostname
                   LIMIT ?""",
                (group_id, limit),
            )
        else:
            cursor = await db.execute(
                """SELECT p.*, h.hostname, h.ip_address, h.device_type, h.group_id
                   FROM monitoring_polls p
                   JOIN hosts h ON h.id = p.host_id
                   WHERE p.id = (SELECT MAX(p2.id) FROM monitoring_polls p2 WHERE p2.host_id = p.host_id)
                   ORDER BY h.hostname
                   LIMIT ?""",
                (limit,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_monitoring_poll_history(
    host_id: int, limit: int = 100,
) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT p.*, h.hostname, h.ip_address
               FROM monitoring_polls p
               JOIN hosts h ON h.id = p.host_id
               WHERE p.host_id = ?
               ORDER BY p.polled_at DESC
               LIMIT ?""",
            (host_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_old_monitoring_polls(retention_days: int) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM monitoring_polls WHERE polled_at < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def get_monitoring_summary(group_id: int | None = None) -> dict:
    db = await get_db()
    try:
        group_filter = ""
        params: list = []
        if group_id is not None:
            group_filter = "AND h.group_id = ?"
            params.append(group_id)

        cursor = await db.execute(
            f"""SELECT COUNT(DISTINCT p.host_id) FROM monitoring_polls p
                JOIN hosts h ON h.id = p.host_id WHERE 1=1 {group_filter}""",
            tuple(params),
        )
        monitored_hosts = (await cursor.fetchone())[0]

        cursor = await db.execute(
            f"""SELECT p.* FROM monitoring_polls p
                JOIN hosts h ON h.id = p.host_id
                WHERE p.id = (SELECT MAX(p2.id) FROM monitoring_polls p2 WHERE p2.host_id = p.host_id)
                {group_filter}""",
            tuple(params),
        )
        latest_polls = rows_to_list(await cursor.fetchall())

        total_cpu = 0.0
        cpu_count = 0
        total_mem = 0.0
        mem_count = 0
        total_if_up = 0
        total_if_down = 0
        total_vpn_up = 0
        total_vpn_down = 0
        total_routes = 0
        error_hosts = 0
        high_cpu_hosts = 0
        high_mem_hosts = 0

        for p in latest_polls:
            if p.get("cpu_percent") is not None:
                total_cpu += p["cpu_percent"]
                cpu_count += 1
                if p["cpu_percent"] >= 80:
                    high_cpu_hosts += 1
            if p.get("memory_percent") is not None:
                total_mem += p["memory_percent"]
                mem_count += 1
                if p["memory_percent"] >= 80:
                    high_mem_hosts += 1
            total_if_up += p.get("if_up_count", 0)
            total_if_down += p.get("if_down_count", 0)
            total_vpn_up += p.get("vpn_tunnels_up", 0)
            total_vpn_down += p.get("vpn_tunnels_down", 0)
            total_routes += p.get("route_count", 0)
            if p.get("poll_status") == "error":
                error_hosts += 1

        a_params = list(params)
        cursor = await db.execute(
            f"""SELECT COUNT(*) FROM monitoring_alerts a
                JOIN hosts h ON h.id = a.host_id
                WHERE a.acknowledged = 0 {group_filter}""",
            tuple(a_params),
        )
        open_alerts = (await cursor.fetchone())[0]

        cursor = await db.execute(
            f"""SELECT MAX(p.polled_at) FROM monitoring_polls p
                JOIN hosts h ON h.id = p.host_id WHERE 1=1 {group_filter}""",
            tuple(params),
        )
        row = await cursor.fetchone()
        last_poll_at = row[0] if row else None

        return {
            "monitored_hosts": monitored_hosts,
            "avg_cpu": round(total_cpu / cpu_count, 1) if cpu_count else None,
            "avg_memory": round(total_mem / mem_count, 1) if mem_count else None,
            "high_cpu_hosts": high_cpu_hosts,
            "high_mem_hosts": high_mem_hosts,
            "interfaces_up": total_if_up,
            "interfaces_down": total_if_down,
            "vpn_tunnels_up": total_vpn_up,
            "vpn_tunnels_down": total_vpn_down,
            "total_routes": total_routes,
            "error_hosts": error_hosts,
            "open_alerts": open_alerts,
            "last_poll_at": last_poll_at,
        }
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Monitoring Alerts
# ═════════════════════════════════════════════════════════════════════════════


async def create_monitoring_alert(
    host_id: int,
    poll_id: int | None,
    alert_type: str,
    metric: str,
    message: str,
    severity: str = "warning",
    value: float | None = None,
    threshold: float | None = None,
    rule_id: int | None = None,
    dedup_key: str = "",
) -> int:
    """Create or deduplicate a monitoring alert.

    If dedup_key is provided and an unacknowledged alert with the same key exists,
    bump its occurrence_count and update last_seen_at instead of creating a new one.
    Returns the alert ID (existing or new).
    """
    db = await get_db()
    try:
        # Dedup check
        if dedup_key:
            cursor = await db.execute(
                """SELECT id, occurrence_count FROM monitoring_alerts
                   WHERE dedup_key = ? AND acknowledged = 0
                   ORDER BY id DESC LIMIT 1""",
                (dedup_key,),
            )
            existing = await cursor.fetchone()
            if existing:
                eid = existing[0] if isinstance(existing, (list, tuple)) else existing["id"]
                cnt = (existing[1] if isinstance(existing, (list, tuple)) else existing["occurrence_count"]) + 1
                await db.execute(
                    """UPDATE monitoring_alerts
                       SET occurrence_count = ?, last_seen_at = datetime('now'),
                           value = ?, poll_id = ?, message = ?
                       WHERE id = ?""",
                    (cnt, value, poll_id, message, eid),
                )
                await db.commit()
                return eid

        if not dedup_key:
            dedup_key = f"{host_id}:{metric}:{alert_type}"

        cursor = await db.execute(
            """INSERT INTO monitoring_alerts
               (host_id, poll_id, rule_id, alert_type, metric, message,
                severity, original_severity, value, threshold,
                dedup_key, occurrence_count, last_seen_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'))""",
            (host_id, poll_id, rule_id, alert_type, metric, message,
             severity, severity, value, threshold, dedup_key),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_monitoring_alerts(
    host_id: int | None = None,
    acknowledged: bool | None = None,
    severity: str | None = None,
    limit: int = 200,
) -> list[dict]:
    db = await get_db()
    try:
        clauses = []
        params: list = []
        if host_id is not None:
            clauses.append("a.host_id = ?")
            params.append(host_id)
        if acknowledged is not None:
            clauses.append("a.acknowledged = ?")
            params.append(1 if acknowledged else 0)
        if severity:
            clauses.append("a.severity = ?")
            params.append(severity)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT a.*, h.hostname, h.ip_address, h.device_type
                FROM monitoring_alerts a
                JOIN hosts h ON h.id = a.host_id
                {where}
                ORDER BY a.created_at DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def acknowledge_monitoring_alert(
    alert_id: int, acknowledged_by: str,
) -> None:
    db = await get_db()
    try:
        await db.execute(
            """UPDATE monitoring_alerts
               SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = datetime('now')
               WHERE id = ?""",
            (acknowledged_by, alert_id),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_old_monitoring_alerts(retention_days: int) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM monitoring_alerts WHERE created_at < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Route Snapshots (churn detection)
# ═════════════════════════════════════════════════════════════════════════════


async def create_route_snapshot(
    host_id: int, route_count: int, routes_text: str, routes_hash: str,
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO route_snapshots
               (host_id, route_count, routes_text, routes_hash, captured_at)
               VALUES (?, ?, ?, ?, datetime('now'))""",
            (host_id, route_count, routes_text, routes_hash),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_route_snapshots(
    host_id: int, limit: int = 50,
) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT r.*, h.hostname, h.ip_address
               FROM route_snapshots r
               JOIN hosts h ON h.id = r.host_id
               WHERE r.host_id = ?
               ORDER BY r.captured_at DESC LIMIT ?""",
            (host_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_latest_route_snapshot(host_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM route_snapshots WHERE host_id = ? ORDER BY id DESC LIMIT 1",
            (host_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def delete_old_route_snapshots(retention_days: int) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM route_snapshots WHERE captured_at < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Alert Rules
# ═════════════════════════════════════════════════════════════════════════════


async def create_alert_rule(
    name: str,
    metric: str,
    rule_type: str = "threshold",
    operator: str = ">=",
    value: float = 0,
    severity: str = "warning",
    consecutive: int = 1,
    cooldown_minutes: int = 15,
    escalate_after_minutes: int = 0,
    escalate_to: str = "critical",
    host_id: int | None = None,
    group_id: int | None = None,
    description: str = "",
    created_by: str = "",
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO alert_rules
               (name, description, metric, rule_type, operator, value, severity,
                consecutive, cooldown_minutes, escalate_after_minutes, escalate_to,
                host_id, group_id, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
            (name, description, metric, rule_type, operator, value, severity,
             consecutive, cooldown_minutes, escalate_after_minutes, escalate_to,
             host_id, group_id, created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_alert_rules(enabled_only: bool = False) -> list[dict]:
    db = await get_db()
    try:
        where = "WHERE r.enabled = 1" if enabled_only else ""
        cursor = await db.execute(
            f"""SELECT r.*, h.hostname, h.ip_address, g.name as group_name
                FROM alert_rules r
                LEFT JOIN hosts h ON h.id = r.host_id
                LEFT JOIN inventory_groups g ON g.id = r.group_id
                {where}
                ORDER BY r.created_at DESC""",
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_alert_rule(rule_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT r.*, h.hostname, h.ip_address, g.name as group_name
               FROM alert_rules r
               LEFT JOIN hosts h ON h.id = r.host_id
               LEFT JOIN inventory_groups g ON g.id = r.group_id
               WHERE r.id = ?""",
            (rule_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_alert_rule(rule_id: int, **kwargs) -> None:
    allowed = {"name", "description", "metric", "rule_type", "operator", "value",
               "severity", "enabled", "consecutive", "cooldown_minutes",
               "escalate_after_minutes", "escalate_to", "host_id", "group_id"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return
    updates["updated_at"] = "datetime('now')"
    set_parts = []
    params: list = []
    for k, v in updates.items():
        if v == "datetime('now')":
            set_parts.append(f"{k} = datetime('now')")
        else:
            set_parts.append(f"{k} = ?")
            params.append(v)
    params.append(rule_id)
    db = await get_db()
    try:
        await db.execute(
            f"UPDATE alert_rules SET {', '.join(set_parts)} WHERE id = ?",
            tuple(params),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_alert_rule(rule_id: int) -> None:
    db = await get_db()
    try:
        await db.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
        await db.commit()
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Alert Suppressions
# ═════════════════════════════════════════════════════════════════════════════


async def create_alert_suppression(
    name: str,
    ends_at: str,
    host_id: int | None = None,
    group_id: int | None = None,
    metric: str = "",
    reason: str = "",
    starts_at: str = "",
    created_by: str = "",
) -> int:
    db = await get_db()
    try:
        starts = starts_at if starts_at else "datetime('now')"
        if starts_at:
            cursor = await db.execute(
                """INSERT INTO alert_suppressions
                   (name, host_id, group_id, metric, reason, starts_at, ends_at, created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
                (name, host_id, group_id, metric, reason, starts_at, ends_at, created_by),
            )
        else:
            cursor = await db.execute(
                """INSERT INTO alert_suppressions
                   (name, host_id, group_id, metric, reason, starts_at, ends_at, created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, datetime('now'), ?, ?, datetime('now'))""",
                (name, host_id, group_id, metric, reason, ends_at, created_by),
            )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_alert_suppressions(active_only: bool = False) -> list[dict]:
    db = await get_db()
    try:
        where = "WHERE s.ends_at > datetime('now')" if active_only else ""
        cursor = await db.execute(
            f"""SELECT s.*, h.hostname, h.ip_address, g.name as group_name
                FROM alert_suppressions s
                LEFT JOIN hosts h ON h.id = s.host_id
                LEFT JOIN inventory_groups g ON g.id = s.group_id
                {where}
                ORDER BY s.ends_at DESC""",
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def is_alert_suppressed(
    host_id: int, metric: str, group_id: int | None = None,
) -> bool:
    """Check if alerts for this host+metric are currently suppressed."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT COUNT(*) FROM alert_suppressions
               WHERE starts_at <= datetime('now') AND ends_at > datetime('now')
                 AND (
                     (host_id IS NULL AND group_id IS NULL AND metric = '')
                     OR (host_id = ? AND (metric = '' OR metric = ?))
                     OR (group_id = ? AND (metric = '' OR metric = ?))
                     OR (host_id IS NULL AND group_id IS NULL AND metric = ?)
                 )""",
            (host_id, metric, group_id or 0, metric, metric),
        )
        count = (await cursor.fetchone())[0]
        return count > 0
    finally:
        await db.close()


async def delete_alert_suppression(suppression_id: int) -> None:
    db = await get_db()
    try:
        await db.execute("DELETE FROM alert_suppressions WHERE id = ?", (suppression_id,))
        await db.commit()
    finally:
        await db.close()


async def delete_expired_suppressions() -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM alert_suppressions WHERE ends_at < datetime('now', '-7 days')",
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Alert Escalation Queries
# ═════════════════════════════════════════════════════════════════════════════


async def get_alerts_for_escalation(escalate_after_minutes: int) -> list[dict]:
    """Return unacknowledged, non-escalated alerts older than the escalation threshold."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT a.*, h.hostname, h.ip_address
               FROM monitoring_alerts a
               JOIN hosts h ON h.id = a.host_id
               WHERE a.acknowledged = 0
                 AND a.escalated = 0
                 AND a.severity != 'critical'
                 AND a.created_at < datetime('now', '-' || ? || ' minutes')
               ORDER BY a.created_at ASC""",
            (escalate_after_minutes,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def escalate_alert(alert_id: int, new_severity: str) -> None:
    db = await get_db()
    try:
        await db.execute(
            """UPDATE monitoring_alerts
               SET severity = ?, escalated = 1,
                   escalation_count = escalation_count + 1,
                   escalated_at = datetime('now')
               WHERE id = ?""",
            (new_severity, alert_id),
        )
        await db.commit()
    finally:
        await db.close()


async def bulk_acknowledge_alerts(alert_ids: list[int], acknowledged_by: str) -> int:
    """Acknowledge multiple alerts at once. Returns count updated."""
    if not alert_ids:
        return 0
    db = await get_db()
    try:
        placeholders = ",".join("?" for _ in alert_ids)
        cursor = await db.execute(
            f"""UPDATE monitoring_alerts
                SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = datetime('now')
                WHERE id IN ({placeholders}) AND acknowledged = 0""",
            (acknowledged_by, *alert_ids),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ── SLA Targets ──────────────────────────────────────────────────────────────


async def get_sla_targets(
    host_id: int | None = None,
    group_id: int | None = None,
) -> list[dict]:
    db = await get_db()
    try:
        where = ["1=1"]
        params: list = []
        if host_id is not None:
            where.append("t.host_id = ?")
            params.append(host_id)
        if group_id is not None:
            where.append("t.group_id = ?")
            params.append(group_id)
        cursor = await db.execute(
            f"""SELECT t.*,
                       h.hostname AS host_name,
                       g.name AS group_name
                FROM sla_targets t
                LEFT JOIN hosts h ON h.id = t.host_id
                LEFT JOIN inventory_groups g ON g.id = t.group_id
                WHERE {' AND '.join(where)}
                ORDER BY t.name""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_sla_target(target_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT t.*, h.hostname AS host_name, g.name AS group_name
               FROM sla_targets t
               LEFT JOIN hosts h ON h.id = t.host_id
               LEFT JOIN inventory_groups g ON g.id = t.group_id
               WHERE t.id = ?""",
            (target_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def create_sla_target(
    name: str,
    metric: str,
    target_value: float,
    warning_value: float,
    host_id: int | None = None,
    group_id: int | None = None,
    created_by: str = "",
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO sla_targets
               (name, metric, target_value, warning_value, host_id, group_id, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (name, metric, target_value, warning_value, host_id, group_id, created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_sla_target(target_id: int, **kwargs) -> None:
    allowed = {"name", "metric", "target_value", "warning_value", "enabled", "host_id", "group_id"}
    fields = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not fields:
        return
    fields["updated_at"] = datetime.now(UTC).isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    db = await get_db()
    try:
        await db.execute(
            f"UPDATE sla_targets SET {set_clause} WHERE id = ?",
            (*fields.values(), target_id),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_sla_target(target_id: int) -> None:
    db = await get_db()
    try:
        await db.execute("DELETE FROM sla_targets WHERE id = ?", (target_id,))
        await db.commit()
    finally:
        await db.close()


# ── SLA Summary & Host Detail ────────────────────────────────────────────────


async def get_sla_summary(
    group_id: int | None = None,
    days: int = 30,
) -> dict:
    """Compute SLA summary from monitoring_polls data directly."""
    db = await get_db()
    try:
        group_filter = ""
        params: list = [days]
        if group_id is not None:
            group_filter = "AND h.group_id = ?"
            params.append(group_id)

        # Per-host uptime (% of polls with status='ok'), latency, packet loss
        cursor = await db.execute(
            f"""SELECT h.id AS host_id, h.hostname, h.ip_address, h.group_id,
                       COUNT(*) AS total_polls,
                       SUM(CASE WHEN p.poll_status = 'ok' THEN 1 ELSE 0 END) AS ok_polls,
                       AVG(p.response_time_ms) AS avg_latency,
                       AVG(p.packet_loss_pct) AS avg_packet_loss
                FROM monitoring_polls p
                JOIN hosts h ON h.id = p.host_id
                WHERE p.polled_at >= datetime('now', '-' || ? || ' days')
                {group_filter}
                GROUP BY h.id
                ORDER BY h.hostname""",
            tuple(params),
        )
        rows = rows_to_list(await cursor.fetchall())

        hosts = []
        total_uptime = 0.0
        total_latency = 0.0
        total_packet_loss = 0.0
        latency_count = 0
        pkt_count = 0

        for r in rows:
            total = r["total_polls"] or 1
            ok = r["ok_polls"] or 0
            uptime_pct = round(ok / total * 100, 3)
            lat = round(r["avg_latency"], 2) if r["avg_latency"] is not None else None
            pkt = round(r["avg_packet_loss"], 2) if r["avg_packet_loss"] is not None else None

            total_uptime += uptime_pct
            if lat is not None:
                total_latency += lat
                latency_count += 1
            if pkt is not None:
                total_packet_loss += pkt
                pkt_count += 1

            hosts.append({
                "host_id": r["host_id"],
                "hostname": r["hostname"],
                "ip_address": r["ip_address"],
                "group_id": r["group_id"],
                "total_polls": total,
                "ok_polls": ok,
                "uptime_pct": uptime_pct,
                "avg_latency_ms": lat,
                "avg_packet_loss_pct": pkt,
            })

        host_count = len(hosts) or 1

        # Compute jitter per host from response_time_ms variance
        for h in hosts:
            jcursor = await db.execute(
                f"""SELECT AVG(p.response_time_ms) AS mean_rt,
                           AVG(p.response_time_ms * p.response_time_ms) AS mean_sq_rt
                    FROM monitoring_polls p
                    WHERE p.host_id = ? AND p.response_time_ms IS NOT NULL
                      AND p.polled_at >= datetime('now', '-' || ? || ' days')""",
                (h["host_id"], days),
            )
            jr = await jcursor.fetchone()
            if jr and jr[0] is not None and jr[1] is not None:
                variance = jr[1] - (jr[0] ** 2)
                h["jitter_ms"] = round(max(0, variance) ** 0.5, 2)
            else:
                h["jitter_ms"] = None

        # MTTR / MTTD from alerts
        cursor = await db.execute(
            f"""SELECT
                   AVG(CASE WHEN a.acknowledged = 1 AND a.acknowledged_at IS NOT NULL
                        THEN (julianday(a.acknowledged_at) - julianday(a.created_at)) * 1440
                        ELSE NULL END) AS avg_mttr_minutes,
                   COUNT(CASE WHEN a.acknowledged = 1 THEN 1 END) AS resolved_alerts,
                   COUNT(*) AS total_alerts
                FROM monitoring_alerts a
                JOIN hosts h ON h.id = a.host_id
                WHERE a.created_at >= datetime('now', '-' || ? || ' days')
                {group_filter}""",
            tuple(params),
        )
        alert_row = await cursor.fetchone()
        mttr = round(alert_row[0], 1) if alert_row and alert_row[0] is not None else None
        resolved_alerts = alert_row[1] if alert_row else 0
        total_alerts = alert_row[2] if alert_row else 0

        # MTTD: time from first failed poll to alert creation
        cursor = await db.execute(
            f"""SELECT AVG(
                    (julianday(a.created_at) -
                     julianday(COALESCE(
                        (SELECT MIN(p2.polled_at) FROM monitoring_polls p2
                         WHERE p2.host_id = a.host_id AND p2.poll_status = 'error'
                           AND p2.polled_at <= a.created_at
                           AND p2.polled_at >= datetime(a.created_at, '-1 day')),
                        a.created_at))
                    ) * 1440) AS avg_mttd_minutes
                FROM monitoring_alerts a
                JOIN hosts h ON h.id = a.host_id
                WHERE a.created_at >= datetime('now', '-' || ? || ' days')
                {group_filter}""",
            tuple(params),
        )
        mttd_row = await cursor.fetchone()
        mttd = round(mttd_row[0], 1) if mttd_row and mttd_row[0] is not None else None

        avg_jitter_vals = [h["jitter_ms"] for h in hosts if h["jitter_ms"] is not None]
        avg_jitter = round(sum(avg_jitter_vals) / len(avg_jitter_vals), 2) if avg_jitter_vals else None

        return {
            "period_days": days,
            "host_count": len(hosts),
            "avg_uptime_pct": round(total_uptime / host_count, 3),
            "avg_latency_ms": round(total_latency / latency_count, 2) if latency_count else None,
            "avg_jitter_ms": avg_jitter,
            "avg_packet_loss_pct": round(total_packet_loss / pkt_count, 2) if pkt_count else None,
            "mttr_minutes": mttr,
            "mttd_minutes": mttd,
            "total_alerts": total_alerts,
            "resolved_alerts": resolved_alerts,
            "hosts": hosts,
        }
    finally:
        await db.close()


async def get_sla_host_detail(
    host_id: int,
    days: int = 30,
) -> dict:
    """Detailed SLA metrics for a single host over time."""
    db = await get_db()
    try:
        # Daily uptime/latency/packet_loss trend
        cursor = await db.execute(
            """SELECT date(p.polled_at) AS day,
                      COUNT(*) AS total_polls,
                      SUM(CASE WHEN p.poll_status = 'ok' THEN 1 ELSE 0 END) AS ok_polls,
                      AVG(p.response_time_ms) AS avg_latency,
                      AVG(p.packet_loss_pct) AS avg_packet_loss,
                      AVG(p.response_time_ms * p.response_time_ms) AS mean_sq_rt,
                      AVG(p.response_time_ms) AS mean_rt
               FROM monitoring_polls p
               WHERE p.host_id = ?
                 AND p.polled_at >= datetime('now', '-' || ? || ' days')
               GROUP BY date(p.polled_at)
               ORDER BY day ASC""",
            (host_id, days),
        )
        daily = []
        for r in rows_to_list(await cursor.fetchall()):
            total = r["total_polls"] or 1
            ok = r["ok_polls"] or 0
            mean = r["mean_rt"]
            mean_sq = r["mean_sq_rt"]
            jitter = None
            if mean is not None and mean_sq is not None:
                variance = mean_sq - (mean ** 2)
                jitter = round(max(0, variance) ** 0.5, 2)
            daily.append({
                "day": r["day"],
                "uptime_pct": round(ok / total * 100, 3),
                "avg_latency_ms": round(r["avg_latency"], 2) if r["avg_latency"] is not None else None,
                "avg_packet_loss_pct": round(r["avg_packet_loss"], 2) if r["avg_packet_loss"] is not None else None,
                "jitter_ms": jitter,
                "total_polls": total,
                "ok_polls": ok,
            })

        # MTTR for this host
        cursor = await db.execute(
            """SELECT
                   AVG(CASE WHEN a.acknowledged = 1 AND a.acknowledged_at IS NOT NULL
                        THEN (julianday(a.acknowledged_at) - julianday(a.created_at)) * 1440
                        ELSE NULL END) AS avg_mttr_minutes,
                   COUNT(CASE WHEN a.acknowledged = 1 THEN 1 END) AS resolved,
                   COUNT(*) AS total
               FROM monitoring_alerts a
               WHERE a.host_id = ?
                 AND a.created_at >= datetime('now', '-' || ? || ' days')""",
            (host_id, days),
        )
        ar = await cursor.fetchone()

        # Host info
        cursor = await db.execute(
            "SELECT hostname, ip_address, device_type, group_id FROM hosts WHERE id = ?",
            (host_id,),
        )
        host_row = await cursor.fetchone()

        return {
            "host_id": host_id,
            "hostname": host_row[0] if host_row else "",
            "ip_address": host_row[1] if host_row else "",
            "device_type": host_row[2] if host_row else "",
            "group_id": host_row[3] if host_row else None,
            "period_days": days,
            "daily": daily,
            "mttr_minutes": round(ar[0], 1) if ar and ar[0] is not None else None,
            "resolved_alerts": ar[1] if ar else 0,
            "total_alerts": ar[2] if ar else 0,
        }
    finally:
        await db.close()


async def delete_old_sla_metrics(retention_days: int) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM sla_metrics WHERE period_start < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()
