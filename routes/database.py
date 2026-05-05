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
    stp_port_states   — latest spanning-tree port states per host/VLAN
    stp_topology_events — spanning-tree root/state change events
    stp_root_policies — expected STP root-bridge policy by group/VLAN
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
    report_artifacts       — persisted report outputs (CSV/SVG/etc) by run
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from datetime import UTC, datetime, timedelta

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

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.getenv(
    "APP_DB_PATH",
    os.path.join(_REPO_ROOT, "netcontrol.db"),
)


def _migrate_legacy_sqlite_path() -> None:
    """Move legacy routes/netcontrol.db (+ WAL/SHM sidecars) to the new default.

    The default SQLite location moved from ``routes/netcontrol.db`` to the repo
    root. Auto-migrate so existing dev installs do not appear to lose data.
    Runs only when ``APP_DB_PATH`` is unset (i.e., we own the default) and the
    legacy file exists.

    A zero-byte file at the new path is treated as a stub (e.g., created by a
    process that imported the module and called ``aiosqlite.connect`` before
    ever writing schema) and is overwritten by the migration. Any non-empty
    file at the new path is left untouched.
    """
    if os.getenv("APP_DB_PATH"):
        return
    legacy = os.path.join(os.path.dirname(__file__), "netcontrol.db")
    if not os.path.isfile(legacy):
        return
    try:
        new_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else -1
    except OSError:
        return
    if new_size > 0:
        return
    try:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        for suffix in ("", "-wal", "-shm"):
            src = legacy + suffix
            if os.path.isfile(src):
                os.replace(src, DB_PATH + suffix)
        _LOGGER.info("Migrated legacy SQLite database from %s to %s", legacy, DB_PATH)
    except OSError as exc:
        _LOGGER.warning("Could not migrate legacy SQLite database (%s); using new default", exc)


_migrate_legacy_sqlite_path()
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
    "stp_port_states",
    "stp_topology_events",
    "stp_root_policies",
    "config_baselines",
    "config_snapshots",
    "config_drift_events",
    "config_drift_event_history",
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
    "availability_transitions",
    "custom_oid_profiles",
    "report_definitions",
    "report_runs",
    "report_artifacts",
    "graph_templates",
    "graph_template_items",
    "host_templates",
    "host_template_graph_links",
    "host_graphs",
    "graph_trees",
    "graph_tree_nodes",
    "data_source_profiles",
    "snmp_data_sources",
    "cdef_definitions",
    "mac_address_table",
    "arp_table",
    "mac_tracking_history",
    "flow_records",
    "flow_summaries",
    "metric_baselines",
    "baseline_alert_rules",
    "upgrade_images",
    "upgrade_campaigns",
    "upgrade_devices",
    "upgrade_events",
    "billing_circuits",
    "billing_periods",
    "cloud_accounts",
    "cloud_resources",
    "cloud_connections",
    "cloud_hybrid_links",
    "cloud_policy_rules",
    "federation_peers",
    "federation_snapshots",
    "lab_environments",
    "lab_devices",
    "lab_runs",
    "lab_runtime_events",
    "lab_topologies",
    "lab_topology_links",
    "lab_drift_runs",
}

# ── SQL safety helpers ────────────────────────────────────────────────────────

# Only allow simple column identifiers in dynamic SQL (letters, digits, underscore).
_SAFE_COLUMN_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')


def _safe_dynamic_update(table: str, field_exprs: list[str], values: list, where_clause: str, where_val) -> tuple[str, tuple]:
    """Build a parameterized UPDATE statement from validated field expressions.

    Each field_expr must be of the form 'column_name = ?' and column_name
    must match a safe identifier pattern.  Raises ValueError if any field
    name contains suspicious characters (defence against SQL injection if
    a future caller passes user-controlled field names).
    """
    for expr in field_exprs:
        col = expr.split('=', 1)[0].strip()
        if not _SAFE_COLUMN_RE.match(col):
            raise ValueError(f"Unsafe column name in dynamic UPDATE: {col!r}")
    all_values = list(values) + [where_val]
    return f"UPDATE {table} SET {', '.join(field_exprs)} WHERE {where_clause}", tuple(all_values)


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
    model       TEXT    DEFAULT '',
    software_version TEXT DEFAULT '',
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

CREATE TABLE IF NOT EXISTS secret_variables (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    enc_value   TEXT    NOT NULL,
    description TEXT    DEFAULT '',
    created_by  TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id     INTEGER NOT NULL REFERENCES playbooks(id),
    inventory_group_id INTEGER REFERENCES inventory_groups(id),
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
    host_ids        TEXT    DEFAULT NULL,
    ad_hoc_ips      TEXT    DEFAULT NULL,
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

CREATE TABLE IF NOT EXISTS stp_port_states (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id                    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    vlan_id                    INTEGER NOT NULL DEFAULT 1,
    bridge_port                INTEGER NOT NULL DEFAULT 0,
    if_index                   INTEGER NOT NULL DEFAULT 0,
    interface_name             TEXT    NOT NULL DEFAULT '',
    port_state                 TEXT    NOT NULL DEFAULT '',
    port_role                  TEXT    NOT NULL DEFAULT '',
    designated_bridge_id       TEXT    NOT NULL DEFAULT '',
    root_bridge_id             TEXT    NOT NULL DEFAULT '',
    root_port                  INTEGER NOT NULL DEFAULT 0,
    topology_change_count      INTEGER NOT NULL DEFAULT 0,
    time_since_topology_change INTEGER NOT NULL DEFAULT 0,
    is_root_bridge             INTEGER NOT NULL DEFAULT 0,
    collected_at               TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host_id, vlan_id, bridge_port)
);

CREATE INDEX IF NOT EXISTS idx_stp_port_states_host_vlan
ON stp_port_states(host_id, vlan_id, collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_stp_port_states_state
ON stp_port_states(vlan_id, port_state);

CREATE TABLE IF NOT EXISTS stp_topology_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    vlan_id         INTEGER NOT NULL DEFAULT 1,
    event_type      TEXT    NOT NULL DEFAULT '',
    severity        TEXT    NOT NULL DEFAULT 'warning',
    interface_name  TEXT    NOT NULL DEFAULT '',
    details         TEXT    NOT NULL DEFAULT '',
    old_value       TEXT    NOT NULL DEFAULT '',
    new_value       TEXT    NOT NULL DEFAULT '',
    acknowledged    INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_stp_events_ack_created
ON stp_topology_events(acknowledged, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_stp_events_host_created
ON stp_topology_events(host_id, created_at DESC);

CREATE TABLE IF NOT EXISTS stp_root_policies (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id                 INTEGER NOT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
    vlan_id                  INTEGER NOT NULL DEFAULT 1,
    expected_root_bridge_id  TEXT    NOT NULL DEFAULT '',
    expected_root_hostname   TEXT    NOT NULL DEFAULT '',
    enabled                  INTEGER NOT NULL DEFAULT 1,
    created_at               TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at               TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(group_id, vlan_id)
);

CREATE INDEX IF NOT EXISTS idx_stp_root_policies_group_vlan
ON stp_root_policies(group_id, vlan_id);
CREATE INDEX IF NOT EXISTS idx_stp_root_policies_enabled
ON stp_root_policies(enabled, group_id, vlan_id);

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

CREATE TABLE IF NOT EXISTS config_drift_event_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id         INTEGER NOT NULL REFERENCES config_drift_events(id) ON DELETE CASCADE,
    host_id          INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    action           TEXT    NOT NULL DEFAULT '',
    from_status      TEXT    NOT NULL DEFAULT '',
    to_status        TEXT    NOT NULL DEFAULT '',
    actor            TEXT    NOT NULL DEFAULT '',
    details          TEXT    NOT NULL DEFAULT '',
    created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_config_drift_event_history_event_created
ON config_drift_event_history(event_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_config_drift_event_history_host_created
ON config_drift_event_history(host_id, created_at DESC);

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

CREATE TABLE IF NOT EXISTS metric_samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    metric_name     TEXT    NOT NULL,
    labels_json     TEXT    NOT NULL DEFAULT '{}',
    value           REAL    NOT NULL,
    sampled_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS metric_rollups (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    metric_name     TEXT    NOT NULL,
    labels_json     TEXT    NOT NULL DEFAULT '{}',
    time_window     TEXT    NOT NULL DEFAULT 'hourly',
    period_start    TEXT    NOT NULL,
    period_end      TEXT    NOT NULL,
    val_min         REAL    NOT NULL DEFAULT 0,
    val_avg         REAL    NOT NULL DEFAULT 0,
    val_max         REAL    NOT NULL DEFAULT 0,
    val_p95         REAL    NOT NULL DEFAULT 0,
    sample_count    INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS interface_ts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    if_index        INTEGER NOT NULL,
    if_name         TEXT    NOT NULL DEFAULT '',
    if_speed_mbps   INTEGER DEFAULT 0,
    in_octets       INTEGER DEFAULT 0,
    out_octets      INTEGER DEFAULT 0,
    in_rate_bps     REAL    DEFAULT NULL,
    out_rate_bps    REAL    DEFAULT NULL,
    utilization_pct REAL    DEFAULT NULL,
    sampled_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS vendor_oid_registry (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor          TEXT    NOT NULL,
    device_type     TEXT    NOT NULL DEFAULT '',
    cpu_oid         TEXT    NOT NULL DEFAULT '',
    cpu_walk        INTEGER NOT NULL DEFAULT 1,
    mem_used_oid    TEXT    NOT NULL DEFAULT '',
    mem_free_oid    TEXT    NOT NULL DEFAULT '',
    mem_total_oid   TEXT    NOT NULL DEFAULT '',
    uptime_oid      TEXT    NOT NULL DEFAULT '1.3.6.1.2.1.1.3',
    notes           TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(vendor, device_type)
);

CREATE TABLE IF NOT EXISTS trap_syslog_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip       TEXT    NOT NULL DEFAULT '',
    host_id         INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    event_type      TEXT    NOT NULL DEFAULT 'trap',
    facility        TEXT    NOT NULL DEFAULT '',
    severity        TEXT    NOT NULL DEFAULT 'info',
    oid             TEXT    NOT NULL DEFAULT '',
    message         TEXT    NOT NULL DEFAULT '',
    raw_data        TEXT    NOT NULL DEFAULT '',
    received_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_metric_samples_lookup
    ON metric_samples (metric_name, sampled_at);
CREATE INDEX IF NOT EXISTS idx_metric_samples_host
    ON metric_samples (host_id, metric_name, sampled_at);
CREATE INDEX IF NOT EXISTS idx_metric_rollups_lookup
    ON metric_rollups (metric_name, time_window, period_start);
CREATE INDEX IF NOT EXISTS idx_metric_rollups_host
    ON metric_rollups (host_id, metric_name, time_window, period_start);
CREATE INDEX IF NOT EXISTS idx_interface_ts_lookup
    ON interface_ts (host_id, if_index, sampled_at);
CREATE INDEX IF NOT EXISTS idx_trap_syslog_received
    ON trap_syslog_events (received_at);
CREATE INDEX IF NOT EXISTS idx_trap_syslog_host
    ON trap_syslog_events (host_id, received_at);

-- Core table indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_jobs_queued_status
    ON jobs (queued_at, status);
CREATE INDEX IF NOT EXISTS idx_hosts_group_id
    ON hosts (group_id);
CREATE INDEX IF NOT EXISTS idx_users_username
    ON users (username);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp
    ON audit_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_job_events_job_id
    ON job_events (job_id);
CREATE INDEX IF NOT EXISTS idx_credentials_owner_id
    ON credentials (owner_id);
CREATE INDEX IF NOT EXISTS idx_topology_links_source
    ON topology_links (source_host_id);
CREATE INDEX IF NOT EXISTS idx_secret_variables_name
    ON secret_variables (name);

CREATE TABLE IF NOT EXISTS dashboards (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    owner           TEXT    NOT NULL DEFAULT '',
    is_default      INTEGER NOT NULL DEFAULT 0,
    layout_json     TEXT    NOT NULL DEFAULT '{}',
    variables_json  TEXT    NOT NULL DEFAULT '[]',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS dashboard_panels (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    dashboard_id      INTEGER NOT NULL REFERENCES dashboards(id) ON DELETE CASCADE,
    title             TEXT    NOT NULL DEFAULT '',
    chart_type        TEXT    NOT NULL DEFAULT 'line',
    metric_query_json TEXT    NOT NULL DEFAULT '{}',
    grid_x            INTEGER NOT NULL DEFAULT 0,
    grid_y            INTEGER NOT NULL DEFAULT 0,
    grid_w            INTEGER NOT NULL DEFAULT 6,
    grid_h            INTEGER NOT NULL DEFAULT 4,
    options_json      TEXT    NOT NULL DEFAULT '{}',
    created_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_dashboard_panels_dashboard
    ON dashboard_panels (dashboard_id);

CREATE TABLE IF NOT EXISTS availability_transitions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    entity_type     TEXT    NOT NULL DEFAULT 'host',
    entity_id       TEXT    NOT NULL DEFAULT '',
    old_state       TEXT    NOT NULL DEFAULT 'unknown',
    new_state       TEXT    NOT NULL DEFAULT 'unknown',
    transition_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    poll_id         INTEGER REFERENCES monitoring_polls(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_avail_transitions_host
    ON availability_transitions (host_id, entity_type, transition_at);

CREATE TABLE IF NOT EXISTS custom_oid_profiles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    vendor          TEXT    NOT NULL DEFAULT '',
    device_type     TEXT    NOT NULL DEFAULT '',
    description     TEXT    NOT NULL DEFAULT '',
    oids_json       TEXT    NOT NULL DEFAULT '[]',
    is_default      INTEGER NOT NULL DEFAULT 0,
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS report_definitions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    report_type     TEXT    NOT NULL DEFAULT 'availability',
    parameters_json TEXT    NOT NULL DEFAULT '{}',
    schedule        TEXT    NOT NULL DEFAULT '',
    last_run_at     TEXT    DEFAULT NULL,
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS report_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id       INTEGER REFERENCES report_definitions(id) ON DELETE CASCADE,
    report_type     TEXT    NOT NULL DEFAULT 'availability',
    parameters_json TEXT    NOT NULL DEFAULT '{}',
    status          TEXT    NOT NULL DEFAULT 'running',
    result_json     TEXT    NOT NULL DEFAULT '{}',
    row_count       INTEGER NOT NULL DEFAULT 0,
    started_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    completed_at    TEXT    DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS report_artifacts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES report_runs(id) ON DELETE CASCADE,
    report_id       INTEGER REFERENCES report_definitions(id) ON DELETE SET NULL,
    artifact_type   TEXT    NOT NULL DEFAULT 'csv',
    file_name       TEXT    NOT NULL DEFAULT '',
    media_type      TEXT    NOT NULL DEFAULT 'text/plain',
    content_text    TEXT    NOT NULL DEFAULT '',
    content_blob    BLOB,
    size_bytes      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_report_artifacts_run
    ON report_artifacts (run_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_artifacts_report
    ON report_artifacts (report_id, created_at DESC);

-- ── Cacti-parity: Graph Templates ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS graph_templates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    graph_type      TEXT    NOT NULL DEFAULT 'line',
    category        TEXT    NOT NULL DEFAULT 'system',
    scope           TEXT    NOT NULL DEFAULT 'device',
    title_format    TEXT    NOT NULL DEFAULT '',
    y_axis_label    TEXT    NOT NULL DEFAULT '',
    y_min           REAL    DEFAULT NULL,
    y_max           REAL    DEFAULT NULL,
    stacked         INTEGER NOT NULL DEFAULT 0,
    area_fill       INTEGER NOT NULL DEFAULT 1,
    grid_w          INTEGER NOT NULL DEFAULT 6,
    grid_h          INTEGER NOT NULL DEFAULT 4,
    options_json    TEXT    NOT NULL DEFAULT '{}',
    built_in        INTEGER NOT NULL DEFAULT 0,
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS graph_template_items (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id     INTEGER NOT NULL REFERENCES graph_templates(id) ON DELETE CASCADE,
    sort_order      INTEGER NOT NULL DEFAULT 0,
    metric_name     TEXT    NOT NULL DEFAULT '',
    label           TEXT    NOT NULL DEFAULT '',
    color           TEXT    NOT NULL DEFAULT '',
    line_type       TEXT    NOT NULL DEFAULT 'area',
    cdef_expression TEXT    NOT NULL DEFAULT '',
    consolidation   TEXT    NOT NULL DEFAULT 'avg',
    transform       TEXT    NOT NULL DEFAULT '',
    legend_format   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_gti_template ON graph_template_items(template_id);

-- ── Cacti-parity: Host Templates ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS host_templates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    device_types    TEXT    NOT NULL DEFAULT '[]',
    auto_apply      INTEGER NOT NULL DEFAULT 1,
    poll_interval   INTEGER DEFAULT NULL,
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(name)
);

CREATE TABLE IF NOT EXISTS host_template_graph_links (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    host_template_id    INTEGER NOT NULL REFERENCES host_templates(id) ON DELETE CASCADE,
    graph_template_id   INTEGER NOT NULL REFERENCES graph_templates(id) ON DELETE CASCADE,
    UNIQUE(host_template_id, graph_template_id)
);

-- ── Cacti-parity: Host Graphs (instances of graph templates applied to devices)

CREATE TABLE IF NOT EXISTS host_graphs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    graph_template_id INTEGER NOT NULL REFERENCES graph_templates(id) ON DELETE CASCADE,
    title           TEXT    NOT NULL DEFAULT '',
    instance_key    TEXT    NOT NULL DEFAULT '',
    instance_label  TEXT    NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1,
    pinned          INTEGER NOT NULL DEFAULT 0,
    options_json    TEXT    NOT NULL DEFAULT '{}',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host_id, graph_template_id, instance_key)
);
CREATE INDEX IF NOT EXISTS idx_hg_host ON host_graphs(host_id);
CREATE INDEX IF NOT EXISTS idx_hg_template ON host_graphs(graph_template_id);

-- ── Cacti-parity: Graph Trees (hierarchical navigation) ────────────────────

CREATE TABLE IF NOT EXISTS graph_trees (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    sort_order      INTEGER NOT NULL DEFAULT 0,
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(name)
);

CREATE TABLE IF NOT EXISTS graph_tree_nodes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tree_id         INTEGER NOT NULL REFERENCES graph_trees(id) ON DELETE CASCADE,
    parent_node_id  INTEGER DEFAULT NULL REFERENCES graph_tree_nodes(id) ON DELETE CASCADE,
    node_type       TEXT    NOT NULL DEFAULT 'header',
    title           TEXT    NOT NULL DEFAULT '',
    sort_order      INTEGER NOT NULL DEFAULT 0,
    host_id         INTEGER DEFAULT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    group_id        INTEGER DEFAULT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
    graph_id        INTEGER DEFAULT NULL REFERENCES host_graphs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_gtn_tree ON graph_tree_nodes(tree_id);
CREATE INDEX IF NOT EXISTS idx_gtn_parent ON graph_tree_nodes(parent_node_id);

-- ── Cacti-parity: Data Source Profiles (per-device poll config) ────────────

CREATE TABLE IF NOT EXISTS data_source_profiles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    profile_name    TEXT    NOT NULL DEFAULT 'default',
    poll_interval   INTEGER NOT NULL DEFAULT 300,
    oids_json       TEXT    NOT NULL DEFAULT '[]',
    enabled         INTEGER NOT NULL DEFAULT 1,
    last_polled_at  TEXT    DEFAULT NULL,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host_id, profile_name)
);
CREATE INDEX IF NOT EXISTS idx_dsp_host ON data_source_profiles(host_id);

-- ── SNMP Data Sources (auto-discovered independent data sources) ──────────

CREATE TABLE IF NOT EXISTS snmp_data_sources (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            TEXT    NOT NULL DEFAULT '',
    ds_type         TEXT    NOT NULL DEFAULT 'interface',
    table_oid       TEXT    NOT NULL DEFAULT '',
    index_oid       TEXT    NOT NULL DEFAULT '',
    instance_key    TEXT    NOT NULL DEFAULT '',
    instance_label  TEXT    NOT NULL DEFAULT '',
    oids_json       TEXT    NOT NULL DEFAULT '[]',
    poll_interval   INTEGER NOT NULL DEFAULT 300,
    enabled         INTEGER NOT NULL DEFAULT 1,
    last_polled_at  TEXT    DEFAULT NULL,
    discovered_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host_id, ds_type, instance_key)
);
CREATE INDEX IF NOT EXISTS idx_snmp_ds_host ON snmp_data_sources(host_id);
CREATE INDEX IF NOT EXISTS idx_snmp_ds_type ON snmp_data_sources(host_id, ds_type);

-- ── CDEF Definitions (calculated data sources) ───────────────────────────

CREATE TABLE IF NOT EXISTS cdef_definitions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    description     TEXT    NOT NULL DEFAULT '',
    expression      TEXT    NOT NULL DEFAULT '',
    built_in        INTEGER NOT NULL DEFAULT 0,
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── MAC/ARP Tracking ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS mac_address_table (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    mac_address     TEXT    NOT NULL,
    vlan            INTEGER DEFAULT 0,
    port_name       TEXT    NOT NULL DEFAULT '',
    port_index      INTEGER DEFAULT 0,
    ip_address      TEXT    DEFAULT '',
    entry_type      TEXT    NOT NULL DEFAULT 'dynamic',
    first_seen      TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host_id, mac_address, vlan)
);
CREATE INDEX IF NOT EXISTS idx_mac_table_mac ON mac_address_table(mac_address);
CREATE INDEX IF NOT EXISTS idx_mac_table_port ON mac_address_table(host_id, port_name);
CREATE INDEX IF NOT EXISTS idx_mac_table_ip ON mac_address_table(ip_address);

CREATE TABLE IF NOT EXISTS arp_table (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    ip_address      TEXT    NOT NULL,
    mac_address     TEXT    NOT NULL,
    interface_name  TEXT    NOT NULL DEFAULT '',
    vrf             TEXT    NOT NULL DEFAULT '',
    first_seen      TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host_id, ip_address, vrf)
);
CREATE INDEX IF NOT EXISTS idx_arp_table_ip ON arp_table(ip_address);
CREATE INDEX IF NOT EXISTS idx_arp_table_mac ON arp_table(mac_address);

CREATE TABLE IF NOT EXISTS mac_tracking_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address     TEXT    NOT NULL,
    ip_address      TEXT    DEFAULT '',
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port_name       TEXT    NOT NULL DEFAULT '',
    vlan            INTEGER DEFAULT 0,
    seen_at         TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_mac_history_mac ON mac_tracking_history(mac_address, seen_at);

-- ── NetFlow / sFlow / IPFIX ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS flow_records (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    exporter_ip     TEXT    NOT NULL,
    host_id         INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    flow_type       TEXT    NOT NULL DEFAULT 'netflow',
    src_ip          TEXT    NOT NULL DEFAULT '',
    dst_ip          TEXT    NOT NULL DEFAULT '',
    src_port        INTEGER DEFAULT 0,
    dst_port        INTEGER DEFAULT 0,
    protocol        INTEGER DEFAULT 0,
    bytes           INTEGER DEFAULT 0,
    packets         INTEGER DEFAULT 0,
    src_as          INTEGER DEFAULT 0,
    dst_as          INTEGER DEFAULT 0,
    input_if        INTEGER DEFAULT 0,
    output_if       INTEGER DEFAULT 0,
    tos             INTEGER DEFAULT 0,
    tcp_flags       INTEGER DEFAULT 0,
    start_time      TEXT    NOT NULL DEFAULT (datetime('now')),
    end_time        TEXT    NOT NULL DEFAULT (datetime('now')),
    received_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_flow_received ON flow_records(received_at);
CREATE INDEX IF NOT EXISTS idx_flow_exporter ON flow_records(exporter_ip, received_at);
CREATE INDEX IF NOT EXISTS idx_flow_src ON flow_records(src_ip, received_at);
CREATE INDEX IF NOT EXISTS idx_flow_dst ON flow_records(dst_ip, received_at);

CREATE TABLE IF NOT EXISTS flow_summaries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    summary_type    TEXT    NOT NULL DEFAULT 'top_talkers',
    time_window     TEXT    NOT NULL DEFAULT 'hourly',
    period_start    TEXT    NOT NULL,
    period_end      TEXT    NOT NULL,
    data_json       TEXT    NOT NULL DEFAULT '{}',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_flow_summary_lookup ON flow_summaries(host_id, summary_type, period_start);

-- ── Metric Baselines (statistical learning) ──────────────────────────────

CREATE TABLE IF NOT EXISTS metric_baselines (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    metric_name     TEXT    NOT NULL,
    labels_json     TEXT    NOT NULL DEFAULT '{}',
    day_of_week     INTEGER NOT NULL DEFAULT -1,
    hour_of_day     INTEGER NOT NULL DEFAULT -1,
    baseline_avg    REAL    NOT NULL DEFAULT 0,
    baseline_stddev REAL    NOT NULL DEFAULT 0,
    baseline_min    REAL    NOT NULL DEFAULT 0,
    baseline_max    REAL    NOT NULL DEFAULT 0,
    baseline_p95    REAL    NOT NULL DEFAULT 0,
    sample_count    INTEGER NOT NULL DEFAULT 0,
    learning_window_days INTEGER NOT NULL DEFAULT 14,
    last_computed   TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host_id, metric_name, labels_json, day_of_week, hour_of_day)
);
CREATE INDEX IF NOT EXISTS idx_baselines_lookup ON metric_baselines(host_id, metric_name, day_of_week, hour_of_day);

CREATE TABLE IF NOT EXISTS baseline_alert_rules (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT    NOT NULL DEFAULT '',
    description         TEXT    NOT NULL DEFAULT '',
    metric_name         TEXT    NOT NULL DEFAULT '',
    host_id             INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    group_id            INTEGER REFERENCES inventory_groups(id) ON DELETE CASCADE,
    sensitivity         REAL    NOT NULL DEFAULT 2.0,
    min_samples         INTEGER NOT NULL DEFAULT 100,
    learning_days       INTEGER NOT NULL DEFAULT 14,
    enabled             INTEGER NOT NULL DEFAULT 1,
    severity            TEXT    NOT NULL DEFAULT 'warning',
    cooldown_minutes    INTEGER NOT NULL DEFAULT 30,
    created_by          TEXT    NOT NULL DEFAULT '',
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── IOS-XE Upgrade System ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS upgrade_images (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    filename        TEXT    NOT NULL UNIQUE,
    original_name   TEXT    NOT NULL DEFAULT '',
    file_size       INTEGER NOT NULL DEFAULT 0,
    md5_hash        TEXT    NOT NULL DEFAULT '',
    model_pattern   TEXT    NOT NULL DEFAULT '',
    version         TEXT    NOT NULL DEFAULT '',
    platform        TEXT    NOT NULL DEFAULT 'iosxe',
    notes           TEXT    NOT NULL DEFAULT '',
    uploaded_by     TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS upgrade_campaigns (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    status          TEXT    NOT NULL DEFAULT 'created',
    image_map       TEXT    NOT NULL DEFAULT '{}',
    options         TEXT    NOT NULL DEFAULT '{}',
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS upgrade_devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id     INTEGER NOT NULL REFERENCES upgrade_campaigns(id) ON DELETE CASCADE,
    host_id         INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    ip_address      TEXT    NOT NULL,
    hostname        TEXT    NOT NULL DEFAULT '',
    model           TEXT    NOT NULL DEFAULT '',
    current_version TEXT    NOT NULL DEFAULT '',
    target_image    TEXT    NOT NULL DEFAULT '',
    phase           TEXT    NOT NULL DEFAULT 'pending',
    phase_detail    TEXT    NOT NULL DEFAULT '',
    health_status   TEXT    NOT NULL DEFAULT '',
    prestage_status TEXT    NOT NULL DEFAULT 'pending',
    transfer_status TEXT    NOT NULL DEFAULT 'pending',
    activate_status TEXT    NOT NULL DEFAULT 'pending',
    verify_status   TEXT    NOT NULL DEFAULT 'pending',
    error_message   TEXT    NOT NULL DEFAULT '',
    started_at      TEXT,
    completed_at    TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(campaign_id, ip_address)
);

CREATE TABLE IF NOT EXISTS upgrade_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id     INTEGER NOT NULL REFERENCES upgrade_campaigns(id) ON DELETE CASCADE,
    device_id       INTEGER REFERENCES upgrade_devices(id) ON DELETE CASCADE,
    level           TEXT    NOT NULL DEFAULT 'info',
    message         TEXT    NOT NULL DEFAULT '',
    host            TEXT    NOT NULL DEFAULT '',
    timestamp       TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Missing FK indexes for join performance ──────────────────────────────
CREATE INDEX IF NOT EXISTS idx_compliance_assign_profile
    ON compliance_profile_assignments (profile_id);
CREATE INDEX IF NOT EXISTS idx_compliance_assign_group
    ON compliance_profile_assignments (group_id);
CREATE INDEX IF NOT EXISTS idx_monitoring_alerts_rule
    ON monitoring_alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_monitoring_alerts_poll
    ON monitoring_alerts (poll_id);
CREATE INDEX IF NOT EXISTS idx_deployment_checks_deploy
    ON deployment_checkpoints (deployment_id);
CREATE INDEX IF NOT EXISTS idx_user_group_member_user
    ON user_group_memberships (user_id);
CREATE INDEX IF NOT EXISTS idx_user_group_member_group
    ON user_group_memberships (group_id);
CREATE INDEX IF NOT EXISTS idx_topology_links_target
    ON topology_links (target_host_id);
CREATE INDEX IF NOT EXISTS idx_access_group_features_group
    ON access_group_features (group_id);
"""


def _convert_sqlite_schema_to_postgres(sqlite_schema: str) -> str:
    converted = sqlite_schema
    converted = converted.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    converted = converted.replace("DEFAULT (datetime('now'))", "DEFAULT NOW()")
    converted = converted.replace(" BLOB", " BYTEA")
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
    await db.commit()


async def init_db():
    """Create all tables and run pending schema migrations."""
    from routes.migrations import run_migrations

    db = await get_db()
    try:
        if DB_ENGINE == "postgres":
            await _init_postgres(db)
        else:
            await db.executescript(SCHEMA)
            await db.commit()

        await run_migrations(db, engine=DB_ENGINE)
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
        await db.rollback()
        if _is_unique_violation(e):
            raise ValueError(f"Username '{username}' already exists.")
        raise
    finally:
        await db.close()


async def update_user_password(
    user_id: int,
    password_hash: str,
    salt: str,
    must_change_password: bool = False,
):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE users SET password_hash = ?, salt = ?, must_change_password = ? WHERE id = ?",
            (password_hash, salt, int(bool(must_change_password)), user_id),
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
        sql, params = _safe_dynamic_update("users", fields, values, "id = ?", user_id)
        await db.execute(sql, params)
        await db.commit()
    except Exception as e:
        await db.rollback()
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
    except Exception:
        await db.rollback()
        raise
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
        await db.rollback()
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
        await db.rollback()
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
        await db.rollback()
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


async def get_user_effective_features(user_id: int) -> list[str] | None:
    """Return the set of feature keys the user has via group memberships.

    Returns ``None`` if the user has **no** group memberships at all (so the
    caller can distinguish "unassigned" from "assigned but zero features").
    """
    db = await get_db()
    try:
        # First check whether the user has any group membership rows
        cursor = await db.execute(
            "SELECT COUNT(*) FROM user_group_memberships WHERE user_id = ?",
            (user_id,),
        )
        count = (await cursor.fetchone())[0]
        if count == 0:
            return None  # No memberships — caller decides default

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
                h.last_seen AS host_last_seen,
                h.model AS host_model,
                h.software_version AS host_software_version,
                h.device_category AS host_device_category,
                h.serial_number AS host_serial_number
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
            "model": row["host_model"] or "",
            "software_version": row["host_software_version"] or "",
            "device_category": row["host_device_category"] or "",
            "serial_number": row["host_serial_number"] or "",
        })
        group["host_count"] += 1

    return groups


async def get_all_groups_for_user(user_id: int) -> list[dict]:
    """Like get_all_groups but ordered by the user's saved drag order.

    Groups the user has not explicitly positioned fall to the bottom
    alphabetically (COALESCE(position, large sentinel)).
    """
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            SELECT g.*, COUNT(h.id) AS host_count, o.position AS _position
            FROM inventory_groups g
            LEFT JOIN hosts h ON h.group_id = g.id
            LEFT JOIN user_inventory_group_order o
                   ON o.group_id = g.id AND o.user_id = ?
            GROUP BY g.id, o.position
            ORDER BY COALESCE(o.position, 2147483647), g.name
            """,
            (user_id,),
        )
        rows = rows_to_list(await cursor.fetchall())
    finally:
        await db.close()
    for row in rows:
        row.pop("_position", None)
    return rows


async def get_all_groups_with_hosts_for_user(user_id: int) -> list[dict]:
    """Per-user-ordered variant of get_all_groups_with_hosts."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            SELECT
                g.id AS group_id,
                g.name AS group_name,
                g.description AS group_description,
                o.position AS _position,
                h.id AS host_id,
                h.group_id AS host_group_id,
                h.hostname AS host_hostname,
                h.ip_address AS host_ip_address,
                h.device_type AS host_device_type,
                h.status AS host_status,
                h.last_seen AS host_last_seen,
                h.model AS host_model,
                h.software_version AS host_software_version,
                h.device_category AS host_device_category,
                h.serial_number AS host_serial_number
            FROM inventory_groups g
            LEFT JOIN hosts h ON h.group_id = g.id
            LEFT JOIN user_inventory_group_order o
                   ON o.group_id = g.id AND o.user_id = ?
            ORDER BY COALESCE(o.position, 2147483647), g.name, h.ip_address
            """,
            (user_id,),
        )
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
            "model": row["host_model"] or "",
            "software_version": row["host_software_version"] or "",
            "device_category": row["host_device_category"] or "",
            "serial_number": row["host_serial_number"] or "",
        })
        group["host_count"] += 1

    return groups


async def set_user_group_order(user_id: int, ordered_group_ids: list[int]) -> None:
    """Replace the saved order for a user with the given list of group ids."""
    db = await get_db()
    try:
        await db.execute(
            "DELETE FROM user_inventory_group_order WHERE user_id = ?",
            (user_id,),
        )
        for position, group_id in enumerate(ordered_group_ids):
            await db.execute(
                "INSERT INTO user_inventory_group_order (user_id, group_id, position) "
                "VALUES (?, ?, ?)",
                (user_id, int(group_id), position),
            )
        await db.commit()
    finally:
        await db.close()


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
    except Exception:
        await db.rollback()
        raise
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


async def get_all_hosts() -> list[dict]:
    """Get every host across all groups, ordered by hostname."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM hosts ORDER BY hostname, ip_address"
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def find_host_by_ip(ip_address: str) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM hosts WHERE ip_address = ? LIMIT 1", (ip_address,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def add_host(group_id: int, hostname: str, ip_address: str,
                   device_type: str = "cisco_ios",
                   vrf_name: str = "", vlan_id: str = "") -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address, device_type, vrf_name, vlan_id) "
            "VALUES (?,?,?,?,?,?)",
            (group_id, hostname, ip_address, device_type, vrf_name or "", str(vlan_id or "")),
        )
        await db.commit()
        new_id = cursor.lastrowid
    finally:
        await db.close()
    if ip_address:
        try:
            await record_ip_assignment(
                address=ip_address, hostname=hostname or "",
                vrf_name=vrf_name or "", source_type="host",
                source_ref=str(new_id), note="host added",
            )
        except Exception:
            pass
    return new_id


async def remove_host(host_id: int):
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT ip_address, vrf_name FROM hosts WHERE id = ?", (host_id,)
        )
        row = await cur.fetchone()
        prior_ip = ""
        prior_vrf = ""
        if row:
            d = dict(row)
            prior_ip = (d.get("ip_address") or "").strip()
            prior_vrf = (d.get("vrf_name") or "").strip()
        await db.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        await db.commit()
    finally:
        await db.close()
    if prior_ip:
        try:
            await record_ip_release(
                address=prior_ip, vrf_name=prior_vrf, note="host removed"
            )
        except Exception:
            pass


async def update_host(host_id: int, hostname: str, ip_address: str,
                      device_type: str = "cisco_ios",
                      vrf_name: str | None = None, vlan_id: str | None = None):
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT ip_address, vrf_name FROM hosts WHERE id = ?", (host_id,)
        )
        prior_row = await cur.fetchone()
        prior = dict(prior_row) if prior_row else {}
        prior_ip = (prior.get("ip_address") or "").strip()
        prior_vrf = (prior.get("vrf_name") or "").strip()

        if vrf_name is None and vlan_id is None:
            await db.execute(
                "UPDATE hosts SET hostname=?, ip_address=?, device_type=? WHERE id=?",
                (hostname, ip_address, device_type, host_id),
            )
        else:
            await db.execute(
                "UPDATE hosts SET hostname=?, ip_address=?, device_type=?, vrf_name=?, vlan_id=? "
                "WHERE id=?",
                (hostname, ip_address, device_type,
                 vrf_name or "", str(vlan_id or ""), host_id),
            )
        await db.commit()
    finally:
        await db.close()

    new_vrf = (vrf_name or prior_vrf) if vrf_name is not None else prior_vrf
    new_ip = (ip_address or "").strip()
    try:
        if prior_ip and (prior_ip != new_ip or prior_vrf != new_vrf):
            await record_ip_release(
                address=prior_ip, vrf_name=prior_vrf, note="host updated"
            )
        if new_ip:
            await record_ip_assignment(
                address=new_ip, hostname=hostname or "",
                vrf_name=new_vrf or "", source_type="host",
                source_ref=str(host_id), note="host updated",
            )
    except Exception:
        pass


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
        cur = await db.execute(
            f"SELECT ip_address, vrf_name FROM hosts WHERE id IN ({placeholders})",
            tuple(host_ids),
        )
        prior_rows = [dict(r) for r in await cur.fetchall()]
        cursor = await db.execute(
            f"DELETE FROM hosts WHERE id IN ({placeholders})",
            tuple(host_ids),
        )
        await db.commit()
        rowcount = cursor.rowcount
    finally:
        await db.close()
    for r in prior_rows:
        ip = (r.get("ip_address") or "").strip()
        vrf = (r.get("vrf_name") or "").strip()
        if ip:
            try:
                await record_ip_release(
                    address=ip, vrf_name=vrf, note="bulk host delete"
                )
            except Exception:
                pass
    return rowcount


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


async def update_host_device_info(host_id: int, model: str, software_version: str,
                                  device_category: str = ""):
    """Update the model, software_version, and device_category fields for a host."""
    db = await get_db()
    try:
        if device_category:
            await db.execute(
                "UPDATE hosts SET model = ?, software_version = ?, device_category = ? WHERE id = ?",
                (model, software_version, device_category, host_id),
            )
        else:
            await db.execute(
                "UPDATE hosts SET model = ?, software_version = ? WHERE id = ?",
                (model, software_version, host_id),
            )
        await db.commit()
    finally:
        await db.close()


async def update_host_serial(host_id: int, serial_number: str) -> None:
    """Update the serial_number field for a host."""
    db = await get_db()
    try:
        await db.execute(
            "UPDATE hosts SET serial_number = ? WHERE id = ?",
            (serial_number, host_id),
        )
        await db.commit()
    finally:
        await db.close()


async def get_all_hosts_for_export() -> list[dict]:
    """Return all hosts with group name for CSV export."""
    db = await get_db()
    try:
        cursor = await db.execute("""
            SELECT h.hostname, h.ip_address, h.device_type, h.status,
                   h.model, h.software_version, g.name AS group_name
            FROM hosts h
            LEFT JOIN inventory_groups g ON g.id = h.group_id
            ORDER BY g.name, h.hostname
        """)
        return rows_to_list(await cursor.fetchall())
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
        await db.rollback()
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
            sql, sql_params = _safe_dynamic_update("playbooks", updates, params, "id = ?", playbook_id)
            await db.execute(sql, sql_params)
            await db.commit()
    except Exception:
        await db.rollback()
        raise
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
# Secret Variables (encrypted key-value store for template substitution)
# ═════════════════════════════════════════════════════════════════════════════


async def get_all_secret_variables() -> list[dict]:
    """Return all secret variables (without decrypted values)."""
    conn = await get_db()
    try:
        cursor = await conn.execute(
            "SELECT id, name, description, created_by, created_at, updated_at FROM secret_variables ORDER BY name"
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await conn.close()


async def get_secret_variable(var_id: int) -> dict | None:
    """Return a single secret variable metadata (no decrypted value)."""
    conn = await get_db()
    try:
        cursor = await conn.execute(
            "SELECT id, name, description, created_by, created_at, updated_at FROM secret_variables WHERE id = ?",
            (var_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await conn.close()


async def get_secret_variable_by_name(name: str) -> dict | None:
    """Return a secret variable including its encrypted value, looked up by name."""
    conn = await get_db()
    try:
        cursor = await conn.execute(
            "SELECT id, name, enc_value, description, created_by FROM secret_variables WHERE name = ?",
            (name,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await conn.close()


async def create_secret_variable(
    name: str, enc_value: str, description: str = "", created_by: str = ""
) -> int:
    conn = await get_db()
    try:
        cursor = await conn.execute(
            "INSERT INTO secret_variables (name, enc_value, description, created_by) VALUES (?,?,?,?)",
            (name, enc_value, description, created_by),
        )
        await conn.commit()
        return cursor.lastrowid
    finally:
        await conn.close()


async def update_secret_variable(
    var_id: int,
    *,
    enc_value: str | None = None,
    description: str | None = None,
) -> bool:
    updates = []
    args = []
    if enc_value is not None:
        updates.append("enc_value = ?")
        args.append(enc_value)
    if description is not None:
        updates.append("description = ?")
        args.append(description)
    if not updates:
        return True
    if DB_ENGINE == "postgres":
        updates.append("updated_at = NOW()::text")
    else:
        updates.append("updated_at = datetime('now')")
    args.append(var_id)
    conn = await get_db()
    try:
        cursor = await conn.execute(
            f"UPDATE secret_variables SET {', '.join(updates)} WHERE id = ?",
            tuple(args),
        )
        await conn.commit()
        return cursor.rowcount > 0
    finally:
        await conn.close()


async def delete_secret_variable(var_id: int) -> bool:
    conn = await get_db()
    try:
        cursor = await conn.execute("DELETE FROM secret_variables WHERE id = ?", (var_id,))
        await conn.commit()
        return cursor.rowcount > 0
    finally:
        await conn.close()


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


async def get_credentials_for_group(group_id: int) -> list[dict]:
    """Return raw credentials available for a group.

    There is no group-credential mapping table yet, so this returns all
    credentials.  The caller picks the first match.
    """
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM credentials ORDER BY id"
        )
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
    db = await get_db()
    try:
        sql, sql_params = _safe_dynamic_update("credentials", updates, args, "id = ?", cred_id)
        await db.execute(sql, sql_params)
        await db.commit()
    except Exception:
        await db.rollback()
        raise
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
            LEFT JOIN inventory_groups g ON g.id = j.inventory_group_id
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
            LEFT JOIN inventory_groups g ON g.id = j.inventory_group_id
            WHERE j.id = ?
        """, (job_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_job(playbook_id: int, inventory_group_id: int | None,
                     credential_id: int | None = None,
                     template_id: int | None = None,
                     dry_run: bool = True,
                     launched_by: str = "admin",
                     priority: int = 2,
                     depends_on: list[int] | None = None,
                     host_ids: list[int] | None = None,
                     ad_hoc_ips: list[str] | None = None) -> int:
    db = await get_db()
    try:
        deps_json = json.dumps(depends_on or [])
        host_ids_json = json.dumps(host_ids) if host_ids else None
        ad_hoc_json = json.dumps(ad_hoc_ips) if ad_hoc_ips else None
        now = datetime.now(UTC).isoformat()
        cursor = await db.execute(
            """INSERT INTO jobs
               (playbook_id, inventory_group_id, credential_id, template_id,
                dry_run, status, priority, depends_on, queued_at, launched_by,
                host_ids, ad_hoc_ips)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (playbook_id, inventory_group_id, credential_id, template_id,
             1 if dry_run else 0, "queued", priority, deps_json, now, launched_by,
             host_ids_json, ad_hoc_json),
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
               LEFT JOIN inventory_groups g ON g.id = j.inventory_group_id
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


# ═════════════════════════════════════════════════════════════════════════════
# STP Topology State + Events
# ═════════════════════════════════════════════════════════════════════════════

async def upsert_stp_port_state(
    host_id: int,
    vlan_id: int,
    bridge_port: int,
    if_index: int,
    interface_name: str,
    port_state: str,
    port_role: str,
    designated_bridge_id: str,
    root_bridge_id: str,
    root_port: int,
    topology_change_count: int,
    time_since_topology_change: int,
    is_root_bridge: bool,
) -> int:
    """Insert or update one STP port-state row for a host/VLAN/bridge-port."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO stp_port_states
               (host_id, vlan_id, bridge_port, if_index, interface_name,
                port_state, port_role, designated_bridge_id, root_bridge_id,
                root_port, topology_change_count, time_since_topology_change,
                is_root_bridge, collected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(host_id, vlan_id, bridge_port)
               DO UPDATE SET
                   if_index = excluded.if_index,
                   interface_name = excluded.interface_name,
                   port_state = excluded.port_state,
                   port_role = excluded.port_role,
                   designated_bridge_id = excluded.designated_bridge_id,
                   root_bridge_id = excluded.root_bridge_id,
                   root_port = excluded.root_port,
                   topology_change_count = excluded.topology_change_count,
                   time_since_topology_change = excluded.time_since_topology_change,
                   is_root_bridge = excluded.is_root_bridge,
                   collected_at = excluded.collected_at""",
            (
                host_id, vlan_id, bridge_port, if_index, interface_name,
                port_state, port_role, designated_bridge_id, root_bridge_id,
                root_port, topology_change_count, time_since_topology_change,
                1 if is_root_bridge else 0,
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def delete_stp_port_states_for_host(host_id: int, vlan_id: int | None = None) -> int:
    """Delete STP port states for a host, optionally restricted to one VLAN."""
    db = await get_db()
    try:
        if vlan_id is None:
            cursor = await db.execute(
                "DELETE FROM stp_port_states WHERE host_id = ?",
                (host_id,),
            )
        else:
            cursor = await db.execute(
                "DELETE FROM stp_port_states WHERE host_id = ? AND vlan_id = ?",
                (host_id, vlan_id),
            )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def get_stp_port_states(
    group_id: int | None = None,
    host_id: int | None = None,
    vlan_id: int | None = None,
    limit: int = 5000,
) -> list[dict]:
    """Return latest STP port states joined with host metadata."""
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if group_id is not None:
            clauses.append("h.group_id = ?")
            params.append(group_id)
        if host_id is not None:
            clauses.append("s.host_id = ?")
            params.append(host_id)
        if vlan_id is not None:
            clauses.append("s.vlan_id = ?")
            params.append(vlan_id)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(int(limit), 20000)))

        cursor = await db.execute(
            f"""SELECT s.*, h.hostname, h.ip_address, h.group_id
                FROM stp_port_states s
                JOIN hosts h ON h.id = s.host_id
                {where_sql}
                ORDER BY s.collected_at DESC, s.host_id, s.vlan_id, s.bridge_port
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def insert_stp_topology_event(
    host_id: int,
    vlan_id: int,
    event_type: str,
    severity: str = "warning",
    interface_name: str = "",
    details: str = "",
    old_value: str = "",
    new_value: str = "",
) -> int:
    """Record an STP event (root change, topology change, port-state change)."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO stp_topology_events
               (host_id, vlan_id, event_type, severity, interface_name,
                details, old_value, new_value, acknowledged, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, datetime('now'))""",
            (
                host_id, vlan_id, event_type, severity, interface_name,
                details, old_value, new_value,
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_stp_topology_events(
    unacknowledged_only: bool = True,
    limit: int = 200,
) -> list[dict]:
    """Return STP events newest-first with host context."""
    db = await get_db()
    try:
        where_sql = "WHERE e.acknowledged = 0" if unacknowledged_only else ""
        cursor = await db.execute(
            f"""SELECT e.*, h.hostname, h.ip_address
                FROM stp_topology_events e
                JOIN hosts h ON h.id = e.host_id
                {where_sql}
                ORDER BY e.created_at DESC, e.id DESC
                LIMIT ?""",
            (max(1, min(int(limit), 5000)),),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_stp_topology_events_count(unacknowledged_only: bool = True) -> int:
    """Return count of STP events."""
    db = await get_db()
    try:
        where_sql = "WHERE acknowledged = 0" if unacknowledged_only else ""
        cursor = await db.execute(
            f"SELECT COUNT(*) FROM stp_topology_events {where_sql}"
        )
        row = await cursor.fetchone()
        return int(row[0]) if row else 0
    finally:
        await db.close()


async def acknowledge_stp_topology_events() -> int:
    """Mark all unacknowledged STP events as acknowledged."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE stp_topology_events SET acknowledged = 1 WHERE acknowledged = 0"
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def count_recent_stp_topology_events(
    host_id: int,
    vlan_id: int,
    event_type: str,
    within_minutes: int = 30,
    max_rows: int = 500,
) -> int:
    """Count STP events of a type for host/VLAN inside a recent time window."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT created_at
               FROM stp_topology_events
               WHERE host_id = ?
                 AND vlan_id = ?
                 AND event_type = ?
               ORDER BY created_at DESC
               LIMIT ?""",
            (
                host_id,
                vlan_id,
                event_type,
                max(1, min(int(max_rows), 5000)),
            ),
        )
        rows = await cursor.fetchall()
        if not rows:
            return 0

        now = datetime.now(UTC)
        cutoff_seconds = max(1, int(within_minutes)) * 60
        count = 0

        for row in rows:
            created_raw = row[0] if isinstance(row, (list, tuple)) else row["created_at"]
            if not created_raw:
                continue
            created_text = str(created_raw).replace(" ", "T")
            try:
                dt = datetime.fromisoformat(created_text)
            except Exception:
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            if (now - dt).total_seconds() <= cutoff_seconds:
                count += 1
            else:
                # Rows are ordered newest-first; once outside window, remaining rows will be older.
                break

        return count
    finally:
        await db.close()


# ── STP Root-Bridge Policies ─────────────────────────────────────────────────

async def upsert_stp_root_policy(
    group_id: int,
    vlan_id: int,
    expected_root_bridge_id: str,
    expected_root_hostname: str = "",
    enabled: bool = True,
) -> int:
    """Upsert expected STP root-bridge policy for one inventory group/VLAN."""
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO stp_root_policies
               (group_id, vlan_id, expected_root_bridge_id, expected_root_hostname,
                enabled, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
               ON CONFLICT(group_id, vlan_id)
               DO UPDATE SET
                   expected_root_bridge_id = excluded.expected_root_bridge_id,
                   expected_root_hostname = excluded.expected_root_hostname,
                   enabled = excluded.enabled,
                   updated_at = datetime('now')""",
            (
                int(group_id),
                int(vlan_id),
                str(expected_root_bridge_id or "").strip(),
                str(expected_root_hostname or "").strip(),
                1 if enabled else 0,
            ),
        )
        await db.commit()

        cursor = await db.execute(
            """SELECT id
               FROM stp_root_policies
               WHERE group_id = ? AND vlan_id = ?""",
            (int(group_id), int(vlan_id)),
        )
        row = await cursor.fetchone()
        return int(row[0]) if row else 0
    finally:
        await db.close()


async def get_stp_root_policy(group_id: int, vlan_id: int) -> dict | None:
    """Return one STP root policy for group/VLAN, or None when absent."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT p.*, g.name AS group_name
               FROM stp_root_policies p
               JOIN inventory_groups g ON g.id = p.group_id
               WHERE p.group_id = ? AND p.vlan_id = ?
               LIMIT 1""",
            (int(group_id), int(vlan_id)),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        rows = rows_to_list([row])
        return rows[0] if rows else None
    finally:
        await db.close()


async def get_stp_root_policies(
    group_id: int | None = None,
    vlan_id: int | None = None,
    enabled_only: bool = False,
    limit: int = 2000,
) -> list[dict]:
    """Return STP root-bridge policies with inventory group context."""
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []

        if group_id is not None:
            clauses.append("p.group_id = ?")
            params.append(int(group_id))
        if vlan_id is not None:
            clauses.append("p.vlan_id = ?")
            params.append(int(vlan_id))
        if enabled_only:
            clauses.append("p.enabled = 1")

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(int(limit), 10000)))

        cursor = await db.execute(
            f"""SELECT p.*, g.name AS group_name
                FROM stp_root_policies p
                JOIN inventory_groups g ON g.id = p.group_id
                {where_sql}
                ORDER BY p.group_id, p.vlan_id, p.id
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_stp_root_policy(policy_id: int) -> int:
    """Delete one STP root policy by ID."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM stp_root_policies WHERE id = ?",
            (int(policy_id),),
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
    """Upsert node positions. positions = {node_id: {x, y} | null}.
    A null value deletes that node's saved position (unpin)."""
    if not positions:
        return 0
    db = await get_db()
    try:
        count = 0
        for node_id, pos in positions.items():
            if pos is None:
                # Delete this node's position (unpin)
                await db.execute(
                    "DELETE FROM topology_node_positions WHERE node_id = ?",
                    (str(node_id),),
                )
            else:
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


async def create_config_drift_event_history(
    event_id: int,
    host_id: int,
    action: str,
    from_status: str = "",
    to_status: str = "",
    actor: str = "",
    details: str = "",
) -> int:
    """Append a history/log entry for a drift event lifecycle action."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO config_drift_event_history
               (event_id, host_id, action, from_status, to_status, actor, details, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (event_id, host_id, action, from_status, to_status, actor, details),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_config_drift_event_history(event_id: int, limit: int = 200) -> list[dict]:
    """Return history entries for a drift event (newest first)."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT h.id, h.event_id, h.host_id, h.action, h.from_status, h.to_status,
                      h.actor, h.details, h.created_at,
                      d.status AS current_status,
                      host.hostname, host.ip_address
               FROM config_drift_event_history h
               JOIN config_drift_events d ON d.id = h.event_id
               LEFT JOIN hosts host ON host.id = h.host_id
               WHERE h.event_id = ?
               ORDER BY h.created_at DESC, h.id DESC
               LIMIT ?""",
            (event_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
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
                       e.status, e.diff_text, e.diff_lines_added, e.diff_lines_removed,
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
    sql, sql_params = _safe_dynamic_update("config_backup_policies", sets, params, "id = ?", policy_id)
    db = await get_db()
    try:
        await db.execute(sql, sql_params)
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


_CONFIG_BACKUP_SEARCH_MODES = {"fulltext", "substring", "regex"}


def _normalize_config_backup_search_mode(mode: str) -> str:
    normalized = (mode or "fulltext").strip().lower() or "fulltext"
    if normalized not in _CONFIG_BACKUP_SEARCH_MODES:
        raise ValueError("invalid_mode")
    return normalized


_CONFIG_BACKUP_REGEX_MAX_LEN = 512

# Reject patterns with shapes that commonly cause catastrophic backtracking:
# nested quantifiers like (a+)+ / (a*)*, or quantified groups containing
# alternation like (a|a)+. Combined with the length cap and admin-only
# access, this defangs ReDoS for the config-backup search endpoint.
_REDOS_SHAPE_RE = re.compile(
    r"\([^)]*[+*][^)]*\)[+*]"      # (...+...)+ / (...*...)*
    r"|\([^)]*\|[^)]*\)[+*]"        # (a|b)+ / (a|b)*
)


def _compile_config_backup_regex(pattern: str) -> re.Pattern:
    """Compile a user-supplied regex with bounds, raising ValueError('invalid_regex') on failure."""
    if pattern is None or len(pattern) > _CONFIG_BACKUP_REGEX_MAX_LEN:
        raise ValueError("invalid_regex")
    if _REDOS_SHAPE_RE.search(pattern):
        raise ValueError("invalid_regex")
    try:
        # codeql[py/regex-injection]: pattern length-bounded, screened for
        # catastrophic-backtracking shapes, and only reachable by admins.
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValueError("invalid_regex") from exc


def _build_sqlite_fts_query(search_query: str) -> str:
    tokens = [tok for tok in re.findall(r"[A-Za-z0-9_.:/-]+", search_query or "") if tok]
    if not tokens:
        escaped = (search_query or "").replace('"', '""')
        return f'"{escaped}"'
    return " AND ".join(f'"{tok.replace(chr(34), chr(34) + chr(34))}"' for tok in tokens[:10])


def _extract_config_backup_match_context(
    config_text: str,
    search_query: str,
    *,
    mode: str,
    context_lines: int = 1,
    compiled_regex: re.Pattern | None = None,
) -> dict | None:
    lines = (config_text or "").splitlines()
    if not lines:
        return None

    mode = _normalize_config_backup_search_mode(mode)
    match_idx: int | None = None

    if mode == "regex":
        regex = compiled_regex
        if regex is None:
            try:
                regex = _compile_config_backup_regex(search_query)
            except ValueError:
                return None
        for idx, line in enumerate(lines):
            if regex.search(line):
                match_idx = idx
                break
    elif mode == "substring":
        needle = (search_query or "").lower()
        if not needle:
            return None
        for idx, line in enumerate(lines):
            if needle in line.lower():
                match_idx = idx
                break
    else:  # fulltext
        tokens = [tok.lower() for tok in re.findall(r"[A-Za-z0-9_.:/-]+", search_query or "") if tok]
        if not tokens:
            tokens = [(search_query or "").strip().lower()]
        tokens = [tok for tok in tokens if tok]
        if not tokens:
            return None
        for idx, line in enumerate(lines):
            lowered = line.lower()
            if any(tok in lowered for tok in tokens):
                match_idx = idx
                break

    if match_idx is None:
        return None

    radius = max(0, min(int(context_lines), 5))
    start = max(0, match_idx - radius)
    end = min(len(lines), match_idx + radius + 1)
    before_lines = lines[start:match_idx]
    match_line = lines[match_idx]
    after_lines = lines[match_idx + 1:end]
    context_text = "\n".join(before_lines + [match_line] + after_lines)
    return {
        "line_number": match_idx + 1,
        "match_line": match_line,
        "before_lines": before_lines,
        "after_lines": after_lines,
        "context_text": context_text,
    }


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


async def get_latest_config_backup(policy_id: int, host_id: int) -> dict | None:
    """Get the most recent successful backup for a policy+host, including config_text."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, config_text FROM config_backups
               WHERE policy_id = ? AND host_id = ? AND status = 'success'
               ORDER BY captured_at DESC LIMIT 1""",
            (policy_id, host_id),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
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


async def get_previous_successful_config_backup(backup_id: int) -> dict | None:
    """Return the previous successful backup for the same host as backup_id."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT prev.id, prev.policy_id, prev.host_id, prev.capture_method, prev.status,
                      prev.error_message, prev.captured_at, prev.config_text,
                      h.hostname, h.ip_address, h.device_type
               FROM config_backups cur
               JOIN config_backups prev ON prev.host_id = cur.host_id
               LEFT JOIN hosts h ON h.id = prev.host_id
               WHERE cur.id = ?
                 AND cur.status = 'success'
                 AND prev.status = 'success'
                 AND (
                    prev.captured_at < cur.captured_at OR
                    (prev.captured_at = cur.captured_at AND prev.id < cur.id)
                 )
               ORDER BY prev.captured_at DESC, prev.id DESC
               LIMIT 1""",
            (backup_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def search_config_backups(
    search_query: str,
    *,
    mode: str = "fulltext",
    limit: int = 50,
    context_lines: int = 1,
) -> dict:
    """Search backed-up configurations and return contextual matches."""
    query = (search_query or "").strip()
    requested_mode = _normalize_config_backup_search_mode(mode)
    row_limit = max(1, min(int(limit), 200))

    if not query:
        return {
            "query": "",
            "requested_mode": requested_mode,
            "mode": requested_mode,
            "limit": row_limit,
            "count": 0,
            "has_more": False,
            "results": [],
        }

    effective_mode = requested_mode
    context_radius = max(0, min(int(context_lines), 5))

    compiled_regex = None
    if requested_mode == "regex":
        compiled_regex = _compile_config_backup_regex(query)

    base_select = """
        SELECT b.id, b.policy_id, b.host_id, b.capture_method, b.status,
               b.error_message, b.captured_at, b.config_text,
               h.hostname, h.ip_address, h.device_type
        FROM config_backups b
        LEFT JOIN hosts h ON h.id = b.host_id
    """
    cursor = None
    db = await get_db()
    try:
        if requested_mode == "fulltext":
            if DB_ENGINE == "postgres":
                cursor = await db.execute(
                    f"""{base_select}
                        WHERE b.status = 'success'
                          AND to_tsvector('simple', COALESCE(b.config_text, ''))
                              @@ plainto_tsquery('simple', ?)
                        ORDER BY b.captured_at DESC, b.id DESC""",
                    (query,),
                )
            else:
                fts_query = _build_sqlite_fts_query(query)
                try:
                    cursor = await db.execute(
                        f"""{base_select}
                            JOIN config_backups_fts fts ON fts.rowid = b.id
                            WHERE b.status = 'success'
                              AND fts.config_backups_fts MATCH ?
                            ORDER BY b.captured_at DESC, b.id DESC""",
                        (fts_query,),
                    )
                except Exception:
                    effective_mode = "substring"

        if cursor is None and effective_mode == "substring":
            if DB_ENGINE == "postgres":
                cursor = await db.execute(
                    f"""{base_select}
                        WHERE b.status = 'success'
                          AND POSITION(LOWER(?) IN LOWER(COALESCE(b.config_text, ''))) > 0
                        ORDER BY b.captured_at DESC, b.id DESC""",
                    (query,),
                )
            else:
                cursor = await db.execute(
                    f"""{base_select}
                        WHERE b.status = 'success'
                          AND instr(LOWER(COALESCE(b.config_text, '')), LOWER(?)) > 0
                        ORDER BY b.captured_at DESC, b.id DESC""",
                    (query,),
                )

        if cursor is None and effective_mode == "regex":
            if DB_ENGINE == "postgres":
                cursor = await db.execute(
                    f"""{base_select}
                        WHERE b.status = 'success'
                          AND COALESCE(b.config_text, '') ~* ?
                        ORDER BY b.captured_at DESC, b.id DESC""",
                    (query,),
                )
            else:
                cursor = await db.execute(
                    f"""{base_select}
                        WHERE b.status = 'success'
                        ORDER BY b.captured_at DESC, b.id DESC"""
                )

        if cursor is None:
            raise ValueError("invalid_mode")

        results: list[dict] = []
        has_more = False

        while True:
            row = await cursor.fetchone()
            if row is None:
                break
            rec = dict(row)
            context = _extract_config_backup_match_context(
                rec.get("config_text") or "",
                query,
                mode=effective_mode,
                context_lines=context_radius,
                compiled_regex=compiled_regex,
            )
            if context is None:
                continue

            results.append(
                {
                    "backup_id": rec["id"],
                    "policy_id": rec.get("policy_id"),
                    "host_id": rec.get("host_id"),
                    "hostname": rec.get("hostname"),
                    "ip_address": rec.get("ip_address"),
                    "device_type": rec.get("device_type"),
                    "captured_at": rec.get("captured_at"),
                    "capture_method": rec.get("capture_method"),
                    "match_line_number": context["line_number"],
                    "match_line": context["match_line"],
                    "context_before": "\n".join(context["before_lines"]),
                    "context_before_lines": context["before_lines"],
                    "context_after": "\n".join(context["after_lines"]),
                    "context_after_lines": context["after_lines"],
                    "match_context": context["context_text"],
                    "config_length": len(rec.get("config_text") or ""),
                    "diff_view_path": f"/api/config-backups/{rec['id']}/diff",
                }
            )

            if len(results) >= row_limit:
                while True:
                    peek = await cursor.fetchone()
                    if peek is None:
                        break
                    peek_rec = dict(peek)
                    peek_context = _extract_config_backup_match_context(
                        peek_rec.get("config_text") or "",
                        query,
                        mode=effective_mode,
                        context_lines=context_radius,
                        compiled_regex=compiled_regex,
                    )
                    if peek_context is not None:
                        has_more = True
                        break
                break

        return {
            "query": query,
            "requested_mode": requested_mode,
            "mode": effective_mode,
            "limit": row_limit,
            "count": len(results),
            "has_more": has_more,
            "results": results,
        }
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
    sql, sql_params = _safe_dynamic_update("compliance_profiles", sets, params, "id = ?", profile_id)
    db = await get_db()
    try:
        await db.execute(sql, sql_params)
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
    sql, sql_params = _safe_dynamic_update("compliance_profile_assignments", sets, params, "id = ?", assignment_id)
    db = await get_db()
    try:
        await db.execute(sql, sql_params)
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
    except Exception:
        await db.rollback()
        raise
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
                """SELECT p.*, h.hostname, h.ip_address, h.device_type, h.group_id,
                          h.model, h.software_version, h.status AS host_status,
                          h.last_seen, g.name AS group_name
                   FROM monitoring_polls p
                   JOIN hosts h ON h.id = p.host_id
                   LEFT JOIN inventory_groups g ON g.id = h.group_id
                   WHERE h.group_id = ?
                     AND p.id = (SELECT MAX(p2.id) FROM monitoring_polls p2 WHERE p2.host_id = p.host_id)
                   ORDER BY h.hostname
                   LIMIT ?""",
                (group_id, limit),
            )
        else:
            cursor = await db.execute(
                """SELECT p.*, h.hostname, h.ip_address, h.device_type, h.group_id,
                          h.model, h.software_version, h.status AS host_status,
                          h.last_seen, g.name AS group_name
                   FROM monitoring_polls p
                   JOIN hosts h ON h.id = p.host_id
                   LEFT JOIN inventory_groups g ON g.id = h.group_id
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


async def get_monitoring_alert(alert_id: int) -> dict | None:
    """Return a single monitoring alert by ID."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT a.*, h.hostname, h.ip_address
               FROM monitoring_alerts a
               LEFT JOIN hosts h ON h.id = a.host_id
               WHERE a.id = ?""",
            (alert_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
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
    sets = []
    params: list = []
    for k, v in updates.items():
        sets.append(f"{k} = ?")
        params.append(v)
    sets.append("updated_at = datetime('now')")
    sql, sql_params = _safe_dynamic_update("alert_rules", sets, params, "id = ?", rule_id)
    db = await get_db()
    try:
        await db.execute(sql, sql_params)
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
    sets = [f"{k} = ?" for k in fields]
    sql, sql_params = _safe_dynamic_update("sla_targets", sets, list(fields.values()), "id = ?", target_id)
    db = await get_db()
    try:
        await db.execute(sql, sql_params)
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
                """SELECT AVG(p.response_time_ms) AS mean_rt,
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


# ═════════════════════════════════════════════════════════════════════════════
# Metric Samples  (Prometheus-style flexible metric storage)
# ═════════════════════════════════════════════════════════════════════════════


async def create_metric_sample(
    host_id: int, metric_name: str, value: float,
    labels_json: str = "{}",
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO metric_samples (host_id, metric_name, labels_json, value)
               VALUES (?, ?, ?, ?)""",
            (host_id, metric_name, labels_json, value),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def create_metric_samples_batch(rows: list[tuple]) -> int:
    """Insert many metric samples at once.  Each tuple:
    (host_id, metric_name, labels_json, value)
    """
    if not rows:
        return 0
    db = await get_db()
    try:
        await db.executemany(
            """INSERT INTO metric_samples (host_id, metric_name, labels_json, value)
               VALUES (?, ?, ?, ?)""",
            rows,
        )
        await db.commit()
        return len(rows)
    finally:
        await db.close()


async def query_metric_samples(
    metric_name: str,
    host_ids: list[int] | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 5000,
) -> list[dict]:
    db = await get_db()
    try:
        clauses = ["metric_name = ?"]
        params: list = [metric_name]
        if host_ids:
            placeholders = ",".join("?" for _ in host_ids)
            clauses.append(f"host_id IN ({placeholders})")
            params.extend(host_ids)
        if start:
            clauses.append("sampled_at >= ?")
            params.append(start)
        if end:
            clauses.append("sampled_at <= ?")
            params.append(end)
        where = " AND ".join(clauses)
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT ms.*, h.hostname, h.ip_address
                FROM metric_samples ms
                JOIN hosts h ON h.id = ms.host_id
                WHERE {where}
                ORDER BY ms.sampled_at DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_old_metric_samples(hours: int = 48) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM metric_samples WHERE sampled_at < datetime('now', '-' || ? || ' hours')",
            (hours,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Metric Rollups  (downsampled aggregates: hourly / daily)
# ═════════════════════════════════════════════════════════════════════════════


async def create_metric_rollup(
    host_id: int, metric_name: str, time_window: str,
    period_start: str, period_end: str,
    val_min: float, val_avg: float, val_max: float, val_p95: float,
    sample_count: int, labels_json: str = "{}",
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO metric_rollups
               (host_id, metric_name, labels_json, time_window,
                period_start, period_end,
                val_min, val_avg, val_max, val_p95, sample_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, metric_name, labels_json, time_window,
             period_start, period_end,
             val_min, val_avg, val_max, val_p95, sample_count),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def query_metric_rollups(
    metric_name: str,
    time_window: str = "hourly",
    host_ids: list[int] | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 5000,
) -> list[dict]:
    db = await get_db()
    try:
        clauses = ["metric_name = ?", "time_window = ?"]
        params: list = [metric_name, time_window]
        if host_ids:
            placeholders = ",".join("?" for _ in host_ids)
            clauses.append(f"host_id IN ({placeholders})")
            params.extend(host_ids)
        if start:
            clauses.append("period_start >= ?")
            params.append(start)
        if end:
            clauses.append("period_end <= ?")
            params.append(end)
        where = " AND ".join(clauses)
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT mr.*, h.hostname, h.ip_address
                FROM metric_rollups mr
                JOIN hosts h ON h.id = mr.host_id
                WHERE {where}
                ORDER BY mr.period_start DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_raw_samples_for_rollup(
    metric_name: str, period_start: str, period_end: str,
) -> list[dict]:
    """Fetch raw samples in a time range, grouped by host+labels,
    for the downsampling engine to aggregate."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT host_id, labels_json, value
               FROM metric_samples
               WHERE metric_name = ? AND sampled_at >= ? AND sampled_at < ?
               ORDER BY host_id, labels_json""",
            (metric_name, period_start, period_end),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_old_metric_rollups(time_window: str, retention_days: int) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM metric_rollups WHERE time_window = ? AND period_start < datetime('now', '-' || ? || ' days')",
            (time_window, retention_days),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Interface Time-Series
# ═════════════════════════════════════════════════════════════════════════════


async def create_interface_ts_sample(
    host_id: int, if_index: int, if_name: str, if_speed_mbps: int,
    in_octets: int, out_octets: int,
    in_rate_bps: float | None = None, out_rate_bps: float | None = None,
    utilization_pct: float | None = None,
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO interface_ts
               (host_id, if_index, if_name, if_speed_mbps,
                in_octets, out_octets, in_rate_bps, out_rate_bps, utilization_pct)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, if_index, if_name, if_speed_mbps,
             in_octets, out_octets, in_rate_bps, out_rate_bps, utilization_pct),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def create_interface_ts_batch(rows: list[tuple]) -> int:
    """Batch insert interface time-series samples.  Each tuple:
    (host_id, if_index, if_name, if_speed_mbps,
     in_octets, out_octets, in_rate_bps, out_rate_bps, utilization_pct)
    """
    if not rows:
        return 0
    db = await get_db()
    try:
        await db.executemany(
            """INSERT INTO interface_ts
               (host_id, if_index, if_name, if_speed_mbps,
                in_octets, out_octets, in_rate_bps, out_rate_bps, utilization_pct)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        await db.commit()
        return len(rows)
    finally:
        await db.close()


async def query_interface_ts(
    host_id: int,
    if_index: int | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 2000,
) -> list[dict]:
    db = await get_db()
    try:
        clauses = ["host_id = ?"]
        params: list = [host_id]
        if if_index is not None:
            clauses.append("if_index = ?")
            params.append(if_index)
        if start:
            clauses.append("sampled_at >= ?")
            params.append(start)
        if end:
            clauses.append("sampled_at <= ?")
            params.append(end)
        where = " AND ".join(clauses)
        params.append(limit)
        cursor = await db.execute(
            f"SELECT * FROM interface_ts WHERE {where} ORDER BY sampled_at DESC LIMIT ?",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_old_interface_ts(retention_days: int = 30) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM interface_ts WHERE sampled_at < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Interface Error/Discard Tracking
# ═════════════════════════════════════════════════════════════════════════════


async def get_interface_error_stats_for_host(host_id: int) -> list[dict]:
    """Fetch current error counter state for all interfaces on a host."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM interface_error_stats WHERE host_id = ?",
            (host_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def upsert_interface_error_stat(
    host_id: int,
    if_index: int,
    if_name: str,
    in_errors: int,
    out_errors: int,
    in_discards: int,
    out_discards: int,
) -> int:
    """Update or insert interface error counters, shifting current to prev."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id, in_errors, out_errors, in_discards, out_discards, polled_at "
            "FROM interface_error_stats WHERE host_id = ? AND if_index = ?",
            (host_id, if_index),
        )
        existing = await cursor.fetchone()
        if existing:
            await db.execute(
                """UPDATE interface_error_stats
                   SET if_name = ?,
                       prev_in_errors = in_errors, prev_out_errors = out_errors,
                       prev_in_discards = in_discards, prev_out_discards = out_discards,
                       prev_polled_at = polled_at,
                       in_errors = ?, out_errors = ?,
                       in_discards = ?, out_discards = ?,
                       polled_at = datetime('now')
                   WHERE host_id = ? AND if_index = ?""",
                (if_name, in_errors, out_errors, in_discards, out_discards,
                 host_id, if_index),
            )
        else:
            await db.execute(
                """INSERT INTO interface_error_stats
                   (host_id, if_index, if_name, in_errors, out_errors,
                    in_discards, out_discards)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (host_id, if_index, if_name, in_errors, out_errors,
                 in_discards, out_discards),
            )
        await db.commit()
        return 1
    finally:
        await db.close()


async def create_interface_error_event(
    host_id: int,
    if_index: int,
    if_name: str,
    event_type: str,
    metric_name: str,
    severity: str,
    current_rate: float,
    baseline_rate: float,
    spike_factor: float,
    root_cause_hint: str,
    root_cause_category: str,
    correlation_details: str = "{}",
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO interface_error_events
               (host_id, if_index, if_name, event_type, metric_name, severity,
                current_rate, baseline_rate, spike_factor,
                root_cause_hint, root_cause_category, correlation_details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, if_index, if_name, event_type, metric_name, severity,
             current_rate, baseline_rate, spike_factor,
             root_cause_hint, root_cause_category, correlation_details),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_interface_error_events(
    host_id: int | None = None,
    severity: str | None = None,
    unresolved_only: bool = False,
    limit: int = 200,
) -> list[dict]:
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if host_id is not None:
            clauses.append("e.host_id = ?")
            params.append(host_id)
        if severity:
            clauses.append("e.severity = ?")
            params.append(severity)
        if unresolved_only:
            clauses.append("e.resolved_at IS NULL")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT e.*, h.hostname, h.ip_address
                FROM interface_error_events e
                LEFT JOIN hosts h ON h.id = e.host_id
                {where}
                ORDER BY e.created_at DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_interface_error_event(event_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT e.*, h.hostname, h.ip_address
               FROM interface_error_events e
               LEFT JOIN hosts h ON h.id = e.host_id
               WHERE e.id = ?""",
            (event_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def acknowledge_interface_error_event(event_id: int, user: str) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE interface_error_events SET acknowledged = 1, acknowledged_by = ? WHERE id = ?",
            (user, event_id),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def resolve_interface_error_event(event_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE interface_error_events SET resolved_at = datetime('now') WHERE id = ?",
            (event_id,),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_interface_error_summary(
    host_id: int,
    days: int = 1,
) -> list[dict]:
    """Per-interface error/discard rate summary with totals."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT ms.host_id, ms.labels_json, ms.metric_name,
                      COUNT(*) AS sample_count,
                      AVG(ms.value) AS avg_value,
                      MAX(ms.value) AS max_value,
                      MIN(ms.value) AS min_value
               FROM metric_samples ms
               WHERE ms.host_id = ?
                 AND ms.metric_name IN ('if_in_errors', 'if_out_errors',
                                        'if_in_discards', 'if_out_discards')
                 AND ms.sampled_at >= datetime('now', '-' || ? || ' days')
               GROUP BY ms.metric_name, ms.labels_json
               ORDER BY ms.metric_name, ms.labels_json""",
            (host_id, days),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_interface_error_trending(
    host_id: int,
    if_index: int | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 5000,
) -> list[dict]:
    """Query error/discard metric_samples for a host, optionally filtered by interface."""
    db = await get_db()
    try:
        clauses = [
            "host_id = ?",
            "metric_name IN ('if_in_errors', 'if_out_errors', 'if_in_discards', 'if_out_discards')",
        ]
        params: list = [host_id]
        if if_index is not None:
            clauses.append("labels_json LIKE ?")
            params.append(f'%"if_index": {if_index}%')
        if start:
            clauses.append("sampled_at >= ?")
            params.append(start)
        if end:
            clauses.append("sampled_at <= ?")
            params.append(end)
        where = " AND ".join(clauses)
        params.append(limit)
        cursor = await db.execute(
            f"SELECT * FROM metric_samples WHERE {where} ORDER BY sampled_at ASC LIMIT ?",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_old_interface_error_events(retention_days: int = 90) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM interface_error_events WHERE created_at < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def get_trap_syslog_events_in_range(
    host_id: int,
    start: str,
    end: str,
    limit: int = 100,
) -> list[dict]:
    """Return trap/syslog events for a host within a time range (for error correlation)."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM trap_syslog_events
               WHERE host_id = ? AND received_at >= ? AND received_at <= ?
               ORDER BY received_at DESC LIMIT ?""",
            (host_id, start, end, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_topology_changes_in_range(
    host_id: int,
    start: str,
    end: str,
    limit: int = 50,
) -> list[dict]:
    """Return topology changes for a host within a time range."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM topology_changes
               WHERE source_host_id = ? AND detected_at >= ? AND detected_at <= ?
               ORDER BY detected_at DESC LIMIT ?""",
            (host_id, start, end, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Vendor OID Registry
# ═════════════════════════════════════════════════════════════════════════════


async def get_vendor_oid_entries() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM vendor_oid_registry ORDER BY vendor, device_type")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_vendor_oid_for_host(device_type: str) -> dict | None:
    """Lookup OIDs by matching device_type substring (case-insensitive)."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM vendor_oid_registry
               WHERE ? LIKE '%' || device_type || '%' COLLATE NOCASE
               ORDER BY LENGTH(device_type) DESC LIMIT 1""",
            (device_type,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def upsert_vendor_oid(
    vendor: str, device_type: str, cpu_oid: str = "",
    cpu_walk: int = 1, mem_used_oid: str = "", mem_free_oid: str = "",
    mem_total_oid: str = "", uptime_oid: str = "1.3.6.1.2.1.1.3",
    notes: str = "",
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO vendor_oid_registry
               (vendor, device_type, cpu_oid, cpu_walk, mem_used_oid, mem_free_oid, mem_total_oid, uptime_oid, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(vendor, device_type) DO UPDATE SET
                   cpu_oid=excluded.cpu_oid, cpu_walk=excluded.cpu_walk,
                   mem_used_oid=excluded.mem_used_oid, mem_free_oid=excluded.mem_free_oid,
                   mem_total_oid=excluded.mem_total_oid, uptime_oid=excluded.uptime_oid,
                   notes=excluded.notes""",
            (vendor, device_type, cpu_oid, cpu_walk, mem_used_oid, mem_free_oid, mem_total_oid, uptime_oid, notes),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def delete_vendor_oid(entry_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM vendor_oid_registry WHERE id = ?", (entry_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Trap / Syslog Events
# ═════════════════════════════════════════════════════════════════════════════


async def create_trap_syslog_event(
    source_ip: str, event_type: str = "trap", facility: str = "",
    severity: str = "info", oid: str = "", message: str = "",
    raw_data: str = "", host_id: int | None = None,
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO trap_syslog_events
               (source_ip, host_id, event_type, facility, severity, oid, message, raw_data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (source_ip, host_id, event_type, facility, severity, oid, message, raw_data),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_trap_syslog_events(
    event_type: str | None = None,
    host_id: int | None = None,
    severity: str | None = None,
    limit: int = 200,
) -> list[dict]:
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if event_type:
            clauses.append("e.event_type = ?")
            params.append(event_type)
        if host_id is not None:
            clauses.append("e.host_id = ?")
            params.append(host_id)
        if severity:
            clauses.append("e.severity = ?")
            params.append(severity)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT e.*, h.hostname, h.ip_address
                FROM trap_syslog_events e
                LEFT JOIN hosts h ON h.id = e.host_id
                {where}
                ORDER BY e.received_at DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_old_trap_syslog_events(retention_days: int = 30) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM trap_syslog_events WHERE received_at < datetime('now', '-' || ? || ' days')",
            (retention_days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ── Dashboards ─────────────────────────────────────────────────────────────────

async def list_dashboards(owner: str | None = None) -> list[dict]:
    db = await get_db()
    try:
        if owner:
            cursor = await db.execute(
                "SELECT * FROM dashboards WHERE owner = ? ORDER BY updated_at DESC", (owner,)
            )
        else:
            cursor = await db.execute("SELECT * FROM dashboards ORDER BY updated_at DESC")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_dashboard(dashboard_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM dashboards WHERE id = ?", (dashboard_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        dashboard = dict(row)
        cursor2 = await db.execute(
            "SELECT * FROM dashboard_panels WHERE dashboard_id = ? ORDER BY grid_y, grid_x",
            (dashboard_id,),
        )
        dashboard["panels"] = rows_to_list(await cursor2.fetchall())
        return dashboard
    finally:
        await db.close()


async def create_dashboard(
    name: str, description: str = "", owner: str = "",
    layout_json: str = "{}", variables_json: str = "[]",
) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO dashboards (name, description, owner, layout_json, variables_json)
               VALUES (?, ?, ?, ?, ?)""",
            (name, description, owner, layout_json, variables_json),
        )
        await db.commit()
        new_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM dashboards WHERE id = ?", (new_id,))
        return dict(await cursor2.fetchone())
    finally:
        await db.close()


async def update_dashboard(dashboard_id: int, **kwargs) -> dict | None:
    allowed = {"name", "description", "layout_json", "variables_json", "is_default"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return await get_dashboard(dashboard_id)
    sets = ", ".join(f"{k} = ?" for k in updates)
    vals = list(updates.values())
    vals.append(dashboard_id)
    db = await get_db()
    try:
        await db.execute(
            f"UPDATE dashboards SET {sets}, updated_at = datetime('now') WHERE id = ?",
            tuple(vals),
        )
        await db.commit()
        return await get_dashboard(dashboard_id)
    finally:
        await db.close()


async def delete_dashboard(dashboard_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM dashboards WHERE id = ?", (dashboard_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def create_dashboard_panel(
    dashboard_id: int, title: str = "", chart_type: str = "line",
    metric_query_json: str = "{}", grid_x: int = 0, grid_y: int = 0,
    grid_w: int = 6, grid_h: int = 4, options_json: str = "{}",
) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO dashboard_panels
               (dashboard_id, title, chart_type, metric_query_json, grid_x, grid_y, grid_w, grid_h, options_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (dashboard_id, title, chart_type, metric_query_json, grid_x, grid_y, grid_w, grid_h, options_json),
        )
        # Update dashboard timestamp in same transaction
        await db.execute("UPDATE dashboards SET updated_at = datetime('now') WHERE id = ?", (dashboard_id,))
        await db.commit()
        new_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM dashboard_panels WHERE id = ?", (new_id,))
        return dict(await cursor2.fetchone())
    finally:
        await db.close()


async def update_dashboard_panel(panel_id: int, **kwargs) -> dict | None:
    allowed = {"title", "chart_type", "metric_query_json", "grid_x", "grid_y", "grid_w", "grid_h", "options_json"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return None
    set_exprs = [f"{k} = ?" for k in updates]
    sql, sql_params = _safe_dynamic_update("dashboard_panels", set_exprs, list(updates.values()), "id = ?", panel_id)
    db = await get_db()
    try:
        await db.execute(sql, sql_params)
        cursor = await db.execute("SELECT * FROM dashboard_panels WHERE id = ?", (panel_id,))
        row = await cursor.fetchone()
        if row:
            # Update parent dashboard timestamp in same transaction
            await db.execute(
                "UPDATE dashboards SET updated_at = datetime('now') WHERE id = ?",
                (dict(row)["dashboard_id"],),
            )
        await db.commit()
        return dict(row) if row else None
    finally:
        await db.close()


async def delete_dashboard_panel(panel_id: int) -> bool:
    db = await get_db()
    try:
        # Get dashboard_id first to update timestamp
        cursor = await db.execute("SELECT dashboard_id FROM dashboard_panels WHERE id = ?", (panel_id,))
        row = await cursor.fetchone()
        cursor2 = await db.execute("DELETE FROM dashboard_panels WHERE id = ?", (panel_id,))
        if row:
            await db.execute(
                "UPDATE dashboards SET updated_at = datetime('now') WHERE id = ?",
                (dict(row)["dashboard_id"],),
            )
        await db.commit()
        return cursor2.rowcount > 0
    finally:
        await db.close()


# ── Annotations ────────────────────────────────────────────────────────────────

async def get_annotations_in_range(
    host_id: int | None = None,
    start: str | None = None,
    end: str | None = None,
    categories: list[str] | None = None,
) -> list[dict]:
    db = await get_db()
    try:
        results = []
        cats = categories or ["deployment", "config", "alert"]

        # When host_id is provided, find deployment IDs that involve this host
        # so we can filter deployment annotations to only relevant ones.
        host_deployment_ids: set[int] | None = None
        if host_id is not None and "deployment" in cats:
            dep_cursor = await db.execute(
                "SELECT id, host_ids FROM deployments",
            )
            host_deployment_ids = set()
            for dep_row in await dep_cursor.fetchall():
                dep = dict(dep_row)
                try:
                    ids = json.loads(dep.get("host_ids") or "[]")
                    if host_id in ids:
                        host_deployment_ids.add(dep["id"])
                except (json.JSONDecodeError, TypeError) as exc:
                    _LOGGER.debug("skipping deployment %s: bad host_ids JSON: %s", dep.get("id"), exc)

        # Audit events
        if any(c in cats for c in ["deployment", "config", "alert"]):
            where = ["1=1"]
            params: list = []
            if start:
                where.append("timestamp >= ?")
                params.append(start)
            if end:
                where.append("timestamp <= ?")
                params.append(end)
            cat_filter = []
            if "deployment" in cats:
                cat_filter.append("category LIKE '%deploy%'")
            if "config" in cats:
                cat_filter.append("category LIKE '%config%'")
            if "alert" in cats:
                cat_filter.append("category LIKE '%alert%'")
            if cat_filter:
                where.append(f"({' OR '.join(cat_filter)})")

            cursor = await db.execute(
                f"SELECT * FROM audit_events WHERE {' AND '.join(where)} ORDER BY timestamp DESC LIMIT 500",
                tuple(params),
            )
            for row in await cursor.fetchall():
                r = dict(row)
                cat = "deployment" if "deploy" in (r.get("category") or "") else \
                      "config" if "config" in (r.get("category") or "") else \
                      "alert" if "alert" in (r.get("category") or "") else "other"

                # Filter by host_id when provided
                if host_id is not None:
                    detail = r.get("detail", "")
                    if cat == "deployment" and host_deployment_ids is not None:
                        # Check if this event references a deployment that involves the host
                        dep_id_match = re.search(r"id=(\d+)", detail)
                        if dep_id_match:
                            dep_id = int(dep_id_match.group(1))
                            if dep_id not in host_deployment_ids:
                                continue
                        else:
                            continue
                    elif cat in ("config", "alert"):
                        # Check if detail references this host_id
                        if f"host_id={host_id}" not in detail and f"host={host_id}" not in detail:
                            continue

                results.append({
                    "timestamp": r.get("timestamp"),
                    "title": r.get("action", ""),
                    "description": r.get("detail", ""),
                    "category": cat,
                    "user": r.get("user", ""),
                })

        return results
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Correlation Queries
# ═════════════════════════════════════════════════════════════════════════════


async def get_config_drift_events_in_range(
    host_ids: list[int],
    start: str,
    end: str,
) -> list[dict]:
    """Return config drift events for the given hosts within a time range."""
    if not host_ids:
        return []
    db = await get_db()
    try:
        placeholders = ",".join("?" for _ in host_ids)
        cursor = await db.execute(
            f"""SELECT d.*, h.hostname, h.ip_address
                FROM config_drift_events d
                LEFT JOIN hosts h ON h.id = d.host_id
                WHERE d.host_id IN ({placeholders})
                  AND d.detected_at >= ? AND d.detected_at <= ?
                ORDER BY d.detected_at DESC LIMIT 200""",
            (*host_ids, start, end),
        )
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_monitoring_alerts_in_range(
    host_ids: list[int],
    start: str,
    end: str,
) -> list[dict]:
    """Return monitoring alerts for the given hosts within a time range."""
    if not host_ids:
        return []
    db = await get_db()
    try:
        placeholders = ",".join("?" for _ in host_ids)
        cursor = await db.execute(
            f"""SELECT a.*, h.hostname, h.ip_address
                FROM monitoring_alerts a
                LEFT JOIN hosts h ON h.id = a.host_id
                WHERE a.host_id IN ({placeholders})
                  AND a.created_at >= ? AND a.created_at <= ?
                ORDER BY a.created_at DESC LIMIT 200""",
            (*host_ids, start, end),
        )
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_deployments_for_host_in_range(
    host_id: int,
    start: str,
    end: str,
) -> list[dict]:
    """Return deployments that include the given host within a time range."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM deployments
               WHERE started_at >= ? AND started_at <= ?
               ORDER BY started_at DESC LIMIT 50""",
            (start, end),
        )
        results = []
        for row in await cursor.fetchall():
            dep = dict(row)
            try:
                ids = json.loads(dep.get("host_ids") or "[]")
                if host_id in ids:
                    results.append(dep)
            except (json.JSONDecodeError, TypeError) as exc:
                _LOGGER.debug("skipping deployment %s: bad host_ids JSON: %s", dep.get("id"), exc)
        return results
    finally:
        await db.close()


async def get_audit_events_for_deployment(
    deployment_id: int,
    start: str,
    end: str,
) -> list[dict]:
    """Return audit events related to a deployment within a time range."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM audit_events
               WHERE timestamp >= ? AND timestamp <= ?
                 AND detail LIKE ?
               ORDER BY timestamp DESC LIMIT 200""",
            (start, end, f"%id={deployment_id}%"),
        )
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Availability Tracking
# ═════════════════════════════════════════════════════════════════════════════


async def record_availability_transition(
    host_id: int,
    entity_type: str,
    entity_id: str,
    old_state: str,
    new_state: str,
    poll_id: int | None = None,
) -> int:
    """Record a state transition (up/down) for a host or interface."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO availability_transitions
               (host_id, entity_type, entity_id, old_state, new_state, poll_id)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (host_id, entity_type, entity_id, old_state, new_state, poll_id),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_last_availability_state(
    host_id: int, entity_type: str = "host", entity_id: str = "",
) -> dict | None:
    """Get the most recent availability transition for an entity."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM availability_transitions
               WHERE host_id = ? AND entity_type = ? AND entity_id = ?
               ORDER BY transition_at DESC LIMIT 1""",
            (host_id, entity_type, entity_id),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def get_availability_transitions(
    host_id: int | None = None,
    entity_type: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 500,
) -> list[dict]:
    db = await get_db()
    try:
        clauses = ["1=1"]
        params: list = []
        if host_id is not None:
            clauses.append("a.host_id = ?")
            params.append(host_id)
        if entity_type:
            clauses.append("a.entity_type = ?")
            params.append(entity_type)
        if start:
            clauses.append("a.transition_at >= ?")
            params.append(start)
        if end:
            clauses.append("a.transition_at <= ?")
            params.append(end)
        where = " AND ".join(clauses)
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT a.*, h.hostname, h.ip_address
                FROM availability_transitions a
                JOIN hosts h ON h.id = a.host_id
                WHERE {where}
                ORDER BY a.transition_at DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_availability_summary(
    group_id: int | None = None,
    days: int = 30,
) -> dict:
    """Compute availability summary with outage counts and uptime % from transitions."""
    db = await get_db()
    try:
        group_filter = ""
        params: list = [days]
        if group_id is not None:
            group_filter = "AND h.group_id = ?"
            params.append(group_id)

        # Get all hosts and their transitions in the window
        cursor = await db.execute(
            f"""SELECT h.id AS host_id, h.hostname, h.ip_address, h.status,
                       h.group_id,
                       (SELECT COUNT(*) FROM availability_transitions t
                        WHERE t.host_id = h.id AND t.entity_type = 'host'
                          AND t.new_state = 'down'
                          AND t.transition_at >= datetime('now', '-' || ? || ' days')
                       ) AS outage_count
                FROM hosts h
                WHERE 1=1 {group_filter}
                ORDER BY h.hostname""",
            tuple(params),
        )
        hosts_raw = rows_to_list(await cursor.fetchall())

        hosts = []
        for h in hosts_raw:
            # Compute uptime from transitions
            tcursor = await db.execute(
                """SELECT transition_at, new_state FROM availability_transitions
                   WHERE host_id = ? AND entity_type = 'host'
                     AND transition_at >= datetime('now', '-' || ? || ' days')
                   ORDER BY transition_at ASC""",
                (h["host_id"], days),
            )
            transitions = rows_to_list(await tcursor.fetchall())

            # Also get the state before the window started
            pcursor = await db.execute(
                """SELECT new_state FROM availability_transitions
                   WHERE host_id = ? AND entity_type = 'host'
                     AND transition_at < datetime('now', '-' || ? || ' days')
                   ORDER BY transition_at DESC LIMIT 1""",
                (h["host_id"], days),
            )
            prev = await pcursor.fetchone()
            initial_state = dict(prev)["new_state"] if prev else "up"

            # Calculate downtime seconds in window
            total_seconds = days * 86400
            down_seconds = 0
            current_state = initial_state
            window_start = None  # We'll approximate with relative positions

            if transitions:
                # Walk through transitions accumulating down time
                last_ts = None
                for t in transitions:
                    ts = t["transition_at"]
                    if current_state == "down" and last_ts is not None:
                        # Approximate duration between transitions
                        try:
                            from datetime import datetime as dt
                            fmt = "%Y-%m-%d %H:%M:%S"
                            t1 = dt.strptime(last_ts[:19], fmt)
                            t2 = dt.strptime(ts[:19], fmt)
                            down_seconds += (t2 - t1).total_seconds()
                        except Exception as exc:
                            _LOGGER.warning("uptime: failed to parse transition timestamps '%s' / '%s': %s", last_ts, ts, exc)
                    current_state = t["new_state"]
                    last_ts = ts

                # If still down at end of window, add remaining time
                if current_state == "down" and last_ts:
                    try:
                        from datetime import datetime as dt
                        fmt = "%Y-%m-%d %H:%M:%S"
                        t1 = dt.strptime(last_ts[:19], fmt)
                        now = dt.utcnow()
                        down_seconds += (now - t1).total_seconds()
                    except Exception as exc:
                        _LOGGER.warning("uptime: failed to parse transition timestamp '%s': %s", last_ts, exc)
            elif initial_state == "down":
                down_seconds = total_seconds

            uptime_pct = round(max(0, (1 - down_seconds / max(total_seconds, 1))) * 100, 3)

            # Get last outage duration
            last_outage = None
            ocursor = await db.execute(
                """SELECT t1.transition_at AS down_at,
                          (SELECT MIN(t2.transition_at) FROM availability_transitions t2
                           WHERE t2.host_id = t1.host_id AND t2.entity_type = 'host'
                             AND t2.new_state = 'up' AND t2.transition_at > t1.transition_at
                          ) AS up_at
                   FROM availability_transitions t1
                   WHERE t1.host_id = ? AND t1.entity_type = 'host' AND t1.new_state = 'down'
                   ORDER BY t1.transition_at DESC LIMIT 1""",
                (h["host_id"],),
            )
            orow = await ocursor.fetchone()
            if orow:
                odict = dict(orow)
                last_outage = {
                    "down_at": odict.get("down_at"),
                    "up_at": odict.get("up_at"),
                }

            hosts.append({
                "host_id": h["host_id"],
                "hostname": h["hostname"],
                "ip_address": h["ip_address"],
                "group_id": h["group_id"],
                "current_state": h["status"],
                "uptime_pct": uptime_pct,
                "outage_count": h["outage_count"] or 0,
                "down_seconds": round(down_seconds),
                "last_outage": last_outage,
            })

        total_hosts = len(hosts) or 1
        avg_uptime = round(sum(h["uptime_pct"] for h in hosts) / total_hosts, 3)
        total_outages = sum(h["outage_count"] for h in hosts)
        currently_down = sum(1 for h in hosts if h["current_state"] in ("down", "error", "unreachable"))

        return {
            "period_days": days,
            "host_count": len(hosts),
            "avg_uptime_pct": avg_uptime,
            "total_outages": total_outages,
            "currently_down": currently_down,
            "hosts": hosts,
        }
    finally:
        await db.close()


async def get_outage_history(
    host_id: int | None = None,
    group_id: int | None = None,
    days: int = 30,
    limit: int = 200,
) -> list[dict]:
    """Get outage records (down transitions paired with recovery)."""
    db = await get_db()
    try:
        group_filter = ""
        params: list = [days]
        if host_id is not None:
            group_filter += " AND t1.host_id = ?"
            params.append(host_id)
        if group_id is not None:
            group_filter += " AND h.group_id = ?"
            params.append(group_id)
        params.append(limit)

        cursor = await db.execute(
            f"""SELECT t1.id, t1.host_id, h.hostname, h.ip_address,
                       t1.entity_type, t1.entity_id,
                       t1.transition_at AS down_at,
                       (SELECT MIN(t2.transition_at) FROM availability_transitions t2
                        WHERE t2.host_id = t1.host_id AND t2.entity_type = t1.entity_type
                          AND t2.entity_id = t1.entity_id
                          AND t2.new_state = 'up' AND t2.transition_at > t1.transition_at
                       ) AS up_at
                FROM availability_transitions t1
                JOIN hosts h ON h.id = t1.host_id
                WHERE t1.new_state = 'down'
                  AND t1.transition_at >= datetime('now', '-' || ? || ' days')
                  {group_filter}
                ORDER BY t1.transition_at DESC LIMIT ?""",
            tuple(params),
        )
        rows = rows_to_list(await cursor.fetchall())
        for r in rows:
            if r.get("down_at") and r.get("up_at"):
                try:
                    from datetime import datetime as dt
                    fmt = "%Y-%m-%d %H:%M:%S"
                    d = dt.strptime(r["down_at"][:19], fmt)
                    u = dt.strptime(r["up_at"][:19], fmt)
                    r["duration_seconds"] = int((u - d).total_seconds())
                except Exception:
                    r["duration_seconds"] = None
            else:
                r["duration_seconds"] = None
                if r.get("down_at") and not r.get("up_at"):
                    r["ongoing"] = True
        return rows
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Per-Port Utilization (95th Percentile)
# ═════════════════════════════════════════════════════════════════════════════


async def get_interface_utilization_summary(
    host_id: int,
    days: int = 1,
) -> list[dict]:
    """Per-interface utilization summary with avg, peak, and 95th percentile."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT if_index, if_name, if_speed_mbps,
                      COUNT(*) AS sample_count,
                      AVG(in_rate_bps) AS avg_in_bps,
                      AVG(out_rate_bps) AS avg_out_bps,
                      MAX(in_rate_bps) AS peak_in_bps,
                      MAX(out_rate_bps) AS peak_out_bps,
                      AVG(utilization_pct) AS avg_util,
                      MAX(utilization_pct) AS peak_util
               FROM interface_ts
               WHERE host_id = ?
                 AND sampled_at >= datetime('now', '-' || ? || ' days')
                 AND in_rate_bps IS NOT NULL
               GROUP BY if_index
               ORDER BY if_name""",
            (host_id, days),
        )
        interfaces = rows_to_list(await cursor.fetchall())

        # Compute 95th percentile per interface
        for iface in interfaces:
            pcursor = await db.execute(
                """SELECT utilization_pct FROM interface_ts
                   WHERE host_id = ? AND if_index = ?
                     AND sampled_at >= datetime('now', '-' || ? || ' days')
                     AND utilization_pct IS NOT NULL
                   ORDER BY utilization_pct ASC""",
                (host_id, iface["if_index"], days),
            )
            values = [r[0] for r in await pcursor.fetchall() if r[0] is not None]
            if values:
                idx = int(len(values) * 0.95)
                idx = min(idx, len(values) - 1)
                iface["p95_util"] = round(values[idx], 2)

                # Also 95th for in/out bps
                for direction in ("in", "out"):
                    bcursor = await db.execute(
                        f"""SELECT {direction}_rate_bps FROM interface_ts
                            WHERE host_id = ? AND if_index = ?
                              AND sampled_at >= datetime('now', '-' || ? || ' days')
                              AND {direction}_rate_bps IS NOT NULL
                            ORDER BY {direction}_rate_bps ASC""",
                        (host_id, iface["if_index"], days),
                    )
                    bvals = [r[0] for r in await bcursor.fetchall() if r[0] is not None]
                    if bvals:
                        bidx = int(len(bvals) * 0.95)
                        bidx = min(bidx, len(bvals) - 1)
                        iface[f"p95_{direction}_bps"] = round(bvals[bidx], 2)
                    else:
                        iface[f"p95_{direction}_bps"] = None
            else:
                iface["p95_util"] = None
                iface["p95_in_bps"] = None
                iface["p95_out_bps"] = None

            # Round numeric fields
            for k in ("avg_in_bps", "avg_out_bps", "peak_in_bps", "peak_out_bps", "avg_util", "peak_util"):
                if iface.get(k) is not None:
                    iface[k] = round(iface[k], 2)

        return interfaces
    finally:
        await db.close()


async def get_port_detail_ts(
    host_id: int,
    if_index: int,
    start: str | None = None,
    end: str | None = None,
    limit: int = 5000,
) -> dict:
    """Detailed time-series for a single port with summary stats."""
    db = await get_db()
    try:
        clauses = ["host_id = ?", "if_index = ?"]
        params: list = [host_id, if_index]
        if start:
            clauses.append("sampled_at >= ?")
            params.append(start)
        if end:
            clauses.append("sampled_at <= ?")
            params.append(end)
        where = " AND ".join(clauses)
        params.append(limit)
        cursor = await db.execute(
            f"SELECT * FROM interface_ts WHERE {where} ORDER BY sampled_at ASC LIMIT ?",
            tuple(params),
        )
        samples = rows_to_list(await cursor.fetchall())

        # Compute summary
        in_rates = [s["in_rate_bps"] for s in samples if s.get("in_rate_bps") is not None]
        out_rates = [s["out_rate_bps"] for s in samples if s.get("out_rate_bps") is not None]
        utils = [s["utilization_pct"] for s in samples if s.get("utilization_pct") is not None]

        def percentile(vals, pct):
            if not vals:
                return None
            sorted_v = sorted(vals)
            idx = min(int(len(sorted_v) * pct / 100), len(sorted_v) - 1)
            return round(sorted_v[idx], 2)

        summary = {
            "sample_count": len(samples),
            "avg_in_bps": round(sum(in_rates) / len(in_rates), 2) if in_rates else None,
            "avg_out_bps": round(sum(out_rates) / len(out_rates), 2) if out_rates else None,
            "peak_in_bps": round(max(in_rates), 2) if in_rates else None,
            "peak_out_bps": round(max(out_rates), 2) if out_rates else None,
            "p95_in_bps": percentile(in_rates, 95),
            "p95_out_bps": percentile(out_rates, 95),
            "avg_util": round(sum(utils) / len(utils), 2) if utils else None,
            "peak_util": round(max(utils), 2) if utils else None,
            "p95_util": percentile(utils, 95),
        }
        if samples:
            summary["if_name"] = samples[0].get("if_name", "")
            summary["if_speed_mbps"] = samples[0].get("if_speed_mbps", 0)

        return {"summary": summary, "samples": samples}
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Custom OID Profiles
# ═════════════════════════════════════════════════════════════════════════════


async def get_custom_oid_profiles(
    vendor: str | None = None,
) -> list[dict]:
    db = await get_db()
    try:
        if vendor:
            cursor = await db.execute(
                "SELECT * FROM custom_oid_profiles WHERE vendor = ? ORDER BY name",
                (vendor,),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM custom_oid_profiles ORDER BY vendor, name"
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_custom_oid_profile(profile_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM custom_oid_profiles WHERE id = ?", (profile_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def create_custom_oid_profile(
    name: str, vendor: str = "", device_type: str = "",
    description: str = "", oids_json: str = "[]",
    is_default: int = 0, created_by: str = "",
) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO custom_oid_profiles
               (name, vendor, device_type, description, oids_json, is_default, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (name, vendor, device_type, description, oids_json, is_default, created_by),
        )
        await db.commit()
        return await get_custom_oid_profile(cursor.lastrowid) or {}
    finally:
        await db.close()


async def update_custom_oid_profile(profile_id: int, **kwargs) -> dict | None:
    db = await get_db()
    try:
        existing = await get_custom_oid_profile(profile_id)
        if not existing:
            return None
        fields = []
        params: list = []
        for key in ("name", "vendor", "device_type", "description", "oids_json", "is_default"):
            if key in kwargs and kwargs[key] is not None:
                fields.append(f"{key} = ?")
                params.append(kwargs[key])
        if not fields:
            return existing
        fields.append("updated_at = datetime('now')")
        sql, sql_params = _safe_dynamic_update("custom_oid_profiles", fields, params, "id = ?", profile_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_custom_oid_profile(profile_id)
    finally:
        await db.close()


async def delete_custom_oid_profile(profile_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM custom_oid_profiles WHERE id = ?", (profile_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Reporting & Export
# ═════════════════════════════════════════════════════════════════════════════


async def create_report_definition(
    name: str, report_type: str = "availability",
    parameters_json: str = "{}", schedule: str = "",
    created_by: str = "",
) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO report_definitions
               (name, report_type, parameters_json, schedule, created_by)
               VALUES (?, ?, ?, ?, ?)""",
            (name, report_type, parameters_json, schedule, created_by),
        )
        await db.commit()
        rid = cursor.lastrowid
        return (await get_report_definition(rid)) or {}
    finally:
        await db.close()


async def get_report_definition(report_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM report_definitions WHERE id = ?", (report_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def list_report_definitions() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM report_definitions ORDER BY updated_at DESC"
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_report_definition(report_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM report_definitions WHERE id = ?", (report_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def update_report_definition_last_run(report_id: int) -> None:
    """Mark a report definition as having just run."""
    db = await get_db()
    try:
        await db.execute(
            """UPDATE report_definitions
               SET last_run_at = datetime('now'),
                   updated_at = datetime('now')
               WHERE id = ?""",
            (report_id,),
        )
        await db.commit()
    finally:
        await db.close()


async def create_report_run(
    report_id: int | None, report_type: str,
    parameters_json: str = "{}",
) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO report_runs
               (report_id, report_type, parameters_json, status)
               VALUES (?, ?, ?, 'running')""",
            (report_id, report_type, parameters_json),
        )
        await db.commit()
        rid = cursor.lastrowid
        rcursor = await db.execute("SELECT * FROM report_runs WHERE id = ?", (rid,))
        row = await rcursor.fetchone()
        return dict(row) if row else {}
    finally:
        await db.close()


async def complete_report_run(
    run_id: int, result_json: str, row_count: int, status: str = "completed",
) -> None:
    db = await get_db()
    try:
        await db.execute(
            """UPDATE report_runs
               SET result_json = ?, row_count = ?, status = ?,
                   completed_at = datetime('now')
               WHERE id = ?""",
            (result_json, row_count, status, run_id),
        )
        await db.commit()
    finally:
        await db.close()


async def create_report_artifact(
    run_id: int,
    report_id: int | None,
    artifact_type: str,
    file_name: str,
    media_type: str,
    content_text: str | None = None,
    content_blob: bytes | None = None,
) -> dict:
    """Persist a generated report artifact (CSV/SVG/etc.)."""
    db = await get_db()
    try:
        blob_payload = None
        text_payload = ""
        if content_blob is not None:
            blob_payload = bytes(content_blob)
            size_bytes = len(blob_payload)
        else:
            text_payload = content_text if isinstance(content_text, str) else str(content_text or "")
            size_bytes = len(text_payload.encode("utf-8"))
        cursor = await db.execute(
            """INSERT INTO report_artifacts
               (run_id, report_id, artifact_type, file_name, media_type, content_text, content_blob, size_bytes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (run_id, report_id, artifact_type, file_name, media_type, text_payload, blob_payload, size_bytes),
        )
        await db.commit()
        artifact_id = cursor.lastrowid
        rcursor = await db.execute(
            """SELECT id, run_id, report_id, artifact_type, file_name, media_type, size_bytes, created_at
               FROM report_artifacts WHERE id = ?""",
            (artifact_id,),
        )
        row = await rcursor.fetchone()
        return dict(row) if row else {}
    finally:
        await db.close()


async def get_report_artifacts(
    run_id: int,
    limit: int = 20,
) -> list[dict]:
    """List report artifacts for a run (without content payload)."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, run_id, report_id, artifact_type, file_name, media_type, size_bytes, created_at
               FROM report_artifacts
               WHERE run_id = ?
               ORDER BY created_at DESC
               LIMIT ?""",
            (run_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_report_artifact(artifact_id: int) -> dict | None:
    """Get one report artifact including content payload."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM report_artifacts WHERE id = ?",
            (artifact_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def delete_old_report_runs(days: int = 90) -> int:
    """Delete report runs older than N days (artifacts cascade)."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM report_runs WHERE started_at < datetime('now', '-' || ? || ' days')",
            (max(1, int(days)),),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def get_report_runs(report_id: int | None = None, limit: int = 50) -> list[dict]:
    db = await get_db()
    try:
        if report_id is not None:
            cursor = await db.execute(
                "SELECT * FROM report_runs WHERE report_id = ? ORDER BY started_at DESC LIMIT ?",
                (report_id, limit),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM report_runs ORDER BY started_at DESC LIMIT ?",
                (limit,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_report_run(run_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM report_runs WHERE id = ?", (run_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def generate_availability_report_data(
    group_id: int | None = None,
    days: int = 30,
) -> list[dict]:
    """Generate availability report rows for CSV export."""
    db = await get_db()
    try:
        group_filter = ""
        params: list = [days]
        if group_id is not None:
            group_filter = "AND h.group_id = ?"
            params.append(group_id)

        cursor = await db.execute(
            f"""SELECT h.id AS host_id, h.hostname, h.ip_address, h.device_type,
                       ig.name AS group_name,
                       COUNT(p.id) AS total_polls,
                       SUM(CASE WHEN p.poll_status = 'ok' THEN 1 ELSE 0 END) AS ok_polls,
                       AVG(p.response_time_ms) AS avg_latency_ms,
                       MAX(p.response_time_ms) AS max_latency_ms,
                       AVG(p.packet_loss_pct) AS avg_packet_loss_pct,
                       AVG(p.cpu_percent) AS avg_cpu,
                       AVG(p.memory_percent) AS avg_memory,
                       (SELECT COUNT(*) FROM availability_transitions t
                        WHERE t.host_id = h.id AND t.entity_type = 'host'
                          AND t.new_state = 'down'
                          AND t.transition_at >= datetime('now', '-' || ? || ' days')
                       ) AS outage_count
                FROM hosts h
                LEFT JOIN monitoring_polls p ON p.host_id = h.id
                  AND p.polled_at >= datetime('now', '-' || ? || ' days')
                LEFT JOIN inventory_groups ig ON ig.id = h.group_id
                WHERE 1=1 {group_filter}
                GROUP BY h.id
                ORDER BY h.hostname""",
            tuple(params + [days]),
        )
        rows = rows_to_list(await cursor.fetchall())
        for r in rows:
            total = r["total_polls"] or 1
            ok = r["ok_polls"] or 0
            r["uptime_pct"] = round(ok / total * 100, 3)
            for k in ("avg_latency_ms", "max_latency_ms", "avg_packet_loss_pct", "avg_cpu", "avg_memory"):
                if r.get(k) is not None:
                    r[k] = round(r[k], 2)
        return rows
    finally:
        await db.close()


async def generate_compliance_report_data(
    group_id: int | None = None,
) -> list[dict]:
    """Generate compliance report rows for CSV export."""
    db = await get_db()
    try:
        group_filter = ""
        params: list = []
        if group_id is not None:
            group_filter = "WHERE h.group_id = ?"
            params.append(group_id)

        cursor = await db.execute(
            f"""SELECT h.id AS host_id, h.hostname, h.ip_address, h.device_type,
                       ig.name AS group_name,
                       csr.profile_id, cp.name AS profile_name,
                       csr.status, csr.total_rules, csr.passed_rules, csr.failed_rules,
                       csr.scanned_at
                FROM compliance_scan_results csr
                JOIN hosts h ON h.id = csr.host_id
                LEFT JOIN inventory_groups ig ON ig.id = h.group_id
                LEFT JOIN compliance_profiles cp ON cp.id = csr.profile_id
                {group_filter}
                ORDER BY csr.scanned_at DESC""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def generate_interface_report_data(
    host_id: int | None = None,
    group_id: int | None = None,
    days: int = 1,
) -> list[dict]:
    """Generate interface utilization report rows for CSV export."""
    db = await get_db()
    try:
        clauses = ["1=1"]
        params: list = [days]
        if host_id is not None:
            clauses.append("h.id = ?")
            params.append(host_id)
        if group_id is not None:
            clauses.append("h.group_id = ?")
            params.append(group_id)
        where = " AND ".join(clauses)

        cursor = await db.execute(
            f"""SELECT h.hostname, h.ip_address,
                       its.if_index, its.if_name, its.if_speed_mbps,
                       COUNT(*) AS samples,
                       AVG(its.in_rate_bps) AS avg_in_bps,
                       AVG(its.out_rate_bps) AS avg_out_bps,
                       MAX(its.in_rate_bps) AS peak_in_bps,
                       MAX(its.out_rate_bps) AS peak_out_bps,
                       AVG(its.utilization_pct) AS avg_util,
                       MAX(its.utilization_pct) AS peak_util
                FROM interface_ts its
                JOIN hosts h ON h.id = its.host_id
                WHERE its.sampled_at >= datetime('now', '-' || ? || ' days')
                  AND {where}
                GROUP BY its.host_id, its.if_index
                ORDER BY h.hostname, its.if_name""",
            tuple(params),
        )
        rows = rows_to_list(await cursor.fetchall())
        for r in rows:
            for k in ("avg_in_bps", "avg_out_bps", "peak_in_bps", "peak_out_bps", "avg_util", "peak_util"):
                if r.get(k) is not None:
                    r[k] = round(r[k], 2)
        return rows
    finally:
        await db.close()


def _infer_ip_network(ip_text: str) -> str:
    """Infer a network CIDR from a host address.

    If CIDR is present, use it directly. For plain host addresses, infer
    /24 for IPv4 and /64 for IPv6 so documentation can still produce an IP plan
    when explicit prefixes are not stored.
    """
    value = str(ip_text or "").strip()
    if not value:
        return ""
    try:
        if "/" in value:
            return str(ipaddress.ip_interface(value).network)
        ip_obj = ipaddress.ip_address(value)
        default_prefix = 24 if ip_obj.version == 4 else 64
        return str(ipaddress.ip_network(f"{value}/{default_prefix}", strict=False))
    except Exception:
        return ""


def _normalize_iface_for_doc(name: str) -> str:
    """Normalize interface names for loose circuit/link matching."""
    value = str(name or "").strip().lower()
    if not value:
        return ""
    value = re.sub(r"\s+", "", value)
    value = (
        value.replace("tengigabitethernet", "te")
        .replace("gigabitethernet", "gi")
        .replace("fastethernet", "fa")
        .replace("port-channel", "po")
        .replace("ethernet", "eth")
    )
    return value


async def generate_network_documentation_report_data(
    group_id: int | None = None,
) -> list[dict]:
    """Generate flattened rows for automated network documentation.

    Sections included:
      - summary
      - inventory
      - topology_link
      - ip_plan
      - vlan_map
      - circuit_map
    """
    db = await get_db()
    try:
        host_where = ""
        host_params: list = []
        if group_id is not None:
            host_where = "WHERE h.group_id = ?"
            host_params.append(group_id)

        host_cursor = await db.execute(
            f"""SELECT h.id AS host_id, h.group_id, h.hostname, h.ip_address,
                       h.device_type, h.status, h.model, h.software_version,
                       ig.name AS group_name
                FROM hosts h
                LEFT JOIN inventory_groups ig ON ig.id = h.group_id
                {host_where}
                ORDER BY ig.name, h.hostname, h.ip_address""",
            tuple(host_params),
        )
        hosts = rows_to_list(await host_cursor.fetchall())

        link_where = ""
        link_params: list = []
        if group_id is not None:
            link_where = "WHERE sh.group_id = ?"
            link_params.append(group_id)

        link_cursor = await db.execute(
            f"""SELECT tl.source_host_id,
                       sh.hostname AS source_hostname,
                       tl.source_interface,
                       tl.target_host_id,
                       COALESCE(th.hostname, tl.target_device_name, '') AS target_device_name,
                       COALESCE(th.ip_address, tl.target_ip, '') AS target_ip,
                       tl.target_interface,
                       tl.protocol
                FROM topology_links tl
                JOIN hosts sh ON sh.id = tl.source_host_id
                LEFT JOIN hosts th ON th.id = tl.target_host_id
                {link_where}
                ORDER BY sh.hostname, tl.source_interface, target_device_name""",
            tuple(link_params),
        )
        links = rows_to_list(await link_cursor.fetchall())

        circuit_where = ""
        circuit_params: list = []
        if group_id is not None:
            circuit_where = "WHERE h.group_id = ?"
            circuit_params.append(group_id)

        circuit_cursor = await db.execute(
            f"""SELECT bc.id AS circuit_id,
                       bc.name AS circuit_name,
                       bc.description AS circuit_description,
                       bc.customer AS circuit_customer,
                       bc.host_id AS circuit_host_id,
                       bc.if_index AS circuit_if_index,
                       bc.if_name AS circuit_if_name,
                       bc.commit_rate_bps,
                       bc.burst_limit_bps,
                       bc.enabled AS circuit_enabled,
                       h.hostname AS circuit_hostname,
                       h.ip_address AS circuit_host_ip,
                       h.group_id AS circuit_group_id,
                       ig.name AS circuit_group_name
                FROM billing_circuits bc
                LEFT JOIN hosts h ON h.id = bc.host_id
                LEFT JOIN inventory_groups ig ON ig.id = h.group_id
                {circuit_where}
                ORDER BY bc.customer, bc.name, h.hostname, bc.if_name""",
            tuple(circuit_params),
        )
        circuits = rows_to_list(await circuit_cursor.fetchall())

        vlan_where = ""
        vlan_params: list = []
        if group_id is not None:
            vlan_where = "WHERE h.group_id = ?"
            vlan_params.append(group_id)

        vlan_cursor = await db.execute(
            f"""SELECT m.vlan AS vlan_id,
                       COUNT(*) AS mac_entry_count,
                       COUNT(DISTINCT m.host_id) AS vlan_device_count
                FROM mac_address_table m
                JOIN hosts h ON h.id = m.host_id
                {vlan_where}
                GROUP BY m.vlan
                ORDER BY m.vlan""",
            tuple(vlan_params),
        )
        vlan_rows = rows_to_list(await vlan_cursor.fetchall())

        if not vlan_rows:
            stp_cursor = await db.execute(
                f"""SELECT s.vlan_id,
                           COUNT(DISTINCT s.host_id) AS vlan_device_count,
                           COUNT(*) AS port_state_count
                    FROM stp_port_states s
                    JOIN hosts h ON h.id = s.host_id
                    {vlan_where}
                    GROUP BY s.vlan_id
                    ORDER BY s.vlan_id""",
                tuple(vlan_params),
            )
            stp_rows = rows_to_list(await stp_cursor.fetchall())
            vlan_rows = [
                {
                    "vlan_id": row.get("vlan_id"),
                    "mac_entry_count": 0,
                    "vlan_device_count": row.get("vlan_device_count", 0),
                    "details": f"Derived from STP port states ({int(row.get('port_state_count', 0))} entries)",
                }
                for row in stp_rows
            ]

        group_name_by_host = {
            int(h.get("host_id")): str(h.get("group_name") or "")
            for h in hosts
            if h.get("host_id") is not None
        }

        circuits_by_host_iface: dict[tuple[int, str], dict] = {}
        for circuit in circuits:
            host_id = int(circuit.get("circuit_host_id") or 0)
            iface_key = _normalize_iface_for_doc(str(circuit.get("circuit_if_name") or ""))
            if host_id <= 0 or not iface_key:
                continue
            circuits_by_host_iface[(host_id, iface_key)] = circuit

        subnet_map: dict[str, dict[str, set[str]]] = {}
        for host in hosts:
            subnet = _infer_ip_network(str(host.get("ip_address") or ""))
            if not subnet:
                continue
            entry = subnet_map.setdefault(subnet, {"hosts": set(), "groups": set()})
            hostname = str(host.get("hostname") or f"host-{host.get('host_id')}")
            if hostname:
                entry["hosts"].add(hostname)
            group_name = str(host.get("group_name") or "").strip()
            if group_name:
                entry["groups"].add(group_name)

        def _row(section: str) -> dict:
            return {
                "section": section,
                "group_name": "",
                "host_id": "",
                "hostname": "",
                "ip_address": "",
                "device_type": "",
                "status": "",
                "model": "",
                "software_version": "",
                "source_host_id": "",
                "source_hostname": "",
                "source_interface": "",
                "target_host_id": "",
                "target_device_name": "",
                "target_ip": "",
                "target_interface": "",
                "protocol": "",
                "subnet": "",
                "subnet_host_count": "",
                "vlan_id": "",
                "vlan_device_count": "",
                "mac_entry_count": "",
                "circuit_id": "",
                "circuit_name": "",
                "circuit_customer": "",
                "circuit_if_index": "",
                "circuit_if_name": "",
                "circuit_commit_mbps": "",
                "circuit_burst_mbps": "",
                "circuit_enabled": "",
                "details": "",
            }

        rows: list[dict] = []

        for host in hosts:
            row = _row("inventory")
            row.update(
                {
                    "group_name": host.get("group_name") or "",
                    "host_id": host.get("host_id") or "",
                    "hostname": host.get("hostname") or "",
                    "ip_address": host.get("ip_address") or "",
                    "device_type": host.get("device_type") or "",
                    "status": host.get("status") or "",
                    "model": host.get("model") or "",
                    "software_version": host.get("software_version") or "",
                }
            )
            rows.append(row)

        for link in links:
            row = _row("topology_link")
            src_host_id = int(link.get("source_host_id") or 0)
            src_iface = str(link.get("source_interface") or "")
            circuit = circuits_by_host_iface.get(
                (src_host_id, _normalize_iface_for_doc(src_iface))
            )
            details = ""
            if circuit:
                commit_mbps = round(float(circuit.get("commit_rate_bps") or 0) / 1_000_000, 3)
                details = (
                    f"Circuit {circuit.get('circuit_name', '')} "
                    f"(customer={circuit.get('circuit_customer', '')}, commit={commit_mbps} Mbps)"
                )
            row.update(
                {
                    "group_name": group_name_by_host.get(src_host_id, ""),
                    "source_host_id": link.get("source_host_id") or "",
                    "source_hostname": link.get("source_hostname") or "",
                    "source_interface": src_iface,
                    "target_host_id": link.get("target_host_id") or "",
                    "target_device_name": link.get("target_device_name") or "",
                    "target_ip": link.get("target_ip") or "",
                    "target_interface": link.get("target_interface") or "",
                    "protocol": link.get("protocol") or "",
                    "circuit_id": circuit.get("circuit_id") if circuit else "",
                    "circuit_name": circuit.get("circuit_name") if circuit else "",
                    "circuit_customer": circuit.get("circuit_customer") if circuit else "",
                    "circuit_if_index": circuit.get("circuit_if_index") if circuit else "",
                    "circuit_if_name": circuit.get("circuit_if_name") if circuit else "",
                    "circuit_commit_mbps": round(float(circuit.get("commit_rate_bps") or 0) / 1_000_000, 3) if circuit else "",
                    "circuit_burst_mbps": round(float(circuit.get("burst_limit_bps") or 0) / 1_000_000, 3) if circuit else "",
                    "circuit_enabled": int(circuit.get("circuit_enabled") or 0) if circuit else "",
                    "details": details,
                }
            )
            rows.append(row)

        def _subnet_sort_key(subnet: str) -> tuple:
            try:
                net = ipaddress.ip_network(subnet, strict=False)
                return (net.version, int(net.network_address), net.prefixlen)
            except Exception:
                return (99, subnet, 0)

        for subnet in sorted(subnet_map.keys(), key=_subnet_sort_key):
            entry = subnet_map[subnet]
            host_names = sorted(entry["hosts"])
            group_names = sorted(entry["groups"])
            preview = ", ".join(host_names[:6])
            if len(host_names) > 6:
                preview = f"{preview} +{len(host_names) - 6} more"

            row = _row("ip_plan")
            row.update(
                {
                    "group_name": ", ".join(group_names),
                    "subnet": subnet,
                    "subnet_host_count": len(host_names),
                    "details": preview,
                }
            )
            rows.append(row)

        for vlan in vlan_rows:
            row = _row("vlan_map")
            row.update(
                {
                    "vlan_id": vlan.get("vlan_id") or "",
                    "vlan_device_count": vlan.get("vlan_device_count") or 0,
                    "mac_entry_count": vlan.get("mac_entry_count") or 0,
                    "details": vlan.get("details") or "",
                }
            )
            rows.append(row)

        for circuit in circuits:
            row = _row("circuit_map")
            commit_mbps = round(float(circuit.get("commit_rate_bps") or 0) / 1_000_000, 3)
            burst_mbps = round(float(circuit.get("burst_limit_bps") or 0) / 1_000_000, 3)
            row.update(
                {
                    "group_name": circuit.get("circuit_group_name") or "",
                    "host_id": circuit.get("circuit_host_id") or "",
                    "hostname": circuit.get("circuit_hostname") or "",
                    "ip_address": circuit.get("circuit_host_ip") or "",
                    "circuit_id": circuit.get("circuit_id") or "",
                    "circuit_name": circuit.get("circuit_name") or "",
                    "circuit_customer": circuit.get("circuit_customer") or "",
                    "circuit_if_index": circuit.get("circuit_if_index") or "",
                    "circuit_if_name": circuit.get("circuit_if_name") or "",
                    "circuit_commit_mbps": commit_mbps,
                    "circuit_burst_mbps": burst_mbps,
                    "circuit_enabled": int(circuit.get("circuit_enabled") or 0),
                    "details": circuit.get("circuit_description") or "",
                }
            )
            rows.append(row)

        summary = _row("summary")
        summary["details"] = (
            f"devices={len(hosts)} links={len(links)} subnets={len(subnet_map)} "
            f"vlans={len(vlan_rows)} circuits={len(circuits)}"
        )
        rows.insert(0, summary)

        return rows
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Graph Templates (Cacti-parity)
# ═════════════════════════════════════════════════════════════════════════════

async def list_graph_templates(
    category: str | None = None, scope: str | None = None, built_in: bool | None = None,
) -> list[dict]:
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if category:
            clauses.append("category = ?")
            params.append(category)
        if scope:
            clauses.append("scope = ?")
            params.append(scope)
        if built_in is not None:
            clauses.append("built_in = ?")
            params.append(1 if built_in else 0)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"SELECT * FROM graph_templates{where} ORDER BY category, name", tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_graph_template(template_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM graph_templates WHERE id = ?", (template_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        tpl = dict(row)
        cursor2 = await db.execute(
            "SELECT * FROM graph_template_items WHERE template_id = ? ORDER BY sort_order",
            (template_id,),
        )
        tpl["items"] = rows_to_list(await cursor2.fetchall())
        return tpl
    finally:
        await db.close()


async def create_graph_template(
    name: str, description: str = "", graph_type: str = "line",
    category: str = "system", scope: str = "device",
    title_format: str = "", y_axis_label: str = "",
    y_min: float | None = None, y_max: float | None = None,
    stacked: bool = False, area_fill: bool = True,
    grid_w: int = 6, grid_h: int = 4, options_json: str = "{}",
    built_in: bool = False, created_by: str = "",
) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO graph_templates
               (name, description, graph_type, category, scope, title_format,
                y_axis_label, y_min, y_max, stacked, area_fill, grid_w, grid_h,
                options_json, built_in, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, description, graph_type, category, scope, title_format,
             y_axis_label, y_min, y_max, int(stacked), int(area_fill),
             grid_w, grid_h, options_json, int(built_in), created_by),
        )
        await db.commit()
        new_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM graph_templates WHERE id = ?", (new_id,))
        return dict(await cursor2.fetchone())
    finally:
        await db.close()


async def update_graph_template(template_id: int, **kwargs) -> dict | None:
    allowed = {
        "name", "description", "graph_type", "category", "scope", "title_format",
        "y_axis_label", "y_min", "y_max", "stacked", "area_fill", "grid_w", "grid_h",
        "options_json",
    }
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return await get_graph_template(template_id)
    for bkey in ("stacked", "area_fill"):
        if bkey in updates:
            updates[bkey] = int(updates[bkey])
    set_exprs = [f"{k} = ?" for k in updates]
    set_exprs.append("updated_at = datetime('now')")
    sql, sql_params = _safe_dynamic_update("graph_templates", set_exprs, list(updates.values()), "id = ?", template_id)
    db = await get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_graph_template(template_id)
    finally:
        await db.close()


async def delete_graph_template(template_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM graph_templates WHERE id = ?", (template_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ── Graph Template Items ───────────────────────────────────────────────────

async def create_graph_template_item(
    template_id: int, sort_order: int = 0, metric_name: str = "",
    label: str = "", color: str = "", line_type: str = "area",
    cdef_expression: str = "", consolidation: str = "avg",
    transform: str = "", legend_format: str = "",
) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO graph_template_items
               (template_id, sort_order, metric_name, label, color, line_type,
                cdef_expression, consolidation, transform, legend_format)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (template_id, sort_order, metric_name, label, color, line_type,
             cdef_expression, consolidation, transform, legend_format),
        )
        await db.commit()
        new_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM graph_template_items WHERE id = ?", (new_id,))
        return dict(await cursor2.fetchone())
    finally:
        await db.close()


async def update_graph_template_item(item_id: int, **kwargs) -> dict | None:
    allowed = {
        "sort_order", "metric_name", "label", "color", "line_type",
        "cdef_expression", "consolidation", "transform", "legend_format",
    }
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return None
    set_exprs = [f"{k} = ?" for k in updates]
    sql, sql_params = _safe_dynamic_update("graph_template_items", set_exprs, list(updates.values()), "id = ?", item_id)
    db = await get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
        cursor = await db.execute("SELECT * FROM graph_template_items WHERE id = ?", (item_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def delete_graph_template_item(item_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM graph_template_items WHERE id = ?", (item_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Host Templates (Cacti-parity)
# ═════════════════════════════════════════════════════════════════════════════

async def list_host_templates() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM host_templates ORDER BY name")
        templates = rows_to_list(await cursor.fetchall())
        for tpl in templates:
            cursor2 = await db.execute(
                """SELECT gt.* FROM graph_templates gt
                   JOIN host_template_graph_links htgl ON htgl.graph_template_id = gt.id
                   WHERE htgl.host_template_id = ?
                   ORDER BY gt.category, gt.name""",
                (tpl["id"],),
            )
            tpl["graph_templates"] = rows_to_list(await cursor2.fetchall())
        return templates
    finally:
        await db.close()


async def get_host_template(template_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM host_templates WHERE id = ?", (template_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        tpl = dict(row)
        cursor2 = await db.execute(
            """SELECT gt.* FROM graph_templates gt
               JOIN host_template_graph_links htgl ON htgl.graph_template_id = gt.id
               WHERE htgl.host_template_id = ?
               ORDER BY gt.category, gt.name""",
            (template_id,),
        )
        tpl["graph_templates"] = rows_to_list(await cursor2.fetchall())
        return tpl
    finally:
        await db.close()


async def create_host_template(
    name: str, description: str = "", device_types: str = "[]",
    auto_apply: bool = True, poll_interval: int | None = None,
    created_by: str = "",
) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO host_templates (name, description, device_types, auto_apply, poll_interval, created_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, description, device_types, int(auto_apply), poll_interval, created_by),
        )
        await db.commit()
        new_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM host_templates WHERE id = ?", (new_id,))
        return dict(await cursor2.fetchone())
    finally:
        await db.close()


async def update_host_template(template_id: int, **kwargs) -> dict | None:
    allowed = {"name", "description", "device_types", "auto_apply", "poll_interval"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return await get_host_template(template_id)
    if "auto_apply" in updates:
        updates["auto_apply"] = int(updates["auto_apply"])
    set_exprs = [f"{k} = ?" for k in updates]
    set_exprs.append("updated_at = datetime('now')")
    sql, sql_params = _safe_dynamic_update("host_templates", set_exprs, list(updates.values()), "id = ?", template_id)
    db = await get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_host_template(template_id)
    finally:
        await db.close()


async def delete_host_template(template_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM host_templates WHERE id = ?", (template_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def link_graph_template_to_host_template(
    host_template_id: int, graph_template_id: int,
) -> dict:
    db = await get_db()
    try:
        await db.execute(
            """INSERT OR IGNORE INTO host_template_graph_links (host_template_id, graph_template_id)
               VALUES (?, ?)""",
            (host_template_id, graph_template_id),
        )
        await db.commit()
        return {"host_template_id": host_template_id, "graph_template_id": graph_template_id}
    finally:
        await db.close()


async def unlink_graph_template_from_host_template(
    host_template_id: int, graph_template_id: int,
) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            """DELETE FROM host_template_graph_links
               WHERE host_template_id = ? AND graph_template_id = ?""",
            (host_template_id, graph_template_id),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Host Graphs (graph template instances applied to devices)
# ═════════════════════════════════════════════════════════════════════════════

async def list_host_graphs(
    host_id: int | None = None, graph_template_id: int | None = None,
    enabled_only: bool = False,
) -> list[dict]:
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if host_id is not None:
            clauses.append("hg.host_id = ?")
            params.append(host_id)
        if graph_template_id is not None:
            clauses.append("hg.graph_template_id = ?")
            params.append(graph_template_id)
        if enabled_only:
            clauses.append("hg.enabled = 1")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT hg.*, gt.name AS template_name, gt.graph_type, gt.category,
                       gt.y_axis_label, gt.stacked, gt.area_fill
                FROM host_graphs hg
                JOIN graph_templates gt ON gt.id = hg.graph_template_id
                {where}
                ORDER BY hg.host_id, gt.category, gt.name, hg.instance_key""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_host_graph(host_graph_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT hg.*, gt.name AS template_name, gt.graph_type, gt.category,
                      gt.y_axis_label, gt.stacked, gt.area_fill, gt.options_json AS template_options
               FROM host_graphs hg
               JOIN graph_templates gt ON gt.id = hg.graph_template_id
               WHERE hg.id = ?""",
            (host_graph_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        hg = dict(row)
        cursor2 = await db.execute(
            "SELECT * FROM graph_template_items WHERE template_id = ? ORDER BY sort_order",
            (hg["graph_template_id"],),
        )
        hg["items"] = rows_to_list(await cursor2.fetchall())
        return hg
    finally:
        await db.close()


async def create_host_graph(
    host_id: int, graph_template_id: int, title: str = "",
    instance_key: str = "", instance_label: str = "",
    enabled: bool = True, pinned: bool = False,
    options_json: str = "{}",
) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT OR IGNORE INTO host_graphs
               (host_id, graph_template_id, title, instance_key, instance_label, enabled, pinned, options_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, graph_template_id, title, instance_key, instance_label,
             int(enabled), int(pinned), options_json),
        )
        await db.commit()
        new_id = cursor.lastrowid
        if new_id:
            cursor2 = await db.execute("SELECT * FROM host_graphs WHERE id = ?", (new_id,))
            return dict(await cursor2.fetchone())
        # Already existed (IGNORE), fetch existing
        cursor3 = await db.execute(
            """SELECT * FROM host_graphs
               WHERE host_id = ? AND graph_template_id = ? AND instance_key = ?""",
            (host_id, graph_template_id, instance_key),
        )
        row = await cursor3.fetchone()
        return dict(row) if row else {}
    finally:
        await db.close()


async def update_host_graph(host_graph_id: int, **kwargs) -> dict | None:
    allowed = {"title", "instance_label", "enabled", "pinned", "options_json"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return await get_host_graph(host_graph_id)
    for bkey in ("enabled", "pinned"):
        if bkey in updates:
            updates[bkey] = int(updates[bkey])
    set_exprs = [f"{k} = ?" for k in updates]
    sql, sql_params = _safe_dynamic_update("host_graphs", set_exprs, list(updates.values()), "id = ?", host_graph_id)
    db = await get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_host_graph(host_graph_id)
    finally:
        await db.close()


async def delete_host_graph(host_graph_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM host_graphs WHERE id = ?", (host_graph_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def apply_graph_templates_to_host(host_id: int) -> list[dict]:
    """Auto-create host_graphs for a device based on matching host templates.

    Matches the host's device_type against host_templates.device_types JSON array.
    Creates host_graph entries for each linked graph_template (scope='device').
    Returns list of newly created host_graph rows.
    """
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM hosts WHERE id = ?", (host_id,))
        host = await cursor.fetchone()
        if not host:
            return []
        host = dict(host)
        device_type = (host.get("device_type") or "").strip().lower()

        cursor2 = await db.execute(
            "SELECT * FROM host_templates WHERE auto_apply = 1"
        )
        htemplates = rows_to_list(await cursor2.fetchall())

        created: list[dict] = []
        for ht in htemplates:
            try:
                dt_list = json.loads(ht.get("device_types", "[]"))
            except (json.JSONDecodeError, TypeError):
                dt_list = []
            # Empty list means "match all devices"
            if dt_list and device_type not in [d.lower() for d in dt_list]:
                continue

            cursor3 = await db.execute(
                """SELECT gt.* FROM graph_templates gt
                   JOIN host_template_graph_links htgl ON htgl.graph_template_id = gt.id
                   WHERE htgl.host_template_id = ? AND gt.scope = 'device'""",
                (ht["id"],),
            )
            graph_templates = rows_to_list(await cursor3.fetchall())
            for gt in graph_templates:
                cursor4 = await db.execute(
                    """INSERT OR IGNORE INTO host_graphs
                       (host_id, graph_template_id, title, instance_key, enabled)
                       VALUES (?, ?, ?, '', 1)""",
                    (host_id, gt["id"], gt.get("title_format") or gt["name"]),
                )
                await db.commit()
                if cursor4.lastrowid:
                    cursor5 = await db.execute(
                        "SELECT * FROM host_graphs WHERE id = ?", (cursor4.lastrowid,)
                    )
                    row = await cursor5.fetchone()
                    if row:
                        created.append(dict(row))
        return created
    finally:
        await db.close()


async def apply_interface_graph_templates_to_host(host_id: int, interfaces: list[dict]) -> list[dict]:
    """Auto-create host_graphs for each interface on a device.

    For graph_templates with scope='interface', creates one host_graph per interface.
    Each interface becomes a unique instance_key (if_index) with instance_label (if_name).
    """
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM graph_templates WHERE scope = 'interface'"
        )
        iface_templates = rows_to_list(await cursor.fetchall())
        if not iface_templates:
            return []

        created: list[dict] = []
        for iface in interfaces:
            if_index = str(iface.get("if_index", iface.get("ifIndex", "")))
            if_name = iface.get("if_name", iface.get("ifDescr", ""))
            if not if_index:
                continue
            for gt in iface_templates:
                title = (gt.get("title_format") or gt["name"]).replace(
                    "$interface", if_name
                ).replace("$ifIndex", if_index)
                cursor2 = await db.execute(
                    """INSERT OR IGNORE INTO host_graphs
                       (host_id, graph_template_id, title, instance_key, instance_label, enabled)
                       VALUES (?, ?, ?, ?, ?, 1)""",
                    (host_id, gt["id"], title, if_index, if_name),
                )
                await db.commit()
                if cursor2.lastrowid:
                    cursor3 = await db.execute(
                        "SELECT * FROM host_graphs WHERE id = ?", (cursor2.lastrowid,)
                    )
                    row = await cursor3.fetchone()
                    if row:
                        created.append(dict(row))
        return created
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Graph Trees (hierarchical navigation)
# ═════════════════════════════════════════════════════════════════════════════

async def list_graph_trees() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM graph_trees ORDER BY sort_order, name")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_graph_tree(tree_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM graph_trees WHERE id = ?", (tree_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        tree = dict(row)
        cursor2 = await db.execute(
            "SELECT * FROM graph_tree_nodes WHERE tree_id = ? ORDER BY sort_order",
            (tree_id,),
        )
        tree["nodes"] = rows_to_list(await cursor2.fetchall())
        return tree
    finally:
        await db.close()


async def create_graph_tree(
    name: str, description: str = "", sort_order: int = 0, created_by: str = "",
) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO graph_trees (name, description, sort_order, created_by) VALUES (?, ?, ?, ?)",
            (name, description, sort_order, created_by),
        )
        await db.commit()
        new_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM graph_trees WHERE id = ?", (new_id,))
        return dict(await cursor2.fetchone())
    finally:
        await db.close()


async def update_graph_tree(tree_id: int, **kwargs) -> dict | None:
    allowed = {"name", "description", "sort_order"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return await get_graph_tree(tree_id)
    set_exprs = [f"{k} = ?" for k in updates]
    set_exprs.append("updated_at = datetime('now')")
    sql, sql_params = _safe_dynamic_update("graph_trees", set_exprs, list(updates.values()), "id = ?", tree_id)
    db = await get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_graph_tree(tree_id)
    finally:
        await db.close()


async def delete_graph_tree(tree_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM graph_trees WHERE id = ?", (tree_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ── Graph Tree Nodes ──────────────────────────────────────────────────────

async def create_graph_tree_node(
    tree_id: int, parent_node_id: int | None = None,
    node_type: str = "header", title: str = "",
    sort_order: int = 0, host_id: int | None = None,
    group_id: int | None = None, graph_id: int | None = None,
) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO graph_tree_nodes
               (tree_id, parent_node_id, node_type, title, sort_order, host_id, group_id, graph_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (tree_id, parent_node_id, node_type, title, sort_order, host_id, group_id, graph_id),
        )
        await db.commit()
        new_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM graph_tree_nodes WHERE id = ?", (new_id,))
        return dict(await cursor2.fetchone())
    finally:
        await db.close()


async def update_graph_tree_node(node_id: int, **kwargs) -> dict | None:
    allowed = {"parent_node_id", "node_type", "title", "sort_order", "host_id", "group_id", "graph_id"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return None
    set_exprs = [f"{k} = ?" for k in updates]
    sql, sql_params = _safe_dynamic_update("graph_tree_nodes", set_exprs, list(updates.values()), "id = ?", node_id)
    db = await get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
        cursor = await db.execute("SELECT * FROM graph_tree_nodes WHERE id = ?", (node_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def delete_graph_tree_node(node_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM graph_tree_nodes WHERE id = ?", (node_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Data Source Profiles (per-device poll configuration)
# ═════════════════════════════════════════════════════════════════════════════

async def list_data_source_profiles(host_id: int | None = None) -> list[dict]:
    db = await get_db()
    try:
        if host_id is not None:
            cursor = await db.execute(
                "SELECT * FROM data_source_profiles WHERE host_id = ? ORDER BY profile_name",
                (host_id,),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM data_source_profiles ORDER BY host_id, profile_name"
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_data_source_profile(profile_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM data_source_profiles WHERE id = ?", (profile_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def create_data_source_profile(
    host_id: int, profile_name: str = "default",
    poll_interval: int = 300, oids_json: str = "[]",
    enabled: bool = True,
) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT OR IGNORE INTO data_source_profiles
               (host_id, profile_name, poll_interval, oids_json, enabled)
               VALUES (?, ?, ?, ?, ?)""",
            (host_id, profile_name, poll_interval, oids_json, int(enabled)),
        )
        await db.commit()
        new_id = cursor.lastrowid
        if new_id:
            cursor2 = await db.execute("SELECT * FROM data_source_profiles WHERE id = ?", (new_id,))
            return dict(await cursor2.fetchone())
        cursor3 = await db.execute(
            "SELECT * FROM data_source_profiles WHERE host_id = ? AND profile_name = ?",
            (host_id, profile_name),
        )
        return dict(await cursor3.fetchone())
    finally:
        await db.close()


async def update_data_source_profile(profile_id: int, **kwargs) -> dict | None:
    allowed = {"profile_name", "poll_interval", "oids_json", "enabled", "last_polled_at"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return await get_data_source_profile(profile_id)
    if "enabled" in updates:
        updates["enabled"] = int(updates["enabled"])
    set_exprs = [f"{k} = ?" for k in updates]
    set_exprs.append("updated_at = datetime('now')")
    sql, sql_params = _safe_dynamic_update("data_source_profiles", set_exprs, list(updates.values()), "id = ?", profile_id)
    db = await get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_data_source_profile(profile_id)
    finally:
        await db.close()


async def delete_data_source_profile(profile_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM data_source_profiles WHERE id = ?", (profile_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ── Built-in Graph Template Seeding ──────────────────────────────────────────

BUILT_IN_GRAPH_TEMPLATES = [
    {
        "name": "CPU Usage",
        "description": "Device CPU utilization over time",
        "graph_type": "line",
        "category": "system",
        "scope": "device",
        "title_format": "CPU Usage",
        "y_axis_label": "Percent",
        "y_min": 0,
        "y_max": 100,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"metric_name": "cpu_usage", "label": "CPU %", "color": "#3B82F6",
             "line_type": "area", "consolidation": "avg", "legend_format": "Avg: {avg} Max: {max}"},
        ],
    },
    {
        "name": "Memory Usage",
        "description": "Device memory utilization over time",
        "graph_type": "line",
        "category": "system",
        "scope": "device",
        "title_format": "Memory Usage",
        "y_axis_label": "Percent",
        "y_min": 0,
        "y_max": 100,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"metric_name": "memory_usage", "label": "Memory %", "color": "#8B5CF6",
             "line_type": "area", "consolidation": "avg", "legend_format": "Avg: {avg} Max: {max}"},
        ],
    },
    {
        "name": "Interface Traffic",
        "description": "Per-interface inbound and outbound traffic in bits per second",
        "graph_type": "line",
        "category": "traffic",
        "scope": "interface",
        "title_format": "Traffic - $interface",
        "y_axis_label": "Bits/sec",
        "y_min": 0,
        "y_max": None,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"sort_order": 0, "metric_name": "if_in_octets", "label": "Inbound",
             "color": "#10B981", "line_type": "area", "consolidation": "avg",
             "transform": "rate,8,*", "legend_format": "In: {avg} bps (peak {max})"},
            {"sort_order": 1, "metric_name": "if_out_octets", "label": "Outbound",
             "color": "#F59E0B", "line_type": "area", "consolidation": "avg",
             "transform": "rate,8,*,negate", "legend_format": "Out: {avg} bps (peak {max})"},
        ],
    },
    {
        "name": "Interface Errors & Discards",
        "description": "Per-interface error and discard counters",
        "graph_type": "line",
        "category": "traffic",
        "scope": "interface",
        "title_format": "Errors - $interface",
        "y_axis_label": "Errors/sec",
        "y_min": 0,
        "y_max": None,
        "stacked": True,
        "area_fill": False,
        "items": [
            {"sort_order": 0, "metric_name": "if_in_errors", "label": "In Errors",
             "color": "#EF4444", "line_type": "line", "consolidation": "avg",
             "transform": "rate"},
            {"sort_order": 1, "metric_name": "if_out_errors", "label": "Out Errors",
             "color": "#F97316", "line_type": "line", "consolidation": "avg",
             "transform": "rate"},
            {"sort_order": 2, "metric_name": "if_in_discards", "label": "In Discards",
             "color": "#A855F7", "line_type": "line", "consolidation": "avg",
             "transform": "rate"},
            {"sort_order": 3, "metric_name": "if_out_discards", "label": "Out Discards",
             "color": "#EC4899", "line_type": "line", "consolidation": "avg",
             "transform": "rate"},
        ],
    },
    {
        "name": "Device Uptime",
        "description": "Device uptime in days (gauge)",
        "graph_type": "gauge",
        "category": "system",
        "scope": "device",
        "title_format": "Uptime",
        "y_axis_label": "Days",
        "y_min": 0,
        "y_max": None,
        "stacked": False,
        "area_fill": False,
        "grid_w": 3,
        "grid_h": 3,
        "items": [
            {"metric_name": "uptime", "label": "Uptime", "color": "#10B981",
             "line_type": "line", "consolidation": "last",
             "transform": "div,8640000", "legend_format": "{last} days"},
        ],
    },
    {
        "name": "Interface Utilization",
        "description": "Per-interface utilization percentage",
        "graph_type": "line",
        "category": "traffic",
        "scope": "interface",
        "title_format": "Utilization - $interface",
        "y_axis_label": "Percent",
        "y_min": 0,
        "y_max": 100,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"sort_order": 0, "metric_name": "if_utilization_in", "label": "In Utilization",
             "color": "#3B82F6", "line_type": "area", "consolidation": "avg",
             "legend_format": "Avg: {avg}% Peak: {max}%"},
            {"sort_order": 1, "metric_name": "if_utilization_out", "label": "Out Utilization",
             "color": "#F59E0B", "line_type": "area", "consolidation": "avg",
             "legend_format": "Avg: {avg}% Peak: {max}%"},
        ],
    },
    {
        "name": "Ping Latency",
        "description": "ICMP round-trip latency over time",
        "graph_type": "line",
        "category": "availability",
        "scope": "device",
        "title_format": "Ping Latency",
        "y_axis_label": "ms",
        "y_min": 0,
        "y_max": None,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"metric_name": "ping_rtt", "label": "RTT", "color": "#06B6D4",
             "line_type": "area", "consolidation": "avg",
             "legend_format": "Avg: {avg}ms Max: {max}ms"},
        ],
    },
]


async def seed_built_in_graph_templates() -> int:
    """Create built-in graph templates if they don't already exist. Returns count created."""
    db = await get_db()
    try:
        created = 0
        for tpl_def in BUILT_IN_GRAPH_TEMPLATES:
            cursor = await db.execute(
                "SELECT id FROM graph_templates WHERE name = ? AND built_in = 1",
                (tpl_def["name"],),
            )
            if await cursor.fetchone():
                continue
            items = tpl_def.pop("items", [])
            cursor2 = await db.execute(
                """INSERT INTO graph_templates
                   (name, description, graph_type, category, scope, title_format,
                    y_axis_label, y_min, y_max, stacked, area_fill, grid_w, grid_h,
                    options_json, built_in, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', 1, 'system')""",
                (tpl_def["name"], tpl_def.get("description", ""),
                 tpl_def.get("graph_type", "line"), tpl_def.get("category", "system"),
                 tpl_def.get("scope", "device"), tpl_def.get("title_format", ""),
                 tpl_def.get("y_axis_label", ""),
                 tpl_def.get("y_min"), tpl_def.get("y_max"),
                 int(tpl_def.get("stacked", False)), int(tpl_def.get("area_fill", True)),
                 tpl_def.get("grid_w", 6), tpl_def.get("grid_h", 4)),
            )
            await db.commit()
            tpl_id = cursor2.lastrowid
            for idx, item in enumerate(items):
                await db.execute(
                    """INSERT INTO graph_template_items
                       (template_id, sort_order, metric_name, label, color, line_type,
                        cdef_expression, consolidation, transform, legend_format)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (tpl_id, item.get("sort_order", idx),
                     item.get("metric_name", ""), item.get("label", ""),
                     item.get("color", ""), item.get("line_type", "area"),
                     item.get("cdef_expression", ""), item.get("consolidation", "avg"),
                     item.get("transform", ""), item.get("legend_format", "")),
                )
            await db.commit()
            tpl_def["items"] = items
            created += 1
            _LOGGER.info("Seeded built-in graph template: %s (id=%s)", tpl_def["name"], tpl_id)

        # Seed a default host template that links all device-scope built-in templates
        cursor_ht = await db.execute(
            "SELECT id FROM host_templates WHERE name = 'Default (All Devices)'"
        )
        if not await cursor_ht.fetchone():
            cursor_ht2 = await db.execute(
                """INSERT INTO host_templates (name, description, device_types, auto_apply, created_by)
                   VALUES ('Default (All Devices)', 'Auto-applies system graphs to all discovered devices',
                           '[]', 1, 'system')""",
            )
            await db.commit()
            ht_id = cursor_ht2.lastrowid
            cursor_device_tpls = await db.execute(
                "SELECT id FROM graph_templates WHERE built_in = 1 AND scope = 'device'"
            )
            for row in await cursor_device_tpls.fetchall():
                await db.execute(
                    "INSERT OR IGNORE INTO host_template_graph_links (host_template_id, graph_template_id) VALUES (?, ?)",
                    (ht_id, row[0] if isinstance(row, tuple) else dict(row)["id"]),
                )
            await db.commit()
            _LOGGER.info("Seeded default host template (id=%s)", ht_id)

        return created
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# SNMP DATA SOURCES  (auto-discovered interfaces as independent data sources)
# ═════════════════════════════════════════════════════════════════════════════


async def list_snmp_data_sources(host_id: int, ds_type: str | None = None) -> list[dict]:
    db = await get_db()
    try:
        if ds_type:
            cursor = await db.execute(
                "SELECT * FROM snmp_data_sources WHERE host_id = ? AND ds_type = ? ORDER BY instance_key",
                (host_id, ds_type),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM snmp_data_sources WHERE host_id = ? ORDER BY ds_type, instance_key",
                (host_id,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_snmp_data_source(ds_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM snmp_data_sources WHERE id = ?", (ds_id,))
        row = await cursor.fetchone()
        return row_to_dict(row) if row else None
    finally:
        await db.close()


async def upsert_snmp_data_source(
    host_id: int, ds_type: str, instance_key: str, **kwargs
) -> int:
    """Atomic upsert using INSERT ... ON CONFLICT DO UPDATE (SQLite 3.24+)."""
    allowed = {"name", "table_oid", "index_oid", "instance_label",
               "oids_json", "poll_interval", "enabled", "last_polled_at"}
    name = kwargs.get("name", "")
    table_oid = kwargs.get("table_oid", "")
    index_oid = kwargs.get("index_oid", "")
    instance_label = kwargs.get("instance_label", "")
    oids_json = kwargs.get("oids_json", "[]")
    poll_interval = kwargs.get("poll_interval", 300)
    enabled = kwargs.get("enabled", 1)
    # Build SET clause for ON CONFLICT from provided kwargs
    update_sets = []
    for k in kwargs:
        if k in allowed:
            update_sets.append(f"{k} = excluded.{k}")
    if not update_sets:
        # Nothing to update on conflict — no-op SET
        update_sets = ["name = excluded.name"]
    db = await get_db()
    try:
        await db.execute(
            f"""INSERT INTO snmp_data_sources
                (host_id, ds_type, instance_key, name, table_oid, index_oid,
                 instance_label, oids_json, poll_interval, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host_id, ds_type, instance_key) DO UPDATE SET
                {', '.join(update_sets)}""",
            (host_id, ds_type, instance_key, name, table_oid, index_oid,
             instance_label, oids_json, poll_interval, enabled),
        )
        await db.commit()
        # Fetch the row id (works for both insert and update)
        cursor = await db.execute(
            "SELECT id FROM snmp_data_sources WHERE host_id = ? AND ds_type = ? AND instance_key = ?",
            (host_id, ds_type, instance_key),
        )
        row = await cursor.fetchone()
        return row[0] if isinstance(row, tuple) else dict(row)["id"]
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def update_snmp_data_source(ds_id: int, **kwargs) -> bool:
    db = await get_db()
    try:
        sets = []
        vals = []
        for k, v in kwargs.items():
            if k in ("name", "poll_interval", "enabled", "oids_json", "last_polled_at"):
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        sql, sql_params = _safe_dynamic_update("snmp_data_sources", sets, vals, "id = ?", ds_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_snmp_data_source(ds_id: int) -> bool:
    db = await get_db()
    try:
        await db.execute("DELETE FROM snmp_data_sources WHERE id = ?", (ds_id,))
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_snmp_data_sources_for_host(host_id: int) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM snmp_data_sources WHERE host_id = ?", (host_id,)
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# CDEF DEFINITIONS  (calculated data sources / expressions)
# ═════════════════════════════════════════════════════════════════════════════

BUILT_IN_CDEFS = [
    {
        "name": "Total Bandwidth",
        "description": "Sum of inbound and outbound traffic (in+out)",
        "expression": "a,b,+",
    },
    {
        "name": "95th Percentile",
        "description": "95th percentile of the data series",
        "expression": "PERCENTILE_95",
    },
    {
        "name": "Average",
        "description": "Average of the data series",
        "expression": "AVG",
    },
    {
        "name": "Peak (Max)",
        "description": "Maximum value of the data series",
        "expression": "MAX",
    },
    {
        "name": "Bits to Bytes",
        "description": "Convert bits to bytes (divide by 8)",
        "expression": "a,8,/",
    },
    {
        "name": "Bytes to Bits",
        "description": "Convert bytes to bits (multiply by 8)",
        "expression": "a,8,*",
    },
    {
        "name": "Invert (Negate)",
        "description": "Negate the value (for outbound display below axis)",
        "expression": "a,-1,*",
    },
]


async def list_cdef_definitions() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM cdef_definitions ORDER BY built_in DESC, name")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cdef_definition(cdef_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM cdef_definitions WHERE id = ?", (cdef_id,))
        row = await cursor.fetchone()
        return row_to_dict(row) if row else None
    finally:
        await db.close()


async def create_cdef_definition(name: str, expression: str, description: str = "",
                                  built_in: int = 0, created_by: str = "") -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO cdef_definitions (name, description, expression, built_in, created_by)
               VALUES (?, ?, ?, ?, ?)""",
            (name, description, expression, built_in, created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_cdef_definition(cdef_id: int, **kwargs) -> bool:
    db = await get_db()
    try:
        sets = []
        vals = []
        for k, v in kwargs.items():
            if k in ("name", "description", "expression"):
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        sql, sql_params = _safe_dynamic_update("cdef_definitions", sets, vals, "id = ?", cdef_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_cdef_definition(cdef_id: int) -> bool:
    db = await get_db()
    try:
        await db.execute("DELETE FROM cdef_definitions WHERE id = ?", (cdef_id,))
        await db.commit()
        return True
    finally:
        await db.close()


async def seed_built_in_cdefs() -> int:
    db = await get_db()
    try:
        created = 0
        for cdef in BUILT_IN_CDEFS:
            cursor = await db.execute(
                "SELECT id FROM cdef_definitions WHERE name = ? AND built_in = 1",
                (cdef["name"],),
            )
            if await cursor.fetchone():
                continue
            await db.execute(
                """INSERT INTO cdef_definitions (name, description, expression, built_in, created_by)
                   VALUES (?, ?, ?, 1, 'system')""",
                (cdef["name"], cdef.get("description", ""), cdef["expression"]),
            )
            await db.commit()
            created += 1
        return created
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# MAC / ARP TRACKING  (MacTrack-style endpoint location)
# ═════════════════════════════════════════════════════════════════════════════


async def upsert_mac_entry(host_id: int, mac_address: str, vlan: int,
                            port_name: str = "", port_index: int = 0,
                            ip_address: str = "", entry_type: str = "dynamic") -> int:
    """Atomic upsert using INSERT ... ON CONFLICT DO UPDATE."""
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO mac_address_table
               (host_id, mac_address, vlan, port_name, port_index, ip_address, entry_type)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(host_id, mac_address, vlan) DO UPDATE SET
                port_name = excluded.port_name,
                port_index = excluded.port_index,
                ip_address = excluded.ip_address,
                entry_type = excluded.entry_type,
                last_seen = datetime('now')""",
            (host_id, mac_address, vlan, port_name, port_index, ip_address, entry_type),
        )
        await db.commit()
        cursor = await db.execute(
            "SELECT id FROM mac_address_table WHERE host_id = ? AND mac_address = ? AND vlan = ?",
            (host_id, mac_address, vlan),
        )
        row = await cursor.fetchone()
        return row[0] if isinstance(row, tuple) else dict(row)["id"]
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def upsert_arp_entry(host_id: int, ip_address: str, mac_address: str,
                            interface_name: str = "", vrf: str = "") -> int:
    """Atomic upsert using INSERT ... ON CONFLICT DO UPDATE."""
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO arp_table
               (host_id, ip_address, mac_address, interface_name, vrf)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(host_id, ip_address, vrf) DO UPDATE SET
                mac_address = excluded.mac_address,
                interface_name = excluded.interface_name,
                last_seen = datetime('now')""",
            (host_id, ip_address, mac_address, interface_name, vrf),
        )
        await db.commit()
        cursor = await db.execute(
            "SELECT id FROM arp_table WHERE host_id = ? AND ip_address = ? AND vrf = ?",
            (host_id, ip_address, vrf),
        )
        row = await cursor.fetchone()
        return row[0] if isinstance(row, tuple) else dict(row)["id"]
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def record_mac_history(mac_address: str, host_id: int, port_name: str,
                              vlan: int = 0, ip_address: str = "") -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO mac_tracking_history
               (mac_address, ip_address, host_id, port_name, vlan)
               VALUES (?, ?, ?, ?, ?)""",
            (mac_address, ip_address, host_id, port_name, vlan),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def search_mac_tracking(query: str, limit: int = 100) -> list[dict]:
    """Search MAC/ARP tables by MAC address, IP address, or port name."""
    db = await get_db()
    try:
        pattern = f"%{query}%"
        cursor = await db.execute(
            """SELECT m.*, h.hostname, h.ip_address as host_ip
               FROM mac_address_table m
               LEFT JOIN hosts h ON h.id = m.host_id
               WHERE m.mac_address LIKE ? OR m.ip_address LIKE ? OR m.port_name LIKE ?
               ORDER BY m.last_seen DESC LIMIT ?""",
            (pattern, pattern, pattern, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_mac_history(mac_address: str, limit: int = 100) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT mh.*, h.hostname, h.ip_address as host_ip
               FROM mac_tracking_history mh
               LEFT JOIN hosts h ON h.id = mh.host_id
               WHERE mh.mac_address = ?
               ORDER BY mh.seen_at DESC LIMIT ?""",
            (mac_address, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_mac_table_for_host(host_id: int) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM mac_address_table WHERE host_id = ? ORDER BY vlan, port_name",
            (host_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_arp_table_for_host(host_id: int) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM arp_table WHERE host_id = ? ORDER BY ip_address",
            (host_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_macs_on_port(host_id: int, port_name: str) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM mac_address_table WHERE host_id = ? AND port_name = ? ORDER BY mac_address",
            (host_id, port_name),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def cleanup_stale_mac_entries(days: int = 30) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM mac_address_table WHERE last_seen < datetime('now', ? || ' days')",
            (f"-{days}",),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# FLOW RECORDS  (NetFlow / sFlow / IPFIX)
# ═════════════════════════════════════════════════════════════════════════════


async def create_flow_records_batch(rows: list[tuple]) -> int:
    """Batch insert flow records.  Each tuple:
    (exporter_ip, host_id, flow_type, src_ip, dst_ip, src_port, dst_port,
     protocol, bytes, packets, src_as, dst_as, input_if, output_if,
     tos, tcp_flags, start_time, end_time)
    """
    if not rows:
        return 0
    db = await get_db()
    try:
        await db.executemany(
            """INSERT INTO flow_records
               (exporter_ip, host_id, flow_type, src_ip, dst_ip, src_port, dst_port,
                protocol, bytes, packets, src_as, dst_as, input_if, output_if,
                tos, tcp_flags, start_time, end_time)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        await db.commit()
        return len(rows)
    finally:
        await db.close()


async def get_flow_top_talkers(host_id: int | None = None, hours: int = 1,
                                direction: str = "src", limit: int = 20) -> list[dict]:
    db = await get_db()
    try:
        col = "src_ip" if direction == "src" else "dst_ip"
        where = "WHERE received_at >= datetime('now', ? || ' hours')"
        params: list = [f"-{hours}"]
        if host_id is not None:
            where += " AND host_id = ?"
            params.append(host_id)
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT {col} as ip, SUM(bytes) as total_bytes, SUM(packets) as total_packets,
                       COUNT(*) as flow_count
               FROM flow_records {where}
               GROUP BY {col} ORDER BY total_bytes DESC LIMIT ?""",
            params,
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_flow_top_applications(host_id: int | None = None, hours: int = 1,
                                     limit: int = 20) -> list[dict]:
    db = await get_db()
    try:
        where = "WHERE received_at >= datetime('now', ? || ' hours')"
        params: list = [f"-{hours}"]
        if host_id is not None:
            where += " AND host_id = ?"
            params.append(host_id)
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT dst_port as port, protocol, SUM(bytes) as total_bytes,
                       SUM(packets) as total_packets, COUNT(*) as flow_count
               FROM flow_records {where}
               GROUP BY dst_port, protocol ORDER BY total_bytes DESC LIMIT ?""",
            params,
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_flow_top_conversations(host_id: int | None = None, hours: int = 1,
                                      limit: int = 20) -> list[dict]:
    db = await get_db()
    try:
        where = "WHERE received_at >= datetime('now', ? || ' hours')"
        params: list = [f"-{hours}"]
        if host_id is not None:
            where += " AND host_id = ?"
            params.append(host_id)
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT src_ip, dst_ip, SUM(bytes) as total_bytes,
                       SUM(packets) as total_packets, COUNT(*) as flow_count
               FROM flow_records {where}
               GROUP BY src_ip, dst_ip ORDER BY total_bytes DESC LIMIT ?""",
            params,
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_flow_timeline(host_id: int | None = None, hours: int = 6,
                             bucket_minutes: int = 5) -> list[dict]:
    """Aggregate flow data into time buckets."""
    # Validate bucket_minutes to prevent SQL injection via f-string
    bucket_minutes = max(1, min(int(bucket_minutes), 60))
    db = await get_db()
    try:
        where = "WHERE received_at >= datetime('now', ? || ' hours')"
        params: list = [f"-{max(1, int(hours))}"]
        if host_id is not None:
            where += " AND host_id = ?"
            params.append(host_id)
        cursor = await db.execute(
            f"""SELECT
                   strftime('%Y-%m-%dT%H:', received_at) ||
                   printf('%02d', (CAST(strftime('%M', received_at) AS INTEGER) / {bucket_minutes}) * {bucket_minutes}) ||
                   ':00' as bucket,
                   SUM(bytes) as total_bytes,
                   SUM(packets) as total_packets,
                   COUNT(*) as flow_count
               FROM flow_records {where}
               GROUP BY bucket ORDER BY bucket""",
            params,
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def create_flow_summary(host_id: int | None, summary_type: str,
                               time_window: str, period_start: str,
                               period_end: str, data_json: str) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO flow_summaries
               (host_id, summary_type, time_window, period_start, period_end, data_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (host_id, summary_type, time_window, period_start, period_end, data_json),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def cleanup_old_flow_records(hours: int = 48) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM flow_records WHERE received_at < datetime('now', ? || ' hours')",
            (f"-{hours}",),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


def _cloud_flow_type(provider: str) -> str:
    normalized = str(provider or "").strip().lower()
    if normalized not in {"aws", "azure", "gcp"}:
        raise ValueError("invalid_provider")
    return f"cloud_{normalized}_flow"


def _cloud_flow_exporter(account_id: int) -> str:
    return f"cloud-account-{int(account_id)}"


async def get_cloud_flow_summary(
    account_id: int | None = None,
    provider: str | None = None,
    hours: int = 24,
) -> dict:
    db = await get_db()
    try:
        clauses = [
            "received_at >= datetime('now', ? || ' hours')",
            "flow_type LIKE 'cloud_%'",
        ]
        params: list = [f"-{max(1, int(hours))}"]
        if account_id is not None:
            clauses.append("exporter_ip = ?")
            params.append(_cloud_flow_exporter(account_id))
        if provider:
            clauses.append("flow_type = ?")
            params.append(_cloud_flow_type(provider))
        where = " AND ".join(clauses)
        cursor = await db.execute(
            f"""SELECT COUNT(*) as flow_count,
                       COALESCE(SUM(bytes), 0) as total_bytes,
                       COALESCE(SUM(packets), 0) as total_packets,
                       COUNT(DISTINCT src_ip) as unique_sources,
                       COUNT(DISTINCT dst_ip) as unique_destinations,
                       MIN(received_at) as first_seen,
                       MAX(received_at) as last_seen
               FROM flow_records
               WHERE {where}""",
            tuple(params),
        )
        return row_to_dict(await cursor.fetchone()) or {
            "flow_count": 0,
            "total_bytes": 0,
            "total_packets": 0,
            "unique_sources": 0,
            "unique_destinations": 0,
            "first_seen": None,
            "last_seen": None,
        }
    finally:
        await db.close()


async def get_cloud_flow_top_talkers(
    account_id: int | None = None,
    provider: str | None = None,
    hours: int = 24,
    direction: str = "src",
    limit: int = 20,
) -> list[dict]:
    db = await get_db()
    try:
        col = "src_ip" if direction == "src" else "dst_ip"
        clauses = [
            "received_at >= datetime('now', ? || ' hours')",
            "flow_type LIKE 'cloud_%'",
        ]
        params: list = [f"-{max(1, int(hours))}"]
        if account_id is not None:
            clauses.append("exporter_ip = ?")
            params.append(_cloud_flow_exporter(account_id))
        if provider:
            clauses.append("flow_type = ?")
            params.append(_cloud_flow_type(provider))
        params.append(max(1, int(limit)))
        where = " AND ".join(clauses)
        cursor = await db.execute(
            f"""SELECT {col} as ip,
                       SUM(bytes) as total_bytes,
                       SUM(packets) as total_packets,
                       COUNT(*) as flow_count
                FROM flow_records
                WHERE {where}
                GROUP BY {col}
                ORDER BY total_bytes DESC
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_flow_timeline(
    account_id: int | None = None,
    provider: str | None = None,
    hours: int = 24,
    bucket_minutes: int = 5,
) -> list[dict]:
    bucket_minutes = max(1, min(int(bucket_minutes), 60))
    db = await get_db()
    try:
        clauses = [
            "received_at >= datetime('now', ? || ' hours')",
            "flow_type LIKE 'cloud_%'",
        ]
        params: list = [f"-{max(1, int(hours))}"]
        if account_id is not None:
            clauses.append("exporter_ip = ?")
            params.append(_cloud_flow_exporter(account_id))
        if provider:
            clauses.append("flow_type = ?")
            params.append(_cloud_flow_type(provider))
        where = " AND ".join(clauses)
        cursor = await db.execute(
            f"""SELECT
                   strftime('%Y-%m-%dT%H:', received_at) ||
                   printf('%02d', (CAST(strftime('%M', received_at) AS INTEGER) / {bucket_minutes}) * {bucket_minutes}) ||
                   ':00' as bucket,
                   SUM(bytes) as total_bytes,
                   SUM(packets) as total_packets,
                   COUNT(*) as flow_count
               FROM flow_records
               WHERE {where}
               GROUP BY bucket
               ORDER BY bucket""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# METRIC BASELINES  (statistical learning for baseline deviation alerting)
# ═════════════════════════════════════════════════════════════════════════════


async def upsert_metric_baseline(host_id: int, metric_name: str,
                                   day_of_week: int, hour_of_day: int,
                                   baseline_avg: float, baseline_stddev: float,
                                   baseline_min: float, baseline_max: float,
                                   baseline_p95: float, sample_count: int,
                                   labels_json: str = "{}",
                                   learning_window_days: int = 14) -> int:
    """Atomic upsert using INSERT ... ON CONFLICT DO UPDATE (SQLite 3.24+)."""
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO metric_baselines
               (host_id, metric_name, labels_json, day_of_week, hour_of_day,
                baseline_avg, baseline_stddev, baseline_min, baseline_max,
                baseline_p95, sample_count, learning_window_days)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(host_id, metric_name, labels_json, day_of_week, hour_of_day) DO UPDATE SET
                baseline_avg = excluded.baseline_avg,
                baseline_stddev = excluded.baseline_stddev,
                baseline_min = excluded.baseline_min,
                baseline_max = excluded.baseline_max,
                baseline_p95 = excluded.baseline_p95,
                sample_count = excluded.sample_count,
                learning_window_days = excluded.learning_window_days,
                last_computed = datetime('now')""",
            (host_id, metric_name, labels_json, day_of_week, hour_of_day,
             baseline_avg, baseline_stddev, baseline_min, baseline_max,
             baseline_p95, sample_count, learning_window_days),
        )
        await db.commit()
        # Retrieve the row id
        cursor = await db.execute(
            """SELECT id FROM metric_baselines
               WHERE host_id = ? AND metric_name = ? AND labels_json = ?
                     AND day_of_week = ? AND hour_of_day = ?""",
            (host_id, metric_name, labels_json, day_of_week, hour_of_day),
        )
        row = await cursor.fetchone()
        return row[0] if isinstance(row, tuple) else dict(row)["id"]
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def get_metric_baseline(host_id: int, metric_name: str,
                                day_of_week: int, hour_of_day: int,
                                labels_json: str = "{}") -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM metric_baselines
               WHERE host_id = ? AND metric_name = ? AND labels_json = ?
                     AND day_of_week = ? AND hour_of_day = ?""",
            (host_id, metric_name, labels_json, day_of_week, hour_of_day),
        )
        row = await cursor.fetchone()
        return row_to_dict(row) if row else None
    finally:
        await db.close()


async def get_baselines_for_host(host_id: int, metric_name: str | None = None) -> list[dict]:
    db = await get_db()
    try:
        if metric_name:
            cursor = await db.execute(
                "SELECT * FROM metric_baselines WHERE host_id = ? AND metric_name = ? ORDER BY day_of_week, hour_of_day",
                (host_id, metric_name),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM metric_baselines WHERE host_id = ? ORDER BY metric_name, day_of_week, hour_of_day",
                (host_id,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ── Baseline Alert Rules ──

async def list_baseline_alert_rules(enabled_only: bool = False) -> list[dict]:
    db = await get_db()
    try:
        q = "SELECT * FROM baseline_alert_rules"
        if enabled_only:
            q += " WHERE enabled = 1"
        q += " ORDER BY name"
        cursor = await db.execute(q)
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_baseline_alert_rule(rule_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM baseline_alert_rules WHERE id = ?", (rule_id,))
        row = await cursor.fetchone()
        return row_to_dict(row) if row else None
    finally:
        await db.close()


async def create_baseline_alert_rule(**kwargs) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO baseline_alert_rules
               (name, description, metric_name, host_id, group_id,
                sensitivity, min_samples, learning_days, enabled,
                severity, cooldown_minutes, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (kwargs.get("name", ""), kwargs.get("description", ""),
             kwargs.get("metric_name", ""), kwargs.get("host_id"),
             kwargs.get("group_id"), kwargs.get("sensitivity", 2.0),
             kwargs.get("min_samples", 100), kwargs.get("learning_days", 14),
             kwargs.get("enabled", 1), kwargs.get("severity", "warning"),
             kwargs.get("cooldown_minutes", 30), kwargs.get("created_by", "")),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_baseline_alert_rule(rule_id: int, **kwargs) -> bool:
    db = await get_db()
    try:
        sets = []
        vals = []
        allowed = ("name", "description", "metric_name", "host_id", "group_id",
                    "sensitivity", "min_samples", "learning_days", "enabled",
                    "severity", "cooldown_minutes")
        for k, v in kwargs.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        sets.append("updated_at = datetime('now')")
        sql, sql_params = _safe_dynamic_update("baseline_alert_rules", sets, vals, "id = ?", rule_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_baseline_alert_rule(rule_id: int) -> bool:
    db = await get_db()
    try:
        await db.execute("DELETE FROM baseline_alert_rules WHERE id = ?", (rule_id,))
        await db.commit()
        return True
    finally:
        await db.close()


# ── IOS-XE Upgrade System ──────────────────────────────────────────────────


async def create_upgrade_image(filename, original_name, file_size, md5_hash,
                               model_pattern, version, platform, notes, uploaded_by):
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO upgrade_images (filename, original_name, file_size, md5_hash, "
            "model_pattern, version, platform, notes, uploaded_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (filename, original_name, file_size, md5_hash,
             model_pattern, version, platform, notes, uploaded_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_all_upgrade_images():
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM upgrade_images ORDER BY created_at DESC")
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_upgrade_image(image_id):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM upgrade_images WHERE id = ?", (image_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def update_upgrade_image(image_id, **kwargs):
    db = await get_db()
    try:
        sets, vals = [], []
        for k, v in kwargs.items():
            if k in ("model_pattern", "version", "platform", "notes"):
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        sql, sql_params = _safe_dynamic_update("upgrade_images", sets, vals, "id = ?", image_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_upgrade_image(image_id):
    db = await get_db()
    try:
        await db.execute("DELETE FROM upgrade_images WHERE id = ?", (image_id,))
        await db.commit()
        return True
    finally:
        await db.close()


async def create_upgrade_campaign(name, description, image_map, options, created_by):
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO upgrade_campaigns (name, description, image_map, options, created_by) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, description, json.dumps(image_map), json.dumps(options), created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_all_upgrade_campaigns():
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM upgrade_campaigns ORDER BY created_at DESC")
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_upgrade_campaign(campaign_id):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM upgrade_campaigns WHERE id = ?", (campaign_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def update_upgrade_campaign(campaign_id, **kwargs):
    db = await get_db()
    try:
        sets, vals = [], []
        for k, v in kwargs.items():
            if k in ("name", "description", "status", "image_map", "options"):
                if k in ("image_map", "options"):
                    v = json.dumps(v)
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        sets.append("updated_at = datetime('now')")
        sql, sql_params = _safe_dynamic_update("upgrade_campaigns", sets, vals, "id = ?", campaign_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_upgrade_campaign(campaign_id):
    db = await get_db()
    try:
        await db.execute("DELETE FROM upgrade_campaigns WHERE id = ?", (campaign_id,))
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_upgrade_devices_by_campaign(campaign_id):
    db = await get_db()
    try:
        await db.execute(
            "DELETE FROM upgrade_devices WHERE campaign_id = ? "
            "AND COALESCE(phase, 'pending') != 'running' "
            "AND COALESCE(prestage_status, 'pending') != 'running' "
            "AND COALESCE(transfer_status, 'pending') != 'running' "
            "AND COALESCE(activate_status, 'pending') != 'running' "
            "AND COALESCE(verify_status, 'pending') != 'running'",
            (campaign_id,),
        )
        await db.commit()
        return True
    finally:
        await db.close()

async def add_upgrade_device(campaign_id, host_id, ip_address, hostname):
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO upgrade_devices (campaign_id, host_id, ip_address, hostname) "
            "VALUES (?, ?, ?, ?)",
            (campaign_id, host_id, ip_address, hostname),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_upgrade_devices(campaign_id):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM upgrade_devices WHERE campaign_id = ? ORDER BY hostname, ip_address",
            (campaign_id,),
        )
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_upgrade_device(device_id):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM upgrade_devices WHERE id = ?", (device_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def update_upgrade_device(device_id, **kwargs):
    db = await get_db()
    try:
        allowed = {
            "model", "current_version", "target_image", "phase", "phase_detail",
            "health_status", "prestage_status", "transfer_status", "activate_status",
            "verify_status", "error_message", "started_at", "completed_at",
        }
        sets, vals = [], []
        for k, v in kwargs.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        sql, sql_params = _safe_dynamic_update("upgrade_devices", sets, vals, "id = ?", device_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return True
    finally:
        await db.close()


async def add_upgrade_event(campaign_id, device_id, level, message, host=""):
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO upgrade_events (campaign_id, device_id, level, message, host) "
            "VALUES (?, ?, ?, ?, ?)",
            (campaign_id, device_id, level, message, host),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_upgrade_events(campaign_id, device_id=None, limit=10000):
    db = await get_db()
    try:
        if device_id:
            cursor = await db.execute(
                "SELECT * FROM upgrade_events WHERE campaign_id = ? AND device_id = ? "
                "ORDER BY timestamp ASC LIMIT ?",
                (campaign_id, device_id, limit),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM upgrade_events WHERE campaign_id = ? "
                "ORDER BY timestamp ASC LIMIT ?",
                (campaign_id, limit),
            )
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# IPAM — Lightweight IP Address Management
# ═════════════════════════════════════════════════════════════════════════════


def _infer_subnet(ip_str: str) -> str | None:
    """Infer network CIDR from a host IP string.

    Handles both notated (10.0.0.1/24) and plain (10.0.0.1) forms.
    Plain IPv4 defaults to /24; plain IPv6 defaults to /64.
    Returns canonical network string (e.g. "10.0.0.0/24") or None on error.
    """
    if not ip_str:
        return None
    ip_str = ip_str.strip()
    try:
        if "/" in ip_str:
            net = ipaddress.ip_interface(ip_str).network
        else:
            addr = ipaddress.ip_address(ip_str)
            prefix = 64 if addr.version == 6 else 24
            net = ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)
        return str(net)
    except ValueError:
        return None


def _ip_in_reservation(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, rsv: dict) -> bool:
    """Return True if *addr* falls within the reservation IP range."""
    try:
        start = ipaddress.ip_address(rsv["start_ip"])
        end = ipaddress.ip_address(rsv["end_ip"])
        return start <= addr <= end
    except (ValueError, KeyError):
        return False


async def get_ipam_overview(
    group_id: int | None = None,
    include_cloud: bool = True,
    include_external: bool = True,
) -> dict:
    """Return a merged IPAM overview across inventory, cloud, and external sources."""
    db = await get_db()
    try:
        # ── 1. Inventory hosts ──────────────────────────────────────────────
        if group_id is not None:
            cursor = await db.execute(
                """SELECT h.ip_address, h.vrf_name, h.vlan_id, g.name AS group_name
                   FROM hosts h
                   JOIN inventory_groups g ON h.group_id = g.id
                   WHERE h.group_id = ? AND h.ip_address != '' AND h.ip_address IS NOT NULL""",
                (group_id,),
            )
        else:
            cursor = await db.execute(
                """SELECT h.ip_address, h.vrf_name, h.vlan_id, g.name AS group_name
                   FROM hosts h
                   JOIN inventory_groups g ON h.group_id = g.id
                   WHERE h.ip_address != '' AND h.ip_address IS NOT NULL"""
            )
        host_rows = rows_to_list(await cursor.fetchall())

        # Subnets are scoped by (subnet, vrf) so the same RFC1918 range in
        # different VRFs does not collapse into one row. Empty VRF = "global".
        subnet_hosts: dict[tuple[str, str], list[dict]] = {}
        subnet_vlans: dict[tuple[str, str], set[str]] = {}
        # Conflict key is (vrf, ip): same IP in different inventory groups but
        # the same VRF is a real conflict; different VRFs are not.
        ip_groups: dict[tuple[str, str], set[str]] = {}

        for row in host_rows:
            ip = row["ip_address"].strip().split("/")[0]
            group = row["group_name"]
            vrf = (row.get("vrf_name") or "").strip()
            vlan = (row.get("vlan_id") or "").strip()
            sn = _infer_subnet(ip)
            if sn is None:
                continue
            key = (sn, vrf)
            subnet_hosts.setdefault(key, []).append({"ip": ip, "group": group, "vrf": vrf, "vlan": vlan})
            if vlan:
                subnet_vlans.setdefault(key, set()).add(vlan)
            ip_groups.setdefault((vrf, ip), set()).add(group)

        # ── 2. Cloud resources (no VRF concept — keyed with vrf="") ─────────
        cloud_keys: set[tuple[str, str]] = set()
        subnet_cloud_count: dict[tuple[str, str], int] = {}

        if include_cloud:
            cursor = await db.execute(
                """SELECT DISTINCT cr.cidr
                   FROM cloud_resources cr
                   WHERE cr.cidr != '' AND cr.cidr IS NOT NULL"""
            )
            cloud_rows = await cursor.fetchall()
            for row in cloud_rows:
                cidr = row[0].strip()
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    sn = str(net)
                except ValueError:
                    continue
                k = (sn, "")
                cloud_keys.add(k)
                subnet_cloud_count[k] = subnet_cloud_count.get(k, 0) + 1

        # ── 3. External IPAM prefixes (carry their own VRF) ─────────────────
        external_keys: set[tuple[str, str]] = set()
        local_keys: set[tuple[str, str]] = set()
        key_vlans: dict[tuple[str, str], set[str]] = {}
        subnet_ext_prefix_count: dict[tuple[str, str], int] = {}
        subnet_ext_alloc_count: dict[tuple[str, str], int] = {}

        if include_external:
            cursor = await db.execute(
                """SELECT p.subnet, p.vrf, p.vlan, s.provider
                   FROM ipam_prefixes p
                   JOIN ipam_sources s ON s.id = p.source_id
                   WHERE p.subnet != '' AND p.subnet IS NOT NULL"""
            )
            ext_prefix_rows = rows_to_list(await cursor.fetchall())
            for row in ext_prefix_rows:
                sn = row["subnet"].strip()
                vrf = (row.get("vrf") or "").strip()
                vlan = (row.get("vlan") or "").strip()
                k = (sn, vrf)
                if vlan:
                    key_vlans.setdefault(k, set()).add(vlan)
                if row["provider"] == "plexus":
                    local_keys.add(k)
                else:
                    external_keys.add(k)
                    subnet_ext_prefix_count[k] = subnet_ext_prefix_count.get(k, 0) + 1

            cursor = await db.execute(
                """SELECT p.subnet, p.vrf, COUNT(a.id) AS cnt
                   FROM ipam_prefixes p
                   LEFT JOIN ipam_allocations a
                     ON a.source_id = p.source_id AND a.prefix_subnet = p.subnet
                   GROUP BY p.subnet, p.vrf"""
            )
            alloc_rows = rows_to_list(await cursor.fetchall())
            for row in alloc_rows:
                k = (row["subnet"], (row.get("vrf") or "").strip())
                subnet_ext_alloc_count[k] = (
                    subnet_ext_alloc_count.get(k, 0) + int(row.get("cnt") or 0)
                )

        # ── 4. Merge all (subnet, vrf) keys ─────────────────────────────────
        inventory_keys = set(subnet_hosts.keys())
        all_keys: set[tuple[str, str]] = (
            inventory_keys | cloud_keys | external_keys | local_keys
        )
        # Exact overlap is now inventory∩cloud per (subnet, vrf); cloud always vrf=""
        exact_overlaps = {sn for (sn, v) in inventory_keys if (sn, "") in cloud_keys and v == ""}

        subnets_out: list[dict] = []
        for k in sorted(all_keys):
            sn, vrf = k
            hosts_in = subnet_hosts.get(k, [])
            unique_ips = {h["ip"] for h in hosts_in}
            group_names = sorted({h["group"] for h in hosts_in})
            vlans = sorted(subnet_vlans.get(k, set()) | key_vlans.get(k, set()))
            src_types: list[str] = []
            if k in inventory_keys:
                src_types.append("inventory")
            if k in cloud_keys:
                src_types.append("cloud")
            if k in local_keys:
                src_types.append("local")
            if k in external_keys:
                src_types.append("external")
            try:
                net = ipaddress.ip_network(sn, strict=False)
                total = net.num_addresses
                usable = max(0, total - 2) if net.prefixlen < 31 else total
            except ValueError:
                total = usable = 0
            used = len(unique_ips)
            utilization_pct = round((used / usable * 100), 1) if usable else 0.0
            subnets_out.append({
                "subnet": sn,
                "vrf_name": vrf,
                "vlan_ids": vlans,
                "inventory_host_count": len(hosts_in),
                "cloud_resource_count": subnet_cloud_count.get(k, 0),
                "external_prefix_count": subnet_ext_prefix_count.get(k, 0),
                "external_allocation_count": subnet_ext_alloc_count.get(k, 0),
                "group_names": group_names,
                "source_types": src_types,
                "used_count": used,
                "total_count": usable,
                "utilization_pct": utilization_pct,
            })

        # ── 5. Duplicate IP detection (VRF-aware) ───────────────────────────
        # Same IP in different inventory groups within the same VRF = conflict.
        # Same IP in different VRFs = NOT a conflict.
        duplicates_out: list[dict] = []
        for (vrf, ip), groups in sorted(ip_groups.items()):
            if len(groups) > 1:
                host_count = sum(
                    1 for row in host_rows
                    if row["ip_address"].strip().split("/")[0] == ip
                    and (row.get("vrf_name") or "").strip() == vrf
                )
                duplicates_out.append({
                    "ip_address": ip,
                    "vrf_name": vrf,
                    "host_count": host_count,
                    "groups": sorted(groups),
                })

        # ── 6. Summary ──────────────────────────────────────────────────────
        total_ext_allocs = sum(subnet_ext_alloc_count.values())
        distinct_vrfs = sorted({vrf for (_, vrf) in all_keys if vrf})
        summary: dict = {
            "inventory_host_count": len(host_rows),
            "total_subnets": len(all_keys),
            "inventory_subnets": len(inventory_keys),
            "cloud_subnets": len(cloud_keys),
            "local_subnets": len(local_keys),
            "external_subnets": len(external_keys),
            "duplicate_ip_count": len(duplicates_out),
            "exact_source_overlap_count": len(exact_overlaps),
            "external_allocation_count": total_ext_allocs,
            "vrf_names": distinct_vrfs,
            "vrf_count": len(distinct_vrfs),
        }
        if group_id is not None:
            summary["group_id"] = group_id

        return {
            "summary": summary,
            "subnets": subnets_out,
            "duplicate_ips": duplicates_out,
        }
    finally:
        await db.close()


async def get_ipam_subnet_detail(
    subnet: str,
    group_id: int | None = None,
    include_cloud: bool = True,
    include_external: bool = True,
) -> dict:
    """Return per-subnet utilisation detail: allocations, reservations, available preview."""
    db = await get_db()
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        net_str = str(net)
        prefix_len = net.prefixlen

        # ── Inventory hosts in this subnet ──────────────────────────────────
        if group_id is not None:
            cursor = await db.execute(
                """SELECT h.ip_address, h.hostname, g.name AS group_name
                   FROM hosts h
                   JOIN inventory_groups g ON h.group_id = g.id
                   WHERE h.group_id = ? AND h.ip_address != '' AND h.ip_address IS NOT NULL""",
                (group_id,),
            )
        else:
            cursor = await db.execute(
                """SELECT h.ip_address, h.hostname, g.name AS group_name
                   FROM hosts h
                   JOIN inventory_groups g ON h.group_id = g.id
                   WHERE h.ip_address != '' AND h.ip_address IS NOT NULL"""
            )
        all_host_rows = rows_to_list(await cursor.fetchall())

        inv_in_subnet: list[dict] = []
        for row in all_host_rows:
            ip_s = row["ip_address"].strip().split("/")[0]
            try:
                addr = ipaddress.ip_address(ip_s)
                if addr in net:
                    inv_in_subnet.append({"ip": ip_s, "hostname": row["hostname"], "group": row["group_name"]})
            except ValueError:
                continue

        # ── Custom reservations ─────────────────────────────────────────────
        cursor = await db.execute(
            "SELECT * FROM ipam_reservations WHERE subnet = ? ORDER BY start_ip",
            (net_str,),
        )
        raw_reservations = rows_to_list(await cursor.fetchall())

        # ── External and local allocations for this prefix ─────────────────
        ext_allocs: list[dict] = []
        if include_external:
            cursor = await db.execute(
                """SELECT a.address, a.dns_name, a.description, a.metadata_json,
                          s.provider, s.name AS source_name
                   FROM ipam_allocations a
                   JOIN ipam_sources s ON s.id = a.source_id
                   WHERE a.prefix_subnet = ?""",
                (net_str,),
            )
            ext_allocs = rows_to_list(await cursor.fetchall())

        # ── Utilisation math ────────────────────────────────────────────────
        if prefix_len >= 31:
            usable = net.num_addresses
        else:
            usable = net.num_addresses - 2  # exclude network + broadcast

        # Count IPs covered by reservations
        reserved_ips: set[str] = set()
        for rsv in raw_reservations:
            try:
                start = ipaddress.ip_address(rsv["start_ip"])
                end = ipaddress.ip_address(rsv["end_ip"])
                cur_ip = start
                while cur_ip <= end:
                    reserved_ips.add(str(cur_ip))
                    cur_ip += 1
            except ValueError:
                continue

        reserved_count = len(reserved_ips)

        # Unique inventory IPs in subnet
        inv_unique_ips: set[str] = {h["ip"] for h in inv_in_subnet}
        # External allocation IPs
        ext_unique_ips: set[str] = set()
        for ea in ext_allocs:
            ip_s = (ea.get("address") or "").strip()
            try:
                if ipaddress.ip_address(ip_s) in net:
                    ext_unique_ips.add(ip_s)
            except ValueError:
                continue

        # Allocated = unique IPs from all sources NOT already counted as reserved
        allocated_ips = (inv_unique_ips | ext_unique_ips) - reserved_ips
        allocated_count = len(allocated_ips)

        available_count = max(0, usable - reserved_count - allocated_count)

        # ── Build allocations list ──────────────────────────────────────────
        allocations_out: list[dict] = []

        # Inventory entries (include even if reserved — flag them)
        for h in inv_in_subnet:
            ip_s = h["ip"]
            allocations_out.append({
                "ip_address": ip_s,
                "source_type": "inventory",
                "hostname": h["hostname"],
                "group_name": h["group"],
                "description": "",
                "is_reserved": ip_s in reserved_ips,
                "allocation_id": None,
            })

        # External allocations
        for ea in ext_allocs:
            ip_s = (ea.get("address") or "").strip()
            provider = ea.get("provider") or ""
            source_type = "local" if provider == "plexus" else "external"
            allocations_out.append({
                "ip_address": ip_s,
                "source_type": source_type,
                "hostname": ea.get("dns_name") or "",
                "group_name": ea.get("source_name") or "",
                "description": ea.get("description") or "",
                "is_reserved": ip_s in reserved_ips,
                "allocation_id": ea.get("id"),
            })

        # Sort by IP
        def _ip_sort_key(item: dict):
            try:
                return int(ipaddress.ip_address(item["ip_address"]))
            except ValueError:
                return 0

        allocations_out.sort(key=_ip_sort_key)

        # ── Reservations list with address_count ────────────────────────────
        reservations_out: list[dict] = []
        for rsv in raw_reservations:
            try:
                start = ipaddress.ip_address(rsv["start_ip"])
                end = ipaddress.ip_address(rsv["end_ip"])
                addr_count = max(0, int(end) - int(start) + 1)
            except ValueError:
                addr_count = 0
            reservations_out.append({
                "id": rsv.get("id"),
                "kind": "custom",
                "subnet": rsv.get("subnet"),
                "start_ip": rsv.get("start_ip"),
                "end_ip": rsv.get("end_ip"),
                "address_count": addr_count,
                "reason": rsv.get("reason") or "",
                "created_by": rsv.get("created_by") or "",
                "created_at": rsv.get("created_at"),
            })

        # ── Available preview (first N free IPs) ────────────────────────────
        occupied = reserved_ips | inv_unique_ips | ext_unique_ips
        available_preview: list[str] = []
        for addr in net.hosts():
            if len(available_preview) >= 20:
                break
            if str(addr) not in occupied:
                available_preview.append(str(addr))

        summary_out = {
            "subnet": net_str,
            "prefix_length": prefix_len,
            "inventory_host_count": len(inv_in_subnet),
            "external_allocation_count": len(ext_allocs),
            "usable_address_count": usable,
            "reserved_address_count": reserved_count,
            "allocated_address_count": allocated_count,
            "available_address_count": available_count,
        }

        return {
            "subnet": net_str,
            "summary": summary_out,
            "allocations": allocations_out,
            "reservations": reservations_out,
            "available_preview": available_preview,
        }
    finally:
        await db.close()


def _serialize_ipam_source(row: dict) -> dict:
    return {
        "id": row.get("id"),
        "provider": row.get("provider"),
        "name": row.get("name"),
        "base_url": row.get("base_url") or "",
        "auth_type": row.get("auth_type") or "",
        "sync_scope": row.get("sync_scope") or "",
        "notes": row.get("notes") or "",
        "enabled": bool(row.get("enabled")),
        "push_enabled": bool(row.get("push_enabled", 0)),
        "verify_tls": bool(row.get("verify_tls", 1)),
        "last_sync_at": row.get("last_sync_at"),
        "last_sync_status": row.get("last_sync_status") or "never",
        "last_sync_message": row.get("last_sync_message") or "",
        "created_by": row.get("created_by") or "",
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "prefix_count": int(row.get("prefix_count") or 0),
        "allocation_count": int(row.get("allocation_count") or 0),
        "has_auth_config": bool(row.get("auth_config_enc")),
    }


async def list_ipam_sources(
    provider: str | None = None,
    enabled_only: bool = False,
) -> list[dict]:
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if provider:
            clauses.append("s.provider = ?")
            params.append(provider)
        if enabled_only:
            clauses.append("s.enabled = 1")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT s.*,
                       (SELECT COUNT(*) FROM ipam_prefixes p WHERE p.source_id = s.id) AS prefix_count,
                       (SELECT COUNT(*) FROM ipam_allocations a WHERE a.source_id = s.id) AS allocation_count
                FROM ipam_sources s
                {where}
                ORDER BY s.provider ASC, s.name ASC""",
            tuple(params),
        )
        return [_serialize_ipam_source(dict(r)) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def create_ipam_source(
    provider: str,
    name: str,
    base_url: str = "",
    auth_type: str = "none",
    auth_config: dict | None = None,
    sync_scope: str = "",
    notes: str = "",
    enabled: bool = True,
    push_enabled: bool = False,
    verify_tls: bool = True,
    created_by: str = "",
) -> dict | None:
    from routes.crypto import encrypt as _enc

    auth_config_enc = ""
    if auth_config:
        auth_config_enc = _enc(json.dumps(auth_config, separators=(",", ":")))

    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO ipam_sources
               (provider, name, base_url, auth_type, auth_config_enc,
                sync_scope, notes, enabled, push_enabled, verify_tls, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                provider,
                name,
                base_url,
                auth_type,
                auth_config_enc,
                sync_scope,
                notes,
                int(bool(enabled)),
                int(bool(push_enabled)),
                int(bool(verify_tls)),
                created_by,
            ),
        )
        await db.commit()
        return await get_ipam_source(cursor.lastrowid)
    finally:
        await db.close()


async def get_ipam_source(source_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT s.*,
                      (SELECT COUNT(*) FROM ipam_prefixes p WHERE p.source_id = s.id) AS prefix_count,
                      (SELECT COUNT(*) FROM ipam_allocations a WHERE a.source_id = s.id) AS allocation_count
               FROM ipam_sources s
               WHERE s.id = ?""",
            (source_id,),
        )
        row = await cursor.fetchone()
        return _serialize_ipam_source(dict(row)) if row else None
    finally:
        await db.close()


async def get_ipam_source_auth_config(source_id: int) -> dict:
    """Return the decrypted auth_config dict for an IPAM source."""
    from routes.crypto import decrypt as _dec

    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT auth_config_enc FROM ipam_sources WHERE id = ?",
            (source_id,),
        )
        row = await cursor.fetchone()
        if not row or not row[0]:
            return {}
        try:
            return json.loads(_dec(row[0]))
        except Exception:
            return {}
    finally:
        await db.close()


async def update_ipam_source(source_id: int, **kwargs) -> dict | None:
    from routes.crypto import encrypt as _enc

    allowed = {
        "provider", "name", "base_url", "auth_type", "sync_scope",
        "notes", "enabled", "push_enabled", "verify_tls", "last_sync_at",
        "last_sync_status", "last_sync_message",
    }
    sets: list[str] = []
    vals: list = []

    # Handle auth_config dict separately (needs encryption)
    auth_config = kwargs.pop("auth_config", None)
    if auth_config is not None:
        enc = _enc(json.dumps(auth_config, separators=(",", ":")))
        sets.append("auth_config_enc = ?")
        vals.append(enc)

    for key, value in kwargs.items():
        if key not in allowed or value is None:
            continue
        if key in ("enabled", "push_enabled", "verify_tls"):
            value = int(bool(value))
        sets.append(f"{key} = ?")
        vals.append(value)

    if not sets:
        return await get_ipam_source(source_id)

    sets.append("updated_at = datetime('now')")
    db = await get_db()
    try:
        sql, sql_params = _safe_dynamic_update("ipam_sources", sets, vals, "id = ?", source_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_ipam_source(source_id)
    finally:
        await db.close()


async def delete_ipam_source(source_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM ipam_sources WHERE id = ?", (source_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def replace_ipam_source_snapshot(
    source_id: int,
    prefixes: list[dict],
    allocations: list[dict],
    sync_status: str = "success",
    sync_message: str = "",
) -> dict:
    """Replace all prefixes/allocations for a source and update sync status."""
    db = await get_db()
    try:
        # Clear existing snapshot data
        await db.execute("DELETE FROM ipam_prefixes WHERE source_id = ?", (source_id,))
        await db.execute("DELETE FROM ipam_allocations WHERE source_id = ?", (source_id,))

        prefix_count = 0
        for pref in prefixes:
            subnet = (pref.get("subnet") or "").strip()
            if not subnet:
                continue
            external_id = str(pref.get("external_id") or pref.get("id") or "")
            await db.execute(
                """INSERT OR IGNORE INTO ipam_prefixes
                   (source_id, external_id, subnet, description, vrf, vlan, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    source_id,
                    external_id,
                    subnet,
                    pref.get("description") or "",
                    pref.get("vrf") or "",
                    str(pref.get("vlan") or ""),
                    json.dumps(pref.get("metadata") or {}, separators=(",", ":")),
                ),
            )
            prefix_count += 1

        # Build a (subnet -> {vrf, vlan}) map to inherit context for allocations
        # whose source data does not carry VRF/VLAN explicitly.
        prefix_ctx: dict[str, dict[str, str]] = {}
        for pref in prefixes:
            sn = (pref.get("subnet") or "").strip()
            if not sn:
                continue
            prefix_ctx.setdefault(sn, {
                "vrf": str(pref.get("vrf") or ""),
                "vlan": str(pref.get("vlan") or ""),
            })

        alloc_count = 0
        for alloc in allocations:
            address = (alloc.get("address") or "").strip()
            if not address:
                continue
            prefix_subnet = (alloc.get("prefix_subnet") or "").strip()
            ctx = prefix_ctx.get(prefix_subnet, {})
            vrf_name = str(alloc.get("vrf") or alloc.get("vrf_name") or ctx.get("vrf") or "")
            vlan_id = str(alloc.get("vlan") or alloc.get("vlan_id") or ctx.get("vlan") or "")
            await db.execute(
                """INSERT OR IGNORE INTO ipam_allocations
                   (source_id, prefix_subnet, address, dns_name, status, description,
                    vrf_name, vlan_id, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    source_id,
                    prefix_subnet,
                    address,
                    alloc.get("dns_name") or "",
                    alloc.get("status") or "",
                    alloc.get("description") or "",
                    vrf_name,
                    vlan_id,
                    json.dumps(alloc.get("metadata") or {}, separators=(",", ":")),
                ),
            )
            alloc_count += 1

        now_iso = datetime.now(UTC).isoformat()
        await db.execute(
            """UPDATE ipam_sources
               SET last_sync_at = ?,
                   last_sync_status = ?,
                   last_sync_message = ?,
                   updated_at = ?
               WHERE id = ?""",
            (now_iso, sync_status, sync_message, now_iso, source_id),
        )
        await db.commit()
        return {"prefixes": prefix_count, "allocations": alloc_count}
    finally:
        await db.close()


async def set_ipam_source_sync_status(
    source_id: int,
    status: str,
    message: str = "",
) -> None:
    """Update only the sync status fields of an IPAM source."""
    db = await get_db()
    try:
        now_iso = datetime.now(UTC).isoformat()
        await db.execute(
            """UPDATE ipam_sources
               SET last_sync_status = ?,
                   last_sync_message = ?,
                   last_sync_at = ?,
                   updated_at = ?
               WHERE id = ?""",
            (status, message, now_iso, now_iso, source_id),
        )
        await db.commit()
    finally:
        await db.close()


async def list_ipam_reservations(subnet: str) -> list[dict]:
    """Return all custom reservations for a subnet."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        subnet_key = str(net)
    except ValueError:
        subnet_key = subnet

    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM ipam_reservations WHERE subnet = ? ORDER BY start_ip",
            (subnet_key,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def create_ipam_reservation(
    subnet: str,
    start_ip: str,
    end_ip: str,
    reason: str = "",
    created_by: str = "",
) -> dict | None:
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        subnet_key = str(net)
    except ValueError:
        subnet_key = subnet

    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO ipam_reservations (subnet, start_ip, end_ip, reason, created_by)
               VALUES (?, ?, ?, ?, ?)""",
            (subnet_key, start_ip, end_ip, reason, created_by),
        )
        await db.commit()
        rsv_id = cursor.lastrowid
        cursor2 = await db.execute(
            "SELECT * FROM ipam_reservations WHERE id = ?", (rsv_id,)
        )
        row = await cursor2.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def delete_ipam_reservation(reservation_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM ipam_reservations WHERE id = ?", (reservation_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_or_create_builtin_ipam_source() -> dict:
    """Return the built-in Plexus IPAM source, creating it idempotently on first call."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM ipam_sources WHERE provider = 'plexus' LIMIT 1"
        )
        row = await cursor.fetchone()
        if row:
            return _serialize_ipam_source(dict(row))
    finally:
        await db.close()
    # Create the built-in source
    return await create_ipam_source(
        provider="plexus",
        name="Plexus (Built-in)",
        base_url="",
        auth_type="none",
        auth_config={},
        sync_scope="",
        notes="Managed directly by Plexus. Subnets and allocations defined here are authoritative.",
        enabled=True,
        verify_tls=True,
        created_by="system",
    )


async def create_ipam_prefix(
    source_id: int,
    subnet: str,
    description: str = "",
    vrf: str = "",
    notes: str = "",
) -> dict | None:
    """Create a manually-defined subnet prefix under the given IPAM source."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        subnet_key = str(net)
    except ValueError:
        return None

    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT OR IGNORE INTO ipam_prefixes
               (source_id, external_id, subnet, description, vrf, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (source_id, subnet_key, subnet_key, description, vrf, json.dumps({"notes": notes})),
        )
        await db.commit()
        prefix_id = cursor.lastrowid
        if not prefix_id:
            # Already existed — fetch it
            cursor2 = await db.execute(
                "SELECT * FROM ipam_prefixes WHERE source_id = ? AND subnet = ? LIMIT 1",
                (source_id, subnet_key),
            )
            row = await cursor2.fetchone()
            return dict(row) if row else None
        cursor3 = await db.execute(
            "SELECT * FROM ipam_prefixes WHERE id = ?", (prefix_id,)
        )
        row = await cursor3.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def get_ipam_prefix(prefix_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM ipam_prefixes WHERE id = ?", (prefix_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def delete_ipam_prefix(prefix_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM ipam_prefixes WHERE id = ?", (prefix_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def create_local_ipam_allocation(
    source_id: int,
    subnet: str,
    address: str,
    hostname: str = "",
    description: str = "",
    created_by: str = "",
) -> dict | None:
    """Manually record an IP address allocation within a subnet."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        subnet_key = str(net)
        ipaddress.ip_address(address)  # validate
    except ValueError:
        return None

    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT OR IGNORE INTO ipam_allocations
               (source_id, prefix_subnet, address, dns_name, status, description, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                source_id,
                subnet_key,
                address,
                hostname,
                "active",
                description,
                json.dumps({"created_by": created_by}),
            ),
        )
        await db.commit()
        alloc_id = cursor.lastrowid
        if not alloc_id:
            cursor2 = await db.execute(
                "SELECT * FROM ipam_allocations WHERE source_id = ? AND address = ? LIMIT 1",
                (source_id, address),
            )
            row = await cursor2.fetchone()
            return dict(row) if row else None
        cursor3 = await db.execute(
            "SELECT * FROM ipam_allocations WHERE id = ?", (alloc_id,)
        )
        row = await cursor3.fetchone()
        result = dict(row) if row else None
    finally:
        await db.close()
    if result:
        try:
            await record_ip_assignment(
                address=address, hostname=hostname or "",
                vrf_name=(result.get("vrf_name") or "").strip(),
                source_type="ipam_allocation",
                source_ref=str(result.get("id") or ""),
                recorded_by=created_by or "",
                note=description or "",
            )
        except Exception:
            pass
    return result


async def delete_ipam_allocation(allocation_id: int) -> bool:
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT address, vrf_name FROM ipam_allocations WHERE id = ?",
            (allocation_id,),
        )
        prior = await cur.fetchone()
        prior_d = dict(prior) if prior else {}
        cursor = await db.execute(
            "DELETE FROM ipam_allocations WHERE id = ?", (allocation_id,)
        )
        await db.commit()
        deleted = cursor.rowcount > 0
    finally:
        await db.close()
    if deleted and prior_d.get("address"):
        try:
            await record_ip_release(
                address=prior_d["address"],
                vrf_name=(prior_d.get("vrf_name") or "").strip(),
                note="ipam allocation deleted",
            )
        except Exception:
            pass
    return deleted


async def list_ipam_allocations_for_source(source_id: int) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, source_id, prefix_subnet, address, dns_name,
                      status, description, metadata_json, discovered_at
               FROM ipam_allocations
               WHERE source_id = ?
               ORDER BY address""",
            (source_id,),
        )
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


# ─────────────────────────────────────────────────────────────────────────────
# IPAM-driven provisioning (Phase H) – next-IP allocation w/ pending state
# ─────────────────────────────────────────────────────────────────────────────


def _serialize_pending_allocation(row: dict) -> dict:
    return {
        "id": int(row.get("id") or 0),
        "subnet": row.get("subnet") or "",
        "address": row.get("address") or "",
        "vrf_name": row.get("vrf_name") or "",
        "hostname": row.get("hostname") or "",
        "description": row.get("description") or "",
        "source_id": (int(row["source_id"]) if row.get("source_id") else None),
        "external_ref": row.get("external_ref") or "",
        "state": row.get("state") or "pending",
        "expires_at": row.get("expires_at"),
        "created_by": row.get("created_by") or "",
        "created_at": row.get("created_at"),
        "committed_at": row.get("committed_at"),
        "released_at": row.get("released_at"),
    }


async def _occupied_ips_for_subnet(
    db, subnet: str, vrf_name: str
) -> set[str]:
    """Return the set of IPs already taken in this subnet+vrf.

    Combines:
      - inventory hosts (filtered to subnet, matching vrf if non-empty)
      - external/local IPAM allocations under this prefix (matching vrf when set)
      - reservations (start..end ranges)
      - active pending allocations that have not expired
    """
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return set()
    occupied: set[str] = set()

    cursor = await db.execute(
        "SELECT ip_address, vrf_name FROM hosts WHERE ip_address != '' AND ip_address IS NOT NULL"
    )
    for row in rows_to_list(await cursor.fetchall()):
        ip_s = (row["ip_address"] or "").strip().split("/")[0]
        h_vrf = (row.get("vrf_name") or "").strip()
        if vrf_name and h_vrf != vrf_name:
            continue
        try:
            if ipaddress.ip_address(ip_s) in net:
                occupied.add(ip_s)
        except ValueError:
            continue

    cursor = await db.execute(
        "SELECT address, vrf_name FROM ipam_allocations WHERE prefix_subnet = ?",
        (str(net),),
    )
    for row in rows_to_list(await cursor.fetchall()):
        a_vrf = (row.get("vrf_name") or "").strip()
        if vrf_name and a_vrf and a_vrf != vrf_name:
            continue
        ip_s = (row.get("address") or "").strip()
        if ip_s:
            occupied.add(ip_s)

    cursor = await db.execute(
        "SELECT start_ip, end_ip FROM ipam_reservations WHERE subnet = ?",
        (str(net),),
    )
    for row in rows_to_list(await cursor.fetchall()):
        try:
            start = ipaddress.ip_address(row["start_ip"])
            end = ipaddress.ip_address(row["end_ip"])
            cur_ip = start
            while cur_ip <= end:
                occupied.add(str(cur_ip))
                cur_ip += 1
        except ValueError:
            continue

    cursor = await db.execute(
        """SELECT address, vrf_name, expires_at FROM ipam_pending_allocations
           WHERE state = 'pending' AND subnet = ?""",
        (str(net),),
    )
    now_iso = datetime.now(UTC).replace(tzinfo=None).isoformat()
    for row in rows_to_list(await cursor.fetchall()):
        p_vrf = (row.get("vrf_name") or "").strip()
        if vrf_name and p_vrf != vrf_name:
            continue
        exp = row.get("expires_at") or ""
        if exp and exp < now_iso:
            continue
        ip_s = (row.get("address") or "").strip()
        if ip_s:
            occupied.add(ip_s)

    return occupied


async def allocate_next_ip(
    *,
    subnet: str,
    vrf_name: str = "",
    hostname: str = "",
    description: str = "",
    source_id: int | None = None,
    ttl_seconds: int = 900,
    created_by: str = "",
) -> dict:
    """Reserve the first available IP in `subnet` and persist a pending row.

    Raises ValueError on bad subnet or when no addresses are available.
    Returns a serialized pending-allocation dict including `address` and `id`.
    """
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid subnet: {subnet}") from exc

    vrf_name = (vrf_name or "").strip()
    ttl = max(60, min(86400, int(ttl_seconds or 900)))
    expires_at = (datetime.now(UTC).replace(tzinfo=None) + timedelta(seconds=ttl)).isoformat()

    db = await get_db()
    try:
        occupied = await _occupied_ips_for_subnet(db, str(net), vrf_name)

        chosen: str | None = None
        if net.prefixlen == 32 or net.prefixlen == 128:
            candidate_iter = iter([net.network_address])
        else:
            candidate_iter = net.hosts()
        for addr in candidate_iter:
            s = str(addr)
            if s not in occupied:
                chosen = s
                break

        if chosen is None:
            raise ValueError(f"No available addresses in {net}")

        cursor = await db.execute(
            """INSERT INTO ipam_pending_allocations
                  (subnet, address, vrf_name, hostname, description,
                   source_id, state, expires_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
            (
                str(net),
                chosen,
                vrf_name,
                hostname or "",
                description or "",
                int(source_id) if source_id else None,
                expires_at,
                created_by or "",
            ),
        )
        await db.commit()
        pid = cursor.lastrowid
        cur2 = await db.execute(
            "SELECT * FROM ipam_pending_allocations WHERE id = ?", (pid,)
        )
        row = await cur2.fetchone()
        return _serialize_pending_allocation(dict(row)) if row else {
            "id": pid, "address": chosen, "subnet": str(net), "vrf_name": vrf_name,
            "state": "pending", "expires_at": expires_at,
        }
    finally:
        await db.close()


async def get_pending_allocation(allocation_id: int) -> dict | None:
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT * FROM ipam_pending_allocations WHERE id = ?", (int(allocation_id),)
        )
        row = await cur.fetchone()
        return _serialize_pending_allocation(dict(row)) if row else None
    finally:
        await db.close()


async def list_pending_allocations(
    state: str | None = None, include_expired: bool = False, limit: int = 200
) -> list[dict]:
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if state:
            clauses.append("state = ?")
            params.append(state)
        if state == "pending" and not include_expired:
            clauses.append("expires_at >= ?")
            params.append(datetime.now(UTC).replace(tzinfo=None).isoformat())
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(int(limit))
        cur = await db.execute(
            f"SELECT * FROM ipam_pending_allocations{where} "
            f"ORDER BY created_at DESC LIMIT ?",
            tuple(params),
        )
        rows = rows_to_list(await cur.fetchall())
        return [_serialize_pending_allocation(r) for r in rows]
    finally:
        await db.close()


async def update_pending_allocation_state(
    allocation_id: int,
    *,
    state: str,
    external_ref: str | None = None,
    source_id: int | None = None,
) -> dict | None:
    """Mark a pending allocation as committed or released."""
    if state not in ("committed", "released"):
        raise ValueError("state must be 'committed' or 'released'")
    ts_col = "committed_at" if state == "committed" else "released_at"
    db = await get_db()
    try:
        sets: list[str] = ["state = ?", f"{ts_col} = ?"]
        params: list = [state, datetime.now(UTC).replace(tzinfo=None).isoformat()]
        if external_ref is not None:
            sets.append("external_ref = ?")
            params.append(external_ref)
        if source_id is not None:
            sets.append("source_id = ?")
            params.append(int(source_id))
        params.append(int(allocation_id))
        await db.execute(
            f"UPDATE ipam_pending_allocations SET {', '.join(sets)} WHERE id = ?",
            tuple(params),
        )
        await db.commit()
        cur = await db.execute(
            "SELECT * FROM ipam_pending_allocations WHERE id = ?", (int(allocation_id),)
        )
        row = await cur.fetchone()
        return _serialize_pending_allocation(dict(row)) if row else None
    finally:
        await db.close()


async def expire_stale_pending_allocations() -> int:
    """Mark expired pending rows as released. Returns number of rows updated."""
    db = await get_db()
    try:
        now_iso = datetime.now(UTC).replace(tzinfo=None).isoformat()
        cur = await db.execute(
            """UPDATE ipam_pending_allocations
               SET state = 'released', released_at = ?
               WHERE state = 'pending' AND expires_at < ?""",
            (now_iso, now_iso),
        )
        await db.commit()
        return int(cur.rowcount or 0)
    finally:
        await db.close()


# ─────────────────────────────────────────────────────────────────────────────
# Historical IP allocation tracking (Phase I)
# ─────────────────────────────────────────────────────────────────────────────


def _serialize_ip_history(row: dict) -> dict:
    return {
        "id": int(row.get("id") or 0),
        "address": row.get("address") or "",
        "vrf_name": row.get("vrf_name") or "",
        "hostname": row.get("hostname") or "",
        "source_type": row.get("source_type") or "",
        "source_ref": row.get("source_ref") or "",
        "started_at": row.get("started_at"),
        "ended_at": row.get("ended_at"),
        "recorded_by": row.get("recorded_by") or "",
        "note": row.get("note") or "",
    }


def _serialize_subnet_utilization(row: dict) -> dict:
    return {
        "id": int(row.get("id") or 0),
        "subnet": row.get("subnet") or "",
        "vrf_name": row.get("vrf_name") or "",
        "total": int(row.get("total") or 0),
        "used": int(row.get("used") or 0),
        "reserved": int(row.get("reserved") or 0),
        "pending": int(row.get("pending") or 0),
        "free": int(row.get("free") or 0),
        "utilization_pct": float(row.get("utilization_pct") or 0.0),
        "captured_at": row.get("captured_at"),
    }


async def record_ip_assignment(
    *,
    address: str,
    hostname: str = "",
    vrf_name: str = "",
    source_type: str = "",
    source_ref: str = "",
    recorded_by: str = "",
    note: str = "",
) -> dict | None:
    """Record that `address` (in optional VRF) is now assigned to `hostname`.

    Closes any existing open history row for the same (address, vrf) before
    inserting the new open row, so the timeline stays consistent. No-op if
    the address is already open with the same hostname/source.
    """
    address = (address or "").strip()
    if not address:
        return None
    try:
        ipaddress.ip_address(address.split("/")[0])
    except ValueError:
        return None
    vrf_name = (vrf_name or "").strip()
    now_iso = datetime.now(UTC).replace(tzinfo=None).isoformat()

    db = await get_db()
    try:
        cur = await db.execute(
            """SELECT id, hostname, source_type, source_ref FROM ipam_ip_history
               WHERE address = ? AND vrf_name = ? AND ended_at IS NULL
               ORDER BY started_at DESC LIMIT 1""",
            (address, vrf_name),
        )
        existing = await cur.fetchone()
        if existing:
            existing_d = dict(existing)
            if (
                (existing_d.get("hostname") or "") == hostname
                and (existing_d.get("source_type") or "") == source_type
                and (existing_d.get("source_ref") or "") == source_ref
            ):
                cur2 = await db.execute(
                    "SELECT * FROM ipam_ip_history WHERE id = ?", (existing_d["id"],)
                )
                row = await cur2.fetchone()
                return _serialize_ip_history(dict(row)) if row else None
            await db.execute(
                "UPDATE ipam_ip_history SET ended_at = ? WHERE id = ?",
                (now_iso, existing_d["id"]),
            )

        cur3 = await db.execute(
            """INSERT INTO ipam_ip_history
                  (address, vrf_name, hostname, source_type, source_ref,
                   started_at, recorded_by, note)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                address,
                vrf_name,
                hostname or "",
                source_type or "",
                source_ref or "",
                now_iso,
                recorded_by or "",
                note or "",
            ),
        )
        await db.commit()
        new_id = cur3.lastrowid
        cur4 = await db.execute(
            "SELECT * FROM ipam_ip_history WHERE id = ?", (new_id,)
        )
        row = await cur4.fetchone()
        return _serialize_ip_history(dict(row)) if row else None
    finally:
        await db.close()


async def record_ip_release(
    *,
    address: str,
    vrf_name: str = "",
    recorded_by: str = "",
    note: str = "",
) -> int:
    """Close the open history row for (address, vrf). Returns rows updated."""
    address = (address or "").strip()
    if not address:
        return 0
    vrf_name = (vrf_name or "").strip()
    now_iso = datetime.now(UTC).replace(tzinfo=None).isoformat()
    db = await get_db()
    try:
        cur = await db.execute(
            """UPDATE ipam_ip_history
               SET ended_at = ?,
                   note = CASE WHEN ? = '' THEN note ELSE ? END
               WHERE address = ? AND vrf_name = ? AND ended_at IS NULL""",
            (now_iso, note or "", note or "", address, vrf_name),
        )
        # recorded_by is intentionally not stored on release — it's an event,
        # not a new assignment. Caller can pass via note if needed.
        _ = recorded_by
        await db.commit()
        return int(cur.rowcount or 0)
    finally:
        await db.close()


async def get_ip_history(
    address: str,
    vrf_name: str = "",
    limit: int = 100,
) -> list[dict]:
    """Return assignment history for an IP, newest first."""
    address = (address or "").strip()
    if not address:
        return []
    vrf_name = (vrf_name or "").strip()
    db = await get_db()
    try:
        cur = await db.execute(
            """SELECT * FROM ipam_ip_history
               WHERE address = ? AND vrf_name = ?
               ORDER BY started_at DESC LIMIT ?""",
            (address, vrf_name, int(limit)),
        )
        rows = rows_to_list(await cur.fetchall())
        return [_serialize_ip_history(r) for r in rows]
    finally:
        await db.close()


async def find_ip_owner_at(
    address: str,
    when_iso: str,
    vrf_name: str = "",
) -> dict | None:
    """Who held `address` at timestamp `when_iso`? Returns the matching history row or None."""
    address = (address or "").strip()
    when_iso = (when_iso or "").strip()
    if not address or not when_iso:
        return None
    vrf_name = (vrf_name or "").strip()
    db = await get_db()
    try:
        cur = await db.execute(
            """SELECT * FROM ipam_ip_history
               WHERE address = ? AND vrf_name = ?
                 AND started_at <= ?
                 AND (ended_at IS NULL OR ended_at >= ?)
               ORDER BY started_at DESC LIMIT 1""",
            (address, vrf_name, when_iso, when_iso),
        )
        row = await cur.fetchone()
        return _serialize_ip_history(dict(row)) if row else None
    finally:
        await db.close()


async def list_ip_history_for_hostname(
    hostname: str, limit: int = 200
) -> list[dict]:
    """All IPs ever assigned to `hostname`, newest first."""
    hostname = (hostname or "").strip()
    if not hostname:
        return []
    db = await get_db()
    try:
        cur = await db.execute(
            """SELECT * FROM ipam_ip_history
               WHERE hostname = ?
               ORDER BY started_at DESC LIMIT ?""",
            (hostname, int(limit)),
        )
        rows = rows_to_list(await cur.fetchall())
        return [_serialize_ip_history(r) for r in rows]
    finally:
        await db.close()


async def snapshot_subnet_utilization(
    subnet: str, vrf_name: str = ""
) -> dict | None:
    """Compute utilization for a subnet+vrf and persist a time-series row."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return None
    vrf_name = (vrf_name or "").strip()
    sn = str(net)

    if net.prefixlen == 32 or net.prefixlen == 128:
        total = 1
        host_iter = [net.network_address]
    else:
        total = max(0, net.num_addresses - 2)
        host_iter = list(net.hosts())
    host_set = {str(h) for h in host_iter}

    db = await get_db()
    try:
        used_set: set[str] = set()
        cur = await db.execute(
            "SELECT ip_address, vrf_name FROM hosts WHERE ip_address != '' AND ip_address IS NOT NULL"
        )
        for row in rows_to_list(await cur.fetchall()):
            ip_s = (row["ip_address"] or "").strip().split("/")[0]
            h_vrf = (row.get("vrf_name") or "").strip()
            if vrf_name and h_vrf != vrf_name:
                continue
            if ip_s in host_set:
                used_set.add(ip_s)

        cur = await db.execute(
            "SELECT address, vrf_name FROM ipam_allocations WHERE prefix_subnet = ?",
            (sn,),
        )
        for row in rows_to_list(await cur.fetchall()):
            a_vrf = (row.get("vrf_name") or "").strip()
            if vrf_name and a_vrf and a_vrf != vrf_name:
                continue
            ip_s = (row.get("address") or "").strip()
            if ip_s in host_set:
                used_set.add(ip_s)

        reserved_set: set[str] = set()
        cur = await db.execute(
            "SELECT start_ip, end_ip FROM ipam_reservations WHERE subnet = ?",
            (sn,),
        )
        for row in rows_to_list(await cur.fetchall()):
            try:
                start = ipaddress.ip_address(row["start_ip"])
                end = ipaddress.ip_address(row["end_ip"])
                cur_ip = start
                while cur_ip <= end:
                    s = str(cur_ip)
                    if s in host_set:
                        reserved_set.add(s)
                    cur_ip += 1
            except ValueError:
                continue

        pending_set: set[str] = set()
        now_iso = datetime.now(UTC).replace(tzinfo=None).isoformat()
        cur = await db.execute(
            """SELECT address, vrf_name, expires_at FROM ipam_pending_allocations
               WHERE state = 'pending' AND subnet = ?""",
            (sn,),
        )
        for row in rows_to_list(await cur.fetchall()):
            p_vrf = (row.get("vrf_name") or "").strip()
            if vrf_name and p_vrf != vrf_name:
                continue
            exp = row.get("expires_at") or ""
            if exp and exp < now_iso:
                continue
            ip_s = (row.get("address") or "").strip()
            if ip_s in host_set:
                pending_set.add(ip_s)

        # Sets may overlap; deduplicate so counts sum correctly.
        used = len(used_set)
        reserved = len(reserved_set - used_set)
        pending = len(pending_set - used_set - reserved_set)
        consumed = used + reserved + pending
        free = max(0, total - consumed)
        pct = (consumed / total * 100.0) if total > 0 else 0.0

        cur = await db.execute(
            """INSERT INTO ipam_subnet_utilization
                  (subnet, vrf_name, total, used, reserved, pending, free, utilization_pct)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (sn, vrf_name, total, used, reserved, pending, free, pct),
        )
        await db.commit()
        new_id = cur.lastrowid
        cur2 = await db.execute(
            "SELECT * FROM ipam_subnet_utilization WHERE id = ?", (new_id,)
        )
        row = await cur2.fetchone()
        return _serialize_subnet_utilization(dict(row)) if row else None
    finally:
        await db.close()


async def snapshot_all_subnet_utilization() -> int:
    """Snapshot utilization for every (subnet, vrf) Plexus knows about.

    Subnet sources: external/local IPAM prefixes plus inferred-from-inventory
    subnets. Returns the number of snapshot rows written.
    """
    pairs: set[tuple[str, str]] = set()
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT DISTINCT subnet, vrf FROM ipam_prefixes WHERE subnet IS NOT NULL AND subnet != ''"
        )
        for row in rows_to_list(await cur.fetchall()):
            sn = (row.get("subnet") or "").strip()
            vrf = (row.get("vrf") or "").strip()
            if sn:
                pairs.add((sn, vrf))

        cur = await db.execute(
            "SELECT ip_address, vrf_name FROM hosts WHERE ip_address != '' AND ip_address IS NOT NULL"
        )
        for row in rows_to_list(await cur.fetchall()):
            ip_s = (row["ip_address"] or "").strip().split("/")[0]
            vrf = (row.get("vrf_name") or "").strip()
            sn = _infer_subnet(ip_s)
            if sn:
                pairs.add((sn, vrf))
    finally:
        await db.close()

    written = 0
    for subnet, vrf in pairs:
        result = await snapshot_subnet_utilization(subnet, vrf)
        if result is not None:
            written += 1
    return written


async def list_subnet_utilization(
    subnet: str | None = None,
    vrf_name: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 500,
) -> list[dict]:
    """Return time-series utilization rows, newest first."""
    clauses: list[str] = []
    params: list = []
    if subnet:
        clauses.append("subnet = ?")
        params.append(subnet)
    if vrf_name is not None:
        clauses.append("vrf_name = ?")
        params.append(vrf_name)
    if since:
        clauses.append("captured_at >= ?")
        params.append(since)
    if until:
        clauses.append("captured_at <= ?")
        params.append(until)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(int(limit))
    db = await get_db()
    try:
        cur = await db.execute(
            f"SELECT * FROM ipam_subnet_utilization{where} "
            f"ORDER BY captured_at DESC LIMIT ?",
            tuple(params),
        )
        rows = rows_to_list(await cur.fetchall())
        return [_serialize_subnet_utilization(r) for r in rows]
    finally:
        await db.close()


async def prune_ip_history(retention_days: int = 365) -> int:
    """Delete closed history rows older than retention_days. Returns rows removed."""
    if retention_days <= 0:
        return 0
    cutoff = (
        datetime.now(UTC).replace(tzinfo=None) - timedelta(days=int(retention_days))
    ).isoformat()
    db = await get_db()
    try:
        cur = await db.execute(
            "DELETE FROM ipam_ip_history WHERE ended_at IS NOT NULL AND ended_at < ?",
            (cutoff,),
        )
        await db.commit()
        return int(cur.rowcount or 0)
    finally:
        await db.close()


async def prune_subnet_utilization(retention_days: int = 365) -> int:
    """Delete utilization snapshots older than retention_days."""
    if retention_days <= 0:
        return 0
    cutoff = (
        datetime.now(UTC).replace(tzinfo=None) - timedelta(days=int(retention_days))
    ).isoformat()
    db = await get_db()
    try:
        cur = await db.execute(
            "DELETE FROM ipam_subnet_utilization WHERE captured_at < ?",
            (cutoff,),
        )
        await db.commit()
        return int(cur.rowcount or 0)
    finally:
        await db.close()


# ─────────────────────────────────────────────────────────────────────────────
# IPAM Reporting (Phase J)
# ─────────────────────────────────────────────────────────────────────────────


async def generate_ipam_utilization_report_data(
    vrf_name: str | None = None,
    threshold_pct: float = 0.0,
) -> list[dict]:
    """Latest utilization snapshot per (subnet, vrf), filtered by threshold.

    Returns one row per known (subnet, vrf), using the most recent snapshot.
    Falls back to a live snapshot computation for subnets that have never been
    captured. Sorted by utilization_pct descending so capacity-planning
    audiences see the most-stressed subnets first.
    """
    pairs: set[tuple[str, str]] = set()
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT DISTINCT subnet, vrf FROM ipam_prefixes "
            "WHERE subnet IS NOT NULL AND subnet != ''"
        )
        for row in rows_to_list(await cur.fetchall()):
            sn = (row.get("subnet") or "").strip()
            v = (row.get("vrf") or "").strip()
            if sn and (vrf_name is None or v == vrf_name):
                pairs.add((sn, v))
        cur = await db.execute(
            "SELECT DISTINCT subnet, vrf_name FROM ipam_subnet_utilization"
        )
        for row in rows_to_list(await cur.fetchall()):
            sn = (row.get("subnet") or "").strip()
            v = (row.get("vrf_name") or "").strip()
            if sn and (vrf_name is None or v == vrf_name):
                pairs.add((sn, v))
        cur = await db.execute(
            "SELECT ip_address, vrf_name FROM hosts "
            "WHERE ip_address IS NOT NULL AND ip_address != ''"
        )
        for row in rows_to_list(await cur.fetchall()):
            ip_s = (row.get("ip_address") or "").strip().split("/")[0]
            v = (row.get("vrf_name") or "").strip()
            if vrf_name is not None and v != vrf_name:
                continue
            sn = _infer_subnet(ip_s)
            if sn:
                pairs.add((sn, v))
    finally:
        await db.close()

    rows: list[dict] = []
    for subnet, vrf in pairs:
        snap = None
        existing = await list_subnet_utilization(
            subnet=subnet, vrf_name=vrf, limit=1
        )
        if existing:
            snap = existing[0]
        else:
            snap = await snapshot_subnet_utilization(subnet, vrf)
        if not snap:
            continue
        pct = float(snap.get("utilization_pct") or 0.0)
        if pct < float(threshold_pct):
            continue
        rows.append(
            {
                "subnet": snap.get("subnet"),
                "vrf_name": snap.get("vrf_name") or "",
                "total": int(snap.get("total") or 0),
                "used": int(snap.get("used") or 0),
                "reserved": int(snap.get("reserved") or 0),
                "pending": int(snap.get("pending") or 0),
                "free": int(snap.get("free") or 0),
                "utilization_pct": round(pct, 2),
                "captured_at": snap.get("captured_at"),
            }
        )
    rows.sort(key=lambda r: (-r["utilization_pct"], r["subnet"]))
    return rows


def _linear_forecast(
    points: list[tuple[float, float]], target_pct: float
) -> tuple[float | None, float | None]:
    """Least-squares linear fit over (t, util%) points.

    Returns (slope_per_day, days_to_target). Slope is utilization_pct change
    per day. days_to_target is days from the most recent point until
    util reaches `target_pct`; None if non-positive slope or already past.
    """
    if len(points) < 2:
        return (None, None)
    n = float(len(points))
    sum_x = sum(p[0] for p in points)
    sum_y = sum(p[1] for p in points)
    sum_xy = sum(p[0] * p[1] for p in points)
    sum_xx = sum(p[0] * p[0] for p in points)
    denom = n * sum_xx - sum_x * sum_x
    if denom == 0:
        return (None, None)
    slope = (n * sum_xy - sum_x * sum_y) / denom  # pct per second
    last_t, last_y = points[-1]
    slope_per_day = slope * 86400.0
    if slope <= 0 or last_y >= target_pct:
        return (slope_per_day, None)
    secs = (target_pct - last_y) / slope
    return (slope_per_day, secs / 86400.0)


async def generate_ipam_forecast_report_data(
    vrf_name: str | None = None,
    lookback_days: int = 30,
    target_pct: float = 90.0,
    min_points: int = 2,
) -> list[dict]:
    """Project subnet exhaustion using a linear fit over recent snapshots.

    Per (subnet, vrf), fit a line through utilization_pct samples in the
    lookback window and project days-until-target. Subnets with fewer than
    `min_points` samples are reported with status="insufficient_data" so the
    report always covers the full inventory.
    """
    cutoff = (
        datetime.now(UTC).replace(tzinfo=None) - timedelta(days=int(lookback_days))
    ).isoformat()
    db = await get_db()
    try:
        clauses = ["captured_at >= ?"]
        params: list = [cutoff]
        if vrf_name is not None:
            clauses.append("vrf_name = ?")
            params.append(vrf_name)
        where = " WHERE " + " AND ".join(clauses)
        cur = await db.execute(
            f"SELECT subnet, vrf_name, captured_at, total, used, reserved, "
            f"pending, free, utilization_pct FROM ipam_subnet_utilization{where} "
            f"ORDER BY subnet, vrf_name, captured_at ASC",
            tuple(params),
        )
        snapshot_rows = rows_to_list(await cur.fetchall())
    finally:
        await db.close()

    grouped: dict[tuple[str, str], list[dict]] = {}
    for r in snapshot_rows:
        key = ((r.get("subnet") or "").strip(), (r.get("vrf_name") or "").strip())
        grouped.setdefault(key, []).append(r)

    rows: list[dict] = []
    for (subnet, vrf), samples in grouped.items():
        if not subnet:
            continue
        latest = samples[-1]
        latest_pct = float(latest.get("utilization_pct") or 0.0)
        if len(samples) < int(min_points):
            rows.append(
                {
                    "subnet": subnet,
                    "vrf_name": vrf,
                    "samples": len(samples),
                    "current_utilization_pct": round(latest_pct, 2),
                    "slope_pct_per_day": None,
                    "days_to_target": None,
                    "projected_exhaustion_at": None,
                    "target_pct": float(target_pct),
                    "status": "insufficient_data",
                }
            )
            continue
        points: list[tuple[float, float]] = []
        for s in samples:
            ts = s.get("captured_at") or ""
            try:
                dt = datetime.fromisoformat(str(ts).replace("Z", ""))
            except ValueError:
                continue
            points.append((dt.timestamp(), float(s.get("utilization_pct") or 0.0)))
        slope, days_to_target = _linear_forecast(points, float(target_pct))
        projected_at: str | None = None
        status = "stable"
        if days_to_target is not None and days_to_target > 0:
            projected_dt = datetime.now(UTC).replace(tzinfo=None) + timedelta(
                days=days_to_target
            )
            projected_at = projected_dt.isoformat()
            if days_to_target <= 30:
                status = "critical"
            elif days_to_target <= 90:
                status = "warning"
            else:
                status = "ok"
        elif latest_pct >= float(target_pct):
            status = "exhausted"
        rows.append(
            {
                "subnet": subnet,
                "vrf_name": vrf,
                "samples": len(samples),
                "current_utilization_pct": round(latest_pct, 2),
                "slope_pct_per_day": (
                    round(slope, 4) if slope is not None else None
                ),
                "days_to_target": (
                    round(days_to_target, 1) if days_to_target is not None else None
                ),
                "projected_exhaustion_at": projected_at,
                "target_pct": float(target_pct),
                "status": status,
            }
        )
    # Sort: critical first, then by days_to_target ascending (None last).
    status_order = {
        "exhausted": 0, "critical": 1, "warning": 2, "ok": 3,
        "stable": 4, "insufficient_data": 5,
    }
    rows.sort(
        key=lambda r: (
            status_order.get(r["status"], 99),
            r["days_to_target"] if r["days_to_target"] is not None else 1e9,
            r["subnet"],
        )
    )
    return rows


async def generate_ipam_history_report_data(
    address: str | None = None,
    hostname: str | None = None,
    vrf_name: str | None = None,
    days: int = 90,
    limit: int = 1000,
) -> list[dict]:
    """Per-IP assignment history rows for forensic/audit reports."""
    cutoff = (
        datetime.now(UTC).replace(tzinfo=None) - timedelta(days=int(days))
    ).isoformat()
    clauses = ["started_at >= ?"]
    params: list = [cutoff]
    if address:
        clauses.append("address = ?")
        params.append(address)
    if hostname:
        clauses.append("hostname = ?")
        params.append(hostname)
    if vrf_name is not None:
        clauses.append("vrf_name = ?")
        params.append(vrf_name)
    where = " WHERE " + " AND ".join(clauses)
    params.append(int(limit))
    db = await get_db()
    try:
        cur = await db.execute(
            f"SELECT address, vrf_name, hostname, source_type, source_ref, "
            f"started_at, ended_at, recorded_by, note FROM ipam_ip_history{where} "
            f"ORDER BY started_at DESC LIMIT ?",
            tuple(params),
        )
        rows = rows_to_list(await cur.fetchall())
    finally:
        await db.close()
    out: list[dict] = []
    for r in rows:
        started = r.get("started_at")
        ended = r.get("ended_at")
        duration_s: float | None = None
        if started:
            try:
                s = datetime.fromisoformat(str(started).replace("Z", ""))
                e = (
                    datetime.fromisoformat(str(ended).replace("Z", ""))
                    if ended else datetime.now(UTC).replace(tzinfo=None)
                )
                duration_s = (e - s).total_seconds()
            except ValueError:
                duration_s = None
        out.append(
            {
                "address": r.get("address"),
                "vrf_name": r.get("vrf_name") or "",
                "hostname": r.get("hostname") or "",
                "source_type": r.get("source_type") or "",
                "source_ref": r.get("source_ref") or "",
                "started_at": started,
                "ended_at": ended,
                "duration_hours": (
                    round(duration_s / 3600.0, 2) if duration_s is not None else None
                ),
                "recorded_by": r.get("recorded_by") or "",
                "note": r.get("note") or "",
            }
        )
    return out


# ─────────────────────────────────────────────────────────────────────────────
# IPAM Reconciliation – runs and diffs
# ─────────────────────────────────────────────────────────────────────────────


def _serialize_reconciliation_run(row: dict) -> dict:
    return {
        "id": int(row.get("id") or 0),
        "source_id": int(row.get("source_id") or 0),
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
        "status": row.get("status") or "running",
        "triggered_by": row.get("triggered_by") or "",
        "diff_count": int(row.get("diff_count") or 0),
        "resolved_count": int(row.get("resolved_count") or 0),
        "message": row.get("message") or "",
    }


def _serialize_reconciliation_diff(row: dict) -> dict:
    plexus_state = row.get("plexus_state_json") or "{}"
    ipam_state = row.get("ipam_state_json") or "{}"
    try:
        plexus_obj = json.loads(plexus_state) if isinstance(plexus_state, str) else plexus_state
    except Exception:
        plexus_obj = {}
    try:
        ipam_obj = json.loads(ipam_state) if isinstance(ipam_state, str) else ipam_state
    except Exception:
        ipam_obj = {}
    return {
        "id": int(row.get("id") or 0),
        "run_id": int(row.get("run_id") or 0),
        "source_id": int(row.get("source_id") or 0),
        "address": row.get("address") or "",
        "drift_type": row.get("drift_type") or "",
        "plexus_state": plexus_obj,
        "ipam_state": ipam_obj,
        "resolution": row.get("resolution") or "",
        "resolved_by": row.get("resolved_by") or "",
        "resolved_at": row.get("resolved_at"),
        "resolution_message": row.get("resolution_message") or "",
        "created_at": row.get("created_at"),
    }


async def create_reconciliation_run(source_id: int, triggered_by: str = "") -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO ipam_reconciliation_runs (source_id, status, triggered_by)
               VALUES (?, 'running', ?)""",
            (source_id, triggered_by),
        )
        await db.commit()
        run_id = cursor.lastrowid
        if not run_id:
            return None
        cur2 = await db.execute(
            "SELECT * FROM ipam_reconciliation_runs WHERE id = ?", (run_id,)
        )
        row = await cur2.fetchone()
        return _serialize_reconciliation_run(dict(row)) if row else None
    finally:
        await db.close()


async def finalize_reconciliation_run(
    run_id: int,
    *,
    status: str,
    diff_count: int,
    message: str = "",
) -> None:
    db = await get_db()
    try:
        await db.execute(
            """UPDATE ipam_reconciliation_runs
               SET status = ?, diff_count = ?, message = ?,
                   finished_at = datetime('now')
               WHERE id = ?""",
            (status, int(diff_count), message, run_id),
        )
        await db.commit()
    finally:
        await db.close()


async def insert_reconciliation_diff(
    *,
    run_id: int,
    source_id: int,
    address: str,
    drift_type: str,
    plexus_state: dict | None = None,
    ipam_state: dict | None = None,
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO ipam_reconciliation_diffs
               (run_id, source_id, address, drift_type,
                plexus_state_json, ipam_state_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                source_id,
                address,
                drift_type,
                json.dumps(plexus_state or {}, separators=(",", ":")),
                json.dumps(ipam_state or {}, separators=(",", ":")),
            ),
        )
        await db.commit()
        return int(cursor.lastrowid or 0)
    finally:
        await db.close()


async def list_reconciliation_runs(
    source_id: int | None = None,
    limit: int = 50,
) -> list[dict]:
    db = await get_db()
    try:
        if source_id is not None:
            cursor = await db.execute(
                """SELECT * FROM ipam_reconciliation_runs
                   WHERE source_id = ?
                   ORDER BY started_at DESC, id DESC
                   LIMIT ?""",
                (source_id, int(max(1, limit))),
            )
        else:
            cursor = await db.execute(
                """SELECT * FROM ipam_reconciliation_runs
                   ORDER BY started_at DESC, id DESC
                   LIMIT ?""",
                (int(max(1, limit)),),
            )
        return [_serialize_reconciliation_run(dict(r)) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def list_reconciliation_diffs(
    *,
    source_id: int | None = None,
    run_id: int | None = None,
    open_only: bool = True,
    limit: int = 500,
) -> list[dict]:
    clauses: list[str] = []
    params: list = []
    if source_id is not None:
        clauses.append("source_id = ?")
        params.append(source_id)
    if run_id is not None:
        clauses.append("run_id = ?")
        params.append(run_id)
    if open_only:
        clauses.append("(resolution IS NULL OR resolution = '')")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(int(max(1, limit)))
    db = await get_db()
    try:
        cursor = await db.execute(
            f"""SELECT * FROM ipam_reconciliation_diffs
                {where}
                ORDER BY id DESC
                LIMIT ?""",
            tuple(params),
        )
        return [_serialize_reconciliation_diff(dict(r)) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_reconciliation_diff(diff_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM ipam_reconciliation_diffs WHERE id = ?", (diff_id,)
        )
        row = await cursor.fetchone()
        return _serialize_reconciliation_diff(dict(row)) if row else None
    finally:
        await db.close()


async def mark_reconciliation_diff_resolved(
    diff_id: int,
    *,
    resolution: str,
    resolved_by: str,
    message: str = "",
) -> dict | None:
    db = await get_db()
    try:
        await db.execute(
            """UPDATE ipam_reconciliation_diffs
               SET resolution = ?, resolved_by = ?, resolution_message = ?,
                   resolved_at = datetime('now')
               WHERE id = ? AND (resolution IS NULL OR resolution = '')""",
            (resolution, resolved_by, message, diff_id),
        )
        await db.commit()
        cursor = await db.execute(
            "SELECT * FROM ipam_reconciliation_diffs WHERE id = ?", (diff_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        diff = _serialize_reconciliation_diff(dict(row))
        # Bump resolved counter on parent run
        await db.execute(
            """UPDATE ipam_reconciliation_runs
               SET resolved_count = resolved_count + 1
               WHERE id = ?""",
            (diff.get("run_id"),),
        )
        await db.commit()
        return diff
    finally:
        await db.close()


# ─────────────────────────────────────────────────────────────────────────────
# DHCP – Servers, Scopes, and Leases
# ─────────────────────────────────────────────────────────────────────────────


def _serialize_dhcp_server(row: dict) -> dict:
    return {
        "id": int(row.get("id") or 0),
        "provider": row.get("provider") or "",
        "name": row.get("name") or "",
        "base_url": row.get("base_url") or "",
        "auth_type": row.get("auth_type") or "",
        "notes": row.get("notes") or "",
        "enabled": bool(row.get("enabled")),
        "verify_tls": bool(row.get("verify_tls", 1)),
        "last_sync_at": row.get("last_sync_at"),
        "last_sync_status": row.get("last_sync_status") or "never",
        "last_sync_message": row.get("last_sync_message") or "",
        "created_by": row.get("created_by") or "",
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "scope_count": int(row.get("scope_count") or 0),
        "lease_count": int(row.get("lease_count") or 0),
        "has_auth_config": bool(row.get("auth_config_enc")),
    }


async def list_dhcp_servers(enabled_only: bool = False) -> list[dict]:
    db = await get_db()
    try:
        where = " WHERE s.enabled = 1" if enabled_only else ""
        cursor = await db.execute(
            f"""SELECT s.*,
                       (SELECT COUNT(*) FROM dhcp_scopes p WHERE p.server_id = s.id) AS scope_count,
                       (SELECT COUNT(*) FROM dhcp_leases l WHERE l.server_id = s.id) AS lease_count
                FROM dhcp_servers s
                {where}
                ORDER BY s.provider ASC, s.name ASC"""
        )
        return [_serialize_dhcp_server(dict(r)) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_dhcp_server(server_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT s.*,
                      (SELECT COUNT(*) FROM dhcp_scopes p WHERE p.server_id = s.id) AS scope_count,
                      (SELECT COUNT(*) FROM dhcp_leases l WHERE l.server_id = s.id) AS lease_count
               FROM dhcp_servers s
               WHERE s.id = ?""",
            (server_id,),
        )
        row = await cursor.fetchone()
        return _serialize_dhcp_server(dict(row)) if row else None
    finally:
        await db.close()


async def create_dhcp_server(
    provider: str,
    name: str,
    base_url: str = "",
    auth_type: str = "none",
    auth_config: dict | None = None,
    notes: str = "",
    enabled: bool = True,
    verify_tls: bool = True,
    created_by: str = "",
) -> dict | None:
    from routes.crypto import encrypt as _enc

    auth_config_enc = ""
    if auth_config:
        auth_config_enc = _enc(json.dumps(auth_config, separators=(",", ":")))

    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO dhcp_servers
               (provider, name, base_url, auth_type, auth_config_enc,
                notes, enabled, verify_tls, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                provider,
                name,
                base_url,
                auth_type,
                auth_config_enc,
                notes,
                int(bool(enabled)),
                int(bool(verify_tls)),
                created_by,
            ),
        )
        await db.commit()
        return await get_dhcp_server(cursor.lastrowid)
    finally:
        await db.close()


async def update_dhcp_server(server_id: int, **kwargs) -> dict | None:
    from routes.crypto import encrypt as _enc

    allowed = {
        "provider", "name", "base_url", "auth_type", "notes",
        "enabled", "verify_tls", "last_sync_at", "last_sync_status",
        "last_sync_message",
    }
    sets: list[str] = []
    vals: list = []

    auth_config = kwargs.pop("auth_config", None)
    if auth_config is not None:
        enc = _enc(json.dumps(auth_config, separators=(",", ":")))
        sets.append("auth_config_enc = ?")
        vals.append(enc)

    for key, value in kwargs.items():
        if key not in allowed or value is None:
            continue
        if key in ("enabled", "verify_tls"):
            value = int(bool(value))
        sets.append(f"{key} = ?")
        vals.append(value)

    if not sets:
        return await get_dhcp_server(server_id)

    sets.append("updated_at = datetime('now')")
    db = await get_db()
    try:
        sql, sql_params = _safe_dynamic_update("dhcp_servers", sets, vals, "id = ?", server_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_dhcp_server(server_id)
    finally:
        await db.close()


async def delete_dhcp_server(server_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM dhcp_servers WHERE id = ?", (server_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_dhcp_server_auth_config(server_id: int) -> dict:
    from routes.crypto import decrypt as _dec

    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT auth_config_enc FROM dhcp_servers WHERE id = ?",
            (server_id,),
        )
        row = await cursor.fetchone()
        if not row or not row[0]:
            return {}
        try:
            return json.loads(_dec(row[0]))
        except Exception:
            return {}
    finally:
        await db.close()


async def replace_dhcp_server_snapshot(
    server_id: int,
    scopes: list[dict],
    leases: list[dict],
    sync_status: str = "success",
    sync_message: str = "",
) -> dict:
    db = await get_db()
    try:
        await db.execute("DELETE FROM dhcp_scopes WHERE server_id = ?", (server_id,))
        await db.execute("DELETE FROM dhcp_leases WHERE server_id = ?", (server_id,))

        scope_count = 0
        for sc in scopes:
            subnet = (sc.get("subnet") or "").strip()
            if not subnet:
                continue
            await db.execute(
                """INSERT OR IGNORE INTO dhcp_scopes
                   (server_id, external_id, subnet, name, range_start, range_end,
                    total_addresses, used_addresses, free_addresses, state, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    server_id,
                    str(sc.get("external_id") or ""),
                    subnet,
                    sc.get("name") or "",
                    sc.get("range_start") or "",
                    sc.get("range_end") or "",
                    int(sc.get("total_addresses") or 0),
                    int(sc.get("used_addresses") or 0),
                    int(sc.get("free_addresses") or 0),
                    sc.get("state") or "",
                    json.dumps(sc.get("metadata") or {}, separators=(",", ":")),
                ),
            )
            scope_count += 1

        lease_count = 0
        for lease in leases:
            address = (lease.get("address") or "").strip()
            if not address:
                continue
            await db.execute(
                """INSERT OR IGNORE INTO dhcp_leases
                   (server_id, scope_subnet, address, mac_address, hostname,
                    client_id, state, starts_at, ends_at, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    server_id,
                    lease.get("scope_subnet") or "",
                    address,
                    lease.get("mac_address") or "",
                    lease.get("hostname") or "",
                    lease.get("client_id") or "",
                    lease.get("state") or "",
                    lease.get("starts_at") or None,
                    lease.get("ends_at") or None,
                    json.dumps(lease.get("metadata") or {}, separators=(",", ":")),
                ),
            )
            lease_count += 1

        now_iso = datetime.now(UTC).isoformat()
        await db.execute(
            """UPDATE dhcp_servers
               SET last_sync_at = ?, last_sync_status = ?,
                   last_sync_message = ?, updated_at = ?
               WHERE id = ?""",
            (now_iso, sync_status, sync_message, now_iso, server_id),
        )
        await db.commit()
        return {"scopes": scope_count, "leases": lease_count}
    finally:
        await db.close()


async def set_dhcp_server_sync_status(
    server_id: int,
    status: str,
    message: str = "",
) -> None:
    db = await get_db()
    try:
        now_iso = datetime.now(UTC).isoformat()
        await db.execute(
            """UPDATE dhcp_servers
               SET last_sync_status = ?, last_sync_message = ?,
                   last_sync_at = ?, updated_at = ?
               WHERE id = ?""",
            (status, message, now_iso, now_iso, server_id),
        )
        await db.commit()
    finally:
        await db.close()


async def list_dhcp_scopes(server_id: int | None = None) -> list[dict]:
    db = await get_db()
    try:
        if server_id is not None:
            cursor = await db.execute(
                """SELECT * FROM dhcp_scopes WHERE server_id = ?
                   ORDER BY subnet""",
                (server_id,),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM dhcp_scopes ORDER BY server_id, subnet"
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def list_dhcp_leases(
    server_id: int | None = None,
    scope_subnet: str | None = None,
    limit: int = 500,
) -> list[dict]:
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if server_id is not None:
            clauses.append("server_id = ?")
            params.append(server_id)
        if scope_subnet:
            clauses.append("scope_subnet = ?")
            params.append(scope_subnet)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(int(max(1, min(limit, 5000))))
        cursor = await db.execute(
            f"SELECT * FROM dhcp_leases{where} ORDER BY address LIMIT ?",
            tuple(params),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Bandwidth Billing – Circuits & 95th Percentile Reports
# ═════════════════════════════════════════════════════════════════════════════


async def create_billing_circuit(
    name: str,
    host_id: int,
    if_index: int,
    if_name: str = "",
    customer: str = "",
    description: str = "",
    commit_rate_bps: float = 0,
    burst_limit_bps: float = 0,
    billing_day: int = 1,
    billing_cycle: str = "monthly",
    cost_per_mbps: float = 0,
    currency: str = "USD",
    overage_enabled: int = 1,
    created_by: str = "",
) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO billing_circuits
               (name, description, customer, host_id, if_index, if_name,
                commit_rate_bps, burst_limit_bps, billing_day, billing_cycle,
                cost_per_mbps, currency, overage_enabled, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, description, customer, host_id, if_index, if_name,
             commit_rate_bps, burst_limit_bps, billing_day, billing_cycle,
             cost_per_mbps, currency, overage_enabled, created_by),
        )
        await db.commit()
        return await get_billing_circuit(cursor.lastrowid)
    finally:
        await db.close()


async def get_billing_circuit(circuit_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM billing_circuits WHERE id = ?", (circuit_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def list_billing_circuits(
    customer: str | None = None,
    host_id: int | None = None,
    enabled_only: bool = False,
) -> list[dict]:
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if customer:
            clauses.append("bc.customer = ?")
            params.append(customer)
        if host_id is not None:
            clauses.append("bc.host_id = ?")
            params.append(host_id)
        if enabled_only:
            clauses.append("bc.enabled = 1")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT bc.*, h.hostname, h.ip_address
                FROM billing_circuits bc
                LEFT JOIN hosts h ON h.id = bc.host_id
                {where}
                ORDER BY bc.customer, bc.name""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def update_billing_circuit(circuit_id: int, **kwargs) -> dict | None:
    db = await get_db()
    try:
        allowed = {
            "name", "description", "customer", "if_name",
            "commit_rate_bps", "burst_limit_bps", "billing_day",
            "billing_cycle", "cost_per_mbps", "currency",
            "overage_enabled", "enabled",
        }
        sets = []
        vals = []
        for k, v in kwargs.items():
            if k in allowed and v is not None:
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return await get_billing_circuit(circuit_id)
        sets.append("updated_at = datetime('now')")
        sql, sql_params = _safe_dynamic_update("billing_circuits", sets, vals, "id = ?", circuit_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_billing_circuit(circuit_id)
    finally:
        await db.close()


async def delete_billing_circuit(circuit_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM billing_circuits WHERE id = ?", (circuit_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def create_billing_period(
    circuit_id: int,
    period_start: str,
    period_end: str,
    total_samples: int = 0,
    p95_in_bps: float = 0,
    p95_out_bps: float = 0,
    p95_billing_bps: float = 0,
    max_in_bps: float = 0,
    max_out_bps: float = 0,
    avg_in_bps: float = 0,
    avg_out_bps: float = 0,
    commit_rate_bps: float = 0,
    overage_bps: float = 0,
    overage_cost: float = 0,
    total_cost: float = 0,
    status: str = "generated",
) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO billing_periods
               (circuit_id, period_start, period_end, total_samples,
                p95_in_bps, p95_out_bps, p95_billing_bps,
                max_in_bps, max_out_bps, avg_in_bps, avg_out_bps,
                commit_rate_bps, overage_bps, overage_cost, total_cost, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (circuit_id, period_start, period_end, total_samples,
             p95_in_bps, p95_out_bps, p95_billing_bps,
             max_in_bps, max_out_bps, avg_in_bps, avg_out_bps,
             commit_rate_bps, overage_bps, overage_cost, total_cost, status),
        )
        await db.commit()
        return await get_billing_period(cursor.lastrowid)
    finally:
        await db.close()


async def get_billing_period(period_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT bp.*, bc.name AS circuit_name, bc.customer,
                      bc.if_name, h.hostname
               FROM billing_periods bp
               JOIN billing_circuits bc ON bc.id = bp.circuit_id
               LEFT JOIN hosts h ON h.id = bc.host_id
               WHERE bp.id = ?""",
            (period_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def list_billing_periods(
    circuit_id: int | None = None,
    customer: str | None = None,
    start_after: str | None = None,
    limit: int = 100,
) -> list[dict]:
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if circuit_id is not None:
            clauses.append("bp.circuit_id = ?")
            params.append(circuit_id)
        if customer:
            clauses.append("bc.customer = ?")
            params.append(customer)
        if start_after:
            clauses.append("bp.period_start >= ?")
            params.append(start_after)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT bp.*, bc.name AS circuit_name, bc.customer,
                       bc.if_name, h.hostname
                FROM billing_periods bp
                JOIN billing_circuits bc ON bc.id = bp.circuit_id
                LEFT JOIN hosts h ON h.id = bc.host_id
                {where}
                ORDER BY bp.period_start DESC
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_billing_period(period_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM billing_periods WHERE id = ?", (period_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_billing_samples_for_period(
    host_id: int,
    if_index: int,
    period_start: str,
    period_end: str,
) -> list[dict]:
    """Fetch raw interface_ts samples for 95th percentile billing calculation."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT in_rate_bps, out_rate_bps, sampled_at
               FROM interface_ts
               WHERE host_id = ? AND if_index = ?
                 AND sampled_at >= ? AND sampled_at < ?
                 AND in_rate_bps IS NOT NULL
               ORDER BY sampled_at ASC""",
            (host_id, if_index, period_start, period_end),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_billing_rollups_for_period(
    host_id: int,
    if_index: int,
    period_start: str,
    period_end: str,
) -> list[dict]:
    """Fetch hourly rollups for longer billing periods (falls back from raw)."""
    db = await get_db()
    try:
        labels_pattern = f'%"if_index": {if_index}%'
        cursor = await db.execute(
            """SELECT val_min, val_avg, val_max, val_p95, sample_count,
                      period_start, period_end
               FROM metric_rollups
               WHERE host_id = ?
                 AND metric_name IN ('if_in_octets', 'if_out_octets')
                 AND labels_json LIKE ?
                 AND time_window = 'hourly'
                 AND period_start >= ? AND period_start < ?
               ORDER BY period_start ASC""",
            (host_id, labels_pattern, period_start, period_end),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_billing_customers() -> list[str]:
    """Get distinct customer names from billing circuits."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT DISTINCT customer FROM billing_circuits WHERE customer != '' ORDER BY customer"
        )
        return [r[0] for r in await cursor.fetchall()]
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Cloud Visibility – Accounts, Resources, and Hybrid Connectivity
# ═════════════════════════════════════════════════════════════════════════════


def _cloud_json_text(value, default: str = "{}") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or default
    try:
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    except Exception:
        return default


async def create_cloud_account(
    provider: str,
    name: str,
    account_identifier: str = "",
    region_scope: str = "",
    auth_type: str = "manual",
    auth_config_json: dict | list | str | None = None,
    notes: str = "",
    enabled: int = 1,
    created_by: str = "",
) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO cloud_accounts
               (provider, name, account_identifier, region_scope, auth_type,
                auth_config_json, notes, enabled, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                provider,
                name,
                account_identifier,
                region_scope,
                auth_type,
                _cloud_json_text(auth_config_json),
                notes,
                int(bool(enabled)),
                created_by,
            ),
        )
        await db.commit()
        return await get_cloud_account(cursor.lastrowid)
    finally:
        await db.close()


async def get_cloud_account(account_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT ca.*,
                      (SELECT COUNT(*) FROM cloud_resources cr WHERE cr.account_id = ca.id) AS resource_count,
                      (SELECT COUNT(*) FROM cloud_connections cc WHERE cc.account_id = ca.id) AS connection_count,
                      (SELECT COUNT(*) FROM cloud_hybrid_links chl WHERE chl.account_id = ca.id) AS hybrid_link_count
               FROM cloud_accounts ca
               WHERE ca.id = ?""",
            (account_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def list_cloud_accounts(
    provider: str | None = None,
    enabled_only: bool = False,
) -> list[dict]:
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if provider:
            clauses.append("ca.provider = ?")
            params.append(provider)
        if enabled_only:
            clauses.append("ca.enabled = 1")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT ca.*,
                       (SELECT COUNT(*) FROM cloud_resources cr WHERE cr.account_id = ca.id) AS resource_count,
                       (SELECT COUNT(*) FROM cloud_connections cc WHERE cc.account_id = ca.id) AS connection_count,
                       (SELECT COUNT(*) FROM cloud_hybrid_links chl WHERE chl.account_id = ca.id) AS hybrid_link_count
                FROM cloud_accounts ca
                {where}
                ORDER BY ca.provider ASC, ca.name ASC""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def update_cloud_account(account_id: int, **kwargs) -> dict | None:
    db = await get_db()
    try:
        allowed = {
            "provider",
            "name",
            "account_identifier",
            "region_scope",
            "auth_type",
            "auth_config_json",
            "notes",
            "enabled",
            "last_sync_at",
            "last_sync_status",
            "last_sync_message",
        }
        sets: list[str] = []
        vals: list = []
        for key, value in kwargs.items():
            if key not in allowed or value is None:
                continue
            if key == "auth_config_json":
                value = _cloud_json_text(value)
            if key == "enabled":
                value = int(bool(value))
            sets.append(f"{key} = ?")
            vals.append(value)
        if not sets:
            return await get_cloud_account(account_id)
        sets.append("updated_at = NOW()" if DB_ENGINE == "postgres" else "updated_at = datetime('now')")
        sql, sql_params = _safe_dynamic_update("cloud_accounts", sets, vals, "id = ?", account_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_cloud_account(account_id)
    finally:
        await db.close()


async def delete_cloud_account(account_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM cloud_accounts WHERE id = ?", (account_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def set_cloud_account_sync_status(
    account_id: int,
    *,
    status: str,
    message: str = "",
    last_sync_at: str | None = None,
) -> dict | None:
    sync_time = last_sync_at or datetime.now(UTC).isoformat()
    return await update_cloud_account(
        account_id,
        last_sync_status=status,
        last_sync_message=message,
        last_sync_at=sync_time,
    )


async def replace_cloud_discovery_snapshot(
    account_id: int,
    *,
    resources: list[dict] | None = None,
    connections: list[dict] | None = None,
    hybrid_links: list[dict] | None = None,
    sync_status: str = "success",
    sync_message: str = "",
) -> dict:
    resources = resources or []
    connections = connections or []
    hybrid_links = hybrid_links or []
    now_iso = datetime.now(UTC).isoformat()

    def _extract_policy_rules(resource_item: dict) -> list[dict]:
        metadata = resource_item.get("metadata")
        if metadata is None and resource_item.get("metadata_json"):
            try:
                metadata = json.loads(str(resource_item.get("metadata_json") or "{}"))
            except Exception:
                metadata = {}
        if not isinstance(metadata, dict):
            return []
        rules = metadata.get("policy_rules")
        return rules if isinstance(rules, list) else []

    def _normalize_policy_rule(resource_item: dict, rule: dict, index: int, provider_name: str) -> dict | None:
        resource_uid = str(resource_item.get("resource_uid") or resource_item.get("id") or "").strip()
        if not resource_uid or not isinstance(rule, dict):
            return None
        rule_name = str(rule.get("rule_name") or rule.get("name") or "").strip()
        direction = str(rule.get("direction") or "").strip().lower()
        if direction == "ingress":
            direction = "inbound"
        elif direction == "egress":
            direction = "outbound"
        action = str(rule.get("action") or "").strip().lower()
        protocol = str(rule.get("protocol") or "all").strip().lower() or "all"
        source_selector = str(rule.get("source_selector") or rule.get("source") or "").strip()
        destination_selector = str(rule.get("destination_selector") or rule.get("destination") or "").strip()
        port_expression = str(rule.get("port_expression") or rule.get("ports") or "").strip()
        raw_priority = rule.get("priority")
        priority = None
        if raw_priority not in (None, ""):
            try:
                priority = int(raw_priority)
            except Exception:
                priority = None
        raw_uid = str(rule.get("rule_uid") or rule.get("id") or "").strip()
        rule_uid = raw_uid or f"{resource_uid}:rule:{index + 1}:{direction or 'any'}:{action or 'any'}:{rule_name or 'unnamed'}"
        metadata = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
        return {
            "provider": str(resource_item.get("provider") or provider_name or "").strip(),
            "resource_uid": resource_uid,
            "rule_uid": rule_uid,
            "rule_name": rule_name,
            "direction": direction,
            "action": action,
            "protocol": protocol,
            "source_selector": source_selector,
            "destination_selector": destination_selector,
            "port_expression": port_expression,
            "priority": priority,
            "metadata_json": _cloud_json_text(metadata),
            "discovered_at": str(rule.get("discovered_at") or now_iso),
        }

    db = await get_db()
    try:
        account_row = await db.execute(
            "SELECT id, provider FROM cloud_accounts WHERE id = ?",
            (account_id,),
        )
        account = await account_row.fetchone()
        if not account:
            return {"ok": False, "resources": 0, "connections": 0, "hybrid_links": 0}
        provider = str(account["provider"])

        await db.execute("DELETE FROM cloud_resources WHERE account_id = ?", (account_id,))
        await db.execute("DELETE FROM cloud_connections WHERE account_id = ?", (account_id,))
        await db.execute("DELETE FROM cloud_hybrid_links WHERE account_id = ?", (account_id,))
        await db.execute("DELETE FROM cloud_policy_rules WHERE account_id = ?", (account_id,))

        resource_seen: dict[str, dict] = {}
        policy_rule_seen: dict[str, dict] = {}
        for item in resources:
            uid = str(item.get("resource_uid") or item.get("id") or "").strip()
            if not uid:
                continue
            resource_seen[uid] = {
                "provider": str(item.get("provider") or provider or "").strip(),
                "resource_uid": uid,
                "resource_type": str(item.get("resource_type") or "resource").strip(),
                "name": str(item.get("name") or "").strip(),
                "region": str(item.get("region") or "").strip(),
                "cidr": str(item.get("cidr") or "").strip(),
                "status": str(item.get("status") or "").strip(),
                "metadata_json": _cloud_json_text(item.get("metadata") or item.get("metadata_json")),
                "discovered_at": str(item.get("discovered_at") or now_iso),
                "updated_at": str(item.get("updated_at") or now_iso),
            }
            for index, raw_rule in enumerate(_extract_policy_rules(item)):
                normalized_rule = _normalize_policy_rule(item, raw_rule, index, provider)
                if not normalized_rule:
                    continue
                policy_rule_seen[normalized_rule["rule_uid"]] = normalized_rule

        for item in resource_seen.values():
            await db.execute(
                """INSERT INTO cloud_resources
                   (account_id, provider, resource_uid, resource_type, name, region, cidr,
                    status, metadata_json, discovered_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    account_id,
                    item["provider"],
                    item["resource_uid"],
                    item["resource_type"],
                    item["name"],
                    item["region"],
                    item["cidr"],
                    item["status"],
                    item["metadata_json"],
                    item["discovered_at"],
                    item["updated_at"],
                ),
            )

        connection_seen: dict[str, dict] = {}
        for item in connections:
            src = str(item.get("source_resource_uid") or item.get("source") or "").strip()
            dst = str(item.get("target_resource_uid") or item.get("target") or "").strip()
            ctype = str(item.get("connection_type") or "peering").strip()
            if not src or not dst:
                continue
            key = f"{src}|{dst}|{ctype}"
            connection_seen[key] = {
                "provider": str(item.get("provider") or provider or "").strip(),
                "source_resource_uid": src,
                "target_resource_uid": dst,
                "connection_type": ctype,
                "state": str(item.get("state") or "").strip(),
                "metadata_json": _cloud_json_text(item.get("metadata") or item.get("metadata_json")),
                "discovered_at": str(item.get("discovered_at") or now_iso),
            }

        for item in connection_seen.values():
            await db.execute(
                """INSERT INTO cloud_connections
                   (account_id, provider, source_resource_uid, target_resource_uid,
                    connection_type, state, metadata_json, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    account_id,
                    item["provider"],
                    item["source_resource_uid"],
                    item["target_resource_uid"],
                    item["connection_type"],
                    item["state"],
                    item["metadata_json"],
                    item["discovered_at"],
                ),
            )

        hybrid_seen: dict[str, dict] = {}
        for item in hybrid_links:
            cloud_uid = str(item.get("cloud_resource_uid") or item.get("target_resource_uid") or "").strip()
            ctype = str(item.get("connection_type") or "vpn").strip()
            host_id_raw = item.get("host_id")
            host_id = None
            if host_id_raw not in (None, ""):
                try:
                    host_id = int(host_id_raw)
                except Exception:
                    host_id = None
            host_label = str(item.get("host_label") or item.get("hostname") or "").strip()
            if not cloud_uid:
                continue
            key = f"{host_id}|{host_label}|{cloud_uid}|{ctype}"
            hybrid_seen[key] = {
                "provider": str(item.get("provider") or provider or "").strip(),
                "host_id": host_id,
                "host_label": host_label,
                "cloud_resource_uid": cloud_uid,
                "connection_type": ctype,
                "state": str(item.get("state") or "").strip(),
                "metadata_json": _cloud_json_text(item.get("metadata") or item.get("metadata_json")),
                "discovered_at": str(item.get("discovered_at") or now_iso),
            }

        for item in hybrid_seen.values():
            await db.execute(
                """INSERT INTO cloud_hybrid_links
                   (account_id, provider, host_id, host_label, cloud_resource_uid,
                    connection_type, state, metadata_json, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    account_id,
                    item["provider"],
                    item["host_id"],
                    item["host_label"],
                    item["cloud_resource_uid"],
                    item["connection_type"],
                    item["state"],
                    item["metadata_json"],
                    item["discovered_at"],
                ),
            )

        for item in policy_rule_seen.values():
            await db.execute(
                """INSERT INTO cloud_policy_rules
                   (account_id, provider, resource_uid, rule_uid, rule_name, direction,
                    action, protocol, source_selector, destination_selector,
                    port_expression, priority, metadata_json, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    account_id,
                    item["provider"],
                    item["resource_uid"],
                    item["rule_uid"],
                    item["rule_name"],
                    item["direction"],
                    item["action"],
                    item["protocol"],
                    item["source_selector"],
                    item["destination_selector"],
                    item["port_expression"],
                    item["priority"],
                    item["metadata_json"],
                    item["discovered_at"],
                ),
            )

        await db.execute(
            """UPDATE cloud_accounts
               SET last_sync_at = ?,
                   last_sync_status = ?,
                   last_sync_message = ?,
                   updated_at = ?"""
            + ("::timestamptz" if DB_ENGINE == "postgres" else "")
            + " WHERE id = ?",
            (now_iso, sync_status, sync_message, now_iso, account_id),
        )
        await db.commit()

        return {
            "ok": True,
            "resources": len(resource_seen),
            "connections": len(connection_seen),
            "hybrid_links": len(hybrid_seen),
            "policy_rules": len(policy_rule_seen),
        }
    finally:
        await db.close()


async def get_cloud_policy_rules(
    account_id: int | None = None,
    provider: str | None = None,
    resource_uid: str | None = None,
    direction: str | None = None,
    action: str | None = None,
    limit: int = 500,
) -> list[dict]:
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if account_id is not None:
            clauses.append("pr.account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("pr.provider = ?")
            params.append(provider)
        if resource_uid:
            clauses.append("pr.resource_uid = ?")
            params.append(resource_uid)
        if direction:
            clauses.append("LOWER(pr.direction) = ?")
            params.append(direction.lower())
        if action:
            clauses.append("LOWER(pr.action) = ?")
            params.append(action.lower())
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(int(limit), 2000)))
        cursor = await db.execute(
            f"""SELECT pr.*, ca.name AS account_name,
                       cr.name AS resource_name,
                       cr.resource_type,
                       cr.region AS resource_region
                FROM cloud_policy_rules pr
                JOIN cloud_accounts ca ON ca.id = pr.account_id
                LEFT JOIN cloud_resources cr
                  ON cr.account_id = pr.account_id
                 AND cr.resource_uid = pr.resource_uid
                {where}
                ORDER BY pr.provider,
                         COALESCE(cr.name, pr.resource_uid),
                         pr.direction,
                         CASE WHEN pr.priority IS NULL THEN 2147483647 ELSE pr.priority END,
                         pr.rule_name,
                         pr.rule_uid
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_policy_effective_views(
    account_id: int | None = None,
    provider: str | None = None,
) -> list[dict]:
    db = await get_db()
    try:
        clauses = [
            "cr.resource_type IN ('security_group', 'network_security_group', 'firewall_policy')",
        ]
        params: list = []
        if account_id is not None:
            clauses.append("cr.account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("cr.provider = ?")
            params.append(provider)
        where = " AND ".join(clauses)
        cursor = await db.execute(
            f"""SELECT cr.account_id,
                       ca.name AS account_name,
                       cr.provider,
                       cr.resource_uid,
                       cr.resource_type,
                       cr.name AS resource_name,
                       cr.region,
                       COUNT(pr.id) AS rule_count,
                       COALESCE(SUM(CASE WHEN LOWER(COALESCE(pr.direction, '')) = 'inbound'
                                             AND LOWER(COALESCE(pr.action, '')) = 'allow'
                                        THEN 1 ELSE 0 END), 0) AS inbound_allow_count,
                       COALESCE(SUM(CASE WHEN LOWER(COALESCE(pr.direction, '')) = 'outbound'
                                             AND LOWER(COALESCE(pr.action, '')) = 'allow'
                                        THEN 1 ELSE 0 END), 0) AS outbound_allow_count,
                       COALESCE(SUM(CASE WHEN LOWER(COALESCE(pr.action, '')) = 'deny'
                                        THEN 1 ELSE 0 END), 0) AS deny_count,
                       COALESCE(SUM(CASE WHEN LOWER(COALESCE(pr.direction, '')) = 'inbound'
                                             AND LOWER(COALESCE(pr.action, '')) = 'allow'
                                             AND (
                                                 pr.source_selector LIKE '%0.0.0.0/0%'
                                                 OR pr.source_selector LIKE '%::/0%'
                                                 OR pr.source_selector = '*'
                                                 OR LOWER(pr.source_selector) = 'any'
                                             )
                                        THEN 1 ELSE 0 END), 0) AS public_ingress_count,
                       COALESCE(SUM(CASE WHEN LOWER(COALESCE(pr.direction, '')) = 'outbound'
                                             AND LOWER(COALESCE(pr.action, '')) = 'allow'
                                             AND (
                                                 pr.destination_selector LIKE '%0.0.0.0/0%'
                                                 OR pr.destination_selector LIKE '%::/0%'
                                                 OR pr.destination_selector = '*'
                                                 OR LOWER(pr.destination_selector) = 'any'
                                             )
                                        THEN 1 ELSE 0 END), 0) AS open_egress_count
                FROM cloud_resources cr
                JOIN cloud_accounts ca ON ca.id = cr.account_id
                LEFT JOIN cloud_policy_rules pr
                  ON pr.account_id = cr.account_id
                 AND pr.resource_uid = cr.resource_uid
                WHERE {where}
                GROUP BY cr.account_id, ca.name, cr.provider, cr.resource_uid, cr.resource_type, cr.name, cr.region
                ORDER BY public_ingress_count DESC, rule_count DESC, cr.provider, cr.name, cr.resource_uid""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_resources(
    account_id: int | None = None,
    provider: str | None = None,
    resource_type: str | None = None,
) -> list[dict]:
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if account_id is not None:
            clauses.append("cr.account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("cr.provider = ?")
            params.append(provider)
        if resource_type:
            clauses.append("cr.resource_type = ?")
            params.append(resource_type)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT cr.*, ca.name AS account_name, ca.account_identifier
                FROM cloud_resources cr
                JOIN cloud_accounts ca ON ca.id = cr.account_id
                {where}
                ORDER BY cr.provider, cr.resource_type, cr.name, cr.resource_uid""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_connections(
    account_id: int | None = None,
    provider: str | None = None,
) -> list[dict]:
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if account_id is not None:
            clauses.append("cc.account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("cc.provider = ?")
            params.append(provider)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT cc.*,
                       ca.name AS account_name,
                       src.name AS source_name,
                       src.resource_type AS source_type,
                       dst.name AS target_name,
                       dst.resource_type AS target_type
                FROM cloud_connections cc
                JOIN cloud_accounts ca ON ca.id = cc.account_id
                LEFT JOIN cloud_resources src
                  ON src.account_id = cc.account_id
                 AND src.resource_uid = cc.source_resource_uid
                LEFT JOIN cloud_resources dst
                  ON dst.account_id = cc.account_id
                 AND dst.resource_uid = cc.target_resource_uid
                {where}
                ORDER BY cc.provider, cc.connection_type, cc.source_resource_uid, cc.target_resource_uid""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_hybrid_links(
    account_id: int | None = None,
    provider: str | None = None,
) -> list[dict]:
    db = await get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if account_id is not None:
            clauses.append("chl.account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("chl.provider = ?")
            params.append(provider)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT chl.*,
                       ca.name AS account_name,
                       h.hostname AS host_hostname,
                       h.ip_address AS host_ip_address,
                       cr.name AS cloud_resource_name,
                       cr.resource_type AS cloud_resource_type
                FROM cloud_hybrid_links chl
                JOIN cloud_accounts ca ON ca.id = chl.account_id
                LEFT JOIN hosts h ON h.id = chl.host_id
                LEFT JOIN cloud_resources cr
                  ON cr.account_id = chl.account_id
                 AND cr.resource_uid = chl.cloud_resource_uid
                {where}
                ORDER BY chl.provider, COALESCE(h.hostname, chl.host_label), chl.cloud_resource_uid""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_topology_snapshot(
    account_id: int | None = None,
    provider: str | None = None,
) -> dict:
    if account_id is not None:
        account = await get_cloud_account(account_id)
        accounts = [account] if account else []
    else:
        accounts = await list_cloud_accounts(provider=provider)
    resources = await get_cloud_resources(account_id=account_id, provider=provider)
    connections = await get_cloud_connections(account_id=account_id, provider=provider)
    hybrid_links = await get_cloud_hybrid_links(account_id=account_id, provider=provider)

    return {
        "accounts": accounts,
        "resources": resources,
        "connections": connections,
        "hybrid_links": hybrid_links,
        "summary": {
            "account_count": len(accounts),
            "resource_count": len(resources),
            "connection_count": len(connections),
            "hybrid_link_count": len(hybrid_links),
        },
    }


# ═════════════════════════════════════════════════════════════════════════════
# Cloud Flow Sync Cursors
# ═════════════════════════════════════════════════════════════════════════════


async def get_cloud_flow_sync_cursor(account_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM cloud_flow_sync_cursors WHERE account_id = ?",
            (account_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def upsert_cloud_flow_sync_cursor(
    account_id: int,
    *,
    last_pull_end: str,
    extra_json: dict | None = None,
) -> None:
    db = await get_db()
    try:
        extra_text = _cloud_json_text(extra_json) if extra_json else "{}"
        now_iso = datetime.now(UTC).isoformat()
        await db.execute(
            """INSERT INTO cloud_flow_sync_cursors (account_id, last_pull_end, extra_json, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(account_id) DO UPDATE SET
                   last_pull_end = excluded.last_pull_end,
                   extra_json = excluded.extra_json,
                   updated_at = excluded.updated_at""",
            (account_id, last_pull_end, extra_text, now_iso),
        )
        await db.commit()
    finally:
        await db.close()


async def list_cloud_flow_sync_cursors() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT c.*, ca.provider, ca.name AS account_name
               FROM cloud_flow_sync_cursors c
               JOIN cloud_accounts ca ON ca.id = c.account_id
               ORDER BY c.account_id""",
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_traffic_metric_sync_cursor(account_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM cloud_traffic_metric_sync_cursors WHERE account_id = ?",
            (account_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def upsert_cloud_traffic_metric_sync_cursor(
    account_id: int,
    *,
    last_pull_end: str,
    extra_json: dict | None = None,
) -> None:
    db = await get_db()
    try:
        extra_text = _cloud_json_text(extra_json) if extra_json else "{}"
        now_iso = datetime.now(UTC).isoformat()
        await db.execute(
            """INSERT INTO cloud_traffic_metric_sync_cursors (account_id, last_pull_end, extra_json, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(account_id) DO UPDATE SET
                   last_pull_end = excluded.last_pull_end,
                   extra_json = excluded.extra_json,
                   updated_at = excluded.updated_at""",
            (account_id, last_pull_end, extra_text, now_iso),
        )
        await db.commit()
    finally:
        await db.close()


async def list_cloud_traffic_metric_sync_cursors() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT c.*, ca.provider, ca.name AS account_name
               FROM cloud_traffic_metric_sync_cursors c
               JOIN cloud_accounts ca ON ca.id = c.account_id
               ORDER BY c.account_id""",
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def create_cloud_traffic_metrics_batch(rows: list[tuple]) -> int:
    """Batch insert normalized cloud traffic metric rows.

    Each tuple:
      (account_id, provider, metric_name, metric_namespace, resource_uid,
       direction, statistic, unit, metric_value, interval_start, interval_end,
       metadata_json, source)
    """
    if not rows:
        return 0
    db = await get_db()
    try:
        await db.executemany(
            """INSERT INTO cloud_traffic_metrics
               (account_id, provider, metric_name, metric_namespace, resource_uid,
                direction, statistic, unit, metric_value, interval_start, interval_end,
                metadata_json, source)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        await db.commit()
        return len(rows)
    finally:
        await db.close()


async def get_cloud_traffic_metric_summary(
    account_id: int | None = None,
    provider: str | None = None,
    hours: int = 24,
) -> dict:
    db = await get_db()
    try:
        clauses = [
            "interval_end >= datetime('now', ? || ' hours')",
        ]
        params: list = [f"-{max(1, int(hours))}"]
        if account_id is not None:
            clauses.append("account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("provider = ?")
            params.append(provider)
        where = " AND ".join(clauses)
        cursor = await db.execute(
            f"""SELECT COUNT(*) as sample_count,
                       COUNT(DISTINCT metric_name) as metric_count,
                       COUNT(DISTINCT resource_uid) as resource_count,
                       COALESCE(SUM(metric_value), 0) as total_value,
                       COALESCE(AVG(metric_value), 0) as avg_value,
                       COALESCE(MIN(metric_value), 0) as min_value,
                       COALESCE(MAX(metric_value), 0) as max_value,
                       MIN(interval_start) as first_seen,
                       MAX(interval_end) as last_seen
                FROM cloud_traffic_metrics
                WHERE {where}""",
            tuple(params),
        )
        return row_to_dict(await cursor.fetchone()) or {
            "sample_count": 0,
            "metric_count": 0,
            "resource_count": 0,
            "total_value": 0,
            "avg_value": 0,
            "min_value": 0,
            "max_value": 0,
            "first_seen": None,
            "last_seen": None,
        }
    finally:
        await db.close()


async def get_cloud_traffic_metric_timeline(
    account_id: int | None = None,
    provider: str | None = None,
    metric_name: str | None = None,
    hours: int = 24,
    bucket_minutes: int = 5,
) -> list[dict]:
    bucket_minutes = max(1, min(int(bucket_minutes), 60))
    db = await get_db()
    try:
        clauses = [
            "interval_end >= datetime('now', ? || ' hours')",
        ]
        params: list = [f"-{max(1, int(hours))}"]
        if account_id is not None:
            clauses.append("account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("provider = ?")
            params.append(provider)
        if metric_name:
            clauses.append("metric_name = ?")
            params.append(metric_name)
        where = " AND ".join(clauses)
        cursor = await db.execute(
            f"""SELECT
                   strftime('%Y-%m-%dT%H:', interval_end) ||
                   printf('%02d', (CAST(strftime('%M', interval_end) AS INTEGER) / {bucket_minutes}) * {bucket_minutes}) ||
                   ':00' as bucket,
                   COUNT(*) as sample_count,
                   COALESCE(SUM(metric_value), 0) as total_value,
                   COALESCE(AVG(metric_value), 0) as avg_value,
                   COALESCE(MAX(metric_value), 0) as max_value
               FROM cloud_traffic_metrics
               WHERE {where}
               GROUP BY bucket
               ORDER BY bucket""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_traffic_metric_top_resources(
    account_id: int | None = None,
    provider: str | None = None,
    metric_name: str | None = None,
    hours: int = 24,
    limit: int = 20,
) -> list[dict]:
    db = await get_db()
    try:
        clauses = [
            "interval_end >= datetime('now', ? || ' hours')",
        ]
        params: list = [f"-{max(1, int(hours))}"]
        if account_id is not None:
            clauses.append("account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("provider = ?")
            params.append(provider)
        if metric_name:
            clauses.append("metric_name = ?")
            params.append(metric_name)
        params.append(max(1, min(int(limit), 200)))
        where = " AND ".join(clauses)
        cursor = await db.execute(
            f"""SELECT
                   resource_uid,
                   COUNT(*) as sample_count,
                   COALESCE(SUM(metric_value), 0) as total_value,
                   COALESCE(AVG(metric_value), 0) as avg_value,
                   COALESCE(MAX(metric_value), 0) as max_value
               FROM cloud_traffic_metrics
               WHERE {where}
               GROUP BY resource_uid
               ORDER BY total_value DESC
               LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Geolocation — Sites, Floors, Placements
# ═════════════════════════════════════════════════════════════════════════════

async def list_geo_sites() -> list:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT s.*,
                      COUNT(DISTINCT f.id)                                AS floor_count,
                      COUNT(DISTINCT p.id)                                AS placed_device_count
               FROM geo_sites s
               LEFT JOIN geo_floors f ON f.site_id = s.id
               LEFT JOIN geo_placements p ON p.floor_id = f.id
               GROUP BY s.id
               ORDER BY s.name"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_geo_site(site_id: int) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM geo_sites WHERE id = ?", (site_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_geo_site(name: str, description: str = "", address: str = "",
                          lat: float | None = None, lng: float | None = None,
                          created_by: str = "") -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO geo_sites (name, description, address, lat, lng, created_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, description, address, lat, lng, created_by),
        )
        await db.commit()
        site_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM geo_sites WHERE id = ?", (site_id,))
        return row_to_dict(await cursor2.fetchone())
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError(f"Site name '{name}' already exists.")
        raise
    finally:
        await db.close()


async def update_geo_site(site_id: int, **kwargs) -> dict | None:
    allowed = {"name", "description", "address", "lat", "lng"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return await get_geo_site(site_id)
    updates["updated_at"] = "datetime('now')"
    set_exprs = [f"{k} = ?" for k in updates if k != "updated_at"]
    set_exprs.append("updated_at = datetime('now')")
    vals = [v for k, v in updates.items() if k != "updated_at"]
    sql, params = _safe_dynamic_update("geo_sites", set_exprs, vals, "id = ?", site_id)
    db = await get_db()
    try:
        await db.execute(sql, params)
        await db.commit()
        cursor = await db.execute("SELECT * FROM geo_sites WHERE id = ?", (site_id,))
        return row_to_dict(await cursor.fetchone())
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError("Site name already exists.")
        raise
    finally:
        await db.close()


async def delete_geo_site(site_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM geo_sites WHERE id = ?", (site_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def list_geo_floors(site_id: int) -> list:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT f.*,
                      COUNT(p.id) AS placed_device_count
               FROM geo_floors f
               LEFT JOIN geo_placements p ON p.floor_id = f.id
               WHERE f.site_id = ?
               GROUP BY f.id
               ORDER BY f.floor_number, f.name""",
            (site_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_geo_floor(floor_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM geo_floors WHERE id = ?", (floor_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_geo_floor(site_id: int, name: str, floor_number: int = 0) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO geo_floors (site_id, name, floor_number)
               VALUES (?, ?, ?)""",
            (site_id, name, floor_number),
        )
        await db.commit()
        floor_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM geo_floors WHERE id = ?", (floor_id,))
        return row_to_dict(await cursor2.fetchone())
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError(f"Floor name '{name}' already exists in this site.")
        raise
    finally:
        await db.close()


async def update_geo_floor(floor_id: int, **kwargs) -> dict | None:
    allowed = {"name", "floor_number", "image_filename", "image_width", "image_height"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return await get_geo_floor(floor_id)
    set_exprs = [f"{k} = ?" for k in updates]
    set_exprs.append("updated_at = datetime('now')")
    vals = list(updates.values())
    sql, params = _safe_dynamic_update("geo_floors", set_exprs, vals, "id = ?", floor_id)
    db = await get_db()
    try:
        await db.execute(sql, params)
        await db.commit()
        cursor = await db.execute("SELECT * FROM geo_floors WHERE id = ?", (floor_id,))
        return row_to_dict(await cursor.fetchone())
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError("Floor name already exists in this site.")
        raise
    finally:
        await db.close()


async def delete_geo_floor(floor_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM geo_floors WHERE id = ?", (floor_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_geo_placements(floor_id: int) -> list:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT p.id, p.floor_id, p.host_id, p.x_pct, p.y_pct,
                      h.hostname, h.ip_address, h.status
               FROM geo_placements p
               JOIN hosts h ON h.id = p.host_id
               WHERE p.floor_id = ?
               ORDER BY h.hostname""",
            (floor_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def upsert_geo_placement(floor_id: int, host_id: int,
                               x_pct: float, y_pct: float) -> dict:
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO geo_placements (floor_id, host_id, x_pct, y_pct)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(floor_id, host_id)
               DO UPDATE SET x_pct = excluded.x_pct,
                             y_pct = excluded.y_pct,
                             updated_at = datetime('now')""",
            (floor_id, host_id, x_pct, y_pct),
        )
        await db.commit()
        cursor = await db.execute(
            "SELECT * FROM geo_placements WHERE floor_id = ? AND host_id = ?",
            (floor_id, host_id),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def delete_geo_placement(floor_id: int, host_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM geo_placements WHERE floor_id = ? AND host_id = ?",
            (floor_id, host_id),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_geo_overview() -> list:
    """Return all sites enriched with floor count and device status counts."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT s.id, s.name, s.description, s.address, s.lat, s.lng,
                      s.created_by, s.created_at, s.updated_at,
                      COUNT(DISTINCT f.id)   AS floor_count,
                      COUNT(DISTINCT p.id)   AS placed_device_count,
                      SUM(CASE WHEN h.status = 'up'      THEN 1 ELSE 0 END) AS online_count,
                      SUM(CASE WHEN h.status = 'down'    THEN 1 ELSE 0 END) AS offline_count,
                      SUM(CASE WHEN h.status NOT IN ('up','down') OR h.status IS NULL
                               THEN 1 ELSE 0 END) AS unknown_count
               FROM geo_sites s
               LEFT JOIN geo_floors f    ON f.site_id = s.id
               LEFT JOIN geo_placements p ON p.floor_id = f.id
               LEFT JOIN hosts h          ON h.id = p.host_id
               GROUP BY s.id
               ORDER BY s.name"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Digital Twin / Lab Mode (migration 0029)
# ═════════════════════════════════════════════════════════════════════════════

async def create_lab_environment(
    name: str,
    description: str = "",
    owner_id: int | None = None,
    shared: bool = False,
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO lab_environments (name, description, owner_id, shared, active)
               VALUES (?,?,?,?,1)""",
            (name, description, owner_id, 1 if shared else 0),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_lab_environments(user_id: int | None = None, is_admin: bool = False) -> list[dict]:
    """List visible environments. Admins see all; non-admins see their own + shared."""
    db = await get_db()
    try:
        if is_admin or user_id is None:
            cursor = await db.execute(
                """SELECT e.*, COUNT(d.id) AS device_count
                   FROM lab_environments e
                   LEFT JOIN lab_devices d ON d.environment_id = e.id
                   GROUP BY e.id
                   ORDER BY e.name"""
            )
        else:
            cursor = await db.execute(
                """SELECT e.*, COUNT(d.id) AS device_count
                   FROM lab_environments e
                   LEFT JOIN lab_devices d ON d.environment_id = e.id
                   WHERE e.owner_id = ? OR e.shared = 1 OR e.owner_id IS NULL
                   GROUP BY e.id
                   ORDER BY e.name""",
                (user_id,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_lab_environment(env_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM lab_environments WHERE id = ?", (env_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_lab_environment(
    env_id: int,
    name: str | None = None,
    description: str | None = None,
    shared: bool | None = None,
    active: bool | None = None,
) -> bool:
    fields = []
    values: list = []
    if name is not None:
        fields.append("name = ?")
        values.append(name)
    if description is not None:
        fields.append("description = ?")
        values.append(description)
    if shared is not None:
        fields.append("shared = ?")
        values.append(1 if shared else 0)
    if active is not None:
        fields.append("active = ?")
        values.append(1 if active else 0)
    if not fields:
        return False
    fields.append("updated_at = ?")
    values.append(datetime.now(UTC).isoformat())
    sql, params = _safe_dynamic_update(
        "lab_environments", fields, values, "id = ?", env_id,
    )
    db = await get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def delete_lab_environment(env_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM lab_environments WHERE id = ?", (env_id,),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def create_lab_device(
    environment_id: int,
    hostname: str,
    ip_address: str = "",
    device_type: str = "cisco_ios",
    model: str = "",
    source_host_id: int | None = None,
    running_config: str = "",
    notes: str = "",
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO lab_devices
               (environment_id, hostname, ip_address, device_type, model,
                source_host_id, running_config, notes)
               VALUES (?,?,?,?,?,?,?,?)""",
            (environment_id, hostname, ip_address, device_type, model,
             source_host_id, running_config, notes),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_lab_devices(environment_id: int) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT d.id, d.environment_id, d.hostname, d.ip_address,
                      d.device_type, d.model, d.source_host_id, d.notes,
                      d.created_at, d.updated_at,
                      LENGTH(d.running_config) AS config_size,
                      d.runtime_kind, d.runtime_status, d.runtime_mgmt_address,
                      d.runtime_node_kind, d.runtime_image,
                      (SELECT COUNT(*) FROM lab_runs r WHERE r.lab_device_id = d.id) AS run_count
               FROM lab_devices d
               WHERE d.environment_id = ?
               ORDER BY d.hostname""",
            (environment_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_lab_device(device_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM lab_devices WHERE id = ?", (device_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_lab_device(
    device_id: int,
    hostname: str | None = None,
    ip_address: str | None = None,
    device_type: str | None = None,
    model: str | None = None,
    running_config: str | None = None,
    notes: str | None = None,
) -> bool:
    fields = []
    values: list = []
    if hostname is not None:
        fields.append("hostname = ?")
        values.append(hostname)
    if ip_address is not None:
        fields.append("ip_address = ?")
        values.append(ip_address)
    if device_type is not None:
        fields.append("device_type = ?")
        values.append(device_type)
    if model is not None:
        fields.append("model = ?")
        values.append(model)
    if running_config is not None:
        fields.append("running_config = ?")
        values.append(running_config)
    if notes is not None:
        fields.append("notes = ?")
        values.append(notes)
    if not fields:
        return False
    fields.append("updated_at = ?")
    values.append(datetime.now(UTC).isoformat())
    sql, params = _safe_dynamic_update(
        "lab_devices", fields, values, "id = ?", device_id,
    )
    db = await get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def delete_lab_device(device_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM lab_devices WHERE id = ?", (device_id,),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def create_lab_run(
    lab_device_id: int,
    submitted_by: str,
    commands: list[str],
    pre_config: str,
    post_config: str,
    diff_text: str,
    diff_added: int,
    diff_removed: int,
    risk_score: float = 0.0,
    risk_level: str = "",
    risk_detail: dict | None = None,
    status: str = "simulated",
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO lab_runs
               (lab_device_id, submitted_by, commands, pre_config, post_config,
                diff_text, diff_added, diff_removed, risk_score, risk_level,
                risk_detail, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                lab_device_id, submitted_by,
                json.dumps(commands or []),
                pre_config, post_config, diff_text, diff_added, diff_removed,
                float(risk_score), risk_level,
                json.dumps(risk_detail or {}),
                status,
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_lab_runs(lab_device_id: int, limit: int = 50) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, lab_device_id, submitted_by, diff_added, diff_removed,
                      risk_score, risk_level, status, promoted_deployment_id,
                      created_at
               FROM lab_runs
               WHERE lab_device_id = ?
               ORDER BY id DESC LIMIT ?""",
            (lab_device_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_lab_run(run_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM lab_runs WHERE id = ?", (run_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_lab_run_status(
    run_id: int,
    status: str,
    promoted_deployment_id: int | None = None,
) -> bool:
    db = await get_db()
    try:
        if promoted_deployment_id is not None:
            cursor = await db.execute(
                "UPDATE lab_runs SET status = ?, promoted_deployment_id = ? WHERE id = ?",
                (status, promoted_deployment_id, run_id),
            )
        else:
            cursor = await db.execute(
                "UPDATE lab_runs SET status = ? WHERE id = ?",
                (status, run_id),
            )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ── Phase B-1: containerlab runtime helpers ──────────────────────────────────


async def update_lab_device_runtime(
    device_id: int,
    *,
    runtime_kind: str | None = None,
    runtime_node_kind: str | None = None,
    runtime_image: str | None = None,
    runtime_status: str | None = None,
    runtime_lab_name: str | None = None,
    runtime_node_name: str | None = None,
    runtime_mgmt_address: str | None = None,
    runtime_credential_id: int | None | object = ...,
    runtime_error: str | None = None,
    runtime_workdir: str | None = None,
    runtime_started_at: str | None | object = ...,
) -> bool:
    """Update runtime fields on a lab device. Skips fields left as the default sentinel."""
    fields: list[str] = []
    values: list = []
    if runtime_kind is not None:
        fields.append("runtime_kind = ?")
        values.append(runtime_kind)
    if runtime_node_kind is not None:
        fields.append("runtime_node_kind = ?")
        values.append(runtime_node_kind)
    if runtime_image is not None:
        fields.append("runtime_image = ?")
        values.append(runtime_image)
    if runtime_status is not None:
        fields.append("runtime_status = ?")
        values.append(runtime_status)
    if runtime_lab_name is not None:
        fields.append("runtime_lab_name = ?")
        values.append(runtime_lab_name)
    if runtime_node_name is not None:
        fields.append("runtime_node_name = ?")
        values.append(runtime_node_name)
    if runtime_mgmt_address is not None:
        fields.append("runtime_mgmt_address = ?")
        values.append(runtime_mgmt_address)
    if runtime_credential_id is not ...:
        fields.append("runtime_credential_id = ?")
        values.append(runtime_credential_id)
    if runtime_error is not None:
        fields.append("runtime_error = ?")
        values.append(runtime_error)
    if runtime_workdir is not None:
        fields.append("runtime_workdir = ?")
        values.append(runtime_workdir)
    if runtime_started_at is not ...:
        fields.append("runtime_started_at = ?")
        values.append(runtime_started_at)
    if not fields:
        return False
    fields.append("updated_at = ?")
    values.append(datetime.now(UTC).isoformat())
    sql, params = _safe_dynamic_update(
        "lab_devices", fields, values, "id = ?", device_id,
    )
    db = await get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def add_lab_runtime_event(
    lab_device_id: int,
    action: str,
    status: str = "ok",
    actor: str = "",
    detail: str = "",
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO lab_runtime_events
               (lab_device_id, action, status, actor, detail)
               VALUES (?,?,?,?,?)""",
            (lab_device_id, action, status, actor, detail),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_lab_runtime_events(lab_device_id: int, limit: int = 50) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, lab_device_id, action, status, actor, detail, created_at
               FROM lab_runtime_events
               WHERE lab_device_id = ?
               ORDER BY id DESC LIMIT ?""",
            (lab_device_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def list_running_lab_devices() -> list[dict]:
    """Return all lab devices currently in `provisioning` or `running` state.

    Used at startup to reconcile in-memory state with whatever containerlab is
    actually still running (or to surface stale rows after a crash).
    """
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM lab_devices
               WHERE runtime_kind = 'containerlab'
                 AND runtime_status IN ('provisioning','running')"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ── Phase B-2: lab topologies (multi-device) ────────────────────────────────


async def create_lab_topology(
    environment_id: int,
    name: str,
    description: str = "",
    mgmt_subnet: str = "",
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO lab_topologies
               (environment_id, name, description, mgmt_subnet)
               VALUES (?, ?, ?, ?)""",
            (environment_id, name, description, mgmt_subnet),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_lab_topologies(environment_id: int) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT t.*,
                      (SELECT COUNT(*) FROM lab_devices d WHERE d.topology_id = t.id) AS device_count,
                      (SELECT COUNT(*) FROM lab_topology_links l WHERE l.topology_id = t.id) AS link_count
               FROM lab_topologies t
               WHERE t.environment_id = ?
               ORDER BY t.name""",
            (environment_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_lab_topology(topology_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM lab_topologies WHERE id = ?", (topology_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_lab_topology_status(
    topology_id: int,
    *,
    status: str | None = None,
    lab_name: str | None = None,
    workdir: str | None = None,
    error: str | None = None,
    started_at: str | None | object = ...,
) -> bool:
    fields: list[str] = []
    values: list = []
    if status is not None:
        fields.append("status = ?")
        values.append(status)
    if lab_name is not None:
        fields.append("lab_name = ?")
        values.append(lab_name)
    if workdir is not None:
        fields.append("workdir = ?")
        values.append(workdir)
    if error is not None:
        fields.append("error = ?")
        values.append(error)
    if started_at is not ...:
        fields.append("started_at = ?")
        values.append(started_at)
    if not fields:
        return False
    fields.append("updated_at = ?")
    values.append(datetime.now(UTC).isoformat())
    sql, params = _safe_dynamic_update(
        "lab_topologies", fields, values, "id = ?", topology_id,
    )
    db = await get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def delete_lab_topology(topology_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM lab_topologies WHERE id = ?", (topology_id,),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def set_lab_device_topology(device_id: int, topology_id: int | None) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE lab_devices SET topology_id = ?, updated_at = ? WHERE id = ?",
            (topology_id, datetime.now(UTC).isoformat(), device_id),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def list_topology_devices(topology_id: int) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM lab_devices
               WHERE topology_id = ?
               ORDER BY hostname""",
            (topology_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def create_lab_topology_link(
    topology_id: int,
    a_device_id: int,
    a_endpoint: str,
    b_device_id: int,
    b_endpoint: str,
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO lab_topology_links
               (topology_id, a_device_id, a_endpoint, b_device_id, b_endpoint)
               VALUES (?, ?, ?, ?, ?)""",
            (topology_id, a_device_id, a_endpoint, b_device_id, b_endpoint),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_topology_links(topology_id: int) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM lab_topology_links WHERE topology_id = ? ORDER BY id",
            (topology_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_lab_topology_link(link_id: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM lab_topology_links WHERE id = ?", (link_id,),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def list_running_lab_topologies() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM lab_topologies
               WHERE status IN ('provisioning','running')"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ── Phase B-3a: drift-from-twin ─────────────────────────────────────────────


async def create_lab_drift_run(
    lab_device_id: int,
    source_host_id: int | None,
    status: str,
    diff_text: str = "",
    diff_added: int = 0,
    diff_removed: int = 0,
    twin_bytes: int = 0,
    prod_bytes: int = 0,
    actor: str = "",
    error: str = "",
) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO lab_drift_runs
               (lab_device_id, source_host_id, status, diff_text,
                diff_added, diff_removed, twin_bytes, prod_bytes, actor, error)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (lab_device_id, source_host_id, status, diff_text,
             diff_added, diff_removed, twin_bytes, prod_bytes, actor, error),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_lab_drift_runs(lab_device_id: int, limit: int = 50) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, lab_device_id, source_host_id, status,
                      diff_added, diff_removed, twin_bytes, prod_bytes,
                      actor, error, checked_at
               FROM lab_drift_runs
               WHERE lab_device_id = ?
               ORDER BY id DESC LIMIT ?""",
            (lab_device_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_lab_drift_run(run_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM lab_drift_runs WHERE id = ?", (run_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def get_latest_lab_drift_run(lab_device_id: int) -> dict | None:
    """Return the most recent drift run for a lab device, sans diff_text."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, lab_device_id, source_host_id, status,
                      diff_added, diff_removed, twin_bytes, prod_bytes,
                      actor, error, checked_at
               FROM lab_drift_runs
               WHERE lab_device_id = ?
               ORDER BY id DESC LIMIT 1""",
            (lab_device_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def list_drift_eligible_devices() -> list[dict]:
    """Lab devices with a source host attached — the only ones drift checks
    can compare. Used by the scheduler to decide what to walk each tick.
    """
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, environment_id, hostname, source_host_id, running_config
               FROM lab_devices
               WHERE source_host_id IS NOT NULL"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()
