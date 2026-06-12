"""
database.py - Async SQLite database layer for Plexus.

Tables:
    inventory_groups  - device groups (name, description)
    hosts             - individual devices linked to a group
    playbooks         - registered automation scripts
    templates         - reusable config snippets
    credentials       - encrypted SSH credentials per inventory group
    jobs              - execution history
    job_events        - per-host log lines for each job
    audit_events      - immutable audit trail for auth, CRUD, and operational actions
    topology_links    - discovered L2/L3 neighbor relationships between devices
    interface_stats   - SNMP interface counter snapshots for utilization calculation
    topology_changes  - detected topology differences between discovery runs
    stp_port_states   - latest spanning-tree port states per host/VLAN
    stp_topology_events - spanning-tree root/state change events
    stp_root_policies - expected STP root-bridge policy by group/VLAN
    config_baselines  - intended/golden configuration per host
    config_snapshots  - timestamped running-config captures per host
    config_drift_events - detected configuration drift instances
    config_backup_policies - scheduled configuration backup policies per group
    config_backups     - stored configuration backup records
    compliance_profiles - golden template compliance rule sets
    compliance_profile_assignments - profile-to-group bindings with scan schedule
    compliance_scan_results - per-host compliance scan findings
    risk_analyses          - pre-change risk analysis records
    deployments            - deployment orchestration records with rollback support
    deployment_checkpoints - pre/post deployment validation checks
    deployment_snapshots   - per-host config snapshots captured before/after deployment
    monitoring_polls       - periodic device health poll snapshots (CPU/mem/interfaces/VPN/routes)
    monitoring_alerts      - threshold violations and anomaly alerts (with dedup/escalation)
    route_snapshots        - route table captures for churn detection
    alert_rules            - user-defined threshold/anomaly alert rules
    alert_suppressions     - time-windowed alert suppression entries
    report_artifacts       - persisted report outputs (CSV/SVG/etc) by run
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
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
    "host_ip_aliases",
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
    "flow_exporters",
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
    "mac_move_events",
    "mac_move_event_history",
    "interface_error_events",
    "maintenance_windows",
    "audit_runs",
    "audit_findings",
    "audit_rule_overrides",
    "audit_schedules",
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
    session_never_expires INTEGER NOT NULL DEFAULT 0,
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
    environment TEXT    DEFAULT NULL,
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
    device_category TEXT NOT NULL DEFAULT '',
    serial_number TEXT NOT NULL DEFAULT '',
    vrf_name    TEXT    NOT NULL DEFAULT '',
    vlan_id     TEXT    NOT NULL DEFAULT '',
    fdm_api_enabled   INTEGER NOT NULL DEFAULT 0,
    fdm_credential_id INTEGER,
    fdm_port          INTEGER NOT NULL DEFAULT 443,
    fdm_verify_tls    INTEGER NOT NULL DEFAULT 0,
    UNIQUE(group_id, ip_address)
);

-- Secondary interface IPs a device owns (learned from its SNMP ipAddrTable).
-- Lets discovery recognise that a probed IP belongs to a device already in
-- inventory instead of creating a duplicate host per interface IP, and lets
-- topology resolve secondary IPs to the owning host. See migration 0053.
CREATE TABLE IF NOT EXISTS host_ip_aliases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    ip_address  TEXT    NOT NULL,
    UNIQUE(host_id, ip_address)
);
CREATE INDEX IF NOT EXISTS idx_host_ip_aliases_ip ON host_ip_aliases(ip_address);

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
    name        TEXT    NOT NULL,
    device_type TEXT    NOT NULL DEFAULT '',
    content     TEXT    NOT NULL DEFAULT '',
    description TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(name, device_type)
);

CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    username    TEXT    NOT NULL,
    password    TEXT    NOT NULL,
    secret      TEXT    NOT NULL DEFAULT '',
    owner_id    INTEGER REFERENCES users(id),
    is_service  INTEGER NOT NULL DEFAULT 0,
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
    "user"          TEXT    NOT NULL DEFAULT '',
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
    -- Counter64 columns: real switches push tens of billions of bytes, which
    -- overflow signed int32 (~2.1B). BIGINT in postgres / INTEGER affinity
    -- in sqlite (which is variable-width) keeps both engines happy.
    in_octets           BIGINT  DEFAULT 0,
    out_octets          BIGINT  DEFAULT 0,
    prev_in_octets      BIGINT  DEFAULT 0,
    prev_out_octets     BIGINT  DEFAULT 0,
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
    requires_approval     INTEGER NOT NULL DEFAULT 0,
    approval_status       TEXT    NOT NULL DEFAULT 'not_required',
    approval_requested_at TEXT,
    approved_by           TEXT    DEFAULT '',
    approved_at           TEXT,
    approval_comment      TEXT    DEFAULT '',
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    started_at      TEXT,
    finished_at     TEXT
);

CREATE TABLE IF NOT EXISTS maintenance_windows (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    start_at        TEXT    NOT NULL,
    end_at          TEXT    NOT NULL,
    recurrence      TEXT    NOT NULL DEFAULT 'none',
    weekday_mask    INTEGER NOT NULL DEFAULT 0,
    policy          TEXT    NOT NULL DEFAULT 'block_outside_window',
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS maintenance_window_scopes (
    window_id   INTEGER NOT NULL REFERENCES maintenance_windows(id) ON DELETE CASCADE,
    group_id    INTEGER NOT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (window_id, group_id)
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
    icmp_alive       INTEGER DEFAULT NULL,
    icmp_rtt_ms      REAL    DEFAULT NULL,
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
    channel_ids     TEXT    NOT NULL DEFAULT '',
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
    in_octets       BIGINT  DEFAULT 0,
    out_octets      BIGINT  DEFAULT 0,
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

-- ── MAC move events (drift-style change tracking) ────────────────────────
-- One row per detected MAC relocation -- the switch, port, VLAN or IP
-- binding changed from the MAC's last-known location. Only written on
-- change, not every poll. Operators acknowledge events and the lifecycle
-- timeline lives in mac_move_event_history.

CREATE TABLE IF NOT EXISTS mac_move_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address     TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'open',
    change_kind     TEXT    NOT NULL DEFAULT '',
    from_host_id    INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    from_port       TEXT    NOT NULL DEFAULT '',
    from_vlan       INTEGER DEFAULT 0,
    from_ip         TEXT    NOT NULL DEFAULT '',
    to_host_id      INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    to_port         TEXT    NOT NULL DEFAULT '',
    to_vlan         INTEGER DEFAULT 0,
    to_ip           TEXT    NOT NULL DEFAULT '',
    detected_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    acknowledged_at TEXT,
    acknowledged_by TEXT    DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_mac_move_events_mac ON mac_move_events(mac_address, detected_at);
CREATE INDEX IF NOT EXISTS idx_mac_move_events_status ON mac_move_events(status, detected_at);

CREATE TABLE IF NOT EXISTS mac_move_event_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        INTEGER NOT NULL REFERENCES mac_move_events(id) ON DELETE CASCADE,
    mac_address     TEXT    NOT NULL,
    action          TEXT    NOT NULL DEFAULT '',
    from_status     TEXT    NOT NULL DEFAULT '',
    to_status       TEXT    NOT NULL DEFAULT '',
    actor           TEXT    NOT NULL DEFAULT '',
    details         TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_mac_move_event_history_event_created
ON mac_move_event_history(event_id, created_at DESC);

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

CREATE TABLE IF NOT EXISTS flow_exporters (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    exporter_ip     TEXT    NOT NULL,
    host_id         INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    flow_type       TEXT    NOT NULL DEFAULT 'netflow',
    packets_received INTEGER NOT NULL DEFAULT 0,
    sampling_rate   INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT    NOT NULL DEFAULT (datetime('now')),
    last_record_at  TEXT,
    UNIQUE(exporter_ip, flow_type)
);
CREATE INDEX IF NOT EXISTS idx_flow_exporters_host ON flow_exporters(host_id);

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
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    scheduled_at    TEXT
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

CREATE TABLE IF NOT EXISTS upgrade_operations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id     INTEGER NOT NULL REFERENCES upgrade_campaigns(id) ON DELETE CASCADE,
    phase           TEXT    NOT NULL DEFAULT '',
    status          TEXT    NOT NULL DEFAULT 'pending',
    requested_by    TEXT    NOT NULL DEFAULT '',
    device_count    INTEGER NOT NULL DEFAULT 0,
    succeeded       INTEGER NOT NULL DEFAULT 0,
    failed          INTEGER NOT NULL DEFAULT 0,
    cancelled       INTEGER NOT NULL DEFAULT 0,
    scheduled_at    TEXT,
    started_at      TEXT,
    completed_at    TEXT,
    error_message   TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_upgrade_operations_campaign_created
    ON upgrade_operations(campaign_id, created_at DESC);

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

-- ════════════════════════════════════════════════════════════════════════════
-- v1.0.0 baseline tables originally added by migrations 0008-0032.
-- Folded into SCHEMA so a fresh deploy creates them all in one shot. The
-- migration runner records 1-32 as applied on first boot, and new schema
-- work starts at migration 0033+.
-- ════════════════════════════════════════════════════════════════════════════

-- 0008: interface error tracking
CREATE TABLE IF NOT EXISTS interface_error_stats (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id             INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    if_index            INTEGER NOT NULL,
    if_name             TEXT    NOT NULL DEFAULT '',
    in_errors           INTEGER DEFAULT 0,
    out_errors          INTEGER DEFAULT 0,
    in_discards         INTEGER DEFAULT 0,
    out_discards        INTEGER DEFAULT 0,
    prev_in_errors      INTEGER DEFAULT 0,
    prev_out_errors     INTEGER DEFAULT 0,
    prev_in_discards    INTEGER DEFAULT 0,
    prev_out_discards   INTEGER DEFAULT 0,
    polled_at           TEXT    NOT NULL DEFAULT (datetime('now')),
    prev_polled_at      TEXT    DEFAULT NULL,
    UNIQUE(host_id, if_index)
);
CREATE INDEX IF NOT EXISTS idx_interface_error_stats_host
    ON interface_error_stats (host_id, if_index);

CREATE TABLE IF NOT EXISTS interface_error_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id             INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    if_index            INTEGER NOT NULL,
    if_name             TEXT    NOT NULL DEFAULT '',
    event_type          TEXT    NOT NULL DEFAULT 'spike',
    metric_name         TEXT    NOT NULL DEFAULT '',
    severity            TEXT    NOT NULL DEFAULT 'warning',
    current_rate        REAL    DEFAULT 0,
    baseline_rate       REAL    DEFAULT 0,
    spike_factor        REAL    DEFAULT 0,
    root_cause_hint     TEXT    NOT NULL DEFAULT '',
    root_cause_category TEXT    NOT NULL DEFAULT 'unknown',
    correlation_details TEXT    NOT NULL DEFAULT '{}',
    acknowledged        INTEGER NOT NULL DEFAULT 0,
    acknowledged_by     TEXT    DEFAULT NULL,
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    resolved_at         TEXT    DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_interface_error_events_host
    ON interface_error_events (host_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_interface_error_events_unresolved
    ON interface_error_events (resolved_at, severity);

-- 0009: bandwidth billing
CREATE TABLE IF NOT EXISTS billing_circuits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL DEFAULT '',
    description     TEXT    NOT NULL DEFAULT '',
    customer        TEXT    NOT NULL DEFAULT '',
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    if_index        INTEGER NOT NULL,
    if_name         TEXT    NOT NULL DEFAULT '',
    commit_rate_bps REAL    NOT NULL DEFAULT 0,
    burst_limit_bps REAL    NOT NULL DEFAULT 0,
    billing_day     INTEGER NOT NULL DEFAULT 1,
    billing_cycle   TEXT    NOT NULL DEFAULT 'monthly',
    cost_per_mbps   REAL    NOT NULL DEFAULT 0,
    currency        TEXT    NOT NULL DEFAULT 'USD',
    overage_enabled INTEGER NOT NULL DEFAULT 1,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_billing_circuits_host
    ON billing_circuits (host_id, if_index);
CREATE INDEX IF NOT EXISTS idx_billing_circuits_customer
    ON billing_circuits (customer);

CREATE TABLE IF NOT EXISTS billing_periods (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    circuit_id      INTEGER NOT NULL REFERENCES billing_circuits(id) ON DELETE CASCADE,
    period_start    TEXT    NOT NULL,
    period_end      TEXT    NOT NULL,
    total_samples   INTEGER NOT NULL DEFAULT 0,
    p95_in_bps      REAL    NOT NULL DEFAULT 0,
    p95_out_bps     REAL    NOT NULL DEFAULT 0,
    p95_billing_bps REAL    NOT NULL DEFAULT 0,
    max_in_bps      REAL    NOT NULL DEFAULT 0,
    max_out_bps     REAL    NOT NULL DEFAULT 0,
    avg_in_bps      REAL    NOT NULL DEFAULT 0,
    avg_out_bps     REAL    NOT NULL DEFAULT 0,
    commit_rate_bps REAL    NOT NULL DEFAULT 0,
    overage_bps     REAL    NOT NULL DEFAULT 0,
    overage_cost    REAL    NOT NULL DEFAULT 0,
    total_cost      REAL    NOT NULL DEFAULT 0,
    status          TEXT    NOT NULL DEFAULT 'generated',
    generated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_billing_periods_circuit
    ON billing_periods (circuit_id, period_start);

-- 0011: cloud visibility
CREATE TABLE IF NOT EXISTS cloud_accounts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    provider            TEXT    NOT NULL,
    name                TEXT    NOT NULL,
    account_identifier  TEXT    NOT NULL DEFAULT '',
    region_scope        TEXT    NOT NULL DEFAULT '',
    auth_type           TEXT    NOT NULL DEFAULT 'manual',
    auth_config_json    TEXT    NOT NULL DEFAULT '{}',
    notes               TEXT    NOT NULL DEFAULT '',
    enabled             INTEGER NOT NULL DEFAULT 1,
    last_sync_at        TEXT,
    last_sync_status    TEXT    NOT NULL DEFAULT 'never',
    last_sync_message   TEXT    NOT NULL DEFAULT '',
    created_by          TEXT    NOT NULL DEFAULT '',
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT
);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_provider_enabled
    ON cloud_accounts (provider, enabled);

CREATE TABLE IF NOT EXISTS cloud_resources (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id      INTEGER NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    provider        TEXT    NOT NULL,
    resource_uid    TEXT    NOT NULL,
    resource_type   TEXT    NOT NULL,
    name            TEXT    NOT NULL DEFAULT '',
    region          TEXT    NOT NULL DEFAULT '',
    cidr            TEXT    NOT NULL DEFAULT '',
    status          TEXT    NOT NULL DEFAULT '',
    metadata_json   TEXT    NOT NULL DEFAULT '{}',
    discovered_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(account_id, resource_uid)
);
CREATE INDEX IF NOT EXISTS idx_cloud_resources_account_type
    ON cloud_resources (account_id, resource_type);

CREATE TABLE IF NOT EXISTS cloud_connections (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id          INTEGER NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    provider            TEXT    NOT NULL,
    source_resource_uid TEXT    NOT NULL,
    target_resource_uid TEXT    NOT NULL,
    connection_type     TEXT    NOT NULL DEFAULT 'peering',
    state               TEXT    NOT NULL DEFAULT '',
    metadata_json       TEXT    NOT NULL DEFAULT '{}',
    discovered_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(account_id, source_resource_uid, target_resource_uid, connection_type)
);
CREATE INDEX IF NOT EXISTS idx_cloud_connections_account
    ON cloud_connections (account_id, source_resource_uid, target_resource_uid);

CREATE TABLE IF NOT EXISTS cloud_hybrid_links (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id          INTEGER NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    provider            TEXT    NOT NULL,
    host_id             INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    host_label          TEXT    NOT NULL DEFAULT '',
    cloud_resource_uid  TEXT    NOT NULL,
    connection_type     TEXT    NOT NULL DEFAULT 'vpn',
    state               TEXT    NOT NULL DEFAULT '',
    metadata_json       TEXT    NOT NULL DEFAULT '{}',
    discovered_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_hybrid_links_unique
    ON cloud_hybrid_links (account_id, host_id, cloud_resource_uid, connection_type);
CREATE INDEX IF NOT EXISTS idx_cloud_hybrid_links_account
    ON cloud_hybrid_links (account_id, host_id, cloud_resource_uid);

-- 0012: cloud flow sync cursors
CREATE TABLE IF NOT EXISTS cloud_flow_sync_cursors (
    account_id      INTEGER PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    last_pull_end   TEXT    NOT NULL DEFAULT '',
    extra_json      TEXT    NOT NULL DEFAULT '{}',
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- 0014: federation
CREATE TABLE IF NOT EXISTS federation_peers (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT    NOT NULL,
    url                 TEXT    NOT NULL,
    api_token_enc       TEXT    NOT NULL DEFAULT '',
    description         TEXT    NOT NULL DEFAULT '',
    enabled             INTEGER NOT NULL DEFAULT 1,
    last_sync_at        TEXT,
    last_sync_status    TEXT    NOT NULL DEFAULT 'never',
    last_sync_message   TEXT    NOT NULL DEFAULT '',
    created_by          TEXT    NOT NULL DEFAULT '',
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT
);

CREATE TABLE IF NOT EXISTS federation_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id     INTEGER NOT NULL REFERENCES federation_peers(id) ON DELETE CASCADE,
    category    TEXT    NOT NULL,
    data_json   TEXT    NOT NULL DEFAULT '{}',
    captured_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- 0015: cloud traffic metrics
CREATE TABLE IF NOT EXISTS cloud_traffic_metrics (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id          INTEGER NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    provider            TEXT    NOT NULL,
    metric_name         TEXT    NOT NULL,
    metric_namespace    TEXT    NOT NULL DEFAULT '',
    resource_uid        TEXT    NOT NULL DEFAULT '',
    direction           TEXT    NOT NULL DEFAULT '',
    statistic           TEXT    NOT NULL DEFAULT '',
    unit                TEXT    NOT NULL DEFAULT '',
    metric_value        REAL    NOT NULL DEFAULT 0,
    interval_start      TEXT    NOT NULL,
    interval_end        TEXT    NOT NULL,
    metadata_json       TEXT    NOT NULL DEFAULT '{}',
    source              TEXT    NOT NULL DEFAULT 'api',
    ingested_at         TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cloud_traffic_metrics_lookup
    ON cloud_traffic_metrics (account_id, provider, metric_name, interval_end);
CREATE INDEX IF NOT EXISTS idx_cloud_traffic_metrics_resource
    ON cloud_traffic_metrics (resource_uid, interval_end);

-- 0016: cloud traffic metric sync cursors
CREATE TABLE IF NOT EXISTS cloud_traffic_metric_sync_cursors (
    account_id      INTEGER PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    last_pull_end   TEXT    NOT NULL DEFAULT '',
    extra_json      TEXT    NOT NULL DEFAULT '{}',
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- 0017: cloud policy rules
CREATE TABLE IF NOT EXISTS cloud_policy_rules (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id              INTEGER NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    provider                TEXT    NOT NULL,
    resource_uid            TEXT    NOT NULL,
    rule_uid                TEXT    NOT NULL,
    rule_name               TEXT    NOT NULL DEFAULT '',
    direction               TEXT    NOT NULL DEFAULT '',
    action                  TEXT    NOT NULL DEFAULT '',
    protocol                TEXT    NOT NULL DEFAULT '',
    source_selector         TEXT    NOT NULL DEFAULT '',
    destination_selector    TEXT    NOT NULL DEFAULT '',
    port_expression         TEXT    NOT NULL DEFAULT '',
    priority                INTEGER,
    metadata_json           TEXT    NOT NULL DEFAULT '{}',
    discovered_at           TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(account_id, rule_uid)
);
CREATE INDEX IF NOT EXISTS idx_cloud_policy_rules_account_resource
    ON cloud_policy_rules (account_id, resource_uid);
CREATE INDEX IF NOT EXISTS idx_cloud_policy_rules_provider_action
    ON cloud_policy_rules (provider, action, direction);

-- 0018 + 0019: ipam sources/prefixes/allocations/reservations (with push_enabled from 0019)
CREATE TABLE IF NOT EXISTS ipam_sources (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    provider            TEXT    NOT NULL,
    name                TEXT    NOT NULL,
    base_url            TEXT    NOT NULL DEFAULT '',
    auth_type           TEXT    NOT NULL DEFAULT 'token',
    auth_config_enc     TEXT    NOT NULL DEFAULT '',
    sync_scope          TEXT    NOT NULL DEFAULT '',
    notes               TEXT    NOT NULL DEFAULT '',
    enabled             INTEGER NOT NULL DEFAULT 1,
    verify_tls          INTEGER NOT NULL DEFAULT 1,
    push_enabled        INTEGER NOT NULL DEFAULT 0,
    last_sync_at        TEXT,
    last_sync_status    TEXT    NOT NULL DEFAULT 'never',
    last_sync_message   TEXT    NOT NULL DEFAULT '',
    created_by          TEXT    NOT NULL DEFAULT '',
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT
);
CREATE INDEX IF NOT EXISTS idx_ipam_sources_provider_enabled
    ON ipam_sources (provider, enabled);

CREATE TABLE IF NOT EXISTS ipam_prefixes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id       INTEGER NOT NULL REFERENCES ipam_sources(id) ON DELETE CASCADE,
    external_id     TEXT    NOT NULL,
    subnet          TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    status          TEXT    NOT NULL DEFAULT '',
    vrf             TEXT    NOT NULL DEFAULT '',
    tenant          TEXT    NOT NULL DEFAULT '',
    site            TEXT    NOT NULL DEFAULT '',
    vlan            TEXT    NOT NULL DEFAULT '',
    metadata_json   TEXT    NOT NULL DEFAULT '{}',
    discovered_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(source_id, external_id, subnet)
);
CREATE INDEX IF NOT EXISTS idx_ipam_prefixes_source_subnet
    ON ipam_prefixes (source_id, subnet);

-- 0018 + 0025: ipam_allocations (with vrf_name/vlan_id columns inlined from 0025)
CREATE TABLE IF NOT EXISTS ipam_allocations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id       INTEGER NOT NULL REFERENCES ipam_sources(id) ON DELETE CASCADE,
    prefix_subnet   TEXT    NOT NULL DEFAULT '',
    address         TEXT    NOT NULL,
    dns_name        TEXT    NOT NULL DEFAULT '',
    status          TEXT    NOT NULL DEFAULT '',
    description     TEXT    NOT NULL DEFAULT '',
    metadata_json   TEXT    NOT NULL DEFAULT '{}',
    discovered_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    vrf_name        TEXT    NOT NULL DEFAULT '',
    vlan_id         TEXT    NOT NULL DEFAULT '',
    UNIQUE(source_id, address)
);
CREATE INDEX IF NOT EXISTS idx_ipam_allocations_source_prefix
    ON ipam_allocations (source_id, prefix_subnet, address);

CREATE TABLE IF NOT EXISTS ipam_reservations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    subnet      TEXT    NOT NULL,
    start_ip    TEXT    NOT NULL,
    end_ip      TEXT    NOT NULL,
    reason      TEXT    NOT NULL DEFAULT '',
    created_by  TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ipam_reservations_subnet
    ON ipam_reservations (subnet, start_ip, end_ip);

-- 0020: geolocation
CREATE TABLE IF NOT EXISTS geo_sites (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    NOT NULL DEFAULT '',
    address     TEXT    NOT NULL DEFAULT '',
    lat         REAL    DEFAULT NULL,
    lng         REAL    DEFAULT NULL,
    created_by  TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS geo_floors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id         INTEGER NOT NULL REFERENCES geo_sites(id) ON DELETE CASCADE,
    name            TEXT    NOT NULL,
    floor_number    INTEGER NOT NULL DEFAULT 0,
    image_filename  TEXT    DEFAULT NULL,
    image_width     INTEGER NOT NULL DEFAULT 1200,
    image_height    INTEGER NOT NULL DEFAULT 800,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(site_id, name)
);
CREATE INDEX IF NOT EXISTS idx_geo_floors_site
    ON geo_floors (site_id);

CREATE TABLE IF NOT EXISTS geo_placements (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    floor_id    INTEGER NOT NULL REFERENCES geo_floors(id) ON DELETE CASCADE,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    x_pct       REAL    NOT NULL DEFAULT 0.5,
    y_pct       REAL    NOT NULL DEFAULT 0.5,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(floor_id, host_id)
);
CREATE INDEX IF NOT EXISTS idx_geo_placements_floor
    ON geo_placements (floor_id);
CREATE INDEX IF NOT EXISTS idx_geo_placements_host
    ON geo_placements (host_id);

-- 0023: ipam reconciliation
CREATE TABLE IF NOT EXISTS ipam_reconciliation_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id       INTEGER NOT NULL REFERENCES ipam_sources(id) ON DELETE CASCADE,
    started_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    finished_at     TEXT,
    status          TEXT    NOT NULL DEFAULT 'running',
    triggered_by    TEXT    NOT NULL DEFAULT '',
    diff_count      INTEGER NOT NULL DEFAULT 0,
    resolved_count  INTEGER NOT NULL DEFAULT 0,
    message         TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ipam_reconciliation_runs_source
    ON ipam_reconciliation_runs (source_id, started_at DESC);

CREATE TABLE IF NOT EXISTS ipam_reconciliation_diffs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              INTEGER NOT NULL REFERENCES ipam_reconciliation_runs(id) ON DELETE CASCADE,
    source_id           INTEGER NOT NULL REFERENCES ipam_sources(id) ON DELETE CASCADE,
    address             TEXT    NOT NULL,
    drift_type          TEXT    NOT NULL,
    plexus_state_json   TEXT    NOT NULL DEFAULT '{}',
    ipam_state_json     TEXT    NOT NULL DEFAULT '{}',
    resolution          TEXT    NOT NULL DEFAULT '',
    resolved_by         TEXT    NOT NULL DEFAULT '',
    resolved_at         TEXT,
    resolution_message  TEXT    NOT NULL DEFAULT '',
    created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ipam_reconciliation_diffs_open
    ON ipam_reconciliation_diffs (source_id, resolution, address);
CREATE INDEX IF NOT EXISTS idx_ipam_reconciliation_diffs_run
    ON ipam_reconciliation_diffs (run_id);

-- 0024: dhcp
CREATE TABLE IF NOT EXISTS dhcp_servers (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    provider            TEXT    NOT NULL,
    name                TEXT    NOT NULL,
    base_url            TEXT    NOT NULL DEFAULT '',
    auth_type           TEXT    NOT NULL DEFAULT 'token',
    auth_config_enc     TEXT    NOT NULL DEFAULT '',
    notes               TEXT    NOT NULL DEFAULT '',
    enabled             INTEGER NOT NULL DEFAULT 1,
    verify_tls          INTEGER NOT NULL DEFAULT 1,
    last_sync_at        TEXT,
    last_sync_status    TEXT    NOT NULL DEFAULT 'never',
    last_sync_message   TEXT    NOT NULL DEFAULT '',
    created_by          TEXT    NOT NULL DEFAULT '',
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT
);

CREATE TABLE IF NOT EXISTS dhcp_scopes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id       INTEGER NOT NULL REFERENCES dhcp_servers(id) ON DELETE CASCADE,
    external_id     TEXT    NOT NULL DEFAULT '',
    subnet          TEXT    NOT NULL,
    name            TEXT    NOT NULL DEFAULT '',
    range_start     TEXT    NOT NULL DEFAULT '',
    range_end       TEXT    NOT NULL DEFAULT '',
    total_addresses INTEGER NOT NULL DEFAULT 0,
    used_addresses  INTEGER NOT NULL DEFAULT 0,
    free_addresses  INTEGER NOT NULL DEFAULT 0,
    state           TEXT    NOT NULL DEFAULT '',
    metadata_json   TEXT    NOT NULL DEFAULT '{}',
    discovered_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(server_id, subnet, external_id)
);
CREATE INDEX IF NOT EXISTS idx_dhcp_scopes_server_subnet
    ON dhcp_scopes (server_id, subnet);

CREATE TABLE IF NOT EXISTS dhcp_leases (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id       INTEGER NOT NULL REFERENCES dhcp_servers(id) ON DELETE CASCADE,
    scope_subnet    TEXT    NOT NULL DEFAULT '',
    address         TEXT    NOT NULL,
    mac_address     TEXT    NOT NULL DEFAULT '',
    hostname        TEXT    NOT NULL DEFAULT '',
    client_id       TEXT    NOT NULL DEFAULT '',
    state           TEXT    NOT NULL DEFAULT '',
    starts_at       TEXT,
    ends_at         TEXT,
    metadata_json   TEXT    NOT NULL DEFAULT '{}',
    discovered_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(server_id, address)
);
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_server_address
    ON dhcp_leases (server_id, address);
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_mac
    ON dhcp_leases (mac_address);

-- 0025: vlan/vrf scoping. Column adds inlined into hosts/ipam_allocations above, just indexes here.
CREATE INDEX IF NOT EXISTS idx_hosts_vrf_ip
    ON hosts (vrf_name, ip_address);
CREATE INDEX IF NOT EXISTS idx_ipam_allocations_vrf_addr
    ON ipam_allocations (vrf_name, address);

-- 0026: ipam pending allocations
CREATE TABLE IF NOT EXISTS ipam_pending_allocations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subnet          TEXT    NOT NULL,
    address         TEXT    NOT NULL,
    vrf_name        TEXT    NOT NULL DEFAULT '',
    hostname        TEXT    NOT NULL DEFAULT '',
    description     TEXT    NOT NULL DEFAULT '',
    source_id       INTEGER,
    external_ref    TEXT    NOT NULL DEFAULT '',
    state           TEXT    NOT NULL DEFAULT 'pending',
    expires_at      TEXT    NOT NULL,
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    committed_at    TEXT,
    released_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_ipam_pending_subnet_state
    ON ipam_pending_allocations (subnet, state);
CREATE INDEX IF NOT EXISTS idx_ipam_pending_vrf_address
    ON ipam_pending_allocations (vrf_name, address, state);

-- 0027: ipam history + utilization
CREATE TABLE IF NOT EXISTS ipam_ip_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    address     TEXT    NOT NULL,
    vrf_name    TEXT    NOT NULL DEFAULT '',
    hostname    TEXT    NOT NULL DEFAULT '',
    source_type TEXT    NOT NULL DEFAULT '',
    source_ref  TEXT    NOT NULL DEFAULT '',
    started_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    ended_at    TEXT,
    recorded_by TEXT    NOT NULL DEFAULT '',
    note        TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ipam_history_address
    ON ipam_ip_history (address, vrf_name, started_at);
-- Note: the partial-index `WHERE ended_at IS NULL` from migration 0027 is
-- supported in both SQLite (3.8+) and Postgres, so it's safe in shared SCHEMA.
CREATE INDEX IF NOT EXISTS idx_ipam_history_open
    ON ipam_ip_history (address, vrf_name) WHERE ended_at IS NULL;

CREATE TABLE IF NOT EXISTS ipam_subnet_utilization (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subnet          TEXT    NOT NULL,
    vrf_name        TEXT    NOT NULL DEFAULT '',
    total           INTEGER NOT NULL DEFAULT 0,
    used            INTEGER NOT NULL DEFAULT 0,
    reserved        INTEGER NOT NULL DEFAULT 0,
    pending         INTEGER NOT NULL DEFAULT 0,
    free            INTEGER NOT NULL DEFAULT 0,
    utilization_pct REAL    NOT NULL DEFAULT 0,
    captured_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ipam_util_subnet_time
    ON ipam_subnet_utilization (subnet, vrf_name, captured_at);

-- 0028: per-user inventory group ordering
CREATE TABLE IF NOT EXISTS user_inventory_group_order (
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id    INTEGER NOT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
    position    INTEGER NOT NULL,
    PRIMARY KEY (user_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_user_inv_group_order_user
    ON user_inventory_group_order (user_id, position);

-- 0029 + 0030 + 0031: lab environments, devices (with runtime_* and topology_id columns inlined), runs
CREATE TABLE IF NOT EXISTS lab_environments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    NOT NULL DEFAULT '',
    owner_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    shared      INTEGER NOT NULL DEFAULT 0,
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- 0031: lab_topologies first so lab_devices.topology_id FK target exists
CREATE TABLE IF NOT EXISTS lab_topologies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    environment_id  INTEGER NOT NULL REFERENCES lab_environments(id) ON DELETE CASCADE,
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
    UNIQUE(environment_id, name)
);

CREATE TABLE IF NOT EXISTS lab_devices (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    environment_id          INTEGER NOT NULL REFERENCES lab_environments(id) ON DELETE CASCADE,
    hostname                TEXT    NOT NULL,
    ip_address              TEXT    NOT NULL DEFAULT '',
    device_type             TEXT    NOT NULL DEFAULT 'cisco_ios',
    model                   TEXT    NOT NULL DEFAULT '',
    source_host_id          INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    running_config          TEXT    NOT NULL DEFAULT '',
    notes                   TEXT    NOT NULL DEFAULT '',
    runtime_kind            TEXT    NOT NULL DEFAULT 'config_only',
    runtime_node_kind       TEXT    NOT NULL DEFAULT '',
    runtime_image           TEXT    NOT NULL DEFAULT '',
    runtime_status          TEXT    NOT NULL DEFAULT '',
    runtime_lab_name        TEXT    NOT NULL DEFAULT '',
    runtime_node_name       TEXT    NOT NULL DEFAULT '',
    runtime_mgmt_address    TEXT    NOT NULL DEFAULT '',
    runtime_credential_id   INTEGER,
    runtime_error           TEXT    NOT NULL DEFAULT '',
    runtime_workdir         TEXT    NOT NULL DEFAULT '',
    runtime_started_at      TEXT,
    topology_id             INTEGER REFERENCES lab_topologies(id) ON DELETE SET NULL,
    created_at              TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at              TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_lab_devices_env
    ON lab_devices (environment_id);
CREATE INDEX IF NOT EXISTS idx_lab_devices_topology
    ON lab_devices (topology_id);

CREATE TABLE IF NOT EXISTS lab_runs (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    lab_device_id           INTEGER NOT NULL REFERENCES lab_devices(id) ON DELETE CASCADE,
    submitted_by            TEXT    NOT NULL DEFAULT '',
    commands                TEXT    NOT NULL DEFAULT '',
    pre_config              TEXT    NOT NULL DEFAULT '',
    post_config             TEXT    NOT NULL DEFAULT '',
    diff_text               TEXT    NOT NULL DEFAULT '',
    diff_added              INTEGER NOT NULL DEFAULT 0,
    diff_removed            INTEGER NOT NULL DEFAULT 0,
    risk_score              REAL    NOT NULL DEFAULT 0,
    risk_level              TEXT    NOT NULL DEFAULT '',
    risk_detail             TEXT    NOT NULL DEFAULT '',
    status                  TEXT    NOT NULL DEFAULT 'simulated',
    promoted_deployment_id  INTEGER,
    created_at              TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_lab_runs_device
    ON lab_runs (lab_device_id, created_at);

-- 0030: lab runtime events
CREATE TABLE IF NOT EXISTS lab_runtime_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    lab_device_id   INTEGER NOT NULL REFERENCES lab_devices(id) ON DELETE CASCADE,
    action          TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'ok',
    actor           TEXT    NOT NULL DEFAULT '',
    detail          TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_lab_runtime_events_device
    ON lab_runtime_events (lab_device_id, created_at);

-- 0031: lab topology links
CREATE TABLE IF NOT EXISTS lab_topology_links (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    topology_id     INTEGER NOT NULL REFERENCES lab_topologies(id) ON DELETE CASCADE,
    a_device_id     INTEGER NOT NULL REFERENCES lab_devices(id) ON DELETE CASCADE,
    a_endpoint      TEXT    NOT NULL,
    b_device_id     INTEGER NOT NULL REFERENCES lab_devices(id) ON DELETE CASCADE,
    b_endpoint      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lab_topology_links_topo
    ON lab_topology_links (topology_id);

-- 0032: lab drift runs
CREATE TABLE IF NOT EXISTS lab_drift_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    lab_device_id   INTEGER NOT NULL REFERENCES lab_devices(id) ON DELETE CASCADE,
    source_host_id  INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    status          TEXT    NOT NULL DEFAULT 'in_sync',
    diff_text       TEXT    NOT NULL DEFAULT '',
    diff_added      INTEGER NOT NULL DEFAULT 0,
    diff_removed    INTEGER NOT NULL DEFAULT 0,
    twin_bytes      INTEGER NOT NULL DEFAULT 0,
    prod_bytes      INTEGER NOT NULL DEFAULT 0,
    actor           TEXT    NOT NULL DEFAULT '',
    error           TEXT    NOT NULL DEFAULT '',
    checked_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_lab_drift_runs_device
    ON lab_drift_runs (lab_device_id, checked_at);
"""


def _convert_sqlite_schema_to_postgres(sqlite_schema: str) -> str:
    converted = sqlite_schema
    converted = converted.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    converted = converted.replace("DEFAULT (datetime('now'))", "DEFAULT NOW()")
    converted = converted.replace(" BLOB", " BYTEA")
    return converted


POSTGRES_SCHEMA = _convert_sqlite_schema_to_postgres(SCHEMA)


# ── Engine-specific extras for full-text search on config_backups ────────────
# The runtime FTS query in `search_config_backups` already branches on engine
# (postgres uses to_tsvector @@ plainto_tsquery; sqlite uses an FTS5 virtual
# table). These DDL blocks are applied alongside SCHEMA on init.

POSTGRES_FTS_EXTRAS = """
CREATE INDEX IF NOT EXISTS idx_config_backups_search_tsv
    ON config_backups USING GIN (to_tsvector('simple', COALESCE(config_text, '')));
"""

SQLITE_FTS_EXTRAS = """
CREATE VIRTUAL TABLE IF NOT EXISTS config_backups_fts
USING fts5(config_text, content='config_backups', content_rowid='id');

CREATE TRIGGER IF NOT EXISTS config_backups_ai
AFTER INSERT ON config_backups BEGIN
    INSERT INTO config_backups_fts(rowid, config_text)
    VALUES (new.id, COALESCE(new.config_text, ''));
END;

CREATE TRIGGER IF NOT EXISTS config_backups_ad
AFTER DELETE ON config_backups BEGIN
    INSERT INTO config_backups_fts(config_backups_fts, rowid, config_text)
    VALUES ('delete', old.id, COALESCE(old.config_text, ''));
END;

CREATE TRIGGER IF NOT EXISTS config_backups_au
AFTER UPDATE ON config_backups BEGIN
    INSERT INTO config_backups_fts(config_backups_fts, rowid, config_text)
    VALUES ('delete', old.id, COALESCE(old.config_text, ''));
    INSERT INTO config_backups_fts(rowid, config_text)
    VALUES (new.id, COALESCE(new.config_text, ''));
END;
"""


_CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\"\w]+)\s*\(",
    re.IGNORECASE,
)
# Matches an inline column-level REFERENCES clause:
#   REFERENCES <table>(<col>) [ON DELETE <action>] [ON UPDATE <action>]
# Postgres validates the referenced table exists at CREATE TABLE time, so
# forward references break schema init. We strip these from CREATE TABLE
# statements and re-add them via ALTER TABLE after all tables exist.
_INLINE_FK_RE = re.compile(
    r"\s+REFERENCES\s+([\"\w]+)\s*\(\s*([\"\w]+)\s*\)"
    r"(?:\s+ON\s+DELETE\s+(CASCADE|SET\s+NULL|SET\s+DEFAULT|RESTRICT|NO\s+ACTION))?"
    r"(?:\s+ON\s+UPDATE\s+(CASCADE|SET\s+NULL|SET\s+DEFAULT|RESTRICT|NO\s+ACTION))?",
    re.IGNORECASE,
)


def _extract_postgres_fks(stmt: str) -> tuple[str, list[str]]:
    """For a CREATE TABLE statement, strip inline FK references and return
    (rewritten_statement, list_of_alter_table_statements).

    Only column-level inline `REFERENCES tbl(col) [ON DELETE ...]` clauses are
    handled - table-level FOREIGN KEY (...) constraints are passed through.
    Returns (stmt, []) for non-CREATE-TABLE statements.
    """
    m = _CREATE_TABLE_RE.search(stmt)
    if not m:
        return stmt, []
    table = m.group(1)
    alters: list[str] = []

    def _replace(fk_match: re.Match) -> str:
        ref_table = fk_match.group(1)
        ref_col = fk_match.group(2)
        on_delete = fk_match.group(3)
        on_update = fk_match.group(4)
        # Find the column name this REFERENCES clause is attached to: walk
        # backwards from the match start to the previous comma or `(`, then
        # take the first identifier on that line.
        prefix = stmt[: fk_match.start()]
        line_start = max(prefix.rfind(","), prefix.rfind("("))
        col_line = stmt[line_start + 1 : fk_match.start()].strip()
        col_name = col_line.split()[0] if col_line else ""
        if not col_name:
            return ""  # malformed; just drop the FK clause
        on_delete_clause = f" ON DELETE {on_delete}" if on_delete else ""
        on_update_clause = f" ON UPDATE {on_update}" if on_update else ""
        # Wrapped in a DO block so re-running init_db on an already-initialized
        # database doesn't fail with "constraint already exists" - Postgres
        # doesn't support `ADD CONSTRAINT IF NOT EXISTS` for FKs.
        alters.append(
            "DO $$ BEGIN "
            f"ALTER TABLE {table} ADD CONSTRAINT "
            f"fk_{table}_{col_name}_{ref_table} "
            f"FOREIGN KEY ({col_name}) REFERENCES {ref_table}({ref_col})"
            f"{on_delete_clause}{on_update_clause}; "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
        )
        return ""

    rewritten = _INLINE_FK_RE.sub(_replace, stmt)
    return rewritten, alters


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
    # Cast NOW() to text so it pairs with the text-cast LHS the modifier
    # translator emits (see _convert_sqlite_datetime_modifiers_to_postgres).
    # All schema columns that previously stored datetime('now') are TEXT, so
    # text-vs-text on inserts/updates and comparisons is the right contract.
    converted = converted.replace("datetime('now')", "NOW()::text")
    converted = _convert_sqlite_datetime_modifiers_to_postgres(converted)
    converted = _convert_sqlite_insert_or_ignore_to_postgres(converted)
    return converted


# Match `datetime(<expr>, <modifier>)` - the SQLite two-argument form. We rewrite
# these into postgres `(<expr>::timestamptz <op> <interval>)` because postgres
# has no equivalent function. Patterns we handle (post-`?`→`$N` substitution):
#
#   datetime('now', '-7 days')                     -- literal interval
#   datetime('now', $1)                            -- whole modifier as param
#   datetime('now', '-' || $1 || ' days')          -- "N days ago", parameterized
#   datetime('now', $1 || ' hours')                -- modifier prefix as param
#   datetime(col, '+' || other_col || ' seconds')  -- column-relative offset
#
# Anything outside these shapes will fall through unchanged and surface as a
# postgres syntax error - flagging unhandled patterns is preferable to silently
# producing wrong SQL.
_SQLITE_DT_BASE = r"(?:'now'|[\w.]+)"   # 'now' or an unquoted column reference
_SQLITE_DT_LITERAL_MOD = r"'([+-]?\d+\s+\w+)'"          # '-7 days'
_SQLITE_DT_PARAM_ONLY = r"\$(\d+)"                       # $1 (whole modifier)
_SQLITE_DT_SIGN_PARAM_UNIT = r"'([+-])'\s*\|\|\s*\$(\d+)\s*\|\|\s*'\s+(\w+)'"  # '-' || $1 || ' days'
_SQLITE_DT_PARAM_UNIT = r"\$(\d+)\s*\|\|\s*'\s+(\w+)'"   # $1 || ' hours'  (sign embedded in value)
_SQLITE_DT_COL_UNIT = r"'([+-])'\s*\|\|\s*([\w.]+)\s*\|\|\s*'\s+(\w+)'"        # '+' || col || ' seconds'

_DT_RE_LITERAL = re.compile(
    rf"datetime\(\s*({_SQLITE_DT_BASE})\s*,\s*{_SQLITE_DT_LITERAL_MOD}\s*\)",
    re.IGNORECASE,
)
_DT_RE_PARAM_ONLY = re.compile(
    rf"datetime\(\s*({_SQLITE_DT_BASE})\s*,\s*{_SQLITE_DT_PARAM_ONLY}\s*\)",
    re.IGNORECASE,
)
_DT_RE_SIGN_PARAM_UNIT = re.compile(
    rf"datetime\(\s*({_SQLITE_DT_BASE})\s*,\s*{_SQLITE_DT_SIGN_PARAM_UNIT}\s*\)",
    re.IGNORECASE,
)
_DT_RE_PARAM_UNIT = re.compile(
    rf"datetime\(\s*({_SQLITE_DT_BASE})\s*,\s*{_SQLITE_DT_PARAM_UNIT}\s*\)",
    re.IGNORECASE,
)
_DT_RE_COL_UNIT = re.compile(
    rf"datetime\(\s*({_SQLITE_DT_BASE})\s*,\s*{_SQLITE_DT_COL_UNIT}\s*\)",
    re.IGNORECASE,
)


def _pg_base(expr: str) -> str:
    """Translate the first arg of datetime() into a postgres timestamp expr."""
    if expr == "'now'":
        return "NOW()"
    # A column reference. Schema stores datetimes as TEXT (ISO-8601), so cast
    # to timestamptz to allow interval math.
    return f"{expr}::timestamptz"


def _convert_sqlite_datetime_modifiers_to_postgres(query: str) -> str:
    # Schema stores all datetime columns as TEXT (ISO-8601). When the
    # comparison side is text, we have to cast our timestamptz result back
    # to text - otherwise postgres rejects `text </>= timestamptz`. Using
    # `::text` on a postgres timestamptz produces a sortable ISO-8601 string
    # that lexically orders correctly against other postgres-written rows.
    def _col_unit(m: re.Match) -> str:
        base = _pg_base(m.group(1))
        sign, col, unit = m.group(2), m.group(3), m.group(4)
        op = "+" if sign == "+" else "-"
        return f"({base} {op} ({col} || ' {unit}')::interval)::text"
    query = _DT_RE_COL_UNIT.sub(_col_unit, query)

    def _sign_param_unit(m: re.Match) -> str:
        base = _pg_base(m.group(1))
        sign, n, unit = m.group(2), m.group(3), m.group(4)
        op = "+" if sign == "+" else "-"
        # Cast $N to text - caller may pass an int, but `||` requires text.
        return f"({base} {op} (${n}::text || ' {unit}')::interval)::text"
    query = _DT_RE_SIGN_PARAM_UNIT.sub(_sign_param_unit, query)

    def _param_unit(m: re.Match) -> str:
        base = _pg_base(m.group(1))
        n, unit = m.group(2), m.group(3)
        return f"({base} + (${n}::text || ' {unit}')::interval)::text"
    query = _DT_RE_PARAM_UNIT.sub(_param_unit, query)

    def _literal(m: re.Match) -> str:
        base = _pg_base(m.group(1))
        modifier = m.group(2).strip()
        return f"({base} + INTERVAL '{modifier}')::text"
    query = _DT_RE_LITERAL.sub(_literal, query)

    def _param_only(m: re.Match) -> str:
        base = _pg_base(m.group(1))
        n = m.group(2)
        return f"({base} + (${n}::text)::interval)::text"
    query = _DT_RE_PARAM_ONLY.sub(_param_only, query)

    return query


# Match top-level `INSERT OR IGNORE INTO <table> (...) VALUES (...)` and rewrite
# to postgres `INSERT INTO ... ON CONFLICT DO NOTHING`. We don't need to know
# the conflict columns - `DO NOTHING` without a target tells postgres to skip
# any conflict on any unique constraint, which matches SQLite's IGNORE
# semantics for the way the codebase uses it.
_INSERT_OR_IGNORE_RE = re.compile(r"\bINSERT\s+OR\s+IGNORE\b", re.IGNORECASE)


def _convert_sqlite_insert_or_ignore_to_postgres(query: str) -> str:
    if not _INSERT_OR_IGNORE_RE.search(query):
        return query
    rewritten = _INSERT_OR_IGNORE_RE.sub("INSERT", query)
    # Append ON CONFLICT DO NOTHING just before the trailing semicolon (if any)
    # or before any RETURNING clause we appended elsewhere.
    if " RETURNING " in rewritten.upper():
        idx = rewritten.upper().rindex(" RETURNING ")
        rewritten = rewritten[:idx] + " ON CONFLICT DO NOTHING" + rewritten[idx:]
    else:
        stripped = rewritten.rstrip().rstrip(";")
        rewritten = stripped + " ON CONFLICT DO NOTHING"
    return rewritten


def _convert_sqlite_ddl_to_postgres(query: str) -> str:
    """Apply SQLite→Postgres DDL transforms so migrations written in SQLite
    syntax run unchanged on postgres. Mirrors the conversions in
    ``_convert_sqlite_schema_to_postgres`` but is applied per-query inside
    ``_PostgresConnectionCompat.execute`` for DDL statements.
    """
    converted = query
    converted = converted.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    converted = converted.replace("DEFAULT (datetime('now'))", "DEFAULT NOW()")
    converted = converted.replace(" BLOB", " BYTEA")
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

    @property
    def description(self):
        # DB-API shape: list of 7-tuples; callers only read [0] (column name).
        # asyncpg.Record exposes column names via .keys(); fall back to an
        # empty list when no rows were returned so callers don't AttributeError.
        if not self._rows:
            return []
        return [(name, None, None, None, None, None, None)
                for name in self._rows[0].keys()]

    async def fetchone(self):
        if self._idx >= len(self._rows):
            return None
        row = self._rows[self._idx]
        self._idx += 1
        return row

    async def fetchall(self):
        return list(self._rows)


def _strip_nuls_from_params(params: tuple) -> tuple:
    # Postgres rejects 0x00 in TEXT values ("invalid byte sequence for
    # encoding UTF8: 0x00") while SQLite accepts them. SNMP-returned device
    # strings, syslog bodies, and some config payloads occasionally carry a
    # trailing NUL. Strip them here so callers can keep treating the
    # backends identically.
    return tuple(v.replace("\x00", "") if isinstance(v, str) else v for v in params)


class _PostgresConnectionCompat:
    def __init__(self, conn):
        self._conn = conn
        self.row_factory = None

    async def execute(self, query: str, params=()):
        params = _strip_nuls_from_params(tuple(params or ()))
        query_stripped = query.strip()
        query_upper = query_stripped.upper()

        # Migrations are written in SQLite-flavored DDL. Transparently convert
        # CREATE/ALTER statements so each migration runs on postgres without
        # needing a hand-written postgres branch.
        if query_upper.startswith("CREATE") or query_upper.startswith("ALTER"):
            query = _convert_sqlite_ddl_to_postgres(query)

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

    async def executemany(self, query: str, params):
        converted = _convert_qmark_to_dollar_params(query)
        cleaned = [_strip_nuls_from_params(tuple(row)) for row in params]
        await self._conn.executemany(converted, cleaned)
        return _PostgresCursorCompat(rowcount=len(cleaned))

    async def commit(self):
        # asyncpg uses autocommit when no explicit transaction is active.
        return None

    async def close(self):
        await self._conn.close()


# ── Connection reuse (singleton SQLite conn / asyncpg pool) ──────────────────
#
# Every callsite follows the same shape:  ``db = await get_db()`` then a
# ``try/finally: await db.close()``.  Historically get_db() opened a *brand
# new* backend connection each call - for SQLite that means an os.makedirs
# syscall, a fresh file handle, and four sequential PRAGMA round-trips; for
# Postgres a full TCP+auth handshake - and close() tore it down.  A single
# job launch makes ~8-12 of these serially before the job flips
# queued->running, which is the "sitting in the queue too long" latency.
#
# We keep all ~500 callsites untouched by changing only what get_db()
# returns and what .close() does:
#
#   * SQLite: one process-lifetime aiosqlite connection (PRAGMAs applied
#     once).  aiosqlite already funnels every operation through a single
#     worker thread, so concurrent coroutines sharing it can't run SQL in
#     parallel anyway; an async lock makes each get_db()->...->close()
#     critical section exclusive so transactions never interleave -
#     identical isolation to the old connection-per-call model.
#   * Postgres: a real asyncpg pool; get_db() acquires, close() releases.
#
# Re-entrancy: ~21 callsites hold a connection and, still holding it,
# await another get_db()-using function (all read-only ``get_*`` helpers
# - verified none commit or write).  With a shared connection + lock a
# naive singleton would self-deadlock there.  A contextvar tracks the
# connection + acquisition depth for the current asyncio task: a nested
# get_db() in the same task reuses the held connection and just bumps the
# depth (no lock, no new connection); the matching close() decrements,
# and only the depth-0 close() releases the lock / pool slot.  The real
# connection is never closed during normal operation.

_sqlite_conn = None
_sqlite_conn_path = None                # DB_PATH the singleton is bound to
_sqlite_conn_loop = None                # event loop the singleton was built on
_sqlite_conn_lock = asyncio.Lock()      # guards lazy creation of _sqlite_conn
_sqlite_access_lock = asyncio.Lock()    # serializes each critical section
_pg_pool = None
_pg_pool_lock = asyncio.Lock()

# Per-task held connection + depth, so nested get_db() is re-entrant.
_held: contextvars.ContextVar = contextvars.ContextVar("_db_held", default=None)


class _ConnProxy:
    """Delegates everything to the real connection except ``close()``.

    ``close()`` decrements this task's acquisition depth; the real
    connection is only released (lock unlocked / pooled conn returned)
    when depth hits zero, and is never actually closed while the
    process runs.
    """

    __slots__ = ("_real", "_closed")

    def __init__(self, real):
        object.__setattr__(self, "_real", real)
        object.__setattr__(self, "_closed", False)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_real"), name)

    def __setattr__(self, name, value):
        # e.g. ``db.row_factory = ...`` - forward to the real connection.
        setattr(object.__getattribute__(self, "_real"), name, value)

    async def close(self):
        # Idempotent per proxy: a callsite's finally: close() must not
        # double-decrement if it somehow runs twice.
        if object.__getattribute__(self, "_closed"):
            return
        object.__setattr__(self, "_closed", True)
        await _release_db()


async def _get_sqlite_singleton():
    # Bind the singleton to DB_PATH *and* the running event loop.  In
    # production both are constant for the process so the connection is
    # created once and every subsequent call hits the fast early-return.
    #
    # Tests are the reason for the loop check: pytest-asyncio gives each
    # test function its own event loop, and the many sync tests that call
    # asyncio.run() several times per case spin up a fresh (then closed)
    # loop on each call.  A connection is owned by the loop that created
    # it — aiosqlite schedules result callbacks back onto that loop — so a
    # singleton carried into a new loop would dispatch onto a dead loop and
    # hang.  Detecting either a DB_PATH change or a loop change rebuilds the
    # connection so each test/loop gets an isolated, live database.
    global _sqlite_conn, _sqlite_conn_path, _sqlite_conn_loop
    running = asyncio.get_running_loop()
    if (_sqlite_conn is not None and _sqlite_conn_path == DB_PATH
            and _sqlite_conn_loop is running):
        return _sqlite_conn
    async with _sqlite_conn_lock:
        if (_sqlite_conn is not None and _sqlite_conn_path == DB_PATH
                and _sqlite_conn_loop is running):
            return _sqlite_conn
        if _sqlite_conn is not None:
            # Only the owning loop can await close() (it schedules onto that
            # loop).  When the loop has changed the old one is typically dead,
            # so signal the worker thread directly: stop() is loop-independent,
            # closes the underlying sqlite connection (releasing the file lock)
            # and terminates the non-daemon worker thread (no leaked thread).
            if _sqlite_conn_loop is running:
                try:
                    await _sqlite_conn.close()
                except Exception as exc:
                    _LOGGER.debug("Failed to close stale SQLite connection: %s", exc)
            else:
                try:
                    _sqlite_conn.stop()
                except Exception as exc:
                    _LOGGER.debug("Failed to stop stale SQLite connection: %s", exc)
            _sqlite_conn = None
        db_dir = os.path.dirname(DB_PATH)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        conn = await aiosqlite.connect(DB_PATH, timeout=SQLITE_CONNECT_TIMEOUT)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        await conn.execute("PRAGMA synchronous=NORMAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        _sqlite_conn = conn
        _sqlite_conn_path = DB_PATH
        _sqlite_conn_loop = running
        return _sqlite_conn


def _dispose_sqlite_singleton_sync():
    """Tear down the SQLite singleton from synchronous (test) teardown.

    Loop-independent: ``stop()`` queues a close onto the worker thread,
    which closes the underlying sqlite connection (releasing the WAL file
    lock) and terminates the non-daemon worker thread — so nothing lingers
    to block process exit or lock the next test's database.  The locks and
    held-state are recreated so a critical section a failed test never
    finished cannot leak into the next one.  No-op when no singleton exists.

    Not used in production; an autouse pytest fixture calls this after each
    test (see tests/conftest.py).
    """
    global _sqlite_conn, _sqlite_conn_path, _sqlite_conn_loop
    global _sqlite_conn_lock, _sqlite_access_lock
    conn = _sqlite_conn
    _sqlite_conn = None
    _sqlite_conn_path = None
    _sqlite_conn_loop = None
    _sqlite_conn_lock = asyncio.Lock()
    _sqlite_access_lock = asyncio.Lock()
    _held.set(None)
    if conn is not None:
        try:
            conn.stop()
        except Exception as exc:
            _LOGGER.debug("Failed to stop SQLite connection during teardown: %s", exc)


async def _get_pg_pool():
    global _pg_pool
    if _pg_pool is not None:
        return _pg_pool
    async with _pg_pool_lock:
        if _pg_pool is not None:
            return _pg_pool
        _pg_pool = await asyncpg.create_pool(
            APP_DATABASE_URL, min_size=1, max_size=10
        )
        return _pg_pool


async def get_db():
    """Return a backend connection (reused, not opened per call).

    The returned object behaves exactly like the old per-call
    connection: ``execute``/``executemany``/``executescript``/``commit``/
    ``rollback``/``row_factory`` all work, and the mandatory
    ``await db.close()`` in each caller's ``finally`` releases it.
    """
    if DB_ENGINE not in _VALID_DB_ENGINES:
        raise RuntimeError(
            f"Unsupported APP_DB_ENGINE '{DB_ENGINE}'. Supported values: {', '.join(sorted(_VALID_DB_ENGINES))}"
        )

    state = _held.get()
    if state is not None:
        # Nested acquisition in the same task: reuse, bump depth.
        state["depth"] += 1
        return _ConnProxy(state["conn"])

    if DB_ENGINE == "postgres":
        if asyncpg is None:
            raise RuntimeError("APP_DB_ENGINE=postgres requires the 'asyncpg' package")
        if not APP_DATABASE_URL:
            raise RuntimeError("APP_DB_ENGINE=postgres requires APP_DATABASE_URL")
        pool = await _get_pg_pool()
        raw = await pool.acquire()
        conn = _PostgresConnectionCompat(raw)
        _held.set({"conn": conn, "depth": 1, "engine": "postgres",
                   "pool": pool, "raw": raw})
        return _ConnProxy(conn)

    # SQLite: acquire the exclusive access lock for this critical section,
    # then hand back the shared singleton.
    conn = await _get_sqlite_singleton()
    await _sqlite_access_lock.acquire()
    _held.set({"conn": conn, "depth": 1, "engine": "sqlite"})
    return _ConnProxy(conn)


async def _release_db():
    """Counterpart to get_db(): decrement depth, release at depth 0."""
    state = _held.get()
    if state is None:
        return
    state["depth"] -= 1
    if state["depth"] > 0:
        return
    _held.set(None)
    if state["engine"] == "postgres":
        await state["pool"].release(state["raw"])
    else:
        _sqlite_access_lock.release()


async def _init_postgres(db) -> None:
    # Two-pass: strip inline FK REFERENCES from CREATE TABLE statements,
    # run all DDL, then re-add the FKs via ALTER TABLE. This makes schema
    # init order-independent so forward references (e.g. monitoring_alerts
    # referencing alert_rules before alert_rules is created) don't fail.
    deferred_alters: list[str] = []
    for stmt in _split_sql_statements(POSTGRES_SCHEMA):
        rewritten, alters = _extract_postgres_fks(stmt)
        deferred_alters.extend(alters)
        await db.execute(rewritten)
    for alter in deferred_alters:
        await db.execute(alter)
    for stmt in _split_sql_statements(POSTGRES_FTS_EXTRAS):
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
            await db.executescript(SQLITE_FTS_EXTRAS)
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
# Domain modules
# ═════════════════════════════════════════════════════════════════════════════
# Split 2026-06: implementations live in routes/db/*.  Star re-exports keep
# the ``routes.database`` facade surface unchanged for the ~500 callsites
# that do ``import routes.database as db``.  Each domain module defines
# __all__, so only its own public names land here.
from routes.db.audit import *  # noqa: E402,F403
from routes.db.baselines import *  # noqa: E402,F403
from routes.db.billing import *  # noqa: E402,F403
from routes.db.cloud import *  # noqa: E402,F403
from routes.db.credentials import *  # noqa: E402,F403
from routes.db.flows import *  # noqa: E402,F403
from routes.db.geolocation import *  # noqa: E402,F403
from routes.db.graphs import *  # noqa: E402,F403
from routes.db.inventory import *  # noqa: E402,F403
from routes.db.ipam import *  # noqa: E402,F403
from routes.db.jobs import *  # noqa: E402,F403
from routes.db.lab import *  # noqa: E402,F403
from routes.db.mac_tracking import *  # noqa: E402,F403
from routes.db.maintenance import *  # noqa: E402,F403
from routes.db.metrics import *  # noqa: E402,F403
from routes.db.monitoring import *  # noqa: E402,F403
from routes.db.playbooks import *  # noqa: E402,F403
from routes.db.reporting import *  # noqa: E402,F403
from routes.db.topology import *  # noqa: E402,F403
from routes.db.users import *  # noqa: E402,F403
