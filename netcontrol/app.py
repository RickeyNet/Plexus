"""
app.py - Plexus FastAPI Application

REST API for inventory, playbooks, templates, credentials, and jobs.
WebSocket endpoint for real-time job output streaming.
Session-based authentication with signed cookies.
"""

from __future__ import annotations

import asyncio
import difflib
import hashlib
import ipaddress
import json
import os
import secrets
import socket
import sys
import traceback
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from starlette.routing import Match, Route

# Ensure project root is on path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import time

import asyncpg
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel, ConfigDict, Field

from netcontrol import listener_sources, syslog_tls
from netcontrol.account_rules import API_TOKEN_USER
from netcontrol.body_limit import BodyLimitMiddleware
from netcontrol.bounded_map import prune_expired
from netcontrol.db_errors import client_error_for
from netcontrol.integrations.cisco_fdm.collector import fdm_poll_loop
from netcontrol.mcp.server import build_mcp_app
from netcontrol.object_scope import request_scope
from netcontrol.plugins import registry as plugin_registry
from netcontrol.routes import notification_channels, object_changes, siem_forwarder, webhooks
from netcontrol.routes.admin import (
    AdminAccessGroupCreateRequest,
    AdminAccessGroupUpdateRequest,
    AdminLoginRulesRequest,
    AdminUserCreateRequest,
    AdminUserGroupAssignmentRequest,
    AdminUserPasswordResetRequest,
    AdminUserUpdateRequest,
    AuthConfigRequest,
    RadiusConfigRequest,
    SyslogConfigRequest,
    _admin_user_payload,
    _security_check_payload,
    _validate_feature_keys,
    admin_get_syslog_config,
    admin_run_retention_cleanup_now,
    admin_test_syslog_config,
    admin_update_syslog_config,
    init_admin,
    router as admin_router,
)
from netcontrol.routes.admin_updates import (
    router as admin_updates_router,
)
from netcontrol.routes.ansible_inventory import (
    router as ansible_inventory_router,
)
from netcontrol.routes.audit import _audit_run_loop, router as audit_router
from netcontrol.routes.auth import (
    PYRAD_AVAILABLE,
    ChangePasswordRequest,
    LoginRequest,
    RegisterRequest,
    UpdateProfileRequest,
    _ensure_radius_dictionary_file,
    _get_user_features,
    _radius_authenticate_sync,
    _session_cookie_secure,
    auth_status,
    authenticate_login_identity,
    init_auth,
    login,
    register,
    router as auth_router,
    upsert_ldap_user,
    upsert_radius_user,
    upsert_tacacs_user,
    verify_ldap_user,
    verify_radius_user,
    verify_tacacs_user,
)
from netcontrol.routes.baseline_alerting import router as baseline_alerting_router
from netcontrol.routes.billing import (
    router as billing_router,
)
from netcontrol.routes.bulk_import import (
    ipam_router as bulk_import_ipam_router,
    router as bulk_import_router,
)
from netcontrol.routes.cato_egress_check import router as cato_egress_check_router
from netcontrol.routes.cato_shared_host_check import router as cato_shared_host_check_router
from netcontrol.routes.cdef_engine import read_router as cdef_read_router, router as cdef_router
from netcontrol.routes.chatops import (
    WEBHOOK_PATHS as CHATOPS_WEBHOOK_PATHS,
    admin_router as chatops_admin_router,
    inbound_router as chatops_inbound_router,
)
from netcontrol.routes.circuits import router as circuits_router
from netcontrol.routes.cloud_flow_pullers import pull_flow_logs_all_accounts
from netcontrol.routes.cloud_metric_pullers import pull_traffic_metrics_all_accounts
from netcontrol.routes.cloud_visibility import (
    build_cloud_sync_status,
    persist_cloud_flow_sync_status,
    persist_cloud_traffic_sync_status,
    router as cloud_visibility_router,
)
from netcontrol.routes.compliance import (
    ComplianceAssignmentCreate,
    ComplianceAssignmentUpdate,
    ComplianceProfileCreate,
    ComplianceProfileUpdate,
    ComplianceScanRequest,
    _compliance_check_loop,
    _evaluate_host_compliance,
    _evaluate_rule,
    _run_compliance_check_once,
    admin_router as compliance_admin_router,
    init_compliance,
    router as compliance_router,
)
from netcontrol.routes.config_backups import (
    _config_backup_loop,
    _run_config_backups_once,
    router as config_backups_router,
)
from netcontrol.routes.config_drift import (
    ConfigDriftStatusUpdate,
    _analyze_drift_for_host,
    _capture_job_sockets,
    _capture_jobs,
    _config_drift_check_loop,
    _run_config_drift_check_once,
    admin_router as config_drift_admin_router,
    init_config_drift,
    router as config_drift_router,
    ws_router as config_drift_ws_router,
)
from netcontrol.routes.credentials import CredentialCreate, CredentialUpdate, router as credentials_router
from netcontrol.routes.custom_fields import (
    admin_router as custom_fields_admin_router,
    inventory_router as custom_fields_inventory_router,
    ipam_router as custom_fields_ipam_router,
    router as custom_fields_router,
)
from netcontrol.routes.dashboards import router as dashboards_router
from netcontrol.routes.dcim import router as dcim_router
from netcontrol.routes.deployments import (
    DeploymentCreate,
    DeploymentExecute,
    DeploymentRollback,
    _broadcast_deploy_line,
    _build_revert_commands,
    _deployment_job_sockets,
    _deployment_jobs,
    _finish_deploy_job,
    _run_deployment_job,
    _run_rollback_job,
    init_deployments,
    router as deployments_router,
    ws_router as deployments_ws_router,
)
from netcontrol.routes.device_model import (
    admin_router as device_model_admin_router,
    inventory_router as device_model_inventory_router,
    router as device_model_router,
)
from netcontrol.routes.dhcp import router as dhcp_router, sync_dhcp_server
from netcontrol.routes.dhcp_adapters import DhcpAdapterError, collect_dhcp_snapshot, is_collection_fed
from netcontrol.routes.dynamic_groups import router as dynamic_groups_router
from netcontrol.routes.export_templates import (
    admin_router as export_templates_admin_router,
    router as export_templates_router,
)
from netcontrol.routes.federation import (
    federation_sync_loop,
    router as federation_router,
)
from netcontrol.routes.flow_collector import (
    FLOW_COLLECTOR_CONFIG,
    _cancel_aggregation_task as _cancel_flow_aggregation_task,
    _ensure_aggregation_task as _ensure_flow_aggregation_task,
    admin_router as flow_collector_admin_router,
    router as flow_collector_router,
    start_flow_collector,
    stop_flow_collector,
)
from netcontrol.routes.geolocation import router as geolocation_router
from netcontrol.routes.git_sources import git_sources_loop, router as git_sources_router
from netcontrol.routes.graph_export import router as graph_export_router
from netcontrol.routes.graph_templates import router as graph_templates_router
from netcontrol.routes.graphql import admin_router as graphql_admin_router, router as graphql_router
from netcontrol.routes.hardware_components import router as hardware_components_router
from netcontrol.routes.hardware_lifecycle import (
    _lifecycle_check_loop,
    router as hardware_lifecycle_router,
)
from netcontrol.routes.help_docs import router as help_docs_router
from netcontrol.routes.intended_config import (
    admin_router as intended_config_admin_router,
    intended_config_loop,
    read_router as intended_config_read_router,
    router as intended_config_router,
)
from netcontrol.routes.interface_errors import (
    router as interface_errors_router,
)
from netcontrol.routes.inventory import (
    DiscoveryOnboardRequest,
    DiscoveryScanRequest,
    DiscoverySyncRequest,
    GroupCreate,
    GroupUpdate,
    HostCreate,
    HostUpdate,
    _discover_hosts,
    _discovery_sync_loop,
    _expand_scan_targets,
    _probe_discovery_target,
    _run_discovery_sync_once,
    _sync_group_hosts,
    admin_router as inventory_admin_router,
    router as inventory_router,
)
from netcontrol.routes.inventory_collection import router as inventory_collection_router
from netcontrol.routes.ipam import router as ipam_router
from netcontrol.routes.ipam_adapters import IpamAdapterError, collect_ipam_snapshot
from netcontrol.routes.ipam_model import admin_router as ipam_model_admin_router, router as ipam_model_router
from netcontrol.routes.jobs import (
    _MAX_CONCURRENT_JOBS as _jobs_MAX_CONCURRENT_JOBS,
    _job_semaphore as _jobs_job_semaphore,
    _process_job_queue,
    approvals_router as jobs_approvals_router,
    drain_running_jobs,
    init_jobs,
    reap_and_resume_jobs,
    router as jobs_router,
    ws_router as jobs_ws_router,
)
from netcontrol.routes.lab import (
    router as lab_router,
)
from netcontrol.routes.lab_drift import (
    lab_drift_scheduler_loop,
    router as lab_drift_router,
)
from netcontrol.routes.lab_runtime import (
    lab_runtime_ttl_loop,
    reconcile_running_labs,
    router as lab_runtime_router,
)
from netcontrol.routes.lab_topology import router as lab_topology_router
from netcontrol.routes.mac_tracking import _mac_move_retention_loop, router as mac_tracking_router
from netcontrol.routes.maintenance_windows import (
    router as maintenance_windows_router,
)
from netcontrol.routes.mcp_tokens import router as mcp_tokens_router
from netcontrol.routes.meraki_alerts import (
    WEBHOOK_PATH as MERAKI_WEBHOOK_PATH,
    admin_router as meraki_alerts_admin_router,
    load_status as load_meraki_alert_status,
    router as meraki_alerts_router,
    webhook_router as meraki_webhook_router,
)
from netcontrol.routes.meraki_compliance import router as meraki_compliance_router
from netcontrol.routes.meraki_topology import init_meraki_topology, router as meraki_topology_router
from netcontrol.routes.metrics_engine import (
    _downsampling_loop,
    admin_router as metrics_engine_admin_router,
    apply_event_receiver_config,
    flush_v3_state,
    router as metrics_engine_router,
    stop_receivers,
)
from netcontrol.routes.monitoring import (
    _alert_escalation_loop,
    _baseline_computation_loop,
    _check_threshold,
    _evaluate_alerts_for_poll,
    _metric_value_from_poll,
    _monitoring_poll_loop,
    _poll_host_monitoring,
    _run_alert_escalation,
    _run_monitoring_poll_once,
    _sla_rollup_loop,
    admin_router as monitoring_admin_router,
    router as monitoring_router,
)
from netcontrol.routes.network_objects import (
    admin_router as network_objects_admin_router,
    backfill_interface_addresses,
    host_router as network_objects_host_router,
    router as network_objects_router,
)
from netcontrol.routes.opnsense_backup_encryption import (
    encrypt_legacy_backups as encrypt_legacy_opnsense_backups,
)
from netcontrol.routes.opnsense_rules import router as opnsense_rules_router
from netcontrol.routes.organization import (
    admin_router as organization_admin_router,
    router as organization_router,
)
from netcontrol.routes.playbooks import (
    PlaybookCreate,
    PlaybookUpdate,
    _sanitize_ansible_filename,
    _sanitize_playbook_filename,
    admin_router as playbooks_admin_router,
    router as playbooks_router,
    sync_playbooks_from_registry,
    write_playbook_file,
)
from netcontrol.routes.plugins import mount_plugin_routers, router as plugins_router
from netcontrol.routes.reporting import (
    _report_scheduler_loop,
    oid_profiles_router,
    router as reporting_router,
)
from netcontrol.routes.risk_analysis import (
    _CRITICAL_PATTERNS,
    RiskAnalysisRequest,
    _classify_change_areas,
    _compute_risk_score,
    _run_risk_analysis_for_host,
    _simulate_config_change,
    router as risk_analysis_router,
)
from netcontrol.routes.routing import router as routing_router
from netcontrol.routes.scope_rules import router as scope_rules_router
from netcontrol.routes.secret_variables import router as secret_variables_router
from netcontrol.routes.secrets_providers import router as secrets_providers_router
from netcontrol.routes.security_events import router as security_events_router
from netcontrol.routes.snmp import (
    PYSMNP_AVAILABLE,
    _build_snmp_auth,
    _discover_neighbors,
    _infer_vendor_os_from_text,
    _parse_cdp_address,
    _probe_discovery_target_snmp,
    _snmp_get,
    _snmp_walk,
)
from netcontrol.routes.software import _software_refresh_loop, router as software_router
from netcontrol.routes.source_import import router as source_import_router
from netcontrol.routes.sync import admin_router as sync_admin_router, router as sync_router
from netcontrol.routes.syslog_rules import router as syslog_rules_router
from netcontrol.routes.templates import TemplateCreate, TemplateUpdate, router as templates_router
from netcontrol.routes.tool_history import router as tool_history_router
from netcontrol.routes.topology import (
    _calc_interface_utilization,
    _record_topology_changes,
    _run_topology_discovery_once,
    _stp_discovery_loop,
    _topology_discovery_loop,
    admin_router as topology_admin_router,
    router as topology_router,
)
from netcontrol.routes.topology_availability import dashboard_topology_summary
from netcontrol.routes.upgrades import (
    init_upgrades,
    rehydrate_scheduled_upgrades,
    router as upgrades_router,
    ws_router as upgrades_ws_router,
)
from netcontrol.routes.validation_rules import router as validation_rules_router
from netcontrol.routes.vendor_alerts import (
    admin_router as vendor_alerts_admin_router,
    load_settings as load_vendor_alert_settings,
    router as vendor_alerts_router,
)
from netcontrol.routes.virtualization import (
    admin_router as virtualization_admin_router,
    router as virtualization_router,
)
from netcontrol.scoped_dashboard import dashboard_for_caller, scoped_dashboard_data
from netcontrol.sso import safe_next
from netcontrol.sync.runner import sync_jobs_loop

# Ensure project root is on path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import importlib

import routes.database as db
from routes.crypto import decrypt, encrypt
from routes.db.change_events import current_actor, current_correlation_id
from routes.runner import LogEvent, execute_playbook, get_playbook_class

try:
    from routes.ansible_runner_backend import execute_ansible_playbook

    ANSIBLE_RUNNER_AVAILABLE = True
except ImportError:
    ANSIBLE_RUNNER_AVAILABLE = False

# Auto-register all playbooks
from templates import playbooks  # noqa: F401

from netcontrol.telemetry import (
    configure_logging,
    configure_syslog_logging,
    increment_metric,
    observe_timing,
    redact_value,
    snapshot_metrics,
)
from netcontrol.version import APP_VERSION

LOGGER = configure_logging("plexus.app")
APP_START_TIME = time.time()
APP_API_TOKEN = os.getenv("APP_API_TOKEN", "").strip()

# Re-exports for backward compatibility (tests monkeypatch these on app_module)
_MAX_CONCURRENT_JOBS = _jobs_MAX_CONCURRENT_JOBS
_job_semaphore = _jobs_job_semaphore

# Re-export route handler functions and helpers referenced by tests
import netcontrol.routes.shared as shared
import netcontrol.routes.state as state
from netcontrol.routes.config_drift import (
    get_config_baseline,
    get_config_drift_summary,
    update_config_drift_event_status,
)
from netcontrol.routes.inventory import discovery_onboard
from netcontrol.routes.shared import _compute_config_diff
from netcontrol.routes.state import _env_flag, _parse_cors_origins
from netcontrol.routes.topology import (
    discover_topology_for_group,
    get_host_topology,
    get_topology,
)

# ── CSRF token helpers ───────────────────────────────────────────────────────

_csrf_serializer: URLSafeTimedSerializer | None = None  # initialised after secret key load
CSRF_TOKEN_MAX_AGE = 86400  # 24 hours - aligned with session lifetime


def _generate_csrf_token(session_user: str) -> str:
    """Create a signed, time-limited CSRF token bound to the session user."""
    if _csrf_serializer is None:
        raise RuntimeError("CSRF serializer not initialised - check SECRET_KEY configuration")
    return _csrf_serializer.dumps({"csrf_user": session_user})


def _validate_csrf_token(token: str, session_user: str) -> bool:
    """Return True when the token is valid, not expired, and bound to the user."""
    if _csrf_serializer is None:
        raise RuntimeError("CSRF serializer not initialised - check SECRET_KEY configuration")
    try:
        data = _csrf_serializer.loads(token, max_age=CSRF_TOKEN_MAX_AGE)
        return data.get("csrf_user") == session_user
    except BadSignature, SignatureExpired:
        return False


def _validate_startup_config() -> None:
    errors = []
    if _env_flag("APP_REQUIRE_API_TOKEN", False) and not APP_API_TOKEN:
        errors.append("APP_REQUIRE_API_TOKEN is true but APP_API_TOKEN is not set")
    if errors:
        raise RuntimeError("; ".join(errors))


_audit = shared._audit
_corr_id = shared._corr_id


def _extract_api_token(request: Request) -> str:
    token = request.headers.get("x-api-token", "").strip()
    if token:
        return token
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return ""


# Playbook filename sanitizers and write_playbook_file - extracted to playbooks.py (re-imported above)


# ═════════════════════════════════════════════════════════════════════════════
# Authentication (DB-backed users)
# ═════════════════════════════════════════════════════════════════════════════

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SECRET_KEY_FILE = os.getenv("APP_SESSION_KEY_FILE", os.path.join(_REPO_ROOT, "session.key"))
SESSION_MAX_AGE = 86400  # 24 hours


def _migrate_legacy_session_key() -> None:
    """Move legacy routes/session.key to the new repo-root default.

    Logging out everyone if the key is missing is acceptable, but if a legacy
    file exists we move it so existing sessions survive the upgrade. A
    zero-byte file at the new path is treated as a stub and overwritten.
    """
    if os.getenv("APP_SESSION_KEY_FILE"):
        return
    legacy = os.path.join(_REPO_ROOT, "routes", "session.key")
    if not os.path.isfile(legacy):
        return
    try:
        new_size = os.path.getsize(SECRET_KEY_FILE) if os.path.exists(SECRET_KEY_FILE) else -1
    except OSError:
        return
    if new_size > 0:
        return
    try:
        os.makedirs(os.path.dirname(SECRET_KEY_FILE) or ".", exist_ok=True)
        os.replace(legacy, SECRET_KEY_FILE)
    except OSError as exc:
        LOGGER.warning("session key migration: could not move %s to %s: %s", legacy, SECRET_KEY_FILE, exc)


_migrate_legacy_session_key()


# Generated keys are 64 hex characters; anything much shorter is not a key.
_MIN_SESSION_KEY_CHARS = 32


def _load_or_create_secret_key() -> str:
    key_dir = os.path.dirname(SECRET_KEY_FILE)
    if key_dir:
        os.makedirs(key_dir, exist_ok=True)

    target = SECRET_KEY_FILE
    if os.path.isfile(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE) as f:
            stored = f.read().strip()
        if len(stored) >= _MIN_SESSION_KEY_CHARS:
            return stored
        # An empty or truncated file (a write cut short, a file emptied by
        # hand) would sign every session and CSRF token with a key anyone can
        # guess. Replace it; the new key is written beside it and moved over.
        LOGGER.warning(
            "session key file %s holds fewer than %d characters; generating a new key (existing sessions end)",
            SECRET_KEY_FILE,
            _MIN_SESSION_KEY_CHARS,
        )
        target = SECRET_KEY_FILE + ".new"
        if os.path.exists(target):
            os.remove(target)
    key = secrets.token_hex(32)
    try:
        # Create file with restrictive permissions atomically (no race window)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
    except OSError:
        # Fallback for Windows (O_EXCL mode bits may not apply)
        with open(target, "w") as f:
            f.write(key)
        try:
            os.chmod(target, 0o600)
        except OSError as exc:
            LOGGER.debug("could not set permissions on %s: %s", target, exc)
    if target != SECRET_KEY_FILE:
        os.replace(target, SECRET_KEY_FILE)
    return key


_secret_key = _load_or_create_secret_key()
_serializer = URLSafeTimedSerializer(_secret_key)
_csrf_serializer = URLSafeTimedSerializer(_secret_key + "-csrf")


def _hash_password(password: str, salt: str = "") -> str:
    # Use PBKDF2 with 600 000 iterations (OWASP recommendation) instead of
    # a single SHA-256 round.  Existing hashes are 64-char hex (SHA-256);
    # new hashes are 128-char hex (PBKDF2-SHA-256, 64-byte dk).
    return hashlib.pbkdf2_hmac("sha256", password.encode(), f"{salt}:".encode(), 600_000, dklen=64).hex()


def _bootstrap_admin_username() -> str:
    raw = os.getenv("PLEXUS_INITIAL_ADMIN_USERNAME", "admin").strip()
    if not raw:
        return "admin"
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    cleaned = "".join(ch for ch in raw if ch in allowed).strip("._-")
    return cleaned or "admin"


def _emit_bootstrap_admin_credentials(
    username: str,
    password: str,
    action: str,
    must_change_password: bool,
) -> None:
    """Print one-time bootstrap credentials to stderr only."""
    guidance = (
        "Change it immediately after first login."
        if must_change_password
        else "Development bootstrap password is active."
    )
    _msg = f"\n*** {action} ***\n    Username: {username}\n    Password: {password}\n    {guidance}\n\n"
    os.write(2, _msg.encode())  # fd 2 = stderr


def _is_dev_bootstrap_mode() -> bool:
    env = os.getenv("APP_ENV", "").strip().lower()
    # "test" intentionally excluded - avoid deterministic admin password
    # in CI/test environments unless explicitly opted in via
    # PLEXUS_DEV_BOOTSTRAP=1.
    if env in {"dev", "development", "local"}:
        return True
    return _env_flag("PLEXUS_DEV_BOOTSTRAP", False)


# auth_settings row that records a PLEXUS_FORCE_ADMIN_PASSWORD_RESET having fired.
_FORCE_RESET_MARKER_KEY = "bootstrap_admin_force_reset"


async def _ensure_default_admin():
    """Ensure at least one local admin account exists.

    First-boot behavior:
      - If no admin user exists, create/promote one and print credentials.
      - ``PLEXUS_INITIAL_ADMIN_PASSWORD`` may provide the initial password.
      - Otherwise the password is ``netcontrol`` (or
        ``PLEXUS_DEFAULT_ADMIN_PASSWORD``). Outside dev mode the account is
        flagged must-change, so the first login forces a new password.

    Recovery behavior:
      - If ``PLEXUS_FORCE_ADMIN_PASSWORD_RESET=true`` is set, reset the
        configured bootstrap admin account password on startup. The reset
        fires once: a marker row records that it was applied, and later boots
        with the flag still set log a warning and leave the account alone.
        Booting once without the flag clears the marker and re-arms it.
        Without this, a flag forgotten in .env re-flags the account
        must-change (and reverts it to the bootstrap password) on every
        restart, which looks like "my password change never sticks".
    """
    users = await db.get_all_users()
    has_admin = any((u.get("role") or "").lower() == "admin" for u in users)

    bootstrap_username = _bootstrap_admin_username()
    configured_password = os.environ.pop("PLEXUS_INITIAL_ADMIN_PASSWORD", "").strip()
    default_bootstrap_password = os.getenv("PLEXUS_DEFAULT_ADMIN_PASSWORD", "netcontrol").strip() or "netcontrol"
    force_reset = _env_flag("PLEXUS_FORCE_ADMIN_PASSWORD_RESET", False)
    dev_bootstrap = _is_dev_bootstrap_mode()

    if force_reset:
        marker = await db.get_auth_setting(_FORCE_RESET_MARKER_KEY)
        if marker and marker.get("applied"):
            LOGGER.warning(
                "PLEXUS_FORCE_ADMIN_PASSWORD_RESET is still set but the reset was already "
                "applied at %s; skipping. Remove the flag from .env - leaving it set would "
                "reset the admin password on every restart.",
                marker.get("applied_at", "an earlier boot"),
            )
            force_reset = False
    else:
        # Flag absent: re-arm so a future PLEXUS_FORCE_ADMIN_PASSWORD_RESET=true
        # boot performs a reset again.
        if await db.get_auth_setting(_FORCE_RESET_MARKER_KEY):
            await db.set_auth_setting(_FORCE_RESET_MARKER_KEY, {"applied": False})

    if has_admin and not force_reset:
        if dev_bootstrap:
            conn = await db.get_db()
            try:
                await conn.execute("UPDATE users SET must_change_password = 0 WHERE must_change_password = 1")
                await conn.commit()
            finally:
                await conn.close()
        return

    password = configured_password or default_bootstrap_password
    # Dev mode keeps the default login usable as is; everywhere else the
    # first login must replace the bootstrap password.
    must_change_password = bool(configured_password) or not dev_bootstrap

    salt = secrets.token_hex(16)
    pw_hash = await asyncio.to_thread(_hash_password, password, salt)

    if has_admin and force_reset:
        target = await db.get_user_by_username(bootstrap_username)
        if not target:
            target = await db.get_user_by_username("admin")
        if not target:
            fallback_admin = next((u for u in users if (u.get("role") or "").lower() == "admin"), None)
            target = await db.get_user_by_id(int(fallback_admin["id"])) if fallback_admin else None
        if not target:
            return

        await db.update_user_admin(int(target["id"]), role="admin")
        await db.update_user_password(
            int(target["id"]),
            pw_hash,
            salt,
            must_change_password=must_change_password,
        )
        # A recovery reset must also end the sessions signed in with the old
        # password, or a stolen admin cookie outlives it.
        await db.bump_user_session_epoch(int(target["id"]))
        await db.set_auth_setting(
            _FORCE_RESET_MARKER_KEY,
            {"applied": True, "applied_at": datetime.now(UTC).isoformat(timespec="seconds")},
        )
        _emit_bootstrap_admin_credentials(
            target["username"],
            password,
            "Reset admin bootstrap password",
            must_change_password,
        )
        LOGGER.warning(
            "Admin password reset applied via PLEXUS_FORCE_ADMIN_PASSWORD_RESET. "
            "Remove the flag from .env now; it will not fire again until it is removed and re-set."
        )
        return

    existing_user = await db.get_user_by_username(bootstrap_username)
    if existing_user:
        await db.update_user_admin(int(existing_user["id"]), role="admin")
        await db.update_user_password(
            int(existing_user["id"]),
            pw_hash,
            salt,
            must_change_password=must_change_password,
        )
        await db.bump_user_session_epoch(int(existing_user["id"]))
        _emit_bootstrap_admin_credentials(
            existing_user["username"],
            password,
            "Promoted existing user to default admin",
            must_change_password,
        )
        return

    username = bootstrap_username
    try:
        await db.create_user(
            username,
            pw_hash,
            salt,
            display_name="Administrator",
            role="admin",
            must_change_password=must_change_password,
        )
    except ValueError:
        username = f"admin-{secrets.token_hex(2)}"
        await db.create_user(
            username,
            pw_hash,
            salt,
            display_name="Administrator",
            role="admin",
            must_change_password=must_change_password,
        )

    _emit_bootstrap_admin_credentials(
        username,
        password,
        "Created default admin account",
        must_change_password,
    )


# An unknown username still costs one hash with the same function and cost,
# so the response time does not tell which usernames exist.
_DUMMY_PASSWORD_SALT = secrets.token_hex(16)


async def verify_user(username: str, password: str) -> dict | None:
    """Verify a local password and return the user dict, or None.

    Only a local account has one: an account an external provider manages
    (``auth_provider`` set) never matches, whatever hash it holds, so the
    password form cannot sign in around the directory or the IdP (its
    lockout, MFA and disablement) on any path: local provider, local
    fallback or break-glass. The hash is computed all the same, so the
    response time does not tell which accounts are managed."""
    user = await db.get_user_by_username(username)
    salt = user["salt"] if user else _DUMMY_PASSWORD_SALT
    # PBKDF2 with 600k iterations is deliberately expensive (~200-500ms CPU);
    # run it off the event loop so a login burst can't stall every other request.
    computed = await asyncio.to_thread(_hash_password, password, salt)
    if user and secrets.compare_digest(computed, user["password_hash"]) and not (user.get("auth_provider") or ""):
        return user
    return None


def create_session_token(username: str, user_id: int, session_epoch: int = 0) -> str:
    # `originally_issued_at` is the absolute-cap anchor; `last_activity` is
    # bumped on every authenticated request to support idle-timeout. Both
    # are unix timestamps. The serializer also embeds its own issue time
    # (used by max_age=) but we need our own field that survives refreshes.
    # `session_epoch` binds the token to the user's current revocation
    # generation; bumping the user's epoch invalidates every prior token.
    now = int(time.time())
    return _serializer.dumps(
        {
            "user": username,
            "user_id": user_id,
            "session_epoch": int(session_epoch or 0),
            "originally_issued_at": now,
            "last_activity": now,
        }
    )


def _refresh_session_token(data: dict) -> str:
    """Re-issue a session token with `last_activity` bumped to now, preserving
    `originally_issued_at` so the absolute lifetime cap continues to apply."""
    return _serializer.dumps(
        {
            "user": data["user"],
            "user_id": data["user_id"],
            "session_epoch": int(data.get("session_epoch") or 0),
            "originally_issued_at": data.get("originally_issued_at", int(time.time())),
            "last_activity": int(time.time()),
        }
    )


def verify_session_token(token: str) -> dict | None:
    """Returns the decoded payload or None. Validates the signature only;
    idle timeout and absolute lifetime are enforced in require_auth where we
    have the user record (and so can honor session_never_expires).

    Tokens minted before originally_issued_at was added still get the
    serializer's max_age check enforced as a hard fallback so they expire
    on the same 24h schedule as legacy behavior.
    """
    try:
        data = _serializer.loads(token)
    except BadSignature:
        return None
    if "user" not in data or "user_id" not in data:
        return None
    # Legacy token without our absolute-cap anchor - fall back to the
    # serializer's own timestamp so old sessions can't outlive 24h.
    if "originally_issued_at" not in data:
        try:
            _serializer.loads(token, max_age=SESSION_MAX_AGE)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
    return data


# Initialize shared module with session verifier
shared.init_shared(verify_session_token)

PUBLIC_PATHS = {
    "/",
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/status",
    "/api/health",
    "/api/version",
    "/favicon.ico",
}

# Public paths that still count against the anonymous API rate limit:
# self-registration creates an account and costs a password hash per request.
# Login is not here; it has its own lockout, delay and in-flight limits.
RATE_LIMITED_PUBLIC_PATHS = frozenset({"/api/auth/register"})

# The SAML assertion consumer service: the IdP's cross-site POST carries no
# CSRF token; the signed response and the saml_tx cookie authenticate it.
SAML_ACS_PATH = "/api/auth/saml/acs"

# Inbound webhook receivers: no session and no CSRF (the sender can do
# neither; each authenticates its body itself). Unlike PUBLIC_PATHS they stay
# rate limited, under their own per-IP budget (``api_rate_limit_middleware``).
WEBHOOK_PATHS = frozenset({MERAKI_WEBHOOK_PATH}) | CHATOPS_WEBHOOK_PATHS
# Webhook deliveries per rate-limit window per source IP. Meraki bursts when
# many devices alert at once, so this is above the anonymous write limit.
WEBHOOK_RATE_LIMIT_MAX = 600

# Paths that remain accessible even when must_change_password is true
PASSWORD_CHANGE_ALLOWED_PATHS = {
    "/api/auth/change-password",
    "/api/auth/logout",
    "/api/auth/status",
    "/api/auth/profile",
}

# State-changing methods that require CSRF validation for cookie-auth
_CSRF_PROTECTED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Sentinel distinguishing "not resolved yet this request" from a legitimate
# None result in the per-request auth caches on request.state.
_AUTH_STATE_UNSET = object()


async def _load_request_user(request: Request, session: dict) -> dict | None:
    """Fetch the session's user record once per request.

    require_auth and every feature/admin gate need the same row; without the
    request.state cache each Depends chain re-queried it 3-4 times per call.
    """
    cached = getattr(request.state, "auth_user", _AUTH_STATE_UNSET)
    if cached is not _AUTH_STATE_UNSET:
        return cached
    user = await db.get_user_by_id(session["user_id"])
    request.state.auth_user = user
    return user


async def _load_request_features(request: Request, user: dict) -> list[str]:
    """Resolve the user's effective feature keys once per request."""
    cached = getattr(request.state, "auth_features", _AUTH_STATE_UNSET)
    if cached is not _AUTH_STATE_UNSET:
        return cached
    features = await _get_user_features(user, request=request)
    request.state.auth_features = features
    return features


def _session_user_gone(response: Response | None) -> HTTPException:
    """The 401 for a validly signed session whose user record is gone
    (deleted by an admin). Clears the orphan cookie so the next request
    takes the unauthenticated path cleanly; the caller raises the result."""
    if response is not None:
        response.delete_cookie("session", samesite="strict")
    return HTTPException(status_code=401, detail="Session user not found")


# The 401 detail for each reason shared.session_rejection gives, a missing
# user aside (_session_user_gone).
_SESSION_REJECTION_DETAIL = {
    "revoked": "Session has been revoked",
    "disabled": "Session has been revoked",
    "expired": "Session expired",
    "idle": "Session idle timeout exceeded",
}


async def require_auth(request: Request, response: Response = None):
    """Dependency that checks for a valid session cookie. Returns session dict.

    Enforces the configurable idle timeout (state.LOGIN_RULES.session_idle_timeout)
    and refreshes the cookie's `last_activity` on every authenticated request.
    Users with users.session_never_expires=1 bypass both the idle check and
    the absolute lifetime - intended for kiosk/display accounts.
    """
    # Per-request cache: routers register require_auth alongside feature
    # gates that call it again as a plain function, so without this the
    # whole check (token verify, user fetch, cookie re-issue) ran 2-3x.
    cached = getattr(request.state, "auth_session", _AUTH_STATE_UNSET)
    if cached is not _AUTH_STATE_UNSET:
        return cached

    path = request.url.path
    if path.startswith("/static/"):
        return None
    if path in PUBLIC_PATHS or path in WEBHOOK_PATHS:
        return None

    api_token = _extract_api_token(request)
    if APP_API_TOKEN and api_token and secrets.compare_digest(api_token, APP_API_TOKEN):
        session = {"user": API_TOKEN_USER, "user_id": 0, "auth_mode": "token"}
        request.state.auth_session = session
        current_actor.set(API_TOKEN_USER)
        current_correlation_id.set(getattr(request.state, "correlation_id", ""))
        return session

    if _env_flag("APP_REQUIRE_API_TOKEN", False) and path.startswith("/api/"):
        raise HTTPException(status_code=401, detail="Missing or invalid API token")

    token = request.cookies.get("session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    # Reuse the rate-limit middleware's verification of this same cookie
    # when it already succeeded earlier in the request.
    session = getattr(request.state, "session_precheck", None) or verify_session_token(token)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired")

    user = await _load_request_user(request, session)
    # The same decision the WebSocket check and /api/auth/status take: a
    # deleted user, a disabled account, a revoked epoch (password change,
    # admin reset, privilege change, rename, sign-out), the 24h cap and the idle timeout. Kiosk
    # accounts skip the two time checks.
    rejection = shared.session_rejection(session, user)
    if rejection == "user_missing" or not user:
        raise _session_user_gone(response)
    if rejection is not None:
        if response is not None:
            response.delete_cookie("session", samesite="strict")
        if rejection == "idle":
            idle_timeout = int(state.LOGIN_RULES.get("session_idle_timeout", 1800))
            elapsed = int(time.time()) - int(session.get("last_activity") or 0)
            await shared._audit(
                "auth",
                "session.idle_timeout",
                user=session.get("user", ""),
                detail=f"idle={elapsed}s threshold={idle_timeout}s path={path}",
                correlation_id=shared._corr_id(request),
            )
        raise HTTPException(status_code=401, detail=_SESSION_REJECTION_DETAIL[rejection])
    if user.get("must_change_password") and path not in PASSWORD_CHANGE_ALLOWED_PATHS:
        raise HTTPException(
            status_code=403,
            detail="Password change required before accessing this resource",
        )

    # Bump activity by re-issuing the cookie, with the attributes the login
    # flow uses. Kiosk accounts keep their cookie; a call with no Response
    # has nowhere to set one.
    if not user.get("session_never_expires") and response is not None:
        refreshed = _refresh_session_token(session)
        response.set_cookie(
            key="session",
            value=refreshed,
            httponly=True,
            samesite="strict",
            max_age=SESSION_MAX_AGE,
            secure=_session_cookie_secure(),
        )

    request.state.auth_session = session
    # Names the user on the object-change events this request causes.
    current_actor.set(str(session.get("user") or ""))
    current_correlation_id.set(getattr(request.state, "correlation_id", ""))
    return session


def _get_session(request: Request) -> dict | None:
    """Extract session data from the request cookie without raising."""
    token = request.cookies.get("session")
    if not token:
        return None
    return verify_session_token(token)


# Re-export mutable state for in-module use (backward compat during migration)
LOGIN_ATTEMPTS = state.LOGIN_ATTEMPTS
LOCKED_OUT = state.LOCKED_OUT
DEFAULT_LOGIN_RULES = state.DEFAULT_LOGIN_RULES

FEATURE_FLAGS = state.FEATURE_FLAGS
AUTH_CONFIG_DEFAULTS = state.AUTH_CONFIG_DEFAULTS
RADIUS_DICTIONARY_FILE = state.RADIUS_DICTIONARY_FILE
LOGIN_RULES = state.LOGIN_RULES
# No AUTH_CONFIG here: startup and every save rebind state.AUTH_CONFIG, so a
# name bound at import would keep the built-in defaults. Read state.AUTH_CONFIG.
DISCOVERY_SYNC_CONFIG = state.DISCOVERY_SYNC_CONFIG
SNMP_DISCOVERY_CONFIG = state.SNMP_DISCOVERY_CONFIG
SNMP_DISCOVERY_PROFILES = state.SNMP_DISCOVERY_PROFILES
SNMP_PROFILES = state.SNMP_PROFILES
GROUP_SNMP_ASSIGNMENTS = state.GROUP_SNMP_ASSIGNMENTS
TOPOLOGY_DISCOVERY_CONFIG = state.TOPOLOGY_DISCOVERY_CONFIG
CONFIG_DRIFT_CHECK_CONFIG = state.CONFIG_DRIFT_CHECK_CONFIG
COMPLIANCE_CHECK_CONFIG = state.COMPLIANCE_CHECK_CONFIG
MONITORING_CONFIG = state.MONITORING_CONFIG
SYSLOG_CONFIG = state.SYSLOG_CONFIG
DISCOVERY_DEFAULT_TIMEOUT_SECONDS = state.DISCOVERY_DEFAULT_TIMEOUT_SECONDS
DISCOVERY_DEFAULT_MAX_HOSTS = state.DISCOVERY_DEFAULT_MAX_HOSTS
DISCOVERY_MAX_CONCURRENT_PROBES = state.DISCOVERY_MAX_CONCURRENT_PROBES
DISCOVERY_PROBE_PORTS = state.DISCOVERY_PROBE_PORTS
JOB_RETENTION_MIN_DAYS = state.JOB_RETENTION_MIN_DAYS
JOB_RETENTION_CLEANUP_INTERVAL_SECONDS = state.JOB_RETENTION_CLEANUP_INTERVAL_SECONDS
APP_HTTPS_ENABLED = state.APP_HTTPS_ENABLED
APP_COOKIE_SECURE = state.APP_COOKIE_SECURE
APP_HSTS_ENABLED = state.APP_HSTS_ENABLED
APP_HSTS_MAX_AGE = state.APP_HSTS_MAX_AGE
APP_HTTPS_REDIRECT = state.APP_HTTPS_REDIRECT
APP_CORS_ALLOW_ORIGINS = state.APP_CORS_ALLOW_ORIGINS
SNMP_DISCOVERY_DEFAULTS = state.SNMP_DISCOVERY_DEFAULTS
SNMP_DISCOVERY_PROFILE_DEFAULTS = state.SNMP_DISCOVERY_PROFILE_DEFAULTS
DISCOVERY_SYNC_DEFAULTS = state.DISCOVERY_SYNC_DEFAULTS
CONFIG_DRIFT_CHECK_DEFAULTS = state.CONFIG_DRIFT_CHECK_DEFAULTS
CONFIG_BACKUP_POLICY_MIN_INTERVAL = state.CONFIG_BACKUP_POLICY_MIN_INTERVAL
CONFIG_BACKUP_POLICY_MAX_INTERVAL = state.CONFIG_BACKUP_POLICY_MAX_INTERVAL
CONFIG_BACKUP_POLICY_MIN_RETENTION = state.CONFIG_BACKUP_POLICY_MIN_RETENTION
CONFIG_BACKUP_POLICY_MAX_RETENTION = state.CONFIG_BACKUP_POLICY_MAX_RETENTION
COMPLIANCE_CHECK_DEFAULTS = state.COMPLIANCE_CHECK_DEFAULTS
COMPLIANCE_ASSIGNMENT_MIN_INTERVAL = state.COMPLIANCE_ASSIGNMENT_MIN_INTERVAL
COMPLIANCE_ASSIGNMENT_MAX_INTERVAL = state.COMPLIANCE_ASSIGNMENT_MAX_INTERVAL
MONITORING_DEFAULTS = state.MONITORING_DEFAULTS
SYSLOG_DEFAULTS = state.SYSLOG_DEFAULTS
TOPOLOGY_DISCOVERY_DEFAULTS = state.TOPOLOGY_DISCOVERY_DEFAULTS
STP_DISCOVERY_DEFAULTS = state.STP_DISCOVERY_DEFAULTS
DISCOVERY_SYNC_MIN_INTERVAL_SECONDS = state.DISCOVERY_SYNC_MIN_INTERVAL_SECONDS
DISCOVERY_SYNC_MAX_INTERVAL_SECONDS = state.DISCOVERY_SYNC_MAX_INTERVAL_SECONDS


_sanitize_login_rules = state._sanitize_login_rules


_sanitize_auth_config = state._sanitize_auth_config
_effective_job_retention_days = state._effective_job_retention_days
_sanitize_discovery_sync_config = state._sanitize_discovery_sync_config
_sanitize_topology_discovery_config = state._sanitize_topology_discovery_config
_sanitize_stp_discovery_config = state._sanitize_stp_discovery_config
_sanitize_config_drift_check_config = state._sanitize_config_drift_check_config
_sanitize_compliance_check_config = state._sanitize_compliance_check_config
_sanitize_monitoring_config = state._sanitize_monitoring_config
_sanitize_syslog_config = state._sanitize_syslog_config
_sanitize_cloud_flow_sync_config = state._sanitize_cloud_flow_sync_config
_sanitize_cloud_traffic_metric_sync_config = state._sanitize_cloud_traffic_metric_sync_config
_sanitize_snmp_discovery_config = state._sanitize_snmp_discovery_config
_sanitize_snmp_discovery_profile = state._sanitize_snmp_discovery_profile
_sanitize_snmp_discovery_profiles = state._sanitize_snmp_discovery_profiles
_sanitize_snmp_profile = state._sanitize_snmp_profile
_sanitize_snmp_profiles = state._sanitize_snmp_profiles
_sanitize_group_snmp_assignments = state._sanitize_group_snmp_assignments
_resolve_snmp_discovery_config = state._resolve_snmp_discovery_config
_resolve_host_snmp_config = state._resolve_host_snmp_config


async def _cleanup_expired_jobs() -> int:
    retention_days = _effective_job_retention_days()
    deleted = await db.delete_expired_jobs(retention_days)
    if deleted:
        LOGGER.info("Deleted %s expired job(s) older than %s day(s)", deleted, retention_days)
        increment_metric("jobs.retention.deleted")
    return deleted


async def _job_retention_cleanup_loop() -> None:
    while True:
        try:
            await _cleanup_expired_jobs()
            await asyncio.sleep(JOB_RETENTION_CLEANUP_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("Retention cleanup failed: %s", redact_value(str(exc)))
            increment_metric("jobs.retention.cleanup.failed")
            await asyncio.sleep(JOB_RETENTION_CLEANUP_INTERVAL_SECONDS)


def _flow_collector_seed_from_env() -> dict | None:
    """Build a flow_collector config dict from legacy APP_* env vars.

    Called only on the very first boot when no persisted row exists yet, so
    operators upgrading from Phase C don't have to re-enter their settings
    in the UI. After this initial seed the DB row is the source of truth.
    """
    seeded: dict[str, object] = {}
    enabled_raw = os.getenv("APP_NETFLOW_ENABLED", "").strip().lower()
    if enabled_raw:
        seeded["enabled"] = enabled_raw in ("1", "true", "yes", "on")
    netflow_port_raw = os.getenv("APP_NETFLOW_PORT", "").strip()
    if netflow_port_raw:
        try:
            seeded["netflow_port"] = int(netflow_port_raw)
        except ValueError:
            LOGGER.warning("flow settings seed: ignoring invalid APP_NETFLOW_PORT value %r", netflow_port_raw)
    sflow_port_raw = os.getenv("APP_SFLOW_PORT", "").strip()
    if sflow_port_raw:
        try:
            seeded["sflow_port"] = int(sflow_port_raw)
        except ValueError:
            LOGGER.warning("flow settings seed: ignoring invalid APP_SFLOW_PORT value %r", sflow_port_raw)
    retention_raw = os.getenv("APP_FLOW_RETENTION_HOURS", "").strip()
    if retention_raw:
        try:
            seeded["retention_hours"] = int(retention_raw)
        except ValueError:
            LOGGER.warning("flow settings seed: ignoring invalid APP_FLOW_RETENTION_HOURS value %r", retention_raw)
    agg_raw = os.getenv("APP_FLOW_AGGREGATION_INTERVAL_SECONDS", "").strip()
    if agg_raw:
        try:
            seeded["aggregation_interval_seconds"] = int(agg_raw)
        except ValueError:
            LOGGER.warning(
                "flow settings seed: ignoring invalid APP_FLOW_AGGREGATION_INTERVAL_SECONDS value %r", agg_raw
            )
    return seeded or None


async def _load_persisted_security_settings():
    login_rules = await db.get_auth_setting("login_rules")
    auth_config = await db.get_auth_setting("auth_config")
    discovery_sync = await db.get_auth_setting("discovery_sync")
    snmp_discovery = await db.get_auth_setting("snmp_discovery")
    snmp_discovery_profiles = await db.get_auth_setting("snmp_discovery_profiles")
    snmp_profiles = await db.get_auth_setting("snmp_profiles")
    group_snmp_assignments = await db.get_auth_setting("group_snmp_assignments")
    topology_discovery = await db.get_auth_setting("topology_discovery")
    topology_stp_discovery = await db.get_auth_setting("topology_stp_discovery")
    state.LOGIN_RULES = _sanitize_login_rules(login_rules)
    state.AUTH_CONFIG = _sanitize_auth_config(state._stored_auth_config(auth_config))
    state.DISCOVERY_SYNC_CONFIG = _sanitize_discovery_sync_config(discovery_sync)
    state.SNMP_DISCOVERY_CONFIG = _sanitize_snmp_discovery_config(snmp_discovery)
    state.SNMP_DISCOVERY_PROFILES = _sanitize_snmp_discovery_profiles(snmp_discovery_profiles)
    state.SNMP_PROFILES = _sanitize_snmp_profiles(snmp_profiles)
    state.GROUP_SNMP_ASSIGNMENTS = _sanitize_group_snmp_assignments(group_snmp_assignments)
    state.TOPOLOGY_DISCOVERY_CONFIG = _sanitize_topology_discovery_config(topology_discovery)
    state.STP_DISCOVERY_CONFIG = _sanitize_stp_discovery_config(topology_stp_discovery)
    config_drift_check = await db.get_auth_setting("config_drift_check")
    state.CONFIG_DRIFT_CHECK_CONFIG = _sanitize_config_drift_check_config(config_drift_check)
    compliance_check = await db.get_auth_setting("compliance_check")
    state.COMPLIANCE_CHECK_CONFIG = _sanitize_compliance_check_config(compliance_check)
    monitoring = await db.get_auth_setting("monitoring")
    state.MONITORING_CONFIG = _sanitize_monitoring_config(monitoring)
    syslog_config = await db.get_auth_setting("syslog_config")
    state.SYSLOG_CONFIG = _sanitize_syslog_config(syslog_config)
    if not configure_syslog_logging(state.SYSLOG_CONFIG):
        LOGGER.warning("syslog: persisted outbound logging configuration could not be applied")
    siem_sinks_raw = await db.get_auth_setting("siem_sinks")
    # auth_settings stores dicts; the SIEM list is wrapped as {"sinks": [...]}.
    if isinstance(siem_sinks_raw, dict):
        state.SIEM_SINKS = siem_forwarder.sanitize_sinks(siem_sinks_raw.get("sinks"))
    else:
        state.SIEM_SINKS = []
    notify_raw = await db.get_auth_setting("notification_channels")
    # auth_settings stores dicts; the channel list is wrapped as
    # {"channels": [...], "default_channel_ids": [...]}.
    if isinstance(notify_raw, dict):
        state.NOTIFICATION_CHANNELS = notification_channels.sanitize_channels(notify_raw.get("channels"))
        valid_ids = {c.id for c in state.NOTIFICATION_CHANNELS}
        state.NOTIFICATION_DEFAULT_CHANNEL_IDS = [
            str(c).strip() for c in (notify_raw.get("default_channel_ids") or []) if str(c).strip() in valid_ids
        ]
    else:
        state.NOTIFICATION_CHANNELS = []
        state.NOTIFICATION_DEFAULT_CHANNEL_IDS = []
    cloud_flow_sync = await db.get_auth_setting("cloud_flow_sync")
    state.CLOUD_FLOW_SYNC_CONFIG = _sanitize_cloud_flow_sync_config(cloud_flow_sync)
    cloud_flow_sync_status = await db.get_auth_setting("cloud_flow_sync_status")
    state.CLOUD_FLOW_SYNC_STATUS = state._sanitize_cloud_sync_status(cloud_flow_sync_status)
    cloud_traffic_metric_sync = await db.get_auth_setting("cloud_traffic_metric_sync")
    state.CLOUD_TRAFFIC_METRIC_SYNC_CONFIG = _sanitize_cloud_traffic_metric_sync_config(cloud_traffic_metric_sync)
    cloud_traffic_metric_sync_status = await db.get_auth_setting("cloud_traffic_metric_sync_status")
    state.CLOUD_TRAFFIC_METRIC_SYNC_STATUS = state._sanitize_cloud_sync_status(cloud_traffic_metric_sync_status)
    cloud_discovery_sync = await db.get_auth_setting("cloud_discovery_sync")
    state.CLOUD_DISCOVERY_SYNC_CONFIG = state._sanitize_cloud_discovery_sync_config(cloud_discovery_sync)
    source_collection_sync = await db.get_auth_setting("source_collection_sync")
    state.SOURCE_COLLECTION_SYNC_CONFIG = state._sanitize_source_collection_sync_config(source_collection_sync)
    meraki_alerts_config = await db.get_auth_setting("meraki_alerts")
    state.MERAKI_ALERTS_CONFIG = state._sanitize_meraki_alerts_config(meraki_alerts_config)
    await load_meraki_alert_status()
    await load_vendor_alert_settings()
    feature_visibility = await db.get_auth_setting("feature_visibility")
    if isinstance(feature_visibility, dict):
        state.FEATURE_VISIBILITY_HIDDEN = state._sanitize_feature_visibility(feature_visibility.get("hidden") or [])
    else:
        # No admin override stored yet: hide experimental/untested features by default.
        state.FEATURE_VISIBILITY_HIDDEN = state._sanitize_feature_visibility(state.DEFAULT_HIDDEN_FEATURES)
    flow_collector = await db.get_auth_setting("flow_collector")
    if flow_collector is None:
        # First boot: seed the persisted row from the legacy APP_* env vars
        # so existing deployments keep working without touching Settings UI.
        flow_collector = _flow_collector_seed_from_env()
        if flow_collector:
            await db.set_auth_setting("flow_collector", flow_collector)
    state.FLOW_COLLECTOR_CONFIG = state._sanitize_flow_collector_config(flow_collector)
    # Mirror persisted config into the collector module so it sees the same
    # values without a separate refresh dance.
    FLOW_COLLECTOR_CONFIG.update(state.FLOW_COLLECTOR_CONFIG)
    # Inbound syslog / SNMP trap receivers (started in the lifespan). Updated
    # in place: the receivers and the syslog rule engine read this dict.
    event_receivers = await db.get_auth_setting("event_receivers")
    state.EVENT_RECEIVER_CONFIG.update(state._sanitize_event_receiver_config(event_receivers))
    # Server certificate and client CA of the syslog TLS receiver.
    syslog_tls.apply(await db.get_auth_setting(syslog_tls.SETTING_KEY))
    # Source allowlist and rate limits of the trap, syslog and flow listeners.
    listener_sources.apply_config(listener_sources.sanitize_config(await db.get_auth_setting("listener_sources")))


def require_feature(feature_key: str):
    async def _dependency(request: Request, response: Response = None):
        session = await require_auth(request, response)
        # API tokens (APP_API_TOKEN env var) are server-level secrets with
        # full admin access by design - they bypass per-user feature checks.
        if session and session.get("auth_mode") == "token":
            return session
        user = await _load_request_user(request, session)
        if not user:
            raise _session_user_gone(response)
        features = await _load_request_features(request, user)
        if user.get("role") != "admin" and feature_key not in features:
            raise HTTPException(status_code=403, detail=f"Access denied for feature '{feature_key}'")
        return session

    return _dependency


_READ_METHODS = {"GET", "HEAD", "OPTIONS"}


def require_feature_method(feature_key: str):
    """Like require_feature but requires `<feature_key>.write` for mutating
    HTTP methods (POST/PUT/PATCH/DELETE). Use this on routers where you
    want to grant some users read-only access while still gating writes.

    Admins and API tokens bypass both checks. The base feature_key is
    always required even on writes, so granting only `<feature>.write`
    without the base read key denies access.
    """

    async def _dependency(request: Request, response: Response = None):
        session = await require_auth(request, response)
        if session and session.get("auth_mode") == "token":
            return session
        user = await _load_request_user(request, session)
        if not user:
            raise _session_user_gone(response)
        if user.get("role") == "admin":
            return session
        features = set(await _load_request_features(request, user))
        if feature_key not in features:
            raise HTTPException(status_code=403, detail=f"Access denied for feature '{feature_key}'")
        if request.method.upper() not in _READ_METHODS:
            write_key = f"{feature_key}.write"
            if write_key not in features:
                raise HTTPException(
                    status_code=403, detail=f"Read-only access for '{feature_key}'; '{write_key}' required to modify"
                )
        return session

    return _dependency


async def require_admin(request: Request, response: Response = None):
    """Dependency that checks for admin access. Returns session dict.

    API tokens (APP_API_TOKEN) are server-level secrets equivalent to admin;
    they bypass the per-user role check intentionally.
    """
    session = await require_auth(request, response)
    if session and session.get("auth_mode") == "token":
        return session
    # Look up by user_id, not username. A user can rename themselves while
    # editing their own account; their existing session keeps the old name,
    # so a username-based lookup would silently strip their admin rights
    # for the rest of the session.
    user = await _load_request_user(request, session)
    if not user:
        raise _session_user_gone(response)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return session


async def _ipam_sync_loop() -> None:
    """Periodically sync all enabled external IPAM sources."""
    while True:
        cfg = state.IPAM_SYNC_CONFIG
        interval = max(state.IPAM_SYNC_MIN_INTERVAL, int(cfg.get("interval_seconds", 1800)))
        await asyncio.sleep(interval)
        if not cfg.get("enabled"):
            continue
        try:
            sources = await db.list_ipam_sources(enabled_only=True)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("IPAM sync loop: failed to list sources: %s", type(exc).__name__)
            continue
        for source in sources:
            source_id = source.get("id")
            # An OPNsense collection fills its own source: never synced here.
            if not source_id or is_collection_fed(source.get("provider")):
                continue
            try:
                auth_config = await db.get_ipam_source_auth_config(source_id)
                snapshot = await collect_ipam_snapshot(source, auth_config)
                await db.replace_ipam_source_snapshot(
                    source_id,
                    prefixes=snapshot.get("prefixes") or [],
                    allocations=snapshot.get("allocations") or [],
                    sync_status="success",
                    sync_message=(
                        f"Scheduled sync: {int(snapshot.get('summary', {}).get('prefix_count', 0))} subnets, "
                        f"{int(snapshot.get('summary', {}).get('allocation_count', 0))} allocations"
                    ),
                )
                LOGGER.info(
                    "IPAM scheduled sync: source_id=%s provider=%s success",
                    source_id,
                    source.get("provider", ""),
                )
            except asyncio.CancelledError:
                raise
            except IpamAdapterError as exc:
                LOGGER.warning("IPAM scheduled sync: source_id=%s adapter error: %s", source_id, exc)
                await _record_sync_status(
                    db.set_ipam_source_sync_status(source_id, status="error", message=str(exc)), "IPAM scheduled sync"
                )
            except Exception as exc:
                LOGGER.warning("IPAM scheduled sync: source_id=%s error: %s", source_id, type(exc).__name__)
                await _record_sync_status(
                    db.set_ipam_source_sync_status(source_id, status="error", message="Scheduled sync failed"),
                    "IPAM scheduled sync",
                )


async def _dhcp_sync_loop() -> None:
    """Periodically pull scope/lease snapshots for all enabled DHCP servers."""
    while True:
        cfg = state.DHCP_SYNC_CONFIG
        interval = max(state.DHCP_SYNC_MIN_INTERVAL, int(cfg.get("interval_seconds", 1800)))
        await asyncio.sleep(interval)
        if not cfg.get("enabled"):
            continue
        try:
            servers = await db.list_dhcp_servers(enabled_only=True)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("DHCP sync loop: failed to list servers: %s", type(exc).__name__)
            continue
        for server in servers:
            server_id = server.get("id")
            if not server_id or is_collection_fed(server.get("provider")):
                # An OPNsense firewall's leases arrive with its topology collection.
                continue
            try:
                auth_config = await db.get_dhcp_server_auth_config(server_id)
                snapshot = await collect_dhcp_snapshot(server, auth_config)
                summary = snapshot.get("summary") or {}
                await db.replace_dhcp_server_snapshot(
                    server_id,
                    scopes=snapshot.get("scopes") or [],
                    leases=snapshot.get("leases") or [],
                    sync_status="success",
                    sync_message=(
                        f"Scheduled sync: {int(summary.get('scope_count', 0))} scopes, "
                        f"{int(summary.get('lease_count', 0))} leases"
                    ),
                )
                LOGGER.info(
                    "DHCP scheduled sync: server_id=%s provider=%s success",
                    server_id,
                    server.get("provider", ""),
                )
            except asyncio.CancelledError:
                raise
            except DhcpAdapterError as exc:
                LOGGER.warning("DHCP scheduled sync: server_id=%s adapter error: %s", server_id, exc)
                await _record_sync_status(
                    db.set_dhcp_server_sync_status(server_id, status="error", message=str(exc)), "DHCP scheduled sync"
                )
            except Exception as exc:
                LOGGER.warning("DHCP scheduled sync: server_id=%s error: %s", server_id, type(exc).__name__)
                await _record_sync_status(
                    db.set_dhcp_server_sync_status(server_id, status="error", message="Scheduled sync failed"),
                    "DHCP scheduled sync",
                )


# How long after start the one-off read of the stored configurations into
# interface addresses waits: startup is not slowed by it, and a short-lived
# app (a test client) never runs it.
INTERFACE_ADDRESSES_BACKFILL_DELAY_SECONDS = 120


async def _interface_addresses_backfill() -> None:
    """Once, after the upgrade to migration 0086, read every host's newest
    stored configuration into its interface addresses (see
    ``netcontrol.routes.network_objects.backfill_interface_addresses``)."""
    await asyncio.sleep(INTERFACE_ADDRESSES_BACKFILL_DELAY_SECONDS)
    try:
        await backfill_interface_addresses()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        LOGGER.warning("interface address backfill failed: %s", type(exc).__name__)


async def _opnsense_backup_encryption_backfill() -> None:
    """At every start, encrypt the OPNsense config backups an older release
    stored in plain text (migration 0133; see
    ``netcontrol.routes.opnsense_backup_encryption.encrypt_legacy_backups``).
    In the background, so a large table does not hold up startup; logs
    counts only."""
    try:
        counts = await encrypt_legacy_opnsense_backups()
        if counts["sealed"]:
            LOGGER.info("Encrypted %s OPNsense config backup(s) stored in plain text", counts["sealed"])
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        LOGGER.warning("OPNsense config backup encryption pass failed: %s", type(exc).__name__)


async def _record_sync_status(coro, what: str) -> None:
    """Await a status-recording DB write from a sync loop's error path.

    These writes run inside except handlers; if one raises (e.g. a transient
    'database is locked') it would kill the whole sync loop until restart, so
    failures here are logged and swallowed."""
    try:
        await coro
    except Exception as exc:
        LOGGER.warning("%s: failed to record sync status: %s", what, type(exc).__name__)


async def _cloud_flow_sync_loop() -> None:
    """Periodically pull cloud flow logs for all enabled accounts."""
    while True:
        cfg = state.CLOUD_FLOW_SYNC_CONFIG
        interval = max(60, int(cfg.get("interval_seconds", 300)))
        await asyncio.sleep(interval)
        if not cfg.get("enabled"):
            continue
        try:
            lookback = max(5, int(cfg.get("lookback_minutes", 15)))
            result = await pull_flow_logs_all_accounts(lookback_minutes=lookback)
            await persist_cloud_flow_sync_status(build_cloud_sync_status(result, source="scheduled", scope="all"))
            total = result.get("total_ingested", 0)
            processed = result.get("accounts_processed", 0)
            if total > 0:
                LOGGER.info(
                    "Cloud flow sync: ingested %s records from %s account(s)",
                    total,
                    processed,
                )
            # Prune old flow records here as well: the NetFlow collector's
            # aggregation cycle only runs when that collector is enabled, so
            # a cloud-only deployment would otherwise grow flow_records
            # without bound.
            retention_hours = int(FLOW_COLLECTOR_CONFIG.get("retention_hours", 48))
            cleaned = await db.cleanup_old_flow_records(retention_hours)
            if cleaned > 0:
                LOGGER.info("Cloud flow sync: pruned %s old flow records", cleaned)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("Cloud flow sync loop failed: %s", type(exc).__name__)
            await _record_sync_status(
                persist_cloud_flow_sync_status(
                    build_cloud_sync_status(
                        {"ok": False, "errors": [type(exc).__name__]}, source="scheduled", scope="all"
                    )
                ),
                "Cloud flow sync",
            )


async def _cloud_discovery_sync_loop() -> None:
    """Periodically refresh live cloud topology snapshots for enabled accounts.

    Without this, topology and policy-rule data only change on manual
    discovery and silently go stale.
    """
    from netcontrol.routes.cloud_visibility import run_scheduled_discovery

    while True:
        cfg = state.CLOUD_DISCOVERY_SYNC_CONFIG
        interval = max(300, int(cfg.get("interval_seconds", 3600)))
        await asyncio.sleep(interval)
        if not cfg.get("enabled"):
            continue
        try:
            result = await run_scheduled_discovery()
            if result.get("refreshed"):
                LOGGER.info(
                    "Cloud discovery sync: refreshed %s of %s account snapshot(s)",
                    result.get("refreshed"),
                    result.get("accounts"),
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("Cloud discovery sync loop failed: %s", type(exc).__name__)


async def _source_collection_sync_loop() -> None:
    """Periodically collect the integration sources (Meraki, Cato, Cisco FMC,
    Palo Alto Panorama, Appgate SDP, OPNsense) that are due.

    Wakes at most every five minutes so a source whose own interval is
    shorter than the default one is still collected on time; which sources
    are due is decided by ``run_scheduled_collections``.
    """
    from netcontrol.routes.meraki_topology import run_scheduled_collections

    while True:
        cfg = state.SOURCE_COLLECTION_SYNC_CONFIG
        interval = min(int(cfg.get("interval_seconds", 3600)), 300)
        await asyncio.sleep(interval)
        cfg = state.SOURCE_COLLECTION_SYNC_CONFIG
        if not cfg.get("enabled"):
            continue
        try:
            result = await run_scheduled_collections()
            if result.get("started"):
                LOGGER.info(
                    "Source collection sync: collected %s of %s due source(s) (%s error(s))",
                    result.get("started"),
                    result.get("due"),
                    result.get("errors"),
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("Source collection sync loop failed: %s", type(exc).__name__)


async def _meraki_alert_poll_loop() -> None:
    """Poll the Meraki organizations' assurance alerts on a short interval
    (``state.MERAKI_ALERTS_CONFIG``), separate from the heavy scheduled
    collection; also closes webhook alerts that never got a recovery."""
    from netcontrol.routes.meraki_alerts import run_alert_poll_cycle

    while True:
        interval = int(state.MERAKI_ALERTS_CONFIG.get("interval_seconds", 60))
        await asyncio.sleep(max(state.MERAKI_ALERTS_MIN_INTERVAL, interval))
        try:
            await run_alert_poll_cycle("scheduled")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("Meraki alert poll loop failed: %s", type(exc).__name__)


async def _vendor_alert_poll_loop() -> None:
    """Poll the vendor alert feeds (the Cato events feed) on their own short
    intervals (``netcontrol.routes.vendor_alerts``); one app worker polls a
    source at a time (a lease on its feed row)."""
    from netcontrol.routes.vendor_alerts import TICK_SECONDS, run_due_cycles

    while True:
        await asyncio.sleep(TICK_SECONDS)
        try:
            await run_due_cycles()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("Vendor alert poll loop failed: %s", type(exc).__name__)


async def _cloud_traffic_metric_sync_loop() -> None:
    """Periodically pull cloud traffic metrics for all enabled accounts."""
    while True:
        cfg = state.CLOUD_TRAFFIC_METRIC_SYNC_CONFIG
        interval = max(60, int(cfg.get("interval_seconds", 300)))
        await asyncio.sleep(interval)
        if not cfg.get("enabled"):
            continue
        try:
            lookback = max(5, int(cfg.get("lookback_minutes", 15)))
            result = await pull_traffic_metrics_all_accounts(lookback_minutes=lookback)
            await persist_cloud_traffic_sync_status(build_cloud_sync_status(result, source="scheduled", scope="all"))
            total = result.get("total_ingested", 0)
            processed = result.get("accounts_processed", 0)
            if total > 0:
                LOGGER.info(
                    "Cloud traffic sync: ingested %s metric samples from %s account(s)",
                    total,
                    processed,
                )
            retention_hours = int(cfg.get("retention_hours", 168))
            cleaned = await db.cleanup_old_cloud_traffic_metrics(retention_hours)
            if cleaned > 0:
                LOGGER.info("Cloud traffic sync: pruned %s old metric samples", cleaned)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("Cloud traffic sync loop failed: %s", type(exc).__name__)
            await _record_sync_status(
                persist_cloud_traffic_sync_status(
                    build_cloud_sync_status(
                        {"ok": False, "errors": [type(exc).__name__]}, source="scheduled", scope="all"
                    )
                ),
                "Cloud traffic sync",
            )


# ═════════════════════════════════════════════════════════════════════════════
# App Lifecycle
# ═════════════════════════════════════════════════════════════════════════════


_mcp_app, _run_mcp = build_mcp_app()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB and seed on startup."""
    _validate_startup_config()
    db.ensure_supported_db_engine()
    LOGGER.info("Starting Plexus API")
    await db.init_db()
    await _ensure_default_admin()
    # Migrate users from auth.json if it exists
    await _migrate_auth_json_users()
    # Settings rows saved before their secrets were encrypted (SNMP, SIEM,
    # notification, RADIUS/TACACS+/LDAP) are re-saved encrypted, once.
    await db.encrypt_legacy_auth_settings()
    await _load_persisted_security_settings()
    # Re-encrypt any cloud account credentials stored as plaintext before
    # at-rest encryption existed; without this they linger until next save.
    try:
        reencrypted = await db.reencrypt_legacy_cloud_auth_configs()
        if reencrypted:
            LOGGER.info("Re-encrypted %s legacy cloud account credential row(s)", reencrypted)
    except Exception as exc:
        LOGGER.warning("cloud auth_config re-encryption pass failed: %s", type(exc).__name__)
    # Auto-seed a database that has never been seeded. Deleting the demo
    # groups later must not bring them back: the seed leaves a marker.
    from routes.seed import database_is_fresh, seed

    if await database_is_fresh():
        await seed()
    await db.seed_built_in_graph_templates()
    await db.seed_built_in_cdefs()
    # Config templates (Delegator > Instructions) that ship with the app.
    # Each is inserted once per install; user edits and deletions stick.
    await db.seed_builtin_templates()
    await db.get_or_create_builtin_ipam_source()
    await _cleanup_expired_jobs()
    # Reconcile the job queue after a possible crash: fail jobs orphaned in
    # 'running' (they would block the concurrency gate forever) and drain any
    # jobs left 'queued' from before the restart.
    await reap_and_resume_jobs()
    await rehydrate_scheduled_upgrades()
    try:
        recon = await reconcile_running_labs()
        if recon.get("checked"):
            LOGGER.info(
                "lab runtime reconcile: checked=%d running=%d stopped=%d skipped=%d",
                recon.get("checked", 0),
                recon.get("still_running", 0),
                recon.get("marked_stopped", 0),
                recon.get("skipped", 0),
            )
    except Exception as exc:
        LOGGER.warning("lab runtime reconcile failed: %s", exc)
    # No discovery scan here: _discovery_sync_loop runs the first one in the
    # background, so the app serves without waiting out a full network sweep.
    state.API_RATE_LIMIT_LOCK = asyncio.Lock()

    # Size the default thread-pool executor to the monitoring poll fan-out.
    # Each concurrent device poll borrows one worker for its blocking SSH
    # session (via asyncio.to_thread); Python's default of min(32, cpu+4) can
    # be smaller than poll_concurrency on low-core hosts, which would throttle
    # the raised concurrency back down. Enlarge it (never shrink below default).
    import concurrent.futures

    _poll_concurrency = int(
        state.MONITORING_CONFIG.get("poll_concurrency", state.MONITORING_DEFAULTS["poll_concurrency"])
    )
    asyncio.get_running_loop().set_default_executor(
        concurrent.futures.ThreadPoolExecutor(
            max_workers=max(32, _poll_concurrency + 8),
            thread_name_prefix="plexus-io",
        )
    )

    def _on_background_loop_done(task: asyncio.Task) -> None:
        # Every loop is written to be immortal (internal try/except); if one
        # still dies, say so loudly at death time instead of the failure being
        # discovered only at shutdown (or never).
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            LOGGER.error(
                "background loop %s died with %s: %s — it will not run again until the app restarts",
                task.get_name(),
                type(exc).__name__,
                exc,
            )

    background_tasks = [
        asyncio.create_task(loop(), name=loop.__name__)
        for loop in (
            _job_retention_cleanup_loop,
            _discovery_sync_loop,
            _topology_discovery_loop,
            _stp_discovery_loop,
            _config_drift_check_loop,
            _mac_move_retention_loop,
            _config_backup_loop,
            _compliance_check_loop,
            _monitoring_poll_loop,
            fdm_poll_loop,
            _alert_escalation_loop,
            _baseline_computation_loop,
            _sla_rollup_loop,
            _downsampling_loop,
            _rate_limit_cleanup_loop,
            _report_scheduler_loop,
            _audit_run_loop,
            _cloud_flow_sync_loop,
            _cloud_traffic_metric_sync_loop,
            _cloud_discovery_sync_loop,
            _source_collection_sync_loop,
            _meraki_alert_poll_loop,
            _vendor_alert_poll_loop,
            federation_sync_loop,
            _ipam_sync_loop,
            _dhcp_sync_loop,
            _software_refresh_loop,
            lab_runtime_ttl_loop,
            lab_drift_scheduler_loop,
            _interface_addresses_backfill,
            _opnsense_backup_encryption_backfill,
            intended_config_loop,
            git_sources_loop,
            _lifecycle_check_loop,
            sync_jobs_loop,
        )
    ]
    for task in background_tasks:
        task.add_done_callback(_on_background_loop_done)

    # SIEM forwarder: start the per-sink dispatcher tasks and register the
    # hook that fans audit events out to them. Done before the rest of the
    # background loops so any auth events emitted by them get forwarded.
    try:
        await siem_forwarder.start_dispatcher(state.SIEM_SINKS)
        db.set_audit_event_hook(siem_forwarder.enqueue_event)
    except Exception as exc:
        LOGGER.warning("siem_forwarder: startup failed: %s", type(exc).__name__)

    # Notification channels: start the per-channel dispatcher tasks and
    # register the hook that fans newly created monitoring alerts out to them.
    try:
        await notification_channels.start_dispatcher(
            state.NOTIFICATION_CHANNELS, state.NOTIFICATION_DEFAULT_CHANNEL_IDS
        )
        db.set_alert_created_hook(notification_channels.on_alert_created)
    except Exception as exc:
        LOGGER.warning("notification_channels: startup failed: %s", type(exc).__name__)

    # Event webhooks: load the subscriptions and register on the structured
    # object-change hook (routes.db.change_events).
    try:
        await webhooks.start_dispatcher()
    except Exception as exc:
        LOGGER.warning("webhooks: startup failed: %s", type(exc).__name__)

    # Per-object change log: record every tracked change (the same hook).
    try:
        await object_changes.start_recorder()
    except Exception as exc:
        LOGGER.warning("change log: startup failed: %s", type(exc).__name__)

    flow_collector_started = False
    # Persisted flow_collector config (loaded above) drives lifecycle now.
    # Env vars only matter on the very first boot, where _load_persisted_
    # security_settings() seeded them into the auth_settings row.
    if FLOW_COLLECTOR_CONFIG.get("enabled"):
        netflow_port = int(FLOW_COLLECTOR_CONFIG.get("netflow_port", 2055))
        raw_sflow = int(FLOW_COLLECTOR_CONFIG.get("sflow_port", 6343))
        sflow_port: int | None = raw_sflow if raw_sflow else None
        try:
            flow_collector_started = await start_flow_collector(netflow_port, sflow_port=sflow_port)
        except Exception as exc:
            LOGGER.warning("flow_collector: startup failed: %s", type(exc).__name__)
        if flow_collector_started:
            _ensure_flow_aggregation_task()

    # Syslog / SNMP trap receivers: each starts when enabled in the saved
    # settings. A port that will not bind is logged and left stopped.
    try:
        await apply_event_receiver_config(state.EVENT_RECEIVER_CONFIG)
    except Exception as exc:
        LOGGER.warning("event receivers: startup failed: %s", type(exc).__name__)
    # Syslog rule counters and pending config-change runs, rebuilt from the
    # stored messages in the background. Only the process whose syslog
    # receiver listens (on UDP, TCP or TLS) acts on syslog (one worker binds
    # the ports), so only it restores, or every worker would start the same
    # backups.
    from netcontrol import syslog_rules
    from netcontrol.monitoring_repoll import keep_task
    from netcontrol.routes.metrics_engine import receiver_running

    if receiver_running("syslog"):
        keep_task(asyncio.ensure_future(syslog_rules.restore_state()))
    # The trap threshold counters, from the stored traps, likewise.
    if receiver_running("trap"):
        from netcontrol import trap_rules

        keep_task(asyncio.ensure_future(trap_rules.restore_state()))

    # Plugins: migrations, startup hooks and background tasks. Each plugin is
    # isolated - one that fails is marked failed and the rest carry on.
    try:
        await plugin_registry.start(db.get_db, shared.supervise_task)
    except Exception as exc:
        LOGGER.error("plugins: startup failed: %s", type(exc).__name__)

    try:
        # The MCP transport's task group lives for the life of the app (a
        # mounted app's own lifespan is never run by Starlette).
        async with _run_mcp():
            yield
    finally:
        # Give in-flight jobs a grace window to finish before tearing the loop
        # down, so a firmware push / config deploy isn't severed mid-write on
        # SIGTERM. Bounded by APP_SHUTDOWN_JOB_GRACE_SECONDS; must stay under
        # the container's stop_grace_period.
        try:
            await drain_running_jobs()
        except Exception as exc:
            LOGGER.warning("shutdown: job drain failed: %s", type(exc).__name__)
        try:
            await plugin_registry.stop()
        except Exception as exc:
            LOGGER.warning("plugins: shutdown failed: %s", type(exc).__name__)
        for task in background_tasks:
            task.cancel()
        # Cancelled loops unwind here; a loop that died with any other
        # exception is logged instead of aborting the rest of shutdown.
        results = await asyncio.gather(*background_tasks, return_exceptions=True)
        for task, res in zip(background_tasks, results):
            if isinstance(res, Exception):
                LOGGER.warning(
                    "background loop %s exited with %s during shutdown",
                    task.get_name(),
                    type(res).__name__,
                )
        await _cancel_flow_aggregation_task()
        if flow_collector_started:
            try:
                await stop_flow_collector()
            except Exception as exc:
                LOGGER.warning("flow_collector: shutdown failed: %s", type(exc).__name__)
        try:
            # The SNMPv3 replay record, written before the receivers close.
            await flush_v3_state()
        except Exception as exc:
            LOGGER.warning("SNMPv3 replay record: shutdown write failed: %s", type(exc).__name__)
        try:
            stop_receivers()
        except Exception as exc:
            LOGGER.warning("event receivers: shutdown failed: %s", type(exc).__name__)
        try:
            db.set_audit_event_hook(None)
            await siem_forwarder.stop_dispatcher()
        except Exception as exc:
            LOGGER.warning("siem_forwarder: shutdown failed: %s", type(exc).__name__)
        try:
            db.set_alert_created_hook(None)
            await notification_channels.stop_dispatcher()
        except Exception as exc:
            LOGGER.warning("notification_channels: shutdown failed: %s", type(exc).__name__)
        try:
            await webhooks.stop_dispatcher()
        except Exception as exc:
            LOGGER.warning("webhooks: shutdown failed: %s", type(exc).__name__)
        try:
            await object_changes.stop_recorder()
        except Exception as exc:
            LOGGER.warning("change log: shutdown failed: %s", type(exc).__name__)
        # Release DB connections last, after every consumer above has stopped.
        try:
            await db.close_db_pool()
        except Exception as exc:
            LOGGER.warning("db pool shutdown failed: %s", type(exc).__name__)


async def _rate_limit_cleanup_loop() -> None:
    """Periodically prune stale entries from the API rate-limit tracker and
    the login attempt/lockout maps (all keyed by client IP; without pruning,
    every IP that ever failed a login stays in memory for the process life).
    The maps are also size-capped (``state.TRACKER_MAX_ENTRIES``); the expiry
    rules live beside them in ``netcontrol/routes/state.py``."""
    while True:
        await asyncio.sleep(300)  # every 5 minutes
        try:
            now = time.time()
            lock = state.API_RATE_LIMIT_LOCK
            if lock:
                async with lock:
                    prune_expired(state.API_RATE_LIMIT_TRACKER, state.rate_limit_entry_expired, now)

            # Login state: drop lockouts that have expired, then attempt
            # lists whose newest entry is older than any window that matters.
            prune_expired(state.LOCKED_OUT, state.lockout_expired, now)
            prune_expired(state.LOGIN_ATTEMPTS, state.login_attempts_expired, now)
            prune_expired(state.LOGIN_USERNAME_FAILURES, state.username_failures_expired, now)
            prune_expired(state.SSO_FAILURE_AUDITS, state.sso_failure_audits_expired, now)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("rate-limit cleanup loop error: %s", type(exc).__name__)


async def _migrate_auth_json_users():
    """One-time migration: import users from legacy auth.json into the DB."""
    auth_file = os.path.join(os.path.dirname(__file__), "..", "routes", "auth.json")
    if not os.path.isfile(auth_file):
        return
    try:
        with open(auth_file) as f:
            legacy_users = json.load(f)
        migrated = 0
        for username, data in legacy_users.items():
            existing = await db.get_user_by_username(username)
            if not existing:
                await db.create_user(
                    username,
                    data["password_hash"],
                    data["salt"],
                    display_name=username.title(),
                    role=data.get("role", "user"),
                )
                migrated += 1
        if migrated:
            LOGGER.info("migration: migrated %s user(s) from auth.json to database", migrated)
        # Rename the file so we don't migrate again
        backup = auth_file + ".bak"
        os.rename(auth_file, backup)
        LOGGER.info("migration: renamed auth.json to auth.json.bak")
    except Exception as e:
        LOGGER.error("migration: auth.json migration error: %s", e)


# Disable OpenAPI docs in production unless explicitly enabled
_enable_docs = _env_flag("APP_ENABLE_DOCS", False)
app = FastAPI(
    title="Plexus API",
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if _enable_docs else None,
    redoc_url="/redoc" if _enable_docs else None,
    openapi_url="/openapi.json" if _enable_docs else None,
)

# Initialize late-binding dependencies for extracted route modules
init_auth(
    require_auth_fn=require_auth,
    generate_csrf_token_fn=_generate_csrf_token,
    validate_csrf_token_fn=_validate_csrf_token,
    hash_password_fn=_hash_password,
    verify_user_fn=verify_user,
    create_session_token_fn=create_session_token,
    session_max_age=SESSION_MAX_AGE,
    # Drives the cookie Secure attribute; use the dedicated cookie-secure flag
    # so a TLS-terminating-proxy deploy can mark cookies Secure even when the
    # app's own listener is plain HTTP (APP_HTTPS=false).
    app_https_enabled=APP_COOKIE_SECURE,
)
init_admin(
    require_admin_fn=require_admin,
    hash_password_fn=_hash_password,
    get_user_features_fn=_get_user_features,
    cleanup_expired_jobs_fn=_cleanup_expired_jobs,
)

# Auth routes - no global auth dependency (login/register are public)
app.include_router(auth_router)
# Admin routes - global require_admin dependency
app.include_router(
    admin_router,
    dependencies=[Depends(require_admin)],
)
# Feature routers below are read with the feature key and changed with
# ``<key>.write`` (require_feature_method). POST routes that only read are
# kept on a separate router mounted with plain require_feature.
app.include_router(
    templates_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("templates"))],
)
app.include_router(
    credentials_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("credentials"))],
)
# Secret Variables - encrypted key-value store for template substitution
# List/names endpoints need auth only (template editor autocomplete);
# create/update/delete enforce admin inside the route handlers.
app.include_router(
    secret_variables_router,
    dependencies=[Depends(require_auth)],
)
# Playbooks: read and edit names, descriptions, tags and inputs with
# playbooks / playbooks.write; creating, deleting and changing a playbook's
# code are admin only (a Python playbook runs inside the server).
app.include_router(
    playbooks_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("playbooks"))],
)
app.include_router(playbooks_admin_router, dependencies=[Depends(require_admin)])

app.add_middleware(
    CORSMiddleware,
    allow_origins=APP_CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token", "X-API-Token", "Authorization"],
)

# Added last so it sits outermost in the stack and compresses every response,
# including static assets. Starlette skips text/event-stream by default, so
# the SSE endpoints (monitoring, topology, inventory) are unaffected. Level 5
# keeps nearly all of level 9's ratio on JSON at a fraction of the CPU, which
# matters on the single event loop that also runs every poller.
app.add_middleware(GZipMiddleware, minimum_size=500, compresslevel=5)


@app.middleware("http")
async def csrf_protection_middleware(request: Request, call_next):
    """Validate CSRF token on state-changing requests authenticated via session cookie.

    Requests authenticated via API token (X-API-Token / Bearer) are exempt
    because they are not susceptible to cross-site request forgery.
    """
    if request.method in _CSRF_PROTECTED_METHODS and request.url.path.startswith("/api/"):
        # Skip CSRF check for public paths (login, register, etc.) and the
        # SAML ACS (the IdP's signed POST, bound to the saml_tx cookie).
        if (
            request.url.path not in PUBLIC_PATHS
            and request.url.path not in WEBHOOK_PATHS
            and request.url.path != SAML_ACS_PATH
        ):
            # Only enforce when using cookie-based auth (no API-token header)
            api_token = _extract_api_token(request)
            using_api_token = bool(APP_API_TOKEN and api_token and secrets.compare_digest(api_token, APP_API_TOKEN))
            if not using_api_token:
                session_cookie = request.cookies.get("session")
                if session_cookie:
                    session = verify_session_token(session_cookie)
                    if session:
                        csrf_tok = (
                            request.headers.get("x-csrf-token", "")
                            or request.headers.get("x-csrftoken", "")
                            or request.headers.get("x-xsrf-token", "")
                        )
                        if not csrf_tok or not _validate_csrf_token(csrf_tok, session["user"]):
                            return _api_error_response(403, "csrf_error", "Missing or invalid CSRF token")
                # No session cookie + no API token on a mutating /api/ request:
                # let require_auth reject it (don't silently skip CSRF)
    return await call_next(request)


@app.middleware("http")
async def api_rate_limit_middleware(request: Request, call_next):
    """Enforce per-IP sliding-window rate limits on API endpoints.

    Read requests (GET) and write requests (POST/PUT/DELETE) have separate
    thresholds.  Public paths (login, health) are exempt - the login
    endpoint already has its own brute-force protection - except those in
    ``RATE_LIMITED_PUBLIC_PATHS`` (self-registration).

    Authenticated requests (valid session cookie or valid API token) are
    exempt: the limiter's job is to throttle anonymous flooders, and a
    legitimate logged-in user with several tabs open or a stale-session
    refresh storm shouldn't be able to self-DoS into a 429 loop.

    A signed cookie alone is not a login. The cookie of a deleted user and
    a revoked one (password change, admin reset, rename, sign-out) are
    counted as anonymous; an idle or over-age session of a live account
    stays exempt, which is the stale-session case above.
    """
    cfg = state.API_RATE_LIMIT
    if cfg.get("enabled") and request.url.path in WEBHOOK_PATHS:
        # Never authenticated by a session: counted on their own budget.
        client_ip = request.client.host if request.client else "unknown"
        retry_after = await _rate_limit_hit(f"webhook:{client_ip}", WEBHOOK_RATE_LIMIT_MAX, cfg)
        if retry_after is not None:
            return _api_error_response(429, "rate_limit_exceeded", f"Too many requests. Try again in {retry_after}s.")
        return await call_next(request)
    path = request.url.path
    unlimited = path in PUBLIC_PATHS and path not in RATE_LIMITED_PUBLIC_PATHS
    if cfg.get("enabled") and path.startswith("/api/") and not unlimited:
        # Skip counting for authenticated requests - see docstring.
        api_token = _extract_api_token(request)
        session_cookie = request.cookies.get("session")
        verified_session = verify_session_token(session_cookie) if session_cookie else None
        session_counts = False
        if verified_session:
            # Stash for require_auth so the same cookie isn't decoded again;
            # the user row is cached on the request for the same reason.
            request.state.session_precheck = verified_session
            session_user = await _load_request_user(request, verified_session)
            session_counts = shared.session_rejection(verified_session, session_user) not in (
                "user_missing",
                "disabled",
                "revoked",
            )
        is_authenticated = bool(
            (APP_API_TOKEN and api_token and secrets.compare_digest(api_token, APP_API_TOKEN)) or session_counts
        )
        if is_authenticated:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        is_write = request.method in _CSRF_PROTECTED_METHODS
        limit = int(cfg.get("max_write", 40) if is_write else cfg.get("max_read", 120))
        retry_after = await _rate_limit_hit(client_ip, limit, cfg)
        if retry_after is not None:
            return _api_error_response(
                429,
                "rate_limit_exceeded",
                f"Too many requests. Try again in {retry_after}s.",
            )

    return await call_next(request)


async def _rate_limit_hit(key: str, limit: int, cfg: dict) -> int | None:
    """Count one request against ``key``'s sliding window. Returns the
    seconds to wait when the window is full, else ``None``."""
    now = time.time()
    window = max(1, int(cfg.get("window", 60)))
    lock = state.API_RATE_LIMIT_LOCK
    if not lock:
        return None
    async with lock:
        tracker = state.API_RATE_LIMIT_TRACKER
        timestamps = tracker.get(key, [])
        # Prune entries outside the sliding window
        timestamps = [t for t in timestamps if now - t < window]
        if len(timestamps) >= limit:
            return int(window - (now - timestamps[0])) + 1
        timestamps.append(now)
        tracker[key] = timestamps
    return None


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    """Attach a correlation ID to every request for log traceability.

    Callers may supply ``X-Correlation-ID``; otherwise one is generated.
    The ID is returned in the response header for client-side linking.
    """
    corr_id = request.headers.get("x-correlation-id", "").strip() or secrets.token_hex(8)
    request.state.correlation_id = corr_id
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = corr_id
    return response


@app.middleware("http")
async def metrics_and_logging_middleware(request: Request, call_next):
    start = time.perf_counter()
    corr_id = getattr(request.state, "correlation_id", "")
    try:
        response = await call_next(request)
    except Exception:
        duration_ms = (time.perf_counter() - start) * 1000
        increment_metric("api.requests.total")
        increment_metric("api.requests.failed")
        observe_timing("api.request.duration_ms", duration_ms)
        LOGGER.warning(
            "request error path=%s correlation_id=%s duration_ms=%.1f", request.url.path, corr_id, duration_ms
        )
        raise

    duration_ms = (time.perf_counter() - start) * 1000
    increment_metric("api.requests.total")
    if response.status_code >= 400:
        increment_metric("api.requests.failed")
    observe_timing("api.request.duration_ms", duration_ms)
    return response


# Response types that are streams read event by event (SSE; NDJSON is
# accepted by the SPA's stream readers too): sent with X-Accel-Buffering: no.
_UNBUFFERED_STREAM_TYPES = frozenset({"text/event-stream", "application/x-ndjson"})


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to every response.

    - HSTS when APP_HSTS/APP_HTTPS is enabled
    - X-Content-Type-Options to prevent MIME sniffing
    - X-Frame-Options to prevent clickjacking
    - Referrer-Policy to limit referrer leakage
    - Content-Security-Policy to mitigate XSS
    - Permissions-Policy to disable unused browser features
    """
    response = await call_next(request)
    if APP_HSTS_ENABLED:
        response.headers["Strict-Transport-Security"] = f"max-age={max(0, APP_HSTS_MAX_AGE)}; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # CSP: restrict resource origins while allowing the SPA to function.
    # script-src is 'self' only: the React bundle ships as external hashed
    # modules from /assets, so no inline <script> or CDN is needed
    # (the legacy index.html onclick= handlers were removed in the React
    # migration). 'unsafe-inline' is kept for style-src alone (dynamic style=
    # attrs from the React app and ECharts).
    # setdefault (not assignment) so a single-purpose endpoint that needs a
    # looser policy - e.g. the graph-export embed page, which renders only
    # escaped JSON and pulls ECharts from a CDN - can set its own CSP without
    # this middleware clobbering it.
    response.headers.setdefault(
        "Content-Security-Policy",
        (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self'; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        ),
    )
    # Not a security header, but this hook already sees every response
    # (mounted apps such as /mcp included). nginx buffers proxied responses
    # (deploy/nginx.conf); a stream tells it to pass each event straight on.
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type in _UNBUFFERED_STREAM_TYPES:
        response.headers.setdefault("X-Accel-Buffering", "no")
    return response


# ── HTTPS redirect middleware ─────────────────────────────────────────────────
# Registered after security_headers so Starlette runs it *first* (LIFO order).
# Redirects plaintext HTTP to HTTPS when APP_HTTPS_REDIRECT is enabled.
# Skips the health endpoint so load-balancer probes still work over HTTP.

_HTTPS_REDIRECT_EXEMPT = {"/api/health"}


@app.middleware("http")
async def https_redirect_middleware(request: Request, call_next):
    if not APP_HTTPS_REDIRECT:
        return await call_next(request)

    # Allow health checks through without redirect
    if request.url.path in _HTTPS_REDIRECT_EXEMPT:
        return await call_next(request)

    # Detect scheme: trust X-Forwarded-Proto from reverse proxy, fall back to
    # the actual request scheme (covers direct TLS termination by uvicorn).
    # The OIDC redirect URI is derived with the same helper.
    scheme = shared._request_scheme(request)

    if scheme != "https":
        target = request.url.replace(scheme="https")
        return RedirectResponse(str(target), status_code=301)

    return await call_next(request)


# ── Request body limit ────────────────────────────────────────────────────────
# Registered last so it is the outermost user middleware: an oversized body
# gets 413 before CSRF, rate limiting, auth or form parsing touch it. Default
# APP_MAX_REQUEST_BODY_MB (10 MB); the upload routes in
# netcontrol/body_limit.py:default_path_limits get larger limits, mirrored by
# the location blocks in deploy/nginx.conf.
app.add_middleware(BodyLimitMiddleware)


def _api_error_response(status_code: int, code: str, message: str, detail: dict | None = None) -> JSONResponse:
    content: dict = {
        "ok": False,
        "error": {
            "code": code,
            "message": message,
        },
    }
    if detail is not None:
        content["detail"] = detail
    return JSONResponse(status_code=status_code, content=content)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if not request.url.path.startswith("/api/"):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    # A structured detail (a dict with a ``message``, e.g. per-field
    # validation errors) is passed through as ``detail`` beside the usual
    # ``error.message``; any other non-string detail stays hidden.
    structured = exc.detail if isinstance(exc.detail, dict) and isinstance(exc.detail.get("message"), str) else None
    if structured is not None:
        detail = structured["message"]
    else:
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
    safe_detail = str(redact_value(detail))
    LOGGER.warning("HTTP %s on %s: %s", exc.status_code, request.url.path, safe_detail)
    if structured is not None:
        structured = {**structured, "message": safe_detail}
    return _api_error_response(exc.status_code, "http_error", safe_detail, structured)
    # A handler that catches everything and answers 500 keeps what it caught
    # as the cause or context. Input the database refused is the caller's
    # mistake there too.
    caught = (exc.__cause__ or exc.__context__) if exc.status_code == 500 else None
    if isinstance(caught, Exception) and client_error_for(caught) is not None:
        return await database_exception_handler(request, caught)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    if not request.url.path.startswith("/api/"):
        return JSONResponse(status_code=422, content={"detail": exc.errors()})

    # Where and why only. An error's ``input`` is the caller's body, and the
    # redaction goes by key name: a secret under a name it does not know
    # (a secret variable's ``value``) would be logged as sent.
    problems = [{"type": e.get("type"), "loc": e.get("loc"), "msg": e.get("msg")} for e in exc.errors()]
    LOGGER.warning("Validation error on %s: %s", request.url.path, redact_value(problems))
    return _api_error_response(422, "validation_error", "Request payload validation failed")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    if request.url.path.startswith("/api/"):
        LOGGER.error("Unhandled error on %s: %s", request.url.path, redact_value(str(exc)))
        LOGGER.debug("Traceback: %s", traceback.format_exc())
        return _api_error_response(500, "internal_error", "Internal server error")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


async def _public_path_caller_authenticated(request: Request) -> bool:
    """For a public path (no ``require_auth``): whether the request carries
    the server API token or, unless ``APP_REQUIRE_API_TOKEN`` is set, a live
    session cookie (``verify_ws_session``: the checks of ``require_auth``
    without refreshing the cookie)."""
    api_token = _extract_api_token(request)
    if APP_API_TOKEN and api_token and secrets.compare_digest(api_token, APP_API_TOKEN):
@app.exception_handler(asyncpg.PostgresError)
@app.exception_handler(asyncpg.InterfaceError)
async def database_exception_handler(request: Request, exc: Exception):
    """Input the database refuses (a number out of range, a missing parent,
    a taken name) is a client error; any other database error is re-raised
    for ``unhandled_exception_handler``."""
    error = client_error_for(exc)
    if error is None:
        raise exc
    LOGGER.warning("Refused by the database on %s: %s", request.url.path, redact_value(str(exc)))
    if not request.url.path.startswith("/api/"):
        return JSONResponse(status_code=error.status, content={"detail": error.message})
    return _api_error_response(error.status, error.code, error.message)


        return True
    if _env_flag("APP_REQUIRE_API_TOKEN", False):
        return False
    token = request.cookies.get("session")
    return bool(token) and await shared.verify_ws_session(token) is not None


def _health_body(body: dict, full: bool) -> dict:
    """The health payload for the caller: only ``ok`` and ``status`` without
    a session or the API token (no metrics, uptime or database error)."""
    return body if full else {"ok": body["ok"], "status": body["status"]}


# The readiness probe is public, so its database query is shared: every
# caller within the TTL gets one probe's result, and a caller that arrives
# while a probe runs gets the result before it. No request rate on
# /api/health can then hold more than one database connection. The timeout
# keeps a probe under the health callers' 4s urlopen timeout.
_HEALTH_PROBE_TTL_SECONDS = 2.0
_HEALTH_PROBE_TIMEOUT_SECONDS = 3.0


async def _db_probe() -> None:
    """One query on a read-only connection, so the probe can't block behind
    (or interfere with) a long write."""
    conn = await db.get_db(read_only=True)
    try:
        cursor = await conn.execute("SELECT 1")
        await cursor.fetchone()
    finally:
        await conn.close()


async def _db_probe_error() -> str | None:
    """The exception class name of a failed database probe, ``None`` when the
    database answers (``state.HEALTH_PROBE``)."""
    probe = state.HEALTH_PROBE
    now = time.monotonic()
    if now < probe["expires"]:
        return probe["error"]
    # Taken before the first await, so one caller probes at a time. A probe
    # that never reports back (its request was cancelled) frees the next one
    # when this runs out.
    probe["expires"] = now + _HEALTH_PROBE_TIMEOUT_SECONDS + _HEALTH_PROBE_TTL_SECONDS
    error = None
    try:
        await asyncio.wait_for(_db_probe(), timeout=_HEALTH_PROBE_TIMEOUT_SECONDS)
    except Exception as exc:
        error = type(exc).__name__
        LOGGER.error("health: database probe failed: %s", error)
    probe.update(error=error, expires=time.monotonic() + _HEALTH_PROBE_TTL_SECONDS)
    return error


@app.get("/api/health")
async def health(request: Request, probe: str = ""):
    # Unauthenticated callers (load balancers, the container healthchecks)
    # get ok/status and the same status code; the metrics, uptime and the
    # database error class are for a session or the API token.
    full = await _public_path_caller_authenticated(request)
    body = {
        "ok": True,
        "status": "healthy",
        "uptime_seconds": int(time.time() - APP_START_TIME),
        "metrics": snapshot_metrics(),
    }
    if probe == "live":
        # Liveness only: the process is up and serving requests. Use this
        # where a briefly busy database must not restart the container.
        return _health_body(body, full)

    # Readiness: every deploy gate (Dockerfile/compose healthchecks,
    # deploy/upgrade.sh) urlopen()s this path and treats non-2xx as
    # unhealthy, so an unreachable or wedged database must become a 503
    # here rather than reporting healthy while every real request fails.
    error = await _db_probe_error()
    if error is not None:
        body["ok"] = False
        body["status"] = "degraded"
        body["db"] = f"error: {error}"
        return JSONResponse(status_code=503, content=_health_body(body, full))
    body["db"] = "ok"
    return _health_body(body, full)


@app.get("/api/version")
async def version(request: Request):
    # The release number is public so external monitoring can read it
    # without a session; the exact build (git SHA) is for a session or the
    # API token (Settings > System compares it during an upgrade).
    from netcontrol.version import APP_GIT_SHA, APP_VERSION

    if not await _public_path_caller_authenticated(request):
        return {"version": APP_VERSION}
    return {"version": APP_VERSION, "git_sha": APP_GIT_SHA}


# The dashboard is the landing page and every SPA tab polls it; the data it
# aggregates changes on the order of poll cycles, not per request. A short
# shared TTL cache absorbs the fan-out (same pattern as /api/topology).
_DASHBOARD_CACHE_TTL_SECONDS = 10.0
_dashboard_cache: dict = {"data": None, "expires": 0.0}
_dashboard_cache_lock = asyncio.Lock()


async def _has_feature(request: Request, feature_key: str) -> bool:
    """Whether the caller passes ``require_feature(feature_key)``: admins and
    API tokens always do."""
    try:
        await require_feature(feature_key)(request)
    except HTTPException:
        return False
    return True


async def _dashboard_data() -> dict:
    if _dashboard_cache["data"] is not None and time.monotonic() < _dashboard_cache["expires"]:
        return _dashboard_cache["data"]
    async with _dashboard_cache_lock:
        # Double-checked: a concurrent request may have refreshed it while
        # this one waited on the lock.
        if _dashboard_cache["data"] is not None and time.monotonic() < _dashboard_cache["expires"]:
            return _dashboard_cache["data"]
        stats, recent_jobs, groups, monitoring, latest_polls, alerts, topology = await asyncio.gather(
            db.get_dashboard_stats(),
            db.get_all_jobs(limit=5),
            db.get_all_groups(),
            db.get_monitoring_summary(),
            db.get_latest_monitoring_polls(),
            db.get_monitoring_alerts(acknowledged=False, limit=50),
            dashboard_topology_summary(),
        )
        data = {
            "stats": stats,
            "recent_jobs": recent_jobs,
            "groups": groups,
            "monitoring": monitoring,
            "device_health": latest_polls,
            "open_alerts": alerts,
            "topology": topology,
        }
        _dashboard_cache["data"] = data
        _dashboard_cache["expires"] = time.monotonic() + _DASHBOARD_CACHE_TTL_SECONDS
        return data


@app.get("/api/dashboard", dependencies=[Depends(require_auth), Depends(require_feature("dashboard"))])
async def dashboard(request: Request):
    scope = await request_scope(request)
    username = str((_get_session(request) or {}).get("user") or "")
    if scope.restricted:
        # Limited to selected inventory groups: computed over its scope, uncached.
        data = await scoped_dashboard_data(scope, username)
    else:
        data = await _dashboard_data()
    # The cache is shared by every user, so the per-user feature gate applies
    # after it, to a copy (dashboard_for_caller).
    return await dashboard_for_caller(request, data, scope, username)


# ═════════════════════════════════════════════════════════════════════════════
# Register extracted route modules
# ═════════════════════════════════════════════════════════════════════════════

# Initialize late-binding dependencies for modules that need them
init_jobs(require_auth, require_feature, verify_session_token, _get_user_features)
init_config_drift(verify_session_token, _get_user_features)
init_compliance(require_auth, require_feature, require_admin)
init_deployments(verify_session_token, _get_user_features)
init_meraki_topology(_has_feature)
init_upgrades(verify_session_token, _get_user_features)

# Jobs
app.include_router(
    jobs_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("jobs"))],
)
# Approve / deny need jobs.approve (checked in the handler), not jobs.write.
app.include_router(
    jobs_approvals_router,
    dependencies=[Depends(require_auth), Depends(require_feature("jobs"))],
)
app.include_router(jobs_ws_router)  # WebSocket - handles its own auth
# Inventory + admin
app.include_router(
    inventory_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("inventory"))],
)
app.include_router(
    inventory_admin_router,
    dependencies=[Depends(require_admin)],
)
# Hardware components with serials and their history (docs/hardware-inventory.md):
# read with inventory, the on-demand SNMP read with inventory.write.
app.include_router(
    hardware_components_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("inventory"))],
)
# Custom fields and tags: definitions are readable by any signed-in user and
# managed by admins; host and group data sit with inventory access, prefix
# data with IPAM access (and admin to change, like every IPAM write).
app.include_router(custom_fields_router, dependencies=[Depends(require_auth)])
app.include_router(custom_fields_admin_router, dependencies=[Depends(require_admin)])
app.include_router(
    custom_fields_inventory_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("inventory"))],
)
app.include_router(
    custom_fields_ipam_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("ipam"))],
)
# Help: the user guides (docs/ and the other pages of
# netcontrol/docs_catalog.py), readable by any signed-in user.
app.include_router(help_docs_router, dependencies=[Depends(require_auth)])
# Device model: the catalogues are readable by any signed-in user and
# managed by admins; bulk edit of hosts sits with inventory access.
app.include_router(device_model_router, dependencies=[Depends(require_auth)])
app.include_router(device_model_admin_router, dependencies=[Depends(require_admin)])
app.include_router(
    device_model_inventory_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("inventory"))],
)
# Circuits, providers, provider networks and circuit types: read with the
# circuits feature, changed with circuits.write (docs/circuits.md).
app.include_router(
    circuits_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("circuits"))],
)
# Physical DCIM (racks, cables, patch panels, power): read with dcim,
# changed with dcim.write (docs/dcim.md).
app.include_router(
    dcim_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("dcim"))],
)
# Sync framework (NetBox, Nautobot, ServiceNow): read with sync, jobs changed
# and run with sync.write; connections (service credentials) admin only
# (docs/sync-framework.md).
app.include_router(
    sync_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("sync"))],
)
app.include_router(sync_admin_router, dependencies=[Depends(require_admin)])
# External secrets providers (Vault, AWS Secrets Manager, Azure Key Vault):
# read with secrets-providers; only admins add, change, delete and test
# them (docs/secrets-providers.md).
app.include_router(
    secrets_providers_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("secrets-providers"))],
)
# Hardware lifecycle (end-of-life notices, support contracts): read with
# lifecycle, changed with lifecycle.write (docs/hardware-lifecycle.md).
app.include_router(
    hardware_lifecycle_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("lifecycle"))],
)
# Dynamic groups (saved host filters): read with inventory access, changed
# with inventory.write; members are resolved within the caller's scope.
app.include_router(
    dynamic_groups_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("inventory"))],
)
# VRF and VLAN records: read with IPAM access, managed by admins. Registered
# before the IPAM router so its greedy ``/api/ipam/subnets/{subnet:path}``
# can never shadow these paths. A host's interface addresses sit with its
# interface inventory (the reports feature).
app.include_router(
    network_objects_router,
    dependencies=[Depends(require_auth), Depends(require_feature("ipam"))],
)
app.include_router(network_objects_admin_router, dependencies=[Depends(require_admin)])
# Namespaces, route targets, VLAN groups, RIRs and aggregates: gated like the
# VRF and VLAN records, and likewise ahead of the IPAM router.
app.include_router(ipam_model_router, dependencies=[Depends(require_auth), Depends(require_feature("ipam"))])
app.include_router(ipam_model_admin_router, dependencies=[Depends(require_admin)])
# Regions, the location tree, tenant groups and tenants: read with the
# organization feature, managed by admins.
app.include_router(
    organization_router,
    dependencies=[Depends(require_auth), Depends(require_feature("organization"))],
)
app.include_router(organization_admin_router, dependencies=[Depends(require_admin)])
# Bulk import (CSV/YAML/JSON): hosts and groups with inventory access and
# inventory.write, within the caller's object scope; prefixes, addresses,
# VLANs and VRFs with IPAM access, and admin to preview or commit like
# every IPAM write.
app.include_router(
    bulk_import_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("inventory"))],
)
app.include_router(
    bulk_import_ipam_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("ipam"))],
)
app.include_router(webhooks.router, dependencies=[Depends(require_admin)])
# Virtualization (clusters, virtual machines): read with virtualization,
# changed with virtualization.write; the cloud sync is for admins.
app.include_router(
    virtualization_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("virtualization"))],
)
app.include_router(virtualization_admin_router, dependencies=[Depends(require_admin)])
# Per-object change log: each object type is readable with the feature of
# its REST routes (checked per type in the router), scoped callers see only
# the hosts, groups and backups of their inventory groups.
app.include_router(object_changes.router, dependencies=[Depends(require_auth)])
app.include_router(
    network_objects_host_router,
    dependencies=[Depends(require_auth), Depends(require_feature("reports"))],
)
# Routing objects (intended BGP state) and their compliance with the observed
# BGP neighbors: read with routing, changed with routing.write. Not scope
# enforced, so a user limited to selected inventory groups gets 403.
app.include_router(
    routing_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("routing"))],
)
# Ansible dynamic inventory provider
app.include_router(
    ansible_inventory_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("inventory"))],
)
# Topology + admin
app.include_router(
    topology_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("topology"))],
)
app.include_router(
    topology_admin_router,
    dependencies=[Depends(require_admin)],
)
# Meraki organization topology (shares the topology feature; org/API-key
# management is additionally admin-gated inside the router)
app.include_router(
    meraki_topology_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("topology"))],
)
# Path, reachability and summarize history: personal, so reading the map is enough to keep one
# (topology, not topology.write, also for its POST and DELETE).
app.include_router(
    tool_history_router,
    dependencies=[Depends(require_auth), Depends(require_feature("topology"))],
)
# Importing a source's devices into the inventory: an administrator action
# that writes to both features, so it is gated by both.
app.include_router(
    source_import_router,
    dependencies=[
        Depends(require_auth),
        Depends(require_feature_method("topology")),
        Depends(require_feature("inventory")),
        Depends(require_admin),
    ],
)
# Inventory route/configuration collection, a source of the topology map:
# collecting is a write, so it needs topology.write like a source build.
app.include_router(
    inventory_collection_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("topology"))],
)
# Config Drift + admin
app.include_router(
    config_drift_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("config-drift"))],
)
app.include_router(
    config_drift_admin_router,
    dependencies=[Depends(require_admin)],
)
app.include_router(config_drift_ws_router)  # WebSocket - handles its own auth
# Intended configuration: read and generate with Config Drift access;
# templates, contexts and previews are managed by admins.
app.include_router(
    intended_config_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("config-drift"))],
)
# The bulk remediation preview is a POST that only reads.
app.include_router(
    intended_config_read_router,
    dependencies=[Depends(require_auth), Depends(require_feature("config-drift"))],
)
app.include_router(intended_config_admin_router, dependencies=[Depends(require_admin)])
# Git data sources (templates, playbooks and config contexts synced from Git): admin only.
app.include_router(git_sources_router, dependencies=[Depends(require_admin)])
# Data validation rules (enforced on inventory and IPAM writes): admin only.
app.include_router(validation_rules_router, dependencies=[Depends(require_admin)])
# Export templates: read and render by any signed-in user (each render checks
# the object type's feature and object scope); managed by admins.
app.include_router(export_templates_router, dependencies=[Depends(require_auth)])
app.include_router(export_templates_admin_router, dependencies=[Depends(require_admin)])
# Config Backups + admin
app.include_router(
    config_backups_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("config-backups"))],
)
# The rule views of OPNsense firewalls, read from their config backups.
app.include_router(
    opnsense_rules_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("config-backups"))],
)
# Compliance + admin
app.include_router(
    compliance_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("compliance"))],
)
app.include_router(
    compliance_admin_router,
    dependencies=[Depends(require_admin)],
)
# Meraki organizations scanned against profiles with "meraki" rules
app.include_router(
    meraki_compliance_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("compliance"))],
)
# Risk Analysis
app.include_router(
    risk_analysis_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("risk-analysis"))],
)
# Deployments
app.include_router(
    deployments_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("deployments"))],
)
app.include_router(deployments_ws_router)  # WebSocket - handles its own auth
# Maintenance windows (gating layer for deployments) -- shares the
# deployments feature key for reads, but mutations require deployments.write
# (or admin). A window can suppress the deployment time-gate, so opening or
# editing one is a privileged change, not a read-level action.
app.include_router(
    maintenance_windows_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("deployments"))],
)
# Monitoring + SLA + admin
app.include_router(
    monitoring_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("monitoring"))],
)
app.include_router(
    monitoring_admin_router,
    dependencies=[Depends(require_admin)],
)
# Syslog alert rules (docs/syslog-rules.md): reads need monitoring, changes
# monitoring.write, like the alert rules.
app.include_router(
    syslog_rules_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("monitoring"))],
)
app.include_router(
    cato_egress_check_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("monitoring"))],
)
app.include_router(
    cato_shared_host_check_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("monitoring"))],
)
# Near-real-time Meraki alerts: the list follows monitoring access; settings
# and Poll Now are admin-only; the webhook receiver authenticates by its
# shared secret and is answered 404 until one is configured.
app.include_router(
    meraki_alerts_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("monitoring"))],
)
app.include_router(
    meraki_alerts_admin_router,
    dependencies=[Depends(require_admin)],
)
app.include_router(meraki_webhook_router)
# Vendor alert feeds (the Cato events feed): the list follows monitoring
# access; settings and Poll Now are admin-only.
app.include_router(
    vendor_alerts_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("monitoring"))],
)
app.include_router(
    vendor_alerts_admin_router,
    dependencies=[Depends(require_admin)],
)
# Security events (IDS alerts of OPNsense firewalls): monitoring access.
app.include_router(
    security_events_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("monitoring"))],
)
# ChatOps (docs/chatops.md): the Slack, Webex and Teams endpoints check each
# platform's request signature (404 until a bot is set up); bots, user
# mappings, job presets and the command log are admin-only.
app.include_router(chatops_inbound_router)
app.include_router(chatops_admin_router, dependencies=[Depends(require_admin)])
# AI access (MCP): endpoint settings and token management, admin-only. The
# /mcp endpoint itself is mounted separately and authenticates by MCP token.
app.include_router(
    mcp_tokens_router,
    dependencies=[Depends(require_admin)],
)
# Object scope rules of access groups (per model, by tenant or site), admin-only.
app.include_router(scope_rules_router, dependencies=[Depends(require_admin)])
# Read-only GraphQL API: the query endpoint (and GraphiQL when enabled) for
# holders of the graphql feature, each field also checking the feature and
# object scope of its REST counterpart; its settings are admin-only.
app.include_router(
    graphql_router,
    dependencies=[Depends(require_auth), Depends(require_feature("graphql"))],
)
app.include_router(graphql_admin_router, dependencies=[Depends(require_admin)])
# Admin self-update routes (check, channel config, apply/rollback via the
# host updater handoff directory, progress).
app.include_router(
    admin_updates_router,
    dependencies=[Depends(require_admin)],
)
# Metrics Engine (Prometheus-style)
app.include_router(
    metrics_engine_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("monitoring"))],
)
app.include_router(
    metrics_engine_admin_router,
    dependencies=[Depends(require_admin)],
)
# Dashboards & Annotations
app.include_router(
    dashboards_router,
    dependencies=[Depends(require_auth), Depends(require_feature("dashboard"))],
)
# Graph Templates (Cacti-parity)
app.include_router(
    graph_templates_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("graph-templates"))],
)

app.include_router(
    reporting_router,
    dependencies=[Depends(require_auth), Depends(require_feature("reports"))],
)
# Custom OID profiles (SNMP poller configuration) - monitoring, not reports
app.include_router(
    oid_profiles_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("monitoring"))],
)
# Audit Report Engine: read with reports; starting a run and changing a
# schedule or an override need reports.write.
app.include_router(
    audit_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("reports"))],
)
# CDEF Engine (calculated data sources)
app.include_router(
    cdef_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("graph-templates"))],
)
# Evaluating a CDEF expression against sample data is a POST that only reads.
app.include_router(
    cdef_read_router,
    dependencies=[Depends(require_auth), Depends(require_feature("graph-templates"))],
)
# MAC/ARP Tracking
app.include_router(
    mac_tracking_router,
    dependencies=[Depends(require_auth), Depends(require_feature("mac-tracking"))],
)
# NetFlow / sFlow / IPFIX
app.include_router(
    flow_collector_router,
    dependencies=[Depends(require_auth), Depends(require_feature("traffic-analysis"))],
)
app.include_router(
    flow_collector_admin_router,
    dependencies=[Depends(require_admin)],
)
# Baseline Deviation Alerting
app.include_router(
    baseline_alerting_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("monitoring"))],
)
# Graph Export (PNG/SVG/embed URLs)
app.include_router(
    graph_export_router,
    dependencies=[Depends(require_auth), Depends(require_feature("reports"))],
)
# Interface Error/Discard Trending
app.include_router(
    interface_errors_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("monitoring"))],
)
# Bandwidth Billing & 95th Percentile: read with reports, changed with
# reports.write.
app.include_router(
    billing_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("reports"))],
)
# Cloud Visibility (AWS/Azure/GCP hybrid foundation)
app.include_router(
    cloud_visibility_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("cloud-visibility"))],
)
# IP Address Management
app.include_router(
    ipam_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("ipam"))],
)
# Software versions and vulnerability alerts
app.include_router(
    software_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("software"))],
)
# DHCP Scope/Lease Integration
app.include_router(
    dhcp_router,
    dependencies=[Depends(require_auth), Depends(require_feature("ipam"))],
)
# Geolocation and Floor Plan Mapping
app.include_router(
    geolocation_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("floor-plan"))],
)
# Multi-Instance Federation
app.include_router(
    federation_router,
    dependencies=[Depends(require_auth), Depends(require_feature("federation"))],
)
# IOS-XE Upgrade Tool
app.include_router(
    upgrades_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("upgrades"))],
)
app.include_router(upgrades_ws_router)  # WebSocket - handles its own auth
# Digital Twin / Lab Mode
app.include_router(
    lab_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("lab"))],
)
app.include_router(
    lab_runtime_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("lab"))],
)
app.include_router(
    lab_topology_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("lab"))],
)
app.include_router(
    lab_drift_router,
    dependencies=[Depends(require_auth), Depends(require_feature_method("lab"))],
)

# Plugins (docs/plugin-development.md): only the ones named in PLEXUS_PLUGINS
# load. A plugin that fails to import, validate or pass its version check is
# recorded as failed and skipped; Plexus starts regardless. Each router is
# mounted at /api/plugins/<name> behind the plugin's feature key.
app.include_router(plugins_router, dependencies=[Depends(require_auth)])
plugin_registry.bind_feature_flags(state.FEATURE_FLAGS)
try:
    plugin_registry.discover()
except Exception as _plugin_exc:  # defensive: discover() isolates each plugin itself
    LOGGER.error("plugin discovery failed: %s", _plugin_exc)
mount_plugin_routers(app, require_feature_method)


# ═════════════════════════════════════════════════════════════════════════════
# Static Frontend (served at root)
# ═════════════════════════════════════════════════════════════════════════════

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
FRONTEND_DIST = os.path.join(STATIC_DIR, "frontend", "dist")
FRONTEND_INDEX = os.path.join(FRONTEND_DIST, "index.html")

# AI access (MCP), read-only. Off until an admin enables it (404 until then)
# and authenticated by MCP tokens only: no session cookie, no APP_API_TOKEN.
# Served with and without the trailing slash; both routes sit ahead of the
# SPA catch-all.
app.router.routes.append(Route("/mcp", endpoint=_mcp_app, methods=None))
app.mount("/mcp", _mcp_app)


class _CachedStaticFiles(StaticFiles):
    """StaticFiles that sends one ``Cache-Control`` on every file response
    (304 revalidations included)."""

    def __init__(self, *args, cache_control: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.cache_control = cache_control

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = self.cache_control
        return response


# Vite content-hashes every filename under dist/assets, so any change
# produces a new URL and the old one can be cached forever.
_IMMUTABLE_CACHE_CONTROL = "public, max-age=31536000, immutable"
# Files that keep their name across releases: the browser revalidates them
# on every use (a cheap 304 against the ETag/Last-Modified StaticFiles sends),
# so an upgrade is never hidden behind a stale copy.
_REVALIDATE_CACHE_CONTROL = "no-cache"

# Mount static files directory. /static is not content-hashed (and holds a
# copy of dist/index.html under frontend/dist), so it revalidates.
if os.path.isdir(STATIC_DIR):
    app.mount(
        "/static",
        _CachedStaticFiles(directory=STATIC_DIR, cache_control=_REVALIDATE_CACHE_CONTROL),
        name="static",
    )


# React frontend - the only UI (migration history: docs/FRONTEND_MIGRATION.md).
# Built from netcontrol/static/frontend via `npm run build`. Served from the
# site root with SPA-style fallback so client-side routes resolve to
# index.html. The catch-all is registered last so every API router, the
# /static mount and the docs routes always win; it only sees paths nothing
# else claimed.


# Prefixes owned by the backend. A miss under one of these is a real 404,
# not a client-side route, so the SPA fallback must not answer with index.html.
_NON_SPA_PREFIXES = ("api/", "ws/", "static/", "docs", "redoc", "openapi.json")


class _SpaFallbackRoute(APIRoute):
    """The SPA catch-all, declining every backend-owned path outright.

    A plain GET ``/{path:path}`` route *partially* matches every path, so a
    POST to an unknown ``/api/...`` path answered 405 (method not allowed on
    the catch-all) instead of 404, and any route registered after it was
    shadowed. Returning no match at all for those prefixes lets the request
    fall through to the router's own 404 regardless of method.
    """

    def matches(self, scope):
        if scope["type"] == "http":
            path = scope.get("path", "")
            root_path = scope.get("root_path", "")
            if root_path and path.startswith(root_path):
                path = path[len(root_path) :]
            if path.lstrip("/").startswith(_NON_SPA_PREFIXES):
                return Match.NONE, {}
        return super().matches(scope)


@app.get("/frontend", include_in_schema=False)
@app.get("/frontend/{path:path}", include_in_schema=False)
async def redirect_legacy_frontend_prefix(request: Request, path: str = ""):
    """The SPA used to live under /frontend/. Bounce old bookmarks and links
    to the same route at the site root."""
    # safe_next: "/frontend//host" must not become the scheme-relative
    # "//host", which a browser follows off the site.
    target = safe_next("/" + path)
    if request.url.query:
        target += "?" + request.url.query
    return RedirectResponse(url=target, status_code=301)


if os.path.isdir(FRONTEND_DIST):
    _frontend_assets = os.path.join(FRONTEND_DIST, "assets")
    if os.path.isdir(_frontend_assets):
        app.mount(
            "/assets",
            _CachedStaticFiles(directory=_frontend_assets, cache_control=_IMMUTABLE_CACHE_CONTROL),
            name="frontend_assets",
        )


@app.get("/favicon.ico")
async def favicon():
    """Handle favicon requests gracefully."""
    return {"detail": "No favicon"}


_REVALIDATE_HEADERS = {"Cache-Control": _REVALIDATE_CACHE_CONTROL}


async def serve_react_frontend(path: str = ""):
    """Serve the React SPA. Returns the requested file when it exists on
    disk (e.g. manifest, viewer-layout.js); otherwise falls back to
    index.html so deep links handled by react-router resolve correctly.
    The root falls back to /docs only when no bundle is deployed.
    Backend-owned prefixes never reach here (see _SpaFallbackRoute).

    These files keep their names across builds (only dist/assets is
    content-hashed), so they are sent ``no-cache``: the browser revalidates
    them on every load. Without it a browser may reuse an old index.html for
    hours after an upgrade, and with it the old bundle it names.
    """
    if path:
        candidate = os.path.realpath(os.path.join(FRONTEND_DIST, path))
        # Guard against path traversal: candidate must stay inside dist/.
        # Compare against realpath + separator so a sibling directory with
        # the same prefix (e.g. dist-evil/) can't satisfy a bare startswith.
        dist_root = os.path.realpath(FRONTEND_DIST)
        if (candidate == dist_root or candidate.startswith(dist_root + os.sep)) and os.path.isfile(candidate):
            return FileResponse(candidate, headers=_REVALIDATE_HEADERS)
    if os.path.isfile(FRONTEND_INDEX):
        return FileResponse(FRONTEND_INDEX, headers=_REVALIDATE_HEADERS)
    if not path:
        return RedirectResponse(url="/docs")
    raise HTTPException(status_code=404, detail="React frontend not built")


for _spa_path in ("/", "/{path:path}"):
    app.router.add_api_route(
        _spa_path, serve_react_frontend, include_in_schema=False, route_class_override=_SpaFallbackRoute
    )
