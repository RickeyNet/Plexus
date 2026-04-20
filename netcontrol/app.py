"""
app.py — Plexus FastAPI Application

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

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

# Ensure project root is on path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import time

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel, ConfigDict, Field

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
    _admin_user_payload,
    _security_check_payload,
    _validate_feature_keys,
    admin_run_retention_cleanup_now,
    init_admin,
    router as admin_router,
)
from netcontrol.routes.auth import (
    PYRAD_AVAILABLE,
    ChangePasswordRequest,
    LoginRequest,
    RegisterRequest,
    UpdateProfileRequest,
    _ensure_radius_dictionary_file,
    _get_user_features,
    _radius_authenticate_sync,
    auth_status,
    authenticate_login_identity,
    init_auth,
    login,
    register,
    router as auth_router,
    upsert_radius_user,
    verify_radius_user,
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
    init_config_backups,
    router as config_backups_router,
)
from netcontrol.routes.config_drift import (
    ConfigDriftStatusUpdate,
    _analyze_drift_for_host,
    _capture_job_sockets,
    _capture_jobs,
    _config_drift_check_loop,
    _run_config_drift_check_once,
    init_config_drift,
    router as config_drift_router,
    ws_router as config_drift_ws_router,
)
from netcontrol.routes.credentials import CredentialCreate, CredentialUpdate, router as credentials_router
from netcontrol.routes.secret_variables import init_secret_variables, router as secret_variables_router
from netcontrol.routes.dashboards import router as dashboards_router
from netcontrol.routes.graph_templates import router as graph_templates_router
from netcontrol.routes.cdef_engine import router as cdef_router
from netcontrol.routes.mac_tracking import router as mac_tracking_router
from netcontrol.routes.flow_collector import router as flow_collector_router
from netcontrol.routes.baseline_alerting import router as baseline_alerting_router
from netcontrol.routes.graph_export import router as graph_export_router
from netcontrol.routes.interface_errors import (
    init_interface_errors,
    router as interface_errors_router,
)
from netcontrol.routes.billing import (
    init_billing,
    router as billing_router,
)
from netcontrol.routes.cloud_visibility import (
    build_cloud_sync_status,
    init_cloud_visibility,
    persist_cloud_flow_sync_status,
    persist_cloud_traffic_sync_status,
    router as cloud_visibility_router,
)
from netcontrol.routes.federation import (
    init_federation,
    federation_sync_loop,
    router as federation_router,
)
from netcontrol.routes.cloud_flow_pullers import pull_flow_logs_all_accounts
from netcontrol.routes.cloud_metric_pullers import pull_traffic_metrics_all_accounts
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
from netcontrol.routes.ansible_inventory import (
    init_ansible_inventory,
    router as ansible_inventory_router,
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
from netcontrol.routes.jobs import (
    _MAX_CONCURRENT_JOBS as _jobs_MAX_CONCURRENT_JOBS,
    _job_semaphore as _jobs_job_semaphore,
    _process_job_queue,
    init_jobs,
    router as jobs_router,
    ws_router as jobs_ws_router,
)
from netcontrol.routes.metrics_engine import (
    _downsampling_loop,
    admin_router as metrics_engine_admin_router,
    inject_auth as metrics_engine_inject_auth,
    router as metrics_engine_router,
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
    admin_router as monitoring_admin_router,
    init_monitoring,
    router as monitoring_router,
)
from netcontrol.routes.playbooks import (
    PlaybookCreate,
    PlaybookUpdate,
    _sanitize_ansible_filename,
    _sanitize_playbook_filename,
    router as playbooks_router,
    sync_playbooks_from_registry,
    write_playbook_file,
)
from netcontrol.routes.reporting import _report_scheduler_loop, router as reporting_router
from netcontrol.routes.risk_analysis import (
    _CRITICAL_PATTERNS,
    RiskAnalysisRequest,
    _classify_change_areas,
    _compute_risk_score,
    _run_risk_analysis_for_host,
    _simulate_config_change,
    init_risk_analysis,
    router as risk_analysis_router,
)
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
from netcontrol.routes.templates import TemplateCreate, TemplateUpdate, router as templates_router
from netcontrol.routes.upgrades import (
    init_upgrades,
    router as upgrades_router,
    ws_router as upgrades_ws_router,
)
from netcontrol.routes.topology import (
    _calc_interface_utilization,
    _record_topology_changes,
    _stp_discovery_loop,
    _run_topology_discovery_once,
    _topology_discovery_loop,
    admin_router as topology_admin_router,
    router as topology_router,
)

# Ensure project root is on path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import importlib

import routes.database as db
from routes.crypto import decrypt, encrypt
from routes.runner import LogEvent, execute_playbook, get_playbook_class

try:
    from routes.ansible_runner_backend import execute_ansible_playbook
    ANSIBLE_RUNNER_AVAILABLE = True
except ImportError:
    ANSIBLE_RUNNER_AVAILABLE = False

# Auto-register all playbooks
from templates import playbooks  # noqa: F401

from netcontrol.telemetry import configure_logging, increment_metric, observe_timing, redact_value, snapshot_metrics
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
CSRF_TOKEN_MAX_AGE = 86400  # 24 hours — aligned with session lifetime


def _generate_csrf_token(session_user: str) -> str:
    """Create a signed, time-limited CSRF token bound to the session user."""
    if _csrf_serializer is None:
        raise RuntimeError("CSRF serializer not initialised — check SECRET_KEY configuration")
    return _csrf_serializer.dumps({"csrf_user": session_user})


def _validate_csrf_token(token: str, session_user: str) -> bool:
    """Return True when the token is valid, not expired, and bound to the user."""
    if _csrf_serializer is None:
        raise RuntimeError("CSRF serializer not initialised — check SECRET_KEY configuration")
    try:
        data = _csrf_serializer.loads(token, max_age=CSRF_TOKEN_MAX_AGE)
        return data.get("csrf_user") == session_user
    except (BadSignature, SignatureExpired):
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


# Playbook filename sanitizers and write_playbook_file — extracted to playbooks.py (re-imported above)


# ═════════════════════════════════════════════════════════════════════════════
# Authentication (DB-backed users)
# ═════════════════════════════════════════════════════════════════════════════

SECRET_KEY_FILE = os.getenv("APP_SESSION_KEY_FILE", os.path.join(os.path.dirname(__file__), "..", "routes", "session.key"))
SESSION_MAX_AGE = 86400  # 24 hours


def _load_or_create_secret_key() -> str:
    key_dir = os.path.dirname(SECRET_KEY_FILE)
    if key_dir:
        os.makedirs(key_dir, exist_ok=True)

    if os.path.isfile(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    try:
        # Create file with restrictive permissions atomically (no race window)
        fd = os.open(SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
    except OSError:
        # Fallback for Windows (O_EXCL mode bits may not apply)
        with open(SECRET_KEY_FILE, "w") as f:
            f.write(key)
        try:
            os.chmod(SECRET_KEY_FILE, 0o600)
        except OSError:
            pass
    return key


_secret_key = _load_or_create_secret_key()
_serializer = URLSafeTimedSerializer(_secret_key)
_csrf_serializer = URLSafeTimedSerializer(_secret_key + "-csrf")


def _hash_password(password: str, salt: str = "") -> str:
    # Use PBKDF2 with 600 000 iterations (OWASP recommendation) instead of
    # a single SHA-256 round.  Existing hashes are 64-char hex (SHA-256);
    # new hashes are 128-char hex (PBKDF2-SHA-256, 64-byte dk).
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), f"{salt}:".encode(), 600_000, dklen=64
    ).hex()


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
    _msg = (
        f"\n*** {action} ***\n"
        f"    Username: {username}\n"
        f"    Password: {password}\n"
        f"    {guidance}\n\n"
    )
    os.write(2, _msg.encode())  # fd 2 = stderr


def _is_dev_bootstrap_mode() -> bool:
    env = os.getenv("APP_ENV", "").strip().lower()
    # "test" intentionally excluded — avoid deterministic admin password
    # in CI/test environments unless explicitly opted in via
    # PLEXUS_DEV_BOOTSTRAP=1.
    if env in {"dev", "development", "local"}:
        return True
    return _env_flag("PLEXUS_DEV_BOOTSTRAP", False)


async def _ensure_default_admin():
    """Ensure at least one local admin account exists.

    First-boot behavior:
      - If no admin user exists, create/promote one and print credentials.
      - ``PLEXUS_INITIAL_ADMIN_PASSWORD`` may provide the initial password.
      - Dev mode defaults to ``netcontrol`` (or ``PLEXUS_DEFAULT_ADMIN_PASSWORD``).
      - Non-dev mode defaults to a random password.

    Recovery behavior:
      - If ``PLEXUS_FORCE_ADMIN_PASSWORD_RESET=true`` is set, reset the
        configured bootstrap admin account password on startup.
    """
    users = await db.get_all_users()
    has_admin = any((u.get("role") or "").lower() == "admin" for u in users)

    bootstrap_username = _bootstrap_admin_username()
    configured_password = os.environ.pop("PLEXUS_INITIAL_ADMIN_PASSWORD", "").strip()
    default_bootstrap_password = os.getenv("PLEXUS_DEFAULT_ADMIN_PASSWORD", "netcontrol").strip() or "netcontrol"
    force_reset = _env_flag("PLEXUS_FORCE_ADMIN_PASSWORD_RESET", False)
    dev_bootstrap = _is_dev_bootstrap_mode()

    if has_admin and not force_reset:
        if dev_bootstrap:
            conn = await db.get_db()
            try:
                await conn.execute("UPDATE users SET must_change_password = 0 WHERE must_change_password = 1")
                await conn.commit()
            finally:
                await conn.close()
        return

    if configured_password:
        password = configured_password
        must_change_password = True
    elif dev_bootstrap:
        password = default_bootstrap_password
        must_change_password = False
    else:
        password = secrets.token_urlsafe(16)
        must_change_password = True

    salt = secrets.token_hex(16)
    pw_hash = _hash_password(password, salt)

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
        _emit_bootstrap_admin_credentials(
            target["username"],
            password,
            "Reset admin bootstrap password",
            must_change_password,
        )
        LOGGER.warning(
            "Reset bootstrap admin password via PLEXUS_FORCE_ADMIN_PASSWORD_RESET. "
            "Credentials were printed to stderr.",
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
        _emit_bootstrap_admin_credentials(
            existing_user["username"],
            password,
            "Promoted existing user to default admin",
            must_change_password,
        )
        LOGGER.warning(
            "Promoted existing user '%s' to admin and reset password (must_change_password=%s). "
            "Credentials were printed to stderr.",
            existing_user["username"],
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
    LOGGER.warning(
        "Created default admin account '%s' (must_change_password=%s). "
        "Credentials were printed to stderr.",
        username,
        must_change_password,
    )


async def verify_user(username: str, password: str) -> dict | None:
    """Verify credentials and return the user dict, or None."""
    user = await db.get_user_by_username(username)
    if not user:
        return None
    computed = _hash_password(password, user["salt"])
    if secrets.compare_digest(computed, user["password_hash"]):
        return user
    return None


def create_session_token(username: str, user_id: int) -> str:
    return _serializer.dumps({"user": username, "user_id": user_id})


def verify_session_token(token: str) -> dict | None:
    """Returns {"user": username, "user_id": id} or None."""
    try:
        data = _serializer.loads(token, max_age=SESSION_MAX_AGE)
        if "user" in data and "user_id" in data:
            return data
        return None
    except (BadSignature, SignatureExpired):
        return None


# Initialize shared module with session verifier
shared.init_shared(verify_session_token)

PUBLIC_PATHS = {"/", "/api/auth/login", "/api/auth/register", "/api/auth/status", "/api/health", "/favicon.ico"}

# Paths that remain accessible even when must_change_password is true
PASSWORD_CHANGE_ALLOWED_PATHS = {
    "/api/auth/change-password",
    "/api/auth/logout",
    "/api/auth/status",
    "/api/auth/profile",
}

# State-changing methods that require CSRF validation for cookie-auth
_CSRF_PROTECTED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


async def require_auth(request: Request):
    """Dependency that checks for a valid session cookie. Returns session dict."""
    path = request.url.path
    if path.startswith("/static/"):
        return None
    if path in PUBLIC_PATHS:
        return None

    api_token = _extract_api_token(request)
    if APP_API_TOKEN and api_token and secrets.compare_digest(api_token, APP_API_TOKEN):
        return {"user": "api-token", "user_id": 0, "auth_mode": "token"}

    if _env_flag("APP_REQUIRE_API_TOKEN", False) and path.startswith("/api/"):
        raise HTTPException(status_code=401, detail="Missing or invalid API token")

    token = request.cookies.get("session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    session = verify_session_token(token)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired")

    # Enforce first-login password reset: block privileged operations
    if path not in PASSWORD_CHANGE_ALLOWED_PATHS:
        user = await db.get_user_by_id(session["user_id"])
        if user and user.get("must_change_password"):
            raise HTTPException(
                status_code=403,
                detail="Password change required before accessing this resource",
            )

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
AUTH_CONFIG = state.AUTH_CONFIG
DISCOVERY_SYNC_CONFIG = state.DISCOVERY_SYNC_CONFIG
SNMP_DISCOVERY_CONFIG = state.SNMP_DISCOVERY_CONFIG
SNMP_DISCOVERY_PROFILES = state.SNMP_DISCOVERY_PROFILES
SNMP_PROFILES = state.SNMP_PROFILES
GROUP_SNMP_ASSIGNMENTS = state.GROUP_SNMP_ASSIGNMENTS
TOPOLOGY_DISCOVERY_CONFIG = state.TOPOLOGY_DISCOVERY_CONFIG
CONFIG_DRIFT_CHECK_CONFIG = state.CONFIG_DRIFT_CHECK_CONFIG
CONFIG_BACKUP_CONFIG = state.CONFIG_BACKUP_CONFIG
COMPLIANCE_CHECK_CONFIG = state.COMPLIANCE_CHECK_CONFIG
MONITORING_CONFIG = state.MONITORING_CONFIG
DISCOVERY_DEFAULT_TIMEOUT_SECONDS = state.DISCOVERY_DEFAULT_TIMEOUT_SECONDS
DISCOVERY_DEFAULT_MAX_HOSTS = state.DISCOVERY_DEFAULT_MAX_HOSTS
DISCOVERY_MAX_CONCURRENT_PROBES = state.DISCOVERY_MAX_CONCURRENT_PROBES
DISCOVERY_PROBE_PORTS = state.DISCOVERY_PROBE_PORTS
JOB_RETENTION_MIN_DAYS = state.JOB_RETENTION_MIN_DAYS
JOB_RETENTION_CLEANUP_INTERVAL_SECONDS = state.JOB_RETENTION_CLEANUP_INTERVAL_SECONDS
APP_HTTPS_ENABLED = state.APP_HTTPS_ENABLED
APP_HSTS_ENABLED = state.APP_HSTS_ENABLED
APP_HSTS_MAX_AGE = state.APP_HSTS_MAX_AGE
APP_HTTPS_REDIRECT = state.APP_HTTPS_REDIRECT
APP_CORS_ALLOW_ORIGINS = state.APP_CORS_ALLOW_ORIGINS
SNMP_DISCOVERY_DEFAULTS = state.SNMP_DISCOVERY_DEFAULTS
SNMP_DISCOVERY_PROFILE_DEFAULTS = state.SNMP_DISCOVERY_PROFILE_DEFAULTS
DISCOVERY_SYNC_DEFAULTS = state.DISCOVERY_SYNC_DEFAULTS
CONFIG_DRIFT_CHECK_DEFAULTS = state.CONFIG_DRIFT_CHECK_DEFAULTS
CONFIG_BACKUP_DEFAULTS = state.CONFIG_BACKUP_DEFAULTS
CONFIG_BACKUP_POLICY_MIN_INTERVAL = state.CONFIG_BACKUP_POLICY_MIN_INTERVAL
CONFIG_BACKUP_POLICY_MAX_INTERVAL = state.CONFIG_BACKUP_POLICY_MAX_INTERVAL
CONFIG_BACKUP_POLICY_MIN_RETENTION = state.CONFIG_BACKUP_POLICY_MIN_RETENTION
CONFIG_BACKUP_POLICY_MAX_RETENTION = state.CONFIG_BACKUP_POLICY_MAX_RETENTION
COMPLIANCE_CHECK_DEFAULTS = state.COMPLIANCE_CHECK_DEFAULTS
COMPLIANCE_ASSIGNMENT_MIN_INTERVAL = state.COMPLIANCE_ASSIGNMENT_MIN_INTERVAL
COMPLIANCE_ASSIGNMENT_MAX_INTERVAL = state.COMPLIANCE_ASSIGNMENT_MAX_INTERVAL
MONITORING_DEFAULTS = state.MONITORING_DEFAULTS
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
_sanitize_config_backup_config = state._sanitize_config_backup_config
_sanitize_compliance_check_config = state._sanitize_compliance_check_config
_sanitize_monitoring_config = state._sanitize_monitoring_config
_sanitize_cloud_flow_sync_config = state._sanitize_cloud_flow_sync_config
_sanitize_cloud_traffic_metric_sync_config = state._sanitize_cloud_traffic_metric_sync_config
_sanitize_snmp_discovery_config = state._sanitize_snmp_discovery_config
_sanitize_snmp_discovery_profile = state._sanitize_snmp_discovery_profile
_sanitize_snmp_discovery_profiles = state._sanitize_snmp_discovery_profiles
_sanitize_snmp_profile = state._sanitize_snmp_profile
_sanitize_snmp_profiles = state._sanitize_snmp_profiles
_sanitize_group_snmp_assignments = state._sanitize_group_snmp_assignments
_resolve_snmp_discovery_config = state._resolve_snmp_discovery_config


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
    state.AUTH_CONFIG = _sanitize_auth_config(auth_config)
    state.DISCOVERY_SYNC_CONFIG = _sanitize_discovery_sync_config(discovery_sync)
    state.SNMP_DISCOVERY_CONFIG = _sanitize_snmp_discovery_config(snmp_discovery)
    state.SNMP_DISCOVERY_PROFILES = _sanitize_snmp_discovery_profiles(snmp_discovery_profiles)
    state.SNMP_PROFILES = _sanitize_snmp_profiles(snmp_profiles)
    state.GROUP_SNMP_ASSIGNMENTS = _sanitize_group_snmp_assignments(group_snmp_assignments)
    state.TOPOLOGY_DISCOVERY_CONFIG = _sanitize_topology_discovery_config(topology_discovery)
    state.STP_DISCOVERY_CONFIG = _sanitize_stp_discovery_config(topology_stp_discovery)
    config_drift_check = await db.get_auth_setting("config_drift_check")
    state.CONFIG_DRIFT_CHECK_CONFIG = _sanitize_config_drift_check_config(config_drift_check)
    config_backup = await db.get_auth_setting("config_backup")
    state.CONFIG_BACKUP_CONFIG = _sanitize_config_backup_config(config_backup)
    compliance_check = await db.get_auth_setting("compliance_check")
    state.COMPLIANCE_CHECK_CONFIG = _sanitize_compliance_check_config(compliance_check)
    monitoring = await db.get_auth_setting("monitoring")
    state.MONITORING_CONFIG = _sanitize_monitoring_config(monitoring)
    cloud_flow_sync = await db.get_auth_setting("cloud_flow_sync")
    state.CLOUD_FLOW_SYNC_CONFIG = _sanitize_cloud_flow_sync_config(cloud_flow_sync)
    cloud_flow_sync_status = await db.get_auth_setting("cloud_flow_sync_status")
    state.CLOUD_FLOW_SYNC_STATUS = state._sanitize_cloud_sync_status(cloud_flow_sync_status)
    cloud_traffic_metric_sync = await db.get_auth_setting("cloud_traffic_metric_sync")
    state.CLOUD_TRAFFIC_METRIC_SYNC_CONFIG = _sanitize_cloud_traffic_metric_sync_config(cloud_traffic_metric_sync)
    cloud_traffic_metric_sync_status = await db.get_auth_setting("cloud_traffic_metric_sync_status")
    state.CLOUD_TRAFFIC_METRIC_SYNC_STATUS = state._sanitize_cloud_sync_status(cloud_traffic_metric_sync_status)


def require_feature(feature_key: str):
    async def _dependency(request: Request):
        session = await require_auth(request)
        # API tokens (APP_API_TOKEN env var) are server-level secrets with
        # full admin access by design — they bypass per-user feature checks.
        if session and session.get("auth_mode") == "token":
            return session
        user = await db.get_user_by_id(session["user_id"])
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        features = await _get_user_features(user)
        if user.get("role") != "admin" and feature_key not in features:
            raise HTTPException(status_code=403, detail=f"Access denied for feature '{feature_key}'")
        return session
    return _dependency

async def require_admin(request: Request):
    """Dependency that checks for admin access. Returns session dict.

    API tokens (APP_API_TOKEN) are server-level secrets equivalent to admin;
    they bypass the per-user role check intentionally.
    """
    session = await require_auth(request)
    if session and session.get("auth_mode") == "token":
        return session
    user = await db.get_user_by_username(session["user"])
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return session


async def _cloud_flow_sync_loop() -> None:
    """Periodically pull cloud flow logs for all enabled accounts."""
    while True:
        cfg = state.CLOUD_FLOW_SYNC_CONFIG
        interval = max(60, int(cfg.get("interval_seconds", 300)))
        await asyncio.sleep(interval)
        if not cfg.get("enabled"):
            continue
        try:
            result = await pull_flow_logs_all_accounts()
            await persist_cloud_flow_sync_status(
                build_cloud_sync_status(result, source="scheduled", scope="all")
            )
            total = result.get("total_ingested", 0)
            processed = result.get("accounts_processed", 0)
            if total > 0:
                LOGGER.info(
                    "Cloud flow sync: ingested %s records from %s account(s)",
                    total,
                    processed,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await persist_cloud_flow_sync_status(
                build_cloud_sync_status({"ok": False, "errors": [type(exc).__name__]}, source="scheduled", scope="all")
            )
            LOGGER.warning("Cloud flow sync loop failed: %s", type(exc).__name__)


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
            await persist_cloud_traffic_sync_status(
                build_cloud_sync_status(result, source="scheduled", scope="all")
            )
            total = result.get("total_ingested", 0)
            processed = result.get("accounts_processed", 0)
            if total > 0:
                LOGGER.info(
                    "Cloud traffic sync: ingested %s metric samples from %s account(s)",
                    total,
                    processed,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await persist_cloud_traffic_sync_status(
                build_cloud_sync_status({"ok": False, "errors": [type(exc).__name__]}, source="scheduled", scope="all")
            )
            LOGGER.warning("Cloud traffic sync loop failed: %s", type(exc).__name__)


# ═════════════════════════════════════════════════════════════════════════════
# App Lifecycle
# ═════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB and seed on startup."""
    _validate_startup_config()
    LOGGER.info("Starting Plexus API")
    await db.init_db()
    await _ensure_default_admin()
    # Migrate users from auth.json if it exists
    await _migrate_auth_json_users()
    await _load_persisted_security_settings()
    # Auto-seed if empty
    check = await db.get_all_groups()
    if not check:
        from routes.seed import seed
        await seed()
    await db.seed_built_in_graph_templates()
    await db.seed_built_in_cdefs()
    await _cleanup_expired_jobs()
    await _run_discovery_sync_once()
    state.API_RATE_LIMIT_LOCK = asyncio.Lock()
    retention_task = asyncio.create_task(_job_retention_cleanup_loop())
    discovery_sync_task = asyncio.create_task(_discovery_sync_loop())
    topology_discovery_task = asyncio.create_task(_topology_discovery_loop())
    stp_discovery_task = asyncio.create_task(_stp_discovery_loop())
    config_drift_task = asyncio.create_task(_config_drift_check_loop())
    config_backup_task = asyncio.create_task(_config_backup_loop())
    compliance_check_task = asyncio.create_task(_compliance_check_loop())
    monitoring_task = asyncio.create_task(_monitoring_poll_loop())
    escalation_task = asyncio.create_task(_alert_escalation_loop())
    baseline_task = asyncio.create_task(_baseline_computation_loop())
    downsampling_task = asyncio.create_task(_downsampling_loop())
    rate_limit_cleanup_task = asyncio.create_task(_rate_limit_cleanup_loop())
    report_scheduler_task = asyncio.create_task(_report_scheduler_loop())
    cloud_flow_sync_task = asyncio.create_task(_cloud_flow_sync_loop())
    cloud_traffic_sync_task = asyncio.create_task(_cloud_traffic_metric_sync_loop())
    federation_task = asyncio.create_task(federation_sync_loop())
    try:
        yield
    finally:
        retention_task.cancel()
        discovery_sync_task.cancel()
        topology_discovery_task.cancel()
        stp_discovery_task.cancel()
        config_drift_task.cancel()
        config_backup_task.cancel()
        compliance_check_task.cancel()
        monitoring_task.cancel()
        escalation_task.cancel()
        baseline_task.cancel()
        downsampling_task.cancel()
        rate_limit_cleanup_task.cancel()
        report_scheduler_task.cancel()
        cloud_flow_sync_task.cancel()
        cloud_traffic_sync_task.cancel()
        federation_task.cancel()
        try:
            await retention_task
        except asyncio.CancelledError:
            pass
        try:
            await discovery_sync_task
        except asyncio.CancelledError:
            pass
        try:
            await topology_discovery_task
        except asyncio.CancelledError:
            pass
        try:
            await stp_discovery_task
        except asyncio.CancelledError:
            pass
        try:
            await config_drift_task
        except asyncio.CancelledError:
            pass
        try:
            await config_backup_task
        except asyncio.CancelledError:
            pass
        try:
            await compliance_check_task
        except asyncio.CancelledError:
            pass
        try:
            await monitoring_task
        except asyncio.CancelledError:
            pass
        try:
            await escalation_task
        except asyncio.CancelledError:
            pass
        try:
            await baseline_task
        except asyncio.CancelledError:
            pass
        try:
            await downsampling_task
        except asyncio.CancelledError:
            pass
        try:
            await rate_limit_cleanup_task
        except asyncio.CancelledError:
            pass
        try:
            await report_scheduler_task
        except asyncio.CancelledError:
            pass
        try:
            await cloud_flow_sync_task
        except asyncio.CancelledError:
            pass
        try:
            await cloud_traffic_sync_task
        except asyncio.CancelledError:
            pass
        try:
            await federation_task
        except asyncio.CancelledError:
            pass


async def _rate_limit_cleanup_loop() -> None:
    """Periodically prune stale entries from the API rate-limit tracker."""
    while True:
        await asyncio.sleep(300)  # every 5 minutes
        window = max(1, int(state.API_RATE_LIMIT.get("window", 60)))
        now = time.time()
        lock = state.API_RATE_LIMIT_LOCK
        if lock:
            async with lock:
                tracker = state.API_RATE_LIMIT_TRACKER
                stale_keys = [ip for ip, ts in tracker.items() if not ts or (now - ts[-1]) > window]
                for key in stale_keys:
                    tracker.pop(key, None)


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
    app_https_enabled=APP_HTTPS_ENABLED,
)
init_admin(
    require_admin_fn=require_admin,
    hash_password_fn=_hash_password,
    get_user_features_fn=_get_user_features,
    cleanup_expired_jobs_fn=_cleanup_expired_jobs,
)

# Auth routes — no global auth dependency (login/register are public)
app.include_router(auth_router)
# Admin routes — global require_admin dependency
app.include_router(
    admin_router,
    dependencies=[Depends(require_admin)],
)
app.include_router(
    templates_router,
    dependencies=[Depends(require_auth), Depends(require_feature("templates"))],
)
app.include_router(
    credentials_router,
    dependencies=[Depends(require_auth), Depends(require_feature("credentials"))],
)
# Secret Variables — encrypted key-value store for template substitution
# List/names endpoints need auth only (template editor autocomplete);
# create/update/delete enforce admin inside the route handlers.
init_secret_variables(require_auth, require_admin)
app.include_router(
    secret_variables_router,
    dependencies=[Depends(require_auth)],
)
app.include_router(
    playbooks_router,
    dependencies=[Depends(require_auth), Depends(require_feature("playbooks"))],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=APP_CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token", "X-API-Token", "Authorization"],
)


@app.middleware("http")
async def csrf_protection_middleware(request: Request, call_next):
    """Validate CSRF token on state-changing requests authenticated via session cookie.

    Requests authenticated via API token (X-API-Token / Bearer) are exempt
    because they are not susceptible to cross-site request forgery.
    """
    if request.method in _CSRF_PROTECTED_METHODS and request.url.path.startswith("/api/"):
        # Skip CSRF check for public paths (login, register, etc.)
        if request.url.path not in PUBLIC_PATHS:
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
    thresholds.  Public paths (login, register, health) are exempt — the
    login endpoint already has its own brute-force protection.
    """
    cfg = state.API_RATE_LIMIT
    if (
        cfg.get("enabled")
        and request.url.path.startswith("/api/")
        and request.url.path not in PUBLIC_PATHS
    ):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window = max(1, int(cfg.get("window", 60)))
        is_write = request.method in _CSRF_PROTECTED_METHODS
        limit = int(cfg.get("max_write", 40) if is_write else cfg.get("max_read", 120))

        lock = state.API_RATE_LIMIT_LOCK
        if lock:
            async with lock:
                tracker = state.API_RATE_LIMIT_TRACKER
                timestamps = tracker.get(client_ip, [])
                # Prune entries outside the sliding window
                timestamps = [t for t in timestamps if now - t < window]
                if len(timestamps) >= limit:
                    retry_after = int(window - (now - timestamps[0])) + 1
                    return _api_error_response(
                        429,
                        "rate_limit_exceeded",
                        f"Too many requests. Try again in {retry_after}s.",
                    )
                timestamps.append(now)
                tracker[client_ip] = timestamps

    return await call_next(request)


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
        LOGGER.warning("request error path=%s correlation_id=%s duration_ms=%.1f", request.url.path, corr_id, duration_ms)
        raise

    duration_ms = (time.perf_counter() - start) * 1000
    increment_metric("api.requests.total")
    if response.status_code >= 400:
        increment_metric("api.requests.failed")
    observe_timing("api.request.duration_ms", duration_ms)
    return response


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
    # 'unsafe-inline' is needed for both styles (dynamic style= attrs) and
    # scripts (onclick= attrs in index.html).  Migrating onclick handlers to
    # addEventListener would allow dropping 'unsafe-inline' from script-src.
    # The CDN entry is for graph export embed pages (ECharts).
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "font-src 'self'; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
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
    scheme = (
        request.headers.get("x-forwarded-proto", request.url.scheme)
        .strip()
        .lower()
    )

    if scheme != "https":
        target = request.url.replace(scheme="https")
        return RedirectResponse(str(target), status_code=301)

    return await call_next(request)


def _api_error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "ok": False,
            "error": {
                "code": code,
                "message": message,
            },
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if not request.url.path.startswith("/api/"):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
    safe_detail = str(redact_value(detail))
    LOGGER.warning("HTTP %s on %s: %s", exc.status_code, request.url.path, safe_detail)
    return _api_error_response(exc.status_code, "http_error", safe_detail)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    if not request.url.path.startswith("/api/"):
        return JSONResponse(status_code=422, content={"detail": exc.errors()})

    LOGGER.warning("Validation error on %s: %s", request.url.path, redact_value(exc.errors()))
    return _api_error_response(422, "validation_error", "Request payload validation failed")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    if request.url.path.startswith("/api/"):
        LOGGER.error("Unhandled error on %s: %s", request.url.path, redact_value(str(exc)))
        LOGGER.debug("Traceback: %s", traceback.format_exc())
        return _api_error_response(500, "internal_error", "Internal server error")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/api/health")
async def health():
    return {
        "ok": True,
        "status": "healthy",
        "uptime_seconds": int(time.time() - APP_START_TIME),
        "metrics": snapshot_metrics(),
    }


@app.get("/api/dashboard", dependencies=[Depends(require_auth), Depends(require_feature("dashboard"))])
async def dashboard():
    stats = await db.get_dashboard_stats()
    recent_jobs = await db.get_all_jobs(limit=5)
    groups = await db.get_all_groups()
    monitoring = await db.get_monitoring_summary()
    latest_polls = await db.get_latest_monitoring_polls()
    alerts = await db.get_monitoring_alerts(acknowledged=False, limit=50)
    return {
        "stats": stats,
        "recent_jobs": recent_jobs,
        "groups": groups,
        "monitoring": monitoring,
        "device_health": latest_polls,
        "open_alerts": alerts,
    }


# ═════════════════════════════════════════════════════════════════════════════
# Register extracted route modules
# ═════════════════════════════════════════════════════════════════════════════

# Initialize late-binding dependencies for modules that need them
init_jobs(require_auth, require_feature, verify_session_token, _get_user_features, require_admin_fn=require_admin)
init_config_drift(require_auth, require_feature, require_admin, verify_session_token, _get_user_features)
init_config_backups(require_auth, require_feature, require_admin, verify_session_token, _get_user_features)
init_compliance(require_auth, require_feature, require_admin)
init_risk_analysis(require_auth, require_feature)
init_deployments(require_auth, require_feature, verify_session_token, _get_user_features)
init_monitoring(require_auth, require_feature, require_admin)
init_interface_errors(require_auth, require_admin)
init_billing(require_auth, require_admin)
init_cloud_visibility(require_admin)
init_federation(require_admin)
init_upgrades(require_auth, require_feature, verify_session_token, _get_user_features)
init_ansible_inventory(require_auth)
metrics_engine_inject_auth(require_auth, require_admin)

# Jobs
app.include_router(
    jobs_router,
    dependencies=[Depends(require_auth), Depends(require_feature("jobs"))],
)
app.include_router(jobs_ws_router)  # WebSocket — handles its own auth
# Inventory + admin
app.include_router(
    inventory_router,
    dependencies=[Depends(require_auth), Depends(require_feature("inventory"))],
)
app.include_router(
    inventory_admin_router,
    dependencies=[Depends(require_admin)],
)
# Ansible dynamic inventory provider
app.include_router(
    ansible_inventory_router,
    dependencies=[Depends(require_auth), Depends(require_feature("inventory"))],
)
# Topology + admin
app.include_router(
    topology_router,
    dependencies=[Depends(require_auth), Depends(require_feature("topology"))],
)
app.include_router(
    topology_admin_router,
    dependencies=[Depends(require_admin)],
)
# Config Drift + admin
app.include_router(
    config_drift_router,
    dependencies=[Depends(require_auth), Depends(require_feature("config-drift"))],
)
app.include_router(config_drift_ws_router)  # WebSocket — handles its own auth
# Config Backups + admin
app.include_router(
    config_backups_router,
    dependencies=[Depends(require_auth), Depends(require_feature("config-backups"))],
)
# Compliance + admin
app.include_router(
    compliance_router,
    dependencies=[Depends(require_auth), Depends(require_feature("compliance"))],
)
app.include_router(
    compliance_admin_router,
    dependencies=[Depends(require_admin)],
)
# Risk Analysis
app.include_router(
    risk_analysis_router,
    dependencies=[Depends(require_auth), Depends(require_feature("risk-analysis"))],
)
# Deployments
app.include_router(
    deployments_router,
    dependencies=[Depends(require_auth), Depends(require_feature("deployments"))],
)
app.include_router(deployments_ws_router)  # WebSocket — handles its own auth
# Monitoring + SLA + admin
app.include_router(
    monitoring_router,
    dependencies=[Depends(require_auth), Depends(require_feature("monitoring"))],
)
app.include_router(
    monitoring_admin_router,
    dependencies=[Depends(require_admin)],
)
# Metrics Engine (Prometheus-style)
app.include_router(
    metrics_engine_router,
    dependencies=[Depends(require_auth), Depends(require_feature("monitoring"))],
)
app.include_router(
    metrics_engine_admin_router,
    dependencies=[Depends(require_admin)],
)
# Dashboards & Annotations
app.include_router(
    dashboards_router,
    dependencies=[Depends(require_auth)],
)
# Graph Templates (Cacti-parity)
app.include_router(
    graph_templates_router,
    dependencies=[Depends(require_auth)],
)

app.include_router(
    reporting_router,
    dependencies=[Depends(require_auth)],
)
# CDEF Engine (calculated data sources)
app.include_router(
    cdef_router,
    dependencies=[Depends(require_auth)],
)
# MAC/ARP Tracking
app.include_router(
    mac_tracking_router,
    dependencies=[Depends(require_auth)],
)
# NetFlow / sFlow / IPFIX
app.include_router(
    flow_collector_router,
    dependencies=[Depends(require_auth)],
)
# Baseline Deviation Alerting
app.include_router(
    baseline_alerting_router,
    dependencies=[Depends(require_auth)],
)
# Graph Export (PNG/SVG/embed URLs)
app.include_router(
    graph_export_router,
    dependencies=[Depends(require_auth)],
)
# Interface Error/Discard Trending
app.include_router(
    interface_errors_router,
    dependencies=[Depends(require_auth)],
)
# Bandwidth Billing & 95th Percentile
app.include_router(
    billing_router,
    dependencies=[Depends(require_auth)],
)
# Cloud Visibility (AWS/Azure/GCP hybrid foundation)
app.include_router(
    cloud_visibility_router,
    dependencies=[Depends(require_auth), Depends(require_feature("topology"))],
)
# Multi-Instance Federation
app.include_router(
    federation_router,
    dependencies=[Depends(require_auth)],
)
# IOS-XE Upgrade Tool
app.include_router(
    upgrades_router,
    dependencies=[Depends(require_auth), Depends(require_feature("upgrades"))],
)
app.include_router(upgrades_ws_router)  # WebSocket — handles its own auth


# ═════════════════════════════════════════════════════════════════════════════
# Static Frontend (served at root)
# ═════════════════════════════════════════════════════════════════════════════

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
INDEX_FILE = os.path.join(STATIC_DIR, "index.html")

# Mount static files directory
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def serve_frontend():
    """Serve the frontend index.html or redirect to API docs."""
    if os.path.isfile(INDEX_FILE):
        return FileResponse(INDEX_FILE)
    # If no frontend, redirect to API docs
    return RedirectResponse(url="/docs")

@app.get("/favicon.ico")
async def favicon():
    """Handle favicon requests gracefully."""
    return {"detail": "No favicon"}
