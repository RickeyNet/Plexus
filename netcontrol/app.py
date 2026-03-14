"""
app.py — Plexus FastAPI Application

REST API for inventory, playbooks, templates, credentials, and jobs.
WebSocket endpoint for real-time job output streaming.
Session-based authentication with signed cookies.
"""

import asyncio
import difflib
import hashlib
import ipaddress
import json
import os
import secrets
import uuid
import socket
import sys
import traceback
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

# Ensure project root is on path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Register converter API
import time

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel, ConfigDict, Field

from netcontrol.routes.converter import prune_converter_sessions, router as converter_router

try:
    from pyrad import packet as radius_packet
    from pyrad.client import Client as RadiusClient
    from pyrad.dictionary import Dictionary as RadiusDictionary
    PYRAD_AVAILABLE = True
except Exception:
    RadiusClient = None
    RadiusDictionary = None
    radius_packet = None
    PYRAD_AVAILABLE = False

try:
    from pysnmp.hlapi.v3arch import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        get_cmd,
        walk_cmd,
        usmAesCfb128Protocol,
        usmAesCfb192Protocol,
        usmAesCfb256Protocol,
        usmDESPrivProtocol,
        usmHMAC192SHA256AuthProtocol,
        usmHMAC384SHA512AuthProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
    )
    PYSMNP_AVAILABLE = True
except Exception:
    CommunityData = None
    ContextData = None
    ObjectIdentity = None
    ObjectType = None
    SnmpEngine = None
    UdpTransportTarget = None
    UsmUserData = None
    get_cmd = None
    walk_cmd = None
    usmAesCfb128Protocol = None
    usmAesCfb192Protocol = None
    usmAesCfb256Protocol = None
    usmDESPrivProtocol = None
    usmHMACMD5AuthProtocol = None
    usmHMACSHAAuthProtocol = None
    usmHMAC192SHA256AuthProtocol = None
    usmHMAC384SHA512AuthProtocol = None
    PYSMNP_AVAILABLE = False

# Ensure project root is on path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import importlib

import routes.database as db
from routes.crypto import decrypt, encrypt
from routes.runner import LogEvent, execute_playbook, get_playbook_class

# Auto-register all playbooks
from templates import playbooks  # noqa: F401

from netcontrol.telemetry import configure_logging, increment_metric, observe_timing, redact_value, snapshot_metrics
from netcontrol.version import APP_VERSION

LOGGER = configure_logging("plexus.app")
APP_START_TIME = time.time()
APP_API_TOKEN = os.getenv("APP_API_TOKEN", "").strip()

# Bounded concurrency for convert/import jobs
_MAX_CONCURRENT_JOBS = int(os.getenv("APP_MAX_CONCURRENT_JOBS", "4"))
_job_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_JOBS)

# Config capture job state (in-memory, like converter jobs)
# capture_job_id -> {job_id, status, started_at, finished_at, output_lines}
_capture_jobs: dict[str, dict] = {}
_capture_job_sockets: dict[str, list] = {}


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_cors_origins() -> list[str]:
    """Return sanitized CORS origin allowlist from APP_CORS_ORIGINS.

    Comma-separated values are accepted. Empty entries are ignored.
    Defaults to localhost dev origins when unset.
    """
    raw = os.getenv("APP_CORS_ORIGINS", "")
    if not raw.strip():
        return ["http://localhost:8080", "http://127.0.0.1:8080"]
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


APP_HTTPS_ENABLED = _env_flag("APP_HTTPS", False)
APP_HSTS_ENABLED = _env_flag("APP_HSTS", APP_HTTPS_ENABLED)
APP_HSTS_MAX_AGE = int(os.getenv("APP_HSTS_MAX_AGE", "31536000"))
APP_CORS_ALLOW_ORIGINS = _parse_cors_origins()
DISCOVERY_DEFAULT_TIMEOUT_SECONDS = float(os.getenv("APP_DISCOVERY_TIMEOUT_SECONDS", "0.35"))
DISCOVERY_DEFAULT_MAX_HOSTS = int(os.getenv("APP_DISCOVERY_MAX_HOSTS", "256"))
DISCOVERY_MAX_CONCURRENT_PROBES = int(os.getenv("APP_DISCOVERY_MAX_CONCURRENT_PROBES", "64"))
DISCOVERY_PROBE_PORTS = (22, 443)
SNMP_DISCOVERY_DEFAULTS = {
    "enabled": False,
    "version": "2c",
    "community": "public",
    "port": 161,
    "timeout_seconds": 1.2,
    "retries": 0,
    "v3": {
        "username": "",
        "auth_protocol": "sha",
        "auth_password": "",
        "priv_protocol": "aes128",
        "priv_password": "",
    },
}
SNMP_DISCOVERY_PROFILE_DEFAULTS = {
    "enabled": False,
    "version": "2c",
    "community": "",
    "port": 161,
    "timeout_seconds": 1.2,
    "retries": 0,
    "v3": {
        "username": "",
        "auth_protocol": "sha",
        "auth_password": "",
        "priv_protocol": "aes128",
        "priv_password": "",
    },
}
DISCOVERY_SYNC_DEFAULTS = {
    "enabled": False,
    "interval_seconds": 900,
    "profiles": [],
}
DISCOVERY_SYNC_MIN_INTERVAL_SECONDS = 60
DISCOVERY_SYNC_MAX_INTERVAL_SECONDS = 86400

TOPOLOGY_DISCOVERY_DEFAULTS = {
    "enabled": False,
    "interval_seconds": 3600,
}
TOPOLOGY_DISCOVERY_MIN_INTERVAL = 300
TOPOLOGY_DISCOVERY_MAX_INTERVAL = 86400

CONFIG_DRIFT_CHECK_DEFAULTS = {
    "enabled": False,
    "interval_seconds": 3600,
    "snapshot_retention_days": 90,
}
CONFIG_DRIFT_CHECK_MIN_INTERVAL = 300
CONFIG_DRIFT_CHECK_MAX_INTERVAL = 86400

CONFIG_BACKUP_DEFAULTS = {
    "enabled": False,
    "interval_seconds": 300,
}
CONFIG_BACKUP_MIN_INTERVAL = 60
CONFIG_BACKUP_MAX_INTERVAL = 86400
CONFIG_BACKUP_POLICY_MIN_INTERVAL = 3600
CONFIG_BACKUP_POLICY_MAX_INTERVAL = 604800
CONFIG_BACKUP_POLICY_MIN_RETENTION = 1
CONFIG_BACKUP_POLICY_MAX_RETENTION = 365
CONFIG_BACKUP_CONFIG = dict(CONFIG_BACKUP_DEFAULTS)


# ── CSRF token helpers ───────────────────────────────────────────────────────

_csrf_serializer: URLSafeTimedSerializer | None = None  # initialised after secret key load
CSRF_TOKEN_MAX_AGE = 86400  # 24 hours — aligned with session lifetime


def _generate_csrf_token(session_user: str) -> str:
    """Create a signed, time-limited CSRF token bound to the session user."""
    assert _csrf_serializer is not None
    return _csrf_serializer.dumps({"csrf_user": session_user})


def _validate_csrf_token(token: str, session_user: str) -> bool:
    """Return True when the token is valid, not expired, and bound to the user."""
    assert _csrf_serializer is not None
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


async def _audit(
    category: str,
    action: str,
    user: str = "",
    detail: str = "",
    correlation_id: str = "",
) -> None:
    """Fire-and-forget audit record.  Never raises to the caller."""
    try:
        await db.add_audit_event(category, action, user=user, detail=detail, correlation_id=correlation_id)
    except Exception:
        LOGGER.warning("Failed to write audit event category=%s action=%s", category, action)


def _corr_id(request: Request) -> str:
    """Extract the correlation ID attached by correlation_id_middleware."""
    return getattr(request.state, "correlation_id", "") if hasattr(request, "state") else ""


def _extract_api_token(request: Request) -> str:
    token = request.headers.get("x-api-token", "").strip()
    if token:
        return token
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return ""


import re as _re

# Allowed playbook filename pattern: alphanumeric, underscores, hyphens only (no path separators)
_PLAYBOOK_FILENAME_RE = _re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]*$")
_PLAYBOOK_ALLOWED_EXT = ".py"


def _sanitize_playbook_filename(filename: str) -> str:
    """Validate and normalise a playbook filename.

    Rules:
      - Strip any leading/trailing whitespace.
      - Strip a trailing ``.py`` extension (we re-add it).
      - The bare stem must match ``[A-Za-z0-9][A-Za-z0-9_-]*`` (no path
        separators, dots, or other special characters).
      - The returned value always ends with ``.py``.

    Raises ``ValueError`` on invalid input.
    """
    name = filename.strip()
    if name.endswith(_PLAYBOOK_ALLOWED_EXT):
        name = name[: -len(_PLAYBOOK_ALLOWED_EXT)]
    # Reject anything that looks like a path
    if "/" in name or "\\" in name or ".." in name:
        raise ValueError("Invalid playbook filename: path separators are not allowed")
    if not _PLAYBOOK_FILENAME_RE.match(name):
        raise ValueError(
            f"Invalid playbook filename '{filename}': "
            "only letters, digits, underscores and hyphens are allowed"
        )
    return name + _PLAYBOOK_ALLOWED_EXT


def write_playbook_file(filename: str, content: str) -> str:
    """
    Write playbook content to a file and reload the module.
    Returns the file path.
    """
    playbooks_dir = os.path.join(project_root, "templates", "playbooks")
    os.makedirs(playbooks_dir, exist_ok=True)

    # Validate and normalise filename
    safe_filename = _sanitize_playbook_filename(filename)

    file_path = os.path.normpath(os.path.join(playbooks_dir, safe_filename))

    # Belt-and-suspenders: ensure resolved path stays inside playbooks_dir
    if not file_path.startswith(os.path.normpath(playbooks_dir)):
        raise ValueError("Invalid playbook filename: resulting path escapes the playbooks directory")

    # Write the file
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    # Reload the playbook module to pick up changes
    module_name = f"templates.playbooks.{safe_filename[:-3]}"
    try:
        # Remove from cache if exists
        if module_name in sys.modules:
            del sys.modules[module_name]
        
        # Reload the playbooks package to re-import all modules
        if 'templates.playbooks' in sys.modules:
            importlib.reload(sys.modules['templates.playbooks'])
        else:
            importlib.import_module('templates.playbooks')
    except Exception as e:
        # If reload fails, log but don't fail - module will be loaded on next server restart
        LOGGER.warning("Failed to reload playbook module %s: %s", module_name, e)
    
    return file_path


# ═════════════════════════════════════════════════════════════════════════════
# Authentication (DB-backed users)
# ═════════════════════════════════════════════════════════════════════════════

SECRET_KEY_FILE = os.path.join(os.path.dirname(__file__), "..", "routes", "session.key")
SESSION_MAX_AGE = 86400  # 24 hours


def _load_or_create_secret_key() -> str:
    if os.path.isfile(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
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
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()


async def _ensure_default_admin():
    """Create the default admin user in the DB if no users exist."""
    existing = await db.get_all_users()
    if existing:
        return
    salt = secrets.token_hex(16)
    pw_hash = _hash_password("netcontrol", salt)
    await db.create_user(
        "admin", pw_hash, salt,
        display_name="Administrator", role="admin",
        must_change_password=True,
    )
    LOGGER.warning("Created default user: admin / netcontrol — CHANGE THIS PASSWORD!")


async def verify_user(username: str, password: str) -> dict | None:
    """Verify credentials and return the user dict, or None."""
    user = await db.get_user_by_username(username)
    if not user:
        return None
    if _hash_password(password, user["salt"]) == user["password_hash"]:
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


PUBLIC_PATHS = {"/", "/api/auth/login", "/api/auth/register", "/api/auth/status", "/api/health", "/favicon.ico", "/docs", "/openapi.json", "/redoc"}

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


# In-memory stores for rate limiting and lockout
LOGIN_ATTEMPTS = {}
LOCKED_OUT = {}
DEFAULT_LOGIN_RULES = {
    "max_attempts": 5,
    "lockout_time": 900,      # 15 minutes
    "rate_limit_window": 60,  # seconds
    "rate_limit_max": 10,
}

FEATURE_FLAGS = [
    "dashboard",
    "inventory",
    "playbooks",
    "jobs",
    "templates",
    "credentials",
    "converter",
    "topology",
    "config-drift",
    "config-backups",
]

AUTH_CONFIG_DEFAULTS = {
    "provider": "local",
    "job_retention_days": 30,
    "converter_session_retention_days": 30,
    "converter_backup_retention_days": 30,
    "radius": {
        "enabled": False,
        "server": "",
        "port": 1812,
        "secret": "",
        "timeout": 5,
        "fallback_to_local": True,
        "fallback_on_reject": False,
    },
}

RADIUS_DICTIONARY_FILE = os.path.join(os.path.dirname(__file__), "..", "routes", "radius.dictionary")

LOGIN_RULES = dict(DEFAULT_LOGIN_RULES)
AUTH_CONFIG = dict(AUTH_CONFIG_DEFAULTS)
DISCOVERY_SYNC_CONFIG = dict(DISCOVERY_SYNC_DEFAULTS)
SNMP_DISCOVERY_CONFIG = dict(SNMP_DISCOVERY_DEFAULTS)
SNMP_DISCOVERY_PROFILES: dict[int, dict] = {}
SNMP_PROFILES: dict[str, dict] = {}
GROUP_SNMP_ASSIGNMENTS: dict[int, str] = {}
TOPOLOGY_DISCOVERY_CONFIG = dict(TOPOLOGY_DISCOVERY_DEFAULTS)
CONFIG_DRIFT_CHECK_CONFIG = dict(CONFIG_DRIFT_CHECK_DEFAULTS)
JOB_RETENTION_MIN_DAYS = 30
JOB_RETENTION_CLEANUP_INTERVAL_SECONDS = 60 * 60 * 6
CONVERTER_SESSION_RETENTION_MIN_DAYS = 1
CONVERTER_BACKUP_RETENTION_MIN_DAYS = 1


def _sanitize_login_rules(data: dict | None) -> dict:
    merged = dict(DEFAULT_LOGIN_RULES)
    if isinstance(data, dict):
        merged.update(data)
    return {
        "max_attempts": max(1, int(merged.get("max_attempts", DEFAULT_LOGIN_RULES["max_attempts"]))),
        "lockout_time": max(1, int(merged.get("lockout_time", DEFAULT_LOGIN_RULES["lockout_time"]))),
        "rate_limit_window": max(1, int(merged.get("rate_limit_window", DEFAULT_LOGIN_RULES["rate_limit_window"]))),
        "rate_limit_max": max(1, int(merged.get("rate_limit_max", DEFAULT_LOGIN_RULES["rate_limit_max"]))),
    }


def _sanitize_auth_config(data: dict | None) -> dict:
    cfg = dict(AUTH_CONFIG_DEFAULTS)
    cfg["radius"] = dict(AUTH_CONFIG_DEFAULTS["radius"])
    if isinstance(data, dict):
        if data.get("provider") in {"local", "radius"}:
            cfg["provider"] = data["provider"]
        if "job_retention_days" in data:
            cfg["job_retention_days"] = int(data.get("job_retention_days", cfg["job_retention_days"]))
        if "converter_session_retention_days" in data:
            cfg["converter_session_retention_days"] = int(
                data.get("converter_session_retention_days", cfg["converter_session_retention_days"])
            )
        if "converter_backup_retention_days" in data:
            cfg["converter_backup_retention_days"] = int(
                data.get("converter_backup_retention_days", cfg["converter_backup_retention_days"])
            )
        radius = data.get("radius")
        if isinstance(radius, dict):
            cfg["radius"].update({
                "enabled": bool(radius.get("enabled", cfg["radius"]["enabled"])),
                "server": str(radius.get("server", cfg["radius"]["server"])).strip(),
                "port": int(radius.get("port", cfg["radius"]["port"])),
                "secret": str(radius.get("secret", cfg["radius"]["secret"])),
                "timeout": int(radius.get("timeout", cfg["radius"]["timeout"])),
                "fallback_to_local": bool(radius.get("fallback_to_local", cfg["radius"]["fallback_to_local"])),
                "fallback_on_reject": bool(radius.get("fallback_on_reject", cfg["radius"]["fallback_on_reject"])),
            })
    cfg["job_retention_days"] = max(JOB_RETENTION_MIN_DAYS, int(cfg.get("job_retention_days", JOB_RETENTION_MIN_DAYS)))
    cfg["converter_session_retention_days"] = max(
        CONVERTER_SESSION_RETENTION_MIN_DAYS,
        int(cfg.get("converter_session_retention_days", AUTH_CONFIG_DEFAULTS["converter_session_retention_days"])),
    )
    cfg["converter_backup_retention_days"] = max(
        CONVERTER_BACKUP_RETENTION_MIN_DAYS,
        int(cfg.get("converter_backup_retention_days", AUTH_CONFIG_DEFAULTS["converter_backup_retention_days"])),
    )
    cfg["radius"]["port"] = max(1, cfg["radius"]["port"])
    cfg["radius"]["timeout"] = max(1, cfg["radius"]["timeout"])
    return cfg


def _effective_job_retention_days() -> int:
    return max(JOB_RETENTION_MIN_DAYS, int(AUTH_CONFIG.get("job_retention_days", JOB_RETENTION_MIN_DAYS)))


def _effective_converter_session_retention_days() -> int:
    return max(
        CONVERTER_SESSION_RETENTION_MIN_DAYS,
        int(
            AUTH_CONFIG.get(
                "converter_session_retention_days",
                AUTH_CONFIG_DEFAULTS["converter_session_retention_days"],
            )
        ),
    )


def _effective_converter_backup_retention_days() -> int:
    return max(
        CONVERTER_BACKUP_RETENTION_MIN_DAYS,
        int(
            AUTH_CONFIG.get(
                "converter_backup_retention_days",
                AUTH_CONFIG_DEFAULTS["converter_backup_retention_days"],
            )
        ),
    )


def _sanitize_discovery_sync_config(data: dict | None) -> dict:
    cfg = {
        "enabled": bool(DISCOVERY_SYNC_DEFAULTS["enabled"]),
        "interval_seconds": int(DISCOVERY_SYNC_DEFAULTS["interval_seconds"]),
        "profiles": [],
    }
    if not isinstance(data, dict):
        return cfg

    cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
    cfg["interval_seconds"] = int(data.get("interval_seconds", cfg["interval_seconds"]))
    cfg["interval_seconds"] = max(
        DISCOVERY_SYNC_MIN_INTERVAL_SECONDS,
        min(DISCOVERY_SYNC_MAX_INTERVAL_SECONDS, cfg["interval_seconds"]),
    )

    profiles = data.get("profiles", [])
    if not isinstance(profiles, list):
        return cfg

    sanitized_profiles: list[dict] = []
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        group_id = profile.get("group_id")
        cidrs = profile.get("cidrs")
        if not isinstance(group_id, int) or group_id <= 0:
            continue
        if not isinstance(cidrs, list) or not cidrs:
            continue
        profile_obj = {
            "group_id": group_id,
            "cidrs": [str(c).strip() for c in cidrs if str(c).strip()],
            "remove_absent": bool(profile.get("remove_absent", False)),
            "use_snmp": bool(profile.get("use_snmp", True)),
            "device_type": str(profile.get("device_type", "unknown")).strip() or "unknown",
            "hostname_prefix": str(profile.get("hostname_prefix", "discovered")).strip() or "discovered",
            "timeout_seconds": float(profile.get("timeout_seconds", DISCOVERY_DEFAULT_TIMEOUT_SECONDS)),
            "max_hosts": int(profile.get("max_hosts", DISCOVERY_DEFAULT_MAX_HOSTS)),
        }
        if not profile_obj["cidrs"]:
            continue
        profile_obj["timeout_seconds"] = max(0.05, min(5.0, profile_obj["timeout_seconds"]))
        profile_obj["max_hosts"] = max(1, min(4096, profile_obj["max_hosts"]))
        sanitized_profiles.append(profile_obj)

    cfg["profiles"] = sanitized_profiles
    return cfg


def _sanitize_topology_discovery_config(data: dict | None) -> dict:
    cfg = {
        "enabled": bool(TOPOLOGY_DISCOVERY_DEFAULTS["enabled"]),
        "interval_seconds": int(TOPOLOGY_DISCOVERY_DEFAULTS["interval_seconds"]),
    }
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        cfg["interval_seconds"] = int(data.get("interval_seconds", cfg["interval_seconds"]))
        cfg["interval_seconds"] = max(
            TOPOLOGY_DISCOVERY_MIN_INTERVAL,
            min(TOPOLOGY_DISCOVERY_MAX_INTERVAL, cfg["interval_seconds"]),
        )
    return cfg


def _sanitize_config_drift_check_config(data: dict | None) -> dict:
    cfg = {
        "enabled": bool(CONFIG_DRIFT_CHECK_DEFAULTS["enabled"]),
        "interval_seconds": int(CONFIG_DRIFT_CHECK_DEFAULTS["interval_seconds"]),
        "snapshot_retention_days": int(CONFIG_DRIFT_CHECK_DEFAULTS["snapshot_retention_days"]),
    }
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        cfg["interval_seconds"] = int(data.get("interval_seconds", cfg["interval_seconds"]))
        cfg["interval_seconds"] = max(
            CONFIG_DRIFT_CHECK_MIN_INTERVAL,
            min(CONFIG_DRIFT_CHECK_MAX_INTERVAL, cfg["interval_seconds"]),
        )
        cfg["snapshot_retention_days"] = max(
            1, min(365, int(data.get("snapshot_retention_days", cfg["snapshot_retention_days"])))
        )
    return cfg


def _sanitize_config_backup_config(data: dict | None) -> dict:
    cfg = {
        "enabled": bool(CONFIG_BACKUP_DEFAULTS["enabled"]),
        "interval_seconds": int(CONFIG_BACKUP_DEFAULTS["interval_seconds"]),
    }
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        cfg["interval_seconds"] = int(data.get("interval_seconds", cfg["interval_seconds"]))
        cfg["interval_seconds"] = max(
            CONFIG_BACKUP_MIN_INTERVAL,
            min(CONFIG_BACKUP_MAX_INTERVAL, cfg["interval_seconds"]),
        )
    return cfg


def _sanitize_snmp_discovery_config(data: dict | None) -> dict:
    cfg = {
        "enabled": bool(SNMP_DISCOVERY_DEFAULTS["enabled"]),
        "version": str(SNMP_DISCOVERY_DEFAULTS["version"]),
        "community": str(SNMP_DISCOVERY_DEFAULTS["community"]),
        "port": int(SNMP_DISCOVERY_DEFAULTS["port"]),
        "timeout_seconds": float(SNMP_DISCOVERY_DEFAULTS["timeout_seconds"]),
        "retries": int(SNMP_DISCOVERY_DEFAULTS["retries"]),
        "v3": dict(SNMP_DISCOVERY_DEFAULTS["v3"]),
    }
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        version = str(data.get("version", cfg["version"]).strip().lower())
        if version in {"2c", "3"}:
            cfg["version"] = version
        cfg["community"] = str(data.get("community", cfg["community"]))
        cfg["port"] = int(data.get("port", cfg["port"]))
        cfg["timeout_seconds"] = float(data.get("timeout_seconds", cfg["timeout_seconds"]))
        cfg["retries"] = int(data.get("retries", cfg["retries"]))
        if isinstance(data.get("v3"), dict):
            v3 = data["v3"]
            cfg["v3"]["username"] = str(v3.get("username", cfg["v3"]["username"]))
            cfg["v3"]["auth_protocol"] = str(v3.get("auth_protocol", cfg["v3"]["auth_protocol"])).lower()
            cfg["v3"]["auth_password"] = str(v3.get("auth_password", cfg["v3"]["auth_password"]))
            cfg["v3"]["priv_protocol"] = str(v3.get("priv_protocol", cfg["v3"]["priv_protocol"])).lower()
            cfg["v3"]["priv_password"] = str(v3.get("priv_password", cfg["v3"]["priv_password"]))

    cfg["port"] = max(1, min(65535, cfg["port"]))
    cfg["timeout_seconds"] = max(0.2, min(10.0, cfg["timeout_seconds"]))
    cfg["retries"] = max(0, min(5, cfg["retries"]))
    if cfg["v3"]["auth_protocol"] not in {"md5", "sha", "sha256", "sha512"}:
        cfg["v3"]["auth_protocol"] = "sha"
    if cfg["v3"]["priv_protocol"] not in {"des", "aes128", "aes192", "aes256"}:
        cfg["v3"]["priv_protocol"] = "aes128"
    return cfg


def _sanitize_snmp_discovery_profile(group_id: int, data: dict | None) -> dict:
    cfg = {
        "group_id": int(group_id),
        "enabled": bool(SNMP_DISCOVERY_PROFILE_DEFAULTS["enabled"]),
        "version": str(SNMP_DISCOVERY_PROFILE_DEFAULTS["version"]),
        "community": str(SNMP_DISCOVERY_PROFILE_DEFAULTS["community"]),
        "port": int(SNMP_DISCOVERY_PROFILE_DEFAULTS["port"]),
        "timeout_seconds": float(SNMP_DISCOVERY_PROFILE_DEFAULTS["timeout_seconds"]),
        "retries": int(SNMP_DISCOVERY_PROFILE_DEFAULTS["retries"]),
        "v3": dict(SNMP_DISCOVERY_PROFILE_DEFAULTS["v3"]),
    }
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        version = str(data.get("version", cfg["version"]).strip().lower())
        if version in {"2c", "3"}:
            cfg["version"] = version
        cfg["community"] = str(data.get("community", cfg["community"]))
        cfg["port"] = int(data.get("port", cfg["port"]))
        cfg["timeout_seconds"] = float(data.get("timeout_seconds", cfg["timeout_seconds"]))
        cfg["retries"] = int(data.get("retries", cfg["retries"]))
        if isinstance(data.get("v3"), dict):
            v3 = data["v3"]
            cfg["v3"]["username"] = str(v3.get("username", cfg["v3"]["username"]))
            cfg["v3"]["auth_protocol"] = str(v3.get("auth_protocol", cfg["v3"]["auth_protocol"])).lower()
            cfg["v3"]["auth_password"] = str(v3.get("auth_password", cfg["v3"]["auth_password"]))
            cfg["v3"]["priv_protocol"] = str(v3.get("priv_protocol", cfg["v3"]["priv_protocol"])).lower()
            cfg["v3"]["priv_password"] = str(v3.get("priv_password", cfg["v3"]["priv_password"]))

    cfg["port"] = max(1, min(65535, cfg["port"]))
    cfg["timeout_seconds"] = max(0.2, min(10.0, cfg["timeout_seconds"]))
    cfg["retries"] = max(0, min(5, cfg["retries"]))
    if cfg["v3"]["auth_protocol"] not in {"md5", "sha", "sha256", "sha512"}:
        cfg["v3"]["auth_protocol"] = "sha"
    if cfg["v3"]["priv_protocol"] not in {"des", "aes128", "aes192", "aes256"}:
        cfg["v3"]["priv_protocol"] = "aes128"
    return cfg


def _sanitize_snmp_discovery_profiles(data: dict | None) -> dict[int, dict]:
    if not isinstance(data, dict):
        return {}
    profiles: dict[int, dict] = {}
    for key, value in data.items():
        try:
            group_id = int(key)
        except Exception:
            continue
        if group_id <= 0:
            continue
        profiles[group_id] = _sanitize_snmp_discovery_profile(group_id, value)
    return profiles


def _sanitize_snmp_profile(profile_id: str, data: dict | None) -> dict:
    cfg = {
        "id": str(profile_id),
        "name": "",
        "enabled": False,
        "version": "2c",
        "community": "",
        "port": 161,
        "timeout_seconds": 1.2,
        "retries": 0,
        "v3": {
            "username": "",
            "auth_protocol": "sha",
            "auth_password": "",
            "priv_protocol": "aes128",
            "priv_password": "",
        },
    }
    if isinstance(data, dict):
        cfg["name"] = str(data.get("name", cfg["name"])).strip()
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        version = str(data.get("version", cfg["version"])).strip().lower()
        if version in {"2c", "3"}:
            cfg["version"] = version
        cfg["community"] = str(data.get("community", cfg["community"]))
        cfg["port"] = int(data.get("port", cfg["port"]))
        cfg["timeout_seconds"] = float(data.get("timeout_seconds", cfg["timeout_seconds"]))
        cfg["retries"] = int(data.get("retries", cfg["retries"]))
        if isinstance(data.get("v3"), dict):
            v3 = data["v3"]
            cfg["v3"]["username"] = str(v3.get("username", cfg["v3"]["username"]))
            cfg["v3"]["auth_protocol"] = str(v3.get("auth_protocol", cfg["v3"]["auth_protocol"])).lower()
            cfg["v3"]["auth_password"] = str(v3.get("auth_password", cfg["v3"]["auth_password"]))
            cfg["v3"]["priv_protocol"] = str(v3.get("priv_protocol", cfg["v3"]["priv_protocol"])).lower()
            cfg["v3"]["priv_password"] = str(v3.get("priv_password", cfg["v3"]["priv_password"]))
    cfg["port"] = max(1, min(65535, cfg["port"]))
    cfg["timeout_seconds"] = max(0.2, min(10.0, cfg["timeout_seconds"]))
    cfg["retries"] = max(0, min(5, cfg["retries"]))
    if cfg["v3"]["auth_protocol"] not in {"md5", "sha", "sha256", "sha512"}:
        cfg["v3"]["auth_protocol"] = "sha"
    if cfg["v3"]["priv_protocol"] not in {"des", "aes128", "aes192", "aes256"}:
        cfg["v3"]["priv_protocol"] = "aes128"
    return cfg


def _sanitize_snmp_profiles(data: dict | None) -> dict[str, dict]:
    if not isinstance(data, dict):
        return {}
    profiles: dict[str, dict] = {}
    for key, value in data.items():
        pid = str(key).strip()
        if not pid:
            continue
        profiles[pid] = _sanitize_snmp_profile(pid, value)
    return profiles


def _sanitize_group_snmp_assignments(data: dict | None) -> dict[int, str]:
    if not isinstance(data, dict):
        return {}
    assignments: dict[int, str] = {}
    for key, value in data.items():
        try:
            group_id = int(key)
        except Exception:
            continue
        if group_id <= 0:
            continue
        pid = str(value).strip()
        if pid:
            assignments[group_id] = pid
    return assignments


def _resolve_snmp_discovery_config(group_id: int | None = None) -> dict:
    effective = _sanitize_snmp_discovery_config(SNMP_DISCOVERY_CONFIG)
    if group_id is None:
        return effective
    # New: check named profile assignment first
    profile_id = GROUP_SNMP_ASSIGNMENTS.get(int(group_id))
    if profile_id and profile_id in SNMP_PROFILES:
        return _sanitize_snmp_discovery_config(SNMP_PROFILES[profile_id])
    # Legacy: fall back to old per-group profiles
    profile = SNMP_DISCOVERY_PROFILES.get(int(group_id))
    if not profile:
        return effective
    merged = dict(effective)
    merged["v3"] = dict(effective.get("v3", {}))
    merged.update({
        "enabled": bool(profile.get("enabled", merged.get("enabled", False))),
        "version": str(profile.get("version", merged.get("version", "2c"))),
        "community": str(profile.get("community", merged.get("community", ""))),
        "port": int(profile.get("port", merged.get("port", 161))),
        "timeout_seconds": float(profile.get("timeout_seconds", merged.get("timeout_seconds", 1.2))),
        "retries": int(profile.get("retries", merged.get("retries", 0))),
    })
    if isinstance(profile.get("v3"), dict):
        merged["v3"].update(profile["v3"])
    return _sanitize_snmp_discovery_config(merged)


async def _cleanup_expired_jobs() -> int:
    retention_days = _effective_job_retention_days()
    deleted = await db.delete_expired_jobs(retention_days)
    if deleted:
        LOGGER.info("Deleted %s expired job(s) older than %s day(s)", deleted, retention_days)
        increment_metric("jobs.retention.deleted")
    return deleted


async def _cleanup_expired_converter_sessions() -> dict:
    session_days = _effective_converter_session_retention_days()
    backup_days = _effective_converter_backup_retention_days()
    summary = await asyncio.to_thread(prune_converter_sessions, session_days, backup_days)

    sessions_deleted = int(summary.get("sessions_deleted", 0))
    snapshots_deleted = int(summary.get("snapshots_deleted", 0))
    if sessions_deleted:
        LOGGER.info(
            "Deleted %s converter session(s) older than %s day(s)",
            sessions_deleted,
            session_days,
        )
        increment_metric("converter.retention.sessions.deleted")
    if snapshots_deleted:
        LOGGER.info(
            "Deleted %s converter snapshot(s) older than %s day(s)",
            snapshots_deleted,
            backup_days,
        )
        increment_metric("converter.retention.snapshots.deleted")
    return summary


async def _job_retention_cleanup_loop() -> None:
    while True:
        try:
            await _cleanup_expired_jobs()
            await _cleanup_expired_converter_sessions()
            await asyncio.sleep(JOB_RETENTION_CLEANUP_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("Retention cleanup failed: %s", redact_value(str(exc)))
            increment_metric("jobs.retention.cleanup.failed")
            increment_metric("converter.retention.cleanup.failed")
            await asyncio.sleep(JOB_RETENTION_CLEANUP_INTERVAL_SECONDS)


async def _run_discovery_sync_once() -> dict:
    if not DISCOVERY_SYNC_CONFIG.get("enabled"):
        return {"enabled": False, "profiles": 0, "synced_groups": 0, "errors": 0}

    profiles = DISCOVERY_SYNC_CONFIG.get("profiles", [])
    synced_groups = 0
    errors = 0
    for profile in profiles:
        group_id = int(profile.get("group_id", 0))
        if group_id <= 0:
            continue
        group = await db.get_group(group_id)
        if not group:
            errors += 1
            LOGGER.warning("discovery sync: skipped missing group_id=%s", group_id)
            continue
        try:
            body = DiscoverySyncRequest.model_validate({
                "cidrs": profile.get("cidrs", []),
                "timeout_seconds": profile.get("timeout_seconds", DISCOVERY_DEFAULT_TIMEOUT_SECONDS),
                "max_hosts": profile.get("max_hosts", DISCOVERY_DEFAULT_MAX_HOSTS),
                "device_type": profile.get("device_type", "unknown"),
                "hostname_prefix": profile.get("hostname_prefix", "discovered"),
                "use_snmp": profile.get("use_snmp", True),
                "remove_absent": profile.get("remove_absent", False),
            })
            _, discovered = await _discover_hosts(body, group_id=group_id)
            result = await _sync_group_hosts(group_id, discovered, remove_absent=body.remove_absent)
            synced_groups += 1
            LOGGER.info(
                "discovery sync: group_id=%s discovered=%s added=%s updated=%s removed=%s",
                group_id,
                len(discovered),
                result["added"],
                result["updated"],
                result["removed"],
            )
            increment_metric("inventory.discovery.sync.success")
        except Exception as exc:
            errors += 1
            LOGGER.warning("discovery sync failed for group_id=%s: %s", group_id, redact_value(str(exc)))
            increment_metric("inventory.discovery.sync.failed")

    return {
        "enabled": True,
        "profiles": len(profiles),
        "synced_groups": synced_groups,
        "errors": errors,
    }


async def _discovery_sync_loop() -> None:
    while True:
        try:
            await _run_discovery_sync_once()
            await asyncio.sleep(int(DISCOVERY_SYNC_CONFIG.get("interval_seconds", DISCOVERY_SYNC_DEFAULTS["interval_seconds"])))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("discovery sync loop failure: %s", redact_value(str(exc)))
            increment_metric("inventory.discovery.sync.loop.failed")
            await asyncio.sleep(DISCOVERY_SYNC_DEFAULTS["interval_seconds"])


async def _run_topology_discovery_once() -> dict:
    """Run neighbor discovery across all SNMP-enabled groups."""
    if not TOPOLOGY_DISCOVERY_CONFIG.get("enabled"):
        return {"enabled": False, "groups_scanned": 0, "links_discovered": 0, "errors": 0}

    groups = await db.get_all_groups()
    total_links = 0
    total_errors = 0
    groups_scanned = 0

    for group in groups:
        snmp_cfg = _resolve_snmp_discovery_config(group["id"])
        if not snmp_cfg.get("enabled", False):
            continue
        hosts = await db.get_hosts_for_group(group["id"])
        if not hosts:
            continue

        groups_scanned += 1
        semaphore = asyncio.Semaphore(max(1, DISCOVERY_MAX_CONCURRENT_PROBES))

        async def _walk_host(host: dict, _cfg=snmp_cfg) -> tuple[dict, list[dict] | None, list[dict]]:
            async with semaphore:
                try:
                    neighbors, if_stats = await _discover_neighbors(
                        host["id"], host["ip_address"], _cfg, timeout_seconds=5.0,
                    )
                    return host, neighbors, if_stats
                except Exception as exc:
                    LOGGER.warning("topology scheduled: discovery failed for %s: %s",
                                   host["ip_address"], exc)
                    return host, None, []

        walk_results = await asyncio.gather(*[_walk_host(h) for h in hosts])

        for host, neighbors, if_stats in walk_results:
            if neighbors is None:
                total_errors += 1
                continue
            try:
                # Snapshot old links for change detection
                old_links = await db.get_topology_links_for_host(host["id"])
                old_link_keys = {
                    (l["source_host_id"], l["source_interface"], l["target_device_name"], l["target_interface"])
                    for l in old_links if l["source_host_id"] == host["id"]
                }
                new_link_keys = {
                    (n["source_host_id"], n["local_interface"], n["remote_device_name"], n["remote_interface"])
                    for n in neighbors
                }

                await db.delete_topology_links_for_host(host["id"])
                for n in neighbors:
                    await db.upsert_topology_link(
                        source_host_id=n["source_host_id"],
                        source_ip=n["source_ip"],
                        source_interface=n["local_interface"],
                        target_host_id=None,
                        target_ip=n.get("remote_ip", ""),
                        target_device_name=n["remote_device_name"],
                        target_interface=n["remote_interface"],
                        protocol=n["protocol"],
                        target_platform=n.get("remote_platform", ""),
                    )
                # Store interface stats
                for stat in if_stats:
                    await db.upsert_interface_stat(**stat)
                # Record topology changes (only if there were previous links)
                if old_link_keys:
                    await _record_topology_changes(host, old_link_keys, new_link_keys, neighbors, old_links)
                total_links += len(neighbors)
            except Exception as exc:
                LOGGER.warning("topology scheduled: DB write failed for %s: %s",
                               host["ip_address"], exc)
                total_errors += 1

    if groups_scanned > 0:
        try:
            await db.resolve_topology_target_host_ids()
        except Exception:
            pass
        LOGGER.info("topology scheduled: scanned %d groups, %d links discovered, %d errors",
                     groups_scanned, total_links, total_errors)
        increment_metric("topology.discovery.scheduled.success")

    return {
        "enabled": True,
        "groups_scanned": groups_scanned,
        "links_discovered": total_links,
        "errors": total_errors,
    }


async def _topology_discovery_loop() -> None:
    while True:
        try:
            await asyncio.sleep(int(TOPOLOGY_DISCOVERY_CONFIG.get(
                "interval_seconds", TOPOLOGY_DISCOVERY_DEFAULTS["interval_seconds"])))
            await _run_topology_discovery_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("topology discovery loop failure: %s", redact_value(str(exc)))
            increment_metric("topology.discovery.scheduled.failed")
            await asyncio.sleep(TOPOLOGY_DISCOVERY_DEFAULTS["interval_seconds"])


async def _run_config_drift_check_once() -> dict:
    """Run drift analysis on all hosts that have baselines."""
    if not CONFIG_DRIFT_CHECK_CONFIG.get("enabled"):
        return {"enabled": False, "hosts_checked": 0, "drifted": 0, "errors": 0}

    baselines = await db.get_config_baselines()
    hosts_checked = 0
    drifted = 0
    errors = 0

    for bl in baselines:
        try:
            result = await _analyze_drift_for_host(bl["host_id"])
            hosts_checked += 1
            if result.get("drifted"):
                drifted += 1
        except Exception as exc:
            errors += 1
            LOGGER.warning("config drift check failed for host_id=%s: %s", bl["host_id"], exc)

    # Retention cleanup
    retention_days = int(CONFIG_DRIFT_CHECK_CONFIG.get(
        "snapshot_retention_days", CONFIG_DRIFT_CHECK_DEFAULTS["snapshot_retention_days"]))
    try:
        await db.delete_old_config_snapshots(retention_days)
        await db.delete_old_config_drift_events(retention_days)
    except Exception:
        pass

    if hosts_checked > 0:
        LOGGER.info("config drift check: checked %d hosts, %d drifted, %d errors",
                     hosts_checked, drifted, errors)
        increment_metric("config_drift.check.scheduled.success")

    return {
        "enabled": True,
        "hosts_checked": hosts_checked,
        "drifted": drifted,
        "errors": errors,
    }


async def _config_drift_check_loop() -> None:
    """Infinite loop that runs drift checks at configurable intervals."""
    while True:
        try:
            await asyncio.sleep(int(CONFIG_DRIFT_CHECK_CONFIG.get(
                "interval_seconds", CONFIG_DRIFT_CHECK_DEFAULTS["interval_seconds"])))
            await _run_config_drift_check_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("config drift check loop failure: %s", redact_value(str(exc)))
            increment_metric("config_drift.check.scheduled.failed")
            await asyncio.sleep(CONFIG_DRIFT_CHECK_DEFAULTS["interval_seconds"])


# ── Config Backup Background Loop ────────────────────────────────────────────


async def _run_config_backups_once() -> dict:
    """Run backups for all due policies."""
    if not CONFIG_BACKUP_CONFIG.get("enabled"):
        return {"enabled": False, "policies_run": 0, "hosts_backed_up": 0, "errors": 0}

    due_policies = await db.get_config_backup_policies_due()
    policies_run = 0
    hosts_backed_up = 0
    errors = 0

    sem = asyncio.Semaphore(4)

    for policy in due_policies:
        try:
            hosts = await db.get_hosts_for_group(policy["group_id"])
            cred = await db.get_credential_raw(policy["credential_id"])
            if not cred:
                LOGGER.warning("config-backup: credential %s not found for policy %s", policy["credential_id"], policy["id"])
                errors += 1
                continue

            async def _backup_host(host, cred_data, pol_id):
                async with sem:
                    try:
                        config_text = await _capture_running_config(host, cred_data)
                        await db.create_config_backup(
                            policy_id=pol_id, host_id=host["id"],
                            config_text=config_text, capture_method="scheduled",
                            status="success", error_message="",
                        )
                        return True
                    except Exception as exc:
                        await db.create_config_backup(
                            policy_id=pol_id, host_id=host["id"],
                            config_text="", capture_method="scheduled",
                            status="error", error_message=str(exc),
                        )
                        return False

            tasks = [_backup_host(h, cred, policy["id"]) for h in hosts]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if r is True:
                    hosts_backed_up += 1
                else:
                    errors += 1

            await db.update_config_backup_policy_last_run(policy["id"])
            policies_run += 1

            # Retention cleanup for this policy
            try:
                await db.delete_old_config_backups(policy["retention_days"])
            except Exception:
                pass

        except Exception as exc:
            errors += 1
            LOGGER.warning("config-backup: policy %s failed: %s", policy["id"], exc)

    if policies_run > 0:
        LOGGER.info("config-backup: ran %d policies, backed up %d hosts, %d errors",
                     policies_run, hosts_backed_up, errors)
        increment_metric("config_backup.scheduled.success")

    return {
        "enabled": True,
        "policies_run": policies_run,
        "hosts_backed_up": hosts_backed_up,
        "errors": errors,
    }


async def _config_backup_loop() -> None:
    """Infinite loop that checks for due backup policies."""
    while True:
        try:
            await asyncio.sleep(int(CONFIG_BACKUP_CONFIG.get(
                "interval_seconds", CONFIG_BACKUP_DEFAULTS["interval_seconds"])))
            await _run_config_backups_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("config backup loop failure: %s", redact_value(str(exc)))
            increment_metric("config_backup.scheduled.failed")
            await asyncio.sleep(CONFIG_BACKUP_DEFAULTS["interval_seconds"])


def _ensure_radius_dictionary_file() -> str:
    """Create a minimal RADIUS dictionary if one does not exist."""
    if os.path.isfile(RADIUS_DICTIONARY_FILE):
        return RADIUS_DICTIONARY_FILE
    os.makedirs(os.path.dirname(RADIUS_DICTIONARY_FILE), exist_ok=True)
    content = """ATTRIBUTE\tUser-Name\t1\tstring
ATTRIBUTE\tUser-Password\t2\tstring
ATTRIBUTE\tReply-Message\t18\tstring
ATTRIBUTE\tNAS-Identifier\t32\tstring
"""
    with open(RADIUS_DICTIONARY_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    return RADIUS_DICTIONARY_FILE


def _radius_authenticate_sync(username: str, password: str, radius_cfg: dict) -> tuple[bool, str]:
    """Perform a blocking RADIUS PAP authentication request."""
    if not PYRAD_AVAILABLE:
        return False, "error"
    assert RadiusClient is not None and RadiusDictionary is not None and radius_packet is not None
    if not radius_cfg.get("server") or not radius_cfg.get("secret"):
        return False, "error"

    dictionary_path = _ensure_radius_dictionary_file()
    try:
        client = RadiusClient(
            server=radius_cfg["server"],
            secret=radius_cfg["secret"].encode("utf-8"),
            dict=RadiusDictionary(dictionary_path),
            authport=int(radius_cfg.get("port", 1812)),
            timeout=int(radius_cfg.get("timeout", 5)),
        )
        req = client.CreateAuthPacket(code=radius_packet.AccessRequest, User_Name=username)
        req["User-Password"] = req.PwCrypt(password)
        req["NAS-Identifier"] = "plexus"
        reply = client.SendPacket(req)
        if reply.code == radius_packet.AccessAccept:
            return True, "accept"
        if reply.code == radius_packet.AccessReject:
            return False, "reject"
        return False, "reject"
    except (TimeoutError, OSError):
        return False, "error"
    except Exception:
        return False, "error"


async def verify_radius_user(username: str, password: str) -> tuple[bool, str]:
    """Returns (is_authenticated, status) where status is accept/reject/error."""
    radius_cfg = AUTH_CONFIG.get("radius", {})
    return await asyncio.to_thread(_radius_authenticate_sync, username, password, radius_cfg)


async def upsert_radius_user(username: str) -> dict | None:
    """Ensure a local shadow user exists for RADIUS-authenticated identities."""
    user = await db.get_user_by_username(username)
    if user:
        return user

    salt = secrets.token_hex(16)
    random_pw = secrets.token_urlsafe(32)
    pw_hash = _hash_password(random_pw, salt)
    try:
        user_id = await db.create_user(
            username,
            pw_hash,
            salt,
            display_name=username,
            role="user",
        )
    except ValueError:
        # Another request may have created it concurrently.
        return await db.get_user_by_username(username)
    return await db.get_user_by_id(user_id)


async def authenticate_login_identity(username: str, password: str) -> tuple[dict | None, str | None, str | None]:
    """Authenticate using configured provider with defined fallback behavior.

    Returns (user, auth_source, error_detail)
    """
    provider = AUTH_CONFIG.get("provider", "local")
    radius_cfg = AUTH_CONFIG.get("radius", {})
    radius_enabled = bool(radius_cfg.get("enabled"))

    if provider == "radius" and radius_enabled:
        accepted, status = await verify_radius_user(username, password)
        if accepted:
            user = await upsert_radius_user(username)
            if user:
                return user, "radius", None
            return None, None, "RADIUS login succeeded but local account provisioning failed"

        if status == "reject" and not bool(radius_cfg.get("fallback_on_reject", False)):
            return None, None, "Invalid username or password"

        if bool(radius_cfg.get("fallback_to_local", True)):
            local_user = await verify_user(username, password)
            if local_user:
                return local_user, "local-fallback", None
            if status == "error":
                return None, None, "RADIUS is unavailable and local fallback credentials failed"
            return None, None, "Invalid username or password"

        if status == "error":
            return None, None, "RADIUS authentication service unavailable"
        return None, None, "Invalid username or password"

    # Default/local provider path.
    user = await verify_user(username, password)
    if user:
        return user, "local", None
    return None, None, "Invalid username or password"


async def _load_persisted_security_settings():
    global LOGIN_RULES, AUTH_CONFIG, DISCOVERY_SYNC_CONFIG, SNMP_DISCOVERY_CONFIG, SNMP_DISCOVERY_PROFILES
    global SNMP_PROFILES, GROUP_SNMP_ASSIGNMENTS, TOPOLOGY_DISCOVERY_CONFIG, CONFIG_DRIFT_CHECK_CONFIG
    global CONFIG_BACKUP_CONFIG
    login_rules = await db.get_auth_setting("login_rules")
    auth_config = await db.get_auth_setting("auth_config")
    discovery_sync = await db.get_auth_setting("discovery_sync")
    snmp_discovery = await db.get_auth_setting("snmp_discovery")
    snmp_discovery_profiles = await db.get_auth_setting("snmp_discovery_profiles")
    snmp_profiles = await db.get_auth_setting("snmp_profiles")
    group_snmp_assignments = await db.get_auth_setting("group_snmp_assignments")
    topology_discovery = await db.get_auth_setting("topology_discovery")
    LOGIN_RULES = _sanitize_login_rules(login_rules)
    AUTH_CONFIG = _sanitize_auth_config(auth_config)
    DISCOVERY_SYNC_CONFIG = _sanitize_discovery_sync_config(discovery_sync)
    SNMP_DISCOVERY_CONFIG = _sanitize_snmp_discovery_config(snmp_discovery)
    SNMP_DISCOVERY_PROFILES = _sanitize_snmp_discovery_profiles(snmp_discovery_profiles)
    SNMP_PROFILES = _sanitize_snmp_profiles(snmp_profiles)
    GROUP_SNMP_ASSIGNMENTS = _sanitize_group_snmp_assignments(group_snmp_assignments)
    TOPOLOGY_DISCOVERY_CONFIG = _sanitize_topology_discovery_config(topology_discovery)
    config_drift_check = await db.get_auth_setting("config_drift_check")
    CONFIG_DRIFT_CHECK_CONFIG = _sanitize_config_drift_check_config(config_drift_check)
    config_backup = await db.get_auth_setting("config_backup")
    CONFIG_BACKUP_CONFIG = _sanitize_config_backup_config(config_backup)


async def _get_user_features(user: dict) -> list[str]:
    if not user:
        return []
    if user.get("role") == "admin":
        return list(FEATURE_FLAGS)
    effective = await db.get_user_effective_features(int(user["id"]))
    if not effective:
        # Backward-compatible default: users without assigned groups keep access.
        return list(FEATURE_FLAGS)
    return [f for f in FEATURE_FLAGS if f in set(effective)]


def require_feature(feature_key: str):
    async def _dependency(request: Request):
        session = await require_auth(request)
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
    """Dependency that checks for admin access. Returns session dict."""
    session = await require_auth(request)
    if session and session.get("auth_mode") == "token":
        return session
    user = await db.get_user_by_username(session["user"])
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return session


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
    await _cleanup_expired_jobs()
    await _cleanup_expired_converter_sessions()
    await _run_discovery_sync_once()
    retention_task = asyncio.create_task(_job_retention_cleanup_loop())
    discovery_sync_task = asyncio.create_task(_discovery_sync_loop())
    topology_discovery_task = asyncio.create_task(_topology_discovery_loop())
    config_drift_task = asyncio.create_task(_config_drift_check_loop())
    config_backup_task = asyncio.create_task(_config_backup_loop())
    try:
        yield
    finally:
        retention_task.cancel()
        discovery_sync_task.cancel()
        topology_discovery_task.cancel()
        config_drift_task.cancel()
        config_backup_task.cancel()
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
            await config_drift_task
        except asyncio.CancelledError:
            pass
        try:
            await config_backup_task
        except asyncio.CancelledError:
            pass


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


app = FastAPI(title="Plexus API", version=APP_VERSION, lifespan=lifespan)
app.include_router(
    converter_router,
    dependencies=[Depends(require_auth), Depends(require_feature("converter"))],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=APP_CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    """Add transport-oriented headers.

    HSTS is enabled only when APP_HSTS/APP_HTTPS is enabled.
    """
    response = await call_next(request)
    if APP_HSTS_ENABLED:
        response.headers["Strict-Transport-Security"] = f"max-age={max(0, APP_HSTS_MAX_AGE)}; includeSubDomains"
    return response


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


# ═════════════════════════════════════════════════════════════════════════════
# Auth Routes
# ═════════════════════════════════════════════════════════════════════════════

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str
    display_name: str = ""

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class UpdateProfileRequest(BaseModel):
    display_name: str | None = None


@app.post("/api/auth/login")
async def login(body: LoginRequest, request: Request):
    ip = request.client.host
    now = time.time()

    # Account lockout check
    if ip in LOCKED_OUT:
        if now < LOCKED_OUT[ip]:
            raise HTTPException(status_code=429, detail=f"Account locked. Try again in {int((LOCKED_OUT[ip]-now)//60)+1} min.")
        else:
            del LOCKED_OUT[ip]
            LOGIN_ATTEMPTS.pop(ip, None)

    # Rate limiting
    attempts = LOGIN_ATTEMPTS.get(ip, [])
    # Remove old attempts
    attempts = [t for t in attempts if now - t < LOGIN_RULES["rate_limit_window"]]
    if len(attempts) >= LOGIN_RULES["rate_limit_max"]:
        raise HTTPException(status_code=429, detail="Too many login attempts. Please wait a minute.")

    user, auth_source, auth_error = await authenticate_login_identity(body.username, body.password)
    if not user:
        attempts.append(now)
        LOGIN_ATTEMPTS[ip] = attempts
        await _audit("auth", "login.failure", user=body.username, detail=auth_error or "bad credentials", correlation_id=_corr_id(request))
        # Lockout if too many failed attempts
        if len(attempts) >= LOGIN_RULES["max_attempts"]:
            LOCKED_OUT[ip] = now + LOGIN_RULES["lockout_time"]
            raise HTTPException(status_code=429, detail="Account locked due to too many failed attempts. Try again later.")
        raise HTTPException(status_code=401, detail=auth_error or "Invalid username or password")
    # On success, reset attempts
    LOGIN_ATTEMPTS.pop(ip, None)
    await _audit("auth", "login.success", user=body.username, detail=f"source={auth_source}", correlation_id=_corr_id(request))
    token = create_session_token(body.username, user["id"])
    csrf_token = _generate_csrf_token(body.username)
    response = JSONResponse({
        "ok": True,
        "username": body.username,
        "user_id": user["id"],
        "display_name": user["display_name"] or body.username,
        "role": user["role"],
        "auth_source": auth_source,
        "feature_access": await _get_user_features(user),
        "must_change_password": bool(user.get("must_change_password")),
        "csrf_token": csrf_token,
    })
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="strict",
        max_age=SESSION_MAX_AGE,
        secure=APP_HTTPS_ENABLED,
    )
    return response


@app.post("/api/auth/register")
async def register(body: RegisterRequest, request: Request = None):
    if not _env_flag("APP_ALLOW_SELF_REGISTER", False):
        raise HTTPException(status_code=403, detail="Self-registration is disabled")
    existing = await db.get_user_by_username(body.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")
    if len(body.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(body.password, salt)
    display = body.display_name or body.username.title()
    user_id = await db.create_user(body.username, pw_hash, salt, display_name=display, role="user")
    user = await db.get_user_by_id(user_id)
    await _audit("auth", "register", user=body.username, correlation_id=_corr_id(request) if request else "")
    token = create_session_token(body.username, user_id)
    csrf_token = _generate_csrf_token(body.username)
    response = JSONResponse({
        "ok": True,
        "username": body.username,
        "user_id": user_id,
        "display_name": display,
        "role": "user",
        "feature_access": await _get_user_features(user),
        "csrf_token": csrf_token,
    })
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="strict",
        max_age=SESSION_MAX_AGE,
        secure=APP_HTTPS_ENABLED,
    )
    return response


@app.post("/api/auth/logout")
async def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie("session")
    return response


@app.get("/api/auth/status")
async def auth_status(request: Request):
    session = _get_session(request)
    if not session:
        return {"authenticated": False}
    user = await db.get_user_by_id(session["user_id"])
    if not user:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "username": user["username"],
        "user_id": user["id"],
        "display_name": user["display_name"] or user["username"],
        "role": user["role"],
        "feature_access": await _get_user_features(user),
        "csrf_token": _generate_csrf_token(user["username"]),
        "must_change_password": bool(user.get("must_change_password")),
    }


@app.post("/api/auth/change-password", dependencies=[Depends(require_auth)])
async def change_password(body: ChangePasswordRequest, request: Request):
    session = _get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await verify_user(session["user"], body.current_password)
    if not user:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(body.new_password, salt)
    await db.update_user_password(user["id"], pw_hash, salt)
    await _audit("auth", "password.change", user=session["user"], correlation_id=_corr_id(request))
    return {"ok": True}


@app.get("/api/auth/profile", dependencies=[Depends(require_auth)])
async def get_profile(request: Request):
    session = _get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await db.get_user_by_id(session["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user["feature_access"] = await _get_user_features(user)
    return user


@app.put("/api/auth/profile", dependencies=[Depends(require_auth)])
async def update_profile(body: UpdateProfileRequest, request: Request):
    session = _get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    await db.update_user_profile(session["user_id"], display_name=body.display_name)
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# Admin Settings Routes
# ═════════════════════════════════════════════════════════════════════════════

class AdminUserCreateRequest(BaseModel):
    username: str
    password: str
    display_name: str = ""
    role: str = "user"
    group_ids: list[int] = []


class AdminUserUpdateRequest(BaseModel):
    username: str | None = None
    display_name: str | None = None
    role: str | None = None


class AdminUserPasswordResetRequest(BaseModel):
    new_password: str


class AdminUserGroupAssignmentRequest(BaseModel):
    group_ids: list[int]


class AdminAccessGroupCreateRequest(BaseModel):
    name: str
    description: str = ""
    feature_keys: list[str] = []


class AdminAccessGroupUpdateRequest(BaseModel):
    name: str
    description: str = ""
    feature_keys: list[str] = []


class AdminLoginRulesRequest(BaseModel):
    max_attempts: int
    lockout_time: int
    rate_limit_window: int
    rate_limit_max: int


class RadiusConfigRequest(BaseModel):
    enabled: bool = False
    server: str = ""
    port: int = 1812
    secret: str = ""
    timeout: int = 5
    fallback_to_local: bool = True
    fallback_on_reject: bool = False


class AuthConfigRequest(BaseModel):
    provider: str = "local"
    job_retention_days: int = Field(default=30, ge=30)
    converter_session_retention_days: int = Field(default=30, ge=1)
    converter_backup_retention_days: int = Field(default=30, ge=1)
    radius: RadiusConfigRequest = RadiusConfigRequest()


def _validate_feature_keys(feature_keys: list[str]) -> list[str]:
    valid = []
    seen = set()
    for key in feature_keys:
        if key in FEATURE_FLAGS and key not in seen:
            valid.append(key)
            seen.add(key)
    return valid


async def _admin_user_payload(user: dict) -> dict:
    group_ids = await db.get_user_group_ids(int(user["id"]))
    features = await _get_user_features(user)
    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user.get("display_name") or user["username"],
        "role": user.get("role", "user"),
        "created_at": user.get("created_at"),
        "group_ids": group_ids,
        "feature_access": features,
    }


def _security_check_payload() -> dict:
    """Build a runtime snapshot of transport and app hardening settings."""
    api_token_required = _env_flag("APP_REQUIRE_API_TOKEN", False)
    warnings = []
    if not APP_HTTPS_ENABLED:
        warnings.append("APP_HTTPS is false: browser traffic may be sent over HTTP if your proxy does not enforce HTTPS.")
    if not APP_HSTS_ENABLED:
        warnings.append("APP_HSTS is false: browsers are not instructed to enforce HTTPS for future requests.")
    if not api_token_required:
        warnings.append("APP_REQUIRE_API_TOKEN is false: non-session API calls are not forced to present an API token.")
    if not APP_API_TOKEN:
        warnings.append("APP_API_TOKEN is not set: token-based API auth cannot be used.")

    return {
        "ok": True,
        "transport": {
            "https_enabled": APP_HTTPS_ENABLED,
            "hsts_enabled": APP_HSTS_ENABLED,
            "hsts_max_age": max(0, APP_HSTS_MAX_AGE),
        },
        "cookies": {
            "session_cookie_secure": APP_HTTPS_ENABLED,
            "session_cookie_httponly": True,
            "session_cookie_samesite": "strict",
        },
        "cors": {
            "allow_origins": APP_CORS_ALLOW_ORIGINS,
            "allow_credentials": True,
        },
        "auth": {
            "csrf_protected_methods": sorted(_CSRF_PROTECTED_METHODS),
            "api_token_required": api_token_required,
            "api_token_configured": bool(APP_API_TOKEN),
        },
        "warnings": warnings,
    }


@app.get("/api/admin/capabilities", dependencies=[Depends(require_admin)])
async def admin_capabilities():
    return {
        "feature_flags": FEATURE_FLAGS,
        "auth_providers": ["local", "radius"],
    }


@app.get("/api/admin/security-check", dependencies=[Depends(require_admin)])
async def admin_security_check():
    """Return active security-relevant runtime settings for quick verification."""
    return _security_check_payload()


@app.get("/api/admin/users", dependencies=[Depends(require_admin)])
async def admin_list_users():
    users = await db.get_all_users()
    result = []
    for user in users:
        result.append(await _admin_user_payload(user))
    return result


@app.post("/api/admin/users", status_code=201, dependencies=[Depends(require_admin)])
async def admin_create_user(body: AdminUserCreateRequest, request: Request):
    username = body.username.strip()
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    role = body.role if body.role in {"admin", "user"} else "user"

    salt = secrets.token_hex(16)
    pw_hash = _hash_password(body.password, salt)
    display = body.display_name.strip() if body.display_name else username.title()
    try:
        user_id = await db.create_user(username, pw_hash, salt, display_name=display, role=role)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if body.group_ids:
        try:
            await db.set_user_groups(user_id, body.group_ids)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    session = _get_session(request)
    await _audit("auth", "user.create", user=session["user"] if session else "", detail=f"created user '{username}' role={role}", correlation_id=_corr_id(request))
    user = await db.get_user_by_id(user_id)
    return await _admin_user_payload(user)


@app.put("/api/admin/users/{user_id}", dependencies=[Depends(require_admin)])
async def admin_update_user(user_id: int, body: AdminUserUpdateRequest, request: Request):
    target = await db.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    username = body.username.strip() if body.username is not None else None
    if username is not None and len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    role = body.role if body.role in {"admin", "user"} else None
    session = _get_session(request)
    if role == "user" and session and int(session["user_id"]) == user_id:
        raise HTTPException(status_code=400, detail="You cannot remove your own admin role")

    try:
        await db.update_user_admin(
            user_id,
            username=username,
            display_name=body.display_name,
            role=role,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    user = await db.get_user_by_id(user_id)
    return await _admin_user_payload(user)


@app.put("/api/admin/users/{user_id}/password", dependencies=[Depends(require_admin)])
async def admin_reset_user_password(user_id: int, body: AdminUserPasswordResetRequest):
    target = await db.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    salt = secrets.token_hex(16)
    pw_hash = _hash_password(body.new_password, salt)
    await db.update_user_password(user_id, pw_hash, salt)
    return {"ok": True}


@app.put("/api/admin/users/{user_id}/groups", dependencies=[Depends(require_admin)])
async def admin_set_user_groups(user_id: int, body: AdminUserGroupAssignmentRequest):
    target = await db.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        await db.set_user_groups(user_id, body.group_ids)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    user = await db.get_user_by_id(user_id)
    return await _admin_user_payload(user)


@app.delete("/api/admin/users/{user_id}", dependencies=[Depends(require_admin)])
async def admin_delete_user(user_id: int, request: Request):
    target = await db.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    session = _get_session(request)
    if session and int(session["user_id"]) == user_id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")

    if target.get("role") == "admin":
        users = await db.get_all_users()
        admin_count = len([u for u in users if u.get("role") == "admin"])
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot delete the last admin user")

    await db.delete_user(user_id)
    await _audit("auth", "user.delete", user=session["user"] if session else "", detail=f"deleted user '{target['username']}'", correlation_id=_corr_id(request))
    return {"ok": True}


@app.get("/api/admin/access-groups", dependencies=[Depends(require_admin)])
async def admin_list_access_groups():
    return await db.get_all_access_groups()


@app.post("/api/admin/access-groups", status_code=201, dependencies=[Depends(require_admin)])
async def admin_create_access_group(body: AdminAccessGroupCreateRequest):
    name = body.name.strip()
    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Group name must be at least 2 characters")
    try:
        group_id = await db.create_access_group(
            name,
            body.description.strip(),
            _validate_feature_keys(body.feature_keys),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    group = await db.get_access_group(group_id)
    return group


@app.put("/api/admin/access-groups/{group_id}", dependencies=[Depends(require_admin)])
async def admin_update_access_group(group_id: int, body: AdminAccessGroupUpdateRequest):
    existing = await db.get_access_group(group_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Access group not found")
    name = body.name.strip()
    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Group name must be at least 2 characters")
    try:
        await db.update_access_group(
            group_id,
            name,
            body.description.strip(),
            _validate_feature_keys(body.feature_keys),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return await db.get_access_group(group_id)


@app.delete("/api/admin/access-groups/{group_id}", dependencies=[Depends(require_admin)])
async def admin_delete_access_group(group_id: int):
    existing = await db.get_access_group(group_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Access group not found")
    await db.delete_access_group(group_id)
    return {"ok": True}


@app.get("/api/admin/audit-events", dependencies=[Depends(require_admin)])
async def admin_get_audit_events(limit: int = Query(200, ge=1, le=1000)):
    """Return recent audit events for the admin dashboard."""
    return await db.get_audit_events(limit=limit)


@app.get("/api/admin/login-rules", dependencies=[Depends(require_admin)])
async def admin_get_login_rules():
    return LOGIN_RULES


@app.put("/api/admin/login-rules", dependencies=[Depends(require_admin)])
async def admin_update_login_rules(body: AdminLoginRulesRequest):
    global LOGIN_RULES
    LOGIN_RULES = _sanitize_login_rules(body.dict())
    await db.set_auth_setting("login_rules", LOGIN_RULES)
    return LOGIN_RULES


@app.get("/api/admin/auth-config", dependencies=[Depends(require_admin)])
async def admin_get_auth_config():
    return AUTH_CONFIG


@app.put("/api/admin/auth-config", dependencies=[Depends(require_admin)])
async def admin_update_auth_config(body: AuthConfigRequest):
    global AUTH_CONFIG
    AUTH_CONFIG = _sanitize_auth_config(body.dict())
    await db.set_auth_setting("auth_config", AUTH_CONFIG)
    return AUTH_CONFIG


@app.post("/api/admin/retention/cleanup-now", dependencies=[Depends(require_admin)])
async def admin_run_retention_cleanup_now():
    """Run retention cleanup immediately for jobs and converter artifacts."""
    jobs_deleted = await _cleanup_expired_jobs()
    converter_summary = await _cleanup_expired_converter_sessions()
    return {
        "ok": True,
        "jobs_deleted": jobs_deleted,
        "converter": converter_summary,
        "effective_retention_days": {
            "jobs": _effective_job_retention_days(),
            "converter_sessions": _effective_converter_session_retention_days(),
            "converter_backups": _effective_converter_backup_retention_days(),
        },
    }


@app.get("/api/admin/discovery-sync", dependencies=[Depends(require_admin)])
async def admin_get_discovery_sync_config():
    return DISCOVERY_SYNC_CONFIG


@app.put("/api/admin/discovery-sync", dependencies=[Depends(require_admin)])
async def admin_update_discovery_sync_config(body: dict):
    global DISCOVERY_SYNC_CONFIG
    DISCOVERY_SYNC_CONFIG = _sanitize_discovery_sync_config(body)
    await db.set_auth_setting("discovery_sync", DISCOVERY_SYNC_CONFIG)
    return DISCOVERY_SYNC_CONFIG


@app.post("/api/admin/discovery-sync/run-now", dependencies=[Depends(require_admin)])
async def admin_run_discovery_sync_now():
    result = await _run_discovery_sync_once()
    return {"ok": True, "result": result}


@app.get("/api/admin/topology-discovery", dependencies=[Depends(require_admin)])
async def admin_get_topology_discovery_config():
    return TOPOLOGY_DISCOVERY_CONFIG


@app.put("/api/admin/topology-discovery", dependencies=[Depends(require_admin)])
async def admin_update_topology_discovery_config(body: dict):
    global TOPOLOGY_DISCOVERY_CONFIG
    TOPOLOGY_DISCOVERY_CONFIG = _sanitize_topology_discovery_config(body)
    await db.set_auth_setting("topology_discovery", TOPOLOGY_DISCOVERY_CONFIG)
    return TOPOLOGY_DISCOVERY_CONFIG


@app.post("/api/admin/topology-discovery/run-now", dependencies=[Depends(require_admin)])
async def admin_run_topology_discovery_now():
    result = await _run_topology_discovery_once()
    return {"ok": True, "result": result}


@app.get("/api/admin/snmp-discovery", dependencies=[Depends(require_admin)])
async def admin_get_snmp_discovery_config():
    return SNMP_DISCOVERY_CONFIG


@app.put("/api/admin/snmp-discovery", dependencies=[Depends(require_admin)])
async def admin_update_snmp_discovery_config(body: dict):
    global SNMP_DISCOVERY_CONFIG
    SNMP_DISCOVERY_CONFIG = _sanitize_snmp_discovery_config(body)
    await db.set_auth_setting("snmp_discovery", SNMP_DISCOVERY_CONFIG)
    return SNMP_DISCOVERY_CONFIG


@app.get("/api/admin/snmp-discovery-profiles", dependencies=[Depends(require_admin)])
async def admin_get_snmp_discovery_profiles():
    return SNMP_DISCOVERY_PROFILES


# ── Named SNMP Profiles CRUD ─────────────────────────────────────────────────

@app.get("/api/admin/snmp-profiles", dependencies=[Depends(require_auth)])
async def admin_list_snmp_profiles():
    return list(SNMP_PROFILES.values())


@app.post("/api/admin/snmp-profiles", dependencies=[Depends(require_admin)])
async def admin_create_snmp_profile(body: dict):
    global SNMP_PROFILES
    profile_id = str(uuid.uuid4())
    profile = _sanitize_snmp_profile(profile_id, body)
    if not profile["name"]:
        raise HTTPException(400, "Profile name is required")
    SNMP_PROFILES[profile_id] = profile
    await db.set_auth_setting("snmp_profiles", SNMP_PROFILES)
    return profile


@app.put("/api/admin/snmp-profiles/{profile_id}", dependencies=[Depends(require_admin)])
async def admin_update_snmp_profile(profile_id: str, body: dict):
    global SNMP_PROFILES
    if profile_id not in SNMP_PROFILES:
        raise HTTPException(404, "Profile not found")
    profile = _sanitize_snmp_profile(profile_id, body)
    if not profile["name"]:
        raise HTTPException(400, "Profile name is required")
    SNMP_PROFILES[profile_id] = profile
    await db.set_auth_setting("snmp_profiles", SNMP_PROFILES)
    return profile


@app.delete("/api/admin/snmp-profiles/{profile_id}", dependencies=[Depends(require_admin)])
async def admin_delete_snmp_profile(profile_id: str):
    global SNMP_PROFILES, GROUP_SNMP_ASSIGNMENTS
    if profile_id not in SNMP_PROFILES:
        raise HTTPException(404, "Profile not found")
    del SNMP_PROFILES[profile_id]
    # Unassign any groups using this profile
    changed = False
    for gid in list(GROUP_SNMP_ASSIGNMENTS):
        if GROUP_SNMP_ASSIGNMENTS[gid] == profile_id:
            del GROUP_SNMP_ASSIGNMENTS[gid]
            changed = True
    await db.set_auth_setting("snmp_profiles", SNMP_PROFILES)
    if changed:
        await db.set_auth_setting("group_snmp_assignments", GROUP_SNMP_ASSIGNMENTS)
    return {"ok": True}


# ── Group SNMP Profile Assignment ────────────────────────────────────────────

@app.get("/api/inventory/{group_id}/snmp-profile-assignment", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def get_group_snmp_profile_assignment(group_id: int):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    profile_id = GROUP_SNMP_ASSIGNMENTS.get(group_id, "")
    profile = SNMP_PROFILES.get(profile_id) if profile_id else None
    return {"group_id": group_id, "snmp_profile_id": profile_id, "profile_name": profile["name"] if profile else ""}


@app.put("/api/inventory/{group_id}/snmp-profile-assignment", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def update_group_snmp_profile_assignment(group_id: int, body: dict):
    global GROUP_SNMP_ASSIGNMENTS
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    profile_id = str(body.get("snmp_profile_id", "")).strip()
    if profile_id and profile_id not in SNMP_PROFILES:
        raise HTTPException(400, "SNMP profile not found")
    if profile_id:
        GROUP_SNMP_ASSIGNMENTS[group_id] = profile_id
    else:
        GROUP_SNMP_ASSIGNMENTS.pop(group_id, None)
    await db.set_auth_setting("group_snmp_assignments", GROUP_SNMP_ASSIGNMENTS)
    profile = SNMP_PROFILES.get(profile_id) if profile_id else None
    return {"group_id": group_id, "snmp_profile_id": profile_id, "profile_name": profile["name"] if profile else ""}


# ═════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ═════════════════════════════════════════════════════════════════════════════

class GroupCreate(BaseModel):
    name: str
    description: str = ""


class GroupUpdate(BaseModel):
    name: str
    description: str = ""

class HostCreate(BaseModel):
    hostname: str
    ip_address: str
    device_type: str = "cisco_ios"

class HostUpdate(BaseModel):
    hostname: str
    ip_address: str
    device_type: str = "cisco_ios"


class DiscoveryScanRequest(BaseModel):
    cidrs: list[str] = Field(default_factory=list)
    timeout_seconds: float = Field(default=DISCOVERY_DEFAULT_TIMEOUT_SECONDS, ge=0.05, le=5.0)
    max_hosts: int = Field(default=DISCOVERY_DEFAULT_MAX_HOSTS, ge=1, le=4096)
    device_type: str = "unknown"
    hostname_prefix: str = "discovered"
    use_snmp: bool = True

    model_config = ConfigDict(extra="forbid")


class DiscoverySyncRequest(DiscoveryScanRequest):
    remove_absent: bool = False


class DiscoveryOnboardRequest(BaseModel):
    discovered_hosts: list[dict] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")

class PlaybookCreate(BaseModel):
    name: str
    filename: str
    description: str = ""
    tags: list[str] = []
    content: str = ""

class PlaybookUpdate(BaseModel):
    name: str | None = None
    filename: str | None = None
    description: str | None = None
    tags: list[str] | None = None
    content: str | None = None

class TemplateCreate(BaseModel):
    name: str
    content: str
    description: str = ""

class TemplateUpdate(BaseModel):
    name: str
    content: str
    description: str = ""

class CredentialCreate(BaseModel):
    name: str
    username: str
    password: str
    secret: str = ""


class CredentialUpdate(BaseModel):
    name: str | None = None
    username: str | None = None
    password: str | None = None
    secret: str | None = None


class JobLaunch(BaseModel):
    playbook_id: int
    inventory_group_id: int | None = None  # Optional for backward compatibility
    host_ids: list[int] | None = None  # List of specific host IDs to target
    credential_id: int | None = None
    template_id: int | None = None
    dry_run: bool = True

    # Forbid unknown fields for strict payload validation.
    model_config = ConfigDict(extra="forbid")


# ── Config Drift Pydantic models ─────────────────────────────────────────────


class ConfigBaselineCreate(BaseModel):
    host_id: int
    name: str = ""
    config_text: str
    source: str = "manual"


class ConfigBaselineUpdate(BaseModel):
    name: str | None = None
    config_text: str | None = None
    source: str | None = None


class ConfigDriftStatusUpdate(BaseModel):
    status: str  # "resolved" or "accepted"


class ConfigSnapshotCaptureRequest(BaseModel):
    host_id: int
    credential_id: int


class ConfigGroupCaptureRequest(BaseModel):
    group_id: int
    credential_id: int


class ConfigDriftAnalyzeRequest(BaseModel):
    host_id: int


class ConfigDriftAnalyzeGroupRequest(BaseModel):
    group_id: int


class ConfigDriftCheckRequest(BaseModel):
    host_id: int
    credential_id: int


class ConfigDriftRevertRequest(BaseModel):
    event_id: int
    credential_id: int


class ConfigBackupPolicyCreate(BaseModel):
    name: str
    group_id: int
    credential_id: int
    interval_seconds: int = 86400
    retention_days: int = 30


class ConfigBackupPolicyUpdate(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    credential_id: int | None = None
    interval_seconds: int | None = None
    retention_days: int | None = None


class ConfigBackupRestoreRequest(BaseModel):
    backup_id: int
    credential_id: int


# ── Config Drift helpers ─────────────────────────────────────────────────────


def _compute_config_diff(
    baseline_text: str,
    actual_text: str,
    baseline_label: str = "baseline",
    actual_label: str = "actual",
) -> tuple[str, int, int]:
    """Compute unified diff between baseline and actual config.

    Returns (diff_text, lines_added, lines_removed).
    """
    baseline_lines = baseline_text.splitlines(keepends=True)
    actual_lines = actual_text.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        baseline_lines, actual_lines,
        fromfile=baseline_label, tofile=actual_label,
    ))
    diff_text = "".join(diff)
    added = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))
    return diff_text, added, removed


async def _capture_running_config(host: dict, credentials: dict) -> str:
    """SSH to a device and pull running-config via Netmiko."""
    import netmiko
    from routes.crypto import decrypt

    def _do_capture():
        device = {
            "device_type": host.get("device_type", "cisco_ios"),
            "host": host["ip_address"],
            "username": credentials["username"],
            "password": decrypt(credentials["password"]),
            "secret": decrypt(credentials.get("secret", "")),
        }
        net_connect = netmiko.ConnectHandler(**device)
        if device["secret"]:
            net_connect.enable()
        config = net_connect.send_command("show running-config")
        net_connect.disconnect()
        return config

    return await asyncio.to_thread(_do_capture)


# ═════════════════════════════════════════════════════════════════════════════
# Dashboard
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/dashboard", dependencies=[Depends(require_auth), Depends(require_feature("dashboard"))])
async def dashboard():
    stats = await db.get_dashboard_stats()
    recent_jobs = await db.get_all_jobs(limit=5)
    groups = await db.get_all_groups()
    return {"stats": stats, "recent_jobs": recent_jobs, "groups": groups}


# ═════════════════════════════════════════════════════════════════════════════
# Inventory Groups
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/inventory", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def list_groups(include_hosts: bool = Query(default=False)):
    if include_hosts:
        return await db.get_all_groups_with_hosts()
    return await db.get_all_groups()


@app.post("/api/inventory", status_code=201, dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def create_group(body: GroupCreate):
    gid = await db.create_group(body.name, body.description)
    return {"id": gid, "name": body.name}


@app.put("/api/inventory/{group_id}", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def update_group(group_id: int, body: GroupUpdate):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    await db.update_group(group_id, body.name, body.description)
    return {"ok": True}


@app.get("/api/inventory/{group_id}", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def get_group(group_id: int):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    hosts = await db.get_hosts_for_group(group_id)
    return {**group, "hosts": hosts}


@app.delete("/api/inventory/{group_id}", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def delete_group(group_id: int):
    await db.delete_group(group_id)
    return {"ok": True}


# ── Hosts ────────────────────────────────────────────────────────────────────

@app.get("/api/inventory/{group_id}/hosts", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def list_hosts(group_id: int):
    return await db.get_hosts_for_group(group_id)


@app.post("/api/inventory/{group_id}/hosts", status_code=201, dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def add_host(group_id: int, body: HostCreate):
    hid = await db.add_host(group_id, body.hostname, body.ip_address, body.device_type)
    return {"id": hid}


@app.put("/api/hosts/{host_id}", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def update_host(host_id: int, body: HostUpdate):
    await db.update_host(host_id, body.hostname, body.ip_address, body.device_type)
    return {"ok": True}


@app.delete("/api/hosts/{host_id}", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def remove_host(host_id: int):
    await db.remove_host(host_id)
    return {"ok": True}


@app.post("/api/hosts/bulk-delete", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def bulk_delete_hosts(body: dict):
    host_ids = body.get("host_ids", [])
    if not host_ids or not isinstance(host_ids, list):
        raise HTTPException(400, "host_ids must be a non-empty list")
    host_ids = [int(h) for h in host_ids]
    deleted = await db.bulk_delete_hosts(host_ids)
    return {"deleted": deleted}


@app.post("/api/hosts/move", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def move_hosts(body: dict):
    host_ids = body.get("host_ids", [])
    target_group_id = body.get("target_group_id")
    if not host_ids or not isinstance(host_ids, list):
        raise HTTPException(400, "host_ids must be a non-empty list")
    if not target_group_id:
        raise HTTPException(400, "target_group_id is required")
    target_group_id = int(target_group_id)
    group = await db.get_group(target_group_id)
    if not group:
        raise HTTPException(404, "Target group not found")
    host_ids = [int(h) for h in host_ids]
    moved = await db.move_hosts(host_ids, target_group_id)
    return {"moved": moved}


def _expand_scan_targets(cidrs: list[str], max_hosts: int) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        for host in network.hosts():
            ip_str = str(host)
            if ip_str in seen:
                continue
            seen.add(ip_str)
            targets.append(ip_str)
            if len(targets) >= max_hosts:
                return targets
    return targets


async def _probe_discovery_target(
    ip_address: str,
    timeout_seconds: float,
    device_type: str,
    hostname_prefix: str,
    use_snmp: bool,
    snmp_config: dict,
) -> dict | None:
    if use_snmp:
        snmp_hit = await _probe_discovery_target_snmp(ip_address, timeout_seconds, snmp_config)
        if snmp_hit is not None:
            return snmp_hit

    detected_port = 0
    detected_protocol = ""
    banner_sample = ""
    for port in DISCOVERY_PROBE_PORTS:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip_address, port), timeout=timeout_seconds)
            if port == 22:
                try:
                    banner = await asyncio.wait_for(reader.read(256), timeout=timeout_seconds)
                    banner_sample = banner.decode("utf-8", errors="ignore").strip()
                except Exception:
                    banner_sample = ""
            writer.close()
            await writer.wait_closed()
            _ = reader
            detected_port = port
            detected_protocol = "ssh" if port == 22 else "https"
            break
        except Exception:
            continue
    if not detected_port:
        return None

    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except Exception:
        hostname = f"{hostname_prefix}-{ip_address.replace('.', '-')}"

    inferred_device_type = device_type
    inferred_os = "unknown"
    inferred_vendor = "unknown"
    if banner_sample:
        lower_banner = banner_sample.lower()
        if "cisco" in lower_banner:
            inferred_vendor = "cisco"
            inferred_device_type = "cisco_ios"
        elif "juniper" in lower_banner or "junos" in lower_banner:
            inferred_vendor = "juniper"
            inferred_device_type = "juniper_junos"
        elif "arista" in lower_banner:
            inferred_vendor = "arista"
            inferred_device_type = "arista_eos"
        elif "forti" in lower_banner:
            inferred_vendor = "fortinet"
            inferred_device_type = "fortinet"

        if "ios" in lower_banner:
            inferred_os = "ios"
        elif "nx-os" in lower_banner or "nxos" in lower_banner:
            inferred_os = "nx-os"
        elif "junos" in lower_banner:
            inferred_os = "junos"
        elif "eos" in lower_banner:
            inferred_os = "eos"
        elif "fortios" in lower_banner:
            inferred_os = "fortios"

    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "device_type": inferred_device_type,
        "status": "online",
        "discovery": {
            "protocol": detected_protocol,
            "port": detected_port,
            "banner": banner_sample,
            "vendor": inferred_vendor,
            "os": inferred_os,
        },
    }


def _infer_vendor_os_from_text(raw_text: str) -> tuple[str, str, str]:
    lowered = (raw_text or "").lower()
    vendor = "unknown"
    detected_type = "unknown"
    os_name = "unknown"

    if "cisco" in lowered:
        vendor = "cisco"
        detected_type = "cisco_ios"
    elif "juniper" in lowered or "junos" in lowered:
        vendor = "juniper"
        detected_type = "juniper_junos"
    elif "arista" in lowered:
        vendor = "arista"
        detected_type = "arista_eos"
    elif "forti" in lowered:
        vendor = "fortinet"
        detected_type = "fortinet"

    if "ios" in lowered:
        os_name = "ios"
    elif "nx-os" in lowered or "nxos" in lowered:
        os_name = "nx-os"
    elif "junos" in lowered:
        os_name = "junos"
    elif "eos" in lowered:
        os_name = "eos"
    elif "fortios" in lowered:
        os_name = "fortios"

    return vendor, detected_type, os_name


async def _snmp_get(ip_address: str, timeout_seconds: float, snmp_config: dict) -> dict | None:
    """Returns device info dict on success, None on no response, raises on auth/config errors."""
    if not PYSMNP_AVAILABLE:
        raise RuntimeError("pysnmp library is not available")
    assert (
        CommunityData is not None and ContextData is not None and ObjectIdentity is not None
        and ObjectType is not None and SnmpEngine is not None and UdpTransportTarget is not None
        and UsmUserData is not None and get_cmd is not None
        and usmAesCfb128Protocol is not None and usmAesCfb192Protocol is not None
        and usmAesCfb256Protocol is not None and usmDESPrivProtocol is not None
        and usmHMACMD5AuthProtocol is not None and usmHMACSHAAuthProtocol is not None
        and usmHMAC192SHA256AuthProtocol is not None and usmHMAC384SHA512AuthProtocol is not None
    )
    if not snmp_config.get("enabled", False):
        return None

    cfg = snmp_config
    version = str(cfg.get("version", "2c"))
    port = int(cfg.get("port", 161))
    retries = int(cfg.get("retries", 0))
    timeout = max(timeout_seconds, float(cfg.get("timeout_seconds", timeout_seconds)))

    auth_data = None
    if version == "3":
        v3 = cfg.get("v3", {})
        username = str(v3.get("username", "")).strip()
        auth_password = str(v3.get("auth_password", "")).strip()
        priv_password = str(v3.get("priv_password", "")).strip()
        if not username or not auth_password:
            return None
        auth_map = {
            "md5": usmHMACMD5AuthProtocol,
            "sha": usmHMACSHAAuthProtocol,
            "sha256": usmHMAC192SHA256AuthProtocol,
            "sha512": usmHMAC384SHA512AuthProtocol,
        }
        priv_map = {
            "des": usmDESPrivProtocol,
            "aes128": usmAesCfb128Protocol,
            "aes192": usmAesCfb192Protocol,
            "aes256": usmAesCfb256Protocol,
        }
        auth_proto = auth_map.get(str(v3.get("auth_protocol", "sha")).lower(), usmHMACSHAAuthProtocol)
        priv_proto = priv_map.get(str(v3.get("priv_protocol", "aes128")).lower(), usmAesCfb128Protocol)
        if priv_password:
            auth_data = UsmUserData(
                username,
                authKey=auth_password,
                privKey=priv_password,
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )
        else:
            auth_data = UsmUserData(
                username,
                authKey=auth_password,
                authProtocol=auth_proto,
            )
    else:
        community = str(cfg.get("community", "public")).strip()
        if not community:
            return None
        auth_data = CommunityData(community, mpModel=1)

    engine = SnmpEngine()
    transport = await UdpTransportTarget.create((ip_address, port), timeout=timeout, retries=retries)
    error_indication, error_status, _error_index, var_binds = await get_cmd(
        engine,
        auth_data,
        transport,
        ContextData(),
        ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
        ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0")),
    )
    engine.close_dispatcher()
    if error_indication:
        raise RuntimeError(str(error_indication))
    if error_status:
        raise RuntimeError(f"SNMP error: {error_status.prettyPrint()}")

    values = {str(name): str(value) for name, value in var_binds}
    sys_descr = values.get("1.3.6.1.2.1.1.1.0", "")
    sys_name = values.get("1.3.6.1.2.1.1.5.0", "")
    vendor, detected_type, os_name = _infer_vendor_os_from_text(sys_descr)
    return {
        "hostname": sys_name or f"snmp-{ip_address.replace('.', '-')}",
        "ip_address": ip_address,
        "device_type": detected_type,
        "status": "online",
        "discovery": {
            "protocol": f"snmpv{version}",
            "port": port,
            "vendor": vendor,
            "os": os_name,
            "sys_descr": sys_descr,
            "auth": "configured",
        },
    }


async def _probe_discovery_target_snmp(ip_address: str, timeout_seconds: float, snmp_config: dict) -> dict | None:
    try:
        return await _snmp_get(ip_address, timeout_seconds, snmp_config)
    except Exception:
        return None


# ── SNMP Walk & Topology Neighbor Discovery ─────────────────────────────────

def _build_snmp_auth(snmp_config: dict):
    """Build pysnmp auth_data from config dict. Returns (auth_data, version, port, timeout, retries) or None."""
    if not PYSMNP_AVAILABLE:
        return None
    cfg = snmp_config
    if not cfg.get("enabled", False):
        return None
    version = str(cfg.get("version", "2c"))
    port = int(cfg.get("port", 161))
    retries = int(cfg.get("retries", 0))
    timeout = float(cfg.get("timeout_seconds", 2.0))

    if version == "3":
        v3 = cfg.get("v3", {})
        username = str(v3.get("username", "")).strip()
        auth_password = str(v3.get("auth_password", "")).strip()
        priv_password = str(v3.get("priv_password", "")).strip()
        if not username or not auth_password:
            return None
        auth_map = {
            "md5": usmHMACMD5AuthProtocol, "sha": usmHMACSHAAuthProtocol,
            "sha256": usmHMAC192SHA256AuthProtocol, "sha512": usmHMAC384SHA512AuthProtocol,
        }
        priv_map = {
            "des": usmDESPrivProtocol, "aes128": usmAesCfb128Protocol,
            "aes192": usmAesCfb192Protocol, "aes256": usmAesCfb256Protocol,
        }
        auth_proto = auth_map.get(str(v3.get("auth_protocol", "sha")).lower(), usmHMACSHAAuthProtocol)
        priv_proto = priv_map.get(str(v3.get("priv_protocol", "aes128")).lower(), usmAesCfb128Protocol)
        if priv_password:
            auth_data = UsmUserData(username, authKey=auth_password, privKey=priv_password,
                                    authProtocol=auth_proto, privProtocol=priv_proto)
        else:
            auth_data = UsmUserData(username, authKey=auth_password, authProtocol=auth_proto)
    else:
        community = str(cfg.get("community", "public")).strip()
        if not community:
            return None
        auth_data = CommunityData(community, mpModel=1)

    return auth_data, version, port, timeout, retries


async def _snmp_walk(ip_address: str, timeout_seconds: float, snmp_config: dict,
                     base_oid: str, max_rows: int = 500) -> dict[str, str]:
    """Walk an SNMP OID subtree and return {oid: value} dict."""
    auth_tuple = _build_snmp_auth(snmp_config)
    if auth_tuple is None:
        return {}
    auth_data, _version, port, timeout, retries = auth_tuple
    timeout = max(timeout, timeout_seconds)

    engine = SnmpEngine()
    transport = await UdpTransportTarget.create((ip_address, port), timeout=timeout, retries=retries)
    results: dict[str, str] = {}
    row_count = 0
    try:
        async for error_indication, error_status, _error_index, var_binds in walk_cmd(
            engine, auth_data, transport, ContextData(),
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                break
            for name, value in var_binds:
                oid_str = str(name)
                results[oid_str] = value
            row_count += 1
            if row_count >= max_rows:
                break
    finally:
        engine.close_dispatcher()
    return results


def _parse_cdp_address(raw_value) -> str:
    """Convert CDP cdpCacheAddress (binary) to dotted IPv4 string."""
    try:
        raw_bytes = bytes(raw_value)
        if len(raw_bytes) == 4:
            return socket.inet_ntoa(raw_bytes)
        return raw_bytes.hex()
    except Exception:
        return str(raw_value)


async def _discover_neighbors(host_id: int, ip_address: str, snmp_config: dict,
                              timeout_seconds: float = 5.0) -> tuple[list[dict], list[dict]]:
    """Discover CDP/LLDP/OSPF/BGP neighbors and poll interface counters.

    Returns (neighbors_list, interface_stats_list).
    All independent SNMP walks run in parallel for speed.
    """
    neighbors: list[dict] = []
    _walk = lambda oid: _snmp_walk(ip_address, timeout_seconds, snmp_config, oid)

    # ── Phase 1: Parallel walk of ALL OID groups ──
    # ifName / ifDescr (need ifName first, ifDescr as fallback)
    if_name_oid = "1.3.6.1.2.1.31.1.1.1.1"
    if_descr_oid = "1.3.6.1.2.1.2.2.1.2"

    # Interface counters
    if_hc_in_oid = "1.3.6.1.2.1.31.1.1.1.6"          # ifHCInOctets (64-bit)
    if_hc_out_oid = "1.3.6.1.2.1.31.1.1.1.10"        # ifHCOutOctets (64-bit)
    if_in_octets_oid = "1.3.6.1.2.1.2.2.1.10"         # ifInOctets (32-bit fallback)
    if_out_octets_oid = "1.3.6.1.2.1.2.2.1.16"        # ifOutOctets (32-bit fallback)
    if_high_speed_oid = "1.3.6.1.2.1.31.1.1.1.15"     # ifHighSpeed (Mbps)
    if_speed_oid = "1.3.6.1.2.1.2.2.1.5"              # ifSpeed (bps)

    # CDP OIDs
    cdp_device_id_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
    cdp_address_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
    cdp_port_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
    cdp_platform_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

    # LLDP OIDs
    lldp_sys_name_base = "1.0.8802.1.1.2.1.4.1.1.9"
    lldp_port_id_base = "1.0.8802.1.1.2.1.4.1.1.7"
    lldp_port_desc_base = "1.0.8802.1.1.2.1.4.1.1.8"
    lldp_sys_desc_base = "1.0.8802.1.1.2.1.4.1.1.10"
    lldp_man_addr_base = "1.0.8802.1.1.2.1.4.2.1.4"

    # OSPF OIDs
    ospf_nbr_rtr_id_base = "1.3.6.1.2.1.14.10.1.3"
    ospf_nbr_state_base = "1.3.6.1.2.1.14.10.1.6"

    # BGP OIDs
    bgp_peer_state_base = "1.3.6.1.2.1.15.3.1.2"
    bgp_peer_remote_as_base = "1.3.6.1.2.1.15.3.1.9"

    LOGGER.info("topology: starting parallel SNMP walks for %s (%s)", ip_address, host_id)

    # Fire ALL walks in parallel — one round-trip instead of 17 sequential ones
    (if_names, if_descr,
     hc_in, hc_out, lo_in, lo_out, high_speed_raw, speed_raw,
     cdp_device_ids, cdp_addresses, cdp_ports, cdp_platforms,
     lldp_names, lldp_port_ids, lldp_port_descs, lldp_sys_descs, lldp_man_addrs,
     ospf_rtr_ids, ospf_states,
     bgp_states, bgp_remote_as,
    ) = await asyncio.gather(
        _walk(if_name_oid), _walk(if_descr_oid),
        _walk(if_hc_in_oid), _walk(if_hc_out_oid),
        _walk(if_in_octets_oid), _walk(if_out_octets_oid),
        _walk(if_high_speed_oid), _walk(if_speed_oid),
        _walk(cdp_device_id_base), _walk(cdp_address_base),
        _walk(cdp_port_base), _walk(cdp_platform_base),
        _walk(lldp_sys_name_base), _walk(lldp_port_id_base),
        _walk(lldp_port_desc_base), _walk(lldp_sys_desc_base), _walk(lldp_man_addr_base),
        _walk(ospf_nbr_rtr_id_base), _walk(ospf_nbr_state_base),
        _walk(bgp_peer_state_base), _walk(bgp_peer_remote_as_base),
    )

    LOGGER.info("topology: SNMP walks complete for %s — CDP:%d LLDP:%d OSPF:%d BGP:%d ifStats:%d",
                ip_address, len(cdp_device_ids), len(lldp_names),
                len(ospf_rtr_ids), len(bgp_states), len(hc_in) or len(lo_in))

    # ── Build ifIndex -> interface name map ──
    effective_if_names = if_names or if_descr
    if_index_map: dict[str, str] = {}
    for oid, val in effective_if_names.items():
        parts = oid.rsplit(".", 1)
        if len(parts) == 2:
            if_index_map[parts[1]] = str(val)

    # ── Interface counter stats ──
    # Prefer 64-bit counters, fall back to 32-bit
    in_octets_raw = hc_in or lo_in
    out_octets_raw = hc_out or lo_out
    # Prefer ifHighSpeed (Mbps), fall back to ifSpeed (bps -> Mbps)
    if not high_speed_raw:
        effective_speed = speed_raw
    else:
        effective_speed = high_speed_raw

    if_stats: list[dict] = []
    all_if_indexes = set()
    for oid in list(in_octets_raw.keys()) + list(out_octets_raw.keys()):
        idx = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if idx:
            all_if_indexes.add(idx)

    for idx in all_if_indexes:
        in_val = 0
        out_val = 0
        speed_mbps = 0
        for oid, val in in_octets_raw.items():
            if oid.endswith("." + idx):
                try:
                    in_val = int(val)
                except (ValueError, TypeError):
                    pass
                break
        for oid, val in out_octets_raw.items():
            if oid.endswith("." + idx):
                try:
                    out_val = int(val)
                except (ValueError, TypeError):
                    pass
                break
        for oid, val in effective_speed.items():
            if oid.endswith("." + idx):
                try:
                    raw_speed = int(val)
                    speed_mbps = raw_speed if high_speed_raw else raw_speed // 1_000_000
                except (ValueError, TypeError):
                    pass
                break

        if_stats.append({
            "host_id": host_id,
            "if_index": int(idx),
            "if_name": if_index_map.get(idx, f"ifIndex-{idx}"),
            "if_speed_mbps": speed_mbps,
            "in_octets": in_val,
            "out_octets": out_val,
        })

    # ── CDP Neighbor Parsing ──
    for oid, device_name_val in cdp_device_ids.items():
        suffix = oid[len(cdp_device_id_base):]
        if not suffix:
            continue
        parts = suffix.lstrip(".").split(".")
        if_index = parts[0] if parts else ""
        local_iface = if_index_map.get(if_index, f"ifIndex-{if_index}")

        remote_name = str(device_name_val).strip()
        if "(" in remote_name:
            remote_name = remote_name.split("(")[0].strip()

        addr_oid = cdp_address_base + suffix
        port_oid = cdp_port_base + suffix
        plat_oid = cdp_platform_base + suffix

        remote_ip = ""
        if addr_oid in cdp_addresses:
            remote_ip = _parse_cdp_address(cdp_addresses[addr_oid])

        remote_port = str(cdp_ports.get(port_oid, "")).strip()
        platform = str(cdp_platforms.get(plat_oid, "")).strip()

        neighbors.append({
            "source_host_id": host_id,
            "source_ip": ip_address,
            "local_interface": local_iface,
            "remote_device_name": remote_name,
            "remote_ip": remote_ip,
            "remote_interface": remote_port,
            "protocol": "cdp",
            "remote_platform": platform,
        })

    # ── LLDP Neighbor Parsing ──
    lldp_addr_map: dict[str, str] = {}
    for oid, val in lldp_man_addrs.items():
        suffix = oid[len(lldp_man_addr_base):]
        parts = suffix.lstrip(".").split(".")
        if len(parts) >= 3:
            key = f"{parts[0]}.{parts[1]}.{parts[2]}"
            try:
                raw = bytes(val)
                if len(raw) == 4:
                    lldp_addr_map[key] = socket.inet_ntoa(raw)
            except Exception:
                pass

    for oid, sys_name_val in lldp_names.items():
        suffix = oid[len(lldp_sys_name_base):]
        if not suffix:
            continue
        parts = suffix.lstrip(".").split(".")
        local_port_num = parts[1] if len(parts) >= 2 else ""
        lldp_key = ".".join(parts[:3]) if len(parts) >= 3 else suffix.lstrip(".")

        local_iface = if_index_map.get(local_port_num, f"port-{local_port_num}")
        remote_name = str(sys_name_val).strip()

        port_id_oid = lldp_port_id_base + suffix
        port_desc_oid = lldp_port_desc_base + suffix
        sys_desc_oid = lldp_sys_desc_base + suffix

        remote_port_raw = str(lldp_port_ids.get(port_id_oid, "")).strip()
        remote_port_desc = str(lldp_port_descs.get(port_desc_oid, "")).strip()
        remote_port = remote_port_desc or remote_port_raw

        sys_desc = str(lldp_sys_descs.get(sys_desc_oid, "")).strip()
        remote_ip = lldp_addr_map.get(lldp_key, "")

        already_found = any(
            n["remote_device_name"].lower() == remote_name.lower()
            and n["local_interface"] == local_iface
            for n in neighbors
        )
        if already_found:
            continue

        neighbors.append({
            "source_host_id": host_id,
            "source_ip": ip_address,
            "local_interface": local_iface,
            "remote_device_name": remote_name or f"lldp-{remote_port_raw}",
            "remote_ip": remote_ip,
            "remote_interface": remote_port,
            "protocol": "lldp",
            "remote_platform": sys_desc[:200] if sys_desc else "",
        })

    # ── OSPF Neighbor Parsing ──
    for oid, rtr_id_val in ospf_rtr_ids.items():
        suffix = oid[len(ospf_nbr_rtr_id_base):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) >= 4:
            nbr_ip = ".".join(parts[:4])
        else:
            continue

        rtr_id = str(rtr_id_val).strip()
        state_oid = ospf_nbr_state_base + "." + suffix
        state_val = str(ospf_states.get(state_oid, "")).strip()

        already_found = any(n["remote_ip"] == nbr_ip for n in neighbors)
        if already_found:
            continue

        neighbors.append({
            "source_host_id": host_id,
            "source_ip": ip_address,
            "local_interface": "",
            "remote_device_name": rtr_id or nbr_ip,
            "remote_ip": nbr_ip,
            "remote_interface": "",
            "protocol": "ospf",
            "remote_platform": f"OSPF state={state_val}" if state_val else "",
        })

    # ── BGP Peer Parsing ──
    for oid, state_val in bgp_states.items():
        suffix = oid[len(bgp_peer_state_base):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) >= 4:
            peer_ip = ".".join(parts[:4])
        else:
            continue

        as_oid = bgp_peer_remote_as_base + "." + suffix
        remote_as = str(bgp_remote_as.get(as_oid, "")).strip()

        already_found = any(n["remote_ip"] == peer_ip for n in neighbors)
        if already_found:
            continue

        neighbors.append({
            "source_host_id": host_id,
            "source_ip": ip_address,
            "local_interface": "",
            "remote_device_name": f"AS{remote_as}" if remote_as else peer_ip,
            "remote_ip": peer_ip,
            "remote_interface": "",
            "protocol": "bgp",
            "remote_platform": f"AS {remote_as}, state={state_val}" if remote_as else "",
        })

    return neighbors, if_stats


async def _discover_hosts(request: DiscoveryScanRequest, group_id: int | None = None) -> tuple[int, list[dict]]:
    targets = _expand_scan_targets(request.cidrs, request.max_hosts)
    semaphore = asyncio.Semaphore(max(1, DISCOVERY_MAX_CONCURRENT_PROBES))
    snmp_cfg = _resolve_snmp_discovery_config(group_id)

    async def _scan_one(ip_address: str) -> dict | None:
        async with semaphore:
            return await _probe_discovery_target(
                ip_address=ip_address,
                timeout_seconds=request.timeout_seconds,
                device_type=request.device_type,
                hostname_prefix=request.hostname_prefix,
                use_snmp=request.use_snmp,
                snmp_config=snmp_cfg,
            )

    discovered_raw = await asyncio.gather(*[_scan_one(ip) for ip in targets])
    discovered = [item for item in discovered_raw if item is not None]
    discovered.sort(key=lambda item: ipaddress.ip_address(item["ip_address"]))
    return len(targets), discovered


async def _sync_group_hosts(
    group_id: int,
    discovered_hosts: list[dict],
    remove_absent: bool = False,
) -> dict:
    existing_hosts = await db.get_hosts_for_group(group_id)
    existing_by_ip = {str(host["ip_address"]): host for host in existing_hosts}

    normalized_discovered: dict[str, dict] = {}
    for host in discovered_hosts:
        ip = str(host.get("ip_address", "")).strip()
        if not ip:
            continue
        normalized_discovered[ip] = {
            "hostname": str(host.get("hostname") or "").strip() or f"host-{ip.replace('.', '-')}",
            "ip_address": ip,
            "device_type": str(host.get("device_type") or "unknown").strip() or "unknown",
            "status": str(host.get("status") or "online").strip() or "online",
        }

    added = 0
    updated = 0
    removed = 0

    for ip, discovered in normalized_discovered.items():
        existing = existing_by_ip.get(ip)
        if existing is None:
            new_id = await db.add_host(group_id, discovered["hostname"], discovered["ip_address"], discovered["device_type"])
            await db.update_host_status(new_id, discovered["status"])
            added += 1
            continue

        if (
            existing.get("hostname") != discovered["hostname"]
            or existing.get("device_type") != discovered["device_type"]
        ):
            await db.update_host(existing["id"], discovered["hostname"], discovered["ip_address"], discovered["device_type"])
            updated += 1
        await db.update_host_status(existing["id"], discovered["status"])

    if remove_absent:
        discovered_ips = set(normalized_discovered)
        for ip, existing in existing_by_ip.items():
            if ip in discovered_ips:
                continue
            await db.remove_host(existing["id"])
            removed += 1

    return {
        "added": added,
        "updated": updated,
        "removed": removed,
        "matched": len(normalized_discovered),
        "existing_before": len(existing_hosts),
        "existing_after": len(existing_hosts) + added - removed,
    }


@app.post("/api/inventory/{group_id}/discovery/scan", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def discovery_scan(group_id: int, body: DiscoveryScanRequest):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    scanned_count, discovered = await _discover_hosts(body, group_id=group_id)
    return {
        "group_id": group_id,
        "scanned_hosts": scanned_count,
        "discovered_count": len(discovered),
        "discovered_hosts": discovered,
    }


@app.post("/api/inventory/{group_id}/discovery/scan/stream", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def discovery_scan_stream(group_id: int, body: DiscoveryScanRequest):
    """SSE streaming scan — yields per-host results as they complete."""
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")

    targets = _expand_scan_targets(body.cidrs, body.max_hosts)
    total = len(targets)
    semaphore = asyncio.Semaphore(max(1, DISCOVERY_MAX_CONCURRENT_PROBES))
    snmp_cfg = _resolve_snmp_discovery_config(group_id)

    async def _scan_one(ip_address: str) -> tuple[str, dict | None]:
        async with semaphore:
            result = await _probe_discovery_target(
                ip_address=ip_address,
                timeout_seconds=body.timeout_seconds,
                device_type=body.device_type,
                hostname_prefix=body.hostname_prefix,
                use_snmp=body.use_snmp,
                snmp_config=snmp_cfg,
            )
            return ip_address, result

    async def event_generator():
        # Send initial metadata
        yield f"data: {json.dumps({'type': 'start', 'total': total})}\n\n"

        scanned = 0
        discovered = []
        tasks = [asyncio.create_task(_scan_one(ip)) for ip in targets]

        for coro in asyncio.as_completed(tasks):
            ip_address, result = await coro
            scanned += 1
            if result is not None:
                discovered.append(result)
            yield f"data: {json.dumps({'type': 'progress', 'scanned': scanned, 'total': total, 'ip': ip_address, 'found': result is not None, 'host': result})}\n\n"

        discovered.sort(key=lambda item: ipaddress.ip_address(item["ip_address"]))
        yield f"data: {json.dumps({'type': 'done', 'scanned_hosts': total, 'discovered_count': len(discovered), 'discovered_hosts': discovered})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/inventory/{group_id}/snmp-discovery-profile", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def get_group_snmp_discovery_profile(group_id: int):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    profile = SNMP_DISCOVERY_PROFILES.get(group_id)
    if profile:
        return profile
    return _sanitize_snmp_discovery_profile(group_id, {})


@app.put("/api/inventory/{group_id}/snmp-discovery-profile", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def update_group_snmp_discovery_profile(group_id: int, body: dict):
    global SNMP_DISCOVERY_PROFILES
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    profile = _sanitize_snmp_discovery_profile(group_id, body)
    SNMP_DISCOVERY_PROFILES[group_id] = profile
    await db.set_auth_setting("snmp_discovery_profiles", SNMP_DISCOVERY_PROFILES)
    return profile


@app.post("/api/inventory/{group_id}/snmp-discovery-profile/test", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def test_group_snmp_profile(group_id: int, body: dict):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    target_ip = str(body.get("target_ip", "")).strip()
    if not target_ip:
        raise HTTPException(400, "target_ip is required")
    snmp_config = _resolve_snmp_discovery_config(group_id)
    if not snmp_config.get("enabled"):
        raise HTTPException(400, "SNMP is not enabled for this group")
    timeout = float(snmp_config.get("timeout_seconds", 1.2))
    try:
        result = await _snmp_get(target_ip, timeout, snmp_config)
    except Exception as exc:
        return {"success": False, "target_ip": target_ip, "error": str(exc)}
    if result is None:
        return {"success": False, "target_ip": target_ip, "error": "SNMP query failed — no response or bad credentials"}
    return {"success": True, "target_ip": target_ip, "result": result}


@app.post("/api/inventory/{group_id}/discovery/sync", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def discovery_sync(group_id: int, body: DiscoverySyncRequest, request: Request):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")

    scanned_count, discovered = await _discover_hosts(body, group_id=group_id)
    sync_result = await _sync_group_hosts(group_id, discovered, remove_absent=body.remove_absent)
    session = _get_session(request)
    audit_user = session["user"] if session else "api-token"

    await _audit(
        "inventory",
        "discovery.sync",
        user=audit_user,
        detail=(
            f"group_id={group_id} scanned={scanned_count} discovered={len(discovered)} "
            f"added={sync_result['added']} updated={sync_result['updated']} removed={sync_result['removed']}"
        ),
        correlation_id=_corr_id(request),
    )

    return {
        "group_id": group_id,
        "scanned_hosts": scanned_count,
        "discovered_count": len(discovered),
        "sync": sync_result,
    }


@app.post("/api/inventory/{group_id}/discovery/onboard", dependencies=[Depends(require_auth), Depends(require_feature("inventory"))])
async def discovery_onboard(group_id: int, body: DiscoveryOnboardRequest, request: Request):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    if not body.discovered_hosts:
        raise HTTPException(400, "No discovered hosts provided")

    sync_result = await _sync_group_hosts(group_id, body.discovered_hosts, remove_absent=False)
    session = _get_session(request)
    audit_user = session["user"] if session else "api-token"
    await _audit(
        "inventory",
        "discovery.onboard",
        user=audit_user,
        detail=(
            f"group_id={group_id} provided={len(body.discovered_hosts)} "
            f"added={sync_result['added']} updated={sync_result['updated']}"
        ),
        correlation_id=_corr_id(request),
    )
    return {
        "group_id": group_id,
        "provided_count": len(body.discovered_hosts),
        "sync": sync_result,
    }


# ═════════════════════════════════════════════════════════════════════════════
# Playbooks
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/playbooks/{playbook_id}", dependencies=[Depends(require_auth), Depends(require_feature("playbooks"))])
async def get_playbook(playbook_id: int):
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    
    # Ensure content is always a string (handle None case)
    content = playbook.get("content")
    if content is None:
        content = ""
    
    # If content is empty, try to load it from the file
    if not content or content.strip() == "":
        playbooks_dir = os.path.join(project_root, "templates", "playbooks")
        filename = playbook["filename"]
        if not filename.endswith('.py'):
            filename += '.py'
        file_path = os.path.join(playbooks_dir, filename)
        
        if os.path.exists(file_path):
            try:
                with open(file_path, encoding='utf-8') as f:
                    file_content = f.read()
                    playbook["content"] = file_content
                # Sync it back to the database
                await db.update_playbook(playbook_id, content=file_content)
                LOGGER.info("Loaded playbook content from file: %s (%s chars)", filename, len(file_content))
            except Exception as e:
                LOGGER.warning("Failed to read playbook file %s: %s", file_path, e)
                playbook["content"] = ""
        else:
            LOGGER.warning("Playbook file not found: %s", file_path)
            playbook["content"] = ""
    else:
        LOGGER.debug("Using playbook content from database (length: %s)", len(content))
    
    # Ensure content is always set (even if empty)
    if "content" not in playbook:
        playbook["content"] = ""
    
    return playbook


@app.get("/api/playbooks", dependencies=[Depends(require_auth), Depends(require_feature("playbooks"))])
async def list_playbooks():
    # Sync registered playbooks that might be missing from database
    await sync_playbooks_from_registry()
    return await db.get_all_playbooks()


async def sync_playbooks_from_registry():
    """Sync playbooks from the registry to the database - add any missing ones."""
    from routes.database import sync_playbook_filename
    from routes.runner import list_registered_playbooks
    
    registered = list_registered_playbooks()
    db_playbooks = await db.get_all_playbooks()
    db_filenames = {pb["filename"] for pb in db_playbooks}
    
    for pb in registered:
        if pb["filename"] not in db_filenames:
            # Check if a playbook with the same name exists (might have different filename)
            existing = next((p for p in db_playbooks if p["name"] == pb["name"]), None)
            if existing:
                # Update the filename
                try:
                    await sync_playbook_filename(pb["name"], pb["filename"])
                    LOGGER.info("sync: updated filename for '%s' to '%s'", pb['name'], pb['filename'])
                except Exception as e:
                    LOGGER.warning("sync: error syncing filename for '%s': %s", pb['name'], e)
            else:
                # Create new playbook
                try:
                    await db.create_playbook(pb["name"], pb["filename"], pb["description"], pb["tags"])
                    LOGGER.info("sync: added missing playbook '%s' (%s)", pb['name'], pb['filename'])
                except Exception as e:
                    LOGGER.warning("sync: error adding playbook '%s': %s", pb['name'], e)


@app.post("/api/playbooks", status_code=201, dependencies=[Depends(require_auth), Depends(require_feature("playbooks"))])
async def create_playbook(body: PlaybookCreate, request: Request = None):
    # Validate and normalise filename (raises ValueError on bad input)
    try:
        filename = _sanitize_playbook_filename(body.filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Write the playbook file
    if body.content:
        write_playbook_file(filename, body.content)

    pid = await db.create_playbook(body.name, filename, body.description, body.tags, body.content)
    session = _get_session(request) if request else None
    await _audit("config", "playbook.create", user=session["user"] if session else "", detail=f"created playbook '{body.name}'", correlation_id=_corr_id(request))
    return {"id": pid}


@app.put("/api/playbooks/{playbook_id}", dependencies=[Depends(require_auth), Depends(require_feature("playbooks"))])
async def update_playbook(playbook_id: int, body: PlaybookUpdate, request: Request = None):
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")

    # Validate filename if provided
    update_filename = None
    if body.filename is not None:
        try:
            update_filename = _sanitize_playbook_filename(body.filename)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    # If content is being updated, write the file
    if body.content is not None:
        target_filename = update_filename or playbook["filename"]
        write_playbook_file(target_filename, body.content)
    
    await db.update_playbook(
        playbook_id,
        name=body.name,
        filename=update_filename,
        description=body.description,
        tags=body.tags,
        content=body.content
    )
    session = _get_session(request) if request else None
    await _audit("config", "playbook.update", user=session["user"] if session else "", detail=f"updated playbook {playbook_id}", correlation_id=_corr_id(request))
    return {"ok": True}


@app.delete("/api/playbooks/{playbook_id}", dependencies=[Depends(require_auth), Depends(require_feature("playbooks"))])
async def delete_playbook(playbook_id: int, request: Request = None):
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    
    # Optionally delete the file (but keep it for now in case of rollback)
    await db.delete_playbook(playbook_id)
    session = _get_session(request) if request else None
    await _audit("config", "playbook.delete", user=session["user"] if session else "", detail=f"deleted playbook {playbook_id} ('{playbook['name']}')", correlation_id=_corr_id(request))
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# Templates
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/templates", dependencies=[Depends(require_auth), Depends(require_feature("templates"))])
async def list_templates():
    return await db.get_all_templates()


@app.post("/api/templates", status_code=201, dependencies=[Depends(require_auth), Depends(require_feature("templates"))])
async def create_template(body: TemplateCreate, request: Request = None):
    tid = await db.create_template(body.name, body.content, body.description)
    session = _get_session(request) if request else None
    await _audit("config", "template.create", user=session["user"] if session else "", detail=f"created template '{body.name}'", correlation_id=_corr_id(request))
    return {"id": tid}


@app.get("/api/templates/{template_id}", dependencies=[Depends(require_auth), Depends(require_feature("templates"))])
async def get_template(template_id: int):
    tpl = await db.get_template(template_id)
    if not tpl:
        raise HTTPException(404, "Template not found")
    return tpl


@app.put("/api/templates/{template_id}", dependencies=[Depends(require_auth), Depends(require_feature("templates"))])
async def update_template(template_id: int, body: TemplateUpdate, request: Request = None):
    await db.update_template(template_id, body.name, body.content, body.description)
    session = _get_session(request) if request else None
    await _audit("config", "template.update", user=session["user"] if session else "", detail=f"updated template {template_id}", correlation_id=_corr_id(request))
    return {"ok": True}


@app.delete("/api/templates/{template_id}", dependencies=[Depends(require_auth), Depends(require_feature("templates"))])
async def delete_template(template_id: int, request: Request = None):
    await db.delete_template(template_id)
    session = _get_session(request) if request else None
    await _audit("config", "template.delete", user=session["user"] if session else "", detail=f"deleted template {template_id}", correlation_id=_corr_id(request))
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# Credentials
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/credentials", dependencies=[Depends(require_auth), Depends(require_feature("credentials"))])
async def list_credentials(request: Request):
    session = _get_session(request)
    owner_id = session["user_id"] if session else None
    return await db.get_all_credentials(owner_id=owner_id)


@app.post("/api/credentials", status_code=201, dependencies=[Depends(require_auth), Depends(require_feature("credentials"))])
async def create_credential(body: CredentialCreate, request: Request):
    session = _get_session(request)
    owner_id = session["user_id"] if session else None
    cid = await db.create_credential(
        body.name, body.username,
        encrypt(body.password),
        encrypt(body.secret) if body.secret else encrypt(body.password),
        owner_id=owner_id,
    )
    await _audit("config", "credential.create", user=session["user"] if session else "", detail=f"created credential '{body.name}'", correlation_id=_corr_id(request))
    return {"id": cid}


@app.delete("/api/credentials/{cred_id}", dependencies=[Depends(require_auth), Depends(require_feature("credentials"))])
async def delete_credential(cred_id: int, request: Request):
    session = _get_session(request)
    cred = await db.get_credential_raw(cred_id)
    if not cred:
        raise HTTPException(404, "Credential not found")
    if cred.get("owner_id") and session and cred["owner_id"] != session["user_id"]:
        raise HTTPException(403, "You can only delete your own credentials")
    await db.delete_credential(cred_id)
    await _audit("config", "credential.delete", user=session["user"] if session else "", detail=f"deleted credential {cred_id}", correlation_id=_corr_id(request))
    return {"ok": True}


@app.put("/api/credentials/{cred_id}", dependencies=[Depends(require_auth), Depends(require_feature("credentials"))])
async def update_credential(cred_id: int, body: CredentialUpdate, request: Request):
    session = _get_session(request)
    cred = await db.get_credential_raw(cred_id)
    if not cred:
        raise HTTPException(404, "Credential not found")
    if cred.get("owner_id") and session and cred["owner_id"] != session["user_id"]:
        raise HTTPException(403, "You can only edit your own credentials")
    updates = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.username is not None:
        updates["username"] = body.username
    if body.password is not None and body.password != "":
        updates["enc_password"] = encrypt(body.password)
    if body.secret is not None and body.secret != "":
        updates["enc_secret"] = encrypt(body.secret)
    if not updates:
        return {"ok": True}
    await db.update_credential(
        cred_id,
        name=updates.get("name"),
        username=updates.get("username"),
        enc_password=updates.get("enc_password"),
        enc_secret=updates.get("enc_secret"),
    )
    await _audit("config", "credential.update", user=session["user"] if session else "", detail=f"updated credential {cred_id}", correlation_id=_corr_id(request))
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# Jobs
# ═════════════════════════════════════════════════════════════════════════════

# Active WebSocket connections keyed by job_id
_job_sockets: dict[int, list[WebSocket]] = {}


@app.get("/api/jobs", dependencies=[Depends(require_auth), Depends(require_feature("jobs"))])
async def list_jobs(limit: int = Query(50, ge=1, le=200)):
    return await db.get_all_jobs(limit=limit)


@app.get("/api/jobs/{job_id}", dependencies=[Depends(require_auth), Depends(require_feature("jobs"))])
async def get_job(job_id: int):
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@app.get("/api/jobs/{job_id}/events", dependencies=[Depends(require_auth), Depends(require_feature("jobs"))])
async def get_job_events(job_id: int):
    return await db.get_job_events(job_id)


@app.post("/api/jobs/launch", status_code=201, dependencies=[Depends(require_auth), Depends(require_feature("jobs"))])
async def launch_job(body: JobLaunch, request: Request):
    """
    Launch a playbook execution as a background task.
    Returns the job ID immediately. Connect to the WebSocket
    at /ws/jobs/{job_id} to stream real-time output.
    """
    session = _get_session(request)
    LOGGER.debug("JobLaunch request: playbook_id=%s host_ids=%s inventory_group_id=%s", body.playbook_id, body.host_ids, body.inventory_group_id)
    
    # Validate playbook exists
    playbook = await db.get_playbook(body.playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")

    # Get hosts - either from selected host_ids or from inventory_group_id
    hosts = []
    inventory_group_id = None
    
    if body.host_ids and len(body.host_ids) > 0:
        hosts = await db.get_hosts_by_ids(body.host_ids)
        if not hosts:
            raise HTTPException(400, "No valid hosts selected")
        if hosts:
            inventory_group_id = hosts[0].get("group_id")
    elif body.inventory_group_id:
        group = await db.get_group(body.inventory_group_id)
        if not group:
            raise HTTPException(404, "Inventory group not found")
        hosts = await db.get_hosts_for_group(body.inventory_group_id)
        if not hosts:
            raise HTTPException(400, "No hosts in inventory group")
        inventory_group_id = body.inventory_group_id
    else:
        raise HTTPException(400, "Must specify either host_ids or inventory_group_id")

    # Get credentials — verify the user owns the selected credential
    credentials = {"username": "netadmin", "password": "cisco123", "secret": "cisco123"}
    if body.credential_id:
        cred = await db.get_credential_raw(body.credential_id)
        if not cred:
            raise HTTPException(404, "Credential not found")
        if cred.get("owner_id") and session and cred["owner_id"] != session["user_id"]:
            raise HTTPException(403, "You can only use your own credentials")
        if cred:
            credentials = {
                "username": cred["username"],
                "password": decrypt(cred["password"]),
                "secret": decrypt(cred["secret"]) if cred["secret"] else "",
            }

    # Get template commands
    template_commands = []
    if body.template_id:
        tpl = await db.get_template(body.template_id)
        if tpl:
            template_commands = [
                line.rstrip() for line in tpl["content"].splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]

    # Find the playbook runner class
    pb_class = get_playbook_class(playbook["filename"])
    if not pb_class:
        raise HTTPException(400, f"No runner registered for '{playbook['filename']}'")

    launched_by = session["user"] if session else "admin"
    job_id = await db.create_job(
        body.playbook_id, inventory_group_id,
        body.credential_id, body.template_id,
        body.dry_run, launched_by=launched_by,
    )

    # Launch as background task
    asyncio.create_task(_run_job(
        job_id, pb_class, hosts, credentials, template_commands, body.dry_run
    ))

    await _audit("jobs", "job.launch", user=launched_by, detail=f"launched job {job_id} playbook='{playbook['name']}' hosts={len(hosts)} dry_run={body.dry_run}", correlation_id=_corr_id(request))
    return {"job_id": job_id, "status": "running"}


async def _run_job(
    job_id: int,
    pb_class: type,
    hosts: list[dict],
    credentials: dict,
    template_commands: list[str],
    dry_run: bool,
):
    """Background task: execute playbook, store events, broadcast via WebSocket."""
    async with _job_semaphore:
        hosts_ok = 0
        hosts_failed = 0

        async def on_event(event: LogEvent):
            nonlocal hosts_ok, hosts_failed

            # Persist event
            await db.add_job_event(job_id, event.level, event.message, event.host)

            # Track host results
            if event.level == "success" and "Finished processing" in event.message:
                hosts_ok += 1
            elif event.level == "error" and event.host:
                hosts_failed += 1

            # Broadcast to WebSocket subscribers
            sockets = _job_sockets.get(job_id, [])
            dead = []
            for ws in sockets:
                try:
                    await ws.send_json(event.to_dict())
                except Exception:
                    dead.append(ws)
            for ws in dead:
                sockets.remove(ws)

        try:
            result = await execute_playbook(
                pb_class, hosts, credentials, template_commands, dry_run, on_event
            )
            await db.finish_job(
                job_id,
                status=result.status,
                hosts_ok=hosts_ok,
                hosts_failed=hosts_failed,
                hosts_skipped=result.hosts_skipped,
            )
        except Exception as e:
            await db.finish_job(job_id, status="failed", hosts_failed=len(hosts))
            await on_event(LogEvent(level="error", message=f"Fatal error: {e}"))

        # Notify WebSocket clients that job is done
        done_msg = {"type": "job_complete", "job_id": job_id, "status": "done"}
        sockets = _job_sockets.pop(job_id, [])
        for ws in sockets:
            try:
                await ws.send_json(done_msg)
            except Exception:
                pass


# ── WebSocket for live job streaming ─────────────────────────────────────────

@app.websocket("/ws/jobs/{job_id}")
async def websocket_job(websocket: WebSocket, job_id: int):
    """
    Stream job events in real-time.

    1. Client connects to /ws/jobs/{job_id}
    2. Server immediately sends all existing events for the job
    3. Server streams new events as they arrive
    4. Server sends {"type": "job_complete"} when done
    """
    token = websocket.cookies.get("session")
    session = verify_session_token(token) if token else None
    if not session:
        await websocket.close(code=1008)
        return

    user = await db.get_user_by_id(session["user_id"])
    if not user:
        await websocket.close(code=1008)
        return

    features = await _get_user_features(user)
    if user.get("role") != "admin" and "jobs" not in features:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    # Send historical events first
    events = await db.get_job_events(job_id)
    for event in events:
        await websocket.send_json({
            "level": event["level"],
            "message": event["message"],
            "host": event["host"],
            "timestamp": event["timestamp"],
        })

    # Check if job is already done
    job = await db.get_job(job_id)
    if job and job["status"] not in ("running", "pending"):
        await websocket.send_json({
            "type": "job_complete", "job_id": job_id, "status": job["status"]
        })
        await websocket.close()
        return

    # Subscribe to live events
    if job_id not in _job_sockets:
        _job_sockets[job_id] = []
    _job_sockets[job_id].append(websocket)

    try:
        # Keep connection alive until client disconnects
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if job_id in _job_sockets and websocket in _job_sockets[job_id]:
            _job_sockets[job_id].remove(websocket)


# ── WebSocket for live converter job streaming (import / cleanup) ─────────────

@app.websocket("/ws/converter-jobs/{job_id}")
async def websocket_converter_job(websocket: WebSocket, job_id: str):
    """
    Stream converter import/cleanup job output in real-time.

    1. Client connects to /ws/converter-jobs/{job_id}
    2. Server immediately sends all accumulated output lines
    3. If job is already complete, sends job_complete and closes
    4. Otherwise streams new lines as they arrive, then sends job_complete
    """
    from netcontrol.routes.converter import _converter_jobs, _converter_job_sockets

    token = websocket.cookies.get("session")
    session = verify_session_token(token) if token else None
    if not session:
        await websocket.close(code=1008)
        return

    user = await db.get_user_by_id(session["user_id"])
    if not user:
        await websocket.close(code=1008)
        return

    features = await _get_user_features(user)
    if user.get("role") != "admin" and "converter" not in features:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    job = _converter_jobs.get(job_id)
    if not job:
        await websocket.send_json({"type": "error", "message": "Job not found"})
        await websocket.close()
        return

    # Replay all accumulated output so reconnecting clients catch up
    for line in list(job.get("output_lines", [])):
        await websocket.send_json({"type": "line", "text": line})

    # If job is already done, notify and close immediately
    if job["status"] not in ("running", "pending"):
        await websocket.send_json({"type": "job_complete", "job_id": job_id, "status": job["status"]})
        await websocket.close()
        return

    # Subscribe to live events
    if job_id not in _converter_job_sockets:
        _converter_job_sockets[job_id] = []
    _converter_job_sockets[job_id].append(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if job_id in _converter_job_sockets and websocket in _converter_job_sockets[job_id]:
            _converter_job_sockets[job_id].remove(websocket)


# ═════════════════════════════════════════════════════════════════════════════
# Topology
# ═════════════════════════════════════════════════════════════════════════════


async def _record_topology_changes(
    host: dict,
    old_link_keys: set[tuple],
    new_link_keys: set[tuple],
    new_neighbors: list[dict],
    old_links: list[dict],
) -> None:
    """Compare old vs new link keys and record added/removed changes."""
    hostname = host.get("hostname", "")

    # Links that were removed (present before, gone now)
    removed_keys = old_link_keys - new_link_keys
    for key in removed_keys:
        _src_id, src_iface, tgt_name, tgt_iface = key
        # Find protocol from old links
        protocol = ""
        target_ip = ""
        for ol in old_links:
            if (ol["source_host_id"] == key[0] and ol["source_interface"] == src_iface
                    and ol["target_device_name"] == tgt_name and ol["target_interface"] == tgt_iface):
                protocol = ol.get("protocol", "")
                target_ip = ol.get("target_ip", "")
                break
        await db.insert_topology_change(
            change_type="removed",
            source_host_id=host["id"],
            source_hostname=hostname,
            source_interface=src_iface,
            target_device_name=tgt_name,
            target_interface=tgt_iface,
            target_ip=target_ip,
            protocol=protocol,
        )

    # Links that were added (not present before, present now)
    added_keys = new_link_keys - old_link_keys
    for key in added_keys:
        _src_id, src_iface, tgt_name, tgt_iface = key
        protocol = ""
        target_ip = ""
        for n in new_neighbors:
            if (n["source_host_id"] == key[0] and n["local_interface"] == src_iface
                    and n["remote_device_name"] == tgt_name and n["remote_interface"] == tgt_iface):
                protocol = n.get("protocol", "")
                target_ip = n.get("remote_ip", "")
                break
        await db.insert_topology_change(
            change_type="added",
            source_host_id=host["id"],
            source_hostname=hostname,
            source_interface=src_iface,
            target_device_name=tgt_name,
            target_interface=tgt_iface,
            target_ip=target_ip,
            protocol=protocol,
        )


def _calc_interface_utilization(stat: dict) -> dict | None:
    """Calculate utilization percentage from two counter snapshots."""
    if not stat.get("prev_polled_at") or not stat.get("polled_at"):
        return None
    try:
        from datetime import datetime as _dt
        t1 = _dt.fromisoformat(stat["prev_polled_at"])
        t2 = _dt.fromisoformat(stat["polled_at"])
        delta_sec = (t2 - t1).total_seconds()
        if delta_sec <= 0:
            return None
        speed_bps = (stat.get("if_speed_mbps") or 0) * 1_000_000
        if speed_bps <= 0:
            return None

        in_delta = stat["in_octets"] - stat["prev_in_octets"]
        out_delta = stat["out_octets"] - stat["prev_out_octets"]
        # Handle 32/64-bit counter wraps
        if in_delta < 0:
            in_delta += 2**32
        if out_delta < 0:
            out_delta += 2**32

        in_bps = (in_delta * 8) / delta_sec
        out_bps = (out_delta * 8) / delta_sec
        in_pct = min(100.0, (in_bps / speed_bps) * 100)
        out_pct = min(100.0, (out_bps / speed_bps) * 100)
        util_pct = max(in_pct, out_pct)

        return {
            "in_bps": round(in_bps),
            "out_bps": round(out_bps),
            "in_pct": round(in_pct, 1),
            "out_pct": round(out_pct, 1),
            "utilization_pct": round(util_pct, 1),
            "speed_mbps": stat.get("if_speed_mbps", 0),
        }
    except Exception:
        return None


@app.get("/api/topology", dependencies=[Depends(require_auth), Depends(require_feature("topology"))])
async def get_topology(group_id: int | None = Query(default=None)):
    """Return topology graph data (nodes + edges) for vis-network rendering."""
    try:
        links = await db.get_topology_links(group_id)

        # Build node set from hosts in groups + external neighbors
        nodes_by_id: dict[str | int, dict] = {}
        edges: list[dict] = []

        # Gather all host IDs referenced as sources
        source_host_ids = {link["source_host_id"] for link in links}
        # Also gather resolved target host IDs
        target_host_ids = {link["target_host_id"] for link in links if link.get("target_host_id")}
        all_host_ids = source_host_ids | target_host_ids

        # Fetch all referenced inventory hosts
        if all_host_ids:
            hosts = await db.get_hosts_by_ids(list(all_host_ids))
        else:
            hosts = []

        # If filtering by group, also include all hosts in that group as nodes
        if group_id is not None:
            group_hosts = await db.get_hosts_for_group(group_id)
            for h in group_hosts:
                if h["id"] not in {hh["id"] for hh in hosts}:
                    hosts.append(h)

        # Fetch group names
        groups = await db.get_all_groups()
        group_name_map = {g["id"]: g["name"] for g in groups}

        # Build inventory nodes
        for h in hosts:
            nodes_by_id[h["id"]] = {
                "id": h["id"],
                "label": h["hostname"],
                "ip": h["ip_address"],
                "device_type": h["device_type"],
                "group_id": h["group_id"],
                "group_name": group_name_map.get(h["group_id"], ""),
                "status": h["status"],
                "in_inventory": True,
            }

        # Fetch interface stats for utilization overlay
        all_stats = await db.get_interface_stats_by_hosts(list(all_host_ids)) if all_host_ids else []
        # Build lookup: (host_id, if_name) -> utilization data
        util_map: dict[tuple[int, str], dict] = {}
        for stat in all_stats:
            util = _calc_interface_utilization(stat)
            if util:
                util_map[(stat["host_id"], stat["if_name"])] = util

        # Fetch unacknowledged change count
        change_count = await db.get_topology_changes_count(unacknowledged_only=True)

        # Build edges + external nodes
        for link in links:
            src_id = link["source_host_id"]
            tgt_host_id = link.get("target_host_id")
            tgt_name = link.get("target_device_name", "")
            tgt_ip = link.get("target_ip", "")

            if tgt_host_id and tgt_host_id in nodes_by_id:
                tgt_id = tgt_host_id
            else:
                # External neighbor — use string ID
                ext_key = f"ext_{tgt_name}" if tgt_name else f"ext_{tgt_ip}"
                tgt_id = ext_key
                if ext_key not in nodes_by_id:
                    nodes_by_id[ext_key] = {
                        "id": ext_key,
                        "label": tgt_name or tgt_ip or "unknown",
                        "ip": tgt_ip,
                        "device_type": "unknown",
                        "group_id": None,
                        "group_name": "",
                        "status": "unknown",
                        "in_inventory": False,
                        "platform": link.get("target_platform", ""),
                    }

            src_iface = link.get("source_interface", "")
            tgt_iface = link.get("target_interface", "")
            label_parts = []
            if src_iface:
                label_parts.append(src_iface)
            if tgt_iface:
                label_parts.append(tgt_iface)
            edge_label = " -- ".join(label_parts) if label_parts else ""

            edge_data = {
                "id": link["id"],
                "from": src_id,
                "to": tgt_id,
                "label": edge_label,
                "protocol": link.get("protocol", "cdp"),
                "source_interface": src_iface,
                "target_interface": tgt_iface,
            }

            # Attach utilization data if available (use source interface stats)
            util = util_map.get((src_id, src_iface))
            if util:
                edge_data["utilization"] = util

            edges.append(edge_data)

        return {
            "nodes": list(nodes_by_id.values()),
            "edges": edges,
            "unacknowledged_changes": change_count,
        }
    except Exception as exc:
        LOGGER.error("topology: failed to build graph: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/topology/discover/{group_id}",
          dependencies=[Depends(require_auth), Depends(require_feature("topology"))])
async def discover_topology_for_group(group_id: int):
    """Run CDP/LLDP neighbor discovery on all hosts in a group."""
    try:
        group = await db.get_group(group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        hosts = await db.get_hosts_for_group(group_id)
        if not hosts:
            return {"hosts_scanned": 0, "links_discovered": 0, "errors": 0}

        snmp_cfg = _resolve_snmp_discovery_config(group_id)
        if not snmp_cfg.get("enabled", False):
            raise HTTPException(status_code=400,
                                detail="SNMP is not enabled for this group. Configure an SNMP profile first.")

        LOGGER.info("topology: starting discovery for group %d (%s) — %d hosts",
                     group_id, group.get("name", "?"), len(hosts))

        semaphore = asyncio.Semaphore(max(1, DISCOVERY_MAX_CONCURRENT_PROBES))
        errors = 0
        total_links = 0

        # Phase 1: concurrent SNMP walks (no DB writes)
        async def _walk_host(host: dict) -> tuple[dict, list[dict] | None, list[dict]]:
            async with semaphore:
                try:
                    LOGGER.info("topology: walking %s (%s)...", host["hostname"], host["ip_address"])
                    neighbors, if_stats = await _discover_neighbors(
                        host["id"], host["ip_address"], snmp_cfg, timeout_seconds=5.0,
                    )
                    LOGGER.info("topology: %s done — %d neighbors, %d if_stats",
                                host["hostname"], len(neighbors), len(if_stats))
                    return host, neighbors, if_stats
                except Exception as exc:
                    LOGGER.warning("topology: neighbor discovery failed for %s (%s): %s",
                                   host["hostname"], host["ip_address"], exc)
                    return host, None, []

        walk_results = await asyncio.gather(*[_walk_host(h) for h in hosts])
        LOGGER.info("topology: all SNMP walks complete, writing results to DB...")

        # Phase 2: sequential DB writes (avoids "database is locked")
        for host, neighbors, if_stats in walk_results:
            if neighbors is None:
                errors += 1
                continue
            try:
                # Snapshot old links for change detection
                old_links = await db.get_topology_links_for_host(host["id"])
                old_link_keys = {
                    (l["source_host_id"], l["source_interface"], l["target_device_name"], l["target_interface"])
                    for l in old_links if l["source_host_id"] == host["id"]
                }
                new_link_keys = {
                    (n["source_host_id"], n["local_interface"], n["remote_device_name"], n["remote_interface"])
                    for n in neighbors
                }

                await db.delete_topology_links_for_host(host["id"])
                for n in neighbors:
                    await db.upsert_topology_link(
                        source_host_id=n["source_host_id"],
                        source_ip=n["source_ip"],
                        source_interface=n["local_interface"],
                        target_host_id=None,
                        target_ip=n.get("remote_ip", ""),
                        target_device_name=n["remote_device_name"],
                        target_interface=n["remote_interface"],
                        protocol=n["protocol"],
                        target_platform=n.get("remote_platform", ""),
                    )
                # Store interface stats
                for stat in if_stats:
                    await db.upsert_interface_stat(**stat)
                # Record topology changes (only if there were previous links)
                if old_link_keys:
                    await _record_topology_changes(host, old_link_keys, new_link_keys, neighbors, old_links)
                total_links += len(neighbors)
            except Exception as exc:
                LOGGER.warning("topology: DB write failed for %s (%s): %s",
                               host["hostname"], host["ip_address"], exc)
                errors += 1

        # Resolve target host IDs against inventory
        resolved = await db.resolve_topology_target_host_ids()
        LOGGER.info("topology: discovered %d links from %d hosts (group %d), resolved %d targets, %d errors",
                     total_links, len(hosts), group_id, resolved, errors)

        return {
            "hosts_scanned": len(hosts),
            "links_discovered": total_links,
            "targets_resolved": resolved,
            "errors": errors,
        }
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.error("topology: discovery error for group %d: %s", group_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/topology/discover",
          dependencies=[Depends(require_auth), Depends(require_feature("topology"))])
async def discover_topology_all():
    """Run CDP/LLDP neighbor discovery on all groups."""
    try:
        groups = await db.get_all_groups()
        total_hosts = 0
        total_links = 0
        total_errors = 0

        for group in groups:
            snmp_cfg = _resolve_snmp_discovery_config(group["id"])
            if not snmp_cfg.get("enabled", False):
                continue
            hosts = await db.get_hosts_for_group(group["id"])
            if not hosts:
                continue

            semaphore = asyncio.Semaphore(max(1, DISCOVERY_MAX_CONCURRENT_PROBES))

            # Phase 1: concurrent SNMP walks (no DB writes)
            async def _walk_host(host: dict, _cfg=snmp_cfg) -> tuple[dict, list[dict] | None, list[dict]]:
                async with semaphore:
                    try:
                        neighbors, if_stats = await _discover_neighbors(
                            host["id"], host["ip_address"], _cfg, timeout_seconds=5.0,
                        )
                        return host, neighbors, if_stats
                    except Exception as exc:
                        LOGGER.warning("topology: neighbor discovery failed for %s: %s",
                                       host["ip_address"], exc)
                        return host, None, []

            walk_results = await asyncio.gather(*[_walk_host(h) for h in hosts])

            # Phase 2: sequential DB writes (avoids "database is locked")
            for host, neighbors, if_stats in walk_results:
                if neighbors is None:
                    total_errors += 1
                    continue
                try:
                    # Snapshot old links for change detection
                    old_links = await db.get_topology_links_for_host(host["id"])
                    old_link_keys = {
                        (l["source_host_id"], l["source_interface"], l["target_device_name"], l["target_interface"])
                        for l in old_links if l["source_host_id"] == host["id"]
                    }
                    new_link_keys = {
                        (n["source_host_id"], n["local_interface"], n["remote_device_name"], n["remote_interface"])
                        for n in neighbors
                    }

                    await db.delete_topology_links_for_host(host["id"])
                    for n in neighbors:
                        await db.upsert_topology_link(
                            source_host_id=n["source_host_id"],
                            source_ip=n["source_ip"],
                            source_interface=n["local_interface"],
                            target_host_id=None,
                            target_ip=n.get("remote_ip", ""),
                            target_device_name=n["remote_device_name"],
                            target_interface=n["remote_interface"],
                            protocol=n["protocol"],
                            target_platform=n.get("remote_platform", ""),
                        )
                    # Store interface stats
                    for stat in if_stats:
                        await db.upsert_interface_stat(**stat)
                    # Record topology changes (only if there were previous links)
                    if old_link_keys:
                        await _record_topology_changes(host, old_link_keys, new_link_keys, neighbors, old_links)
                    total_links += len(neighbors)
                except Exception as exc:
                    LOGGER.warning("topology: DB write failed for %s: %s",
                                   host["ip_address"], exc)
                    total_errors += 1
            total_hosts += len(hosts)

        resolved = await db.resolve_topology_target_host_ids()
        return {
            "hosts_scanned": total_hosts,
            "links_discovered": total_links,
            "targets_resolved": resolved,
            "errors": total_errors,
        }
    except Exception as exc:
        LOGGER.error("topology: full discovery error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/topology/host/{host_id}",
         dependencies=[Depends(require_auth), Depends(require_feature("topology"))])
async def get_host_topology(host_id: int):
    """Return topology links for a specific host."""
    try:
        host = await db.get_host(host_id)
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        links = await db.get_topology_links_for_host(host_id)
        return {"host": host, "links": links}
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.error("topology: host topology error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/topology/changes",
         dependencies=[Depends(require_auth), Depends(require_feature("topology"))])
async def get_topology_changes(unacknowledged: bool = Query(default=True),
                               limit: int = Query(default=100)):
    """Return recent topology changes (added/removed links)."""
    try:
        changes = await db.get_topology_changes(
            unacknowledged_only=unacknowledged, limit=limit)
        count = await db.get_topology_changes_count(unacknowledged_only=True)
        return {"changes": changes, "unacknowledged_count": count}
    except Exception as exc:
        LOGGER.error("topology: changes error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/topology/changes/acknowledge",
          dependencies=[Depends(require_auth), Depends(require_feature("topology"))])
async def acknowledge_topology_changes():
    """Mark all topology changes as acknowledged."""
    try:
        count = await db.acknowledge_topology_changes()
        return {"acknowledged": count}
    except Exception as exc:
        LOGGER.error("topology: acknowledge error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/topology/positions",
         dependencies=[Depends(require_auth), Depends(require_feature("topology"))])
async def get_topology_positions():
    """Return saved node positions."""
    try:
        return await db.get_topology_positions()
    except Exception as exc:
        LOGGER.error("topology: get positions error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.put("/api/topology/positions",
         dependencies=[Depends(require_auth), Depends(require_feature("topology"))])
async def save_topology_positions(payload: dict):
    """Save/update node positions. Body: {positions: {nodeId: {x, y}}}."""
    try:
        positions = payload.get("positions", {})
        count = await db.save_topology_positions(positions)
        return {"saved": count}
    except Exception as exc:
        LOGGER.error("topology: save positions error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.delete("/api/topology/positions",
            dependencies=[Depends(require_auth), Depends(require_feature("topology"))])
async def delete_topology_positions():
    """Delete all saved node positions (reset layout)."""
    try:
        count = await db.delete_topology_positions()
        return {"deleted": count}
    except Exception as exc:
        LOGGER.error("topology: delete positions error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


# ═════════════════════════════════════════════════════════════════════════════
# Config Drift Detection
# ═════════════════════════════════════════════════════════════════════════════

_DRIFT_DEPS = [Depends(require_auth), Depends(require_feature("config-drift"))]


# ── Baselines ────────────────────────────────────────────────────────────────


@app.get("/api/config-drift/baselines", dependencies=_DRIFT_DEPS)
async def list_config_baselines(host_id: int | None = Query(default=None)):
    """List config baselines, optionally filtered by host."""
    try:
        return await db.get_config_baselines(host_id=host_id)
    except Exception as exc:
        LOGGER.error("config-drift: list baselines error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/config-drift/baselines/{baseline_id}", dependencies=_DRIFT_DEPS)
async def get_config_baseline(baseline_id: int):
    """Get a single config baseline."""
    baseline = await db.get_config_baseline(baseline_id)
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found")
    return baseline


@app.post("/api/config-drift/baselines", status_code=201, dependencies=_DRIFT_DEPS)
async def create_config_baseline(body: ConfigBaselineCreate, request: Request):
    """Create or replace a config baseline for a host."""
    host = await db.get_host(body.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    session = _get_session(request)
    user = session["user"] if session else ""
    baseline_id = await db.create_config_baseline(
        host_id=body.host_id,
        name=body.name,
        config_text=body.config_text,
        source=body.source,
        created_by=user,
    )
    await _audit(
        "config-drift", "baseline.created",
        user=user,
        detail=f"host_id={body.host_id} name={body.name!r}",
        correlation_id=_corr_id(request),
    )
    return {"id": baseline_id}


@app.put("/api/config-drift/baselines/{baseline_id}", dependencies=_DRIFT_DEPS)
async def update_config_baseline_endpoint(baseline_id: int, body: ConfigBaselineUpdate, request: Request):
    """Update a config baseline."""
    existing = await db.get_config_baseline(baseline_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Baseline not found")
    await db.update_config_baseline(
        baseline_id,
        name=body.name,
        config_text=body.config_text,
        source=body.source,
    )
    session = _get_session(request)
    await _audit(
        "config-drift", "baseline.updated",
        user=session["user"] if session else "",
        detail=f"baseline_id={baseline_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@app.delete("/api/config-drift/baselines/{baseline_id}", dependencies=_DRIFT_DEPS)
async def delete_config_baseline_endpoint(baseline_id: int, request: Request):
    """Delete a config baseline."""
    existing = await db.get_config_baseline(baseline_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Baseline not found")
    await db.delete_config_baseline(baseline_id)
    session = _get_session(request)
    await _audit(
        "config-drift", "baseline.deleted",
        user=session["user"] if session else "",
        detail=f"baseline_id={baseline_id} host_id={existing.get('host_id')}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Snapshots ────────────────────────────────────────────────────────────────


@app.get("/api/config-drift/snapshots", dependencies=_DRIFT_DEPS)
async def list_config_snapshots(host_id: int = Query(), limit: int = Query(default=50)):
    """List config snapshots for a host."""
    return await db.get_config_snapshots_for_host(host_id, limit=limit)


@app.get("/api/config-drift/snapshots/{snapshot_id}", dependencies=_DRIFT_DEPS)
async def get_config_snapshot(snapshot_id: int):
    """Get a single snapshot with full config text."""
    snapshot = await db.get_config_snapshot(snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return snapshot


@app.post("/api/config-drift/snapshots/capture", dependencies=_DRIFT_DEPS)
async def capture_config_snapshot(body: ConfigSnapshotCaptureRequest, request: Request):
    """SSH to a device and capture its running-config."""
    host = await db.get_host(body.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    try:
        config_text = await _capture_running_config(host, cred)
    except Exception as exc:
        LOGGER.error("config-drift: capture failed for host %s: %s", host["ip_address"], exc)
        raise HTTPException(status_code=502, detail=f"SSH capture failed: {exc}")
    snapshot_id = await db.create_config_snapshot(
        host_id=body.host_id,
        config_text=config_text,
        capture_method="manual",
    )
    session = _get_session(request)
    await _audit(
        "config-drift", "snapshot.captured",
        user=session["user"] if session else "",
        detail=f"host_id={body.host_id} snapshot_id={snapshot_id}",
        correlation_id=_corr_id(request),
    )
    return {"snapshot_id": snapshot_id, "config_length": len(config_text)}


@app.post("/api/config-drift/snapshots/capture-group", dependencies=_DRIFT_DEPS)
async def capture_group_config_snapshots(body: ConfigGroupCaptureRequest, request: Request):
    """Capture running-config for all hosts in a group."""
    hosts = await db.get_hosts_for_group(body.group_id)
    if not hosts:
        raise HTTPException(status_code=404, detail="No hosts found in group")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    results = []
    sem = asyncio.Semaphore(4)

    async def _capture_one(h):
        async with sem:
            try:
                config_text = await _capture_running_config(h, cred)
                sid = await db.create_config_snapshot(
                    host_id=h["id"], config_text=config_text, capture_method="manual",
                )
                return {"host_id": h["id"], "hostname": h["hostname"], "ok": True, "snapshot_id": sid}
            except Exception as exc:
                return {"host_id": h["id"], "hostname": h["hostname"], "ok": False, "error": str(exc)}

    tasks = [asyncio.create_task(_capture_one(h)) for h in hosts]
    results = await asyncio.gather(*tasks)
    session = _get_session(request)
    await _audit(
        "config-drift", "snapshot.captured_group",
        user=session["user"] if session else "",
        detail=f"group_id={body.group_id} hosts={len(hosts)}",
        correlation_id=_corr_id(request),
    )
    return {"results": list(results)}


# ── Config Capture Job (background with WebSocket streaming) ─────────────────


async def _broadcast_capture_line(job_id: str, text: str) -> None:
    """Send a text line to all WebSocket subscribers of a capture job."""
    job = _capture_jobs.get(job_id)
    if job:
        job["output_lines"].append(text)
    sockets = _capture_job_sockets.get(job_id, [])
    dead = []
    for ws in sockets:
        try:
            await ws.send_json({"type": "line", "text": text})
        except Exception:
            dead.append(ws)
    for ws in dead:
        try:
            sockets.remove(ws)
        except ValueError:
            pass


async def _finish_capture_job(job_id: str, status: str) -> None:
    """Mark a capture job done, notify all WebSocket subscribers."""
    job = _capture_jobs.get(job_id)
    if job:
        job["status"] = status
        job["finished_at"] = datetime.now(UTC).isoformat()
    done_msg = {"type": "job_complete", "job_id": job_id, "status": status}
    sockets = _capture_job_sockets.pop(job_id, [])
    for ws in sockets:
        try:
            await ws.send_json(done_msg)
        except Exception:
            pass


async def _run_config_capture_job(
    job_id: str,
    hosts: list[dict],
    credentials: dict,
    user: str,
) -> None:
    """Background task: capture running-config from hosts, streaming progress."""
    total = len(hosts)
    ok_count = 0
    fail_count = 0

    await _broadcast_capture_line(job_id,
        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Starting config capture for {total} host(s)...\n")

    sem = asyncio.Semaphore(4)

    captured_host_ids = []

    async def _capture_one(idx: int, h: dict):
        nonlocal ok_count, fail_count
        hostname = h.get("hostname", h.get("ip_address", "unknown"))
        ip = h.get("ip_address", "")
        async with sem:
            await _broadcast_capture_line(job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] ({idx}/{total}) Connecting to {hostname} ({ip})...\n")
            try:
                config_text = await _capture_running_config(h, credentials)
                sid = await db.create_config_snapshot(
                    host_id=h["id"], config_text=config_text, capture_method="manual",
                )
                ok_count += 1
                captured_host_ids.append(h["id"])
                # Auto-set baseline if none exists for this host
                baseline = await db.get_config_baseline_for_host(h["id"])
                if not baseline:
                    await db.create_config_baseline(
                        host_id=h["id"],
                        name=f"{hostname} baseline",
                        config_text=config_text,
                        source="auto-capture",
                        created_by=user,
                    )
                    await _broadcast_capture_line(job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] ({idx}/{total}) ✓ {hostname} — captured ({len(config_text)} chars, snapshot #{sid}) [baseline set]\n")
                else:
                    await _broadcast_capture_line(job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] ({idx}/{total}) ✓ {hostname} — captured ({len(config_text)} chars, snapshot #{sid})\n")
            except Exception as exc:
                fail_count += 1
                await _broadcast_capture_line(job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] ({idx}/{total}) ✗ {hostname} — FAILED: {exc}\n")

    tasks = [asyncio.create_task(_capture_one(i + 1, h)) for i, h in enumerate(hosts)]
    await asyncio.gather(*tasks)

    await _broadcast_capture_line(job_id,
        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Capture complete: {ok_count} succeeded, {fail_count} failed out of {total} host(s).\n")

    # Run drift analysis for each successfully captured host
    if captured_host_ids:
        await _broadcast_capture_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Running drift analysis...\n")
        drift_count = 0
        compliant_count = 0
        skip_count = 0
        for hid in captured_host_ids:
            try:
                result = await _analyze_drift_for_host(hid)
                if result.get("diff_summary") == "No baseline set":
                    skip_count += 1
                elif result.get("drifted"):
                    drift_count += 1
                else:
                    compliant_count += 1
            except Exception as exc:
                LOGGER.error("config-drift: analysis failed for host %s: %s", hid, exc)
        await _broadcast_capture_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Analysis complete: {compliant_count} compliant, {drift_count} drifted, {skip_count} skipped (no baseline).\n")

    status = "completed" if fail_count == 0 else ("partial" if ok_count > 0 else "failed")
    await _finish_capture_job(job_id, status)


@app.post("/api/config-drift/snapshots/capture-job", dependencies=_DRIFT_DEPS)
async def capture_config_job(body: ConfigGroupCaptureRequest, request: Request):
    """Start a background config capture job for a group, returning a job_id for WebSocket streaming."""
    hosts = await db.get_hosts_for_group(body.group_id)
    if not hosts:
        raise HTTPException(status_code=404, detail="No hosts found in group")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    job_id = str(uuid.uuid4())
    _capture_jobs[job_id] = {
        "job_id": job_id,
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "finished_at": None,
        "output_lines": [],
    }

    session = _get_session(request)
    launched_by = session["user"] if session else "admin"
    asyncio.create_task(_run_config_capture_job(job_id, hosts, cred, launched_by))

    await _audit(
        "config-drift", "snapshot.capture_job",
        user=launched_by,
        detail=f"group_id={body.group_id} hosts={len(hosts)} job_id={job_id}",
        correlation_id=_corr_id(request),
    )
    return {"job_id": job_id, "host_count": len(hosts)}


@app.post("/api/config-drift/snapshots/capture-single-job", dependencies=_DRIFT_DEPS)
async def capture_config_single_job(body: ConfigSnapshotCaptureRequest, request: Request):
    """Start a background config capture job for a single host, returning a job_id for WebSocket streaming."""
    host = await db.get_host(body.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    job_id = str(uuid.uuid4())
    _capture_jobs[job_id] = {
        "job_id": job_id,
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "finished_at": None,
        "output_lines": [],
    }

    session = _get_session(request)
    launched_by = session["user"] if session else "admin"
    asyncio.create_task(_run_config_capture_job(job_id, [host], cred, launched_by))

    await _audit(
        "config-drift", "snapshot.capture_job",
        user=launched_by,
        detail=f"host_id={body.host_id} job_id={job_id}",
        correlation_id=_corr_id(request),
    )
    return {"job_id": job_id, "host_count": 1}


@app.get("/api/config-drift/capture-job/{job_id}", dependencies=_DRIFT_DEPS)
async def get_capture_job(job_id: str):
    """Return status and output for a config capture job."""
    job = _capture_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Capture job not found")
    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
        "output": "".join(job["output_lines"]),
    }


@app.websocket("/ws/config-capture/{job_id}")
async def websocket_config_capture(websocket: WebSocket, job_id: str):
    """Stream config capture job output in real-time."""
    token = websocket.cookies.get("session")
    session = verify_session_token(token) if token else None
    if not session:
        await websocket.close(code=1008)
        return

    user = await db.get_user_by_id(session["user_id"])
    if not user:
        await websocket.close(code=1008)
        return

    features = await _get_user_features(user)
    if user.get("role") != "admin" and "config-drift" not in features:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    job = _capture_jobs.get(job_id)
    if not job:
        await websocket.send_json({"type": "error", "message": "Job not found"})
        await websocket.close()
        return

    # Replay accumulated output
    for line in list(job.get("output_lines", [])):
        await websocket.send_json({"type": "line", "text": line})

    # If already done, notify and close
    if job["status"] not in ("running", "pending"):
        await websocket.send_json({"type": "job_complete", "job_id": job_id, "status": job["status"]})
        await websocket.close()
        return

    # Subscribe to live events
    if job_id not in _capture_job_sockets:
        _capture_job_sockets[job_id] = []
    _capture_job_sockets[job_id].append(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if job_id in _capture_job_sockets and websocket in _capture_job_sockets[job_id]:
            _capture_job_sockets[job_id].remove(websocket)


@app.delete("/api/config-drift/snapshots/{snapshot_id}", dependencies=_DRIFT_DEPS)
async def delete_config_snapshot_endpoint(snapshot_id: int, request: Request):
    """Delete a config snapshot."""
    existing = await db.get_config_snapshot(snapshot_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    await db.delete_config_snapshot(snapshot_id)
    return {"ok": True}


# ── Drift Events ─────────────────────────────────────────────────────────────


@app.get("/api/config-drift/events", dependencies=_DRIFT_DEPS)
async def list_config_drift_events(
    status: str | None = Query(default=None),
    host_id: int | None = Query(default=None),
    limit: int = Query(default=100),
):
    """List drift events with optional filters."""
    return await db.get_config_drift_events(status=status, host_id=host_id, limit=limit)


@app.get("/api/config-drift/events/{event_id}", dependencies=_DRIFT_DEPS)
async def get_config_drift_event(event_id: int):
    """Get a single drift event with diff text."""
    event = await db.get_config_drift_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Drift event not found")
    return event


@app.put("/api/config-drift/events/{event_id}/status", dependencies=_DRIFT_DEPS)
async def update_config_drift_event_status(event_id: int, body: ConfigDriftStatusUpdate, request: Request):
    """Update drift event status to resolved or accepted."""
    if body.status not in ("resolved", "accepted", "open"):
        raise HTTPException(status_code=400, detail="Status must be 'open', 'resolved', or 'accepted'")
    event = await db.get_config_drift_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Drift event not found")
    session = _get_session(request)
    user = session["user"] if session else ""
    await db.update_config_drift_event_status(event_id, body.status, resolved_by=user)

    # When accepting, update the baseline to match the snapshot (the new config is now the standard)
    if body.status == "accepted" and event.get("snapshot_id"):
        snapshot = await db.get_config_snapshot(event["snapshot_id"])
        if snapshot and snapshot.get("config_text"):
            host = await db.get_host(event["host_id"])
            hostname = host["hostname"] if host else f"host-{event['host_id']}"
            await db.create_config_baseline(
                host_id=event["host_id"],
                name=f"{hostname} baseline",
                config_text=snapshot["config_text"],
                source="accepted-drift",
                created_by=user,
            )
            LOGGER.info("config-drift: baseline updated for host %s after accepting event %s", event["host_id"], event_id)

    await _audit(
        "config-drift", f"drift.{body.status}",
        user=user,
        detail=f"event_id={event_id} host_id={event.get('host_id')}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Revert (push baseline back to device) ────────────────────────────────────


async def _push_config_to_device(host: dict, credentials: dict, config_lines: list[str]) -> str:
    """SSH to a device and push config lines via Netmiko."""
    import netmiko
    from routes.crypto import decrypt

    def _do_push():
        device = {
            "device_type": host.get("device_type", "cisco_ios"),
            "host": host["ip_address"],
            "username": credentials["username"],
            "password": decrypt(credentials["password"]),
            "secret": decrypt(credentials.get("secret", "")),
        }
        net_connect = netmiko.ConnectHandler(**device)
        if device["secret"]:
            net_connect.enable()
        output = net_connect.send_config_set(config_lines)
        save_output = net_connect.save_config()
        net_connect.disconnect()
        return output + "\n" + save_output

    return await asyncio.to_thread(_do_push)


_revert_jobs: dict[str, dict] = {}
_revert_job_sockets: dict[str, list] = {}


async def _broadcast_revert_line(job_id: str, line: str):
    _revert_jobs[job_id]["output"] += line
    for ws in list(_revert_job_sockets.get(job_id, [])):
        try:
            await ws.send_json({"type": "line", "data": line})
        except Exception:
            _revert_job_sockets[job_id].remove(ws)


async def _finish_revert_job(job_id: str, status: str = "completed"):
    _revert_jobs[job_id]["status"] = status
    for ws in list(_revert_job_sockets.get(job_id, [])):
        try:
            await ws.send_json({"type": "job_complete", "status": status})
        except Exception:
            pass


def _build_revert_commands(diff_text: str) -> list[str]:
    """Parse a unified diff and build the minimal set of config commands to revert drift.

    In the diff (baseline → running-config):
      - Lines starting with '-' (not '---') = in baseline but missing from device → re-add them
      - Lines starting with '+' (not '+++') = on device but not in baseline → negate with 'no' prefix
    """
    commands: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
            continue
        if line.startswith("-"):
            # Missing from device — re-add the baseline line
            cmd = line[1:]  # strip the leading '-'
            stripped = cmd.strip()
            if not stripped or stripped.startswith("!") or stripped == "end":
                continue
            if stripped.startswith("Building configuration") or stripped.startswith("Current configuration"):
                continue
            commands.append(cmd)
        elif line.startswith("+"):
            # Present on device but not in baseline — negate it
            cmd = line[1:]  # strip the leading '+'
            stripped = cmd.strip()
            if not stripped or stripped.startswith("!") or stripped == "end":
                continue
            if stripped.startswith("Building configuration") or stripped.startswith("Current configuration"):
                continue
            # Add 'no' prefix to remove the line, preserving indentation
            indent = cmd[: len(cmd) - len(cmd.lstrip())]
            if stripped.startswith("no "):
                # "no ..." line was added — removing it means re-adding without "no"
                commands.append(indent + stripped[3:])
            else:
                commands.append(indent + "no " + stripped)
    return commands


async def _run_revert_job(job_id: str, event: dict, host: dict, baseline: dict, credentials: dict, user: str):
    """Background task: push only the changed lines back to the device, then re-capture and re-analyze."""
    hostname = host.get("hostname", host["ip_address"])
    try:
        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Analyzing diff for {hostname}...\n")

        diff_text = event.get("diff_text", "")
        config_lines = _build_revert_commands(diff_text)

        if not config_lines:
            await _broadcast_revert_line(job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] No config changes to revert.\n")
            await _finish_revert_job(job_id, "completed")
            return

        # Log what will be pushed
        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] {len(config_lines)} lines to revert (only changed lines, not full config):\n")
        for cmd in config_lines:
            await _broadcast_revert_line(job_id, f"  {cmd}\n")

        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Connecting to {hostname} ({host['ip_address']})...\n")

        output = await _push_config_to_device(host, credentials, config_lines)
        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Config pushed successfully.\n")

        # Re-capture the running config to verify
        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Re-capturing running config to verify...\n")
        new_config = await _capture_running_config(host, credentials)
        sid = await db.create_config_snapshot(
            host_id=host["id"],
            config_text=new_config,
            capture_method="post-revert",
        )
        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Snapshot #{sid} captured ({len(new_config)} chars).\n")

        # Re-analyze drift
        result = await _analyze_drift_for_host(host["id"])
        if result.get("drifted"):
            await _broadcast_revert_line(job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Warning: device still shows drift after revert.\n")
        else:
            await _broadcast_revert_line(job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Device is now compliant with baseline.\n")

        # Mark original event as resolved
        await db.update_config_drift_event_status(event["id"], "resolved", resolved_by=user)
        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Drift event marked as resolved.\n")

        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Revert complete.\n")
        await _finish_revert_job(job_id, "completed")
    except Exception as exc:
        LOGGER.error("config-drift revert failed for %s: %s", hostname, exc)
        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] FAILED: {exc}\n")
        await _finish_revert_job(job_id, "failed")


@app.post("/api/config-drift/events/revert", dependencies=_DRIFT_DEPS)
async def revert_drift_event(body: ConfigDriftRevertRequest, request: Request):
    """Revert a device to its baseline config by pushing the baseline via SSH."""
    event = await db.get_config_drift_event(body.event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Drift event not found")

    host = await db.get_host(event["host_id"])
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    baseline = await db.get_config_baseline_for_host(event["host_id"])
    if not baseline or not baseline.get("config_text"):
        raise HTTPException(status_code=400, detail="No baseline config found for this host")

    credentials = await db.get_credential_raw(body.credential_id)
    if not credentials:
        raise HTTPException(status_code=404, detail="Credential not found")

    session = _get_session(request)
    user = session["user"] if session else ""

    job_id = str(uuid.uuid4())
    _revert_jobs[job_id] = {"status": "running", "output": "", "event_id": body.event_id, "host_id": event["host_id"]}
    _revert_job_sockets[job_id] = []

    asyncio.create_task(_run_revert_job(job_id, event, host, baseline, credentials, user))

    await _audit(
        "config-drift", "drift.revert",
        user=user,
        detail=f"event_id={body.event_id} host_id={event['host_id']} job_id={job_id}",
        correlation_id=_corr_id(request),
    )
    return {"job_id": job_id}


@app.websocket("/ws/config-revert/{job_id}")
async def ws_config_revert(websocket: WebSocket, job_id: str):
    """WebSocket for streaming revert job output."""
    await websocket.accept()
    job = _revert_jobs.get(job_id)
    if not job:
        await websocket.send_json({"type": "error", "data": "Job not found"})
        await websocket.close()
        return

    # Replay history
    if job["output"]:
        for line in job["output"].splitlines(keepends=True):
            await websocket.send_json({"type": "line", "data": line})

    if job["status"] != "running":
        await websocket.send_json({"type": "job_complete", "status": job["status"]})
        await websocket.close()
        return

    _revert_job_sockets.setdefault(job_id, []).append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _revert_job_sockets.get(job_id, []):
            _revert_job_sockets[job_id].remove(websocket)


# ── Analysis ─────────────────────────────────────────────────────────────────


async def _analyze_drift_for_host(host_id: int) -> dict:
    """Compare latest snapshot vs baseline for a single host.

    Returns {drifted: bool, event_id: int|None, diff_summary: str}.
    """
    baseline = await db.get_config_baseline_for_host(host_id)
    if not baseline:
        return {"drifted": False, "event_id": None, "diff_summary": "No baseline set"}
    snapshot = await db.get_latest_config_snapshot(host_id)
    if not snapshot:
        return {"drifted": False, "event_id": None, "diff_summary": "No snapshot available"}

    diff_text, added, removed = _compute_config_diff(
        baseline["config_text"], snapshot["config_text"],
        baseline_label="baseline", actual_label="running-config",
    )
    if not diff_text:
        return {"drifted": False, "event_id": None, "diff_summary": "In compliance"}

    event_id = await db.create_config_drift_event(
        host_id=host_id,
        snapshot_id=snapshot["id"],
        baseline_id=baseline["id"],
        diff_text=diff_text,
        diff_lines_added=added,
        diff_lines_removed=removed,
    )
    return {
        "drifted": True,
        "event_id": event_id,
        "diff_summary": f"+{added} -{removed} lines changed",
    }


@app.post("/api/config-drift/analyze", dependencies=_DRIFT_DEPS)
async def analyze_config_drift(body: ConfigDriftAnalyzeRequest, request: Request):
    """Run drift analysis for a single host."""
    host = await db.get_host(body.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    result = await _analyze_drift_for_host(body.host_id)
    session = _get_session(request)
    await _audit(
        "config-drift", "drift.analyzed",
        user=session["user"] if session else "",
        detail=f"host_id={body.host_id} drifted={result['drifted']}",
        correlation_id=_corr_id(request),
    )
    result["host_id"] = body.host_id
    result["hostname"] = host["hostname"]
    return result


@app.post("/api/config-drift/analyze-group", dependencies=_DRIFT_DEPS)
async def analyze_group_config_drift(body: ConfigDriftAnalyzeGroupRequest, request: Request):
    """Run drift analysis for all hosts in a group."""
    hosts = await db.get_hosts_for_group(body.group_id)
    if not hosts:
        raise HTTPException(status_code=404, detail="No hosts found in group")
    results = []
    for h in hosts:
        r = await _analyze_drift_for_host(h["id"])
        r["host_id"] = h["id"]
        r["hostname"] = h["hostname"]
        results.append(r)
    session = _get_session(request)
    drifted_count = sum(1 for r in results if r["drifted"])
    await _audit(
        "config-drift", "drift.analyzed_group",
        user=session["user"] if session else "",
        detail=f"group_id={body.group_id} hosts={len(results)} drifted={drifted_count}",
        correlation_id=_corr_id(request),
    )
    return {"results": results}


@app.post("/api/config-drift/check", dependencies=_DRIFT_DEPS)
async def full_config_drift_check(body: ConfigDriftCheckRequest, request: Request):
    """Full cycle: capture running-config then analyze drift for one host."""
    host = await db.get_host(body.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    try:
        config_text = await _capture_running_config(host, cred)
    except Exception as exc:
        LOGGER.error("config-drift: capture failed for host %s: %s", host["ip_address"], exc)
        raise HTTPException(status_code=502, detail=f"SSH capture failed: {exc}")
    snapshot_id = await db.create_config_snapshot(
        host_id=body.host_id, config_text=config_text, capture_method="manual",
    )
    result = await _analyze_drift_for_host(body.host_id)
    result["snapshot_id"] = snapshot_id
    result["host_id"] = body.host_id
    result["hostname"] = host["hostname"]
    session = _get_session(request)
    await _audit(
        "config-drift", "drift.check",
        user=session["user"] if session else "",
        detail=f"host_id={body.host_id} drifted={result['drifted']}",
        correlation_id=_corr_id(request),
    )
    return result


# ── Summary ──────────────────────────────────────────────────────────────────


@app.get("/api/config-drift/summary", dependencies=_DRIFT_DEPS)
async def get_config_drift_summary():
    """Return drift detection summary stats."""
    return await db.get_config_drift_summary()


# ── Admin Config Drift Schedule ──────────────────────────────────────────────


@app.get("/api/admin/config-drift", dependencies=[Depends(require_admin)])
async def admin_get_config_drift_config():
    """Get the scheduled drift check configuration."""
    return CONFIG_DRIFT_CHECK_CONFIG


@app.put("/api/admin/config-drift", dependencies=[Depends(require_admin)])
async def admin_update_config_drift_config(body: dict, request: Request):
    """Update drift check schedule settings."""
    global CONFIG_DRIFT_CHECK_CONFIG
    CONFIG_DRIFT_CHECK_CONFIG = _sanitize_config_drift_check_config(body)
    await db.set_auth_setting("config_drift_check", CONFIG_DRIFT_CHECK_CONFIG)
    session = _get_session(request)
    await _audit(
        "config-drift", "config.updated",
        user=session["user"] if session else "",
        detail=f"enabled={CONFIG_DRIFT_CHECK_CONFIG['enabled']} interval={CONFIG_DRIFT_CHECK_CONFIG['interval_seconds']}s",
        correlation_id=_corr_id(request),
    )
    return CONFIG_DRIFT_CHECK_CONFIG


@app.post("/api/admin/config-drift/run-now", dependencies=[Depends(require_admin)])
async def admin_run_config_drift_check_now(request: Request):
    """Trigger an immediate scheduled drift check."""
    result = await _run_config_drift_check_once()
    session = _get_session(request)
    await _audit(
        "config-drift", "check.manual",
        user=session["user"] if session else "",
        detail=f"hosts_checked={result.get('hosts_checked', 0)} drifted={result.get('drifted', 0)}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "result": result}


# ═════════════════════════════════════════════════════════════════════════════
# Config Backups
# ═════════════════════════════════════════════════════════════════════════════

_BACKUP_DEPS = [Depends(require_auth), Depends(require_feature("config-backups"))]


# ── Backup Policy CRUD ───────────────────────────────────────────────────────


@app.get("/api/config-backups/policies", dependencies=_BACKUP_DEPS)
async def list_config_backup_policies(group_id: int | None = Query(default=None)):
    return await db.get_config_backup_policies(group_id)


@app.post("/api/config-backups/policies", status_code=201, dependencies=_BACKUP_DEPS)
async def create_config_backup_policy(body: ConfigBackupPolicyCreate, request: Request):
    group = await db.get_group(body.group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Inventory group not found")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    interval = max(CONFIG_BACKUP_POLICY_MIN_INTERVAL, min(CONFIG_BACKUP_POLICY_MAX_INTERVAL, body.interval_seconds))
    retention = max(CONFIG_BACKUP_POLICY_MIN_RETENTION, min(CONFIG_BACKUP_POLICY_MAX_RETENTION, body.retention_days))
    session = _get_session(request)
    policy_id = await db.create_config_backup_policy(
        name=body.name, group_id=body.group_id, credential_id=body.credential_id,
        interval_seconds=interval, retention_days=retention,
        created_by=session["user"] if session else "",
    )
    await _audit(
        "config-backups", "policy.created",
        user=session["user"] if session else "",
        detail=f"policy_id={policy_id} name={body.name}",
        correlation_id=_corr_id(request),
    )
    return await db.get_config_backup_policy(policy_id)


@app.get("/api/config-backups/policies/{policy_id}", dependencies=_BACKUP_DEPS)
async def get_config_backup_policy(policy_id: int):
    policy = await db.get_config_backup_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@app.put("/api/config-backups/policies/{policy_id}", dependencies=_BACKUP_DEPS)
async def update_config_backup_policy(policy_id: int, body: ConfigBackupPolicyUpdate, request: Request):
    policy = await db.get_config_backup_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    updates = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.enabled is not None:
        updates["enabled"] = 1 if body.enabled else 0
    if body.credential_id is not None:
        cred = await db.get_credential_raw(body.credential_id)
        if not cred:
            raise HTTPException(status_code=404, detail="Credential not found")
        updates["credential_id"] = body.credential_id
    if body.interval_seconds is not None:
        updates["interval_seconds"] = max(CONFIG_BACKUP_POLICY_MIN_INTERVAL,
                                          min(CONFIG_BACKUP_POLICY_MAX_INTERVAL, body.interval_seconds))
    if body.retention_days is not None:
        updates["retention_days"] = max(CONFIG_BACKUP_POLICY_MIN_RETENTION,
                                       min(CONFIG_BACKUP_POLICY_MAX_RETENTION, body.retention_days))
    await db.update_config_backup_policy(policy_id, **updates)
    session = _get_session(request)
    await _audit(
        "config-backups", "policy.updated",
        user=session["user"] if session else "",
        detail=f"policy_id={policy_id}",
        correlation_id=_corr_id(request),
    )
    return await db.get_config_backup_policy(policy_id)


@app.delete("/api/config-backups/policies/{policy_id}", dependencies=_BACKUP_DEPS)
async def delete_config_backup_policy_route(policy_id: int, request: Request):
    policy = await db.get_config_backup_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    await db.delete_config_backup_policy(policy_id)
    session = _get_session(request)
    await _audit(
        "config-backups", "policy.deleted",
        user=session["user"] if session else "",
        detail=f"policy_id={policy_id} name={policy['name']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Backup Records ───────────────────────────────────────────────────────────


@app.get("/api/config-backups", dependencies=_BACKUP_DEPS)
async def list_config_backups(
    host_id: int | None = Query(default=None),
    policy_id: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    return await db.get_config_backups(host_id=host_id, policy_id=policy_id, limit=limit)


@app.get("/api/config-backups/summary", dependencies=_BACKUP_DEPS)
async def get_config_backup_summary():
    return await db.get_config_backup_summary()


@app.get("/api/config-backups/{backup_id}", dependencies=_BACKUP_DEPS)
async def get_config_backup_detail(backup_id: int):
    backup = await db.get_config_backup(backup_id)
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")
    return backup


@app.delete("/api/config-backups/{backup_id}", dependencies=_BACKUP_DEPS)
async def delete_config_backup_route(backup_id: int, request: Request):
    backup = await db.get_config_backup(backup_id)
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")
    await db.delete_config_backup(backup_id)
    session = _get_session(request)
    await _audit(
        "config-backups", "backup.deleted",
        user=session["user"] if session else "",
        detail=f"backup_id={backup_id} host_id={backup['host_id']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Backup Actions ───────────────────────────────────────────────────────────


@app.post("/api/config-backups/policies/{policy_id}/run-now", dependencies=_BACKUP_DEPS)
async def run_config_backup_policy_now(policy_id: int, request: Request):
    """Trigger an immediate backup run for a specific policy."""
    policy = await db.get_config_backup_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    hosts = await db.get_hosts_for_group(policy["group_id"])
    cred = await db.get_credential_raw(policy["credential_id"])
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    backed_up = 0
    errs = 0
    sem = asyncio.Semaphore(4)

    async def _do_backup(host):
        nonlocal backed_up, errs
        async with sem:
            try:
                config_text = await _capture_running_config(host, cred)
                await db.create_config_backup(
                    policy_id=policy_id, host_id=host["id"],
                    config_text=config_text, capture_method="manual",
                    status="success", error_message="",
                )
                backed_up += 1
            except Exception as exc:
                await db.create_config_backup(
                    policy_id=policy_id, host_id=host["id"],
                    config_text="", capture_method="manual",
                    status="error", error_message=str(exc),
                )
                errs += 1

    await asyncio.gather(*[_do_backup(h) for h in hosts], return_exceptions=True)
    await db.update_config_backup_policy_last_run(policy_id)

    session = _get_session(request)
    await _audit(
        "config-backups", "policy.run-now",
        user=session["user"] if session else "",
        detail=f"policy_id={policy_id} backed_up={backed_up} errors={errs}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "backed_up": backed_up, "errors": errs}


@app.post("/api/config-backups/restore", dependencies=_BACKUP_DEPS)
async def restore_config_from_backup(body: ConfigBackupRestoreRequest, request: Request):
    """Restore configuration from a backup and validate."""
    backup = await db.get_config_backup(body.backup_id)
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")
    if not backup.get("config_text"):
        raise HTTPException(status_code=400, detail="Backup has no config text")
    host = await db.get_host(backup["host_id"])
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    # Push config
    import netmiko
    from routes.crypto import decrypt

    def _push_config():
        device = {
            "device_type": host.get("device_type", "cisco_ios"),
            "host": host["ip_address"],
            "username": cred["username"],
            "password": decrypt(cred["password"]),
            "secret": decrypt(cred.get("secret", "")),
        }
        net_connect = netmiko.ConnectHandler(**device)
        if device["secret"]:
            net_connect.enable()
        config_lines = backup["config_text"].splitlines()
        net_connect.send_config_set(config_lines)
        net_connect.disconnect()

    try:
        await asyncio.to_thread(_push_config)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Config push failed: {exc}")

    # Re-capture and validate
    validated = False
    diff_text = ""
    lines_changed = 0
    try:
        current_config = await _capture_running_config(host, cred)
        diff_text, added, removed = _compute_config_diff(
            backup["config_text"], current_config,
            baseline_label="backup", actual_label="current",
        )
        lines_changed = added + removed
        validated = lines_changed == 0
    except Exception as exc:
        diff_text = f"Validation capture failed: {exc}"

    session = _get_session(request)
    await _audit(
        "config-backups", "restore",
        user=session["user"] if session else "",
        detail=f"backup_id={body.backup_id} host={host['ip_address']} validated={validated} lines_changed={lines_changed}",
        correlation_id=_corr_id(request),
    )
    return {
        "restored": True,
        "validated": validated,
        "diff_text": diff_text,
        "lines_changed": lines_changed,
        "host_id": host["id"],
        "hostname": host["hostname"],
    }


# ── Admin Config Backup Schedule ─────────────────────────────────────────────


@app.get("/api/admin/config-backups", dependencies=[Depends(require_admin)])
async def admin_get_config_backup_config():
    return CONFIG_BACKUP_CONFIG


@app.put("/api/admin/config-backups", dependencies=[Depends(require_admin)])
async def admin_update_config_backup_config(body: dict, request: Request):
    global CONFIG_BACKUP_CONFIG
    CONFIG_BACKUP_CONFIG = _sanitize_config_backup_config(body)
    await db.set_auth_setting("config_backup", CONFIG_BACKUP_CONFIG)
    session = _get_session(request)
    await _audit(
        "config-backups", "config.updated",
        user=session["user"] if session else "",
        detail=f"enabled={CONFIG_BACKUP_CONFIG['enabled']} interval={CONFIG_BACKUP_CONFIG['interval_seconds']}s",
        correlation_id=_corr_id(request),
    )
    return CONFIG_BACKUP_CONFIG


@app.post("/api/admin/config-backups/run-now", dependencies=[Depends(require_admin)])
async def admin_run_config_backups_now(request: Request):
    result = await _run_config_backups_once()
    session = _get_session(request)
    await _audit(
        "config-backups", "scheduled.manual",
        user=session["user"] if session else "",
        detail=f"policies_run={result.get('policies_run', 0)} hosts_backed_up={result.get('hosts_backed_up', 0)}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "result": result}


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
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/docs")

@app.get("/favicon.ico")
async def favicon():
    """Handle favicon requests gracefully."""
    return {"detail": "No favicon"}
