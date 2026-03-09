"""
app.py — Plexus FastAPI Application

REST API for inventory, playbooks, templates, credentials, and jobs.
WebSocket endpoint for real-time job output streaming.
Session-based authentication with signed cookies.
"""

import asyncio
import hashlib
import json
import os
import secrets
import sys
import traceback
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
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


# ── CSRF token helpers ───────────────────────────────────────────────────────

_csrf_serializer: URLSafeTimedSerializer | None = None  # initialised after secret key load
CSRF_TOKEN_MAX_AGE = 86400  # 24 hours — aligned with session lifetime


def _generate_csrf_token(session_user: str) -> str:
    """Create a signed, time-limited CSRF token bound to the session user."""
    return _csrf_serializer.dumps({"csrf_user": session_user})


def _validate_csrf_token(token: str, session_user: str) -> bool:
    """Return True when the token is valid, not expired, and bound to the user."""
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
    global LOGIN_RULES, AUTH_CONFIG
    login_rules = await db.get_auth_setting("login_rules")
    auth_config = await db.get_auth_setting("auth_config")
    LOGIN_RULES = _sanitize_login_rules(login_rules)
    AUTH_CONFIG = _sanitize_auth_config(auth_config)


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
    retention_task = asyncio.create_task(_job_retention_cleanup_loop())
    try:
        yield
    finally:
        retention_task.cancel()
        try:
            await retention_task
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
async def list_groups():
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
