"""
app.py — Plexus FastAPI Application

REST API for inventory, playbooks, templates, credentials, and jobs.
WebSocket endpoint for real-time job output streaming.
Session-based authentication with signed cookies.
"""

import sys
import os
import json
import asyncio
import hashlib
import secrets
import socket
import traceback
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query, Request, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

# Ensure project root is on path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Register converter API
from netcontrol.routes.converter import router as converter_router
from pydantic import BaseModel, ConfigDict
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import time

try:
    from pyrad.client import Client as RadiusClient
    from pyrad.dictionary import Dictionary as RadiusDictionary
    from pyrad import packet as radius_packet
    PYRAD_AVAILABLE = True
except Exception:
    RadiusClient = None
    RadiusDictionary = None
    radius_packet = None
    PYRAD_AVAILABLE = False

# Ensure project root is on path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import routes.database as db
from routes.crypto import encrypt, decrypt
from routes.runner import get_playbook_class, execute_playbook, LogEvent
from netcontrol.telemetry import configure_logging, increment_metric, observe_timing, redact_value, snapshot_metrics
import importlib

# Auto-register all playbooks
from templates import playbooks  # noqa: F401


LOGGER = configure_logging("plexus.app")
APP_START_TIME = time.time()
APP_API_TOKEN = os.getenv("APP_API_TOKEN", "").strip()


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _validate_startup_config() -> None:
    errors = []
    if _env_flag("APP_REQUIRE_API_TOKEN", False) and not APP_API_TOKEN:
        errors.append("APP_REQUIRE_API_TOKEN is true but APP_API_TOKEN is not set")
    if errors:
        raise RuntimeError("; ".join(errors))


def _extract_api_token(request: Request) -> str:
    token = request.headers.get("x-api-token", "").strip()
    if token:
        return token
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return ""


def write_playbook_file(filename: str, content: str) -> str:
    """
    Write playbook content to a file and reload the module.
    Returns the file path.
    """
    playbooks_dir = os.path.join(project_root, "templates", "playbooks")
    os.makedirs(playbooks_dir, exist_ok=True)
    
    file_path = os.path.join(playbooks_dir, filename)
    
    # Ensure filename ends with .py
    if not filename.endswith('.py'):
        file_path += '.py'
        filename += '.py'
    
    # Write the file
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    # Reload the playbook module to pick up changes
    module_name = f"templates.playbooks.{filename[:-3]}"
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
        print(f"[warning] Failed to reload playbook module {module_name}: {e}")
    
    return file_path


# ═════════════════════════════════════════════════════════════════════════════
# Authentication (DB-backed users)
# ═════════════════════════════════════════════════════════════════════════════

SECRET_KEY_FILE = os.path.join(os.path.dirname(__file__), "..", "routes", "session.key")
SESSION_MAX_AGE = 86400  # 24 hours


def _load_or_create_secret_key() -> str:
    if os.path.isfile(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, "r") as f:
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


def _hash_password(password: str, salt: str = "") -> str:
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()


async def _ensure_default_admin():
    """Create the default admin user in the DB if no users exist."""
    existing = await db.get_all_users()
    if existing:
        return
    salt = secrets.token_hex(16)
    pw_hash = _hash_password("netcontrol", salt)
    await db.create_user("admin", pw_hash, salt, display_name="Administrator", role="admin")
    print("[auth] Created default user: admin / netcontrol  — CHANGE THIS PASSWORD!")


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
    cfg["radius"]["port"] = max(1, cfg["radius"]["port"])
    cfg["radius"]["timeout"] = max(1, cfg["radius"]["timeout"])
    return cfg


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
    except (socket.timeout, OSError):
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
    yield


async def _migrate_auth_json_users():
    """One-time migration: import users from legacy auth.json into the DB."""
    auth_file = os.path.join(os.path.dirname(__file__), "..", "routes", "auth.json")
    if not os.path.isfile(auth_file):
        return
    try:
        with open(auth_file, "r") as f:
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
            print(f"[migration] Migrated {migrated} user(s) from auth.json to database")
        # Rename the file so we don't migrate again
        backup = auth_file + ".bak"
        os.rename(auth_file, backup)
        print(f"[migration] Renamed auth.json to auth.json.bak")
    except Exception as e:
        print(f"[migration] auth.json migration error: {e}")


app = FastAPI(title="Plexus API", version="1.0.0", lifespan=lifespan)
app.include_router(
    converter_router,
    dependencies=[Depends(require_auth), Depends(require_feature("converter"))],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def metrics_and_logging_middleware(request: Request, call_next):
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        duration_ms = (time.perf_counter() - start) * 1000
        increment_metric("api.requests.total")
        increment_metric("api.requests.failed")
        observe_timing("api.request.duration_ms", duration_ms)
        raise

    duration_ms = (time.perf_counter() - start) * 1000
    increment_metric("api.requests.total")
    if response.status_code >= 400:
        increment_metric("api.requests.failed")
    observe_timing("api.request.duration_ms", duration_ms)
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
    display_name: Optional[str] = None


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
        # Lockout if too many failed attempts
        if len(attempts) >= LOGIN_RULES["max_attempts"]:
            LOCKED_OUT[ip] = now + LOGIN_RULES["lockout_time"]
            raise HTTPException(status_code=429, detail="Account locked due to too many failed attempts. Try again later.")
        raise HTTPException(status_code=401, detail=auth_error or "Invalid username or password")
    # On success, reset attempts
    LOGIN_ATTEMPTS.pop(ip, None)
    token = create_session_token(body.username, user["id"])
    response = JSONResponse({
        "ok": True,
        "username": body.username,
        "user_id": user["id"],
        "display_name": user["display_name"] or body.username,
        "role": user["role"],
        "auth_source": auth_source,
        "feature_access": await _get_user_features(user),
    })
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="strict",
        max_age=SESSION_MAX_AGE,
        secure=False,
    )
    return response


@app.post("/api/auth/register")
async def register(body: RegisterRequest):
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
    token = create_session_token(body.username, user_id)
    response = JSONResponse({
        "ok": True,
        "username": body.username,
        "user_id": user_id,
        "display_name": display,
        "role": "user",
        "feature_access": await _get_user_features(user),
    })
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="strict",
        max_age=SESSION_MAX_AGE,
        secure=False,
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
    username: Optional[str] = None
    display_name: Optional[str] = None
    role: Optional[str] = None


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


@app.get("/api/admin/capabilities", dependencies=[Depends(require_admin)])
async def admin_capabilities():
    return {
        "feature_flags": FEATURE_FLAGS,
        "auth_providers": ["local", "radius"],
    }


@app.get("/api/admin/users", dependencies=[Depends(require_admin)])
async def admin_list_users():
    users = await db.get_all_users()
    result = []
    for user in users:
        result.append(await _admin_user_payload(user))
    return result


@app.post("/api/admin/users", status_code=201, dependencies=[Depends(require_admin)])
async def admin_create_user(body: AdminUserCreateRequest):
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
    name: Optional[str] = None
    filename: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[list[str]] = None
    content: Optional[str] = None

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
    name: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    secret: Optional[str] = None


class JobLaunch(BaseModel):
    playbook_id: int
    inventory_group_id: Optional[int] = None  # Optional for backward compatibility
    host_ids: Optional[list[int]] = None  # List of specific host IDs to target
    credential_id: Optional[int] = None
    template_id: Optional[int] = None
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
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_content = f.read()
                    playbook["content"] = file_content
                # Sync it back to the database
                await db.update_playbook(playbook_id, content=file_content)
                print(f"[info] Loaded playbook content from file: {filename} ({len(file_content)} chars)")
            except Exception as e:
                print(f"[warning] Failed to read playbook file {file_path}: {e}")
                playbook["content"] = ""
        else:
            print(f"[warning] Playbook file not found: {file_path}")
            playbook["content"] = ""
    else:
        print(f"[info] Using playbook content from database (length: {len(content)})")
    
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
    from routes.runner import list_registered_playbooks
    from routes.database import sync_playbook_filename
    
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
                    print(f"[sync] Updated filename for '{pb['name']}' to '{pb['filename']}'")
                except Exception as e:
                    print(f"[sync] Error syncing filename for '{pb['name']}': {e}")
            else:
                # Create new playbook
                try:
                    await db.create_playbook(pb["name"], pb["filename"], pb["description"], pb["tags"])
                    print(f"[sync] Added missing playbook '{pb['name']}' ({pb['filename']})")
                except Exception as e:
                    print(f"[sync] Error adding playbook '{pb['name']}': {e}")


@app.post("/api/playbooks", status_code=201, dependencies=[Depends(require_auth), Depends(require_feature("playbooks"))])
async def create_playbook(body: PlaybookCreate):
    # Ensure filename ends with .py
    filename = body.filename if body.filename.endswith('.py') else body.filename + '.py'
    
    # Write the playbook file
    if body.content:
        write_playbook_file(filename, body.content)
    
    pid = await db.create_playbook(body.name, filename, body.description, body.tags, body.content)
    return {"id": pid}


@app.put("/api/playbooks/{playbook_id}", dependencies=[Depends(require_auth), Depends(require_feature("playbooks"))])
async def update_playbook(playbook_id: int, body: PlaybookUpdate):
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    
    # If content is being updated, write the file
    if body.content is not None:
        filename = body.filename if body.filename else playbook["filename"]
        if not filename.endswith('.py'):
            filename += '.py'
        write_playbook_file(filename, body.content)
    
    # Update filename if provided
    update_filename = body.filename
    if update_filename and not update_filename.endswith('.py'):
        update_filename += '.py'
    
    await db.update_playbook(
        playbook_id,
        name=body.name,
        filename=update_filename,
        description=body.description,
        tags=body.tags,
        content=body.content
    )
    return {"ok": True}


@app.delete("/api/playbooks/{playbook_id}", dependencies=[Depends(require_auth), Depends(require_feature("playbooks"))])
async def delete_playbook(playbook_id: int):
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    
    # Optionally delete the file (but keep it for now in case of rollback)
    await db.delete_playbook(playbook_id)
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# Templates
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/templates", dependencies=[Depends(require_auth), Depends(require_feature("templates"))])
async def list_templates():
    return await db.get_all_templates()


@app.post("/api/templates", status_code=201, dependencies=[Depends(require_auth), Depends(require_feature("templates"))])
async def create_template(body: TemplateCreate):
    tid = await db.create_template(body.name, body.content, body.description)
    return {"id": tid}


@app.get("/api/templates/{template_id}", dependencies=[Depends(require_auth), Depends(require_feature("templates"))])
async def get_template(template_id: int):
    tpl = await db.get_template(template_id)
    if not tpl:
        raise HTTPException(404, "Template not found")
    return tpl


@app.put("/api/templates/{template_id}", dependencies=[Depends(require_auth), Depends(require_feature("templates"))])
async def update_template(template_id: int, body: TemplateUpdate):
    await db.update_template(template_id, body.name, body.content, body.description)
    return {"ok": True}


@app.delete("/api/templates/{template_id}", dependencies=[Depends(require_auth), Depends(require_feature("templates"))])
async def delete_template(template_id: int):
    await db.delete_template(template_id)
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
    print(f"[debug] JobLaunch request: playbook_id={body.playbook_id}, host_ids={body.host_ids}, inventory_group_id={body.inventory_group_id}")
    
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
