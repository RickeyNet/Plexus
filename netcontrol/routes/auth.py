"""
auth.py -- Authentication routes: login, register, logout, status, profile, change-password.

Includes RADIUS authentication helpers and login rate-limiting logic.
"""

import asyncio
import hashlib
import os
import secrets
import sys
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import routes.database as db
import netcontrol.routes.state as state
from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.routes.state import _env_flag
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.auth")

# ── pyrad imports (optional) ─────────────────────────────────────────────────

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

# ── Late-binding dependency injection ─────────────────────────────────────────
# app.py calls init_auth() after defining require_auth to avoid circular imports.

_require_auth = None
_generate_csrf_token = None
_validate_csrf_token = None
_hash_password_fn = None
_verify_user_fn = None
_create_session_token_fn = None

# Session / cookie constants — injected from app.py
_SESSION_MAX_AGE = 86400
_APP_HTTPS_ENABLED = False


def _app_module():
    """Return the netcontrol.app module for late-bound lookups.

    This allows tests to monkeypatch ``app_module.verify_user`` etc. and
    have the patched version picked up by functions in this module.
    """
    return sys.modules["netcontrol.app"]


def init_auth(
    *,
    require_auth_fn,
    generate_csrf_token_fn,
    validate_csrf_token_fn,
    hash_password_fn,
    verify_user_fn,
    create_session_token_fn,
    session_max_age: int,
    app_https_enabled: bool,
):
    """Called from app.py after helpers are defined."""
    global _require_auth, _generate_csrf_token, _validate_csrf_token
    global _hash_password_fn, _verify_user_fn, _create_session_token_fn
    global _SESSION_MAX_AGE, _APP_HTTPS_ENABLED
    _require_auth = require_auth_fn
    _generate_csrf_token = generate_csrf_token_fn
    _validate_csrf_token = validate_csrf_token_fn
    _hash_password_fn = hash_password_fn
    _verify_user_fn = verify_user_fn
    _create_session_token_fn = create_session_token_fn
    _SESSION_MAX_AGE = session_max_age
    _APP_HTTPS_ENABLED = app_https_enabled


# ── RADIUS helpers ────────────────────────────────────────────────────────────

RADIUS_DICTIONARY_FILE = state.RADIUS_DICTIONARY_FILE


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
    radius_cfg = state.AUTH_CONFIG.get("radius", {})
    return await asyncio.to_thread(_radius_authenticate_sync, username, password, radius_cfg)


async def upsert_radius_user(username: str) -> dict | None:
    """Ensure a local shadow user exists for RADIUS-authenticated identities."""
    user = await db.get_user_by_username(username)
    if user:
        return user

    salt = secrets.token_hex(16)
    random_pw = secrets.token_urlsafe(32)
    pw_hash = _hash_password_fn(random_pw, salt)
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

    Looks up ``verify_radius_user``, ``upsert_radius_user``, ``verify_user``
    and ``AUTH_CONFIG`` through the app module so that tests can monkeypatch
    ``app_module.X`` and the patched version is used here.
    """
    _app = _app_module()
    auth_config = getattr(_app, "AUTH_CONFIG", state.AUTH_CONFIG)
    provider = auth_config.get("provider", "local")
    radius_cfg = auth_config.get("radius", {})
    radius_enabled = bool(radius_cfg.get("enabled"))

    _verify_radius = getattr(_app, "verify_radius_user", verify_radius_user)
    _upsert_radius = getattr(_app, "upsert_radius_user", upsert_radius_user)
    _verify_local = getattr(_app, "verify_user", _verify_user_fn)

    if provider == "radius" and radius_enabled:
        accepted, status = await _verify_radius(username, password)
        if accepted:
            user = await _upsert_radius(username)
            if user:
                return user, "radius", None
            return None, None, "RADIUS login succeeded but local account provisioning failed"

        if status == "reject" and not bool(radius_cfg.get("fallback_on_reject", False)):
            return None, None, "Invalid username or password"

        if bool(radius_cfg.get("fallback_to_local", True)):
            local_user = await _verify_local(username, password)
            if local_user:
                return local_user, "local-fallback", None
            if status == "error":
                return None, None, "RADIUS is unavailable and local fallback credentials failed"
            return None, None, "Invalid username or password"

        if status == "error":
            return None, None, "RADIUS authentication service unavailable"
        return None, None, "Invalid username or password"

    # Default/local provider path.
    user = await _verify_local(username, password)
    if user:
        return user, "local", None
    return None, None, "Invalid username or password"


# ── Feature helper (shared with other modules) ───────────────────────────────

FEATURE_FLAGS = state.FEATURE_FLAGS


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


# ── Pydantic models ──────────────────────────────────────────────────────────

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


# ── Router ────────────────────────────────────────────────────────────────────

router = APIRouter()


@router.post("/api/auth/login")
async def login(body: LoginRequest, request: Request):
    _app = _app_module()
    _auth_identity = getattr(_app, "authenticate_login_identity", authenticate_login_identity)
    _audit_fn = getattr(_app, "_audit", _audit)
    _features_fn = getattr(_app, "_get_user_features", _get_user_features)

    ip = request.client.host
    now = time.time()

    LOGIN_ATTEMPTS = getattr(_app, "LOGIN_ATTEMPTS", state.LOGIN_ATTEMPTS)
    LOCKED_OUT = getattr(_app, "LOCKED_OUT", state.LOCKED_OUT)
    LOGIN_RULES = state.LOGIN_RULES

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

    user, auth_source, auth_error = await _auth_identity(body.username, body.password)
    if not user:
        attempts.append(now)
        LOGIN_ATTEMPTS[ip] = attempts
        await _audit_fn("auth", "login.failure", user=body.username, detail=auth_error or "bad credentials", correlation_id=_corr_id(request))
        # Lockout if too many failed attempts
        if len(attempts) >= LOGIN_RULES["max_attempts"]:
            LOCKED_OUT[ip] = now + LOGIN_RULES["lockout_time"]
            raise HTTPException(status_code=429, detail="Account locked due to too many failed attempts. Try again later.")
        raise HTTPException(status_code=401, detail=auth_error or "Invalid username or password")
    # On success, reset attempts
    LOGIN_ATTEMPTS.pop(ip, None)
    await _audit_fn("auth", "login.success", user=body.username, detail=f"source={auth_source}", correlation_id=_corr_id(request))
    token = _create_session_token_fn(body.username, user["id"])
    csrf_token = _generate_csrf_token(body.username)
    response = JSONResponse({
        "ok": True,
        "username": body.username,
        "user_id": user["id"],
        "display_name": user["display_name"] or body.username,
        "role": user["role"],
        "auth_source": auth_source,
        "feature_access": await _features_fn(user),
        "must_change_password": bool(user.get("must_change_password")),
        "csrf_token": csrf_token,
    })
    _https = getattr(_app, "APP_HTTPS_ENABLED", _APP_HTTPS_ENABLED)
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="strict",
        max_age=_SESSION_MAX_AGE,
        secure=_https,
    )
    return response


@router.post("/api/auth/register")
async def register(body: RegisterRequest, request: Request = None):
    _app = _app_module()
    _features_fn = getattr(_app, "_get_user_features", _get_user_features)

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
    pw_hash = _hash_password_fn(body.password, salt)
    display = body.display_name or body.username.title()
    user_id = await db.create_user(body.username, pw_hash, salt, display_name=display, role="user")
    user = await db.get_user_by_id(user_id)
    await _audit("auth", "register", user=body.username, correlation_id=_corr_id(request) if request else "")
    token = _create_session_token_fn(body.username, user_id)
    csrf_token = _generate_csrf_token(body.username)
    response = JSONResponse({
        "ok": True,
        "username": body.username,
        "user_id": user_id,
        "display_name": display,
        "role": "user",
        "feature_access": await _features_fn(user),
        "csrf_token": csrf_token,
    })
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="strict",
        max_age=_SESSION_MAX_AGE,
        secure=_APP_HTTPS_ENABLED,
    )
    return response


@router.post("/api/auth/logout")
async def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie("session")
    return response


@router.get("/api/auth/status")
async def auth_status(request: Request):
    _app = _app_module()
    _features_fn = getattr(_app, "_get_user_features", _get_user_features)

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
        "feature_access": await _features_fn(user),
        "csrf_token": _generate_csrf_token(user["username"]),
        "must_change_password": bool(user.get("must_change_password")),
    }


async def _require_auth_dep(request: Request):
    """Late-bound wrapper for require_auth dependency."""
    return await _require_auth(request)


@router.post("/api/auth/change-password", dependencies=[Depends(_require_auth_dep)])
async def change_password(body: ChangePasswordRequest, request: Request):
    session = _get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await _verify_user_fn(session["user"], body.current_password)
    if not user:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    salt = secrets.token_hex(16)
    pw_hash = _hash_password_fn(body.new_password, salt)
    await db.update_user_password(user["id"], pw_hash, salt)
    await _audit("auth", "password.change", user=session["user"], correlation_id=_corr_id(request))
    return {"ok": True}


@router.get("/api/auth/profile", dependencies=[Depends(_require_auth_dep)])
async def get_profile(request: Request):
    session = _get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await db.get_user_by_id(session["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user["feature_access"] = await _get_user_features(user)
    return user


@router.put("/api/auth/profile", dependencies=[Depends(_require_auth_dep)])
async def update_profile(body: UpdateProfileRequest, request: Request):
    session = _get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    await db.update_user_profile(session["user_id"], display_name=body.display_name)
    return {"ok": True}
