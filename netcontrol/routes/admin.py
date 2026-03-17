"""
admin.py -- Core admin routes: capabilities, security-check, users CRUD,
access-groups CRUD, audit-events, login-rules, auth-config, retention cleanup.

Domain-specific admin routes (discovery-sync, topology-discovery, config-drift,
config-backups, compliance, monitoring, SNMP) remain in app.py for now.
"""

import os
import secrets
import sys

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

import routes.database as db
import netcontrol.routes.state as state
from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.routes.state import _env_flag
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.admin")

# ── Late-binding dependency injection ─────────────────────────────────────────

_require_admin = None
_hash_password_fn = None
_get_user_features_fn = None
_cleanup_expired_jobs_fn = None
_cleanup_expired_converter_sessions_fn = None


def _app_module():
    """Return the netcontrol.app module for late-bound lookups.

    This allows tests to monkeypatch ``app_module.X`` and have the patched
    version picked up by functions in this module.
    """
    return sys.modules["netcontrol.app"]


def init_admin(
    *,
    require_admin_fn,
    hash_password_fn,
    get_user_features_fn,
    cleanup_expired_jobs_fn,
    cleanup_expired_converter_sessions_fn,
):
    """Called from app.py after helpers are defined."""
    global _require_admin, _hash_password_fn, _get_user_features_fn
    global _cleanup_expired_jobs_fn, _cleanup_expired_converter_sessions_fn
    _require_admin = require_admin_fn
    _hash_password_fn = hash_password_fn
    _get_user_features_fn = get_user_features_fn
    _cleanup_expired_jobs_fn = cleanup_expired_jobs_fn
    _cleanup_expired_converter_sessions_fn = cleanup_expired_converter_sessions_fn


# ── Pydantic models ──────────────────────────────────────────────────────────

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
    default_credential_id: int | None = None
    job_retention_days: int = Field(default=30, ge=30)
    converter_session_retention_days: int = Field(default=30, ge=1)
    converter_backup_retention_days: int = Field(default=30, ge=1)
    radius: RadiusConfigRequest = RadiusConfigRequest()


# ── Helpers ───────────────────────────────────────────────────────────────────

FEATURE_FLAGS = state.FEATURE_FLAGS
APP_API_TOKEN = os.getenv("APP_API_TOKEN", "").strip()
APP_HTTPS_ENABLED = state.APP_HTTPS_ENABLED
APP_HSTS_ENABLED = state.APP_HSTS_ENABLED
APP_HSTS_MAX_AGE = state.APP_HSTS_MAX_AGE
APP_CORS_ALLOW_ORIGINS = state.APP_CORS_ALLOW_ORIGINS
_CSRF_PROTECTED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


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
    features = await _get_user_features_fn(user)
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
    """Build a runtime snapshot of transport and app hardening settings.

    Looks up config values through the app module so tests can monkeypatch them.
    """
    _app = _app_module()
    _https = getattr(_app, "APP_HTTPS_ENABLED", APP_HTTPS_ENABLED)
    _hsts = getattr(_app, "APP_HSTS_ENABLED", APP_HSTS_ENABLED)
    _hsts_age = getattr(_app, "APP_HSTS_MAX_AGE", APP_HSTS_MAX_AGE)
    _cors = getattr(_app, "APP_CORS_ALLOW_ORIGINS", APP_CORS_ALLOW_ORIGINS)
    _api_token = getattr(_app, "APP_API_TOKEN", APP_API_TOKEN)

    api_token_required = _env_flag("APP_REQUIRE_API_TOKEN", False)
    warnings = []
    if not _https:
        warnings.append("APP_HTTPS is false: browser traffic may be sent over HTTP if your proxy does not enforce HTTPS.")
    if not _hsts:
        warnings.append("APP_HSTS is false: browsers are not instructed to enforce HTTPS for future requests.")
    if not api_token_required:
        warnings.append("APP_REQUIRE_API_TOKEN is false: non-session API calls are not forced to present an API token.")
    if not _api_token:
        warnings.append("APP_API_TOKEN is not set: token-based API auth cannot be used.")

    return {
        "ok": True,
        "transport": {
            "https_enabled": _https,
            "hsts_enabled": _hsts,
            "hsts_max_age": max(0, _hsts_age),
        },
        "cookies": {
            "session_cookie_secure": _https,
            "session_cookie_httponly": True,
            "session_cookie_samesite": "strict",
        },
        "cors": {
            "allow_origins": _cors,
            "allow_credentials": True,
        },
        "auth": {
            "csrf_protected_methods": sorted(_CSRF_PROTECTED_METHODS),
            "api_token_required": api_token_required,
            "api_token_configured": bool(_api_token),
        },
        "warnings": warnings,
    }


# ── Router ────────────────────────────────────────────────────────────────────

router = APIRouter()


def _admin_dep():
    """Return the require_admin dependency; resolved at call time."""
    return Depends(lambda request: _require_admin(request))


@router.get("/api/admin/capabilities")
async def admin_capabilities():
    return {
        "feature_flags": FEATURE_FLAGS,
        "auth_providers": ["local", "radius"],
    }


@router.get("/api/admin/security-check")
async def admin_security_check():
    """Return active security-relevant runtime settings for quick verification."""
    return _security_check_payload()


@router.get("/api/admin/users")
async def admin_list_users():
    users = await db.get_all_users()
    result = []
    for user in users:
        result.append(await _admin_user_payload(user))
    return result


@router.post("/api/admin/users", status_code=201)
async def admin_create_user(body: AdminUserCreateRequest, request: Request):
    username = body.username.strip()
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    role = body.role if body.role in {"admin", "user"} else "user"

    salt = secrets.token_hex(16)
    pw_hash = _hash_password_fn(body.password, salt)
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


@router.put("/api/admin/users/{user_id}")
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


@router.put("/api/admin/users/{user_id}/password")
async def admin_reset_user_password(user_id: int, body: AdminUserPasswordResetRequest):
    target = await db.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    salt = secrets.token_hex(16)
    pw_hash = _hash_password_fn(body.new_password, salt)
    await db.update_user_password(user_id, pw_hash, salt)
    return {"ok": True}


@router.put("/api/admin/users/{user_id}/groups")
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


@router.delete("/api/admin/users/{user_id}")
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


@router.get("/api/admin/access-groups")
async def admin_list_access_groups():
    return await db.get_all_access_groups()


@router.post("/api/admin/access-groups", status_code=201)
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


@router.put("/api/admin/access-groups/{group_id}")
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


@router.delete("/api/admin/access-groups/{group_id}")
async def admin_delete_access_group(group_id: int):
    existing = await db.get_access_group(group_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Access group not found")
    await db.delete_access_group(group_id)
    return {"ok": True}


@router.get("/api/admin/audit-events")
async def admin_get_audit_events(limit: int = Query(200, ge=1, le=1000)):
    """Return recent audit events for the admin dashboard."""
    return await db.get_audit_events(limit=limit)


@router.get("/api/admin/login-rules")
async def admin_get_login_rules():
    return state.LOGIN_RULES


@router.put("/api/admin/login-rules")
async def admin_update_login_rules(body: AdminLoginRulesRequest):
    state.LOGIN_RULES = state._sanitize_login_rules(body.dict())
    await db.set_auth_setting("login_rules", state.LOGIN_RULES)
    return state.LOGIN_RULES


@router.get("/api/admin/auth-config")
async def admin_get_auth_config():
    return state.AUTH_CONFIG


@router.put("/api/admin/auth-config")
async def admin_update_auth_config(body: AuthConfigRequest):
    state.AUTH_CONFIG = state._sanitize_auth_config(body.dict())
    await db.set_auth_setting("auth_config", state.AUTH_CONFIG)
    return state.AUTH_CONFIG


@router.post("/api/admin/retention/cleanup-now")
async def admin_run_retention_cleanup_now():
    """Run retention cleanup immediately for jobs and converter artifacts.

    Looks up cleanup functions and retention helpers through the app module
    so that tests can monkeypatch them on ``app_module``.
    """
    _app = _app_module()
    _cleanup_jobs = getattr(_app, "_cleanup_expired_jobs", _cleanup_expired_jobs_fn)
    _cleanup_converter = getattr(_app, "_cleanup_expired_converter_sessions", _cleanup_expired_converter_sessions_fn)
    _eff_job_ret = getattr(_app, "_effective_job_retention_days", state._effective_job_retention_days)
    _eff_conv_sess_ret = getattr(_app, "_effective_converter_session_retention_days", state._effective_converter_session_retention_days)
    _eff_conv_bak_ret = getattr(_app, "_effective_converter_backup_retention_days", state._effective_converter_backup_retention_days)

    jobs_deleted = await _cleanup_jobs()
    converter_summary = await _cleanup_converter()
    return {
        "ok": True,
        "jobs_deleted": jobs_deleted,
        "converter": converter_summary,
        "effective_retention_days": {
            "jobs": _eff_job_ret(),
            "converter_sessions": _eff_conv_sess_ret(),
            "converter_backups": _eff_conv_bak_ret(),
        },
    }
