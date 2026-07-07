"""
admin.py -- Core admin routes: capabilities, security-check, users CRUD,
access-groups CRUD, audit-events, login-rules, auth-config, retention cleanup.

Domain-specific admin routes (discovery-sync, topology-discovery, config-drift,
config-backups, compliance, monitoring, SNMP) remain in app.py for now.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import sys

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

import netcontrol.routes.state as state
from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.routes.state import _env_flag
from netcontrol.telemetry import configure_logging, configure_syslog_logging, syslog_logging_enabled

LOGGER = configure_logging("plexus.admin")

# ── Late-binding dependency injection ─────────────────────────────────────────

_require_admin = None
_hash_password_fn = None
_get_user_features_fn = None
_cleanup_expired_jobs_fn = None


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
):
    """Called from app.py after helpers are defined."""
    global _require_admin, _hash_password_fn, _get_user_features_fn
    global _cleanup_expired_jobs_fn
    _require_admin = require_admin_fn
    _hash_password_fn = hash_password_fn
    _get_user_features_fn = get_user_features_fn
    _cleanup_expired_jobs_fn = cleanup_expired_jobs_fn


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
    session_never_expires: bool | None = None


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
    session_idle_timeout: int = 1800


class RadiusConfigRequest(BaseModel):
    enabled: bool = False
    server: str = ""
    port: int = 1812
    secret: str = ""
    timeout: int = 5
    fallback_to_local: bool = True
    fallback_on_reject: bool = False
    default_group_ids: list[int] = []


class LdapConfigRequest(BaseModel):
    enabled: bool = False
    server: str = ""
    port: int = 389
    use_ssl: bool = False
    bind_dn: str = ""
    bind_password: str = ""
    base_dn: str = ""
    user_search_filter: str = "(sAMAccountName={username})"
    user_dn_template: str = ""
    group_search_base: str = ""
    group_search_filter: str = "(&(objectClass=group)(member={user_dn}))"
    admin_group_dn: str = ""
    default_role: str = "user"
    timeout: int = 10
    fallback_to_local: bool = True
    fallback_on_reject: bool = False


class AuthConfigRequest(BaseModel):
    provider: str = "local"
    default_credential_id: int | None = None
    service_credential_id: int | None = None
    job_retention_days: int = Field(default=30, ge=30)
    radius: RadiusConfigRequest = RadiusConfigRequest()
    ldap: LdapConfigRequest = LdapConfigRequest()


class SyslogConfigRequest(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = Field(default=514, ge=1, le=65535)
    protocol: str = "udp"
    facility: str = "local0"
    level: str = "INFO"
    app_name: str = "plexus"


class SiemSinkRequest(BaseModel):
    """One audit-event forwarding sink. Validated by
    siem_forwarder.sanitize_sink before being stored."""

    id: str = ""  # generated if blank on create
    name: str = ""
    enabled: bool = True
    protocol: str = "udp"     # udp | tcp | tls | https
    format: str = "json"      # cef | json
    host: str = ""
    port: int = Field(default=514, ge=1, le=65535)
    url: str = ""
    bearer_token: str = ""
    tls_verify: bool = True
    tls_ca_pem: str = ""
    tls_client_cert_pem: str = ""
    tls_client_key_pem: str = ""
    severity_floor: str = "info"
    queue_size: int = Field(default=1000, ge=10, le=100_000)
    max_retries: int = Field(default=5, ge=0, le=20)
    backoff_base: float = Field(default=1.0, ge=0.1, le=30.0)
    backoff_cap: float = Field(default=60.0, ge=1.0, le=600.0)


class NotificationChannelRequest(BaseModel):
    """One outbound alert notification channel. Validated by
    notification_channels.sanitize_channel before being stored."""

    id: str = ""  # generated if blank on create
    name: str = ""
    enabled: bool = True
    type: str = "webhook"  # email | pagerduty | webhook | teams
    severity_floor: str = "warning"
    queue_size: int = Field(default=1000, ge=10, le=100_000)
    max_retries: int = Field(default=4, ge=0, le=20)
    backoff_base: float = Field(default=1.0, ge=0.1, le=30.0)
    backoff_cap: float = Field(default=60.0, ge=1.0, le=600.0)
    # email
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    smtp_username: str = ""
    smtp_password: str = ""
    mail_from: str = ""
    mail_to: str = ""
    # pagerduty
    routing_key: str = ""
    # webhook
    webhook_url: str = ""
    webhook_auth_header: str = ""
    webhook_auth_value: str = ""
    verify_tls: bool = True
    # teams
    teams_webhook_url: str = ""


class NotificationDefaultsRequest(BaseModel):
    """The set of channels used for alerts not tied to a user rule."""

    default_channel_ids: list[str] = Field(default_factory=list)


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
        "session_never_expires": bool(user.get("session_never_expires")),
    }


def _security_check_payload() -> dict:
    """Build a runtime snapshot of transport and app hardening settings.

    Looks up config values through the app module so tests can monkeypatch them.
    """
    _app = _app_module()
    _https = getattr(_app, "APP_HTTPS_ENABLED", APP_HTTPS_ENABLED)
    _hsts = getattr(_app, "APP_HSTS_ENABLED", APP_HSTS_ENABLED)
    _hsts_age = getattr(_app, "APP_HSTS_MAX_AGE", APP_HSTS_MAX_AGE)
    _https_redirect = getattr(_app, "APP_HTTPS_REDIRECT", getattr(state, "APP_HTTPS_REDIRECT", False))
    _cors = getattr(_app, "APP_CORS_ALLOW_ORIGINS", APP_CORS_ALLOW_ORIGINS)
    _api_token = getattr(_app, "APP_API_TOKEN", APP_API_TOKEN)

    api_token_required = _env_flag("APP_REQUIRE_API_TOKEN", False)
    warnings = []
    if not _https:
        warnings.append("APP_HTTPS is false: browser traffic may be sent over HTTP if your proxy does not enforce HTTPS.")
    if not _hsts:
        warnings.append("APP_HSTS is false: browsers are not instructed to enforce HTTPS for future requests.")
    if not _https_redirect:
        warnings.append("APP_HTTPS_REDIRECT is false: plaintext HTTP requests are not redirected to HTTPS at the app level.")
    if not api_token_required:
        warnings.append("APP_REQUIRE_API_TOKEN is false: non-session API calls are not forced to present an API token.")
    if not _api_token:
        warnings.append("APP_API_TOKEN is not set: token-based API auth cannot be used.")

    return {
        "ok": True,
        "transport": {
            "https_enabled": _https,
            "https_redirect": _https_redirect,
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
        "auth_providers": ["local", "radius", "ldap"],
        "feature_visibility": {
            "catalog": state.FEATURE_VISIBILITY_CATALOG,
            "hidden": list(state.FEATURE_VISIBILITY_HIDDEN),
        },
    }


class AdminFeatureVisibilityRequest(BaseModel):
    hidden: list[str] = []


@router.get("/api/admin/feature-visibility")
async def admin_get_feature_visibility():
    return {
        "catalog": state.FEATURE_VISIBILITY_CATALOG,
        "hidden": list(state.FEATURE_VISIBILITY_HIDDEN),
    }


@router.put("/api/admin/feature-visibility")
async def admin_update_feature_visibility(body: AdminFeatureVisibilityRequest, request: Request):
    sanitized = state._sanitize_feature_visibility(body.hidden)
    state.FEATURE_VISIBILITY_HIDDEN = sanitized
    await db.set_auth_setting("feature_visibility", {"hidden": sanitized})
    session = _get_session(request)
    await _audit(
        "auth",
        "feature_visibility.update",
        user=session["user"] if session else "",
        detail=f"hidden={sanitized}",
        correlation_id=_corr_id(request),
    )
    return {
        "catalog": state.FEATURE_VISIBILITY_CATALOG,
        "hidden": list(state.FEATURE_VISIBILITY_HIDDEN),
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
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if body.role is not None and body.role not in {"admin", "user"}:
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'user'")
    role = body.role or "user"

    salt = secrets.token_hex(16)
    pw_hash = await asyncio.to_thread(_hash_password_fn, body.password, salt)
    display = body.display_name.strip() if body.display_name else username.title()
    try:
        user_id = await db.create_user(username, pw_hash, salt, display_name=display, role=role)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if body.group_ids:
        try:
            await db.set_user_groups(user_id, body.group_ids)
        except ValueError as e:
            # Roll back the just-created user so a bad group id doesn't leave an
            # orphaned account (whose name then blocks the admin's retry).
            await db.delete_user(user_id)
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
    if body.role is not None and body.role not in {"admin", "user"}:
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'user'")
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
            session_never_expires=body.session_never_expires,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # A role change alters privileges; revoke the target's outstanding
    # sessions so a demotion/promotion takes effect immediately.
    if role is not None and role != (target.get("role") or ""):
        await db.bump_user_session_epoch(user_id)
    await _audit(
        "auth", "user.update",
        user=session["user"] if session else "",
        detail=f"updated user id={user_id}" + (f" role={role}" if role else ""),
        correlation_id=_corr_id(request),
    )
    user = await db.get_user_by_id(user_id)
    return await _admin_user_payload(user)


@router.put("/api/admin/users/{user_id}/password")
async def admin_reset_user_password(user_id: int, body: AdminUserPasswordResetRequest, request: Request):
    target = await db.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    salt = secrets.token_hex(16)
    pw_hash = await asyncio.to_thread(_hash_password_fn, body.new_password, salt)
    await db.update_user_password(user_id, pw_hash, salt)
    # Force the target off all existing sessions after an admin reset.
    await db.bump_user_session_epoch(user_id)
    session = _get_session(request)
    await _audit(
        "auth", "user.password_reset",
        user=session["user"] if session else "",
        detail=f"reset password for user id={user_id} ('{target.get('username', '')}')",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.put("/api/admin/users/{user_id}/groups")
async def admin_set_user_groups(user_id: int, body: AdminUserGroupAssignmentRequest, request: Request):
    target = await db.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        await db.set_user_groups(user_id, body.group_ids)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # Group membership drives effective feature access; revoke the target's
    # sessions so the new privilege set applies on their next request.
    await db.bump_user_session_epoch(user_id)
    session = _get_session(request)
    await _audit(
        "auth", "user.groups_changed",
        user=session["user"] if session else "",
        detail=f"set groups for user id={user_id}: {body.group_ids}",
        correlation_id=_corr_id(request),
    )
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

    # Atomic last-admin guard (the check lives inside the DELETE), so two
    # concurrent deletes of the final admins can't both slip through.
    outcome = await db.delete_user_guarded(user_id)
    if outcome == "not_found":
        raise HTTPException(status_code=404, detail="User not found")
    if outcome == "last_admin":
        raise HTTPException(status_code=400, detail="Cannot delete the last admin user")
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


@router.get("/api/admin/audit-events/verify")
async def admin_verify_audit_chain():
    """Walk the audit_events hash chain and report tamper status."""
    return await db.verify_audit_chain()


@router.get("/api/admin/login-rules")
async def admin_get_login_rules():
    return state.LOGIN_RULES


@router.put("/api/admin/login-rules")
async def admin_update_login_rules(body: AdminLoginRulesRequest):
    state.LOGIN_RULES = state._sanitize_login_rules(body.dict())
    await db.set_auth_setting("login_rules", state.LOGIN_RULES)
    return state.LOGIN_RULES


_SECRET_MASK = "••••••••"


def _redact_auth_config(cfg: dict) -> dict:
    """Return a copy of auth config with secrets masked for API responses."""
    import copy
    redacted = copy.deepcopy(cfg)
    if redacted.get("radius", {}).get("secret"):
        redacted["radius"]["secret"] = _SECRET_MASK
    if redacted.get("ldap", {}).get("bind_password"):
        redacted["ldap"]["bind_password"] = _SECRET_MASK
    return redacted


@router.get("/api/admin/auth-config")
async def admin_get_auth_config():
    return _redact_auth_config(state.AUTH_CONFIG)


@router.put("/api/admin/auth-config")
async def admin_update_auth_config(body: AuthConfigRequest):
    data = body.dict()
    # Preserve existing secrets when client sends back the redaction mask
    if data.get("radius", {}).get("secret") == _SECRET_MASK:
        data["radius"]["secret"] = state.AUTH_CONFIG.get("radius", {}).get("secret", "")
    if data.get("ldap", {}).get("bind_password") == _SECRET_MASK:
        data["ldap"]["bind_password"] = state.AUTH_CONFIG.get("ldap", {}).get("bind_password", "")
    state.AUTH_CONFIG = state._sanitize_auth_config(data)
    await db.set_auth_setting("auth_config", state.AUTH_CONFIG)
    return _redact_auth_config(state.AUTH_CONFIG)


def _syslog_config_payload() -> dict:
    payload = dict(state.SYSLOG_CONFIG)
    payload["active"] = syslog_logging_enabled()
    return payload


@router.get("/api/admin/syslog-config")
async def admin_get_syslog_config():
    return _syslog_config_payload()


@router.put("/api/admin/syslog-config")
async def admin_update_syslog_config(body: SyslogConfigRequest, request: Request):
    data = body.model_dump() if hasattr(body, "model_dump") else body.dict()
    if data.get("enabled") and not str(data.get("host", "")).strip():
        raise HTTPException(status_code=400, detail="Syslog host is required when enabled")

    sanitized = state._sanitize_syslog_config(data)
    if sanitized.get("enabled") and not configure_syslog_logging(sanitized):
        LOGGER.warning("syslog: failed to configure outbound logging handler")
        raise HTTPException(status_code=400, detail="Unable to configure syslog logging")

    if not sanitized.get("enabled"):
        configure_syslog_logging(sanitized)

    state.SYSLOG_CONFIG = sanitized
    await db.set_auth_setting("syslog_config", state.SYSLOG_CONFIG)
    session = _get_session(request)
    await _audit(
        "system",
        "syslog.config.updated",
        user=session["user"] if session else "",
        detail=(
            f"enabled={state.SYSLOG_CONFIG['enabled']} "
            f"target={state.SYSLOG_CONFIG['host']}:{state.SYSLOG_CONFIG['port']} "
            f"protocol={state.SYSLOG_CONFIG['protocol']}"
        ),
        correlation_id=_corr_id(request),
    )
    return _syslog_config_payload()


@router.post("/api/admin/syslog-config/test")
async def admin_test_syslog_config(request: Request):
    if not state.SYSLOG_CONFIG.get("enabled") or not syslog_logging_enabled():
        raise HTTPException(status_code=400, detail="Syslog logging is not enabled")

    session = _get_session(request)
    LOGGER.info(
        "syslog: test message requested by user=%s target=%s:%s protocol=%s",
        session["user"] if session else "",
        state.SYSLOG_CONFIG.get("host", ""),
        state.SYSLOG_CONFIG.get("port", ""),
        state.SYSLOG_CONFIG.get("protocol", ""),
    )
    await _audit(
        "system",
        "syslog.test",
        user=session["user"] if session else "",
        detail="sent syslog test message",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── SIEM audit-event forwarding ────────────────────────────────────────────

from netcontrol.routes import siem_forwarder  # noqa: E402

# Serializes read-modify-write of the shared `state.SIEM_SINKS` global across
# concurrent admin requests (same rationale as _channel_mutation_lock below).
_sink_mutation_lock = asyncio.Lock()


async def _persist_and_apply_sinks() -> list[dict]:
    """Persist `state.SIEM_SINKS` to auth_settings and reconcile the
    dispatcher. Returns the list of redacted dicts the API surfaces."""
    payload = {"sinks": [siem_forwarder.sink_config_to_dict(sc, redact_secrets=False)
                         for sc in state.SIEM_SINKS]}
    await db.set_auth_setting("siem_sinks", payload)
    await siem_forwarder.apply_sinks(state.SIEM_SINKS)
    return [siem_forwarder.sink_config_to_dict(sc) for sc in state.SIEM_SINKS]


def _sink_index(sink_id: str) -> int:
    for i, sc in enumerate(state.SIEM_SINKS):
        if sc.id == sink_id:
            return i
    return -1


def _merge_secrets(new: dict, existing) -> dict:
    """If the client posts the redaction sentinel for a secret field, keep
    the previously stored value instead of overwriting."""
    mask = "••••••••"
    if existing is None:
        return new
    if new.get("bearer_token") == mask:
        new["bearer_token"] = existing.bearer_token
    if new.get("tls_client_key_pem") == mask:
        new["tls_client_key_pem"] = existing.tls_client_key_pem
    return new


@router.get("/api/admin/siem-sinks")
async def admin_list_siem_sinks():
    """Return the configured sinks (secrets redacted) plus live runtime stats."""
    return {
        "sinks": [siem_forwarder.sink_config_to_dict(sc) for sc in state.SIEM_SINKS],
        "stats": siem_forwarder.get_stats(),
    }


@router.post("/api/admin/siem-sinks")
async def admin_create_siem_sink(body: SiemSinkRequest, request: Request):
    data = body.model_dump()
    if not data.get("id"):
        data["id"] = secrets.token_hex(8)
    sc = siem_forwarder.sanitize_sink(data)
    if sc is None:
        raise HTTPException(status_code=400, detail="Invalid sink configuration")
    async with _sink_mutation_lock:
        if _sink_index(sc.id) >= 0:
            raise HTTPException(status_code=409, detail="Sink id already exists")
        state.SIEM_SINKS.append(sc)
        redacted = await _persist_and_apply_sinks()
    session = _get_session(request)
    await _audit(
        "system",
        "siem.sink.create",
        user=session["user"] if session else "",
        detail=f"sink={sc.id} protocol={sc.protocol} format={sc.format}",
        correlation_id=_corr_id(request),
    )
    return next((s for s in redacted if s["id"] == sc.id), None)


@router.put("/api/admin/siem-sinks/{sink_id}")
async def admin_update_siem_sink(sink_id: str, body: SiemSinkRequest, request: Request):
    async with _sink_mutation_lock:
        idx = _sink_index(sink_id)
        if idx < 0:
            raise HTTPException(status_code=404, detail="Sink not found")
        data = body.model_dump()
        data["id"] = sink_id
        data = _merge_secrets(data, state.SIEM_SINKS[idx])
        sc = siem_forwarder.sanitize_sink(data)
        if sc is None:
            raise HTTPException(status_code=400, detail="Invalid sink configuration")
        state.SIEM_SINKS[idx] = sc
        redacted = await _persist_and_apply_sinks()
    session = _get_session(request)
    await _audit(
        "system",
        "siem.sink.update",
        user=session["user"] if session else "",
        detail=f"sink={sc.id} protocol={sc.protocol} enabled={sc.enabled}",
        correlation_id=_corr_id(request),
    )
    return next((s for s in redacted if s["id"] == sc.id), None)


@router.delete("/api/admin/siem-sinks/{sink_id}")
async def admin_delete_siem_sink(sink_id: str, request: Request):
    async with _sink_mutation_lock:
        idx = _sink_index(sink_id)
        if idx < 0:
            raise HTTPException(status_code=404, detail="Sink not found")
        state.SIEM_SINKS.pop(idx)
        await _persist_and_apply_sinks()
    session = _get_session(request)
    await _audit(
        "system",
        "siem.sink.delete",
        user=session["user"] if session else "",
        detail=f"sink={sink_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/admin/siem-sinks/{sink_id}/test")
async def admin_test_siem_sink(sink_id: str, request: Request):
    """Synthesize a probe event and deliver it through the configured sink.
    Useful for verifying credentials/connectivity from the Settings UI."""
    idx = _sink_index(sink_id)
    if idx < 0:
        raise HTTPException(status_code=404, detail="Sink not found")
    result = await siem_forwarder.send_test_event(sink_id)
    session = _get_session(request)
    await _audit(
        "system",
        "siem.sink.test",
        user=session["user"] if session else "",
        detail=f"sink={sink_id} ok={result['ok']} error={result['error']}",
        correlation_id=_corr_id(request),
    )
    return result


# ── Alert notification channels ────────────────────────────────────────────

from netcontrol.routes import notification_channels  # noqa: E402

# Serializes read-modify-write of the shared `state.NOTIFICATION_CHANNELS` /
# NOTIFICATION_DEFAULT_CHANNEL_IDS globals across concurrent admin requests.
# Without it, two interleaved create/update/delete calls each rebuild the DB
# payload from the shared list at different points, so the last set_auth_setting
# to land can clobber a concurrent change (lost update) or the id-uniqueness
# check can race the append.
_channel_mutation_lock = asyncio.Lock()


async def _persist_and_apply_channels() -> list[dict]:
    """Persist `state.NOTIFICATION_CHANNELS` + defaults to auth_settings and
    reconcile the dispatcher. Returns the list of redacted dicts for the API."""
    payload = {
        "channels": [
            notification_channels.channel_config_to_dict(c, redact_secrets=False)
            for c in state.NOTIFICATION_CHANNELS
        ],
        "default_channel_ids": list(state.NOTIFICATION_DEFAULT_CHANNEL_IDS),
    }
    await db.set_auth_setting("notification_channels", payload)
    await notification_channels.apply_channels(
        state.NOTIFICATION_CHANNELS, state.NOTIFICATION_DEFAULT_CHANNEL_IDS)
    return [notification_channels.channel_config_to_dict(c)
            for c in state.NOTIFICATION_CHANNELS]


def _channel_index(channel_id: str) -> int:
    for i, c in enumerate(state.NOTIFICATION_CHANNELS):
        if c.id == channel_id:
            return i
    return -1


@router.get("/api/admin/notification-channels")
async def admin_list_notification_channels():
    """Return configured channels (secrets redacted), default channel ids, and
    live runtime stats."""
    return {
        "channels": [notification_channels.channel_config_to_dict(c)
                     for c in state.NOTIFICATION_CHANNELS],
        "default_channel_ids": list(state.NOTIFICATION_DEFAULT_CHANNEL_IDS),
        "stats": notification_channels.get_stats(),
    }


@router.post("/api/admin/notification-channels")
async def admin_create_notification_channel(body: NotificationChannelRequest, request: Request):
    data = body.model_dump()
    if not data.get("id"):
        data["id"] = secrets.token_hex(8)
    cfg = notification_channels.sanitize_channel(data)
    if cfg is None:
        raise HTTPException(status_code=400, detail="Invalid channel configuration")
    async with _channel_mutation_lock:
        if _channel_index(cfg.id) >= 0:
            raise HTTPException(status_code=409, detail="Channel id already exists")
        state.NOTIFICATION_CHANNELS.append(cfg)
        redacted = await _persist_and_apply_channels()
    session = _get_session(request)
    await _audit(
        "system",
        "notification.channel.create",
        user=session["user"] if session else "",
        detail=f"channel={cfg.id} type={cfg.type}",
        correlation_id=_corr_id(request),
    )
    return next((c for c in redacted if c["id"] == cfg.id), None)


@router.put("/api/admin/notification-channels/{channel_id}")
async def admin_update_notification_channel(
    channel_id: str, body: NotificationChannelRequest, request: Request,
):
    async with _channel_mutation_lock:
        idx = _channel_index(channel_id)
        if idx < 0:
            raise HTTPException(status_code=404, detail="Channel not found")
        data = body.model_dump()
        data["id"] = channel_id
        data = notification_channels.merge_secrets(data, state.NOTIFICATION_CHANNELS[idx])
        cfg = notification_channels.sanitize_channel(data)
        if cfg is None:
            raise HTTPException(status_code=400, detail="Invalid channel configuration")
        state.NOTIFICATION_CHANNELS[idx] = cfg
        redacted = await _persist_and_apply_channels()
    session = _get_session(request)
    await _audit(
        "system",
        "notification.channel.update",
        user=session["user"] if session else "",
        detail=f"channel={cfg.id} type={cfg.type} enabled={cfg.enabled}",
        correlation_id=_corr_id(request),
    )
    return next((c for c in redacted if c["id"] == cfg.id), None)


@router.delete("/api/admin/notification-channels/{channel_id}")
async def admin_delete_notification_channel(channel_id: str, request: Request):
    async with _channel_mutation_lock:
        idx = _channel_index(channel_id)
        if idx < 0:
            raise HTTPException(status_code=404, detail="Channel not found")
        state.NOTIFICATION_CHANNELS.pop(idx)
        # Drop the deleted channel from the default set too.
        state.NOTIFICATION_DEFAULT_CHANNEL_IDS = [
            c for c in state.NOTIFICATION_DEFAULT_CHANNEL_IDS if c != channel_id
        ]
        await _persist_and_apply_channels()
    session = _get_session(request)
    await _audit(
        "system",
        "notification.channel.delete",
        user=session["user"] if session else "",
        detail=f"channel={channel_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.put("/api/admin/notification-channels-defaults")
async def admin_set_notification_defaults(body: NotificationDefaultsRequest, request: Request):
    """Set the default channel set used for alerts not tied to a user rule."""
    async with _channel_mutation_lock:
        valid_ids = {c.id for c in state.NOTIFICATION_CHANNELS}
        state.NOTIFICATION_DEFAULT_CHANNEL_IDS = [
            cid for cid in body.default_channel_ids if cid in valid_ids
        ]
        await _persist_and_apply_channels()
    session = _get_session(request)
    await _audit(
        "system",
        "notification.defaults.update",
        user=session["user"] if session else "",
        detail=f"defaults={state.NOTIFICATION_DEFAULT_CHANNEL_IDS}",
        correlation_id=_corr_id(request),
    )
    return {"default_channel_ids": list(state.NOTIFICATION_DEFAULT_CHANNEL_IDS)}


@router.post("/api/admin/notification-channels/{channel_id}/test")
async def admin_test_notification_channel(channel_id: str, request: Request):
    """Deliver a synthetic probe alert through the channel so the operator can
    verify credentials/connectivity from the Settings UI."""
    if _channel_index(channel_id) < 0:
        raise HTTPException(status_code=404, detail="Channel not found")
    result = await notification_channels.send_test_event(channel_id)
    session = _get_session(request)
    await _audit(
        "system",
        "notification.channel.test",
        user=session["user"] if session else "",
        detail=f"channel={channel_id} ok={result['ok']} error={result['error']}",
        correlation_id=_corr_id(request),
    )
    return result


@router.post("/api/admin/retention/cleanup-now")
async def admin_run_retention_cleanup_now():
    """Run retention cleanup immediately for jobs.

    Looks up cleanup functions and retention helpers through the app module
    so that tests can monkeypatch them on ``app_module``.
    """
    _app = _app_module()
    _cleanup_jobs = getattr(_app, "_cleanup_expired_jobs", _cleanup_expired_jobs_fn)
    _eff_job_ret = getattr(_app, "_effective_job_retention_days", state._effective_job_retention_days)

    jobs_deleted = await _cleanup_jobs()
    return {
        "ok": True,
        "jobs_deleted": jobs_deleted,
        "effective_retention_days": {
            "jobs": _eff_job_ret(),
        },
    }
