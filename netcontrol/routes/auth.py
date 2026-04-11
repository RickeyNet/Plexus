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

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

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

# ── python-ldap imports (optional) ───────────────────────────────────────────

try:
    import ldap as python_ldap
    from ldap.dn import escape_dn_chars as _escape_dn_chars
    from ldap.filter import escape_filter_chars as _escape_filter_chars
    LDAP_AVAILABLE = True
except Exception:
    python_ldap = None
    _escape_dn_chars = None
    _escape_filter_chars = None
    LDAP_AVAILABLE = False

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


async def upsert_external_user(username: str, display_name: str = "",
                                role: str = "user") -> dict | None:
    """Ensure a local shadow user exists for externally-authenticated identities (RADIUS/LDAP)."""
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
            display_name=display_name or username,
            role=role,
        )
    except ValueError:
        return await db.get_user_by_username(username)
    return await db.get_user_by_id(user_id)


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


# ── LDAP / Active Directory helpers ──────────────────────────────────────────


def _ldap_authenticate_sync(username: str, password: str, ldap_cfg: dict) -> tuple[bool, str, dict]:
    """Perform a blocking LDAP bind authentication.

    Returns (success, status, user_attrs).
    status is one of: "accept", "reject", "error"
    user_attrs may contain: display_name, email, groups
    """
    if not LDAP_AVAILABLE:
        return False, "error", {}
    assert python_ldap is not None

    server = ldap_cfg.get("server", "").strip()
    if not server:
        return False, "error", {}

    port = int(ldap_cfg.get("port", 389))
    use_ssl = bool(ldap_cfg.get("use_ssl", False))
    timeout = int(ldap_cfg.get("timeout", 10))
    bind_dn = ldap_cfg.get("bind_dn", "").strip()
    bind_password = ldap_cfg.get("bind_password", "")
    base_dn = ldap_cfg.get("base_dn", "").strip()
    user_search_filter = ldap_cfg.get("user_search_filter", "(sAMAccountName={username})").strip()
    user_dn_template = ldap_cfg.get("user_dn_template", "").strip()
    group_search_base = ldap_cfg.get("group_search_base", "").strip()
    group_search_filter = ldap_cfg.get("group_search_filter", "").strip()
    tls_verify = str(ldap_cfg.get("tls_verify", "demand")).lower().strip()

    protocol = "ldaps" if use_ssl else "ldap"
    uri = f"{protocol}://{server}:{port}"

    _TLS_LEVEL_MAP = {
        "never": python_ldap.OPT_X_TLS_NEVER,
        "allow": python_ldap.OPT_X_TLS_ALLOW,
        "try": python_ldap.OPT_X_TLS_TRY,
        "demand": python_ldap.OPT_X_TLS_DEMAND,
        "hard": python_ldap.OPT_X_TLS_HARD,
    }

    try:
        conn = python_ldap.initialize(uri)
        conn.set_option(python_ldap.OPT_NETWORK_TIMEOUT, timeout)
        conn.set_option(python_ldap.OPT_TIMEOUT, timeout)
        conn.set_option(python_ldap.OPT_REFERRALS, 0)
        conn.protocol_version = python_ldap.VERSION3

        if use_ssl:
            tls_level = _TLS_LEVEL_MAP.get(tls_verify, python_ldap.OPT_X_TLS_DEMAND)
            conn.set_option(python_ldap.OPT_X_TLS_REQUIRE_CERT, tls_level)
            conn.set_option(python_ldap.OPT_X_TLS_NEWCTX, 0)
            if tls_verify == "allow":
                LOGGER.warning("ldap: TLS certificate verification is permissive (allow) — use 'demand' in production")

        user_dn = None
        user_attrs: dict = {}

        if user_dn_template:
            # Direct bind: template like "CN={username},OU=Users,DC=corp,DC=local"
            user_dn = user_dn_template.replace("{username}", _escape_dn_chars(username))
        elif bind_dn and base_dn:
            # Search bind: first bind as service account, then search for user
            try:
                conn.simple_bind_s(bind_dn, bind_password)
            except python_ldap.INVALID_CREDENTIALS:
                LOGGER.warning("ldap: service account bind failed — check bind_dn / bind_password")
                return False, "error", {}

            search_filter = user_search_filter.replace("{username}", _escape_filter_chars(username))
            try:
                result = conn.search_s(
                    base_dn, python_ldap.SCOPE_SUBTREE, search_filter,
                    ["dn", "displayName", "mail", "sAMAccountName", "cn", "memberOf"],
                )
            except python_ldap.NO_SUCH_OBJECT:
                return False, "reject", {}

            # Filter out referrals (entries with dn=None)
            entries = [(dn, attrs) for dn, attrs in result if dn is not None]
            if not entries:
                return False, "reject", {}

            user_dn = entries[0][0]
            raw_attrs = entries[0][1]

            # Decode LDAP byte values
            def _first_str(attr_name):
                vals = raw_attrs.get(attr_name, [])
                if vals and isinstance(vals[0], bytes):
                    return vals[0].decode("utf-8", errors="replace")
                return str(vals[0]) if vals else ""

            user_attrs["display_name"] = _first_str("displayName") or _first_str("cn") or username
            user_attrs["email"] = _first_str("mail")
            user_attrs["groups"] = [
                g.decode("utf-8", errors="replace") if isinstance(g, bytes) else str(g)
                for g in raw_attrs.get("memberOf", [])
            ]

            # Unbind the service account before re-binding as the user
            conn.unbind_s()
            conn = python_ldap.initialize(uri)
            conn.set_option(python_ldap.OPT_NETWORK_TIMEOUT, timeout)
            conn.set_option(python_ldap.OPT_TIMEOUT, timeout)
            conn.set_option(python_ldap.OPT_REFERRALS, 0)
            conn.protocol_version = python_ldap.VERSION3
            if use_ssl:
                conn.set_option(python_ldap.OPT_X_TLS_REQUIRE_CERT, python_ldap.OPT_X_TLS_ALLOW)
                conn.set_option(python_ldap.OPT_X_TLS_NEWCTX, 0)
        else:
            # No service account and no template — try direct bind with UPN
            user_dn = f"{username}@{base_dn}" if base_dn else username

        if not user_dn:
            return False, "error", {}

        # Authenticate the user by binding with their credentials
        try:
            conn.simple_bind_s(user_dn, password)
        except python_ldap.INVALID_CREDENTIALS:
            return False, "reject", user_attrs

        # If we didn't get attributes from the search, fetch them now
        if not user_attrs.get("display_name") and base_dn:
            try:
                search_filter = user_search_filter.replace("{username}", _escape_filter_chars(username))
                result = conn.search_s(
                    base_dn, python_ldap.SCOPE_SUBTREE, search_filter,
                    ["displayName", "mail", "cn", "memberOf"],
                )
                entries = [(dn, attrs) for dn, attrs in result if dn is not None]
                if entries:
                    raw_attrs = entries[0][1]

                    def _first(attr):
                        vals = raw_attrs.get(attr, [])
                        if vals and isinstance(vals[0], bytes):
                            return vals[0].decode("utf-8", errors="replace")
                        return str(vals[0]) if vals else ""

                    user_attrs["display_name"] = _first("displayName") or _first("cn") or username
                    user_attrs["email"] = _first("mail")
                    user_attrs["groups"] = [
                        g.decode("utf-8", errors="replace") if isinstance(g, bytes) else str(g)
                        for g in raw_attrs.get("memberOf", [])
                    ]
            except Exception as exc:
                LOGGER.warning("ldap: failed to retrieve user attributes for '%s': %s", username, exc)

        # Fetch group memberships if a group search is configured
        if group_search_base and group_search_filter and not user_attrs.get("groups"):
            try:
                gfilter = group_search_filter.replace("{user_dn}", _escape_filter_chars(user_dn)).replace("{username}", _escape_filter_chars(username))
                g_result = conn.search_s(group_search_base, python_ldap.SCOPE_SUBTREE, gfilter, ["dn", "cn"])
                user_attrs["groups"] = [
                    dn for dn, _ in g_result if dn is not None
                ]
            except Exception as exc:
                LOGGER.warning("ldap: group search failed for '%s': %s", username, exc)

        conn.unbind_s()
        return True, "accept", user_attrs

    except python_ldap.SERVER_DOWN:
        LOGGER.warning("ldap: server %s unreachable", server)
        return False, "error", {}
    except python_ldap.INVALID_CREDENTIALS:
        return False, "reject", {}
    except Exception as exc:
        LOGGER.warning("ldap: authentication error: %s", str(exc))
        return False, "error", {}


async def verify_ldap_user(username: str, password: str) -> tuple[bool, str, dict]:
    """Returns (is_authenticated, status, user_attrs)."""
    ldap_cfg = state.AUTH_CONFIG.get("ldap", {})
    return await asyncio.to_thread(_ldap_authenticate_sync, username, password, ldap_cfg)


async def upsert_ldap_user(username: str, ldap_attrs: dict) -> dict | None:
    """Ensure a local shadow user exists for LDAP-authenticated identities.

    If the user has groups that match admin_group_dn, promote to admin role.
    """
    ldap_cfg = state.AUTH_CONFIG.get("ldap", {})
    admin_group_dn = ldap_cfg.get("admin_group_dn", "").strip().lower()
    default_role = ldap_cfg.get("default_role", "user")

    # Determine role from group membership
    role = default_role
    user_groups = [g.lower() for g in ldap_attrs.get("groups", [])]
    if admin_group_dn and any(g == admin_group_dn for g in user_groups):
        role = "admin"

    display_name = ldap_attrs.get("display_name", "") or username

    return await upsert_external_user(username, display_name=display_name, role=role)


def _dev_bootstrap_enabled() -> bool:
    # Require explicit opt-in via env var; "test" alone is not sufficient
    # to avoid accidental bootstrap with real data.
    if _env_flag("PLEXUS_DEV_BOOTSTRAP", False):
        return True
    env = os.getenv("APP_ENV", "").strip().lower()
    if env in {"dev", "development", "local"}:
        return True
    return False


def _dev_bootstrap_username() -> str:
    raw = os.getenv("PLEXUS_INITIAL_ADMIN_USERNAME", "admin").strip()
    if not raw:
        return "admin"
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    cleaned = "".join(ch for ch in raw if ch in allowed).strip("._-")
    return cleaned or "admin"


def _dev_bootstrap_password() -> str:
    return os.getenv("PLEXUS_DEFAULT_ADMIN_PASSWORD", "netcontrol").strip() or "netcontrol"


async def _authenticate_dev_bootstrap(username: str, password: str) -> dict | None:
    """Dev-only deterministic local admin login.

    If APP_ENV indicates development (or PLEXUS_DEV_BOOTSTRAP=true), allow
    login with bootstrap credentials and ensure the corresponding local admin
    account exists with must_change_password=False.
    """
    if not _dev_bootstrap_enabled():
        return None

    expected_username = _dev_bootstrap_username()
    expected_password = _dev_bootstrap_password()
    if username != expected_username or password != expected_password:
        return None

    if _hash_password_fn is None:
        return None

    user = await db.get_user_by_username(expected_username)
    salt = secrets.token_hex(16)
    pw_hash = _hash_password_fn(expected_password, salt)

    if user:
        await db.update_user_admin(int(user["id"]), role="admin")
        await db.update_user_password(int(user["id"]), pw_hash, salt, must_change_password=False)
    else:
        try:
            await db.create_user(
                expected_username,
                pw_hash,
                salt,
                display_name="Administrator",
                role="admin",
                must_change_password=False,
            )
        except ValueError:
            pass

    return await db.get_user_by_username(expected_username)


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

    # Dev bootstrap shortcut: deterministic local admin credentials.
    dev_bootstrap_user = await _authenticate_dev_bootstrap(username, password)
    if dev_bootstrap_user:
        return dev_bootstrap_user, "local-dev-bootstrap", None

    # Break-glass: always allow local admin credentials when enabled, even if
    # the primary auth provider is LDAP/RADIUS and local fallback is disabled.
    # This prevents lockout after external auth misconfiguration.
    allow_breakglass = _env_flag("PLEXUS_BREAKGLASS_LOCAL_ADMIN", True)
    if allow_breakglass:
        local_admin = await _verify_local(username, password)
        if local_admin and (local_admin.get("role") or "").lower() == "admin":
            return local_admin, "local-admin-breakglass", None

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

    # LDAP / Active Directory provider
    ldap_cfg = auth_config.get("ldap", {})
    ldap_enabled = bool(ldap_cfg.get("enabled"))

    if provider == "ldap" and ldap_enabled:
        accepted, status, ldap_attrs = await verify_ldap_user(username, password)
        if accepted:
            user = await upsert_ldap_user(username, ldap_attrs)
            if user:
                return user, "ldap", None
            return None, None, "LDAP login succeeded but local account provisioning failed"

        if status == "reject" and not bool(ldap_cfg.get("fallback_on_reject", False)):
            return None, None, "Invalid username or password"

        if bool(ldap_cfg.get("fallback_to_local", True)):
            local_user = await _verify_local(username, password)
            if local_user:
                return local_user, "local-fallback", None
            if status == "error":
                return None, None, "LDAP server is unavailable and local fallback credentials failed"
            return None, None, "Invalid username or password"

        if status == "error":
            return None, None, "LDAP authentication service unavailable"
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
    if effective is None:
        # No group_memberships rows at all — legacy/unassigned user.
        # Default to empty (least-privilege).  Admins should assign groups.
        return []
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

_login_lock = asyncio.Lock()


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

    # Acquire lock for rate-limit check (prevent concurrent bypass)
    async with _login_lock:
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

    # Auth identity check runs outside lock (may be slow: LDAP/RADIUS)
    user, auth_source, auth_error = await _auth_identity(body.username, body.password)

    # Re-acquire lock for result tracking
    async with _login_lock:
        if not user:
            # Re-fetch the canonical list (may have been mutated by a
            # concurrent request while we were outside the lock).
            attempts = LOGIN_ATTEMPTS.get(ip, [])
            attempts = [t for t in attempts if now - t < LOGIN_RULES["rate_limit_window"]]
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
    # Use the canonical username from the DB (may differ in case from input)
    canonical_user = user["username"]
    await _audit_fn("auth", "login.success", user=canonical_user, detail=f"source={auth_source}", correlation_id=_corr_id(request))
    token = _create_session_token_fn(canonical_user, user["id"])
    csrf_token = _generate_csrf_token(canonical_user)
    response = JSONResponse({
        "ok": True,
        "username": canonical_user,
        "user_id": user["id"],
        "display_name": user["display_name"] or canonical_user,
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
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
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


# Per-user rate limiter for change-password (keyed on user_id)
_PASSWORD_CHANGE_ATTEMPTS: dict[int, list[float]] = {}
_PASSWORD_CHANGE_MAX = 5       # max attempts per window
_PASSWORD_CHANGE_WINDOW = 300  # 5-minute window


@router.post("/api/auth/change-password", dependencies=[Depends(_require_auth_dep)])
async def change_password(body: ChangePasswordRequest, request: Request):
    session = _get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Rate-limit password verification attempts per user
    uid = session["user_id"]
    now = time.time()
    attempts = [t for t in _PASSWORD_CHANGE_ATTEMPTS.get(uid, []) if now - t < _PASSWORD_CHANGE_WINDOW]
    if len(attempts) >= _PASSWORD_CHANGE_MAX:
        raise HTTPException(status_code=429, detail="Too many password change attempts. Try again later.")

    user = await _verify_user_fn(session["user"], body.current_password)
    if not user:
        attempts.append(now)
        _PASSWORD_CHANGE_ATTEMPTS[uid] = attempts
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(status_code=400, detail="New password must be different from your current password")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
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
