"""
auth.py -- Authentication routes: login, register, logout, status, profile, change-password.

Includes RADIUS, TACACS+ and LDAP authentication helpers and login rate-limiting logic.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import re
import secrets
import sys
import time
from collections.abc import Callable

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer
from pydantic import BaseModel, Field

import netcontrol.routes.state as state
from netcontrol import object_scope, oidc, saml
from netcontrol.routes.shared import _audit, _corr_id, _get_session, _request_scheme
from netcontrol.routes.state import _env_flag
from netcontrol.sso import SsoError, SsoIdentity, safe_next
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

# ── tacacs_plus imports (optional) ───────────────────────────────────────────

try:
    from tacacs_plus.client import TACACSClient
    from tacacs_plus.flags import (
        TAC_PLUS_AUTHEN_TYPE_ASCII,
        TAC_PLUS_AUTHEN_TYPE_PAP,
        TAC_PLUS_AUTHOR_STATUS_ERROR,
    )

    TACACS_AVAILABLE = True
except Exception:
    TACACSClient = None
    TAC_PLUS_AUTHEN_TYPE_ASCII = 0x01
    TAC_PLUS_AUTHEN_TYPE_PAP = 0x02
    TAC_PLUS_AUTHOR_STATUS_ERROR = 0x11
    TACACS_AVAILABLE = False

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

# Session / cookie constants - injected from app.py
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
    # Defense in depth (mirrors the LDAP guard): never send an empty
    # password to the RADIUS server - the API layer already rejects it,
    # but this function must stay safe if called from a new path.
    if not password:
        return False, "reject"
    if not PYRAD_AVAILABLE:
        LOGGER.warning("radius: pyrad library is not installed - cannot authenticate")
        return False, "error"
    assert RadiusClient is not None and RadiusDictionary is not None and radius_packet is not None
    server = radius_cfg.get("server", "")
    if not server or not radius_cfg.get("secret"):
        LOGGER.warning("radius: server or shared secret not configured")
        return False, "error"

    dictionary_path = _ensure_radius_dictionary_file()
    try:
        client = RadiusClient(
            server=server,
            secret=radius_cfg["secret"].encode("utf-8"),
            dict=RadiusDictionary(dictionary_path),
            authport=int(radius_cfg.get("port", 1812)),
            timeout=int(radius_cfg.get("timeout", 5)),
            # Blast-RADIUS (CVE-2024-3596) mitigation: adds Message-Authenticator
            # to the Access-Request and rejects replies that omit or fail it.
            # Requires a server that echoes the attribute (post-CVE releases do).
            enforce_ma=bool(radius_cfg.get("enforce_message_authenticator", False)),
        )
        req = client.CreateAuthPacket(code=radius_packet.AccessRequest, User_Name=username)
        req["User-Password"] = req.PwCrypt(password)
        req["NAS-Identifier"] = "plexus"
        reply = client.SendPacket(req)
        if reply.code == radius_packet.AccessAccept:
            LOGGER.info("radius: user '%s' accepted by %s", username, server)
            return True, "accept"
        if reply.code == radius_packet.AccessReject:
            LOGGER.info("radius: user '%s' rejected by %s", username, server)
            return False, "reject"
        LOGGER.warning("radius: unexpected reply code %s from %s for user '%s'", reply.code, server, username)
        return False, "reject"
    except (TimeoutError, OSError) as exc:
        LOGGER.warning("radius: server %s unreachable for user '%s': %s", server, username, exc)
        return False, "error"
    except Exception as exc:
        LOGGER.warning("radius: authentication error for user '%s': %s", username, exc)
        return False, "error"


async def verify_radius_user(username: str, password: str) -> tuple[bool, str]:
    """Returns (is_authenticated, status) where status is accept/reject/error."""
    radius_cfg = state.AUTH_CONFIG.get("radius", {})
    return await asyncio.to_thread(_radius_authenticate_sync, username, password, radius_cfg)


async def upsert_external_user(
    username: str,
    display_name: str = "",
    role: str = "user",
    provider: str = "",
    sync_role: bool = False,
) -> dict | None:
    """Ensure a local shadow user exists for externally-authenticated identities (RADIUS/LDAP).

    Guards against directory name-collision privilege escalation: if a local
    account with this username already exists as an ``admin`` but the external
    provider did NOT explicitly map this identity to admin (``role != "admin"``),
    refuse to adopt it. Otherwise anyone who controls a directory account named
    like a local admin (e.g. ``admin``) would authenticate straight into the
    local admin account. Legitimate local admins still log in via the
    break-glass local-password path; LDAP admin-group members pass ``role=admin``
    and are allowed through.

    Provenance and re-sync: ``users.auth_provider`` records which provider
    manages an account. Adopting an unmanaged account claims it (stamps the
    provider) so pre-provenance shadow users converge after one login. When
    ``sync_role`` is set (LDAP, whose directory groups are authoritative), the
    role and display name are re-synced on every login - directory promotion
    AND demotion both propagate, including demotion of accounts promoted only
    in the Plexus UI. RADIUS asserts no role, so it never passes sync_role.
    """
    user = await db.get_user_by_username(username)
    if user:
        current_role = (user.get("role") or "").lower()
        managed = bool(provider) and (user.get("auth_provider") or "") == provider
        if not managed:
            if current_role == "admin" and role != "admin":
                LOGGER.warning(
                    "auth: refusing to bind external identity '%s' onto pre-existing "
                    "local admin account (external mapping did not grant admin)",
                    username,
                )
                return None
            if provider:
                await db.set_user_auth_provider(int(user["id"]), provider)
        if sync_role:
            updates: dict = {}
            if role != current_role:
                updates["role"] = role
            if display_name and display_name != (user.get("display_name") or ""):
                updates["display_name"] = display_name
            if updates:
                await db.update_user_admin(int(user["id"]), **updates)
                LOGGER.info(
                    "auth: re-synced %s-managed account '%s' from directory (%s)",
                    provider,
                    username,
                    ", ".join(sorted(updates)),
                )
                user = await db.get_user_by_username(username)
        return user

    salt = secrets.token_hex(16)
    random_pw = secrets.token_urlsafe(32)
    pw_hash = await asyncio.to_thread(_hash_password_fn, random_pw, salt)
    try:
        user_id = await db.create_user(
            username,
            pw_hash,
            salt,
            display_name=display_name or username,
            role=role,
            auth_provider=provider,
        )
    except ValueError:
        return await db.get_user_by_username(username)
    return await db.get_user_by_id(user_id)


async def upsert_radius_user(username: str) -> dict | None:
    """Ensure a local shadow user exists for RADIUS-authenticated identities."""
    existing = await db.get_user_by_username(username)
    user = existing or await upsert_external_user(username, provider="radius")
    if user and not existing:
        group_ids = state.AUTH_CONFIG.get("radius", {}).get("default_group_ids", [])
        if group_ids:
            try:
                await db.set_user_groups(int(user["id"]), group_ids)
                user = await db.get_user_by_id(int(user["id"]))
            except ValueError:
                LOGGER.warning("radius: default access group assignment failed for user '%s'", username)
    return user


# ── TACACS+ helpers ──────────────────────────────────────────────────────────
#
# TACACS+ (RFC 8907) is the protocol Cisco ISE "Device Admin" speaks to
# switches and routers.  Compared with the RADIUS-PAP path above it (a)
# obfuscates the *whole* packet body under the shared secret rather than
# only the password, (b) runs over TCP/49 so replies can't be spoofed by
# an off-path attacker, and (c) has a separate authorization exchange
# that lets the server hand back attributes - which Plexus uses to map
# an ISE shell profile onto a Plexus role.  The obfuscation is an MD5
# keystream (the RFC calls it obfuscation, not encryption) so it belongs
# on a trusted management network, exactly like the switches it fronts.

_TACACS_AUTHEN_TYPES = ("ascii", "pap")
_TACACS_DEFAULT_ROLE_ATTRIBUTE = "plexus-role"


def _parse_tacacs_av_pairs(raw_args) -> dict[str, str]:
    """Decode TACACS+ authorization AV pairs into a ``{name: value}`` dict.

    RFC 8907 §6.1: mandatory attributes use ``name=value``, optional ones
    ``name*value``.  Both forms are accepted; a later duplicate wins.
    Names are lower-cased for lookup, values are kept verbatim.
    """
    out: dict[str, str] = {}
    for arg in raw_args or []:
        if isinstance(arg, bytes):
            try:
                arg = arg.decode("utf-8", errors="replace")
            except Exception:  # pragma: no cover - decode never raises with replace
                continue
        arg = str(arg)
        eq, star = arg.find("="), arg.find("*")
        cut = min(i for i in (eq, star) if i >= 0) if (eq >= 0 or star >= 0) else -1
        if cut <= 0:
            continue
        out[arg[:cut].strip().lower()] = arg[cut + 1 :].strip()
    return out


def _tacacs_role_from_attrs(attrs: dict[str, str], tacacs_cfg: dict) -> tuple[str, int | None]:
    """Map authorization attributes onto a Plexus role.

    Precedence:
      1. ``role_attribute`` (default ``plexus-role``) present with value
         ``admin`` / ``user`` - an explicit assertion from the ISE shell
         profile's custom attributes.
      2. ``priv-lvl`` >= ``admin_priv_lvl`` (default 15) - the same
         signal switches use for enable-level access.  ``admin_priv_lvl``
         of 0 disables this rule.
      3. ``default_role``.

    Returns ``(role, priv_lvl)``; ``priv_lvl`` is None when the server
    sent none or it wasn't an integer.
    """
    role_attr = (tacacs_cfg.get("role_attribute") or _TACACS_DEFAULT_ROLE_ATTRIBUTE).strip().lower()
    default_role = tacacs_cfg.get("default_role") or "user"
    if default_role not in ("user", "admin"):
        default_role = "user"

    priv_lvl: int | None = None
    raw_priv = attrs.get("priv-lvl")
    if raw_priv is not None:
        try:
            priv_lvl = int(raw_priv)
        except TypeError, ValueError:
            priv_lvl = None

    asserted = (attrs.get(role_attr) or "").strip().lower()
    if asserted in ("admin", "user"):
        return asserted, priv_lvl

    try:
        admin_priv_lvl = int(tacacs_cfg.get("admin_priv_lvl", 15))
    except TypeError, ValueError:
        admin_priv_lvl = 15
    if admin_priv_lvl > 0 and priv_lvl is not None and priv_lvl >= admin_priv_lvl:
        return "admin", priv_lvl

    return default_role, priv_lvl


def _tacacs_authenticate_sync(username: str, password: str, tacacs_cfg: dict) -> tuple[bool, str, dict]:
    """Blocking TACACS+ authentication (+ optional authorization).

    Returns ``(accepted, status, attrs)`` where ``status`` is one of
    ``accept`` / ``reject`` / ``error`` and ``attrs`` carries
    ``role``, ``priv_lvl`` and the raw ``attributes`` dict from the
    authorization reply (empty when authorization is disabled).

    Authorization is a *second* exchange after a PASS: Plexus asks for
    ``service=shell cmd=`` (the exec-authorization request every Cisco
    device sends at login) so an ISE TACACS profile / shell profile
    applies unchanged.  An authorization FAIL is surfaced as ``reject``
    - the user is who they say they are but ISE policy doesn't grant
    them Plexus - and never falls through to a default role.
    """
    # Defense in depth (mirrors the RADIUS and LDAP guards): never send an
    # empty password - the API layer already rejects it, but no future
    # caller should be able to reach the wire with one.
    if not password:
        LOGGER.warning("tacacs: refusing to authenticate '%s' with an empty password", username)
        return False, "reject", {}
    if not TACACS_AVAILABLE:
        LOGGER.warning("tacacs: tacacs_plus library is not installed - cannot authenticate")
        return False, "error", {}
    assert TACACSClient is not None
    server = (tacacs_cfg.get("server") or "").strip()
    secret = tacacs_cfg.get("secret") or ""
    if not server or not secret:
        # tacacs_plus accepts secret=None to send cleartext bodies; refuse
        # rather than silently downgrade to an unobfuscated exchange.
        LOGGER.warning("tacacs: server or shared secret not configured")
        return False, "error", {}

    authen_type_name = str(tacacs_cfg.get("authen_type") or "ascii").lower()
    authen_type = TAC_PLUS_AUTHEN_TYPE_PAP if authen_type_name == "pap" else TAC_PLUS_AUTHEN_TYPE_ASCII
    port = int(tacacs_cfg.get("port", 49))
    timeout = int(tacacs_cfg.get("timeout", 5))

    try:
        client = TACACSClient(server, port, secret, timeout=timeout)
        reply = client.authenticate(username, password, authen_type=authen_type)
    except (OSError, TimeoutError) as exc:
        LOGGER.warning("tacacs: server %s unreachable for user '%s': %s", server, username, exc)
        return False, "error", {}
    except Exception as exc:
        LOGGER.warning("tacacs: authentication error for user '%s': %s", username, exc)
        return False, "error", {}

    if getattr(reply, "error", False):
        LOGGER.warning("tacacs: server %s returned ERROR for user '%s'", server, username)
        return False, "error", {}
    if not getattr(reply, "valid", False):
        LOGGER.info("tacacs: user '%s' rejected by %s", username, server)
        return False, "reject", {}
    LOGGER.info("tacacs: user '%s' authenticated by %s", username, server)

    if not bool(tacacs_cfg.get("authorize", True)):
        return True, "accept", {"role": None, "priv_lvl": None, "attributes": {}}

    service = (tacacs_cfg.get("service") or "shell").strip() or "shell"
    try:
        # A fresh client per exchange: tacacs_plus closes the socket after
        # each request and reuses the session id, which some servers
        # (ISE included) reject for a second START on the same session.
        authz_client = TACACSClient(server, port, secret, timeout=timeout)
        authz = authz_client.authorize(
            username,
            arguments=[f"service={service}".encode(), b"cmd="],
            authen_type=authen_type,
        )
    except (OSError, TimeoutError) as exc:
        LOGGER.warning("tacacs: authorization to %s failed for user '%s': %s", server, username, exc)
        return False, "error", {}
    except Exception as exc:
        LOGGER.warning("tacacs: authorization error for user '%s': %s", username, exc)
        return False, "error", {}

    authz_status = getattr(authz, "status", None)
    if authz_status == TAC_PLUS_AUTHOR_STATUS_ERROR:
        LOGGER.warning("tacacs: server %s returned authorization ERROR for user '%s'", server, username)
        return False, "error", {}
    if not getattr(authz, "valid", False):
        LOGGER.info("tacacs: user '%s' authenticated but not authorized by %s", username, server)
        return False, "reject", {}

    attributes = _parse_tacacs_av_pairs(getattr(authz, "arguments", None))
    role, priv_lvl = _tacacs_role_from_attrs(attributes, tacacs_cfg)
    LOGGER.info("tacacs: user '%s' authorized by %s (priv-lvl=%s, role=%s)", username, server, priv_lvl, role)
    return True, "accept", {"role": role, "priv_lvl": priv_lvl, "attributes": attributes}


async def verify_tacacs_user(username: str, password: str) -> tuple[bool, str, dict]:
    """Returns (is_authenticated, status, attrs)."""
    tacacs_cfg = state.AUTH_CONFIG.get("tacacs", {})
    return await asyncio.to_thread(_tacacs_authenticate_sync, username, password, tacacs_cfg)


async def upsert_tacacs_user(username: str, tacacs_attrs: dict) -> dict | None:
    """Ensure a local shadow user exists for TACACS+-authenticated identities.

    With authorization enabled the ISE shell profile is authoritative for
    the role, so it is re-synced on every login (``sync_role``) exactly
    like LDAP group membership - a user dropped from the admin profile is
    demoted on their next login.  With authorization disabled TACACS+
    asserts nothing and the RADIUS semantics apply: the role is whatever
    a Plexus admin set locally.
    """
    tacacs_cfg = state.AUTH_CONFIG.get("tacacs", {})
    authorize = bool(tacacs_cfg.get("authorize", True))
    role = (tacacs_attrs or {}).get("role") if authorize else None
    if role not in ("user", "admin"):
        role = tacacs_cfg.get("default_role") or "user"
        if role not in ("user", "admin"):
            role = "user"

    existing = await db.get_user_by_username(username)
    user = await upsert_external_user(username, role=role, provider="tacacs", sync_role=authorize)
    if user and not existing:
        group_ids = tacacs_cfg.get("default_group_ids", [])
        if group_ids:
            try:
                await db.set_user_groups(int(user["id"]), group_ids)
                user = await db.get_user_by_id(int(user["id"]))
            except ValueError:
                LOGGER.warning("tacacs: default access group assignment failed for user '%s'", username)
    return user


# ── LDAP / Active Directory helpers ──────────────────────────────────────────


def _normalize_dn(dn: str) -> str:
    """Normalize a DN for comparison: lowercase, whitespace stripped around
    unescaped component separators, so "CN=Admins, OU=IT" == "cn=admins,ou=it".

    Pure-Python (no python-ldap) so role mapping also works on platforms where
    the library is unavailable and in tests."""
    parts = re.split(r"(?<!\\),", dn)
    return ",".join(p.strip() for p in parts).lower()


def _upn_domain_from_base_dn(base_dn: str) -> str:
    """Derive the AD UPN domain from a base DN's DC components:
    "DC=corp,DC=local" -> "corp.local". Returns "" if there are none."""
    parts = re.split(r"(?<!\\),", base_dn)
    dcs = []
    for part in parts:
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "dc" and value.strip():
            dcs.append(value.strip())
    return ".".join(dcs)


def _safe_unbind(conn) -> None:
    if conn is None:
        return
    try:
        conn.unbind_s()
    except Exception:
        pass


def _ldap_open_connection(uri: str, ldap_cfg: dict, *, timeout: int):
    """Initialize a connection with timeouts, referral handling, and the
    admin-configured TLS policy; performs STARTTLS when configured.

    Every connection (service-account search AND user-credential bind) goes
    through here so no path can silently downgrade the TLS policy."""
    conn = python_ldap.initialize(uri)
    conn.set_option(python_ldap.OPT_NETWORK_TIMEOUT, timeout)
    conn.set_option(python_ldap.OPT_TIMEOUT, timeout)
    conn.set_option(python_ldap.OPT_REFERRALS, 0)
    conn.protocol_version = python_ldap.VERSION3

    use_ssl = bool(ldap_cfg.get("use_ssl", False))
    use_starttls = bool(ldap_cfg.get("use_starttls", False)) and not use_ssl
    if use_ssl or use_starttls:
        tls_verify = str(ldap_cfg.get("tls_verify", "demand")).lower().strip()
        tls_level = {
            "never": python_ldap.OPT_X_TLS_NEVER,
            "allow": python_ldap.OPT_X_TLS_ALLOW,
            "try": python_ldap.OPT_X_TLS_TRY,
            "demand": python_ldap.OPT_X_TLS_DEMAND,
            "hard": python_ldap.OPT_X_TLS_HARD,
        }.get(tls_verify, python_ldap.OPT_X_TLS_DEMAND)
        conn.set_option(python_ldap.OPT_X_TLS_REQUIRE_CERT, tls_level)
        ca_cert_file = str(ldap_cfg.get("ca_cert_file", "")).strip()
        if ca_cert_file:
            conn.set_option(python_ldap.OPT_X_TLS_CACERTFILE, ca_cert_file)
        # NEWCTX must come last: it builds the TLS context from the options above.
        conn.set_option(python_ldap.OPT_X_TLS_NEWCTX, 0)
        if tls_verify in ("never", "allow"):
            LOGGER.warning(
                "ldap: TLS certificate verification is permissive (%s) - use 'demand' in production", tls_verify
            )
        if use_starttls:
            conn.start_tls_s()
    return conn


def _ldap_authenticate_sync(username: str, password: str, ldap_cfg: dict) -> tuple[bool, str, dict]:
    """Perform a blocking LDAP bind authentication.

    Returns (success, status, user_attrs).
    status is one of: "accept", "reject", "error"
    user_attrs may contain: display_name, email, groups
    """
    if not LDAP_AVAILABLE:
        return False, "error", {}

    # RFC 4513 §5.1.2: a simple bind with an empty password is an
    # *unauthenticated* bind, which many directory servers accept without
    # verifying anything. Reject it before ever touching the server.
    if not password:
        return False, "reject", {}
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

    protocol = "ldaps" if use_ssl else "ldap"
    uri = f"{protocol}://{server}:{port}"

    conn = None
    try:
        user_dn = None
        user_attrs: dict = {}

        if user_dn_template:
            # Direct bind: template like "CN={username},OU=Users,DC=corp,DC=local"
            user_dn = user_dn_template.replace("{username}", _escape_dn_chars(username))
        elif bind_dn and base_dn:
            # The user-bind guard above, applied to the service account: an
            # empty bind_password would be the same RFC 4513 unauthenticated
            # bind, silently searching the directory with no credential.
            if not bind_password:
                LOGGER.warning("ldap: bind_dn is set but bind_password is empty - refusing unauthenticated bind")
                return False, "error", {}

            # Search bind: first bind as service account, then search for user
            conn = _ldap_open_connection(uri, ldap_cfg, timeout=timeout)
            try:
                conn.simple_bind_s(bind_dn, bind_password)
            except python_ldap.INVALID_CREDENTIALS:
                LOGGER.warning("ldap: service account bind failed - check bind_dn / bind_password")
                return False, "error", {}

            search_filter = user_search_filter.replace("{username}", _escape_filter_chars(username))
            try:
                result = conn.search_s(
                    base_dn,
                    python_ldap.SCOPE_SUBTREE,
                    search_filter,
                    ["dn", "displayName", "mail", "sAMAccountName", "cn", "memberOf"],
                )
            except python_ldap.NO_SUCH_OBJECT:
                return False, "reject", {}

            # Filter out referrals (entries with dn=None)
            entries = [(dn, attrs) for dn, attrs in result if dn is not None]
            if not entries:
                return False, "reject", {}
            if len(entries) > 1:
                # Which account would authenticate depends on directory return
                # order - fail closed instead of picking one.
                LOGGER.warning(
                    "ldap: user search for '%s' matched %d entries - refusing ambiguous match "
                    "(tighten user_search_filter or base_dn)",
                    username,
                    len(entries),
                )
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
            _safe_unbind(conn)
            conn = None
        else:
            # No service account and no template - direct bind with a UPN
            # derived from the base DN's DC components (DC=corp,DC=local ->
            # user@corp.local); plain username as a last resort.
            domain = _upn_domain_from_base_dn(base_dn)
            user_dn = f"{username}@{domain}" if domain else username

        if not user_dn:
            return False, "error", {}

        # Authenticate the user by binding with their credentials
        if conn is None:
            conn = _ldap_open_connection(uri, ldap_cfg, timeout=timeout)
        try:
            conn.simple_bind_s(user_dn, password)
        except python_ldap.INVALID_CREDENTIALS:
            return False, "reject", user_attrs

        # If we didn't get attributes from the search, fetch them now
        if not user_attrs.get("display_name") and base_dn:
            try:
                search_filter = user_search_filter.replace("{username}", _escape_filter_chars(username))
                result = conn.search_s(
                    base_dn,
                    python_ldap.SCOPE_SUBTREE,
                    search_filter,
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

        # Merge in a configured group search. This runs even when memberOf
        # returned direct groups: AD's memberOf omits nested memberships, and a
        # matching-rule-in-chain filter here (1.2.840.113556.1.4.1941) is the
        # supported way to resolve them - it must not be skipped just because
        # direct groups exist.
        if group_search_base and group_search_filter:
            try:
                gfilter = group_search_filter.replace("{user_dn}", _escape_filter_chars(user_dn)).replace(
                    "{username}", _escape_filter_chars(username)
                )
                g_result = conn.search_s(group_search_base, python_ldap.SCOPE_SUBTREE, gfilter, ["dn", "cn"])
                found = [dn for dn, _ in g_result if dn is not None]
                existing = user_attrs.get("groups", [])
                user_attrs["groups"] = existing + [g for g in found if g not in existing]
            except Exception as exc:
                LOGGER.warning("ldap: group search failed for '%s': %s", username, exc)

        return True, "accept", user_attrs

    except python_ldap.SERVER_DOWN:
        LOGGER.warning("ldap: server %s unreachable", server)
        return False, "error", {}
    except python_ldap.INVALID_CREDENTIALS:
        return False, "reject", {}
    except Exception as exc:
        LOGGER.warning("ldap: authentication error: %s", str(exc))
        return False, "error", {}
    finally:
        _safe_unbind(conn)


async def verify_ldap_user(username: str, password: str) -> tuple[bool, str, dict]:
    """Returns (is_authenticated, status, user_attrs)."""
    ldap_cfg = state.AUTH_CONFIG.get("ldap", {})
    return await asyncio.to_thread(_ldap_authenticate_sync, username, password, ldap_cfg)


async def upsert_ldap_user(username: str, ldap_attrs: dict) -> dict | None:
    """Ensure a local shadow user exists for LDAP-authenticated identities.

    If the user has groups that match admin_group_dn, promote to admin role.
    Role and display name are re-synced from the directory on every login
    (sync_role) - see upsert_external_user for the demotion semantics.
    """
    ldap_cfg = state.AUTH_CONFIG.get("ldap", {})
    admin_group_dn = _normalize_dn(ldap_cfg.get("admin_group_dn", "").strip())
    default_role = ldap_cfg.get("default_role", "user")

    # Determine role from group membership. DNs are normalized on both sides
    # so spacing variants ("CN=Admins, OU=IT") still match.
    role = default_role
    user_groups = [_normalize_dn(g) for g in ldap_attrs.get("groups", [])]
    if admin_group_dn and admin_group_dn in user_groups:
        role = "admin"

    display_name = ldap_attrs.get("display_name", "") or username

    existing = await db.get_user_by_username(username)
    user = await upsert_external_user(username, display_name=display_name, role=role, provider="ldap", sync_role=True)
    if user and not existing:
        group_ids = ldap_cfg.get("default_group_ids", [])
        if group_ids:
            try:
                await db.set_user_groups(int(user["id"]), group_ids)
                user = await db.get_user_by_id(int(user["id"]))
            except ValueError:
                LOGGER.warning("ldap: default access group assignment failed for user '%s'", username)
    return user


async def _existing_access_group_ids(group_ids: list[int], username: str, provider: str = "oidc") -> list[int]:
    """``group_ids`` without the ones that no longer exist (warned)."""
    known = {int(g["id"]) for g in await db.get_all_access_groups()}
    kept = sorted({gid for gid in group_ids if gid in known})
    skipped = sorted({gid for gid in group_ids if gid not in known})
    if skipped:
        LOGGER.warning("%s: skipping unknown access group ids %s for user '%s'", provider, skipped, username)
    return kept


async def upsert_sso_user(identity: SsoIdentity, sso_cfg: dict, provider: str) -> tuple[dict | None, str]:
    """Provision or re-sync the account of a single sign-on (``provider``
    is ``oidc`` or ``saml``; ``sso_cfg`` is that protocol's config block).

    Returns ``(user, "")`` or ``(None, reason)``. The account is bound to
    the provider's subject (OIDC ``sub``, SAML ``NameID``) on its first
    sign-in through that provider (``users.external_id``); a later sign-in
    whose subject differs from the bound one is refused.
    Role: ``admin`` when a group value is in ``admin_groups``, else
    ``default_role``, re-synced every login through upsert_external_user
    (whose admin name-collision guard applies). Access groups: the defaults
    on first login; with ``sync_groups`` the defaults plus every mapped
    group on each login. When the groups are unknown (overage), an existing
    account keeps its role and groups.
    """
    username = identity.username
    existing = await db.get_user_by_username(username)
    sso_managed = bool(existing) and (existing.get("auth_provider") or "") == provider
    bound_sub = str((existing or {}).get("external_id") or "") if sso_managed else ""
    if bound_sub and not hmac.compare_digest(bound_sub.encode(), identity.sub.encode()):
        return None, "subject does not match the subject bound to this account"

    groups = set(identity.groups)
    current_role = ((existing or {}).get("role") or "user").lower()
    # Overage: the groups are unknown, so keep the role. Not for adopting an
    # unmanaged local admin: that still needs an explicit grant.
    if existing and identity.overage and (sso_managed or current_role != "admin"):
        role = current_role
    elif groups & set(sso_cfg.get("admin_groups") or []):
        role = "admin"
    else:
        role = sso_cfg.get("default_role") or "user"

    user = await upsert_external_user(
        username, display_name=identity.display_name, role=role, provider=provider, sync_role=True
    )
    if not user:
        return None, "local account provisioning refused (name collides with a local admin) or failed"
    user_id = int(user["id"])
    if not bound_sub:
        await db.set_user_external_id(user_id, identity.sub)

    if not existing or (sso_cfg.get("sync_groups") and not identity.overage):
        group_ids = list(sso_cfg.get("default_group_ids") or [])
        if sso_cfg.get("sync_groups") and not identity.overage:
            group_ids += [
                int(m["access_group_id"]) for m in sso_cfg.get("group_mappings") or [] if m.get("group") in groups
            ]
        group_ids = await _existing_access_group_ids(group_ids, username, provider)
        if existing or group_ids:
            try:
                await db.set_user_groups(user_id, group_ids)
            except ValueError:
                LOGGER.warning("%s: access group assignment failed for user '%s'", provider, username)
    return await db.get_user_by_id(user_id), ""


async def upsert_oidc_user(identity: oidc.OidcIdentity, oidc_cfg: dict) -> tuple[dict | None, str]:
    """Provision or re-sync the account of an OIDC sign-in (see upsert_sso_user)."""
    return await upsert_sso_user(identity, oidc_cfg, "oidc")


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
    pw_hash = await asyncio.to_thread(_hash_password_fn, expected_password, salt)

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
        except ValueError as exc:
            LOGGER.debug("auth bootstrap: create_user failed (user likely already exists): %s", exc)

    return await db.get_user_by_username(expected_username)


async def authenticate_login_identity(username: str, password: str) -> tuple[dict | None, str | None, str | None]:
    """Authenticate using configured provider with defined fallback behavior.

    Returns (user, auth_source, error_detail)

    Looks up ``verify_radius_user``, ``upsert_radius_user``,
    ``verify_tacacs_user``, ``upsert_tacacs_user``, ``verify_user``
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
    _verify_ldap = getattr(_app, "verify_ldap_user", verify_ldap_user)
    _upsert_ldap = getattr(_app, "upsert_ldap_user", upsert_ldap_user)
    _verify_tacacs = getattr(_app, "verify_tacacs_user", verify_tacacs_user)
    _upsert_tacacs = getattr(_app, "upsert_tacacs_user", upsert_tacacs_user)
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

    # TACACS+ provider (Cisco ISE Device Admin and friends)
    tacacs_cfg = auth_config.get("tacacs", {})
    tacacs_enabled = bool(tacacs_cfg.get("enabled"))

    if provider == "tacacs" and tacacs_enabled:
        accepted, status, tacacs_attrs = await _verify_tacacs(username, password)
        if accepted:
            user = await _upsert_tacacs(username, tacacs_attrs)
            if user:
                return user, "tacacs", None
            return None, None, "TACACS+ login succeeded but local account provisioning failed"

        if status == "reject" and not bool(tacacs_cfg.get("fallback_on_reject", False)):
            return None, None, "Invalid username or password"

        if bool(tacacs_cfg.get("fallback_to_local", True)):
            local_user = await _verify_local(username, password)
            if local_user:
                return local_user, "local-fallback", None
            if status == "error":
                return None, None, "TACACS+ server is unavailable and local fallback credentials failed"
            return None, None, "Invalid username or password"

        if status == "error":
            return None, None, "TACACS+ authentication service unavailable"
        return None, None, "Invalid username or password"

    # LDAP / Active Directory provider
    ldap_cfg = auth_config.get("ldap", {})
    ldap_enabled = bool(ldap_cfg.get("enabled"))

    if provider == "ldap" and ldap_enabled:
        accepted, status, ldap_attrs = await _verify_ldap(username, password)
        if accepted:
            user = await _upsert_ldap(username, ldap_attrs)
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
        # No group_memberships rows at all - legacy/unassigned user.
        # Default to empty (least-privilege).  Admins should assign groups.
        return []
    features = [f for f in FEATURE_FLAGS if f in set(effective)]
    # Fail closed: a user limited to selected inventory groups keeps only
    # the features whose modules enforce that limit, so every other
    # feature gate (HTTP, WebSocket, MCP, the sidebar) refuses them.
    if features and (await object_scope.scope_for_user(user)).restricted:
        features = object_scope.enforced_features(features)
    return features


# ── Pydantic models ──────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


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


def _login_throttle_state() -> tuple[dict, dict]:
    """The per-IP failure and lockout maps (late-bound so tests can swap them)."""
    _app = _app_module()
    return getattr(_app, "LOGIN_ATTEMPTS", state.LOGIN_ATTEMPTS), getattr(_app, "LOCKED_OUT", state.LOCKED_OUT)


async def _login_blocked(ip: str, now: float) -> str | None:
    """Why a sign-in from ``ip`` is refused right now (lockout or failure
    rate limit), else ``None``. Shared by password login and the OIDC callback."""
    attempts_by_ip, locked_out = _login_throttle_state()
    rules = state.LOGIN_RULES
    # Lock prevents concurrent requests from bypassing the check.
    async with _login_lock:
        if ip in locked_out:
            if now < locked_out[ip]:
                return f"Account locked. Try again in {int((locked_out[ip] - now) // 60) + 1} min."
            del locked_out[ip]
            attempts_by_ip.pop(ip, None)
        attempts = [t for t in attempts_by_ip.get(ip, []) if now - t < rules["rate_limit_window"]]
        if len(attempts) >= rules["rate_limit_max"]:
            return "Too many login attempts. Please wait a minute."
    return None


async def _note_login_failure(ip: str, now: float) -> bool:
    """Count a failed sign-in from ``ip``; True when it locked the IP out."""
    attempts_by_ip, locked_out = _login_throttle_state()
    rules = state.LOGIN_RULES
    async with _login_lock:
        # Re-read the canonical list: a concurrent request may have changed it.
        attempts = [t for t in attempts_by_ip.get(ip, []) if now - t < rules["rate_limit_window"]]
        attempts.append(now)
        attempts_by_ip[ip] = attempts
        if len(attempts) >= rules["max_attempts"]:
            locked_out[ip] = now + rules["lockout_time"]
            return True
    return False


async def _note_login_success(ip: str) -> None:
    attempts_by_ip, _ = _login_throttle_state()
    async with _login_lock:
        attempts_by_ip.pop(ip, None)


def _session_cookie_secure() -> bool:
    return bool(getattr(_app_module(), "APP_HTTPS_ENABLED", _APP_HTTPS_ENABLED))


def _set_session_cookie(response: Response, user: dict) -> None:
    """Issue the session cookie for ``user`` on ``response``: the one place
    password login and the OIDC callback sign a browser in."""
    token = _create_session_token_fn(user["username"], user["id"], user.get("session_epoch") or 0)
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="strict",
        max_age=_SESSION_MAX_AGE,
        secure=_session_cookie_secure(),
    )


@router.post("/api/auth/login")
async def login(body: LoginRequest, request: Request):
    _app = _app_module()
    _auth_identity = getattr(_app, "authenticate_login_identity", authenticate_login_identity)
    _audit_fn = getattr(_app, "_audit", _audit)
    _features_fn = getattr(_app, "_get_user_features", _get_user_features)

    ip = request.client.host
    now = time.time()

    blocked = await _login_blocked(ip, now)
    if blocked:
        raise HTTPException(status_code=429, detail=blocked)

    # Auth identity check runs outside lock (may be slow: LDAP/RADIUS)
    user, auth_source, auth_error = await _auth_identity(body.username, body.password)

    if not user:
        locked = await _note_login_failure(ip, now)
        await _audit_fn(
            "auth",
            "login.failure",
            user=body.username,
            detail=auth_error or "bad credentials",
            correlation_id=_corr_id(request),
        )
        if locked:
            raise HTTPException(status_code=429, detail="Account locked due to too many failed attempts. Try again later.")
        raise HTTPException(status_code=401, detail=auth_error or "Invalid username or password")
    await _note_login_success(ip)
    # Use the canonical username from the DB (may differ in case from input)
    canonical_user = user["username"]
    await _audit_fn(
        "auth", "login.success", user=canonical_user, detail=f"source={auth_source}", correlation_id=_corr_id(request)
    )
    csrf_token = _generate_csrf_token(canonical_user)
    response = JSONResponse(
        {
            "ok": True,
            "username": canonical_user,
            "user_id": user["id"],
            "display_name": user["display_name"] or canonical_user,
            "role": user["role"],
            "auth_source": auth_source,
            "feature_access": await _features_fn(user),
            "feature_visibility_hidden": list(state.FEATURE_VISIBILITY_HIDDEN),
            "object_scope": (await object_scope.scope_for_user(user)).status(),
            "must_change_password": bool(user.get("must_change_password")),
            "csrf_token": csrf_token,
        }
    )
    _set_session_cookie(response, user)
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
    pw_hash = await asyncio.to_thread(_hash_password_fn, body.password, salt)
    display = body.display_name or body.username.title()
    user_id = await db.create_user(body.username, pw_hash, salt, display_name=display, role="user")
    user = await db.get_user_by_id(user_id)
    await _audit("auth", "register", user=body.username, correlation_id=_corr_id(request) if request else "")
    csrf_token = _generate_csrf_token(body.username)
    response = JSONResponse(
        {
            "ok": True,
            "username": body.username,
            "user_id": user_id,
            "display_name": display,
            "role": "user",
            "feature_access": await _features_fn(user),
            "feature_visibility_hidden": list(state.FEATURE_VISIBILITY_HIDDEN),
            "object_scope": (await object_scope.scope_for_user(user)).status(),
            "csrf_token": csrf_token,
        }
    )
    _set_session_cookie(response, user)
    return response


@router.post("/api/auth/logout")
async def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie("session")
    return response


@router.post("/api/auth/heartbeat")
async def heartbeat(request: Request, response: Response):
    """Bump session activity without doing anything else.

    Used by the SPA's idle-countdown banner "Stay signed in" button. Calls
    require_auth directly (instead of via _require_auth_dep) so the response
    is in scope and the cookie's last_activity field is actually refreshed.
    Returns the new deadline so the SPA can reset its timer without waiting
    for the next /api/auth/status poll.
    """
    await _require_auth(request, response)
    idle_timeout = int(state.LOGIN_RULES.get("session_idle_timeout", 1800))
    now = int(time.time())
    return {
        "ok": True,
        "session_last_activity": now,
        "idle_timeout_seconds": idle_timeout,
        "server_time": now,
    }


def _logged_out_status() -> dict:
    """Status body for a request with no valid session.

    allow_self_register lets the login screen offer the Register link only
    when /api/auth/register would accept the request.
    """
    oidc_cfg = _oidc_config()
    saml_cfg = _saml_config()
    return {
        "authenticated": False,
        "allow_self_register": _env_flag("APP_ALLOW_SELF_REGISTER", False),
        # Single sign-on offered on the login screen (display data only).
        "sso": {
            "oidc": {
                "enabled": _oidc_ready(oidc_cfg),
                "label": oidc_cfg.get("button_label") or "Sign in with SSO",
                "primary": bool(oidc_cfg.get("primary")),
            },
            "saml": {
                "enabled": _saml_ready(saml_cfg),
                "label": saml_cfg.get("button_label") or "Sign in with SAML",
                "primary": bool(saml_cfg.get("primary")),
            },
        },
    }


@router.get("/api/auth/status")
async def auth_status(request: Request, response: Response):
    _app = _app_module()
    _features_fn = getattr(_app, "_get_user_features", _get_user_features)

    session = _get_session(request)
    if not session:
        return _logged_out_status()
    user = await db.get_user_by_id(session["user_id"])
    if not user:
        return _logged_out_status()

    # Mirror the idle-timeout enforcement done by require_auth so that a stale
    # cookie can't make the SPA think it's still logged in. Kiosk accounts
    # (session_never_expires) bypass the check just like require_auth does.
    if not bool(user.get("session_never_expires")):
        idle_timeout = int(state.LOGIN_RULES.get("session_idle_timeout", 1800))
        last_activity = int(session.get("last_activity") or 0)
        if idle_timeout > 0 and last_activity > 0:
            elapsed = int(time.time()) - last_activity
            if elapsed > idle_timeout:
                response.delete_cookie("session", samesite="strict")
                await _audit(
                    "auth",
                    "session.idle_timeout",
                    user=user["username"],
                    detail=f"idle={elapsed}s threshold={idle_timeout}s path=/api/auth/status",
                    correlation_id=_corr_id(request),
                )
                return _logged_out_status()

    never_expires = bool(user.get("session_never_expires"))
    idle_timeout = int(state.LOGIN_RULES.get("session_idle_timeout", 1800))
    last_activity = int(session.get("last_activity") or 0)
    return {
        "authenticated": True,
        "username": user["username"],
        "user_id": user["id"],
        "display_name": user["display_name"] or user["username"],
        "role": user["role"],
        "feature_access": await _features_fn(user),
        "feature_visibility_hidden": list(state.FEATURE_VISIBILITY_HIDDEN),
        "object_scope": (await object_scope.scope_for_user(user)).status(),
        "csrf_token": _generate_csrf_token(user["username"]),
        "must_change_password": bool(user.get("must_change_password")),
        # Drives the SPA idle-countdown banner. The SPA computes
        # remaining = (last_activity + idle_timeout) - now, accounting for
        # clock skew via server_time. idle_timeout=0 disables enforcement;
        # session_never_expires=true means this user bypasses the timer.
        "idle_timeout_seconds": idle_timeout,
        "session_last_activity": last_activity,
        "session_never_expires": never_expires,
        "server_time": int(time.time()),
    }


async def _require_auth_dep(request: Request):
    """Late-bound wrapper for require_auth dependency."""
    return await _require_auth(request)


# Per-user rate limiter for change-password (keyed on user_id)
_PASSWORD_CHANGE_ATTEMPTS: dict[int, list[float]] = {}
_PASSWORD_CHANGE_MAX = 5  # max attempts per window
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
    pw_hash = await asyncio.to_thread(_hash_password_fn, body.new_password, salt)
    await db.update_user_password(user["id"], pw_hash, salt)
    # Revoke all previously-issued sessions for this user (a password change
    # should log out other devices), then re-issue THIS request's cookie with
    # the new epoch so the user who just changed their password stays signed in.
    new_epoch = await db.bump_user_session_epoch(user["id"])
    await _audit("auth", "password.change", user=session["user"], correlation_id=_corr_id(request))
    token = _create_session_token_fn(session["user"], user["id"], new_epoch)
    response = JSONResponse({"ok": True})
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="strict",
        max_age=_SESSION_MAX_AGE,
        secure=_APP_HTTPS_ENABLED,
    )
    return response


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


# ── OpenID Connect single sign-on ────────────────────────────────────────────
#
# An additional sign-in method next to the password form (which keeps its
# provider chain and the break-glass local admin). The protocol lives in
# netcontrol/oidc.py; these routes hold the browser side: a signed,
# short-lived ``oidc_tx`` cookie carries state, nonce, PKCE verifier, the
# redirect URI and where to return, and the callback signs the browser in
# with the same session cookie as password login. Both routes are GET and
# need no session; they stay under the anonymous API rate limit, and
# callback failures count toward the login lockout like a bad password.

_OIDC_TX_COOKIE = "oidc_tx"
_OIDC_TX_SALT = "plexus-oidc-tx"
_OIDC_TX_MAX_AGE = 600
_OIDC_COOKIE_PATH = "/api/auth/oidc"


def _oidc_config() -> dict:
    return state.AUTH_CONFIG.get("oidc") or {}


def _oidc_ready(cfg: dict) -> bool:
    return bool(cfg.get("enabled") and cfg.get("issuer") and cfg.get("client_id"))


def _oidc_client_secret(cfg: dict) -> str:
    """The decrypted client secret, ``""`` for a public client."""
    stored = str(cfg.get("client_secret_enc") or "")
    if not stored:
        return ""
    from routes.crypto import decrypt

    try:
        return decrypt(stored) or ""
    except Exception as exc:  # a key change makes the secret unreadable
        raise oidc.OidcError("provider", "the stored client secret could not be decrypted") from exc


def _oidc_redirect_uri(request: Request, cfg: dict) -> str:
    """The configured redirect URI, else one derived from the request."""
    return oidc.derive_redirect_uri(str(cfg.get("redirect_uri") or ""), _request_scheme(request), request.url.netloc)


def _oidc_tx_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(_app_module()._secret_key, salt=_OIDC_TX_SALT)


def _drop_oidc_tx_cookie(response: Response) -> None:
    response.delete_cookie(
        _OIDC_TX_COOKIE, path=_OIDC_COOKIE_PATH, secure=_session_cookie_secure(), httponly=True, samesite="lax"
    )


def _sso_error_redirect(code: str, drop_tx: Callable[[Response], None] | None = None) -> RedirectResponse:
    """Back to the login screen with one of the fixed error codes; the
    protocol's transaction cookie (OIDC unless ``drop_tx`` says otherwise)
    is always dropped."""
    response = RedirectResponse(f"/login?sso_error={code}", status_code=303)
    (drop_tx or _drop_oidc_tx_cookie)(response)
    return response


class _SsoAttempt:
    """One sign-in callback of any single sign-on protocol: the lockout
    check, failures (counted toward the lockout like a bad password and
    audited) and success (provision, audit, session cookie, redirect)."""

    def __init__(self, request: Request, provider: str, drop_tx: Callable[[Response], None]):
        self.request = request
        self.provider = provider
        self.drop_tx = drop_tx
        self.ip = request.client.host if request.client else "unknown"
        self.now = time.time()
        self.audit = getattr(_app_module(), "_audit", _audit)

    async def blocked(self) -> RedirectResponse | None:
        reason = await _login_blocked(self.ip, self.now)
        return await self.fail("denied", f"refused, {reason}", count=False) if reason else None

    async def fail(self, code: str, step: str, *, user: str = "", count: bool = True) -> RedirectResponse:
        # ``step`` never carries a token, assertion, code, secret or verifier.
        if count:
            await _note_login_failure(self.ip, self.now)
        await self.audit(
            "auth",
            "login.failure",
            user=user,
            detail=f"source={self.provider} step={step}",
            correlation_id=_corr_id(self.request),
        )
        return _sso_error_redirect(code, self.drop_tx)

    async def succeed(self, identity: SsoIdentity, cfg: dict, next_path: str | None) -> RedirectResponse:
        user, reason = await upsert_sso_user(identity, cfg, self.provider)
        if not user:
            LOGGER.warning("%s: sign-in refused for '%s': %s", self.provider, identity.username, reason)
            return await self.fail("account", reason, user=identity.username)
        await _note_login_success(self.ip)
        detail = f"source={self.provider}"
        if identity.overage:
            detail += " groups=unknown (overage): role and access groups left unchanged"
        await self.audit(
            "auth", "login.success", user=user["username"], detail=detail, correlation_id=_corr_id(self.request)
        )
        response = RedirectResponse(safe_next(next_path), status_code=303)
        response.headers["Cache-Control"] = "no-store"
        _set_session_cookie(response, user)
        self.drop_tx(response)
        return response


@router.get(oidc.LOGIN_PATH)
async def oidc_login(request: Request, next_path: str = Query("/", alias="next")):
    """Start an OIDC sign-in: remember the transaction, send the browser to
    the provider."""
    cfg = _oidc_config()
    if not _oidc_ready(cfg):
        return _sso_error_redirect("disabled")
    try:
        meta = await oidc.CLIENT.discover(str(cfg["issuer"]), str(cfg.get("ca_cert_file") or ""))
    except oidc.OidcError as exc:
        LOGGER.warning("oidc: sign-in could not start: %s", exc.step)
        return _sso_error_redirect(exc.code)
    verifier = oidc.new_code_verifier()
    tx = {
        "state": oidc.new_state(),
        "nonce": oidc.new_nonce(),
        "verifier": verifier,
        "redirect_uri": _oidc_redirect_uri(request, cfg),
        "next": oidc.safe_next(next_path),
    }
    url = oidc.CLIENT.authorization_url(
        meta,
        client_id=str(cfg["client_id"]),
        redirect_uri=tx["redirect_uri"],
        scopes=str(cfg.get("scopes") or ""),
        state=tx["state"],
        nonce=tx["nonce"],
        challenge=oidc.code_challenge(verifier),
    )
    response = RedirectResponse(url, status_code=302)
    response.headers["Cache-Control"] = "no-store"
    response.set_cookie(
        _OIDC_TX_COOKIE,
        _oidc_tx_serializer().dumps(tx),
        max_age=_OIDC_TX_MAX_AGE,
        path=_OIDC_COOKIE_PATH,
        httponly=True,
        samesite="lax",
        secure=_session_cookie_secure(),
    )
    return response


def _load_oidc_tx(request: Request) -> dict | None:
    raw = request.cookies.get(_OIDC_TX_COOKIE)
    if not raw:
        return None
    try:
        tx = _oidc_tx_serializer().loads(raw, max_age=_OIDC_TX_MAX_AGE)
    except BadSignature:  # also covers SignatureExpired
        return None
    if not isinstance(tx, dict) or not all(isinstance(tx.get(k), str) for k in ("state", "nonce", "verifier")):
        return None
    return tx


@router.get(oidc.CALLBACK_PATH)
async def oidc_callback(request: Request):
    """The provider sends the browser back here with a code (or an error)."""
    attempt = _SsoAttempt(request, "oidc", _drop_oidc_tx_cookie)
    params = request.query_params

    refused = await attempt.blocked()
    if refused:
        return refused
    cfg = _oidc_config()
    if not _oidc_ready(cfg):
        return await attempt.fail("disabled", "single sign-on is disabled")
    tx = _load_oidc_tx(request)
    if tx is None:
        return await attempt.fail("state", "transaction cookie is missing, expired or invalid")
    state_param = params.get("state") or ""
    if not state_param or not hmac.compare_digest(state_param.encode(), tx["state"].encode()):
        return await attempt.fail("state", "state does not match the transaction")
    if params.get("error"):
        error = oidc.log_safe(params.get("error"), 60)
        LOGGER.warning(
            "oidc: provider returned error=%s description=%s", error, oidc.log_safe(params.get("error_description"))
        )
        return await attempt.fail(
            "denied" if params.get("error") == "access_denied" else "provider", f"provider error {error}"
        )
    code = params.get("code") or ""
    if not code:
        return await attempt.fail("provider", "no authorization code in the callback")

    try:
        identity = await oidc.CLIENT.complete_login(
            cfg,
            code=code,
            redirect_uri=str(tx.get("redirect_uri") or _oidc_redirect_uri(request, cfg)),
            code_verifier=tx["verifier"],
            nonce=tx["nonce"],
            client_secret=_oidc_client_secret(cfg),
        )
    except oidc.OidcError as exc:
        LOGGER.warning("oidc: sign-in failed: %s", exc.step)
        return await attempt.fail(exc.code, exc.step)
    return await attempt.succeed(identity, cfg, tx.get("next"))


# ── SAML 2.0 single sign-on ──────────────────────────────────────────────────
#
# Another sign-in method next to the password form and OIDC. The protocol
# lives in netcontrol/saml.py; these routes hold the browser side. Login
# sends the browser to the IdP with an AuthnRequest (HTTP-Redirect) and sets
# a signed, short-lived ``saml_tx`` cookie with the request ID; the IdP
# POSTs the signed response to the ACS, which checks it against that ID,
# refuses a replayed assertion and signs the browser in through the same
# provisioning and session cookie as OIDC. The ACS POST arrives cross-site,
# so over HTTPS the cookie is ``SameSite=None; Secure``; on plain HTTP only
# a same-site IdP can complete a sign-in.

_SAML_TX_COOKIE = "saml_tx"
_SAML_TX_SALT = "plexus-saml-tx"
_SAML_TX_MAX_AGE = 600
_SAML_COOKIE_PATH = "/api/auth/saml"


def _saml_config() -> dict:
    return state.AUTH_CONFIG.get("saml") or {}


def _saml_ready(cfg: dict) -> bool:
    return bool(cfg.get("enabled") and cfg.get("idp_entity_id") and cfg.get("idp_sso_url") and cfg.get("idp_certs"))


def _request_base(request: Request) -> str:
    return f"{_request_scheme(request)}://{request.url.netloc}"


def saml_sp_entity_id(request: Request, cfg: dict) -> str:
    """The configured SP entity ID, else the metadata URL on this host."""
    return str(cfg.get("sp_entity_id") or "").strip() or _request_base(request) + saml.METADATA_PATH


def saml_acs_url(request: Request, cfg: dict) -> str:
    """The configured ACS URL, else the ACS path on this host."""
    return str(cfg.get("acs_url") or "").strip() or _request_base(request) + saml.ACS_PATH


def _saml_settings(request: Request, cfg: dict) -> saml.SamlSettings:
    return saml.SamlSettings(
        idp_entity_id=str(cfg.get("idp_entity_id") or ""),
        certs=tuple(cfg.get("idp_certs") or ()),
        sp_entity_id=saml_sp_entity_id(request, cfg),
        acs_url=saml_acs_url(request, cfg),
        username_attribute=str(cfg.get("username_attribute") or ""),
        email_attribute=str(cfg.get("email_attribute") or ""),
        display_name_attribute=str(cfg.get("display_name_attribute") or ""),
        groups_attribute=str(cfg.get("groups_attribute") or ""),
    )


def _saml_tx_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(_app_module()._secret_key, salt=_SAML_TX_SALT)


def _saml_cookie_samesite() -> str:
    # The IdP POSTs cross-site: only SameSite=None reaches the ACS, and
    # browsers accept that only with Secure.
    return "none" if _session_cookie_secure() else "lax"


def _drop_saml_tx_cookie(response: Response) -> None:
    response.delete_cookie(
        _SAML_TX_COOKIE,
        path=_SAML_COOKIE_PATH,
        secure=_session_cookie_secure(),
        httponly=True,
        samesite=_saml_cookie_samesite(),  # type: ignore[arg-type]
    )


@router.get(saml.METADATA_PATH)
async def saml_metadata(request: Request):
    """The SP metadata to register at the IdP (entity ID and ACS URL)."""
    cfg = _saml_config()
    xml = saml.sp_metadata_xml(saml_sp_entity_id(request, cfg), saml_acs_url(request, cfg))
    return Response(content=xml, media_type="application/samlmetadata+xml")


@router.get(saml.LOGIN_PATH)
async def saml_login(request: Request, next_path: str = Query("/", alias="next")):
    """Start a SAML sign-in: remember the request ID, send the browser to
    the IdP with an AuthnRequest."""
    cfg = _saml_config()
    if not _saml_ready(cfg):
        return _sso_error_redirect("disabled", _drop_saml_tx_cookie)
    request_id = saml.new_request_id()
    relay_state = safe_next(next_path)
    url = saml.authn_request_url(
        str(cfg["idp_sso_url"]),
        request_id=request_id,
        sp_entity_id=saml_sp_entity_id(request, cfg),
        acs_url=saml_acs_url(request, cfg),
        relay_state=relay_state,
    )
    response = RedirectResponse(url, status_code=302)
    response.headers["Cache-Control"] = "no-store"
    response.set_cookie(
        _SAML_TX_COOKIE,
        _saml_tx_serializer().dumps({"request_id": request_id, "next": relay_state}),
        max_age=_SAML_TX_MAX_AGE,
        path=_SAML_COOKIE_PATH,
        httponly=True,
        samesite=_saml_cookie_samesite(),  # type: ignore[arg-type]
        secure=_session_cookie_secure(),
    )
    return response


def _load_saml_tx(request: Request) -> dict | None:
    raw = request.cookies.get(_SAML_TX_COOKIE)
    if not raw:
        return None
    try:
        tx = _saml_tx_serializer().loads(raw, max_age=_SAML_TX_MAX_AGE)
    except BadSignature:  # also covers SignatureExpired
        return None
    if not isinstance(tx, dict) or not isinstance(tx.get("request_id"), str) or not tx["request_id"]:
        return None
    return tx


@router.post(saml.ACS_PATH)
async def saml_acs(request: Request):
    """The IdP POSTs the signed response here (HTTP-POST binding)."""
    attempt = _SsoAttempt(request, "saml", _drop_saml_tx_cookie)
    refused = await attempt.blocked()
    if refused:
        return refused
    cfg = _saml_config()
    if not _saml_ready(cfg):
        return await attempt.fail("disabled", "SAML single sign-on is disabled")
    tx = _load_saml_tx(request)
    if tx is None:
        return await attempt.fail("state", "transaction cookie is missing, expired or invalid")
    try:
        form = await request.form()
    except Exception:  # malformed or oversized body
        return await attempt.fail("provider", "the POST body could not be read")
    saml_response = form.get("SAMLResponse")
    relay_state = form.get("RelayState")
    try:
        result = saml.parse_response(
            saml_response if isinstance(saml_response, str) else "",
            _saml_settings(request, cfg),
            request_id=tx["request_id"],
        )
    except SsoError as exc:
        LOGGER.warning("saml: sign-in failed: %s", exc.step)
        return await attempt.fail(exc.code, exc.step)
    if not await db.remember_saml_assertion(result.assertion_id, result.expires_at):
        return await attempt.fail("token", "the assertion was already used (replay)", user=result.identity.username)
    # RelayState goes back through the same-site path rule; without one,
    # the path remembered at login.
    next_path = relay_state if isinstance(relay_state, str) and relay_state else tx.get("next")
    return await attempt.succeed(result.identity, cfg, next_path)
