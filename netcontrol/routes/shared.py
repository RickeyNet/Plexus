"""
shared.py -- Cross-domain helper functions used by multiple route modules.

Provides audit logging, config capture/push/diff, and session helpers.
"""
from __future__ import annotations

import asyncio
import difflib
import re
import time

import routes.database as db
from fastapi import HTTPException

import netcontrol.routes.state as state
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.shared")

# Mirrors app.SESSION_MAX_AGE (absolute session lifetime cap, 24h). Kept as a
# local constant so WS auth can enforce the same cap require_auth does without
# importing app (which would create a cycle).
_WS_SESSION_MAX_AGE = 86400


# ── Audit helper ─────────────────────────────────────────────────────────────

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
        LOGGER.info(
            "audit: category=%s action=%s user=%s correlation_id=%s detail=%s",
            category,
            action,
            user,
            correlation_id,
            detail,
        )
    except Exception:
        LOGGER.warning("Failed to write audit event category=%s action=%s", category, action)


# Strong references to supervised fire-and-forget tasks. asyncio holds only a
# weak reference to a pending task, so without this a task can be garbage-
# collected before it runs. Tasks remove themselves on completion.
_supervised_tasks: set[asyncio.Task] = set()


def supervise_task(task: asyncio.Task, label: str) -> None:
    """Log an exception escaping a fire-and-forget task rather than letting
    asyncio swallow it silently, and retain a strong reference so the task
    can't be GC'd mid-flight. Attach to any create_task whose result nobody
    awaits, so a crash surfaces in logs instead of vanishing."""
    _supervised_tasks.add(task)

    def _cb(t: asyncio.Task) -> None:
        _supervised_tasks.discard(t)
        if t.cancelled():
            return
        exc = t.exception()
        if exc is not None:
            LOGGER.error("%s crashed: %s", label, exc, exc_info=exc)
    task.add_done_callback(_cb)


def _corr_id(request) -> str:
    """Extract the correlation ID attached by correlation_id_middleware."""
    return getattr(request.state, "correlation_id", "") if hasattr(request, "state") else ""


# ── Session helper (initialized by app.py) ───────────────────────────────────

_verify_session_token_fn = None


def init_shared(verify_session_token_fn):
    """Called by app.py at module load time to inject the session verifier."""
    global _verify_session_token_fn
    _verify_session_token_fn = verify_session_token_fn


def _get_session(request) -> dict | None:
    """Extract session data from the request cookie without raising."""
    token = request.cookies.get("session")
    if not token:
        return None
    if _verify_session_token_fn is None:
        return None
    return _verify_session_token_fn(token)


async def verify_ws_session(token: str) -> dict | None:
    """Validate a WebSocket session token the same way require_auth does.

    The raw ``verify_session_token`` only checks the signature; the idle
    timeout and absolute-lifetime cap are enforced by ``require_auth`` for
    HTTP requests. WebSocket handlers bypass ``require_auth``, so without
    this an arbitrarily old (but validly signed) cookie could open a stream.
    This mirrors require_auth's time checks, honoring the
    ``session_never_expires`` kiosk opt-out.

    Returns the session dict on success, or None (caller should close the
    socket with code 1008).
    """
    if not token or _verify_session_token_fn is None:
        return None
    session = _verify_session_token_fn(token)
    if not session or "user_id" not in session:
        return None
    user = await db.get_user_by_id(session["user_id"])
    if not user:
        return None
    # Forced-password-change gate (mirrors the HTTP middleware, which blocks
    # every route except the password-change endpoints). A user who must
    # rotate their password may not open device-output streams first.
    if user.get("must_change_password"):
        return None
    # Session revocation check (mirrors require_auth).
    if int(session.get("session_epoch") or 0) != int(user.get("session_epoch") or 0):
        return None
    if bool(user.get("session_never_expires")):
        return session
    now = int(time.time())
    originally_issued = int(session.get("originally_issued_at") or 0)
    if originally_issued > 0 and now - originally_issued > _WS_SESSION_MAX_AGE:
        return None
    idle_timeout = int(state.LOGIN_RULES.get("session_idle_timeout", 1800))
    last_activity = int(session.get("last_activity") or 0)
    if idle_timeout > 0 and last_activity > 0 and now - last_activity > idle_timeout:
        return None
    return session


# ── Object-level authorization (ownership) ───────────────────────────────────

async def require_owner_or_admin(request, owner_username: str | None) -> dict | None:
    """Enforce that the caller owns an object (by username) or is an admin.

    Router-level ``require_auth``/``require_feature`` has already
    authenticated the request before any handler runs, so if no session
    cookie is present the request was authenticated via the server API
    token (``auth_mode == "token"``), which is admin-equivalent by design -
    such callers are allowed through.

    For cookie-authenticated requests the caller must either be the object's
    owner (``owner_username`` matches the session user) or hold the admin
    role. Raises HTTPException(403) otherwise. Returns the session dict (or
    None for API-token callers).

    This is object-level authorization layered on top of the feature-level
    gate; it prevents a user who merely holds a feature (e.g. ``jobs``) from
    reading or controlling objects created by other users.
    """
    session = _get_session(request)
    if session is None:
        # No cookie => authenticated via API token upstream. Allow.
        return None
    if owner_username and session.get("user") == owner_username:
        return session
    user = await db.get_user_by_id(session["user_id"])
    if user and user.get("role") == "admin":
        return session
    raise HTTPException(status_code=403, detail="You do not have access to this resource")


# ── Credential ownership enforcement ─────────────────────────────────────────

async def require_credential_access(
    credential_id,
    *,
    session: dict | None = None,
    submitter_username: str | None = None,
    allow_service: bool = False,
) -> dict:
    """Fetch a credential and enforce that the caller is allowed to use it.

    Pass either a live `session` dict (HTTP request context) or a
    `submitter_username` (background worker / scheduler running a task that
    was originally queued by a user).  At least one must be provided.

    Rules for **user credentials** (is_service=0):
      - Strictly per-owner: ``owner_id`` must match the caller's user id.
      - Admin role does NOT grant access to another user's credential.
      - API-token callers bypass the owner check.
      - Unowned (``owner_id`` is NULL) creds are usable only by API tokens.

    Rules for **service credentials** (is_service=1):
      - Reserved for Plexus-internal background work (monitoring, scheduled
        discovery). Callers must opt in by passing ``allow_service=True``;
        this prevents user-driven endpoints (job launch, etc.) from picking
        up a service cred via misconfiguration.
      - When opted in, admins, API-token callers, and admin submitters may
        use them. Non-admin users cannot use a service cred even with the
        opt-in flag.

    Raises HTTPException(400/401/403/404) on any failure so callers that
    already propagate HTTPException don't need extra handling.

    Every decision (allow or deny) emits a ``credential`` audit event so the
    trail records who used which credential. Grants that don't rest on plain
    ownership (API-token bypass, admin use of a service credential) are
    flagged with an ``override`` marker so legitimate admin use is
    distinguishable from a future authorization regression.
    """
    caller = (
        "api-token" if session is not None and session.get("auth_mode") == "token"
        else (session or {}).get("user") or submitter_username or "(unauthenticated)"
    )

    async def _deny(status: int, detail: str, cred: dict | None = None) -> HTTPException:
        await _audit(
            "credential", "use_denied", user=str(caller),
            detail=f"credential_id={credential_id} "
                   f"owner_id={cred.get('owner_id') if cred else '?'} reason={detail}",
        )
        return HTTPException(status_code=status, detail=detail)

    async def _allow(cred: dict, override: str | None = None) -> dict:
        await _audit(
            "credential", "use", user=str(caller),
            detail=f"credential_id={credential_id} owner_id={cred.get('owner_id')} "
                   f"service={int(bool(cred.get('is_service')))}"
                   + (f" override={override}" if override else ""),
        )
        return cred

    if credential_id is None:
        raise await _deny(400, "credential_id is required")

    cred = await db.get_credential_raw(credential_id)
    if not cred:
        raise await _deny(404, "Credential not found")

    is_service_cred = bool(cred.get("is_service"))

    if is_service_cred and not allow_service:
        # Service creds are only available to call sites that explicitly
        # opt in; this protects user-facing flows from accidentally pulling
        # a Plexus-internal cred just because it was configured as a default.
        raise await _deny(403, "This credential is reserved for Plexus internal use", cred)

    if session is not None:
        if session.get("auth_mode") == "token":
            return await _allow(cred, override="api-token")
        user_id = session.get("user_id")
        if user_id is None:
            raise await _deny(401, "Not authenticated", cred)
        if is_service_cred:
            user = await db.get_user_by_id(int(user_id))
            if user and user.get("role") == "admin":
                return await _allow(cred, override="admin-service-cred")
            raise await _deny(403, "Service credentials require admin access", cred)
        if cred.get("owner_id") == int(user_id):
            return await _allow(cred)
        raise await _deny(403, "You can only use your own credentials", cred)

    if submitter_username:
        user = await db.get_user_by_username(submitter_username)
        if not user:
            # Submitter no longer exists (deleted account). Fail closed.
            raise await _deny(403, "Submitter account is no longer valid", cred)
        if is_service_cred:
            if user.get("role") == "admin":
                return await _allow(cred, override="admin-service-cred")
            raise await _deny(403, "Service credentials require admin submitter", cred)
        if cred.get("owner_id") == int(user["id"]):
            return await _allow(cred)
        raise await _deny(403, "Credential is not owned by the task submitter", cred)

    raise await _deny(401, "Not authenticated", cred)


# ── Config capture/push/diff ────────────────────────────────────────────────

# Patterns matching volatile IOS/NX-OS metadata lines that change between
# captures but do not represent actual configuration drift.
_VOLATILE_LINE_RES = [
    re.compile(r"^Current configuration\s*:\s*\d+\s*bytes", re.IGNORECASE),
    re.compile(r"^Building configuration\.\.\.", re.IGNORECASE),
    re.compile(r"^! Last configuration change at\b"),
    re.compile(r"^! NVRAM config last updated at\b"),
    re.compile(r"^! No configuration change since last restart", re.IGNORECASE),
    re.compile(r"^ntp clock-period\s+\d+"),
]


def _normalize_config(text: str) -> str:
    """Strip volatile metadata lines so they don't appear as drift."""
    lines = text.splitlines(keepends=True)
    return "".join(
        line for line in lines
        if not any(pat.search(line.strip()) for pat in _VOLATILE_LINE_RES)
    )


def _compute_config_diff(
    baseline_text: str,
    actual_text: str,
    baseline_label: str = "baseline",
    actual_label: str = "actual",
) -> tuple[str, int, int]:
    """Compute unified diff between baseline and actual config.

    Volatile metadata lines (byte counts, timestamps, ntp clock-period) are
    stripped before comparison so they never show up as false drift.

    Returns (diff_text, lines_added, lines_removed).
    """
    baseline_lines = _normalize_config(baseline_text).splitlines(keepends=True)
    actual_lines = _normalize_config(actual_text).splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        baseline_lines, actual_lines,
        fromfile=baseline_label, tofile=actual_label,
    ))
    diff_text = "".join(diff)
    added = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))
    return diff_text, added, removed


def _open_netmiko_session(host: dict, credentials: dict):
    """Open a Netmiko session, autodetecting device_type when generic.

    Returns ``(connection, resolved_device_type)``.  The caller is
    responsible for ``disconnect()``.

    When the stored device_type is the generic 'cisco_ios' default
    (or 'unknown'), Netmiko's SSHDetect is used first to autodetect the
    real platform (e.g. cisco_xe for IOS-XE devices like Catalyst
    9200/9300).  Returning the resolved type lets callers look up the
    matching ``Driver`` after the autodetect, so per-vendor command
    syntax is correct even when inventory has the wrong type stored.
    """
    import netmiko
    from netmiko import SSHDetect
    from routes.crypto import decrypt

    device = {
        "device_type": host.get("device_type", "cisco_ios"),
        "host": host["ip_address"],
        "username": credentials["username"],
        "password": decrypt(credentials["password"]),
        "secret": decrypt(credentials.get("secret", "")),
    }

    # Autodetect when the stored type is a generic Cisco default
    # that may be wrong (e.g. IOS-XE devices mis-classified as IOS).
    if device["device_type"] in ("cisco_ios", "unknown"):
        guesser = None
        try:
            detect_device = {**device, "device_type": "autodetect"}
            guesser = SSHDetect(**detect_device)
            best = guesser.autodetect()
            if best:
                LOGGER.info("Autodetected device_type %s for %s (was %s)",
                            best, device["host"], device["device_type"])
                device["device_type"] = best
        except Exception:
            LOGGER.debug("SSHDetect failed for %s, using %s",
                         device["host"], device["device_type"])
        finally:
            # Disconnect even when autodetect() raised, or the probe session
            # (socket + paramiko transport thread) leaks until GC.
            if guesser is not None:
                try:
                    guesser.connection.disconnect()
                except Exception:
                    LOGGER.debug("SSHDetect disconnect failed for %s", device["host"])

    net_connect = netmiko.ConnectHandler(**device)
    if device["secret"]:
        net_connect.enable()
    return net_connect, device["device_type"]


async def _capture_running_config(host: dict, credentials: dict) -> str:
    """SSH to a device and pull running-config via Netmiko.

    The exact show-command comes from the driver registered for the
    autodetected device_type, so non-Cisco vendors (Junos uses
    ``show configuration | display set``) get the right syntax once a
    driver ships.  Falls back to ``show running-config`` if the
    resolved driver doesn't implement the capability - matches the
    legacy behaviour and keeps backups working for vendors that share
    the Cisco command.
    """
    from netcontrol.drivers import DriverCapabilityError, get_driver

    def _do_capture():
        conn, resolved_type = _open_netmiko_session(host, credentials)
        try:
            try:
                capture_cmd = get_driver(resolved_type).capture_running_config_command()
            except DriverCapabilityError:
                capture_cmd = "show running-config"
            return conn.send_command(capture_cmd)
        finally:
            conn.disconnect()

    return await asyncio.to_thread(_do_capture)


async def _run_show_command(host: dict, credentials: dict, command: str) -> str:
    """SSH to a device and run a single show command via Netmiko.

    The command is supplied by the caller verbatim - this helper only
    handles the SSH session lifecycle and autodetect.  Returns the raw
    command output string.
    """
    def _do_run():
        conn, _ = _open_netmiko_session(host, credentials)
        try:
            return conn.send_command(command)
        finally:
            conn.disconnect()

    return await asyncio.to_thread(_do_run)


async def _collect_mac_table_via_cli(host: dict, credentials: dict) -> list[dict]:
    """SSH to a device and pull the MAC address-table via Netmiko + ntc-templates.

    Returns a normalised list of ``{"mac", "vlan", "port", "type"}`` rows.

    The mac_tracking collector uses this in preference to the SNMP
    bridge/Q-BRIDGE MIB walks because the CLI returns every VLAN's FDB
    in one round-trip - on Cisco, SNMP only exposes VLAN 1's bridge MIB
    in the default context and needs a per-VLAN SNMPv3 context dance to
    see anything else, which is unreliable in the wild.

    Raises ``DriverCapabilityError`` when the resolved driver doesn't
    implement ``mac_table_show_command()`` (firewalls, routers without
    L2 forwarding, etc.) - the caller is expected to fall back to SNMP
    in that case.
    """
    from netcontrol.drivers import get_driver

    def _do_collect() -> list[dict]:
        conn, resolved_type = _open_netmiko_session(host, credentials)
        try:
            driver = get_driver(resolved_type)
            # mac_table_show_command() may raise DriverCapabilityError for
            # platforms with no L2 table; let it propagate so the caller
            # knows to fall back rather than silently returning an empty
            # list (which would look the same as "device has no MACs").
            cmd = driver.mac_table_show_command()
            # use_textfsm pulls ntc-templates' parsed output (a list of
            # dicts).  When no template matches, Netmiko returns the raw
            # string instead - guard against that so we don't crash with
            # AttributeError downstream.
            parsed = conn.send_command(cmd, use_textfsm=True)
            if not isinstance(parsed, list):
                return []
            return driver.parse_mac_table(parsed)
        finally:
            conn.disconnect()

    return await asyncio.to_thread(_do_collect)


async def _push_config_to_device(host: dict, credentials: dict, config_lines: list[str]) -> str:
    """SSH to a device and push config lines via Netmiko, then save."""
    def _do_push():
        conn, _ = _open_netmiko_session(host, credentials)
        try:
            output = conn.send_config_set(config_lines)
            # save_config() is Netmiko's vendor-aware persist call - it
            # already knows ``write memory`` vs ``copy running-config
            # startup-config`` per platform, so the driver's
            # save_config_commands() is only used by routes that bypass
            # Netmiko's high-level helper.
            save_output = conn.save_config()
            return output + "\n" + save_output
        finally:
            conn.disconnect()

    return await asyncio.to_thread(_do_push)
