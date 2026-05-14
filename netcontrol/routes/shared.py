"""
shared.py -- Cross-domain helper functions used by multiple route modules.

Provides audit logging, config capture/push/diff, and session helpers.
"""
from __future__ import annotations

import asyncio
import difflib
import re

import routes.database as db
from fastapi import HTTPException

from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.shared")


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
    """
    if credential_id is None:
        raise HTTPException(status_code=400, detail="credential_id is required")

    cred = await db.get_credential_raw(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    is_service_cred = bool(cred.get("is_service"))

    if is_service_cred and not allow_service:
        # Service creds are only available to call sites that explicitly
        # opt in; this protects user-facing flows from accidentally pulling
        # a Plexus-internal cred just because it was configured as a default.
        raise HTTPException(
            status_code=403,
            detail="This credential is reserved for Plexus internal use",
        )

    if session is not None:
        if session.get("auth_mode") == "token":
            return cred
        user_id = session.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if is_service_cred:
            user = await db.get_user_by_id(int(user_id))
            if user and user.get("role") == "admin":
                return cred
            raise HTTPException(
                status_code=403,
                detail="Service credentials require admin access",
            )
        if cred.get("owner_id") == int(user_id):
            return cred
        raise HTTPException(status_code=403, detail="You can only use your own credentials")

    if submitter_username:
        user = await db.get_user_by_username(submitter_username)
        if not user:
            # Submitter no longer exists (deleted account). Fail closed.
            raise HTTPException(status_code=403, detail="Submitter account is no longer valid")
        if is_service_cred:
            if user.get("role") == "admin":
                return cred
            raise HTTPException(
                status_code=403,
                detail="Service credentials require admin submitter",
            )
        if cred.get("owner_id") == int(user["id"]):
            return cred
        raise HTTPException(status_code=403, detail="Credential is not owned by the task submitter")

    raise HTTPException(status_code=401, detail="Not authenticated")


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
        try:
            detect_device = {**device, "device_type": "autodetect"}
            guesser = SSHDetect(**detect_device)
            best = guesser.autodetect()
            if best:
                LOGGER.info("Autodetected device_type %s for %s (was %s)",
                            best, device["host"], device["device_type"])
                device["device_type"] = best
            guesser.connection.disconnect()
        except Exception:
            LOGGER.debug("SSHDetect failed for %s, using %s",
                         device["host"], device["device_type"])

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
