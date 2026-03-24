"""
shared.py -- Cross-domain helper functions used by multiple route modules.

Provides audit logging, config capture/push/diff, and session helpers.
"""

import asyncio
import difflib
import re

import routes.database as db
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
