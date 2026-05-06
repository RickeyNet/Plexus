"""
_common.py — Shared helpers for playbooks.

This module is intentionally underscore-prefixed so the playbook
auto-loader in ``__init__.py`` skips it.  It contains plumbing that
would otherwise be copy-pasted across every playbook:

* a single source of truth for ``NETMIKO_AVAILABLE`` and the Netmiko
  exception classes,
* a ``connect_device`` helper that builds the device dict, opens the
  connection, handles timeout/auth errors, and yields the appropriate
  LogEvents,
* a ``pin_snmp_engine_id`` helper used by the SNMP-touching playbooks
  to keep SNMPv3 keys valid across config changes,
* a ``simulate_connect`` helper that mimics a real connection (with an
  occasional fake timeout) for development without devices.

Playbooks remain ordinary ``BasePlaybook`` subclasses; these helpers
simply remove the boilerplate so each playbook's file shows what is
*unique* to that workflow.
"""

from __future__ import annotations

import asyncio
import random
import re
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from routes.runner import BasePlaybook, LogEvent

# Netmiko is optional: when it isn't installed (typical in dev),
# playbooks fall back to simulation mode.  We import it once here so
# every playbook can read the same flag instead of repeating the try/except.
try:
    from netmiko import ConnectHandler  # type: ignore
    from netmiko.exceptions import (  # type: ignore
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )

    NETMIKO_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without netmiko
    ConnectHandler = None  # type: ignore[assignment]
    NetmikoAuthenticationException = Exception  # type: ignore[assignment,misc]
    NetmikoTimeoutException = Exception  # type: ignore[assignment,misc]
    NETMIKO_AVAILABLE = False


# Default Netmiko keepalive/banner timeouts used by every playbook.
DEFAULT_TIMEOUT = 30
DEFAULT_BANNER_TIMEOUT = 30

# Probability used in simulation mode to mimic a flaky network.
SIMULATED_TIMEOUT_RATE = 0.08


def build_device_dict(
    ip: str,
    device_type: str,
    credentials: dict,
) -> dict[str, Any]:
    """Assemble the kwargs Netmiko's ``ConnectHandler`` expects.

    Centralized so every playbook uses the same shape (host, username,
    password, secret fallback, and the standard timeouts).
    """
    return {
        "device_type": device_type,
        "host": ip,
        "username": credentials.get("username"),
        "password": credentials.get("password"),
        # Fall back to the login password if no enable secret was provided.
        "secret": credentials.get("secret") or credentials.get("password"),
        "timeout": DEFAULT_TIMEOUT,
        "banner_timeout": DEFAULT_BANNER_TIMEOUT,
    }


@asynccontextmanager
async def connect_device(
    pb: BasePlaybook,
    ip: str,
    hostname: str,
    device_type: str,
    credentials: dict,
) -> AsyncGenerator[tuple[Any | None, list[LogEvent]], None]:
    """Async context manager that opens a Netmiko connection.

    Usage:
        async with connect_device(self, ip, hostname, dt, creds) as (conn, events):
            for ev in events:
                yield ev
            if conn is None:
                return  # connection failed; the error event is already in `events`
            ...use conn...

    On entry it tries to connect, drops into enable mode, and reports a
    "Connected to ..." success event.  On any failure it leaves
    ``conn`` as ``None`` and puts the appropriate error event in
    ``events`` so the caller can simply yield them and bail out.

    On exit it always disconnects cleanly if a connection was opened.
    """
    events: list[LogEvent] = []
    conn = None
    device = build_device_dict(ip, device_type, credentials)

    try:
        # Netmiko is blocking, so push it onto a worker thread to keep
        # the playbook's async loop responsive.
        conn = await asyncio.to_thread(ConnectHandler, **device)
    except NetmikoTimeoutException:
        events.append(pb.log_error(f"TIMEOUT connecting to {ip} — skipping.", host=hostname))
    except NetmikoAuthenticationException:
        events.append(pb.log_error(f"AUTH FAILED for {ip} — skipping.", host=hostname))
    except Exception as exc:  # noqa: BLE001 - surface any other failure to the UI
        events.append(pb.log_error(f"Connection error for {ip}: {exc}", host=hostname))

    if conn is not None:
        try:
            # Many show/config commands require enable mode; promote if needed.
            if not conn.check_enable_mode():
                await asyncio.to_thread(conn.enable)
            # Strip the trailing prompt char so the success message is clean.
            prompt = conn.find_prompt().replace("#", "").replace(">", "").strip()
            events.append(pb.log_success(f"Connected to {prompt} ({ip})", host=hostname))
        except Exception as exc:  # noqa: BLE001
            events.append(pb.log_error(f"Post-connect error for {ip}: {exc}", host=hostname))
            try:
                conn.disconnect()
            finally:
                conn = None

    try:
        yield conn, events
    finally:
        # Always release the SSH session, even if the caller raised.
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:  # noqa: BLE001 - disconnect failures are non-fatal
                pass


async def pin_snmp_engine_id(
    pb: BasePlaybook,
    conn: Any,
    hostname: str,
) -> AsyncGenerator[LogEvent, None]:
    """Pin the device's current SNMP engine ID before SNMP changes.

    Cisco IOS regenerates the engine ID when certain ``snmp-server``
    lines are added or removed.  Because SNMPv3 auth/priv keys are
    *localized* to the engine ID, regeneration silently invalidates
    every existing user — monitoring then breaks until the keys are
    re-cut.  Reading the current engine ID and pinning it with
    ``snmp-server engineID local <id>`` keeps the keys valid across
    the change.
    """
    try:
        output = await asyncio.to_thread(conn.send_command, "show snmp engineID")
        # Typical output: "Local SNMP engineID: 80000009030050568D9CDFC0"
        match = re.search(r"[Ll]ocal\s+.*[Ee]ngine\s*ID[:\s]+([0-9A-Fa-f]+)", output)
        if not match:
            yield pb.log_info(
                "Could not detect SNMP engine ID — skipping pin.",
                host=hostname,
            )
            return
        engine_id = match.group(1).strip()
        yield pb.log_info(
            f"Pinning SNMP engine ID ({engine_id}) to prevent SNMPv3 key invalidation.",
            host=hostname,
        )
        await asyncio.to_thread(
            conn.send_config_set,
            [f"snmp-server engineID local {engine_id}"],
        )
    except Exception as exc:  # noqa: BLE001
        yield pb.log_warn(f"Could not pin SNMP engine ID: {exc}", host=hostname)


async def simulate_connect(
    pb: BasePlaybook,
    ip: str,
    hostname: str,
) -> AsyncGenerator[LogEvent, None]:
    """Pretend to open a connection for dev/testing without real devices.

    Sleeps a short random interval, occasionally yields a fake timeout
    error (controlled by ``SIMULATED_TIMEOUT_RATE``), and otherwise
    yields a "Connected to ..." success event.

    Callers should treat the first yielded ``error`` event as a signal
    to ``return`` from their host loop (mirroring the real connect
    helper's contract).
    """
    await asyncio.sleep(random.uniform(0.2, 0.6))
    if random.random() < SIMULATED_TIMEOUT_RATE:
        yield pb.log_error(f"TIMEOUT connecting to {ip} — skipping.", host=hostname)
        return
    yield pb.log_success(f"Connected to {hostname} ({ip})", host=hostname)
