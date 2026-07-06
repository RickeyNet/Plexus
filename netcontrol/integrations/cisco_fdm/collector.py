"""FDM metrics collector - polls FDM-managed FTDs and feeds the monitoring pipeline.

Each enabled host (``hosts.fdm_api_enabled = 1``, ``device_type = cisco_ftd``)
is polled over the FDM REST API for a CPU/memory/interface health snapshot,
normalised into the standard poll-result dict, and handed to
``monitoring._process_poll_result`` - the *same* function the SNMP poll uses.
So FDM hosts get availability tracking, threshold + baseline alerting, metric
samples, and notification-channel fan-out with zero firewall-specific alert
code.

Session discipline: one :class:`FdmClient` per host is cached for the process
lifetime and reused across cycles, so each FTD holds exactly one HTTPS session
(FDM caps each device at 5 sessions shared with its web UI). The client is
rebuilt only when a host's connection params or credential change.
"""

from __future__ import annotations

import asyncio
import time

import routes.database as db

import netcontrol.routes.state as state
from netcontrol.integrations.cisco_fdm.client import FdmApiError, FdmClient
from netcontrol.integrations.cisco_fdm.normalize import build_poll_result, error_result
from netcontrol.telemetry import configure_logging, redact_value

LOGGER = configure_logging("plexus.cisco_fdm")

# host_id -> (fingerprint, FdmClient). Reused across poll cycles; rebuilt when
# the fingerprint (connection params / credential) changes.
_CLIENTS: dict[int, tuple[tuple, FdmClient]] = {}
_CLIENTS_LOCK = asyncio.Lock()


def _verify_tls(host: dict) -> bool:
    """Resolve the per-host TLS-verify setting, secure by default.

    A missing value means verification is ON; only an explicit stored 0
    (operator opt-out for a self-signed FDM cert) disables it.
    """
    val = host.get("fdm_verify_tls", 1)
    return bool(1 if val is None else val)


def _fingerprint(host: dict, cred: dict) -> tuple:
    return (
        host.get("ip_address"),
        int(host.get("fdm_port") or 443),
        _verify_tls(host),
        host.get("fdm_credential_id"),
        cred.get("username"),
    )


async def _get_client(host: dict, cred: dict, password: str) -> FdmClient:
    fp = _fingerprint(host, cred)
    host_id = host["id"]
    async with _CLIENTS_LOCK:
        existing = _CLIENTS.get(host_id)
        if existing is not None and existing[0] == fp:
            return existing[1]
        if existing is not None:
            # Connection params changed - retire the stale session before
            # opening a new one so we don't leak a slot in the 5-session budget.
            try:
                await existing[1].close()
            except Exception as exc:  # noqa: BLE001 - best-effort teardown
                LOGGER.debug("cisco_fdm: error closing stale session for host %s: %s",
                             host_id, exc)
        client = FdmClient(
            host["ip_address"],
            cred.get("username") or "",
            password,
            port=int(host.get("fdm_port") or 443),
            verify_tls=_verify_tls(host),
            api_version=state.FDM_CONFIG.get("api_version", state.FDM_DEFAULTS["api_version"]),
        )
        _CLIENTS[host_id] = (fp, client)
        return client


async def collect_host(host: dict) -> dict:
    """Poll one FDM host and return a normalised poll-result dict.

    Never raises for expected failures (missing credential, decryption error,
    API/transport error): those become an ``error_result`` so the host is
    persisted as 'down' rather than aborting the cycle.
    """
    from routes.crypto import decrypt

    host_id = host["id"]
    cred_id = host.get("fdm_credential_id")
    if not cred_id:
        return error_result(host_id, "no FDM credential assigned")

    cred = await db.get_credential_raw(cred_id)
    if not cred:
        return error_result(host_id, f"FDM credential {cred_id} not found")
    if not cred.get("is_service"):
        # Same policy as the monitoring and MAC CLI pollers: an unattended
        # collector has no user context, so it may only use Plexus-owned
        # service credentials - never a user's personal stored credential
        # (which a host binding could otherwise exfiltrate via a poller
        # pointed at an attacker-controlled endpoint).
        return error_result(
            host_id,
            f"FDM credential {cred_id} is not a service credential; "
            "background polling requires one",
        )
    try:
        password = decrypt(cred["password"]) if cred.get("password") else ""
    except Exception:  # noqa: BLE001 - decryption failure must not crash the cycle
        return error_result(host_id, "FDM credential decryption failed")

    client = await _get_client(host, cred, password)
    start = time.monotonic()
    try:
        systeminfo = await client.get_system_info()
        metrics = await client.get_operational_metrics()
    except FdmApiError as exc:
        return error_result(host_id, str(exc))

    res = build_poll_result(host_id, systeminfo, metrics)
    res["response_time_ms"] = round((time.monotonic() - start) * 1000, 1)
    return res


async def run_fdm_poll_once(*, force: bool = False) -> dict:
    """Run one FDM poll cycle across all FDM-enabled hosts."""
    if not force and not state.FDM_CONFIG.get("enabled"):
        return {"enabled": False, "hosts_polled": 0, "alerts_created": 0, "errors": 0}

    # Imported lazily: monitoring imports a large dependency graph, and
    # importing it at module load would create a cycle (app wires both).
    from netcontrol.routes.monitoring import _process_poll_result

    hosts = await db.get_fdm_hosts()
    if not hosts:
        return {"enabled": True, "hosts_polled": 0, "alerts_created": 0, "errors": 0}

    alert_rules_cache = await db.get_alert_rules(enabled_only=True)
    max_concurrency = max(1, int(state.FDM_CONFIG.get(
        "poll_concurrency", state.FDM_DEFAULTS["poll_concurrency"])))
    timeout = float(state.FDM_CONFIG.get(
        "per_host_timeout_seconds", state.FDM_DEFAULTS["per_host_timeout_seconds"]))
    sem = asyncio.Semaphore(max_concurrency)

    polled = alerts = errors = 0

    async def _poll_one(h: dict):
        async with sem:
            try:
                res = await asyncio.wait_for(collect_host(h), timeout=timeout)
                return h, res, None
            except Exception as exc:  # noqa: BLE001 - recorded per host below
                return h, None, exc

    tasks = [asyncio.create_task(_poll_one(h)) for h in hosts]
    for coro in asyncio.as_completed(tasks):
        h, res, err = await coro
        if err is not None:
            errors += 1
            LOGGER.warning("cisco_fdm: poll failed for %s: %s",
                           h.get("hostname", "?"), redact_value(str(err)))
            continue
        polled += 1
        try:
            alerts += await _process_poll_result(h, res, alert_rules_cache)
        except Exception as exc:  # noqa: BLE001 - one host must not abort the cycle
            LOGGER.warning("cisco_fdm: post-process error for %s: %s",
                           h.get("hostname", "?"), redact_value(str(exc)))

    LOGGER.info("cisco_fdm: poll complete - %d hosts, %d alerts, %d errors",
                polled, alerts, errors)
    return {"enabled": True, "hosts_polled": polled, "alerts_created": alerts, "errors": errors}


async def close_all_clients() -> None:
    """Close every cached FDM session (called on shutdown)."""
    async with _CLIENTS_LOCK:
        for _fp, client in _CLIENTS.values():
            try:
                await client.close()
            except Exception as exc:  # noqa: BLE001 - best-effort teardown
                LOGGER.debug("cisco_fdm: error closing session on shutdown: %s", exc)
        _CLIENTS.clear()


async def fdm_poll_loop() -> None:
    """Infinite loop that polls FDM-managed firewalls at configurable intervals."""
    while True:
        try:
            await asyncio.sleep(int(state.FDM_CONFIG.get(
                "interval_seconds", state.FDM_DEFAULTS["interval_seconds"])))
            await run_fdm_poll_once()
        except asyncio.CancelledError:
            await close_all_clients()
            raise
        except Exception as exc:  # noqa: BLE001 - loop must survive a bad cycle
            LOGGER.warning("cisco_fdm poll loop failure: %s", redact_value(str(exc)))
            await asyncio.sleep(state.FDM_DEFAULTS["interval_seconds"])
