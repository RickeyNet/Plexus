"""
monitoring.py -- Real-time device monitoring, alerting, SLA dashboards,
and background poll/escalation loops.

Object scope: polls, alerts, SLA and availability rows follow their host;
alert rules, suppressions and SLA targets follow the host or inventory group
they target (a global one is read by everyone, changed only by unrestricted
callers); topology (integration) entities are visible to a scoped caller
only when matched to one of their inventory hosts.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Literal

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

import netcontrol.routes.state as state
from netcontrol.drivers import supports_cli
from netcontrol.integrations.apc import snmp as apc_snmp
from netcontrol.integrations.availability import ENTITY_TYPES as TOPOLOGY_ENTITY_TYPES
from netcontrol.integrations.opnsense import health as opnsense_health
from netcontrol.object_scope import (
    HOST_NOT_FOUND,
    READ_ONLY_DETAIL,
    ScopeModel,
    filter_rows,
    group_filter,
    readable_host_ids,
    refuse_scoped,
    register_model,
    request_scope,
    require_new_row,
    require_object_host,
    require_row,
    scoped,
)
from netcontrol.routes import opnsense_health as opnsense_health_poll, topology_availability as topology_tracking
from netcontrol.routes.icmp import ICMP_AVAILABLE, ping_host
from netcontrol.routes.maintenance_windows import _parse_iso
from netcontrol.routes.metrics_engine import (
    emit_metric_samples_from_poll,
    run_retention_cleanup as metrics_retention_cleanup,
    store_interface_error_metrics_from_poll,
    store_interface_ts_from_poll,
)
from netcontrol.routes.route_capture import (  # re-exported: tests and callers import them from here
    _is_route_table as _is_route_table,
    _parse_route_summary_count as _parse_route_summary_count,
    _route_table_commands as _route_table_commands,
    assemble_route_text,
    read_full_route_tables,
    store_route_snapshot,
)
from netcontrol.routes.shared import _audit, _corr_id, _get_session, _session_user
from netcontrol.routes.snmp import (
    PYSMNP_AVAILABLE,
    SNMP_TIMEOUT_ERROR,
    SnmpEngine,
    _snmp_get_values,
    _snmp_walk,
)
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

router = APIRouter()
admin_router = APIRouter()
LOGGER = configure_logging("plexus.monitoring")

# Alert rules, alert suppressions, SLA targets and baseline alert rules: a row
# that targets a host or an inventory group follows it; a global row (neither)
# is shared: every scoped caller reads it, only unrestricted callers change it.
MONITORING_RULE = register_model(
    ScopeModel(
        "monitoring_rule",
        {"host": "host_id", "group": "group_id"},
        shared=True,
        not_found="Rule not found",
        description="Alert rules, suppressions, SLA targets and baseline rules (by target host or group)",
    )
)

# Monotonic timestamp of the last retention cleanup. Retention is a set of
# full-table DELETE scans, so we throttle it (see retention_interval_seconds)
# rather than running it on every poll cycle.
_last_retention_cleanup = 0.0


def _exc_text(exc: BaseException) -> str:
    """str(exc), falling back to the type name — TimeoutError and friends
    stringify to '' and would otherwise log an empty message."""
    return str(exc) or type(exc).__name__


async def _track_availability_from_poll(
    res: dict,
    poll_id: int,
    *,
    hostname: str | None = None,
    ip_address: str | None = None,
) -> None:
    """Record host/interface up-down transitions using batched DB writes."""
    host_id = res["host_id"]
    transitions: list[tuple] = []

    new_host_state = "up" if res["poll_status"] == "ok" else "down"
    host_states = await db.get_last_availability_states(host_id, "host")
    prev_host = host_states.get("", "unknown")
    if prev_host != new_host_state:
        transitions.append(
            (host_id, "host", "", prev_host, new_host_state, poll_id),
        )

    if_states = await db.get_last_availability_states(host_id, "interface")
    for iface in res.get("if_details", []):
        if_idx = str(iface.get("if_index", ""))
        if not if_idx:
            continue
        if_state = "up" if iface.get("status") == "up" else "down"
        prev_if = if_states.get(if_idx, "unknown")
        if prev_if != if_state:
            transitions.append(
                (host_id, "interface", if_idx, prev_if, if_state, poll_id),
            )

    if not transitions:
        return

    await db.record_availability_transitions_batch(transitions)
    for _host_id, entity_type, entity_id, old_state, new_state, _poll_id in transitions:
        if entity_type == "host":
            LOGGER.info(
                "availability: host %s (%s) %s → %s",
                hostname or "?",
                ip_address or "?",
                old_state,
                new_state,
            )
            break


# ── Helpers ───────────────────────────────────────────────────────────────────


# Per-host route-poll cadence state: host_id -> (monotonic ts of the last full
# `show ip route` pull, route count from the last summary). The full table is
# only pulled when the summary count changes or route_full_interval_seconds
# has elapsed; the cheap summary runs every tick.
_ROUTE_POLL_STATE: dict[int, tuple[float, int | None]] = {}

# Exponential backoff for hosts whose polls raise or time out. Such hosts
# produce no poll row or availability transition anyway, but each attempt
# holds a semaphore slot and an executor thread for the full per-host timeout;
# without backoff a dead host burns that every cycle. host_id ->
# [consecutive_failures, cycles_to_skip]. Manual polls (force=True) bypass the
# skip; any successful poll clears the entry.
_POLL_BACKOFF: dict[int, list[int]] = {}
_POLL_BACKOFF_MAX_SKIP = 8


def _poll_backoff_should_skip(host_id: int) -> bool:
    entry = _POLL_BACKOFF.get(host_id)
    if not entry or entry[1] <= 0:
        return False
    entry[1] -= 1
    return True


def _poll_backoff_record(host_id: int, *, ok: bool) -> None:
    if ok:
        _POLL_BACKOFF.pop(host_id, None)
        return
    failures = _POLL_BACKOFF.get(host_id, [0, 0])[0] + 1
    # 1st failure retries next cycle; from the 2nd on skip 1, 2, 4, ... cycles.
    skip = 0 if failures < 2 else min(2 ** (failures - 2), _POLL_BACKOFF_MAX_SKIP)
    _POLL_BACKOFF[host_id] = [failures, skip]


async def _poll_host_monitoring(host: dict, cred: dict, snmp_cfg: dict) -> dict:
    """Poll a single host for CPU, memory, interfaces, VPN, and routes via SNMP + SSH."""
    import netmiko
    from routes.crypto import decrypt

    result = {
        "host_id": host["id"],
        "cpu_percent": None,
        "memory_percent": None,
        "memory_used_mb": None,
        "memory_total_mb": None,
        "uptime_seconds": None,
        "if_up_count": 0,
        "if_down_count": 0,
        "if_admin_down": 0,
        "if_details": [],
        "vpn_tunnels_up": 0,
        "vpn_tunnels_down": 0,
        "vpn_details": [],
        "route_count": 0,
        "route_snapshot": "",
        "poll_status": "ok",
        "poll_error": "",
        "response_time_ms": None,
        "packet_loss_pct": None,
        # ICMP is an independent liveness probe - it never gates SNMP or
        # SSH polling.  Recording icmp_alive separately lets the UI show
        # "pings fine but SNMP broken" as a distinct state, which is the
        # exact signal an operator needs when triaging a misconfigured
        # SNMPv3 setup on (eg) a Cisco FTD.
        "icmp_alive": None,
        "icmp_rtt_ms": None,
    }

    poll_start = time.monotonic()

    # ── ICMP liveness probe (runs in parallel with SNMP/SSH) ──
    icmp_cfg = state.MONITORING_CONFIG
    icmp_task = None
    if ICMP_AVAILABLE and icmp_cfg.get("icmp_enabled", True):
        icmp_task = asyncio.create_task(
            ping_host(
                host["ip_address"],
                count=int(icmp_cfg.get("icmp_count", 3)),
                timeout=float(icmp_cfg.get("icmp_timeout_seconds", 2.0)),
                privileged=bool(icmp_cfg.get("icmp_privileged", False)),
            )
        )

    # ── SNMP polling for CPU, memory, interfaces ──
    # Skip SNMP entirely for icmp_only hosts: they're declared at onboarding
    # as ping-only, so issuing v3 walks against them would just produce a
    # cycle of timeouts and noisy log lines.
    is_icmp_only_host = host.get("device_type") == "icmp_only"
    # The one SNMP engine of a UPS poll (below), closed when the poll ends.
    snmp_engine = None
    if PYSMNP_AVAILABLE and snmp_cfg.get("enabled") and not is_icmp_only_host:
        try:
            from netcontrol.routes.metrics_engine import resolve_oids_for_device

            device_type = host.get("device_type", "cisco_ios")
            # An APC card's SNMP agent is small: it answers SNMPv3 slowly and
            # holds few requests. The walks below, sent together and each an
            # SNMP session of its own (an engine discovery apiece), lose
            # requests on it, and the UPS state with them. A UPS is polled in
            # one session, a request at a time.
            if device_type == apc_snmp.STATUS_KIND:
                snmp_engine = SnmpEngine()
            snmp_turn = asyncio.Lock()
            snmp_errors: list[str] = []

            async def _in_turn(request: Callable[[], Awaitable[tuple[dict, str | None]]]) -> dict:
                """One request to a UPS card at a time, and none after one it
                did not answer: each would wait out one more timeout."""
                async with snmp_turn:
                    if SNMP_TIMEOUT_ERROR in snmp_errors:
                        return {}
                    values, error = await request()
                    if error:
                        snmp_errors.append(error)
                    return values

            async def _walk(oid: str) -> dict:
                if snmp_engine is None:
                    return await _snmp_walk(host["ip_address"], 5.0, snmp_cfg, oid)
                return await _in_turn(
                    lambda: _snmp_walk(host["ip_address"], 5.0, snmp_cfg, oid, return_errors=True, engine=snmp_engine)
                )

            async def _get(oids: tuple[str, ...]) -> dict:
                return await _in_turn(
                    lambda: _snmp_get_values(host["ip_address"], 5.0, snmp_cfg, oids, engine=snmp_engine)
                )

            # Resolve vendor-specific OIDs (DB overrides → built-in map → fallback)
            oid_map = await resolve_oids_for_device(device_type)
            cpu_oid = oid_map.get("cpu_oid", "1.3.6.1.4.1.9.9.109.1.1.1.1.8")
            cpu_old_oid = "1.3.6.1.4.1.9.2.1.58.0"  # avgBusy5 (Cisco legacy fallback)
            mem_used_oid = oid_map.get("mem_used_oid", "1.3.6.1.4.1.9.9.48.1.1.1.5")
            mem_free_oid = oid_map.get("mem_free_oid", "1.3.6.1.4.1.9.9.48.1.1.1.6")
            mem_total_oid = oid_map.get("mem_total_oid", "")
            uptime_oid = oid_map.get("uptime_oid", "1.3.6.1.2.1.1.3")

            # Interface OIDs are standard MIB-II / IF-MIB - vendor-independent
            if_oper_status_oid = "1.3.6.1.2.1.2.2.1.8"  # ifOperStatus
            if_admin_status_oid = "1.3.6.1.2.1.2.2.1.7"  # ifAdminStatus
            if_name_oid = "1.3.6.1.2.1.31.1.1.1.1"  # ifName
            if_descr_oid = "1.3.6.1.2.1.2.2.1.2"  # ifDescr
            if_high_speed_oid = "1.3.6.1.2.1.31.1.1.1.15"  # ifHighSpeed
            if_hc_in_oid = "1.3.6.1.2.1.31.1.1.1.6"  # ifHCInOctets
            if_hc_out_oid = "1.3.6.1.2.1.31.1.1.1.10"  # ifHCOutOctets

            # Interface error/discard counter OIDs (IF-MIB)
            if_in_errors_oid = "1.3.6.1.2.1.2.2.1.14"  # ifInErrors
            if_out_errors_oid = "1.3.6.1.2.1.2.2.1.20"  # ifOutErrors
            if_in_discards_oid = "1.3.6.1.2.1.2.2.1.13"  # ifInDiscards
            if_out_discards_oid = "1.3.6.1.2.1.2.2.1.19"  # ifOutDiscards

            # Build walk list - skip empty OIDs
            async def _empty_walk():
                return {}

            walk_targets = [
                _walk(cpu_oid) if cpu_oid else _empty_walk(),
                _walk(cpu_old_oid),
                _walk(mem_used_oid) if mem_used_oid else _empty_walk(),
                _walk(mem_free_oid) if mem_free_oid else _empty_walk(),
                _walk(if_oper_status_oid),
                _walk(if_admin_status_oid),
                _walk(if_name_oid),
                _walk(if_descr_oid),
                _walk(if_high_speed_oid),
                _walk(if_hc_in_oid),
                _walk(if_hc_out_oid),
                _walk(uptime_oid),
                _walk(if_in_errors_oid),
                _walk(if_out_errors_oid),
                _walk(if_in_discards_oid),
                _walk(if_out_discards_oid),
            ]
            # Also walk mem_total if the vendor provides a total OID
            if mem_total_oid:
                walk_targets.append(_walk(mem_total_oid))

            walk_results = await asyncio.gather(*walk_targets)

            cpu_vals = walk_results[0]
            cpu_old_vals = walk_results[1]
            mem_used_vals = walk_results[2]
            mem_free_vals = walk_results[3]
            if_oper = walk_results[4]
            if_admin = walk_results[5]
            if_names = walk_results[6]
            if_descrs = walk_results[7]
            if_speeds = walk_results[8]
            hc_in = walk_results[9]
            hc_out = walk_results[10]
            uptime_vals = walk_results[11]
            if_in_errs = walk_results[12]
            if_out_errs = walk_results[13]
            if_in_disc = walk_results[14]
            if_out_disc = walk_results[15]
            mem_total_vals = walk_results[16] if len(walk_results) > 16 else {}

            # CPU
            if cpu_vals:
                cpu_val = next(iter(cpu_vals.values()), None)
                if cpu_val is not None:
                    try:
                        result["cpu_percent"] = float(int(cpu_val))
                    except (ValueError, TypeError) as exc:
                        LOGGER.warning(
                            "monitoring: bad CPU value from %s (oid %s): %s",
                            host["ip_address"],
                            cpu_oid,
                            redact_value(str(exc)),
                        )
            elif cpu_old_vals:
                cpu_val = next(iter(cpu_old_vals.values()), None)
                if cpu_val is not None:
                    try:
                        result["cpu_percent"] = float(int(cpu_val))
                    except (ValueError, TypeError) as exc:
                        LOGGER.warning(
                            "monitoring: bad CPU value from %s (oid %s): %s",
                            host["ip_address"],
                            cpu_old_oid,
                            redact_value(str(exc)),
                        )

            # Memory - supports two patterns:
            #   Cisco:  used + free OIDs (bytes) → compute total
            #   HOST-RESOURCES / Fortinet:  used + total OIDs (allocation units or %)
            if mem_used_vals and mem_free_vals:
                try:
                    used = int(next(iter(mem_used_vals.values())))
                    free = int(next(iter(mem_free_vals.values())))
                    total = used + free
                    if total > 0:
                        result["memory_used_mb"] = round(used / 1048576, 1)
                        result["memory_total_mb"] = round(total / 1048576, 1)
                        result["memory_percent"] = round(used / total * 100, 1)
                except (ValueError, TypeError, StopIteration) as exc:
                    LOGGER.warning(
                        "monitoring: bad memory values from %s (oids %s/%s): %s",
                        host["ip_address"],
                        mem_used_oid,
                        mem_free_oid,
                        redact_value(str(exc)),
                    )
            elif mem_used_vals and mem_total_vals:
                try:
                    used = int(next(iter(mem_used_vals.values())))
                    total = int(next(iter(mem_total_vals.values())))
                    if total > 0:
                        result["memory_used_mb"] = round(used / 1048576, 1)
                        result["memory_total_mb"] = round(total / 1048576, 1)
                        result["memory_percent"] = round(used / total * 100, 1)
                except (ValueError, TypeError, StopIteration) as exc:
                    LOGGER.warning(
                        "monitoring: bad memory values from %s (oids %s/%s): %s",
                        host["ip_address"],
                        mem_used_oid,
                        mem_total_oid,
                        redact_value(str(exc)),
                    )
            elif mem_used_vals:
                # Fortinet fgSysMemUsage returns usage as a percentage directly
                try:
                    pct = float(int(next(iter(mem_used_vals.values()))))
                    if 0 <= pct <= 100:
                        result["memory_percent"] = pct
                except (ValueError, TypeError, StopIteration) as exc:
                    LOGGER.warning(
                        "monitoring: bad memory usage value from %s (oid %s): %s",
                        host["ip_address"],
                        mem_used_oid,
                        redact_value(str(exc)),
                    )

            # Uptime
            if uptime_vals:
                try:
                    ticks = int(next(iter(uptime_vals.values())))
                    result["uptime_seconds"] = ticks // 100
                except (ValueError, TypeError, StopIteration) as exc:
                    LOGGER.warning(
                        "monitoring: bad uptime value from %s (oid %s): %s",
                        host["ip_address"],
                        uptime_oid,
                        redact_value(str(exc)),
                    )

            # Interface details
            effective_names = if_names or if_descrs
            name_map: dict[str, str] = {}
            for oid, val in effective_names.items():
                idx = oid.rsplit(".", 1)[-1] if "." in oid else ""
                if idx:
                    name_map[idx] = str(val)

            if_details = []
            for oid, val in if_oper.items():
                idx = oid.rsplit(".", 1)[-1] if "." in oid else ""
                if not idx:
                    continue
                oper = int(val) if val else 0
                admin_oid = if_admin_status_oid + "." + idx
                admin_val = if_admin.get(admin_oid)
                admin = int(admin_val) if admin_val else 0

                iface_name = name_map.get(idx, f"ifIndex-{idx}")
                speed_mbps = 0
                for s_oid, s_val in if_speeds.items():
                    if s_oid.endswith("." + idx):
                        try:
                            speed_mbps = int(s_val)
                        except (ValueError, TypeError) as exc:
                            LOGGER.debug(
                                "monitoring: bad ifHighSpeed value from %s for ifIndex %s: %s",
                                host["ip_address"],
                                idx,
                                str(exc),
                            )
                        break

                in_octets = 0
                out_octets = 0
                for i_oid, i_val in hc_in.items():
                    if i_oid.endswith("." + idx):
                        try:
                            in_octets = int(i_val)
                        except (ValueError, TypeError) as exc:
                            LOGGER.debug(
                                "monitoring: bad ifHCInOctets value from %s for ifIndex %s: %s",
                                host["ip_address"],
                                idx,
                                str(exc),
                            )
                        break
                for o_oid, o_val in hc_out.items():
                    if o_oid.endswith("." + idx):
                        try:
                            out_octets = int(o_val)
                        except (ValueError, TypeError) as exc:
                            LOGGER.debug(
                                "monitoring: bad ifHCOutOctets value from %s for ifIndex %s: %s",
                                host["ip_address"],
                                idx,
                                str(exc),
                            )
                        break

                status_str = "up" if oper == 1 else ("admin_down" if admin == 2 else "down")
                if status_str == "up":
                    result["if_up_count"] += 1
                elif status_str == "admin_down":
                    result["if_admin_down"] += 1
                else:
                    result["if_down_count"] += 1

                # Extract error/discard counters
                in_errors = 0
                out_errors = 0
                in_discards = 0
                out_discards = 0
                for e_oid, e_val in if_in_errs.items():
                    if e_oid.endswith("." + idx):
                        try:
                            in_errors = int(e_val)
                        except (ValueError, TypeError) as exc:
                            LOGGER.debug(
                                "monitoring: bad ifInErrors value from %s for ifIndex %s: %s",
                                host["ip_address"],
                                idx,
                                str(exc),
                            )
                        break
                for e_oid, e_val in if_out_errs.items():
                    if e_oid.endswith("." + idx):
                        try:
                            out_errors = int(e_val)
                        except (ValueError, TypeError) as exc:
                            LOGGER.debug(
                                "monitoring: bad ifOutErrors value from %s for ifIndex %s: %s",
                                host["ip_address"],
                                idx,
                                str(exc),
                            )
                        break
                for e_oid, e_val in if_in_disc.items():
                    if e_oid.endswith("." + idx):
                        try:
                            in_discards = int(e_val)
                        except (ValueError, TypeError) as exc:
                            LOGGER.debug(
                                "monitoring: bad ifInDiscards value from %s for ifIndex %s: %s",
                                host["ip_address"],
                                idx,
                                str(exc),
                            )
                        break
                for e_oid, e_val in if_out_disc.items():
                    if e_oid.endswith("." + idx):
                        try:
                            out_discards = int(e_val)
                        except (ValueError, TypeError) as exc:
                            LOGGER.debug(
                                "monitoring: bad ifOutDiscards value from %s for ifIndex %s: %s",
                                host["ip_address"],
                                idx,
                                str(exc),
                            )
                        break

                if_details.append(
                    {
                        "if_index": int(idx),
                        "name": iface_name,
                        "status": status_str,
                        "speed_mbps": speed_mbps,
                        "in_octets": in_octets,
                        "out_octets": out_octets,
                        "in_errors": in_errors,
                        "out_errors": out_errors,
                        "in_discards": in_discards,
                        "out_discards": out_discards,
                    }
                )

            result["if_details"] = if_details

            # An APC UPS: its battery, output and identity (PowerNet-MIB).
            if device_type == apc_snmp.STATUS_KIND:
                result["ups"] = await apc_snmp.read_ups_status(_get, _walk)
                if not result["ups"]:
                    # No state is no alerts and no UPS firmware row: say why.
                    LOGGER.warning(
                        "monitoring: no UPS state read from %s over SNMP: %s",
                        host.get("hostname", host["ip_address"]),
                        redact_value(
                            snmp_errors[-1] if snmp_errors else "the card answered none of the PowerNet-MIB objects"
                        ),
                    )

        except Exception as exc:
            LOGGER.warning(
                "monitoring: SNMP poll failed for %s: %s",
                host.get("hostname", host["ip_address"]),
                redact_value(str(exc)),
            )
        finally:
            if snmp_engine is not None:
                snmp_engine.close_dispatcher()

    # ── SSH polling for VPN and routes ──
    # Not for a host that is only pinged, nor for a platform with no command
    # line (an Aruba Instant On switch): it is polled over SNMP alone.
    if cred and supports_cli(host.get("device_type")):
        try:

            def _ssh_poll():
                device = {
                    "device_type": host.get("device_type", "cisco_ios"),
                    "host": host["ip_address"],
                    "username": cred["username"],
                    "password": decrypt(cred["password"]),
                    "secret": decrypt(cred.get("secret", "")),
                    "conn_timeout": 15,
                    "timeout": 30,
                    # Cap the whole SSH session. asyncio.wait_for can't kill the
                    # worker thread this runs in, so a wedged command must be
                    # bounded here too or it leaks a thread past the poll.
                    "session_timeout": 45,
                }
                # Per-command read ceiling: a command that connects but never
                # returns a prompt fails fast instead of burning the full
                # netmiko retry cycle.
                read_timeout = 20
                net_connect = netmiko.ConnectHandler(**device)
                try:
                    if device["secret"]:
                        net_connect.enable()
                    outputs = {}

                    # VPN health
                    if state.MONITORING_CONFIG.get("collect_vpn", True):
                        dtype = host.get("device_type", "cisco_ios")
                        if dtype.startswith("cisco_asa") or dtype == "asa":
                            outputs["vpn"] = net_connect.send_command(
                                "show vpn-sessiondb summary", read_timeout=read_timeout
                            )
                        else:
                            outputs["vpn"] = net_connect.send_command(
                                "show crypto isakmp sa", read_timeout=read_timeout
                            )

                    # Route table: the cheap summary runs every tick; the full
                    # table (route_snapshot + churn hash) is only pulled when the
                    # summary count moves or the slow cadence elapses. Unparseable
                    # summaries fall back to pulling the full table every tick.
                    if state.MONITORING_CONFIG.get("collect_routes", True):
                        commands = _route_table_commands(str(host.get("device_type") or "cisco_ios"))
                        summary_count = None
                        if commands.summary:
                            outputs["routes"] = net_connect.send_command(commands.summary, read_timeout=read_timeout)
                            summary_count = _parse_route_summary_count(outputs["routes"])
                        outputs["route_summary_count"] = summary_count
                        full_interval = float(state.MONITORING_CONFIG.get("route_full_interval_seconds", 900))
                        last_full_ts, last_count = _ROUTE_POLL_STATE.get(host["id"], (0.0, None))
                        now = time.monotonic()
                        need_full = (
                            summary_count is None
                            or last_count is None
                            or summary_count != last_count
                            or full_interval <= 0
                            or (now - last_full_ts) >= full_interval
                        )
                        if need_full:
                            # The VRF tables too, for the path trace. Best-effort:
                            # a device that rejects the command keeps the global table.
                            outputs["routes_full"], outputs["routes_vrf"] = read_full_route_tables(
                                net_connect, commands, read_timeout
                            )
                            _ROUTE_POLL_STATE[host["id"]] = (now, summary_count)
                        else:
                            _ROUTE_POLL_STATE[host["id"]] = (last_full_ts, summary_count)

                    return outputs
                finally:
                    # A read-timeout mid-command otherwise abandons the SSH
                    # socket + paramiko transport thread until GC — one leaked
                    # session per failing host per poll cycle on a flaky fleet.
                    try:
                        net_connect.disconnect()
                    except Exception:
                        pass

            ssh_outputs = await asyncio.to_thread(_ssh_poll)

            # Parse VPN output
            vpn_text = ssh_outputs.get("vpn", "")
            if vpn_text:
                vpn_details = []
                for line in vpn_text.strip().splitlines():
                    line_lower = line.lower().strip()
                    if not line_lower or line_lower.startswith(("dst", "---", "status")):
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        # Detect ISAKMP SA lines: status field typically has QM_IDLE or MM_*
                        status_keywords_up = {"qm_idle", "active", "established"}
                        status_keywords_down = {"mm_no_state", "mm_key_exch", "deleted", "down", "inactive"}
                        status_found = False
                        for p in parts:
                            pl = p.lower()
                            if pl in status_keywords_up:
                                result["vpn_tunnels_up"] += 1
                                vpn_details.append({"peer": parts[0], "status": "up", "raw": line.strip()})
                                status_found = True
                                break
                            elif pl in status_keywords_down:
                                result["vpn_tunnels_down"] += 1
                                vpn_details.append({"peer": parts[0], "status": "down", "raw": line.strip()})
                                status_found = True
                                break
                        if not status_found and any(c.isdigit() for c in line):
                            # ASA summary lines with session counts
                            pass
                result["vpn_details"] = vpn_details

            # Parse route output. route_count prefers the summary total so the
            # metric stays in one domain across lean and full ticks; the
            # snapshot (and churn hashing downstream) only exists on full ticks.
            # The VRF tables follow the global one; the count stays the global table's.
            result["route_snapshot"], result["route_count"] = assemble_route_text(
                str(ssh_outputs.get("routes_full") or ""),
                str(ssh_outputs.get("routes_vrf") or ""),
                ssh_outputs.get("route_summary_count"),
            )

        except Exception as exc:
            LOGGER.warning(
                "monitoring: SSH poll failed for %s: %s",
                host.get("hostname", host["ip_address"]),
                redact_value(str(exc)),
            )
            if result["cpu_percent"] is None and result["if_up_count"] == 0:
                result["poll_status"] = "error"
                result["poll_error"] = str(exc)[:500]

    # ── An OPNsense firewall's health over its API (no SNMP profile needed) ──
    await opnsense_health_poll.add_to_poll(host, result)

    # ── ICMP results: real RTT + loss override the wall-clock placeholder ──
    icmp_result = None
    if icmp_task is not None:
        try:
            icmp_result = await icmp_task
        except Exception as exc:
            LOGGER.warning(
                "monitoring: ICMP probe failed for %s: %s",
                host.get("hostname", host["ip_address"]),
                redact_value(str(exc)),
            )

    if icmp_result is not None:
        result["icmp_alive"] = icmp_result["alive"]
        result["icmp_rtt_ms"] = icmp_result["rtt_ms"]
        result["response_time_ms"] = icmp_result["rtt_ms"]
        result["packet_loss_pct"] = icmp_result["packet_loss_pct"]
        # ICMP-only hosts (no SNMP/SSH credentials) rely on ping alone for
        # liveness - promote ICMP failure to a real poll error so the
        # availability state machine flips them to "down".
        is_icmp_only = host.get("device_type") == "icmp_only"
        if is_icmp_only:
            if not icmp_result["alive"]:
                result["poll_status"] = "error"
                result["poll_error"] = icmp_result["error"] or "host did not respond to ICMP"
    else:
        # ICMP disabled or icmplib missing - fall back to the prior wall-clock
        # signal so dashboards built on response_time_ms keep working.
        poll_elapsed = (time.monotonic() - poll_start) * 1000  # ms
        result["response_time_ms"] = round(poll_elapsed, 2)
        result["packet_loss_pct"] = 100.0 if result["poll_status"] == "error" else 0.0

    return result


def _metric_value_from_poll(res: dict, metric: str) -> float | None:
    """Extract a metric value from a poll result dict."""
    metric_map = {
        "cpu": res.get("cpu_percent"),
        "memory": res.get("memory_percent"),
        "interface_down": float(res.get("if_down_count", 0)),
        "vpn_down": float(res.get("vpn_tunnels_down", 0)),
        "route_count": float(res.get("route_count", 0)),
        "if_up": float(res.get("if_up_count", 0)),
        "uptime": float(res.get("uptime_seconds") or 0),
    }
    if metric in apc_snmp.UPS_METRICS:
        return apc_snmp.ups_metric_value(res.get("ups"), metric)
    if metric in opnsense_health.FIREWALL_METRICS:
        return opnsense_health.firewall_metric_value(res.get("opnsense_health"), metric)
    return metric_map.get(metric)


def _check_threshold(value: float | None, operator: str, threshold: float) -> bool:
    """Evaluate a threshold condition."""
    if value is None:
        return False
    ops = {
        ">=": value >= threshold,
        ">": value > threshold,
        "<=": value <= threshold,
        "<": value < threshold,
        "==": value == threshold,
        "!=": value != threshold,
    }
    return ops.get(operator, False)


def _suppression_active_local(
    rows: list[dict],
    host_id: int,
    metric: str,
    group_id: int | None,
) -> bool:
    """In-memory equivalent of db.is_alert_suppressed against a preloaded set of
    active suppression rows (see db.get_active_alert_suppressions). Mirrors the
    SQL match: a global (host+group NULL) row with empty or matching metric, a
    host-scoped row, or a group-scoped row, in each case matching when the row's
    metric is '' (all metrics) or equals this metric."""
    for r in rows:
        r_metric = r.get("metric") or ""
        if r_metric and r_metric != metric:
            continue
        r_host = r.get("host_id")
        r_group = r.get("group_id")
        if r_host is None and r_group is None:
            return True  # global suppression (metric already matched above)
        if r_host is not None and r_host == host_id:
            return True
        if group_id is not None and r_group is not None and r_group == group_id:
            return True
    return False


async def _evaluate_alerts_for_poll(
    res: dict,
    poll_id: int,
    group_id: int | None,
    rules: list[dict],
    hostname: str = "",
    suppressions: list[dict] | None = None,
) -> int:
    """Evaluate built-in thresholds and user-defined rules against a poll result.

    Returns the number of new alerts created (dedup'd alerts count as 0).

    ``suppressions`` is an optional preloaded list of active suppression rows
    (from db.get_active_alert_suppressions); when provided, suppression is
    tested in-memory instead of one DB round-trip per firing check. When None,
    falls back to the per-check db.is_alert_suppressed query.
    """
    alerts_created = 0
    host_id = res["host_id"]

    async def _suppressed(metric: str) -> bool:
        if suppressions is not None:
            return _suppression_active_local(suppressions, host_id, metric, group_id)
        return await db.is_alert_suppressed(host_id, metric, group_id)

    # ── Built-in threshold checks (always active as fallbacks) ──
    built_in_checks = []
    cpu_thresh = state.MONITORING_CONFIG.get("cpu_threshold", 90)
    mem_thresh = state.MONITORING_CONFIG.get("memory_threshold", 90)

    if res["cpu_percent"] is not None and res["cpu_percent"] >= cpu_thresh:
        built_in_checks.append(
            {
                "metric": "cpu",
                "alert_type": "threshold",
                "message": f"CPU utilization at {res['cpu_percent']}% (threshold: {cpu_thresh}%)",
                "severity": "critical" if res["cpu_percent"] >= 95 else "warning",
                "value": res["cpu_percent"],
                "threshold": float(cpu_thresh),
            }
        )

    if res["memory_percent"] is not None and res["memory_percent"] >= mem_thresh:
        built_in_checks.append(
            {
                "metric": "memory",
                "alert_type": "threshold",
                "message": f"Memory utilization at {res['memory_percent']}% (threshold: {mem_thresh}%)",
                "severity": "critical" if res["memory_percent"] >= 95 else "warning",
                "value": res["memory_percent"],
                "threshold": float(mem_thresh),
            }
        )

    if res["if_down_count"] > 0:
        down_names = [i["name"] for i in res["if_details"] if i.get("status") == "down"]
        if down_names:
            built_in_checks.append(
                {
                    "metric": "interface_down",
                    "alert_type": "status",
                    "message": f"{len(down_names)} interface(s) down: {', '.join(down_names[:5])}",
                    "severity": "warning",
                    "value": float(len(down_names)),
                    "threshold": None,
                }
            )

    if res["vpn_tunnels_down"] > 0:
        down_peers = [v["peer"] for v in res["vpn_details"] if v.get("status") == "down"]
        built_in_checks.append(
            {
                "metric": "vpn_down",
                "alert_type": "status",
                "message": f"{res['vpn_tunnels_down']} VPN tunnel(s) down"
                + (f": {', '.join(down_peers[:3])}" if down_peers else ""),
                "severity": "warning",
                "value": float(res["vpn_tunnels_down"]),
                "threshold": None,
            }
        )

    # An APC UPS: on battery, battery low / failed / to replace, output off or
    # on bypass, overload, battery temperature. Each clears its open alert
    # once the UPS reports it gone (the UPS's traps use the same keys).
    ups_status = res.get("ups") or {}
    ups_checks = apc_snmp.ups_alert_checks(ups_status)
    built_in_checks.extend(ups_checks)
    for metric in apc_snmp.ups_cleared_alerts(ups_status, ups_checks):
        await db.resolve_monitoring_alerts(apc_snmp.alert_dedup_key(host_id, metric))

    # An OPNsense firewall read over its API: a nearly full file system, a
    # state table near its limit; each clears its open alert once below.
    firewall_health = res.get("opnsense_health") or {}
    firewall_checks = opnsense_health.firewall_alert_checks(firewall_health)
    built_in_checks.extend(firewall_checks)
    for metric in opnsense_health.firewall_cleared_alerts(firewall_health, firewall_checks):
        await db.resolve_monitoring_alerts(opnsense_health.alert_dedup_key(host_id, metric))

    # Fire built-in checks with dedup + suppression
    for chk in built_in_checks:
        if await _suppressed(chk["metric"]):
            continue
        dedup_key = f"{host_id}:{chk['metric']}:{chk['alert_type']}"
        await db.create_monitoring_alert(
            host_id=host_id,
            poll_id=poll_id,
            alert_type=chk["alert_type"],
            metric=chk["metric"],
            message=chk["message"],
            severity=chk["severity"],
            value=chk["value"],
            threshold=chk.get("threshold"),
            dedup_key=dedup_key,
            hostname=hostname,
        )
        alerts_created += 1

    # ── User-defined rule checks ──
    for rule in rules:
        # Scope check: rule applies to this host?
        if rule.get("host_id") and rule["host_id"] != host_id:
            continue
        if rule.get("group_id") and rule["group_id"] != group_id:
            continue

        metric_val = _metric_value_from_poll(res, rule["metric"])
        if metric_val is None:
            continue

        triggered = _check_threshold(metric_val, rule.get("operator", ">="), rule["value"])
        if not triggered:
            continue

        # Check suppression
        if await _suppressed(rule["metric"]):
            continue

        dedup_key = f"{host_id}:{rule['metric']}:rule:{rule['id']}"
        msg = f"Rule '{rule['name']}': {rule['metric']} = {metric_val} {rule['operator']} {rule['value']}"

        await db.create_monitoring_alert(
            host_id=host_id,
            poll_id=poll_id,
            alert_type=rule.get("rule_type", "threshold"),
            metric=rule["metric"],
            message=msg,
            severity=rule.get("severity", "warning"),
            value=metric_val,
            threshold=rule["value"],
            rule_id=rule["id"],
            dedup_key=dedup_key,
            channel_ids=rule.get("channel_ids", "") or "",
            hostname=hostname,
        )
        alerts_created += 1

    return alerts_created


async def _run_alert_escalation() -> int:
    """Escalate unacknowledged alerts that have exceeded the escalation timeout."""
    if not state.MONITORING_CONFIG.get("escalation_enabled", True):
        return 0
    escalate_after = state.MONITORING_CONFIG.get("escalation_after_minutes", 30)
    if escalate_after <= 0:
        return 0

    # Also check rules with per-rule escalation settings
    rules = await db.get_alert_rules(enabled_only=True)
    rule_escalation_map = {}
    for r in rules:
        if r.get("escalate_after_minutes", 0) > 0:
            rule_escalation_map[r["id"]] = {
                "after_minutes": r["escalate_after_minutes"],
                "escalate_to": r.get("escalate_to", "critical"),
            }

    # Get alerts eligible for global escalation
    alerts = await db.get_alerts_for_escalation(escalate_after)
    escalated = 0
    for alert in alerts:
        rule_id = alert.get("rule_id")
        if rule_id and rule_id in rule_escalation_map:
            target = rule_escalation_map[rule_id]["escalate_to"]
        else:
            target = "critical"
        await db.escalate_alert(alert["id"], target)
        escalated += 1
        LOGGER.info(
            "monitoring: escalated alert %d (%s on %s) to %s",
            alert["id"],
            alert.get("metric", "?"),
            alert.get("hostname", "?"),
            target,
        )

    return escalated


# ── Background loops ─────────────────────────────────────────────────────────


async def _build_poll_targets() -> list[tuple[dict, dict | None, dict]]:
    """(host, credential, snmp_cfg) for every host in every group.

    Shared by the scheduled cycle and the manual SSE stream so credential
    resolution and target building can't drift apart. Prefers the dedicated
    service credential; falls back to the legacy default_credential_id for
    deployments that haven't migrated yet."""
    cred_id = state.AUTH_CONFIG.get("service_credential_id") or state.AUTH_CONFIG.get("default_credential_id")
    default_cred = await db.get_credential_raw(cred_id) if cred_id else None
    targets: list[tuple[dict, dict | None, dict]] = []
    for group in await db.get_all_groups():
        hosts = await db.get_hosts_for_group(group["id"])
        # Every host is a target whatever its SNMP state, carrying its own
        # effective SNMP config.
        for h, snmp_cfg in state._hosts_with_snmp_config(hosts, group["id"], enabled_only=False):
            targets.append((h, default_cred, snmp_cfg))
    return targets


async def _run_retention_cleanup_throttled() -> None:
    """Aged-row cleanup (polls/alerts/snapshots/suppressions/metrics).

    These are full-table DELETE scans, so run at most once per
    retention_interval_seconds no matter who triggers a poll (scheduled
    cycle or manual stream)."""
    global _last_retention_cleanup
    retention_interval = float(
        state.MONITORING_CONFIG.get(
            "retention_interval_seconds", state.MONITORING_DEFAULTS["retention_interval_seconds"]
        )
    )
    now_mono = time.monotonic()
    if now_mono - _last_retention_cleanup < retention_interval:
        return
    _last_retention_cleanup = now_mono
    retention_days = state.MONITORING_CONFIG.get("retention_days", 30)
    try:
        await db.delete_old_monitoring_polls(retention_days)
        await db.delete_old_monitoring_alerts(retention_days)
        await db.delete_old_route_snapshots(retention_days)
        await db.delete_expired_suppressions()
        await db.delete_old_sla_metrics(
            int(state.MONITORING_CONFIG.get("sla_retention_days", state.MONITORING_DEFAULTS["sla_retention_days"]))
        )
        await metrics_retention_cleanup()
        await db.purge_topology_availability(retention_days)
        await db.purge_topology_entity_metrics(
            retention_days,
            int(state.MONITORING_CONFIG.get("sla_retention_days", state.MONITORING_DEFAULTS["sla_retention_days"])),
        )
        await db.purge_meraki_alerts(retention_days)
        await db.purge_security_events(retention_days)
    except Exception as exc:
        LOGGER.warning("monitoring: retention cleanup failed: %s", redact_value(_exc_text(exc)))


async def _process_poll_result(
    h: dict,
    res: dict,
    alert_rules_cache: list,
    suppressions: list[dict] | None = None,
) -> int:
    """Persist one poll result and run availability/alerting/metrics/baseline/
    churn for the host. Returns the number of alerts created.

    Invoked per-host as each poll completes (see ``_run_monitoring_poll_once``)
    so this DB and alert work overlaps with the network polls still in flight,
    rather than running as a serial tail after every device has been polled.
    """
    alerts_created = 0

    # Store poll result
    poll_id = await db.create_monitoring_poll(
        host_id=res["host_id"],
        cpu_percent=res["cpu_percent"],
        memory_percent=res["memory_percent"],
        memory_used_mb=res["memory_used_mb"],
        memory_total_mb=res["memory_total_mb"],
        uptime_seconds=res["uptime_seconds"],
        if_up_count=res["if_up_count"],
        if_down_count=res["if_down_count"],
        if_admin_down=res["if_admin_down"],
        if_details=json.dumps(res["if_details"]),
        vpn_tunnels_up=res["vpn_tunnels_up"],
        vpn_tunnels_down=res["vpn_tunnels_down"],
        vpn_details=json.dumps(res["vpn_details"]),
        route_count=res["route_count"],
        route_snapshot=res["route_snapshot"][:5000],
        poll_status=res["poll_status"],
        poll_error=res["poll_error"],
        response_time_ms=res.get("response_time_ms"),
        packet_loss_pct=res.get("packet_loss_pct"),
        icmp_alive=res.get("icmp_alive"),
        icmp_rtt_ms=res.get("icmp_rtt_ms"),
    )

    # ── Vendor state: an APC UPS's newest state and identity ──
    if res.get("ups"):
        try:
            await _store_ups_status(h, res["ups"])
        except Exception as exc:
            LOGGER.warning(
                "monitoring: storing UPS state failed for host %s: %s", res["host_id"], redact_value(str(exc))
            )

    # ── Availability Tracking: detect state transitions ──
    try:
        await _track_availability_from_poll(
            res,
            poll_id,
            hostname=h.get("hostname"),
            ip_address=h.get("ip_address"),
        )
    except Exception as exc:
        LOGGER.debug("availability: tracking error for host %s: %s", res["host_id"], str(exc))

    # ── Alerting Engine: evaluate built-in thresholds + user rules ──
    alerts_created += await _evaluate_alerts_for_poll(
        res, poll_id, h.get("group_id"), alert_rules_cache, hostname=h.get("hostname", ""), suppressions=suppressions
    )

    # ── Metrics Engine: emit flexible metric samples + interface TS ──
    try:
        await emit_metric_samples_from_poll(res)
        await store_interface_ts_from_poll(res["host_id"], res.get("if_details", []))
        await store_interface_error_metrics_from_poll(res["host_id"], res.get("if_details", []))
    except Exception as exc:
        LOGGER.debug("metrics: emission error for host %s: %s", res["host_id"], redact_value(str(exc)))

    # ── Baseline Deviation Alerting ──
    try:
        from netcontrol.routes.baseline_alerting import evaluate_baseline_alerts_for_poll

        baseline_alerts = await evaluate_baseline_alerts_for_poll(res, poll_id)
        alerts_created += baseline_alerts
    except Exception as exc:
        LOGGER.debug("baseline: evaluation error for host %s: %s", res["host_id"], redact_value(str(exc)))

    # Route churn detection
    if res["route_snapshot"]:
        written, prev_snap = await store_route_snapshot(res["host_id"], res["route_snapshot"], res["route_count"])
        if written:
            if prev_snap is not None:
                delta = abs(res["route_count"] - prev_snap["route_count"])
                suppressed = await db.is_alert_suppressed(res["host_id"], "route_churn", h.get("group_id"))
                if not suppressed:
                    await db.create_monitoring_alert(
                        host_id=res["host_id"],
                        poll_id=poll_id,
                        alert_type="churn",
                        metric="route_churn",
                        message=f"Route table changed: {prev_snap['route_count']} -> {res['route_count']} routes (delta: {delta})",
                        severity="warning" if delta < 10 else "critical",
                        value=float(delta),
                        dedup_key=f"{res['host_id']}:route_churn:churn",
                    )
                    alerts_created += 1

    return alerts_created


async def _store_ups_status(h: dict, ups: dict) -> None:
    """Keep a UPS's newest state as its vendor status, and its identity on
    the host: the UPS model and serial (the card's sysDescr names only the
    card) and the card's firmware as the software version. A field is
    written only when the UPS reported it and it changed."""
    await db.set_host_vendor_status(h["id"], apc_snmp.STATUS_KIND, ups)
    model = str(ups.get("model") or "").strip()
    version = str(ups.get("nmc_firmware") or "").strip()
    if (model and model != (h.get("model") or "")) or (version and version != (h.get("software_version") or "")):
        await db.update_host_device_info(
            h["id"], model or h.get("model") or "", version or h.get("software_version") or ""
        )
    serial = str(ups.get("serial") or "").strip()
    if serial and serial != (h.get("serial_number") or ""):
        await db.update_host_serial(h["id"], serial)


async def _run_monitoring_poll_once(*, force: bool = False, host_ids: frozenset[int] | None = None) -> dict:
    """Run one monitoring poll cycle across all groups with SNMP enabled
    (``host_ids``: only those hosts, for a caller limited by object scope)."""
    if not force and not state.MONITORING_CONFIG.get("enabled"):
        return {"enabled": False, "hosts_polled": 0, "alerts_created": 0, "errors": 0}

    hosts_polled = 0
    alerts_created = 0
    errors = 0

    max_concurrency = max(
        1, int(state.MONITORING_CONFIG.get("poll_concurrency", state.MONITORING_DEFAULTS["poll_concurrency"]))
    )
    sem = asyncio.Semaphore(max_concurrency)

    # Pre-load user-defined alert rules + active suppressions once for this
    # cycle so alert evaluation matches them in-memory instead of issuing one
    # is_alert_suppressed() query per firing check per host.
    alert_rules_cache = await db.get_alert_rules(enabled_only=True)
    suppressions_cache = await db.get_active_alert_suppressions()

    poll_timeout = float(state.MONITORING_CONFIG.get("per_host_timeout_seconds", 90))

    # One flat work list across every group, polled as a single concurrent
    # batch (a per-group gather would let one slow host in an early group
    # delay every later group). Backed-off hosts are skipped unless this is
    # a manual (force) poll.
    targets: list[tuple[dict, dict | None, dict]] = []
    backed_off = 0
    for h, cred, snmp_cfg in await _build_poll_targets():
        if host_ids is not None and int(h["id"]) not in host_ids:
            continue
        if not force and _poll_backoff_should_skip(h["id"]):
            backed_off += 1
            continue
        targets.append((h, cred, snmp_cfg))

    async def _poll_one(h, c, s):
        # Returns (host, result, error) so as_completed can attribute each
        # result to its host; the per-device timeout/exception is captured
        # rather than raised (see streaming poll for details).
        async with sem:
            try:
                res = await asyncio.wait_for(_poll_host_monitoring(h, c, s), timeout=poll_timeout)
                return h, res, None
            except TimeoutError:
                # Bare TimeoutError stringifies to '' - name it like the
                # streaming poll does so the log says what happened.
                return h, None, TimeoutError(f"poll exceeded {poll_timeout:.0f}s")
            except Exception as exc:  # noqa: BLE001 - recorded per host below
                return h, None, exc

    tasks = [asyncio.create_task(_poll_one(h, c, s)) for h, c, s in targets]

    # Process each host as its poll completes rather than after the whole
    # batch finishes, so the per-host DB writes + alert/metric/baseline/churn
    # work overlaps with the network polls still in flight instead of running
    # as a serial tail once every device has been polled.
    for coro in asyncio.as_completed(tasks):
        try:
            h, res, err = await coro
        except Exception as exc:  # task crashed without host context
            errors += 1
            LOGGER.warning("monitoring: poll task crashed: %s", redact_value(_exc_text(exc)))
            continue

        if err is not None:
            errors += 1
            _poll_backoff_record(h["id"], ok=False)
            LOGGER.warning(
                "monitoring: poll exception for %s: %s", h.get("hostname", "?"), redact_value(_exc_text(err))
            )
            continue

        _poll_backoff_record(h["id"], ok=True)
        hosts_polled += 1
        try:
            alerts_created += await _process_poll_result(h, res, alert_rules_cache, suppressions=suppressions_cache)
        except Exception as exc:  # one host's persistence must not abort the cycle
            LOGGER.warning(
                "monitoring: post-process error for %s: %s", h.get("hostname", "?"), redact_value(_exc_text(exc))
            )

    await _run_retention_cleanup_throttled()

    LOGGER.info(
        "monitoring: poll complete - %d hosts, %d alerts, %d errors, %d backed off",
        hosts_polled,
        alerts_created,
        errors,
        backed_off,
    )
    return {
        "enabled": True,
        "hosts_polled": hosts_polled,
        "alerts_created": alerts_created,
        "errors": errors,
        "backed_off": backed_off,
    }


async def poll_host_now(host_id: int) -> dict:
    """Poll one host now, outside the schedule, through the scheduled
    cycle's code (an APC UPS after one of its SNMP traps). Nothing while
    monitoring is off."""
    if not state.MONITORING_CONFIG.get("enabled"):
        return {"enabled": False, "hosts_polled": 0, "alerts_created": 0, "errors": 0}
    return await _run_monitoring_poll_once(force=True, host_ids=frozenset({int(host_id)}))


async def _monitoring_poll_loop() -> None:
    """Infinite loop that polls device health at configurable intervals."""
    while True:
        try:
            interval = int(
                state.MONITORING_CONFIG.get("interval_seconds", state.MONITORING_DEFAULTS["interval_seconds"])
            )
            # Small positive jitter so poll ticks don't stay phase-locked with
            # the other background loops (escalation, drift, federation, FDM)
            # that all start at the same instant on app startup.
            await asyncio.sleep(interval + random.uniform(0, max(1.0, interval * 0.05)))
            await _run_monitoring_poll_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("monitoring poll loop failure: %s", redact_value(_exc_text(exc)))
            await asyncio.sleep(state.MONITORING_DEFAULTS["interval_seconds"])


async def _baseline_computation_loop() -> None:
    """Background loop that recomputes metric baselines every 6 hours."""
    while True:
        try:
            await asyncio.sleep(6 * 3600)  # Every 6 hours
            from netcontrol.routes.baseline_alerting import run_baseline_computation_cycle

            await run_baseline_computation_cycle()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.debug("baseline computation loop failure: %s", redact_value(str(exc)))
            await asyncio.sleep(3600)


async def _alert_escalation_loop() -> None:
    """Background loop that checks for alerts needing escalation."""
    while True:
        try:
            interval = int(state.MONITORING_CONFIG.get("escalation_check_interval", 60))
            await asyncio.sleep(interval)
            escalated = await _run_alert_escalation()
            if escalated > 0:
                LOGGER.info("monitoring: escalation cycle - %d alerts escalated", escalated)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("alert escalation loop failure: %s", redact_value(str(exc)))
            await asyncio.sleep(60)


# ── SLA rollups and target evaluation ───────────────────────────────────────

# The summary value each SLA metric is compared on, and how it is printed.
_SLA_VALUE_KEYS = {
    "uptime": "uptime_pct",
    "latency": "avg_latency_ms",
    "jitter": "jitter_ms",
    "packet_loss": "avg_packet_loss_pct",
}
_SLA_METRIC_LABELS = {
    "uptime": ("Uptime", "%"),
    "latency": ("Latency", " ms"),
    "jitter": ("Jitter", " ms"),
    "packet_loss": ("Packet loss", "%"),
}
_SLA_WINDOW_DAYS_MAX = 365
# First SLA pass after startup: soon, so a restart does not push the rollups
# back by a whole interval, but after the first poll cycles have settled.
_SLA_STARTUP_DELAY_SECONDS = 120


def classify_sla_value(metric: str, value: float | None, target_value: float, warning_value: float) -> str:
    """``met`` / ``warn`` / ``breach`` (``no_data`` without a value). Uptime is
    higher-is-better; latency, jitter and packet loss are lower-is-better."""
    if value is None:
        return "no_data"
    if metric == "uptime":
        if value >= target_value:
            return "met"
        return "warn" if value >= warning_value else "breach"
    if value <= target_value:
        return "met"
    return "warn" if value <= warning_value else "breach"


def _sla_alert_message(target: dict, status: str, value: float, window_days: int) -> str:
    label, unit = _SLA_METRIC_LABELS.get(target["metric"], (target["metric"], ""))
    state_text = "breached" if status == "breach" else "at warning level"
    return (
        f"SLA target '{target['name']}' {state_text}: {label} {value:g}{unit} over the last "
        f"{window_days} days (target {target['target_value']:g}{unit}, "
        f"warning {target['warning_value']:g}{unit})"
    )


async def _raise_sla_alert(target: dict, host: dict, status: str, value: float, window_days: int) -> int:
    """Open (or bump) the SLA alert of one (target, host). Severity is
    ``warning`` for warn and ``critical`` for breach; an open warning alert
    that turns into a breach is escalated to critical."""
    severity = "critical" if status == "breach" else "warning"
    threshold = target["warning_value"] if status == "breach" else target["target_value"]
    alert_id = await db.create_monitoring_alert(
        host_id=host["host_id"],
        poll_id=None,
        alert_type="sla_breach",
        metric=f"sla_{target['metric']}",
        message=_sla_alert_message(target, status, value, window_days),
        severity=severity,
        value=value,
        threshold=threshold,
        dedup_key=f"sla:{target['id']}:{host['host_id']}",
        hostname=host.get("hostname") or "",
    )
    if severity == "critical":
        existing = await db.get_monitoring_alert(alert_id)
        if existing and existing.get("severity") == "warning":
            await db.escalate_alert(alert_id, "critical")
    return alert_id


def _sla_sample_count(metric: str, values: dict | None) -> int:
    if values is None:
        return 0
    if metric == "uptime":
        return int(values["total_polls"])
    if metric == "packet_loss":
        return int(values["packet_loss_samples"])
    return int(values["latency_samples"])


async def evaluate_sla_targets(now: datetime | None = None) -> dict:
    """Evaluate every enabled SLA target for every host it applies to, store
    the result (latest status + history of changes) and open an alert for
    each warn/breach that no active suppression covers. Targets of topology
    entities (with a ``provider``) are left to ``topology_sla``."""
    targets = [t for t in await db.get_sla_targets() if t.get("enabled") and not str(t.get("provider") or "").strip()]
    evaluated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    suppressions = await db.get_active_alert_suppressions()
    metrics_by_window: dict[int, dict] = {}
    results: list[dict] = []
    alerts: list[tuple[dict, dict, str, float, int]] = []
    suppressed = 0
    for target in targets:
        metric = target.get("metric")
        if metric not in _SLA_VALUE_KEYS:
            continue
        window_days = max(1, min(_SLA_WINDOW_DAYS_MAX, int(target.get("window_days") or 30)))
        if window_days not in metrics_by_window:
            metrics_by_window[window_days] = await db.get_sla_host_metrics(window_days, now=now)
        window = metrics_by_window[window_days]
        hosts = await db.get_sla_target_hosts(host_id=target.get("host_id"), group_id=target.get("group_id"))
        for host in hosts:
            values = window["hosts"].get(int(host["host_id"]))
            value = values.get(_SLA_VALUE_KEYS[metric]) if values else None
            status = classify_sla_value(metric, value, float(target["target_value"]), float(target["warning_value"]))
            results.append(
                {
                    "target_id": target["id"],
                    "host_id": host["host_id"],
                    "metric": metric,
                    "value": value,
                    "target_value": target["target_value"],
                    "warning_value": target["warning_value"],
                    "status": status,
                    "sample_count": _sla_sample_count(metric, values),
                    "window_days": window_days,
                    "window_start": window["window_start"],
                    "window_end": window["window_end"],
                }
            )
            if status in ("warn", "breach") and value is not None:
                if _suppression_active_local(suppressions, host["host_id"], f"sla_{metric}", host.get("group_id")):
                    suppressed += 1
                    continue
                alerts.append((target, host, status, value, window_days))

    await db.record_sla_target_statuses(results, evaluated_at)

    alerts_raised = 0
    for target, host, status, value, window_days in alerts:
        try:
            await _raise_sla_alert(target, host, status, value, window_days)
            alerts_raised += 1
        except Exception as exc:
            LOGGER.warning(
                "sla: alert for target %s host %s failed: %s",
                target["id"],
                host["host_id"],
                redact_value(_exc_text(exc)),
            )

    counts = {"met": 0, "warn": 0, "breach": 0, "no_data": 0}
    for res in results:
        counts[res["status"]] += 1
    return {
        "targets": len(targets),
        "evaluated": len(results),
        **counts,
        "alerts": alerts_raised,
        "suppressed": suppressed,
        "evaluated_at": evaluated_at,
    }


async def run_sla_cycle(now: datetime | None = None) -> dict:
    """One SLA pass: roll up the completed hours and days, then evaluate the
    host targets and the targets of topology entities."""
    # Imported here: topology_sla imports this module.
    from netcontrol.routes.topology_sla import evaluate_topology_sla_targets

    rollups = await db.rollup_sla_metrics(now)
    evaluation = await evaluate_sla_targets(now)
    try:
        topology = await evaluate_topology_sla_targets(await db.get_sla_targets(), now)
    except Exception as exc:
        LOGGER.warning("sla: topology targets not evaluated: %s", redact_value(_exc_text(exc)))
        topology = {"targets": 0, "evaluated": 0, "met": 0, "warn": 0, "breach": 0, "no_data": 0, "alerts": 0}
    LOGGER.info(
        "sla: rollup %d hourly / %d daily rows; %d evaluations (%d met, %d warn, %d breach, %d no data), %d alerts",
        rollups["hourly_rows"],
        rollups["daily_rows"],
        evaluation["evaluated"],
        evaluation["met"],
        evaluation["warn"],
        evaluation["breach"],
        evaluation["no_data"],
        evaluation["alerts"],
    )
    if topology["evaluated"]:
        LOGGER.info(
            "sla: %d topology evaluations (%d met, %d warn, %d breach, %d no data), %d alerts",
            topology["evaluated"],
            topology["met"],
            topology["warn"],
            topology["breach"],
            topology["no_data"],
            topology["alerts"],
        )
    return {"rollups": rollups, "evaluation": evaluation, "topology_evaluation": topology}


async def _sla_rollup_loop() -> None:
    """Background loop: SLA rollups + target evaluation every
    ``sla_rollup_interval_seconds`` while monitoring is enabled."""
    delay: float = _SLA_STARTUP_DELAY_SECONDS
    while True:
        try:
            await asyncio.sleep(delay)
            interval = int(
                state.MONITORING_CONFIG.get(
                    "sla_rollup_interval_seconds", state.MONITORING_DEFAULTS["sla_rollup_interval_seconds"]
                )
            )
            delay = interval + random.uniform(0, max(1.0, interval * 0.05))
            if state.MONITORING_CONFIG.get("enabled"):
                await run_sla_cycle()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("sla rollup loop failure: %s", redact_value(_exc_text(exc)))
            delay = 300


# ── Scope helpers ─────────────────────────────────────────────────────────────

_ALERT_NOT_FOUND = "Alert not found"
_TARGET_NOT_FOUND = "Target not found"
_ENTITY_NOT_FOUND = "No such tracked entity"
_MUTE_NOT_FOUND = "Mute not found"


async def _require_alert(request: Request, alert_id: int, *, write: bool = False) -> None:
    """For a scoped caller: 404 unless the alert exists and its host is
    readable, 403 on ``write`` unless writable. Nothing is read for an
    unrestricted caller."""
    if (await request_scope(request)).unrestricted:
        return
    alert = await db.get_monitoring_alert(alert_id)
    await require_object_host(request, alert.get("host_id") if alert else None, write=write, not_found=_ALERT_NOT_FOUND)


async def require_rule_change(request: Request, row: dict | None, changes: dict, *, not_found: str) -> dict:
    """A change to a monitoring rule row (alert rule, suppression, SLA
    target, baseline rule): 404 ``not_found`` when unknown or unreadable,
    403 when not writable, and 403 when ``changes`` moves it to a host or
    group the caller cannot write."""
    row = await require_row(request, MONITORING_RULE.name, row, write=True, not_found=not_found)
    moved = {k: changes[k] for k in ("host_id", "group_id") if k in changes}
    if moved:
        await require_new_row(request, MONITORING_RULE.name, {**row, **moved})
    return row


async def _require_sla_target(request: Request, target_id: int, *, write: bool = False) -> dict:
    """The SLA target; a topology target (no host or group) is hidden from
    a scoped caller like the topology entities it applies to."""
    target = await db.get_sla_target(target_id)
    if target and str(target.get("provider") or "").strip() and (await request_scope(request)).restricted:
        target = None
    return await require_row(request, MONITORING_RULE.name, target, write=write, not_found=_TARGET_NOT_FOUND)


def _topology_key(row: dict) -> tuple[str, int, str, str]:
    return (
        str(row.get("provider") or ""),
        int(row.get("org_ref") or 0),
        str(row.get("entity_type") or ""),
        str(row.get("entity_id") or ""),
    )


async def _topology_keys(request: Request, *, write: bool = False) -> set[tuple[str, int, str, str]] | None:
    """``None`` for an unrestricted caller; else the keys of the tracked
    topology entities matched to an inventory host the caller may read
    (``write``: change). Entities with no inventory host are not in a
    scoped caller's scope."""
    hosts = await readable_host_ids(request, write=write)
    if hosts is None:
        return None
    rows = await db.list_topology_entity_states() if hosts else []
    return {_topology_key(r) for r in rows if r.get("host_id") is not None and int(r["host_id"]) in hosts}


async def _filter_topology_rows(request: Request, rows: list[dict]) -> list[dict]:
    keys = await _topology_keys(request)
    if keys is None:
        return rows
    return [r for r in rows if _topology_key(r) in keys]


# ── Monitoring Routes ─────────────────────────────────────────────────────────


@router.get("/api/monitoring/summary")
@scoped("list")
async def monitoring_summary(request: Request, group_id: int | None = Query(default=None)):
    return await db.get_monitoring_summary(group_id, **await group_filter(request))


@router.get("/api/monitoring/polls")
@scoped("list")
async def monitoring_polls(
    request: Request,
    group_id: int | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=10000),
    include_details: bool = Query(default=False),
):
    # include_details appends the large per-poll blobs (if_details, vpn_details,
    # route_snapshot). Bound that path so a wide ?limit can't serialize thousands
    # of full blobs at once; the lean list view (default) keeps the full range.
    if include_details:
        limit = min(limit, 500)
    return await db.get_latest_monitoring_polls(group_id, limit, include_details, **await group_filter(request))


@router.get("/api/monitoring/polls/{host_id}/history")
@scoped("host")
async def monitoring_poll_history(
    request: Request,
    host_id: int,
    limit: int = Query(default=100, ge=1, le=10000),
    include_details: bool = Query(default=False),
):
    # Same blob gating as /api/monitoring/polls: history tables only need the
    # lean columns; the device-detail page opts in for the latest poll's blobs.
    if include_details:
        limit = min(limit, 500)
    await require_object_host(request, host_id, not_found=HOST_NOT_FOUND)
    return await db.get_monitoring_poll_history(host_id, limit, include_details)


@router.get("/api/monitoring/alerts")
@scoped("list")
async def monitoring_alerts(
    request: Request,
    host_id: int | None = Query(default=None),
    acknowledged: bool | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=10000),
):
    return await db.get_monitoring_alerts(host_id, acknowledged, severity, limit, **await group_filter(request))


@router.post("/api/monitoring/alerts/{alert_id}/acknowledge")
@scoped("alert")
async def acknowledge_alert(alert_id: int, request: Request):
    await _require_alert(request, alert_id, write=True)
    session = _get_session(request)
    user = session["user"] if session else ""
    await db.acknowledge_monitoring_alert(alert_id, user)
    await _audit(
        "monitoring", "alert.acknowledged", user=user, detail=f"alert_id={alert_id}", correlation_id=_corr_id(request)
    )
    return {"ok": True}


@router.get("/api/monitoring/alerts/{alert_id}/correlation")
@scoped("alert")
async def get_alert_correlation(alert_id: int, request: Request):
    """Return deployments and drift events correlated to an alert."""
    alert = await db.get_monitoring_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=_ALERT_NOT_FOUND)
    await require_object_host(request, alert.get("host_id"), not_found=_ALERT_NOT_FOUND)

    alert_time = alert.get("created_at", "")
    host_id = alert.get("host_id")
    window_start = (datetime.fromisoformat(alert_time) - timedelta(minutes=30)).isoformat() if alert_time else None

    related_deployments = (
        await db.get_deployments_for_host_in_range(host_id, window_start, alert_time)
        if host_id and window_start
        else []
    )
    related_drift = (
        await db.get_config_drift_events_in_range([host_id], window_start, alert_time)
        if host_id and window_start
        else []
    )

    return {
        "alert": alert,
        "related_deployments": related_deployments,
        "related_drift_events": related_drift,
    }


@router.get("/api/monitoring/routes/{host_id}")
@scoped("host")
async def monitoring_route_snapshots(request: Request, host_id: int, limit: int = Query(default=50, ge=1, le=10000)):
    await require_object_host(request, host_id, not_found=HOST_NOT_FOUND)
    return await db.get_route_snapshots(host_id, limit)


@router.get("/api/monitoring/hosts/{host_id}/vendor-status")
@scoped("host")
async def monitoring_vendor_status(request: Request, host_id: int):
    """The newest vendor-specific state the poll read from the host (an APC
    UPS's battery, output and identity): ``{"kind": "", "status": {}}`` when
    there is none."""
    await require_object_host(request, host_id, not_found=HOST_NOT_FOUND)
    row = await db.get_host_vendor_status(host_id)
    if not row:
        return {"host_id": host_id, "kind": "", "status": {}, "polled_at": ""}
    return row


@router.post("/api/monitoring/poll-now")
@scoped("hosts")
async def monitoring_poll_now(request: Request):
    """Trigger an immediate monitoring poll across all groups (a caller
    limited by object scope polls the hosts it may change)."""
    session = _get_session(request)
    user = session["user"] if session else ""
    result = await _run_monitoring_poll_once(force=True, host_ids=await readable_host_ids(request, write=True))
    await _audit(
        "monitoring",
        "poll.manual",
        user=user,
        detail=f"hosts={result.get('hosts_polled', 0)} alerts={result.get('alerts_created', 0)}",
        correlation_id=_corr_id(request),
    )
    return result


@router.post("/api/monitoring/poll-now/stream")
@scoped("hosts")
async def monitoring_poll_now_stream(request: Request):
    """Trigger a monitoring poll with SSE progress events (a caller limited
    by object scope polls the hosts it may change)."""
    session = _get_session(request)
    user = session["user"] if session else ""
    allowed_hosts = await readable_host_ids(request, write=True)

    async def _event_generator():
        # Same target building, persistence, and post-processing as the
        # scheduled cycle (_build_poll_targets/_process_poll_result) — this
        # stream previously carried an inline copy that silently drifted
        # (it skipped interface-error metrics and baseline alerting).
        all_hosts = await _build_poll_targets()
        if allowed_hosts is not None:
            all_hosts = [t for t in all_hosts if int(t[0]["id"]) in allowed_hosts]
        alert_rules_cache = await db.get_alert_rules(enabled_only=True)
        suppressions_cache = await db.get_active_alert_suppressions()

        total = len(all_hosts)
        yield f"data: {json.dumps({'type': 'start', 'total_hosts': total})}\n\n"

        if total == 0:
            yield f"data: {json.dumps({'type': 'done', 'hosts_polled': 0, 'alerts_created': 0, 'errors': 0})}\n\n"
            return

        hosts_polled = 0
        alerts_created = 0
        errors = 0
        completed = 0
        max_concurrency = max(
            1, int(state.MONITORING_CONFIG.get("poll_concurrency", state.MONITORING_DEFAULTS["poll_concurrency"]))
        )
        sem = asyncio.Semaphore(max_concurrency)

        poll_timeout = float(state.MONITORING_CONFIG.get("per_host_timeout_seconds", 90))

        async def _poll_one(h, cred, snmp_cfg):
            async with sem:
                # Hard ceiling per device. Without this a host whose SNMP agent
                # stalls mid-walk or whose SSH session connects but never
                # returns a prompt blocks forever, pinning a semaphore slot and
                # freezing the progress bar. Return the host with the result (or
                # the exception) so the caller can name a timed-out device.
                try:
                    res = await asyncio.wait_for(
                        _poll_host_monitoring(h, cred, snmp_cfg),
                        timeout=poll_timeout,
                    )
                    return h, res, None
                except TimeoutError:
                    return h, None, TimeoutError(f"poll exceeded {poll_timeout:.0f}s")
                except Exception as exc:  # noqa: BLE001 - surfaced to client
                    return h, None, exc

        tasks = [asyncio.create_task(_poll_one(h, cred, snmp_cfg)) for h, cred, snmp_cfg in all_hosts]

        try:
            for coro in asyncio.as_completed(tasks):
                try:
                    h, res, err = await coro
                except Exception as exc:  # task itself crashed (no host context)
                    errors += 1
                    completed += 1
                    LOGGER.warning("monitoring: poll exception: %s", redact_value(_exc_text(exc)))
                    yield f"data: {json.dumps({'type': 'host_error', 'completed': completed, 'total_hosts': total, 'hostname': '(unknown)', 'error': 'Poll failed for host.'})}\n\n"
                    continue

                if err is not None:
                    hostname = h.get("hostname", h.get("ip_address", "unknown"))
                    errors += 1
                    completed += 1
                    _poll_backoff_record(h["id"], ok=False)
                    LOGGER.warning("monitoring: poll failed for %s: %s", hostname, redact_value(_exc_text(err)))
                    detail = (
                        "Timed out - device unresponsive." if isinstance(err, TimeoutError) else "Poll failed for host."
                    )
                    yield f"data: {json.dumps({'type': 'host_error', 'completed': completed, 'total_hosts': total, 'hostname': hostname, 'error': detail})}\n\n"
                    continue

                hostname = h.get("hostname", h.get("ip_address", "unknown"))
                hosts_polled += 1
                completed += 1
                _poll_backoff_record(h["id"], ok=True)

                try:
                    host_alerts = await _process_poll_result(h, res, alert_rules_cache, suppressions=suppressions_cache)
                except Exception as exc:  # one host's persistence must not kill the stream
                    host_alerts = 0
                    LOGGER.warning("monitoring: post-process error for %s: %s", hostname, redact_value(_exc_text(exc)))
                alerts_created += host_alerts

                status_icon = "ok" if res["poll_status"] == "ok" else "error"
                yield f"data: {json.dumps({'type': 'host_done', 'completed': completed, 'total_hosts': total, 'hostname': hostname, 'status': status_icon, 'cpu': res.get('cpu_percent'), 'memory': res.get('memory_percent'), 'alerts': host_alerts})}\n\n"
        finally:
            # Client disconnect lands GeneratorExit at a yield above: cancel
            # the outstanding polls instead of letting the whole fleet sweep
            # run to completion with nobody consuming (or persisting) it.
            for t in tasks:
                if not t.done():
                    t.cancel()

        await _run_retention_cleanup_throttled()

        await _audit("monitoring", "poll.manual", user=user, detail=f"hosts={hosts_polled} alerts={alerts_created}")

        yield f"data: {json.dumps({'type': 'done', 'hosts_polled': hosts_polled, 'alerts_created': alerts_created, 'errors': errors})}\n\n"

    return StreamingResponse(_event_generator(), media_type="text/event-stream")


# ── Admin Monitoring Routes ───────────────────────────────────────────────────


@admin_router.get("/api/admin/monitoring")
async def admin_get_monitoring_config():
    return state.MONITORING_CONFIG


@admin_router.put("/api/admin/monitoring")
async def admin_update_monitoring_config(body: dict, request: Request):
    state.MONITORING_CONFIG = state._sanitize_monitoring_config(body)
    await db.set_auth_setting("monitoring", state.MONITORING_CONFIG)
    session = _get_session(request)
    await _audit(
        "monitoring",
        "config.updated",
        user=session["user"] if session else "",
        detail=f"enabled={state.MONITORING_CONFIG['enabled']} interval={state.MONITORING_CONFIG['interval_seconds']}s",
        correlation_id=_corr_id(request),
    )
    return state.MONITORING_CONFIG


@admin_router.post("/api/admin/monitoring/run-now")
async def admin_run_monitoring_now(request: Request):
    result = await _run_monitoring_poll_once(force=True)
    session = _get_session(request)
    await _audit(
        "monitoring",
        "poll.admin_triggered",
        user=session["user"] if session else "",
        detail=f"hosts={result.get('hosts_polled', 0)}",
        correlation_id=_corr_id(request),
    )
    return result


@admin_router.post("/api/sla/evaluate")
async def admin_evaluate_sla(request: Request):
    """Run an SLA pass now: roll up the completed hours and days, then
    evaluate every enabled target (whether or not monitoring is enabled)."""
    result = await run_sla_cycle()
    session = _get_session(request)
    evaluation = result["evaluation"]
    await _audit(
        "sla",
        "targets.evaluated",
        user=session["user"] if session else "",
        detail=(
            f"evaluated={evaluation['evaluated']} met={evaluation['met']} warn={evaluation['warn']} "
            f"breach={evaluation['breach']} alerts={evaluation['alerts']}"
        ),
        correlation_id=_corr_id(request),
    )
    return result


# ── Alert Rules CRUD ─────────────────────────────────────────────────────────


def _normalize_channel_ids(raw) -> str:
    """Store a rule's notification-channel assignment as a JSON list string.

    Accepts a list, a comma-separated string, or None; always returns a stable
    JSON-encoded list (``"[]"`` when empty) for the ``alert_rules.channel_ids``
    TEXT column.
    """
    if raw is None:
        return "[]"
    if isinstance(raw, str):
        raw = [t.strip() for t in raw.split(",") if t.strip()]
    if not isinstance(raw, list):
        return "[]"
    return json.dumps([str(x).strip() for x in raw if str(x).strip()])


_ALERT_RULE_OPERATORS = {">", ">=", "<", "<=", "==", "!="}


def _validate_alert_rule_fields(body: dict) -> dict:
    """Validated ``name`` / ``metric`` / ``operator`` / numeric fields present
    in ``body`` (HTTP 400 for a bad value). Shared by rule create and update."""
    out: dict = {}
    try:
        if "value" in body:
            out["value"] = float(body["value"])
        for key in ("consecutive", "cooldown_minutes", "escalate_after_minutes"):
            if key in body:
                out[key] = int(body[key])
    except ValueError, TypeError:
        raise HTTPException(status_code=400, detail="Numeric fields must be valid numbers")
    if "name" in body:
        out["name"] = (body["name"] or "").strip()
        if not out["name"]:
            raise HTTPException(status_code=400, detail="Rule name is required")
    if "metric" in body:
        out["metric"] = (body["metric"] or "").strip()
        if not out["metric"]:
            raise HTTPException(status_code=400, detail="Metric is required")
    if "operator" in body:
        if body["operator"] not in _ALERT_RULE_OPERATORS:
            raise HTTPException(status_code=400, detail=f"Operator must be one of {_ALERT_RULE_OPERATORS}")
        out["operator"] = body["operator"]
    return out


@router.get("/api/monitoring/rules")
@scoped("list")
async def list_alert_rules(request: Request):
    return await filter_rows(MONITORING_RULE.name, await db.get_alert_rules(), request)


@router.post("/api/monitoring/rules", status_code=201)
@scoped("create")
async def create_alert_rule_endpoint(body: dict, request: Request):
    await require_new_row(
        request, MONITORING_RULE.name, {"host_id": body.get("host_id"), "group_id": body.get("group_id")}
    )
    session = _get_session(request)
    user = session["user"] if session else ""
    fields = _validate_alert_rule_fields(
        {
            "name": "",
            "metric": "",
            "operator": ">=",
            "value": 0,
            "consecutive": 1,
            "cooldown_minutes": 15,
            "escalate_after_minutes": 0,
            **body,
        }
    )
    rule_id = await db.create_alert_rule(
        name=fields["name"],
        metric=fields["metric"],
        rule_type=body.get("rule_type", "threshold"),
        operator=fields["operator"],
        value=fields["value"],
        severity=body.get("severity", "warning"),
        consecutive=fields["consecutive"],
        cooldown_minutes=fields["cooldown_minutes"],
        escalate_after_minutes=fields["escalate_after_minutes"],
        escalate_to=body.get("escalate_to", "critical"),
        host_id=body.get("host_id"),
        group_id=body.get("group_id"),
        description=body.get("description", ""),
        created_by=user,
        channel_ids=_normalize_channel_ids(body.get("channel_ids")),
    )
    await _audit(
        "monitoring",
        "rule.created",
        user=user,
        detail=f"rule_id={rule_id} name='{body.get('name', '')}' metric={body.get('metric', '')}",
        correlation_id=_corr_id(request),
    )
    return {"id": rule_id}


@router.get("/api/monitoring/rules/{rule_id}")
@scoped("rule")
async def get_alert_rule_endpoint(rule_id: int, request: Request):
    return await require_row(
        request, MONITORING_RULE.name, await db.get_alert_rule(rule_id), not_found="Rule not found"
    )


@router.put("/api/monitoring/rules/{rule_id}")
@scoped("rule")
async def update_alert_rule_endpoint(rule_id: int, body: dict, request: Request):
    await require_rule_change(request, await db.get_alert_rule(rule_id), body, not_found="Rule not found")
    if "channel_ids" in body:
        body["channel_ids"] = _normalize_channel_ids(body.get("channel_ids"))
    await db.update_alert_rule(rule_id, **{**body, **_validate_alert_rule_fields(body)})
    session = _get_session(request)
    await _audit(
        "monitoring",
        "rule.updated",
        user=session["user"] if session else "",
        detail=f"rule_id={rule_id}",
        correlation_id=_corr_id(request),
    )
    return await db.get_alert_rule(rule_id)


@router.delete("/api/monitoring/rules/{rule_id}")
@scoped("rule")
async def delete_alert_rule_endpoint(rule_id: int, request: Request):
    rule = await require_rule_change(request, await db.get_alert_rule(rule_id), {}, not_found="Rule not found")
    await db.delete_alert_rule(rule_id)
    session = _get_session(request)
    await _audit(
        "monitoring",
        "rule.deleted",
        user=session["user"] if session else "",
        detail=f"rule_id={rule_id} name='{rule.get('name', '')}'",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Alert Suppressions CRUD ──────────────────────────────────────────────────


@router.get("/api/monitoring/suppressions")
@scoped("list")
async def list_alert_suppressions(request: Request, active_only: bool = Query(default=False)):
    return await filter_rows(MONITORING_RULE.name, await db.get_alert_suppressions(active_only), request)


@router.post("/api/monitoring/suppressions", status_code=201)
@scoped("create")
async def create_alert_suppression_endpoint(body: dict, request: Request):
    await require_new_row(
        request, MONITORING_RULE.name, {"host_id": body.get("host_id"), "group_id": body.get("group_id")}
    )
    session = _get_session(request)
    user = session["user"] if session else ""
    if not body.get("ends_at"):
        raise HTTPException(status_code=400, detail="ends_at is required")
    # A window that ends at or before its start never suppresses anything.
    # Without starts_at the window starts now, and an already-ended window is
    # still accepted (it is listed as expired).
    if body.get("starts_at"):
        try:
            window_ok = _parse_iso(str(body["ends_at"])) > _parse_iso(str(body["starts_at"]))
        except ValueError:
            raise HTTPException(status_code=400, detail="starts_at and ends_at must be valid timestamps")
        if not window_ok:
            raise HTTPException(status_code=400, detail="ends_at must be after starts_at")
    sup_id = await db.create_alert_suppression(
        name=body.get("name", ""),
        ends_at=body["ends_at"],
        host_id=body.get("host_id"),
        group_id=body.get("group_id"),
        metric=body.get("metric", ""),
        reason=body.get("reason", ""),
        starts_at=body.get("starts_at", ""),
        created_by=user,
    )
    await _audit(
        "monitoring",
        "suppression.created",
        user=user,
        detail=f"suppression_id={sup_id} name='{body.get('name', '')}' ends_at={body['ends_at']}",
        correlation_id=_corr_id(request),
    )
    return {"id": sup_id}


@router.delete("/api/monitoring/suppressions/{suppression_id}")
@scoped("rule")
async def delete_alert_suppression_endpoint(suppression_id: int, request: Request):
    if (await request_scope(request)).restricted:
        found = next((s for s in await db.get_alert_suppressions() if int(s["id"]) == suppression_id), None)
        await require_rule_change(request, found, {}, not_found="Suppression not found")
    await db.delete_alert_suppression(suppression_id)
    session = _get_session(request)
    await _audit(
        "monitoring",
        "suppression.deleted",
        user=session["user"] if session else "",
        detail=f"suppression_id={suppression_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Bulk Alert Operations ────────────────────────────────────────────────────


@router.post("/api/monitoring/alerts/bulk-acknowledge")
@scoped("hosts")
async def bulk_acknowledge_alerts_endpoint(body: dict, request: Request):
    """Acknowledge many alerts; a caller limited by object scope acknowledges
    only the alerts of hosts it may change (the others are skipped and not
    counted)."""
    alert_ids = body.get("alert_ids", [])
    if not alert_ids:
        raise HTTPException(status_code=400, detail="alert_ids required")
    if not isinstance(alert_ids, list) or len(alert_ids) > 1000:
        raise HTTPException(status_code=400, detail="alert_ids must be a list of at most 1000 IDs")
    session = _get_session(request)
    user = session["user"] if session else ""
    count = await db.bulk_acknowledge_alerts(alert_ids, user, host_ids=await readable_host_ids(request, write=True))
    await _audit(
        "monitoring",
        "alerts.bulk_acknowledged",
        user=user,
        detail=f"count={count} ids={alert_ids[:10]}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "acknowledged": count}


# Topology source types and tracked entity types (query parameter patterns).
_TOPOLOGY_PROVIDER_RE = r"^(meraki|cato|fmc|panorama|appgate|opnsense|aws|azure|gcp)$"
_TOPOLOGY_ENTITY_RE = rf"^({'|'.join(TOPOLOGY_ENTITY_TYPES)})$"


# ── SLA Dashboard Routes ─────────────────────────────────────────────────────


@router.get("/api/sla/summary")
@scoped("list")
async def sla_summary(
    request: Request,
    group_id: int | None = Query(default=None),
    days: int = Query(default=30, ge=1, le=365),
):
    return await db.get_sla_summary(group_id, days, **await group_filter(request))


@router.get("/api/sla/compliance")
@scoped("list")
async def sla_compliance(
    request: Request,
    group_id: int | None = Query(default=None),
    host_id: int | None = Query(default=None),
    target_id: int | None = Query(default=None),
    scope: Literal["hosts", "topology"] = Query(default="hosts"),
    provider: str | None = Query(default=None, pattern=_TOPOLOGY_PROVIDER_RE),
    org_ref: int | None = Query(default=None),
    entity_type: str | None = Query(default=None, pattern=_TOPOLOGY_ENTITY_RE),
    entity_id: str | None = Query(default=None, max_length=500),
):
    """Latest server-side evaluation of every SLA target for every host it
    applies to (``group_id`` includes the group's sub-groups). With
    ``scope=topology``: of every topology target for every tracked entity it
    applies to (filtered by ``provider``, ``org_ref``, ``entity_type``,
    ``entity_id``), worst first."""
    if scope == "topology":
        rows = await db.get_topology_sla_compliance(
            provider=provider, org_ref=org_ref, entity_type=entity_type, entity_id=entity_id, target_id=target_id
        )
        return await _filter_topology_rows(request, rows)
    return await db.get_sla_compliance(
        group_id=group_id, host_id=host_id, target_id=target_id, **await group_filter(request)
    )


@router.get("/api/sla/compliance/history")
@scoped("list")
async def sla_compliance_history(
    request: Request,
    target_id: int | None = Query(default=None),
    host_id: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    scope: Literal["hosts", "topology"] = Query(default="hosts"),
    provider: str | None = Query(default=None, pattern=_TOPOLOGY_PROVIDER_RE),
    org_ref: int | None = Query(default=None),
    entity_id: str | None = Query(default=None, max_length=500),
):
    """SLA status changes, newest first (``scope=topology``: of the targets
    of topology entities)."""
    if scope == "topology":
        rows = await db.get_topology_sla_compliance_history(
            target_id=target_id, provider=provider, org_ref=org_ref, entity_id=entity_id, limit=limit
        )
        return await _filter_topology_rows(request, rows)
    return await db.get_sla_compliance_history(
        target_id=target_id, host_id=host_id, limit=limit, **await group_filter(request)
    )


@router.get("/api/sla/host/{host_id}")
@scoped("host")
async def sla_host_detail(request: Request, host_id: int, days: int = Query(default=30, ge=1, le=365)):
    await require_object_host(request, host_id, not_found=HOST_NOT_FOUND)
    return await db.get_sla_host_detail(host_id, days)


@router.get("/api/sla/targets")
@scoped("list")
async def sla_targets_list(
    request: Request,
    host_id: int | None = Query(default=None),
    group_id: int | None = Query(default=None),
):
    targets = await db.get_sla_targets(host_id, group_id)
    if (await request_scope(request)).unrestricted:
        return targets
    # Topology targets apply to integration entities, not inventory hosts.
    targets = [t for t in targets if not str(t.get("provider") or "").strip()]
    return await filter_rows(MONITORING_RULE.name, targets, request)


def _validate_sla_target_fields(body: dict) -> dict:
    """Validated ``metric`` / ``window_days`` / threshold fields present in
    ``body`` (HTTP 400 for a bad value)."""
    out: dict = {}
    if "metric" in body:
        if body["metric"] not in _SLA_VALUE_KEYS:
            raise HTTPException(status_code=400, detail=f"metric must be one of: {', '.join(_SLA_VALUE_KEYS)}")
        out["metric"] = body["metric"]
    for key in ("target_value", "warning_value"):
        if key in body:
            try:
                out[key] = float(body[key])
            except ValueError, TypeError:
                raise HTTPException(status_code=400, detail="target_value and warning_value must be valid numbers")
    if "window_days" in body and body["window_days"] is not None:
        try:
            window_days = int(body["window_days"])
        except ValueError, TypeError:
            window_days = 0
        if not 1 <= window_days <= _SLA_WINDOW_DAYS_MAX:
            raise HTTPException(
                status_code=400, detail=f"window_days must be a whole number from 1 to {_SLA_WINDOW_DAYS_MAX}"
            )
        out["window_days"] = window_days
    out.update(_validate_sla_target_scope(body))
    return out


def _validate_sla_target_scope(body: dict) -> dict:
    """The topology scope fields present in ``body``: ``provider`` (a target
    of topology entities instead of hosts; ``""`` for hosts), ``org_ref``,
    ``entity_type`` and ``entity_id`` (HTTP 400 for a bad value, or for a
    provider combined with a host or group)."""
    out: dict = {}
    provider = str(body.get("provider") or "").strip()
    if "provider" in body:
        if provider and not re.fullmatch(_TOPOLOGY_PROVIDER_RE, provider):
            raise HTTPException(status_code=400, detail="provider must be a topology source type (e.g. opnsense)")
        out["provider"] = provider
    if provider and (body.get("host_id") is not None or body.get("group_id") is not None):
        raise HTTPException(status_code=400, detail="A target of topology entities has no host_id or group_id")
    if body.get("org_ref") is not None:
        try:
            out["org_ref"] = int(body["org_ref"])
        except ValueError, TypeError:
            raise HTTPException(status_code=400, detail="org_ref must be a whole number")
    if "entity_type" in body:
        entity_type = str(body.get("entity_type") or "").strip()
        if entity_type and not re.fullmatch(_TOPOLOGY_ENTITY_RE, entity_type):
            raise HTTPException(status_code=400, detail="entity_type is not a tracked entity type")
        out["entity_type"] = entity_type
    if "entity_id" in body:
        entity_id = str(body.get("entity_id") or "").strip()
        if len(entity_id) > 500:
            raise HTTPException(status_code=400, detail="entity_id is too long")
        out["entity_id"] = entity_id
    return out


@router.post("/api/sla/targets", status_code=201)
@scoped("create")
async def sla_target_create(body: dict, request: Request):
    await require_new_row(
        request, MONITORING_RULE.name, {"host_id": body.get("host_id"), "group_id": body.get("group_id")}
    )
    session = _get_session(request)
    user = session["user"] if session else ""
    if not body.get("name") or not body.get("metric"):
        raise HTTPException(status_code=400, detail="name and metric required")
    fields = _validate_sla_target_fields({"target_value": 99.9, "warning_value": 99.0, "window_days": 30, **body})
    target_id = await db.create_sla_target(
        name=body["name"],
        metric=fields["metric"],
        target_value=fields["target_value"],
        warning_value=fields["warning_value"],
        host_id=body.get("host_id"),
        group_id=body.get("group_id"),
        created_by=user,
        window_days=fields["window_days"],
        provider=fields.get("provider", ""),
        org_ref=fields.get("org_ref"),
        entity_type=fields.get("entity_type", ""),
        entity_id=fields.get("entity_id", ""),
    )
    await _audit(
        "sla",
        "target.created",
        user=user,
        detail=f"target_id={target_id} name='{body['name']}' metric={body['metric']}",
        correlation_id=_corr_id(request),
    )
    return {"id": target_id}


@router.put("/api/sla/targets/{target_id}")
@scoped("rule")
async def sla_target_update(target_id: int, body: dict, request: Request):
    target = await require_rule_change(
        request, await _require_sla_target(request, target_id), body, not_found=_TARGET_NOT_FOUND
    )
    fields = _validate_sla_target_fields(body)
    merged = {**target, **body, **fields}
    if str(merged.get("provider") or "").strip() and (
        merged.get("host_id") is not None or merged.get("group_id") is not None
    ):
        raise HTTPException(status_code=400, detail="A target of topology entities has no host_id or group_id")
    await db.update_sla_target(target_id, **{**body, **fields})
    session = _get_session(request)
    await _audit(
        "sla",
        "target.updated",
        user=session["user"] if session else "",
        detail=f"target_id={target_id}",
        correlation_id=_corr_id(request),
    )
    return await db.get_sla_target(target_id)


@router.delete("/api/sla/targets/{target_id}")
@scoped("rule")
async def sla_target_delete(target_id: int, request: Request):
    target = await _require_sla_target(request, target_id, write=True)
    await db.delete_sla_target(target_id)
    session = _get_session(request)
    await _audit(
        "sla",
        "target.deleted",
        user=session["user"] if session else "",
        detail=f"target_id={target_id} name='{target.get('name', '')}'",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Availability Tracking Routes ─────────────────────────────────────────────


@router.get("/api/availability/summary")
@scoped("list")
async def availability_summary_api(
    request: Request,
    group_id: int | None = Query(default=None),
    days: int = Query(default=30),
):
    return await db.get_availability_summary(group_id, days, **await group_filter(request))


@router.get("/api/availability/transitions")
@scoped("list")
async def availability_transitions_api(
    request: Request,
    host_id: int | None = Query(default=None),
    group_id: int | None = Query(default=None),
    entity_type: str | None = Query(default=None),
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    days: int | None = Query(default=None, ge=1, le=365),
    limit: int = Query(default=500, ge=1, le=10000),
):
    return {
        "transitions": await db.get_availability_transitions(
            host_id=host_id,
            entity_type=entity_type,
            start=start,
            end=end,
            limit=limit,
            group_id=group_id,
            days=days,
            **await group_filter(request),
        )
    }


@router.get("/api/availability/outages")
@scoped("list")
async def availability_outages_api(
    request: Request,
    host_id: int | None = Query(default=None),
    group_id: int | None = Query(default=None),
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=200, ge=1, le=10000),
):
    return {
        "outages": await db.get_outage_history(
            host_id=host_id,
            group_id=group_id,
            days=days,
            limit=limit,
            **await group_filter(request),
        )
    }


@router.get("/api/availability/topology/summary")
@scoped("list")
async def topology_availability_summary_api(
    request: Request,
    provider: str | None = Query(default=None, pattern=_TOPOLOGY_PROVIDER_RE),
    org_ref: int | None = Query(default=None),
    entity_type: str | None = Query(default=None, pattern=_TOPOLOGY_ENTITY_RE),
    days: int = Query(default=30, ge=1, le=365),
):
    """Uptime of the devices, sites, uplinks, tunnels, VPN connections,
    circuits, peerings and links that integrations collect. Each entity also
    carries the window means of the latency, jitter and loss its vendor
    reports (``null`` when none: only OPNsense gateways today), of its
    traffic in / out in bits per second (``avg_in_bps`` / ``avg_out_bps``,
    ``null`` when none: OPNsense tunnels and OpenVPN servers today) and
    ``sla_status``, the worst latest status of the SLA targets that apply
    to it (``null`` when none)."""
    summary = await db.get_topology_availability_summary(
        provider, org_ref, entity_type, days, host_ids=await readable_host_ids(request)
    )
    metrics = await db.get_topology_entity_metric_values(
        days, provider=provider, org_ref=org_ref, entity_type=entity_type
    )
    statuses: dict[tuple, list[str]] = {}
    for row in await db.get_topology_sla_compliance(provider=provider, org_ref=org_ref, entity_type=entity_type):
        key = (row["provider"], int(row["org_ref"]), row["entity_type"], row["entity_id"])
        statuses.setdefault(key, []).append(row["status"])
    rank = {"breach": 3, "warn": 2, "met": 1, "no_data": 0}
    for entity in summary["entities"]:
        key = (entity["provider"], int(entity["org_ref"]), entity["entity_type"], entity["entity_id"])
        values = metrics["entities"].get(key) or {}
        for field in ("avg_latency_ms", "jitter_ms", "avg_packet_loss_pct", "avg_in_bps", "avg_out_bps"):
            entity[field] = values.get(field)
        found = statuses.get(key)
        entity["sla_status"] = max(found, key=lambda s: rank.get(s, 0)) if found else None
    return summary


@router.get("/api/availability/topology/metrics")
@scoped("entity")
async def topology_availability_metrics_api(
    request: Request,
    provider: str = Query(pattern=_TOPOLOGY_PROVIDER_RE),
    org_ref: int = Query(),
    entity_type: str = Query(pattern=_TOPOLOGY_ENTITY_RE),
    entity_id: str = Query(min_length=1, max_length=500),
    days: int = Query(default=7, ge=1, le=365),
    limit: int = Query(default=5000, ge=1, le=50000),
):
    """The latency, jitter, loss and traffic history of one tracked entity
    (an OPNsense gateway uplink; an OPNsense tunnel or OpenVPN server for
    traffic, ``in_bps`` / ``out_bps``): the raw samples still retained, one
    row per day from the daily rollups (which outlive the raw retention),
    and the window means."""
    keys = await _topology_keys(request)
    if keys is not None and (provider, org_ref, entity_type, entity_id) not in keys:
        raise HTTPException(status_code=404, detail=_ENTITY_NOT_FOUND)
    return await db.get_topology_entity_metric_history(provider, org_ref, entity_type, entity_id, days, limit=limit)


@router.get("/api/availability/topology/transitions")
@scoped("list")
async def topology_availability_transitions_api(
    request: Request,
    provider: str | None = Query(default=None, pattern=_TOPOLOGY_PROVIDER_RE),
    org_ref: int | None = Query(default=None),
    entity_type: str | None = Query(default=None, pattern=_TOPOLOGY_ENTITY_RE),
    entity_id: str | None = Query(default=None, max_length=500),
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=500, ge=1, le=10000),
):
    return {
        "transitions": await db.get_topology_transitions(
            provider=provider,
            org_ref=org_ref,
            entity_type=entity_type,
            entity_id=entity_id,
            days=days,
            limit=limit,
            host_ids=await readable_host_ids(request),
        )
    }


@router.get("/api/availability/topology/outages")
@scoped("list")
async def topology_availability_outages_api(
    request: Request,
    provider: str | None = Query(default=None, pattern=_TOPOLOGY_PROVIDER_RE),
    org_ref: int | None = Query(default=None),
    entity_type: str | None = Query(default=None, pattern=_TOPOLOGY_ENTITY_RE),
    entity_id: str | None = Query(default=None, max_length=500),
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=200, ge=1, le=10000),
):
    return {
        "outages": await db.get_topology_outages(
            provider=provider,
            org_ref=org_ref,
            entity_type=entity_type,
            entity_id=entity_id,
            days=days,
            limit=limit,
            host_ids=await readable_host_ids(request),
        )
    }


# Mutes of topology entities: same gate as acknowledging an alert.
_MUTE_REASON_MAX = 500
_TOPOLOGY_ENTITY_OR_EMPTY_RE = _TOPOLOGY_ENTITY_RE.replace("^(", "^(|", 1)


class TopologyMuteCreate(BaseModel):
    provider: str = Field(pattern=_TOPOLOGY_PROVIDER_RE)
    org_ref: int
    scope: Literal["entity", "site"]
    entity_type: str = Field(default="", pattern=_TOPOLOGY_ENTITY_OR_EMPTY_RE)
    entity_id: str = Field(default="", max_length=500)
    site: str = Field(default="", max_length=200)
    reason: str = ""


def _mute_audit_detail(mute: dict) -> str:
    # The reason is free text: kept out of the audit detail.
    target = mute["entity_id"] or mute["site"]
    return f"{mute['provider']}:{mute['org_ref']} {mute['scope']} {mute['entity_type']}:{target}"


async def _require_mute_entity(request: Request, mute: dict, *, not_found: str) -> None:
    """For a scoped caller: a mute of one entity matched to an inventory
    host it may read (else 404 ``not_found``) and change (else 403); a site
    mute covers entities beyond any inventory group and is refused."""
    keys = await _topology_keys(request)
    if keys is None:
        return
    if mute.get("scope") != "entity":
        await refuse_scoped(request)
    key = _topology_key(mute)
    if key not in keys:
        raise HTTPException(status_code=404, detail=not_found)
    if key not in (await _topology_keys(request, write=True) or set()):
        raise HTTPException(status_code=403, detail=READ_ONLY_DETAIL)


@router.get("/api/availability/topology/mutes")
@scoped("list")
async def list_topology_mutes_api(request: Request):
    mutes = await db.list_topology_mutes()
    if (await request_scope(request)).restricted:
        mutes = [m for m in await _filter_topology_rows(request, mutes) if m.get("scope") == "entity"]
    return {"mutes": mutes}


@router.post("/api/availability/topology/mutes", status_code=201)
@scoped("entity")
async def create_topology_mute_api(body: TopologyMuteCreate, request: Request):
    """Mute one tracked entity, or every entity at one site, of one source.
    Its open alerts are acknowledged as ``muted``."""
    await _require_mute_entity(request, body.model_dump(), not_found=_ENTITY_NOT_FOUND)
    reason = body.reason.strip()
    if not 1 <= len(reason) <= _MUTE_REASON_MAX:
        raise HTTPException(status_code=400, detail=f"A reason of 1 to {_MUTE_REASON_MAX} characters is required")
    if body.scope == "entity":
        found = bool(body.entity_type and body.entity_id) and bool(
            await db.list_topology_entity_states(
                body.provider, body.org_ref, body.entity_type, entity_id=body.entity_id
            )
        )
        if not found:
            raise HTTPException(status_code=404, detail="No such tracked entity")
    else:
        site = body.site.strip()
        rows = await db.list_topology_entity_states(body.provider, body.org_ref) if site else []
        if not any(str(r.get("site") or "") == site for r in rows):
            raise HTTPException(status_code=404, detail="No tracked entity is at that site")
    mute = await db.create_topology_mute(
        body.provider,
        body.org_ref,
        body.scope,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        site=body.site.strip(),
        reason=reason,
        created_by=_session_user(request),
    )
    acknowledged = await topology_tracking.mute_entities(mute)
    await _audit(
        "monitoring",
        "topology.muted",
        user=_session_user(request),
        detail=_mute_audit_detail(mute),
        correlation_id=_corr_id(request),
    )
    return {"mute": mute, "acknowledged": acknowledged}


@router.delete("/api/availability/topology/mutes/{mute_id}")
@scoped("entity")
async def delete_topology_mute_api(mute_id: int, request: Request):
    """Unmute. Nothing is raised retroactively: an alert swallowed while
    muted counts as raised."""
    mute = await db.get_topology_mute(mute_id)
    if mute is not None and (await request_scope(request)).restricted:
        if mute.get("scope") != "entity":
            mute = None
        else:
            await _require_mute_entity(request, mute, not_found=_MUTE_NOT_FOUND)
    if mute is None or not await db.delete_topology_mute(mute_id):
        raise HTTPException(status_code=404, detail=_MUTE_NOT_FOUND)
    await _audit(
        "monitoring",
        "topology.unmuted",
        user=_session_user(request),
        detail=_mute_audit_detail(mute),
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Per-Port Utilization Routes ──────────────────────────────────────────────


@router.get("/api/interfaces/{host_id}/summary")
@scoped("host")
async def interface_utilization_summary_api(
    request: Request,
    host_id: int,
    days: int = Query(default=1, ge=1, le=365),
):
    await require_object_host(request, host_id, not_found=HOST_NOT_FOUND)
    return {
        "host_id": host_id,
        "interfaces": await db.get_interface_utilization_summary(host_id, days),
    }


@router.get("/api/interfaces/{host_id}/port/{if_index}")
@scoped("host")
async def port_detail_api(
    request: Request,
    host_id: int,
    if_index: int,
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    limit: int = Query(default=5000, ge=1, le=50000),
):
    await require_object_host(request, host_id, not_found=HOST_NOT_FOUND)
    return await db.get_port_detail_ts(host_id, if_index, start, end, limit)
