"""
monitoring.py -- Real-time device monitoring, alerting, SLA dashboards,
and background poll/escalation loops.
"""

import asyncio
import hashlib
import json
import time

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

import netcontrol.routes.state as state
from netcontrol.routes.metrics_engine import (
    emit_metric_samples_from_poll,
    run_retention_cleanup as metrics_retention_cleanup,
    store_interface_ts_from_poll,
)
from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.routes.snmp import PYSMNP_AVAILABLE, _snmp_walk
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

router = APIRouter()
admin_router = APIRouter()
LOGGER = configure_logging("plexus.monitoring")

# ── Late-binding auth dependencies (injected by app.py) ──────────────────────

_require_auth = None
_require_feature = None
_require_admin = None


def init_monitoring(require_auth, require_feature, require_admin):
    global _require_auth, _require_feature, _require_admin
    _require_auth = require_auth
    _require_feature = require_feature
    _require_admin = require_admin


# ── Helpers ───────────────────────────────────────────────────────────────────


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
    }

    # ── Measure response time via ICMP-like TCP connect ──
    poll_start = time.monotonic()

    # ── SNMP polling for CPU, memory, interfaces ──
    if PYSMNP_AVAILABLE and snmp_cfg.get("enabled"):
        try:
            from netcontrol.routes.metrics_engine import resolve_oids_for_device
            def _walk(oid):
                return _snmp_walk(host["ip_address"], 5.0, snmp_cfg, oid)

            # Resolve vendor-specific OIDs (DB overrides → built-in map → fallback)
            device_type = host.get("device_type", "cisco_ios")
            oid_map = await resolve_oids_for_device(device_type)
            cpu_oid = oid_map.get("cpu_oid", "1.3.6.1.4.1.9.9.109.1.1.1.1.8")
            cpu_old_oid = "1.3.6.1.4.1.9.2.1.58.0"               # avgBusy5 (Cisco legacy fallback)
            mem_used_oid = oid_map.get("mem_used_oid", "1.3.6.1.4.1.9.9.48.1.1.1.5")
            mem_free_oid = oid_map.get("mem_free_oid", "1.3.6.1.4.1.9.9.48.1.1.1.6")
            mem_total_oid = oid_map.get("mem_total_oid", "")
            uptime_oid = oid_map.get("uptime_oid", "1.3.6.1.2.1.1.3")

            # Interface OIDs are standard MIB-II / IF-MIB — vendor-independent
            if_oper_status_oid = "1.3.6.1.2.1.2.2.1.8"           # ifOperStatus
            if_admin_status_oid = "1.3.6.1.2.1.2.2.1.7"          # ifAdminStatus
            if_name_oid = "1.3.6.1.2.1.31.1.1.1.1"               # ifName
            if_descr_oid = "1.3.6.1.2.1.2.2.1.2"                 # ifDescr
            if_high_speed_oid = "1.3.6.1.2.1.31.1.1.1.15"        # ifHighSpeed
            if_hc_in_oid = "1.3.6.1.2.1.31.1.1.1.6"              # ifHCInOctets
            if_hc_out_oid = "1.3.6.1.2.1.31.1.1.1.10"            # ifHCOutOctets

            # Build walk list — skip empty OIDs
            async def _empty_walk():
                return {}

            walk_targets = [
                _walk(cpu_oid) if cpu_oid else _empty_walk(),
                _walk(cpu_old_oid),
                _walk(mem_used_oid) if mem_used_oid else _empty_walk(),
                _walk(mem_free_oid) if mem_free_oid else _empty_walk(),
                _walk(if_oper_status_oid), _walk(if_admin_status_oid),
                _walk(if_name_oid), _walk(if_descr_oid), _walk(if_high_speed_oid),
                _walk(if_hc_in_oid), _walk(if_hc_out_oid),
                _walk(uptime_oid),
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
            mem_total_vals = walk_results[12] if len(walk_results) > 12 else {}

            # CPU
            if cpu_vals:
                cpu_val = next(iter(cpu_vals.values()), None)
                if cpu_val is not None:
                    try:
                        result["cpu_percent"] = float(int(cpu_val))
                    except (ValueError, TypeError):
                        pass
            elif cpu_old_vals:
                cpu_val = next(iter(cpu_old_vals.values()), None)
                if cpu_val is not None:
                    try:
                        result["cpu_percent"] = float(int(cpu_val))
                    except (ValueError, TypeError):
                        pass

            # Memory — supports two patterns:
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
                except (ValueError, TypeError, StopIteration):
                    pass
            elif mem_used_vals and mem_total_vals:
                try:
                    used = int(next(iter(mem_used_vals.values())))
                    total = int(next(iter(mem_total_vals.values())))
                    if total > 0:
                        result["memory_used_mb"] = round(used / 1048576, 1)
                        result["memory_total_mb"] = round(total / 1048576, 1)
                        result["memory_percent"] = round(used / total * 100, 1)
                except (ValueError, TypeError, StopIteration):
                    pass
            elif mem_used_vals:
                # Fortinet fgSysMemUsage returns usage as a percentage directly
                try:
                    pct = float(int(next(iter(mem_used_vals.values()))))
                    if 0 <= pct <= 100:
                        result["memory_percent"] = pct
                except (ValueError, TypeError, StopIteration):
                    pass

            # Uptime
            if uptime_vals:
                try:
                    ticks = int(next(iter(uptime_vals.values())))
                    result["uptime_seconds"] = ticks // 100
                except (ValueError, TypeError, StopIteration):
                    pass

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
                        except (ValueError, TypeError):
                            pass
                        break

                in_octets = 0
                out_octets = 0
                for i_oid, i_val in hc_in.items():
                    if i_oid.endswith("." + idx):
                        try:
                            in_octets = int(i_val)
                        except (ValueError, TypeError):
                            pass
                        break
                for o_oid, o_val in hc_out.items():
                    if o_oid.endswith("." + idx):
                        try:
                            out_octets = int(o_val)
                        except (ValueError, TypeError):
                            pass
                        break

                status_str = "up" if oper == 1 else ("admin_down" if admin == 2 else "down")
                if status_str == "up":
                    result["if_up_count"] += 1
                elif status_str == "admin_down":
                    result["if_admin_down"] += 1
                else:
                    result["if_down_count"] += 1

                if_details.append({
                    "name": iface_name,
                    "status": status_str,
                    "speed_mbps": speed_mbps,
                    "in_octets": in_octets,
                    "out_octets": out_octets,
                })

            result["if_details"] = if_details

        except Exception as exc:
            LOGGER.warning("monitoring: SNMP poll failed for %s: %s",
                           host.get("hostname", host["ip_address"]), redact_value(str(exc)))

    # ── SSH polling for VPN and routes ──
    if cred:
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
                }
                net_connect = netmiko.ConnectHandler(**device)
                if device["secret"]:
                    net_connect.enable()
                outputs = {}

                # VPN health
                if state.MONITORING_CONFIG.get("collect_vpn", True):
                    dtype = host.get("device_type", "cisco_ios")
                    if "asa" in dtype:
                        outputs["vpn"] = net_connect.send_command("show vpn-sessiondb summary")
                    else:
                        outputs["vpn"] = net_connect.send_command("show crypto isakmp sa")

                # Route table
                if state.MONITORING_CONFIG.get("collect_routes", True):
                    outputs["routes"] = net_connect.send_command("show ip route summary")
                    outputs["routes_full"] = net_connect.send_command("show ip route")

                net_connect.disconnect()
                return outputs

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

            # Parse route output
            routes_full = ssh_outputs.get("routes_full", "")
            if routes_full:
                route_lines = [line for line in routes_full.strip().splitlines()
                               if line.strip() and not line.strip().startswith(("Codes:", "Gateway", "---"))]
                result["route_count"] = len(route_lines)
                result["route_snapshot"] = routes_full.strip()

        except Exception as exc:
            LOGGER.warning("monitoring: SSH poll failed for %s: %s",
                           host.get("hostname", host["ip_address"]), redact_value(str(exc)))
            if result["cpu_percent"] is None and result["if_up_count"] == 0:
                result["poll_status"] = "error"
                result["poll_error"] = str(exc)[:500]

    # Record response time
    poll_elapsed = (time.monotonic() - poll_start) * 1000  # ms
    result["response_time_ms"] = round(poll_elapsed, 2)
    # Packet loss: 100% if error, 0% if ok
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


async def _evaluate_alerts_for_poll(
    res: dict, poll_id: int, group_id: int | None, rules: list[dict],
) -> int:
    """Evaluate built-in thresholds and user-defined rules against a poll result.

    Returns the number of new alerts created (dedup'd alerts count as 0).
    """
    alerts_created = 0
    host_id = res["host_id"]

    # ── Built-in threshold checks (always active as fallbacks) ──
    built_in_checks = []
    cpu_thresh = state.MONITORING_CONFIG.get("cpu_threshold", 90)
    mem_thresh = state.MONITORING_CONFIG.get("memory_threshold", 90)

    if res["cpu_percent"] is not None and res["cpu_percent"] >= cpu_thresh:
        built_in_checks.append({
            "metric": "cpu", "alert_type": "threshold",
            "message": f"CPU utilization at {res['cpu_percent']}% (threshold: {cpu_thresh}%)",
            "severity": "critical" if res["cpu_percent"] >= 95 else "warning",
            "value": res["cpu_percent"], "threshold": float(cpu_thresh),
        })

    if res["memory_percent"] is not None and res["memory_percent"] >= mem_thresh:
        built_in_checks.append({
            "metric": "memory", "alert_type": "threshold",
            "message": f"Memory utilization at {res['memory_percent']}% (threshold: {mem_thresh}%)",
            "severity": "critical" if res["memory_percent"] >= 95 else "warning",
            "value": res["memory_percent"], "threshold": float(mem_thresh),
        })

    if res["if_down_count"] > 0:
        down_names = [i["name"] for i in res["if_details"] if i.get("status") == "down"]
        if down_names:
            built_in_checks.append({
                "metric": "interface_down", "alert_type": "status",
                "message": f"{len(down_names)} interface(s) down: {', '.join(down_names[:5])}",
                "severity": "warning", "value": float(len(down_names)), "threshold": None,
            })

    if res["vpn_tunnels_down"] > 0:
        down_peers = [v["peer"] for v in res["vpn_details"] if v.get("status") == "down"]
        built_in_checks.append({
            "metric": "vpn_down", "alert_type": "status",
            "message": f"{res['vpn_tunnels_down']} VPN tunnel(s) down" +
                       (f": {', '.join(down_peers[:3])}" if down_peers else ""),
            "severity": "warning", "value": float(res["vpn_tunnels_down"]), "threshold": None,
        })

    # Fire built-in checks with dedup + suppression
    for chk in built_in_checks:
        suppressed = await db.is_alert_suppressed(host_id, chk["metric"], group_id)
        if suppressed:
            continue
        dedup_key = f"{host_id}:{chk['metric']}:{chk['alert_type']}"
        await db.create_monitoring_alert(
            host_id=host_id, poll_id=poll_id,
            alert_type=chk["alert_type"], metric=chk["metric"],
            message=chk["message"], severity=chk["severity"],
            value=chk["value"], threshold=chk.get("threshold"),
            dedup_key=dedup_key,
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
        suppressed = await db.is_alert_suppressed(host_id, rule["metric"], group_id)
        if suppressed:
            continue

        dedup_key = f"{host_id}:{rule['metric']}:rule:{rule['id']}"
        msg = f"Rule '{rule['name']}': {rule['metric']} = {metric_val} {rule['operator']} {rule['value']}"

        await db.create_monitoring_alert(
            host_id=host_id, poll_id=poll_id,
            alert_type=rule.get("rule_type", "threshold"),
            metric=rule["metric"],
            message=msg, severity=rule.get("severity", "warning"),
            value=metric_val, threshold=rule["value"],
            rule_id=rule["id"],
            dedup_key=dedup_key,
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
        LOGGER.info("monitoring: escalated alert %d (%s on %s) to %s",
                     alert["id"], alert.get("metric", "?"),
                     alert.get("hostname", "?"), target)

    return escalated


# ── Background loops ─────────────────────────────────────────────────────────


async def _run_monitoring_poll_once(*, force: bool = False) -> dict:
    """Run one monitoring poll cycle across all groups with SNMP enabled."""
    from netcontrol.routes.state import _resolve_snmp_discovery_config

    if not force and not state.MONITORING_CONFIG.get("enabled"):
        return {"enabled": False, "hosts_polled": 0, "alerts_created": 0, "errors": 0}

    groups = await db.get_all_groups()
    hosts_polled = 0
    alerts_created = 0
    errors = 0
    sem = asyncio.Semaphore(4)

    # Pre-load user-defined alert rules for this cycle
    alert_rules_cache = await db.get_alert_rules(enabled_only=True)

    # Resolve app-wide default credential for SSH polling
    default_cred_id = state.AUTH_CONFIG.get("default_credential_id")
    default_cred = await db.get_credential_raw(default_cred_id) if default_cred_id else None

    for group in groups:
        snmp_cfg = _resolve_snmp_discovery_config(group["id"])
        hosts = await db.get_hosts_for_group(group["id"])
        if not hosts:
            continue

        cred = default_cred

        async def _poll_one(h, c, s):
            async with sem:
                return await _poll_host_monitoring(h, c, s)

        tasks = [asyncio.create_task(_poll_one(h, cred, snmp_cfg)) for h in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for h, res in zip(hosts, results):
            if isinstance(res, Exception):
                errors += 1
                LOGGER.warning("monitoring: poll exception for %s: %s",
                               h.get("hostname", "?"), redact_value(str(res)))
                continue

            hosts_polled += 1

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
            )

            # ── Availability Tracking: detect state transitions ──
            try:
                new_host_state = "up" if res["poll_status"] == "ok" else "down"
                last_transition = await db.get_last_availability_state(
                    res["host_id"], "host", "")
                prev_state = last_transition["new_state"] if last_transition else "unknown"
                if prev_state != new_host_state:
                    await db.record_availability_transition(
                        host_id=res["host_id"],
                        entity_type="host",
                        entity_id="",
                        old_state=prev_state,
                        new_state=new_host_state,
                        poll_id=poll_id,
                    )
                    LOGGER.info("availability: host %s (%s) %s → %s",
                                h.get("hostname", "?"), h.get("ip_address", "?"),
                                prev_state, new_host_state)

                # Track interface state transitions
                for iface in res.get("if_details", []):
                    if_idx = str(iface.get("if_index", ""))
                    if not if_idx:
                        continue
                    if_state = "up" if iface.get("oper_status") == "up" else "down"
                    last_if = await db.get_last_availability_state(
                        res["host_id"], "interface", if_idx)
                    prev_if_state = last_if["new_state"] if last_if else "unknown"
                    if prev_if_state != if_state:
                        await db.record_availability_transition(
                            host_id=res["host_id"],
                            entity_type="interface",
                            entity_id=if_idx,
                            old_state=prev_if_state,
                            new_state=if_state,
                            poll_id=poll_id,
                        )
            except Exception as exc:
                LOGGER.debug("availability: tracking error for host %s: %s",
                             res["host_id"], str(exc))

            # ── Alerting Engine: evaluate built-in thresholds + user rules ──
            alerts_created += await _evaluate_alerts_for_poll(
                res, poll_id, h.get("group_id"), alert_rules_cache)

            # ── Metrics Engine: emit flexible metric samples + interface TS ──
            try:
                await emit_metric_samples_from_poll(res)
                await store_interface_ts_from_poll(res["host_id"], res.get("if_details", []))
            except Exception as exc:
                LOGGER.debug("metrics: emission error for host %s: %s",
                             res["host_id"], redact_value(str(exc)))

            # Route churn detection
            if res["route_snapshot"]:
                route_hash = hashlib.sha256(res["route_snapshot"].encode()).hexdigest()[:16]
                prev_snap = await db.get_latest_route_snapshot(res["host_id"])
                if prev_snap is None or prev_snap["routes_hash"] != route_hash:
                    await db.create_route_snapshot(
                        host_id=res["host_id"],
                        route_count=res["route_count"],
                        routes_text=res["route_snapshot"][:10000],
                        routes_hash=route_hash,
                    )
                    if prev_snap is not None:
                        delta = abs(res["route_count"] - prev_snap["route_count"])
                        suppressed = await db.is_alert_suppressed(
                            res["host_id"], "route_churn", h.get("group_id"))
                        if not suppressed:
                            await db.create_monitoring_alert(
                                host_id=res["host_id"], poll_id=poll_id,
                                alert_type="churn", metric="route_churn",
                                message=f"Route table changed: {prev_snap['route_count']} -> {res['route_count']} routes (delta: {delta})",
                                severity="warning" if delta < 10 else "critical",
                                value=float(delta),
                                dedup_key=f"{res['host_id']}:route_churn:churn",
                            )
                            alerts_created += 1

    # Retention cleanup
    retention_days = state.MONITORING_CONFIG.get("retention_days", 30)
    try:
        await db.delete_old_monitoring_polls(retention_days)
        await db.delete_old_monitoring_alerts(retention_days)
        await db.delete_old_route_snapshots(retention_days)
        await db.delete_expired_suppressions()
        await metrics_retention_cleanup()
    except Exception:
        pass

    LOGGER.info("monitoring: poll complete — %d hosts, %d alerts, %d errors",
                hosts_polled, alerts_created, errors)
    return {"enabled": True, "hosts_polled": hosts_polled,
            "alerts_created": alerts_created, "errors": errors}


async def _monitoring_poll_loop() -> None:
    """Infinite loop that polls device health at configurable intervals."""
    while True:
        try:
            await asyncio.sleep(int(state.MONITORING_CONFIG.get(
                "interval_seconds", state.MONITORING_DEFAULTS["interval_seconds"])))
            await _run_monitoring_poll_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("monitoring poll loop failure: %s", redact_value(str(exc)))
            await asyncio.sleep(state.MONITORING_DEFAULTS["interval_seconds"])


async def _alert_escalation_loop() -> None:
    """Background loop that checks for alerts needing escalation."""
    while True:
        try:
            interval = int(state.MONITORING_CONFIG.get("escalation_check_interval", 60))
            await asyncio.sleep(interval)
            escalated = await _run_alert_escalation()
            if escalated > 0:
                LOGGER.info("monitoring: escalation cycle — %d alerts escalated", escalated)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("alert escalation loop failure: %s", redact_value(str(exc)))
            await asyncio.sleep(60)


# ── Monitoring Routes ─────────────────────────────────────────────────────────


@router.get("/api/monitoring/summary")
async def monitoring_summary(group_id: int | None = Query(default=None)):
    return await db.get_monitoring_summary(group_id)


@router.get("/api/monitoring/polls")
async def monitoring_polls(group_id: int | None = Query(default=None), limit: int = Query(default=200)):
    return await db.get_latest_monitoring_polls(group_id, limit)


@router.get("/api/monitoring/polls/{host_id}/history")
async def monitoring_poll_history(host_id: int, limit: int = Query(default=100)):
    return await db.get_monitoring_poll_history(host_id, limit)


@router.get("/api/monitoring/alerts")
async def monitoring_alerts(
    host_id: int | None = Query(default=None),
    acknowledged: bool | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=200),
):
    return await db.get_monitoring_alerts(host_id, acknowledged, severity, limit)


@router.post("/api/monitoring/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int, request: Request):
    session = _get_session(request)
    user = session["user"] if session else ""
    await db.acknowledge_monitoring_alert(alert_id, user)
    await _audit("monitoring", "alert.acknowledged", user=user,
                 detail=f"alert_id={alert_id}", correlation_id=_corr_id(request))
    return {"ok": True}


@router.get("/api/monitoring/routes/{host_id}")
async def monitoring_route_snapshots(host_id: int, limit: int = Query(default=50)):
    return await db.get_route_snapshots(host_id, limit)


@router.post("/api/monitoring/poll-now")
async def monitoring_poll_now(request: Request):
    """Trigger an immediate monitoring poll across all groups."""
    session = _get_session(request)
    user = session["user"] if session else ""
    result = await _run_monitoring_poll_once(force=True)
    await _audit("monitoring", "poll.manual", user=user,
                 detail=f"hosts={result.get('hosts_polled', 0)} alerts={result.get('alerts_created', 0)}",
                 correlation_id=_corr_id(request))
    return result


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
        "monitoring", "config.updated",
        user=session["user"] if session else "",
        detail=f"enabled={state.MONITORING_CONFIG['enabled']} interval={state.MONITORING_CONFIG['interval_seconds']}s",
        correlation_id=_corr_id(request),
    )
    return state.MONITORING_CONFIG


@admin_router.post("/api/admin/monitoring/run-now")
async def admin_run_monitoring_now(request: Request):
    result = await _run_monitoring_poll_once(force=True)
    session = _get_session(request)
    await _audit("monitoring", "poll.admin_triggered", user=session["user"] if session else "",
                 detail=f"hosts={result.get('hosts_polled', 0)}", correlation_id=_corr_id(request))
    return result


# ── Alert Rules CRUD ─────────────────────────────────────────────────────────


@router.get("/api/monitoring/rules")
async def list_alert_rules():
    return await db.get_alert_rules()


@router.post("/api/monitoring/rules", status_code=201)
async def create_alert_rule_endpoint(body: dict, request: Request):
    session = _get_session(request)
    user = session["user"] if session else ""
    rule_id = await db.create_alert_rule(
        name=body.get("name", ""),
        metric=body.get("metric", ""),
        rule_type=body.get("rule_type", "threshold"),
        operator=body.get("operator", ">="),
        value=float(body.get("value", 0)),
        severity=body.get("severity", "warning"),
        consecutive=int(body.get("consecutive", 1)),
        cooldown_minutes=int(body.get("cooldown_minutes", 15)),
        escalate_after_minutes=int(body.get("escalate_after_minutes", 0)),
        escalate_to=body.get("escalate_to", "critical"),
        host_id=body.get("host_id"),
        group_id=body.get("group_id"),
        description=body.get("description", ""),
        created_by=user,
    )
    await _audit("monitoring", "rule.created", user=user,
                 detail=f"rule_id={rule_id} name='{body.get('name', '')}' metric={body.get('metric', '')}",
                 correlation_id=_corr_id(request))
    return {"id": rule_id}


@router.get("/api/monitoring/rules/{rule_id}")
async def get_alert_rule_endpoint(rule_id: int):
    rule = await db.get_alert_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.put("/api/monitoring/rules/{rule_id}")
async def update_alert_rule_endpoint(rule_id: int, body: dict, request: Request):
    rule = await db.get_alert_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.update_alert_rule(rule_id, **body)
    session = _get_session(request)
    await _audit("monitoring", "rule.updated", user=session["user"] if session else "",
                 detail=f"rule_id={rule_id}", correlation_id=_corr_id(request))
    return await db.get_alert_rule(rule_id)


@router.delete("/api/monitoring/rules/{rule_id}")
async def delete_alert_rule_endpoint(rule_id: int, request: Request):
    rule = await db.get_alert_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete_alert_rule(rule_id)
    session = _get_session(request)
    await _audit("monitoring", "rule.deleted", user=session["user"] if session else "",
                 detail=f"rule_id={rule_id} name='{rule.get('name', '')}'",
                 correlation_id=_corr_id(request))
    return {"ok": True}


# ── Alert Suppressions CRUD ──────────────────────────────────────────────────


@router.get("/api/monitoring/suppressions")
async def list_alert_suppressions(active_only: bool = Query(default=False)):
    return await db.get_alert_suppressions(active_only)


@router.post("/api/monitoring/suppressions", status_code=201)
async def create_alert_suppression_endpoint(body: dict, request: Request):
    session = _get_session(request)
    user = session["user"] if session else ""
    if not body.get("ends_at"):
        raise HTTPException(status_code=400, detail="ends_at is required")
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
    await _audit("monitoring", "suppression.created", user=user,
                 detail=f"suppression_id={sup_id} name='{body.get('name', '')}' ends_at={body['ends_at']}",
                 correlation_id=_corr_id(request))
    return {"id": sup_id}


@router.delete("/api/monitoring/suppressions/{suppression_id}")
async def delete_alert_suppression_endpoint(suppression_id: int, request: Request):
    await db.delete_alert_suppression(suppression_id)
    session = _get_session(request)
    await _audit("monitoring", "suppression.deleted", user=session["user"] if session else "",
                 detail=f"suppression_id={suppression_id}",
                 correlation_id=_corr_id(request))
    return {"ok": True}


# ── Bulk Alert Operations ────────────────────────────────────────────────────


@router.post("/api/monitoring/alerts/bulk-acknowledge")
async def bulk_acknowledge_alerts_endpoint(body: dict, request: Request):
    alert_ids = body.get("alert_ids", [])
    if not alert_ids:
        raise HTTPException(status_code=400, detail="alert_ids required")
    session = _get_session(request)
    user = session["user"] if session else ""
    count = await db.bulk_acknowledge_alerts(alert_ids, user)
    await _audit("monitoring", "alerts.bulk_acknowledged", user=user,
                 detail=f"count={count} ids={alert_ids[:10]}",
                 correlation_id=_corr_id(request))
    return {"ok": True, "acknowledged": count}


# ── SLA Dashboard Routes ─────────────────────────────────────────────────────


@router.get("/api/sla/summary")
async def sla_summary(
    group_id: int | None = Query(default=None),
    days: int = Query(default=30),
):
    return await db.get_sla_summary(group_id, days)


@router.get("/api/sla/host/{host_id}")
async def sla_host_detail(host_id: int, days: int = Query(default=30)):
    return await db.get_sla_host_detail(host_id, days)


@router.get("/api/sla/targets")
async def sla_targets_list(
    host_id: int | None = Query(default=None),
    group_id: int | None = Query(default=None),
):
    return await db.get_sla_targets(host_id, group_id)


@router.post("/api/sla/targets", status_code=201)
async def sla_target_create(body: dict, request: Request):
    session = _get_session(request)
    user = session["user"] if session else ""
    if not body.get("name") or not body.get("metric"):
        raise HTTPException(status_code=400, detail="name and metric required")
    target_id = await db.create_sla_target(
        name=body["name"],
        metric=body["metric"],
        target_value=float(body.get("target_value", 99.9)),
        warning_value=float(body.get("warning_value", 99.0)),
        host_id=body.get("host_id"),
        group_id=body.get("group_id"),
        created_by=user,
    )
    await _audit("sla", "target.created", user=user,
                 detail=f"target_id={target_id} name='{body['name']}' metric={body['metric']}",
                 correlation_id=_corr_id(request))
    return {"id": target_id}


@router.put("/api/sla/targets/{target_id}")
async def sla_target_update(target_id: int, body: dict, request: Request):
    target = await db.get_sla_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await db.update_sla_target(target_id, **body)
    session = _get_session(request)
    await _audit("sla", "target.updated", user=session["user"] if session else "",
                 detail=f"target_id={target_id}", correlation_id=_corr_id(request))
    return await db.get_sla_target(target_id)


@router.delete("/api/sla/targets/{target_id}")
async def sla_target_delete(target_id: int, request: Request):
    target = await db.get_sla_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await db.delete_sla_target(target_id)
    session = _get_session(request)
    await _audit("sla", "target.deleted", user=session["user"] if session else "",
                 detail=f"target_id={target_id} name='{target.get('name', '')}'",
                 correlation_id=_corr_id(request))
    return {"ok": True}


# ── Availability Tracking Routes ─────────────────────────────────────────────


@router.get("/api/availability/summary")
async def availability_summary_api(
    group_id: int | None = Query(default=None),
    days: int = Query(default=30),
):
    return await db.get_availability_summary(group_id, days)


@router.get("/api/availability/transitions")
async def availability_transitions_api(
    host_id: int | None = Query(default=None),
    entity_type: str | None = Query(default=None),
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    limit: int = Query(default=500),
):
    return {
        "transitions": await db.get_availability_transitions(
            host_id=host_id, entity_type=entity_type,
            start=start, end=end, limit=limit,
        )
    }


@router.get("/api/availability/outages")
async def availability_outages_api(
    host_id: int | None = Query(default=None),
    group_id: int | None = Query(default=None),
    days: int = Query(default=30),
    limit: int = Query(default=200),
):
    return {
        "outages": await db.get_outage_history(
            host_id=host_id, group_id=group_id, days=days, limit=limit,
        )
    }


# ── Per-Port Utilization Routes ──────────────────────────────────────────────


@router.get("/api/interfaces/{host_id}/summary")
async def interface_utilization_summary_api(
    host_id: int,
    days: int = Query(default=1),
):
    return {
        "host_id": host_id,
        "interfaces": await db.get_interface_utilization_summary(host_id, days),
    }


@router.get("/api/interfaces/{host_id}/port/{if_index}")
async def port_detail_api(
    host_id: int,
    if_index: int,
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    limit: int = Query(default=5000),
):
    return await db.get_port_detail_ts(host_id, if_index, start, end, limit)
