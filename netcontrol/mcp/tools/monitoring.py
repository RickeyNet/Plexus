"""Monitoring tools: alerts, device health, SLA status and outages.

All from what the monitoring poller and the alert pipeline already stored;
nothing here polls a device.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any

import routes.database as db

from netcontrol.mcp.auth import McpContext
from netcontrol.mcp.dispatch import no_data, page_args
from netcontrol.mcp.registry import Tool, register
from netcontrol.mcp.tools._common import PAGING, TIME_RANGE, db_time, host_ref, in_window, schema, time_window
from netcontrol.mcp.tools._hosts import HOST_ARG, resolve_host

_ROWS = 5000
_POLL_ROWS = 5000
_MAX_INTERFACE_ROWS = 200
_MAX_TRANSITIONS = 100
_MAX_EVALUATIONS = 200
# Poll columns that are summarised (min / avg / max) over the window.
_METRICS = ("cpu_percent", "memory_percent", "response_time_ms", "icmp_rtt_ms", "packet_loss_pct")
# Bulky per-poll JSON that is not returned.
_POLL_DETAIL_COLUMNS = ("if_details", "vpn_details", "route_snapshot")


def _inventory_alert(alert: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": alert.get("id"),
        "host": {"id": alert.get("host_id"), "hostname": alert.get("hostname"), "ip_address": alert.get("ip_address")},
        "severity": alert.get("severity"),
        "type": alert.get("alert_type"),
        "metric": alert.get("metric"),
        "message": alert.get("message"),
        "value": alert.get("value"),
        "threshold": alert.get("threshold"),
        "acknowledged": bool(alert.get("acknowledged")),
        "occurrences": alert.get("occurrence_count"),
        "started_at": alert.get("created_at"),
        "last_seen": alert.get("last_seen_at") or alert.get("created_at"),
        "source": "inventory",
    }


def _meraki_alert(alert: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": alert.get("id"),
        "device": alert.get("device_name") or None,
        "network": alert.get("network_name") or None,
        "organization": alert.get("org_name") or None,
        "host_id": alert.get("host_id"),
        "severity": alert.get("severity"),
        "type": alert.get("alert_type") or alert.get("condition"),
        "message": alert.get("title") or alert.get("message"),
        "status": alert.get("status"),
        "occurrences": alert.get("occurrences"),
        "started_at": alert.get("started_at") or alert.get("first_seen"),
        "resolved_at": alert.get("resolved_at") or None,
        "last_seen": alert.get("last_seen"),
        "source": "meraki",
    }


async def list_alerts(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    active_only = str(args.get("state") or "active") == "active"
    bounded = bool(args.get("since") or args.get("until")) or not active_only
    since, until = time_window(args) if bounded else (None, datetime.now(UTC))
    severity = str(args.get("severity") or "").strip().lower() or None
    host_id = int((await resolve_host(args["host"]))["id"]) if args.get("host") else None

    rows = [
        _inventory_alert(alert)
        for alert in await db.get_monitoring_alerts(
            host_id=host_id, acknowledged=False if active_only else None, severity=severity, limit=_ROWS
        )
    ]
    for alert in await db.list_meraki_alerts(include_resolved=not active_only, limit=_ROWS):
        if severity and str(alert.get("severity") or "").lower() != severity:
            continue
        if host_id is not None and alert.get("host_id") != host_id:
            continue
        rows.append(_meraki_alert(alert))
    if not rows and not await db.get_latest_monitoring_polls(limit=1):
        return no_data("monitoring")
    if bounded:
        rows = [row for row in rows if in_window(row["last_seen"] or row["started_at"], since, until)]
    rows.sort(key=lambda row: str(row.get("last_seen") or row.get("started_at") or ""), reverse=True)
    return page_args(rows, args)


def _summary(polls: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for metric in _METRICS:
        values = [float(p[metric]) for p in polls if p.get(metric) is not None]
        if values:
            summary[metric] = {
                "min": round(min(values), 2),
                "avg": round(sum(values) / len(values), 2),
                "max": round(max(values), 2),
                "samples": len(values),
            }
    return summary


async def get_device_health(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    host = await resolve_host(args["host"])
    hours = int(args.get("hours", 24))
    polls = await db.get_monitoring_poll_history(int(host["id"]), limit=_POLL_ROWS)
    if not polls:
        return no_data(f"monitoring polls of {host['hostname']}")
    newest = max(polls, key=lambda p: str(p.get("polled_at") or ""))
    until = datetime.now(UTC)
    since, _ = time_window({"since": None, "until": None}, default_hours=hours)
    window = [p for p in polls if in_window(p.get("polled_at"), since, until)]
    failed = [p for p in window if str(p.get("poll_status") or "ok") != "ok"]
    interfaces = await db.get_interface_error_stats_for_host(int(host["id"]))
    return {
        "host": host_ref(host),
        "status": host.get("status"),
        "latest_poll": {k: v for k, v in newest.items() if k not in _POLL_DETAIL_COLUMNS},
        "window_hours": hours,
        "polls_in_window": len(window),
        "failed_polls_in_window": len(failed),
        "summary": _summary(window),
        "interface_error_counters": interfaces[:_MAX_INTERFACE_ROWS],
    }


async def get_sla_status(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    targets = await db.get_sla_targets()
    if not targets:
        return no_data("SLA targets")
    wanted = str(args.get("target") or "").strip().lower()
    evaluations: dict[int, list[dict[str, Any]]] = {}
    for row in await db.get_sla_compliance():
        evaluations.setdefault(int(row["target_id"]), []).append(row)
    rows = []
    for target in targets:
        if wanted and wanted not in str(target.get("name") or "").lower():
            continue
        results = evaluations.get(int(target["id"]), [])
        breaching = [r for r in results if str(r.get("status") or "").lower() not in ("ok", "met", "compliant", "")]
        rows.append(
            {
                "id": target["id"],
                "name": target.get("name"),
                "metric": target.get("metric"),
                "target_value": target.get("target_value"),
                "warning_value": target.get("warning_value"),
                "enabled": bool(target.get("enabled", 1)),
                "hosts_evaluated": len(results),
                "hosts_not_meeting_target": len(breaching),
                "breaching_hosts": [
                    {k: v for k, v in r.items() if k not in ("target_id", "target_name", "group_id")}
                    for r in breaching[:_MAX_EVALUATIONS]
                ],
            }
        )
    summary = await db.get_sla_summary()
    return {"targets": rows, "summary": {k: v for k, v in summary.items() if k != "hosts"}}


async def list_outages(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    since, until = time_window(args)
    days = max(1, min(365, math.ceil((datetime.now(UTC) - since).total_seconds() / 86400))) if since else 30
    entity = str(args.get("entity") or "").strip().lower()

    def _wanted(row: dict[str, Any]) -> bool:
        if not entity:
            return True
        return any(entity in str(row.get(k) or "").lower() for k in ("name", "entity_id", "site", "org_name"))

    def _overlaps(outage: dict[str, Any]) -> bool:
        started, ended = db_time(outage.get("started_at")), db_time(outage.get("ended_at"))
        return (started is None or started <= until) and (ended is None or since is None or ended >= since)

    outages = [o for o in await db.get_topology_outages(days=days, limit=_ROWS) if _wanted(o) and _overlaps(o)]
    transitions = [
        t
        for t in await db.get_topology_transitions(days=days, limit=_ROWS)
        if _wanted(t) and in_window(t.get("transition_at"), since, until)
    ]
    for outage in outages:
        outage["source"] = outage.get("provider")
    result = page_args(outages, args)
    result["transitions"] = transitions[:_MAX_TRANSITIONS]
    result["transition_count"] = len(transitions)
    return result


register(
    Tool(
        name="list_alerts",
        description=(
            "Lists monitoring alerts: threshold and anomaly alerts on inventory devices, and Meraki "
            "dashboard alerts; each row names its source. By default only active alerts (unacknowledged "
            "or open) of any age. state 'all' adds acknowledged and resolved alerts, limited to the time "
            "range (default: the last 24 hours). Filter by device and severity."
        ),
        category="monitoring",
        input_schema=schema(
            {
                "host": HOST_ARG,
                "severity": {"type": "string", "enum": ["critical", "warning", "info"]},
                "state": {"type": "string", "enum": ["active", "all"]},
                **TIME_RANGE,
                **PAGING,
            }
        ),
        handler=list_alerts,
    )
)
register(
    Tool(
        name="get_device_health",
        description=(
            "Returns the health of one device from stored monitoring polls: the latest poll (CPU, "
            "memory, interface counts, reachability, response time), the minimum, average and maximum "
            "of each metric over the last 'hours' (default 24), failed polls in that window, and the "
            "interface error counters."
        ),
        category="monitoring",
        input_schema=schema(
            {"host": HOST_ARG, "hours": {"type": "integer", "minimum": 1, "maximum": 168}}, required=("host",)
        ),
        handler=get_device_health,
    )
)
register(
    Tool(
        name="get_sla_status",
        description=(
            "Returns the SLA targets (availability, latency, packet loss) with how many devices were "
            "evaluated against each, which devices are not meeting it, and the overall uptime and "
            "latency summary for the last 30 days. 'target' matches part of a target's name."
        ),
        category="monitoring",
        input_schema=schema({"target": {"type": "string", "maxLength": 200}}),
        handler=get_sla_status,
    )
)
register(
    Tool(
        name="list_outages",
        description=(
            "Lists availability outages (periods a device, site, tunnel or cloud resource was down) "
            "that overlap the time range, across every vendor Plexus tracks, with start, end and "
            "duration; an outage still under way has no end. Also returns the up/down state "
            "transitions in the range. 'entity' matches part of a name, id, site or organization. "
            "Default range: the last 24 hours."
        ),
        category="monitoring",
        input_schema=schema({**TIME_RANGE, "entity": {"type": "string", "maxLength": 255}, **PAGING}),
        handler=list_outages,
    )
)
