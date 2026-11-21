"""
security_events.py -- Security events: storage, alerting and the event list.

A vendor-neutral store (``routes.db.security_events``, migration 0126) of
the security events integrations read from a device: today the intrusion
detection (Suricata) alerts of an OPNsense firewall
(``netcontrol.routes.opnsense_ids``). ``record_events`` stores one read
and raises the alerts:

  - **Stored.** Every event, once (its ``event_key`` is unique per source
    and kind), with the source, the inventory host when the device is one,
    severity, signature, action and flow. At most
    ``MAX_EVENTS_PER_SOURCE`` per source (the oldest go first) and no
    longer than the monitoring retention (``retention_days``).
  - **Alerted.** Not one alert per event: one per source and signature
    (dedup key ``security:<provider>:<org_ref>:<kind>:<signature id>``)
    for the new events at ``ALERT_SEVERITIES`` (critical, warning; info
    and unknown are stored only) that happened less than
    ``ALERT_MAX_AGE_MINUTES`` ago (the backlog of a first read raises
    nothing). A device that is an inventory host gets a monitoring alert
    on that host (``topology_availability.deliver_alert``), counted on
    every read that brings new events of the signature while it is open;
    another device's alert goes straight to the notification channels,
    once per open period (no new notification while the signature had an
    alerting event less than ``QUIET_MINUTES`` before). The message says
    how many events there were and whether the device blocked them or
    only detected them. At most ``ALERTS_PER_READ`` signatures per read.
  - **Ended.** An alert resolves on its own once its signature has been
    quiet for ``QUIET_MINUTES`` (``resolve_quiet_alerts``, run every minute
    by the metrics loop), as ``auto-resolved (quiet)``; it can be
    acknowledged by hand like any alert.
  - **Muted.** A mute of the source's device (or its site) in the topology
    availability tracker covers its security event alerts: nothing is
    raised while it lasts, and creating it acknowledges the open ones
    (``mute_source_alerts``). A monitoring suppression of the inventory
    host (all metrics or ``ids_alert``) covers them too.

``GET /api/monitoring/security-events`` lists the events (monitoring
access; object scope: a scoped caller sees the events of the hosts it may
read only, never those of a device that is no inventory host).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import routes.database as db
from fastapi import APIRouter, Query, Request

from netcontrol.integrations.traffic import parse_time, store_time
from netcontrol.object_scope import readable_host_ids, require_host, scoped
from netcontrol.routes.topology_availability import PROVIDER_LABELS, deliver_alert
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.security_events")

router = APIRouter()

ALERT_TYPE = "security_event"
ALERT_SEVERITIES = ("critical", "warning")
QUIET_MINUTES = 60
ALERT_MAX_AGE_MINUTES = 60
ALERTS_PER_READ = 50
MAX_EVENTS_PER_SOURCE = 50000
RESOLVED_BY = "auto-resolved (quiet)"
MUTED_BY = "muted"
# The monitoring metric of each kind of event (alert rules and
# suppressions name it).
KIND_METRICS: dict[str, str] = {"ids_alert": "ids_alert"}
KIND_LABELS: dict[str, str] = {"ids_alert": "IDS alert"}
# The list API's bounds.
LIST_MAX_HOURS = 24 * 365
LIST_MAX_LIMIT = 500
LIST_MAX_OFFSET = 100_000
SEARCH_MAX = 200

_LOCKS: dict[tuple[str, int], asyncio.Lock] = {}


def dedup_prefix(provider: str, org_ref: int) -> str:
    return f"security:{provider}:{int(org_ref)}:"


def dedup_key(provider: str, org_ref: int, kind: str, signature_id: Any) -> str:
    return f"{dedup_prefix(provider, org_ref)}{kind}:{signature_id}"


def metric_of(kind: str) -> str:
    return KIND_METRICS.get(kind, kind)


def action_text(count: int, blocked: int) -> str:
    """Whether the device stopped the traffic: ``blocked``, ``detected
    only, not blocked`` or ``b of n blocked``."""
    if blocked and blocked >= count:
        return "blocked"
    if not blocked:
        return "detected only, not blocked"
    return f"{blocked} of {count} blocked"


def _rank(severity: str) -> int:
    return ALERT_SEVERITIES.index(severity) if severity in ALERT_SEVERITIES else len(ALERT_SEVERITIES)


def alert_groups(events: list[dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
    """The alerts a read's new events raise: one per kind and signature,
    from the events at ``ALERT_SEVERITIES`` that happened less than
    ``ALERT_MAX_AGE_MINUTES`` before ``now``; the worst severity, the
    count, how many were blocked, the first and last time and the last
    event. Worst first, then the most events. Pure."""
    oldest = now - timedelta(minutes=ALERT_MAX_AGE_MINUTES)
    groups: dict[tuple[str, Any], dict[str, Any]] = {}
    for event in sorted(events, key=lambda e: str(e.get("occurred_at") or "")):
        at = parse_time(event.get("occurred_at"))
        if event.get("severity") not in ALERT_SEVERITIES or at is None or at < oldest:
            continue
        key = (str(event.get("kind") or ""), event.get("signature_id"))
        group = groups.setdefault(
            key,
            {
                "kind": key[0],
                "signature_id": key[1],
                "signature": event.get("signature") or "",
                "category": event.get("category") or "",
                "priority": event.get("priority"),
                "severity": event["severity"],
                "count": 0,
                "blocked": 0,
                "first_at": event["occurred_at"],
            },
        )
        group["count"] += 1
        group["blocked"] += int(event.get("action") == "blocked")
        group["last_at"] = event["occurred_at"]
        group["last"] = event
        if _rank(event["severity"]) < _rank(group["severity"]):
            group["severity"] = event["severity"]
    return sorted(groups.values(), key=lambda g: (_rank(g["severity"]), -g["count"]))


def endpoint_text(address: Any, port: Any) -> str:
    text = str(address or "?")
    if port is None:
        return text
    return f"[{text}]:{port}" if ":" in text else f"{text}:{port}"


def alert_message(group: dict[str, Any], device: str, provider: str) -> str:
    """The text of the alert of one ``alert_groups`` group. Pure."""
    last = group.get("last") or {}
    what = KIND_LABELS.get(group["kind"], group["kind"])
    details = [f"sid {group['signature_id']}"]
    if group.get("category"):
        details.append(str(group["category"]))
    if group.get("priority") is not None:
        details.append(f"priority {group['priority']}")
    flow = f"{endpoint_text(last.get('src_ip'), last.get('src_port'))} -> {endpoint_text(last.get('dest_ip'), last.get('dest_port'))}"
    if last.get("protocol"):
        flow += f" {last['protocol']}"
    return (
        f"{what} on {device} ({PROVIDER_LABELS.get(provider, provider)}): {group['signature'] or 'unnamed signature'}"
        f" ({', '.join(details)}): {group['count']} event(s), {action_text(group['count'], group['blocked'])};"
        f" last {flow} at {group['last_at']} UTC"
    )


def _lock(provider: str, org_ref: int) -> asyncio.Lock:
    return _LOCKS.setdefault((provider, int(org_ref)), asyncio.Lock())


async def source_muted(provider: str, org_ref: int) -> bool:
    """Whether a mute of the availability tracker covers a device of the
    source (the device itself or its site). A failure means "not muted"."""
    try:
        index = await db.load_topology_mute_index(provider, org_ref)
        if not index:
            return False
        devices = await db.list_topology_entity_states(provider, org_ref, "device")
        return any(index.match(row) for row in devices)
    except Exception as exc:  # noqa: BLE001 - an alert too many beats a silenced attack
        LOGGER.warning("security events: mutes of %s %s not read: %s", provider, org_ref, type(exc).__name__)
        return False


async def _suppressed(host: dict | None, metric: str) -> bool:
    if not host:
        return False
    try:
        return bool(await db.is_alert_suppressed(int(host["id"]), metric, host.get("group_id")))
    except Exception as exc:  # noqa: BLE001 - as for the mutes
        LOGGER.warning("security events: suppressions of host %s not read: %s", host.get("id"), type(exc).__name__)
        return False


async def record_events(
    provider: str,
    org_ref: int,
    events: list[dict[str, Any]],
    *,
    host: dict | None,
    source_name: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Store one read's events of source ``(provider, org_ref)`` and raise
    their alerts (see the module docstring). ``host``: the inventory host
    the device is, or ``None``. Returns ``stored`` (the new events),
    ``alerted``, ``muted`` and ``repeated`` (alerts not notified again)."""
    moment = now or datetime.now(UTC)
    outcome: dict[str, Any] = {"stored": [], "alerted": 0, "muted": 0, "repeated": 0}
    if not events:
        return outcome
    host_id = int(host["id"]) if host and host.get("id") else None
    async with _lock(provider, org_ref):
        alerting = {
            (str(e["kind"]), e["signature_id"])
            for e in events
            if e.get("severity") in ALERT_SEVERITIES and e.get("signature_id") is not None
        }
        previous: dict[tuple[str, Any], str] = {}
        for kind in {k for k, _sid in alerting}:
            found = await db.latest_alerting_security_events(
                provider, org_ref, kind, [sid for k, sid in alerting if k == kind]
            )
            previous.update({(kind, sid): at for sid, at in found.items()})
        new = await db.insert_security_events(
            provider, org_ref, events, host_id=host_id, source_name=source_name, received_at=store_time(moment)
        )
        outcome["stored"] = new
        if not new:
            return outcome
        await db.trim_security_events(provider, org_ref, MAX_EVENTS_PER_SOURCE)
        groups = alert_groups(new, moment)[:ALERTS_PER_READ]
        if not groups:
            return outcome
        if await source_muted(provider, org_ref):
            outcome["muted"] = len(groups)
            return outcome
        device = (host or {}).get("hostname") or source_name or f"{provider} {org_ref}"
        for group in groups:
            metric = metric_of(group["kind"])
            if await _suppressed(host, metric):
                outcome["muted"] += 1
                continue
            if host_id is None:
                # No monitoring alert to count on: notified once per open period.
                before = parse_time(previous.get((group["kind"], group["signature_id"])))
                first = parse_time(group["first_at"])
                if before is not None and first is not None and before >= first - timedelta(minutes=QUIET_MINUTES):
                    outcome["repeated"] += 1
                    continue
            try:
                await deliver_alert(
                    host_id=host_id,
                    name=device,
                    alert_type=ALERT_TYPE,
                    metric=metric,
                    message=alert_message(group, device, provider),
                    severity=group["severity"],
                    dedup_key=dedup_key(provider, org_ref, group["kind"], group["signature_id"]),
                    value=float(group["count"]),
                )
                outcome["alerted"] += 1
            except Exception as exc:  # noqa: BLE001 - delivery never loses the stored events
                LOGGER.warning("security events: alert of %s %s not raised: %s", provider, org_ref, type(exc).__name__)
    return outcome


async def resolve_quiet_alerts() -> int:
    """Resolve the open security event alerts not seen again for
    ``QUIET_MINUTES``. Called every minute by the metrics loop."""
    resolved = 0
    for metric in sorted(set(KIND_METRICS.values())):
        resolved += await db.resolve_stale_monitoring_alerts(ALERT_TYPE, metric, QUIET_MINUTES, RESOLVED_BY)
    return resolved


async def mute_source_alerts(provider: str, org_ref: int) -> int:
    """Acknowledge as ``muted`` the open security event alerts of a source
    whose device was just muted. Returns how many."""
    return await db.resolve_security_event_alerts(ALERT_TYPE, dedup_prefix(provider, org_ref), MUTED_BY)


# ── API ──────────────────────────────────────────────────────────────────────


@router.get("/api/monitoring/security-events")
@scoped("list")
async def list_security_events_api(
    request: Request,
    provider: str | None = Query(default=None, max_length=32, pattern=r"^[a-z0-9_-]+$"),
    org_ref: int | None = Query(default=None, ge=1),
    host_id: int | None = Query(default=None, ge=1),
    kind: str | None = Query(default=None, max_length=32, pattern=r"^[a-z0-9_]+$"),
    severity: Literal["critical", "warning", "info", "unknown"] | None = Query(default=None),
    action: Literal["allowed", "blocked"] | None = Query(default=None),
    hours: int = Query(default=24, ge=1, le=LIST_MAX_HOURS),
    q: str | None = Query(default=None, max_length=SEARCH_MAX),
    limit: int = Query(default=100, ge=1, le=LIST_MAX_LIMIT),
    offset: int = Query(default=0, ge=0, le=LIST_MAX_OFFSET),
) -> dict[str, Any]:
    """The security events of the last ``hours``, newest first, with how
    many match and how many of each severity (``counts``). ``q`` matches
    the signature, its id, the category and the addresses."""
    if host_id is not None:
        await require_host(request, host_id)
    since = store_time(datetime.now(UTC) - timedelta(hours=hours))
    found = await db.list_security_events(
        provider=provider,
        org_ref=org_ref,
        host_id=host_id,
        kind=kind,
        severity=severity,
        action=action,
        since=since,
        search=q,
        host_ids=await readable_host_ids(request),
        limit=limit,
        offset=offset,
    )
    return {**found, "since": since, "hours": hours, "limit": limit, "offset": offset}
