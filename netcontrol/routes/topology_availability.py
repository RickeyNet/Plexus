"""Availability tracking of the entities that integrations collect.

``record_snapshot_states`` is called after every stored collection (a Meraki,
Cato, FMC, Panorama, Appgate or OPNsense snapshot, an AWS, Azure or GCP
discovery; see
``netcontrol.routes.meraki_topology``). It extracts the state of every
tracked entity (``netcontrol.integrations.availability``), records the
changes (``routes.db.topology_availability``) and raises an alert when an
entity turns ``degraded`` or ``down``:

  - an entity matched to an inventory host (``node["inventory"]["host_id"]``)
    gets a monitoring alert on that host (``create_monitoring_alert``): it is
    listed in the Alerts tab, deduplicated while unacknowledged, and the
    alert-created hook hands it to the notification channels;
  - any other entity (most of them: ``monitoring_alerts`` rows need a host)
    goes straight to the notification channels
    (``notification_channels.on_alert_created``), like software alerts.

No alert is raised again while the entity stays down (or degraded); one
that recovers to ``up`` can alert again. A member of a redundancy group
(``meta["role"]``: an OPNsense CARP group) whose role changes between
MASTER and BACKUP from one collection to the next raises a failover
warning the same way (``failovers``), although both roles are healthy; it
honours the same mutes. The latency, jitter and loss a
vendor reports for an entity (``EntityState.metrics``) are stored as a time
series with daily rollups (``record_topology_entity_metrics``) for the SLA
targets of topology entities (``netcontrol.routes.topology_sla``). An entity seen for the first time
is a baseline and raises nothing. Best-effort throughout: a failure is
logged and never fails the collection.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import routes.database as db

from netcontrol.integrations.availability import FAILOVER_ROLES, clean_entity_types, extract_entity_states
from netcontrol.routes import notification_channels
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.topology_availability")

ALERT_TYPE = "topology_availability"
PROVIDER_LABELS = {
    "meraki": "Meraki",
    "cato": "Cato",
    "fmc": "Cisco FMC",
    "panorama": "Panorama",
    "appgate": "Appgate SDP",
    "opnsense": "OPNsense",
    "aws": "AWS",
    "azure": "Azure",
    "gcp": "GCP",
}
TYPE_LABELS = {
    "device": "Device",
    "site": "Site",
    "uplink": "Uplink",
    "tunnel": "Tunnel",
    "vpn_connection": "VPN connection",
    "circuit": "Circuit",
    "peering": "Peering",
    "link": "Link",
    "service": "Service",
}


def dedup_key(t: dict) -> str:
    return f"topo:{t['provider']}:{t['org_ref']}:{t['entity_type']}:{t['entity_id']}"


def failover_dedup_key(t: dict, role: str) -> str:
    """The dedup key of a failover alert of entity ``t`` into ``role``: one
    per direction, so a failover is raised again once the last one into the
    same role was acknowledged, and repeated (a bump) while it is open."""
    return f"{dedup_key(t)}:failover:{role}"


def alert_keys(row: dict) -> list[str]:
    """Every dedup key an entity's open alerts may have: its state alert's
    and, for a role-tracked entity, its failover alerts'."""
    keys = [dedup_key(row)]
    if "role" in (row.get("meta") or {}):
        keys += [failover_dedup_key(row, role) for role in FAILOVER_ROLES]
    return keys


def failovers(entities: list[dict], stored: list[dict]) -> list[dict]:
    """The role-tracked entities (``meta["role"]``, see
    ``availability.ha_entity_states``) whose role changed between MASTER and
    BACKUP since the stored state (``raw_status`` of the state rows read
    before this collection was applied), with ``old_role`` and ``new_role``.
    A first sight, or a role coming from anything else (``init``,
    ``disabled``, missing: the stored ``raw_status`` is then empty), is no
    failover: the state transition alert covers it. Pure."""
    before = {(str(r["entity_type"]), str(r["entity_id"])): str(r.get("raw_status") or "").lower() for r in stored}
    found = []
    for entity in entities:
        role = str((entity.get("meta") or {}).get("role") or "").lower()
        if role not in FAILOVER_ROLES:
            continue
        old = before.get((str(entity["entity_type"]), str(entity["entity_id"])), "")
        if old in FAILOVER_ROLES and old != role:
            found.append({**entity, "old_role": old, "new_role": role})
    return found


def _subject(t: dict) -> str:
    """``<name> at <site> (<provider> <source>)`` of an alert message."""
    where = PROVIDER_LABELS.get(t["provider"], t["provider"])
    if t.get("org_name"):
        where = f"{where} {t['org_name']}"
    site = f" at {t['site']}" if t.get("site") and t["site"] != t.get("name") else ""
    return f"{t['name'] or t['entity_id']}{site} ({where})"


def _failover_message(t: dict) -> str:
    return f"{_subject(t)} failed over: {t['old_role'].upper()} to {t['new_role'].upper()}"


def _message(t: dict) -> str:
    return (
        f"{TYPE_LABELS.get(t['entity_type'], t['entity_type'])} {_subject(t)} "
        f"is {t['new_state']} (was {t['old_state']})"
    )


async def _meraki_alert_already_raised(t: dict) -> bool:
    """A Meraki device going down whose device-down alert the near-real-time
    Meraki alerts (``netcontrol.routes.meraki_alerts``) already raised: the
    same condition is not notified twice. Any failure means "not raised"."""
    entity_id = str(t.get("entity_id") or "")
    if t.get("provider") != "meraki" or t.get("entity_type") != "device" or t.get("new_state") != "down":
        return False
    if not entity_id.startswith("d:"):
        return False
    try:
        return await db.meraki_device_down_alerted(int(t["org_ref"]), entity_id[2:])
    except Exception as exc:  # noqa: BLE001 - fall back to alerting
        LOGGER.debug("topology availability: meraki alert lookup failed: %s", type(exc).__name__)
        return False


async def deliver_alert(
    *,
    host_id: Any,
    name: str,
    alert_type: str,
    metric: str,
    message: str,
    severity: str,
    dedup_key: str,
    value: float | None = None,
    threshold: float | None = None,
) -> str:
    """Raise an alert about a topology entity: a monitoring alert on its
    inventory host when it has one, else straight to the notification
    channels. Returns how: ``monitoring`` or ``notification``."""
    if host_id and await db.get_host(int(host_id)):
        await db.create_monitoring_alert(
            host_id=int(host_id),
            poll_id=None,
            alert_type=alert_type,
            metric=metric,
            message=message,
            severity=severity,
            value=value,
            threshold=threshold,
            dedup_key=dedup_key,
            hostname=name,
        )
        return "monitoring"
    event = {
        "alert_id": dedup_key,
        "host_id": None,
        "hostname": name,
        "poll_id": None,
        "rule_id": None,
        "alert_type": alert_type,
        "metric": metric,
        "message": message,
        "severity": severity,
        "value": value,
        "threshold": threshold,
        "dedup_key": dedup_key,
        "channel_ids": "",
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    await notification_channels.on_alert_created(event)
    return "notification"


async def _raise_alert(t: dict) -> str:
    """Raise the alert of one transition. Returns how: ``monitoring``,
    ``notification`` or ``meraki`` (already raised by the Meraki alerts)."""
    if await _meraki_alert_already_raised(t):
        return "meraki"
    return await deliver_alert(
        host_id=t.get("host_id"),
        name=t["name"],
        alert_type=ALERT_TYPE,
        metric=f"topology {t['entity_type']}",
        message=_message(t),
        severity="critical" if t["new_state"] == "down" else "warning",
        dedup_key=dedup_key(t),
    )


async def _raise_failover(t: dict) -> str:
    """Raise the alert of one failover (``failovers``): a warning, through
    the same path as a state alert. Returns how (see ``deliver_alert``)."""
    return await deliver_alert(
        host_id=t.get("host_id"),
        name=t["name"],
        alert_type=ALERT_TYPE,
        metric="topology failover",
        message=_failover_message(t),
        severity="warning",
        dedup_key=failover_dedup_key(t, t["new_role"]),
    )


async def _stored_roles(provider: str, org_ref: int, entities: list[dict]) -> list[dict]:
    """The stored state rows ``failovers`` compares with: only read when
    the collection reports a role-tracked entity. Never raises (``[]``:
    no failover is detected this time)."""
    if not any("role" in (e.get("meta") or {}) for e in entities):
        return []
    try:
        return await db.list_topology_entity_states(provider, org_ref)
    except Exception as exc:  # noqa: BLE001 - best effort
        LOGGER.warning("topology availability: stored roles not read: %s", type(exc).__name__)
        return []


async def _mute_index(provider: str | None = None, org_ref: int | None = None) -> db.TopologyMuteIndex | None:
    """The mutes, or ``None`` when they cannot be read (then nothing is
    treated as muted: an alert too many beats a silenced outage)."""
    try:
        return await db.load_topology_mute_index(provider, org_ref)
    except Exception as exc:  # noqa: BLE001 - best effort
        LOGGER.warning("topology availability: mutes not read: %s", type(exc).__name__)
        return None


async def _record_metrics(provider: str, org_ref: int, entities: list[dict], now: str | None) -> int:
    """Store the latency / jitter / loss and traffic rates the snapshot
    reported for its entities (``EntityState.metrics``; a rate was put on
    the snapshot when it was stored, ``integrations.traffic``). Never
    raises."""
    samples = [e for e in entities if e.get("metrics")]
    if not samples:
        return 0
    try:
        return await db.record_topology_entity_metrics(provider, org_ref, samples, now=now)
    except Exception as exc:  # noqa: BLE001 - the collection is already stored
        LOGGER.warning(
            "topology availability: %s org %s metrics not recorded: %s", provider, org_ref, type(exc).__name__
        )
        return 0


async def record_snapshot_states(
    provider: str,
    org_ref: int,
    snapshot: dict | None,
    *,
    snapshot_ref: str = "",
    now: str | None = None,
) -> dict[str, Any]:
    """Track the availability of everything ``snapshot`` reports. An entity
    the snapshot no longer reports is deleted when the collection proves it
    is gone (``clean_entity_types``). Never raises."""
    clean = clean_entity_types(provider, snapshot)
    try:
        snapshot = snapshot or {}
        entities = [e.as_dict() for e in extract_entity_states(provider, org_ref, snapshot)]
        # The roles as they were, before this collection overwrites them.
        roles_before = await _stored_roles(provider, org_ref, entities)
        result = await db.apply_topology_entity_states(
            provider,
            org_ref,
            entities,
            org_name=str((snapshot.get("org") or {}).get("name") or ""),
            snapshot_ref=snapshot_ref,
            now=now,
            clean_types=clean,
        )
    except Exception as exc:  # noqa: BLE001 - the collection is already stored
        LOGGER.warning("topology availability: %s org %s not recorded: %s", provider, org_ref, type(exc).__name__)
        return {
            "tracked": 0,
            "transitions": [],
            "alerts": [],
            "recoveries": [],
            "alerted": 0,
            "muted_alerts": 0,
            "removed": 0,
            "failovers": [],
        }
    await _record_metrics(provider, org_ref, entities, now)
    removed = await finish_removal(result["removed"])
    if "device" in clean:
        await _drop_site_mutes_of_gone_sites(provider, org_ref, snapshot)
    alerted = muted = 0
    changes = failovers(entities, roles_before)
    index = await _mute_index(provider, org_ref) if result["alerts"] or changes else None
    metas = {(e["entity_type"], e["entity_id"]): e.get("meta") or {} for e in entities} if index else {}
    for t in result["alerts"]:
        if index and index.match({**t, "meta": metas.get((t["entity_type"], t["entity_id"]), {})}):
            # Muted: the transition and alert_state are stored; nothing is raised.
            muted += 1
            continue
        try:
            await _raise_alert(t)
            alerted += 1
        except Exception as exc:  # noqa: BLE001 - delivery must never break the collection
            LOGGER.warning("topology availability: alert for %s failed: %s", dedup_key(t), type(exc).__name__)
    org_name = str((snapshot.get("org") or {}).get("name") or "")
    for change in changes:
        LOGGER.info(
            "topology availability: %s failed over (%s -> %s)",
            dedup_key(change),
            change["old_role"],
            change["new_role"],
        )
        if index and index.match(change):
            muted += 1
            continue
        try:
            await _raise_failover({**change, "org_name": org_name})
            alerted += 1
        except Exception as exc:  # noqa: BLE001 - delivery must never break the collection
            LOGGER.warning(
                "topology availability: failover alert for %s failed: %s", dedup_key(change), type(exc).__name__
            )
    for t in result["recoveries"]:
        LOGGER.info("topology availability: %s recovered (%s -> up)", dedup_key(t), t["old_state"])
    if result["transitions"]:
        LOGGER.info(
            "topology availability: %s org %s: %s entities, %s change(s), %s alert(s)",
            provider,
            org_ref,
            result["tracked"],
            sum(1 for t in result["transitions"] if not t["baseline"]),
            alerted,
        )
    return {**result, "alerted": alerted, "muted_alerts": muted, "removed": removed, "failovers": changes}


# ── Mutes ────────────────────────────────────────────────────────────────────

MUTED_BY = "muted"


async def mute_entities(mute: dict) -> int:
    """After ``mute`` was created: acknowledge as ``muted`` the open alerts of
    every entity of its source the mutes now cover (the tracker's ``topo:``
    alerts and, for Meraki, the open Meraki alerts of those devices and
    networks). Returns how many monitoring alerts were acknowledged."""
    provider, org_ref = str(mute["provider"]), int(mute["org_ref"])
    index = await db.load_topology_mute_index(provider, org_ref)
    acknowledged = 0
    for row in await db.list_topology_entity_states(provider, org_ref):
        if index.match(row):
            for key in alert_keys(row):
                acknowledged += await db.resolve_monitoring_alerts(key, MUTED_BY)
    if provider == "meraki":
        # Imported here: meraki_alerts imports this package's routes.
        from netcontrol.routes import meraki_alerts

        async with meraki_alerts._APPLY_LOCK:
            for alert in await db.list_meraki_alerts(org_ref=org_ref, limit=5000):
                if not meraki_alerts._muted(alert, index):
                    continue
                key = str(alert["alert_key"])
                acknowledged += await db.resolve_monitoring_alerts(meraki_alerts.dedup_key(key), MUTED_BY)
                await db.set_meraki_alert_raised(key, str(alert.get("severity") or ""), MUTED_BY, alert.get("host_id"))
    return acknowledged


# ── Removal ──────────────────────────────────────────────────────────────────


async def finish_removal(rows: list[dict]) -> int:
    """After entities were deleted because the vendor no longer has them:
    acknowledge their open alerts as ``auto-resolved``. Sends no
    notification. Returns the number of entities removed."""
    for row in rows:
        # The state alert is open only with an alert_state; a failover
        # alert may be open whatever the state.
        keys = alert_keys(row)[0 if row.get("alert_state") else 1 :]
        try:
            for key in keys:
                await db.resolve_monitoring_alerts(key, "auto-resolved")
        except Exception as exc:  # noqa: BLE001 - best effort
            LOGGER.warning("topology availability: clearing %s failed: %s", dedup_key(row), type(exc).__name__)
    if rows:
        LOGGER.info("topology availability: %s entities removed (gone at the vendor)", len(rows))
    return len(rows)


async def _drop_site_mutes_of_gone_sites(provider: str, org_ref: int, snapshot: dict) -> None:
    """Delete the site mutes of sites the snapshot's site list no longer has
    (named as ``extract_entity_states`` names them: name, else id)."""
    names = [
        str(site.get("name") or "").strip() or str(site.get("id") or "").strip()
        for site in snapshot.get("sites") or []
        if isinstance(site, dict)
    ]
    try:
        await db.delete_topology_site_mutes_except(provider, org_ref, names)
    except Exception as exc:  # noqa: BLE001 - best effort
        LOGGER.warning("topology availability: site mutes not pruned: %s", type(exc).__name__)


# ── Dashboard ────────────────────────────────────────────────────────────────

# Most entities have no inventory host, so they never become a monitoring
# alert; the Dashboard lists the worst of them next to the host alerts.
DASHBOARD_PROBLEM_LIMIT = 50
_COUNTED_STATES = ("up", "degraded", "down", "unknown")
_PROBLEM_STATES = ("down", "degraded")


def _state_counts() -> dict[str, int]:
    return dict.fromkeys((*_COUNTED_STATES, "muted"), 0)


async def dashboard_topology_summary(limit: int = DASHBOARD_PROBLEM_LIMIT) -> dict[str, Any]:
    """The current state of every tracked entity, for ``GET /api/dashboard``:
    counts in total, per provider and per source and entity type
    (``by_source``: one ``{provider, org_ref, entity_type, up, degraded,
    down, unknown, muted}`` row per type a source has, for the Dashboard's
    integration cards), and the down / degraded entities (down first, the
    most recent change first, at most ``limit``). A muted entity that is
    down or degraded is counted under ``muted`` instead and is no problem;
    one that is up or unknown is counted under its state. The AWS, Azure and
    GCP accounts of one cloud share one ``org_ref``: their discoveries are
    recorded as one snapshot per cloud."""
    totals = _state_counts()
    by_provider: dict[str, dict[str, int]] = {}
    by_source: dict[tuple[str, int, str], dict[str, int]] = {}
    for row in await db.count_topology_entity_states():
        state = row["state"] if row["state"] in _COUNTED_STATES else "unknown"
        totals[state] += row["count"]
        by_provider.setdefault(row["provider"], _state_counts())[state] += row["count"]
        key = (row["provider"], row["org_ref"], row["entity_type"])
        by_source.setdefault(key, _state_counts())[state] += row["count"]
    index = await _mute_index()
    if index:
        problems = []
        for row in await db.list_topology_entity_states(states=_PROBLEM_STATES, worst_first=True):
            if not index.match(row):
                problems.append(row)
                continue
            for counts in (
                totals,
                by_provider.setdefault(row["provider"], _state_counts()),
                by_source.setdefault((row["provider"], row["org_ref"], row["entity_type"]), _state_counts()),
            ):
                counts[row["state"]] -= 1
                counts["muted"] += 1
        problems = problems[: max(0, int(limit))]
    else:
        problems = await db.list_topology_entity_states(states=_PROBLEM_STATES, worst_first=True, limit=limit)
    return {
        "entity_counts": {**totals, "total": sum(totals.values())},
        "by_provider": by_provider,
        "by_source": [
            {"provider": provider, "org_ref": org_ref, "entity_type": entity_type, **counts}
            for (provider, org_ref, entity_type), counts in sorted(by_source.items())
        ],
        "problem_count": totals["down"] + totals["degraded"],
        "problems": [
            {
                "provider": row["provider"],
                "provider_label": PROVIDER_LABELS.get(row["provider"], row["provider"]),
                "org_ref": row["org_ref"],
                "org_name": row.get("org_name") or "",
                "entity_type": row["entity_type"],
                "type_label": TYPE_LABELS.get(row["entity_type"], row["entity_type"]),
                "entity_id": row["entity_id"],
                "name": row.get("name") or row["entity_id"],
                "site": row.get("site") or "",
                "host_id": row.get("host_id"),
                "state": row["state"],
                "raw_status": row.get("raw_status") or "",
                "since": row.get("state_since") or None,
            }
            for row in problems
        ],
    }
