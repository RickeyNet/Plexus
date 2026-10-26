"""Availability tracking of the entities that integrations collect.

``record_snapshot_states`` is called after every stored collection (a Meraki,
Cato, FMC, Panorama or Appgate snapshot, an AWS, Azure or GCP discovery; see
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
that recovers to ``up`` can alert again. An entity seen for the first time
is a baseline and raises nothing. Best-effort throughout: a failure is
logged and never fails the collection.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import routes.database as db

from netcontrol.integrations.availability import extract_entity_states
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
}


def dedup_key(t: dict) -> str:
    return f"topo:{t['provider']}:{t['org_ref']}:{t['entity_type']}:{t['entity_id']}"


def _message(t: dict) -> str:
    where = PROVIDER_LABELS.get(t["provider"], t["provider"])
    if t.get("org_name"):
        where = f"{where} {t['org_name']}"
    site = f" at {t['site']}" if t.get("site") and t["site"] != t.get("name") else ""
    return (
        f"{TYPE_LABELS.get(t['entity_type'], t['entity_type'])} {t['name'] or t['entity_id']}{site} "
        f"({where}) is {t['new_state']} (was {t['old_state']})"
    )


async def _raise_alert(t: dict) -> str:
    """Raise the alert of one transition. Returns how: ``monitoring`` or
    ``notification``."""
    severity = "critical" if t["new_state"] == "down" else "warning"
    message = _message(t)
    metric = f"topology {t['entity_type']}"
    host_id = t.get("host_id")
    if host_id and await db.get_host(int(host_id)):
        await db.create_monitoring_alert(
            host_id=int(host_id),
            poll_id=None,
            alert_type=ALERT_TYPE,
            metric=metric,
            message=message,
            severity=severity,
            dedup_key=dedup_key(t),
            hostname=t["name"],
        )
        return "monitoring"
    event = {
        "alert_id": dedup_key(t),
        "host_id": None,
        "hostname": t["name"],
        "poll_id": None,
        "rule_id": None,
        "alert_type": ALERT_TYPE,
        "metric": metric,
        "message": message,
        "severity": severity,
        "value": None,
        "threshold": None,
        "dedup_key": dedup_key(t),
        "channel_ids": "",
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    await notification_channels.on_alert_created(event)
    return "notification"


async def record_snapshot_states(
    provider: str,
    org_ref: int,
    snapshot: dict | None,
    *,
    snapshot_ref: str = "",
    now: str | None = None,
) -> dict[str, Any]:
    """Track the availability of everything ``snapshot`` reports. Never raises."""
    try:
        snapshot = snapshot or {}
        entities = [e.as_dict() for e in extract_entity_states(provider, org_ref, snapshot)]
        result = await db.apply_topology_entity_states(
            provider,
            org_ref,
            entities,
            org_name=str((snapshot.get("org") or {}).get("name") or ""),
            snapshot_ref=snapshot_ref,
            now=now,
        )
    except Exception as exc:  # noqa: BLE001 - the collection is already stored
        LOGGER.warning("topology availability: %s org %s not recorded: %s", provider, org_ref, type(exc).__name__)
        return {"tracked": 0, "transitions": [], "alerts": [], "recoveries": [], "alerted": 0}
    alerted = 0
    for t in result["alerts"]:
        try:
            await _raise_alert(t)
            alerted += 1
        except Exception as exc:  # noqa: BLE001 - delivery must never break the collection
            LOGGER.warning("topology availability: alert for %s failed: %s", dedup_key(t), type(exc).__name__)
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
    return {**result, "alerted": alerted}
