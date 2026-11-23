"""Azure alerts for the vendor alert feed (``netcontrol.routes.azure_alerts``):
the mapping of Azure Monitor fired alerts and Resource Health availability
statuses to alert events. Pure: the provider makes the ARM calls and hands
the answers here; the tests hand the invented answers of ``azure.sample``.

Sources, with the Azure REST API reference (``azure-rest-api-specs``) each
field is read from:

- **Azure Monitor alerts** (Alerts Management, ``Alerts_GetAll``:
  ``GET /subscriptions/{id}/providers/Microsoft.AlertsManagement/alerts``,
  api-version ``2019-03-01``, with ``monitorCondition=Fired``,
  ``timeRange=30d`` (the default is one day) and ``pageCount`` (1 to 250);
  ``nextLink`` paging). Per alert ``id`` and ``properties.essentials``:
  ``severity`` (``Sev0`` highest to ``Sev4`` lowest), ``signalType``
  (``Metric`` / ``Log`` / ``Unknown``), ``alertState`` (``New`` /
  ``Acknowledged`` / ``Closed``, set by a user), ``monitorCondition``
  (``Fired`` / ``Resolved``: whether the rule's condition holds),
  ``monitorService`` (``Platform``, ``Log Analytics``, ``ActivityLog
  Administrative``, ``ServiceHealth``, ``Resource Health``...),
  ``targetResource`` (the full ARM ID of the resource the alert fired on),
  ``targetResourceName``, ``targetResourceType``, ``targetResourceGroup``,
  ``alertRule``, ``startDateTime``, ``lastModifiedDateTime``,
  ``monitorConditionResolvedDateTime`` and ``description``; the alert's
  ``name`` is the rule's name. A fired alert is open until its monitor
  condition is ``Resolved`` or a user closes it.
- **Resource Health** (``AvailabilityStatuses_ListBySubscriptionId``:
  ``GET /subscriptions/{id}/providers/Microsoft.ResourceHealth/
  availabilityStatuses``, api-version ``2025-05-01``; ``nextLink``
  paging; "the current availability status for all the resources in the
  subscription"). Per status ``id`` (the resource's ARM ID followed by
  ``/providers/Microsoft.ResourceHealth/availabilityStatuses/current``),
  ``properties.availabilityState`` (``Available`` / ``Unavailable`` /
  ``Degraded`` / ``Unknown``), ``title``, ``summary``, ``reasonType``,
  ``reasonChronicity``, ``occuredTime`` (the last change of the health
  status), ``reportedTime``, ``resolutionETA``.

Each alert names the tracked entity of its resource when the topology
availability tracker follows it (``cloud_alerts.match_entity``: a VM is the
device ``vm:<subscription>:<group>:<name>``, a VPN gateway ``vng:...``, a
load balancer the service ``azure:load_balancer:...``), else it is a
subscription-level alert.
"""

from __future__ import annotations

from typing import Any

from netcontrol.integrations.azure.collect import resource_uid, rid_of
from netcontrol.integrations.cloud_alerts import (
    alert_event,
    key_part,
    match_entity,
    scope_prefix,
    text,
    utc_text,
)

PROVIDER = "azure"
PART_MONITOR = "monitor_alerts"
PART_HEALTH = "resource_health"
PARTS: tuple[tuple[str, str], ...] = (
    (PART_MONITOR, "Azure Monitor fired alerts (metric, log, activity log, Resource Health alert rules)"),
    (PART_HEALTH, "Resource Health: resources Unavailable or Degraded"),
)
ARM_HOST = "management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"
ALERTS_API_VERSION = "2019-03-01"
RESOURCE_HEALTH_API_VERSION = "2025-05-01"
ALERTS_PAGE_COUNT = 250
ALERTS_TIME_RANGE = "30d"

# Severity of an Azure Monitor alert: Sev0 (critical) and Sev1 (error) are
# critical, Sev2 (warning) a warning, Sev3 (informational) and Sev4
# (verbose) are listed only.
SEVERITY_MAP = {"Sev0": "critical", "Sev1": "critical", "Sev2": "warning", "Sev3": "info", "Sev4": "info"}
# Resource Health: ``Unknown`` (no health signal) neither opens nor
# resolves an alert; ``Available`` resolves it.
HEALTH_SEVERITY = {"Unavailable": "critical", "Degraded": "warning"}
HEALTH_UNDETERMINED = "Unknown"
_HEALTH_SUFFIX = "/providers/microsoft.resourcehealth/availabilitystatuses/current"

# Snapshot node prefix of each Cloud Visibility kind the map draws as a
# device (``azure.normalize``: ``vm:<sub>:<group>:<name>``...).
_DEVICE_PREFIX = {
    "vm": "vm",
    "nat_gateway": "nat",
    "firewall": "fw",
    "virtual_network_gateway": "vng",
    "expressroute": "er",
    "local_network_gateway": "lng",
}


def alerts_path(subscription_id: str) -> str:
    return (
        f"/subscriptions/{subscription_id}/providers/Microsoft.AlertsManagement/alerts"
        f"?api-version={ALERTS_API_VERSION}&monitorCondition=Fired&timeRange={ALERTS_TIME_RANGE}"
        f"&pageCount={ALERTS_PAGE_COUNT}"
    )


def resource_health_path(subscription_id: str) -> str:
    return (
        f"/subscriptions/{subscription_id}/providers/Microsoft.ResourceHealth/availabilityStatuses"
        f"?api-version={RESOURCE_HEALTH_API_VERSION}"
    )


def candidates(resource_id: Any) -> list[str]:
    """The entity ids an ARM resource ID may have on the map: its Cloud
    Visibility uid (a service) and, for a kind drawn as a device, its node id."""
    uid = resource_uid(text(resource_id, 1000))
    if not uid:
        return []
    kind = uid.split(":", 2)[1]
    found = [uid]
    if kind in _DEVICE_PREFIX:
        found.append(f"{_DEVICE_PREFIX[kind]}:{rid_of(uid)}")
    return found


def health_resource_id(status_id: Any) -> str:
    """The ARM ID of the resource an availability status is about."""
    raw = text(status_id, 1000)
    if raw.lower().endswith(_HEALTH_SUFFIX):
        return raw[: -len(_HEALTH_SUFFIX)]
    return raw


def _resource_name(resource_id: str) -> str:
    return resource_id.rstrip("/").rsplit("/", 1)[-1]


def monitor_alert_events(
    account_id: int, account_name: str, subscription_id: str, alerts: list[dict], index: dict[str, dict]
) -> list[dict]:
    """The open alert of every fired, not closed Azure Monitor alert."""
    prefix = scope_prefix(PROVIDER, account_id, PART_MONITOR)
    found: list[dict] = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        essentials = ((alert.get("properties") or {}).get("essentials")) or {}
        if essentials.get("monitorCondition") != "Fired" or essentials.get("alertState") == "Closed":
            continue
        alert_id = text(alert.get("id"), 1000)
        if not alert_id:
            continue
        target = text(essentials.get("targetResource"), 1000)
        entity = match_entity(index, candidates(target)) if target else None
        service = text(essentials.get("monitorService"), 80)
        rule = text(alert.get("name"), 200) or _resource_name(text(essentials.get("alertRule"), 1000))
        severity = text(essentials.get("severity"), 8)
        found.append(
            alert_event(
                key=prefix + key_part(alert_id.rsplit("/", 1)[-1]),
                org_ref=0,
                org_name=account_name,
                condition="azure_monitor_alert",
                title=rule or "Azure Monitor alert",
                message=text(essentials.get("description")) or f"{severity} {service} alert".strip(),
                severity=SEVERITY_MAP.get(severity, "warning"),
                started_at=utc_text(essentials.get("startDateTime")),
                event_type="Azure Monitor alert",
                event_sub_type=f"{service} {severity}".strip(),
                entity=entity,
                entity_name=text(essentials.get("targetResourceName"), 200),
                vendor_event_id=alert_id.rsplit("/", 1)[-1],
                detail={
                    "subscription": subscription_id,
                    "severity": severity,
                    "signal_type": essentials.get("signalType"),
                    "alert_state": essentials.get("alertState"),
                    "monitor_service": service,
                    "target_resource": target,
                    "target_type": essentials.get("targetResourceType"),
                    "resource_group": essentials.get("targetResourceGroup"),
                    "rule": essentials.get("alertRule"),
                    "last_modified": utc_text(essentials.get("lastModifiedDateTime")),
                },
            )
        )
    return found


def resource_health_events(
    account_id: int,
    account_name: str,
    subscription_id: str,
    statuses: list[dict],
    index: dict[str, dict],
    now: str,
) -> tuple[list[dict], list[str]]:
    """The open alert of every resource ``Unavailable`` or ``Degraded``, and
    the keys of the resources ``Unknown`` (left as they are)."""
    prefix = scope_prefix(PROVIDER, account_id, PART_HEALTH)
    found: list[dict] = []
    unknown: list[str] = []
    for status in statuses:
        if not isinstance(status, dict):
            continue
        resource_id = health_resource_id(status.get("id"))
        if not resource_id:
            continue
        props = status.get("properties") or {}
        state = text(props.get("availabilityState"), 20)
        key = prefix + key_part(resource_id.lower())
        if state == HEALTH_UNDETERMINED:
            unknown.append(key)
            continue
        severity = HEALTH_SEVERITY.get(state)
        if severity is None:
            continue
        entity = match_entity(index, candidates(resource_id))
        found.append(
            alert_event(
                key=key,
                org_ref=0,
                org_name=account_name,
                condition=f"resource_health_{state.lower()}",
                title=f"Resource Health: {state}",
                message=text(props.get("summary")) or text(props.get("title")) or state,
                severity=severity,
                started_at=utc_text(props.get("occuredTime")) or now,
                event_type="Resource Health",
                event_sub_type=text(props.get("reasonType"), 80) or state,
                entity=entity,
                entity_name=_resource_name(resource_id),
                vendor_event_id=text(props.get("healthEventId"), 200),
                detail={
                    "subscription": subscription_id,
                    "resource": resource_id,
                    "state": state,
                    "title": props.get("title"),
                    "reason": props.get("reasonType"),
                    "chronicity": props.get("reasonChronicity"),
                    "reported": utc_text(props.get("reportedTime")),
                    "resolution_eta": utc_text(props.get("resolutionETA")),
                },
                # The resource is down or degraded: the tracker's entity.
                tracker_scope="entity",
            )
        )
    return found, unknown
