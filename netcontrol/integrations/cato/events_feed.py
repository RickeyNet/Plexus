"""The Cato events feed (``eventsFeed``) read as vendor alerts and security events.

Sources: the Cato GraphQL schema descriptions of ``eventsFeed``, its
``EventsFeedData`` / ``EventsFeedAccountRecords`` / ``EventRecord`` types and
the ``EventFieldName`` / ``EventFeedFilterFieldName`` enums (as published at
api.catonetworks.com/documentation and in Cato's cato-cli repository,
``models/query.eventsFeed.json`` and ``queryPayloads/query.eventsFeed.txt``).

Request: ``eventsFeed(accountIDs, filters, marker)`` returns ``marker``
("the next position in the event queue"), ``fetchedCount`` ("number of event
records returned in this response") and ``accounts { id errorString records
{ time fieldsMap } }``; ``records(fieldNames:)`` limits the fields returned.
Marker: "If omitted or empty, the API returns the current position in the
event queue and may not return any event records"; "Use the marker returned
in the previous response to fetch the next batch"; "The queue retains events
for approximately three days"; "Always use the returned marker as-is"; with
filters, "the marker represents the position where the backend stopped
scanning the queue". Filters: ``fieldName`` ``event_type`` or
``event_sub_type``, ``operator`` ``is`` / ``is_not`` / ``in`` / ``not_in``,
``values`` "must match the exact strings used in the event feed".

Not documented there, so not relied on: the rate limit of ``eventsFeed``,
how the account must be set up for it (Cato's knowledge base describes
enabling the events integration in the management application; the page
could not be read), the key permission it needs, the error an account
without it answers (Plexus shows ``errorString`` / the GraphQL message
as Cato words it) and the exact format of ``EventRecord.time``
(:func:`event_time` takes ISO 8601 text or Unix seconds / milliseconds).

The fields read (``EventFieldName`` with their documented meaning):

  - ``event_type``: "Routing, Security, Connectivity, System or Sockets
    Management event"; ``event_sub_type``: "Sub-type for Routing, Security,
    Connectivity, System or Sockets Management event";
  - ``event_message``: "Cato's description of the event"; ``event_id``:
    "Event Id"; ``internalId``: "Cato Internal-use only" (a fallback key);
  - ``src_site_id``: "Unique internal Cato ID for the site or remote
    user"; ``src_site_name``: "Source site or remote user";
    ``src_is_site_or_vpn``: "Source type: site or remote user";
    ``vpn_user_email``: "User's email address";
  - ``socket_interface``: "Name for Socket interface"; ``socket_serial``:
    "Socket serial number"; ``socket_role``: "For Socket HA events,
    indicates if the Socket is primary or secondary"; ``link_type``: "Link
    type - Cato, Alt. WAN or LAG"; ``pop_name``: "Name of PoP location";
    ``ISP_name``: "The ISP related to this event"; ``src_isp_ip``: "IP
    address provided by ISP to site or Client";
  - ``link_health_latency`` / ``link_health_jitter`` /
    ``link_health_pkt_loss``: the measurements of a link;
  - ``severity``: "Severity defined for the rule"; ``risk_level``: "(IPS or
    SAM event) Indicates the overall impact of a threat ... Low ... Medium
    ... High"; ``signature_id``: "For IPS and SAM, ID of the IPS
    signature"; ``threat_name``: "For IPS events, explains the reason why
    the traffic was blocked"; ``threat_type``: "Type of malware event";
    ``rule_name``: "Rule name"; ``action``: "Firewall, QoS or LAG action";
  - ``src_ip`` / ``dest_ip`` / ``src_port`` / ``dest_port`` /
    ``ip_protocol`` / ``application_name``: the flow;
  - ``time``: "Time stamp of the event (Linux epoch format)"; ``time_str``:
    the same, human-readable.

The sub-type strings below are the ones the ``event_sub_type`` filter enum
lists. What each one means is read from its name: the schema gives no
description per sub-type, and none was checked against a live account.

Pure: no I/O, so the tests run from the samples in
``netcontrol.integrations.cato.sample``.
"""

from __future__ import annotations

import hashlib
import zlib
from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.traffic import parse_time, store_time

PROVIDER = "cato"
FEED = "events_feed"
# The kind security events of this feed are stored as (the same kind as
# OPNsense's Suricata alerts: an intrusion prevention / detection alert).
SECURITY_KIND = "ids_alert"

EVENTS_FEED_QUERY = """
query plexusEventsFeed($accountIDs: [ID!], $marker: String, $filters: [EventFeedFieldFilterInput!],
                       $fieldNames: [EventFieldName!]) {
  eventsFeed(accountIDs: $accountIDs, marker: $marker, filters: $filters) {
    marker
    fetchedCount
    accounts {
      id
      errorString
      records(fieldNames: $fieldNames) {
        time
        fieldsMap
      }
    }
  }
}
"""

CRITICAL, WARNING, INFO = "critical", "warning", "info"

# How each connectivity sub-type becomes an alert: (condition, state,
# severity, scope). ``state`` ``open`` raises, ``resolved`` is the recovery
# of the same condition, ``once`` is a one-shot event with no recovery (it
# closes after the open TTL). ``scope``: ``site`` (the site), ``link`` (the
# Socket interface named by the event, else the site), ``port`` (a LAN port).
CONNECTIVITY: dict[str, tuple[str, str, str, str]] = {
    "Disconnected": ("disconnected", "open", CRITICAL, "link"),
    "Connected": ("disconnected", "resolved", INFO, "link"),
    "Reconnected": ("disconnected", "resolved", INFO, "link"),
    "Alt. WAN Disconnected": ("alt_wan_disconnected", "open", WARNING, "link"),
    "Alt. WAN Connected": ("alt_wan_disconnected", "resolved", INFO, "link"),
    "HA Not Ready": ("ha_not_ready", "open", WARNING, "site"),
    "HA Ready": ("ha_not_ready", "resolved", INFO, "site"),
    "LAN port disconnected": ("lan_port_disconnected", "open", INFO, "port"),
    "LAN port connected": ("lan_port_disconnected", "resolved", INFO, "port"),
    "Socket Fail-Over": ("socket_failover", "once", WARNING, "site"),
    "Last-Mile Quality": ("last_mile_quality", "once", WARNING, "link"),
}
# Intrusion prevention events (the ``Security`` type's ``IPS`` sub-type).
SECURITY_SUB_TYPES = ("IPS",)
# What the feed is asked for (an ``event_sub_type`` ``in`` filter), so a
# busy account's firewall and traffic events are never downloaded.
SUB_TYPES = (*CONNECTIVITY, *SECURITY_SUB_TYPES)
# Sub-types not mapped, on purpose: ``Passive Connected`` / ``Passive
# Disconnected`` and ``BGP Session`` (their meaning and direction are not
# documented), every other Security sub-type (firewall, anti-malware and
# DNS events are traffic logs, not alerts), System, Routing, Sockets
# Management, Detection and Response and Posture events.

# The fields asked for (``records(fieldNames:)``), every one an
# ``EventFieldName`` value.
FIELD_NAMES = (
    "event_type",
    "event_sub_type",
    "event_message",
    "event_id",
    "internalId",
    "time",
    "time_str",
    "src_site_id",
    "src_site_name",
    "src_is_site_or_vpn",
    "vpn_user_email",
    "socket_interface",
    "socket_serial",
    "socket_role",
    "link_type",
    "pop_name",
    "ISP_name",
    "src_isp_ip",
    "link_health_latency",
    "link_health_jitter",
    "link_health_pkt_loss",
    "severity",
    "risk_level",
    "signature_id",
    "threat_name",
    "threat_type",
    "rule_name",
    "action",
    "src_ip",
    "dest_ip",
    "src_port",
    "dest_port",
    "ip_protocol",
    "application_name",
)
# Copied into an alert's detail (each bounded) when present.
_DETAIL_FIELDS = (
    "event_message",
    "socket_interface",
    "socket_role",
    "link_type",
    "pop_name",
    "ISP_name",
    "src_isp_ip",
    "link_health_latency",
    "link_health_jitter",
    "link_health_pkt_loss",
)
_MAX_TEXT = 300
_MAX_KEY = 128
_BLOCK_ACTIONS = frozenset({"block", "blocked", "prevent", "prevented", "drop", "dropped", "deny", "denied", "reject"})


def variables(account_id: str, marker: str) -> dict[str, Any]:
    """The variables of one ``eventsFeed`` request for one account."""
    return {
        "accountIDs": [str(account_id)],
        "marker": str(marker or ""),
        "filters": [{"fieldName": "event_sub_type", "operator": "in", "values": list(SUB_TYPES)}],
        "fieldNames": list(FIELD_NAMES),
    }


def _text(value: Any, limit: int = _MAX_TEXT) -> str:
    return str(value).strip()[:limit] if value is not None else ""


def parse_page(data: dict | None) -> dict[str, Any]:
    """One ``eventsFeed`` answer as ``{"marker", "fetched", "records",
    "errors"}``: ``records`` the field maps (each with ``time`` from the
    record when its map has none), ``errors`` the non-empty per-account
    ``errorString`` values (bounded)."""
    feed = (data or {}).get("eventsFeed") if isinstance(data, dict) else None
    feed = feed if isinstance(feed, dict) else {}
    try:
        fetched = int(feed.get("fetchedCount") or 0)
    except TypeError, ValueError:
        fetched = 0
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    for account in feed.get("accounts") or []:
        if not isinstance(account, dict):
            continue
        if _text(account.get("errorString")):
            errors.append(_text(account.get("errorString")))
        for record in account.get("records") or []:
            if not isinstance(record, dict):
                continue
            fields = record.get("fieldsMap")
            fields = dict(fields) if isinstance(fields, dict) else {}
            if record.get("time") not in (None, ""):
                fields.setdefault("_record_time", record.get("time"))
            records.append(fields)
    return {"marker": _text(feed.get("marker"), 4096), "fetched": fetched, "records": records, "errors": errors}


def event_time(fields: dict) -> str:
    """When an event happened as UTC ``YYYY-MM-DD HH:MM:SS``, or ``""``:
    the record's ``time``, else the ``time`` field, else ``time_str``.
    ISO 8601 text or Unix seconds / milliseconds."""
    for value in (fields.get("_record_time"), fields.get("time"), fields.get("time_str")):
        text = _text(value, 64)
        if not text:
            continue
        if text.replace(".", "", 1).isdigit():
            number = float(text)
            if number > 1e12:
                number /= 1000.0
            try:
                return store_time(datetime.fromtimestamp(number, UTC))
            except OverflowError, OSError, ValueError:
                continue
        parsed = parse_time(text)
        if parsed is not None:
            return store_time(parsed)
    return ""


def _is_user(fields: dict) -> bool:
    """An event about a remote (SDP) user rather than a site: users come
    and go, which is no outage (the availability tracker skips them too)."""
    if _text(fields.get("vpn_user_email")):
        return True
    kind = _text(fields.get("src_is_site_or_vpn")).lower()
    return bool(kind) and "site" not in kind


def _site(fields: dict) -> tuple[str, str]:
    site_id = _text(fields.get("src_site_id"), 64)
    name = _text(fields.get("src_site_name"), 120)
    return site_id or name, name or site_id


def alert_key(org_ref: int, entity_type: str, entity_id: str, condition: str) -> str:
    """The dedupe key: one alert per (source, entity, condition)."""
    return f"{PROVIDER}:{int(org_ref)}:{entity_type}:{entity_id}:{condition}"[:400]


def alert_event(fields: dict, *, org_ref: int, org_name: str = "") -> dict[str, Any] | None:
    """One connectivity record as a vendor alert event, or ``None`` when it
    is not one this feed maps (an unmapped sub-type, a remote user, no
    site)."""
    sub_type = _text(fields.get("event_sub_type"))
    mapped = CONNECTIVITY.get(sub_type)
    if mapped is None or _is_user(fields):
        return None
    condition, kind, severity, scope = mapped
    site_id, site_name = _site(fields)
    if not site_id:
        return None
    interface = _text(fields.get("socket_interface"), 64)
    if scope == "port" and interface:
        entity_type, entity_id, entity_name = "port", f"{site_id}:{interface}", f"{site_name} {interface}"
    elif scope == "link" and interface:
        entity_type, entity_id, entity_name = "uplink", f"{site_id}:{interface}", f"{site_name} {interface}"
    else:
        entity_type, entity_id, entity_name = "site", site_id, site_name
    # The tracker entities this alert stands for (see routes.vendor_alerts).
    tracker_scope = ""
    if condition in ("disconnected", "alt_wan_disconnected"):
        tracker_scope = "entity" if entity_type == "site" else "site_links"
    if condition == "disconnected" and entity_type == "uplink":
        severity = WARNING  # one link of the site; the site itself is still up
    at = event_time(fields)
    message = _text(fields.get("event_message")) or sub_type
    return {
        "key": alert_key(org_ref, entity_type, entity_id, condition),
        "org_ref": int(org_ref),
        "org_name": _text(org_name, 120),
        "entity_type": entity_type,
        "entity_id": entity_id,
        "entity_name": entity_name,
        "site": site_name,
        "serial": _text(fields.get("socket_serial"), 64).upper(),
        "condition": condition,
        "event_type": _text(fields.get("event_type"), 60),
        "event_sub_type": sub_type,
        "title": sub_type,
        "message": message,
        "severity": severity,
        "state": "resolved" if kind == "resolved" else "open",
        "auto_expire": kind == "once",
        "tracker_scope": tracker_scope,
        "started_at": "" if kind == "resolved" else at,
        "resolved_at": at if kind == "resolved" else "",
        "vendor_event_id": _text(fields.get("event_id"), 64) or _text(fields.get("internalId"), 64),
        "detail": {k: _text(fields.get(k)) for k in _DETAIL_FIELDS if _text(fields.get(k))},
    }


def _int(value: Any) -> int | None:
    text = _text(value, 20)
    return int(text) if text.isdigit() else None


def security_severity(fields: dict) -> str:
    """Plexus severity of an IPS event: its ``risk_level`` (High, Medium,
    Low), else the rule's ``severity`` in the same words; ``unknown``."""
    for value in (fields.get("risk_level"), fields.get("severity")):
        text = _text(value, 20).lower()
        if text in ("high", "critical"):
            return CRITICAL
        if text == "medium":
            return WARNING
        if text in ("low", "info", "informational"):
            return INFO
    return "unknown"


def signature_number(fields: dict) -> int | None:
    """The signature as a number: Cato's ``signature_id`` when it is one,
    else a stable number derived from it (or from ``threat_name``), so the
    events of one signature group into one alert. ``None`` without either."""
    raw = _text(fields.get("signature_id"), 64)
    number = _int(raw)
    if number is not None:
        return number
    basis = raw or _text(fields.get("threat_name"))
    return zlib.crc32(basis.encode("utf-8")) if basis else None


def security_event(fields: dict) -> dict[str, Any] | None:
    """One IPS record as a ``security_events`` row (``kind`` ``ids_alert``)
    with the site it came from (``site_id``, ``site_name``, ``serial``, not
    stored as columns), or ``None`` when it is no IPS event."""
    if _text(fields.get("event_sub_type")) not in SECURITY_SUB_TYPES:
        return None
    at = event_time(fields)
    if not at:
        return None
    site_id, site_name = _site(fields)
    key = _text(fields.get("event_id"), _MAX_KEY) or _text(fields.get("internalId"), _MAX_KEY)
    if not key:
        basis = "|".join(
            _text(fields.get(k)) for k in ("signature_id", "threat_name", "src_ip", "src_port", "dest_ip", "dest_port")
        )
        key = "h:" + hashlib.sha256(f"{at}|{site_id}|{basis}".encode()).hexdigest()[:40]
    action = _text(fields.get("action"), 40)
    return {
        "kind": SECURITY_KIND,
        "event_key": key,
        "occurred_at": at,
        "severity": security_severity(fields),
        "priority": None,
        "signature_id": signature_number(fields),
        "signature": _text(fields.get("threat_name")) or _text(fields.get("event_message")) or "IPS event",
        "category": _text(fields.get("threat_type"), 120) or _text(fields.get("rule_name"), 120),
        "action": ("blocked" if action.lower() in _BLOCK_ACTIONS else "allowed") if action else "",
        "protocol": _text(fields.get("ip_protocol"), 20),
        "src_ip": _text(fields.get("src_ip"), 64),
        "src_port": _int(fields.get("src_port")),
        "dest_ip": _text(fields.get("dest_ip"), 64),
        "dest_port": _int(fields.get("dest_port")),
        "interface": _text(fields.get("socket_interface"), 64),
        "flow_id": "",
        "app_proto": _text(fields.get("application_name"), 60),
        "site_id": site_id,
        "site_name": site_name,
        "serial": _text(fields.get("socket_serial"), 64).upper(),
    }


def classify(records: list[dict], *, org_ref: int, org_name: str = "") -> dict[str, Any]:
    """The records of a page as ``alerts`` (vendor alert events),
    ``security`` (security event rows) and the count of ``ignored``."""
    alerts: list[dict] = []
    security: list[dict] = []
    ignored = 0
    for fields in records:
        alert = alert_event(fields, org_ref=org_ref, org_name=org_name)
        if alert is not None:
            alerts.append(alert)
            continue
        found = security_event(fields)
        if found is not None:
            security.append(found)
            continue
        ignored += 1
    return {"alerts": alerts, "security": security, "ignored": ignored}
