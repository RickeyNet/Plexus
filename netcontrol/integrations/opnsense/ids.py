"""OPNsense intrusion detection (Suricata) alerts: what is read and how a row
becomes a security event. Pure: no database, no network.

The calls (``collector.collect_ids_alerts`` makes them, every path under
``/api``; checked against opnsense/core ``IDS/Api/ServiceController.php``,
``IDS/Api/SettingsController.php``, ``scripts/suricata/queryAlertLog.py``
and the ``IDS/ACL/ACL.xml`` privilege, master):

  - ``ids/service/status`` (GET)            ``{"status": "running" |
                                            "stopped" | "disabled" |
                                            "unknown"}``: whether the IDS is
                                            enabled. ``disabled``: nothing
                                            else is read
  - ``ids/service/query_alerts`` (POST,     the alerts of Suricata's
    ``{"rowCount": n, "current": page}``)   ``eve.json``, newest first. The
                                            action reads its parameters with
                                            ``getPost``, so it is a POST that
                                            only reads (no ``fileid``: the
                                            current log only, not the
                                            rotated ones)
  - ``ids/settings/get_rule_info/{sid}``    the installed rule of a
    (GET)                                   signature, for its ``classtype``

All three are granted by the privilege "Services: Intrusion Detection"
(``api/ids/*``). It is the only IDS privilege, so it also grants the IDS
actions that change the firewall; Plexus never calls them (no
``reconfigure``, ``update_rules``, ``reload_rules``, ``start``, ``stop``,
``restart``, ``set_rule``, ``toggle_rule`` or ``drop_alert_log``).

A row of ``query_alerts`` is an ``eve.json`` alert record flattened by
``queryAlertLog.py``: ``alert`` is the signature text, ``alert_sid`` its
signature id, ``alert_action`` ``allowed`` or ``blocked`` (IPS mode), next
to ``timestamp``, ``flow_id``, ``in_iface``, ``src_ip``, ``src_port``,
``dest_ip``, ``dest_port``, ``proto``, ``app_proto``, ``filepos``. The
flattening drops the record's ``alert.category`` and ``alert.severity``:
the category is the rule's ``classtype`` (``get_rule_info``) and its
priority comes from Suricata's default ``classification.config``
(``CLASSTYPE_PRIORITY``). A row that still carries the ``alert`` object of
the record keeps its own ``severity`` and ``category``.

Bounds: ``IDS_PAGE_ROWS`` rows per page, ``IDS_MAX_PAGES`` pages per read
(only the alerts newer than the newest one stored are read: the pages stop
at the first older row) and ``IDS_MAX_RULE_LOOKUPS`` rule lookups per read.
Every text field comes from network traffic or rule files: it is cut to a
bound and stripped of control characters here, before it is stored.
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime
from typing import Any

from netcontrol.integrations.traffic import parse_time, store_time

PATH_IDS_STATUS = ("ids/service/status",)
PATH_IDS_ALERTS = ("ids/service/query_alerts", "ids/service/queryAlerts")
PATH_IDS_RULE_INFO = ("ids/settings/get_rule_info/", "ids/settings/getRuleInfo/")
IDS_PRIVILEGE = "Services: Intrusion Detection"

# Rows asked for per page, pages per read, rule lookups per read.
IDS_PAGE_ROWS = 200
IDS_MAX_PAGES = 5
IDS_MAX_RULE_LOOKUPS = 20

# What ``ids/service/status`` answers when the IDS is off in its settings.
STATUS_DISABLED = "disabled"
# Plexus' own status of a firewall whose API has no IDS endpoint (404).
STATUS_UNAVAILABLE = "unavailable"

KIND_IDS_ALERT = "ids_alert"

# The fields kept of a row (the record may carry payloads, HTTP and TLS
# details); each string value cut to ``_RAW_TEXT_MAX``.
_ROW_KEPT = (
    "timestamp",
    "alert",
    "alert_sid",
    "alert_action",
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "proto",
    "in_iface",
    "flow_id",
    "app_proto",
)
_ALERT_KEPT = ("signature", "signature_id", "action", "category", "severity")
_RAW_TEXT_MAX = 512

# Bounds of the stored text fields.
SIGNATURE_MAX = 300
CATEGORY_MAX = 120
SHORT_MAX = 40

# Suricata's default classification.config (OISF/suricata etc/), which the
# ET Open and Snort rule sets use: classtype -> priority (1 is the worst).
CLASSTYPE_PRIORITY: dict[str, int] = {
    "not-suspicious": 3,
    "unknown": 3,
    "bad-unknown": 2,
    "attempted-recon": 2,
    "successful-recon-limited": 2,
    "successful-recon-largescale": 2,
    "attempted-dos": 2,
    "successful-dos": 2,
    "attempted-user": 1,
    "unsuccessful-user": 1,
    "successful-user": 1,
    "attempted-admin": 1,
    "successful-admin": 1,
    "rpc-portmap-decode": 2,
    "shellcode-detect": 1,
    "string-detect": 3,
    "suspicious-filename-detect": 2,
    "suspicious-login": 2,
    "system-call-detect": 2,
    "tcp-connection": 4,
    "trojan-activity": 1,
    "unusual-client-port-connection": 2,
    "network-scan": 3,
    "denial-of-service": 2,
    "non-standard-protocol": 2,
    "protocol-command-decode": 3,
    "web-application-activity": 2,
    "web-application-attack": 1,
    "misc-activity": 3,
    "misc-attack": 2,
    "icmp-event": 3,
    "inappropriate-content": 1,
    "policy-violation": 1,
    "default-login-attempt": 2,
    "targeted-activity": 1,
    "exploit-kit": 1,
    "external-ip-check": 2,
    "domain-c2": 1,
    "pup-activity": 2,
    "credential-theft": 1,
    "social-engineering": 2,
    "coin-mining": 2,
    "command-and-control": 1,
}

SEVERITY_CRITICAL = "critical"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"
SEVERITY_UNKNOWN = "unknown"


def clean_text(value: Any, limit: int) -> str:
    """``value`` as text without control characters, cut to ``limit``."""
    text = "" if value is None else str(value)
    return "".join(ch if ch.isprintable() else " " for ch in text[: limit * 2]).strip()[:limit]


def _keep(value: Any) -> Any:
    if isinstance(value, str):
        return value[:_RAW_TEXT_MAX]
    if isinstance(value, bool) or value is None or isinstance(value, int | float):
        return value
    return str(value)[:_RAW_TEXT_MAX]


def keep_row(row: dict) -> dict[str, Any]:
    """A ``query_alerts`` row with only ``_ROW_KEPT`` (and the ``alert``
    object's ``_ALERT_KEPT`` when the row still has it), strings bounded."""
    kept: dict[str, Any] = {}
    for key in _ROW_KEPT:
        if key not in row:
            continue
        value = row[key]
        if key == "alert" and isinstance(value, dict):
            kept[key] = {k: _keep(value.get(k)) for k in _ALERT_KEPT if k in value}
        else:
            kept[key] = _keep(value)
    return kept


def alert_rows(body: Any) -> list[dict[str, Any]]:
    """The rows of a ``query_alerts`` answer, kept (``keep_row``)."""
    rows = body.get("rows") if isinstance(body, dict) else None
    return [keep_row(r) for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def row_time(row: dict) -> datetime | None:
    """When an alert row was logged (its ``timestamp``), or ``None``."""
    return parse_time(row.get("timestamp"))


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except TypeError, ValueError:
        return None


def row_sid(row: dict) -> int | None:
    """The signature id of an alert row."""
    alert = row.get("alert")
    if isinstance(alert, dict):
        return _int(alert.get("signature_id"))
    return _int(row.get("alert_sid"))


def rule_classtype(body: Any) -> str:
    """The ``classtype`` of a ``get_rule_info`` answer ("" when it has none:
    an unknown signature answers an empty list)."""
    found = body.get("classtype") if isinstance(body, dict) else None
    text = clean_text(found, CATEGORY_MAX).lower()
    return "" if text in ("", "##none##") else text


def priority_severity(priority: int | None) -> str:
    """``critical`` for priority 1, ``warning`` for 2, ``info`` for 3 and
    up, ``unknown`` without one."""
    if priority is None or priority < 1:
        return SEVERITY_UNKNOWN
    if priority == 1:
        return SEVERITY_CRITICAL
    if priority == 2:
        return SEVERITY_WARNING
    return SEVERITY_INFO


def _address(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def _port(value: Any) -> int | None:
    port = _int(value)
    return port if port is not None and 0 <= port <= 65535 else None


def _action(value: Any) -> str:
    text = clean_text(value, SHORT_MAX).lower()
    return text or "allowed"


def event_key(row: dict) -> str:
    """A stable key of one alert: the same alert read twice (an overlapping
    page, the poll and a collection) has the same key."""
    parts = (
        row.get("timestamp"),
        row.get("flow_id"),
        row_sid(row),
        row.get("src_ip"),
        row.get("src_port"),
        row.get("dest_ip"),
        row.get("dest_port"),
        row.get("proto"),
    )
    return hashlib.sha256("|".join("" if p is None else str(p) for p in parts).encode()).hexdigest()


def alert_event(row: dict, classtypes: dict[int, str]) -> dict[str, Any] | None:
    """The security event of one kept alert row (``keep_row``), or ``None``
    when it has no time or no signature id. ``classtypes``: sid -> the
    rule's classtype."""
    at = row_time(row)
    sid = row_sid(row)
    if at is None or sid is None:
        return None
    alert = row.get("alert")
    signature = alert.get("signature") if isinstance(alert, dict) else alert
    action = alert.get("action") if isinstance(alert, dict) else None
    category = clean_text(alert.get("category"), CATEGORY_MAX) if isinstance(alert, dict) else ""
    priority = _int(alert.get("severity")) if isinstance(alert, dict) else None
    if not category:
        category = classtypes.get(sid, "")
    if priority is None and category:
        priority = CLASSTYPE_PRIORITY.get(category.lower())
    return {
        "kind": KIND_IDS_ALERT,
        "event_key": event_key(row),
        "occurred_at": store_time(at),
        "signature_id": sid,
        "signature": clean_text(signature, SIGNATURE_MAX),
        "category": category,
        "priority": priority,
        "severity": priority_severity(priority),
        "action": _action(action if action is not None else row.get("alert_action")),
        "protocol": clean_text(row.get("proto"), SHORT_MAX).upper(),
        "src_ip": _address(row.get("src_ip")),
        "src_port": _port(row.get("src_port")),
        "dest_ip": _address(row.get("dest_ip")),
        "dest_port": _port(row.get("dest_port")),
        "interface": clean_text(row.get("in_iface"), SHORT_MAX).lstrip("^"),
        "flow_id": clean_text(row.get("flow_id"), SHORT_MAX),
        "app_proto": clean_text(row.get("app_proto"), SHORT_MAX),
    }


def alert_events(ids: dict | None, known: dict[int, str] | None = None) -> list[dict[str, Any]]:
    """The security events of an IDS read (``collector.collect_ids_alerts``),
    oldest first, one per event key. ``known``: the classtypes already
    stored (sid -> classtype), completed by the ones the read looked up."""
    if not isinstance(ids, dict):
        return []
    classtypes = {**(known or {})}
    for sid, classtype in (ids.get("classtypes") or {}).items():
        number = _int(sid)
        if number is not None and classtype:
            classtypes[number] = str(classtype)
    events: dict[str, dict[str, Any]] = {}
    for row in ids.get("rows") or []:
        if isinstance(row, dict):
            event = alert_event(row, classtypes)
            if event is not None:
                events.setdefault(event["event_key"], event)
    return sorted(events.values(), key=lambda e: e["occurred_at"])
