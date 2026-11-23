"""Shared by the AWS and Azure alert feeds (``netcontrol.integrations.aws.alerts``,
``netcontrol.integrations.azure.alerts``): the alert key of a scope, the
alert event shape of the vendor alert pipeline (``netcontrol.routes.
vendor_alerts``), times, bounded text and the match of a cloud resource to
the entity the topology availability tracker follows for it.

Pure: no database, no network, no SDK.

Both clouds are read as *current state* (what is wrong now): each read of
one scope (an account's region and part, a subscription's part) returns the
complete open set of that scope, and the pipeline resolves a stored alert of
the scope the read no longer reports. Every key therefore starts with its
scope's prefix (:func:`scope_prefix`).
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.traffic import parse_time, store_time

# The longest vendor identifier kept in a key as is; a longer one (an AWS
# Health event ARN with an entity, an Azure resource ID) is hashed, so the
# key (and the monitoring alert's dedup key built from it) stays short.
MAX_KEY_PART = 160
MAX_TEXT = 500
MAX_DETAIL_VALUE = 300
MAX_DETAIL_ITEMS = 20

SEVERITIES = ("critical", "warning", "info")


def text(value: Any, limit: int = MAX_TEXT) -> str:
    """``value`` as stripped text with collapsed whitespace, at most ``limit``
    characters. Shown as text only (never as HTML)."""
    found = " ".join(str(value if value is not None else "").split())
    return found if len(found) <= limit else found[: limit - 3] + "..."


def utc_text(value: Any) -> str:
    """A vendor time (a ``datetime`` from boto3, ISO 8601 text from ARM,
    possibly with seven fractional digits) as the store's UTC
    ``YYYY-MM-DD HH:MM:SS``; ``""`` when it is none."""
    if isinstance(value, datetime):
        return store_time(value if value.tzinfo else value.replace(tzinfo=UTC))
    raw = text(value, 64)
    if not raw:
        return ""
    # ARM writes up to seven fractional digits; ``fromisoformat`` reads six.
    head, dot, tail = raw.partition(".")
    if dot:
        digits = len(tail) - len(tail.lstrip("0123456789"))
        raw = head + "." + tail[: min(digits, 6)] + tail[digits:] if digits else head + tail
    parsed = parse_time(raw)
    return store_time(parsed) if parsed is not None else ""


def scope_prefix(provider: str, account_id: int, part: str, scope: str = "") -> str:
    """The key prefix of one scope: ``aws:12:cloudwatch:us-east-1:``. Every
    key of the scope starts with it (see the module docstring)."""
    return f"{provider}:{int(account_id)}:{part}:" + (f"{scope}:" if scope else "")


def key_part(value: Any) -> str:
    """A vendor identifier as part of a key: kept when short, else hashed."""
    raw = str(value if value is not None else "").strip()
    if len(raw) <= MAX_KEY_PART:
        return raw
    return "h:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:40]


def bounded_detail(detail: dict[str, Any]) -> dict[str, Any]:
    """A small, credential-free detail: text values bounded, lists cut to
    ``MAX_DETAIL_ITEMS``, empty values dropped. The callers put only the
    vendor's description of the alert in it."""
    out: dict[str, Any] = {}
    for name, value in detail.items():
        if value is None or value == "" or value == [] or value == {}:
            continue
        if isinstance(value, bool | int | float):
            out[name] = value
        elif isinstance(value, list | tuple):
            out[name] = [text(v, MAX_DETAIL_VALUE) for v in list(value)[:MAX_DETAIL_ITEMS]]
        else:
            out[name] = text(value, MAX_DETAIL_VALUE)
    return out


def alert_event(
    *,
    key: str,
    org_ref: int,
    org_name: str,
    condition: str,
    title: str,
    severity: str,
    started_at: str,
    message: str = "",
    event_type: str = "",
    event_sub_type: str = "",
    entity: dict | None = None,
    entity_name: str = "",
    vendor_event_id: str = "",
    detail: dict[str, Any] | None = None,
    tracker_scope: str = "",
) -> dict[str, Any]:
    """One open alert event in the shape ``vendor_alerts.ingest`` takes.
    ``entity`` is the tracked entity it names (:func:`match_entity`), or
    ``None`` for an account-level alert; ``tracker_scope`` is kept only
    with an entity."""
    found = entity or {}
    return {
        "key": key,
        "state": "open",
        # Read as open now (not a past event): a resolved row opens again
        # even when the condition began before it was resolved.
        "observed": True,
        "org_ref": int(org_ref),
        "org_name": text(org_name, 120),
        "entity_type": str(found.get("entity_type") or ""),
        "entity_id": str(found.get("entity_id") or ""),
        "entity_name": text(found.get("name") or entity_name, 200),
        "site": text(found.get("site") or "", 200),
        "serial": "",
        "condition": text(condition, 80),
        "event_type": text(event_type, 80),
        "event_sub_type": text(event_sub_type, 120),
        "title": text(title, 200),
        "message": text(message),
        "severity": severity if severity in SEVERITIES else "warning",
        "started_at": started_at,
        "auto_expire": False,
        "tracker_scope": tracker_scope if found else "",
        "vendor_event_id": text(vendor_event_id, 200),
        "detail": bounded_detail(detail or {}),
    }


def entity_index(tracked: list[dict]) -> dict[str, dict]:
    """The tracked devices and services of a cloud by their entity id
    (lower case: AWS ids are lower case, Azure IDs are case-insensitive)."""
    return {
        str(t.get("entity_id") or "").lower(): t
        for t in tracked
        if t.get("entity_type") in ("device", "service") and t.get("entity_id")
    }


def match_entity(index: dict[str, dict], candidates: list[str]) -> dict | None:
    """The first tracked entity whose id is one of ``candidates`` (the ids
    the topology snapshot may give the resource: a device node id such as
    ``i:i-0abc`` or ``vm:<sub>:<group>:<name>``, a service's resource uid
    such as ``aws:rds_instance:db1``), else ``None``."""
    for candidate in candidates:
        found = index.get(str(candidate or "").lower())
        if found is not None:
            return found
    return None


def service_match(index: dict[str, dict], provider: str, resource_id: str) -> dict | None:
    """A tracked service whose resource uid (``<provider>:<type>:<id>``)
    ends with ``resource_id``: how an AWS dimension value or Health entity
    (a DB identifier, a load balancer ARN) names a managed service."""
    wanted = str(resource_id or "").strip().lower()
    if not wanted:
        return None
    prefix = f"{provider}:"
    for entity_id, entity in sorted(index.items()):
        if entity.get("entity_type") != "service" or not entity_id.startswith(prefix):
            continue
        parts = entity_id.split(":", 2)
        if len(parts) == 3 and parts[2] == wanted:
            return entity
    return None
