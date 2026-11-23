"""Vendor alert feeds: near-real-time alerts read from a vendor's API feed.

A vendor-neutral pipeline over one store (``routes.db.vendor_alerts``,
migration 0132). A *provider* (:class:`FeedProvider`, registered with
:func:`register`) knows how to list its sources and read one page of its
feed from a cursor; everything else is shared:

  - **Poll.** ``_vendor_alert_poll_loop`` in ``netcontrol.app`` calls
    :func:`run_due_cycles` every ``TICK_SECONDS``; each provider whose
    interval (default 60 s, 30 to 3600) has passed and whose polling is on
    gets :func:`run_poll_cycle`. Each source of the provider not opted out
    is polled in turn: at most ``MAX_PAGES_PER_POLL`` pages per cycle, the
    cursor stored after every page once its events are stored (a restart
    neither replays nor skips; a replayed page is deduplicated anyway). A
    source is polled by one app worker at a time (a lease on its feed row,
    ``LEASE_SECONDS``) and once per interval whichever worker does it (its
    stored ``last_poll_at``); a failure backs it off exponentially (an access or
    feed refusal up to hourly, anything else up to ten minutes), stored on
    the feed row so every worker sees it; it never stops the other sources.
    A refusal is logged once when it starts, not every cycle.
  - **Alerts.** :func:`ingest` stores the alert events and raises each new
    warning or critical alert once, server-side: on the inventory host the
    entity matches (by Socket / device serial, else the host the topology
    availability tracker matched to the entity or to a device of its site)
    as a monitoring alert (alert type ``vendor_alert``), otherwise straight
    to the notification channels (``topology_availability.deliver_alert``).
    It is cleared (acknowledged ``auto-resolved``) when its row resolves: a
    recovery event, a one-shot event's open TTL (``open_ttl_hours``) or the
    condition clearing in the tracker (:func:`resolve_cleared`).
  - **No double notification with the availability tracker.** An alert
    whose ``tracker_scope`` is ``entity`` stands for that tracker entity
    (a Cato site); ``site_links`` for the uplinks, tunnels and links of its
    site. Such an alert is recorded without a notification (``alert_via``
    ``topology``) when the tracker already alerted on what it stands for
    (the entity down or degraded with an alert raised), and the tracker
    does not alert on an entity an open vendor alert already notified
    (``vendor_alert_covers_entity``). The same rule as the Meraki feed's
    device-down alerts.
  - **Mutes.** A topology mute of the entity or its site covers the alert:
    stored with ``alert_via`` ``muted`` and not raised; creating a mute
    acknowledges the open ones (:func:`mute_covered`).
  - **Security events.** A provider may return security events too; they go
    to the vendor-neutral security event store (``security_events.
    record_events``), grouped per site so each gets its inventory host and
    its own mute.

What a new provider implements (in its own module, which calls
:func:`register` at import and is imported by :func:`providers`; see
``netcontrol.routes.cato_alerts``): a :class:`FeedProvider` with ``provider``
(the topology provider key), ``label``, ``feed`` (the cursor's name),
``list_sources`` (the sources: ``id``, ``name``, ``has_api_key``),
``read_pages(source, cursor, max_pages)`` (an async iterator of
:class:`FeedPage`: the new cursor, the alert events, the security events,
how many records were read) and ``describe_error(exc)`` (a
:class:`FeedError`: the text shown to the administrator, a short
``feed_status`` and whether it is an access problem backed off hourly).
Each alert event carries ``key`` (unique per provider; build it from the
source, the entity and the condition), ``state`` (``open`` /
``resolved``), ``org_ref``, ``org_name``, ``entity_type`` / ``entity_id``
(as the tracker names the entity, when it tracks it), ``entity_name``,
``site``, ``serial``, ``condition``, ``event_type``, ``event_sub_type``,
``title``, ``message``, ``severity`` (``critical`` / ``warning`` /
``info``: info is stored and listed only), ``started_at`` or
``resolved_at`` (UTC text), ``auto_expire`` (no recovery event exists),
``tracker_scope`` (``""``, ``entity`` or ``site_links``),
``vendor_event_id`` and a small ``detail``.

Current-state providers (``current_state=True``: AWS and Azure, see
``netcontrol.routes.aws_alerts`` and ``azure_alerts``) read what is wrong *now* rather than a
stream of events. Their pages declare ``complete_scopes``: key prefixes
whose open set the page holds in full (one region's CloudWatch alarms, one
subscription's fired alerts). After the page is stored, every open alert of
the provider whose key starts with such a prefix and that the page neither
reports open nor lists in ``unknown_keys`` (state not determined: left as
it is) is resolved (:func:`resolve_absent`). A scope whose read failed, or
was cut short by a page bound, is not declared complete, so a failed or
partial read never resolves anything. A page's ``notes`` (a part refused,
a region that failed) are shown as the source's status
(``feed_status`` ``partial``) without backing the source off. Such a
provider may also declare ``parts`` (each can be switched off in its
settings, ``disabled_parts``) and its own ``defaults`` (a longer interval).
Its events are ``observed`` (open now, whenever they began): a resolved
row the read reports again opens again, whatever its start time. Its keys
start with ``<provider>:<source id>:``, so the open alerts of a source that
is no longer polled (an account removed, disabled or opted out) are
resolved at the next cycle (:func:`resolve_orphaned`).

Object scope: a caller limited to selected inventory groups lists only the
alerts raised on an inventory host it may read.
"""

from __future__ import annotations

import asyncio
import os
import socket
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from netcontrol.integrations.meraki.enrich import load_inventory_index
from netcontrol.integrations.meraki.normalize import InventoryIndex
from netcontrol.object_scope import readable_host_ids, scoped
from netcontrol.routes.shared import _audit, _corr_id, _session_user, admin_session
from netcontrol.routes.topology_availability import PROVIDER_LABELS, _mute_index, deliver_alert
from netcontrol.telemetry import configure_logging

router = APIRouter()
admin_router = APIRouter()
LOGGER = configure_logging("plexus.vendor_alerts")

ALERT_TYPE = "vendor_alert"
CONFIG_SETTING = "vendor_alert_feeds"
MUTED_BY = "muted"
TICK_SECONDS = 15
MIN_INTERVAL, MAX_INTERVAL = 30, 3600
MAX_PAGES_PER_POLL = 5
LEASE_SECONDS = 300
# Back-off caps: an access or feed refusal is retried at most hourly,
# anything else (unreachable, rate limited) every ten minutes.
MAX_BACKOFF_AUTH = 3600
MAX_BACKOFF_OTHER = 600
DEFAULTS: dict[str, Any] = {
    "poll_enabled": True,
    "interval_seconds": 60,
    "excluded_sources": [],
    # A one-shot alert (no recovery event exists) is closed after this long.
    "open_ttl_hours": 24,
    # Store the feed's security events (Cato IPS) as security events.
    "security_events": True,
}
_FMT = "%Y-%m-%d %H:%M:%S"
_LINK_TYPES = ("uplink", "tunnel", "link")
_PROBLEM_STATES = ("down", "degraded")

# One owner name per app process: the feed lease is taken in its name.
OWNER = f"{socket.gethostname()[:40]}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
# One writer of the alert rows at a time in this process.
_APPLY_LOCK = asyncio.Lock()
_CYCLE_LOCKS: dict[str, asyncio.Lock] = {}
_LAST_CYCLE: dict[str, float] = {}
_CONFIG: dict[str, dict[str, Any]] = {}


@dataclass
class FeedPage:
    """One page a provider read: the cursor after it, the alert events, the
    security events and how many records it held."""

    cursor: str
    alerts: list[dict] = field(default_factory=list)
    security: list[dict] = field(default_factory=list)
    records: int = 0
    last_event_at: str = ""
    # Current-state providers: key prefixes whose complete open set this
    # page holds, keys whose state could not be determined (neither opened
    # nor resolved) and what to show the administrator about the read.
    complete_scopes: list[str] = field(default_factory=list)
    unknown_keys: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class FeedError(Exception):
    """A read that failed: ``text`` for the administrator, ``feed_status``
    (``no_access``, ``refused``, ``rate_limited``, ``unreachable``,
    ``error``), ``access`` (back off hourly)."""

    def __init__(self, text: str, feed_status: str = "error", *, access: bool = False) -> None:
        super().__init__(text)
        self.text = text
        self.feed_status = feed_status
        self.access = access


@dataclass(frozen=True)
class FeedProvider:
    provider: str
    label: str
    feed: str
    list_sources: Callable[[], Awaitable[list[dict]]]
    read_pages: Callable[[dict, str, int], AsyncIterator[FeedPage]]
    describe_error: Callable[[Exception], FeedError]
    description: str = ""
    # A current-state read (see the module docstring): no cursor to position.
    current_state: bool = False
    # Settings that differ from ``DEFAULTS`` for this provider.
    defaults: dict[str, Any] = field(default_factory=dict)
    # ``(key, label)`` of the parts of the feed that can be switched off.
    parts: tuple[tuple[str, str], ...] = ()


_PROVIDERS: dict[str, FeedProvider] = {}


def register(provider: FeedProvider) -> None:
    _PROVIDERS[provider.provider] = provider


def providers() -> dict[str, FeedProvider]:
    """The registered providers (the built-in ones are imported here)."""
    # Imported here: each provider module imports this one.
    from netcontrol.routes import aws_alerts, azure_alerts, cato_alerts  # noqa: F401

    return _PROVIDERS


def _provider_or_404(name: str) -> FeedProvider:
    found = providers().get(str(name))
    if found is None:
        raise HTTPException(status_code=404, detail="Unknown alert feed")
    return found


def _now() -> str:
    return datetime.now(UTC).strftime(_FMT)


def dedup_key(alert_key: str) -> str:
    return f"{ALERT_TYPE}:{alert_key}"


def backoff_delay(failures: int, interval: int, cap: int) -> float:
    """Seconds to wait after ``failures`` failures in a row: the interval
    doubled per failure (at most 2^10), at most ``cap``. Shared with the
    Meraki alert poll."""
    return float(min(cap, int(interval) * 2 ** int(min(max(1, failures), 10))))


async def clear_monitoring_alerts(keys: list[str], resolved_by: str = "auto-resolved") -> int:
    """Acknowledge the open monitoring alerts with these dedup keys (their
    condition cleared). Never raises; returns how many were open. Shared
    with the Meraki alert feed."""
    cleared = 0
    for key in keys:
        try:
            cleared += await db.resolve_monitoring_alerts(key, resolved_by)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("alert feeds: clearing an alert failed: %s", type(exc).__name__)
    return cleared


# ── Settings ─────────────────────────────────────────────────────────────────


def defaults_for(feed: FeedProvider | None) -> dict[str, Any]:
    """The default settings of a provider: ``DEFAULTS`` with its own
    ``defaults``, and ``disabled_parts`` when it has parts."""
    cfg = dict(DEFAULTS)
    if feed is not None:
        cfg.update(feed.defaults)
        if feed.parts:
            cfg["disabled_parts"] = []
    return cfg


def sanitize_config(data: dict | None, feed: FeedProvider | None = None) -> dict[str, Any]:
    cfg = defaults_for(feed)
    if not isinstance(data, dict):
        return cfg
    if feed is not None and feed.parts:
        known = [key for key, _label in feed.parts]
        wanted = {str(p) for p in data.get("disabled_parts") or [] if isinstance(p, str)}
        cfg["disabled_parts"] = [key for key in known if key in wanted]
    for flag in ("poll_enabled", "security_events"):
        if flag in data:
            cfg[flag] = bool(data[flag])
    for name, low, high in (("interval_seconds", MIN_INTERVAL, MAX_INTERVAL), ("open_ttl_hours", 1, 24 * 30)):
        try:
            cfg[name] = max(low, min(high, int(data.get(name, cfg[name]))))
        except TypeError, ValueError:
            pass
    refs: list[int] = []
    for ref in data.get("excluded_sources") or []:
        try:
            value = int(ref)
        except TypeError, ValueError:
            continue
        if value > 0 and value not in refs:
            refs.append(value)
    cfg["excluded_sources"] = sorted(refs)
    return cfg


def config(provider: str) -> dict[str, Any]:
    return _CONFIG.get(provider) or defaults_for(_PROVIDERS.get(provider))


def part_enabled(provider: str, part: str) -> bool:
    """Whether a part of a provider's feed is switched on."""
    return part not in (config(provider).get("disabled_parts") or [])


async def load_settings() -> None:
    """Load the stored settings of every provider at startup."""
    stored = await db.get_auth_setting(CONFIG_SETTING)
    known = providers()
    _CONFIG.clear()
    if isinstance(stored, dict):
        for name, cfg in stored.items():
            _CONFIG[str(name)] = sanitize_config(cfg, known.get(str(name)))


async def _save_settings() -> None:
    await db.set_auth_setting(CONFIG_SETTING, {k: dict(v) for k, v in _CONFIG.items()})


# ── Raising alerts ───────────────────────────────────────────────────────────


def _entity(row: dict) -> dict:
    return {
        "provider": str(row.get("provider") or ""),
        "org_ref": int(row.get("org_ref") or 0),
        "entity_type": str(row.get("entity_type") or ""),
        "entity_id": str(row.get("entity_id") or ""),
        "site": str(row.get("site") or ""),
        "meta": {},
    }


def muted(row: dict, index: db.TopologyMuteIndex | None) -> dict | None:
    """The topology mute covering an alert row: a mute of its entity, or of
    its site."""
    if not index:
        return None
    entity = _entity(row)
    return index.match(entity) or index.match_site(entity["provider"], entity["org_ref"], entity["site"])


def tracker_covered(row: dict, tracked: list[dict]) -> bool:
    """Whether the availability tracker already alerted on what this alert
    stands for (its ``tracker_scope``). Pure."""
    scope = str(row.get("tracker_scope") or "")
    if not scope:
        return False
    for t in tracked:
        if t.get("state") not in _PROBLEM_STATES or not t.get("alert_state"):
            continue
        if scope == "entity" and (t.get("entity_type"), t.get("entity_id")) == (
            row.get("entity_type"),
            row.get("entity_id"),
        ):
            return True
        if scope == "site_links" and t.get("entity_type") in _LINK_TYPES and t.get("site") == row.get("site"):
            return True
    return False


def host_id_for(row: dict, index: InventoryIndex | None, tracked: list[dict]) -> int | None:
    """The inventory host of an alert: by serial, else the host the tracker
    matched to its entity, else to a device of its site. Pure."""
    serial = str(row.get("serial") or "")
    if serial and index is not None:
        host = index.match(serial=serial)
        if host:
            return int(host["id"])
    for t in tracked:
        if (t.get("entity_type"), t.get("entity_id")) == (row.get("entity_type"), row.get("entity_id")):
            if t.get("host_id"):
                return int(t["host_id"])
    site = str(row.get("site") or "")
    devices = sorted(
        (t for t in tracked if t.get("entity_type") == "device" and t.get("host_id") and site and t.get("site") == site),
        key=lambda t: str(t.get("entity_id") or ""),
    )
    return int(devices[0]["host_id"]) if devices else None


def message_of(row: dict) -> str:
    provider = str(row.get("provider") or "")
    where = PROVIDER_LABELS.get(provider, provider)
    if row.get("org_name"):
        where = f"{where} {row['org_name']}"
    text = f"{where}: {row.get('title') or row.get('condition')}"
    if row.get("entity_name"):
        text += f" on {row['entity_name']}"
    if row.get("message") and row.get("message") != row.get("title"):
        text += f": {row['message']}"
    return text[:1000]


async def _tracked(provider: str, org_ref: int, cache: dict[int, list[dict]]) -> list[dict]:
    if org_ref not in cache:
        try:
            cache[org_ref] = await db.list_topology_entity_states(provider, org_ref)
        except Exception as exc:  # noqa: BLE001 - match without the tracker
            LOGGER.warning("alert feeds: tracked entities not read: %s", type(exc).__name__)
            cache[org_ref] = []
    return cache[org_ref]


async def _raise(row: dict, index: InventoryIndex | None, tracked: list[dict]) -> tuple[str, int | None]:
    """Raise one alert. Returns how (``monitoring``, ``notification`` or
    ``topology``) and the host it was raised on."""
    if tracker_covered(row, tracked):
        return "topology", None
    host_id = host_id_for(row, index, tracked)
    host = await db.get_host(host_id) if host_id else None
    name = str(row.get("entity_name") or row.get("site") or row.get("org_name") or "")
    via = await deliver_alert(
        host_id=int(host["id"]) if host else None,
        name=str(host.get("hostname") or name) if host else name,
        alert_type=ALERT_TYPE,
        metric=f"{row.get('provider')} {row.get('condition') or 'alert'}",
        message=message_of(row),
        severity=str(row.get("severity") or "warning"),
        dedup_key=dedup_key(str(row["alert_key"])),
    )
    return via, (int(host["id"]) if host and via == "monitoring" else None)


async def ingest(provider: str, events: list[dict]) -> dict[str, Any]:
    """Store normalised alert events of one provider and raise / clear
    their alerts (see the module docstring)."""
    async with _APPLY_LOCK:
        result = await db.apply_vendor_alert_events(provider, events)
        raised = muted_count = 0
        index: InventoryIndex | None = None
        mutes = await _mute_index(provider) if result["alerts"] else None
        cache: dict[int, list[dict]] = {}
        for row in result["alerts"]:
            row = {**row, "provider": provider}
            key, severity = str(row["alert_key"]), str(row.get("severity") or "")
            try:
                if muted(row, mutes):
                    # Stored and counted as raised, so unmuting does not notify it.
                    await db.set_vendor_alert_raised(provider, key, severity, MUTED_BY, None)
                    muted_count += 1
                    continue
                if index is None:
                    index = await load_inventory_index()
                tracked = await _tracked(provider, int(row.get("org_ref") or 0), cache)
                via, host_id = await _raise(row, index, tracked)
                await db.set_vendor_alert_raised(provider, key, severity, via, host_id)
                raised += 1
            except Exception as exc:  # noqa: BLE001 - delivery must never break ingestion
                LOGGER.warning("alert feeds: raising a %s alert failed: %s", provider, type(exc).__name__)
        cleared = await clear_monitoring_alerts([dedup_key(str(r["alert_key"])) for r in result["clears"]])
    return {
        "new": result["new"],
        "updated": result["updated"],
        "reopened": result["reopened"],
        "resolved": result["resolved"],
        "alerted": raised,
        "muted": muted_count,
        "alerts_cleared": cleared,
    }


def cleared_keys(rows: list[dict], tracked: list[dict]) -> list[str]:
    """The open alerts whose condition the tracker shows cleared: a
    collection newer than the alert's last event reports its entity
    (``entity``) up, or every uplink, tunnel and link of its site
    (``site_links``) up. One-shot alerts and alerts with no tracker scope
    are left to their recovery event or TTL. Pure."""
    keys: list[str] = []
    for row in rows:
        scope = str(row.get("tracker_scope") or "")
        seen = str(row.get("last_seen") or "")
        if row.get("status") != "open" or row.get("auto_expire") or not scope:
            continue
        if scope == "entity":
            found = [
                t
                for t in tracked
                if (t.get("entity_type"), t.get("entity_id")) == (row.get("entity_type"), row.get("entity_id"))
            ]
        else:
            found = [t for t in tracked if t.get("entity_type") in _LINK_TYPES and t.get("site") == row.get("site")]
        if found and all(t.get("state") == "up" and str(t.get("last_seen") or "") > seen for t in found):
            keys.append(str(row["alert_key"]))
    return keys


async def resolve_cleared(provider: str, org_ref: int) -> int:
    """Resolve the open alerts of a source whose condition cleared in the
    availability tracker (``cleared_keys``) and clear their alerts."""
    async with _APPLY_LOCK:
        rows = await db.list_vendor_alerts(provider=provider, org_ref=org_ref, limit=5000)
        if not any(r.get("tracker_scope") for r in rows):
            return 0
        keys = cleared_keys(rows, await db.list_topology_entity_states(provider, org_ref))
        done = await db.resolve_vendor_alerts(provider, keys)
        await clear_monitoring_alerts([dedup_key(str(r["alert_key"])) for r in done if r.get("alert_state")])
    return len(done)


def absent_keys(stored_open: list[str], scopes: list[str], seen: set[str]) -> list[str]:
    """The stored open keys a complete read of ``scopes`` (key prefixes)
    no longer reports: in one of the scopes, not in ``seen``. Pure."""
    return sorted(
        key for key in stored_open if key not in seen and any(key.startswith(scope) for scope in scopes if scope)
    )


async def resolve_absent(provider: str, scopes: list[str], seen: set[str]) -> int:
    """Resolve the open alerts of the complete ``scopes`` (key prefixes)
    that the read did not report open (``seen``: the keys reported open
    and those whose state was not determined) and clear their alerts."""
    scopes = [s for s in scopes if s]
    if not scopes:
        return 0
    async with _APPLY_LOCK:
        stored: list[str] = []
        for scope in scopes:
            stored += await db.list_open_vendor_alert_keys(provider, scope)
        done = await db.resolve_vendor_alerts(provider, absent_keys(stored, scopes, seen))
        await clear_monitoring_alerts([dedup_key(str(r["alert_key"])) for r in done if r.get("alert_state")])
    return len(done)


def orphaned_keys(provider: str, stored_open: list[str], source_ids: set[int]) -> list[str]:
    """The stored open keys of a current-state provider
    (``<provider>:<source id>:...``) whose source is not in ``source_ids``.
    A key of another shape is left alone. Pure."""
    found = []
    for key in stored_open:
        head, _, rest = key.partition(":")
        source = rest.partition(":")[0]
        if head == provider and source.isdigit() and int(source) not in source_ids:
            found.append(key)
    return sorted(found)


async def resolve_orphaned(provider: str, source_ids: set[int]) -> int:
    """Resolve the open alerts of a current-state provider whose source is
    no longer polled (an account removed, disabled or opted out: nothing
    would ever read them clear) and clear their alerts."""
    async with _APPLY_LOCK:
        stored = await db.list_open_vendor_alert_keys(provider, f"{provider}:")
        done = await db.resolve_vendor_alerts(provider, orphaned_keys(provider, stored, source_ids))
        await clear_monitoring_alerts([dedup_key(str(r["alert_key"])) for r in done if r.get("alert_state")])
    return len(done)


async def expire(provider: str) -> int:
    """Close the one-shot alerts older than the provider's open TTL."""
    async with _APPLY_LOCK:
        rows = await db.expire_vendor_alerts(provider, int(config(provider)["open_ttl_hours"]))
        await clear_monitoring_alerts([dedup_key(str(r["alert_key"])) for r in rows if r.get("alert_state")])
    return len(rows)


async def mute_covered(provider: str, org_ref: int, index: db.TopologyMuteIndex) -> int:
    """After a mute was created: acknowledge as ``muted`` the open alerts of
    the source the mutes now cover. Returns how many monitoring alerts."""
    acknowledged = 0
    async with _APPLY_LOCK:
        for row in await db.list_vendor_alerts(provider=provider, org_ref=org_ref, limit=5000):
            if not muted(row, index):
                continue
            key = str(row["alert_key"])
            acknowledged += await db.resolve_monitoring_alerts(dedup_key(key), MUTED_BY)
            await db.set_vendor_alert_raised(provider, key, str(row.get("severity") or ""), MUTED_BY, row.get("host_id"))
    return acknowledged


# ── Security events ──────────────────────────────────────────────────────────


async def record_security(provider: str, source: dict, events: list[dict]) -> dict[str, int]:
    """Store a page's security events, per site: each site's events with its
    inventory host and its own mute (a mute of the site or of the Socket the
    tracker knows there). The unmuted sites go first: a site with no
    inventory host is notified once per account and signature while the
    signature stays active (``security_events.record_events``), and a muted
    site's events must not stand in for that notification. Never raises."""
    # Imported here: security_events imports topology_availability too.
    from netcontrol.routes import security_events

    totals = {"stored": 0, "alerted": 0, "muted": 0}
    if not events:
        return totals
    org_ref = int(source["id"])
    org_name = str(source.get("name") or "")
    try:
        index = await load_inventory_index()
        mutes = await _mute_index(provider, org_ref)
        tracked = await db.list_topology_entity_states(provider, org_ref)
    except Exception as exc:  # noqa: BLE001 - stored without host or mutes
        LOGGER.warning("alert feeds: security event context not read: %s", type(exc).__name__)
        index, mutes, tracked = None, None, []
    groups: list[tuple[bool, str, dict, list[dict]]] = []
    by_site: dict[str, list[dict]] = {}
    for event in events:
        by_site.setdefault(str(event.get("site_name") or ""), []).append(event)
    for site, found in by_site.items():
        row = {
            "provider": provider,
            "org_ref": org_ref,
            "entity_type": "site",
            "entity_id": str(found[0].get("site_id") or site),
            "site": site,
            "serial": str(found[0].get("serial") or ""),
        }
        groups.append((bool(muted(row, mutes)), site, row, found))
    for is_muted, site, row, found in sorted(groups, key=lambda g: (g[0], g[1])):
        host_id = host_id_for(row, index, tracked)
        try:
            host = await db.get_host(host_id) if host_id else None
            outcome = await security_events.record_events(
                provider,
                org_ref,
                found,
                host=host,
                source_name=f"{org_name} / {site}" if site else org_name,
                muted=is_muted,
            )
        except Exception as exc:  # noqa: BLE001 - the feed goes on
            LOGGER.warning("alert feeds: %s security events not stored: %s", provider, type(exc).__name__)
            continue
        totals["stored"] += len(outcome["stored"])
        totals["alerted"] += int(outcome["alerted"])
        totals["muted"] += int(outcome["muted"])
    return totals


# ── Poll ─────────────────────────────────────────────────────────────────────


def _later(seconds: float) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).strftime(_FMT)


async def poll_source(feed: FeedProvider, source: dict, *, force: bool = False) -> dict[str, Any]:
    """Poll one source's feed once (see the module docstring). Never raises."""
    org_ref = int(source["id"])
    out: dict[str, Any] = {"org_ref": org_ref, "ok": True}
    try:
        row = await db.claim_vendor_alert_feed(feed.provider, org_ref, feed.feed, OWNER, LEASE_SECONDS)
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("alert feeds: %s source %s not claimed: %s", feed.provider, org_ref, type(exc).__name__)
        return {**out, "ok": False, "error": type(exc).__name__}
    if row is None:
        return {**out, "skipped": "polled by another worker"}
    try:
        if not force and str(row.get("next_poll_at") or "") > _now():
            return {**out, "skipped": "backing off"}
        # Another app worker polled it within this interval: not again.
        recent = _later(-0.8 * int(config(feed.provider)["interval_seconds"]))
        if not force and str(row.get("last_poll_at") or "") > recent:
            return {**out, "skipped": "polled recently"}
        return {**out, **await _read(feed, source, row)}
    finally:
        try:
            await db.release_vendor_alert_feed(feed.provider, org_ref, feed.feed, OWNER)
        except Exception as exc:  # noqa: BLE001 - the lease runs out on its own
            LOGGER.debug("alert feeds: lease not released: %s", type(exc).__name__)


async def _read(feed: FeedProvider, source: dict, row: dict) -> dict[str, Any]:
    org_ref = int(source["id"])
    cursor = str(row.get("feed_cursor") or "")
    totals: dict[str, Any] = {"pages": 0, "records": 0, "new": 0, "resolved": 0, "alerted": 0, "security": 0}
    notes: list[str] = []
    try:
        async for page in feed.read_pages(source, cursor, MAX_PAGES_PER_POLL):
            result = await ingest(feed.provider, page.alerts)
            if page.complete_scopes:
                seen = {str(a["key"]) for a in page.alerts if a.get("state", "open") == "open"}
                totals["resolved"] += await resolve_absent(
                    feed.provider, page.complete_scopes, seen | {str(k) for k in page.unknown_keys}
                )
            notes += [n for n in page.notes if n and n not in notes]
            if page.security and config(feed.provider)["security_events"]:
                totals["security"] += (await record_security(feed.provider, source, page.security))["stored"]
            await db.save_vendor_alert_feed_cursor(
                feed.provider,
                org_ref,
                feed.feed,
                OWNER,
                page.cursor,
                events=page.records,
                last_event_at=page.last_event_at,
            )
            totals["pages"] += 1
            totals["records"] += page.records
            for name in ("new", "resolved", "alerted"):
                totals[name] += int(result[name])
        totals["resolved"] += await resolve_cleared(feed.provider, org_ref)
    except Exception as exc:  # noqa: BLE001 - one source never stops the others
        error = exc if isinstance(exc, FeedError) else feed.describe_error(exc)
        failures = int(row.get("failures") or 0) + 1
        cap = MAX_BACKOFF_AUTH if error.access else MAX_BACKOFF_OTHER
        delay = backoff_delay(failures, int(config(feed.provider)["interval_seconds"]), cap)
        if error.text != str(row.get("last_error") or ""):
            LOGGER.warning(
                "alert feeds: %s source %s: %s; retried in %ss", feed.provider, org_ref, error.text, int(delay)
            )
        await db.record_vendor_alert_feed_poll(
            feed.provider,
            org_ref,
            feed.feed,
            ok=False,
            error=error.text,
            feed_status=error.feed_status,
            failures=failures,
            next_poll_at=_later(delay),
        )
        return {**totals, "ok": False, "error": error.text, "feed_status": error.feed_status}
    status = "positioned" if not cursor and totals["pages"] and not feed.current_state else "ok"
    note = "; ".join(notes)
    if note:
        # Read, with a part refused or a region / subscription failed: shown,
        # not backed off (the parts that answered are current).
        status = "partial"
        if note != str(row.get("last_error") or ""):
            LOGGER.warning("alert feeds: %s source %s: %s", feed.provider, org_ref, note[:300])
    await db.record_vendor_alert_feed_poll(feed.provider, org_ref, feed.feed, ok=True, error=note, feed_status=status)
    return {**totals, "feed_status": status, **({"note": note} if note else {})}


async def run_poll_cycle(provider: str, trigger: str = "scheduled", *, force: bool = False) -> dict[str, Any]:
    """Poll every source of one provider once and close stale one-shot
    alerts. ``force`` (Poll Now) polls even when polling is off and ignores
    back-off. Never raises."""
    feed = providers().get(provider)
    if feed is None:
        return {"ok": False, "trigger": trigger, "polled": 0, "error": "unknown provider"}
    lock = _CYCLE_LOCKS.setdefault(provider, asyncio.Lock())
    async with lock:
        _LAST_CYCLE[provider] = time.monotonic()
        try:
            expired = await expire(provider)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("alert feeds: expiring %s alerts failed: %s", provider, type(exc).__name__)
            expired = 0
        cfg = config(provider)
        if not cfg["poll_enabled"] and not force:
            return {"ok": True, "trigger": trigger, "polled": 0, "skipped": "polling is off", "expired": expired}
        try:
            sources = [s for s in await feed.list_sources() if int(s["id"]) not in cfg["excluded_sources"]]
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("alert feeds: listing %s sources failed: %s", provider, type(exc).__name__)
            return {"ok": False, "trigger": trigger, "polled": 0, "error": type(exc).__name__}
        sources = [s for s in sources if s.get("has_api_key")]
        orphaned = 0
        if feed.current_state:
            try:
                orphaned = await resolve_orphaned(provider, {int(s["id"]) for s in sources})
            except Exception as exc:  # noqa: BLE001 - tried again at the next cycle
                LOGGER.warning("alert feeds: resolving orphaned %s alerts failed: %s", provider, type(exc).__name__)
        results = [await poll_source(feed, s, force=force) for s in sources]
        polled = [r for r in results if not r.get("skipped")]
        failed = [r for r in polled if not r["ok"]]
        summary = {name: sum(int(r.get(name) or 0) for r in polled) for name in ("new", "resolved", "alerted", "security")}
        summary["resolved"] += orphaned
        if summary["new"] or summary["resolved"] or summary["security"]:
            LOGGER.info(
                "alert feeds (%s, %s): %s source(s) polled, %s failed, %s new, %s resolved, %s alert(s), "
                "%s security event(s)",
                provider,
                trigger,
                len(polled),
                len(failed),
                summary["new"],
                summary["resolved"],
                summary["alerted"],
                summary["security"],
            )
        return {
            "ok": not failed,
            "trigger": trigger,
            "polled": len(polled),
            "failed": len(failed),
            "skipped": len(results) - len(polled),
            **summary,
            "expired": expired,
            "sources": results,
        }


async def run_due_cycles() -> None:
    """Run the poll cycle of every provider whose interval has passed."""
    now = time.monotonic()
    for name in sorted(providers()):
        interval = int(config(name)["interval_seconds"])
        if now - _LAST_CYCLE.get(name, 0.0) < interval:
            continue
        try:
            await run_poll_cycle(name)
        except Exception as exc:  # noqa: BLE001 - one provider never stops the others
            LOGGER.warning("alert feeds: %s cycle failed: %s", name, type(exc).__name__)


# ── API ──────────────────────────────────────────────────────────────────────


class FeedSettingsUpdate(BaseModel):
    poll_enabled: bool | None = None
    interval_seconds: int | None = None
    excluded_sources: list[int] | None = None
    open_ttl_hours: int | None = None
    security_events: bool | None = None
    disabled_parts: list[str] | None = None


async def settings_payload(feed: FeedProvider) -> dict[str, Any]:
    cfg = config(feed.provider)
    try:
        sources = await feed.list_sources()
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("alert feeds: listing %s sources failed: %s", feed.provider, type(exc).__name__)
        sources = []
    try:
        rows = {int(r["org_ref"]): r for r in await db.list_vendor_alert_feeds(feed.provider, feed.feed)}
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("alert feeds: %s feed status not read: %s", feed.provider, type(exc).__name__)
        rows = {}
    listed = []
    for source in sources:
        row = rows.get(int(source["id"])) or {}
        listed.append(
            {
                "id": int(source["id"]),
                "name": str(source.get("name") or ""),
                "has_api_key": bool(source.get("has_api_key")),
                "excluded": int(source["id"]) in cfg["excluded_sources"],
                "last_poll_at": str(row.get("last_poll_at") or ""),
                "last_ok_at": str(row.get("last_ok_at") or ""),
                "last_error": str(row.get("last_error") or ""),
                "feed_status": str(row.get("feed_status") or ""),
                "cursor_set": bool(row.get("feed_cursor")),
                "last_event_at": str(row.get("last_event_at") or ""),
                "events_read": int(row.get("events_read") or 0),
                "next_poll_at": str(row.get("next_poll_at") or ""),
            }
        )
    polled = [s for s in listed if s["last_poll_at"]]
    # A partial read (a part refused, a region failed) is not a failed poll.
    failed = [s for s in polled if s["last_error"] and s["feed_status"] != "partial"]
    disabled = set(cfg.get("disabled_parts") or [])
    return {
        "provider": feed.provider,
        "label": feed.label,
        "description": feed.description,
        "current_state": feed.current_state,
        "parts": [{"key": key, "label": label, "enabled": key not in disabled} for key, label in feed.parts],
        "config": dict(cfg),
        "min_interval_seconds": MIN_INTERVAL,
        "max_interval_seconds": MAX_INTERVAL,
        "status": {
            "last_poll_at": max((str(s["last_poll_at"]) for s in polled), default=""),
            "last_poll_ok": (not failed) if polled else None,
            "last_poll_error": f"{len(failed)} of {len(polled)} source(s) failed" if failed else "",
        },
        "sources": listed,
    }


@router.get("/api/monitoring/vendor-alerts")
@scoped("list")
async def list_vendor_alerts_api(
    request: Request = None,  # type: ignore[assignment]  # None: called directly (unrestricted)
    provider: str | None = Query(default=None, max_length=32, pattern=r"^[a-z0-9_-]+$"),
    include_resolved: bool = Query(default=False),
    org_ref: int | None = Query(default=None, ge=1),
    limit: int = Query(default=500, ge=1, le=5000),
):
    """The alerts of the vendor alert feeds; ``muted`` marks the alerts of a
    muted entity or site."""
    rows = await db.list_vendor_alerts(
        provider=provider,
        include_resolved=include_resolved,
        org_ref=org_ref,
        limit=limit,
        host_ids=await readable_host_ids(request),
    )
    indexes: dict[str, Any] = {}
    for row in rows:
        name = str(row["provider"])
        if name not in indexes:
            indexes[name] = await _mute_index(name, org_ref)
        row["muted"] = bool(muted(row, indexes[name]))
    return {"alerts": rows}


@admin_router.get("/api/monitoring/vendor-alerts/{provider}/settings", dependencies=[Depends(admin_session)])
async def get_vendor_alert_settings_api(provider: str):
    """The feed's settings and the poll status of each source."""
    return await settings_payload(_provider_or_404(provider))


@admin_router.put("/api/monitoring/vendor-alerts/{provider}/settings", dependencies=[Depends(admin_session)])
async def update_vendor_alert_settings_api(provider: str, body: FeedSettingsUpdate, request: Request):
    feed = _provider_or_404(provider)
    current = dict(config(feed.provider))
    for name, value in body.model_dump(exclude_none=True).items():
        current[name] = value
    sanitized = sanitize_config(current, feed)
    _CONFIG[feed.provider] = sanitized
    await _save_settings()
    parts = f" disabled_parts={','.join(sanitized['disabled_parts']) or '-'}" if feed.parts else ""
    await _audit(
        "monitoring",
        "vendor_alerts.settings_updated",
        user=_session_user(request),
        detail=(
            f"provider={feed.provider} poll={sanitized['poll_enabled']} interval={sanitized['interval_seconds']}s "
            f"excluded={len(sanitized['excluded_sources'])} security_events={sanitized['security_events']} "
            f"open_ttl={sanitized['open_ttl_hours']}h{parts}"
        ),
        correlation_id=_corr_id(request),
    )
    return await settings_payload(feed)


@admin_router.post("/api/monitoring/vendor-alerts/{provider}/poll", dependencies=[Depends(admin_session)])
async def poll_vendor_alerts_now_api(provider: str, request: Request):
    """Poll every source of the feed now, ignoring back-off and the poll
    switch (a source another worker is polling is skipped)."""
    feed = _provider_or_404(provider)
    result = await run_poll_cycle(feed.provider, "manual", force=True)
    await _audit(
        "monitoring",
        "vendor_alerts.polled",
        user=_session_user(request),
        detail=(
            f"provider={feed.provider} polled={result.get('polled')} failed={result.get('failed')} "
            f"new={result.get('new')}"
        ),
        correlation_id=_corr_id(request),
    )
    return result

