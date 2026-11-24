"""Who may send to the inbound UDP listeners, and how fast.

The SNMP trap and syslog receivers (``netcontrol/routes/metrics_engine.py``)
and the NetFlow / IPFIX / sFlow collector
(``netcontrol/routes/flow_collector.py``) accept unauthenticated UDP, whose
source address can be forged. Each listener asks its :class:`SourceGuard`
(``GUARDS``) about every datagram before parsing it:

- **Source allowlist.** With the default policy ``inventory`` a datagram is
  processed only when its source address is an inventory host address: a
  host's primary IP or a recorded interface IP (``host_ip_aliases``), the
  same set the flow collector resolves exporters with. The admin can add
  extra networks (``extra_cidrs``, for an exporter or firewall that is not
  an inventory host) or set the policy to ``any`` (every source, the
  behaviour before the allowlist).
- **Per-source rate limit.** A token bucket per source address, with its
  own packets-per-second limit per listener (``trap_rate_limit``,
  ``syslog_rate_limit``, ``flow_rate_limit``; 0 turns it off) and a burst of
  ``BURST_SECONDS`` worth of packets. The buckets live in a
  :class:`~netcontrol.bounded_map.BoundedDict`, so a flood of forged sources
  cannot grow them past ``MAX_TRACKED_SOURCES``.

The inventory address set (``INVENTORY_ADDRESSES``, address -> host id) is
loaded from the database by :func:`refresh_inventory`: when a listener
starts, after every inventory host change (``flow_collector.on_host_changed``)
and at most every ``INVENTORY_REFRESH_SECONDS`` in the background while
datagrams arrive. A datagram never waits for, or causes, a database query.
The same refresh loads each host's hostname (``INVENTORY_HOSTNAMES``), which
the syslog TLS receiver compares with a client certificate.

A dropped datagram is counted per listener and reason (``source``, ``rate``,
``community`` for a trap whose community is wrong, and ``v3`` for an SNMPv3
trap or inform from an inventory host that fails its USM checks) and logged at most
once per ``DROP_LOG_INTERVAL_SECONDS`` per listener.

The settings are persisted in ``auth_settings("listener_sources")`` and
changed through ``/api/admin/listener-sources`` (``netcontrol/routes/admin.py``).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections.abc import Callable
from typing import Any

import routes.database as db

from netcontrol.bounded_map import BoundedDict

LOGGER = logging.getLogger("plexus.listener_sources")

LISTENERS: tuple[str, ...] = ("trap", "syslog", "flow")
LISTENER_LABELS = {"trap": "SNMP trap", "syslog": "syslog", "flow": "flow"}
POLICY_INVENTORY = "inventory"
POLICY_ANY = "any"
POLICIES: tuple[str, ...] = (POLICY_INVENTORY, POLICY_ANY)
DROP_REASONS: tuple[str, ...] = ("source", "rate", "community", "v3")

DEFAULTS: dict[str, Any] = {
    # inventory: only inventory host addresses (plus extra_cidrs); any: every source.
    "policy": POLICY_INVENTORY,
    "extra_cidrs": [],
    # Packets per second per source address; 0 = no limit.
    "trap_rate_limit": 100,
    "syslog_rate_limit": 1000,
    "flow_rate_limit": 5000,
}
RATE_LIMIT_KEYS: tuple[str, ...] = tuple(f"{name}_rate_limit" for name in LISTENERS)
MAX_EXTRA_CIDRS = 256
MAX_RATE_LIMIT = 1_000_000

# A source may send this many seconds' worth of its limit at once.
BURST_SECONDS = 2.0
# Rate-limit buckets kept; a bucket idle this long is dropped first.
MAX_TRACKED_SOURCES = 4096
BUCKET_IDLE_SECONDS = 60.0
INVENTORY_REFRESH_SECONDS = 60.0
DROP_LOG_INTERVAL_SECONDS = 60.0

# Monotonic clock, replaced in tests.
_clock: Callable[[], float] = time.monotonic


# ── Settings ─────────────────────────────────────────────────────────────────


def _rate(value: Any, default: int, key: str, strict: bool) -> int:
    if isinstance(value, bool):
        if strict:
            raise ValueError(f"{key} must be a whole number.")
        return default
    try:
        number = int(value)
    except TypeError, ValueError:
        if strict:
            raise ValueError(f"{key} must be a whole number.") from None
        return default
    if strict and not 0 <= number <= MAX_RATE_LIMIT:
        raise ValueError(f"{key} must be from 0 to {MAX_RATE_LIMIT}.")
    return max(0, min(MAX_RATE_LIMIT, number))


def _cidrs(value: Any, strict: bool) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        if strict:
            raise ValueError("extra_cidrs must be a list of networks.")
        return []
    out: list[str] = []
    for item in value:
        text = str(item or "").strip()
        if not text:
            continue
        try:
            network = str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            if strict:
                raise ValueError(f"{text!r} is not an IP address or network.") from None
            LOGGER.warning("listener sources: ignoring invalid network %r", text)
            continue
        if network not in out:
            out.append(network)
    if len(out) > MAX_EXTRA_CIDRS:
        if strict:
            raise ValueError(f"At most {MAX_EXTRA_CIDRS} extra networks.")
        out = out[:MAX_EXTRA_CIDRS]
    return out


def sanitize_config(data: Any, *, strict: bool = False) -> dict[str, Any]:
    """The settings from ``data`` (the stored row or an API body), defaults
    for what is missing. ``strict`` (the API): ``ValueError`` for an invalid
    value instead of keeping the default."""
    cfg: dict[str, Any] = {**DEFAULTS, "extra_cidrs": []}
    if not isinstance(data, dict):
        return cfg
    policy = str(data.get("policy", cfg["policy"]) or "").strip().lower()
    if policy in POLICIES:
        cfg["policy"] = policy
    elif strict:
        raise ValueError(f"policy must be one of: {', '.join(POLICIES)}.")
    cfg["extra_cidrs"] = _cidrs(data.get("extra_cidrs"), strict)
    for key in RATE_LIMIT_KEYS:
        cfg[key] = _rate(data.get(key, cfg[key]), DEFAULTS[key], key, strict)
    return cfg


CONFIG: dict[str, Any] = sanitize_config(None)
_extra_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()


def apply_config(cfg: dict[str, Any]) -> dict[str, Any]:
    """Make ``cfg`` (already sanitized) the live settings. Returns them."""
    global _extra_networks
    CONFIG.clear()
    CONFIG.update(cfg)
    _extra_networks = tuple(ipaddress.ip_network(c, strict=False) for c in CONFIG.get("extra_cidrs") or ())
    return dict(CONFIG)


# ── Inventory addresses ──────────────────────────────────────────────────────

# address -> host id: every host's primary IP and recorded interface IPs.
# The flow collector's exporter cache is this same dict.
INVENTORY_ADDRESSES: dict[str, int] = {}
# host id -> hostname, from the same refresh (the syslog TLS receiver
# matches a client certificate against it).
INVENTORY_HOSTNAMES: dict[int, str] = {}
_inventory_loaded_at = float("-inf")
_refresh_task: asyncio.Task | None = None


async def refresh_inventory() -> int:
    """Reload ``INVENTORY_ADDRESSES`` and ``INVENTORY_HOSTNAMES``
    (``db.get_exporter_host_map``). A failed load keeps the previous sets.
    Returns the number of addresses.

    No lock: the swap after the query runs without an ``await``, so two
    refreshes at once each install a complete set (a lock held by a refresh
    whose event loop closed would block every later one)."""
    global _inventory_loaded_at
    hostnames: dict[int, str] = {}
    try:
        mapping = await db.get_exporter_host_map(hostnames=hostnames)
    except Exception as exc:  # noqa: BLE001 - keep the old set, retry later
        LOGGER.warning("listener sources: inventory address refresh failed: %s", type(exc).__name__)
        _inventory_loaded_at = _clock()
        return len(INVENTORY_ADDRESSES)
    INVENTORY_ADDRESSES.clear()
    # Keyed in canonical form, so an IPv6 host address matches the source
    # address the socket reports however the host's address was written.
    for address, host_id in mapping.items():
        INVENTORY_ADDRESSES.setdefault(canonical_address(address), host_id)
    INVENTORY_HOSTNAMES.clear()
    INVENTORY_HOSTNAMES.update(hostnames)
    _inventory_loaded_at = _clock()
    return len(INVENTORY_ADDRESSES)


def _maybe_refresh(now: float) -> None:
    """Start a background refresh when the set is older than
    ``INVENTORY_REFRESH_SECONDS`` and none is running (no event loop: no-op)."""
    global _refresh_task
    if now - _inventory_loaded_at < INVENTORY_REFRESH_SECONDS:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    if _refresh_task is not None and not _refresh_task.done() and _refresh_task.get_loop() is loop:
        return
    _refresh_task = loop.create_task(refresh_inventory())


def canonical_address(address: str) -> str:
    """A source or inventory address in one comparable form: an
    IPv4-mapped IPv6 address (``::ffff:192.0.2.1``, any spelling) as its
    IPv4 address, any other IPv6 address in its compressed lower-case form
    (a zone, ``%eth0``, kept). An IPv4 address, or text that is no address,
    is returned as given (stripped)."""
    address = str(address or "").strip()
    if ":" not in address:
        return address
    try:
        parsed = ipaddress.IPv6Address(address)
    except ValueError:
        return address
    mapped = parsed.ipv4_mapped
    return str(mapped) if mapped is not None else str(parsed)


_canonical = canonical_address


def inventory_host_id(address: str) -> int | None:
    """The inventory host whose address (primary or interface) ``address`` is."""
    return INVENTORY_ADDRESSES.get(_canonical(address))


def inventory_hostname(address: str) -> str:
    """The hostname of the inventory host at ``address`` ("" when the
    address is no inventory host or the host has no hostname)."""
    host_id = inventory_host_id(address)
    return INVENTORY_HOSTNAMES.get(host_id, "") if host_id is not None else ""


def source_allowed(address: str) -> bool:
    """The allowlist alone: an inventory host address, an address in
    ``extra_cidrs``, or any address under the ``any`` policy."""
    address = _canonical(address)
    if address in INVENTORY_ADDRESSES or CONFIG.get("policy") == POLICY_ANY:
        return True
    if not _extra_networks:
        return False
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    return any(ip in network for network in _extra_networks)


# ── The guard of one listener ────────────────────────────────────────────────


def _bucket_idle(_key: Any, bucket: list[float], now: float) -> bool:
    return now - bucket[1] > BUCKET_IDLE_SECONDS


class SourceGuard:
    """The allowlist, rate limit and drop counters of one listener."""

    def __init__(self, listener: str) -> None:
        self.listener = listener
        self.label = LISTENER_LABELS.get(listener, listener)
        self._rate_key = f"{listener}_rate_limit"
        self.dropped: dict[str, int] = dict.fromkeys(DROP_REASONS, 0)
        # source -> [tokens, last refill time]
        self._buckets: BoundedDict = BoundedDict(MAX_TRACKED_SOURCES, _bucket_idle, clock=lambda: _clock())
        self._last_log = float("-inf")
        self._unlogged = 0

    def allow_source(self, source_ip: str, now: float | None = None) -> bool:
        """The allowlist alone, without taking a rate-limit token (a syslog
        TCP / TLS connection at accept): a refused source is counted as a
        ``source`` drop (and logged, rate limited)."""
        now = _clock() if now is None else now
        _maybe_refresh(now)
        if source_allowed(source_ip):
            return True
        self.note_drop("source", source_ip, now)
        return False

    def admit(self, source_ip: str) -> bool:
        """True when a datagram from ``source_ip`` may be processed; a
        refused one is counted (and logged, rate limited)."""
        now = _clock()
        if not self.allow_source(source_ip, now):
            return False
        limit = CONFIG.get(self._rate_key) or 0
        if limit and not self._take(_canonical(source_ip), float(limit), now):
            self.note_drop("rate", source_ip, now)
            return False
        return True

    def _take(self, source: str, limit: float, now: float) -> bool:
        capacity = max(1.0, limit * BURST_SECONDS)
        bucket = self._buckets.get(source)
        if bucket is None:
            self._buckets[source] = [capacity - 1.0, now]
            return True
        tokens = min(capacity, bucket[0] + (now - bucket[1]) * limit)
        bucket[1] = now
        if tokens < 1.0:
            bucket[0] = tokens
            return False
        bucket[0] = tokens - 1.0
        return True

    def note_drop(self, reason: str, source_ip: str, now: float | None = None) -> None:
        """Count a dropped datagram; log at most once per
        ``DROP_LOG_INTERVAL_SECONDS`` with the number dropped since the last
        log line."""
        self.dropped[reason] = self.dropped.get(reason, 0) + 1
        self._unlogged += 1
        now = _clock() if now is None else now
        if now - self._last_log < DROP_LOG_INTERVAL_SECONDS:
            return
        LOGGER.warning(
            "%s listener: dropped %d datagram(s) since the last report (latest from %s: %s); "
            "see the listener source settings",
            self.label,
            self._unlogged,
            source_ip,
            _REASON_TEXT.get(reason, reason),
        )
        self._last_log = now
        self._unlogged = 0

    def stats(self) -> dict[str, int]:
        """The drop counters since Plexus started, and the buckets held."""
        return {
            "dropped_source": self.dropped.get("source", 0),
            "dropped_rate": self.dropped.get("rate", 0),
            "dropped_community": self.dropped.get("community", 0),
            "dropped_v3": self.dropped.get("v3", 0),
            "tracked_sources": len(self._buckets),
        }

    def reset(self) -> None:
        """Forget counters and buckets (tests)."""
        self.dropped = dict.fromkeys(DROP_REASONS, 0)
        self._buckets.clear()
        self._last_log = float("-inf")
        self._unlogged = 0


_REASON_TEXT = {
    "source": "not an inventory host or allowed network",
    "rate": "over the per-source rate limit",
    "community": "wrong SNMP community",
    "v3": "SNMPv3 trap or inform not from the host's SNMPv3 user (authentication, level, time window or replay)",
}

GUARDS: dict[str, SourceGuard] = {name: SourceGuard(name) for name in LISTENERS}


def guard(listener: str) -> SourceGuard:
    return GUARDS[listener]


def snapshot() -> dict[str, Any]:
    """The settings, the size of the inventory address set and each
    listener's drop counters (the admin API)."""
    return {
        **CONFIG,
        "extra_cidrs": list(CONFIG.get("extra_cidrs") or []),
        "inventory_addresses": len(INVENTORY_ADDRESSES),
        "listeners": {name: GUARDS[name].stats() for name in LISTENERS},
    }
