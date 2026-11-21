"""Traffic of tunnels from the cumulative byte counters a vendor reports.

A normaliser that knows how many bytes a tunnel (or a VPN server) carried
puts a ``traffic`` block on the snapshot edge or node (``traffic_block``):

    {"key": "<stable id of the entity at the vendor>",
     "bytes_in": <total received by the device>, "bytes_out": <total sent>,
     "counters": {"<counter id>": [bytes_in, bytes_out], ...}}

``bytes_in`` / ``bytes_out`` are what the vendor shows as totals.
``counters`` are the cumulative counters the rate is computed from, one per
thing that has its own counter and its own life (an IPsec child SA, a
WireGuard peer, an OpenVPN session), keyed so that a new life gets a new id
(a rekeyed child SA has a new unique id, a reconnected OpenVPN client a new
address and start time). ``None`` when the counters are not known (the rate
is then not computed); ``{}`` when the vendor says there is none (a tunnel
that is down).

The last reading of every key lives in the database (the counter store,
``routes.db.topology_traffic``), so it works in any worker and across
restarts. Each reading (a stored collection, ``apply_traffic_rates``, or a
monitoring poll of the firewall, ``netcontrol.routes.topology_traffic``)
compares its counters with the last reading of the same ``key`` and, when
the comparison can be trusted (``traffic_rates``), gives the average rate
since then as ``in_bps`` / ``out_bps`` (bits per second), stored like a
gateway's latency; then it replaces that reading. Collections and polls
thus interleave with one sample per reading and no overlap. At a
collection the rate goes on the item's ``metrics`` and a "Traffic" section
with the totals and the rate is added to the item's details.

No rate (rather than a wrong one) when:

  - there is no previous reading of the entity (its first reading, or
    the previous one did not know its counters);
  - a counter of the previous reading is gone (a child SA rekeyed or
    deleted, an OpenVPN session ended): what it carried since is unknown;
  - a counter went down (a reset: the interface restarted, the firewall
    rebooted);
  - the readings are more than ``MAX_RATE_GAP_SECONDS`` apart, or their
    times are unknown.

With readings every few minutes (the poll), a rekey or reconnect costs
the one interval it falls in.

Pure: no database, no network.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.meraki.normalize import kv_section

# Two readings further apart than this give no rate: a counter may have
# reset and grown past its old value in between. Three hours keeps a rate
# across one missed hourly collection.
MAX_RATE_GAP_SECONDS = 3 * 3600
SECTION_TRAFFIC = "Traffic"

REASON_FIRST = "first reading"
REASON_GONE = "a counter of the previous reading ended (rekey, reconnect)"
REASON_RESET = "a counter was reset"
REASON_GAP = "previous reading too old"
REASON_TIME = "reading time unknown"
REASON_UNKNOWN = "counters not reported"


def byte_count(value: Any) -> int | None:
    """A byte counter as an int (OPNsense sends numbers or digit strings);
    ``None`` for anything else (missing, negative, not a number)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        return int(value) if value >= 0 else None
    text = str(value if value is not None else "").strip()
    return int(text) if text.isdigit() else None


def counter_pair(bytes_in: Any, bytes_out: Any) -> list[int] | None:
    """``[bytes_in, bytes_out]``, or ``None`` when either is not a count."""
    found = byte_count(bytes_in), byte_count(bytes_out)
    if found[0] is None or found[1] is None:
        return None
    return [found[0], found[1]]


def traffic_block(key: str, totals: list[int] | None, counters: dict[str, list[int]] | None) -> dict | None:
    """The ``traffic`` block of an edge or node (see the module doc), or
    ``None`` when nothing is known. Without ``totals`` the totals are the
    sums of ``counters``."""
    if totals is None and counters is not None:
        totals = [sum(c[0] for c in counters.values()), sum(c[1] for c in counters.values())]
    if totals is None:
        return None
    return {"key": key, "bytes_in": totals[0], "bytes_out": totals[1], "counters": counters}


def _counters(traffic: Any) -> dict[str, list[int]] | None:
    found = traffic.get("counters") if isinstance(traffic, dict) else None
    if not isinstance(found, dict):
        return None
    pairs = {str(k): counter_pair(*v) for k, v in found.items() if isinstance(v, (list, tuple)) and len(v) == 2}
    return None if any(v is None for v in pairs.values()) else {k: v for k, v in pairs.items() if v is not None}


def traffic_rates(
    previous: dict | None, current: dict | None, elapsed_seconds: float | None
) -> tuple[dict[str, float] | None, str]:
    """``({"in_bps", "out_bps"}, "")``: the average rate between two
    readings of the same entity's ``traffic`` blocks taken
    ``elapsed_seconds`` apart, or ``(None, reason)`` when it cannot be
    trusted (see the module doc). A counter that is new in ``current``
    started after the previous reading (which listed every counter), so all
    of it counts."""
    now = _counters(current)
    if now is None:
        return None, REASON_UNKNOWN
    before = _counters(previous)
    if before is None:
        return None, REASON_FIRST
    if elapsed_seconds is None or elapsed_seconds <= 0:
        return None, REASON_TIME
    if elapsed_seconds > MAX_RATE_GAP_SECONDS:
        return None, REASON_GAP
    if any(key not in now for key in before):
        return None, REASON_GONE
    if any(now[key][0] < old[0] or now[key][1] < old[1] for key, old in before.items()):
        return None, REASON_RESET
    delta_in = sum(v[0] for v in now.values()) - sum(v[0] for v in before.values())
    delta_out = sum(v[1] for v in now.values()) - sum(v[1] for v in before.values())
    return {
        "in_bps": round(delta_in * 8 / elapsed_seconds, 2),
        "out_bps": round(delta_out * 8 / elapsed_seconds, 2),
    }, ""


def format_bps(bps: float) -> str:
    """Human-readable bits per second: ``1.50 Gbps``, ``512.00 Kbps``."""
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Mbps"
    if bps >= 1_000:
        return f"{bps / 1_000:.2f} Kbps"
    return f"{bps:.0f} bps"


def format_bytes(count: float) -> str:
    """Human-readable byte count (decimal units): ``104.9 MB``."""
    for step, unit in ((1e12, "TB"), (1e9, "GB"), (1e6, "MB"), (1e3, "kB")):
        if count >= step:
            return f"{count / step:.1f} {unit}"
    return f"{count:.0f} B"


def _interval_text(seconds: float) -> str:
    minutes = round(seconds / 60)
    return f"{minutes} min" if minutes >= 1 else f"{round(seconds)} s"


def traffic_section(traffic: dict, rates: dict[str, float] | None, reason: str, elapsed: float | None) -> dict | None:
    """The "Traffic" section of an item's details: the totals and the rate
    (or why there is none)."""
    rows: list[tuple[str, Any]] = [
        ("Received (total)", format_bytes(traffic.get("bytes_in") or 0)),
        ("Sent (total)", format_bytes(traffic.get("bytes_out") or 0)),
    ]
    if rates is not None and elapsed:
        rows += [
            ("Rate in", format_bps(rates["in_bps"])),
            ("Rate out", format_bps(rates["out_bps"])),
            ("Averaged over", f"{_interval_text(elapsed)} since the previous reading"),
        ]
    else:
        rows.append(("Rate", f"not measured ({reason})"))
    return kv_section(SECTION_TRAFFIC, rows)


def parse_time(value: Any) -> datetime | None:
    """An ISO time, or Plexus' ``YYYY-MM-DD HH:MM:SS`` UTC text (a time
    without a zone is UTC); ``None`` when it is none."""
    try:
        parsed = datetime.fromisoformat(str(value or "").strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def reading_time(snapshot: dict) -> datetime | None:
    """When a snapshot's counters were read: its ``traffic_read_at`` (the
    end of the VPN calls), else when it was built."""
    return parse_time(snapshot.get("traffic_read_at") or snapshot.get("generated_at"))


def store_time(at: datetime) -> str:
    """``at`` as the store and the metric samples write it (UTC text)."""
    return at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")


def rate_since(
    previous: dict | None, block: dict, at: datetime | None
) -> tuple[dict[str, float] | None, str, float | None]:
    """``traffic_rates`` of ``block`` read at ``at`` against the previous
    reading of its key (``{"counters", "read_at"}``, as the store keeps
    it), with the seconds between the two."""
    previous_at = parse_time(previous.get("read_at")) if previous else None
    elapsed = (at - previous_at).total_seconds() if at and previous_at else None
    rates, reason = traffic_rates(previous, block, elapsed)
    return rates, reason, elapsed


def traffic_items(snapshot: dict | None) -> list[dict]:
    """The nodes and edges of ``snapshot`` that carry a ``traffic`` block."""
    if not isinstance(snapshot, dict):
        return []
    return [
        item
        for group in ("nodes", "edges")
        for item in snapshot.get(group) or []
        if isinstance(item, dict) and isinstance(item.get("traffic"), dict)
    ]


def apply_traffic_rates(snapshot: dict, previous: dict[str, dict], at: datetime | None) -> int:
    """Compute the rate of every ``traffic`` block of ``snapshot``, read at
    ``at``, against ``previous`` (key -> the last reading of that key:
    ``{"counters", "read_at"}``, from the counter store, which a
    collection and the monitoring poll both update), put it on the item's
    ``metrics`` and add the "Traffic" section. Returns how many rates were
    computed. Mutates ``snapshot``."""
    computed = 0
    for item in traffic_items(snapshot):
        traffic = item["traffic"]
        rates, reason, elapsed = rate_since(previous.get(str(traffic.get("key") or "")), traffic, at)
        if rates is not None:
            metrics = item.get("metrics")
            item["metrics"] = {**(metrics if isinstance(metrics, dict) else {}), **rates}
            traffic.update(rates, interval_seconds=elapsed)
            computed += 1
        section = traffic_section(traffic, rates, reason, elapsed)
        sections = [
            s for s in item.get("sections") or [] if not (isinstance(s, dict) and s.get("title") == SECTION_TRAFFIC)
        ]
        item["sections"] = [*sections, section] if section else sections
    return computed
