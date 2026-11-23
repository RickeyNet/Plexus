"""Loss, latency and jitter history of WAN links, read in time buckets.

A vendor that keeps a short history of its own link measurements (a Meraki
MX's uplink loss and latency, ``devices/uplinksLossAndLatency``; a Cato
Socket's link RTT, jitter and loss, ``accountMetrics``) is read at each
collection over the time since the last stored sample, in buckets of
``WINDOW_SECONDS``, rather than once at the collection time: an hourly
collection then still leaves a continuous five-minute history.

A normaliser puts the buckets of a link on its snapshot edge as
``metric_samples``, each one bucket::

    {"start": "<UTC YYYY-MM-DD HH:MM:SS>", "at": "<end of the bucket>",
     "latency_ms": float | None, "jitter_ms": float | None,
     "loss_pct": float | None}

Availability tracking (``netcontrol.routes.topology_availability``) stores
each bucket that starts at or after the newest sample already stored for
the entity (``new_samples``) as one raw sample at its ``at`` time, with the
daily rollups, the way an OPNsense gateway's measurements are stored; the
SLA targets of topology entities evaluate them. A value a vendor does not
report is ``None`` and is never made up.

Pure: no database, no network.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from netcontrol.integrations.traffic import parse_time, store_time

# One bucket: the span of one Meraki call (its ``timespan`` is at most 300
# seconds), and the bucket size asked of Cato.
WINDOW_SECONDS = 300
# How far back a collection reads when nothing is stored yet, and at most
# (a source collected less often than this keeps a gap before each read).
DEFAULT_LOOKBACK_SECONDS = 3600
MAX_LOOKBACK_SECONDS = 6 * 3600
# The most buckets one link may carry on a snapshot.
MAX_SAMPLES_PER_LINK = MAX_LOOKBACK_SECONDS // WINDOW_SECONDS + 2
SAMPLE_KEYS = ("latency_ms", "jitter_ms", "loss_pct")


def number(value: Any) -> float | None:
    """``value`` as a finite float; ``None`` for anything else (a bool too)."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        found = float(value)
    except ValueError:
        return None
    return found if math.isfinite(found) else None


def mean(values: Iterable[Any]) -> float | None:
    """The mean of the numbers among ``values`` (rounded to 3 places);
    ``None`` when there is none."""
    found = [v for v in (number(x) for x in values) if v is not None]
    return round(sum(found) / len(found), 3) if found else None


def worst(values: Iterable[Any]) -> float | None:
    """The largest of the numbers among ``values``; ``None`` when none."""
    found = [v for v in (number(x) for x in values) if v is not None]
    return max(found) if found else None


def clamp_lookback(seconds: Any) -> int:
    """``seconds`` rounded up to whole buckets, between one bucket and
    ``MAX_LOOKBACK_SECONDS``; ``DEFAULT_LOOKBACK_SECONDS`` when not a
    positive number."""
    found = number(seconds)
    if found is None or found <= 0:
        return DEFAULT_LOOKBACK_SECONDS
    buckets = max(1, math.ceil(found / WINDOW_SECONDS))
    return min(MAX_LOOKBACK_SECONDS, buckets * WINDOW_SECONDS)


def lookback_since(newest: Any, now: datetime | None = None) -> int:
    """How far back a collection reads: the time since ``newest`` (the
    newest sample stored, UTC text or a datetime), clamped by
    ``clamp_lookback``; ``DEFAULT_LOOKBACK_SECONDS`` when nothing is
    stored."""
    at = newest if isinstance(newest, datetime) else parse_time(newest)
    if at is None:
        return DEFAULT_LOOKBACK_SECONDS
    current = now or datetime.now(UTC)
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    return clamp_lookback((current - at).total_seconds())


def aligned_windows(now: datetime, lookback_seconds: int, *, delay_seconds: int = 0) -> list[tuple[datetime, datetime]]:
    """The buckets that cover ``lookback_seconds`` up to ``now`` minus
    ``delay_seconds`` (how long the vendor needs to have the data), on whole
    multiples of ``WINDOW_SECONDS`` since the epoch, so that consecutive
    collections ask for the same buckets: ``(start, end)``, newest first."""
    current = now if now.tzinfo else now.replace(tzinfo=UTC)
    latest = int(current.timestamp()) - max(0, int(delay_seconds))
    end = latest - latest % WINDOW_SECONDS
    count = clamp_lookback(lookback_seconds) // WINDOW_SECONDS
    found = []
    for index in range(count):
        stop = end - index * WINDOW_SECONDS
        found.append((datetime.fromtimestamp(stop - WINDOW_SECONDS, UTC), datetime.fromtimestamp(stop, UTC)))
    return found


def make_sample(
    start: datetime,
    end: datetime,
    *,
    latency_ms: Any = None,
    jitter_ms: Any = None,
    loss_pct: Any = None,
) -> dict[str, Any] | None:
    """One bucket's sample (see the module docstring); ``None`` when it has
    no value at all."""
    values = {"latency_ms": number(latency_ms), "jitter_ms": number(jitter_ms), "loss_pct": number(loss_pct)}
    if all(v is None for v in values.values()):
        return None
    return {"start": store_time(start), "at": store_time(end), **values}


def edge_samples(item: dict) -> list[dict[str, Any]]:
    """The valid ``metric_samples`` of a snapshot edge, oldest first, at
    most ``MAX_SAMPLES_PER_LINK`` (the newest)."""
    found: list[dict[str, Any]] = []
    for sample in item.get("metric_samples") or []:
        if not isinstance(sample, dict):
            continue
        start, at = parse_time(sample.get("start")), parse_time(sample.get("at"))
        if start is None or at is None or start > at:
            continue
        values = {key: number(sample.get(key)) for key in SAMPLE_KEYS}
        if all(v is None for v in values.values()):
            continue
        found.append({"start": store_time(start), "at": store_time(at), **values})
    found.sort(key=lambda s: str(s["at"]))
    return found[-MAX_SAMPLES_PER_LINK:]


def new_samples(samples: Iterable[dict], newest_stored: str | None) -> list[dict]:
    """The ``samples`` that start at or after ``newest_stored`` (the newest
    sample stored for the entity, UTC text; all of them when none): a
    bucket read again by the next collection is stored once, and a bucket
    that overlaps one already stored is left out."""
    if not newest_stored:
        return list(samples)
    floor = str(newest_stored)[:19].replace("T", " ")
    return [s for s in samples if str(s.get("start") or "") >= floor]


def latest_text(samples: list[dict]) -> str:
    """``loss 0.0 %, latency 21.4 ms, jitter 1.2 ms (5 min to 2026-01-01 10:05 UTC)``
    for the newest of ``samples``; ``""`` when there is none."""
    if not samples:
        return ""
    newest = max(samples, key=lambda s: str(s.get("at") or ""))
    parts = []
    for key, label, unit in (
        ("loss_pct", "loss", " %"),
        ("latency_ms", "latency", " ms"),
        ("jitter_ms", "jitter", " ms"),
    ):
        value = number(newest.get(key))
        if value is not None:
            parts.append(f"{label} {value:.1f}{unit}")
    start, end = parse_time(newest.get("start")), parse_time(newest.get("at"))
    span = ""
    if start and end:
        minutes = round((end - start) / timedelta(minutes=1))
        span = f" ({minutes} min to {store_time(end)[:16]} UTC)"
    return ", ".join(parts) + span
