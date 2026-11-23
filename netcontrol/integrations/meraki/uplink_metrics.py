"""Meraki MX uplink loss and latency as bucketed link samples.

``collector._uplink_loss_latency`` stores the answers of
``GET /organizations/{organizationId}/devices/uplinksLossAndLatency`` as
``raw["org"]["uplink_loss_latency"]``: one ``{"t0", "t1", "rows"}`` per
five-minute window. ``uplink_metric_samples`` turns them into one sample
per uplink and window (``netcontrol.integrations.link_metrics``), which
``normalize`` puts on the uplink's edge as ``metric_samples``:

  - ``loss_pct``: the mean of the window's ``lossPercent`` points (packet
    loss in percent);
  - ``latency_ms``: the mean of its ``latencyMs`` points (milliseconds); a
    point with no latency (all probes lost) is left out of the mean;
  - ``jitter_ms``: never set. The API reports no jitter, and Plexus does
    not derive one from the latency points (they are already averages).

An MX may probe more than one destination per uplink (``ip``: a public address by
default); the points of every destination of the uplink are averaged
together, so the sample is the uplink's, as the availability tracker keys
it (serial and interface).

Pure: no database, no network.
"""

from __future__ import annotations

from typing import Any

from netcontrol.integrations.link_metrics import make_sample, mean
from netcontrol.integrations.traffic import parse_time


def uplink_metric_samples(windows: Any) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """``{(serial, interface): [sample, ...]}`` (oldest first) of the stored
    windows; an uplink with no number in a window has no sample for it."""
    found: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for window in windows if isinstance(windows, list) else []:
        if not isinstance(window, dict):
            continue
        start, end = parse_time(window.get("t0")), parse_time(window.get("t1"))
        if start is None or end is None:
            continue
        points: dict[tuple[str, str], list[dict]] = {}
        for row in window.get("rows") or []:
            if not isinstance(row, dict):
                continue
            serial, uplink = str(row.get("serial") or ""), str(row.get("uplink") or "")
            if not serial or not uplink:
                continue
            series = row.get("timeSeries")
            points.setdefault((serial, uplink), []).extend(p for p in series or [] if isinstance(p, dict))
        for key, rows in points.items():
            sample = make_sample(
                start,
                end,
                latency_ms=mean(p.get("latencyMs") for p in rows),
                loss_pct=mean(p.get("lossPercent") for p in rows),
            )
            if sample is not None:
                found.setdefault(key, []).append(sample)
    for samples in found.values():
        samples.sort(key=lambda s: s["at"])
    return found
