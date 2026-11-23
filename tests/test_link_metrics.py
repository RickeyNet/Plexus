"""Loss, latency and jitter history of Meraki uplinks and Cato WAN links.

Covers, with no network access (the samples of ``meraki.sample`` and
``cato.sample`` and mock transports):
  * link_metrics      - buckets, lookback, which buckets are new
  * Meraki            - ``uplinksLossAndLatency`` windows read best-effort,
                        averaged per uplink onto the uplink edge
  * Cato              - ``accountMetrics`` read in chunks with a reduced
                        fallback, matched to the Socket WAN links
  * tracking          - each bucket stored once at its own time, kept in the
                        daily rollups and evaluated by topology SLA targets
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import netcontrol.routes.monitoring as monitoring_routes
import netcontrol.routes.topology_availability as tracking
import pytest
import routes.database as db_module
from netcontrol.integrations import availability, link_metrics
from netcontrol.integrations.cato import link_metrics as cato_metrics
from netcontrol.integrations.cato.client import CatoClient
from netcontrol.integrations.cato.normalize import build_snapshot as build_cato
from netcontrol.integrations.cato.sample import build_sample_raw as cato_raw
from netcontrol.integrations.meraki.client import MerakiClient
from netcontrol.integrations.meraki.collector import collect_organization, sanitize_options
from netcontrol.integrations.meraki.normalize import build_snapshot as build_meraki
from netcontrol.integrations.meraki.sample import build_sample_raw as meraki_raw
from netcontrol.integrations.meraki.uplink_metrics import uplink_metric_samples

NOW = datetime(2026, 1, 1, 0, 3, 30, tzinfo=UTC)


def _uplinks(provider: str, snapshot: dict) -> dict[str, availability.EntityState]:
    return {
        e.entity_id: e for e in availability.extract_entity_states(provider, 1, snapshot) if e.entity_type == "uplink"
    }


# ── link_metrics ─────────────────────────────────────────────────────────────


def test_windows_are_aligned_newest_first_and_leave_the_delay_out():
    windows = link_metrics.aligned_windows(NOW, 900, delay_seconds=120)
    # 00:03:30 minus 2 minutes is 00:01:30: the last whole window ends at 00:00.
    assert [(s.strftime("%H:%M"), e.strftime("%H:%M")) for s, e in windows] == [
        ("23:55", "00:00"),
        ("23:50", "23:55"),
        ("23:45", "23:50"),
    ]


def test_lookback_is_the_time_since_the_newest_sample_within_bounds():
    assert link_metrics.lookback_since(None, NOW) == link_metrics.DEFAULT_LOOKBACK_SECONDS
    assert link_metrics.lookback_since("2026-01-01 00:00:00", NOW) == 300
    assert link_metrics.lookback_since("2025-12-31 23:00:00", NOW) == 3900
    assert link_metrics.lookback_since("2025-12-01 00:00:00", NOW) == link_metrics.MAX_LOOKBACK_SECONDS
    assert link_metrics.clamp_lookback("x") == link_metrics.DEFAULT_LOOKBACK_SECONDS


def test_only_buckets_from_the_newest_stored_on_are_new():
    samples = [
        {"start": "2026-01-01 00:00:00", "at": "2026-01-01 00:05:00"},
        {"start": "2026-01-01 00:05:00", "at": "2026-01-01 00:10:00"},
        {"start": "2026-01-01 00:07:00", "at": "2026-01-01 00:12:00"},
    ]
    assert link_metrics.new_samples(samples, None) == samples
    assert [s["at"] for s in link_metrics.new_samples(samples, "2026-01-01 00:05:00")] == [
        "2026-01-01 00:10:00",
        "2026-01-01 00:12:00",
    ]
    assert link_metrics.new_samples(samples, "2026-01-01 00:10:00") == []


def test_a_sample_needs_a_value_and_invalid_ones_are_dropped():
    start, end = NOW, NOW.replace(minute=8)
    assert link_metrics.make_sample(start, end) is None
    assert link_metrics.make_sample(start, end, loss_pct=True) is None
    edge = {
        "metric_samples": [
            {"start": "2026-01-01 00:05:00", "at": "2026-01-01 00:00:00", "loss_pct": 1},  # ends before it starts
            {"start": "2026-01-01 00:00:00", "at": "2026-01-01 00:05:00", "loss_pct": "n/a"},
            {"start": "2026-01-01 00:00:00", "at": "2026-01-01 00:05:00", "latency_ms": 7},
        ]
    }
    assert link_metrics.edge_samples(edge) == [
        {
            "start": "2026-01-01 00:00:00",
            "at": "2026-01-01 00:05:00",
            "latency_ms": 7.0,
            "jitter_ms": None,
            "loss_pct": None,
        }
    ]


# ── Meraki ───────────────────────────────────────────────────────────────────


def test_meraki_uplinks_carry_their_loss_and_latency_and_no_jitter():
    snapshot = build_meraki(meraki_raw(branches=4))
    uplinks = _uplinks("meraki", snapshot)
    hub = uplinks["uplink:w:Q2MX-0000-0001:wan1>d:Q2MX-0000-0001:wan1"]
    assert len(hub.metric_samples) == 12
    newest = hub.metric_samples[-1]
    assert newest["start"] == "2025-12-31 23:55:00" and newest["at"] == "2026-01-01 00:00:00"
    assert newest["loss_pct"] == 0.0 and newest["latency_ms"] == 13.4
    # The API reports no jitter, and none is made up.
    assert all(s["jitter_ms"] is None for e in uplinks.values() for s in e.metric_samples)
    # A failed uplink: every probe lost, no latency.
    failed = uplinks["uplink:w:Q2MX-0003-0001:wan2>d:Q2MX-0003-0001:wan2"]
    assert {s["loss_pct"] for s in failed.metric_samples} == {100.0}
    assert {s["latency_ms"] for s in failed.metric_samples} == {None}
    # Measurements are bucketed history, not a single collection-time value.
    assert hub.metrics == {}
    wan = next(n for n in snapshot["nodes"] if n["id"] == "w:Q2MX-0000-0001:wan1")
    rows = dict(next(s for s in wan["sections"] if s["title"] == "WAN uplink")["rows"])
    assert rows["Loss / latency"] == "loss 0.0 %, latency 13.4 ms (5 min to 2026-01-01 00:00 UTC)"


def test_meraki_destinations_of_one_uplink_are_averaged():
    windows = [
        {
            "t0": "2026-01-01T00:00:00Z",
            "t1": "2026-01-01T00:05:00Z",
            "rows": [
                {
                    "serial": "Q2",
                    "uplink": "wan1",
                    "ip": "192.0.2.1",
                    "timeSeries": [{"lossPercent": 0, "latencyMs": 10}],
                },
                {
                    "serial": "Q2",
                    "uplink": "wan1",
                    "ip": "192.0.2.2",
                    "timeSeries": [{"lossPercent": 4, "latencyMs": 30}],
                },
                {"serial": "Q2", "uplink": "wan2", "ip": "192.0.2.1", "timeSeries": [{"lossPercent": None}]},
            ],
        }
    ]
    found = uplink_metric_samples(windows)
    assert found[("Q2", "wan1")][0]["latency_ms"] == 20.0 and found[("Q2", "wan1")][0]["loss_pct"] == 2.0
    assert ("Q2", "wan2") not in found  # nothing measured


def _meraki_client(handler) -> MerakiClient:
    return MerakiClient("test-key", transport=httpx.MockTransport(handler), requests_per_second=10, max_retries=0)


_INVENTORY = {
    "organizations/1": {"id": "1", "name": "Acme"},
    "organizations/1/networks": [{"id": "N1", "name": "HQ", "productTypes": ["appliance"]}],
    "organizations/1/devices": [{"serial": "Q2", "name": "hq-mx", "model": "MX68", "networkId": "N1"}],
}


@pytest.mark.asyncio
async def test_meraki_collection_reads_one_call_per_window():
    asked: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/v1/")
        if path in _INVENTORY:
            return httpx.Response(200, json=_INVENTORY[path])
        if path == "organizations/1/devices/uplinksLossAndLatency":
            asked.append((request.url.params["t0"], request.url.params["t1"]))
            row = {"serial": "Q2", "uplink": "wan1", "ip": "192.0.2.8"}
            return httpx.Response(200, json=[{**row, "timeSeries": [{"lossPercent": 1.0, "latencyMs": 9.0}]}])
        return httpx.Response(404)

    async with _meraki_client(handler) as client:
        raw = await collect_organization(client, "1", metrics_lookback_seconds=900, now=NOW)

    assert sorted(asked) == [
        ("2025-12-31T23:45:00Z", "2025-12-31T23:50:00Z"),
        ("2025-12-31T23:50:00Z", "2025-12-31T23:55:00Z"),
        ("2025-12-31T23:55:00Z", "2026-01-01T00:00:00Z"),
    ]
    assert len(raw["org"]["uplink_loss_latency"]) == 3 and raw["errors"] == []


@pytest.mark.asyncio
async def test_meraki_refused_metrics_cost_one_call_and_a_warning_only():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/v1/")
        calls.append(path)
        if path in _INVENTORY:
            return httpx.Response(200, json=_INVENTORY[path])
        if path == "organizations/1/devices/uplinksLossAndLatency":
            return httpx.Response(403, json={"errors": ["forbidden"]})
        return httpx.Response(404)

    async with _meraki_client(handler) as client:
        raw = await collect_organization(client, "1", metrics_lookback_seconds=3600, now=NOW)

    assert calls.count("organizations/1/devices/uplinksLossAndLatency") == 1
    assert "uplink_loss_latency" not in raw["org"]
    assert [(e["scope"], e["status"]) for e in raw["errors"]] == [("uplink metrics", 403)]
    # Not an organization inventory call: uplinks and tunnels stay clean.
    snapshot = {"collection": {"errors": raw["errors"]}}
    assert "uplink" in availability.clean_entity_types("meraki", snapshot)


@pytest.mark.asyncio
async def test_meraki_uplink_metrics_are_optional():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/v1/")
        assert not path.endswith("uplinksLossAndLatency")
        return httpx.Response(200, json=_INVENTORY[path]) if path in _INVENTORY else httpx.Response(404)

    assert sanitize_options(None)["include_uplink_metrics"] is True
    async with _meraki_client(handler) as client:
        raw = await collect_organization(client, "1", {"include_uplink_metrics": False}, now=NOW)
    assert "uplink_loss_latency" not in raw["org"]


# ── Cato ─────────────────────────────────────────────────────────────────────


def test_cato_wan_links_carry_rtt_jitter_and_loss_of_settled_buckets():
    snapshot = build_cato(cato_raw())
    uplinks = _uplinks("cato", snapshot)
    wan1 = uplinks["uplink:w:5001:1>d:5001:WAN 01"]
    # 13 buckets in the answer; the newest (ending at the read time) is not settled.
    assert len(wan1.metric_samples) == 12
    assert wan1.metric_samples[0] == {
        "start": "2026-10-01 11:55:00",
        "at": "2026-10-01 12:00:00",
        "latency_ms": 11.0,
        "jitter_ms": 1.1,  # the worse direction
        "loss_pct": 0.0,
    }
    wan2 = uplinks["uplink:w:5001:2>d:5001:WAN 02"]
    assert max(s["loss_pct"] for s in wan2.metric_samples) == 1.5
    # An HA pair is one in accountMetrics: filed under the primary Socket only.
    assert uplinks["uplink:w:5002:1>d:5002:WAN 01"].metric_samples == []
    # Madison's WAN 02 is not connected: no WAN link, so its idle series goes nowhere.
    assert "uplink:w:5003:2>d:5003:WAN 02" not in uplinks
    assert len(uplinks["uplink:w:5003:1>d:5003:WAN 01"].metric_samples) == 12
    wan = next(n for n in snapshot["nodes"] if n["id"] == "w:5001:1")
    rows = dict(next(s for s in wan["sections"] if s["title"] == "WAN link")["rows"])
    assert rows["Loss / RTT / jitter"].startswith("loss 0.0 %, latency ")


def test_cato_links_match_by_name_without_interface_info_and_skip_other_units():
    raw = cato_raw()
    for site in raw["link_metrics"]["sites"]:
        for interface in site["interfaces"]:
            interface.pop("interfaceInfo")
            for series in interface["timeseries"]:
                if series["label"] == "rtt" and interface["name"] == "WAN 02":
                    series["units"] = "seconds"
    uplinks = _uplinks("cato", build_cato(raw))
    assert len(uplinks["uplink:w:5001:1>d:5001:WAN 01"].metric_samples) == 12
    # An RTT in another unit is not misread: no RTT, no sample.
    assert uplinks["uplink:w:5001:2>d:5001:WAN 02"].metric_samples == []


def test_cato_link_metrics_not_collected_leave_the_links_without_samples():
    raw = cato_raw()
    raw["link_metrics"] = None
    assert all(not e.metric_samples for e in _uplinks("cato", build_cato(raw)).values())


def _cato_client(handler) -> CatoClient:
    return CatoClient("test-key", transport=httpx.MockTransport(handler), requests_per_second=1000, max_retries=0)


@pytest.mark.asyncio
async def test_cato_metrics_are_read_in_chunks_of_sites():
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        sites = [{"id": s, "interfaces": []} for s in body["variables"]["siteIDs"]]
        return httpx.Response(200, json={"data": {"accountMetrics": {"sites": sites}}})

    errors: list[dict] = []
    site_ids = [str(n) for n in range(cato_metrics.SITES_PER_QUERY + 3)]
    async with _cato_client(handler) as client:
        found = await cato_metrics.collect_link_metrics(client, "42", site_ids, 3600, errors)
    assert errors == [] and len(found["sites"]) == len(site_ids)
    assert [len(b["variables"]["siteIDs"]) for b in seen] == [cato_metrics.SITES_PER_QUERY, 3]
    variables = seen[0]["variables"]
    # The lookback plus the settling time, in five-minute buckets.
    assert variables["timeFrame"] == "last.PT65M" and variables["buckets"] == 13
    assert variables["labels"] == list(cato_metrics.LABELS) and variables["accountID"] == "42"
    assert "groupDevices: true" in seen[0]["query"] and "interfaceInfo" in seen[0]["query"]


@pytest.mark.asyncio
async def test_cato_refused_metrics_fall_back_then_give_up_with_a_warning():
    names: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        names.append(json.loads(request.content)["operationName"])
        return httpx.Response(200, json={"errors": [{"message": "permission denied"}]})

    errors: list[dict] = []
    async with _cato_client(handler) as client:
        found = await cato_metrics.collect_link_metrics(client, "42", ["1", "2"], 3600, errors)
    assert found is None
    assert names == ["plexusLinkMetrics", "plexusLinkMetricsBasic"]
    assert [e["path"] for e in errors] == [f"{cato_metrics.PATH} (link ids)", cato_metrics.PATH]
    assert all("permission denied" in e["message"] for e in errors)
    # A measurement that was not read says nothing about what exists: the
    # account's gone sites and links are still removed.
    snapshot = {"collection": {"errors": errors}}
    assert "uplink" in availability.clean_entity_types("cato", snapshot)
    other = {"collection": {"errors": [*errors, {"scope": "account", "path": "entityLookup", "message": "refused"}]}}
    assert availability.clean_entity_types("cato", other) == frozenset()


# ── Tracking and SLA ─────────────────────────────────────────────────────────


@pytest.fixture
def notifications(monkeypatch):
    events: list[dict] = []

    async def _capture(event: dict) -> None:
        events.append(event)

    monkeypatch.setattr(tracking.notification_channels, "on_alert_created", _capture)
    return events


async def test_buckets_are_stored_once_at_their_own_time(notifications):
    snapshot = build_meraki(meraki_raw(branches=2))
    entity = "uplink:w:Q2MX-0000-0001:wan1>d:Q2MX-0000-0001:wan1"
    await tracking.record_snapshot_states("meraki", 51, snapshot, now="2026-01-01 00:10:00")
    # The next collection reads the same windows again: nothing is stored twice.
    await tracking.record_snapshot_states("meraki", 51, snapshot, now="2026-01-01 01:10:00")
    history = await db_module.get_topology_entity_metric_history(
        "meraki", 51, "uplink", entity, days=2, now="2026-01-01 02:00:00"
    )
    stamps = [s["sampled_at"] for s in history["samples"]]
    assert len(stamps) == 12 and stamps[0] == "2025-12-31 23:05:00" and stamps[-1] == "2026-01-01 00:00:00"
    assert {s["jitter_ms"] for s in history["samples"]} == {None}
    # Kept in the daily rollups of the day each bucket belongs to.
    assert [d["day"] for d in history["daily"]] == ["2025-12-31", "2026-01-01"]
    assert history["daily"][1]["latency"]["samples"] == 1
    assert "jitter" not in history["daily"][0]

    newest = await db_module.latest_topology_entity_metric_times("meraki", 51, "uplink")
    assert newest[("uplink", entity)] == "2026-01-01 00:00:00"
    assert await tracking.metrics_lookback_seconds("meraki", 51, datetime(2026, 1, 1, 1, tzinfo=UTC)) == 3600


async def test_topology_sla_targets_evaluate_meraki_and_cato_links(notifications):
    await tracking.record_snapshot_states("meraki", 52, build_meraki(meraki_raw(branches=4)), now="2026-01-01 00:10:00")
    await tracking.record_snapshot_states("cato", 53, build_cato(cato_raw()), now="2026-10-01 13:00:00")
    loss = await db_module.create_sla_target(
        "Uplink loss", "packet_loss", 1.0, 5.0, window_days=7, provider="meraki", org_ref=52, entity_type="uplink"
    )
    jitter = await db_module.create_sla_target(
        "Link jitter", "jitter", 1.0, 5.0, window_days=7, provider="cato", org_ref=53, entity_type="uplink"
    )
    try:
        await monitoring_routes.run_sla_cycle(datetime(2026, 1, 1, 12, tzinfo=UTC))
        rows = await db_module.get_topology_sla_compliance(provider="meraki", org_ref=52, target_id=loss)
        by_id = {r["entity_id"]: (r["status"], r["value"], r["sample_count"]) for r in rows}
        assert by_id["uplink:w:Q2MX-0000-0001:wan1>d:Q2MX-0000-0001:wan1"] == ("met", 0.0, 12)
        assert by_id["uplink:w:Q2MX-0003-0001:wan2>d:Q2MX-0003-0001:wan2"] == ("breach", 100.0, 12)
        # Raised on the server: no browser involved.
        assert any(n.get("alert_type") == "sla_breach" for n in notifications)

        await monitoring_routes.run_sla_cycle(datetime(2026, 10, 1, 14, tzinfo=UTC))
        rows = await db_module.get_topology_sla_compliance(provider="cato", org_ref=53, target_id=jitter)
        by_id = {r["entity_id"]: (r["status"], r["sample_count"]) for r in rows}
        assert by_id["uplink:w:5001:1>d:5001:WAN 01"] == ("warn", 12)
        assert by_id["uplink:w:5002:1>d:5002:WAN 01"][0] == "no_data"
    finally:
        await db_module.delete_sla_target(loss)
        await db_module.delete_sla_target(jitter)
