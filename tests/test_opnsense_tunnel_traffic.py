"""Tests for the traffic of OPNsense tunnels (IPsec, WireGuard, OpenVPN).

Covers, with no network access and invented sample data:
  * normalize - the ``traffic`` block of each IPsec connection (phase 1
                totals, a counter per child SA), WireGuard peer, OpenVPN
                client instance and OpenVPN server (the sum of its clients)
  * rates     - ``traffic_rates`` / ``apply_traffic_rates``: first reading,
                a normal delta, a counter reset, a rekeyed child SA, a gap
                too long, an entity gone and back, the "Traffic" section
  * storage   - the rates stored with the topology entity metrics (raw and
                daily rows), next to the gateway latency, and read back
  * store     - collections and monitoring polls interleaved through the
                counter store: one sample per reading, no overlap; a rekey
                between two polls costs one sample; a poll before any
                collection writes nothing; an older reading never replaces
                a newer one; cleanup (gone key, retention, deleted source)
  * poll      - the VPN counters read in the health session of the poll;
                a failed VPN read leaves the health intact
  * HTTP API  - two sample collections give a tunnel ``avg_in_bps`` /
                ``avg_out_bps`` in the summary and ``in_bps`` / ``out_bps``
                samples in /api/availability/topology/metrics
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta

import httpx
import netcontrol.app as app_module
import netcontrol.routes.opnsense_health as health_poll
import netcontrol.routes.topology_availability as tracking
import netcontrol.routes.topology_traffic as topology_traffic
import pytest
import routes.database as db_module
from netcontrol.integrations import availability, traffic
from netcontrol.integrations.opnsense.client import OpnsenseClient
from netcontrol.integrations.opnsense.normalize import build_snapshot, vpn_traffic_blocks
from netcontrol.integrations.opnsense.sample import IPSEC_BRANCH_1, build_sample_raw, sample_api_answers

T0 = "2026-03-01T10:00:00+00:00"
T1 = "2026-03-01T11:00:00+00:00"  # one hour later
_FW = "d:fw-edge-1.example.com"
_WG = "wg:wg0:c2FtcGxlLXBlZXItYnJhbmNoLTItcHVibGljLWtleTA="


def _snapshot(raw: dict | None = None, at: str = T0) -> dict:
    snapshot = build_snapshot(raw or build_sample_raw())
    snapshot["generated_at"] = at
    return snapshot


def _traffic(snapshot: dict) -> dict[str, dict]:
    return {item["traffic"]["key"]: item for item in [*snapshot["nodes"], *snapshot["edges"]] if item.get("traffic")}


def _peer(raw: dict, name: str) -> dict:
    return next(r for r in raw["wireguard"] if r.get("name") == name and r["type"] == "peer")


def _store(snapshot: dict | None) -> dict[str, dict]:
    """The counter store as ``snapshot``'s readings would leave it."""
    if snapshot is None:
        return {}
    return {
        key: {"counters": item["traffic"]["counters"], "read_at": snapshot["generated_at"]}
        for key, item in _traffic(snapshot).items()
    }


def _apply(after: dict, before: dict | None) -> int:
    """``apply_traffic_rates`` of ``after`` against the readings of ``before``."""
    return traffic.apply_traffic_rates(after, _store(before), traffic.reading_time(after))


def _section(item: dict) -> dict[str, str]:
    found = next(s for s in item["sections"] if s["title"] == traffic.SECTION_TRAFFIC)
    return dict(found["rows"])


# ── Normalize ────────────────────────────────────────────────────────────────


def test_every_vpn_type_carries_its_byte_counters():
    blocks = {key: item["traffic"] for key, item in _traffic(_snapshot()).items()}
    # IPsec: the phase 1 totals, one counter per installed child SA (its unique id).
    branch = blocks[f"ipsec:{IPSEC_BRANCH_1}"]
    assert (branch["bytes_in"], branch["bytes_out"]) == (104857600, 52428800)
    assert branch["counters"] == {"sa:5": [104857600, 52428800]}
    # A connection that is down has no child SA, so no counter (a known zero).
    partner = next(b for k, b in blocks.items() if k.startswith("ipsec:") and b["bytes_in"] == 0 and not b["counters"])
    assert partner["counters"] == {}
    # WireGuard: transfer-rx / transfer-tx of the peer.
    assert blocks[_WG]["counters"] == {"peer": [2048000, 1024000]}
    # OpenVPN client instance: bytes_received / bytes_sent (digit strings) of its session.
    client = blocks["ovpn:client:2"]
    assert (client["bytes_in"], client["bytes_out"]) == (73400320, 36700160)
    assert list(client["counters"]) == ["|203.0.113.150|2026-11-13 22:10:00"]
    # An OpenVPN client instance that does not run reports no counters: no block.
    assert "ovpn:client:4" not in blocks
    # OpenVPN server: the sum of its connected clients, a counter per session.
    server = blocks["ovpn:server:1"]
    assert (server["bytes_in"], server["bytes_out"]) == (102400, 204800)
    assert list(server["counters"]) == ["ana.example|198.51.100.50:51234|2026-11-14 07:30:00"]


def test_traffic_items_are_the_tracked_tunnels_and_servers():
    snapshot = _snapshot()
    items = _traffic(snapshot)
    # Every tunnel but the OpenVPN client instance that does not run.
    without = [e["b"] for e in snapshot["edges"] if e["kind"] == "vpn3p" and not e.get("traffic")]
    assert without == ["p:ovpn:4"]
    assert items["ovpn:server:1"]["kind"] == "vpn_server"
    # Gateways carry no traffic block.
    assert not any(e.get("traffic") for e in snapshot["edges"] if e["kind"] == "uplink")


def test_ipsec_counters_unknown_without_child_sa_rows():
    raw = build_sample_raw()
    raw["ipsec_phase2"] = None  # the phase 2 call did not answer
    branch = _traffic(_snapshot(raw))[f"ipsec:{IPSEC_BRANCH_1}"]["traffic"]
    assert branch["bytes_in"] == 104857600 and branch["counters"] is None


# ── Rates ────────────────────────────────────────────────────────────────────


def test_first_reading_gives_no_rate_but_shows_the_totals():
    snapshot = _snapshot()
    assert _apply(snapshot, None) == 0
    wg = _traffic(snapshot)[_WG]
    assert "metrics" not in wg
    rows = _section(wg)
    assert rows["Received (total)"] == "2.0 MB" and rows["Sent (total)"] == "1.0 MB"
    assert rows["Rate"] == f"not measured ({traffic.REASON_FIRST})"


def test_normal_delta_gives_the_average_rate():
    before = _snapshot(at=T0)
    raw = build_sample_raw()
    _peer(raw, "branch-2").update({"transfer-rx": 2048000 + 450_000_000, "transfer-tx": 1024000 + 90_000_000})
    after = _snapshot(raw, at=T1)
    assert _apply(after, before) == 8  # every block with counters
    wg = _traffic(after)[_WG]
    assert wg["metrics"] == {"in_bps": 1_000_000.0, "out_bps": 200_000.0}
    rows = _section(wg)
    assert rows["Rate in"] == "1.00 Mbps" and rows["Rate out"] == "200.00 Kbps"
    assert rows["Averaged over"] == "60 min since the previous reading"
    # Unchanged counters: a true zero rate.
    assert _traffic(after)["ovpn:server:1"]["metrics"] == {"in_bps": 0.0, "out_bps": 0.0}
    # The rate reaches the availability entity like a gateway's latency.
    entity = next(
        e
        for e in availability.extract_entity_states("opnsense", 1, after)
        if e.entity_id.endswith(":WireGuard") and "branch-2" in e.entity_id
    )
    assert entity.metrics == {"in_bps": 1_000_000.0, "out_bps": 200_000.0}


def test_counter_reset_gives_no_sample():
    before = _snapshot(at=T0)
    raw = build_sample_raw()
    _peer(raw, "branch-2").update({"transfer-rx": 1000, "transfer-tx": 5_000_000})  # interface restarted
    after = _snapshot(raw, at=T1)
    _apply(after, before)
    wg = _traffic(after)[_WG]
    assert "in_bps" not in (wg.get("metrics") or {})
    assert _section(wg)["Rate"] == f"not measured ({traffic.REASON_RESET})"


def test_rekeyed_child_sa_gives_no_sample_and_a_new_sa_counts_whole():
    before = _snapshot(at=T0)
    raw = build_sample_raw()
    child = raw["ipsec_phase2"][IPSEC_BRANCH_1][0]
    child.update({"uniqueid": "6", "bytes-in": "9000000000", "bytes-out": "9000000000"})  # bigger, yet a new SA
    after = _snapshot(raw, at=T1)
    _apply(after, before)
    branch = _traffic(after)[f"ipsec:{IPSEC_BRANCH_1}"]
    assert "metrics" not in branch
    assert _section(branch)["Rate"] == f"not measured ({traffic.REASON_GONE})"

    # Previous SA still there plus a new one: the new SA started after the
    # previous reading, so all of its bytes belong to the interval.
    raw = build_sample_raw()
    first = raw["ipsec_phase2"][IPSEC_BRANCH_1][0]
    second = {**first, "uniqueid": "7", "bytes-in": "36000000", "bytes-out": "0"}
    raw["ipsec_phase2"][IPSEC_BRANCH_1].append(second)
    after = _snapshot(raw, at=T1)
    _apply(after, before)
    assert _traffic(after)[f"ipsec:{IPSEC_BRANCH_1}"]["metrics"] == {"in_bps": 80000.0, "out_bps": 0.0}


def test_long_gap_and_unknown_times_give_no_sample():
    before = _snapshot(at=T0)
    late = (datetime.fromisoformat(T0) + timedelta(seconds=traffic.MAX_RATE_GAP_SECONDS + 60)).isoformat()
    after = _snapshot(at=late)
    assert _apply(after, before) == 0
    assert _section(_traffic(after)[_WG])["Rate"] == f"not measured ({traffic.REASON_GAP})"
    # Exactly at the limit is still trusted.
    edge = (datetime.fromisoformat(T0) + timedelta(seconds=traffic.MAX_RATE_GAP_SECONDS)).isoformat()
    assert _apply(_snapshot(at=edge), before) == 8
    # Same second (or a clock going back), or no time: nothing.
    assert _apply(_snapshot(at=T0), before) == 0
    assert _apply(_snapshot(at=""), before) == 0


def test_entity_gone_and_back():
    raw = build_sample_raw()
    raw["wireguard"] = [r for r in raw["wireguard"] if r.get("name") != "branch-2"]
    gone = _snapshot(raw, at=T0)
    assert _WG not in _traffic(gone)
    # Back: there is no previous reading of it, so this is a first reading.
    back = _snapshot(at=T1)
    _apply(back, gone)
    assert _section(_traffic(back)[_WG])["Rate"] == f"not measured ({traffic.REASON_FIRST})"
    # Back with its counters restarted from zero, against an older reading: a reset.
    raw = build_sample_raw()
    _peer(raw, "branch-2").update({"transfer-rx": 10, "transfer-tx": 10})
    back = _snapshot(raw, at=T1)
    _apply(back, _snapshot(at=T0))
    assert "metrics" not in _traffic(back)[_WG]


def test_traffic_rates_rules():
    block = traffic.traffic_block("k", None, {"a": [100, 100]})
    assert block == {"key": "k", "bytes_in": 100, "bytes_out": 100, "counters": {"a": [100, 100]}}
    grown = traffic.traffic_block("k", None, {"a": [1100, 100]})
    assert traffic.traffic_rates(block, grown, 8) == ({"in_bps": 1000.0, "out_bps": 0.0}, "")
    assert traffic.traffic_rates(None, grown, 8) == (None, traffic.REASON_FIRST)
    assert traffic.traffic_rates(block, traffic.traffic_block("k", [5, 5], None), 8) == (None, traffic.REASON_UNKNOWN)
    assert traffic.traffic_rates(block, grown, 0) == (None, traffic.REASON_TIME)
    assert traffic.traffic_rates(block, grown, None) == (None, traffic.REASON_TIME)
    assert traffic.byte_count("12") == 12 and traffic.byte_count(-1) is None and traffic.byte_count("1e3") is None
    assert traffic.byte_count(True) is None and traffic.counter_pair("1", None) is None
    assert traffic.format_bps(1_500_000_000) == "1.50 Gbps" and traffic.format_bytes(999) == "999 B"


# ── Storage ──────────────────────────────────────────────────────────────────


def _rated_pair() -> tuple[dict, dict]:
    before = _snapshot(at=T0)
    raw = build_sample_raw()
    _peer(raw, "branch-2").update({"transfer-rx": 2048000 + 450_000_000, "transfer-tx": 1024000 + 90_000_000})
    after = _snapshot(raw, at=T1)
    _apply(after, before)
    return before, after


async def test_rates_are_stored_with_the_entity_metrics(monkeypatch):
    async def _capture(event: dict) -> None:
        return None

    monkeypatch.setattr(tracking.notification_channels, "on_alert_created", _capture)
    _before, after = _rated_pair()
    now = "2026-03-01 11:00:00"
    await tracking.record_snapshot_states("opnsense", 71, after, now=now)
    values = await db_module.get_topology_entity_metric_values(
        1, now="2026-03-01 12:00:00", provider="opnsense", org_ref=71
    )
    wg_key = next(k for k in values["entities"] if k[2] == "tunnel" and "branch-2" in k[3])
    wg = values["entities"][wg_key]
    assert wg["avg_in_bps"] == 1_000_000.0 and wg["avg_out_bps"] == 200_000.0
    assert wg["traffic_in_samples"] == 1 and wg["avg_latency_ms"] is None and wg["latency_samples"] == 0
    # Gateways keep their latency, with no traffic.
    gw = next(v for k, v in values["entities"].items() if k[2] == "uplink" and v["latency_samples"])
    assert gw["avg_in_bps"] is None and gw["traffic_in_samples"] == 0
    # The OpenVPN server (a device entity) has its rate too.
    assert values["entities"][("opnsense", 71, "device", "ovpn:server:1")]["avg_in_bps"] == 0.0

    history = await db_module.get_topology_entity_metric_history(
        "opnsense", 71, wg_key[2], wg_key[3], days=1, now="2026-03-01 12:00:00"
    )
    assert history["samples"] == [
        {
            "sampled_at": now,
            "latency_ms": None,
            "jitter_ms": None,
            "loss_pct": None,
            "in_bps": 1_000_000.0,
            "out_bps": 200_000.0,
        }
    ]
    assert history["daily"][0]["traffic_in"] == {
        "avg": 1_000_000.0,
        "min": 1_000_000.0,
        "max": 1_000_000.0,
        "samples": 1,
    }
    assert "latency" not in history["daily"][0]

    # The daily rows outlive the raw retention.
    await db_module.purge_topology_entity_metrics(1, 3650)
    history = await db_module.get_topology_entity_metric_history(
        "opnsense", 71, wg_key[2], wg_key[3], days=3650, now="2026-03-02 12:00:00"
    )
    assert history["samples"] == [] and history["summary"]["avg_out_bps"] == 200_000.0


# ── Collections and monitoring polls share the counter store ────────────────

_START = datetime(2026, 3, 1, 10, 0, tzinfo=UTC)


def _at(minutes: int) -> datetime:
    return _START + timedelta(minutes=minutes)


def _text(minutes: int) -> str:
    return _at(minutes).strftime("%Y-%m-%d %H:%M:%S")


def _raw_with(wg_rx: int = 0, sa_bytes: int = 0, sa_id: str = "5") -> dict:
    """The sample payloads, branch-2 having received ``wg_rx`` more bytes and
    branch 1's child SA (unique id ``sa_id``) at ``sa_bytes`` in."""
    raw = build_sample_raw()
    _peer(raw, "branch-2")["transfer-rx"] = 2048000 + wg_rx
    child = raw["ipsec_phase2"][IPSEC_BRANCH_1][0]
    child.update({"uniqueid": sa_id, "bytes-in": str(sa_bytes or 104857600)})
    return raw


async def _collect(org_ref: int, raw: dict, minutes: int) -> dict:
    """A stored collection: rates from the store, readings into it, metrics recorded."""
    snapshot = build_snapshot(raw)
    snapshot["traffic_read_at"] = _at(minutes).isoformat()
    await topology_traffic.record_collection_traffic("opnsense", org_ref, snapshot)
    await tracking.record_snapshot_states("opnsense", org_ref, snapshot, now=_text(minutes))
    return snapshot


async def _poll(org_ref: int, raw: dict, minutes: int) -> int:
    return await topology_traffic.record_poll_traffic("opnsense", org_ref, vpn_traffic_blocks(raw), _at(minutes))


async def _samples(org_ref: int, key: str) -> list[dict]:
    entity = (await db_module.get_topology_traffic_counters("opnsense", org_ref))[key]
    history = await db_module.get_topology_entity_metric_history(
        "opnsense", org_ref, entity["entity_type"], entity["entity_id"], days=1, now=_text(120)
    )
    return [{"at": s["sampled_at"], "in": s["in_bps"]} for s in history["samples"]]


@pytest.fixture
def quiet(monkeypatch):
    async def _capture(event: dict) -> None:
        return None

    monkeypatch.setattr(tracking.notification_channels, "on_alert_created", _capture)


async def test_collection_and_polls_interleave_one_sample_per_reading(quiet):
    # 37.5 MB every 5 minutes is 1 Mbps.
    await _collect(91, _raw_with(), 0)
    stored = await db_module.get_topology_traffic_counters("opnsense", 91)
    assert stored[_WG]["entity_type"] == "tunnel" and stored[_WG]["read_at"] == _text(0)
    assert await _poll(91, _raw_with(37_500_000), 5) == 8  # every tunnel and server the collection named
    assert await _poll(91, _raw_with(75_000_000), 10) == 8
    snapshot = await _collect(91, _raw_with(112_500_000), 15)
    rows = _section(_traffic(snapshot)[_WG])
    assert rows["Rate in"] == "1.00 Mbps" and rows["Averaged over"] == "5 min since the previous reading"
    assert await _samples(91, _WG) == [
        {"at": _text(5), "in": 1_000_000.0},
        {"at": _text(10), "in": 1_000_000.0},
        {"at": _text(15), "in": 1_000_000.0},
    ]
    assert (await db_module.get_topology_traffic_counters("opnsense", 91))[_WG]["read_at"] == _text(15)


async def test_a_rekey_between_two_polls_costs_one_sample(quiet):
    ipsec = f"ipsec:{IPSEC_BRANCH_1}"
    await _collect(92, _raw_with(sa_bytes=1_000_000), 0)
    await _poll(92, _raw_with(sa_bytes=38_500_000), 5)  # 1 Mbps
    await _poll(92, _raw_with(sa_bytes=2_000_000, sa_id="6"), 10)  # rekeyed: the old SA's tail is unknown
    await _poll(92, _raw_with(sa_bytes=39_500_000, sa_id="6"), 15)  # 1 Mbps on the new SA
    assert await _samples(92, ipsec) == [{"at": _text(5), "in": 1_000_000.0}, {"at": _text(15), "in": 1_000_000.0}]
    # The WireGuard peer, not rekeyed, has all three.
    assert len(await _samples(92, _WG)) == 3


async def test_a_poll_before_any_collection_writes_nothing(quiet):
    assert await _poll(93, _raw_with(37_500_000), 5) == 0
    assert await db_module.get_topology_traffic_counters("opnsense", 93) == {}
    values = await db_module.get_topology_entity_metric_values(1, now=_text(60), provider="opnsense", org_ref=93)
    assert values["entities"] == {}


async def test_an_older_reading_never_replaces_a_newer_one(quiet):
    await _collect(95, _raw_with(), 10)
    # A poll whose read finished before the collection's: no sample, store unchanged.
    assert await _poll(95, _raw_with(37_500_000), 5) == 0
    stored = await db_module.get_topology_traffic_counters("opnsense", 95)
    assert stored[_WG]["read_at"] == _text(10) and stored[_WG]["counters"] == {"peer": [2048000, 1024000]}


async def test_the_store_is_cleaned_up(quiet):
    await _collect(94, _raw_with(), 0)
    assert _WG in await db_module.get_topology_traffic_counters("opnsense", 94)
    # A clean collection that no longer lists the peer drops its key.
    raw = _raw_with()
    raw["wireguard"] = [r for r in raw["wireguard"] if r.get("name") != "branch-2"]
    await _collect(94, raw, 60)
    stored = await db_module.get_topology_traffic_counters("opnsense", 94)
    assert _WG not in stored and stored
    # A collection with a failed call proves nothing: keys are kept.
    raw = _raw_with()
    raw["errors"] = [{"scope": "vpn", "path": "/wireguard/service/show", "status": 500, "message": "failed"}]
    raw["wireguard"] = None
    await _collect(94, raw, 120)
    assert set(await db_module.get_topology_traffic_counters("opnsense", 94)) == set(stored)
    # Old readings go with the monitoring retention; all of them with the source.
    await db_module.save_topology_traffic_counters(
        "opnsense", 94, [{"key": "wg:old", "counters": {"peer": [1, 1]}}], "2000-01-01 00:00:00"
    )
    await db_module.purge_topology_entity_metrics(30, 3650)
    assert "wg:old" not in await db_module.get_topology_traffic_counters("opnsense", 94)
    await db_module.delete_meraki_org(94)
    assert await db_module.get_topology_traffic_counters("opnsense", 94) == {}


# ── The monitoring poll of the firewall ──────────────────────────────────────

_KEY, _SECRET = "plexus-key-0009", "plexus-secret-0009-not-real"


class _Firewall:
    """The sample's answers over the API: GET, and POST for the child SAs."""

    def __init__(self) -> None:
        self.answers = sample_api_answers()
        self.calls: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/")
        self.calls.append(path)
        found = self.answers.get(path)
        if found is not None and request.method == "POST":
            found = found.get(json.loads(request.content)["id"])
        if found is None:
            return httpx.Response(404, json={"errorMessage": "Endpoint not found"})
        return httpx.Response(200, json=copy.deepcopy(found))


@pytest.fixture
def firewall(monkeypatch):
    import netcontrol.routes.meraki_topology as topology_routes

    fake = _Firewall()

    def _opnsense_client(org, secret, options, **kwargs):
        key, value = secret.split(":", 1)
        kwargs["transport"] = httpx.MockTransport(fake.handler)
        return OpnsenseClient(org["base_url"], key, value, requests_per_second=1000, **kwargs)

    monkeypatch.setattr(topology_routes, "_opnsense_client", _opnsense_client)
    health_poll.forget_sources()
    yield fake
    health_poll.forget_sources()


async def _firewall_host(name: str) -> tuple[dict, int]:
    group = await db_module.create_group(f"opn-traffic-{name}")
    host_id = await db_module.add_host(group, "fw-edge-1.example.com", "192.0.2.1", "opnsense")
    org = await db_module.create_meraki_org(
        f"Traffic firewall {name}",
        provider="opnsense",
        base_url="https://fw9.example.com",
        api_key=f"{_KEY}:{_SECRET}",
        created_by="test",
    )
    snapshot = build_snapshot(build_sample_raw())
    snapshot["summary"][health_poll.SUMMARY_KEY] = host_id
    await db_module.create_meraki_snapshot(org["id"], snapshot, built_by="test")
    # The collection named the entities five minutes ago.
    snapshot["traffic_read_at"] = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    await topology_traffic.record_collection_traffic("opnsense", int(org["id"]), snapshot)
    return await db_module.get_host(host_id), int(org["id"])


async def test_the_poll_reads_the_vpn_counters_in_the_health_session(firewall, quiet):
    host, org_ref = await _firewall_host("a")
    result: dict = {}
    assert await health_poll.add_to_poll(host, result) is True and "opnsense_health" in result
    assert "ipsec/sessions/search_phase2" in firewall.calls and "wireguard/service/show" in firewall.calls
    assert "ipsec/connections/search_child" not in firewall.calls  # configured child SAs: the collection's
    # Unchanged counters five minutes later: a true 0 for every tunnel.
    values = await db_module.get_topology_entity_metric_values(1, provider="opnsense", org_ref=org_ref)
    tunnels = [v for k, v in values["entities"].items() if k[2] == "tunnel"]
    assert tunnels and all(v["avg_in_bps"] == 0.0 and v["traffic_in_samples"] == 1 for v in tunnels)


async def test_a_failed_vpn_read_leaves_the_health_intact(firewall, quiet, monkeypatch):
    host, org_ref = await _firewall_host("b")

    async def _broken(*_args, **_kwargs):
        raise RuntimeError("vpn read failed")

    monkeypatch.setattr(health_poll, "collect_vpn", _broken)
    result: dict = {"poll_status": "error", "poll_error": "snmp timeout"}
    assert await health_poll.add_to_poll(host, result) is True
    assert result["opnsense_health"] and result["poll_status"] == "ok"
    values = await db_module.get_topology_entity_metric_values(1, provider="opnsense", org_ref=org_ref)
    assert values["entities"] == {}


# ── HTTP API ─────────────────────────────────────────────────────────────────


@pytest.fixture
def api(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-tunnel-traffic")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    import netcontrol.routes.meraki_topology as topology_routes

    topology_routes._SNAPSHOT_CACHE.clear()

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return client, {"X-CSRF-Token": resp.json().get("csrf_token", "")}


def test_api_reports_tunnel_traffic_after_two_collections(api, monkeypatch):
    import netcontrol.routes.meraki_topology as topology_routes

    client, headers = api
    first = client.post("/api/sources/sample?provider=opnsense", headers=headers)
    assert first.status_code == 201, first.text
    org_ref = first.json()["org_ref"]
    try:
        # The second collection, half an hour later, with branch-2 having moved traffic.
        real_raw, real_build = topology_routes.build_opnsense_sample_raw, topology_routes.build_opnsense_snapshot

        def raw_later() -> dict:
            raw = real_raw()
            _peer(raw, "branch-2").update({"transfer-rx": 2048000 + 225_000_000, "transfer-tx": 1024000})
            return raw

        def build_later(raw: dict) -> dict:
            snapshot = real_build(raw)
            later = datetime.now(UTC) + timedelta(minutes=30)
            snapshot["generated_at"] = later.isoformat(timespec="seconds")
            return snapshot

        monkeypatch.setattr(topology_routes, "build_opnsense_sample_raw", raw_later)
        monkeypatch.setattr(topology_routes, "build_opnsense_snapshot", build_later)
        second = client.post("/api/sources/sample?provider=opnsense", headers=headers)
        assert second.status_code == 201, second.text

        summary = client.get(f"/api/availability/topology/summary?provider=opnsense&org_ref={org_ref}").json()
        wg = next(e for e in summary["entities"] if e["entity_type"] == "tunnel" and "branch-2" in e["entity_id"])
        # About 1 Mbps in (225 MB in ~30 min; the build times are a few ms apart).
        assert 990_000 < wg["avg_in_bps"] < 1_010_000 and wg["avg_out_bps"] == 0.0
        gateway = next(e for e in summary["entities"] if e["entity_type"] == "uplink" and e["avg_latency_ms"])
        assert gateway["avg_in_bps"] is None and gateway["avg_out_bps"] is None

        metrics = client.get(
            "/api/availability/topology/metrics",
            params={"provider": "opnsense", "org_ref": org_ref, "entity_type": "tunnel", "entity_id": wg["entity_id"]},
        )
        assert metrics.status_code == 200, metrics.text
        found = metrics.json()
        assert len(found["samples"]) == 1 and found["samples"][0]["out_bps"] == 0.0
        assert found["summary"]["avg_in_bps"] == wg["avg_in_bps"] and found["daily"][0]["traffic_in"]["samples"] == 1

        # The stored snapshot shows the rate in the tunnel's details.
        stored = client.get(f"/api/sources/snapshots/{second.json()['snapshot_id']}/data")
        assert stored.status_code == 200, stored.text
        edge = next(e for e in stored.json()["edges"] if (e.get("traffic") or {}).get("key") == _WG)
        rows = _section(edge)
        assert rows["Rate in"].endswith((" Kbps", " Mbps")) and rows["Rate out"] == "0 bps"
        assert edge["metrics"]["in_bps"] == wg["avg_in_bps"]
    finally:
        assert client.delete(f"/api/sources/{org_ref}", headers=headers).status_code == 200
        topology_routes._SNAPSHOT_CACHE.clear()


def test_sample_payloads_are_not_mutated_between_builds():
    raw = build_sample_raw()
    copy_before = copy.deepcopy(raw)
    _snapshot(raw)
    assert raw == copy_before
