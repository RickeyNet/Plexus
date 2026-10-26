"""Tests for availability tracking of topology (API-collected) entities.

Covers, with no network access:
  * extraction  - the entities and states read from the sample snapshot of
                  every integration (Meraki, Cato, FMC, Panorama, Appgate,
                  AWS, Azure, GCP), and the status vocabularies they map
  * tracking    - baseline, transitions, alerts (notification channels and
                  monitoring alerts), no re-alert while down, recovery,
                  entities missing from a collection
  * uptime      - the time-weighted uptime and outage math
  * HTTP API    - the three /api/availability/topology routes, fed by the
                  sample collections of a Meraki org, a Cato account and an
                  AWS account; parameter validation
  * retention   - purge of old transitions and stale entities, and its call
                  from the monitoring retention cleanup
"""

from __future__ import annotations

import copy
from collections import Counter

import netcontrol.app as app_module
import netcontrol.routes.monitoring as monitoring_routes
import netcontrol.routes.topology_availability as tracking
import pytest
import routes.database as db_module
from netcontrol.integrations import availability
from netcontrol.integrations.appgate.normalize import build_snapshot as build_appgate
from netcontrol.integrations.appgate.sample import build_sample_raw as appgate_raw
from netcontrol.integrations.aws.normalize import build_snapshot as build_aws
from netcontrol.integrations.aws.sample import build_sample as aws_sample
from netcontrol.integrations.azure.normalize import build_snapshot as build_azure
from netcontrol.integrations.azure.sample import build_sample as azure_sample
from netcontrol.integrations.cato.normalize import _tunnel_status, build_snapshot as build_cato
from netcontrol.integrations.cato.sample import build_sample_raw as cato_raw
from netcontrol.integrations.fmc.normalize import _TUNNEL_EDGE_STATUS, build_snapshot as build_fmc
from netcontrol.integrations.fmc.sample import build_sample_raw as fmc_raw
from netcontrol.integrations.gcp.normalize import build_snapshot as build_gcp
from netcontrol.integrations.gcp.sample import build_sample as gcp_sample
from netcontrol.integrations.meraki.normalize import _STATUS_RANK, _UPLINK_STATUS, build_snapshot as build_meraki
from netcontrol.integrations.meraki.sample import build_sample_raw as meraki_raw
from netcontrol.integrations.panorama.normalize import build_snapshot as build_panorama
from netcontrol.integrations.panorama.sample import build_sample_raw as panorama_raw

T0 = "2026-01-01 00:00:00"
T1 = "2026-01-02 00:00:00"
T2 = "2026-01-03 00:00:00"
T3 = "2026-01-04 00:00:00"
T4 = "2026-01-05 00:00:00"


def _cloud(build, sample) -> dict:
    resources, connections = sample()
    for row in (*resources, *connections):
        row.setdefault("account_id", 1)
    return build([{"id": 1, "name": "demo", "account_identifier": "sample"}], resources, connections, None)


SNAPSHOTS = {
    "meraki": lambda: build_meraki(meraki_raw()),
    "cato": lambda: build_cato(cato_raw()),
    "fmc": lambda: build_fmc(fmc_raw()),
    "panorama": lambda: build_panorama(panorama_raw()),
    "appgate": lambda: build_appgate(appgate_raw()),
    "aws": lambda: _cloud(build_aws, aws_sample),
    "azure": lambda: _cloud(build_azure, azure_sample),
    "gcp": lambda: _cloud(build_gcp, gcp_sample),
}


def _by_id(entities) -> dict:
    return {(e.entity_type, e.entity_id): e for e in entities}


# ── Vocabularies ─────────────────────────────────────────────────────────────


def test_state_maps_cover_every_normaliser_vocabulary():
    assert set(availability.NODE_STATES) == set(_STATUS_RANK)
    assert availability.NODE_STATES == {
        "online": "up",
        "alerting": "degraded",
        "dormant": "down",
        "offline": "down",
        "unknown": "unknown",
    }
    for raw in _UPLINK_STATUS:
        assert availability.edge_state(raw) != "unknown"
    for raw in _TUNNEL_EDGE_STATUS.values():
        assert availability.edge_state(raw) in ("up", "down")
    for site_status in ("online", "alerting", "offline"):
        for index in (0, 1):
            assert availability.edge_state(_tunnel_status(site_status, index)) != "unknown"
    assert availability.edge_state("failed") == "down"
    assert availability.edge_state("connecting") == "degraded"
    assert availability.edge_state("") == "unknown"
    assert availability.CLOUD_LINK_TYPES["Direct Connect virtual interface"] == "circuit"
    assert availability.CLOUD_LINK_TYPES["ExpressRoute connection"] == "circuit"
    assert availability.CLOUD_LINK_TYPES["VNet peering"] == "peering"
    assert availability.CLOUD_LINK_TYPES["Internet gateway"] == ""


# ── Extraction ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("provider", sorted(SNAPSHOTS))
def test_every_provider_yields_entities_with_valid_states(provider):
    snapshot = SNAPSHOTS[provider]()
    entities = availability.extract_entity_states(provider, 7, snapshot)
    assert entities
    keys = [(e.entity_type, e.entity_id) for e in entities]
    assert len(keys) == len(set(keys))
    nodes = {n["id"]: n for n in snapshot["nodes"]}
    for e in entities:
        assert e.provider == provider and e.org_ref == 7
        assert e.state in availability.STATES
        assert e.entity_type in availability.ENTITY_TYPES
        assert e.name
        if e.entity_type == "device":
            kind = nodes[e.entity_id]["kind"]
            assert kind not in ("wan", "external", "users", "user", "vpc", "vpn_peer")
            assert e.state == availability.node_state(nodes[e.entity_id]["status"])
    # The same snapshot twice gives the same ids (edge ids are positional).
    again = availability.extract_entity_states(provider, 7, SNAPSHOTS[provider]())
    assert keys == [(e.entity_type, e.entity_id) for e in again]


def test_meraki_devices_uplinks_and_tunnels():
    snapshot = SNAPSHOTS["meraki"]()
    entities = availability.extract_entity_states("meraki", 1, snapshot)
    counts = Counter(e.entity_type for e in entities)
    devices = [n for n in snapshot["nodes"] if n["kind"] in ("appliance", "switch", "wireless")]
    assert counts["device"] == len(devices)
    assert counts["uplink"] == sum(1 for e in snapshot["edges"] if e["kind"] == "uplink")
    assert counts["tunnel"] == sum(1 for e in snapshot["edges"] if e["kind"] in ("vpn", "vpn3p"))
    assert "site" not in counts  # a Meraki network is only the worst of its devices
    states = Counter((e.entity_type, e.state) for e in entities)
    assert states[("device", "down")] == sum(1 for n in devices if n["status"] == "offline")
    assert states[("device", "degraded")] == sum(1 for n in devices if n["status"] == "alerting")
    assert states[("uplink", "down")] == sum(
        1 for e in snapshot["edges"] if e["kind"] == "uplink" and e["status"] == "failed"
    )
    uplink = _by_id(entities)[("uplink", "uplink:w:Q2MX-0000-0001:wan1>d:Q2MX-0000-0001:wan1")]
    assert uplink.name == "HQ-DataCenter-MX wan1" and uplink.state == "up" and uplink.site == "HQ-DataCenter"


def test_cato_sites_sockets_and_tunnels_leave_users_and_pops_out():
    snapshot = SNAPSHOTS["cato"]()
    entities = availability.extract_entity_states("cato", 2, snapshot)
    by_id = _by_id(entities)
    sites = [s for s in snapshot["sites"] if not s["id"].startswith("__")]
    assert sum(1 for e in entities if e.entity_type == "site") == len(sites)
    offline = next(s for s in sites if s["status"] == "offline")
    assert by_id[("site", offline["id"])].state == "down"
    assert not any(e.meta.get("kind") in ("user", "cloud") for e in entities if e.entity_type == "device")
    tunnels = [e for e in entities if e.entity_type == "tunnel"]
    assert {e.state for e in tunnels} == {"up", "down"}
    # The primary and secondary IPsec tunnels of a site share their ends.
    assert len({e.entity_id for e in tunnels}) == len(tunnels)


def test_fmc_panorama_and_appgate_track_ha_and_peer_links():
    fmc = availability.extract_entity_states("fmc", 3, SNAPSHOTS["fmc"]())
    assert ("link", "down") in {(e.entity_type, e.state) for e in fmc}  # the failed cluster link
    assert not any(e.meta.get("kind") == "manage" and e.raw_status == "" for e in fmc)
    panorama = availability.extract_entity_states("panorama", 4, SNAPSHOTS["panorama"]())
    assert ("uplink", "down") in {(e.entity_type, e.state) for e in panorama}
    appgate = availability.extract_entity_states("appgate", 5, SNAPSHOTS["appgate"]())
    kinds = Counter((e.entity_type, e.state) for e in appgate)
    assert kinds[("link", "down")] == 1 and kinds[("site", "degraded")] == 1
    assert not any("user" in e.entity_id for e in appgate)


def test_cloud_connections_circuits_and_peerings():
    aws = Counter(e.entity_type for e in availability.extract_entity_states("aws", -1, SNAPSHOTS["aws"]()))
    assert aws["vpn_connection"] == 1 and aws["circuit"] >= 1 and aws["peering"] >= 1
    azure = availability.extract_entity_states("azure", -2, SNAPSHOTS["azure"]())
    vpns = {e.name: e.state for e in azure if e.entity_type == "vpn_connection"}
    assert sorted(vpns.values()) == ["down", "up"]
    assert any(e.entity_type == "circuit" and "ExpressRoute" in e.name for e in azure)
    gcp = Counter(e.entity_type for e in availability.extract_entity_states("gcp", -3, SNAPSHOTS["gcp"]()))
    assert gcp["circuit"] >= 1 and gcp["vpn_connection"] == 2


def test_failed_cloud_connection_is_down():
    snapshot = SNAPSHOTS["aws"]()
    for edge in snapshot["edges"]:
        edge["status"] = "failed" if edge["kind"] == "attach" else edge["status"]
    states = {e.state for e in availability.extract_entity_states("aws", -1, snapshot) if e.entity_type == "circuit"}
    assert states == {"down"}


# ── Uptime math ──────────────────────────────────────────────────────────────


def test_uptime_is_time_weighted_and_ignores_unknown_time():
    # Window of 4 days: unknown for day 1, up day 2, down day 3, degraded day 4.
    stats = db_module.topology_uptime(
        "unknown",
        [(T1, "up"), (T2, "down"), (T3, "degraded")],
        window_start=T0,
        now=T4,
    )
    assert stats["unknown_seconds"] == 86400 and stats["down_seconds"] == 86400
    assert stats["uptime_pct"] == pytest.approx(66.667, abs=0.001)
    assert stats["outages"] == [(T2, T3)]
    # Down since before the window: the outage starts at the window start and is ongoing.
    ongoing = db_module.topology_uptime("down", [], window_start=T0, now=T1)
    assert ongoing["uptime_pct"] == 0 and ongoing["outages"] == [(T0, None)]
    assert db_module.topology_uptime("unknown", [], window_start=T0, now=T1)["uptime_pct"] is None


# ── Tracking ─────────────────────────────────────────────────────────────────


def _cato_with(snapshot: dict, site_status: dict[str, str]) -> dict:
    snapshot = copy.deepcopy(snapshot)
    for site in snapshot["sites"]:
        if site["id"] in site_status:
            site["status"] = site_status[site["id"]]
    return snapshot


@pytest.fixture
def notifications(monkeypatch):
    events: list[dict] = []

    async def _capture(event: dict) -> None:
        events.append(event)

    monkeypatch.setattr(tracking.notification_channels, "on_alert_created", _capture)
    return events


async def test_status_flip_records_transition_alerts_once_and_recovers(notifications):
    base = SNAPSHOTS["cato"]()
    site_id = next(s["id"] for s in base["sites"] if s["status"] == "online" and not s["id"].startswith("__"))
    first = await tracking.record_snapshot_states("cato", 11, base, snapshot_ref="snapshot:1", now=T0)
    assert first["tracked"] == len(availability.extract_entity_states("cato", 11, base))
    assert first["alerts"] == [] and notifications == []  # the first sighting is a baseline

    down = _cato_with(base, {site_id: "offline"})
    second = await tracking.record_snapshot_states("cato", 11, down, snapshot_ref="snapshot:2", now=T1)
    changed = [t for t in second["transitions"] if t["entity_type"] == "site"]
    assert [(t["entity_id"], t["old_state"], t["new_state"]) for t in changed] == [(site_id, "up", "down")]
    assert len(notifications) == 1
    event = notifications[0]
    assert event["severity"] == "critical" and event["alert_type"] == "topology_availability"
    assert event["dedup_key"] == f"topo:cato:11:site:{site_id}"
    assert event["host_id"] is None and "is down" in event["message"]

    # Still down: no second alert.
    await tracking.record_snapshot_states("cato", 11, down, now=T2)
    assert len(notifications) == 1
    # Recovered, then down again: alerts again.
    third = await tracking.record_snapshot_states("cato", 11, base, now=T3)
    assert [t["entity_id"] for t in third["recoveries"]] == [site_id]
    await tracking.record_snapshot_states("cato", 11, _cato_with(base, {site_id: "alerting"}), now=T4)
    assert len(notifications) == 2 and notifications[1]["severity"] == "warning"

    transitions = await db_module.get_topology_transitions(provider="cato", org_ref=11, entity_id=site_id, days=3650)
    assert [t["new_state"] for t in transitions] == ["degraded", "up", "down", "up"]
    assert transitions[-1]["snapshot_ref"] == "snapshot:1" and transitions[-2]["snapshot_ref"] == "snapshot:2"

    summary = await db_module.get_topology_availability_summary("cato", 11, "site", 4, now=T4)
    row = next(e for e in summary["entities"] if e["entity_id"] == site_id)
    # Up day 1, down days 2-3, up day 4 (the change to degraded is at the window end).
    assert row["down_seconds"] == 2 * 86400 and row["uptime_pct"] == pytest.approx(50.0)
    assert row["outage_count"] == 1 and row["current_state"] == "degraded" and row["last_change"] == T4
    outages = await db_module.get_topology_outages("cato", 11, "site", site_id, days=4, now=T4)
    assert [(o["started_at"], o["ended_at"], o["duration_seconds"]) for o in outages] == [(T1, T3, 2 * 86400)]


async def test_entity_missing_from_a_collection_turns_unknown(notifications):
    base = SNAPSHOTS["appgate"]()
    await tracking.record_snapshot_states("appgate", 12, base, now=T0)
    gone = copy.deepcopy(base)
    node = next(n for n in gone["nodes"] if n["kind"] == "appliance" and n["status"] == "online")
    gone["nodes"].remove(node)
    result = await tracking.record_snapshot_states("appgate", 12, gone, now=T1)
    assert result["missing"] == 1 and notifications == []
    states = {s["entity_id"]: s for s in await db_module.list_topology_entity_states("appgate", 12, "device")}
    assert states[node["id"]]["state"] == "unknown" and states[node["id"]]["missing"] is True
    # Back in the next collection.
    await tracking.record_snapshot_states("appgate", 12, base, now=T2)
    states = {s["entity_id"]: s for s in await db_module.list_topology_entity_states("appgate", 12, "device")}
    assert states[node["id"]]["state"] == "up" and states[node["id"]]["missing"] is False


async def test_entity_of_an_inventory_host_raises_a_monitoring_alert(notifications):
    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (931, 'Edge')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type) "
            "VALUES (9311, 931, 'hq-mx', '10.0.0.1', 'meraki')"
        )
        await db.commit()
    finally:
        await db.close()
    base = SNAPSHOTS["meraki"]()
    node = next(n for n in base["nodes"] if n["id"] == "d:Q2MX-0000-0001")
    node["inventory"] = {"host_id": 9311}
    await tracking.record_snapshot_states("meraki", 13, base, now=T0)
    down = copy.deepcopy(base)
    next(n for n in down["nodes"] if n["id"] == node["id"])["status"] = "offline"
    await tracking.record_snapshot_states("meraki", 13, down, now=T1)
    alerts = await db_module.get_monitoring_alerts(host_id=9311)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "topology_availability" and alerts[0]["severity"] == "critical"
    assert alerts[0]["dedup_key"] == f"topo:meraki:13:device:{node['id']}"
    assert notifications == []  # the monitoring alert's own hook notifies


async def test_tracking_never_raises(monkeypatch):
    async def _boom(*_args, **_kwargs):
        raise RuntimeError("db down")

    monkeypatch.setattr(db_module, "apply_topology_entity_states", _boom)
    result = await tracking.record_snapshot_states("meraki", 1, SNAPSHOTS["meraki"]())
    assert result["tracked"] == 0 and result["alerts"] == []


# ── Retention ────────────────────────────────────────────────────────────────


async def test_purge_drops_old_transitions_and_stale_entities():
    old = "2000-01-01 00:00:00"
    await tracking.record_snapshot_states("panorama", 14, SNAPSHOTS["panorama"](), now=old)
    await tracking.record_snapshot_states("fmc", 15, SNAPSHOTS["fmc"]())
    deleted = await db_module.purge_topology_availability(30)
    assert deleted > 0
    assert await db_module.list_topology_entity_states("panorama", 14) == []
    assert await db_module.list_topology_entity_states("fmc", 15)
    assert await db_module.get_topology_transitions(provider="fmc", org_ref=15)


async def test_monitoring_retention_cleanup_purges_topology_availability(monkeypatch):
    calls: list[int] = []

    async def _purge(days: int) -> int:
        calls.append(days)
        return 0

    async def _noop(*_args, **_kwargs):
        return 0

    for name in (
        "delete_old_monitoring_polls",
        "delete_old_monitoring_alerts",
        "delete_old_route_snapshots",
        "delete_expired_suppressions",
    ):
        monkeypatch.setattr(db_module, name, _noop)
    monkeypatch.setattr(monitoring_routes, "metrics_retention_cleanup", _noop)
    monkeypatch.setattr(db_module, "purge_topology_availability", _purge)
    monkeypatch.setattr(monitoring_routes, "_last_retention_cleanup", 0.0)
    monkeypatch.setitem(monitoring_routes.state.MONITORING_CONFIG, "retention_interval_seconds", 0)
    monkeypatch.setitem(monitoring_routes.state.MONITORING_CONFIG, "retention_days", 21)
    await monitoring_routes._run_retention_cleanup_throttled()
    assert calls == [21]


# ── HTTP API ─────────────────────────────────────────────────────────────────


@pytest.fixture
def api(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-topology-availability")
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
    csrf = resp.json().get("csrf_token", "")
    return client, {"X-CSRF-Token": csrf}


def test_api_summary_outages_and_transitions_after_sample_collections(api):
    client, headers = api
    for provider in ("meraki", "cato", "aws"):
        resp = client.post(f"/api/sources/sample?provider={provider}", headers=headers)
        assert resp.status_code == 201, resp.text

    resp = client.get("/api/availability/topology/summary?days=7")
    assert resp.status_code == 200
    body = resp.json()
    assert {o["provider"] for o in body["orgs"]} == {"meraki", "cato", "aws"}
    assert body["entity_count"] == len(body["entities"]) == sum(o["entity_count"] for o in body["orgs"])
    assert body["down"] > 0 and body["up"] > 0

    cato = client.get("/api/availability/topology/summary?provider=cato&entity_type=site").json()
    assert cato["entities"] and {e["entity_type"] for e in cato["entities"]} == {"site"}
    expected = sum(
        1
        for e in availability.extract_entity_states("cato", 0, SNAPSHOTS["cato"]())
        if e.entity_type == "site" and e.state == "down"
    )
    assert cato["down"] == expected
    org_ref = cato["entities"][0]["org_ref"]

    outages = client.get(f"/api/availability/topology/outages?provider=cato&org_ref={org_ref}").json()["outages"]
    assert outages and all(o["ongoing"] for o in outages)

    aws = client.get("/api/availability/topology/summary?provider=aws").json()
    assert aws["entities"] and aws["entities"][0]["org_ref"] == -1
    assert {"vpn_connection", "circuit"} <= {e["entity_type"] for e in aws["entities"]}

    transitions = client.get("/api/availability/topology/transitions?provider=meraki&limit=5").json()["transitions"]
    assert len(transitions) == 5 and all(t["old_state"] == "unknown" for t in transitions)


def test_api_validates_parameters(api):
    client, _headers = api
    assert client.get("/api/availability/topology/summary?provider=bogus").status_code == 422
    assert client.get("/api/availability/topology/summary?entity_type=vpc").status_code == 422
    assert client.get("/api/availability/topology/summary?days=0").status_code == 422
    assert client.get("/api/availability/topology/outages?limit=0").status_code == 422
    assert client.get("/api/availability/topology/transitions?days=366").status_code == 422
