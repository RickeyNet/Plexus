"""Tests for the Cato Networks topology integration.

Covers the pipeline with no network access:
  * CatoClient  - API key header, GraphQL errors, rate-limit retry, URL trust
  * collector   - reduced-query fallback, best-effort users/ranges, paging
  * normalize   - sites, Sockets, WAN links, PoPs, remote users, subnets
  * unified     - a Cato snapshot merges into the Topology graph as-is
  * HTTP API    - account CRUD, sample build, merged /api/topology, subnets,
                  node details, deep search, collection job
"""

from __future__ import annotations

import json

import httpx
import netcontrol.app as app_module
import pytest
import routes.database as db_module
from netcontrol.integrations.cato.client import CatoApiError, CatoClient, validate_base_url
from netcontrol.integrations.cato.collector import SITES_QUERY_WAN, collect_account, sanitize_options
from netcontrol.integrations.cato.normalize import (
    CLOUD_NODE_ID,
    CLOUD_SITE_ID,
    POP_SITE_ID,
    USER_NODE_PREFIX,
    USERS_SITE_ID,
    build_snapshot,
)
from netcontrol.integrations.cato.sample import build_sample_raw
from netcontrol.integrations.meraki.subnets import subnet_index
from netcontrol.integrations.meraki.unified import graph_to_snapshot, merge_meraki_into_graph, node_details

# ── Client ───────────────────────────────────────────────────────────────────


def _client(handler, **kwargs) -> CatoClient:
    kwargs.setdefault("requests_per_second", 1000)
    return CatoClient("test-key", transport=httpx.MockTransport(handler), **kwargs)


def _operation(request: httpx.Request) -> dict:
    return json.loads(request.content)


@pytest.mark.asyncio
async def test_client_posts_query_with_api_key_header():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == "https://api.catonetworks.com/api/v1/graphql2"
        assert request.headers["x-api-key"] == "test-key"
        body = _operation(request)
        assert body["variables"] == {"accountID": "42"} and "query" in body
        return httpx.Response(200, json={"data": {"accountSnapshot": {"id": "42"}}})

    async with _client(handler) as client:
        data = await client.query("q", "query q { x }", {"accountID": "42"})
    assert data == {"accountSnapshot": {"id": "42"}}


@pytest.mark.asyncio
async def test_client_turns_graphql_errors_into_exceptions_with_detail():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "errors": [
                    {"message": 'Cannot query field "nope" on type "SiteSnapshot".'},
                    {"message": 'Cannot query field "keys" on type "HaStatus".'},
                ]
            },
        )

    async with _client(handler) as client:
        with pytest.raises(CatoApiError) as excinfo:
            await client.query("q", "query q { x }")
    assert excinfo.value.graphql is True and excinfo.value.status_code is None
    # Every refused field is reported, so one collection names them all.
    assert '"nope"' in excinfo.value.detail and '"keys"' in excinfo.value.detail


@pytest.mark.asyncio
async def test_client_retries_rate_limit_then_succeeds(monkeypatch):
    import netcontrol.integrations.cato.client as client_module

    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(client_module.asyncio, "sleep", _no_sleep)
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429)
        if calls["n"] == 2:
            return httpx.Response(200, json={"errors": [{"message": "Rate limit exceeded for accountSnapshot"}]})
        return httpx.Response(200, json={"data": {"ok": True}})

    async with _client(handler) as client:
        assert await client.query("q", "query q { x }") == {"ok": True}
        assert client.stats["rate_limited"] == 2


@pytest.mark.asyncio
async def test_client_does_not_retry_a_rejected_key():
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(401)

    async with _client(handler) as client:
        with pytest.raises(CatoApiError) as excinfo:
            await client.query("q", "query q { x }")
    assert excinfo.value.status_code == 401 and calls["n"] == 1


def test_base_url_must_be_https_cato():
    assert validate_base_url("") == "https://api.catonetworks.com/api/v1/graphql2"
    assert validate_base_url("https://api.us1.catonetworks.com/api/v1/graphql2/").startswith("https://api.us1.")
    for bad in (
        "http://api.catonetworks.com/api/v1/graphql2",
        "https://evil.example.com/api/v1/graphql2",
        "https://catonetworks.com.evil.example/graphql2",
    ):
        with pytest.raises(ValueError):
            validate_base_url(bad)


# ── Collector ────────────────────────────────────────────────────────────────


def test_sanitize_options_defaults_and_coerces():
    opts = sanitize_options({"include_users": 0, "site_name_contains": "  branch ", "bogus": 1})
    assert opts["include_users"] is False and opts["include_ranges"] is True
    assert opts["site_name_contains"] == "branch" and "bogus" not in opts


@pytest.mark.asyncio
async def test_collect_account_falls_back_and_stays_best_effort():
    sample = build_sample_raw()
    seen: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = _operation(request)
        name, variables = body["operationName"], body["variables"]
        seen.append((name, variables))
        if name == "plexusSites":
            return httpx.Response(200, json={"errors": [{"message": 'Cannot query field "hostCount"'}]})
        if name == "plexusSitesWan":
            return httpx.Response(200, json={"errors": [{"message": 'Cannot query field "haRole"'}]})
        if name == "plexusSitesBasic":
            return httpx.Response(200, json={"data": {"accountSnapshot": {"id": "42", "sites": sample["sites"]}}})
        if name == "plexusUsers":
            return httpx.Response(403)
        # entityLookup: the large page is refused, the default page size works.
        if variables["limit"] == 1000:
            return httpx.Response(200, json={"errors": [{"message": "limit too large"}]})
        items = sample["ranges"] if variables["type"] == "siteRange" else sample["interfaces"]
        page = items[variables["from"] : variables["from"] + 2]
        return httpx.Response(200, json={"data": {"entityLookup": {"total": len(items), "items": page}}})

    progress: list[dict] = []
    async with _client(handler) as client:
        raw = await collect_account(client, "42", {"site_name_contains": "branch"}, progress.append)

    assert [s["info"]["name"] for s in raw["sites"]] == ["Branch-Cleveland", "Branch-Denver"]
    assert raw["users"] == []
    assert len(raw["ranges"]) == len(sample["ranges"]) and len(raw["interfaces"]) == len(sample["interfaces"])
    scopes = [e["path"] for e in raw["errors"]]
    assert scopes == [
        "accountSnapshot.sites (full detail)",
        "accountSnapshot.sites (WAN links)",
        "accountSnapshot.users",
    ]
    assert "hostCount" in raw["errors"][0]["message"] and raw["errors"][2]["status"] == 403
    assert progress[-1]["phase"] == "collected" and progress[-1]["calls_done"] == progress[-1]["calls_total"]
    # The reduced snapshot still builds a map.
    assert build_snapshot(raw)["summary"]["sites"] == 2


@pytest.mark.asyncio
async def test_collect_account_keeps_the_wan_links_when_the_full_query_is_refused():
    # The WAN links' public addresses are what tie a vSocket to its cloud instance.
    sample = build_sample_raw()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        name = _operation(request)["operationName"]
        seen.append(name)
        if name == "plexusSites":
            return httpx.Response(200, json={"errors": [{"message": 'Cannot query field "keys" on type "HaStatus"'}]})
        if name == "plexusSitesWan":
            return httpx.Response(200, json={"data": {"accountSnapshot": {"id": "42", "sites": sample["sites"]}}})
        raise AssertionError(name)

    async with _client(handler) as client:
        raw = await collect_account(client, "42", {"include_users": False, "include_ranges": False})

    assert seen == ["plexusSites", "plexusSitesWan"]
    assert [e["path"] for e in raw["errors"]] == ["accountSnapshot.sites (full detail)"]
    wans = [n for n in build_snapshot(raw)["nodes"] if n["kind"] == "wan"]
    assert wans and all(n["ip"] for n in wans if n["status"] == "online")
    assert "tunnelRemoteIP" in SITES_QUERY_WAN and "haStatus" not in SITES_QUERY_WAN


@pytest.mark.asyncio
async def test_collect_account_falls_back_to_the_basic_user_query():
    sample = build_sample_raw()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        name = _operation(request)["operationName"]
        seen.append(name)
        if name == "plexusSites":
            return httpx.Response(200, json={"data": {"accountSnapshot": {"id": "42", "sites": sample["sites"]}}})
        if name == "plexusUsers":
            return httpx.Response(200, json={"errors": [{"message": 'Cannot query field "recentConnections"'}]})
        if name == "plexusUsersBasic":
            return httpx.Response(200, json={"data": {"accountSnapshot": {"users": sample["users"]}}})
        raise AssertionError(name)

    async with _client(handler) as client:
        raw = await collect_account(client, "42", {"include_ranges": False})

    assert seen == ["plexusSites", "plexusUsers", "plexusUsersBasic"]
    assert len(raw["users"]) == 3
    assert [e["path"] for e in raw["errors"]] == ["accountSnapshot.users (full detail)"]


@pytest.mark.asyncio
async def test_collect_account_fails_when_sites_unreadable():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    async with _client(handler) as client:
        with pytest.raises(CatoApiError):
            await collect_account(client, "42")


# ── Normalize ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def snapshot() -> dict:
    return build_snapshot(build_sample_raw())


def _section(entity: dict, title: str) -> dict:
    return next(s for s in entity["sections"] if s["title"] == title)


def test_snapshot_counts_sites_sockets_and_users(snapshot):
    summary = snapshot["summary"]
    assert snapshot["provider"] == "cato" and snapshot["schema"] == 1
    assert summary["sites"] == 4 and summary["devices"] == 5
    assert summary["devices_by_status"] == {"online": 4, "offline": 1}
    assert summary["wan_uplinks"] == 4 and summary["remote_users"] == 3 and summary["vlans"] == 6
    # The cloud is a box of its own, sorted ahead of the sites.
    assert snapshot["sites"][0]["id"] == CLOUD_SITE_ID


def test_snapshot_nodes_are_positioned_and_edges_resolve(snapshot):
    ids = {n["id"] for n in snapshot["nodes"]}
    assert all("x" in n and "y" in n for n in snapshot["nodes"])
    assert all(e["a"] in ids and e["b"] in ids and e["sections"] for e in snapshot["edges"])


def test_snapshot_joins_sockets_to_their_pop_and_pops_to_the_cloud(snapshot):
    links = {(e["a"], e["b"]): e for e in snapshot["edges"]}
    assert links[("d:5003", "pop:New York")]["status"] == "reachable"
    assert links[("d:5001", "pop:Ashburn")]["kind"] == "vpn"
    assert ("pop:Ashburn", CLOUD_NODE_ID) in links and ("pop:New York", CLOUD_NODE_ID) in links
    # A site without a Socket is one node standing for its connection.
    assert links[("s:1004", "pop:Ashburn")]["status"] == "reachable"
    # A site that is down stays attached to the cloud by a down tunnel.
    assert links[("d:5004", CLOUD_NODE_ID)]["status"] == "unreachable"
    down = next(n for n in snapshot["nodes"] if n["id"] == "d:5004")
    assert down["status"] == "offline"


def test_an_ipsec_site_reads_cato_list_of_tunnels():
    # Cato returns a site's IPsec settings as a list, one per tunnel (the
    # sample has the primary second); older captures hold a single object.
    site = next(s for s in build_snapshot(build_sample_raw())["sites"] if s["id"] == "1004")
    rows = _section(site, "IPsec tunnel")["rows"]
    assert [r[1] for r in rows] == ["192.0.2.90", "192.0.2.91"]
    raw = build_sample_raw()
    for item in raw["sites"]:
        if item["info"]["ipsec"]:
            item["info"]["ipsec"] = item["info"]["ipsec"][1]
        # Object fields that come back as a list of objects are read too.
        item["haStatus"] = [item["haStatus"]]
        for device in item["devices"]:
            device["socketInfo"] = [device["socketInfo"]]
            for iface in device["interfaces"]:
                iface["tunnelRemoteIPInfo"] = [iface["tunnelRemoteIPInfo"]]
    built = build_snapshot(raw)
    node = next(n for n in built["nodes"] if n["id"] == "s:1004")
    assert node["ip"] == "192.0.2.90"
    primary = next(n for n in built["nodes"] if n["id"] == "d:5001")
    assert primary["serial"] == "X1700-0001-AAAA" and primary.get("site_sections") is True


def test_snapshot_ha_pair_and_wan_links(snapshot):
    labels = {n["id"]: n["label"] for n in snapshot["nodes"]}
    assert labels["d:5001"] == "HQ-DataCenter (primary)" and labels["d:5002"] == "HQ-DataCenter (secondary)"
    primary = next(n for n in snapshot["nodes"] if n["id"] == "d:5001")
    assert primary.get("site_sections") is True and primary["serial"] == "X1700-0001-AAAA"
    assert len(_section(primary, "WAN links")["rows"]) == 2
    wans = [n for n in snapshot["nodes"] if n["kind"] == "wan"]
    # The unused second WAN port of the branch is not drawn.
    assert sorted(n["ip"] for n in wans) == ["198.51.100.10", "198.51.100.11", "198.51.100.30", "203.0.113.10"]


def test_every_remote_user_is_a_node_in_the_box_of_its_pop(snapshot):
    users = {n["label"]: n for n in snapshot["nodes"] if n["kind"] == "user"}
    assert sorted(users) == ["Dana Reyes", "Priya Nair", "Sam Okafor"]
    dana = users["Dana Reyes"]
    assert dana["id"] == f"{USER_NODE_PREFIX}9001" and dana["ip"] == "10.41.0.11"
    assert dana["site"] == f"{POP_SITE_ID}:New York" and users["Sam Okafor"]["site"] == f"{POP_SITE_ID}:Ashburn"
    boxes = {s["id"]: s for s in snapshot["sites"]}
    ashburn = boxes[f"{POP_SITE_ID}:Ashburn"]
    assert ashburn["name"] == "PoP Ashburn" and ashburn["device_count"] == 3
    assert [r[0] for r in _section(ashburn, "Connected remote users")["rows"]] == ["Priya Nair", "Sam Okafor"]
    # The PoPs' boxes are not counted as sites.
    assert snapshot["summary"]["sites"] == 4
    pop = next(n for n in snapshot["nodes"] if n["id"] == "pop:Ashburn")
    # The PoP is in its box, over its users; the backbone is in a box alone.
    assert pop["site"] == f"{POP_SITE_ID}:Ashburn"
    assert all(pop["y"] < users[name]["y"] for name in ("Priya Nair", "Sam Okafor"))
    assert [n["id"] for n in snapshot["nodes"] if n["site"] == CLOUD_SITE_ID] == [CLOUD_NODE_ID]
    assert ["Remote users connected", "2"] in _section(pop, "Cato PoP")["rows"]
    rows = _section(pop, "Connected remote users")["rows"]
    assert [r[0] for r in rows] == ["Priya Nair", "Sam Okafor"]
    assert rows[1][3:5] == ["10.41.0.12", "198.51.100.202"]


def test_a_remote_user_says_where_it_connects_from_and_to(snapshot):
    users = {n["label"]: n for n in snapshot["nodes"] if n["kind"] == "user"}
    dana = users["Dana Reyes"]
    assert ["Email", "dana.reyes@example.com"] in _section(dana, "Remote user")["rows"]
    origin = dict(_section(dana, "Connecting from")["rows"])
    assert origin["Connected from"] == "Remote (not in an office)" and origin["Public IP"] == "198.51.100.201"
    assert origin["ISP"] == "Example ISP" and origin["City"] == "Columbus" and origin["State"] == "Ohio"
    target = dict(_section(dana, "Connected to (Cato)")["rows"])
    assert target["PoP"] == "New York" and target["VPN IP"] == "10.41.0.11"
    assert dict(_section(dana, "Device")["rows"])["Device"] == "LT-DANA"
    recent = _section(dana, "Recent connections")
    assert recent["rows"][0][4] == "New York" and recent["rows"][0][3] == "Wi-Fi"
    # A user in an office is told which one, from the office's public address.
    priya = dict(_section(users["Priya Nair"], "Connecting from")["rows"])
    assert priya["Connected from"] == "Office: HQ-DataCenter"


def test_remote_users_link_to_the_pops_they_use(snapshot):
    links = {(e["a"], e["b"]): e for e in snapshot["edges"]}
    assert links[(f"{USER_NODE_PREFIX}9002", "pop:Ashburn")]["label"] == "Cato Client"
    assert links[(f"{USER_NODE_PREFIX}9001", "pop:New York")]["kind"] == "vpn"
    # Every user has a PoP, so none is tied to the backbone.
    assert not any(a.startswith(USER_NODE_PREFIX) and b == CLOUD_NODE_ID for a, b in links)


def test_a_pop_only_remote_users_use_is_drawn_behind_them():
    raw = build_sample_raw()
    raw["users"][0]["popName"] = "Hong Kong"
    raw["users"].append({"id": "9", "name": "No PoP", "connectivityStatus": "connected"})
    raw["users"].append({"id": "10", "name": "Gone", "connectivityStatus": "disconnected"})
    snap = build_snapshot(raw)
    links = {(e["a"], e["b"]) for e in snap["edges"]}
    assert (f"{USER_NODE_PREFIX}9001", "pop:Hong Kong") in links and ("pop:Hong Kong", CLOUD_NODE_ID) in links
    # A user without a PoP is tied to the backbone, in a box of its own.
    assert (f"{USER_NODE_PREFIX}9", CLOUD_NODE_ID) in links
    assert next(n for n in snap["nodes"] if n["id"] == f"{USER_NODE_PREFIX}9")["site"] == USERS_SITE_ID
    # A disconnected user is not drawn.
    assert not any(n["id"] == f"{USER_NODE_PREFIX}10" for n in snap["nodes"])


def test_remote_users_can_be_left_out():
    raw = build_sample_raw()
    raw["options"] = {"include_users": False}
    snap = build_snapshot(raw)
    assert not any(n["kind"] == "user" for n in snap["nodes"])
    assert not any(s["id"].startswith(USERS_SITE_ID) for s in snap["sites"])
    # The PoPs keep their boxes.
    assert {s["name"] for s in snap["sites"] if s["id"].startswith(POP_SITE_ID)} == {"PoP Ashburn", "PoP New York"}


def test_snapshot_ranges_are_deduplicated_per_site(snapshot):
    hq = next(s for s in snapshot["sites"] if s["name"] == "HQ-DataCenter")
    subnets = [r[0] for r in _section(hq, "Network ranges")["rows"]]
    assert sorted(subnets) == ["10.50.1.0/24", "10.50.10.0/24", "10.50.20.0/24"]
    branch = next(s for s in snapshot["sites"] if s["name"] == "Branch-Cleveland")
    # Listed both as a range and as the interface's native range: kept once.
    assert [r[:2] for r in _section(branch, "Network ranges")["rows"]] == [["10.60.20.0/24", "Users"]]


def test_subnet_index_places_ranges_on_the_site_gateway(snapshot):
    index = {s["cidr"]: s for s in subnet_index(snapshot)}
    assert index["10.50.10.0/24"]["node_id"] == "d:5001" and index["10.50.10.0/24"]["kind"] == "range"
    assert index["10.50.10.0/24"]["name"] == "Servers (VLAN 10)" and index["10.50.10.0/24"]["in_vpn"] is True
    assert index["172.31.0.0/16"]["node_id"] == "s:1004"
    # Nothing is owned by a PoP, the backbone or the user group.
    assert not any(s["site_id"] == CLOUD_SITE_ID for s in index.values())


def test_account_without_sites_builds_only_the_cloud():
    empty = build_snapshot({"account": {"id": "1"}, "sites": [], "options": {"include_users": False}})
    assert [n["id"] for n in empty["nodes"]] == [CLOUD_NODE_ID]
    assert empty["summary"]["sites"] == 0 and empty["edges"] == []


# ── Merge into the Topology graph ────────────────────────────────────────────


def test_merge_marks_cato_nodes_with_their_provider(snapshot):
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(nodes, edges, [(7, snapshot)], host_node=lambda _id: None, resolve_external=lambda *_: None)
    socket = nodes["meraki:7:d:5003"]
    assert socket["device_type"] == "cato" and socket["device_category"] == "firewall"
    assert socket["meraki"]["provider"] == "cato" and socket["meraki"]["site_name"] == "Branch-Cleveland"
    assert nodes["meraki:7:cato:cloud"]["meraki"]["kind"] == "cloud"
    tunnel = next(e for e in edges if e["from"] == "meraki:7:d:5003" and e["to"] == "meraki:7:pop:New York")
    assert tunnel["protocol"] == "vpn" and tunnel["provider"] == "cato"
    assert len(edges) == len(snapshot["edges"])


def test_export_marks_only_the_cloud_to_pop_links_as_backbone(snapshot):
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(nodes, edges, [(7, snapshot)], host_node=lambda _id: None, resolve_external=lambda *_: None)
    export = graph_to_snapshot({"nodes": list(nodes.values()), "edges": edges}, {7: snapshot}, {})
    backbone = {(e["a"], e["b"]) for e in export["edges"] if e.get("backbone")}
    pops = [n["id"] for n in snapshot["nodes"] if n["id"].startswith("pop:")]
    # The HTML viewer always draws these; site tunnels and users stay optional.
    assert backbone == {(f"meraki:7:{pop}", "meraki:7:cato:cloud") for pop in pops}


def test_node_details_report_the_provider_and_site(snapshot):
    details = node_details(snapshot, "d:5001")
    assert details["provider"] == "cato" and details["site_name"] == "HQ-DataCenter"
    assert any(s["title"] == "Network ranges" for s in details["site_sections"])
    # The cloud's nodes carry no site addressing.
    assert node_details(snapshot, CLOUD_NODE_ID)["site_addressing"] == []


# ── HTTP API ─────────────────────────────────────────────────────────────────


class _CsrfClient:
    def __init__(self, client, csrf):
        self._c, self._headers = client, {"X-CSRF-Token": csrf}

    def get(self, url, **kw):
        return self._c.get(url, **kw)

    def post(self, url, **kw):
        return self._c.post(url, headers=self._headers, **kw)

    def put(self, url, **kw):
        return self._c.put(url, headers=self._headers, **kw)

    def delete(self, url, **kw):
        return self._c.delete(url, headers=self._headers, **kw)


@pytest.fixture
def api(tmp_path, monkeypatch, request):
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "cato.db"))
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-cato")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    # Each test gets a fresh database, where snapshot ids start over; the
    # parsed-snapshot cache is keyed by id and must not outlive the database.
    import netcontrol.routes.meraki_topology as routes_module

    routes_module._SNAPSHOT_CACHE.clear()

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return _CsrfClient(client, resp.json().get("csrf_token", ""))


def test_api_cato_account_crud_keeps_the_key_write_only(api):
    listing = api.get("/api/meraki/orgs").json()
    assert listing["cato_default_options"]["include_users"] is True

    created = api.post(
        "/api/meraki/orgs",
        json={"name": "Acme Cato", "provider": "cato", "org_id": "4242", "api_key": "super-secret-key"},
    )
    assert created.status_code == 201, created.text
    org = created.json()["org"]
    assert org["provider"] == "cato" and org["has_api_key"] is True
    assert org["base_url"] == "https://api.catonetworks.com/api/v1/graphql2"
    assert org["options"] == {
        "site_name_contains": "",
        "include_users": True,
        "include_ranges": True,
        "inventory_enrich": True,
    }
    assert "super-secret-key" not in created.text
    assert "super-secret-key" not in api.get("/api/meraki/orgs").text

    # The key only ever goes to a Cato host, and the provider is a known one.
    bad_url = {"name": "Evil", "provider": "cato", "base_url": "https://api.meraki.com/api/v1"}
    assert api.post("/api/meraki/orgs", json=bad_url).status_code == 400
    assert api.post("/api/meraki/orgs", json={"name": "Other", "provider": "zscaler"}).status_code == 400

    updated = api.put(f"/api/meraki/orgs/{org['id']}", json={"options": {"include_users": False}})
    assert updated.status_code == 200
    assert updated.json()["org"]["options"]["include_users"] is False
    assert updated.json()["org"]["has_api_key"] is True

    # A Meraki organization is unaffected by the provider column.
    meraki = api.post("/api/meraki/orgs", json={"name": "Acme Meraki"}).json()["org"]
    assert meraki["provider"] == "meraki" and "include_lldp_cdp" in meraki["options"]

    assert api.delete(f"/api/meraki/orgs/{org['id']}").status_code == 200


def test_api_cato_sample_is_merged_into_the_topology(api):
    built = api.post("/api/meraki/sample?provider=cato")
    assert built.status_code == 201, built.text
    assert built.json()["summary"]["remote_users"] == 3
    org_ref = built.json()["org_ref"]

    graph = api.get("/api/topology").json()
    cato = [n for n in graph["nodes"] if (n.get("meraki") or {}).get("provider") == "cato"]
    assert {n["meraki"]["kind"] for n in cato} == {"appliance", "wan", "cloud", "user"}
    dana = next(n for n in cato if n["label"] == "Dana Reyes")
    assert dana["ip"] == "10.41.0.11" and dana["meraki"]["site_name"] == "PoP New York"
    assert any(e.get("provider") == "cato" and e["protocol"] == "vpn" for e in graph["edges"])

    details = api.get(f"/api/meraki/nodes?org_ref={org_ref}&node_id=d:5003").json()
    assert details["provider"] == "cato" and details["site_name"] == "Branch-Cleveland"

    # Subnets of Cato sites can be picked as path endpoints.
    subnets = api.get("/api/meraki/subnets").json()["subnets"]
    vpc = next(s for s in subnets if s["cidr"] == "172.31.0.0/16")
    assert vpc["site_name"] == "AWS-us-east-1" and vpc["org_ref"] == org_ref

    # A remote user is found by name, on their own node and their PoP.
    hits = api.get("/api/topology/search/deep?q=dana").json()["results"]
    assert sorted((h["org_ref"], h["node_id"]) for h in hits) == [
        (org_ref, f"{USER_NODE_PREFIX}9001"),
        (org_ref, "pop:New York"),
    ]

    # Both samples share the map and the HTML export.
    assert api.post("/api/meraki/sample").status_code == 201
    merged = api.get("/api/topology").json()["nodes"]
    assert {(n.get("meraki") or {}).get("provider") for n in merged if n.get("meraki")} == {"meraki", "cato"}
    export = api.get("/api/topology/export.html")
    assert export.status_code == 200 and "PoP New York" in export.text


def test_api_cato_build_job_runs_the_cato_collector(api, monkeypatch):
    import netcontrol.routes.meraki_topology as routes_module

    async def _fake_collect(_client, account_id, options, progress):
        assert account_id == "4242" and options["include_ranges"] is True
        progress({"phase": "cato sites"})
        return build_sample_raw()

    monkeypatch.setattr(routes_module, "collect_account", _fake_collect)
    body = {"name": "Acme Cato", "provider": "cato", "org_id": "4242", "api_key": "k"}
    org = api.post("/api/meraki/orgs", json=body).json()["org"]
    started = api.post(f"/api/meraki/orgs/{org['id']}/build")
    assert started.status_code == 202, started.text

    job = {}
    for _ in range(200):
        job = api.get(f"/api/meraki/builds/{started.json()['job_id']}").json()
        if job["status"] != "running":
            break
    assert job["status"] == "completed", job
    assert job["result"]["summary"]["sites"] == 4 and "clients_tracked" not in job["result"]
    # The snapshot is named after the entry, not the collector's placeholder.
    snapshot = api.get(f"/api/meraki/snapshots/{job['result']['snapshot_id']}/data").json()
    assert snapshot["org"]["name"] == "Acme Cato"


def test_api_collection_warnings_are_listed_for_the_sources_dialog(api, monkeypatch):
    import netcontrol.routes.meraki_topology as routes_module

    async def _fake_collect(_client, _account_id, _options, _progress):
        raw = build_sample_raw()
        raw["errors"] = [
            {"scope": "account", "path": "accountSnapshot.users", "status": 403, "message": "Permission denied"}
        ]
        return raw

    monkeypatch.setattr(routes_module, "collect_account", _fake_collect)
    body = {"name": "Warned Cato", "provider": "cato", "org_id": "4243", "api_key": "k"}
    org = api.post("/api/meraki/orgs", json=body).json()["org"]
    started = api.post(f"/api/meraki/orgs/{org['id']}/build")
    job = {}
    for _ in range(200):
        job = api.get(f"/api/meraki/builds/{started.json()['job_id']}").json()
        if job["status"] != "running":
            break
    assert job["status"] == "partial", job

    sources = api.get("/api/topology/sources").json()["sources"]
    source = next(s for s in sources if s["key"] == f"org:{org['id']}")
    assert source["warning_count"] == 1 and source["snapshot_id"] == job["result"]["snapshot_id"]

    listed = api.get(f"/api/meraki/snapshots/{source['snapshot_id']}/warnings").json()
    assert listed["warnings"] == [
        {"scope": "account", "path": "accountSnapshot.users", "status": 403, "message": "Permission denied"}
    ]
    assert api.get("/api/meraki/snapshots/999999/warnings").status_code == 404


def test_api_cato_build_needs_an_account_id(api):
    org = api.post("/api/meraki/orgs", json={"name": "NoAccount", "provider": "cato", "api_key": "k"}).json()["org"]
    started = api.post(f"/api/meraki/orgs/{org['id']}/build")
    assert started.status_code == 202
    job = {}
    for _ in range(200):
        job = api.get(f"/api/meraki/builds/{started.json()['job_id']}").json()
        if job["status"] != "running":
            break
    assert job["status"] == "failed" and "account ID" in job["error"]


def test_export_draws_each_pop_over_its_users(snapshot):
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(nodes, edges, [(7, snapshot)], host_node=lambda _id: None, resolve_external=lambda *_: None)
    export = graph_to_snapshot({"nodes": list(nodes.values()), "edges": edges}, {7: snapshot}, {})
    by_label = {n["label"]: n for n in export["nodes"]}
    pop = by_label["PoP Ashburn"]
    users = [by_label["Priya Nair"], by_label["Sam Okafor"]]
    assert all(u["site"] == pop["site"] and u["y"] > pop["y"] for u in users)
    assert min(u["x"] for u in users) <= pop["x"] <= max(u["x"] for u in users)
