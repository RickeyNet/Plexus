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
        if name == "plexusBgpPeersOfSite":
            return httpx.Response(200, json={"data": {"site": {"bgpPeerList": {"bgpPeer": [], "total": 0}}}})
        # entityLookup: the large page is refused, the default page size works.
        if variables["limit"] == 1000:
            return httpx.Response(200, json={"errors": [{"message": "limit too large"}]})
        items = sample["ranges"] if variables["type"] == "siteRange" else sample["interfaces"]
        page = items[variables["from"] : variables["from"] + 2]
        return httpx.Response(200, json={"data": {"entityLookup": {"total": len(items), "items": page}}})

    progress: list[dict] = []
    async with _client(handler) as client:
        raw = await collect_account(
            client, "42", {"site_name_contains": "branch", "include_firewall": False}, progress.append
        )

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
    assert raw["wan_firewall"] is None and raw["internet_firewall"] is None
    assert raw["bgp_peers"] == []
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
        raw = await collect_account(
            client, "42", {"include_users": False, "include_ranges": False, "include_firewall": False}
        )

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
        raw = await collect_account(client, "42", {"include_ranges": False, "include_firewall": False})

    assert seen == ["plexusSites", "plexusUsers", "plexusUsersBasic"]
    assert len(raw["users"]) == 3
    assert [e["path"] for e in raw["errors"]] == ["accountSnapshot.users (full detail)"]


def _policy_response(field: str, payload: dict) -> httpx.Response:
    """A firewall policy as Cato returns it: every rule wrapped in ``rule``."""
    policy = {"enabled": payload["enabled"], "rules": [{"rule": r} for r in payload["rules"]]}
    return httpx.Response(200, json={"data": {"policy": {field: {"policy": policy}}}})


@pytest.mark.asyncio
async def test_collect_account_reads_the_wan_and_internet_firewall_policies():
    sample = build_sample_raw()
    seen: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = _operation(request)
        seen.append((body["operationName"], body["variables"]))
        if body["operationName"] == "plexusSites":
            return httpx.Response(200, json={"data": {"accountSnapshot": {"id": "42", "sites": sample["sites"]}}})
        if body["operationName"] == "plexusWanFirewall":
            assert "policy(accountId: $accountId)" in body["query"] and "direction" in body["query"]
            return _policy_response("wanFirewall", sample["wan_firewall"])
        if body["operationName"] == "plexusInternetFirewall":
            assert "appCategory" in body["query"] and "direction" not in body["query"]
            return _policy_response("internetFirewall", sample["internet_firewall"])
        raise AssertionError(body["operationName"])

    progress: list[dict] = []
    async with _client(handler) as client:
        raw = await collect_account(client, "42", {"include_users": False, "include_ranges": False}, progress.append)

    assert seen[1:] == [("plexusWanFirewall", {"accountId": "42"}), ("plexusInternetFirewall", {"accountId": "42"})]
    assert raw["errors"] == []
    assert raw["wan_firewall"] == sample["wan_firewall"]
    assert raw["internet_firewall"] == sample["internet_firewall"]
    assert progress[-1]["calls_done"] == progress[-1]["calls_total"] == 3


@pytest.mark.asyncio
async def test_collect_account_falls_back_to_the_reduced_firewall_queries():
    sample = build_sample_raw()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        name = _operation(request)["operationName"]
        seen.append(name)
        if name == "plexusSites":
            return httpx.Response(200, json={"data": {"accountSnapshot": {"id": "42", "sites": sample["sites"]}}})
        if name == "plexusWanFirewallBasic":
            return _policy_response("wanFirewall", sample["wan_firewall"])
        if name in ("plexusWanFirewall", "plexusInternetFirewall", "plexusInternetFirewallBasic"):
            return httpx.Response(200, json={"errors": [{"message": 'Cannot query field "policy" on type "Query"'}]})
        raise AssertionError(name)

    async with _client(handler) as client:
        raw = await collect_account(client, "42", {"include_users": False, "include_ranges": False})

    assert seen == [
        "plexusSites",
        "plexusWanFirewall",
        "plexusWanFirewallBasic",
        "plexusInternetFirewall",
        "plexusInternetFirewallBasic",
    ]
    # The reduced rules are kept, and marked as such.
    assert raw["wan_firewall"]["reduced"] is True and len(raw["wan_firewall"]["rules"]) == 4
    # Not collected at all: absent, not an empty policy.
    assert raw["internet_firewall"] is None
    assert [e["path"] for e in raw["errors"]] == [
        "policy.wanFirewall (full detail)",
        "policy.internetFirewall (full detail)",
        "policy.internetFirewall",
    ]
    cloud = next(n for n in build_snapshot(raw)["nodes"] if n["id"] == CLOUD_NODE_ID)["forwarding"]
    assert [p["name"] for p in cloud["policies"]] == ["WAN firewall rules"]
    # The ranges were not asked for either.
    assert cloud["not_collected"] == ["Route table (site network ranges)", "Internet firewall rules"]
    # What the reduced query leaves out may narrow any rule: none is decided on addresses alone.
    assert all(r["src"] == r["dst"] == ["any"] for r in cloud["policies"][0]["rules"])
    assert all("fields Cato did not return" in r["unresolved"] for r in cloud["policies"][0]["rules"])


_BGP_PEER = {
    "id": "b-1",
    "name": "Core router",
    "site": {"id": "1002", "name": "Branch-Cleveland"},
    "peerAsn": 65010,
    "catoAsn": 8075,
    "peerIp": "10.60.20.2",
    "catoIp": "10.60.20.1",
    "advertiseDefaultRoute": True,
    "advertiseAllRoutes": False,
    "advertiseSummaryRoutes": True,
    "summaryRoute": [{"route": "10.0.0.0/8"}],
}

_SITE_IDS = ["1001", "1002", "1003", "1004"]


def _bgp_handler(sample: dict, seen: list[str], answers: dict):
    """The site list and empty lookups, then ``answers[operation](site_id)``
    for the per-site BGP peer queries."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = _operation(request)
        name = body["operationName"]
        seen.append(name)
        if name == "plexusSites":
            return httpx.Response(200, json={"data": {"accountSnapshot": {"id": "42", "sites": sample["sites"]}}})
        if name == "plexusLookup":
            return httpx.Response(200, json={"data": {"entityLookup": {"total": 0, "items": []}}})
        assert name in ("plexusBgpPeersOfSite", "plexusBgpPeersOfSiteBasic")
        assert "site(accountId: $accountId)" in body["query"] and "bgpPeerList(input: $input)" in body["query"]
        assert "$input: BgpPeerListInput!" in body["query"]
        # A secret: never asked for.
        assert "md5AuthKey" not in body["query"]
        site_id = body["variables"]["input"]["site"]["input"]
        assert body["variables"] == {"accountId": "42", "input": {"site": {"by": "ID", "input": site_id}}}
        return answers[name](site_id)

    return handler


def _peers_response(peers: list[dict]) -> httpx.Response:
    return httpx.Response(200, json={"data": {"site": {"bgpPeerList": {"bgpPeer": peers, "total": len(peers)}}}})


def _refused(field: str) -> httpx.Response:
    return httpx.Response(200, json={"errors": [{"message": f'Cannot query field "{field}"'}]})


@pytest.mark.asyncio
async def test_collect_account_reads_the_bgp_peers_site_by_site_with_the_ranges():
    sample = build_sample_raw()
    seen: list[str] = []
    asked: list[str] = []
    unnamed = {"id": "b-2", "name": "VPC router", "peerIp": "172.31.0.2"}

    def of_site(site_id: str) -> httpx.Response:
        asked.append(site_id)
        return _peers_response({"1002": [_BGP_PEER], "1004": [unnamed]}.get(site_id, []))

    progress: list[dict] = []
    async with _client(_bgp_handler(sample, seen, {"plexusBgpPeersOfSite": of_site})) as client:
        raw = await collect_account(client, "42", {"include_users": False, "include_firewall": False}, progress.append)

    assert seen == ["plexusSites", "plexusLookup", "plexusLookup"] + ["plexusBgpPeersOfSite"] * 4
    assert asked == _SITE_IDS
    # A peer that does not name its site is given the one asked for.
    assert raw["bgp_peers"] == [_BGP_PEER, {**unnamed, "site": {"id": "1004"}}]
    assert raw["errors"] == []
    # Progress is reported once for the routing data, not per site.
    assert [p["phase"] for p in progress].count("cato routing") == 1
    assert progress[-1]["calls_done"] == progress[-1]["calls_total"] == 4
    notes = {
        n["id"]: n["forwarding"]["not_collected"]
        for n in build_snapshot(raw)["nodes"]
        if n["id"] in ("d:5003", "s:1004", "d:5001")
    }
    assert notes == {"d:5001": [], "d:5003": ["Routes learned by BGP"], "s:1004": ["Routes learned by BGP"]}


@pytest.mark.asyncio
async def test_collect_account_falls_back_to_the_reduced_bgp_peer_query():
    sample = build_sample_raw()
    seen: list[str] = []
    asked: list[str] = []
    reduced = {"id": "b-1", "name": "Core router", "site": {"id": "1002"}, "peerIp": "10.60.20.2"}

    def basic(site_id: str) -> httpx.Response:
        asked.append(site_id)
        return _peers_response([reduced] if site_id == "1002" else [])

    answers = {"plexusBgpPeersOfSite": lambda _site: _refused("catoAsn"), "plexusBgpPeersOfSiteBasic": basic}
    async with _client(_bgp_handler(sample, seen, answers)) as client:
        raw = await collect_account(client, "42", {"include_users": False, "include_firewall": False})

    # Refused once: the full query is not asked again for the later sites.
    assert seen[3:] == ["plexusBgpPeersOfSite"] + ["plexusBgpPeersOfSiteBasic"] * 4
    assert asked == _SITE_IDS
    assert raw["bgp_peers"] == [reduced]
    assert [e["path"] for e in raw["errors"]] == ["site.bgpPeerList (full detail)"]


@pytest.mark.asyncio
async def test_collect_account_leaves_the_bgp_peers_uncollected_when_cato_refuses_them():
    sample = build_sample_raw()
    seen: list[str] = []
    answers = {
        "plexusBgpPeersOfSite": lambda _site: _refused("catoAsn"),
        "plexusBgpPeersOfSiteBasic": lambda _site: _refused("bgpPeer"),
    }
    async with _client(_bgp_handler(sample, seen, answers)) as client:
        raw = await collect_account(client, "42", {"include_users": False, "include_firewall": False})

    # The first site's reduced query is refused too: no other site is asked.
    assert seen[3:] == ["plexusBgpPeersOfSite", "plexusBgpPeersOfSiteBasic"]
    # None, not []: the normalizer must not take it for sites without peers.
    assert raw["bgp_peers"] is None
    assert [e["path"] for e in raw["errors"]] == ["site.bgpPeerList (full detail)", "site.bgpPeerList"]


@pytest.mark.asyncio
async def test_collect_account_asks_for_no_bgp_peers_without_the_ranges():
    sample = build_sample_raw()
    seen: list[str] = []
    async with _client(_bgp_handler(sample, seen, {})) as client:
        raw = await collect_account(
            client, "42", {"include_users": False, "include_ranges": False, "include_firewall": False}
        )
    assert seen == ["plexusSites"] and raw["bgp_peers"] is None


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
    # A site without a Socket is one node standing for its connection, with
    # an edge per IPsec tunnel: the primary first, the secondary standing by.
    tunnels = [e for e in snapshot["edges"] if (e["a"], e["b"]) == ("s:1004", "pop:Ashburn")]
    assert [(e["kind"], e["label"], e["status"], e["a_port"], e["b_port"]) for e in tunnels] == [
        ("vpn3p", "IPsec tunnel (primary)", "reachable", "192.0.2.90", "192.0.2.80"),
        ("vpn3p", "IPsec tunnel (secondary)", "ready", "192.0.2.91", "192.0.2.81"),
    ]
    assert dict(tunnels[0]["sections"][0]["rows"]) == {
        "A end": "AWS-us-east-1",
        "B end": "PoP Ashburn",
        "Site IP": "192.0.2.90",
        "Cato IP": "192.0.2.80",
        "IKE version": "2",
        "Primary": "Yes",
        "Status": "reachable",
        "Discovered via": "Cato API",
    }
    assert tunnels[0]["sections"][0]["title"] == "IPsec tunnel (primary)"
    # Four Sockets' tunnels, two PoPs' backbone links, three users' and the two IPsec tunnels.
    assert snapshot["summary"]["vpn_tunnels"] == len([e for e in snapshot["edges"] if e["kind"] != "uplink"]) == 11
    # A site that is down stays attached to the cloud by a down tunnel.
    assert links[("d:5004", CLOUD_NODE_ID)]["status"] == "unreachable"
    down = next(n for n in snapshot["nodes"] if n["id"] == "d:5004")
    assert down["status"] == "offline"


def test_an_ipsec_site_reads_cato_list_of_tunnels():
    # Cato returns a site's IPsec settings as a list, one per tunnel (the
    # sample has the primary second); older captures hold a single object.
    site = next(s for s in build_snapshot(build_sample_raw())["sites"] if s["id"] == "1004")
    rows = _section(site, "IPsec tunnel")["rows"]
    assert [(r[1], r[4]) for r in rows] == [("192.0.2.90", "reachable"), ("192.0.2.91", "ready")]
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
    # One tunnel: one edge.
    tunnels = [e for e in built["edges"] if e["a"] == "s:1004"]
    assert [(e["b"], e["label"], e["a_port"]) for e in tunnels] == [
        ("pop:Ashburn", "IPsec tunnel (primary)", "192.0.2.90")
    ]
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
    # An IPsec site's tunnels are IPsec links, not backbone.
    ipsec = [e for e in export["edges"] if e["a"] == "meraki:7:s:1004"]
    assert [(e["b"], e["kind"], e.get("backbone", False)) for e in ipsec] == [
        ("meraki:7:pop:Ashburn", "vpn3p", False),
        ("meraki:7:pop:Ashburn", "vpn3p", False),
    ]
    merged = [e for e in edges if e["from"] == "meraki:7:s:1004"]
    assert [e["protocol"] for e in merged] == ["vpn-ipsec", "vpn-ipsec"]


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
        "include_firewall": True,
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

    # An inventory host on a user's VPN address is not that user: the address
    # is Cato's, handed out to whoever connects.
    group = api.post("/api/inventory", json={"name": "core", "description": ""})
    assert group.status_code in (200, 201), group.text
    host = api.post(
        f"/api/inventory/{group.json()['id']}/hosts",
        json={"hostname": "not-dana", "ip_address": "10.41.0.11", "device_type": "cisco_xe"},
    )
    assert host.status_code in (200, 201), host.text

    graph = api.get("/api/topology").json()
    cato = [n for n in graph["nodes"] if (n.get("meraki") or {}).get("provider") == "cato"]
    assert {n["meraki"]["kind"] for n in cato} == {"appliance", "wan", "cloud", "user"}
    dana = next(n for n in cato if n["label"] == "Dana Reyes")
    assert dana["ip"] == "10.41.0.11" and dana["meraki"]["site_name"] == "PoP New York"
    assert dana["source"] == "meraki" and not dana["in_inventory"]
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


def test_export_draws_a_pop_over_its_only_user_too():
    # One user, whose name sorts before "PoP ...": the tree is still rooted at the PoP.
    raw = build_sample_raw()
    raw["users"][0]["popName"] = "Hong Kong"
    raw["users"][0]["name"] = "Aaron Chen"
    snap = build_snapshot(raw)
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(nodes, edges, [(7, snap)], host_node=lambda _id: None, resolve_external=lambda *_: None)
    export = graph_to_snapshot({"nodes": list(nodes.values()), "edges": edges}, {7: snap}, {})
    by_label = {n["label"]: n for n in export["nodes"]}
    pop, user = by_label["PoP Hong Kong"], by_label["Aaron Chen"]
    assert user["site"] == pop["site"] and user["y"] > pop["y"]


# ── Forwarding data (path tracing) ───────────────────────────────────────────


def _fwd(snapshot: dict, node_id: str) -> dict:
    return next(n for n in snapshot["nodes"] if n["id"] == node_id)["forwarding"]


def test_sockets_pops_and_the_cloud_carry_forwarding_hops(snapshot):
    socket = _fwd(snapshot, "d:5003")  # Branch-Cleveland, on PoP New York
    assert set(socket) == {"version", "interfaces", "routes", "vpn", "policies", "nat", "not_collected"}
    assert [(i["name"], i["kind"], i["ip"], i["cidr"]) for i in socket["interfaces"]] == [
        ("WAN 01", "wan", "198.51.100.30", ""),
        ("Users (10.60.20.0/24)", "lan", "", "10.60.20.0/24"),
    ]
    assert [(r["prefix"], r["kind"], r["peer"]) for r in socket["routes"]] == [
        ("10.60.20.0/24", "connected", None),
        ("0.0.0.0/0", "default", {"org_node": "pop:New York"}),
    ]
    # The firewall policies are the Cloud's, not the Sockets'.
    assert socket["policies"] == [] and socket["nat"] == [] and socket["vpn"] == []
    assert socket["not_collected"] == []

    # A PoP routes its own sites to their Socket, the rest over the backbone.
    pop = {r["prefix"]: r for r in _fwd(snapshot, "pop:New York")["routes"]}
    assert pop["10.60.20.0/24"]["peer"] == {"org_node": "d:5003"} and pop["10.60.20.0/24"]["kind"] == "static"
    assert pop["10.50.10.0/24"]["peer"] == {"org_node": CLOUD_NODE_ID}
    assert pop["10.41.0.11/32"]["peer"] == {"org_node": "cato:user:9001"}
    assert pop["0.0.0.0/0"]["kind"] == "default" and pop["0.0.0.0/0"]["peer"] == {"org_node": CLOUD_NODE_ID}

    # The Cato Cloud hands each range to the PoP of its site.
    cloud = _fwd(snapshot, CLOUD_NODE_ID)
    by_prefix = {r["prefix"]: r for r in cloud["routes"]}
    assert by_prefix["10.50.10.0/24"]["peer"] == {"org_node": "pop:Ashburn"}
    assert by_prefix["10.60.20.0/24"]["peer"] == {"org_node": "pop:New York"}
    assert by_prefix["172.31.0.0/16"]["peer"] == {"org_node": "pop:Ashburn"}
    # A site that is down is reached over its down tunnel to the cloud.
    assert by_prefix["10.61.20.0/24"]["peer"] == {"org_node": "d:5004"}
    assert _fwd(snapshot, "d:5004")["routes"][-1]["peer"] == {"org_node": CLOUD_NODE_ID}
    # Everything else leaves for the internet, behind a Cato address that is not collected.
    assert [(i["name"], i["kind"], i["ip"]) for i in cloud["interfaces"]] == [("Internet", "wan", "")]
    default = by_prefix["0.0.0.0/0"]
    assert (default["kind"], default["interface"], default["peer"]) == ("default", "Internet", None)
    assert cloud["routes"][-1] is default
    assert [(n["kind"], n["original_src"], n["translated_src"]) for n in cloud["nat"]] == [
        ("interface_pat", ["any"], ["interface"])
    ]
    assert [(p["name"], p["applies"], p["default"]) for p in cloud["policies"]] == [
        ("WAN firewall rules", "wan_traffic", "deny"),
        ("Internet firewall rules", "internet_traffic", "allow"),
    ]
    assert cloud["not_collected"] == []
    # Cato enforces its policy at the PoP a flow enters by: every PoP carries the same rule sets.
    for pop_id in ("pop:New York", "pop:Ashburn"):
        assert _fwd(snapshot, pop_id)["policies"] == cloud["policies"]
        assert _fwd(snapshot, pop_id)["policies"] is not cloud["policies"]


def test_firewall_policies_not_collected_are_notes_on_the_pops_and_the_cloud():
    raw = build_sample_raw()
    raw["wan_firewall"] = raw["internet_firewall"] = None
    snapshot = build_snapshot(raw)
    for node_id in (CLOUD_NODE_ID, "pop:New York", "pop:Ashburn"):
        block = _fwd(snapshot, node_id)
        assert block["policies"] == []
        assert block["not_collected"] == ["WAN firewall rules", "Internet firewall rules"]
    assert _fwd(snapshot, "d:5003")["not_collected"] == []


def _rules(snapshot: dict, name: str) -> list[dict]:
    policy = next(p for p in _fwd(snapshot, CLOUD_NODE_ID)["policies"] if p["name"] == name)
    return policy["rules"]


def test_sample_firewall_rules_map_onto_forwarding_rules(snapshot):
    wan = _rules(snapshot, "WAN firewall rules")
    assert [(r["index"], r["name"], r["action"]) for r in wan] == [
        (1, "Isolate Denver from servers", "deny"),
        # Direction BOTH: a second rule with the ends swapped.
        (1, "Isolate Denver from servers (return)", "deny"),
        (2, "Sites to HQ servers", "allow"),
        (3, "Remote users to HQ", "allow"),
        (4, "Any to any", "allow"),
    ]
    # A site is every range of it.
    assert (wan[0]["src"], wan[0]["dst"]) == (["10.61.20.0/24"], ["10.50.10.0/24"])
    assert (wan[1]["src"], wan[1]["dst"]) == (["10.50.10.0/24"], ["10.61.20.0/24"])
    # A range is found by its entity id; a custom service is its protocol and ports.
    servers = wan[2]
    assert servers["src"] == ["10.60.20.0/24", "172.31.0.0/16"] and servers["dst"] == ["10.50.10.0/24"]
    assert (servers["protocol"], servers["dst_ports"], servers["unresolved"]) == ("tcp", "443", [])
    # A users group is not addresses: any, and named as unresolved.
    assert wan[3]["src"] == ["any"] and wan[3]["unresolved"] == ["users group VPN Users"]
    assert wan[3]["dst"] == ["10.50.10.0/24", "10.50.20.0/24", "10.50.1.0/24"]
    assert (wan[4]["src"], wan[4]["dst"], wan[4]["protocol"], wan[4]["dst_ports"]) == (["any"], ["any"], "any", "any")

    internet = _rules(snapshot, "Internet firewall rules")
    assert [(r["index"], r["action"], r["unresolved"]) for r in internet] == [
        (1, "deny", ["app category Malware"]),
        (2, "allow", []),
    ]


def _rule_raw(**fields) -> dict:
    return {"id": "x", "name": "Rule", "index": 1, "enabled": True, "action": "ALLOW", **fields}


def _one_policy(rules: list[dict], key: str = "wan_firewall") -> list[dict]:
    raw = build_sample_raw()
    raw[key] = {"enabled": True, "rules": rules, "reduced": False}
    name = "WAN firewall rules" if key == "wan_firewall" else "Internet firewall rules"
    return _rules(build_snapshot(raw), name)


def test_firewall_rule_addresses_services_and_conditions_are_resolved_or_kept_unresolved():
    rules = _one_policy(
        [
            _rule_raw(
                index=2,
                name="Ranges and users",
                direction="FROM",
                source={
                    "ip": ["10.9.0.1"],
                    "ipRange": [{"from": "10.9.1.0", "to": "10.9.1.255"}],
                    "siteNetworkSubnet": [{"name": "Servers"}],
                    "user": [{"id": "nope", "name": "Dana Reyes"}],
                },
                destination={"networkInterface": [{"name": "HQ-DataCenter \\ LAN 01"}]},
                service={
                    "custom": [
                        {"port": ["80", "8080"], "protocol": "TCP"},
                        {"portRange": {"from": "1000", "to": "2000"}, "protocol": "TCP_UDP"},
                    ]
                },
            ),
            _rule_raw(
                index=1,
                name="Shared names",
                action="PROMPT",
                enabled=False,
                source={"siteNetworkSubnet": [{"name": "Users"}], "host": [{"name": "printer"}]},
                service={"standard": [{"name": "HTTPS"}, {"name": "Microsoft Teams"}]},
                schedule={"activeOn": "WORKING_HOURS"},
                connectionOrigin="REMOTE",
            ),
            _rule_raw(index=3, name="Isolated", action="RBI", service={"standard": [{"name": "SSH"}]}),
        ]
    )
    # Cato's order, by index.
    assert [r["name"] for r in rules] == ["Shared names", "Ranges and users", "Ranges and users", "Isolated"]

    shared = rules[0]
    assert shared["enabled"] is False and shared["action"] == "prompt"
    # "Users" is a range of several sites: not a guess at one of them.
    assert shared["src"] == ["any"] and shared["protocol"] == "any" and shared["dst_ports"] == "any"
    assert shared["unresolved"] == [
        "network range Users",
        "host printer",
        "service Microsoft Teams",
        "connection origin remote",
        "schedule working hours",
    ]

    # FROM: the rule applies from its destination to its source. One rule per protocol.
    tcp, udp = rules[1], rules[2]
    assert tcp["src"] == ["10.50.10.0/24", "10.50.20.0/24", "10.50.1.0/24"]
    assert tcp["dst"] == ["10.9.0.1/32", "10.9.1.0/24", "10.50.10.0/24", "10.41.0.11/32"]
    assert (tcp["protocol"], tcp["dst_ports"]) == ("tcp", "80,8080,1000-2000")
    assert (udp["protocol"], udp["dst_ports"], udp["src"], udp["dst"]) == ("udp", "1000-2000", tcp["src"], tcp["dst"])
    assert tcp["unresolved"] == udp["unresolved"] == []

    isolated = rules[3]
    assert (isolated["action"], isolated["comment"]) == ("allow", "Remote browser isolation")
    assert (isolated["protocol"], isolated["dst_ports"]) == ("tcp", "22")


def test_a_firewall_policy_turned_off_has_no_rules_and_an_unknown_default():
    # What Cato does with traffic when a policy is off is not documented: never a guess.
    raw = build_sample_raw()
    raw["wan_firewall"]["enabled"] = False
    policy = next(p for p in _fwd(build_snapshot(raw), CLOUD_NODE_ID)["policies"] if p["name"] == "WAN firewall rules")
    assert policy["rules"] == [] and policy["default"] == "unknown"


def test_ha_sockets_ipsec_sites_and_users_carry_forwarding_too(snapshot):
    assert _fwd(snapshot, "d:5002")["routes"] == _fwd(snapshot, "d:5001")["routes"]
    ipsec = _fwd(snapshot, "s:1004")
    assert [(r["prefix"], r["peer"]) for r in ipsec["routes"]] == [
        ("172.31.0.0/16", None),
        ("0.0.0.0/0", {"org_node": "pop:Ashburn"}),
    ]
    # Each IPsec tunnel is an interface of the site, named like its edge.
    assert [(i["name"], i["kind"], i["ip"], i["enabled"]) for i in ipsec["interfaces"]] == [
        ("IPsec tunnel (primary)", "tunnel", "192.0.2.90", True),
        ("IPsec tunnel (secondary)", "tunnel", "192.0.2.91", True),
        ("VPC (172.31.0.0/16)", "lan", "", True),
    ]
    user = _fwd(snapshot, "cato:user:9002")
    assert user["interfaces"][0]["ip"] == "10.41.0.12" and user["interfaces"][0]["kind"] == "tunnel"
    assert [(r["prefix"], r["kind"]) for r in user["routes"]] == [
        ("10.41.0.12/32", "connected"),
        ("0.0.0.0/0", "default"),
    ]


def _ipsec_site(raw: dict) -> dict:
    return next(s for s in raw["sites"] if s["id"] == "1004")


def test_ipsec_tunnel_states_follow_the_site():
    # Cato reports no state per tunnel: a disconnected site has every tunnel down.
    raw = build_sample_raw()
    _ipsec_site(raw)["connectivityStatus"] = "disconnected"
    snap = build_snapshot(raw)
    tunnels = [e for e in snap["edges"] if e["a"] == "s:1004"]
    assert [(e["b"], e["status"]) for e in tunnels] == [("pop:Ashburn", "unreachable"), ("pop:Ashburn", "unreachable")]
    block = _fwd(snap, "s:1004")
    assert [(i["name"], i["enabled"]) for i in block["interfaces"] if i["kind"] == "tunnel"] == [
        ("IPsec tunnel (primary)", False),
        ("IPsec tunnel (secondary)", False),
    ]
    # Still routed by its PoP, where the trace meets the down tunnels.
    assert block["routes"][-1]["peer"] == {"org_node": "pop:Ashburn"}
    assert {r["prefix"]: r["peer"] for r in _fwd(snap, "pop:Ashburn")["routes"]}["172.31.0.0/16"] == {
        "org_node": "s:1004"
    }
    site = next(s for s in snap["sites"] if s["id"] == "1004")
    assert [r[4] for r in _section(site, "IPsec tunnel")["rows"]] == ["unreachable", "unreachable"]

    _ipsec_site(raw)["connectivityStatus"] = "degraded"
    degraded = [e["status"] for e in build_snapshot(raw)["edges"] if e["a"] == "s:1004"]
    assert degraded == ["degraded", "degraded"]

    # No PoP: the one tunnel to the Cato Cloud, as for a Socket.
    _ipsec_site(raw)["popName"] = None
    _ipsec_site(raw)["connectivityStatus"] = "disconnected"
    links = [(e["b"], e["kind"], e["status"]) for e in build_snapshot(raw)["edges"] if e["a"] == "s:1004"]
    assert links == [(CLOUD_NODE_ID, "vpn", "unreachable")]


_SITE_BLOCKS = ("d:5001", "d:5002", "d:5003", "d:5004", "s:1004")


def test_a_site_with_a_bgp_peer_may_learn_routes_that_are_not_collected():
    raw = build_sample_raw()
    # Named by site name only (the reduced query's peers may lack the id).
    raw["bgp_peers"] = [_BGP_PEER, {"id": "b-2", "name": "VPC router", "site": {"name": "aws-us-east-1"}}]
    snap = build_snapshot(raw)
    notes = {node_id: _fwd(snap, node_id)["not_collected"] for node_id in _SITE_BLOCKS}
    assert notes == {
        "d:5001": [],
        "d:5002": [],
        "d:5003": ["Routes learned by BGP"],
        "d:5004": [],
        "s:1004": ["Routes learned by BGP"],
    }
    assert _fwd(snap, "pop:New York")["not_collected"] == [] and _fwd(snap, CLOUD_NODE_ID)["not_collected"] == []

    columns = ["Peer", "Peer IP", "Peer ASN", "Cato IP", "Cato ASN", "Advertises"]
    row = ["Core router", "10.60.20.2", "65010", "10.60.20.1", "8075", "Default route, Summary routes 10.0.0.0/8"]
    site = next(s for s in snap["sites"] if s["id"] == "1002")
    socket = next(n for n in snap["nodes"] if n["id"] == "d:5003")
    for entity in (site, socket):
        section = _section(entity, "BGP peers")
        assert section["columns"] == columns and section["rows"] == [row]
    assert not any(s["title"] == "BGP peers" for s in next(x for x in snap["sites"] if x["id"] == "1001")["sections"])


def test_bgp_peers_not_read_are_a_note_on_every_site():
    raw = build_sample_raw()
    raw["bgp_peers"] = None
    snap = build_snapshot(raw)
    for node_id in _SITE_BLOCKS:
        assert _fwd(snap, node_id)["not_collected"] == ["Routes learned by BGP (BGP peers were not read)"]
    # The PoPs and the Cloud have the ranges; only the sites may learn more.
    assert _fwd(snap, "pop:Ashburn")["not_collected"] == []
    # Read and empty: nothing is missing (the sample).
    assert all(_fwd(build_snapshot(build_sample_raw()), n)["not_collected"] == [] for n in _SITE_BLOCKS)


def test_ranges_not_read_leave_every_route_table_incomplete():
    raw = build_sample_raw()
    raw["ranges"] = raw["interfaces"] = []
    raw["errors"] = [{"scope": "account", "path": "entityLookup siteRange", "status": 403, "message": "denied"}]
    snap = build_snapshot(raw)
    for node_id in (*_SITE_BLOCKS, "pop:Ashburn", "pop:New York", CLOUD_NODE_ID):
        assert _fwd(snap, node_id)["not_collected"] == ["Route table (site network ranges)"], node_id
    assert _fwd(snap, "cato:user:9001")["not_collected"] == []

    # Not asked for: neither the ranges nor the BGP peers were read, and one note says so.
    raw = build_sample_raw()
    raw["options"] = {**raw["options"], "include_ranges": False}
    raw["ranges"] = raw["interfaces"] = []
    raw["bgp_peers"] = None
    snap = build_snapshot(raw)
    for node_id in (*_SITE_BLOCKS, "pop:Ashburn", CLOUD_NODE_ID):
        assert _fwd(snap, node_id)["not_collected"] == ["Route table (site network ranges)"], node_id
