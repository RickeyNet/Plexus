"""Tests for the Meraki topology integration.

Covers the whole pipeline with no network access:
  * MerakiClient - pagination, 429 retry, redirect/base-URL trust rules
  * collector    - best-effort endpoints, secret scrubbing, network filters
  * normalize    - nodes/links/VPN/sections/layout from the sample organization
  * html_export  - self-contained document with safely embedded JSON
  * unified      - merge into the Topology graph, node details, deep search,
                   whole-topology export snapshot
  * HTTP API     - org CRUD (write-only key), sample build, merged /api/topology,
                   node details, deep search, HTML export
"""

from __future__ import annotations

import json
import re

import httpx
import netcontrol.app as app_module
import pytest
import routes.database as db_module
from netcontrol.integrations.meraki.client import MerakiApiError, MerakiClient, validate_base_url
from netcontrol.integrations.meraki.clients import client_records
from netcontrol.integrations.meraki.collector import collect_organization, sanitize_options, scrub_secrets
from netcontrol.integrations.meraki.enrich import enrich_snapshot, load_inventory_index, show_commands_for
from netcontrol.integrations.meraki.forwarding import meraki_addresses
from netcontrol.integrations.meraki.html_export import export_filename, render_topology_html
from netcontrol.integrations.meraki.normalize import VPN_PEER_SITE_ID, InventoryIndex, build_snapshot
from netcontrol.integrations.meraki.sample import build_sample_raw
from netcontrol.integrations.meraki.subnets import subnet_index
from netcontrol.integrations.meraki.unified import (
    build_search_index,
    external_key,
    graph_to_snapshot,
    meraki_graph_id,
    merge_meraki_into_graph,
    node_details,
    search_index,
)

# ── Client ───────────────────────────────────────────────────────────────────


def _client(handler, **kwargs) -> MerakiClient:
    kwargs.setdefault("requests_per_second", 10)
    return MerakiClient("test-key", transport=httpx.MockTransport(handler), **kwargs)


@pytest.mark.asyncio
async def test_client_sends_bearer_and_follows_pagination():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        assert request.headers["Authorization"] == "Bearer test-key"
        if "startingAfter" not in str(request.url):
            link = '<https://api.meraki.com/api/v1/organizations/1/networks?perPage=2&startingAfter=b>; rel="next"'
            return httpx.Response(200, json=[{"id": "a"}, {"id": "b"}], headers={"Link": link})
        return httpx.Response(200, json=[{"id": "c"}])

    async with _client(handler) as client:
        items = await client.get_all("organizations/1/networks", per_page=2)
    assert [i["id"] for i in items] == ["a", "b", "c"]
    assert len(seen) == 2 and "perPage=2" in seen[0]


@pytest.mark.asyncio
async def test_client_retries_rate_limit_then_succeeds(monkeypatch):
    import netcontrol.integrations.meraki.client as client_module

    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(client_module.asyncio, "sleep", _no_sleep)
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(429, headers={"Retry-After": "1"})
        return httpx.Response(200, json={"ok": True})

    async with _client(handler) as client:
        assert await client.get("organizations/1") == {"ok": True}
        assert client.stats["rate_limited"] == 2


@pytest.mark.asyncio
async def test_client_raises_with_status_and_does_not_retry_4xx():
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404, json={"errors": ["not found"]})

    async with _client(handler) as client:
        with pytest.raises(MerakiApiError) as excinfo:
            await client.get("networks/x/appliance/vlans")
    assert excinfo.value.status_code == 404
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_client_follows_meraki_redirect_but_refuses_foreign_host():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.meraki.com" and request.url.path.endswith("/shard"):
            return httpx.Response(302, headers={"Location": "https://n123.meraki.com/api/v1/shard"})
        if request.url.host == "n123.meraki.com":
            # The API key must survive a same-domain redirect.
            assert request.headers["Authorization"] == "Bearer test-key"
            return httpx.Response(200, json={"shard": True})
        return httpx.Response(302, headers={"Location": "https://evil.example.com/steal"})

    async with _client(handler) as client:
        assert await client.get("shard") == {"shard": True}
        with pytest.raises(MerakiApiError, match="untrusted host"):
            await client.get("elsewhere")


def test_base_url_must_be_https_meraki():
    assert validate_base_url("") == "https://api.meraki.com/api/v1"
    assert validate_base_url("https://api.meraki.cn/api/v1/") == "https://api.meraki.cn/api/v1"
    for bad in ("http://api.meraki.com/api/v1", "https://evil.example.com/api/v1", "https://notmeraki.com.evil.io"):
        with pytest.raises(ValueError):
            validate_base_url(bad)


# ── Collector ────────────────────────────────────────────────────────────────


def test_scrub_secrets_removes_nested_secret_keys():
    payload = {
        "name": "Guest",
        "psk": "hunter2",
        "radiusServers": [{"host": "10.0.0.1", "secret": "s3cret"}],
        "peers": [{"name": "aws", "secret": "ipsec-shared", "publicIp": "192.0.2.1"}],
    }
    cleaned = scrub_secrets(payload)
    assert "hunter2" not in json.dumps(cleaned) and "s3cret" not in json.dumps(cleaned)
    assert cleaned["peers"][0] == {"name": "aws", "publicIp": "192.0.2.1"}


def test_sanitize_options_clamps_and_defaults():
    opts = sanitize_options({"requests_per_second": 500, "max_concurrency": 0, "network_tags": "a, b ,", "bogus": 1})
    assert opts["requests_per_second"] == 10.0
    assert opts["max_concurrency"] == 1
    assert opts["network_tags"] == ["a", "b"]
    assert "bogus" not in opts
    assert sanitize_options(None)["include_lldp_cdp"] is True


@pytest.mark.asyncio
async def test_collect_organization_is_best_effort_and_filters_networks():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/v1/")
        routes = {
            "organizations/1": {"id": "1", "name": "Acme"},
            "organizations/1/networks": [
                {"id": "N1", "name": "HQ", "productTypes": ["appliance", "switch"], "tags": ["prod"]},
                {"id": "N2", "name": "Lab", "productTypes": ["appliance"], "tags": ["lab"]},
            ],
            "organizations/1/devices": [
                {"serial": "S1", "name": "hq-mx", "model": "MX68", "networkId": "N1", "productType": "appliance"},
                {"serial": "S2", "name": "lab-mx", "model": "MX68", "networkId": "N2", "productType": "appliance"},
            ],
            "organizations/1/appliance/vpn/thirdPartyVPNPeers": {"peers": [{"name": "aws", "secret": "shh"}]},
            "networks/N1/appliance/vlans": [{"id": 10, "name": "Data", "subnet": "10.0.10.0/24"}],
            "networks/N1/clients": [{"mac": "aa:bb:cc:00:00:01", "ip": "10.0.10.50", "recentDeviceSerial": "S1"}],
        }
        if path == "networks/N1/clients":
            assert request.url.params["timespan"] == "86400" and request.url.params["perPage"] == "1000"
        if path in routes:
            return httpx.Response(200, json=routes[path])
        if path == "networks/N1/appliance/staticRoutes":
            return httpx.Response(403, json={"errors": ["forbidden"]})
        return httpx.Response(404, json={"errors": ["n/a"]})

    progress: list[dict] = []
    async with _client(handler, max_retries=0) as client:
        raw = await collect_organization(client, "1", {"network_tags": ["prod"]}, progress.append)

    assert [n["id"] for n in raw["networks"]] == ["N1"]
    assert [d["serial"] for d in raw["devices"]] == ["S1"]
    assert raw["networks_detail"]["N1"]["vlans"][0]["subnet"] == "10.0.10.0/24"
    assert raw["networks_detail"]["N1"]["clients"][0]["mac"] == "aa:bb:cc:00:00:01"
    # 404s are "not applicable" and silent; the 403 is a recorded warning.
    assert [e["status"] for e in raw["errors"]] == [403]
    assert "shh" not in json.dumps(raw)
    assert progress and progress[-1]["phase"] == "collected"


@pytest.mark.asyncio
async def test_collect_organization_fails_when_inventory_unreadable():
    async with _client(lambda _r: httpx.Response(401), max_retries=0) as client:
        with pytest.raises(MerakiApiError) as excinfo:
            await collect_organization(client, "1")
    assert excinfo.value.status_code == 401


# ── Snapshot builder ─────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def snapshot() -> dict:
    inventory = InventoryIndex(
        [{"id": 7, "hostname": "core-sw1", "ip_address": "10.0.0.2", "device_type": "cisco_xe", "serial_number": ""}],
        [],
    )
    return build_snapshot(build_sample_raw(branches=6), inventory)


def _section(entity: dict, title: str) -> dict:
    return next(s for s in entity["sections"] if s["title"] == title)


def test_snapshot_counts_and_kinds(snapshot):
    summary = snapshot["summary"]
    assert summary["sites"] == 8
    assert summary["devices_by_kind"]["appliance"] == 8
    assert summary["external_neighbors"] == 1
    assert summary["inventory_matches"] == 1
    assert summary["vpn_tunnels"] > 0 and summary["lan_links"] > 0 and summary["wan_uplinks"] > 0


def test_snapshot_links_reference_known_nodes_and_are_positioned(snapshot):
    ids = {n["id"] for n in snapshot["nodes"]}
    assert all(e["a"] in ids and e["b"] in ids for e in snapshot["edges"])
    sites = {s["id"]: s for s in snapshot["sites"]}
    positions = set()
    for node in snapshot["nodes"]:
        site = sites[node["site"]]
        assert site["x"] <= node["x"] <= site["x"] + site["w"]
        assert site["y"] <= node["y"] <= site["y"] + site["h"]
        positions.add((node["x"], node["y"]))
    assert len(positions) == len(snapshot["nodes"]), "two nodes share a position"


def test_snapshot_vpn_tunnels_are_deduplicated_and_peers_grouped(snapshot):
    vpn_pairs = [frozenset((e["a"], e["b"])) for e in snapshot["edges"] if e["kind"] == "vpn"]
    assert len(vpn_pairs) == len(set(vpn_pairs))
    peer = next(n for n in snapshot["nodes"] if n["kind"] == "vpn_peer")
    assert peer["site"] == VPN_PEER_SITE_ID and peer["label"] == "AWS-Transit"
    assert any(e["kind"] == "vpn3p" and peer["id"] in (e["a"], e["b"]) for e in snapshot["edges"])
    # An unreachable peer on either side marks the tunnel unreachable.
    assert any(e["kind"] == "vpn" and e["status"] == "unreachable" for e in snapshot["edges"])


def test_snapshot_site_sections_cover_vlans_vpn_and_routes(snapshot):
    site = next(s for s in snapshot["sites"] if s["name"] == "Branch-Atlanta")
    assert site["vpn_mode"] == "spoke"
    vlans = _section(site, "VLANs")
    assert ["10", "Data"] == vlans["rows"][0][:2]
    routes = _section(site, "Effective routes (derived)")
    types = {row[1] for row in routes["rows"]}
    assert {"Connected", "Static", "AutoVPN", "Default"} <= types
    assert _section(site, "VPN peers")["rows"]
    assert _section(site, "Layer 3 firewall rules")["rows"][0][-1] == "Guest isolation"


def test_snapshot_external_neighbor_matches_inventory(snapshot):
    external = next(n for n in snapshot["nodes"] if n["kind"] == "external")
    assert external["label"] == "core-sw1.example.net"
    assert external["inventory"]["host_id"] == 7
    assert any(e["kind"] == "lan" and external["id"] in (e["a"], e["b"]) for e in snapshot["edges"])
    assert "_info" not in external


def test_snapshot_switch_has_ports_and_appliance_inherits_site(snapshot):
    switch = next(n for n in snapshot["nodes"] if n["kind"] == "switch")
    assert len(_section(switch, "Switch ports")["rows"]) == 24
    appliance = next(n for n in snapshot["nodes"] if n["kind"] == "appliance")
    assert appliance["site_sections"] is True
    assert _section(appliance, "WAN uplinks")["rows"]


def test_snapshot_has_clients_and_port_vlans(snapshot):
    switch = next(n for n in snapshot["nodes"] if n["kind"] == "switch")
    clients = _section(switch, "Clients (MAC/ARP)")
    assert clients["columns"][:4] == ["MAC", "IP", "VLAN", "Port"]
    assert len(clients["rows"]) == 3 and all(row[0].startswith("3c:22:fb:") for row in clients["rows"])
    port_vlans = _section(switch, "VLANs on ports")
    assert port_vlans["columns"] == ["VLAN", "Access ports", "Voice ports", "Native on trunks"]
    assert port_vlans["rows"] and all(row[0].isdigit() for row in port_vlans["rows"])
    # Every port lands under the VLAN it is configured for.
    listed = {p for row in port_vlans["rows"] for p in (row[1] + ", " + row[3]).split(", ") if p}
    assert listed == {row[0] for row in _section(switch, "Switch ports")["rows"]}
    wireless = next(n for n in snapshot["nodes"] if n["kind"] == "wireless")
    assert _section(wireless, "Clients (MAC/ARP)")["rows"][0][6] == "Guest"
    # The site (shown on its appliance) lists every client with where it was seen.
    site = next(s for s in snapshot["sites"] if s["id"] == switch["site"])
    network_clients = _section(site, "Network clients (MAC/ARP)")
    assert network_clients["columns"][-1] == "Seen on"
    assert any(row[-1] == switch["label"] for row in network_clients["rows"])


# ── Client records (MAC tracking) ────────────────────────────────────────────


def test_client_records_normalize_and_deduplicate():
    raw = {
        "networks": [{"id": "N1", "name": "Branch"}],
        "devices": [{"serial": "Q2-SW", "name": "branch-sw1"}],
        "networks_detail": {
            "N1": {
                "clients": [
                    {
                        "mac": "AA-BB-CC-00-00-01",
                        "ip": "10.1.1.5",
                        "vlan": "20",
                        "switchport": "7",
                        "user": "jdoe",
                        "recentDeviceSerial": "Q2-SW",
                        "firstSeen": 1767225600,
                        "lastSeen": "2026-01-02T03:04:05Z",
                    },
                    # The same MAC again, seen earlier: the later sighting wins.
                    {"mac": "aabb.cc00.0001", "ip": "10.1.1.9", "lastSeen": "2026-01-01T00:00:00Z"},
                    {"mac": "aa:bb:cc:00:00:02", "vlan": None, "ssid": "Guest", "lastSeen": "not a time"},
                    {"mac": "not-a-mac"},
                    "junk",
                ]
            },
            "N2": {},
        },
    }
    records = client_records(raw)
    assert [r["mac_address"] for r in records] == ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"]
    wired, wireless = records
    assert (wired["ip_address"], wired["vlan"], wired["port_name"]) == ("10.1.1.5", 20, "7")
    assert (wired["network_name"], wired["device_name"], wired["description"]) == ("Branch", "branch-sw1", "jdoe")
    assert (wired["first_seen"], wired["last_seen"]) == ("2026-01-01 00:00:00", "2026-01-02 03:04:05")
    # No usable time from Meraki: the collection time stands in.
    assert wireless["vlan"] == 0 and len(wireless["last_seen"]) == 19 and wireless["last_seen"] > "2026-01-02"
    assert client_records({}) == []


def test_empty_organization_builds_an_empty_snapshot():
    snap = build_snapshot({"organization": {"id": "1", "name": "Empty"}, "networks": [], "devices": []})
    assert snap["nodes"] == [] and snap["edges"] == [] and snap["sites"] == []


# ── Inventory / SSH enrichment ───────────────────────────────────────────────


def test_show_commands_are_chosen_by_device_type():
    assert "show ip route" in show_commands_for("cisco_xe")
    assert "show route" in show_commands_for("cisco_asa")
    assert show_commands_for("juniper_junos")[0] == "show route terse"
    assert show_commands_for("linux") == ()


@pytest.mark.asyncio
async def test_enrich_attaches_collected_inventory_data(tmp_path, monkeypatch):
    import netcontrol.routes.state as state

    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "enrich.db"))
    await db_module.init_db()
    monkeypatch.setitem(state.AUTH_CONFIG, "service_credential_id", None)
    conn = await db_module.get_db()
    try:
        cur = await conn.execute("INSERT INTO inventory_groups (name) VALUES (?)", ("core",))
        cur = await conn.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address, device_type) VALUES (?, ?, ?, ?)",
            (cur.lastrowid, "core-sw1", "10.0.0.2", "cisco_xe"),
        )
        host_id = cur.lastrowid
        await conn.commit()
    finally:
        await conn.close()
    await db_module.upsert_vlan_definition(host_id, 100, "Servers", "active")

    snap = build_snapshot(build_sample_raw(branches=1), await load_inventory_index())
    await enrich_snapshot(snap, ssh=True)

    external = next(n for n in snap["nodes"] if n["kind"] == "external")
    assert external["inventory"]["host_id"] == host_id
    assert _section(external, "VLANs (Plexus SNMP)")["rows"] == [["100", "Servers", "active"]]
    assert "Plexus inventory (SNMP/SSH-collected data)" in snap["collection"]["sources"]
    # Live SSH was requested but no service credential exists: skipped, and said so.
    assert any("service credential" in e["message"] for e in snap["collection"]["errors"])
    assert not any(s["title"].startswith("CLI (live SSH)") for s in external["sections"])


# ── HTML export ──────────────────────────────────────────────────────────────


def test_export_is_self_contained_and_embeds_valid_json(snapshot):
    html = render_topology_html(snapshot)
    assert html.startswith("<!DOCTYPE html>")
    # No external resources: the file must work offline / air-gapped.
    assert not re.search(r"""(src|href)\s*=\s*["']https?://""", html)
    assert not re.search(r"<link|<img|<iframe|<script[^>]*src=|@import|url\(", html)
    assert not re.search(r"(fetch|XMLHttpRequest|WebSocket|sendBeacon|EventSource)", html)
    # The saved file enforces that itself, without the response header.
    assert """http-equiv="Content-Security-Policy" content="default-src 'none';""" in html
    embedded = re.search(r'<script type="application/json" id="topology-data">(.*?)</script>', html, re.S).group(1)
    assert json.loads(embedded)["summary"] == snapshot["summary"]
    assert export_filename(snapshot).startswith("topology-sample-organization-demo-data-")


def test_export_embeds_the_subnet_index(snapshot):
    html = render_topology_html(snapshot)
    embedded = re.search(r'<script type="application/json" id="topology-data">(.*?)</script>', html, re.S).group(1)
    assert json.loads(embedded)["subnets"] == subnet_index(snapshot)
    assert "subnets" not in snapshot


# ── Subnet index (path mode) ─────────────────────────────────────────────────


def test_subnet_index_places_each_subnet_on_its_owner(snapshot):
    index = subnet_index(snapshot)
    nodes = {n["id"]: n for n in snapshot["nodes"]}
    assert index and all(e["node_id"] in nodes for e in index)
    assert len({(e["cidr"], e["node_id"]) for e in index}) == len(index)
    assert not any(e["cidr"] == "0.0.0.0/0" for e in index)

    # A VLAN belongs to its site's appliance and knows whether it is in the VPN.
    hq = next(s for s in snapshot["sites"] if s["name"] == "HQ-DataCenter")
    by_cidr = {e["cidr"]: e for e in index if e["site_id"] == hq["id"]}
    data, guest = by_cidr["10.0.10.0/24"], by_cidr["10.0.30.0/24"]
    assert nodes[data["node_id"]]["kind"] == "appliance" and nodes[data["node_id"]]["site"] == hq["id"]
    assert (data["kind"], data["name"], data["in_vpn"]) == ("vlan", "VLAN 10 Data", True)
    assert guest["in_vpn"] is False
    # An SVI belongs to the L3 switch that routes it, a static route to the appliance.
    assert nodes[by_cidr["10.0.100.0/24"]["node_id"]]["kind"] == "switch"
    assert by_cidr["172.16.0.0/24"]["kind"] == "static"
    # A subnet behind a non-Meraki VPN peer belongs to the peer, once.
    behind = [e for e in index if e["kind"] == "peer"]
    assert [nodes[e["node_id"]]["kind"] for e in behind] == ["vpn_peer"]


def test_subnet_index_ignores_text_that_is_not_a_network():
    snapshot = {
        "sites": [
            {
                "id": "N1",
                "name": "One",
                "sections": [
                    {
                        "title": "VLANs",
                        "kind": "table",
                        "columns": ["VLAN", "Name", "Subnet"],
                        "rows": [["10", "Data", "10.9.10.1/24"], ["20", "Broken", "not a subnet"], ["30", "Short"]],
                    },
                    {
                        "title": "Single LAN",
                        "kind": "kv",
                        "rows": [["Subnet", "192.168.9.0/24"], ["Appliance IP", "192.168.9.1"]],
                    },
                ],
            }
        ],
        "nodes": [
            {"id": "ap", "kind": "wireless", "site": "N1", "label": "ap"},
            {"id": "sw", "kind": "switch", "site": "N1", "label": "sw"},
        ],
    }
    index = subnet_index(snapshot)
    # Host bits are dropped; with no appliance the switch stands for the site.
    assert [(e["cidr"], e["node_id"], e["in_vpn"]) for e in index] == [
        ("10.9.10.0/24", "sw", None),
        ("192.168.9.0/24", "sw", None),
    ]
    assert subnet_index({}) == []


def test_export_escapes_markup_in_device_names():
    raw = build_sample_raw(branches=1)
    raw["devices"][0]["name"] = '</script><script>alert("x")</script>'
    raw["organization"]["name"] = "<b>Org & Co</b>"
    html = render_topology_html(build_snapshot(raw))
    assert '<script>alert("x")' not in html
    assert "<title>&lt;b&gt;Org &amp; Co&lt;/b&gt; - Network Topology</title>" in html
    assert html.count("</script>") == 3  # data block, layout and viewer only


# ── Merge into the Topology graph ────────────────────────────────────────────


def _host_graph_node(host_id: int) -> dict:
    return {
        "id": host_id,
        "label": "core-sw1",
        "ip": "10.0.0.2",
        "device_type": "cisco_xe",
        "device_category": "switch",
        "model": "C9300",
        "group_id": 1,
        "group_name": "core",
        "status": "up",
        "in_inventory": True,
    }


def _merged_graph(snapshot, *, with_host: bool = True, edges: list[dict] | None = None):
    nodes_by_id: dict = {7: _host_graph_node(7)} if with_host else {}
    edges = edges if edges is not None else []
    merge_meraki_into_graph(
        nodes_by_id,
        edges,
        [(3, snapshot)],
        host_node=lambda host_id: nodes_by_id.get(host_id),
        resolve_external=lambda _name, _ip: None,
    )
    return nodes_by_id, edges


def test_merge_adds_meraki_nodes_and_collapses_inventory_match(snapshot):
    nodes, edges = _merged_graph(snapshot)
    appliance = next(n for n in snapshot["nodes"] if n["kind"] == "appliance")
    merged = nodes[meraki_graph_id(3, appliance["id"])]
    assert merged["source"] == "meraki" and merged["device_category"] == "firewall"
    assert merged["in_inventory"] is False
    assert merged["meraki"]["org_ref"] == 3 and merged["meraki"]["node_id"] == appliance["id"]
    assert merged["meraki"]["site_name"]

    # The LLDP neighbor that is inventory host 7 becomes that host's node:
    # no duplicate, still an inventory node, now carrying the Meraki reference.
    external = next(n for n in snapshot["nodes"] if n["kind"] == "external")
    host = nodes[7]
    assert host["in_inventory"] is True and "source" not in host
    assert host["meraki"]["node_id"] == external["id"]
    assert not any(str(k).startswith("ext_") for k in nodes)
    assert any(7 in (e["from"], e["to"]) and e["source"] == "meraki" for e in edges)

    assert all(e["from"] in nodes and e["to"] in nodes for e in edges)
    assert {e["protocol"] for e in edges} >= {"lldp", "wan", "vpn", "vpn-ipsec"}
    assert any(e["protocol"] == "vpn" and e["status"] == "unreachable" for e in edges)
    assert len({e["id"] for e in edges}) == len(edges)


def test_merge_keeps_unmatched_neighbor_as_external_and_is_stable(snapshot):
    nodes, _edges = _merged_graph(snapshot, with_host=False)
    external = next(n for n in snapshot["nodes"] if n["kind"] == "external")
    assert external_key(external["label"], external.get("ip") or "") == "ext_core-sw1"
    key = meraki_graph_id(3, external["id"])
    assert nodes[key]["in_inventory"] is False and "source" not in nodes[key]
    assert not any(str(k).startswith("ext_") for k in nodes)
    # Ids depend only on (org, node), so saved positions survive a rebuild.
    again, _ = _merged_graph(snapshot, with_host=False)
    assert set(again) == set(nodes)


def test_merge_prefers_discovered_link_over_meraki_view(snapshot):
    external = next(n for n in snapshot["nodes"] if n["kind"] == "external")
    lan = next(e for e in snapshot["edges"] if e["kind"] == "lan" and external["id"] in (e["a"], e["b"]))
    other = lan["b"] if lan["a"] == external["id"] else lan["a"]
    discovered = {"id": 1, "from": 7, "to": meraki_graph_id(3, other), "protocol": "cdp"}
    _nodes, edges = _merged_graph(snapshot, edges=[discovered])
    between = [e for e in edges if {e["from"], e["to"]} == {7, meraki_graph_id(3, other)}]
    assert between == [discovered]


def test_merge_stacks_organizations_without_overlap(snapshot):
    nodes_by_id: dict = {}
    merge_meraki_into_graph(
        nodes_by_id,
        [],
        [(1, snapshot), (2, snapshot)],
        host_node=lambda _host_id: None,
        resolve_external=lambda name, ip: external_key(name, ip) if external_key(name, ip) in nodes_by_id else None,
    )
    first = [n["y"] for n in nodes_by_id.values() if n["meraki"]["org_ref"] == 1 and n.get("source") == "meraki"]
    second = [n["y"] for n in nodes_by_id.values() if n["meraki"]["org_ref"] == 2 and n.get("source") == "meraki"]
    assert first and second and max(first) < min(second)
    # A neighbor only Meraki knows is not shared between organizations.
    assert sum(1 for n in nodes_by_id.values() if n["meraki"]["kind"] == "external") == 2


def test_merge_keeps_same_named_neighbors_of_different_sites_apart():
    def site(n: int) -> list[dict]:
        return [
            {"id": f"sw{n}", "kind": "switch", "site": f"N{n}", "label": f"sw{n}"},
            {"id": f"x:N{n}:unknown", "kind": "external", "site": f"N{n}", "label": "Unknown neighbor"},
        ]

    snapshot = {
        "sites": [{"id": "N1", "name": "One"}, {"id": "N2", "name": "Two"}],
        "nodes": site(1) + site(2),
        "edges": [
            {"id": "e1", "kind": "lan", "a": "sw1", "b": "x:N1:unknown"},
            {"id": "e2", "kind": "lan", "a": "sw2", "b": "x:N2:unknown"},
        ],
    }
    nodes, edges = _merged_graph(snapshot, with_host=False)
    assert len(nodes) == 4
    # No node ties the two sites together.
    assert {frozenset((e["from"], e["to"])) for e in edges} == {
        frozenset((meraki_graph_id(3, "sw1"), meraki_graph_id(3, "x:N1:unknown"))),
        frozenset((meraki_graph_id(3, "sw2"), meraki_graph_id(3, "x:N2:unknown"))),
    }


def test_node_details_include_site_configuration_for_the_appliance(snapshot):
    appliance = next(n for n in snapshot["nodes"] if n["kind"] == "appliance")
    details = node_details(snapshot, appliance["id"])
    assert details["site_name"] and any(s["title"] == "VLANs" for s in details["site_sections"])
    switch = next(n for n in snapshot["nodes"] if n["kind"] == "switch")
    switch_details = node_details(snapshot, switch["id"])
    assert switch_details["site_sections"] == []
    # The site's VLANs are still offered for every managed device of the site.
    assert [s["title"] for s in switch_details["site_addressing"]] == ["VLANs"]
    external = next(n for n in snapshot["nodes"] if n["kind"] == "external")
    assert node_details(snapshot, external["id"])["site_addressing"] == []
    assert node_details(snapshot, "nope") is None


def test_deep_search_finds_site_content_and_reports_where(snapshot):
    index = build_search_index(snapshot)
    hits = search_index(index, ["guest", "isolation"], 50)
    assert hits and all(h["node_id"] for h in hits)
    assert "Layer 3 firewall rules" in hits[0]["snippet"]
    # A name match needs no snippet; nonsense matches nothing; limit is honoured.
    by_name = {h["node_id"]: h for h in search_index(index, ["aws-transit"], 50)}
    assert by_name["p:AWS-Transit"]["snippet"] == ""
    assert search_index(index, ["zz-no-such-thing"], 50) == []
    # A client's MAC leads to the device it was seen on.
    switch = next(n for n in snapshot["nodes"] if n["kind"] == "switch")
    mac = next(s for s in switch["sections"] if s["title"] == "Clients (MAC/ARP)")["rows"][0][0]
    assert switch["id"] in {h["node_id"] for h in search_index(index, [mac], 50)}
    assert len(search_index(index, ["mx"], 2)) <= 2


def test_graph_to_snapshot_covers_inventory_and_meraki(snapshot):
    nodes, edges = _merged_graph(snapshot)
    nodes["ext_legacy"] = {"id": "ext_legacy", "label": "legacy", "ip": "10.9.9.9", "in_inventory": False}
    edges.append({"id": 99, "from": 7, "to": "ext_legacy", "protocol": "cdp", "source_interface": "Gi1/0/1"})
    graph = {"nodes": list(nodes.values()), "edges": edges}
    host_sections = {7: [{"title": "VLANs (Plexus SNMP)", "kind": "table", "columns": ["ID"], "rows": [["100"]]}]}

    unified = graph_to_snapshot(graph, {3: snapshot}, host_sections, title="Plexus")
    ids = {n["id"] for n in unified["nodes"]}
    assert len(ids) == len(unified["nodes"]) == len(nodes)
    assert all(e["a"] in ids and e["b"] in ids for e in unified["edges"])
    assert all("x" in n and "y" in n for n in unified["nodes"])

    host = next(n for n in unified["nodes"] if n["id"] == "7")
    titles = [s["title"] for s in host["sections"]]
    assert titles[0] == "Overview" and "VLANs (Plexus SNMP)" in titles
    assert host["inventory"] == {"host_id": 7}
    legacy = next(n for n in unified["nodes"] if n["id"] == "ext_legacy")
    assert legacy["kind"] == "external"
    assert unified["summary"]["vpn_tunnels"] == snapshot["summary"]["vpn_tunnels"]
    assert any(s["name"] == "Branch-Atlanta" and s["sections"] for s in unified["sites"])
    # The result is a valid viewer document.
    assert "topology-data" in render_topology_html(unified)


def test_graph_to_snapshot_tags_sources_for_the_viewer_picker():
    def ref(node_id: str, provider: str) -> dict:
        return {"org_ref": 1, "node_id": node_id, "site_id": "S", "site_name": "S", "kind": "vpc", "provider": provider}

    graph = {
        "nodes": [
            {"id": 7, "label": "core", "in_inventory": True, "group_id": 1, "group_name": "HQ"},
            {"id": "m:1:hq", "label": "matched", "in_inventory": True, "meraki": ref("hq", "")},
            {"id": "m:1:v1", "label": "vpc-a", "source": "meraki", "meraki": ref("v1", "aws")},
            {"id": "m:1:v2", "label": "vpc-b", "source": "meraki", "meraki": ref("v2", "aws")},
        ],
        "edges": [
            {"from": "m:1:v1", "to": "m:1:v2", "protocol": "attach", "source": "meraki", "provider": "aws"},
            {"from": 7, "to": "m:1:hq", "protocol": "cdp"},
        ],
    }
    unified = graph_to_snapshot(graph, {}, {})
    nodes = {n["id"]: n for n in unified["nodes"]}
    # An inventory host has no provider; one matched to an integration keeps
    # it but stays in the inventory view; an integration-only node is marked.
    assert "provider" not in nodes["7"] and "integration_only" not in nodes["7"]
    assert nodes["m:1:hq"]["provider"] == "meraki" and "integration_only" not in nodes["m:1:hq"]
    assert nodes["m:1:v1"]["provider"] == "aws" and nodes["m:1:v1"]["integration_only"] is True
    assert [e.get("provider") for e in unified["edges"]] == ["aws", None]
    assert 'id="source"' in render_topology_html(unified)
    # What the page's tidy layout reads, for the viewer to lay the map out the same way.
    assert nodes["7"]["topo"] == {"group_name": "HQ", "in_inventory": True}
    assert nodes["m:1:v1"]["topo"] == {
        "source": "meraki",
        "meraki": {"provider": "aws", "node_id": "v1", "kind": "vpc", "org_ref": 1, "site_id": "S", "site_name": "S"},
    }
    assert [e["protocol"] for e in unified["edges"]] == ["attach", "cdp"]


def test_export_inlines_the_page_layout_when_the_frontend_is_built(snapshot, tmp_path, monkeypatch):
    from netcontrol.integrations.meraki import html_export

    script = tmp_path / "viewer-layout.js"
    script.write_text('var PlexusLayout=(function(e){return e})({});var s="</script>";', encoding="utf-8")
    monkeypatch.setattr(html_export, "_LAYOUT_SCRIPT_PATH", script)
    html = render_topology_html(snapshot)
    # Inlined, and unable to close its own script block early.
    assert '<script>var PlexusLayout=(function(e){return e})({});var s="<\\/script>";</script>' in html

    monkeypatch.setattr(html_export, "_LAYOUT_SCRIPT_PATH", tmp_path / "missing.js")
    # Not built: the viewer keeps the export's own layout.
    assert "<script></script>" in render_topology_html(snapshot)
    assert "__LAYOUT_JS__" not in render_topology_html(snapshot)


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
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "meraki.db"))
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-meraki")
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


def test_api_requires_authentication(api):
    api._c.cookies.clear()
    assert api.get("/api/meraki/orgs").status_code == 401


def test_api_org_crud_never_returns_the_api_key(api):
    created = api.post("/api/meraki/orgs", json={"name": "Acme", "api_key": "super-secret-key", "org_id": "123"})
    assert created.status_code == 201, created.text
    org = created.json()["org"]
    assert org["has_api_key"] is True and org["options"]["include_lldp_cdp"] is True
    assert "super-secret-key" not in created.text

    listing = api.get("/api/meraki/orgs")
    assert "super-secret-key" not in listing.text and "api_key_enc" not in listing.text

    # Duplicate name and non-Meraki base URL are rejected.
    assert api.post("/api/meraki/orgs", json={"name": "Acme"}).status_code == 409
    bad = api.post("/api/meraki/orgs", json={"name": "Evil", "base_url": "https://evil.example.com/api/v1"})
    assert bad.status_code == 400

    # An update without api_key keeps the stored key.
    updated = api.put(f"/api/meraki/orgs/{org['id']}", json={"options": {"ssh_enrich": True}})
    assert updated.status_code == 200
    assert updated.json()["org"]["has_api_key"] is True and updated.json()["org"]["options"]["ssh_enrich"] is True

    assert api.delete(f"/api/meraki/orgs/{org['id']}").status_code == 200
    assert api.get("/api/meraki/orgs").json()["orgs"] == []


def test_api_build_requires_api_key(api):
    org = api.post("/api/meraki/orgs", json={"name": "NoKey"}).json()["org"]
    assert api.post(f"/api/meraki/orgs/{org['id']}/build").status_code == 400


def _add_inventory_host(api, hostname: str, ip: str) -> int:
    group = api.post("/api/inventory", json={"name": "core", "description": ""})
    assert group.status_code in (200, 201), group.text
    host = api.post(
        f"/api/inventory/{group.json()['id']}/hosts",
        json={"hostname": hostname, "ip_address": ip, "device_type": "cisco_xe"},
    )
    assert host.status_code in (200, 201), host.text
    return host.json()["id"]


def test_api_sample_build_is_merged_into_the_topology(api):
    assert not any(n.get("meraki") for n in api.get("/api/topology").json()["nodes"])

    built = api.post("/api/meraki/sample")
    assert built.status_code == 201, built.text
    snapshot_id, org_ref = built.json()["snapshot_id"], built.json()["org_ref"]

    listed = api.get("/api/meraki/snapshots").json()["snapshots"]
    assert listed[0]["id"] == snapshot_id and listed[0]["summary"]["sites"] > 0
    assert "snapshot_json" not in listed[0]
    data = api.get(f"/api/meraki/snapshots/{snapshot_id}/data").json()
    assert data["schema"] == 1 and data["nodes"]

    # The build shows up on the normal topology graph straight away.
    graph = api.get("/api/topology").json()
    # Every snapshot node is on the map exactly once: as a Meraki node, or
    # collapsed into the inventory host / external neighbor it matched (the
    # dev-bootstrap database seeds hosts that overlap the sample addresses).
    referenced = [n for n in graph["nodes"] if n.get("meraki")]
    assert len(referenced) == len(data["nodes"])
    assert {n["meraki"]["node_id"] for n in referenced} == {n["id"] for n in data["nodes"]}
    assert all(n["meraki"]["org_ref"] == org_ref and "x" in n and "y" in n for n in referenced)
    meraki_nodes = [n for n in referenced if n.get("source") == "meraki"]
    assert len(meraki_nodes) > 50 and not any(n["in_inventory"] for n in meraki_nodes)
    ids = {n["id"] for n in graph["nodes"]}
    assert all(e["from"] in ids and e["to"] in ids for e in graph["edges"])
    assert {"vpn", "wan"} <= {e["protocol"] for e in graph["edges"]}

    # A single-group view stays inventory-only.
    assert not any(n.get("meraki") for n in api.get("/api/topology?group_id=999").json()["nodes"])

    appliance = next(n for n in meraki_nodes if n["meraki"]["kind"] == "appliance")
    details = api.get("/api/meraki/nodes", params={"org_ref": org_ref, "node_id": appliance["meraki"]["node_id"]})
    assert details.status_code == 200
    assert details.json()["sections"] and details.json()["site_sections"]
    assert api.get("/api/meraki/nodes", params={"org_ref": org_ref, "node_id": "nope"}).status_code == 404

    hits = api.get("/api/topology/search/deep", params={"q": "guest isolation"}).json()["results"]
    assert hits and hits[0]["org_ref"] == org_ref
    on_map = {(n["meraki"]["org_ref"], n["meraki"]["node_id"]) for n in graph["nodes"] if n.get("meraki")}
    assert all((h["org_ref"], h["node_id"]) in on_map for h in hits)
    assert api.get("/api/topology/search/deep", params={"q": "x"}).status_code == 422

    # Deleting the snapshot takes Meraki back off the map.
    assert api.delete(f"/api/meraki/snapshots/{snapshot_id}").status_code == 200
    assert api.get(f"/api/meraki/snapshots/{snapshot_id}").status_code == 404
    assert not any(n.get("meraki") for n in api.get("/api/topology").json()["nodes"])
    assert api.get("/api/topology/search/deep", params={"q": "guest isolation"}).json()["results"] == []


def test_api_lists_subnets_of_the_latest_snapshots(api):
    assert api.get("/api/meraki/subnets").json() == {"subnets": []}
    assert api.post("/api/meraki/sample").status_code == 201

    subnets = api.get("/api/meraki/subnets").json()["subnets"]
    data = next(s for s in subnets if s["cidr"] == "10.0.10.0/24")
    assert data["site_name"] == "HQ-DataCenter" and data["in_vpn"] is True
    # The owner is a node of the merged map.
    on_map = {
        (n["meraki"]["org_ref"], n["meraki"]["node_id"])
        for n in api.get("/api/topology").json()["nodes"]
        if n.get("meraki")
    }
    assert (data["org_ref"], data["node_id"]) in on_map


def test_api_meraki_clients_join_mac_tracking(api):
    assert api.get("/api/mac-tracking/stats").json()["meraki_clients"] == 0
    built = api.post("/api/meraki/sample")
    assert built.status_code == 201, built.text
    org_ref, tracked = built.json()["org_ref"], built.json()["clients_tracked"]
    assert tracked > 0

    stats = api.get("/api/mac-tracking/stats").json()
    assert stats["meraki_clients"] == tracked and stats["meraki_devices"] > 0
    assert stats["total_entries"] >= tracked and stats["unique_macs"] >= tracked

    # Any MAC format finds the client, with the Meraki device it was seen on.
    hits = api.get("/api/mac-tracking/search", params={"query": "3C22.FB01.0102"}).json()
    assert len(hits) == 1
    hit = hits[0]
    assert hit["source"] == "meraki" and hit["host_id"] is None and hit["org_ref"] == org_ref
    assert hit["mac_address"] == "3c:22:fb:01:01:02" and hit["vlan"] == 20 and hit["port_name"] == "2"
    assert hit["hostname"] and hit["entry_type"] == "wired" and hit["last_seen"] == "2026-01-01 00:00:00"
    on_map = {
        (n["meraki"]["org_ref"], n["meraki"]["node_id"])
        for n in api.get("/api/topology").json()["nodes"]
        if n.get("meraki")
    }
    assert (hit["org_ref"], hit["node_id"]) in on_map
    # IP and client name match too; wireless clients carry their SSID.
    assert any(h["mac_address"] == hit["mac_address"] for h in _mac_search(api, hit["ip_address"]))
    guest = _mac_search(api, "GUEST-1-1")
    assert [(g["ssid"], g["entry_type"]) for g in guest] == [("Guest", "wireless")]
    assert _mac_search(api, "zz-no-such-client") == []

    # A second collection refreshes the same rows instead of adding more.
    assert api.post("/api/meraki/sample").json()["clients_tracked"] == tracked
    assert api.get("/api/mac-tracking/stats").json()["meraki_clients"] == tracked

    # Clients outlive their snapshot but not their organization.
    assert api.post("/api/mac-tracking/cleanup", params={"days": 1}).json()["removed"] == tracked
    assert api.post("/api/meraki/sample").json()["clients_tracked"] == tracked
    assert api.delete(f"/api/meraki/orgs/{org_ref}").status_code == 200
    assert api.get("/api/mac-tracking/stats").json()["meraki_clients"] == 0


def _mac_search(api, query: str) -> list[dict]:
    return api.get("/api/mac-tracking/search", params={"query": query}).json()


def test_api_meraki_neighbor_collapses_into_inventory_host(api):
    # The sample's LLDP neighbor is core-sw1 / 10.0.0.2. The host is added
    # *after* nothing has been built, and has no discovered links of its own.
    _add_inventory_host(api, "core-sw1", "10.0.0.2")
    assert api.post("/api/meraki/sample").status_code == 201

    graph = api.get("/api/topology").json()
    host = next(n for n in graph["nodes"] if (n.get("meraki") or {}).get("kind") == "external")
    assert host["in_inventory"] is True and isinstance(host["id"], int)
    assert not any(str(n["id"]).startswith("ext_") for n in graph["nodes"])
    assert any(host["id"] in (e["from"], e["to"]) and e.get("source") == "meraki" for e in graph["edges"])


def test_api_topology_html_export(api):
    _add_inventory_host(api, "core-sw1", "10.0.0.2")
    assert api.post("/api/meraki/sample").status_code == 201

    inline = api.get("/api/topology/export.html")
    assert inline.status_code == 200 and inline.headers["content-type"].startswith("text/html")
    csp = inline.headers["Content-Security-Policy"]
    # Sandboxed away from the Plexus origin and never framed.
    assert "sandbox allow-scripts" in csp and "allow-same-origin" not in csp
    assert "frame-ancestors 'none'" in csp
    assert inline.headers["X-Frame-Options"] == "DENY"
    assert "content-disposition" not in inline.headers

    embedded = re.search(r'<script type="application/json" id="topology-data">(.*?)</script>', inline.text, re.S)
    exported = json.loads(embedded.group(1))
    kinds = {n["kind"] for n in exported["nodes"]}
    assert {"appliance", "switch", "wan", "vpn_peer"} <= kinds
    host = next(n for n in exported["nodes"] if n.get("inventory"))
    assert host["id"] == str(host["inventory"]["host_id"]) and host["sections"][0]["title"] == "Overview"
    ids = {n["id"] for n in exported["nodes"]}
    assert all(e["a"] in ids and e["b"] in ids for e in exported["edges"])

    download = api.get("/api/topology/export.html?download=1")
    assert download.headers["content-disposition"].startswith('attachment; filename="topology-plexus-')

    # With no Meraki data the export is still a valid inventory-only map.
    group_only = api.get("/api/topology/export.html?group_id=999")
    assert group_only.status_code == 200


def test_api_build_job_runs_collector_and_stores_snapshot(api, monkeypatch):
    import netcontrol.routes.meraki_topology as routes_module

    async def _fake_collect(_client, org_id, _options, progress):
        assert org_id == "sample"
        progress({"phase": "inventory"})
        return build_sample_raw(branches=2)

    monkeypatch.setattr(routes_module, "collect_organization", _fake_collect)
    org = api.post("/api/meraki/orgs", json={"name": "Acme", "api_key": "k", "org_id": "sample"}).json()["org"]
    started = api.post(f"/api/meraki/orgs/{org['id']}/build")
    assert started.status_code == 202, started.text

    job = {}
    for _ in range(200):
        job = api.get(f"/api/meraki/builds/{started.json()['job_id']}").json()
        if job["status"] != "running":
            break
    assert job["status"] == "completed", job
    assert job["result"]["summary"]["sites"] == 4
    refreshed = api.get("/api/meraki/orgs").json()["orgs"][0]
    assert refreshed["last_build_status"] == "success" and refreshed["snapshot_count"] == 1


# ── Forwarding data (path tracing) ───────────────────────────────────────────


def _node_of(snapshot: dict, node_id: str) -> dict:
    return next(n for n in snapshot["nodes"] if n["id"] == node_id)


def _policy(block: dict, name: str) -> dict:
    return next(p for p in block["policies"] if p["name"] == name)


def test_meraki_address_syntax_is_resolved():
    vlans = {"30": "10.2.30.0/24", "10": "10.2.10.0/24"}
    assert meraki_addresses("Any", vlans) == (["any"], [])
    assert meraki_addresses("VLAN(30).*", vlans) == (["10.2.30.0/24"], [])
    assert meraki_addresses("VLAN(30).17, 10.9.0.5,192.168.1.0/24", vlans) == (
        ["10.2.30.17/32", "10.9.0.5/32", "192.168.1.0/24"],
        [],
    )
    assert meraki_addresses("10.1.2.3/16", vlans) == (["10.1.0.0/16"], [])
    assert meraki_addresses("VLAN(77).*, www.example.com", vlans) == ([], ["VLAN(77).*", "www.example.com"])
    assert meraki_addresses("10.0.0.1, any", vlans) == (["any"], [])


def test_snapshot_branch_appliance_carries_its_forwarding_block(snapshot):
    block = _node_of(snapshot, "d:Q2MX-0002-0001")["forwarding"]  # Branch-Atlanta
    assert set(block) == {"version", "interfaces", "routes", "vpn", "policies", "nat", "not_collected"}
    interfaces = {i["name"]: i for i in block["interfaces"]}
    assert interfaces["VLAN 10"] == {
        "name": "VLAN 10",
        "kind": "vlan",
        "ip": "10.2.10.1",
        "cidr": "10.2.10.0/24",
        "zone": "",
        "vrf": "",
        "enabled": True,
    }
    assert interfaces["wan1"]["kind"] == "wan" and interfaces["wan1"]["ip"] == "198.51.100.12"
    routes = {(r["prefix"], r["kind"]): r for r in block["routes"]}
    assert routes[("10.2.30.0/24", "connected")]["advertised"] is False
    static = routes[("172.16.2.0/24", "static")]
    assert (static["next_hop"], static["interface"], static["source"]) == ("10.2.0.11", "VLAN 99", "Static route Lab")
    autovpn = routes[("10.0.10.0/24", "autovpn")]
    assert autovpn["peer"] == {"site": "N_1000"} and autovpn["source"] == "AutoVPN from HQ-DataCenter"
    defaults = [r for r in block["routes"] if r["kind"] == "default"]
    assert [(r["interface"], r["next_hop"]) for r in defaults] == [("wan1", "198.51.100.1"), ("wan2", "203.0.113.1")]
    assert block["vpn"] == []
    # Policies in the order the MX applies them; Meraki syntax resolved.
    assert [(p["name"], p["kind"], p["applies"], p["default"]) for p in block["policies"]] == [
        ("Layer 3 firewall rules", "firewall", "lan_in", "allow"),
        ("Site-to-site VPN firewall rules", "vpn_firewall", "vpn_out", "allow"),
        ("Inbound firewall rules", "inbound", "wan_in", "deny"),
    ]
    guest = _policy(block, "Layer 3 firewall rules")["rules"][0]
    assert (guest["index"], guest["action"], guest["src"], guest["dst"], guest["comment"]) == (
        1,
        "deny",
        ["10.2.30.0/24"],
        ["10.0.0.0/8"],
        "Guest isolation",
    )
    # The trailing default rule of the Dashboard is kept as the last rule.
    assert _policy(block, "Layer 3 firewall rules")["rules"][-1]["comment"] == "Default rule"
    vpn_rule = _policy(block, "Site-to-site VPN firewall rules")["rules"][0]
    assert vpn_rule["src"] == ["10.1.30.0/24", "10.2.30.0/24"] and vpn_rule["action"] == "deny"
    assert [n["kind"] for n in block["nat"]] == ["interface_pat"]
    assert block["nat"][0]["translated_src"] == ["interface"]
    assert block["not_collected"] == ["Layer 7 firewall rules", "Group policies"]


def test_snapshot_hub_appliance_has_nat_and_inbound_rules(snapshot):
    block = _node_of(snapshot, "d:Q2MX-0000-0001")["forwarding"]  # HQ-DataCenter
    nat = {n["kind"]: n for n in block["nat"]}
    assert list(nat) == ["one_to_one", "port_forward", "one_to_many", "interface_pat"]
    assert (nat["one_to_one"]["original_dst"], nat["one_to_one"]["translated_dst"]) == (
        ["198.51.100.150/32"],
        ["10.0.10.80/32"],
    )
    assert nat["one_to_one"]["dst_interface"] == "wan1" and nat["one_to_one"]["allowed_src"] == ["any"]
    forward = nat["port_forward"]
    assert (forward["original_dst"], forward["original_port"], forward["translated_port"]) == (
        ["interface"],
        "2222",
        "22",
    )
    assert forward["allowed_src"] == ["203.0.113.0/24"] and forward["dst_interface"] == ""
    assert nat["one_to_many"]["translated_dst"] == ["10.0.10.25/32"] and nat["one_to_many"]["protocol"] == "tcp"
    inbound = _policy(block, "Inbound firewall rules")["rules"]
    assert (inbound[0]["action"], inbound[0]["dst"], inbound[0]["dst_ports"]) == ("allow", ["10.0.10.80/32"], "443")
    assert inbound[1]["action"] == "deny"
    # AutoVPN routes back to every spoke, and the subnets of the non-Meraki peer.
    routes = {(r["prefix"], r["kind"]): r for r in block["routes"]}
    assert routes[("10.2.10.0/24", "autovpn")]["peer"] == {"site": "N_1002"}
    assert routes[("172.31.0.0/16", "vpn3p")]["peer"] == {"org_node": "p:AWS-Transit"}
    assert routes[("10.0.10.0/24", "connected")]["interface"] == "VLAN 10"
    assert "Routes learned by BGP" in block["not_collected"]


def test_snapshot_l3_switch_and_vpn_peer_carry_forwarding(snapshot):
    switch = _node_of(snapshot, "d:Q2SW-0000-0001")["forwarding"]
    assert switch["interfaces"][0]["name"] == "Servers" and switch["interfaces"][0]["kind"] == "svi"
    assert switch["interfaces"][0]["ip"] == "10.0.100.1"
    assert [(r["prefix"], r["kind"], r["next_hop"]) for r in switch["routes"]] == [
        ("10.0.100.0/24", "connected", ""),
        ("0.0.0.0/0", "static", "10.0.0.1"),
    ]
    acl = switch["policies"][0]
    assert (acl["name"], acl["kind"], acl["applies"], acl["stateful"]) == ("Switch ACL", "acl", "any", False)
    assert acl["rules"][0]["src"] == ["10.0.30.0/24"] and acl["rules"][0]["dst"] == ["10.0.100.0/24"]
    assert switch["not_collected"] == []
    # A switch with no SVI forwards nothing of its own.
    assert "forwarding" not in _node_of(snapshot, "d:Q2SW-0002-0001")
    peer = _node_of(snapshot, "p:AWS-Transit")["forwarding"]
    assert [(r["prefix"], r["kind"]) for r in peer["routes"]] == [("172.31.0.0/16", "connected")]
    assert peer["not_collected"] == ["Everything behind a non-Meraki VPN peer"]


def test_snapshot_lists_the_new_rule_sets_in_the_details(snapshot):
    hub = next(s for s in snapshot["sites"] if s["name"] == "HQ-DataCenter")
    titles = {s["title"] for s in hub["sections"]}
    assert {"Inbound firewall rules", "Site-to-site VPN firewall rules", "1:Many NAT"} <= titles
    assert _section(hub, "1:Many NAT")["rows"][0][:3] == ["198.51.100.151", "internet1", "Mail relay"]
    vpn_rules = _section(hub, "Site-to-site VPN firewall rules")
    assert vpn_rules["rows"][0][-1] == "Block guest VLANs over the VPN"
    switch = _node_of(snapshot, "d:Q2SW-0000-0001")
    assert _section(switch, "Switch ACL")["rows"][0][-1] == "Guest to servers"


def test_forwarding_of_a_capture_without_the_new_collections():
    raw = build_sample_raw(branches=1)
    raw["org"].pop("vpn_firewall")
    for detail in raw["networks_detail"].values():
        for key in ("inbound_firewall", "one_to_many_nat", "switch_acl", "l3_firewall"):
            detail.pop(key, None)
    detail = raw["networks_detail"]["N_1002"]
    detail["vlans"][0]["vpnNatSubnet"] = "172.30.10.0/24"
    # A warm spare forwards like the primary.
    primary = next(d for d in raw["devices"] if d["serial"] == "Q2MX-0002-0001")
    raw["devices"].append(dict(primary, serial="Q2MX-0002-0002", name="spare"))
    snap = build_snapshot(raw)
    block = _node_of(snap, "d:Q2MX-0002-0001")["forwarding"]
    assert block["policies"] == []
    assert block["not_collected"] == [
        "Layer 3 firewall rules",
        "Site-to-site VPN firewall rules",
        "Inbound firewall rules",
        "1:Many NAT",
        "Layer 7 firewall rules",
        "Group policies",
    ]
    vpn_nat = next(n for n in block["nat"] if n["kind"] == "vpn_nat")
    assert (vpn_nat["original_src"], vpn_nat["translated_src"]) == (["10.2.10.0/24"], ["172.30.10.0/24"])
    assert _node_of(snap, "d:Q2MX-0002-0002")["forwarding"] == block
    assert _node_of(snap, "d:Q2SW-0000-0001")["forwarding"]["not_collected"] == ["Switch ACL"]


@pytest.mark.asyncio
async def test_collect_organization_reads_the_rule_sets_best_effort():
    payloads = {
        "organizations/1": {"id": "1", "name": "Acme"},
        "organizations/1/networks": [{"id": "N1", "name": "HQ", "productTypes": ["appliance", "switch"]}],
        "organizations/1/devices": [],
        "organizations/1/appliance/vpn/vpnFirewallRules": {"rules": [{"policy": "allow", "srcCidr": "Any"}]},
        "networks/N1/appliance/firewall/oneToManyNatRules": {"rules": [{"publicIp": "198.51.100.5", "portRules": []}]},
        "networks/N1/switch/accessControlLists": {"rules": [{"policy": "deny", "srcCidr": "10.0.0.0/8"}]},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/v1/")
        if path in payloads:
            return httpx.Response(200, json=payloads[path])
        if path == "networks/N1/appliance/firewall/inboundFirewallRules":
            return httpx.Response(403, json={"errors": ["forbidden"]})
        return httpx.Response(404, json={"errors": ["n/a"]})

    async with _client(handler, max_retries=0) as client:
        raw = await collect_organization(client, "1")
    assert raw["org"]["vpn_firewall"]["rules"][0]["policy"] == "allow"
    detail = raw["networks_detail"]["N1"]
    assert detail["one_to_many_nat"]["rules"][0]["publicIp"] == "198.51.100.5"
    assert detail["switch_acl"]["rules"][0]["policy"] == "deny"
    # Denied: recorded, and the rest of the build goes on.
    assert "inbound_firewall" not in detail
    assert [(e["path"], e["status"]) for e in raw["errors"]] == [
        ("networks/N1/appliance/firewall/inboundFirewallRules", 403)
    ]

    # Without the firewall and switch routing options none of them is asked for.
    async with _client(handler, max_retries=0) as client:
        bare = await collect_organization(client, "1", {"include_firewall": False, "include_switch_routing": False})
    assert "vpn_firewall" not in bare["org"] and bare["errors"] == []
    assert not {"one_to_many_nat", "inbound_firewall", "switch_acl"} & set(bare["networks_detail"]["N1"])
