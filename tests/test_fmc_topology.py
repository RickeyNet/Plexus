"""Tests for the Cisco FMC topology integration.

Covers the pipeline with no network access:
  * FmcClient   - token login, domain resolution, re-login on 401, rate-limit
                  retry, paging, URL trust
  * collector   - every resource of a full read, the headend-only scope,
                  silent 404s for resources an older FMC does not serve,
                  best-effort errors, HA pairs read once, container
                  assignment targets, the access rule cap, secret scrubbing
  * normalize   - device, HA and cluster boxes, outside interfaces, connected
                  subnets and routes, dynamic routing, NAT, access control,
                  site-to-site VPN, health, the FMC node, an old capture
  * subnets     - connected subnets and static routes of an FTD
  * unified     - an FMC snapshot merges into the Topology graph as-is; the
                  FTDv HA members collapse into their AWS instances and the
                  site-to-site VPN ends collapse with the AWS sample's
  * HTTP API    - FMC CRUD (and the legacy "anyconnect" key), sample build,
                  merged /api/topology, subnets, IPAM, node details, deep
                  search, collection job, migration 0070
"""

from __future__ import annotations

import asyncio
import copy
import importlib
import json

import httpx
import netcontrol.app as app_module
import pytest
import routes.database as db_module
from netcontrol.integrations.aws.normalize import build_snapshot as build_aws_snapshot
from netcontrol.integrations.aws.sample import build_sample as build_aws_sample
from netcontrol.integrations.fmc import collector as collector_module
from netcontrol.integrations.fmc.client import CONFIG_PATH, TOKEN_PATH, FmcApiError, FmcClient, validate_base_url
from netcontrol.integrations.fmc.collector import DEFAULT_OPTIONS, collect_fmc, sanitize_options
from netcontrol.integrations.fmc.normalize import FMC_NODE_ID, FMC_SITE_ID, build_snapshot, pool_cidr, value_cidr
from netcontrol.integrations.fmc.sample import (
    ACP_ID,
    CLUSTER,
    DEVICE_1,
    DEVICE_2,
    DEVICE_3,
    DEVICE_4,
    DEVICE_5,
    DOMAIN_UUID,
    HA_PAIR,
    NAT_POLICY_ID,
    POLICY_ID,
    PREFILTER_ID,
    ZONE_GUEST,
    ZONE_OUTSIDE,
    build_sample_raw,
)
from netcontrol.integrations.meraki.normalize import VPN_PEER_SITE_ID
from netcontrol.integrations.meraki.subnets import subnet_index
from netcontrol.integrations.meraki.unified import (
    build_search_index,
    merge_meraki_into_graph,
    node_details,
    search_index,
    virtual_appliance_pairs,
)

DOMAINS_HEADER = json.dumps([{"name": "Global", "uuid": DOMAIN_UUID}, {"name": "Global/Branch", "uuid": "branch-uuid"}])
LOGIN_HEADERS = {
    "X-auth-access-token": "tok-1",
    "X-auth-refresh-token": "ref-1",
    "DOMAIN_UUID": DOMAIN_UUID,
    "DOMAINS": DOMAINS_HEADER,
}

D1, D2, D3, D4, D5 = DEVICE_1, DEVICE_2, DEVICE_3, DEVICE_4, DEVICE_5
ALL_DEVICES = ["ftd-branch-dc", "ftd-dc-unit-1", "ftd-dc-unit-2", "ftdv-ravpn-1", "ftdv-ravpn-2"]

# Interface resource -> the ``type`` of its items in the sample.
_INTERFACE_TYPES = {resource: kind for resource, kind, _newer in collector_module.INTERFACE_RESOURCES}
_ROUTING_KEYS = {
    "ipv4staticroutes": "static_v4",
    "ipv6staticroutes": "static_v6",
    "bgp": "bgp",
    "ospfv2routes": "ospf",
    "eigrproutes": "eigrp",
    "ecmpzones": "ecmp",
}
_OBJECT_KEYS = {resource: key for resource, key in collector_module.OBJECT_RESOURCES}


def _untag(items: list[dict]) -> list[dict]:
    """Routing items as the FMC serves them (the collector adds ``vr``)."""
    return [{k: v for k, v in item.items() if k != "vr"} for item in items]


class _FakeFmc:
    """An FMC serving the sample data, with knobs for failure cases."""

    def __init__(self) -> None:
        self.raw = build_sample_raw()
        self.logins = 0
        self.calls: list[str] = []
        self.fail: dict[str, int] = {}  # path fragment -> HTTP status
        self.missing: set[str] = set()  # path fragments the release does not serve (404)
        self.expire_token_once = False
        self.page_devices = False

    @staticmethod
    def _items(items: list, request: httpx.Request | None = None) -> httpx.Response:
        if request is not None and "limit" in request.url.params:
            offset = int(request.url.params.get("offset", 0))
            limit = int(request.url.params["limit"])
            page = items[offset : offset + limit]
            return httpx.Response(
                200, json={"items": page, "paging": {"offset": offset, "limit": limit, "count": len(items)}}
            )
        return httpx.Response(200, json={"items": items, "paging": {"count": len(items)}})

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append(path)
        if path == TOKEN_PATH:
            assert request.method == "POST"
            assert request.headers["Authorization"].startswith("Basic ")
            self.logins += 1
            return httpx.Response(204, headers={**LOGIN_HEADERS, "X-auth-access-token": f"tok-{self.logins}"})
        assert request.method == "GET"
        if request.headers.get("X-auth-access-token") != f"tok-{self.logins}" or self.expire_token_once:
            self.expire_token_once = False
            return httpx.Response(401, json={"error": {"messages": [{"description": "Access token invalid."}]}})
        for fragment, status in self.fail.items():
            if fragment in path:
                return httpx.Response(status, json={"error": {"messages": [{"description": f"Refused {fragment}"}]}})
        for fragment in self.missing:
            if fragment in path:
                return httpx.Response(404, json={"error": {"messages": [{"description": "Not found"}]}})
        found = self._route(path, request)
        if found is not None:
            return found
        return httpx.Response(404, json={"error": {"messages": [{"description": f"No such resource {path}"}]}})

    def _route(self, path: str, request: httpx.Request) -> httpx.Response | None:
        raw = self.raw
        domain = f"{CONFIG_PATH}/domain/{DOMAIN_UUID}"
        if path.endswith("/info/serverversion"):
            return httpx.Response(200, json={"items": [{"serverVersion": "7.4.1 (build 172)"}]})
        if not path.startswith(domain):
            return None
        rel = path.removeprefix(domain)
        if rel == "/devices/devicerecords":
            items = raw["devices"]
            if self.page_devices:
                offset = int(request.url.params.get("offset", 0))
                page = items[offset : offset + 2]
                return httpx.Response(
                    200, json={"items": page, "paging": {"offset": offset, "limit": 2, "count": len(items)}}
                )
            return self._items(items)
        simple = {
            "/devicehapairs/ftddevicehapairs": raw["ha_pairs"],
            "/deviceclusters/ftddevicecluster": raw["clusters"],
            "/assignment/policyassignments": raw["assignments"],
            "/policies/ravpns": raw["policies"],
            "/object/ipv4addresspools": raw["pools"],
            "/policies/ftdnatpolicies": raw["nat_policies"],
            "/policies/accesspolicies": raw["access_policies"],
            "/policies/prefilterpolicies": raw["prefilter_policies"],
            "/policies/ftds2svpns": raw["s2s_vpns"],
            "/health/tunnelstatuses": raw["tunnel_status"],
            "/health/alerts": raw["health_alerts"],
            "/deployment/deployabledevices": raw["deployable"],
            "/health/ravpnsessions": raw["sessions"],
        }
        if rel in simple:
            return self._items(simple[rel])
        if rel.startswith("/object/") and rel.removeprefix("/object/") in _OBJECT_KEYS:
            return self._items(raw["objects"][_OBJECT_KEYS[rel.removeprefix("/object/")]])
        for pair_id, monitored in raw["ha_monitored"].items():
            if rel == f"/devicehapairs/ftddevicehapairs/{pair_id}/monitoredinterfaces":
                return self._items(monitored)
        for policy_id, detail in raw["policy_details"].items():
            base = f"/policies/ravpns/{policy_id}"
            if rel == f"{base}/connectionprofiles":
                return self._items(detail["connection_profiles"])
            if rel == f"{base}/addressassignmentsettings":
                return httpx.Response(200, json=detail["address_assignment"][0])  # one object, not a collection
            if rel == f"{base}/accessinterfacesettings":
                return self._items(detail["access_interfaces"])
        for policy_id, rules in raw["nat_rules"].items():
            if rel == f"/policies/ftdnatpolicies/{policy_id}/natrules":
                return self._items(rules, request)
        for policy_id, rules in raw["access_rules"].items():
            if rel == f"/policies/accesspolicies/{policy_id}/accessrules":
                return self._items(rules, request)
        for policy_id, rules in raw["prefilter_rules"].items():
            if rel == f"/policies/prefilterpolicies/{policy_id}/prefilterrules":
                return self._items(rules, request)
        for topology_id, detail in raw["s2s_details"].items():
            base = f"/policies/ftds2svpns/{topology_id}"
            if rel == f"{base}/endpoints":
                return self._items(detail["endpoints"])
            if rel == f"{base}/ikesettings":
                # A real FMC can answer with the pre-shared key; it must never be kept.
                ike = copy.deepcopy(detail["ike"][0])
                ike["ikeV2Settings"]["manualPreSharedKey"] = "pre-shared-secret-value"
                return httpx.Response(200, json=ike)
            if rel == f"{base}/ipsecsettings":
                return self._items(detail["ipsec"])
        if rel.startswith("/devices/devicerecords/"):
            return self._device_resource(rel.removeprefix("/devices/devicerecords/"))
        return None

    def _device_resource(self, rest: str) -> httpx.Response | None:
        device_id, _sep, resource = rest.partition("/")
        if device_id not in self.raw["interfaces"]:
            return None
        if resource in _INTERFACE_TYPES:
            kind = _INTERFACE_TYPES[resource]
            return self._items([i for i in self.raw["interfaces"][device_id] if i.get("type") == kind])
        routing = self.raw["routing"][device_id]
        if resource == "routing/virtualrouters":
            return self._items(routing["virtual_routers"])
        if resource == "routing/policybasedroutes":
            return self._items(_untag(routing["pbr"]))
        if resource.startswith("routing/virtualrouters/"):
            vr_id, _sep, kind = resource.removeprefix("routing/virtualrouters/").partition("/")
            vr = next((r for r in routing["virtual_routers"] if r["id"] == vr_id), None)
            if vr is None or kind not in _ROUTING_KEYS:
                return None
            return self._items(_untag([i for i in routing[_ROUTING_KEYS[kind]] if i["vr"] == vr["name"]]))
        kind = resource.removeprefix("routing/")
        if kind in _ROUTING_KEYS and kind != "ecmpzones":
            # The device level holds the global routing table.
            return self._items(_untag([i for i in routing[_ROUTING_KEYS[kind]] if i["vr"] == "Global"]))
        return None


def _client(fake: _FakeFmc, **kwargs) -> FmcClient:
    kwargs.setdefault("requests_per_second", 1000)
    return FmcClient(
        "https://fmc.example.com", "api-user", "api-pass", transport=httpx.MockTransport(fake.handler), **kwargs
    )


def _section(entity: dict, title: str) -> dict:
    return next(s for s in entity["sections"] if s["title"] == title)


def _node(snapshot: dict, node_id: str) -> dict:
    return next(n for n in snapshot["nodes"] if n["id"] == node_id)


def _kv(entity: dict, title: str) -> dict[str, str]:
    return dict(_section(entity, title)["rows"])


def _table(entity: dict, title: str) -> list[dict[str, str]]:
    section = _section(entity, title)
    return [dict(zip(section["columns"], row, strict=False)) for row in section["rows"]]


# ── Client ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_client_logs_in_with_basic_auth_and_learns_the_domains():
    fake = _FakeFmc()
    async with _client(fake) as client:
        await client.login()
        assert [d["name"] for d in client.domains] == ["Global", "Global/Branch"]
        assert client.resolve_domain("")["uuid"] == DOMAIN_UUID
        assert client.resolve_domain("branch")["uuid"] == "branch-uuid"
        assert client.resolve_domain("Global/Branch")["uuid"] == "branch-uuid"
        with pytest.raises(FmcApiError) as excinfo:
            client.resolve_domain("Nope")
        assert "Global/Branch" in excinfo.value.detail
        body = await client.get(f"{CONFIG_PATH}/domain/{DOMAIN_UUID}/policies/ravpns")
        assert body["items"][0]["name"] == "Corp-RAVPN"
    assert fake.logins == 1


@pytest.mark.asyncio
async def test_client_sends_the_fmc_user_agent():
    agents: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        agents.append(request.headers.get("User-Agent", ""))
        if request.url.path == TOKEN_PATH:
            return httpx.Response(204, headers=LOGIN_HEADERS)
        return httpx.Response(200, json={"items": []})

    async with FmcClient("https://fmc.example.com", "u", "p", transport=httpx.MockTransport(handler)) as client:
        await client.get("/x")
    assert agents == ["Plexus-FmcTopology/1.0", "Plexus-FmcTopology/1.0"]


@pytest.mark.asyncio
async def test_client_rejected_credentials_are_not_retried():
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(401, json={"error": {"messages": [{"description": "User authentication failed"}]}})

    client = FmcClient(
        "https://fmc.example.com", "u", "p", transport=httpx.MockTransport(handler), requests_per_second=1000
    )
    with pytest.raises(FmcApiError) as excinfo:
        await client.login()
    assert excinfo.value.status_code == 401 and "authentication failed" in excinfo.value.detail
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_client_logs_in_again_once_when_the_token_expires():
    fake = _FakeFmc()
    fake.expire_token_once = True
    async with _client(fake) as client:
        body = await client.get(f"{CONFIG_PATH}/domain/{DOMAIN_UUID}/policies/ravpns")
    assert body["items"] and fake.logins == 2


@pytest.mark.asyncio
async def test_client_retries_rate_limit_then_succeeds(monkeypatch):
    import netcontrol.integrations.fmc.client as client_module

    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(client_module.asyncio, "sleep", _no_sleep)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == TOKEN_PATH:
            return httpx.Response(204, headers=LOGIN_HEADERS)
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "1"})
        if calls["n"] == 2:
            return httpx.Response(503)
        return httpx.Response(200, json={"items": [{"ok": True}]})

    client = FmcClient(
        "https://fmc.example.com", "u", "p", transport=httpx.MockTransport(handler), requests_per_second=1000
    )
    assert (await client.get("/x"))["items"] == [{"ok": True}]
    assert client.stats["rate_limited"] == 1 and client.stats["retries"] == 2


@pytest.mark.asyncio
async def test_client_get_all_follows_pages():
    fake = _FakeFmc()
    fake.page_devices = True
    async with _client(fake) as client:
        items = await client.get_all(f"{CONFIG_PATH}/domain/{DOMAIN_UUID}/devices/devicerecords")
    assert [d["name"] for d in items] == [
        "ftdv-ravpn-1",
        "ftdv-ravpn-2",
        "ftd-branch-dc",
        "ftd-dc-unit-1",
        "ftd-dc-unit-2",
    ]


def test_base_url_must_be_the_https_fmc_host():
    assert validate_base_url("fmc.example.com") == "https://fmc.example.com"
    assert validate_base_url("https://10.1.1.5:8443/") == "https://10.1.1.5:8443"
    for bad in (
        "",
        "http://fmc.example.com",
        "https://user:pw@fmc.example.com",
        "https://fmc.example.com/api/x",
        "https://fmc?x=1",
    ):
        with pytest.raises(ValueError):
            validate_base_url(bad)


# ── Collector ────────────────────────────────────────────────────────────────


def test_sanitize_options_defaults_and_coerces():
    opts = sanitize_options({"username": " api ", "include_sessions": 0, "device_name_contains": " ftdv ", "bogus": 1})
    assert opts["username"] == "api" and opts["include_sessions"] is False and opts["verify_tls"] is True
    assert opts["device_name_contains"] == "ftdv" and "bogus" not in opts and opts["inventory_enrich"] is True
    # Every managed device is drawn by default now, and every new part is read.
    assert opts["include_all_devices"] is True
    for key in ("include_routing", "include_s2s_vpn", "include_nat", "include_access_policies", "include_health"):
        assert opts[key] is True
    assert set(collector_module._BOOL_OPTIONS) == {k for k, v in DEFAULT_OPTIONS.items() if isinstance(v, bool)}
    assert sanitize_options({"include_nat": False, "include_routing": ""})["include_nat"] is False


@pytest.mark.asyncio
async def test_collect_fmc_reads_every_resource_of_the_fmc():
    fake = _FakeFmc()
    progress: list[dict] = []
    async with _client(fake) as client:
        raw = await collect_fmc(client, "", None, progress.append)
    sample = build_sample_raw()
    assert raw["fmc"]["version"].startswith("7.4") and raw["fmc"]["domain"] == "Global"
    assert sorted(d["name"] for d in raw["devices"]) == ALL_DEVICES
    assert sorted(raw["on_map"]) == sorted([D1, D2, D3, D4, D5])
    assert raw["errors"] == [] and raw["unsupported"] == []
    assert [p["name"] for p in raw["ha_pairs"]] == ["ftdv-ravpn-ha"] and [c["name"] for c in raw["clusters"]] == [
        "ftd-dc-cluster"
    ]
    assert raw["ha_monitored"] == sample["ha_monitored"]
    assert {k: len(v) for k, v in raw["objects"].items()} == {k: len(v) for k, v in sample["objects"].items()}
    assert len(raw["sessions"]) == 4
    detail = raw["policy_details"][POLICY_ID]
    assert [p["name"] for p in detail["connection_profiles"]] == ["Employees", "Contractors"]
    assert detail["address_assignment"][0]["useLocalPools"] is True  # the one-object shape
    # Every interface kind, and per virtual router routing for the branch.
    assert len(raw["interfaces"][D3]) == len(sample["interfaces"][D3])
    assert {i["type"] for i in raw["interfaces"][D3]} == {
        "PhysicalInterface",
        "SubInterface",
        "LoopbackInterface",
        "VTIInterface",
    }
    branch = raw["routing"][D3]
    assert [r["name"] for r in branch["virtual_routers"]] == ["Global", "Guest"]
    assert sorted((r["vr"], r["id"]) for r in branch["static_v4"]) == [
        ("Global", "rt-br-1"),
        ("Global", "rt-br-2"),
        ("Global", "rt-br-3"),
        ("Guest", "rt-br-4"),
    ]
    assert [b["asNumber"] for b in branch["bgp"]] == ["65010"] and len(branch["pbr"]) == 1
    assert len(branch["ospf"]) == 1 and len(branch["eigrp"]) == 1 and len(branch["ecmp"]) == 1
    # NAT, access control (with the policy's real rule count), VPN, health.
    assert len(raw["nat_rules"][NAT_POLICY_ID]) == 2 and len(raw["access_rules"][ACP_ID]) == 3
    assert raw["access_rule_counts"] == {ACP_ID: 3}
    assert [p["name"] for p in raw["prefilter_policies"]] == ["Corp-Prefilter"]
    assert sorted(raw["s2s_details"]) == sorted(t["id"] for t in sample["s2s_vpns"])
    assert len(raw["tunnel_status"]) == 2 and len(raw["health_alerts"]) == 2 and len(raw["deployable"]) == 1
    assert progress[-1]["phase"] == "collected" and progress[-1]["calls_done"] == progress[-1]["calls_total"]
    phases = list(dict.fromkeys(p["phase"] for p in progress))
    assert phases == [
        "fmc login",
        "fmc devices",
        "fmc ha",
        "fmc objects",
        "fmc vpn policies",
        "fmc pools",
        "fmc interfaces",
        "fmc routing",
        "fmc nat",
        "fmc access policies",
        "fmc s2s vpn",
        "fmc health",
        "fmc sessions",
        "collected",
    ]
    assert fake.logins == 1
    # The collected FMC builds the same map as the bundled sample it was served from.
    assert build_snapshot(raw)["summary"] == build_snapshot(sample)["summary"]


@pytest.mark.asyncio
async def test_collect_fmc_never_keeps_an_ike_pre_shared_key():
    fake = _FakeFmc()
    async with _client(fake) as client:
        raw = await collect_fmc(client, "", None)
    assert "pre-shared-secret-value" not in json.dumps(raw)
    ike = raw["s2s_details"][build_sample_raw()["s2s_vpns"][0]["id"]]["ike"][0]
    assert ike["ikeV2Settings"] == {"authenticationType": "MANUAL_PRE_SHARED_KEY"}


@pytest.mark.asyncio
async def test_collect_fmc_reads_an_ha_pair_once_through_its_primary():
    fake = _FakeFmc()
    async with _client(fake) as client:
        raw = await collect_fmc(client, "", None)
    base = f"{CONFIG_PATH}/domain/{DOMAIN_UUID}/devices/devicerecords"
    assert f"{base}/{D1}/physicalinterfaces" in fake.calls
    assert not any(c.startswith(f"{base}/{D2}/") for c in fake.calls)
    assert raw["interfaces"][D2] == raw["interfaces"][D1] and raw["routing"][D2] == raw["routing"][D1]
    # Cluster units are read each on their own.
    assert f"{base}/{D4}/etherchannelinterfaces" in fake.calls and f"{base}/{D5}/etherchannelinterfaces" in fake.calls


@pytest.mark.asyncio
async def test_collect_fmc_reads_the_pair_container_when_the_primary_has_no_interfaces():
    fake = _FakeFmc()
    # Some releases keep a pair's interfaces on the pair record.
    fake.raw["interfaces"][HA_PAIR] = fake.raw["interfaces"].pop(D1)
    fake.raw["interfaces"].pop(D2)
    fake.raw["routing"][HA_PAIR] = fake.raw["routing"][D1]
    fake.raw["interfaces"][D1] = []
    async with _client(fake) as client:
        raw = await collect_fmc(client, "", {"include_routing": False})
    assert [i["ifname"] for i in raw["interfaces"][D1]] == ["outside", "inside"]
    assert raw["interfaces"][D2] == raw["interfaces"][D1] and raw["errors"] == []


@pytest.mark.asyncio
async def test_collect_fmc_headend_scope_resolves_pair_assignments_to_members():
    fake = _FakeFmc()
    async with _client(fake) as client:
        raw = await collect_fmc(client, "", {"include_all_devices": False})
    # The RA VPN policy targets the HA pair container: both members are headends.
    assert sorted(raw["on_map"]) == sorted([D1, D2])
    assert set(raw["interfaces"]) == {D1, D2} and set(raw["routing"]) == {D1, D2}
    base = f"{CONFIG_PATH}/domain/{DOMAIN_UUID}/devices/devicerecords"
    assert not any(c.startswith(f"{base}/{D3}/") for c in fake.calls)
    # Only the policies of the devices on the map get their rules read.
    assert set(raw["nat_rules"]) == {NAT_POLICY_ID} and set(raw["access_rules"]) == {ACP_ID}
    snapshot = build_snapshot(raw)
    assert snapshot["summary"]["devices"] == 2 and snapshot["summary"]["sites"] == 1


@pytest.mark.asyncio
async def test_collect_fmc_falls_back_to_device_routing_without_virtual_routers():
    fake = _FakeFmc()
    fake.missing = {"routing/virtualrouters", "eigrproutes", "health/alerts", "loopbackinterfaces"}
    async with _client(fake) as client:
        raw = await collect_fmc(client, "", None)
    # Not served by this release: listed as unsupported, not as errors.
    assert raw["errors"] == []
    assert f"/devices/devicerecords/{D3}/routing/virtualrouters" in raw["unsupported"]
    assert "/health/alerts" in raw["unsupported"] and raw["health_alerts"] is None
    assert f"/devices/devicerecords/{D3}/loopbackinterfaces" in raw["unsupported"]
    branch = raw["routing"][D3]
    assert branch["virtual_routers"] == [] and branch["eigrp"] == []
    # The device level holds the global table.
    assert sorted(r["id"] for r in branch["static_v4"]) == ["rt-br-1", "rt-br-2", "rt-br-3"]
    assert {r["vr"] for r in branch["static_v4"]} == {"Global"}
    assert len(branch["bgp"]) == 1
    snapshot = build_snapshot(raw)
    assert snapshot["collection"]["unsupported"] == raw["unsupported"] and snapshot["collection"]["errors"] == []
    fmc = _node(snapshot, FMC_NODE_ID)
    assert _kv(fmc, "Cisco FMC")["Unsupported resources"] == str(len(raw["unsupported"]))


@pytest.mark.asyncio
async def test_collect_fmc_records_a_nat_rules_failure_and_still_builds():
    fake = _FakeFmc()
    fake.fail = {"natrules": 500}
    async with _client(fake, max_retries=0) as client:
        raw = await collect_fmc(client, "", None)
    assert [(e["path"], e["status"]) for e in raw["errors"]] == [
        (f"/policies/ftdnatpolicies/{NAT_POLICY_ID}/natrules", 500)
    ]
    assert raw["nat_rules"] == {} and raw["unsupported"] == []
    snapshot = build_snapshot(raw)
    assert len(snapshot["collection"]["errors"]) == 1
    branch = _node(snapshot, f"d:{D3}")
    assert "NAT rules" not in {s["title"] for s in branch["sections"]}
    assert _kv(branch, "Overview")["NAT policy"] == "Corp-NAT"


@pytest.mark.asyncio
async def test_collect_fmc_caps_access_rules_and_keeps_the_real_count(monkeypatch):
    monkeypatch.setattr(collector_module, "MAX_ACCESS_RULES", 2)
    fake = _FakeFmc()
    async with _client(fake) as client:
        raw = await collect_fmc(client, "", None)
    assert len(raw["access_rules"][ACP_ID]) == 2 and raw["access_rule_counts"][ACP_ID] == 3
    branch = _node(build_snapshot(raw), f"d:{D3}")
    assert len(_section(branch, "Access control rules")["rows"]) == 2
    assert _section(branch, "Access control rules (note)")["text"] == "Showing the first 2 of 3 rules"
    assert _kv(branch, "Access control")["Rules"] == "3"


@pytest.mark.asyncio
async def test_collect_fmc_is_best_effort_past_the_device_list():
    fake = _FakeFmc()
    fake.fail = {"ravpnsessions": 404, "policyassignments": 403, "physicalinterfaces": 500}
    async with _client(fake, max_retries=0) as client:
        raw = await collect_fmc(client, "Global", {"device_name_contains": "ftdv", "include_all_devices": False})
    assert [d["name"] for d in raw["devices"]] == ["ftdv-ravpn-1", "ftdv-ravpn-2"]
    assert raw["sessions"] is None
    paths = sorted(e["path"] for e in raw["errors"])
    assert paths[0] == "/assignment/policyassignments" and paths[-1] == "/health/ravpnsessions"
    # A 404 on a resource every release serves is an error, not a gap.
    assert any("Refused ravpnsessions" in e["message"] and e["status"] == 404 for e in raw["errors"])
    # The reduced capture still builds a map, every filtered device on it.
    snapshot = build_snapshot(raw)
    assert snapshot["summary"]["devices"] == 2 and snapshot["summary"]["remote_users"] == 0


@pytest.mark.asyncio
async def test_collect_fmc_fails_when_devices_unreadable():
    fake = _FakeFmc()
    fake.fail = {"devicerecords": 403}
    async with _client(fake, max_retries=0) as client:
        with pytest.raises(FmcApiError) as excinfo:
            await collect_fmc(client, "")
    assert excinfo.value.status_code == 403
    with pytest.raises(FmcApiError):
        async with _client(_FakeFmc()) as client:
            await collect_fmc(client, "NoSuchDomain")


# ── Normalize ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def snapshot() -> dict:
    return build_snapshot(build_sample_raw())


def test_snapshot_summary_counts_every_part(snapshot):
    summary = snapshot["summary"]
    assert snapshot["provider"] == "fmc" and snapshot["schema"] == 1
    assert summary["sites"] == 3 and summary["devices"] == 5
    assert summary["devices_by_kind"] == {"appliance": 5}
    assert summary["devices_by_status"] == {"online": 3, "alerting": 1, "offline": 1}
    # HA + cluster links; 2 users + 1 FTD-to-FTD tunnel + 1 extranet tunnel.
    assert summary["lan_links"] == 2 and summary["vpn_tunnels"] == 4
    assert summary["wan_uplinks"] == 3 and summary["remote_users"] == 4
    # 15 connected subnets (2 + 2 + 7 + 2 + 2) and the 2 address pools.
    assert summary["vlans"] == 17
    assert summary["ha_pairs"] == 1 and summary["clusters"] == 1 and summary["s2s_topologies"] == 2
    assert summary["nat_rules"] == 2 and summary["access_rules"] == 3
    assert snapshot["collection"]["sources"] == ["Cisco FMC REST API"] and snapshot["collection"]["unsupported"] == []
    # The FMC is a box of its own, sorted ahead of the devices; the VPN peers next.
    assert [s["id"] for s in snapshot["sites"][:2]] == [FMC_SITE_ID, VPN_PEER_SITE_ID]
    assert all("x" in n and "y" in n for n in snapshot["nodes"])
    ids = {n["id"] for n in snapshot["nodes"]}
    assert all(e["a"] in ids and e["b"] in ids and e["sections"] for e in snapshot["edges"])
    # A device is never marked as a cloud instance.
    assert not any("alias_ips" in n for n in snapshot["nodes"])


def test_snapshot_draws_an_ha_pair_as_one_box(snapshot):
    site = next(s for s in snapshot["sites"] if s["id"] == f"ha:{HA_PAIR}")
    assert site["name"] == "ftdv-ravpn-ha" and site["device_count"] == 2
    members = [n for n in snapshot["nodes"] if n["site"] == site["id"] and n["kind"] == "appliance"]
    assert [n["label"] for n in members] == ["ftdv-ravpn-1", "ftdv-ravpn-2"]
    link = next(e for e in snapshot["edges"] if e["kind"] == "stack" and e["label"] == "HA")
    assert (link["a"], link["b"]) == (f"d:{D1}", f"d:{D2}")
    assert link["a_port"] == link["b_port"] == "failover-link" and link["status"] == "active"
    assert link["sections"][0]["title"] == "High availability"
    primary, secondary = _kv(_node(snapshot, f"d:{D1}"), "Overview"), _kv(_node(snapshot, f"d:{D2}"), "Overview")
    assert (primary["HA pair"], primary["HA role"], primary["HA state"]) == ("ftdv-ravpn-ha", "primary", "Active")
    assert (secondary["HA role"], secondary["HA state"]) == ("secondary", "Standby")
    # The secondary answers on the standby addresses of the monitored interfaces.
    rows = _table(_node(snapshot, f"d:{D2}"), "FTD interfaces")
    assert [(r["Name"], r["IP address"]) for r in rows] == [("outside", "10.210.0.12"), ("inside", "10.210.1.12")]
    assert [r["IP address"] for r in _table(_node(snapshot, f"d:{D1}"), "FTD interfaces")] == [
        "10.210.0.11",
        "10.210.1.11",
    ]
    # Pair-level policies reach both members.
    assert primary["NAT policy"] == secondary["NAT policy"] == "Corp-NAT"
    assert primary["Remote access VPN policy"] == secondary["Remote access VPN policy"] == "Corp-RAVPN"


def test_snapshot_draws_a_cluster_with_the_control_unit_first(snapshot):
    site = next(s for s in snapshot["sites"] if s["id"] == f"cluster:{CLUSTER}")
    assert site["name"] == "ftd-dc-cluster" and site["status"] == "offline"
    link = next(e for e in snapshot["edges"] if e["kind"] == "stack" and e["label"] == "Cluster")
    assert (link["a"], link["b"]) == (f"d:{D4}", f"d:{D5}") and link["status"] == "failed"
    assert link["sections"][0]["title"] == "Cluster"
    control, data = _node(snapshot, f"d:{D4}"), _node(snapshot, f"d:{D5}")
    assert _kv(control, "Overview")["Cluster role"] == "control" and _kv(data, "Overview")["Cluster role"] == "data"
    # The red health alert takes the data unit offline.
    assert data["status"] == "offline" and _table(data, "Health alerts")[0]["Severity"] == "red"
    # The control unit sits above its data unit.
    assert control["y"] < data["y"]


def test_cluster_record_of_older_releases_is_read_too():
    raw = build_sample_raw()
    raw["clusters"] = [
        {
            "id": CLUSTER,
            "name": "ftd-dc-cluster",
            "masterDevice": {"deviceDetails": {"id": D5, "name": "ftd-dc-unit-2"}},
            "slaveDevices": [{"deviceDetails": {"id": D4, "name": "ftd-dc-unit-1"}}],
        }
    ]
    snapshot = build_snapshot(raw)
    link = next(e for e in snapshot["edges"] if e.get("label") == "Cluster")
    assert (link["a"], link["b"]) == (f"d:{D5}", f"d:{D4}")


def test_snapshot_outside_interfaces_are_wan_stubs(snapshot):
    stubs = {n["id"]: n for n in snapshot["nodes"] if n["kind"] == "wan"}
    # RA VPN access interfaces of both pair members, and the branch's public
    # outside (also the egress of its default route). Inside interfaces are not.
    assert sorted(stubs) == sorted([f"w:{D1}:outside", f"w:{D2}:outside", f"w:{D3}:outside"])
    assert stubs[f"w:{D2}:outside"]["ip"] == "10.210.0.12"
    assert _section(stubs[f"w:{D1}:outside"], "VPN access interface")["rows"]
    branch = stubs[f"w:{D3}:outside"]
    assert branch["ip"] == "198.51.100.10" and branch["label"] == "outside 198.51.100.10"
    wan = _kv(branch, "WAN interface")
    assert wan["Default route via"] == "gw-branch-isp (198.51.100.1)" and wan["Virtual router"] == "Global"
    uplink = next(e for e in snapshot["edges"] if e["a"] == f"w:{D3}:outside")
    assert uplink["kind"] == "uplink" and uplink["b"] == f"d:{D3}" and uplink["b_port"] == "outside"
    assert uplink["sections"][0]["title"] == "WAN interface"


def test_default_route_egress_makes_a_private_interface_outside():
    raw = build_sample_raw()
    raw["policies"], raw["assignments"] = [], []
    snapshot = build_snapshot(raw)
    # Without the RA VPN policy, the FTDv outside is still the default route's egress.
    stub = _node(snapshot, f"w:{D1}:outside")
    assert stub["ip"] == "10.210.0.11" and _kv(stub, "WAN interface")["Default route via"] == "10.210.0.1"


def test_snapshot_interfaces_subnets_and_routes_of_the_branch(snapshot):
    branch = _node(snapshot, f"d:{D3}")
    interfaces = {r["Name"]: r for r in _table(branch, "FTD interfaces")}
    assert (
        interfaces["voice"]["Interface"] == "GigabitEthernet1/2.20" and interfaces["voice"]["Type"] == "Sub-interface"
    )
    assert interfaces["lo-router-id"]["Type"] == "Loopback" and interfaces["guest"]["Virtual router"] == "Guest"
    assert interfaces["vti-aws"]["Type"] == "VTI"
    assert interfaces["vti-aws"]["Description"] == "Tunnel source GigabitEthernet1/1, peer 203.0.113.101"
    connected = {r["Subnet"]: r for r in _table(branch, "Connected subnets")}
    assert set(connected) == {
        "198.51.100.0/28",
        "2001:db8:100::/64",
        "10.60.0.0/24",
        "10.60.20.0/24",
        "10.60.30.0/24",
        "10.60.255.1/32",
        "169.254.21.0/30",
    }
    assert connected["10.60.30.0/24"]["Virtual router"] == "Guest" and connected["10.60.20.0/24"]["Name"] == "voice"
    routes = [
        (r["Destination"], r["Subnet"], r["Gateway"], r["Virtual router"]) for r in _table(branch, "Static routes")
    ]
    assert routes == [
        ("any-ipv4", "0.0.0.0/0", "gw-branch-isp (198.51.100.1)", "Global"),
        ("DC-Networks", "10.70.0.0/16", "10.60.0.254", "Global"),
        # A group is one row per member; a range is its covering network.
        ("Partner-Nets / Partner-A", "172.16.10.0/24", "gw-branch-core (10.60.0.254)", "Global"),
        ("Partner-Nets / Partner-B-Range", "172.16.30.0/26", "gw-branch-core (10.60.0.254)", "Global"),
        ("Partner-Nets / 172.16.20.5", "172.16.20.5/32", "gw-branch-core (10.60.0.254)", "Global"),
        ("guest-dns", "10.60.31.53/32", "10.60.30.254", "Guest"),
        ("any-ipv6", "::/0", "2001:db8:100::1", "Global"),
    ]
    assert _table(branch, "Static routes")[0]["Tracked"] == "isp-sla"
    assert [r["Name"] for r in _table(branch, "Virtual routers")] == ["Global", "Guest"]
    # An FMC without virtual routers shows no table of them.
    assert "Virtual routers" not in {s["title"] for s in _node(snapshot, f"d:{D1}")["sections"]}


def test_static_route_to_an_fqdn_keeps_the_name_without_a_subnet():
    raw = build_sample_raw()
    route = raw["routing"][D3]["static_v4"][1]
    route["selectedNetworks"] = [{"id": "fqdn-0001", "type": "FQDN", "name": "updates-cdn"}]
    rows = _table(_node(build_snapshot(raw), f"d:{D3}"), "Static routes")
    assert ("updates.example.com", "") in [(r["Destination"], r["Subnet"]) for r in rows]
    assert value_cidr("10.0.0.5") == "10.0.0.5/32" and value_cidr("10.0.0.10-10.0.0.20") == "10.0.0.0/27"
    assert value_cidr("updates.example.com") == ""


def test_snapshot_dynamic_routing_sections(snapshot):
    branch = _node(snapshot, f"d:{D3}")
    bgp = _kv(branch, "BGP")
    assert bgp["AS number"] == "65010" and bgp["Router ID"] == "10.60.255.1" and bgp["Redistributes"] == "Connected"
    assert bgp["Networks advertised"] == "Branch-LAN (10.60.0.0/24), Branch-Voice (10.60.20.0/24)"
    neighbor = _table(branch, "BGP neighbors")[0]
    assert (neighbor["Neighbor"], neighbor["Remote AS"], neighbor["Update source"], neighbor["Enabled"]) == (
        "169.254.21.1",
        "64512",
        "vti-aws",
        "Yes",
    )
    assert _kv(branch, "OSPF") == {"Process ID": "1", "Router ID": "10.60.255.1", "Virtual router": "Global"}
    assert _table(branch, "OSPF areas")[0]["Area"] == "0"
    assert _kv(branch, "EIGRP")["AS number"] == "100"
    assert _table(branch, "Policy-based routes") == [
        {"Ingress interface": "inside", "Match (ACL)": "Voice-to-ISP", "Egress interfaces": "outside", "Order": "1"}
    ]
    assert _table(branch, "ECMP zones")[0] == {
        "Zone": "ecmp-inside",
        "Interfaces": "inside, voice",
        "Virtual router": "Global",
    }


def test_snapshot_nat_and_access_control(snapshot):
    branch = _node(snapshot, f"d:{D3}")
    nat = _table(branch, "NAT rules")
    assert [(r["#"], r["Type"], r["Section"]) for r in nat] == [
        ("1", "Manual", "Before auto"),
        ("2", "Auto", "Auto NAT"),
    ]
    assert nat[0]["Original destination"] == "AWS-VPCs" and nat[1]["Translated source"] == "Destination interface IP"
    assert nat[1]["Source interface"] == "inside" and nat[1]["Destination interface"] == "outside"
    acp = _kv(branch, "Access control")
    assert acp["Policy"] == "Corp-ACP" and acp["Default action"] == "BLOCK" and acp["Rules"] == "3"
    assert acp["Prefilter policy"] == "Corp-Prefilter"
    rules = _table(branch, "Access control rules")
    assert [r["Name"] for r in rules] == ["Allow-VPN-Users-to-Apps", "Allow-Branch-Web", "Block-Guest-to-Corp"]
    assert rules[0]["Destination ports"] == "TCP/443" and rules[0]["Destination networks"] == "AWS-VPCs"
    assert rules[1]["URLs"] == "Business and Economy" and rules[1]["File policy"] == "Block-Malware"
    assert rules[2]["Action"] == "BLOCK" and rules[2]["Source zones"] == "guest"
    assert "Access control rules (note)" not in {s["title"] for s in branch["sections"]}
    # The cluster has an access control policy but no NAT policy.
    unit = _node(snapshot, f"d:{D4}")
    assert _kv(unit, "Access control")["Policy"] == "Corp-ACP"
    assert "NAT rules" not in {s["title"] for s in unit["sections"]}


def test_snapshot_site_to_site_tunnels_and_their_status(snapshot):
    tunnels = [e for e in snapshot["edges"] if e.get("detail")]
    hub = next(e for e in tunnels if e["detail"] == "DC-to-AWS-Hub")
    # Hub and spoke: the pair's primary to the spoke, reported UP.
    assert (hub["a"], hub["b"], hub["kind"], hub["label"]) == (f"d:{D1}", f"d:{D3}", "vpn", "Site-to-site VPN")
    assert hub["status"] == "reachable"
    # Point to point to an extranet peer, reported DOWN.
    vgw = next(e for e in tunnels if e["detail"] == "Branch-to-AWS-VGW")
    assert (vgw["a"], vgw["b"], vgw["kind"], vgw["label"]) == (f"d:{D3}", "p:AWS-VGW", "vpn3p", "IPsec")
    assert vgw["status"] == "unreachable" and vgw["sections"][0]["title"] == "IPsec"
    peer = _node(snapshot, "p:AWS-VGW")
    assert peer["kind"] == "vpn_peer" and peer["ip"] == "203.0.113.101" and peer["site"] == VPN_PEER_SITE_ID
    assert _kv(peer, "Site-to-site VPN peer")["Topologies"] == "Branch-to-AWS-VGW"
    rows = _table(_node(snapshot, f"d:{D3}"), "Site-to-site VPN")
    assert [(r["Topology"], r["Type"], r["Role"], r["Peer"], r["Status"]) for r in rows] == [
        ("DC-to-AWS-Hub", "Hub and spoke", "spoke", "ftdv-ravpn-ha", "up"),
        ("Branch-to-AWS-VGW", "Point to point", "peer", "AWS-VGW", "down"),
    ]
    assert rows[1]["Peer address"] == "203.0.113.101" and rows[1]["Local interface"] == "vti-aws"
    assert rows[0]["IKE"] == "IKEv2" and rows[0]["IPsec"] == "AES-GCM-256"
    # The addresses the FTD's VPN endpoints use: how another integration's
    # view of the same tunnel finds it.
    assert _node(snapshot, f"d:{D3}")["endpoint_ips"] == ["198.51.100.10", "169.254.21.2"]
    assert _node(snapshot, f"d:{D1}")["endpoint_ips"] == ["10.210.0.11"]
    assert "endpoint_ips" not in _node(snapshot, f"d:{D2}")


def test_tunnel_status_is_blank_without_a_matching_entry():
    raw = build_sample_raw()
    raw["tunnel_status"] = None
    snapshot = build_snapshot(raw)
    assert {e["status"] for e in snapshot["edges"] if e.get("detail")} == {""}
    rows = _table(_node(snapshot, f"d:{D3}"), "Site-to-site VPN")
    assert {r["Status"] for r in rows} == {"unknown"}


def test_full_mesh_joins_every_pair_once():
    raw = build_sample_raw()
    topology = raw["s2s_vpns"][0]
    topology["topologyType"] = "FULL_MESH"
    endpoints = raw["s2s_details"][topology["id"]]["endpoints"]
    endpoints.append(
        {**endpoints[1], "device": {"id": D4, "name": "ftd-dc-unit-1", "type": "Device"}, "peerType": "PEER"}
    )
    snapshot = build_snapshot(raw)
    pairs = {frozenset((e["a"], e["b"])) for e in snapshot["edges"] if e.get("detail") == topology["name"]}
    assert pairs == {
        frozenset((f"d:{D1}", f"d:{D3}")),
        frozenset((f"d:{D1}", f"d:{D4}")),
        frozenset((f"d:{D3}", f"d:{D4}")),
    }


def test_snapshot_health_and_pending_deployment(snapshot):
    branch = _kv(_node(snapshot, f"d:{D3}"), "Overview")
    assert branch["Pending deployment"] == "Yes" and branch["Site-to-site VPN topologies"] == (
        "DC-to-AWS-Hub, Branch-to-AWS-VGW"
    )
    assert branch["Virtual routers"] == "Global, Guest"
    standby = _node(snapshot, f"d:{D2}")
    assert standby["status"] == "alerting" and _kv(standby, "Overview")["Health alerts"] == "1"
    assert _kv(standby, "Overview")["Pending deployment"] == "No"


def test_snapshot_ra_vpn_sections_sit_on_the_pair_box(snapshot):
    site = next(s for s in snapshot["sites"] if s["id"] == f"ha:{HA_PAIR}")
    assert [s["title"] for s in site["sections"]] == [
        "Remote access VPN",
        "Connection profiles",
        "VPN address pools",
        "Access interfaces",
    ]
    assert dict(_section(site, "Remote access VPN")["rows"])["Headend"] == "ftdv-ravpn-ha"
    assert [r[2] for r in _section(site, "Access interfaces")["rows"]] == ["10.210.0.11", "10.210.0.12"]
    users = _node(snapshot, f"u:{D2}")
    assert users["kind"] == "users" and users["label"] == "AnyConnect users (2)"
    rows = _section(users, "Connected users")["rows"]
    assert [r[0] for r in rows] == ["ext.contractor1", "sam.okafor"]
    assert rows[0][1] == "10.220.8.10" and rows[0][3] == "Contractors" and rows[0][6] == "Ubuntu 24.04"
    links = {(e["a"], e["b"]): e for e in snapshot["edges"]}
    assert (
        links[(f"u:{D1}", f"d:{D1}")]["label"] == "AnyConnect"
        and links[(f"u:{D1}", f"d:{D1}")]["status"] == "reachable"
    )
    assert links[(FMC_NODE_ID, f"d:{D3}")]["kind"] == "manage"
    # Devices without a policy have no users node.
    assert f"u:{D3}" not in {n["id"] for n in snapshot["nodes"]}


def test_snapshot_fmc_node_lists_the_whole_fmc(snapshot):
    fmc = _node(snapshot, FMC_NODE_ID)
    assert fmc["kind"] == "cloud" and fmc["ip"] == "10.210.2.20"
    info = _kv(fmc, "Cisco FMC")
    assert info["HA pairs"] == "1" and info["Clusters"] == "1" and info["Site-to-site VPN topologies"] == "2"
    assert info["Network objects"] == "16" and info["Security zones"] == "5" and info["Health alerts"] == "2"
    assert info["Devices pending deployment"] == "1" and info["Unsupported resources"] == "0"
    managed = _table(fmc, "Managed devices")
    assert [r["Device"] for r in managed] == ALL_DEVICES
    assert managed[3]["HA pair / cluster"] == "HA ftdv-ravpn-ha" and managed[0]["Pending deployment"] == "Yes"
    assert {r["On the map"] for r in managed} == {"Yes"}
    assert _table(fmc, "High availability pairs") == [
        {
            "Pair": "ftdv-ravpn-ha",
            "Primary": "ftdv-ravpn-1",
            "Secondary": "ftdv-ravpn-2",
            "Primary state": "Active",
            "Secondary state": "Standby",
            "Failover link": "failover-link",
        }
    ]
    assert _table(fmc, "Clusters")[0]["Data units"] == "ftd-dc-unit-2"
    assert _table(fmc, "Access control policies")[0]["Rules"] == "3"
    assert _table(fmc, "NAT policies")[0]["Devices"] == "ftd-branch-dc, ftdv-ravpn-1, ftdv-ravpn-2"
    assert {r["Topology"]: r["Tunnels up / down"] for r in _table(fmc, "Site-to-site VPN topologies")} == {
        "Branch-to-AWS-VGW": "0 / 1",
        "DC-to-AWS-Hub": "1 / 0",
    }
    objects = {r["Name"]: r for r in _table(fmc, "Network objects")}
    assert objects["Partner-B-Range"]["Type"] == "Range" and objects["updates-cdn"]["Value"] == "updates.example.com"
    assert {r["Group"] for r in _table(fmc, "Network groups")} == {"AWS-VPCs", "Partner-Nets"}
    zones = {r["Zone"]: r for r in _table(fmc, "Security zones")}
    assert zones["outside"]["Interfaces"] == "ftd-branch-dc:outside, ftdv-ravpn-1:outside, ftdv-ravpn-2:outside"
    assert len(_table(fmc, "Health alerts")) == 2 and _table(fmc, "Pending deployment")[0]["Device"] == "ftd-branch-dc"
    assert [r[0] for r in _section(fmc, "Remote access VPN policies")["rows"]] == ["Corp-RAVPN"]


def test_pool_cidr_handles_masks_and_bare_ranges():
    assert pool_cidr({"ipAddressRange": "10.220.0.1-10.220.3.254", "mask": "255.255.252.0"}) == "10.220.0.0/22"
    assert pool_cidr({"ipAddressRange": "10.9.9.10-10.9.9.20", "mask": "24"}) == "10.9.9.0/24"
    assert pool_cidr({"ipAddressRange": "10.9.9.10-10.9.9.20"}) == "10.9.9.0/27"
    assert pool_cidr({"ipAddressRange": "10.9.9.10"}) == "10.9.9.10/32"
    assert pool_cidr({"ipAddressRange": "nope"}) == ""


def test_build_snapshot_reads_a_capture_of_an_earlier_release():
    """A raw capture stored before the FMC provider read everything: no HA
    pairs, objects, routing, policies, VPN topologies or health."""
    sample = build_sample_raw()
    old = {
        key: sample[key]
        for key in ("fmc", "timestamp", "devices", "policies", "policy_details", "pools", "sessions", "errors", "stats")
    }
    old["assignments"] = [
        {
            "policy": {"id": POLICY_ID, "type": "RAVpn", "name": "Corp-RAVPN"},
            "targets": [{"id": D1, "type": "Device"}, {"id": D2, "type": "Device"}],
        }
    ]
    old["on_map"] = [D1, D2]
    old["interfaces"] = {
        D1: sample["interfaces"][D1],
        D2: [
            {
                **i,
                "ipv4": {"static": {"address": i["ipv4"]["static"]["address"].replace(".11", ".12"), "netmask": "24"}},
            }
            for i in sample["interfaces"][D1]
        ],
    }
    old["options"] = {
        "username": "plexus",
        "include_all_devices": False,
        "include_interfaces": True,
        "include_sessions": True,
    }
    snapshot = build_snapshot(old)
    assert snapshot["summary"]["sites"] == 2 and snapshot["summary"]["devices"] == 2
    assert snapshot["summary"]["vlans"] == 4 + 4  # 2 connected subnets each, 2 pools each
    assert snapshot["summary"]["wan_uplinks"] == 2 and snapshot["summary"]["remote_users"] == 4
    assert snapshot["collection"]["unsupported"] == []
    assert {s["id"] for s in snapshot["sites"]} == {FMC_SITE_ID, f"dev:{D1}", f"dev:{D2}"}
    assert _node(snapshot, f"w:{D2}:outside")["ip"] == "10.210.0.12"
    # And one with nothing but the device list.
    bare = build_snapshot({"devices": sample["devices"][:1], "options": {}})
    assert [n["kind"] for n in bare["nodes"]] == ["appliance", "cloud"]


def test_fmc_with_only_headends_wanted_draws_no_other_device():
    raw = build_sample_raw()
    raw["assignments"], raw["policies"], raw["on_map"], raw["sessions"] = [], [], [], None
    raw["options"] = {**raw["options"], "include_all_devices": False}
    empty = build_snapshot(raw)
    assert [n["id"] for n in empty["nodes"]] == [FMC_NODE_ID]
    assert empty["summary"]["sites"] == 0 and empty["edges"] == [] and empty["summary"]["remote_users"] == 0


# ── Subnet index ─────────────────────────────────────────────────────────────


def test_subnet_index_lists_connected_subnets_and_static_routes(snapshot):
    index = subnet_index(snapshot)
    by_key = {(s["cidr"], s["node_id"]): s for s in index}
    voice = by_key[("10.60.20.0/24", f"d:{D3}")]
    assert voice["kind"] == "connected" and voice["name"] == "voice (inside)" and voice["site_name"] == "ftd-branch-dc"
    route = by_key[("10.70.0.0/16", f"d:{D3}")]
    assert route["kind"] == "static" and route["name"] == "Static route DC-Networks"
    assert by_key[("172.16.30.0/26", f"d:{D3}")]["name"] == "Static route Partner-Nets / Partner-B-Range"
    assert by_key[("2001:db8:100::/64", f"d:{D3}")]["kind"] == "connected"
    # Both HA members own their connected subnets; the default routes are not subnets.
    assert ("10.210.0.0/24", f"d:{D1}") in by_key and ("10.210.0.0/24", f"d:{D2}") in by_key
    assert not any(s["cidr"] in ("0.0.0.0/0", "::/0") for s in index)
    # The pools stay owned by the pair's primary, the box's first appliance.
    pools = [s for s in index if s["kind"] == "pool"]
    assert {(s["cidr"], s["node_id"]) for s in pools} == {("10.220.0.0/22", f"d:{D1}"), ("10.220.8.0/24", f"d:{D1}")}
    assert pools[0]["name"] == "VPN pool RAVPN-Pool-Employees"
    # Nothing is owned by the FMC, a users node or a VPN peer.
    assert not any(s["site_id"] in (FMC_SITE_ID, VPN_PEER_SITE_ID) for s in index)


def test_subnet_index_skips_a_disabled_static_route():
    snapshot = {
        "sites": [{"id": "s", "name": "S", "sections": []}],
        "nodes": [
            {
                "id": "d",
                "kind": "appliance",
                "site": "s",
                "sections": [
                    {
                        "title": "Static routes",
                        "kind": "table",
                        "columns": ["Enabled", "Subnet", "Destination"],
                        "rows": [["No", "10.1.0.0/16", "off"], ["Yes", "10.2.0.0/16", "on"]],
                    }
                ],
            }
        ],
    }
    assert [(s["cidr"], s["name"]) for s in subnet_index(snapshot)] == [("10.2.0.0/16", "Static route on")]


# ── Merge into the Topology graph ────────────────────────────────────────────


def test_merge_marks_fmc_nodes_and_links(snapshot):
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(nodes, edges, [(7, snapshot)], host_node=lambda _id: None, resolve_external=lambda *_: None)
    ftd = nodes[f"meraki:7:d:{D1}"]
    assert ftd["device_type"] == "fmc" and ftd["device_category"] == "firewall"
    assert ftd["meraki"]["provider"] == "fmc" and ftd["meraki"]["site_name"] == "ftdv-ravpn-ha"
    assert nodes[f"meraki:7:{FMC_NODE_ID}"]["meraki"]["kind"] == "cloud"
    managed = next(e for e in edges if e["from"] == f"meraki:7:{FMC_NODE_ID}" and e["to"] == f"meraki:7:d:{D1}")
    assert managed["protocol"] == "management" and managed["provider"] == "fmc"
    protocols = {e["protocol"] for e in edges}
    assert {"management", "stack", "vpn", "vpn-ipsec", "wan"} <= protocols
    assert len(edges) == len(snapshot["edges"])


def test_merge_collapses_the_ftdv_pair_members_into_their_instances(snapshot):
    resources, connections = build_aws_sample()
    aws = build_aws_snapshot([{"id": 1, "name": "AWS", "account_identifier": "sample"}], resources, connections, None)
    pairs = virtual_appliance_pairs([(7, snapshot), (-1, aws)])
    assert pairs == {(-1, "i:i-0f7d001"): (7, f"d:{D1}"), (-1, "i:i-0f7d002"): (7, f"d:{D2}")}
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(
        nodes, edges, [(7, snapshot), (-1, aws)], host_node=lambda _id: None, resolve_external=lambda *_: None
    )
    assert "meraki:-1:i:i-0f7d001" not in nodes and "meraki:-1:i:i-0f7d002" not in nodes
    ftd = nodes[f"meraki:7:d:{D1}"]
    # The member stays in its pair's box and gains the instance's link to its VPC.
    assert ftd["meraki"]["provider"] == "fmc"
    assert any(
        e["from"] == ftd["id"] and e["protocol"] == "cloud" and e["to"].startswith("meraki:-1:vpc:") for e in edges
    )


def _public(snapshot: dict) -> dict:
    """The sample with its documentation addresses swapped for global ones:
    the merge only joins integrations by addresses that are public on the
    internet, which documentation ranges are not."""
    text = json.dumps(snapshot).replace("198.51.100.10", "8.8.4.4").replace("203.0.113.101", "8.8.8.8")
    return json.loads(text)


def test_merge_joins_the_site_to_site_vpn_with_the_aws_view_of_it(snapshot):
    resources, connections = build_aws_sample()
    aws = build_aws_snapshot([{"id": 1, "name": "AWS", "account_identifier": "sample"}], resources, connections, None)
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(
        nodes,
        edges,
        [(7, _public(snapshot)), (-1, _public(aws))],
        host_node=lambda _id: None,
        resolve_external=lambda *_: None,
    )
    branch = nodes[f"meraki:7:d:{D3}"]
    # The AWS customer gateway is the branch FTD (its outside address)...
    assert not any(k.startswith("meraki:-1:cgw:") for k in nodes) and branch["also_providers"] == ["aws"]
    # ...and the FTD's extranet peer is the AWS transit gateway (its tunnel address).
    assert "meraki:7:p:AWS-VGW" not in nodes
    tgw = next(n for k, n in nodes.items() if k.startswith("meraki:-1:tgw:"))
    assert tgw["also_providers"] == ["fmc"]
    ipsec = next(e for e in edges if e["protocol"] == "vpn-ipsec")
    assert (ipsec["from"], ipsec["to"]) == (branch["id"], tgw["id"]) and ipsec["status"] == "unreachable"


def test_node_details_report_the_provider_and_pools(snapshot):
    details = node_details(snapshot, f"d:{D1}")
    assert details["provider"] == "fmc" and details["site_name"] == "ftdv-ravpn-ha"
    assert [s["title"] for s in details["site_addressing"]] == ["VPN address pools"]
    assert node_details(snapshot, FMC_NODE_ID)["site_addressing"] == []


def test_search_finds_objects_and_static_routes(snapshot):
    index = build_search_index(snapshot)
    assert {h["node_id"] for h in search_index(index, ["partner-b-range"], 50)} >= {FMC_NODE_ID, f"d:{D3}"}
    # The route on the branch, the object on the FMC.
    assert {h["node_id"] for h in search_index(index, ["dc-networks", "10.70.0.0/16"], 50)} == {
        f"d:{D3}",
        FMC_NODE_ID,
    }


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
def api(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-fmc")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    import netcontrol.routes.meraki_topology as routes_module

    routes_module._SNAPSHOT_CACHE.clear()

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return _CsrfClient(client, resp.json().get("csrf_token", ""))


def _wait(api, job_id: str) -> dict:
    job: dict = {}
    for _ in range(400):
        job = api.get(f"/api/meraki/builds/{job_id}").json()
        if job["status"] != "running":
            break
    return job


def test_api_fmc_crud_keeps_the_password_write_only(api):
    listing = api.get("/api/meraki/orgs").json()
    assert listing["fmc_default_options"] == DEFAULT_OPTIONS and "anyconnect_default_options" not in listing

    body = {
        "name": "Prod FMC",
        "provider": "fmc",
        "org_id": "Global",
        "base_url": "fmc.example.com",
        "api_key": "super-secret-password",
        "options": {"username": "plexus", "verify_tls": False, "include_nat": 0},
    }
    created = api.post("/api/meraki/orgs", json=body)
    assert created.status_code == 201, created.text
    org = created.json()["org"]
    assert org["provider"] == "fmc" and org["has_api_key"] is True
    assert org["base_url"] == "https://fmc.example.com"
    assert org["options"] == {**DEFAULT_OPTIONS, "username": "plexus", "verify_tls": False, "include_nat": False}
    assert "super-secret-password" not in created.text
    assert "super-secret-password" not in api.get("/api/meraki/orgs").text

    # The credentials only ever go to an https host, with no path.
    bad = {"name": "Evil", "provider": "fmc", "base_url": "http://fmc.example.com"}
    assert api.post("/api/meraki/orgs", json=bad).status_code == 400
    bad["base_url"] = "https://fmc.example.com/api/fmc_platform"
    assert api.post("/api/meraki/orgs", json=bad).status_code == 400
    unknown = api.post("/api/meraki/orgs", json={"name": "X", "provider": "fortinet"})
    assert unknown.status_code == 400 and "Provider must be meraki, cato, fmc or panorama" in unknown.text

    updated = api.put(f"/api/meraki/orgs/{org['id']}", json={"options": {"username": "ro", "include_sessions": False}})
    assert updated.status_code == 200
    assert updated.json()["org"]["options"]["include_sessions"] is False
    assert updated.json()["org"]["options"]["username"] == "ro" and updated.json()["org"]["has_api_key"] is True
    assert api.delete(f"/api/meraki/orgs/{org['id']}").status_code == 200


def test_api_accepts_the_legacy_anyconnect_provider_as_fmc(api):
    body = {
        "name": "Old client FMC",
        "provider": "anyconnect",
        "base_url": "https://fmc.example.com",
        "api_key": "pw",
        "options": {"username": "plexus"},
    }
    created = api.post("/api/meraki/orgs", json=body)
    assert created.status_code == 201, created.text
    org = created.json()["org"]
    assert org["provider"] == "fmc" and org["options"]["include_routing"] is True
    stored = asyncio.run(db_module.get_meraki_org(org["id"]))
    assert stored["provider"] == "fmc"
    # The legacy sample key builds the FMC sample.
    built = api.post("/api/meraki/sample?provider=anyconnect")
    assert built.status_code == 201
    sample = asyncio.run(db_module.get_meraki_org(built.json()["org_ref"]))
    assert sample["provider"] == "fmc" and sample["name"] == "Sample Cisco FMC (demo data)"


def test_api_reads_a_stored_anyconnect_entry_and_snapshot_as_fmc(api):
    async def _seed() -> int:
        org = await db_module.create_meraki_org(
            "Sample AnyConnect FMC (demo data)", provider="anyconnect", base_url="https://10.210.2.20"
        )
        snapshot = build_snapshot(build_sample_raw())
        snapshot["provider"] = "anyconnect"
        await db_module.create_meraki_snapshot(org["id"], snapshot, built_by="test", duration_seconds=0.1)
        return org["id"]

    org_ref = asyncio.run(_seed())
    org = next(o for o in api.get("/api/meraki/orgs").json()["orgs"] if o["id"] == org_ref)
    assert org["provider"] == "fmc" and org["options"]["include_all_devices"] is True
    source = next(s for s in api.get("/api/topology/sources").json()["sources"] if s.get("id") == org_ref)
    # The demo entry of the earlier release is still flagged as demo data.
    assert source["type"] == "fmc" and source["demo"] is True
    graph = api.get("/api/topology").json()
    assert {(n.get("meraki") or {}).get("provider") for n in graph["nodes"] if n.get("meraki")} == {"fmc"}
    assert api.get(f"/api/meraki/nodes?org_ref={org_ref}&node_id=d:{D3}").json()["provider"] == "fmc"
    # Rebuilding the sample renames that entry instead of adding a second demo FMC.
    built = api.post("/api/meraki/sample?provider=fmc").json()
    assert built["org_ref"] == org_ref
    names = [o["name"] for o in api.get("/api/meraki/orgs").json()["orgs"]]
    assert names.count("Sample Cisco FMC (demo data)") == 1 and "Sample AnyConnect FMC (demo data)" not in names


def test_api_fmc_sample_is_merged_into_the_topology(api):
    built = api.post("/api/meraki/sample?provider=fmc")
    assert built.status_code == 201, built.text
    assert built.json()["summary"]["remote_users"] == 4 and built.json()["summary"]["ha_pairs"] == 1
    org_ref = built.json()["org_ref"]

    graph = api.get("/api/topology").json()
    ours = [n for n in graph["nodes"] if (n.get("meraki") or {}).get("provider") == "fmc"]
    assert {n["meraki"]["kind"] for n in ours} == {"appliance", "wan", "cloud", "users", "vpn_peer"}
    assert any(n["label"] == "AnyConnect users (2)" for n in ours)
    protocols = {e["protocol"] for e in graph["edges"] if e.get("provider") == "fmc"}
    assert {"management", "stack", "vpn", "vpn-ipsec", "wan"} <= protocols

    details = api.get(f"/api/meraki/nodes?org_ref={org_ref}&node_id=d:{D3}").json()
    assert details["provider"] == "fmc" and details["site_name"] == "ftd-branch-dc"
    titles = [s["title"] for s in details["sections"]]
    for title in ("Connected subnets", "Static routes", "BGP neighbors", "NAT rules", "Access control rules"):
        assert title in titles

    # Connected subnets, static routes and pools can be picked as path endpoints.
    subnets = api.get("/api/meraki/subnets").json()["subnets"]
    pool = next(s for s in subnets if s["cidr"] == "10.220.8.0/24")
    assert pool["provider"] == "fmc" and pool["kind"] == "pool" and pool["org_ref"] == org_ref
    voice = next(s for s in subnets if s["cidr"] == "10.60.20.0/24")
    assert voice["kind"] == "connected" and voice["node_id"] == f"d:{D3}"
    assert any(s["cidr"] == "10.70.0.0/16" and s["kind"] == "static" for s in subnets)

    # A remote user, a network object and a static route are found by name.
    hits = api.get("/api/topology/search/deep?q=dana.reyes").json()["results"]
    assert [(h["org_ref"], h["node_id"]) for h in hits] == [(org_ref, f"u:{D1}")]
    hits = api.get("/api/topology/search/deep?q=Partner-B-Range").json()["results"]
    assert {h["node_id"] for h in hits} >= {FMC_NODE_ID, f"d:{D3}"}
    hits = api.get("/api/topology/search/deep?q=10.70.0.0/16").json()["results"]
    assert {h["node_id"] for h in hits} == {f"d:{D3}", FMC_NODE_ID}

    # The sources list shows the demo FMC and the map exports.
    sources = api.get("/api/topology/sources").json()["sources"]
    fmc = next(s for s in sources if s["type"] == "fmc")
    assert fmc["demo"] and not fmc["can_collect"] and fmc["status"] == "success"
    assert fmc["name"] == "Sample Cisco FMC (demo data)"
    export = api.get("/api/topology/export.html")
    assert export.status_code == 200 and "AnyConnect users (2)" in export.text

    # Loading the AWS sample too joins the FTDv instances to the pair members.
    assert api.post("/api/meraki/sample?provider=aws").status_code == 201
    merged = api.get("/api/topology").json()["nodes"]
    assert {(n.get("meraki") or {}).get("provider") for n in merged if n.get("meraki")} == {"fmc", "aws"}
    assert not any(n["id"] in ("meraki:-1:i:i-0f7d001", "meraki:-1:i:i-0f7d002") for n in merged)


def test_api_ipam_overview_lists_the_fmc_subnets(api):
    assert api.post("/api/meraki/sample?provider=fmc").status_code == 201
    assert api.post("/api/meraki/sample?provider=aws").status_code == 201

    body = api.get("/api/ipam/overview").json()
    subnets = {s["subnet"]: s for s in body["subnets"]}
    pool = subnets["10.220.8.0/24"]
    assert pool["source_types"] == ["topology"] and pool["topology_providers"] == ["fmc"]
    assert pool["topology_sites_preview"] == ["ftdv-ravpn-ha (VPN pool RAVPN-Pool-Contractors)"]
    # The branch's connected subnets and static routes are listed too.
    voice = subnets["10.60.20.0/24"]
    assert voice["source_types"] == ["topology"] and voice["topology_sites_preview"] == [
        "ftd-branch-dc (voice (inside))"
    ]
    assert subnets["10.70.0.0/16"]["topology_sites_preview"] == ["ftd-branch-dc (Static route DC-Networks)"]
    # The AWS snapshot's subnets are not listed a second time as topology.
    vpc = subnets["10.220.0.0/16"]
    assert vpc["source_types"] == ["cloud", "topology"] and vpc["topology_count"] == 2
    # The demo pools are carved out of the apps VPC: an overlap, not a VPN one.
    pairs = [(p["a"]["subnet"], p["b"]["subnet"], p["relation"], p["vpn_conflict"]) for p in body["overlaps"]]
    assert ("10.220.0.0/16", "10.220.0.0/22", "contains", False) in pairs
    assert ("10.220.0.0/16", "10.220.8.0/24", "contains", False) in pairs
    # Connected subnets and routes are not owned ranges: no overlap of their own.
    assert not any("10.60.20.0/24" in (a, b) for a, b, _r, _v in pairs)


def test_api_fmc_build_job_runs_the_fmc_collector(api, monkeypatch):
    import netcontrol.routes.meraki_topology as routes_module

    async def _fake_collect(client, domain, options, progress):
        assert client.base_url == "https://fmc.example.com:8443" and domain == "Global/Branch"
        assert options["username"] == "plexus" and options["include_sessions"] is True
        progress({"phase": "fmc devices"})
        return build_sample_raw()

    monkeypatch.setattr(routes_module, "collect_fmc", _fake_collect)
    body = {
        "name": "Prod FMC",
        "provider": "fmc",
        "org_id": "Global/Branch",
        "base_url": "https://fmc.example.com:8443",
        "api_key": "pw",
        "options": {"username": "plexus"},
    }
    org = api.post("/api/meraki/orgs", json=body).json()["org"]
    started = api.post(f"/api/meraki/orgs/{org['id']}/build")
    assert started.status_code == 202, started.text
    job = _wait(api, started.json()["job_id"])
    assert job["status"] == "completed", job
    assert job["result"]["summary"]["sites"] == 3 and "clients_tracked" not in job["result"]
    snapshot = api.get(f"/api/meraki/snapshots/{job['result']['snapshot_id']}/data").json()
    assert snapshot["org"]["name"] == "Prod FMC" and snapshot["provider"] == "fmc"


def test_api_fmc_build_job_against_the_fake_fmc_is_partial_on_a_failed_resource(api, monkeypatch):
    import netcontrol.routes.meraki_topology as routes_module

    fake = _FakeFmc()
    fake.fail = {"natrules": 500}
    real_client = routes_module.FmcClient

    def _client_factory(base_url, username, password, **kwargs):
        assert username == "plexus" and password == "pw"
        kwargs.update(transport=httpx.MockTransport(fake.handler), requests_per_second=1000, max_retries=0)
        return real_client(base_url, username, password, **kwargs)

    monkeypatch.setattr(routes_module, "FmcClient", _client_factory)
    body = {
        "name": "Lab FMC",
        "provider": "fmc",
        "base_url": "https://fmc.example.com",
        "api_key": "pw",
        "options": {"username": "plexus"},
    }
    org = api.post("/api/meraki/orgs", json=body).json()["org"]
    job = _wait(api, api.post(f"/api/meraki/orgs/{org['id']}/build").json()["job_id"])
    assert job["status"] == "partial", job
    assert job["result"]["warning_count"] == 1 and job["result"]["summary"]["devices"] == 5
    warnings = api.get(f"/api/meraki/snapshots/{job['result']['snapshot_id']}/warnings").json()
    assert "natrules" in json.dumps(warnings)
    stored = api.get(f"/api/meraki/snapshots/{job['result']['snapshot_id']}/data").text
    assert "pre-shared-secret-value" not in stored


def test_api_fmc_build_needs_a_username(api):
    body = {"name": "NoUser", "provider": "fmc", "base_url": "https://fmc.example.com", "api_key": "pw"}
    org = api.post("/api/meraki/orgs", json=body).json()["org"]
    started = api.post(f"/api/meraki/orgs/{org['id']}/build")
    assert started.status_code == 202
    job = _wait(api, started.json()["job_id"])
    assert job["status"] == "failed" and "username" in job["error"]
    # Validation says the same, without contacting anything.
    checked = api.post(f"/api/meraki/orgs/{org['id']}/validate").json()
    assert checked["ok"] is False and "username" in checked["message"]


# ── Migration 0070 ───────────────────────────────────────────────────────────


def test_migration_0070_renames_anyconnect_rows_to_fmc():
    migration = importlib.import_module("routes.migrations.0070_rename_anyconnect_provider_to_fmc")

    async def _run() -> dict:
        await db_module.init_db()
        db = await db_module.get_db()
        try:
            await db.execute(
                "INSERT INTO meraki_orgs (name, provider, org_id, base_url) VALUES (?, ?, '', '')",
                ("Old FMC", "anyconnect"),
            )
            await db.execute(
                "INSERT INTO meraki_orgs (name, provider, org_id, base_url) VALUES (?, ?, '', '')", ("Org", "meraki")
            )
            for key, source in (("anyconnect:5:9A1DEMO00001", "anyconnect"), ("meraki:3:Q2XX", "meraki")):
                await db.execute(
                    "INSERT INTO software_versions (device_key, source, version) VALUES (?, ?, '7.4.1')", (key, source)
                )
                await db.execute(
                    "INSERT INTO software_version_history (device_key, version) VALUES (?, '7.4.1')", (key,)
                )
                await db.execute(
                    "INSERT INTO software_alerts (device_key, advisory_id) VALUES (?, 'cisco-sa-1')", (key,)
                )
            await db.commit()
            await migration.up(db)
            # Running it again changes nothing.
            await migration.up(db)
            result: dict = {}
            for table, columns in (
                ("meraki_orgs", "name, provider"),
                ("software_versions", "device_key, source"),
                ("software_version_history", "device_key"),
                ("software_alerts", "device_key"),
            ):
                cursor = await db.execute(f"SELECT {columns} FROM {table} ORDER BY 1")
                result[table] = [tuple(row) for row in await cursor.fetchall()]
            return result
        finally:
            await db.close()

    result = asyncio.run(_run())
    assert result["meraki_orgs"] == [("Old FMC", "fmc"), ("Org", "meraki")]
    assert result["software_versions"] == [("fmc:5:9A1DEMO00001", "fmc"), ("meraki:3:Q2XX", "meraki")]
    assert result["software_version_history"] == [("fmc:5:9A1DEMO00001",), ("meraki:3:Q2XX",)]
    assert result["software_alerts"] == [("fmc:5:9A1DEMO00001",), ("meraki:3:Q2XX",)]
    assert migration.VERSION == 70


# ── Forwarding data (path tracing) ───────────────────────────────────────────


def _fwd(snapshot: dict, device_id: str) -> dict:
    return _node(snapshot, f"d:{device_id}")["forwarding"]


def test_snapshot_branch_ftd_carries_its_forwarding_block(snapshot):
    block = _fwd(snapshot, D3)
    assert set(block) == {"version", "interfaces", "routes", "vpn", "policies", "nat", "not_collected"}
    interfaces = {i["name"]: i for i in block["interfaces"]}
    assert interfaces["outside"] == {
        "name": "outside",
        "kind": "wan",
        "ip": "198.51.100.10",
        "cidr": "198.51.100.0/28",
        "zone": "outside",
        "vrf": "",
        "enabled": True,
    }
    assert (interfaces["guest"]["kind"], interfaces["guest"]["vrf"]) == ("routed", "Guest")
    assert interfaces["vti-aws"]["kind"] == "tunnel" and interfaces["lo-router-id"]["kind"] == "loopback"
    routes = {(r["prefix"], r["vrf"]): r for r in block["routes"]}
    assert (
        routes[("10.60.20.0/24", "")]["kind"] == "connected" and routes[("10.60.20.0/24", "")]["interface"] == "voice"
    )
    dc = routes[("10.70.0.0/16", "")]
    assert (dc["kind"], dc["next_hop"], dc["interface"], dc["metric"]) == ("static", "10.60.0.254", "inside", 10)
    default = routes[("0.0.0.0/0", "")]
    # The gateway object resolves to its address.
    assert (default["kind"], default["next_hop"], default["interface"]) == ("default", "198.51.100.1", "outside")
    assert routes[("10.60.31.53/32", "Guest")]["next_hop"] == "10.60.30.254"
    assert routes[("172.16.30.0/26", "")]["source"] == "Static route Partner-Nets / Partner-B-Range"
    # The policy-based hub and spoke topology; the route-based one is a VTI.
    assert block["vpn"] == [
        {
            "name": "DC-to-AWS-Hub",
            "interface": "outside",
            "local": ["10.60.0.0/24", "10.60.20.0/24"],
            "remote": ["10.200.0.0/16", "10.220.0.0/16"],
            "peer": {"org_node": f"d:{D1}"},
            "status": "up",
        }
    ]
    prefilter, access = block["policies"]
    assert (prefilter["kind"], prefilter["applies"], prefilter["default"]) == ("prefilter", "any", "allow")
    fastpath = prefilter["rules"][0]
    assert (fastpath["action"], fastpath["protocol"], fastpath["dst_ports"]) == ("fastpath", "tcp", "873")
    assert (fastpath["src"], fastpath["dst"], fastpath["src_zones"]) == (["10.60.0.0/24"], ["10.70.0.0/16"], ["inside"])
    assert (access["kind"], access["stateful"], access["default"], access["complete"]) == (
        "firewall",
        True,
        "deny",
        True,
    )
    rules = [(r["index"], r["action"], r["protocol"], r["dst_ports"]) for r in access["rules"]]
    # Port objects resolved; the rule mixing TCP and UDP is split, same index.
    assert rules == [
        (1, "allow", "tcp", "443"),
        (2, "allow", "tcp", "80,443"),
        (2, "allow", "udp", "53"),
        (3, "deny", "any", "any"),
    ]
    assert access["rules"][0]["dst"] == ["10.200.0.0/16", "10.220.0.0/16"]
    assert access["rules"][0]["unresolved"] == ["user Employees"]
    assert "application HTTPS" in access["rules"][1]["unresolved"]
    assert (access["rules"][3]["src_zones"], access["rules"][3]["dst_zones"]) == (["guest"], ["inside"])
    first, second = block["nat"]
    assert (first["index"], first["kind"], first["original_dst"], first["dst_interface"]) == (
        1,
        "manual_before",
        ["10.200.0.0/16", "10.220.0.0/16"],
        "outside",
    )
    assert (second["kind"], second["original_src"], second["translated_src"], second["translated_dst"]) == (
        "auto",
        ["10.60.0.0/24"],
        ["interface"],
        [],
    )
    assert block["not_collected"] == [
        "Routes learned by BGP",
        "Routes learned by OSPF",
        "Routes learned by EIGRP",
        "Policy-based routes",
    ]


def test_ha_and_cluster_members_share_the_configuration_owner_block(snapshot):
    assert _fwd(snapshot, D2) == _fwd(snapshot, D1) and _fwd(snapshot, D5) == _fwd(snapshot, D4)
    pair = _fwd(snapshot, D1)
    assert [(i["name"], i["kind"]) for i in pair["interfaces"]] == [("outside", "wan"), ("inside", "routed")]
    assert pair["vpn"][0]["peer"] == {"org_node": f"d:{D3}"} and pair["vpn"][0]["local"] == [
        "10.200.0.0/16",
        "10.220.0.0/16",
    ]
    # The cluster has an access policy but no NAT policy.
    assert _fwd(snapshot, D4)["nat"] == [] and _fwd(snapshot, D4)["policies"][-1]["kind"] == "firewall"


def test_forwarding_notes_what_was_cut_or_not_collected():
    raw = build_sample_raw()
    raw["access_rule_counts"][ACP_ID] = 1400
    raw.pop("prefilter_rules")
    raw["nat_rules"] = {}
    raw["routing"].pop(D4)
    block = _fwd(build_snapshot(raw), D3)
    access = block["policies"][-1]
    assert access["complete"] is False and len(block["policies"]) == 1
    assert {"Prefilter rules", "Access control rules beyond the first 3", "NAT rules"} <= set(block["not_collected"])
    assert block["nat"] == []
    assert _fwd(build_snapshot(raw), D4)["not_collected"][0] == "Static routes and dynamic routing"


def test_forwarding_resolves_static_auto_nat_and_unresolved_networks():
    raw = build_sample_raw()
    raw["nat_rules"][NAT_POLICY_ID].append(
        {
            "id": "nat-0003",
            "type": "FTDAutoNatRule",
            "natType": "STATIC",
            "originalNetwork": {"type": "Host", "id": "host-0004", "name": "guest-dns"},
            "translatedNetwork": {"type": "Host", "id": "host-0001", "name": "gw-branch-isp"},
            "serviceProtocol": "TCP",
            "originalPort": 53,
            "translatedPort": 5353,
            "sourceInterface": {"type": "SecurityZone", "id": ZONE_GUEST, "name": "guest"},
            "destinationInterface": {"type": "SecurityZone", "id": ZONE_OUTSIDE, "name": "outside"},
        }
    )
    raw["access_rules"][ACP_ID][2]["destinationNetworks"] = {
        "objects": [{"type": "FQDN", "id": "fqdn-0001", "name": "updates-cdn"}, {"type": "Country", "name": "Narnia"}]
    }
    block = _fwd(build_snapshot(raw), D3)
    out, back = [n for n in block["nat"] if n["index"] == 3]
    # Outbound: the real source leaves as the mapped one.
    assert (out["original_src"], out["translated_src"], out["translated_dst"]) == (
        ["10.60.31.53/32"],
        ["198.51.100.1/32"],
        [],
    )
    assert (out["src_interface"], out["dst_interface"]) == ("guest", "outside")
    # Inbound to the mapped address and port reaches the real ones.
    assert (back["original_dst"], back["translated_dst"], back["original_port"], back["translated_port"]) == (
        ["198.51.100.1/32"],
        ["10.60.31.53/32"],
        "5353",
        "53",
    )
    assert (back["src_interface"], back["dst_interface"], back["protocol"]) == ("outside", "guest", "tcp")
    blocked = block["policies"][-1]["rules"][-1]
    assert blocked["dst"] == ["any"] and blocked["unresolved"] == ["updates.example.com", "Country Narnia"]


def test_snapshot_fmc_node_lists_port_objects_and_prefilter_rules(snapshot):
    fmc = _node(snapshot, FMC_NODE_ID)
    ports = {r["Name"]: r for r in _table(fmc, "Port objects")}
    assert ports["HTTPS"]["Protocol"] == "TCP" and ports["HTTPS"]["Port / ICMP type"] == "443"
    assert ports["Web-Ports"]["Type"] == "Port group" and ports["Web-Ports"]["Members"] == "HTTP, HTTPS"
    assert ports["Echo-Request"]["Type"] == "ICMP"
    prefilter = _table(fmc, "Prefilter rules")
    assert [(r["Policy"], r["Name"], r["Action"]) for r in prefilter] == [
        ("Corp-Prefilter", "Fastpath-DC-Backup", "FASTPATH")
    ]


@pytest.mark.asyncio
async def test_collect_fmc_reads_port_objects_and_prefilter_rules_best_effort():
    fake = _FakeFmc()
    async with _client(fake) as client:
        raw = await collect_fmc(client, "", None)
    assert [p["name"] for p in raw["objects"]["ports"]] == ["HTTP", "HTTPS", "DNS-UDP", "Rsync"]
    assert [g["name"] for g in raw["objects"]["port_groups"]] == ["Web-Ports"]
    assert [i["name"] for i in raw["objects"]["icmp"]] == ["Echo-Request"]
    assert [r["name"] for r in raw["prefilter_rules"][PREFILTER_ID]] == ["Fastpath-DC-Backup"]
    assert raw["prefilter_rule_counts"] == {PREFILTER_ID: 1}

    # Denied: recorded, the rest of the capture builds.
    fake = _FakeFmc()
    fake.fail = {"prefilterrules": 403, "protocolportobjects": 403}
    async with _client(fake, max_retries=0) as client:
        denied = await collect_fmc(client, "", None)
    assert sorted(e["path"] for e in denied["errors"]) == [
        "/object/protocolportobjects",
        f"/policies/prefilterpolicies/{PREFILTER_ID}/prefilterrules",
    ]
    assert denied["prefilter_rules"] == {} and denied["objects"]["ports"] == []
    block = _fwd(build_snapshot(denied), D3)
    assert "Prefilter rules" in block["not_collected"]
    # A port group whose members were not read leaves the rule unknown.
    assert "HTTP" in block["policies"][-1]["rules"][1]["unresolved"]

    # A release that does not serve prefilter rules: a gap, not an error.
    fake = _FakeFmc()
    fake.missing = {"prefilterrules"}
    async with _client(fake) as client:
        older = await collect_fmc(client, "", None)
    assert older["errors"] == [] and older["unsupported"] == [
        f"/policies/prefilterpolicies/{PREFILTER_ID}/prefilterrules"
    ]

    # The default prefilter policy holds no rules: they are not asked for.
    fake = _FakeFmc()
    fake.raw["prefilter_policies"][0]["name"] = "Default Prefilter Policy"
    async with _client(fake) as client:
        default = await collect_fmc(client, "", None)
    assert default["prefilter_rules"] == {} and not any("prefilterrules" in c for c in fake.calls)
    assert "Prefilter rules" not in _fwd(build_snapshot(default), D3)["not_collected"]
