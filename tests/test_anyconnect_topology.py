"""Tests for the Cisco AnyConnect (FMC) topology integration.

Covers the pipeline with no network access:
  * FmcClient   - token login, domain resolution, re-login on 401, rate-limit
                  retry, paging, URL trust
  * collector   - required device list, best-effort policies / interfaces /
                  sessions, device scoping
  * normalize   - headends, access interfaces, users, pools, the FMC node
  * unified     - an AnyConnect snapshot merges into the Topology graph as-is
                  and an FTDv in AWS collapses into its headend
  * HTTP API    - FMC CRUD, sample build, merged /api/topology, subnets,
                  node details, deep search, collection job
"""

from __future__ import annotations

import json

import httpx
import netcontrol.app as app_module
import pytest
import routes.database as db_module
from netcontrol.integrations.anyconnect.client import CONFIG_PATH, TOKEN_PATH, FmcApiError, FmcClient, validate_base_url
from netcontrol.integrations.anyconnect.collector import collect_fmc, sanitize_options
from netcontrol.integrations.anyconnect.normalize import FMC_NODE_ID, FMC_SITE_ID, build_snapshot, pool_cidr
from netcontrol.integrations.anyconnect.sample import DEVICE_1, DEVICE_2, DEVICE_3, DOMAIN_UUID, build_sample_raw
from netcontrol.integrations.aws.normalize import build_snapshot as build_aws_snapshot
from netcontrol.integrations.aws.sample import build_sample as build_aws_sample
from netcontrol.integrations.meraki.subnets import subnet_index
from netcontrol.integrations.meraki.unified import merge_meraki_into_graph, node_details, virtual_appliance_pairs

DOMAINS_HEADER = json.dumps([{"name": "Global", "uuid": DOMAIN_UUID}, {"name": "Global/Branch", "uuid": "branch-uuid"}])
LOGIN_HEADERS = {
    "X-auth-access-token": "tok-1",
    "X-auth-refresh-token": "ref-1",
    "DOMAIN_UUID": DOMAIN_UUID,
    "DOMAINS": DOMAINS_HEADER,
}

D1, D2, D3 = DEVICE_1, DEVICE_2, DEVICE_3


class _FakeFmc:
    """An FMC serving the sample data, with knobs for failure cases."""

    def __init__(self) -> None:
        self.raw = build_sample_raw()
        self.logins = 0
        self.calls: list[str] = []
        self.fail: dict[str, int] = {}  # path fragment -> HTTP status
        self.expire_token_once = False
        self.page_devices = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append(path)
        if path == TOKEN_PATH:
            assert request.method == "POST"
            assert request.headers["Authorization"].startswith("Basic ")
            self.logins += 1
            return httpx.Response(204, headers={**LOGIN_HEADERS, "X-auth-access-token": f"tok-{self.logins}"})
        if request.headers.get("X-auth-access-token") != f"tok-{self.logins}" or self.expire_token_once:
            self.expire_token_once = False
            return httpx.Response(401, json={"error": {"messages": [{"description": "Access token invalid."}]}})
        for fragment, status in self.fail.items():
            if fragment in path:
                return httpx.Response(status, json={"error": {"messages": [{"description": f"Refused {fragment}"}]}})
        domain = f"{CONFIG_PATH}/domain/{DOMAIN_UUID}"
        if path.endswith("/info/serverversion"):
            return httpx.Response(200, json={"items": [{"serverVersion": "7.4.1 (build 172)"}]})
        if path == f"{domain}/devices/devicerecords":
            items = self.raw["devices"]
            if self.page_devices:
                offset = int(request.url.params.get("offset", 0))
                page = items[offset : offset + 2]
                return httpx.Response(
                    200, json={"items": page, "paging": {"offset": offset, "limit": 2, "count": len(items)}}
                )
            return httpx.Response(200, json={"items": items, "paging": {"count": len(items)}})
        if path == f"{domain}/policies/ravpns":
            return httpx.Response(200, json={"items": self.raw["policies"]})
        if path == f"{domain}/assignment/policyassignments":
            return httpx.Response(200, json={"items": self.raw["assignments"]})
        if path == f"{domain}/object/ipv4addresspools":
            return httpx.Response(200, json={"items": self.raw["pools"]})
        for policy_id, detail in self.raw["policy_details"].items():
            base = f"{domain}/policies/ravpns/{policy_id}"
            if path == f"{base}/connectionprofiles":
                return httpx.Response(200, json={"items": detail["connection_profiles"]})
            if path == f"{base}/addressassignmentsettings":
                return httpx.Response(200, json=detail["address_assignment"][0])  # one object, not a collection
            if path == f"{base}/accessinterfacesettings":
                return httpx.Response(200, json={"items": detail["access_interfaces"]})
        for device_id, interfaces in self.raw["interfaces"].items():
            if path == f"{domain}/devices/devicerecords/{device_id}/physicalinterfaces":
                return httpx.Response(200, json={"items": interfaces})
        if "/subinterfaces" in path or "/physicalinterfaces" in path:
            return httpx.Response(200, json={"items": []})
        if path == f"{domain}/health/ravpnsessions":
            return httpx.Response(200, json={"items": self.raw["sessions"]})
        return httpx.Response(404, json={"error": {"messages": [{"description": f"No such resource {path}"}]}})


def _client(fake: _FakeFmc, **kwargs) -> FmcClient:
    kwargs.setdefault("requests_per_second", 1000)
    return FmcClient(
        "https://fmc.example.com", "api-user", "api-pass", transport=httpx.MockTransport(fake.handler), **kwargs
    )


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
    import netcontrol.integrations.anyconnect.client as client_module

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
    assert [d["name"] for d in items] == ["ftdv-ravpn-1", "ftdv-ravpn-2", "ftd-branch-dc"]


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


@pytest.mark.asyncio
async def test_collect_fmc_reads_everything_and_scopes_interfaces_to_headends():
    fake = _FakeFmc()
    progress: list[dict] = []
    async with _client(fake) as client:
        raw = await collect_fmc(client, "", None, progress.append)
    assert raw["fmc"]["version"].startswith("7.4") and raw["fmc"]["domain"] == "Global"
    assert [d["name"] for d in raw["devices"]] == ["ftdv-ravpn-1", "ftdv-ravpn-2", "ftd-branch-dc"]
    # Only the two headends get interface calls; the branch has no RA VPN policy.
    assert sorted(raw["on_map"]) == sorted([D1, D2]) and set(raw["interfaces"]) == {D1, D2}
    assert len(raw["sessions"]) == 4 and raw["errors"] == []
    detail = raw["policy_details"][raw["policies"][0]["id"]]
    assert [p["name"] for p in detail["connection_profiles"]] == ["Employees", "Contractors"]
    assert detail["address_assignment"][0]["useLocalPools"] is True  # the one-object shape
    assert progress[-1]["phase"] == "collected" and progress[-1]["calls_done"] == progress[-1]["calls_total"]
    assert fake.logins == 1


@pytest.mark.asyncio
async def test_collect_fmc_is_best_effort_past_the_device_list():
    fake = _FakeFmc()
    fake.fail = {"ravpnsessions": 404, "policyassignments": 403, "physicalinterfaces": 500}
    async with _client(fake, max_retries=0) as client:
        raw = await collect_fmc(client, "Global", {"device_name_contains": "ftdv"})
    assert [d["name"] for d in raw["devices"]] == ["ftdv-ravpn-1", "ftdv-ravpn-2"]
    assert raw["sessions"] is None
    paths = sorted(e["path"] for e in raw["errors"])
    assert paths[0] == "/assignment/policyassignments" and paths[-1] == "/health/ravpnsessions"
    assert any("Refused ravpnsessions" in e["message"] and e["status"] == 404 for e in raw["errors"])
    # The reduced capture still builds a map, every filtered device on it.
    snapshot = build_snapshot(raw)
    assert snapshot["summary"]["sites"] == 2 and snapshot["summary"]["remote_users"] == 0


@pytest.mark.asyncio
async def test_collect_fmc_fails_when_devices_unreadable():
    fake = _FakeFmc()
    fake.fail = {"devicerecords": 403}
    async with _client(fake, max_retries=0) as client:
        with pytest.raises(FmcApiError) as excinfo:
            await collect_fmc(client, "")
    assert excinfo.value.status_code == 403
    with pytest.raises(FmcApiError):
        async with _client(fake) as client:
            await collect_fmc(client, "NoSuchDomain")


# ── Normalize ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def snapshot() -> dict:
    return build_snapshot(build_sample_raw())


def _section(entity: dict, title: str) -> dict:
    return next(s for s in entity["sections"] if s["title"] == title)


def test_snapshot_counts_headends_pools_and_users(snapshot):
    summary = snapshot["summary"]
    assert snapshot["provider"] == "anyconnect" and snapshot["schema"] == 1
    assert summary["sites"] == 2 and summary["devices"] == 2
    assert summary["devices_by_status"] == {"online": 1, "alerting": 1}
    assert summary["wan_uplinks"] == 2 and summary["vpn_tunnels"] == 2
    assert summary["remote_users"] == 4 and summary["vlans"] == 4
    # The FMC is a box of its own, sorted ahead of the headends.
    assert snapshot["sites"][0]["id"] == FMC_SITE_ID
    assert all("x" in n and "y" in n for n in snapshot["nodes"])
    ids = {n["id"] for n in snapshot["nodes"]}
    assert all(e["a"] in ids and e["b"] in ids and e["sections"] for e in snapshot["edges"])


def test_snapshot_draws_each_headend_with_its_access_interface_and_users(snapshot):
    links = {(e["a"], e["b"]): e for e in snapshot["edges"]}
    assert links[(f"w:{D1}:outside", f"d:{D1}")]["kind"] == "uplink"
    assert (
        links[(f"u:{D1}", f"d:{D1}")]["status"] == "reachable"
        and links[(f"u:{D1}", f"d:{D1}")]["label"] == "AnyConnect"
    )
    assert links[(FMC_NODE_ID, f"d:{D1}")]["kind"] == "manage" and links[(FMC_NODE_ID, f"d:{D2}")]["kind"] == "manage"
    wan = next(n for n in snapshot["nodes"] if n["id"] == f"w:{D1}:outside")
    assert wan["kind"] == "wan" and wan["ip"] == "10.210.0.11" and wan["label"] == "outside 10.210.0.11"
    assert ["IPsec IKEv2", "Yes"] in _section(wan, "VPN access interface")["rows"]
    ftd = next(n for n in snapshot["nodes"] if n["id"] == f"d:{D1}")
    assert ftd["serial"] == "9A1DEMO00001" and ftd["ip"] == "10.210.2.11" and ftd.get("site_sections") is True
    assert ftd["model"].endswith("for AWS")
    assert [r[1] for r in _section(ftd, "FTD interfaces")["rows"]] == ["outside", "inside"]
    # The branch firewall has no RA VPN policy: listed on the FMC, not drawn.
    assert f"d:{D3}" not in {n["id"] for n in snapshot["nodes"]}
    fmc = next(n for n in snapshot["nodes"] if n["id"] == FMC_NODE_ID)
    assert fmc["kind"] == "cloud" and fmc["ip"] == "10.210.2.20"
    managed = _section(fmc, "Managed devices")["rows"]
    assert [(r[0], r[6]) for r in managed] == [
        ("ftd-branch-dc", "No"),
        ("ftdv-ravpn-1", "Yes"),
        ("ftdv-ravpn-2", "Yes"),
    ]


def test_snapshot_lists_sessions_behind_each_headends_users_node(snapshot):
    users = next(n for n in snapshot["nodes"] if n["id"] == f"u:{D2}")
    assert users["kind"] == "users" and users["label"] == "AnyConnect users (2)"
    rows = _section(users, "Connected users")["rows"]
    assert [r[0] for r in rows] == ["ext.contractor1", "sam.okafor"]
    assert rows[0][1] == "10.220.8.10" and rows[0][3] == "Contractors" and rows[0][6] == "Ubuntu 24.04"


def test_snapshot_pools_are_the_headends_subnets(snapshot):
    site = next(s for s in snapshot["sites"] if s["name"] == "ftdv-ravpn-1")
    assert [s["title"] for s in site["sections"]] == [
        "Remote access VPN",
        "Connection profiles",
        "VPN address pools",
        "Access interfaces",
    ]
    pools = _section(site, "VPN address pools")["rows"]
    assert [r[:2] for r in pools] == [
        ["10.220.0.0/22", "RAVPN-Pool-Employees"],
        ["10.220.8.0/24", "RAVPN-Pool-Contractors"],
    ]
    assert ["Protocols", "IPsec IKEv2, SSL"] in _section(site, "Remote access VPN")["rows"]
    index = [s for s in subnet_index(snapshot) if s["cidr"] == "10.220.0.0/22"]
    assert sorted(s["node_id"] for s in index) == [f"d:{D1}", f"d:{D2}"]
    assert index[0]["kind"] == "pool" and index[0]["name"] == "VPN pool RAVPN-Pool-Employees"
    # Nothing is owned by the FMC or a users node.
    assert not any(s["site_id"] == FMC_SITE_ID for s in subnet_index(snapshot))


def test_pool_cidr_handles_masks_and_bare_ranges():
    assert pool_cidr({"ipAddressRange": "10.220.0.1-10.220.3.254", "mask": "255.255.252.0"}) == "10.220.0.0/22"
    assert pool_cidr({"ipAddressRange": "10.9.9.10-10.9.9.20", "mask": "24"}) == "10.9.9.0/24"
    assert pool_cidr({"ipAddressRange": "10.9.9.10-10.9.9.20"}) == "10.9.9.0/27"
    assert pool_cidr({"ipAddressRange": "10.9.9.10"}) == "10.9.9.10/32"
    assert pool_cidr({"ipAddressRange": "nope"}) == ""


def test_fmc_without_headends_builds_only_the_fmc():
    raw = build_sample_raw()
    raw["assignments"], raw["policies"], raw["on_map"], raw["sessions"] = [], [], [], None
    empty = build_snapshot(raw)
    assert [n["id"] for n in empty["nodes"]] == [FMC_NODE_ID]
    assert empty["summary"]["sites"] == 0 and empty["edges"] == [] and empty["summary"]["remote_users"] == 0
    # With every device wanted, a device without a policy is drawn without a users node.
    raw = build_sample_raw()
    raw["sessions"] = None
    raw["options"] = {**raw["options"], "include_all_devices": True}
    everything = build_snapshot(raw)
    kinds = {n["id"]: n["kind"] for n in everything["nodes"]}
    assert kinds[f"d:{D3}"] == "appliance" and f"u:{D3}" not in kinds
    users = next(n for n in everything["nodes"] if n["id"] == f"u:{D1}")
    assert users["label"] == "AnyConnect users"  # sessions not collected


# ── Merge into the Topology graph ────────────────────────────────────────────


def test_merge_marks_anyconnect_nodes_and_management_links(snapshot):
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(nodes, edges, [(7, snapshot)], host_node=lambda _id: None, resolve_external=lambda *_: None)
    ftd = nodes[f"meraki:7:d:{D1}"]
    assert ftd["device_type"] == "anyconnect" and ftd["device_category"] == "firewall"
    assert ftd["meraki"]["provider"] == "anyconnect" and ftd["meraki"]["site_name"] == "ftdv-ravpn-1"
    assert nodes[f"meraki:7:{FMC_NODE_ID}"]["meraki"]["kind"] == "cloud"
    managed = next(e for e in edges if e["from"] == f"meraki:7:{FMC_NODE_ID}" and e["to"] == f"meraki:7:d:{D1}")
    assert managed["protocol"] == "management" and managed["provider"] == "anyconnect"
    assert len(edges) == len(snapshot["edges"])


def test_merge_collapses_an_ftdv_instance_into_its_headend(snapshot):
    resources, connections = build_aws_sample()
    aws = build_aws_snapshot([{"id": 1, "name": "AWS", "account_identifier": "sample"}], resources, connections, None)
    pairs = virtual_appliance_pairs([(7, snapshot), (-1, aws)])
    assert pairs == {(-1, "i:i-0f7d001"): (7, f"d:{D1}"), (-1, "i:i-0f7d002"): (7, f"d:{D2}")}
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(
        nodes, edges, [(7, snapshot), (-1, aws)], host_node=lambda _id: None, resolve_external=lambda *_: None
    )
    assert "meraki:-1:i:i-0f7d001" not in nodes
    ftd = nodes[f"meraki:7:d:{D1}"]
    # The headend stays in its own site and gains the instance's link to its VPC.
    assert ftd["meraki"]["provider"] == "anyconnect"
    assert any(
        e["from"] == ftd["id"] and e["protocol"] == "cloud" and e["to"].startswith("meraki:-1:vpc:") for e in edges
    )


def test_node_details_report_the_provider_and_pools(snapshot):
    details = node_details(snapshot, f"d:{D1}")
    assert details["provider"] == "anyconnect" and details["site_name"] == "ftdv-ravpn-1"
    assert [s["title"] for s in details["site_addressing"]] == ["VPN address pools"]
    assert node_details(snapshot, FMC_NODE_ID)["site_addressing"] == []


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
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "anyconnect.db"))
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-anyconnect")
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
    for _ in range(200):
        job = api.get(f"/api/meraki/builds/{job_id}").json()
        if job["status"] != "running":
            break
    return job


def test_api_fmc_crud_keeps_the_password_write_only(api):
    listing = api.get("/api/meraki/orgs").json()
    assert listing["anyconnect_default_options"]["include_sessions"] is True

    body = {
        "name": "Prod FMC",
        "provider": "anyconnect",
        "org_id": "Global",
        "base_url": "fmc.example.com",
        "api_key": "super-secret-password",
        "options": {"username": "plexus", "verify_tls": False, "include_all_devices": "yes"},
    }
    created = api.post("/api/meraki/orgs", json=body)
    assert created.status_code == 201, created.text
    org = created.json()["org"]
    assert org["provider"] == "anyconnect" and org["has_api_key"] is True
    assert org["base_url"] == "https://fmc.example.com"
    assert org["options"] == {
        "username": "plexus",
        "device_name_contains": "",
        "include_all_devices": True,
        "include_interfaces": True,
        "include_sessions": True,
        "verify_tls": False,
        "inventory_enrich": True,
    }
    assert "super-secret-password" not in created.text
    assert "super-secret-password" not in api.get("/api/meraki/orgs").text

    # The credentials only ever go to an https host, with no path.
    bad = {"name": "Evil", "provider": "anyconnect", "base_url": "http://fmc.example.com"}
    assert api.post("/api/meraki/orgs", json=bad).status_code == 400
    bad["base_url"] = "https://fmc.example.com/api/fmc_platform"
    assert api.post("/api/meraki/orgs", json=bad).status_code == 400

    updated = api.put(f"/api/meraki/orgs/{org['id']}", json={"options": {"username": "ro", "include_sessions": False}})
    assert updated.status_code == 200
    assert updated.json()["org"]["options"]["include_sessions"] is False
    assert updated.json()["org"]["options"]["username"] == "ro" and updated.json()["org"]["has_api_key"] is True
    assert api.delete(f"/api/meraki/orgs/{org['id']}").status_code == 200


def test_api_anyconnect_sample_is_merged_into_the_topology(api):
    built = api.post("/api/meraki/sample?provider=anyconnect")
    assert built.status_code == 201, built.text
    assert built.json()["summary"]["remote_users"] == 4
    org_ref = built.json()["org_ref"]

    graph = api.get("/api/topology").json()
    ours = [n for n in graph["nodes"] if (n.get("meraki") or {}).get("provider") == "anyconnect"]
    assert {n["meraki"]["kind"] for n in ours} == {"appliance", "wan", "cloud", "users"}
    assert any(n["label"] == "AnyConnect users (2)" for n in ours)
    assert any(e.get("provider") == "anyconnect" and e["protocol"] == "management" for e in graph["edges"])
    assert any(e.get("provider") == "anyconnect" and e["protocol"] == "vpn" for e in graph["edges"])

    details = api.get(f"/api/meraki/nodes?org_ref={org_ref}&node_id=d:{D1}").json()
    assert details["provider"] == "anyconnect" and details["site_name"] == "ftdv-ravpn-1"

    # Address pools can be picked as path endpoints.
    subnets = api.get("/api/meraki/subnets").json()["subnets"]
    pool = next(s for s in subnets if s["cidr"] == "10.220.8.0/24")
    assert pool["provider"] == "anyconnect" and pool["kind"] == "pool" and pool["org_ref"] == org_ref

    # A remote user is found by name, on the headend's users node.
    hits = api.get("/api/topology/search/deep?q=dana.reyes").json()["results"]
    assert [(h["org_ref"], h["node_id"]) for h in hits] == [(org_ref, f"u:{D1}")]

    # The sources list shows the demo FMC and the map exports.
    sources = api.get("/api/topology/sources").json()["sources"]
    fmc = next(s for s in sources if s["type"] == "anyconnect")
    assert fmc["demo"] and not fmc["can_collect"] and fmc["status"] == "success"
    export = api.get("/api/topology/export.html")
    assert export.status_code == 200 and "AnyConnect users (2)" in export.text

    # Loading the AWS sample too joins the FTDv instances to their headends.
    assert api.post("/api/meraki/sample?provider=aws").status_code == 201
    merged = api.get("/api/topology").json()["nodes"]
    assert {(n.get("meraki") or {}).get("provider") for n in merged if n.get("meraki")} == {"anyconnect", "aws"}
    assert not any(n["id"] == "meraki:-1:i:i-0f7d001" for n in merged)


def test_api_ipam_overview_lists_the_pools_and_their_overlap_with_the_vpc(api):
    assert api.post("/api/meraki/sample?provider=anyconnect").status_code == 201
    assert api.post("/api/meraki/sample?provider=aws").status_code == 201

    body = api.get("/api/ipam/overview").json()
    subnets = {s["subnet"]: s for s in body["subnets"]}
    pool = subnets["10.220.8.0/24"]
    assert pool["source_types"] == ["topology"] and pool["topology_providers"] == ["anyconnect"]
    assert pool["topology_sites_preview"] == [
        "ftdv-ravpn-1 (VPN pool RAVPN-Pool-Contractors)",
        "ftdv-ravpn-2 (VPN pool RAVPN-Pool-Contractors)",
    ]
    # The AWS snapshot's subnets are not listed a second time as topology.
    vpc = subnets["10.220.0.0/16"]
    assert vpc["source_types"] == ["cloud"] and vpc["topology_count"] == 0
    # The demo pools are carved out of the apps VPC: an overlap, not a VPN one.
    pairs = [(p["a"]["subnet"], p["b"]["subnet"], p["relation"], p["vpn_conflict"]) for p in body["overlaps"]]
    assert ("10.220.0.0/16", "10.220.0.0/22", "contains", False) in pairs
    assert ("10.220.0.0/16", "10.220.8.0/24", "contains", False) in pairs
    # Both demo headends hand out the same pools: each pool is one more pair.
    assert ("10.220.8.0/24", "10.220.8.0/24", "same", False) in pairs
    assert body["summary"]["topology_subnets"] == 2 and body["summary"]["overlap_count"] == len(pairs)


def test_api_anyconnect_build_job_runs_the_fmc_collector(api, monkeypatch):
    import netcontrol.routes.meraki_topology as routes_module

    async def _fake_collect(client, domain, options, progress):
        assert client.base_url == "https://fmc.example.com:8443" and domain == "Global/Branch"
        assert options["username"] == "plexus" and options["include_sessions"] is True
        progress({"phase": "fmc devices"})
        return build_sample_raw()

    monkeypatch.setattr(routes_module, "collect_fmc", _fake_collect)
    body = {
        "name": "Prod FMC",
        "provider": "anyconnect",
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
    assert job["result"]["summary"]["sites"] == 2 and "clients_tracked" not in job["result"]
    snapshot = api.get(f"/api/meraki/snapshots/{job['result']['snapshot_id']}/data").json()
    assert snapshot["org"]["name"] == "Prod FMC" and snapshot["provider"] == "anyconnect"


def test_api_anyconnect_build_needs_a_username(api):
    body = {"name": "NoUser", "provider": "anyconnect", "base_url": "https://fmc.example.com", "api_key": "pw"}
    org = api.post("/api/meraki/orgs", json=body).json()["org"]
    started = api.post(f"/api/meraki/orgs/{org['id']}/build")
    assert started.status_code == 202
    job = _wait(api, started.json()["job_id"])
    assert job["status"] == "failed" and "username" in job["error"]
    # Validation says the same, without contacting anything.
    checked = api.post(f"/api/meraki/orgs/{org['id']}/validate").json()
    assert checked["ok"] is False and "username" in checked["message"]
