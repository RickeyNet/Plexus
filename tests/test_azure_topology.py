"""Tests for Azure in the Topology map.

Covers the pipeline with no Azure access:
  * collect      - reshaping Network API models, secrets left behind
  * collector    - the live discovery against a stand-in for the SDK client
  * normalize    - VNet sites, gateways, forwarding VMs, VPNs, the report
  * subnets      - VNet subnets are owned by the VNet's router
  * unified      - an Azure VM that is a Meraki vMX
  * reachability - effective routes and network security groups decide a flow
  * HTTP API     - a discovered Azure subscription on /api/topology, node
                   details, subnets, the path check, sources, the sample
"""

from __future__ import annotations

import json
from types import SimpleNamespace as NS

import netcontrol.app as app_module
import netcontrol.routes.cloud_collectors as collectors_module
import pytest
import routes.database as db_module
from netcontrol.integrations.azure import collect
from netcontrol.integrations.azure.normalize import TRANSIT_SITE_ID, build_snapshot
from netcontrol.integrations.azure.reachability import Reachability
from netcontrol.integrations.azure.sample import HUB, PROD, build_sample
from netcontrol.integrations.meraki.normalize import InventoryIndex
from netcontrol.integrations.meraki.subnets import subnet_index
from netcontrol.integrations.meraki.unified import build_search_index, search_index, virtual_appliance_pairs

SUB = "00000000-0000-0000-0000-00000000000a"
ACCOUNT = {"id": 1, "name": "Prod", "last_sync_at": "2026-10-01T12:00:00+00:00", "last_sync_status": "success"}


def _rid(group: str, kind: str, name: str) -> str:
    return f"/subscriptions/{SUB}/resourceGroups/{group}/providers/Microsoft.Network/{kind}/{name}"


# ── Collector helpers ────────────────────────────────────────────────────────


def test_resource_uid_follows_the_azure_resource_id():
    assert collect.resource_uid(_rid("rg-a", "virtualNetworks", "hub")) == f"azure:vnet:{SUB}:rg-a:hub"
    subnet = _rid("rg-a", "virtualNetworks", "hub") + "/subnets/app"
    assert collect.resource_uid(subnet) == f"azure:subnet:{SUB}:rg-a:hub/app"
    assert (
        collect.resource_uid(_rid("rg-a", "localNetworkGateways", "hq")) == f"azure:local_network_gateway:{SUB}:rg-a:hq"
    )
    vm = f"/subscriptions/{SUB}/resourceGroups/rg-a/providers/Microsoft.Compute/virtualMachines/vm1"
    assert collect.resource_uid(vm) == f"azure:vm:{SUB}:rg-a:vm1"
    assert collect.resource_uid("/subscriptions/x") == ""


def test_vnet_and_subnets_keep_what_applies_to_each_subnet():
    vnet = NS(
        id=_rid("rg-a", "virtualNetworks", "hub"),
        name="hub",
        location="eastus",
        provisioning_state="Succeeded",
        address_space=NS(address_prefixes=["10.0.0.0/16", "10.9.0.0/16"]),
        dhcp_options=None,
        subnets=[
            NS(
                id=_rid("rg-a", "virtualNetworks", "hub") + "/subnets/app",
                name="app",
                address_prefix="10.0.1.0/24",
                address_prefixes=None,
                route_table=NS(id=_rid("rg-a", "routeTables", "rt")),
                network_security_group=NS(id=_rid("rg-a", "networkSecurityGroups", "nsg")),
                nat_gateway=None,
                delegations=[],
                service_endpoints=[],
                ip_configurations=[NS(), NS()],
                provisioning_state="Succeeded",
            )
        ],
    )
    resource = collect.vnet_resource(vnet, SUB)
    assert resource["cidr"] == "10.0.0.0/16"
    assert resource["metadata"]["address_prefixes"] == ["10.0.0.0/16", "10.9.0.0/16"]
    [subnet] = collect.subnet_resources(vnet, SUB)
    meta = subnet["metadata"]
    assert subnet["resource_uid"] == f"azure:subnet:{SUB}:rg-a:hub/app" and subnet["cidr"] == "10.0.1.0/24"
    assert meta["vnet_id"] == f"{SUB}:rg-a:hub" and meta["ip_configuration_count"] == 2
    assert meta["route_table"] == f"azure:route_table:{SUB}:rg-a:rt"
    assert meta["network_security_group"] == f"azure:nsg:{SUB}:rg-a:nsg"


def test_gateway_connection_never_carries_the_shared_key():
    conn = NS(
        id=_rid("rg-a", "connections", "hq"),
        name="hq",
        connection_type="IPsec",
        connection_status="Connected",
        provisioning_state="Succeeded",
        shared_key="TOP-SECRET-PSK",
        virtual_network_gateway1=NS(id=_rid("rg-a", "virtualNetworkGateways", "vgw")),
        local_network_gateway2=NS(id=_rid("rg-a", "localNetworkGateways", "hq")),
        virtual_network_gateway2=None,
        peer=None,
        enable_bgp=True,
    )
    record = collect.gateway_connection(conn, SUB)
    assert "TOP-SECRET-PSK" not in json.dumps(record)
    assert record["connection_type"] == "ipsec" and record["metadata"]["connection_status"] == "Connected"
    assert record["target_resource_uid"] == f"azure:local_network_gateway:{SUB}:rg-a:hq"


def test_nsg_rules_name_direction_ports_and_defaults():
    explicit = NS(
        id="r1",
        name="AllowHttps",
        direction="Inbound",
        access="Allow",
        protocol="Tcp",
        source_address_prefix="10.0.0.0/8",
        source_address_prefixes=[],
        destination_address_prefix="*",
        destination_address_prefixes=[],
        destination_port_range=None,
        destination_port_ranges=["443", "8443"],
        priority=100,
        description="",
    )
    default = NS(
        id="r2",
        name="DenyAllInBound",
        direction="Inbound",
        access="Deny",
        protocol="*",
        source_address_prefix="*",
        destination_address_prefix="*",
        destination_port_range="*",
        priority=65500,
    )
    rules = collect.nsg_rules(NS(security_rules=[explicit], default_security_rules=[default]))
    assert [(r["rule_name"], r["direction"], r["action"], r["protocol"], r["port_expression"]) for r in rules] == [
        ("AllowHttps", "inbound", "allow", "tcp", "443, 8443"),
        ("DenyAllInBound", "inbound", "deny", "all", "*"),
    ]
    assert [r["metadata"]["is_default"] for r in rules] == [False, True]


def test_vms_are_read_from_their_network_interfaces():
    vm_id = f"/subscriptions/{SUB}/resourceGroups/rg-a/providers/Microsoft.Compute/virtualMachines/vmx1"
    pip = _rid("rg-a", "publicIPAddresses", "vmx1-pip")
    nics = [
        NS(
            id=_rid("rg-a", "networkInterfaces", "vmx1-lan"),
            name="vmx1-lan",
            location="eastus",
            primary=False,
            enable_ip_forwarding=True,
            virtual_machine=NS(id=vm_id),
            ip_configurations=[
                NS(
                    private_ip_address="10.0.2.10",
                    subnet=NS(id=_rid("rg-a", "virtualNetworks", "hub") + "/subnets/lan"),
                    public_ip_address=None,
                    primary=True,
                )
            ],
        ),
        NS(
            id=_rid("rg-a", "networkInterfaces", "vmx1-wan"),
            name="vmx1-wan",
            location="eastus",
            primary=True,
            enable_ip_forwarding=False,
            virtual_machine=NS(id=vm_id),
            ip_configurations=[
                NS(
                    private_ip_address="10.0.1.10",
                    subnet=NS(id=_rid("rg-a", "virtualNetworks", "hub") + "/subnets/wan"),
                    public_ip_address=NS(id=pip),
                    primary=True,
                )
            ],
        ),
        # A private endpoint's NIC belongs to no virtual machine.
        NS(id=_rid("rg-a", "networkInterfaces", "pe"), name="pe", virtual_machine=None, ip_configurations=[]),
    ]
    [vm] = collect.vm_resources(nics, SUB, {pip.lower(): "52.1.2.3"})
    meta = vm["metadata"]
    assert vm["resource_uid"] == f"azure:vm:{SUB}:rg-a:vmx1"
    # The primary interface gives the VM its address and subnet.
    assert meta["private_ip"] == "10.0.1.10" and meta["subnet_id"] == f"{SUB}:rg-a:hub/wan"
    assert meta["public_ip"] == "52.1.2.3" and meta["ip_forwarding"] is True
    assert [i["name"] for i in meta["interfaces"]] == ["vmx1-wan", "vmx1-lan"]


def test_error_code_never_quotes_the_message():
    exc = Exception("The client 'x@corp' does not have authorization")
    exc.error = NS(code="AuthorizationFailed")
    warning = collect.warning_resource("network_interfaces", exc)
    assert warning["metadata"] == {"section": "network_interfaces", "error": "AuthorizationFailed"}
    assert "corp" not in json.dumps(warning)


# ── The live collector, against a stand-in for the SDK ───────────────────────


class _Denied(Exception):
    error = NS(code="AuthorizationFailed")


class _Ops:
    def __init__(self, items=None, *, deny: bool = False, by_vnet=None):
        self._items, self._deny, self._by_vnet = items or [], deny, by_vnet or {}

    def list_all(self):
        if self._deny:
            raise _Denied()
        return list(self._items)

    def list(self, _group, name):
        return list(self._by_vnet.get(name, []))


def _client():
    hub_id = _rid("rg-a", "virtualNetworks", "hub")
    vnet = NS(
        id=hub_id,
        name="hub",
        location="eastus",
        provisioning_state="Succeeded",
        address_space=NS(address_prefixes=["10.0.0.0/16"]),
        subnets=[NS(id=hub_id + "/subnets/GatewaySubnet", name="GatewaySubnet", address_prefix="10.0.0.0/27")],
    )
    peering = NS(
        name="hub-to-spoke",
        peering_state="Connected",
        remote_virtual_network=NS(id=_rid("rg-b", "virtualNetworks", "spoke")),
    )
    pip = _rid("rg-a", "publicIPAddresses", "vgw-pip")
    gateway = NS(
        id=_rid("rg-a", "virtualNetworkGateways", "vgw"),
        name="vgw",
        location="eastus",
        provisioning_state="Succeeded",
        gateway_type="Vpn",
        ip_configurations=[NS(subnet=NS(id=hub_id + "/subnets/GatewaySubnet"), public_ip_address=NS(id=pip))],
    )
    return NS(
        public_ip_addresses=_Ops([NS(id=pip, ip_address="52.9.9.9")]),
        virtual_networks=_Ops([vnet]),
        virtual_network_peerings=_Ops(by_vnet={"hub": [peering]}),
        express_route_circuits=_Ops(),
        virtual_network_gateways=_Ops([gateway]),
        local_network_gateways=_Ops(),
        route_tables=_Ops(),
        network_security_groups=_Ops(),
        virtual_network_gateway_connections=_Ops(),
        nat_gateways=_Ops(),
        network_interfaces=_Ops(deny=True),
        azure_firewalls=_Ops(),
    )


def test_live_collector_reads_the_network_and_skips_a_denied_section():
    resources, connections = collectors_module._collect_azure_network(_client(), SUB)
    by_type = {}
    for r in resources:
        by_type.setdefault(r["resource_type"], []).append(r)
    assert [r["name"] for r in by_type["vnet"]] == ["hub"]
    assert [r["name"] for r in by_type["subnet"]] == ["GatewaySubnet"]
    [gateway] = by_type["virtual_network_gateway"]
    assert gateway["metadata"]["public_ips"] == ["52.9.9.9"] and gateway["metadata"]["vnet_id"] == f"{SUB}:rg-a:hub"
    [warning] = by_type["collection_warning"]
    assert warning["metadata"] == {"section": "network_interfaces", "error": "AuthorizationFailed"}
    kinds = {(c["connection_type"], c["target_resource_uid"]) for c in connections}
    assert ("vnet_peering", f"azure:vnet:{SUB}:rg-b:spoke") in kinds
    assert ("virtual_network_gateway_attachment", f"azure:virtual_network_gateway:{SUB}:rg-a:vgw") in kinds


def test_live_collector_fails_when_a_base_section_cannot_be_read():
    client = _client()
    client.route_tables = _Ops(deny=True)
    with pytest.raises(collectors_module.CloudCollectorExecutionError, match="route_tables"):
        collectors_module._collect_azure_network(client, SUB)


# ── Snapshot ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def snapshot() -> dict:
    resources, connections = build_sample()
    return build_snapshot([ACCOUNT], resources, connections)


def _node(snapshot: dict, node_id: str) -> dict:
    return next(n for n in snapshot["nodes"] if n["id"] == node_id)


def test_snapshot_has_a_site_per_vnet_and_a_transit_box(snapshot):
    sites = {s["id"]: s for s in snapshot["sites"]}
    assert snapshot["provider"] == "azure" and snapshot["summary"]["sites"] == 3
    assert sites[HUB]["name"] == "hub-vnet (eastus)" and TRANSIT_SITE_ID in sites
    hub = _node(snapshot, f"vnet:{HUB}")
    assert hub["kind"] == "vpc" and hub["site_sections"]


def test_snapshot_shows_only_vms_that_forward_traffic(snapshot):
    ids = {n["id"] for n in snapshot["nodes"]}
    assert "vm:sample:rg-hub:vmx-hub-1" in ids and "vm:sample:rg-prod:app-vm-1" not in ids
    vmx = _node(snapshot, "vm:sample:rg-hub:vmx-hub-1")
    assert vmx["kind"] == "appliance" and "203.0.113.61" in vmx["alias_ips"]
    # Every VM is still listed in its VNet.
    prod = next(s for s in snapshot["sites"] if s["id"] == PROD)
    listed = next(sec for sec in prod["sections"] if sec["title"] == "Virtual machines")
    assert {row[0] for row in listed["rows"]} == {"app-vm-1", "db-vm-1"}


def test_snapshot_vm_in_inventory_becomes_a_node():
    resources, connections = build_sample()
    inventory = InventoryIndex([{"id": 7, "hostname": "db-vm-1", "ip_address": "10.231.20.31"}])
    snap = build_snapshot([ACCOUNT], resources, connections, inventory)
    node = _node(snap, "vm:sample:rg-prod:db-vm-1")
    assert node["kind"] == "server" and node["inventory"]["host_id"] == 7


def test_snapshot_links_vnets_gateways_and_vpns(snapshot):
    edges = {(e["a"], e["b"]): e for e in snapshot["edges"]}
    vgw, hq, dr = "vng:sample:rg-hub:vgw-hub", "lng:sample:rg-hub:lng-hq", "lng:sample:rg-hub:lng-dr"
    assert edges[(vgw, hq)]["kind"] == "vpn" and edges[(vgw, hq)]["status"] == "reachable"
    assert edges[(vgw, dr)]["status"] == "unreachable"
    assert (f"vnet:{HUB}", f"vnet:{PROD}") in edges
    # The VPN gateway's public address is a tunnel endpoint for the merge.
    assert _node(snapshot, vgw)["endpoint_ips"] == ["203.0.113.201"]
    # A peering to a VNet of another subscription keeps its far end.
    stub = next(n for n in snapshot["nodes"] if n["id"].startswith("x:vnet:"))
    assert stub["kind"] == "vpc" and stub["model"] == "Not collected"
    site = next(s for s in snapshot["sites"] if s["id"] == stub["site"])
    assert site["name"].endswith("(not collected)") and site["not_collected"]


def test_snapshot_subnets_name_their_default_route(snapshot):
    prod = next(s for s in snapshot["sites"] if s["id"] == PROD)
    rows = {row[1]: row for row in next(sec for sec in prod["sections"] if sec["title"] == "Subnets")["rows"]}
    assert rows["app"][3] == "Virtual appliance 10.230.1.4" and rows["app"][4] == "nsg-app"
    rules = next(sec for sec in prod["sections"] if sec["title"] == "Network security group rules")
    assert any(row[0] == "nsg-db" and "AllowPostgresFromApp" not in row for row in rules["rows"])


def test_subnet_index_places_subnets_on_the_vnet_router(snapshot):
    owners = {row["cidr"]: row["node_id"] for row in subnet_index(snapshot)}
    assert owners["10.231.20.0/24"] == f"vnet:{PROD}"
    assert owners["10.230.3.0/24"] == f"vnet:{HUB}"


def test_search_finds_a_vm_that_is_not_a_node(snapshot):
    hits = search_index(build_search_index(snapshot), ["db-vm-1"], 10)
    assert [h["node_id"] for h in hits] == [f"vnet:{PROD}"]


def test_snapshot_reports_what_discovery_could_not_read():
    resources, connections = build_sample()
    resources.append(collect.warning_resource("azure_firewalls", _Denied()))
    snap = build_snapshot(
        [{**ACCOUNT, "last_sync_status": "error", "last_sync_message": "boom"}], resources, connections
    )
    messages = [e["message"] for e in snap["collection"]["errors"]]
    assert any("boom" in m for m in messages) and any("AuthorizationFailed" in m for m in messages)


def test_snapshot_of_nothing_is_empty():
    snap = build_snapshot([], [], [])
    assert snap["sites"] == [] and snap["nodes"] == [] and snap["edges"] == []


# ── Merged with another integration ──────────────────────────────────────────


def test_a_vm_on_a_meraki_appliances_public_address_is_that_appliance():
    resources, connections = build_sample()
    vmx = next(r for r in resources if r["name"] == "vmx-hub-1")
    # Documentation addresses are not public; give the appliance a real one.
    vmx["metadata"]["public_ip"] = "8.8.4.4"
    vmx["metadata"]["interfaces"][0]["public_ips"] = ["8.8.4.4"]
    snapshot = build_snapshot([ACCOUNT], resources, connections)
    meraki = {
        "provider": "meraki",
        "nodes": [{"id": "Q2-VMX", "kind": "appliance", "ip": "8.8.4.4", "site": "N1"}],
        "edges": [],
    }
    pairs = virtual_appliance_pairs([(1, meraki), (-2, snapshot)])
    assert pairs[(-2, "vm:sample:rg-hub:vmx-hub-1")] == (1, "Q2-VMX")


# ── Reachability ─────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def reach() -> Reachability:
    return Reachability(*build_sample())


def _check(reach, source, destination, protocol="tcp", port=None):
    return reach.check(source, destination, protocol=protocol, port=port)


def test_reachability_allows_what_routes_and_groups_allow(reach):
    result = _check(reach, "10.231.10.21", "10.231.20.31", port=5432)
    assert result["verdict"] == "allowed" and result["traffic"] == "tcp/5432"
    assert result["source"]["label"] == "virtual machine app-vm-1 (10.231.10.21)"
    stages = {(s["stage"], s["status"]) for s in result["steps"]}
    assert ("route", "ok") in stages and ("security_group", "ok") in stages


def test_reachability_blocks_a_port_the_group_does_not_open(reach):
    result = _check(reach, "10.231.10.21", "10.231.20.31", port=22)
    assert result["verdict"] == "blocked" and "nsg-db" in result["summary"]


def test_reachability_reaches_on_premises_through_the_hubs_gateway(reach):
    # The spoke uses the hub's VPN gateway over its peering.
    out = _check(reach, "10.231.10.21", "10.10.5.5", port=443)
    assert out["verdict"] == "allowed"
    assert any("hq-s2s" in s["text"] for s in out["steps"])
    inbound = _check(reach, "10.10.5.5", "10.231.10.21", port=443)
    assert inbound["verdict"] == "allowed"


def test_reachability_reports_a_vpn_that_is_down(reach):
    result = _check(reach, "10.230.2.5", "10.20.1.1", port=22)
    assert result["verdict"] == "blocked" and "dr-s2s" in result["summary"] and "not connected" in result["summary"]


def test_reachability_stops_at_the_azure_firewall(reach):
    result = _check(reach, "10.231.10.21", "198.51.100.99", port=443)
    assert result["verdict"] == "unknown" and "firewall policy" in result["summary"]


def test_reachability_follows_peerings_only_between_their_vnets(reach):
    assert _check(reach, "10.231.10.21", "10.232.1.11", port=443)["verdict"] == "allowed"
    # The hub is not peered with the west VNet.
    result = _check(reach, "10.230.2.5", "10.232.1.11", port=443)
    assert result["verdict"] in ("blocked", "unknown")


def test_reachability_honours_a_route_that_drops_traffic(reach):
    result = _check(reach, "10.231.10.21", "10.99.1.1", protocol="")
    assert result["verdict"] == "blocked" and "drop-legacy" in result["summary"]


def test_reachability_of_nothing_azure_knows_does_not_apply(reach):
    assert reach.check("192.0.2.1", "192.0.2.2")["applies"] is False
    with pytest.raises(ValueError):
        reach.check("nope", "10.231.10.21")


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


@pytest.fixture
def api(tmp_path, monkeypatch, request):
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "azure.db"))
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-azure")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    import netcontrol.routes.meraki_topology as routes_module
    from netcontrol.routes.topology import invalidate_topology_cache

    def reset() -> None:
        # The graph and snapshot caches outlive this test's database.
        routes_module._SNAPSHOT_CACHE.clear()
        invalidate_topology_cache()

    reset()

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(reset)
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return _CsrfClient(client, resp.json().get("csrf_token", ""))


def _azure_nodes(api) -> list[dict]:
    graph = api.get("/api/topology").json()
    return [n for n in graph["nodes"] if (n.get("meraki") or {}).get("provider") == "azure"]


def test_api_discovered_azure_subscription_is_on_the_topology(api):
    assert _azure_nodes(api) == []
    account = api.post("/api/cloud/accounts", json={"provider": "azure", "name": "Prod Azure"}).json()["account"]
    assert _azure_nodes(api) == []

    body = {"mode": "sample", "include_hybrid_links": False}
    assert api.post(f"/api/cloud/accounts/{account['id']}/discover", json=body).status_code == 200

    azure = _azure_nodes(api)
    assert {n["meraki"]["kind"] for n in azure} == {"vpc", "appliance", "cloud", "vpn_peer"}
    org_ref = azure[0]["meraki"]["org_ref"]
    assert org_ref == -2

    details = api.get(f"/api/meraki/nodes?org_ref={org_ref}&node_id=vnet:{PROD}").json()
    assert details["provider"] == "azure" and details["site_name"] == "prod-vnet (eastus)"

    subnets = api.get("/api/meraki/subnets").json()["subnets"]
    db_subnet = next(s for s in subnets if s["cidr"] == "10.231.20.0/24")
    assert db_subnet["provider"] == "azure" and db_subnet["site_id"] == PROD

    check = "/api/meraki/azure/reachability?source=10.231.10.21&destination=10.231.20.31&protocol=tcp"
    allowed = api.get(f"{check}&port=5432&source_vnet={PROD}").json()
    assert allowed["applies"] and allowed["verdict"] == "allowed"
    assert api.get(f"{check}&port=22").json()["verdict"] == "blocked"
    assert api.get("/api/meraki/azure/reachability?source=nope&destination=10.231.20.31").status_code == 400
    # The AWS check does not see Azure.
    assert (
        api.get("/api/meraki/aws/reachability?source=10.231.10.21&destination=10.231.20.31").json()["applies"] is False
    )

    export = api.get("/api/topology/export.html")
    assert export.status_code == 200 and "prod-vnet" in export.text

    assert api.put(f"/api/cloud/accounts/{account['id']}", json={"enabled": False}).status_code == 200
    assert _azure_nodes(api) == []


def test_api_azure_sample_and_sources(api):
    built = api.post("/api/meraki/sample?provider=azure")
    assert built.status_code == 201, built.text
    assert built.json()["org_ref"] == -2 and built.json()["summary"]["sites"] == 3
    assert api.post("/api/meraki/sample?provider=azure").status_code == 201
    assert api.post("/api/meraki/sample?provider=aws").status_code == 201
    accounts = api.get("/api/cloud/accounts").json()["accounts"]
    assert sorted((a["provider"], a["auth_type"]) for a in accounts) == [("aws", "sample"), ("azure", "sample")]
    providers = {(n.get("meraki") or {}).get("provider") for n in api.get("/api/topology").json()["nodes"]}
    assert {"aws", "azure"} <= providers

    body = {"provider": "azure", "name": "Prod Azure", "auth_config": {"client_secret": "hunter2"}}
    account = api.post("/api/cloud/accounts", json=body).json()["account"]
    sources = {s["key"]: s for s in api.get("/api/topology/sources").json()["sources"]}
    demo = next(s for s in sources.values() if s["type"] == "azure" and s["demo"])
    assert demo["status"] == "success" and not demo["can_collect"]
    prod = sources[f"azure:{account['id']}"]
    assert (prod["status"], prod["can_collect"], prod["enabled"]) == ("never", True, True)
    assert "hunter2" not in api.get("/api/topology/sources").text
