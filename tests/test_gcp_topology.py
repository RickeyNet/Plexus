"""Tests for GCP in the Topology map.

Covers the pipeline with no GCP access:
  * collect      - reshaping Compute Engine API items, secrets left behind
  * collector    - the live discovery against a stand-in for the API client
  * normalize    - network sites, gateways, forwarding instances, VPNs, the report
  * subnets      - subnets are owned by the network's router
  * unified      - a GCP instance that is a Meraki vMX
  * reachability - routes and VPC firewall rules decide a flow
  * HTTP API     - a discovered GCP project on /api/topology, node details,
                   subnets, the check, the path trace, sources, the sample
"""

from __future__ import annotations

import json
from types import SimpleNamespace as NS

import netcontrol.app as app_module
import netcontrol.routes.cloud_collectors as collectors_module
import pytest
from netcontrol.integrations.gcp import collect
from netcontrol.integrations.gcp.normalize import TRANSIT_SITE_ID, build_snapshot
from netcontrol.integrations.gcp.reachability import Reachability
from netcontrol.integrations.gcp.sample import HUB, PROD, SHARED, build_sample
from netcontrol.integrations.meraki.normalize import InventoryIndex
from netcontrol.integrations.meraki.subnets import subnet_index
from netcontrol.integrations.meraki.unified import build_search_index, search_index, virtual_appliance_pairs

PROJECT = "acme-net"
ACCOUNT = {"id": 1, "name": "Prod", "last_sync_at": "2026-10-01T12:00:00+00:00", "last_sync_status": "success"}
BASE = "https://www.googleapis.com/compute/v1/projects"


def _link(path: str, project: str = PROJECT) -> str:
    return f"{BASE}/{project}/{path}"


# ── Collector helpers ────────────────────────────────────────────────────────


def test_parse_link_reads_any_self_link():
    assert collect.parse_link(_link("regions/us-central1/subnetworks/app")) == {
        "project": PROJECT,
        "region": "us-central1",
        "zone": "",
        "collection": "subnetworks",
        "name": "app",
    }
    assert collect.link_uid(_link("global/networks/hub")) == f"gcp:vpc:{PROJECT}:hub"
    assert collect.link_uid(_link("zones/us-central1-a/instances/vm1")) == f"gcp:instance:{PROJECT}:us-central1-a:vm1"
    # A partial link takes the project it is read for.
    assert collect.link_uid("global/networks/hub", "other") == "gcp:vpc:other:hub"
    assert collect.link_uid(_link("global/gateways/default-internet-gateway")) == ""


def test_a_peering_with_another_project_names_that_project():
    network = {
        "name": "hub",
        "selfLink": _link("global/networks/hub"),
        "routingConfig": {"routingMode": "GLOBAL"},
        "peerings": [{"name": "to-shared", "network": _link("global/networks/shared", "host-prj"), "state": "ACTIVE"}],
    }
    resource = collect.network_resource(network, PROJECT)
    assert resource["resource_uid"] == f"gcp:vpc:{PROJECT}:hub"
    assert resource["metadata"]["routing_mode"] == "GLOBAL" and resource["metadata"]["subnet_mode"] == "custom"
    [peering] = collect.peering_connections(network, PROJECT)
    assert peering["target_resource_uid"] == "gcp:vpc:host-prj:shared" and peering["state"] == "ACTIVE"


def test_subnet_and_route_keep_what_evaluation_needs():
    subnet = collect.subnet_resource(
        {
            "name": "app",
            "selfLink": _link("regions/us-central1/subnetworks/app"),
            "region": _link("regions/us-central1"),
            "network": _link("global/networks/shared", "host-prj"),
            "ipCidrRange": "10.0.1.0/24",
            "secondaryIpRanges": [{"rangeName": "pods", "ipCidrRange": "10.4.0.0/14"}],
            "privateIpGoogleAccess": True,
        },
        PROJECT,
    )
    meta = subnet["metadata"]
    assert subnet["resource_uid"] == f"gcp:subnet:{PROJECT}:us-central1:app" and subnet["cidr"] == "10.0.1.0/24"
    # A Shared VPC subnet names the host project's network.
    assert meta["network_id"] == "host-prj:shared" and meta["secondary_ranges"] == [
        {"name": "pods", "cidr": "10.4.0.0/14"}
    ]
    route = collect.route_resource(
        {
            "name": "to-lab",
            "network": _link("global/networks/hub"),
            "destRange": "10.70.0.0/16",
            "priority": 900,
            "tags": ["lab"],
            "nextHopInstance": _link("zones/us-central1-a/instances/fw-1"),
        },
        PROJECT,
    )
    assert route["resource_uid"] == f"gcp:route:{PROJECT}:to-lab" and route["resource_type"] == "route_entry"
    assert {k: route["metadata"][k] for k in ("next_hop_type", "next_hop_id", "tags", "priority")} == {
        "next_hop_type": "instance",
        "next_hop_id": f"{PROJECT}:us-central1-a:fw-1",
        "tags": ["lab"],
        "priority": 900,
    }


def test_each_network_gets_its_own_internet_gateway():
    resources, connections = collect.assemble(
        PROJECT,
        routes=[
            {
                "name": f"default-{n}",
                "network": _link(f"global/networks/{n}"),
                "destRange": "0.0.0.0/0",
                "priority": 1000,
                "nextHopGateway": _link("global/gateways/default-internet-gateway"),
            }
            for n in ("hub", "prod")
        ],
    )
    gateways = sorted(r["resource_uid"] for r in resources if r["resource_type"] == "internet_gateway")
    assert gateways == [f"gcp:internet_gateway:{PROJECT}:hub", f"gcp:internet_gateway:{PROJECT}:prod"]
    assert ("route_next_hop", f"gcp:internet_gateway:{PROJECT}:hub") in {
        (c["connection_type"], c["target_resource_uid"]) for c in connections
    }


def test_instance_keeps_every_interface():
    instance = collect.instance_resource(
        {
            "name": "vmx-1",
            "zone": _link("zones/us-central1-a"),
            "status": "RUNNING",
            "machineType": _link("zones/us-central1-a/machineTypes/n2-standard-4"),
            "canIpForward": True,
            "tags": {"items": ["vmx"]},
            "serviceAccounts": [{"email": "vmx@acme-net.iam.gserviceaccount.com"}],
            "networkInterfaces": [
                {
                    "name": "nic0",
                    "network": _link("global/networks/wan"),
                    "subnetwork": _link("regions/us-central1/subnetworks/wan"),
                    "networkIP": "10.0.1.10",
                    "accessConfigs": [{"natIP": "34.1.2.3"}],
                },
                {
                    "name": "nic1",
                    "network": _link("global/networks/lan"),
                    "subnetwork": _link("regions/us-central1/subnetworks/lan"),
                    "networkIP": "10.0.2.10",
                    "aliasIpRanges": [{"ipCidrRange": "10.0.2.64/28"}],
                },
            ],
        },
        PROJECT,
    )
    meta = instance["metadata"]
    assert instance["resource_uid"] == f"gcp:instance:{PROJECT}:us-central1-a:vmx-1"
    assert (meta["vpc_id"], meta["subnet_id"], meta["private_ip"], meta["public_ip"]) == (
        f"{PROJECT}:wan",
        f"{PROJECT}:us-central1:wan",
        "10.0.1.10",
        "34.1.2.3",
    )
    assert meta["can_ip_forward"] is True and meta["machine_type"] == "n2-standard-4"
    assert [i["network_id"] for i in meta["interfaces"]] == [f"{PROJECT}:wan", f"{PROJECT}:lan"]
    assert meta["interfaces"][1]["alias_ranges"] == ["10.0.2.64/28"]


def test_vpn_tunnel_never_carries_the_shared_secret():
    tunnel = {
        "name": "t0",
        "selfLink": _link("regions/us-central1/vpnTunnels/t0"),
        "region": _link("regions/us-central1"),
        "status": "ESTABLISHED",
        "peerIp": "198.51.100.20",
        "sharedSecret": "TOP-SECRET-PSK",
        "sharedSecretHash": "TOP-SECRET-HASH",
        "vpnGateway": _link("regions/us-central1/vpnGateways/ha"),
        "peerExternalGateway": _link("global/externalVpnGateways/hq"),
        "peerExternalGatewayInterface": 0,
        "router": _link("regions/us-central1/routers/cr"),
    }
    resources, connections = collect.assemble(PROJECT, vpn_tunnels=[tunnel])
    dumped = json.dumps([resources, connections])
    assert "TOP-SECRET" not in dumped
    link = next(c for c in connections if c["connection_type"] == "vpn_tunnel")
    assert link["target_resource_uid"] == f"gcp:external_vpn_gateway:{PROJECT}:hq"
    assert link["metadata"]["gateway"] == f"gcp:ha_vpn_gateway:{PROJECT}:us-central1:ha"


def test_firewall_rules_keep_the_policy_rule_shape():
    resource = collect.firewall_resource(
        {
            "name": "allow-web",
            "network": _link("global/networks/hub"),
            "direction": "INGRESS",
            "priority": 1000,
            "allowed": [{"IPProtocol": "tcp", "ports": ["80", "443"]}, {"IPProtocol": "icmp"}],
            "sourceRanges": ["0.0.0.0/0"],
            "targetTags": ["web"],
        },
        PROJECT,
    )
    uid = f"gcp:firewall_policy:{PROJECT}:allow-web"
    assert resource["resource_uid"] == uid
    rules = resource["metadata"]["policy_rules"]
    assert [(r["rule_uid"], r["direction"], r["action"], r["protocol"], r["port_expression"]) for r in rules] == [
        (f"{uid}:allow:1", "inbound", "allow", "tcp", "80, 443"),
        (f"{uid}:allow:2", "inbound", "allow", "icmp", "all"),
    ]
    assert rules[0]["source_selector"] == "0.0.0.0/0" and rules[0]["destination_selector"] == "self"
    assert rules[0]["metadata"] == {"disabled": False, "target_tags": ["web"]}
    assert resource["metadata"]["target_tags"] == ["web"] and resource["metadata"]["network_id"] == f"{PROJECT}:hub"


class _Denied(Exception):
    resp = NS(status=403)
    error_details = [{"reason": "forbidden", "message": "Required 'compute.instances.list' for 'projects/secret-prj'"}]


def test_error_code_never_quotes_the_message():
    exc = _Denied("Required 'compute.instances.list' permission for 'projects/secret-prj'")
    warning = collect.warning_resource("instances", exc)
    assert warning["metadata"] == {"section": "instances", "error": "forbidden (HTTP 403)"}
    assert "secret" not in json.dumps(warning)
    assert collect.error_code(ValueError("boom")) == "ValueError"


# ── The live collector, against a stand-in for the API client ────────────────


class _Request:
    def __init__(self, page: dict, deny: bool) -> None:
        self._page, self._deny = page, deny

    def execute(self) -> dict:
        if self._deny:
            raise _Denied("Required permission for 'projects/secret-prj'")
        return self._page


class _Collection:
    """One Compute Engine collection: ``list`` / ``aggregatedList`` and their ``*_next``."""

    def __init__(self, items=None, *, aggregated=None, deny: bool = False, status=None) -> None:
        self._items, self._aggregated, self._deny, self._status = items or [], aggregated or {}, deny, status

    def list(self, project):
        return _Request({"items": list(self._items)}, self._deny)

    def aggregatedList(self, project):
        return _Request({"items": dict(self._aggregated)}, self._deny)

    def list_next(self, previous_request, previous_response):
        return None

    aggregatedList_next = list_next

    def getRouterStatus(self, project, region, router):
        return _Request({"result": self._status or {}}, False)

    def getHealth(self, project, backendService, body, region=None):
        # ``status`` maps a backend group link to its healthStatus entries.
        self.health_asked = [*getattr(self, "health_asked", []), (region, backendService, body["group"])]
        return _Request({"healthStatus": (self._status or {}).get(body["group"], [])}, self._deny)


def _compute(**override):
    hub = _link("global/networks/hub")
    collections = {
        "networks": _Collection(
            [
                {
                    "name": "hub",
                    "selfLink": hub,
                    "peerings": [{"name": "to-spoke", "network": _link("global/networks/spoke"), "state": "ACTIVE"}],
                }
            ]
        ),
        "subnetworks": _Collection(
            aggregated={
                "regions/us-central1": {
                    "subnetworks": [
                        {
                            "name": "mgmt",
                            "selfLink": _link("regions/us-central1/subnetworks/mgmt"),
                            "region": _link("regions/us-central1"),
                            "network": hub,
                            "ipCidrRange": "10.0.0.0/24",
                        }
                    ]
                },
                # A region with nothing in it answers with a warning, not items.
                "regions/asia-east1": {"warning": {"code": "NO_RESULTS_ON_PAGE", "message": "none"}},
            }
        ),
        "routes": _Collection([]),
        "firewalls": _Collection([]),
        "routers": _Collection(
            aggregated={
                "regions/us-central1": {
                    "routers": [
                        {
                            "name": "cr",
                            "region": _link("regions/us-central1"),
                            "network": hub,
                            "bgp": {"asn": 64514},
                        }
                    ]
                }
            },
            status={"bestRoutes": [{"destRange": "10.10.0.0/16", "nextHopIp": "169.254.0.2", "priority": 100}]},
        ),
        "vpnGateways": _Collection(
            aggregated={
                "regions/us-central1": {
                    "vpnGateways": [
                        {
                            "name": "ha",
                            "region": _link("regions/us-central1"),
                            "network": hub,
                            "vpnInterfaces": [{"id": 0, "ipAddress": "34.9.9.9"}],
                        }
                    ]
                }
            }
        ),
        "targetVpnGateways": _Collection(),
        "vpnTunnels": _Collection(),
        "externalVpnGateways": _Collection(),
        "interconnectAttachments": _Collection(),
        "interconnects": _Collection(),
        "instances": _Collection(deny=True),
        "networkFirewallPolicies": _Collection(),
        **{
            name: _Collection()
            for name in (
                "forwardingRules",
                "globalForwardingRules",
                "backendServices",
                "urlMaps",
                "targetHttpProxies",
                "targetHttpsProxies",
                "targetTcpProxies",
                "targetSslProxies",
                "targetPools",
                "instanceGroups",
                "networkEndpointGroups",
                "serviceAttachments",
            )
        },
    }
    collections.update(override)
    return NS(**{name: (lambda c=c: c) for name, c in collections.items()})


def test_live_collector_reads_the_network_and_skips_a_denied_section():
    resources, connections = collectors_module._collect_gcp_compute(_compute(), PROJECT)
    by_type: dict[str, list[dict]] = {}
    for r in resources:
        by_type.setdefault(r["resource_type"], []).append(r)
    assert [r["name"] for r in by_type["vpc"]] == ["hub"]
    assert [r["name"] for r in by_type["subnet"]] == ["mgmt"]
    [router] = by_type["cloud_router"]
    assert (
        router["metadata"]["bgp_asn"] == 64514 and router["metadata"]["learned_routes"][0]["prefix"] == "10.10.0.0/16"
    )
    [gateway] = by_type["ha_vpn_gateway"]
    assert gateway["metadata"]["public_ips"] == ["34.9.9.9"] and gateway["metadata"]["network_id"] == f"{PROJECT}:hub"
    [warning] = by_type["collection_warning"]
    assert warning["metadata"] == {
        "section": "instances",
        "error": "forbidden (HTTP 403)",
        "permissions": ["compute.instances.list"],
    }
    kinds = {(c["connection_type"], c["target_resource_uid"]) for c in connections}
    assert ("vpc_peering", f"gcp:vpc:{PROJECT}:spoke") in kinds
    assert ("vpn_gateway_attachment", f"gcp:ha_vpn_gateway:{PROJECT}:us-central1:ha") in kinds


def test_live_collector_fails_when_a_base_section_cannot_be_read():
    with pytest.raises(collectors_module.CloudCollectorExecutionError, match="firewalls"):
        collectors_module._collect_gcp_compute(_compute(firewalls=_Collection(deny=True)), PROJECT)
    with pytest.raises(collectors_module.CloudCollectorAuthError):
        collectors_module._collect_gcp_compute(_compute(networks=_Collection(deny=True)), PROJECT)


def _install_fake_gcp_sdk(monkeypatch, compute) -> None:
    """Stand-ins for google-auth and google-api-python-client."""
    import sys
    import types

    service_account = types.ModuleType("google.oauth2.service_account")
    service_account.Credentials = NS(from_service_account_info=lambda _info, scopes: object())
    oauth2 = types.ModuleType("google.oauth2")
    oauth2.service_account = service_account
    discovery = types.ModuleType("googleapiclient.discovery")
    discovery.build = lambda *_args, **_kwargs: compute
    for name, module in (
        ("google", types.ModuleType("google")),
        ("google.auth", types.ModuleType("google.auth")),
        ("google.oauth2", oauth2),
        ("google.oauth2.service_account", service_account),
        ("googleapiclient", types.ModuleType("googleapiclient")),
        ("googleapiclient.discovery", discovery),
    ):
        monkeypatch.setitem(sys.modules, name, module)


def test_live_collector_reports_progress_per_section(monkeypatch):
    """The map's progress bar: login, then every section is one step, ending below the total."""
    _install_fake_gcp_sdk(monkeypatch, _compute())
    auth = {"project_id": PROJECT, "service_account_json": {"type": "service_account"}}
    events: list[dict] = []
    collectors_module.collect_provider_snapshot(
        {"provider": "gcp", "auth_config_json": json.dumps(auth)}, events.append
    )
    assert events[0] == {"phase": "gcp login"}
    steps = [e for e in events if e["phase"] == "gcp section"]
    total = len(collectors_module._GCP_SECTIONS)
    assert [e["steps_done"] for e in steps] == list(range(total))
    assert {e["steps_total"] for e in steps} == {total}
    assert [e["section"] for e in steps] == list(collectors_module._GCP_SECTIONS.values())
    assert len(events) == 1 + total


# ── Snapshot ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def snapshot() -> dict:
    resources, connections = build_sample()
    return build_snapshot([ACCOUNT], resources, connections)


def _node(snapshot: dict, node_id: str) -> dict:
    return next(n for n in snapshot["nodes"] if n["id"] == node_id)


def _section(sections: list[dict], title: str) -> dict:
    return next(s for s in sections if s["title"] == title)


VMX = "sample:us-central1-a:vmx-hub-1"


def test_snapshot_has_a_site_per_network_and_a_transit_box(snapshot):
    sites = {s["id"]: s for s in snapshot["sites"]}
    assert snapshot["provider"] == "gcp" and snapshot["summary"]["sites"] == 2
    assert sites[HUB]["name"] == "hub-vpc" and TRANSIT_SITE_ID in sites
    hub = _node(snapshot, f"vpc:{HUB}")
    assert hub["kind"] == "vpc" and hub["site_sections"]
    # A network per box, an internet gateway per network that has a route to it.
    assert _node(snapshot, f"igw:{HUB}")["kind"] == "wan" and _node(snapshot, f"igw:{PROD}")["site"] == PROD


def test_snapshot_shows_only_instances_that_forward_traffic(snapshot):
    ids = {n["id"] for n in snapshot["nodes"]}
    assert f"i:{VMX}" in ids and "i:sample:us-central1-a:app-1" not in ids
    vmx = _node(snapshot, f"i:{VMX}")
    assert vmx["kind"] == "appliance" and "203.0.113.61" in vmx["alias_ips"]
    # Every instance is still listed in its network.
    prod = next(s for s in snapshot["sites"] if s["id"] == PROD)
    assert {row[0] for row in _section(prod["sections"], "VM instances")["rows"]} == {"app-1", "db-1"}


def test_snapshot_instance_in_inventory_becomes_a_node():
    resources, connections = build_sample()
    inventory = InventoryIndex([{"id": 7, "hostname": "db-1", "ip_address": "10.241.20.31"}])
    snap = build_snapshot([ACCOUNT], resources, connections, inventory)
    node = _node(snap, "i:sample:us-central1-a:db-1")
    assert node["kind"] == "server" and node["inventory"]["host_id"] == 7


def test_snapshot_links_networks_gateways_and_tunnels(snapshot):
    edges = {
        (e["a"], e["b"], e["sections"][0]["rows"][2][1] if e["kind"] == "vpn" else ""): e for e in snapshot["edges"]
    }
    gateway = "vpngw:sample:us-central1:ha-vpn-hub"
    up = edges[(gateway, "evpn:sample:hq-edge/0", "tunnel-hq-0")]
    down = edges[(gateway, "evpn:sample:hq-edge/1", "tunnel-hq-1")]
    assert up["kind"] == "vpn" and up["status"] == "reachable" and down["status"] == "unreachable"
    assert (f"vpc:{HUB}", f"vpc:{PROD}", "") in edges
    assert ("router:sample:us-central1:cr-hub", "ia:sample:us-central1:ia-dc1-primary", "") in edges
    # The gateway's public addresses are tunnel endpoints for the merge, the
    # far end's are what a device on the map answers on.
    assert _node(snapshot, gateway)["endpoint_ips"] == ["203.0.113.201", "203.0.113.202"]
    assert _node(snapshot, "evpn:sample:hq-edge/0")["ip"] == "198.51.100.20"
    assert _node(snapshot, "evpn:sample:hq-edge/0")["kind"] == "vpn_peer"
    # A peering to a network of another project keeps its far end.
    stub = _node(snapshot, f"x:vpc:{SHARED}")
    assert stub["kind"] == "vpc" and stub["model"] == "Not collected"
    site = next(s for s in snapshot["sites"] if s["id"] == stub["site"])
    assert site["name"] == "shared-vpc (not collected)" and site["not_collected"]


def test_snapshot_subnets_name_their_default_route(snapshot):
    hub = next(s for s in snapshot["sites"] if s["id"] == HUB)
    rows = {row[1]: row for row in _section(hub["sections"], "Subnets")["rows"]}
    assert rows["hub-mgmt"][4] == "Default internet gateway" and rows["hub-mgmt"][5] == "nat-hub-mgmt"
    assert not rows["hub-nva"][5] and rows["hub-eu"][2] == "europe-west1"
    prod = next(s for s in snapshot["sites"] if s["id"] == PROD)
    app = next(row for row in _section(prod["sections"], "Subnets")["rows"] if row[1] == "app")
    assert app[3] == "pods 10.241.128.0/20"
    rules = _section(prod["sections"], "VPC firewall rules")["rows"]
    assert [row[0] for row in rules[-2:]] == ["implied allow egress", "implied deny ingress"]
    assert any(row[0] == "prod-deny-ssh" and row[3] == "deny" for row in rules)
    routes = _section(hub["sections"], "Dynamic routes")["rows"]
    assert ["10.10.0.0/16", "cr-hub", "us-central1", "169.254.0.2", "VPN tunnel tunnel-hq-0", "100"] in routes


def test_subnet_index_places_subnets_on_the_network_router(snapshot):
    index = {row["cidr"]: row for row in subnet_index(snapshot)}
    assert index["10.241.20.0/24"]["node_id"] == f"vpc:{PROD}"
    assert index["10.240.3.0/24"]["node_id"] == f"vpc:{HUB}"
    host = index["10.241.20.31/32"]
    assert host["node_id"] == f"vpc:{PROD}" and host["kind"] == "host" and host["name"] == "VM instance db-1"


def test_search_finds_an_instance_that_is_not_a_node(snapshot):
    hits = search_index(build_search_index(snapshot), ["db-1"], 10)
    assert [h["node_id"] for h in hits] == [f"vpc:{PROD}"]


def test_snapshot_reports_what_discovery_could_not_read():
    resources, connections = build_sample()
    resources.append(collect.warning_resource("instances", _Denied()))
    snap = build_snapshot(
        [{**ACCOUNT, "last_sync_status": "error", "last_sync_message": "boom"}], resources, connections
    )
    messages = [e["message"] for e in snap["collection"]["errors"]]
    assert any("boom" in m for m in messages) and any("forbidden (HTTP 403)" in m for m in messages)


def test_snapshot_of_nothing_is_empty():
    snap = build_snapshot([], [], [])
    assert snap["sites"] == [] and snap["nodes"] == [] and snap["edges"] == []


# ── Merged with another integration ──────────────────────────────────────────


def test_an_instance_on_a_meraki_appliances_public_address_is_that_appliance():
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
    pairs = virtual_appliance_pairs([(1, meraki), (-3, snapshot)])
    assert pairs[(-3, f"i:{VMX}")] == (1, "Q2-VMX")


# ── Reachability ─────────────────────────────────────────────────────────────

APP, DB, JUMP = "10.241.10.21", "10.241.20.31", "10.240.1.5"


@pytest.fixture(scope="module")
def reach() -> Reachability:
    return Reachability(*build_sample())


def _check(reach, source, destination, protocol="tcp", port=None, **kw):
    return reach.check(source, destination, protocol=protocol, port=port, **kw)


def test_reachability_allows_what_routes_and_firewall_allow(reach):
    result = _check(reach, APP, DB, port=5432)
    assert result["verdict"] == "allowed" and result["traffic"] == "tcp/5432", result["summary"]
    assert result["source"] == {"address": APP, "label": f"instance app-1 ({APP})", "in_gcp": True}
    stages = {(s["stage"], s["status"]) for s in result["steps"]}
    assert ("route", "ok") in stages and ("security_group", "ok") in stages
    assert any("prod-allow-postgres-from-app" in s["text"] for s in result["steps"])


def test_reachability_blocks_a_port_the_firewall_denies(reach):
    result = _check(reach, APP, DB, port=22)
    assert result["verdict"] == "blocked" and "prod-deny-ssh" in result["summary"]


def test_reachability_lists_the_ports_the_firewall_rules_allow(reach):
    steps = _check(reach, APP, DB, protocol="")["steps"]
    ingress = next(s for s in steps if s["stage"] == "security_group" and s["where"].endswith("ingress"))
    # db-1 (tag db) takes 5432 from the app subnet; prod-deny-ssh and the implied deny the rest.
    assert ingress["ports"] == {"allowed": {"tcp": "5432"}, "partial": {}, "unknown": {}, "text": "allowed tcp 5432"}
    egress = next(s for s in steps if s["stage"] == "security_group" and s["where"].endswith("egress"))
    assert egress["ports"]["text"] == "allowed tcp any · udp any · icmp"
    # A whole subnet is not an instance: the rules for tagged instances allow in part.
    subnet = _check(reach, APP, "10.241.20.0/24", protocol="")["steps"]
    rules = next(s for s in subnet if s["stage"] == "security_group" and s["where"].endswith("ingress"))
    assert rules["ports"]["text"] == "allowed none; in part tcp 443, 5432 · icmp"
    assert all("ports" not in s for s in subnet if s["status"] == "info")


def test_reachability_a_deny_wins_a_priority_tie():
    resources, connections = build_sample()
    resources += collect.assemble(
        "sample",
        firewalls=[
            {
                "name": "prod-allow-ssh-tie",
                "network": _link("global/networks/prod-vpc", "sample"),
                "direction": "INGRESS",
                "priority": 900,
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                "sourceRanges": ["10.241.10.0/24"],
            }
        ],
    )[0]
    result = _check(Reachability(resources, connections), APP, DB, port=22)
    assert result["verdict"] == "blocked" and "On a tie a deny rule wins" in result["summary"]


def test_reachability_a_tagged_route_applies_only_to_a_tagged_instance(reach):
    # mgmt-jump carries the "lab" tag: the route hands it to the appliance.
    tagged = _check(reach, JUMP, "10.70.1.1", port=443)
    assert tagged["verdict"] == "unknown" and "lab-via-vmx" in tagged["summary"]
    # A whole subnet is not an instance: the tagged route is left out, and said so.
    subnet = _check(reach, "10.240.1.0/24", "10.70.1.1", port=443)
    assert subnet["verdict"] != "allowed"
    assert any(s["status"] == "info" and "network tags" in s["text"] for s in subnet["steps"])
    assert not any("lab-via-vmx" in s["text"] for s in subnet["steps"])


def test_reachability_follows_peerings_only_between_their_networks(reach):
    assert _check(reach, APP, JUMP, port=443)["verdict"] == "allowed"
    # Prod is peered with the hub, not with what is behind the hub's VPN.
    result = _check(reach, APP, "10.10.5.5", port=443)
    assert result["verdict"] == "blocked" and "a private address, to the internet" in result["summary"]


def test_reachability_a_peered_network_that_is_not_collected_is_unknown(reach):
    result = _check(reach, JUMP, "10.250.1.1", port=443)
    assert result["verdict"] == "unknown" and "shared-vpc" in result["summary"]


def test_reachability_leaves_and_enters_over_the_established_tunnel(reach):
    out = _check(reach, JUMP, "10.10.5.5", port=22)
    assert out["verdict"] == "allowed", out["summary"]
    assert any("tunnel-hq-0" in s["text"] for s in out["steps"])
    inbound = _check(reach, "10.10.5.5", JUMP, port=22)
    assert inbound["verdict"] == "allowed", inbound["summary"]
    assert inbound["source"]["in_gcp"] is False
    assert any(s["where"] == "VPN tunnel tunnel-hq-0" and s["status"] == "ok" for s in inbound["steps"])
    # Over the Interconnect too.
    assert _check(reach, JUMP, "10.30.1.1", port=443)["verdict"] == "allowed"


def test_reachability_reports_a_tunnel_that_is_down(reach):
    result = _check(reach, JUMP, "10.20.1.1", port=22)
    assert result["verdict"] == "blocked" and "tunnel-hq-1 is not established" in result["summary"]


def test_reachability_an_instance_without_external_ip_needs_cloud_nat(reach):
    nat = _check(reach, JUMP, "8.8.8.8", port=443)
    assert nat["verdict"] == "allowed" and any("Cloud NAT nat-hub-mgmt" in s["text"] for s in nat["steps"])
    none = _check(reach, DB, "8.8.8.8", port=443)
    assert none["verdict"] == "blocked" and "no external IP and no Cloud NAT" in none["summary"]
    assert _check(reach, APP, "8.8.8.8", port=443)["verdict"] == "allowed"
    # From the internet only an instance with an external IP is reachable.
    assert _check(reach, "8.8.8.8", APP, port=443)["verdict"] == "allowed"
    assert _check(reach, "8.8.8.8", DB, port=443)["verdict"] == "blocked"


def test_reachability_the_appliance_next_hop_stops_or_goes_on_through_a_carrier(reach):
    stopped = _check(reach, JUMP, "10.99.1.1", port=443)
    assert stopped["verdict"] == "unknown" and "vmx-hub-1" in stopped["summary"]

    class Carrier:
        name = "Meraki vMX hub"

        def carry(self, inside, outside):
            return [("ok", "AutoVPN", "Carried to the branch.")]

    carried = _check(reach, JUMP, "10.99.1.1", port=443, carriers={VMX: Carrier()})
    assert carried["verdict"] == "allowed", carried["summary"]
    assert any(s["stage"] == "vpn" and s["where"] == "AutoVPN" for s in carried["steps"])


def test_reachability_finds_an_alias_range_of_an_instance(reach):
    place = reach.locate("10.241.128.20")
    assert place["instance"]["name"] == "app-1" and place["range"] == "pods"


def test_reachability_a_range_in_two_networks_needs_its_network():
    resources, connections = build_sample()
    resources += collect.assemble(
        "sample",
        subnetworks=[
            {
                "name": "dev-app",
                "region": _link("regions/us-east1", "sample"),
                "network": _link("global/networks/dev-vpc", "sample"),
                "ipCidrRange": "10.241.10.0/24",
            }
        ],
    )[0]
    reach = Reachability(resources, connections)
    result = _check(reach, APP, DB, port=5432)
    assert result["verdict"] == "unknown" and "several VPC networks" in result["summary"]
    assert _check(reach, APP, DB, port=5432, source_vpc=PROD)["verdict"] == "allowed"


def test_reachability_of_nothing_gcp_knows_does_not_apply(reach):
    assert reach.check("192.0.2.1", "192.0.2.2")["applies"] is False
    with pytest.raises(ValueError):
        reach.check("nope", APP)


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
def api(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-gcp")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    import netcontrol.routes.meraki_topology as routes_module
    from netcontrol.routes.topology import invalidate_topology_cache

    def reset() -> None:
        # The graph and snapshot caches outlive this test's database.
        routes_module._SNAPSHOT_CACHE.clear()
        routes_module._HOST_FORWARDING.clear()
        invalidate_topology_cache()

    reset()

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(reset)
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return _CsrfClient(client, resp.json().get("csrf_token", ""))


def _gcp_nodes(api) -> list[dict]:
    graph = api.get("/api/topology").json()
    return [n for n in graph["nodes"] if (n.get("meraki") or {}).get("provider") == "gcp"]


def test_api_discovered_gcp_project_is_on_the_topology(api):
    assert _gcp_nodes(api) == []
    account = api.post("/api/cloud/accounts", json={"provider": "gcp", "name": "Prod GCP"}).json()["account"]
    assert _gcp_nodes(api) == []

    body = {"mode": "sample", "include_hybrid_links": False}
    assert api.post(f"/api/cloud/accounts/{account['id']}/discover", json=body).status_code == 200

    gcp = _gcp_nodes(api)
    assert {n["meraki"]["kind"] for n in gcp} >= {"vpc", "appliance", "cloud", "vpn_peer", "wan"}
    org_ref = gcp[0]["meraki"]["org_ref"]
    assert org_ref == -3

    details = api.get(f"/api/sources/nodes?org_ref={org_ref}&node_id=vpc:{PROD}").json()
    assert details["provider"] == "gcp" and details["site_name"] == "prod-vpc"

    subnets = api.get("/api/sources/subnets").json()["subnets"]
    db_subnet = next(s for s in subnets if s["cidr"] == "10.241.20.0/24")
    assert db_subnet["provider"] == "gcp" and db_subnet["site_id"] == PROD

    check = f"/api/sources/gcp/reachability?source={APP}&destination={DB}&protocol=tcp"
    allowed = api.get(f"{check}&port=5432&source_network={PROD}").json()
    assert allowed["applies"] and allowed["verdict"] == "allowed"
    assert api.get(f"{check}&port=22").json()["verdict"] == "blocked"
    assert api.get(f"/api/sources/gcp/reachability?source=nope&destination={DB}").status_code == 400
    # The AWS and Azure checks do not see GCP.
    for other in ("aws", "azure"):
        assert api.get(f"/api/sources/{other}/reachability?source={APP}&destination={DB}").json()["applies"] is False

    export = api.get("/api/topology/export.html")
    assert export.status_code == 200 and "prod-vpc" in export.text

    assert api.put(f"/api/cloud/accounts/{account['id']}", json={"enabled": False}).status_code == 200
    assert _gcp_nodes(api) == []


def test_api_traces_a_path_between_two_gcp_subnets(api):
    assert api.post("/api/sources/sample?provider=gcp").status_code == 201
    path = f"/api/topology/path?source={APP}&destination={DB}&protocol=tcp"
    allowed = api.get(f"{path}&port=5432")
    assert allowed.status_code == 200, allowed.text
    body = allowed.json()
    assert body["applies"] and body["verdict"] == "allowed", body["summary"]
    hop = next(h for h in body["request"]["hops"] if h["label"] == "prod-vpc")
    stages = {i["stage"] for i in hop["items"]}
    assert {"route", "security_group"} <= stages
    assert any("prod-allow-postgres-from-app" in i["text"] for i in hop["items"])
    blocked = api.get(f"{path}&port=22").json()
    assert blocked["verdict"] == "blocked", blocked["summary"]


def test_api_gcp_sample_and_sources(api):
    built = api.post("/api/sources/sample?provider=gcp")
    assert built.status_code == 201, built.text
    assert built.json()["org_ref"] == -3 and built.json()["summary"]["sites"] == 2
    assert api.post("/api/sources/sample?provider=gcp").status_code == 201
    accounts = api.get("/api/cloud/accounts").json()["accounts"]
    assert [(a["provider"], a["auth_type"]) for a in accounts] == [("gcp", "sample")]
    providers = {(n.get("meraki") or {}).get("provider") for n in api.get("/api/topology").json()["nodes"]}
    assert "gcp" in providers

    body = {
        "provider": "gcp",
        "name": "Prod GCP",
        "auth_config": {"service_account_json": '{"private_key": "hunter2"}'},
    }
    account = api.post("/api/cloud/accounts", json=body).json()["account"]
    sources = {s["key"]: s for s in api.get("/api/topology/sources").json()["sources"]}
    demo = next(s for s in sources.values() if s["type"] == "gcp" and s["demo"])
    assert demo["status"] == "success" and not demo["can_collect"]
    prod = sources[f"gcp:{account['id']}"]
    assert (prod["status"], prod["can_collect"], prod["enabled"]) == ("never", True, True)
    assert "hunter2" not in api.get("/api/topology/sources").text


# ── Load balancers and Private Service Connect ───────────────────────────────


def _rule(name: str, scheme: str, target: str = "", region: str = "us-central1", **extra) -> dict:
    scope = f"regions/{region}" if region else "global"
    return {
        "name": name,
        "selfLink": _link(f"{scope}/forwardingRules/{name}"),
        **({"region": _link(f"regions/{region}")} if region else {}),
        "loadBalancingScheme": scheme,
        **({"target": target} if target else {}),
        **extra,
    }


def test_load_balancer_kind_follows_scheme_scope_and_target():
    https = _link("global/targetHttpsProxies/p")
    regional_http = _link("regions/us-central1/targetHttpProxies/p")
    tcp = _link("global/targetTcpProxies/p")
    cases = {
        ("EXTERNAL_MANAGED", https, ""): "Global external Application Load Balancer",
        ("EXTERNAL", https, ""): "Classic Application Load Balancer",
        ("EXTERNAL_MANAGED", regional_http, "us-central1"): "Regional external Application Load Balancer",
        ("INTERNAL_MANAGED", regional_http, "us-central1"): "Regional internal Application Load Balancer",
        ("INTERNAL_MANAGED", https, ""): "Cross-region internal Application Load Balancer",
        ("EXTERNAL", tcp, ""): "Classic proxy Network Load Balancer",
        ("INTERNAL", "", "us-central1"): "Internal passthrough Network Load Balancer",
        ("EXTERNAL", "", "us-central1"): "External passthrough Network Load Balancer",
        (
            "EXTERNAL",
            _link("regions/us-central1/targetPools/tp"),
            "us-central1",
        ): "External passthrough Network Load Balancer (target pool)",
        ("EXTERNAL", _link("zones/us-central1-a/targetInstances/ti"), "us-central1"): "Protocol forwarding",
    }
    for (scheme, target, region), kind in cases.items():
        assert collect.load_balancer_kind(_rule("fr", scheme, target, region)) == kind, (scheme, target)


def test_forwarding_rule_joins_its_proxy_url_map_backend_services_and_groups():
    hub = _link("global/networks/hub")
    backends = collect.Backends(
        PROJECT,
        target_proxies=[
            {"selfLink": _link("global/targetHttpsProxies/web-proxy"), "urlMap": _link("global/urlMaps/web")}
        ],
        url_maps=[
            {
                "selfLink": _link("global/urlMaps/web"),
                "defaultService": _link("global/backendServices/web"),
                "pathMatchers": [{"pathRules": [{"service": _link("global/backendServices/api")}]}],
            }
        ],
        backend_services=[
            {
                "selfLink": _link("global/backendServices/web"),
                "protocol": "HTTPS",
                "backends": [{"group": _link("zones/us-central1-a/instanceGroups/web")}],
            },
            {
                "selfLink": _link("global/backendServices/api"),
                "protocol": "HTTP",
                "backends": [{"group": _link("zones/us-central1-b/networkEndpointGroups/api")}],
            },
        ],
        instance_groups=[{"selfLink": _link("zones/us-central1-a/instanceGroups/web"), "network": hub}],
        network_endpoint_groups=[{"selfLink": _link("zones/us-central1-b/networkEndpointGroups/api"), "network": hub}],
    )
    rule = _rule(
        "web",
        "EXTERNAL_MANAGED",
        # A beta link names the same proxy as the v1 self link.
        "https://compute.googleapis.com/compute/beta/projects/acme-net/global/targetHttpsProxies/web-proxy",
        "",
        IPAddress="203.0.113.10",
        IPProtocol="TCP",
        portRange="443-443",
    )
    record = collect.forwarding_rule_resource(rule, PROJECT, backends)
    meta = record["metadata"]
    assert record["resource_uid"] == f"gcp:load_balancer:{PROJECT}:web" and record["region"] == "global"
    assert meta["kind"] == "Global external Application Load Balancer"
    assert meta["url_map"] == "web" and meta["backend_services"] == ["web", "api"]
    assert meta["backend_protocols"] == ["HTTPS", "HTTP"] and meta["backend_count"] == 2
    # An external load balancer names no network: its backends place it.
    assert meta["vpc_id"] == f"{PROJECT}:hub" and meta["subnet_ids"] == []
    # Its address is public: listed, not a host of the network.
    assert meta["public_ips"] == ["203.0.113.10"] and meta["endpoints"] == [] and meta["ports"] == ["443"]


def test_internal_forwarding_rule_is_an_endpoint_of_its_subnet():
    rule = _rule(
        "ilb",
        "INTERNAL",
        IPAddress="10.0.0.50",
        IPProtocol="TCP",
        ports=["80", "443"],
        network=_link("global/networks/hub"),
        subnetwork=_link("regions/us-central1/subnetworks/mgmt"),
        backendService=_link("regions/us-central1/backendServices/bs"),
        serviceName="web.ilb.il4.us-central1.lb.acme-net.internal",
    )
    meta = collect.forwarding_rule_resource(rule, PROJECT)["metadata"]
    assert meta["kind"] == "Internal passthrough Network Load Balancer"
    assert meta["vpc_id"] == f"{PROJECT}:hub" and meta["subnet_ids"] == [f"{PROJECT}:us-central1:mgmt"]
    # Two ports: no single port on the endpoint.
    assert meta["endpoints"] == [
        {"role": "Frontend", "dns_name": "web.ilb.il4.us-central1.lb.acme-net.internal", "ip_addresses": ["10.0.0.50"]}
    ]
    # The backend service was not collected: its name is still recorded.
    assert meta["backend_services"] == ["bs"] and meta["backend_count"] == 0


def test_psc_endpoints_service_attachments_and_vpn_forwarding_rules():
    hub = _link("global/networks/hub")
    google = collect.forwarding_rule_resource(
        _rule("apis", "", "all-apis", "", IPAddress="10.0.9.5", network=hub, pscConnectionStatus="ACCEPTED"),
        PROJECT,
    )
    assert google["resource_type"] == "psc_endpoint" and google["status"] == "accepted"
    assert google["metadata"]["psc_target"] == "Google APIs (all-apis)" and google["metadata"]["psc_target_id"] == ""
    producer = _link("regions/us-central1/serviceAttachments/sa", "producer-prj")
    endpoint = collect.forwarding_rule_resource(
        _rule("db", "", producer, IPAddress="10.0.0.60", network=hub, pscConnectionStatus="PENDING"), PROJECT
    )
    assert endpoint["metadata"]["kind"] == "Private Service Connect endpoint"
    assert endpoint["metadata"]["psc_target_id"] == "producer-prj:us-central1:sa"
    assert endpoint["metadata"]["endpoints"][0]["ip_addresses"] == ["10.0.0.60"]
    # The ESP / IKE forwarding rules of a Classic VPN gateway are no load balancer.
    vpn = _rule("vpn-esp", "EXTERNAL", _link("regions/us-central1/targetVpnGateways/classic"))
    assert collect.forwarding_rule_resource(vpn, PROJECT) is None

    resources, _ = collect.assemble(
        PROJECT,
        subnetworks=[
            {
                "name": "nat",
                "selfLink": _link("regions/us-central1/subnetworks/nat"),
                "region": _link("regions/us-central1"),
                "network": hub,
                "ipCidrRange": "10.0.30.0/24",
                "purpose": "PRIVATE_SERVICE_CONNECT",
            }
        ],
        service_attachments=[
            {
                "name": "sa",
                "selfLink": _link("regions/us-central1/serviceAttachments/sa"),
                "region": _link("regions/us-central1"),
                # Not collected: the NAT subnet places the attachment.
                "targetService": _link("regions/us-central1/forwardingRules/ilb"),
                "natSubnets": [_link("regions/us-central1/subnetworks/nat")],
                "connectionPreference": "ACCEPT_AUTOMATIC",
                "connectedEndpoints": [
                    {"status": "ACCEPTED", "consumerNetwork": _link("global/networks/c", "consumer-prj")},
                    {"status": "PENDING", "consumerNetwork": _link("global/networks/d", "consumer-prj")},
                ],
            }
        ],
    )
    [attachment] = [r for r in resources if r["resource_type"] == "service_attachment"]
    meta = attachment["metadata"]
    assert attachment["resource_uid"] == f"gcp:service_attachment:{PROJECT}:us-central1:sa"
    assert meta["vpc_id"] == f"{PROJECT}:hub" and meta["nat_subnets"] == ["nat"]
    assert meta["target_service_id"] == f"{PROJECT}:us-central1:ilb"
    assert (meta["connected_endpoints"], meta["pending_endpoints"]) == (1, 1)
    assert meta["consumer_networks"] == ["consumer-prj:c", "consumer-prj:d"]


def test_live_collector_reads_load_balancers_and_names_the_permission_of_a_denied_section():
    hub = _link("global/networks/hub")
    group = _link("zones/us-central1-a/instanceGroups/ig")
    health = _Collection(
        status={
            group: [
                {"instance": "vm-1", "ipAddress": "10.0.0.11", "healthState": "HEALTHY"},
                {"instance": "vm-2", "ipAddress": "10.0.0.12", "healthState": "UNHEALTHY"},
                {"instance": "vm-3", "ipAddress": "10.0.0.13", "healthState": "DRAINING"},
            ]
        }
    )
    compute = _compute(
        forwardingRules=_Collection(
            aggregated={
                "regions/us-central1": {
                    "forwardingRules": [
                        _rule(
                            "ilb",
                            "INTERNAL",
                            IPAddress="10.0.0.50",
                            network=hub,
                            backendService=_link("regions/us-central1/backendServices/bs"),
                        )
                    ]
                }
            }
        ),
        backendServices=_Collection(
            aggregated={
                "regions/us-central1": {
                    "backendServices": [
                        {
                            "selfLink": _link("regions/us-central1/backendServices/bs"),
                            "protocol": "TCP",
                            "backends": [{"group": _link("zones/us-central1-a/instanceGroups/ig")}],
                        }
                    ]
                }
            }
        ),
        targetSslProxies=_Collection(deny=True),
        regionBackendServices=health,
    )
    resources, _ = collectors_module._collect_gcp_compute(compute, PROJECT)
    [lb] = [r for r in resources if r["resource_type"] == "load_balancer"]
    assert lb["metadata"]["backend_services"] == ["bs"] and lb["metadata"]["backend_count"] == 1
    # One getHealth call per backend group, through the regional collection.
    assert health.health_asked == [("us-central1", "bs", group)]
    assert lb["metadata"]["backend_health"] == {"healthy": 1, "unhealthy": 1, "unknown": 1}
    assert lb["metadata"]["backend_health_groups"] == [
        {"backend_service": "bs", "group": "ig", "healthy": 1, "unhealthy": 1, "unknown": 1}
    ]
    warnings = {
        r["metadata"]["section"]: r["metadata"] for r in resources if r["resource_type"] == "collection_warning"
    }
    assert set(warnings) == {"instances", "target_proxies"}
    assert "compute.targetSslProxies.list" in warnings["target_proxies"]["permissions"]


def test_backend_health_is_skipped_alone_when_denied_and_absent_without_it():
    service = {
        "selfLink": _link("global/backendServices/web"),
        "backends": [{"group": _link("zones/us-central1-a/networkEndpointGroups/neg")}],
    }
    # Global backend services answer getHealth through backendServices, here denied.
    compute = _compute(
        backendServices=_DeniedHealth(service),
        globalForwardingRules=_Collection(
            [_rule("web", "INTERNAL_MANAGED", region="", backendService=service["selfLink"], IPAddress="10.0.0.9")]
        ),
    )
    resources, _ = collectors_module._collect_gcp_compute(compute, PROJECT)
    warnings = {r["name"]: r["metadata"] for r in resources if r["resource_type"] == "collection_warning"}
    assert warnings["backend_health"]["permissions"] == [
        "compute.backendServices.get",
        "compute.regionBackendServices.get",
    ]
    [lb] = [r for r in resources if r["resource_type"] == "load_balancer"]
    assert lb["metadata"]["backend_services"] == ["web"] and "backend_health" not in lb["metadata"]


class _DeniedHealth(_Collection):
    """Backend services that list but may not be asked for their health."""

    def __init__(self, service):
        super().__init__(aggregated={"global": {"backendServices": [service]}})

    def getHealth(self, project, backendService, body, region=None):
        return _Request({}, True)


def test_backend_health_calls_are_capped(monkeypatch):
    monkeypatch.setattr(collectors_module, "_GCP_HEALTH_CALLS_MAX", 2)
    services = [
        {
            "name": f"bs{i}",
            "selfLink": _link(f"global/backendServices/bs{i}"),
            "backends": [{"group": "g1"}, {"group": "g2"}],
        }
        for i in range(2)
    ]
    collection = _Collection()
    found = collectors_module._gcp_backend_health(NS(backendServices=lambda: collection), PROJECT, services)
    assert [(r["backendService"].rsplit("/", 1)[-1], r["group"]) for r in found] == [("bs0", "g1"), ("bs0", "g2")]
    assert collection.health_asked == [(None, "bs0", "g1"), (None, "bs0", "g2")]


_SQL = {
    "name": "orders-db",
    "project": PROJECT,
    "region": "us-central1",
    "gceZone": "us-central1-b",
    "databaseVersion": "POSTGRES_15",
    "state": "RUNNABLE",
    "connectionName": f"{PROJECT}:us-central1:orders-db",
    "instanceType": "CLOUD_SQL_INSTANCE",
    "ipAddresses": [
        {"type": "PRIVATE", "ipAddress": "10.0.5.3"},
        {"type": "PRIMARY", "ipAddress": "203.0.113.40"},
        {"type": "OUTGOING", "ipAddress": "203.0.113.41"},
    ],
    "settings": {
        "tier": "db-custom-2-7680",
        "availabilityType": "REGIONAL",
        "ipConfiguration": {
            "ipv4Enabled": True,
            "privateNetwork": f"projects/{PROJECT}/global/networks/hub",
            "pscConfig": {"pscEnabled": False},
        },
    },
}
_REDIS = {
    "name": f"projects/{PROJECT}/locations/us-central1/instances/sessions",
    "locationId": "us-central1-a",
    "currentLocationId": "us-central1-a",
    "redisVersion": "REDIS_7_0",
    "host": "10.0.6.4",
    "port": 6379,
    "readEndpoint": "10.0.6.5",
    "readEndpointPort": 6379,
    "authorizedNetwork": f"projects/{PROJECT}/global/networks/hub",
    "connectMode": "PRIVATE_SERVICE_ACCESS",
    "state": "READY",
    "tier": "STANDARD_HA",
    "memorySizeGb": 5,
}


def test_cloud_sql_instance_is_a_service_of_its_private_network():
    record = collect.cloud_sql_resource(_SQL, PROJECT)
    meta = record["metadata"]
    assert record["resource_uid"] == f"gcp:cloud_sql_instance:{PROJECT}:us-central1:orders-db"
    assert record["status"] == "runnable" and meta["kind"] == "Cloud SQL instance"
    assert (meta["engine"], meta["engine_version"]) == ("postgres", "15")
    assert meta["vpc_id"] == f"{PROJECT}:hub"
    assert meta["endpoints"] == [{"role": "Private IP", "dns_name": "", "port": 5432, "ip_addresses": ["10.0.5.3"]}]
    assert meta["public_ips"] == ["203.0.113.40"] and meta["outgoing_ips"] == ["203.0.113.41"]
    assert meta["psc_enabled"] is False and meta["tier"] == "db-custom-2-7680"
    assert collect.cloud_sql_resource({"databaseVersion": "MYSQL_8_0"}, PROJECT) is None
    mysql = collect.cloud_sql_resource({"name": "m", "databaseVersion": "MYSQL_8_0"}, PROJECT)
    assert mysql["metadata"]["engine_version"] == "8.0" and mysql["metadata"]["vpc_id"] == ""


def test_memorystore_instance_is_a_service_of_its_authorized_network():
    record = collect.memorystore_redis_resource(_REDIS, PROJECT)
    meta = record["metadata"]
    assert record["resource_uid"] == f"gcp:memorystore_redis_instance:{PROJECT}:us-central1:sessions"
    assert record["name"] == "sessions" and record["status"] == "ready"
    assert meta["vpc_id"] == f"{PROJECT}:hub" and meta["engine_version"] == "7.0"
    assert [(e["role"], e["port"], e["ip_addresses"]) for e in meta["endpoints"]] == [
        ("Primary", 6379, ["10.0.6.4"]),
        ("Read endpoint", 6379, ["10.0.6.5"]),
    ]
    assert meta["connect_mode"] == "PRIVATE_SERVICE_ACCESS" and meta["tier"] == "STANDARD_HA"


class _ApiList:
    """A ``list`` collection of another discovery API (one page, ``key`` items)."""

    def __init__(self, key, items, *, deny=False):
        self._key, self._items, self._deny = key, items, deny
        self.asked: list[dict] = []

    def list(self, **kwargs):
        self.asked.append(kwargs)
        return _Request({self._key: list(self._items)}, self._deny)

    def list_next(self, previous_request, previous_response):
        return None


def test_live_collector_reads_cloud_sql_and_memorystore_through_their_apis():
    sql = _ApiList("items", [_SQL])
    redis = _ApiList("instances", [_REDIS])
    apis = {
        ("sqladmin", "v1"): NS(instances=lambda: sql),
        ("redis", "v1"): NS(projects=lambda: NS(locations=lambda: NS(instances=lambda: redis))),
    }
    resources, _ = collectors_module._collect_gcp_compute(_compute(), PROJECT, None, lambda *api: apis[api])
    names = {(r["resource_type"], r["name"]) for r in resources}
    assert ("cloud_sql_instance", "orders-db") in names and ("memorystore_redis_instance", "sessions") in names
    assert sql.asked == [{"project": PROJECT}]
    assert redis.asked == [{"parent": f"projects/{PROJECT}/locations/-"}]
    # A denied API is skipped alone and names its permission.
    apis[("redis", "v1")] = NS(
        projects=lambda: NS(locations=lambda: NS(instances=lambda: _ApiList("instances", [], deny=True)))
    )
    resources, _ = collectors_module._collect_gcp_compute(_compute(), PROJECT, None, lambda *api: apis[api])
    warnings = {r["name"]: r["metadata"] for r in resources if r["resource_type"] == "collection_warning"}
    assert warnings["memorystore_redis_instances"]["permissions"] == ["redis.instances.list"]
    assert "cloud_sql_instances" not in warnings
    # Without the client factory (an older caller) neither is read nor reported.
    resources, _ = collectors_module._collect_gcp_compute(_compute(), PROJECT)
    assert not [r for r in resources if r["resource_type"] in ("cloud_sql_instance", "memorystore_redis_instance")]


def test_gcp_permissions_are_documented():
    import pathlib

    text = (pathlib.Path(__file__).resolve().parents[1] / "docs" / "gcp-topology.md").read_text(encoding="utf-8")
    start = text.index("### Permissions")
    doc = text[start : text.index("\n## ", start)]
    assert set(collectors_module.GCP_SECTION_PERMISSIONS) == {*collectors_module._GCP_SECTIONS, "router_status"}
    for section, permissions in collectors_module.GCP_SECTION_PERMISSIONS.items():
        for permission in permissions:
            assert f"`{permission}`" in doc, (section, permission)


def test_snapshot_lists_load_balancers_and_psc_in_their_network(snapshot):
    prod = next(s for s in snapshot["sites"] if s["id"] == PROD)
    hub = next(s for s in snapshot["sites"] if s["id"] == HUB)
    lbs = {row[0]: row for row in _section(prod["sections"], "Load balancers")["rows"]}
    assert lbs["ilb-db"][2] == "Internal passthrough Network Load Balancer"
    # Cells are text: one address, one subnet.
    assert lbs["ilb-db"][7] == "10.241.20.100" and lbs["ilb-db"][8] == "db (10.241.20.0/24)"
    assert lbs["web-https"][2] == "Global external Application Load Balancer"
    assert lbs["web-https"][7] == "203.0.113.80"
    assert {row[0] for row in _section(prod["sections"], "Private Service Connect")["rows"]} == {"sa-db"}
    assert {row[0] for row in _section(hub["sections"], "Private Service Connect")["rows"]} == {
        "psc-db",
        "pscgoogleapis",
    }
    overview = dict(_section(prod["sections"], "VPC network overview")["rows"])
    assert overview["Load balancers"] == "2" and overview["Private Service Connect"] == "1"
    # Internal addresses are hosts of the network; the public one is not.
    index = {row["cidr"]: row for row in subnet_index(snapshot)}
    assert index["10.241.20.100/32"]["node_id"] == f"vpc:{PROD}"
    assert index["10.240.1.50/32"]["node_id"] == f"vpc:{HUB}"
    assert "203.0.113.80/32" not in index
    # No node is drawn for them.
    assert not [n for n in snapshot["nodes"] if "ilb-db" in n["id"] or "sa-db" in n["id"]]


def test_snapshot_lists_cloud_sql_memorystore_and_backend_health(snapshot):
    prod = next(s for s in snapshot["sites"] if s["id"] == PROD)
    sql = {row[0]: row for row in _section(prod["sections"], "Cloud SQL")["rows"]}
    assert sql["orders-sql"][2] == "Cloud SQL instance" and sql["orders-sql"][5] == "runnable"
    redis = {row[0]: row for row in _section(prod["sections"], "Memorystore")["rows"]}
    assert redis["sessions-redis"][5] == "ready"
    lbs = {row[0]: row for row in _section(prod["sections"], "Load balancers")["rows"]}
    assert "healthy" in json.dumps(lbs["ilb-db"][10])
    # Their private addresses are hosts of the production network.
    index = {row["cidr"]: row for row in subnet_index(snapshot)}
    for address in ("10.241.200.3", "10.241.201.4", "10.241.201.5"):
        assert index[f"{address}/32"]["node_id"] == f"vpc:{PROD}"
    resources, _ = build_sample()
    [lb] = [r for r in resources if r["name"] == "ilb-db"]
    assert lb["metadata"]["backend_health"] == {"healthy": 1, "unhealthy": 0, "unknown": 0}


def test_search_finds_a_load_balancer_by_its_dns_name(snapshot):
    hits = search_index(build_search_index(snapshot), ["db.ilb-db.il4.us-central1.lb.sample.internal"], 10)
    assert f"vpc:{PROD}" in [h["node_id"] for h in hits]
