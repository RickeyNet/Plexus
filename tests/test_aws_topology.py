"""Tests for AWS in the Topology map.

Covers the pipeline with no AWS access:
  * collect     - reshaping EC2 items, secrets left behind, optional sections
  * normalize   - VPC sites, gateways, forwarding instances, VPNs, the report
  * subnets     - VPC subnets are owned by the VPC's router
  * unified     - snapshots of different integrations joined by public address
  * HTTP API    - a discovered AWS account on /api/topology, node details,
                  subnets, deep search, HTML export
"""

from __future__ import annotations

import json

import netcontrol.app as app_module
import netcontrol.routes.cloud_collectors as collectors_module
import pytest
import routes.database as db_module
from netcontrol.integrations.aws import collect
from netcontrol.integrations.aws.normalize import TRANSIT_SITE_ID, build_snapshot
from netcontrol.integrations.aws.sample import build_sample
from netcontrol.integrations.meraki.normalize import InventoryIndex
from netcontrol.integrations.meraki.subnets import subnet_index
from netcontrol.integrations.meraki.unified import build_search_index, merge_meraki_into_graph, node_details

ACCOUNT = {"id": 1, "name": "Prod", "last_sync_at": "2026-10-01T12:00:00+00:00", "last_sync_status": "success"}

# ── Collector helpers ────────────────────────────────────────────────────────


def test_instance_resource_reads_interfaces_and_forwarding():
    instance = {
        "InstanceId": "i-1",
        "State": {"Name": "running"},
        "Tags": [{"Key": "Name", "Value": "ftdv-1"}],
        "VpcId": "vpc-1",
        "SubnetId": "subnet-m",
        "InstanceType": "c5.xlarge",
        "PrivateIpAddress": "10.0.2.11",
        "PublicIpAddress": "52.1.2.3",
        "SourceDestCheck": True,
        "NetworkInterfaces": [
            {
                "NetworkInterfaceId": "eni-b",
                "SubnetId": "subnet-o",
                "SourceDestCheck": False,
                "Attachment": {"DeviceIndex": 1},
                "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.0.11", "Association": {"PublicIp": "52.1.2.3"}}],
            },
            {
                "NetworkInterfaceId": "eni-a",
                "SubnetId": "subnet-m",
                "SourceDestCheck": True,
                "Attachment": {"DeviceIndex": 0},
                "PrivateIpAddress": "10.0.2.11",
            },
        ],
    }
    resource = collect.instance_resource(instance, "us-east-1")
    meta = resource["metadata"]
    assert resource["resource_uid"] == "aws:instance:i-1" and resource["name"] == "ftdv-1"
    # One interface with the check off makes the instance a forwarder.
    assert meta["source_dest_check"] is False
    assert [i["id"] for i in meta["interfaces"]] == ["eni-a", "eni-b"]
    assert meta["interfaces"][1]["public_ips"] == ["52.1.2.3"]
    assert collect.instance_resource({"InstanceId": "i-2", "State": {"Name": "terminated"}}, "us-east-1") is None


def test_vpn_metadata_never_carries_keys():
    vpn = {
        "VpnConnectionId": "vpn-1",
        "CustomerGatewayId": "cgw-1",
        "TransitGatewayId": "tgw-1",
        "CustomerGatewayConfiguration": "<xml><pre_shared_key>TOP-SECRET-PSK</pre_shared_key></xml>",
        "Options": {
            "StaticRoutesOnly": True,
            "TunnelOptions": [{"TunnelInsideCidr": "169.254.10.0/30", "PreSharedKey": "TOP-SECRET-PSK"}],
        },
        "Routes": [{"DestinationCidrBlock": "10.9.0.0/16"}],
        "VgwTelemetry": [{"OutsideIpAddress": "52.9.9.9", "Status": "UP", "AcceptedRouteCount": 2}],
    }
    meta = collect.vpn_connection_metadata(vpn)
    assert "TOP-SECRET-PSK" not in json.dumps(meta)
    assert meta["tunnel_inside_cidrs"] == ["169.254.10.0/30"] and meta["static_routes"] == ["10.9.0.0/16"]
    assert meta["tunnels"][0]["outside_ip"] == "52.9.9.9" and meta["static_routes_only"] is True


def test_route_table_detail_names_targets():
    detail = collect.route_table_detail(
        {
            "Associations": [{"Main": True}],
            "Routes": [
                {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"},
                {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1", "State": "active"},
                {"DestinationCidrBlock": "10.8.0.0/16", "NetworkInterfaceId": "eni-9", "State": "blackhole"},
            ],
        }
    )
    assert detail["main"] is True
    assert [(r["destination"], r["target"]) for r in detail["routes"]] == [
        ("10.0.0.0/16", "local"),
        ("0.0.0.0/0", "nat-1"),
        ("10.8.0.0/16", "eni-9"),
    ]


class _Denied(Exception):
    response = {"Error": {"Code": "UnauthorizedOperation", "Message": "not authorized: arn:aws:iam::1:user/x"}}


class _FakeEc2:
    def can_paginate(self, _operation):
        return False

    def describe_subnets(self):
        return {"Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24"}]}

    def describe_instances(self):
        raise _Denied()

    def describe_customer_gateways(self):
        return {"CustomerGateways": [{"CustomerGatewayId": "cgw-1", "IpAddress": "52.5.5.5", "State": "available"}]}


class _FakeDx:
    def can_paginate(self, _operation):
        return False

    def describe_virtual_interfaces(self):
        return {
            "virtualInterfaces": [
                {"connectionId": "dxcon-1", "directConnectGatewayId": "dxgw-1", "virtualInterfaceState": "available"}
            ]
        }

    def describe_direct_connect_gateways(self):
        return {"directConnectGateways": [{"directConnectGatewayId": "dxgw-1", "directConnectGatewayName": "corp"}]}

    def describe_direct_connect_gateway_associations(self, directConnectGatewayId):
        assert directConnectGatewayId == "dxgw-1"
        return {
            "directConnectGatewayAssociations": [
                {"associatedGateway": {"id": "tgw-1", "type": "transitGateway"}, "associationState": "associated"}
            ]
        }


class _FakeSession:
    def client(self, name, **_kwargs):
        assert name == "directconnect"
        return _FakeDx()


def test_map_detail_skips_a_section_it_may_not_read():
    resources: list[dict] = []
    connections: list[dict] = []
    collectors_module._collect_aws_map_detail(_FakeSession(), _FakeEc2(), "us-east-1", None, resources, connections)
    by_type = {r["resource_type"]: r for r in resources}
    assert set(by_type) == {"subnet", "customer_gateway", "direct_connect_gateway", collect.WARNING_TYPE}
    warning = by_type[collect.WARNING_TYPE]
    # The AWS error code is kept; the message (which names the caller) is not.
    assert warning["metadata"] == {"section": "instances", "error": "UnauthorizedOperation"}
    assert "arn:aws" not in json.dumps(warning)
    assert {(c["source_resource_uid"], c["target_resource_uid"]) for c in connections} == {
        ("aws:direct_connect:dxcon-1", "aws:direct-connect-gateway:dxgw-1"),
        ("aws:direct-connect-gateway:dxgw-1", "aws:tgw:tgw-1"),
    }


# ── Snapshot ─────────────────────────────────────────────────────────────────


def _records() -> tuple[list[dict], list[dict]]:
    resources, connections = build_sample()
    return [{**r, "account_id": 1} for r in resources], [{**c, "account_id": 1} for c in connections]


@pytest.fixture(scope="module")
def snapshot() -> dict:
    resources, connections = _records()
    return build_snapshot([ACCOUNT], resources, connections)


def _node(snapshot: dict, node_id: str) -> dict:
    return next(n for n in snapshot["nodes"] if n["id"] == node_id)


def _section(entity: dict, title: str) -> dict:
    return next(s for s in entity["sections"] if s["title"] == title)


def test_snapshot_has_a_site_per_vpc_and_a_transit_box(snapshot):
    assert snapshot["provider"] == "aws" and snapshot["generated_at"] == ACCOUNT["last_sync_at"]
    assert snapshot["summary"]["sites"] == 3 and snapshot["summary"]["vlans"] == 7
    names = {s["id"]: s["name"] for s in snapshot["sites"]}
    assert names["vpc-0c0re00001"] == "prod-core-vpc (us-east-1)"
    assert TRANSIT_SITE_ID in names
    ids = {n["id"] for n in snapshot["nodes"]}
    assert all("x" in n and "y" in n for n in snapshot["nodes"])
    assert all(e["a"] in ids and e["b"] in ids for e in snapshot["edges"])


def test_snapshot_shows_only_instances_that_forward_traffic(snapshot):
    kinds = {n["id"]: n["kind"] for n in snapshot["nodes"]}
    assert kinds["i:i-0f7d001"] == "appliance" and kinds["i:i-0f7d002"] == "appliance"
    assert "i:i-0f3c001" not in kinds and "i:i-0a99001" not in kinds
    # ...but every instance is listed, and so searchable, in its VPC.
    edge = next(s for s in snapshot["sites"] if s["id"] == "vpc-0ed9e00002")
    assert [r[0] for r in _section(edge, "Instances")["rows"]] == ["fmc-01", "ftdv-ravpn-1", "ftdv-ravpn-2"]
    ftd = _node(snapshot, "i:i-0f7d001")
    assert ftd["ip"] == "10.210.2.11" and "203.0.113.11" in ftd["alias_ips"]
    assert len(_section(ftd, "Network interfaces")["rows"]) == 3


def test_snapshot_instance_in_inventory_becomes_a_node():
    resources, connections = _records()
    inventory = InventoryIndex([{"id": 9, "hostname": "fmc-01", "ip_address": "10.210.2.20", "device_type": "linux"}])
    snap = build_snapshot([ACCOUNT], resources, connections, inventory)
    fmc = _node(snap, "i:i-0f3c001")
    assert fmc["kind"] == "server" and fmc["inventory"]["host_id"] == 9


def test_snapshot_links_vpcs_gateways_and_vpn(snapshot):
    links = {(e["a"], e["b"]): e for e in snapshot["edges"]}
    tgw = "tgw:tgw-0910ba100001"
    assert links[("vpc:vpc-0c0re00001", tgw)]["kind"] == "attach"
    assert links[("vpc:vpc-0c0re00001", "vpc:vpc-0a9950003")]["status"] == "active"
    assert links[("igw:igw-0ed9e", "vpc:vpc-0ed9e00002")]["kind"] == "uplink"
    assert links[("dxgw:dxgw-0c0rp", tgw)]["kind"] == "attach"
    vpn = links[(tgw, "cgw:cgw-0d4c0001")]
    # One of the two tunnels is up, so the VPN carries traffic.
    assert vpn["kind"] == "vpn" and vpn["status"] == "reachable"
    gateway = _node(snapshot, tgw)
    assert gateway["endpoint_ips"] == ["203.0.113.101", "203.0.113.102"]
    row = _section(gateway, "VPN connections")["rows"][0]
    assert row[0] == "hq-datacenter-edge" and row[4] == "1 of 2 up"
    peer = _node(snapshot, "cgw:cgw-0d4c0001")
    assert peer["kind"] == "vpn_peer" and peer["ip"] == "198.51.100.10"


def test_snapshot_subnets_name_their_default_route(snapshot):
    edge = next(s for s in snapshot["sites"] if s["id"] == "vpc-0ed9e00002")
    rows = {r[1]: r for r in _section(edge, "Subnets")["rows"]}
    assert rows["edge-outside-a"][4:6] == ["edge-outside", "Internet gateway"]
    # The inside subnets leave through the firewall's interface.
    assert rows["edge-inside-a"][4:6] == ["edge-inside", "Appliance interface"]


def test_subnet_index_places_subnets_on_the_vpc_router(snapshot):
    index = {s["cidr"]: s for s in subnet_index(snapshot)}
    assert len(index) == 7
    inside = index["10.210.1.0/24"]
    # The VPC's router owns the subnet even though the VPC holds firewalls.
    assert inside["node_id"] == "vpc:vpc-0ed9e00002" and inside["kind"] == "subnet"
    assert inside["name"] == "edge-inside-a (us-east-1a)" and inside["site_name"] == "edge-security-vpc (us-east-1)"


def test_search_finds_an_instance_that_is_not_a_node(snapshot):
    index = build_search_index(snapshot)
    owner = next(e for e in index if "app-server-1" in e["blob"])
    assert owner["node_id"] == "vpc:vpc-0c0re00001"
    details = node_details(snapshot, "vpc:vpc-0c0re00001")
    assert details["provider"] == "aws" and any(s["title"] == "Subnets" for s in details["site_sections"])


def test_snapshot_reports_what_discovery_could_not_read():
    resources, connections = _records()
    resources.append({**collect.warning_resource("instances", "us-east-1", _Denied()), "account_id": 1})
    failed = {**ACCOUNT, "last_sync_status": "error", "last_sync_message": "Live provider discovery failed"}
    errors = build_snapshot([failed], resources, connections)["collection"]["errors"]
    assert [e["path"] for e in errors] == ["discovery", "instances (us-east-1)"]
    assert "UnauthorizedOperation" in errors[1]["message"]


def test_snapshot_keeps_an_attachment_to_a_vpc_it_did_not_collect():
    resources = [
        {"resource_uid": "aws:tgw:tgw-1", "resource_type": "transit_gateway", "name": "hub", "status": "available"},
        {"resource_uid": "aws:vpc:vpc-1", "resource_type": "vpc", "name": "a", "cidr": "10.1.0.0/16"},
    ]
    connections = [
        {"source_resource_uid": f"aws:vpc:{vpc}", "target_resource_uid": "aws:tgw:tgw-1",
         "connection_type": "transit_gateway_attachment", "state": state}
        for vpc, state in (("vpc-1", "available"), ("vpc-other", "failed"))
    ]  # fmt: skip
    snap = build_snapshot([ACCOUNT], resources, connections)
    stub = _node(snap, "x:vpc:vpc-other")
    assert stub["kind"] == "cloud" and stub["site"] == TRANSIT_SITE_ID
    statuses = {e["a"]: e["status"] for e in snap["edges"]}
    # A failed attachment stays on the map but is not routed through.
    assert statuses == {"vpc:vpc-1": "active", "x:vpc:vpc-other": "failed"}


def test_snapshot_of_nothing_is_empty():
    snap = build_snapshot([], [], [])
    assert snap["nodes"] == [] and snap["sites"] == [] and snap["summary"]["sites"] == 0


# ── Joining snapshots by public address ──────────────────────────────────────


def _n(node_id: str, kind: str, site: str = "s", **fields) -> dict:
    return {"id": node_id, "kind": kind, "site": site, "label": node_id, **fields}


def _merge(*snapshots: dict) -> tuple[dict, list[dict]]:
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(
        nodes,
        edges,
        list(enumerate(snapshots, start=1)),
        host_node=lambda _id: None,
        resolve_external=lambda *_: None,
    )
    return nodes, edges


def _pairs(edges: list[dict]) -> set[frozenset]:
    return {frozenset((e["from"], e["to"])) for e in edges}


BRANCH = {
    "provider": "meraki",
    "sites": [{"id": "s", "name": "Branch"}],
    "nodes": [_n("mx", "appliance"), _n("wan1", "wan", ip="8.8.4.4")],
    "edges": [{"id": "e1", "kind": "uplink", "a": "wan1", "b": "mx"}],
}


def test_merge_makes_a_customer_gateway_the_device_on_that_address():
    aws = {
        "provider": "aws",
        "sites": [],
        "nodes": [_n("tgw", "cloud"), _n("cgw", "vpn_peer", ip="8.8.4.4")],
        "edges": [{"id": "e1", "kind": "vpn", "a": "tgw", "b": "cgw", "status": "reachable"}],
    }
    nodes, edges = _merge(BRANCH, aws)
    # The customer gateway is the branch appliance: no separate peer node.
    assert "meraki:2:cgw" not in nodes
    tunnel = next(e for e in edges if e["provider"] == "aws")
    assert {tunnel["from"], tunnel["to"]} == {"meraki:2:tgw", "meraki:1:mx"} and tunnel["protocol"] == "vpn"


def test_merge_leaves_a_peer_on_a_private_address_alone():
    aws = {"provider": "aws", "sites": [], "nodes": [_n("cgw", "vpn_peer", ip="10.0.0.1")], "edges": []}
    lan = {**BRANCH, "nodes": [_n("mx", "appliance", ip="10.0.0.1")], "edges": []}
    nodes, _edges = _merge(lan, aws)
    assert "meraki:2:cgw" in nodes


def test_merge_recognises_a_virtual_appliance_by_its_public_address():
    aws = {
        "provider": "aws",
        "sites": [],
        "nodes": [_n("vpc", "vpc"), _n("i", "appliance", ip="10.1.0.5", alias_ips=["10.1.1.5", "8.8.4.4"])],
        "edges": [{"id": "e1", "kind": "attach", "a": "i", "b": "vpc", "status": "active"}],
    }
    nodes, edges = _merge(BRANCH, aws)
    # The instance is the appliance the other integration already shows.
    assert "meraki:2:i" not in nodes and nodes["meraki:1:mx"]["meraki"]["provider"] == "meraki"
    assert frozenset(("meraki:1:mx", "meraki:2:vpc")) in _pairs(edges)
    attach = next(e for e in edges if e["provider"] == "aws")
    assert attach["protocol"] == "cloud"


def test_merge_joins_a_vpn_seen_from_both_ends():
    # A site that names the AWS tunnel address as its IPsec peer, and a Cato
    # style site whose own address is the AWS tunnel address.
    meraki = {
        "provider": "meraki",
        "sites": [{"id": "s", "name": "Branch"}],
        "nodes": [_n("mx", "appliance"), _n("p:aws", "vpn_peer", ip="8.8.8.8")],
        "edges": [{"id": "e1", "kind": "vpn3p", "a": "mx", "b": "p:aws"}],
    }
    cato = {"provider": "cato", "sites": [], "nodes": [_n("s:9", "appliance", ip="1.1.1.1")], "edges": []}
    aws = {
        "provider": "aws",
        "sites": [],
        "nodes": [_n("tgw", "cloud", endpoint_ips=["8.8.8.8", "1.1.1.1"])],
        "edges": [],
    }
    nodes, edges = _merge(meraki, cato, aws)
    # The Meraki peer is the transit gateway; the Cato site gets a tunnel to it.
    assert "meraki:1:p:aws" not in nodes
    assert _pairs(edges) == {
        frozenset(("meraki:1:mx", "meraki:3:tgw")),
        frozenset(("meraki:2:s:9", "meraki:3:tgw")),
    }
    assert {e["protocol"] for e in edges} == {"vpn-ipsec", "vpn"}


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
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "aws.db"))
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-aws")
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


def _aws_nodes(api) -> list[dict]:
    graph = api.get("/api/topology").json()
    return [n for n in graph["nodes"] if (n.get("meraki") or {}).get("provider") == "aws"]


def test_api_discovered_aws_account_is_on_the_topology(api):
    assert _aws_nodes(api) == []
    account = api.post("/api/cloud/accounts", json={"provider": "aws", "name": "Prod AWS"}).json()["account"]
    # An account that was never discovered adds nothing.
    assert _aws_nodes(api) == []

    body = {"mode": "sample", "include_hybrid_links": False}
    assert api.post(f"/api/cloud/accounts/{account['id']}/discover", json=body).status_code == 200

    aws = _aws_nodes(api)
    assert {n["meraki"]["kind"] for n in aws} == {"vpc", "appliance", "wan", "cloud", "vpn_peer"}
    org_ref = aws[0]["meraki"]["org_ref"]
    assert org_ref < 0 and all(n["source"] == "meraki" for n in aws)
    graph = api.get("/api/topology").json()
    assert any(e.get("provider") == "aws" and e["protocol"] == "cloud" for e in graph["edges"])

    details = api.get(f"/api/meraki/nodes?org_ref={org_ref}&node_id=vpc:vpc-0c0re00001").json()
    assert details["provider"] == "aws" and details["site_name"] == "prod-core-vpc (us-east-1)"

    subnets = api.get("/api/meraki/subnets").json()["subnets"]
    db_subnet = next(s for s in subnets if s["cidr"] == "10.200.20.0/24")
    assert db_subnet["org_ref"] == org_ref and db_subnet["node_id"] == "vpc:vpc-0c0re00001"

    hits = api.get("/api/topology/search/deep?q=fmc-01").json()["results"]
    assert [(h["org_ref"], h["node_id"]) for h in hits] == [(org_ref, "vpc:vpc-0ed9e00002")]

    export = api.get("/api/topology/export.html")
    assert export.status_code == 200 and "prod-core-vpc" in export.text

    # Disabling the account takes it off the map; the discovery is kept.
    assert api.put(f"/api/cloud/accounts/{account['id']}", json={"enabled": False}).status_code == 200
    assert _aws_nodes(api) == []


def test_api_aws_shares_the_map_with_meraki_and_cato(api):
    account = api.post("/api/cloud/accounts", json={"provider": "aws", "name": "Prod AWS"}).json()["account"]
    api.post(f"/api/cloud/accounts/{account['id']}/discover", json={"mode": "sample", "include_hybrid_links": False})
    assert api.post("/api/meraki/sample").status_code == 201
    assert api.post("/api/meraki/sample?provider=cato").status_code == 201
    nodes = api.get("/api/topology").json()["nodes"]
    assert {(n.get("meraki") or {}).get("provider") for n in nodes if n.get("meraki")} == {"meraki", "cato", "aws"}
    # The snapshot history lists stored snapshots only; AWS has none of its own.
    assert all(s["org_ref"] > 0 for s in api.get("/api/meraki/snapshots").json()["snapshots"])


def test_api_aws_sample_is_a_cloud_visibility_account(api):
    built = api.post("/api/meraki/sample?provider=aws")
    assert built.status_code == 201, built.text
    assert built.json()["org_ref"] < 0 and built.json()["summary"]["sites"] == 3
    # Loading it again refreshes the same account.
    assert api.post("/api/meraki/sample?provider=aws").status_code == 201
    accounts = api.get("/api/cloud/accounts").json()["accounts"]
    assert [(a["provider"], a["auth_type"]) for a in accounts] == [("aws", "sample")]
    assert len({n["id"] for n in _aws_nodes(api)}) == 12
    # It is not an organization of the Meraki / Cato dialog.
    assert api.get("/api/meraki/orgs").json()["orgs"] == []


# ── The live collector, against a stand-in for boto3 ─────────────────────────


class _StubClient:
    """Answers every ``describe_*`` call from a table; anything else is empty."""

    def __init__(self, answers: dict):
        self._answers = answers

    def can_paginate(self, _operation):
        return False

    def get_caller_identity(self):
        return {"Account": "111122223333"}

    def __getattr__(self, operation):
        return lambda **_kwargs: self._answers.get(operation, {})


_EC2_ANSWERS = {
    "describe_vpcs": {"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.1.0.0/16", "State": "available"}]},
    "describe_transit_gateways": {"TransitGateways": [{"TransitGatewayId": "tgw-1", "State": "available"}]},
    "describe_transit_gateway_attachments": {
        "TransitGatewayAttachments": [
            {
                "TransitGatewayAttachmentId": "tgw-attach-1",
                "TransitGatewayId": "tgw-1",
                "ResourceType": "vpc",
                "ResourceId": "vpc-1",
                "State": "available",
            }
        ]
    },
    "describe_route_tables": {
        "RouteTables": [
            {
                "RouteTableId": "rtb-1",
                "VpcId": "vpc-1",
                "Associations": [{"Main": True}],
                "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "TransitGatewayId": "tgw-1", "State": "active"}],
            }
        ]
    },
    "describe_vpn_connections": {
        "VpnConnections": [
            {
                "VpnConnectionId": "vpn-1",
                "State": "available",
                "TransitGatewayId": "tgw-1",
                "CustomerGatewayId": "cgw-1",
                "CustomerGatewayConfiguration": "<pre_shared_key>TOP-SECRET-PSK</pre_shared_key>",
                "Options": {"TunnelOptions": [{"PreSharedKey": "TOP-SECRET-PSK"}]},
                "VgwTelemetry": [{"OutsideIpAddress": "52.9.9.9", "Status": "DOWN"}],
            }
        ]
    },
    "describe_subnets": {"Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.1.1.0/24"}]},
    "describe_customer_gateways": {
        "CustomerGateways": [{"CustomerGatewayId": "cgw-1", "IpAddress": "52.5.5.5", "State": "available"}]
    },
}


def _install_fake_boto3(monkeypatch):
    import sys
    import types

    class _Session:
        def __init__(self, **_kwargs):
            pass

        def client(self, name, **_kwargs):
            return _StubClient(_EC2_ANSWERS if name == "ec2" else {})

    boto3 = types.ModuleType("boto3")
    boto3.Session = _Session
    botocore = types.ModuleType("botocore")
    config = types.ModuleType("botocore.config")
    config.Config = lambda **_kwargs: None
    exceptions = types.ModuleType("botocore.exceptions")
    exceptions.BotoCoreError = type("BotoCoreError", (Exception,), {})
    exceptions.ClientError = type("ClientError", (Exception,), {})
    for name, module in (
        ("boto3", boto3),
        ("botocore", botocore),
        ("botocore.config", config),
        ("botocore.exceptions", exceptions),
    ):
        monkeypatch.setitem(sys.modules, name, module)


def test_live_collector_output_builds_the_map(monkeypatch):
    _install_fake_boto3(monkeypatch)
    resources, connections = collectors_module.collect_provider_snapshot(
        {"provider": "aws", "region_scope": "us-east-1", "auth_config_json": "{}"}
    )
    assert "TOP-SECRET-PSK" not in json.dumps([resources, connections])
    assert not any(r["resource_type"] == collect.WARNING_TYPE for r in resources)

    snap = build_snapshot(
        [ACCOUNT],
        [{**r, "account_id": 1} for r in resources],
        [{**c, "account_id": 1} for c in connections],
    )
    links = {(e["a"], e["b"]): e for e in snap["edges"]}
    assert links[("vpc:vpc-1", "tgw:tgw-1")]["status"] == "active"
    # Every tunnel of the VPN is down, so it is not routed through.
    assert links[("tgw:tgw-1", "cgw:cgw-1")]["status"] == "unreachable"
    assert [s["cidr"] for s in subnet_index(snap)] == ["10.1.1.0/24"]
    vpc = next(s for s in snap["sites"] if s["id"] == "vpc-1")
    assert _section(vpc, "Subnets")["rows"][0][4:6] == ["rtb-1", "Transit gateway"]
