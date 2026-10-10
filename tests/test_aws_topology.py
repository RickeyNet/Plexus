"""Tests for AWS in the Topology map.

Covers the pipeline with no AWS access:
  * collect     - reshaping EC2 items, secrets left behind, optional sections
  * normalize   - VPC sites, gateways, forwarding instances, VPNs, the report
  * subnets     - VPC subnets are owned by the VPC's router
  * unified     - snapshots of different integrations joined by public address
  * reachability - route tables, transit gateway route tables, peerings,
                  network ACLs and security groups decide a flow
  * HTTP API    - a discovered AWS account on /api/topology, node details,
                  subnets, deep search, HTML export
"""

from __future__ import annotations

import json

import netcontrol.app as app_module
import netcontrol.routes.cloud_collectors as collectors_module
import pytest
from netcontrol.integrations.aws import collect
from netcontrol.integrations.aws.normalize import TRANSIT_SITE_ID, build_snapshot
from netcontrol.integrations.aws.reachability import Reachability
from netcontrol.integrations.aws.sample import build_sample
from netcontrol.integrations.meraki.normalize import InventoryIndex
from netcontrol.integrations.meraki.subnets import subnet_index
from netcontrol.integrations.meraki.unified import (
    build_search_index,
    graph_to_snapshot,
    merge_meraki_into_graph,
    node_details,
    virtual_appliance_pairs,
)
from netcontrol.integrations.meraki.vpn_reach import VpnCarrier

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


def test_network_acl_resource_names_protocols_and_orders_rules():
    acl = {
        "NetworkAclId": "acl-1",
        "VpcId": "vpc-1",
        "IsDefault": False,
        "Associations": [{"SubnetId": "subnet-1"}],
        "Entries": [
            {"RuleNumber": 32767, "Egress": False, "RuleAction": "deny", "Protocol": "-1", "CidrBlock": "0.0.0.0/0"},
            {
                "RuleNumber": 100,
                "Egress": False,
                "RuleAction": "allow",
                "Protocol": "6",
                "CidrBlock": "10.0.0.0/8",
                "PortRange": {"From": 443, "To": 443},
            },
            {"RuleNumber": 100, "Egress": True, "RuleAction": "allow", "Protocol": "-1", "CidrBlock": "0.0.0.0/0"},
        ],
    }
    resource = collect.network_acl_resource(acl, "us-east-1")
    meta = resource["metadata"]
    assert resource["resource_uid"] == "aws:network_acl:acl-1" and meta["subnet_ids"] == ["subnet-1"]
    assert [(e["egress"], e["rule_number"], e["protocol"]) for e in meta["entries"]] == [
        (False, 100, "tcp"),
        (False, 32767, "all"),
        (True, 100, "all"),
    ]
    assert meta["entries"][0]["port_from"] == 443 and meta["entries"][1]["port_from"] is None


def test_transit_gateway_route_table_resource_keeps_where_each_route_goes():
    routes = [
        {
            "DestinationCidrBlock": "10.1.0.0/16",
            "State": "active",
            "Type": "propagated",
            "TransitGatewayAttachments": [
                {"TransitGatewayAttachmentId": "tgw-attach-1", "ResourceType": "vpc", "ResourceId": "vpc-1"}
            ],
        },
        {"DestinationCidrBlock": "10.9.0.0/16", "State": "blackhole", "Type": "static"},
    ]
    table = {"TransitGatewayRouteTableId": "tgw-rtb-1", "TransitGatewayId": "tgw-1", "State": "available"}
    resource = collect.transit_gateway_route_table_resource(table, routes, True, "us-east-1")
    meta = resource["metadata"]
    assert resource["resource_type"] == "transit_gateway_route_table" and meta["transit_gateway_id"] == "tgw-1"
    assert meta["truncated"] is True and meta["routes"][1] == {
        "destination": "10.9.0.0/16",
        "state": "blackhole",
        "type": "static",
        "attachments": [],
    }
    assert meta["routes"][0]["attachments"] == [
        {"attachment_id": "tgw-attach-1", "resource_type": "vpc", "resource_id": "vpc-1"}
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

    def describe_network_acls(self):
        return {"NetworkAcls": [{"NetworkAclId": "acl-1", "VpcId": "vpc-1", "Entries": []}]}

    def describe_transit_gateway_route_tables(self):
        return {"TransitGatewayRouteTables": [{"TransitGatewayRouteTableId": "tgw-rtb-1", "TransitGatewayId": "tgw-1"}]}

    def search_transit_gateway_routes(self, TransitGatewayRouteTableId, Filters, MaxResults):
        assert TransitGatewayRouteTableId == "tgw-rtb-1" and Filters[0]["Values"] == ["active", "blackhole"]
        return {"Routes": [{"DestinationCidrBlock": "10.1.0.0/16", "State": "active"}]}


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
    assert set(by_type) == {
        "subnet",
        "customer_gateway",
        "direct_connect_gateway",
        "network_acl",
        "transit_gateway_route_table",
        collect.WARNING_TYPE,
    }
    assert by_type["transit_gateway_route_table"]["metadata"]["routes"][0]["destination"] == "10.1.0.0/16"
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
    assert [r[0] for r in _section(edge, "Instances")["rows"]] == [
        "fmc-01",
        "ftdv-ravpn-1",
        "ftdv-ravpn-2",
        "pa-vm-edge-1",
    ]
    ftd = _node(snapshot, "i:i-0f7d001")
    assert ftd["ip"] == "10.210.2.11" and "203.0.113.11" in ftd["alias_ips"]
    assert len(_section(ftd, "Network interfaces")["rows"]) == 3


def test_snapshot_instance_in_inventory_becomes_a_node():
    resources, connections = _records()
    inventory = InventoryIndex([{"id": 9, "hostname": "fmc-01", "ip_address": "10.210.2.20", "device_type": "linux"}])
    snap = build_snapshot([ACCOUNT], resources, connections, inventory)
    fmc = _node(snap, "i:i-0f3c001")
    assert fmc["kind"] == "server" and fmc["inventory"]["host_id"] == 9
    assert fmc["instance_id"] == "i-0f3c001" and fmc["subnet"] == "edge-mgmt-a"
    assert "i:i-0f3c001" not in {n["id"] for n in snap["latent"]["nodes"]}


def test_inventory_index_matches_a_named_instance_before_any_address():
    named = {"id": 1, "hostname": "app1", "ip_address": "192.0.2.50", "aws_instance_id": " I-0A99001 "}
    by_address = {"id": 2, "hostname": "app-server-1", "ip_address": "10.200.10.21", "aws_instance_id": ""}
    index = InventoryIndex([named, by_address])
    # The host that names the instance wins over the one with its address, in any case.
    assert index.match(instance_id="i-0a99001", ips=["10.200.10.21"])["id"] == 1
    assert index.match(instance_id="I-0a99001")["id"] == 1
    # No instance ID (or one no host names): addresses as before.
    assert index.match(instance_id="", ips=["10.200.10.21"])["id"] == 2
    assert index.match(instance_id="i-0ffff01", ips=["10.200.10.21"])["id"] == 2
    # A host that names one instance is not some other instance sharing its address.
    assert index.match(instance_id="i-0ffff01", ips=["192.0.2.50"]) is None
    assert index.match(ips=["192.0.2.50"])["id"] == 1


def test_snapshot_instance_named_by_a_host_becomes_its_node():
    resources, connections = _records()
    host = {"id": 4, "hostname": "app1", "ip_address": "192.0.2.50", "aws_instance_id": "i-0a99001"}
    snap = build_snapshot([ACCOUNT], resources, connections, InventoryIndex([host]))
    app = _node(snap, "i:i-0a99001")
    assert app["kind"] == "server" and app["inventory"]["host_id"] == 4
    assert app["instance_id"] == "i-0a99001" and app["subnet"] == "core-app-a"
    overview = dict(_section(app, "Overview")["rows"])
    assert overview["Instance ID"] == "i-0a99001" and overview["Subnet"] == "core-app-a"
    assert snap["summary"]["inventory_matches"] == 1


def test_snapshot_keeps_the_instances_that_are_not_nodes_aside(snapshot):
    latent = {n["id"]: n for n in snapshot["latent"]["nodes"]}
    assert set(latent) == {"i:i-0f3c001", "i:i-0a99001", "i:i-0a99002"}
    fmc = latent["i:i-0f3c001"]
    assert fmc["kind"] == "server" and "inventory" not in fmc and fmc["ip"] == "10.210.2.20"
    assert fmc["instance_id"] == "i-0f3c001" and fmc["subnet"] == "edge-mgmt-a"
    assert dict(_section(fmc, "Overview")["rows"])["Subnet"] == "edge-mgmt-a"
    # Placed at its VPC, so it has somewhere to start when it is put on the map.
    vpc = _node(snapshot, "vpc:vpc-0ed9e00002")
    assert fmc["x"] == vpc["x"] and fmc["y"] > vpc["y"]
    links = {e["a"]: e for e in snapshot["latent"]["edges"]}
    assert links["i:i-0f3c001"]["b"] == "vpc:vpc-0ed9e00002" and links["i:i-0f3c001"]["kind"] == "attach"
    assert links["i:i-0a99001"]["b"] == "vpc:vpc-0c0re00001" and links["i:i-0a99001"]["sections"]
    # Not on the map: not in the nodes, the counts or the search.
    assert not set(latent) & {n["id"] for n in snapshot["nodes"]}
    assert snapshot["summary"]["devices_by_kind"].get("server", 0) == 0
    assert node_details(snapshot, "i:i-0f3c001")["provider"] == "aws"
    # Forwarding instances say which instance they are too.
    ftd = _node(snapshot, "i:i-0f7d001")
    assert ftd["instance_id"] == "i-0f7d001" and ftd["subnet"] == "edge-mgmt-a"
    assert dict(_section(ftd, "Overview")["rows"])["Subnet"] == "edge-mgmt-a"


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


def test_snapshot_lists_network_acls_and_transit_gateway_routes(snapshot):
    core = next(s for s in snapshot["sites"] if s["id"] == "vpc-0c0re00001")
    rows = {r[1]: r for r in _section(core, "Subnets")["rows"]}
    assert rows["core-db-a"][7] == "core-db" and rows["core-app-a"][7] == "core-default"
    acl = [r for r in _section(core, "Network ACL rules")["rows"] if r[0] == "core-db"]
    assert acl[0][1:7] == ["inbound", "100", "allow", "tcp", "5432", "10.200.0.0/16"]
    # The rule that ends every ACL is shown the way the AWS console shows it.
    assert ["inbound", "*", "deny"] in [r[1:4] for r in acl]
    routes = _section(_node(snapshot, "tgw:tgw-0910ba100001"), "Transit gateway routes")["rows"]
    assert ["global-main", "10.10.0.0/16", "tgw-attach-0d4c0", "vpn-0d4c0001", "active", "propagated"] in routes


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
    # A VPC Plexus does not collect is still drawn as a VPC, in a box of its own.
    assert stub["kind"] == "vpc" and stub["site"] == "vpc-other" and stub["model"] == "AWS VPC (not collected)"
    site = next(s for s in snap["sites"] if s["id"] == "vpc-other")
    assert site["name"] == "vpc-other (not collected)"
    assert snap["summary"]["sites"] == 1 and snap["summary"]["devices_by_kind"] == {"vpc": 1}
    statuses = {e["a"]: e["status"] for e in snap["edges"]}
    # A failed attachment stays on the map but is not routed through.
    assert statuses == {"vpc:vpc-1": "active", "x:vpc:vpc-other": "failed"}


def _peered_vpc(**account: str) -> tuple[dict, dict]:
    """A collected VPC peered with one of another account, and the snapshot."""
    resources = [
        {"resource_uid": "aws:vpc:vpc-1", "resource_type": "vpc", "name": "core", "cidr": "172.30.0.0/16"},
        {"resource_uid": "aws:route_table:rtb-1", "resource_type": "route_table", "name": "main",
         "metadata": {"vpc_id": "vpc-1", "routes": [
             {"destination": "10.7.1.0/24", "target": "pcx-1", "state": "active"},
             {"destination": "0.0.0.0/0", "target": "igw-1", "state": "active"},
         ]}},
    ]  # fmt: skip
    peering = {
        "source_resource_uid": "aws:vpc:vpc-far",
        "target_resource_uid": "aws:vpc:vpc-1",
        "connection_type": "vpc_peering",
        "state": "active",
        "metadata": {
            "peering_id": "pcx-1",
            "requester_cidr": "10.7.1.0/24",
            "requester_cidrs": ["10.7.1.0/24", "10.7.2.0/24"],
            "requester_owner_id": "222222222222",
            "requester_region": "us-east-2",
            "accepter_cidr": "172.30.0.0/16",
            "accepter_owner_id": "111111111111",
            "accepter_region": "us-east-1",
        },
    }
    accounts = [{**ACCOUNT, "account_identifier": "111111111111", "region_scope": "all", **account}]
    snap = build_snapshot(accounts, resources, [peering])
    return _node(snap, "x:vpc:vpc-far"), snap


def test_a_peered_vpc_not_collected_shows_what_its_peering_records():
    stub, snap = _peered_vpc()
    assert stub["model"] == "AWS VPC 10.7.1.0/24, 10.7.2.0/24 (not collected)"
    overview = dict(_section(stub, "Overview")["rows"])
    assert overview["Region"] == "us-east-2" and overview["Account"] == "222222222222"
    assert overview["Not collected"].startswith("Account 222222222222 is not added to Cloud Visibility")
    site = next(s for s in snap["sites"] if s["id"] == "vpc-far")
    assert site["name"] == "vpc-far (us-east-2, not collected)" and site["tags"] == ["us-east-2", "222222222222"]
    details = node_details(snap, "x:vpc:vpc-far")
    by_title = {s["title"]: s["rows"] for s in details["site_sections"]}
    assert by_title["VPC peerings"] == [
        ["pcx-1", "core", "172.30.0.0/16", "us-east-1", "Prod (111111111111)", "active"]
    ]
    # Only the routes over the peering, not the VPC's other routes.
    assert by_title["Routes to this VPC"] == [["core", "main", "10.7.1.0/24", "pcx-1", "active"]]
    # The collected VPC lists the peering from its side.
    core = next(s for s in snap["sites"] if s["id"] == "vpc-1")
    peerings = next(s for s in core["sections"] if s["title"] == "VPC peerings")["rows"]
    assert peerings == [["pcx-1", "vpc-far", "10.7.1.0/24, 10.7.2.0/24", "us-east-2", "222222222222", "active"]]
    assert snap["summary"]["devices_by_kind"] == {"vpc": 1}


def test_a_peered_vpc_not_collected_says_why():
    stub, _snap = _peered_vpc(account_identifier="222222222222", region_scope="us-east-1, us-west-2")
    reason = dict(_section(stub, "Overview")["rows"])["Not collected"]
    assert reason.startswith("Region us-east-2 is not among the regions Prod discovers")
    stub, _snap = _peered_vpc(account_identifier="222222222222", region_scope="all")
    assert dict(_section(stub, "Overview")["rows"])["Not collected"].startswith("Prod has not discovered it yet")


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
    # The AWS view of the map shows it too, on the page and in the HTML export.
    assert nodes["meraki:1:mx"]["also_providers"] == ["aws"]
    export = graph_to_snapshot({"nodes": list(nodes.values()), "edges": edges}, {}, {})
    exported = {n["id"]: n for n in export["nodes"]}
    assert exported["meraki:1:mx"]["provider"] == "meraki" and exported["meraki:1:mx"]["also_providers"] == ["aws"]
    assert "also_providers" not in exported["meraki:2:tgw"]


def test_merge_leaves_a_peer_on_a_private_address_alone():
    aws = {"provider": "aws", "sites": [], "nodes": [_n("cgw", "vpn_peer", ip="10.0.0.1")], "edges": []}
    lan = {**BRANCH, "nodes": [_n("mx", "appliance", ip="10.0.0.1")], "edges": []}
    nodes, _edges = _merge(lan, aws)
    assert "meraki:2:cgw" in nodes
    assert "also_providers" not in nodes["meraki:1:mx"]


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
    assert nodes["meraki:1:mx"]["also_providers"] == ["aws"]
    assert frozenset(("meraki:1:mx", "meraki:2:vpc")) in _pairs(edges)
    attach = next(e for e in edges if e["provider"] == "aws")
    assert attach["protocol"] == "cloud"


def test_merge_recognises_a_virtual_appliance_whichever_snapshot_comes_first():
    aws = {
        "provider": "aws",
        "sites": [],
        "nodes": [_n("vpc", "vpc"), _n("i", "appliance", ip="10.1.0.5", alias_ips=["8.8.4.4"])],
        "edges": [{"id": "e1", "kind": "attach", "a": "i", "b": "vpc", "status": "active"}],
    }
    nodes, edges = _merge(aws, BRANCH)
    assert "meraki:1:i" not in nodes
    assert frozenset(("meraki:2:mx", "meraki:1:vpc")) in _pairs(edges)


def test_merge_keeps_the_instance_of_a_host_another_integration_drew_first():
    host = {"id": 5, "label": "fw-1", "in_inventory": True}
    meraki = {**BRANCH, "nodes": [_n("mx", "appliance", inventory={"host_id": 5})], "edges": []}
    aws = {
        "provider": "aws",
        "sites": [{"id": "vpc-1", "name": "core (us-east-1)"}],
        "nodes": [
            _n("vpc:vpc-1", "vpc", site="vpc-1"),
            _n("i:i-1", "server", site="vpc-1", ip="10.0.0.5", alias_ips=[], instance_id="i-1", subnet="app-a",
               inventory={"host_id": 5}),
        ],
        "edges": [{"id": "e1", "kind": "attach", "a": "i:i-1", "b": "vpc:vpc-1", "status": "active"}],
    }  # fmt: skip
    nodes: dict = {5: host}
    edges: list[dict] = []
    merge_meraki_into_graph(
        nodes,
        edges,
        [(1, meraki), (2, aws)],
        host_node=lambda host_id: nodes.get(host_id),
        resolve_external=lambda *_: None,
    )
    # The host is the Meraki appliance; AWS says which instance it is all the same.
    assert host["meraki"]["provider"] == "meraki" and host["also_providers"] == ["aws"]
    assert host["instance"] == {
        "provider": "aws",
        "id": "i-1",
        "subnet": "app-a",
        "vpc": "core (us-east-1)",
        "org_ref": 2,
        "node_id": "i:i-1",
    }
    assert frozenset((5, "meraki:2:vpc:vpc-1")) in _pairs(edges)
    # A node AWS draws itself carries it on its reference and beside it.
    alone, _edges = _merge(aws)
    instance = alone["meraki:1:i:i-1"]
    assert instance["meraki"]["instance_id"] == "i-1" and instance["meraki"]["subnet"] == "app-a"
    assert instance["instance"]["id"] == "i-1" and instance["instance"]["vpc"] == "core (us-east-1)"
    assert "instance" not in alone["meraki:1:vpc:vpc-1"] and "instance_id" not in alone["meraki:1:vpc:vpc-1"]["meraki"]


def _uplink(node_id: str, public: str, inside: str) -> dict:
    """A WAN uplink known by ``public`` whose own interface has ``inside``."""
    section = {"title": "WAN uplink", "kind": "kv", "rows": [["Interface", "wan1"], ["IP", inside]]}
    return _n(node_id, "wan", ip=public, sections=[section])


def _behind_nat(model: str, public: str = "8.8.4.4", inside: str = "10.1.0.5") -> dict:
    return {
        "provider": "meraki",
        "sites": [{"id": "s", "name": "AWS hub"}],
        "nodes": [_n("vmx", "appliance", model=model), _uplink("wan1", public, inside)],
        "edges": [{"id": "e1", "kind": "uplink", "a": "wan1", "b": "vmx"}],
    }


def _vpc_with(*instances: dict, nat: str = "8.8.4.4") -> dict:
    return {
        "provider": "aws",
        "sites": [],
        "nodes": [_n("vpc", "vpc"), _n("nat", "cloud", ip=nat), *instances],
        "edges": [{"id": f"e{i}", "kind": "attach", "a": n["id"], "b": "vpc"} for i, n in enumerate(instances)],
    }


def test_merge_recognises_a_virtual_appliance_behind_a_nat_gateway():
    # In a private subnet the vMX has no public address: Meraki knows it by
    # the NAT gateway's address, AWS by its private one.
    aws = _vpc_with(_n("i", "appliance", ip="10.1.0.5", alias_ips=[]))
    nodes, edges = _merge(_behind_nat("VMX-M"), aws)
    assert "meraki:2:i" not in nodes and nodes["meraki:1:vmx"]["meraki"]["provider"] == "meraki"
    assert frozenset(("meraki:1:vmx", "meraki:2:vpc")) in _pairs(edges)
    # Any appliance is accepted when its public address is the VPC's NAT gateway...
    assert virtual_appliance_pairs([(1, _behind_nat("Z3")), (2, aws)]) == {(2, "i"): (1, "vmx")}
    # ...and a virtual model when the NAT in front of it is not in the VPC.
    elsewhere = _vpc_with(_n("i", "appliance", ip="10.1.0.5", alias_ips=[]), nat="8.8.8.8")
    assert virtual_appliance_pairs([(1, _behind_nat("vMX100")), (2, elsewhere)]) == {(2, "i"): (1, "vmx")}


def test_merge_does_not_join_devices_that_only_share_a_private_address():
    instance = _n("i", "appliance", ip="10.1.0.5", alias_ips=[])
    # A branch appliance behind some other NAT happens to use the address.
    assert virtual_appliance_pairs([(1, _behind_nat("MX68")), (2, _vpc_with(instance, nat="8.8.8.8"))]) == {}
    # Two forwarding instances (overlapping VPCs) hold it: neither is picked.
    twin = _n("i2", "appliance", ip="10.1.0.5", alias_ips=[])
    assert virtual_appliance_pairs([(1, _behind_nat("VMX-M")), (2, _vpc_with(instance, twin))]) == {}
    # Two uplinks have it: the instance could be either device.
    assert (
        virtual_appliance_pairs([(1, _behind_nat("VMX-M")), (3, _behind_nat("VMX-M")), (2, _vpc_with(instance))]) == {}
    )
    # An instance that does not forward traffic is not an appliance.
    server = _n("i", "server", ip="10.1.0.5", alias_ips=[])
    assert virtual_appliance_pairs([(1, _behind_nat("VMX-M")), (2, _vpc_with(server))]) == {}


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


# ── Reachability: what AWS does with a flow ─────────────────────────────────

APP, DB, FIREWALL = "10.200.10.21", "10.200.20.31", "10.210.1.11"


@pytest.fixture(scope="module")
def reach() -> Reachability:
    return Reachability(*_records())


def _blocked_at(result: dict) -> list[str]:
    return [f"{s['direction']} {s['stage']}" for s in result["steps"] if s["status"] == "blocked"]


def test_reachability_allows_what_routes_acls_and_groups_all_allow(reach):
    result = reach.check(APP, DB, protocol="tcp", port=5432)
    assert result["verdict"] == "allowed" and result["traffic"] == "tcp/5432"
    assert {s["status"] for s in result["steps"]} == {"ok"}
    # Both directions are routed, both ACLs are matched both ways, and the
    # stateful security groups once.
    assert [(s["direction"], s["stage"]) for s in result["steps"]] == [
        ("forward", "route"),
        ("forward", "acl"),
        ("forward", "acl"),
        ("forward", "security_group"),
        ("forward", "security_group"),
        ("return", "route"),
        ("return", "acl"),
        ("return", "acl"),
    ]
    # The database's group names the application servers' group, not a CIDR.
    assert "sg:sg-0c0re0a1" in result["steps"][4]["text"]


def test_reachability_blocks_a_port_the_acl_and_group_do_not_open(reach):
    result = reach.check(APP, DB, protocol="tcp", port=22)
    assert result["verdict"] == "blocked"
    assert _blocked_at(result) == ["forward acl", "forward security_group"]
    assert "core-db" in result["summary"] and "final deny" in result["summary"]


def test_reachability_of_any_traffic_is_partial_when_only_some_ports_are_open(reach):
    result = reach.check("10.200.10.0/24", "10.200.20.0/24")
    assert result["verdict"] == "partial" and result["traffic"] == "any traffic"
    partial = next(s for s in result["steps"] if s["status"] == "partial")
    assert "rule 100, rule 120 allow part of it" in partial["text"]
    # Whole subnets have no security groups to check, and the result says so.
    assert [s["stage"] for s in result["steps"] if s["status"] == "info"] == ["security_group", "security_group"]


def test_reachability_follows_the_transit_gateway_route_table_both_ways(reach):
    result = reach.check(APP, FIREWALL, protocol="tcp", port=443)
    assert result["verdict"] == "allowed"
    transit = [s["text"] for s in result["steps"] if s["stage"] == "transit"]
    assert "10.210.0.0/16 via attachment tgw-attach-0ed9e" in transit[0]
    assert "10.200.0.0/16 via attachment tgw-attach-0c0re" in transit[1]
    blackhole = reach.check(APP, "10.99.1.1")
    assert blackhole["verdict"] == "blocked" and "blackhole" in blackhole["summary"]


def test_reachability_leaves_and_enters_aws_over_the_vpn(reach):
    out = reach.check("10.200.10.0/24", "10.10.5.0/24")
    assert out["verdict"] == "allowed" and out["destination"]["in_aws"] is False
    assert any("leaves AWS over VPN hq-datacenter-vpn" in s["text"] for s in out["steps"])
    # From the datacenter the route and the ACL let the flow in; the
    # database's security group does not know the address.
    inbound = reach.check("10.10.5.9", DB, protocol="tcp", port=5432)
    assert inbound["verdict"] == "blocked" and _blocked_at(inbound) == ["forward security_group"]
    assert inbound["steps"][0]["text"].startswith("Enters AWS over VPN")


def test_reachability_stops_when_every_tunnel_of_the_vpn_is_down():
    resources, connections = _records()
    vpn = next(r for r in resources if r["resource_type"] == "vpn_connection")
    for tunnel in vpn["metadata"]["tunnels"]:
        tunnel["status"] = "DOWN"
    result = Reachability(resources, connections).check("10.200.10.0/24", "10.10.5.0/24")
    assert result["verdict"] == "blocked" and "every tunnel of that VPN is down" in result["summary"]


def test_reachability_uses_a_peering_only_between_its_two_vpcs(reach):
    assert reach.check("10.200.11.0/24", "10.220.1.0/24", protocol="icmp")["verdict"] == "allowed"
    # The edge VPC has no peering with apps-west: its 10.0.0.0/8 route sends
    # the traffic to the transit gateway, whose only route for it is the
    # default one back into the edge VPC.
    result = reach.check("10.210.2.20", "10.220.1.10")
    assert result["verdict"] != "allowed"


def test_reachability_through_gateways_to_the_internet(reach):
    assert reach.check(APP, "8.8.8.8", protocol="tcp", port=443)["verdict"] == "allowed"
    # A NAT gateway takes no connection from outside; an internet gateway
    # does, for an instance that has a public address.
    assert reach.check("8.8.8.8", APP, protocol="tcp", port=443)["verdict"] == "blocked"
    assert reach.check("8.8.8.8", "10.210.0.11", protocol="tcp", port=443)["verdict"] == "allowed"
    # A route to a firewall's interface ends what AWS can tell.
    appliance = reach.check("10.210.1.0/24", "8.8.8.8")
    assert appliance["verdict"] == "unknown" and "ftdv-ravpn-1" in appliance["summary"]


def test_reachability_does_not_guess_what_was_not_collected():
    resources, connections = _records()
    kept = [r for r in resources if r["resource_type"] not in ("network_acl", "transit_gateway_route_table")]
    old = Reachability(kept, connections)
    acl = old.check(APP, DB, protocol="tcp", port=5432)
    assert acl["verdict"] == "unknown" and "ec2:DescribeNetworkAcls" in acl["summary"]
    transit = old.check(APP, FIREWALL, protocol="tcp", port=443)
    assert any(s["stage"] == "transit" and s["status"] == "unknown" for s in transit["steps"])


def test_reachability_needs_the_vpc_of_a_range_that_exists_twice():
    resources, connections = _records()
    twin = {"resource_uid": "aws:vpc:vpc-twin", "resource_type": "vpc", "name": "twin", "cidr": "10.200.0.0/16"}
    subnet = {
        "resource_uid": "aws:subnet:subnet-twin",
        "resource_type": "subnet",
        "cidr": "10.200.10.0/24",
        "metadata": {"vpc_id": "vpc-twin"},
    }
    reach = Reachability([*resources, twin, subnet], connections)
    vague = reach.check(APP, DB)
    assert vague["verdict"] == "unknown" and "several VPCs" in vague["summary"] and vague["steps"] == []
    assert reach.check(APP, DB, source_vpc="vpc-0c0re00001", protocol="tcp", port=5432)["verdict"] == "allowed"
    with pytest.raises(ValueError):
        reach.check("not-an-address", DB)
    with pytest.raises(ValueError):
        reach.check(APP, DB, protocol="gre")


# ── Reachability through a Meraki vMX ────────────────────────────────────────

VMX, BRANCH_HOST = "i-0f0e0vmx", "10.50.1.20"


def _table(title: str, rows: list[list[str]]) -> dict:
    return {"title": title, "kind": "table", "rows": rows}


def _meraki_org(*, tunnel: str = "reachable", branch_in_vpn: str = "Yes", hub_subnets: list[list[str]] | None = None):
    """A vMX hub in AWS and one branch whose VLAN 10 is 10.50.1.0/24."""
    hub = hub_subnets if hub_subnets is not None else [["10.200.0.0/16", "Yes", ""]]
    return {
        "provider": "meraki",
        "sites": [
            {"id": "hub", "name": "AWS hub", "sections": [_table("VPN local subnets", hub)]},
            {
                "id": "br",
                "name": "Branch 12",
                "sections": [
                    _table("VLANs", [["10", "Users", "10.50.1.0/24"]]),
                    _table("VPN local subnets", [["10.50.1.0/24", branch_in_vpn, ""]]),
                ],
            },
        ],
        "nodes": [
            _n("vmx", "appliance", "hub", label="aws-vmx", model="VMX-M"),
            _n("mx", "appliance", "br", label="branch-mx", model="MX68"),
        ],
        "edges": [{"id": "e1", "kind": "vpn", "a": "vmx", "b": "mx", "status": tunnel}],
    }


def _reach_with_vmx() -> Reachability:
    """The sample account with a vMX in the application subnet that the
    VPC's route table sends the branch ranges to."""
    resources, connections = _records()
    table = next(r for r in resources if r["resource_uid"] == "aws:route_table:rtb-0c0re")
    table["metadata"]["routes"].append(
        {"destination": "10.50.0.0/16", "target": "eni-0f0e0vmx0", "state": "active", "origin": "CreateRoute"}
    )
    resources.append(
        {
            "resource_uid": f"aws:instance:{VMX}",
            "resource_type": "instance",
            "name": "aws-vmx",
            "status": "running",
            "metadata": {
                "vpc_id": "vpc-0c0re00001",
                "private_ip": "10.200.10.50",
                "source_dest_check": False,
                "interfaces": [{"id": "eni-0f0e0vmx0", "subnet_id": "subnet-0c0re0a", "private_ips": ["10.200.10.50"]}],
            },
        }
    )
    return Reachability(resources, connections)


def test_reachability_stops_at_an_appliance_it_knows_nothing_about():
    result = _reach_with_vmx().check(APP, BRANCH_HOST, protocol="tcp", port=443)
    assert result["verdict"] == "unknown" and "aws-vmx" in result["summary"]


def test_reachability_goes_on_through_a_meraki_vmx():
    reach = _reach_with_vmx()
    carriers = {VMX: VpnCarrier(_meraki_org(), "vmx")}
    result = reach.check(APP, BRANCH_HOST, protocol="tcp", port=443, carriers=carriers)
    assert result["verdict"] == "allowed", result["summary"]
    vpn = [s for s in result["steps"] if s["stage"] == "vpn"]
    assert [s["status"] for s in vpn] == ["ok", "ok"] and vpn[0]["where"].startswith("Meraki VMX-M aws-vmx")
    assert "10.50.1.0/24 at Branch 12 is reached over AutoVPN: aws-vmx → branch-mx" in vpn[0]["text"]
    assert "advertises 10.200.10.21/32 into AutoVPN" in vpn[1]["text"]
    # The reply comes back in at the vMX, which is in the application subnet.
    back = [s["text"] for s in result["steps"] if s["direction"] == "return"]
    assert back[0].startswith("Enters AWS at instance aws-vmx") and back[1].startswith("Same subnet")

    # Opened from the branch, the same VPN is checked once and the
    # application servers' security group decides.
    inbound = reach.check(BRANCH_HOST, APP, protocol="tcp", port=443, carriers=carriers)
    assert inbound["verdict"] == "allowed" and len([s for s in inbound["steps"] if s["stage"] == "vpn"]) == 2
    assert reach.check(BRANCH_HOST, APP, protocol="tcp", port=3389, carriers=carriers)["verdict"] == "blocked"


def test_reachability_through_a_vmx_follows_what_meraki_reports():
    reach = _reach_with_vmx()

    def verdict(org: dict, destination: str = BRANCH_HOST) -> tuple[str, str]:
        result = reach.check(APP, destination, protocol="tcp", port=443, carriers={VMX: VpnCarrier(org, "vmx")})
        return result["verdict"], result["summary"]

    down = verdict(_meraki_org(tunnel="unreachable"))
    assert down[0] == "blocked" and "No AutoVPN tunnel that is up joins the appliance to Branch 12" in down[1]
    hidden = verdict(_meraki_org(branch_in_vpn="No"))
    assert hidden[0] == "blocked" and "not advertised into the VPN at Branch 12" in hidden[1]
    excluded = verdict(_meraki_org(hub_subnets=[["10.200.0.0/16", "No", ""]]))
    assert excluded[0] == "blocked" and "excluded from the VPN" in excluded[1]
    # Not advertised is not a block: a full-tunnel spoke still routes there.
    unlisted = verdict(_meraki_org(hub_subnets=[["10.210.0.0/16", "Yes", ""]]))
    assert unlisted[0] == "unknown" and "default route" in unlisted[1]
    # An address no Meraki site owns is not guessed at.
    stranger = verdict(_meraki_org(), "10.50.9.9")
    assert stranger[0] == "unknown" and "not a subnet of a site" in stranger[1]


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
    assert db_subnet["provider"] == "aws" and db_subnet["site_id"] == "vpc-0c0re00001"

    check = "/api/meraki/aws/reachability?source=10.200.10.21&destination=10.200.20.31&protocol=tcp"
    allowed = api.get(f"{check}&port=5432&source_vpc=vpc-0c0re00001").json()
    assert allowed["applies"] and allowed["verdict"] == "allowed" and allowed["traffic"] == "tcp/5432"
    assert api.get(f"{check}&port=22").json()["verdict"] == "blocked"
    assert api.get("/api/meraki/aws/reachability?source=nope&destination=10.200.20.31").status_code == 400
    assert api.get("/api/meraki/aws/reachability?source=192.0.2.1&destination=192.0.2.2").json()["applies"] is False

    hits = api.get("/api/topology/search/deep?q=fmc-01").json()["results"]
    assert [(h["org_ref"], h["node_id"]) for h in hits] == [(org_ref, "vpc:vpc-0ed9e00002")]

    export = api.get("/api/topology/export.html")
    assert export.status_code == 200 and "prod-core-vpc" in export.text

    # Disabling the account takes it off the map; the discovery is kept.
    assert api.put(f"/api/cloud/accounts/{account['id']}", json={"enabled": False}).status_code == 200
    assert _aws_nodes(api) == []


def test_api_a_host_added_after_discovery_is_its_instance_on_the_map(api):
    import netcontrol.routes.meraki_topology as routes_module
    from netcontrol.routes.topology import invalidate_topology_cache

    account = api.post("/api/cloud/accounts", json={"provider": "aws", "name": "Prod AWS"}).json()["account"]
    api.post(f"/api/cloud/accounts/{account['id']}/discover", json={"mode": "sample", "include_hybrid_links": False})
    # The AWS snapshot is built (and cached) before the hosts exist.
    aws = _aws_nodes(api)
    org_ref = aws[0]["meraki"]["org_ref"]
    assert not {"i:i-0f3c001", "i:i-0a99001"} & {n["meraki"]["node_id"] for n in aws}

    group = api.post("/api/inventory", json={"name": "Cloud"}).json()["id"]
    by_address = {"hostname": "fmc-01", "ip_address": "10.210.2.20", "device_type": "linux"}
    fmc = api.post(f"/api/inventory/{group}/hosts", json=by_address)
    assert fmc.status_code == 201, fmc.text
    # An address AWS does not know, but the instance named outright (in upper case).
    named = {"hostname": "app1", "ip_address": "192.0.2.50", "device_type": "linux", "aws_instance_id": "I-0A99001"}
    app = api.post(f"/api/inventory/{group}/hosts", json=named)
    assert app.status_code == 201, app.text
    bad = api.post(f"/api/inventory/{group}/hosts", json={**named, "ip_address": "192.0.2.51", "aws_instance_id": "x"})
    assert bad.status_code == 422 and "AWS instance ID" in bad.json()["error"]["message"]

    invalidate_topology_cache()
    graph = api.get("/api/topology").json()
    nodes = {n["id"]: n for n in graph["nodes"]}
    vpcs = {"fmc-01": "vpc:vpc-0ed9e00002", "app1": "vpc:vpc-0c0re00001"}
    expected = {
        "fmc-01": ("i-0f3c001", "edge-mgmt-a", "edge-security-vpc (us-east-1)"),
        "app1": ("i-0a99001", "core-app-a", "prod-core-vpc (us-east-1)"),
    }
    for host_id, hostname in ((fmc.json()["id"], "fmc-01"), (app.json()["id"], "app1")):
        node = nodes[host_id]
        instance_id, subnet, vpc = expected[hostname]
        assert node["in_inventory"] and node["meraki"]["provider"] == "aws"
        assert node["meraki"]["instance_id"] == instance_id and node["meraki"]["subnet"] == subnet
        assert node["instance"] == {
            "provider": "aws",
            "id": instance_id,
            "subnet": subnet,
            "vpc": vpc,
            "org_ref": org_ref,
            "node_id": f"i:{instance_id}",
        }
        vpc_id = f"meraki:{org_ref}:{vpcs[hostname]}"
        assert any({e["from"], e["to"]} == {host_id, vpc_id} and e["protocol"] == "cloud" for e in graph["edges"])

    # Its details, though the cached snapshot has no node for it.
    details = api.get(f"/api/meraki/nodes?org_ref={org_ref}&node_id=i:i-0f3c001")
    assert details.status_code == 200, details.text
    assert details.json()["provider"] == "aws"
    overview = dict(next(s for s in details.json()["sections"] if s["title"] == "Overview")["rows"])
    assert overview["Subnet"] == "edge-mgmt-a" and overview["Instance ID"] == "i-0f3c001"
    cached = routes_module._SNAPSHOT_CACHE[org_ref]["snapshot"]
    assert "i:i-0f3c001" not in {n["id"] for n in cached["nodes"]}

    # The ID is stored as entered (trimmed), and an edit is checked like an add.
    host_id = fmc.json()["id"]
    edit = {**by_address, "aws_instance_id": "foo"}
    rejected = api.put(f"/api/hosts/{host_id}", json=edit)
    assert rejected.status_code == 422 and "AWS instance ID" in rejected.json()["error"]["message"]
    assert api.put(f"/api/hosts/{host_id}", json={**edit, "aws_instance_id": " i-0f3c001 "}).status_code == 200
    assert api.put(f"/api/hosts/{app.json()['id']}", json={**named}).status_code == 200
    stored = {h["hostname"]: h["aws_instance_id"] for h in api.get(f"/api/inventory/{group}/hosts").json()}
    assert stored == {"fmc-01": "i-0f3c001", "app1": "I-0A99001"}
    # Leaving it out of an edit leaves it alone; an empty one clears it.
    assert api.put(f"/api/hosts/{host_id}", json=by_address).status_code == 200
    assert api.put(f"/api/hosts/{app.json()['id']}", json={**named, "aws_instance_id": ""}).status_code == 200
    stored = {h["hostname"]: h["aws_instance_id"] for h in api.get(f"/api/inventory/{group}/hosts").json()}
    assert stored == {"fmc-01": "i-0f3c001", "app1": ""}


def test_api_aws_shares_the_map_with_meraki_and_cato(api):
    account = api.post("/api/cloud/accounts", json={"provider": "aws", "name": "Prod AWS"}).json()["account"]
    api.post(f"/api/cloud/accounts/{account['id']}/discover", json={"mode": "sample", "include_hybrid_links": False})
    assert api.post("/api/meraki/sample").status_code == 201
    assert api.post("/api/meraki/sample?provider=cato").status_code == 201
    nodes = api.get("/api/topology").json()["nodes"]
    assert {(n.get("meraki") or {}).get("provider") for n in nodes if n.get("meraki")} == {"meraki", "cato", "aws"}
    # The AWS check looks for virtual appliances among every snapshot.
    check = api.get("/api/meraki/aws/reachability?source=10.200.10.21&destination=10.200.20.31&protocol=tcp&port=5432")
    assert check.status_code == 200 and check.json()["verdict"] == "allowed"
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
    assert len({n["id"] for n in _aws_nodes(api)}) == 13
    # It is not an organization of the Meraki / Cato dialog.
    assert api.get("/api/meraki/orgs").json()["orgs"] == []


def test_api_sources_lists_everything_that_feeds_the_map(api):
    def sources() -> dict[str, dict]:
        response = api.get("/api/topology/sources")
        assert response.status_code == 200, response.text
        return {s["key"]: s for s in response.json()["sources"]}

    # Neighbor discovery is always a source, even with nothing else set up.
    listed = sources()
    assert list(listed) == ["neighbors"]
    assert listed["neighbors"]["type"] == "neighbors" and listed["neighbors"]["status"] == "never"

    org = api.post("/api/meraki/orgs", json={"name": "HQ", "api_key": "k" * 40}).json()["org"]
    assert api.post("/api/meraki/sample?provider=cato").status_code == 201
    assert api.post("/api/meraki/sample?provider=aws").status_code == 201
    body = {"provider": "aws", "name": "Prod AWS", "auth_config": {"secret_access_key": "hunter2"}}
    account = api.post("/api/cloud/accounts", json=body).json()["account"]

    listed = sources()
    assert [s["type"] for s in listed.values()] == ["neighbors", "meraki", "cato", "aws", "aws"]
    real = listed[f"org:{org['id']}"]
    assert (real["status"], real["can_collect"], real["demo"], real["detail"]) == ("never", True, False, "")
    cato = next(s for s in listed.values() if s["type"] == "cato")
    assert cato["status"] == "success" and cato["demo"] and not cato["can_collect"]
    assert cato["last_collected_at"] and "site" in cato["detail"] and "device" in cato["detail"]
    prod = listed[f"aws:{account['id']}"]
    assert (prod["status"], prod["can_collect"], prod["enabled"], prod["demo"]) == ("never", True, True, False)
    demo = next(s for s in listed.values() if s["type"] == "aws" and s["demo"])
    assert demo["status"] == "success" and not demo["can_collect"] and "resources" in demo["detail"]
    # Keys and credentials never leave the server.
    text = api.get("/api/topology/sources").text
    assert "hunter2" not in text and "k" * 40 not in text and "auth_config" not in text

    assert api.put(f"/api/cloud/accounts/{account['id']}", json={"enabled": False}).status_code == 200
    assert sources()[f"aws:{account['id']}"]["enabled"] is False


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
