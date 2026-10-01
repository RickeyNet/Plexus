"""Demo AWS discovery (no credentials needed).

The records have the shape the Cloud Visibility AWS collector returns, so
sample discovery exercises the same path to the Topology map as a live one:
three VPCs in two regions, a transit gateway, a firewall pair that forwards
traffic, a site-to-site VPN with one tunnel down and a Direct Connect.
Addresses are from the documentation ranges.
"""

from __future__ import annotations

from typing import Any

_R1 = "us-east-1"
_R2 = "us-west-2"


def _res(
    uid: str, kind: str, name: str, region: str, *, cidr: str = "", status: str = "available", **meta: Any
) -> dict:
    return {
        "resource_uid": f"aws:{uid}",
        "resource_type": kind,
        "name": name,
        "region": region,
        "cidr": cidr,
        "status": status,
        "metadata": meta,
    }


def _conn(source: str, target: str, kind: str, state: str = "available", **meta: Any) -> dict:
    return {
        "source_resource_uid": f"aws:{source}",
        "target_resource_uid": f"aws:{target}",
        "connection_type": kind,
        "state": state,
        "metadata": meta,
    }


def _subnet(subnet_id: str, name: str, vpc: str, cidr: str, zone: str, region: str = _R1) -> dict:
    return _res(
        f"subnet:{subnet_id}",
        "subnet",
        name,
        region,
        cidr=cidr,
        subnet_id=subnet_id,
        vpc_id=vpc,
        availability_zone=zone,
        available_ips=180,
        map_public_ip=False,
        ipv6_cidrs=[],
    )


def _route(destination: str, target: str) -> dict:
    return {"destination": destination, "target": target, "state": "active", "origin": "CreateRoute"}


def _instance(
    instance_id: str,
    name: str,
    vpc: str,
    interfaces: list[tuple[str, str, str]],
    *,
    kind: str,
    forwards: bool,
    zone: str,
    region: str = _R1,
    status: str = "running",
) -> dict:
    """``interfaces`` are ``(subnet id, private IP, public IP)`` in device order."""
    return _res(
        f"instance:{instance_id}",
        "instance",
        name,
        region,
        status=status,
        instance_id=instance_id,
        vpc_id=vpc,
        subnet_id=interfaces[0][0],
        availability_zone=zone,
        instance_type=kind,
        platform="Linux/UNIX",
        private_ip=interfaces[0][1],
        public_ip=next((public for _s, _p, public in interfaces if public), ""),
        source_dest_check=not forwards,
        security_groups=["sg-app-edge"],
        launched="2026-03-02T14:05:00+00:00",
        interfaces=[
            {
                "id": f"eni-{instance_id[2:]}{index}",
                "subnet_id": subnet,
                "description": "",
                "device_index": index,
                "mac": "",
                "private_ips": [private],
                "public_ips": [public] if public else [],
                "source_dest_check": not forwards,
            }
            for index, (subnet, private, public) in enumerate(interfaces)
        ],
    )


def build_sample() -> tuple[list[dict], list[dict]]:
    """``(resources, connections)`` of the demo AWS account."""
    core, edge, apps = "vpc-0c0re00001", "vpc-0ed9e00002", "vpc-0a9950003"
    tgw = "tgw-0910ba100001"
    resources = [
        _res(f"vpc:{core}", "vpc", "prod-core-vpc", _R1, cidr="10.200.0.0/16", is_default=False),
        _res(f"vpc:{edge}", "vpc", "edge-security-vpc", _R1, cidr="10.210.0.0/16", is_default=False),
        _res(f"vpc:{apps}", "vpc", "apps-west-vpc", _R2, cidr="10.220.0.0/16", is_default=False),
        _subnet("subnet-0c0re0a", "core-app-a", core, "10.200.10.0/24", "us-east-1a"),
        _subnet("subnet-0c0re0b", "core-app-b", core, "10.200.11.0/24", "us-east-1b"),
        _subnet("subnet-0c0re0d", "core-db-a", core, "10.200.20.0/24", "us-east-1a"),
        _subnet("subnet-0ed9e0o", "edge-outside-a", edge, "10.210.0.0/24", "us-east-1a"),
        _subnet("subnet-0ed9e0i", "edge-inside-a", edge, "10.210.1.0/24", "us-east-1a"),
        _subnet("subnet-0ed9e0m", "edge-mgmt-a", edge, "10.210.2.0/24", "us-east-1a"),
        _subnet("subnet-0a9950w", "apps-web-a", apps, "10.220.1.0/24", "us-west-2a", _R2),
        _res(f"tgw:{tgw}", "transit_gateway", "global-tgw", _R1, owner_id="111122223333", amazon_asn="64512"),
        _res("internet_gateway:igw-0ed9e", "internet_gateway", "igw-0ed9e", _R1, status="available", vpc_ids=[edge]),
        _res("internet_gateway:igw-0c0re", "internet_gateway", "igw-0c0re", _R1, status="available", vpc_ids=[core]),
        _res(
            "nat_gateway:nat-0c0re0a",
            "nat_gateway",
            "nat-0c0re0a",
            _R1,
            vpc_id=core,
            subnet_id="subnet-0c0re0a",
            connectivity_type="public",
            public_ips=["203.0.113.40"],
            private_ips=["10.200.10.5"],
        ),
        _res(
            "route_table:rtb-0c0re",
            "route_table",
            "core-private",
            _R1,
            status="active",
            vpc_id=core,
            route_count=3,
            association_count=3,
            associated_subnet_ids=["subnet-0c0re0a", "subnet-0c0re0b", "subnet-0c0re0d"],
            main=True,
            propagating_vgws=[],
            routes=[
                _route("10.200.0.0/16", "local"),
                _route("10.0.0.0/8", tgw),
                _route("0.0.0.0/0", "nat-0c0re0a"),
            ],
        ),
        _res(
            "route_table:rtb-0ed9e0o",
            "route_table",
            "edge-outside",
            _R1,
            status="active",
            vpc_id=edge,
            route_count=2,
            association_count=1,
            associated_subnet_ids=["subnet-0ed9e0o"],
            main=False,
            propagating_vgws=[],
            routes=[_route("10.210.0.0/16", "local"), _route("0.0.0.0/0", "igw-0ed9e")],
        ),
        _res(
            "route_table:rtb-0ed9e0i",
            "route_table",
            "edge-inside",
            _R1,
            status="active",
            vpc_id=edge,
            route_count=3,
            association_count=2,
            associated_subnet_ids=["subnet-0ed9e0i", "subnet-0ed9e0m"],
            main=True,
            propagating_vgws=[],
            routes=[
                _route("10.210.0.0/16", "local"),
                _route("10.0.0.0/8", tgw),
                _route("0.0.0.0/0", "eni-0f7d0011"),
            ],
        ),
        _instance(
            "i-0f7d001",
            "ftdv-ravpn-1",
            edge,
            [
                ("subnet-0ed9e0m", "10.210.2.11", ""),
                ("subnet-0ed9e0o", "10.210.0.11", "203.0.113.11"),
                ("subnet-0ed9e0i", "10.210.1.11", ""),
            ],
            kind="c5.xlarge",
            forwards=True,
            zone="us-east-1a",
        ),
        _instance(
            "i-0f7d002",
            "ftdv-ravpn-2",
            edge,
            [
                ("subnet-0ed9e0m", "10.210.2.12", ""),
                ("subnet-0ed9e0o", "10.210.0.12", "203.0.113.12"),
                ("subnet-0ed9e0i", "10.210.1.12", ""),
            ],
            kind="c5.xlarge",
            forwards=True,
            zone="us-east-1a",
        ),
        _instance(
            "i-0f3c001",
            "fmc-01",
            edge,
            [("subnet-0ed9e0m", "10.210.2.20", "")],
            kind="c5.4xlarge",
            forwards=False,
            zone="us-east-1a",
        ),
        _instance(
            "i-0a99001",
            "app-server-1",
            core,
            [("subnet-0c0re0a", "10.200.10.21", "")],
            kind="m6i.large",
            forwards=False,
            zone="us-east-1a",
        ),
        _instance(
            "i-0a99002",
            "db-server-1",
            core,
            [("subnet-0c0re0d", "10.200.20.31", "")],
            kind="r6i.xlarge",
            forwards=False,
            zone="us-east-1a",
        ),
        _res(
            "customer_gateway:cgw-0d4c0001",
            "customer_gateway",
            "hq-datacenter-edge",
            _R1,
            customer_gateway_id="cgw-0d4c0001",
            ip_address="198.51.100.10",
            bgp_asn="65010",
            device_name="hq-edge-fw",
            type="ipsec.1",
        ),
        _res(
            "vpn_connection:vpn-0d4c0001",
            "vpn_connection",
            "hq-datacenter-vpn",
            _R1,
            vpn_connection_id="vpn-0d4c0001",
            customer_gateway_id="cgw-0d4c0001",
            transit_gateway_id=tgw,
            vpn_gateway_id="",
            type="ipsec.1",
            category="VPN",
            static_routes_only=False,
            static_routes=[],
            tunnel_inside_cidrs=["169.254.21.0/30", "169.254.22.0/30"],
            tunnels=[
                {
                    "outside_ip": "203.0.113.101",
                    "status": "UP",
                    "status_message": "4 BGP ROUTES",
                    "accepted_routes": 4,
                    "last_change": "2026-09-21T08:12:00+00:00",
                },
                {
                    "outside_ip": "203.0.113.102",
                    "status": "DOWN",
                    "status_message": "IPSEC IS DOWN",
                    "accepted_routes": 0,
                    "last_change": "2026-09-30T02:40:00+00:00",
                },
            ],
        ),
        _res("direct_connect:dxcon-0pr1mary", "direct_connect", "dx-primary", _R1, bandwidth="1Gbps"),
        _res(
            "direct-connect-gateway:dxgw-0c0rp",
            "direct_connect_gateway",
            "corp-dxgw",
            "global",
            amazon_asn="64513",
            owner_id="111122223333",
        ),
        _res(
            "sg:app-edge",
            "security_group",
            "sg-app-edge",
            _R1,
            status="active",
            vpc_id=edge,
            policy_rules=[
                {
                    "rule_uid": "aws:sg:app-edge:ingress:https",
                    "rule_name": "HTTPS ingress",
                    "direction": "inbound",
                    "action": "allow",
                    "protocol": "tcp",
                    "source_selector": "0.0.0.0/0",
                    "destination_selector": "self",
                    "port_expression": "443",
                },
                {
                    "rule_uid": "aws:sg:app-edge:egress:any",
                    "rule_name": "All egress",
                    "direction": "outbound",
                    "action": "allow",
                    "protocol": "all",
                    "source_selector": "self",
                    "destination_selector": "0.0.0.0/0",
                    "port_expression": "all",
                },
            ],
        ),
    ]
    connections = [
        _conn(
            f"vpc:{core}",
            f"tgw:{tgw}",
            "transit_gateway_attachment",
            attachment_id="tgw-attach-0c0re",
            resource_type="vpc",
            resource_id=core,
        ),
        _conn(
            f"vpc:{edge}",
            f"tgw:{tgw}",
            "transit_gateway_attachment",
            attachment_id="tgw-attach-0ed9e",
            resource_type="vpc",
            resource_id=edge,
        ),
        _conn(f"vpc:{core}", f"vpc:{apps}", "vpc_peering", "active", peering_id="pcx-0c0re0a99"),
        _conn(f"vpc:{edge}", "internet_gateway:igw-0ed9e", "internet_gateway_attachment"),
        _conn(f"vpc:{core}", "internet_gateway:igw-0c0re", "internet_gateway_attachment"),
        _conn(f"vpc:{core}", "nat_gateway:nat-0c0re0a", "nat_gateway_attachment"),
        _conn(f"vpc:{core}", "route_table:rtb-0c0re", "route_table_association", "attached", association_count=3),
        _conn(f"vpc:{edge}", "route_table:rtb-0ed9e0o", "route_table_association", "attached", association_count=1),
        _conn(f"vpc:{edge}", "route_table:rtb-0ed9e0i", "route_table_association", "attached", association_count=2),
        _conn("route_table:rtb-0c0re", "nat_gateway:nat-0c0re0a", "route_next_hop", "active", destination="0.0.0.0/0"),
        _conn("route_table:rtb-0c0re", f"tgw:{tgw}", "route_next_hop", "active", destination="10.0.0.0/8"),
        _conn(
            "route_table:rtb-0ed9e0o",
            "internet_gateway:igw-0ed9e",
            "route_next_hop",
            "active",
            destination="0.0.0.0/0",
        ),
        _conn("vpn_connection:vpn-0d4c0001", f"tgw:{tgw}", "vpn_tunnel"),
        _conn("vpn_connection:vpn-0d4c0001", "customer_gateway:cgw-0d4c0001", "customer_gateway_attachment"),
        _conn(
            "direct_connect:dxcon-0pr1mary",
            "direct-connect-gateway:dxgw-0c0rp",
            "direct_connect_virtual_interface",
            name="corp-transit-vif",
            type="transit",
            vlan=310,
        ),
        _conn(
            "direct-connect-gateway:dxgw-0c0rp",
            f"tgw:{tgw}",
            "direct_connect_gateway_association",
            "associated",
            region=_R1,
        ),
        _conn(f"vpc:{edge}", "sg:app-edge", "security_boundary", "enforced"),
    ]
    return resources, connections
