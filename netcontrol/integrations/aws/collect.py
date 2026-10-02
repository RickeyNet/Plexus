"""Reshape AWS EC2 / Direct Connect API items into Cloud Visibility records.

Pure functions: the Cloud Visibility AWS collector fetches the items with
boto3 and passes them here. Only named fields are copied. A VPN connection
is the one item that carries secrets (pre-shared keys, in ``TunnelOptions``
and in the ``CustomerGatewayConfiguration`` document); neither is read.
"""

from __future__ import annotations

from typing import Any

WARNING_TYPE = "collection_warning"

# Instance states that are gone; they are not part of the network any more.
_GONE_STATES = ("terminated", "shutting-down")


def _t(value: Any) -> str:
    return str(value or "").strip()


def tag_name(tags: Any) -> str:
    for tag in tags or []:
        if isinstance(tag, dict) and _t(tag.get("Key")).lower() == "name":
            return _t(tag.get("Value"))
    return ""


def _resource(
    uid: str, resource_type: str, *, name: str, region: str, cidr: str = "", status: str = "", metadata: dict
) -> dict:
    return {
        "provider": "aws",
        "resource_uid": uid,
        "resource_type": resource_type,
        "name": name,
        "region": region,
        "cidr": cidr,
        "status": status,
        "metadata": metadata,
    }


def error_code(exc: BaseException) -> str:
    """The AWS error code of a failed call (``UnauthorizedOperation``...),
    else the exception type. Never the message: it can quote the request."""
    response = getattr(exc, "response", None)
    code = _t(((response or {}).get("Error") or {}).get("Code")) if isinstance(response, dict) else ""
    return code or type(exc).__name__


def warning_resource(section: str, region: str, exc: BaseException) -> dict:
    """Record of a detail section that could not be read. It is stored with
    the discovery so the map's report can say what is missing and why."""
    return _resource(
        f"aws:{WARNING_TYPE}:{section}:{region}",
        WARNING_TYPE,
        name=section,
        region=region,
        status="skipped",
        metadata={"section": section, "error": error_code(exc)},
    )


def subnet_resource(subnet: dict, region: str) -> dict | None:
    subnet_id = _t(subnet.get("SubnetId"))
    if not subnet_id:
        return None
    return _resource(
        f"aws:subnet:{subnet_id}",
        "subnet",
        name=tag_name(subnet.get("Tags")) or subnet_id,
        region=region,
        cidr=_t(subnet.get("CidrBlock")),
        status=_t(subnet.get("State")),
        metadata={
            "subnet_id": subnet_id,
            "vpc_id": _t(subnet.get("VpcId")),
            "availability_zone": _t(subnet.get("AvailabilityZone")),
            "available_ips": subnet.get("AvailableIpAddressCount"),
            "map_public_ip": bool(subnet.get("MapPublicIpOnLaunch", False)),
            "ipv6_cidrs": [
                _t(item.get("Ipv6CidrBlock"))
                for item in subnet.get("Ipv6CidrBlockAssociationSet") or []
                if _t(item.get("Ipv6CidrBlock"))
            ],
        },
    )


def route_target(route: dict) -> str:
    """The next hop of a route as AWS names it (``igw-...``, ``tgw-...``, ``local``)."""
    for key in (
        "GatewayId",
        "NatGatewayId",
        "TransitGatewayId",
        "VpcPeeringConnectionId",
        "NetworkInterfaceId",
        "InstanceId",
        "VpcEndpointId",
        "EgressOnlyInternetGatewayId",
        "LocalGatewayId",
        "CarrierGatewayId",
        "CoreNetworkArn",
    ):
        value = _t(route.get(key))
        if value:
            return value
    return ""


def route_table_detail(route_table: dict) -> dict:
    """Routes and associations of a route table, for its resource metadata."""
    associations = route_table.get("Associations") or []
    return {
        "main": any(bool(item.get("Main")) for item in associations),
        "propagating_vgws": [
            _t(item.get("GatewayId")) for item in route_table.get("PropagatingVgws") or [] if _t(item.get("GatewayId"))
        ],
        "routes": [
            {
                "destination": _t(
                    route.get("DestinationCidrBlock")
                    or route.get("DestinationIpv6CidrBlock")
                    or route.get("DestinationPrefixListId")
                ),
                "target": route_target(route),
                "state": _t(route.get("State")),
                "origin": _t(route.get("Origin")),
            }
            for route in route_table.get("Routes") or []
        ],
    }


_PROTOCOL_NAMES = {"-1": "all", "1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6"}


def network_acl_resource(acl: dict, region: str) -> dict | None:
    """A network ACL with its numbered rules and the subnets it guards."""
    acl_id = _t(acl.get("NetworkAclId"))
    if not acl_id:
        return None
    entries = []
    for entry in acl.get("Entries") or []:
        ports = entry.get("PortRange") or {}
        protocol = _t(entry.get("Protocol")).lower()
        entries.append(
            {
                "rule_number": entry.get("RuleNumber"),
                "egress": bool(entry.get("Egress", False)),
                "action": _t(entry.get("RuleAction")).lower(),
                # AWS gives the IANA protocol number; "-1" is every protocol.
                "protocol": _PROTOCOL_NAMES.get(protocol, protocol),
                "cidr": _t(entry.get("CidrBlock") or entry.get("Ipv6CidrBlock")),
                "port_from": ports.get("From"),
                "port_to": ports.get("To"),
            }
        )
    entries.sort(key=lambda e: (e["egress"], e["rule_number"] if isinstance(e["rule_number"], int) else 0))
    return _resource(
        f"aws:network_acl:{acl_id}",
        "network_acl",
        name=tag_name(acl.get("Tags")) or acl_id,
        region=region,
        status="active",
        metadata={
            "vpc_id": _t(acl.get("VpcId")),
            "is_default": bool(acl.get("IsDefault", False)),
            "subnet_ids": [
                _t(item.get("SubnetId")) for item in acl.get("Associations") or [] if _t(item.get("SubnetId"))
            ],
            "entries": entries,
        },
    )


def transit_gateway_route_table_resource(table: dict, routes: list[dict], truncated: bool, region: str) -> dict | None:
    """A transit gateway route table with its active and blackhole routes
    (``routes`` are the items of ``SearchTransitGatewayRoutes``)."""
    table_id = _t(table.get("TransitGatewayRouteTableId"))
    if not table_id:
        return None
    return _resource(
        f"aws:tgw_route_table:{table_id}",
        "transit_gateway_route_table",
        name=tag_name(table.get("Tags")) or table_id,
        region=region,
        status=_t(table.get("State")),
        metadata={
            "transit_gateway_id": _t(table.get("TransitGatewayId")),
            "default_association": bool(table.get("DefaultAssociationRouteTable", False)),
            "default_propagation": bool(table.get("DefaultPropagationRouteTable", False)),
            # AWS returns at most 1000 routes per search.
            "truncated": bool(truncated),
            "routes": [
                {
                    "destination": _t(route.get("DestinationCidrBlock") or route.get("PrefixListId")),
                    "state": _t(route.get("State")),
                    "type": _t(route.get("Type")),
                    "attachments": [
                        {
                            "attachment_id": _t(item.get("TransitGatewayAttachmentId")),
                            "resource_type": _t(item.get("ResourceType")).lower(),
                            "resource_id": _t(item.get("ResourceId")),
                        }
                        for item in route.get("TransitGatewayAttachments") or []
                    ],
                }
                for route in routes
            ],
        },
    )


def _group_ids(groups: Any) -> list[str]:
    return [_t(g.get("GroupId")) for g in groups or [] if isinstance(g, dict) and _t(g.get("GroupId"))]


def nat_gateway_addresses(gateway: dict) -> dict:
    addresses = gateway.get("NatGatewayAddresses") or []
    return {
        "public_ips": [_t(a.get("PublicIp")) for a in addresses if _t(a.get("PublicIp"))],
        "private_ips": [_t(a.get("PrivateIp")) for a in addresses if _t(a.get("PrivateIp"))],
    }


def _interface(eni: dict) -> dict:
    private_ips: list[str] = []
    public_ips: list[str] = []
    for item in eni.get("PrivateIpAddresses") or []:
        if _t(item.get("PrivateIpAddress")):
            private_ips.append(_t(item.get("PrivateIpAddress")))
        public = _t((item.get("Association") or {}).get("PublicIp"))
        if public:
            public_ips.append(public)
    for value, bucket in (
        (_t(eni.get("PrivateIpAddress")), private_ips),
        (_t((eni.get("Association") or {}).get("PublicIp")), public_ips),
    ):
        if value and value not in bucket:
            bucket.append(value)
    return {
        "id": _t(eni.get("NetworkInterfaceId")),
        "subnet_id": _t(eni.get("SubnetId")),
        "description": _t(eni.get("Description")),
        "device_index": (eni.get("Attachment") or {}).get("DeviceIndex"),
        "mac": _t(eni.get("MacAddress")),
        "private_ips": private_ips,
        "public_ips": public_ips,
        "source_dest_check": bool(eni.get("SourceDestCheck", True)),
        "security_group_ids": _group_ids(eni.get("Groups")),
    }


def instance_resource(instance: dict, region: str) -> dict | None:
    instance_id = _t(instance.get("InstanceId"))
    state = _t((instance.get("State") or {}).get("Name"))
    if not instance_id or state in _GONE_STATES:
        return None
    interfaces = sorted(
        (_interface(eni) for eni in instance.get("NetworkInterfaces") or [] if isinstance(eni, dict)),
        key=lambda i: (i["device_index"] is None, i["device_index"] or 0),
    )
    private_ip = _t(instance.get("PrivateIpAddress"))
    public_ip = _t(instance.get("PublicIpAddress"))
    launched = instance.get("LaunchTime")
    return _resource(
        f"aws:instance:{instance_id}",
        "instance",
        name=tag_name(instance.get("Tags")) or instance_id,
        region=region,
        status=state,
        metadata={
            "instance_id": instance_id,
            "vpc_id": _t(instance.get("VpcId")),
            "subnet_id": _t(instance.get("SubnetId")),
            "availability_zone": _t((instance.get("Placement") or {}).get("AvailabilityZone")),
            "instance_type": _t(instance.get("InstanceType")),
            "platform": _t(instance.get("PlatformDetails") or instance.get("Platform")),
            "private_ip": private_ip,
            "public_ip": public_ip,
            # Off on anything that forwards traffic it does not own: firewalls,
            # routers, SD-WAN and VPN appliances.
            "source_dest_check": bool(instance.get("SourceDestCheck", True))
            and all(i["source_dest_check"] for i in interfaces),
            "security_groups": [
                _t(g.get("GroupName")) for g in instance.get("SecurityGroups") or [] if _t(g.get("GroupName"))
            ],
            "security_group_ids": _group_ids(instance.get("SecurityGroups")),
            "launched": launched.isoformat() if hasattr(launched, "isoformat") else _t(launched),
            "interfaces": interfaces,
        },
    )


def customer_gateway_resource(gateway: dict, region: str) -> dict | None:
    gateway_id = _t(gateway.get("CustomerGatewayId"))
    if not gateway_id or _t(gateway.get("State")) == "deleted":
        return None
    return _resource(
        f"aws:customer_gateway:{gateway_id}",
        "customer_gateway",
        name=tag_name(gateway.get("Tags")) or _t(gateway.get("DeviceName")) or gateway_id,
        region=region,
        status=_t(gateway.get("State")),
        metadata={
            "customer_gateway_id": gateway_id,
            "ip_address": _t(gateway.get("IpAddress")),
            "bgp_asn": _t(gateway.get("BgpAsn")),
            "device_name": _t(gateway.get("DeviceName")),
            "type": _t(gateway.get("Type")),
        },
    )


def vpn_connection_metadata(vpn: dict) -> dict:
    """What the map shows of a site-to-site VPN connection. Tunnel options
    and the customer gateway configuration hold pre-shared keys and are not
    read; the inside CIDRs are the only tunnel options copied."""
    options = vpn.get("Options") or {}
    changed = [t.get("LastStatusChange") for t in vpn.get("VgwTelemetry") or []]
    return {
        "vpn_connection_id": _t(vpn.get("VpnConnectionId")),
        "customer_gateway_id": _t(vpn.get("CustomerGatewayId")),
        "transit_gateway_id": _t(vpn.get("TransitGatewayId")),
        "vpn_gateway_id": _t(vpn.get("VpnGatewayId")),
        "type": _t(vpn.get("Type")),
        "category": _t(vpn.get("Category")),
        "static_routes_only": bool(options.get("StaticRoutesOnly", False)),
        "static_routes": [
            _t(r.get("DestinationCidrBlock")) for r in vpn.get("Routes") or [] if _t(r.get("DestinationCidrBlock"))
        ],
        "tunnel_inside_cidrs": [
            _t(o.get("TunnelInsideCidr")) for o in options.get("TunnelOptions") or [] if _t(o.get("TunnelInsideCidr"))
        ],
        "tunnels": [
            {
                "outside_ip": _t(t.get("OutsideIpAddress")),
                "status": _t(t.get("Status")),
                "status_message": _t(t.get("StatusMessage")),
                "accepted_routes": t.get("AcceptedRouteCount"),
                "last_change": when.isoformat() if hasattr(when, "isoformat") else _t(when),
            }
            for t, when in zip(vpn.get("VgwTelemetry") or [], changed, strict=True)
        ],
    }


def virtual_interface_metadata(vif: dict) -> dict:
    """A Direct Connect virtual interface, without its BGP auth key."""
    return {
        "virtual_interface_id": _t(vif.get("virtualInterfaceId")),
        "name": _t(vif.get("virtualInterfaceName")),
        "type": _t(vif.get("virtualInterfaceType")),
        "vlan": vif.get("vlan"),
        "customer_asn": _t(vif.get("asn")),
        "amazon_asn": _t(vif.get("amazonSideAsn")),
        "customer_address": _t(vif.get("customerAddress")),
        "amazon_address": _t(vif.get("amazonAddress")),
    }
