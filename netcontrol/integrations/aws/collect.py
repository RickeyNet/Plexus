"""Reshape AWS EC2 / Direct Connect / FSx and service API items into Cloud
Visibility records.

Pure functions: the Cloud Visibility AWS collector fetches the items with
boto3 and passes them here. Only named fields are copied. A VPN connection
carries secrets (pre-shared keys, in ``TunnelOptions`` and in the
``CustomerGatewayConfiguration`` document); neither is read. Neither are the
credential-like fields of an FSx file system or storage virtual machine (the
Active Directory service account, the ONTAP ``fsxadmin`` password, the KMS key),
nor those of the services whose endpoints are collected (RDS, ElastiCache,
OpenSearch, MSK, Redshift: master user names and passwords, auth tokens,
Secrets Manager ARNs, KMS keys, access policies).

Every service resource carries its endpoints as ``{role, dns_name, port?,
ip_addresses}`` (``endpoint``) next to ``vpc_id``, ``subnet_ids``,
``security_group_ids`` and the ``interfaces`` of its network interfaces
(``service_resource``), which is all the map needs to list it.
"""

from __future__ import annotations

from typing import Any

from netcontrol.integrations.aws.failures import failure_category
from netcontrol.integrations.aws.normalize import (
    EFS_TYPE,
    ELASTICACHE_CLUSTER_TYPE,
    ELASTICACHE_GROUP_TYPE,
    ELASTICACHE_SERVERLESS_TYPE,
    FSX_SVM_TYPE,
    FSX_TYPE,
    LOAD_BALANCER_TYPE,
    MSK_TYPE,
    OPENSEARCH_TYPE,
    RDS_CLUSTER_TYPE,
    RDS_INSTANCE_TYPE,
    RDS_PROXY_TYPE,
    REDSHIFT_TYPE,
    REDSHIFT_WORKGROUP_TYPE,
    VPC_ENDPOINT_TYPE,
    WARNING_TYPE,
)

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


def warning_resource(
    section: str, region: str, exc: BaseException, *, title: str = "", actions: tuple[str, ...] | list[str] = ()
) -> dict:
    """Record of a detail section that could not be read. It is stored with
    the discovery so the map's report can say what is missing and why:
    ``category`` (``failures.failure_category``), and for the report the
    section's ``title`` and the IAM ``actions`` it needs, when given."""
    code = error_code(exc)
    metadata: dict[str, Any] = {"section": section, "error": code, "category": failure_category(code)}
    if title:
        metadata["title"] = title
    if actions:
        metadata["actions"] = list(actions)
    return _resource(
        f"aws:{WARNING_TYPE}:{section}:{region}",
        WARNING_TYPE,
        name=section,
        region=region,
        status="skipped",
        metadata=metadata,
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
            "launched": launched.isoformat()
            if launched is not None and hasattr(launched, "isoformat")
            else _t(launched),
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


# FSx lifecycles of a file system or storage virtual machine that is going away.
_FSX_GONE_STATES = ("deleting",)


def _addresses(*values: Any) -> list[str]:
    """The non-empty addresses among ``values`` (strings or lists of them), once each."""
    found: list[str] = []
    for value in values:
        for item in value if isinstance(value, list) else [value]:
            text = _t(item)
            if text and text not in found:
                found.append(text)
    return found


def endpoint(role: str, dns_name: Any = "", port: Any = None, addresses: Any = ()) -> dict | None:
    """One endpoint of a resource as ``{role, dns_name, port, ip_addresses}``
    (``port`` only when AWS gives one), or ``None`` when it has neither a
    name nor an address. ``addresses`` is a list of strings or of lists."""
    name = _t(dns_name)
    found = _addresses(*addresses) if isinstance(addresses, (list, tuple)) else _addresses(addresses)
    if not name and not found:
        return None
    record: dict[str, Any] = {"role": role, "dns_name": name}
    if isinstance(port, int) and not isinstance(port, bool) and port > 0:
        record["port"] = port
    record["ip_addresses"] = found
    return record


def _fsx_endpoint(role: str, value: Any) -> dict | None:
    """An ONTAP file system or SVM endpoint (``DNSName``, ``IpAddresses``,
    ``Ipv6Addresses``)."""
    if not isinstance(value, dict):
        return None
    return endpoint(
        role, value.get("DNSName"), None, [value.get("IpAddresses") or [], value.get("Ipv6Addresses") or []]
    )


def _fsx_endpoints(file_system: dict) -> list[dict]:
    """Every endpoint AWS reports for a file system, whatever its type."""
    kind = _t(file_system.get("FileSystemType")).upper()
    windows = file_system.get("WindowsConfiguration") or {}
    ontap = file_system.get("OntapConfiguration") or {}
    openzfs = file_system.get("OpenZFSConfiguration") or {}
    # The file system's own DNS name: the file server of a Windows file
    # system, the mount target of Lustre and OpenZFS.
    dns_name = _t(file_system.get("DNSName"))
    own = _addresses(
        windows.get("PreferredFileServerIp"),
        windows.get("PreferredFileServerIpv6"),
        openzfs.get("EndpointIpAddress"),
        openzfs.get("EndpointIpv6Address"),
    )
    candidates = [
        endpoint("File server" if kind == "WINDOWS" else "File system", dns_name, None, own),
        endpoint("Remote administration", windows.get("RemoteAdministrationEndpoint")),
        *[
            endpoint("DNS alias", alias.get("Name"))
            for alias in windows.get("Aliases") or []
            if isinstance(alias, dict)
        ],
        *[_fsx_endpoint(role, (ontap.get("Endpoints") or {}).get(role)) for role in ("Management", "Intercluster")],
    ]
    return [e for e in candidates if e]


def fsx_network_interface_ids(file_system: dict) -> list[str]:
    return [_t(i) for i in file_system.get("NetworkInterfaceIds") or [] if _t(i)]


def fsx_file_system_resource(file_system: dict, region: str, interfaces: dict[str, dict] | None = None) -> dict | None:
    """An Amazon FSx file system (Windows File Server, Lustre, NetApp ONTAP
    or OpenZFS) with every endpoint it answers on.

    ``interfaces`` maps a network interface ID to its ``_interface`` record
    (from ``DescribeNetworkInterfaces``); they give a Lustre or Windows file
    system its addresses. The Active Directory service account, the ONTAP
    ``fsxadmin`` password and the KMS key are not read.
    """
    file_system_id = _t(file_system.get("FileSystemId"))
    lifecycle = _t(file_system.get("Lifecycle")).lower()
    if not file_system_id or lifecycle in _FSX_GONE_STATES:
        return None
    kind = _t(file_system.get("FileSystemType")).upper()
    windows = file_system.get("WindowsConfiguration") or {}
    lustre = file_system.get("LustreConfiguration") or {}
    ontap = file_system.get("OntapConfiguration") or {}
    openzfs = file_system.get("OpenZFSConfiguration") or {}
    detail = {"WINDOWS": windows, "LUSTRE": lustre, "ONTAP": ontap, "OPENZFS": openzfs}.get(kind, {})
    eni_ids = fsx_network_interface_ids(file_system)
    known = interfaces or {}
    self_managed = windows.get("SelfManagedActiveDirectoryConfiguration") or {}
    return _resource(
        f"aws:{FSX_TYPE}:{file_system_id}",
        FSX_TYPE,
        name=tag_name(file_system.get("Tags")) or file_system_id,
        region=region,
        status=lifecycle,
        metadata={
            "file_system_id": file_system_id,
            "file_system_type": kind,
            "file_system_type_version": _t(file_system.get("FileSystemTypeVersion")),
            "lifecycle": lifecycle,
            "owner_id": _t(file_system.get("OwnerId")),
            "vpc_id": _t(file_system.get("VpcId")),
            "subnet_ids": [_t(s) for s in file_system.get("SubnetIds") or [] if _t(s)],
            "preferred_subnet_id": _t(detail.get("PreferredSubnetId")),
            "storage_capacity": file_system.get("StorageCapacity"),
            "storage_type": _t(file_system.get("StorageType")),
            "deployment_type": _t(detail.get("DeploymentType")),
            "throughput_capacity": detail.get("ThroughputCapacity"),
            "dns_name": _t(file_system.get("DNSName")),
            "mount_name": _t(lustre.get("MountName")),
            "endpoint_ip_range": _t(detail.get("EndpointIpAddressRange")),
            "active_directory_id": _t(windows.get("ActiveDirectoryId")),
            "domain_name": _t(self_managed.get("DomainName")),
            "network_interface_ids": eni_ids,
            "endpoints": _fsx_endpoints(file_system),
            "interfaces": [known[i] for i in eni_ids if i in known],
        },
    )


def fsx_storage_virtual_machine_resource(svm: dict, region: str, vpc_id: str = "") -> dict | None:
    """A storage virtual machine of an FSx for NetApp ONTAP file system with
    its NFS, SMB, iSCSI and management endpoints. ``vpc_id`` is its file
    system's VPC (an SVM does not name one). The Active Directory service
    account is not read."""
    svm_id = _t(svm.get("StorageVirtualMachineId"))
    lifecycle = _t(svm.get("Lifecycle")).lower()
    if not svm_id or lifecycle in _FSX_GONE_STATES:
        return None
    endpoints = svm.get("Endpoints") or {}
    directory = svm.get("ActiveDirectoryConfiguration") or {}
    return _resource(
        f"aws:{FSX_SVM_TYPE}:{svm_id}",
        FSX_SVM_TYPE,
        name=_t(svm.get("Name")) or tag_name(svm.get("Tags")) or svm_id,
        region=region,
        status=lifecycle,
        metadata={
            "storage_virtual_machine_id": svm_id,
            "file_system_id": _t(svm.get("FileSystemId")),
            "vpc_id": vpc_id,
            "lifecycle": lifecycle,
            "subtype": _t(svm.get("Subtype")),
            "root_volume_security_style": _t(svm.get("RootVolumeSecurityStyle")),
            "netbios_name": _t(directory.get("NetBiosName")),
            "domain_name": _t((directory.get("SelfManagedActiveDirectoryConfiguration") or {}).get("DomainName")),
            "endpoints": [
                endpoint
                for role, key in (("NFS", "Nfs"), ("SMB", "Smb"), ("iSCSI", "Iscsi"), ("Management", "Management"))
                if (endpoint := _fsx_endpoint(role, endpoints.get(key)))
            ],
        },
    )


def network_interfaces_by_id(enis: list[dict]) -> dict[str, dict]:
    """``DescribeNetworkInterfaces`` items as ``_interface`` records, by ID."""
    found = {}
    for eni in enis:
        if isinstance(eni, dict) and _t(eni.get("NetworkInterfaceId")):
            found[_t(eni.get("NetworkInterfaceId"))] = _interface(eni)
    return found


def network_interfaces_by_description(enis: list[dict]) -> dict[str, list[dict]]:
    """``DescribeNetworkInterfaces`` items as ``_interface`` records, by the
    ENI's description (how a load balancer's interfaces are named)."""
    found: dict[str, list[dict]] = {}
    for eni in enis:
        if isinstance(eni, dict) and _t(eni.get("NetworkInterfaceId")):
            found.setdefault(_t(eni.get("Description")), []).append(_interface(eni))
    return found


# ── Services with DNS endpoints (RDS, load balancers, VPC endpoints, EFS,
#    ElastiCache, OpenSearch, MSK, Redshift) ────────────────────────────────

# States of a resource that is going away; it is not collected.
_SERVICE_GONE_STATES = ("deleting", "deleted", "delete-in-progress")


def _gone(state: Any) -> bool:
    return _t(state).lower() in _SERVICE_GONE_STATES


def _ids(values: Any, key: str = "") -> list[str]:
    """Non-empty IDs of a list of strings, or of dicts by ``key``."""
    found: list[str] = []
    for item in values or []:
        value = _t(item.get(key)) if isinstance(item, dict) else _t(item)
        if value and value not in found:
            found.append(value)
    return found


def dns_suffix(region: str) -> str:
    """The DNS suffix of AWS service names in ``region``'s partition."""
    return "amazonaws.com.cn" if _t(region).lower().startswith("cn-") else "amazonaws.com"


def service_resource(
    resource_type: str,
    resource_id: str,
    *,
    name: str,
    region: str,
    status: str,
    kind: str = "",
    engine: str = "",
    engine_version: str = "",
    vpc_id: str = "",
    subnet_ids: list[str] | None = None,
    security_group_ids: list[str] | None = None,
    endpoints: list[dict | None] | None = None,
    network_interface_ids: list[str] | None = None,
    interfaces: list[dict] | None = None,
    public_ips: list[str] | None = None,
    **details: Any,
) -> dict:
    """The record of a service resource the map lists in its VPC's details.

    ``kind`` names what it is ("Aurora PostgreSQL cluster", "Application load
    balancer"); ``engine_version`` is the software version AWS reports. A
    resource that names no VPC (an MSK cluster, a Redshift Serverless
    workgroup, an ElastiCache serverless cache) is placed by its subnets.
    ``public_ips`` are listed, not indexed as hosts of the VPC.
    ``details`` are the service's own named fields."""
    return _resource(
        f"aws:{resource_type}:{resource_id}",
        resource_type,
        name=name or resource_id,
        region=region,
        status=_t(status).lower(),
        metadata={
            "resource_id": resource_id,
            "kind": kind,
            "engine": engine,
            "engine_version": engine_version,
            "vpc_id": vpc_id,
            "subnet_ids": subnet_ids or [],
            "security_group_ids": security_group_ids or [],
            "endpoints": [e for e in endpoints or [] if e],
            "network_interface_ids": network_interface_ids or [],
            "interfaces": interfaces or [],
            "public_ips": public_ips or [],
            **details,
        },
    )


def subnet_groups_by_name(groups: list[dict], name_key: str) -> dict[str, dict]:
    """RDS ``DBSubnetGroup`` or ElastiCache ``CacheSubnetGroup`` items as
    ``{name: {vpc_id, subnet_ids}}``; ``name_key`` is the field naming the group."""
    found: dict[str, dict] = {}
    for group in groups:
        name = _t(group.get(name_key)) if isinstance(group, dict) else ""
        if name:
            found[name] = {
                "vpc_id": _t(group.get("VpcId")),
                "subnet_ids": _ids(group.get("Subnets"), "SubnetIdentifier"),
            }
    return found


# RDS also lists Neptune and DocumentDB; each is named by its engine.
_RDS_ENGINES = {
    "aurora": "Aurora MySQL",
    "aurora-mysql": "Aurora MySQL",
    "aurora-postgresql": "Aurora PostgreSQL",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "postgres": "PostgreSQL",
    "neptune": "Neptune",
    "docdb": "DocumentDB",
}
_RDS_ENGINE_PREFIXES = (("oracle", "Oracle"), ("custom-oracle", "Oracle"), ("sqlserver", "SQL Server"), ("db2", "Db2"))


def _rds_engine(engine: Any) -> str:
    text = _t(engine).lower()
    if text in _RDS_ENGINES:
        return _RDS_ENGINES[text]
    for prefix, name in _RDS_ENGINE_PREFIXES:
        if text.startswith(prefix) or text.startswith(f"custom-{prefix}"):
            return name
    return _t(engine)


def rds_instance_resource(db: dict, region: str) -> dict | None:
    """An RDS DB instance (also Aurora, Neptune and DocumentDB instances).
    The master user name and password, the KMS key and the Secrets Manager
    secret are not read."""
    identifier = _t(db.get("DBInstanceIdentifier"))
    status = _t(db.get("DBInstanceStatus"))
    if not identifier or _gone(status):
        return None
    group = db.get("DBSubnetGroup") or {}
    own = db.get("Endpoint") or {}
    listener = db.get("ListenerEndpoint") or {}
    return service_resource(
        RDS_INSTANCE_TYPE,
        _t(db.get("DBInstanceArn")) or identifier,
        name=identifier,
        region=region,
        status=status,
        kind=f"{_rds_engine(db.get('Engine'))} instance".strip(),
        engine=_t(db.get("Engine")),
        engine_version=_t(db.get("EngineVersion")),
        vpc_id=_t(group.get("VpcId")),
        subnet_ids=_ids(group.get("Subnets"), "SubnetIdentifier"),
        security_group_ids=_ids(db.get("VpcSecurityGroups"), "VpcSecurityGroupId"),
        endpoints=[
            endpoint("Instance", own.get("Address"), own.get("Port")),
            endpoint("Listener", listener.get("Address"), listener.get("Port")),
        ],
        subnet_group=_t(group.get("DBSubnetGroupName")),
        instance_class=_t(db.get("DBInstanceClass")),
        availability_zone=_t(db.get("AvailabilityZone")),
        multi_az=bool(db.get("MultiAZ")),
        publicly_accessible=bool(db.get("PubliclyAccessible")),
        cluster_id=_t(db.get("DBClusterIdentifier")),
    )


def rds_cluster_resource(cluster: dict, region: str, subnet_groups: dict[str, dict] | None = None) -> dict | None:
    """An Aurora / Multi-AZ DB cluster with its writer, reader and custom
    endpoints. A cluster names only its subnet group; ``subnet_groups``
    (``subnet_groups_by_name``) gives its VPC and subnets."""
    identifier = _t(cluster.get("DBClusterIdentifier"))
    status = _t(cluster.get("Status"))
    if not identifier or _gone(status):
        return None
    port = cluster.get("Port")
    group = (subnet_groups or {}).get(_t(cluster.get("DBSubnetGroup"))) or {}
    return service_resource(
        RDS_CLUSTER_TYPE,
        _t(cluster.get("DBClusterArn")) or identifier,
        name=identifier,
        region=region,
        status=status,
        kind=f"{_rds_engine(cluster.get('Engine'))} cluster".strip(),
        engine=_t(cluster.get("Engine")),
        engine_version=_t(cluster.get("EngineVersion")),
        vpc_id=_t(group.get("vpc_id")),
        subnet_ids=list(group.get("subnet_ids") or []),
        security_group_ids=_ids(cluster.get("VpcSecurityGroups"), "VpcSecurityGroupId"),
        endpoints=[
            endpoint("Writer", cluster.get("Endpoint"), port),
            endpoint("Reader", cluster.get("ReaderEndpoint"), port),
            *[endpoint("Custom", name, port) for name in cluster.get("CustomEndpoints") or []],
        ],
        subnet_group=_t(cluster.get("DBSubnetGroup")),
        engine_mode=_t(cluster.get("EngineMode")),
        multi_az=bool(cluster.get("MultiAZ")),
        publicly_accessible=bool(cluster.get("PubliclyAccessible")),
        members=_ids(cluster.get("DBClusterMembers"), "DBInstanceIdentifier"),
    )


def rds_proxy_resource(proxy: dict, region: str) -> dict | None:
    """An RDS Proxy. Its ``Auth`` list (user names, Secrets Manager ARNs) is not read."""
    name = _t(proxy.get("DBProxyName"))
    status = _t(proxy.get("Status"))
    if not name or _gone(status):
        return None
    return service_resource(
        RDS_PROXY_TYPE,
        _t(proxy.get("DBProxyArn")) or name,
        name=name,
        region=region,
        status=status,
        kind="RDS proxy",
        engine=_t(proxy.get("EngineFamily")),
        vpc_id=_t(proxy.get("VpcId")),
        subnet_ids=_ids(proxy.get("VpcSubnetIds")),
        security_group_ids=_ids(proxy.get("VpcSecurityGroupIds")),
        endpoints=[endpoint("Proxy", proxy.get("Endpoint"))],
        require_tls=bool(proxy.get("RequireTLS")),
    )


_LOAD_BALANCER_KINDS = {
    "application": "Application load balancer",
    "network": "Network load balancer",
    "gateway": "Gateway load balancer",
}


def load_balancer_eni_description(lb: dict) -> str:
    """The description AWS gives a load balancer's network interfaces:
    ``ELB app/<name>/<id>`` (``net/``, ``gwy/``) or ``ELB <classic name>``."""
    arn = _t(lb.get("LoadBalancerArn"))
    if arn:
        _head, sep, tail = arn.partition(":loadbalancer/")
        return f"ELB {tail}" if sep and tail else ""
    name = _t(lb.get("LoadBalancerName"))
    return f"ELB {name}" if name else ""


def load_balancer_resource(lb: dict, region: str, interfaces: list[dict] | None = None) -> dict | None:
    """An Application, Network or Gateway Load Balancer
    (``elbv2:DescribeLoadBalancers``) or a Classic Load Balancer
    (``elb:DescribeLoadBalancers``, no ARN). ``interfaces`` are its network
    interfaces (found by their description), which give its private addresses."""
    arn = _t(lb.get("LoadBalancerArn"))
    name = _t(lb.get("LoadBalancerName"))
    dns_name = _t(lb.get("DNSName"))
    if not (arn or dns_name):
        return None
    zones = [z for z in lb.get("AvailabilityZones") or [] if isinstance(z, dict)]
    private: list[str] = []
    public: list[str] = []
    for zone in zones:
        for address in zone.get("LoadBalancerAddresses") or []:
            private += _addresses(address.get("PrivateIPv4Address"), address.get("IPv6Address"))
            public += _addresses(address.get("IpAddress"))
    if arn:
        kind = _LOAD_BALANCER_KINDS.get(_t(lb.get("Type")).lower(), "Load balancer")
        subnet_ids = _ids(zones, "SubnetId")
        status = _t((lb.get("State") or {}).get("Code"))
        listener_ports: list[int] = []
    else:
        kind = "Classic load balancer"
        subnet_ids = _ids(lb.get("Subnets"))
        # A Classic Load Balancer reports no state of its own.
        status = ""
        listener_ports = sorted(
            {
                port
                for item in lb.get("ListenerDescriptions") or []
                if isinstance(port := (item.get("Listener") or {}).get("LoadBalancerPort"), int)
            }
        )
    return service_resource(
        LOAD_BALANCER_TYPE,
        arn or dns_name,
        name=name,
        region=region,
        status=status,
        kind=kind,
        vpc_id=_t(lb.get("VpcId") or lb.get("VPCId")),
        subnet_ids=subnet_ids,
        security_group_ids=_ids(lb.get("SecurityGroups")),
        endpoints=[endpoint("DNS name", dns_name, None, private)],
        network_interface_ids=[i["id"] for i in interfaces or [] if i.get("id")],
        interfaces=list(interfaces or []),
        public_ips=public,
        scheme=_t(lb.get("Scheme")),
        listener_ports=listener_ports,
    )


# A VPC endpoint in these states is gone or never came up.
_VPC_ENDPOINT_GONE_STATES = ("deleting", "deleted", "rejected", "expired")


def vpc_endpoint_resource(vpce: dict, region: str, interfaces: dict[str, dict] | None = None) -> dict | None:
    """An interface, gateway load balancer or gateway VPC endpoint with its
    DNS entries. Its policy document is not read. A gateway endpoint (S3,
    DynamoDB) has no DNS entry and no network interface."""
    vpce_id = _t(vpce.get("VpcEndpointId"))
    state = _t(vpce.get("State")).lower()
    if not vpce_id or state in _VPC_ENDPOINT_GONE_STATES:
        return None
    eni_ids = _ids(vpce.get("NetworkInterfaceIds"))
    known = interfaces or {}
    endpoint_type = _t(vpce.get("VpcEndpointType"))
    return service_resource(
        VPC_ENDPOINT_TYPE,
        vpce_id,
        name=tag_name(vpce.get("Tags")) or vpce_id,
        region=region,
        status=state,
        kind=f"{endpoint_type} endpoint".strip() if endpoint_type else "VPC endpoint",
        vpc_id=_t(vpce.get("VpcId")),
        subnet_ids=_ids(vpce.get("SubnetIds")),
        security_group_ids=_group_ids(vpce.get("Groups")),
        endpoints=[endpoint("DNS name", entry.get("DnsName")) for entry in vpce.get("DnsEntries") or []],
        network_interface_ids=eni_ids,
        interfaces=[known[i] for i in eni_ids if i in known],
        service_name=_t(vpce.get("ServiceName")),
        endpoint_type=endpoint_type,
        private_dns_enabled=bool(vpce.get("PrivateDnsEnabled")),
        route_table_ids=_ids(vpce.get("RouteTableIds")),
        owner_id=_t(vpce.get("OwnerId")),
    )


def efs_file_system_resource(fs: dict, region: str, mount_targets: list[dict] | None = None) -> dict | None:
    """An EFS file system with its mount targets. AWS returns no DNS name:
    it is ``<fs-id>.efs.<region>.<suffix>`` for the file system and
    ``<az>.<fs-id>.efs.<region>.<suffix>`` for each mount target. The KMS key
    is not read."""
    fs_id = _t(fs.get("FileSystemId"))
    state = _t(fs.get("LifeCycleState"))
    if not fs_id or _gone(state):
        return None
    targets = [t for t in mount_targets or [] if isinstance(t, dict) and not _gone(t.get("LifeCycleState"))]
    base = f"{fs_id}.efs.{region}.{dns_suffix(region)}"
    addresses = [[t.get("IpAddress"), t.get("Ipv6Address")] for t in targets]
    endpoints = [endpoint("File system", base, None, addresses)]
    for target in targets:
        zone = _t(target.get("AvailabilityZoneName"))
        endpoints.append(
            endpoint(
                f"Mount target {zone}".strip(),
                f"{zone}.{base}" if zone else "",
                None,
                [target.get("IpAddress"), target.get("Ipv6Address")],
            )
        )
    return service_resource(
        EFS_TYPE,
        fs_id,
        name=_t(fs.get("Name")) or tag_name(fs.get("Tags")) or fs_id,
        region=region,
        status=state,
        kind="EFS file system",
        vpc_id=next((_t(t.get("VpcId")) for t in targets if _t(t.get("VpcId"))), ""),
        subnet_ids=_ids(targets, "SubnetId"),
        endpoints=endpoints,
        network_interface_ids=_ids(targets, "NetworkInterfaceId"),
        owner_id=_t(fs.get("OwnerId")),
        performance_mode=_t(fs.get("PerformanceMode")),
        throughput_mode=_t(fs.get("ThroughputMode")),
        availability_zone=_t(fs.get("AvailabilityZoneName")),
        mount_target_ids=_ids(targets, "MountTargetId"),
    )


def _address_port(value: Any) -> tuple[str, Any]:
    value = value if isinstance(value, dict) else {}
    return _t(value.get("Address")), value.get("Port")


def _cache_node_endpoints(cluster: dict) -> list[dict | None]:
    found: list[dict | None] = []
    cluster_id = _t(cluster.get("CacheClusterId"))
    for node in cluster.get("CacheNodes") or []:
        if isinstance(node, dict):
            address, port = _address_port(node.get("Endpoint"))
            found.append(endpoint(f"Node {cluster_id}/{_t(node.get('CacheNodeId'))}", address, port))
    return found


def _cache_location(clusters: list[dict], subnet_groups: dict[str, dict] | None) -> dict:
    """VPC, subnets and security groups of ElastiCache clusters, from their subnet group."""
    names = _ids(clusters, "CacheSubnetGroupName")
    group = next(((subnet_groups or {}).get(n) for n in names if (subnet_groups or {}).get(n)), None) or {}
    return {
        "vpc_id": _t(group.get("vpc_id")),
        "subnet_ids": list(group.get("subnet_ids") or []),
        "security_group_ids": _ids([g for c in clusters for g in c.get("SecurityGroups") or []], "SecurityGroupId"),
        "subnet_group": names[0] if names else "",
    }


def elasticache_replication_group_resource(
    group: dict, region: str, members: list[dict] | None = None, subnet_groups: dict[str, dict] | None = None
) -> dict | None:
    """A Redis OSS / Valkey replication group with its configuration,
    primary and reader endpoints and the endpoints of its nodes.
    ``members`` are its cache clusters (``DescribeCacheClusters`` with node
    info), which name the subnet group and the engine version. Auth tokens,
    user groups and the KMS key are not read."""
    group_id = _t(group.get("ReplicationGroupId"))
    status = _t(group.get("Status"))
    if not group_id or _gone(status):
        return None
    clusters = [c for c in members or [] if isinstance(c, dict)]
    shards = [g for g in group.get("NodeGroups") or [] if isinstance(g, dict)]
    endpoints = [endpoint("Configuration", *_address_port(group.get("ConfigurationEndpoint")))]
    for shard in shards:
        prefix = f"Shard {_t(shard.get('NodeGroupId'))} " if len(shards) > 1 else ""
        endpoints.append(endpoint(f"{prefix}primary".capitalize(), *_address_port(shard.get("PrimaryEndpoint"))))
        endpoints.append(endpoint(f"{prefix}reader".capitalize(), *_address_port(shard.get("ReaderEndpoint"))))
    if clusters:
        endpoints += [e for c in clusters for e in _cache_node_endpoints(c)]
    else:
        for shard in shards:
            for member in shard.get("NodeGroupMembers") or []:
                if isinstance(member, dict):
                    address, port = _address_port(member.get("ReadEndpoint"))
                    endpoints.append(endpoint(f"Node {_t(member.get('CacheClusterId'))}", address, port))
    engine = _t(group.get("Engine")) or next((_t(c.get("Engine")) for c in clusters if _t(c.get("Engine"))), "")
    return service_resource(
        ELASTICACHE_GROUP_TYPE,
        _t(group.get("ARN")) or group_id,
        name=group_id,
        region=region,
        status=status,
        kind="ElastiCache replication group",
        engine=engine,
        engine_version=next((_t(c.get("EngineVersion")) for c in clusters if _t(c.get("EngineVersion"))), ""),
        endpoints=endpoints,
        node_type=_t(group.get("CacheNodeType")),
        cluster_mode=bool(group.get("ClusterEnabled")),
        multi_az=_t(group.get("MultiAZ")),
        transit_encryption=bool(group.get("TransitEncryptionEnabled")),
        **_cache_location(clusters, subnet_groups),
    )


def elasticache_cache_cluster_resource(
    cluster: dict, region: str, subnet_groups: dict[str, dict] | None = None
) -> dict | None:
    """A cache cluster outside any replication group (Memcached, or a single
    Redis OSS / Valkey node) with its configuration and node endpoints."""
    cluster_id = _t(cluster.get("CacheClusterId"))
    status = _t(cluster.get("CacheClusterStatus"))
    if not cluster_id or _gone(status):
        return None
    return service_resource(
        ELASTICACHE_CLUSTER_TYPE,
        _t(cluster.get("ARN")) or cluster_id,
        name=cluster_id,
        region=region,
        status=status,
        kind="ElastiCache cluster",
        engine=_t(cluster.get("Engine")),
        engine_version=_t(cluster.get("EngineVersion")),
        endpoints=[
            endpoint("Configuration", *_address_port(cluster.get("ConfigurationEndpoint"))),
            *_cache_node_endpoints(cluster),
        ],
        node_type=_t(cluster.get("CacheNodeType")),
        node_count=cluster.get("NumCacheNodes"),
        **_cache_location([cluster], subnet_groups),
    )


def elasticache_serverless_cache_resource(cache: dict, region: str) -> dict | None:
    """An ElastiCache serverless cache. It names its subnets, not its VPC.
    The user group and the KMS key are not read."""
    name = _t(cache.get("ServerlessCacheName"))
    status = _t(cache.get("Status"))
    if not name or _gone(status):
        return None
    return service_resource(
        ELASTICACHE_SERVERLESS_TYPE,
        _t(cache.get("ARN")) or name,
        name=name,
        region=region,
        status=status,
        kind="ElastiCache serverless cache",
        engine=_t(cache.get("Engine")),
        engine_version=_t(cache.get("FullEngineVersion")) or _t(cache.get("MajorEngineVersion")),
        subnet_ids=_ids(cache.get("SubnetIds")),
        security_group_ids=_ids(cache.get("SecurityGroupIds")),
        endpoints=[
            endpoint("Endpoint", *_address_port(cache.get("Endpoint"))),
            endpoint("Reader", *_address_port(cache.get("ReaderEndpoint"))),
        ],
    )


def opensearch_domain_resource(domain: dict, region: str) -> dict | None:
    """An OpenSearch Service domain with its public, VPC, dual-stack and
    custom endpoints. Of the fine-grained access control settings only
    whether it is enabled is kept (no master user, SAML or Cognito field);
    the access policy is not read."""
    name = _t(domain.get("DomainName"))
    if not name or domain.get("Deleted"):
        return None
    engine, _sep, version = _t(domain.get("EngineVersion")).partition("_")
    vpc = domain.get("VPCOptions") or {}
    options = domain.get("DomainEndpointOptions") or {}
    cluster = domain.get("ClusterConfig") or {}
    status = _t(domain.get("DomainProcessingStatus")) or ("processing" if domain.get("Processing") else "active")
    raw_named = domain.get("Endpoints")
    named: dict = raw_named if isinstance(raw_named, dict) else {}
    return service_resource(
        OPENSEARCH_TYPE,
        _t(domain.get("ARN")) or _t(domain.get("DomainId")) or name,
        name=name,
        region=region,
        status=status,
        kind="OpenSearch domain",
        engine=engine if version else "",
        engine_version=version or engine,
        vpc_id=_t(vpc.get("VPCId")),
        subnet_ids=_ids(vpc.get("SubnetIds")),
        security_group_ids=_ids(vpc.get("SecurityGroupIds")),
        endpoints=[
            endpoint("Endpoint", domain.get("Endpoint")),
            *[endpoint(f"{key.upper()} endpoint" if key == "vpc" else key, value) for key, value in named.items()],
            endpoint("Dual-stack endpoint", domain.get("EndpointV2")),
            endpoint("Custom endpoint", options.get("CustomEndpoint") if options.get("CustomEndpointEnabled") else ""),
        ],
        instance_type=_t(cluster.get("InstanceType")),
        instance_count=cluster.get("InstanceCount"),
        enforce_https=bool(options.get("EnforceHTTPS")),
        fine_grained_access_control=bool((domain.get("AdvancedSecurityOptions") or {}).get("Enabled")),
    )


# GetBootstrapBrokers keys (after ``BootstrapBrokerString``), by the words they hold.
_BOOTSTRAP_WORDS = (
    ("Public", "public"),
    ("VpcConnectivity", "multi-VPC"),
    ("Tls", "TLS"),
    ("SaslScram", "SASL/SCRAM"),
    ("SaslIam", "IAM"),
    ("Ipv6", "IPv6"),
)


def _bootstrap_role(key: str) -> str:
    rest = key.removeprefix("BootstrapBrokerString")
    words = []
    for token, word in _BOOTSTRAP_WORDS:
        if token in rest:
            words.append(word)
            rest = rest.replace(token, "")
    return f"Bootstrap ({', '.join(words)})" if words else "Bootstrap (plaintext)"


def msk_bootstrap_endpoints(brokers: dict | None) -> list[dict]:
    """Every ``BootstrapBrokerString*`` of ``GetBootstrapBrokers`` (a comma
    separated ``host:port`` list) as endpoints."""
    found: list[dict] = []
    for key, value in (brokers or {}).items():
        if not str(key).startswith("BootstrapBrokerString") or not isinstance(value, str):
            continue
        for item in value.split(","):
            host, _sep, port = item.strip().rpartition(":")
            record = endpoint(_bootstrap_role(str(key)), host or item.strip(), int(port) if port.isdigit() else None)
            if record and record not in found:
                found.append(record)
    return found


def _msk_node_endpoints(nodes: list[dict] | None) -> tuple[list[dict | None], list[str]]:
    """The endpoints and network interfaces of an MSK cluster's brokers and
    ZooKeeper nodes (``ListNodes``)."""
    endpoints: list[dict | None] = []
    eni_ids: list[str] = []
    for node in nodes or []:
        for info_key, id_key, label in (
            ("BrokerNodeInfo", "BrokerId", "Broker"),
            ("ZookeeperNodeInfo", "ZookeeperId", "ZooKeeper"),
        ):
            info = node.get(info_key) if isinstance(node, dict) else None
            if not isinstance(info, dict):
                continue
            number = info.get(id_key)
            role = f"{label} {int(number) if isinstance(number, (int, float)) else ''}".strip()
            address = info.get("ClientVpcIpAddress")
            names = _ids(info.get("Endpoints")) or [""]
            endpoints += [endpoint(role, name, None, [address]) for name in names]
            eni_ids += _ids([info.get("AttachedENIId")])
    return endpoints, eni_ids


def msk_cluster_resource(
    cluster: dict, region: str, bootstrap: dict | None = None, nodes: list[dict] | None = None
) -> dict | None:
    """A provisioned or serverless MSK cluster with its bootstrap brokers
    (``GetBootstrapBrokers``) and broker nodes (``ListNodes``). It names its
    client subnets, not its VPC. Client authentication settings are not read."""
    arn = _t(cluster.get("ClusterArn"))
    state = _t(cluster.get("State"))
    if not arn or _gone(state):
        return None
    provisioned = cluster.get("Provisioned") or {}
    serverless = cluster.get("Serverless") or {}
    group = provisioned.get("BrokerNodeGroupInfo") or {}
    configs = [c for c in serverless.get("VpcConfigs") or [] if isinstance(c, dict)]
    node_endpoints, eni_ids = _msk_node_endpoints(nodes)
    cluster_type = _t(cluster.get("ClusterType")).upper()
    return service_resource(
        MSK_TYPE,
        arn,
        name=_t(cluster.get("ClusterName")),
        region=region,
        status=state,
        kind="MSK Serverless cluster" if cluster_type == "SERVERLESS" else "MSK cluster",
        engine="Kafka",
        engine_version=_t((provisioned.get("CurrentBrokerSoftwareInfo") or {}).get("KafkaVersion")),
        subnet_ids=_ids(group.get("ClientSubnets")) or _ids([s for c in configs for s in c.get("SubnetIds") or []]),
        security_group_ids=_ids(group.get("SecurityGroups"))
        or _ids([g for c in configs for g in c.get("SecurityGroupIds") or []]),
        endpoints=[*msk_bootstrap_endpoints(bootstrap), *node_endpoints],
        network_interface_ids=eni_ids,
        cluster_type=cluster_type,
        broker_count=provisioned.get("NumberOfBrokerNodes"),
        instance_type=_t(group.get("InstanceType")),
    )


def _vpc_endpoint_addresses(vpc_endpoints: Any, keys: tuple[str, str, str, str]) -> tuple[list[dict | None], str]:
    """Endpoints of the managed VPC endpoints of a Redshift cluster or
    workgroup (``keys``: endpoint ID, VPC ID, interfaces, address field
    names, which differ in case between the two APIs), and their VPC."""
    id_key, vpc_key, interfaces_key, address_key = keys
    found: list[dict | None] = []
    vpc_id = ""
    for item in vpc_endpoints or []:
        if not isinstance(item, dict):
            continue
        vpc_id = vpc_id or _t(item.get(vpc_key))
        addresses = [ni.get(address_key) for ni in item.get(interfaces_key) or [] if isinstance(ni, dict)]
        found.append(endpoint(f"VPC endpoint {_t(item.get(id_key))}".strip(), "", None, addresses))
    return found, vpc_id


def redshift_cluster_resource(cluster: dict, region: str) -> dict | None:
    """A provisioned Redshift cluster with its endpoint, its managed VPC
    endpoints and the private addresses of its nodes. The master user name,
    the master password secret and the KMS key are not read."""
    identifier = _t(cluster.get("ClusterIdentifier"))
    status = _t(cluster.get("ClusterStatus"))
    if not identifier or _gone(status):
        return None
    own = cluster.get("Endpoint") or {}
    managed, _vpc = _vpc_endpoint_addresses(
        own.get("VpcEndpoints"), ("VpcEndpointId", "VpcId", "NetworkInterfaces", "PrivateIpAddress")
    )
    nodes = [n for n in cluster.get("ClusterNodes") or [] if isinstance(n, dict)]
    version = _t(cluster.get("ClusterVersion"))
    revision = _t(cluster.get("ClusterRevisionNumber"))
    return service_resource(
        REDSHIFT_TYPE,
        _t(cluster.get("ClusterNamespaceArn")) or f"{region}/{identifier}",
        name=identifier,
        region=region,
        status=status,
        kind="Redshift cluster",
        engine="Redshift",
        engine_version=f"{version} (revision {revision})" if version and revision else version,
        vpc_id=_t(cluster.get("VpcId")),
        security_group_ids=_ids(cluster.get("VpcSecurityGroups"), "VpcSecurityGroupId"),
        endpoints=[
            endpoint("Cluster", own.get("Address"), own.get("Port")),
            *managed,
            *[
                endpoint(
                    f"{_t(n.get('NodeRole')).capitalize() or 'Cluster'} node", "", None, [n.get("PrivateIPAddress")]
                )
                for n in nodes
            ],
        ],
        public_ips=_addresses(*[n.get("PublicIPAddress") for n in nodes]),
        subnet_group=_t(cluster.get("ClusterSubnetGroupName")),
        node_type=_t(cluster.get("NodeType")),
        node_count=cluster.get("NumberOfNodes"),
        publicly_accessible=bool(cluster.get("PubliclyAccessible")),
        availability_zone=_t(cluster.get("AvailabilityZone")),
    )


def redshift_workgroup_resource(workgroup: dict, region: str) -> dict | None:
    """A Redshift Serverless workgroup with its endpoint and the addresses of
    its VPC endpoints. The namespace's admin user and password are not read
    (the namespace is not asked for)."""
    name = _t(workgroup.get("workgroupName"))
    status = _t(workgroup.get("status"))
    if not name or _gone(status):
        return None
    own = workgroup.get("endpoint") or {}
    managed, vpc_id = _vpc_endpoint_addresses(
        own.get("vpcEndpoints"), ("vpcEndpointId", "vpcId", "networkInterfaces", "privateIpAddress")
    )
    return service_resource(
        REDSHIFT_WORKGROUP_TYPE,
        _t(workgroup.get("workgroupArn")) or _t(workgroup.get("workgroupId")) or name,
        name=name,
        region=region,
        status=status,
        kind="Redshift Serverless workgroup",
        engine="Redshift",
        engine_version=_t(workgroup.get("workgroupVersion")),
        vpc_id=vpc_id,
        subnet_ids=_ids(workgroup.get("subnetIds")),
        security_group_ids=_ids(workgroup.get("securityGroupIds")),
        endpoints=[endpoint("Workgroup", own.get("address"), own.get("port") or workgroup.get("port")), *managed],
        namespace=_t(workgroup.get("namespaceName")),
        base_capacity=workgroup.get("baseCapacity"),
        publicly_accessible=bool(workgroup.get("publiclyAccessible")),
    )


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
