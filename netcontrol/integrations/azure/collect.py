"""Reshape Azure Network API models into Cloud Visibility records.

Pure functions: the Cloud Visibility Azure collector lists the models with
``azure-mgmt-network`` and passes them here. Only named attributes are read,
so the functions work on the SDK models and on plain stand-ins alike. A
gateway connection is the one model that carries a secret (``shared_key``);
it is never read.

Resource uids follow the subscription / resource group / name hierarchy of
Azure resource IDs: ``azure:vnet:<subscription>:<resource group>:<name>``,
and ``azure:subnet:<subscription>:<resource group>:<vnet>/<name>`` for a
subnet. What follows ``azure:<type>:`` is unique across subscriptions, so
several accounts share one map.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from netcontrol.integrations.azure.normalize import (
    APPLICATION_GATEWAY_TYPE,
    LOAD_BALANCER_TYPE,
    PRIVATE_ENDPOINT_TYPE,
    WARNING_TYPE,
)
from netcontrol.integrations.cloud_services import endpoint, service_record, unique_addresses

PROVIDER = "azure"

# Azure resource type (lower case) -> record type of its uid.
_UID_KINDS = {
    "virtualnetworkgateways": "virtual_network_gateway",
    "localnetworkgateways": "local_network_gateway",
    "routetables": "route_table",
    "networksecuritygroups": "nsg",
    "expressroutecircuits": "expressroute",
    "natgateways": "nat_gateway",
    "networkinterfaces": "nic",
    "virtualmachines": "vm",
    "azurefirewalls": "firewall",
    "publicipaddresses": "public_ip",
    "loadbalancers": LOAD_BALANCER_TYPE,
    "applicationgateways": APPLICATION_GATEWAY_TYPE,
    "privateendpoints": PRIVATE_ENDPOINT_TYPE,
}


def _t(value: Any) -> str:
    # The SDK answers many fields as str-mixin enums (SecurityRuleDirection,
    # RouteNextHopType...): str() of those is "RouteNextHopType.VIRTUAL_APPLIANCE",
    # the value "VirtualAppliance" is what Azure says and what the map reads.
    if isinstance(value, Enum):
        value = value.value
    return str(value or "").strip()


def _get(obj: Any, *path: str) -> Any:
    """``obj.a.b`` with ``None`` for any missing step."""
    for step in path:
        if obj is None:
            return None
        obj = obj.get(step) if isinstance(obj, dict) else getattr(obj, step, None)
    return obj


def _id(obj: Any) -> str:
    return _t(_get(obj, "id"))


def _list(value: Any) -> list:
    return list(value) if value else []


def resource_parts(resource_id: str) -> dict[str, str]:
    """``/subscriptions/S/resourceGroups/RG/providers/Microsoft.Network/virtualNetworks/V/subnets/N``
    -> ``{"subscriptions": "S", "resourcegroups": "RG", "virtualnetworks": "V", "subnets": "N", ...}``."""
    parts = [p for p in _t(resource_id).strip("/").split("/") if p]
    out: dict[str, str] = {}
    for index in range(0, len(parts) - 1, 2):
        out[parts[index].lower()] = parts[index + 1]
    return out


def resource_name(resource_id: str) -> str:
    parts = [p for p in _t(resource_id).strip("/").split("/") if p]
    return parts[-1] if parts else ""


def resource_uid(resource_id: str, subscription_id: str = "") -> str:
    """The Cloud Visibility uid of the resource an Azure resource ID names,
    or ``""`` for a kind the map does not keep. The subscription of the ID
    wins over ``subscription_id`` (a peering can name another one)."""
    parts = resource_parts(resource_id)
    subscription = parts.get("subscriptions") or subscription_id
    group = parts.get("resourcegroups", "")
    if not subscription or not group:
        return ""
    if parts.get("virtualnetworks"):
        if parts.get("subnets"):
            return f"azure:subnet:{subscription}:{group}:{parts['virtualnetworks']}/{parts['subnets']}"
        return f"azure:vnet:{subscription}:{group}:{parts['virtualnetworks']}"
    for azure_type, kind in _UID_KINDS.items():
        if parts.get(azure_type):
            return f"azure:{kind}:{subscription}:{group}:{parts[azure_type]}"
    return ""


def rid_of(uid: str) -> str:
    """``azure:vnet:S:RG:hub`` -> ``S:RG:hub``: the part that identifies the resource."""
    parts = uid.split(":", 2)
    return parts[2] if len(parts) == 3 else uid


def _ref(obj: Any, *path: str) -> str:
    """The uid of a resource another model references by ID."""
    return resource_uid(_t(_get(obj, *path, "id")))


def _resource(
    uid: str, resource_type: str, *, name: str, region: str, cidr: str = "", status: str = "", metadata: dict
) -> dict:
    return {
        "provider": PROVIDER,
        "resource_uid": uid,
        "resource_type": resource_type,
        "name": name,
        "region": region,
        "cidr": cidr,
        "status": status,
        "metadata": metadata,
    }


def _own_uid(model: Any, kind: str, subscription_id: str) -> tuple[str, str, str]:
    """``(uid, resource group, name)`` of a top-level model."""
    parts = resource_parts(_id(model))
    name = _t(_get(model, "name")) or resource_name(_id(model))
    group = parts.get("resourcegroups", "")
    subscription = parts.get("subscriptions") or subscription_id
    return f"azure:{kind}:{subscription}:{group}:{name}", group, name


def _state(model: Any) -> str:
    return _t(_get(model, "provisioning_state"))


def error_code(exc: BaseException) -> str:
    """The Azure error code of a failed call (``AuthorizationFailed``...),
    else the HTTP status, else the exception type. Never the message."""
    code = _t(_get(exc, "error", "code"))
    if code:
        return code
    status = _get(exc, "status_code")
    if isinstance(status, int):
        return f"HTTP {status}"
    return type(exc).__name__


def warning_resource(
    section: str, exc: BaseException, *, title: str = "", actions: tuple[str, ...] | list[str] = ()
) -> dict:
    """Record of a detail section that could not be read, stored with the
    discovery so the map's report can say what is missing and why, and,
    when given, the section's ``title`` and the Azure RBAC ``actions`` it needs."""
    metadata: dict[str, Any] = {"section": section, "error": error_code(exc)}
    if title:
        metadata["title"] = title
    if actions:
        metadata["actions"] = list(actions)
    return _resource(
        f"azure:{WARNING_TYPE}:{section}",
        WARNING_TYPE,
        name=section,
        region="",
        status="skipped",
        metadata=metadata,
    )


# ── Virtual networks ─────────────────────────────────────────────────────────


def _prefixes(space: Any) -> list[str]:
    return [_t(p) for p in _list(_get(space, "address_prefixes")) if _t(p)]


def vnet_resource(vnet: Any, subscription_id: str) -> dict | None:
    uid, group, name = _own_uid(vnet, "vnet", subscription_id)
    if not name:
        return None
    prefixes = _prefixes(_get(vnet, "address_space"))
    return _resource(
        uid,
        "vnet",
        name=name,
        region=_t(_get(vnet, "location")),
        # IPAM reads one range per resource; the others are in the metadata.
        cidr=prefixes[0] if prefixes else "",
        status=_state(vnet),
        metadata={
            "resource_group": group,
            "address_prefixes": prefixes,
            "dns_servers": [_t(d) for d in _list(_get(vnet, "dhcp_options", "dns_servers")) if _t(d)],
            "subnet_count": len(_list(_get(vnet, "subnets"))),
        },
    )


def subnet_resources(vnet: Any, subscription_id: str) -> list[dict]:
    """The subnets of a virtual network, each with the route table, network
    security group and NAT gateway applied to it."""
    vnet_uid, _group, vnet_name = _own_uid(vnet, "vnet", subscription_id)
    region = _t(_get(vnet, "location"))
    found: list[dict] = []
    for subnet in _list(_get(vnet, "subnets")):
        name = _t(_get(subnet, "name")) or resource_name(_id(subnet))
        if not name:
            continue
        prefixes = [_t(_get(subnet, "address_prefix"))] + [_t(p) for p in _list(_get(subnet, "address_prefixes"))]
        prefixes = [p for p in dict.fromkeys(prefixes) if p]
        found.append(
            _resource(
                f"azure:subnet:{rid_of(vnet_uid)}/{name}",
                "subnet",
                name=name,
                region=region,
                cidr=prefixes[0] if prefixes else "",
                status=_state(subnet),
                metadata={
                    "subnet_name": name,
                    "vnet_id": rid_of(vnet_uid),
                    "vnet_name": vnet_name,
                    "address_prefixes": prefixes,
                    "route_table": _ref(subnet, "route_table"),
                    "network_security_group": _ref(subnet, "network_security_group"),
                    "nat_gateway": _ref(subnet, "nat_gateway"),
                    "delegations": [
                        _t(_get(d, "service_name"))
                        for d in _list(_get(subnet, "delegations"))
                        if _t(_get(d, "service_name"))
                    ],
                    "service_endpoints": [
                        _t(_get(e, "service"))
                        for e in _list(_get(subnet, "service_endpoints"))
                        if _t(_get(e, "service"))
                    ],
                    "ip_configuration_count": len(_list(_get(subnet, "ip_configurations"))),
                },
            )
        )
    return found


def peering_connection(vnet_uid: str, peering: Any, subscription_id: str) -> dict | None:
    """A VNet peering as a connection from ``vnet_uid`` to the remote VNet."""
    remote = _ref(peering, "remote_virtual_network") or resource_uid(
        _t(_get(peering, "remote_virtual_network", "id")), subscription_id
    )
    if not remote:
        return None
    return {
        "provider": PROVIDER,
        "source_resource_uid": vnet_uid,
        "target_resource_uid": remote,
        "connection_type": "vnet_peering",
        "state": _t(_get(peering, "peering_state")),
        "metadata": {
            "name": _t(_get(peering, "name")),
            "allow_virtual_network_access": bool(_get(peering, "allow_virtual_network_access")),
            "allow_forwarded_traffic": bool(_get(peering, "allow_forwarded_traffic")),
            "allow_gateway_transit": bool(_get(peering, "allow_gateway_transit")),
            "use_remote_gateways": bool(_get(peering, "use_remote_gateways")),
            "remote_address_space": _prefixes(_get(peering, "remote_address_space")),
            "peering_sync_level": _t(_get(peering, "peering_sync_level")),
        },
    }


# ── Gateways and circuits ────────────────────────────────────────────────────


def public_ip_table(public_ips: Any) -> dict[str, str]:
    """Public IP resource ID (lower case) -> address, for the models that
    reference a public IP by ID."""
    table: dict[str, str] = {}
    for item in _list(public_ips):
        if _id(item) and _t(_get(item, "ip_address")):
            table[_id(item).lower()] = _t(_get(item, "ip_address"))
    return table


def _public_ips_of(configs: Any, public_ips: dict[str, str]) -> list[str]:
    found: list[str] = []
    for config in _list(configs):
        address = public_ips.get(_t(_get(config, "public_ip_address", "id")).lower())
        if address and address not in found:
            found.append(address)
    return found


def _bgp(model: Any) -> dict:
    settings = _get(model, "bgp_settings")
    addresses = [_t(_get(settings, "bgp_peering_address"))]
    for item in _list(_get(settings, "bgp_peering_addresses")):
        addresses += [_t(a) for a in _list(_get(item, "default_bgp_ip_addresses"))]
        addresses += [_t(a) for a in _list(_get(item, "custom_bgp_ip_addresses"))]
    return {
        "bgp_asn": _t(_get(settings, "asn")),
        "bgp_peering_addresses": [a for a in dict.fromkeys(addresses) if a],
    }


def virtual_network_gateway_resource(gateway: Any, subscription_id: str, public_ips: dict[str, str]) -> dict | None:
    """A VPN or ExpressRoute gateway, with the VNet and subnet it sits in."""
    uid, group, name = _own_uid(gateway, "virtual_network_gateway", subscription_id)
    if not name:
        return None
    configs = _list(_get(gateway, "ip_configurations"))
    subnet_uid = next((_ref(c, "subnet") for c in configs if _ref(c, "subnet")), "")
    return _resource(
        uid,
        "virtual_network_gateway",
        name=name,
        region=_t(_get(gateway, "location")),
        status=_state(gateway),
        metadata={
            "resource_group": group,
            "gateway_type": _t(_get(gateway, "gateway_type")),
            "vpn_type": _t(_get(gateway, "vpn_type")),
            "sku": _t(_get(gateway, "sku", "name")),
            "active_active": bool(_get(gateway, "active")),
            "enable_bgp": bool(_get(gateway, "enable_bgp")),
            "public_ips": _public_ips_of(configs, public_ips),
            "vnet_id": _vnet_of_subnet(subnet_uid),
            "subnet_id": rid_of(subnet_uid) if subnet_uid else "",
            **_bgp(gateway),
        },
    )


def gateway_attachment(gateway_resource: dict) -> dict | None:
    """The connection that places a virtual network gateway in its VNet."""
    meta = gateway_resource.get("metadata") or {}
    vnet_id = _t(meta.get("vnet_id"))
    if not vnet_id:
        return None
    return {
        "provider": PROVIDER,
        "source_resource_uid": f"azure:vnet:{vnet_id}",
        "target_resource_uid": gateway_resource["resource_uid"],
        "connection_type": "virtual_network_gateway_attachment",
        "state": gateway_resource.get("status") or "attached",
        "metadata": {"subnet_name": _t(meta.get("subnet_id")).rsplit("/", 1)[-1]},
    }


def local_network_gateway_resource(gateway: Any, subscription_id: str) -> dict | None:
    """The far end of a site-to-site VPN: an on-premises gateway's address
    and the ranges behind it."""
    uid, group, name = _own_uid(gateway, "local_network_gateway", subscription_id)
    if not name:
        return None
    return _resource(
        uid,
        "local_network_gateway",
        name=name,
        region=_t(_get(gateway, "location")),
        status=_state(gateway),
        metadata={
            "resource_group": group,
            "gateway_ip_address": _t(_get(gateway, "gateway_ip_address")),
            "fqdn": _t(_get(gateway, "fqdn")),
            "address_prefixes": _prefixes(_get(gateway, "local_network_address_space")),
            **_bgp(gateway),
        },
    )


def express_route_resource(circuit: Any, subscription_id: str) -> dict | None:
    uid, group, name = _own_uid(circuit, "expressroute", subscription_id)
    if not name:
        return None
    provider = _get(circuit, "service_provider_properties")
    return _resource(
        uid,
        "expressroute",
        name=name,
        region=_t(_get(circuit, "location")),
        status=_t(_get(circuit, "service_provider_provisioning_state")) or _state(circuit),
        metadata={
            "resource_group": group,
            "service_provider": _t(_get(provider, "service_provider_name")),
            "peering_location": _t(_get(provider, "peering_location")),
            "bandwidth_mbps": _get(provider, "bandwidth_in_mbps"),
            "circuit_provisioning_state": _t(_get(circuit, "circuit_provisioning_state")),
            "service_provider_provisioning_state": _t(_get(circuit, "service_provider_provisioning_state")),
            "sku_tier": _t(_get(circuit, "sku", "tier")),
            "sku_family": _t(_get(circuit, "sku", "family")),
            "service_key": "",  # never read: it identifies the circuit to the provider
            "peerings": [
                {
                    "type": _t(_get(p, "peering_type")),
                    "state": _t(_get(p, "state")),
                    "azure_asn": _t(_get(p, "azure_asn")),
                    "peer_asn": _t(_get(p, "peer_asn")),
                    "primary_peer_prefix": _t(_get(p, "primary_peer_address_prefix")),
                    "secondary_peer_prefix": _t(_get(p, "secondary_peer_address_prefix")),
                    "vlan": _get(p, "vlan_id"),
                }
                for p in _list(_get(circuit, "peerings"))
            ],
        },
    )


def gateway_connection(conn: Any, subscription_id: str) -> dict | None:
    """A virtual network gateway connection: site-to-site (IPsec) to a local
    network gateway, VNet-to-VNet, or ExpressRoute to a circuit. The shared
    key is not read."""
    source = _ref(conn, "virtual_network_gateway1")
    target = _ref(conn, "virtual_network_gateway2") or _ref(conn, "local_network_gateway2") or _ref(conn, "peer")
    if not source or not target:
        return None
    kind = _t(_get(conn, "connection_type")).lower() or "gateway_connection"
    return {
        "provider": PROVIDER,
        "source_resource_uid": source,
        "target_resource_uid": target,
        "connection_type": kind,
        "state": _state(conn),
        "metadata": {
            "name": _t(_get(conn, "name")) or resource_name(_id(conn)),
            "connection_type": _t(_get(conn, "connection_type")),
            "connection_status": _t(_get(conn, "connection_status")),
            "connection_protocol": _t(_get(conn, "connection_protocol")),
            "routing_weight": _get(conn, "routing_weight"),
            "enable_bgp": bool(_get(conn, "enable_bgp")),
            "use_policy_based_traffic_selectors": bool(_get(conn, "use_policy_based_traffic_selectors")),
            "ingress_bytes_transferred": _get(conn, "ingress_bytes_transferred"),
            "egress_bytes_transferred": _get(conn, "egress_bytes_transferred"),
            "express_route_gateway_bypass": bool(_get(conn, "express_route_gateway_bypass")),
        },
    }


# ── Routing and filtering ────────────────────────────────────────────────────


def route_table_resource(table: Any, subscription_id: str) -> dict | None:
    """A route table with every route and the subnets it is applied to."""
    uid, group, name = _own_uid(table, "route_table", subscription_id)
    if not name:
        return None
    routes = [
        {
            "name": _t(_get(r, "name")),
            "prefix": _t(_get(r, "address_prefix")),
            "next_hop_type": _t(_get(r, "next_hop_type")),
            "next_hop_ip": _t(_get(r, "next_hop_ip_address")),
        }
        for r in _list(_get(table, "routes"))
    ]
    subnet_uids = [_ref(s) for s in _list(_get(table, "subnets")) if _ref(s)]
    return _resource(
        uid,
        "route_table",
        name=name,
        region=_t(_get(table, "location")),
        status=_state(table) or "active",
        metadata={
            "resource_group": group,
            "disable_bgp_route_propagation": bool(_get(table, "disable_bgp_route_propagation")),
            "route_count": len(routes),
            "routes": routes,
            "route_summaries": routes[:20],
            "subnet_ids": [rid_of(s) for s in subnet_uids],
        },
    )


def route_table_associations(table_resource: dict) -> list[dict]:
    """One ``route_table_association`` per VNet the table's subnets are in."""
    meta = table_resource.get("metadata") or {}
    found: list[dict] = []
    for subnet_id in meta.get("subnet_ids") or []:
        vnet_id, _slash, subnet_name = _t(subnet_id).rpartition("/")
        if not vnet_id:
            continue
        found.append(
            {
                "provider": PROVIDER,
                "source_resource_uid": f"azure:vnet:{vnet_id}",
                "target_resource_uid": table_resource["resource_uid"],
                "connection_type": "route_table_association",
                "state": "attached",
                "metadata": {"subnet_name": subnet_name},
            }
        )
    return found


def _selector(rule: Any, singular: str, plural: str) -> str:
    values: list[str] = []
    single = _get(rule, singular)
    if single not in (None, ""):
        values.append(_t(single))
    values += [_t(item) for item in _list(_get(rule, plural)) if _t(item)]
    unique = list(dict.fromkeys(values))
    return ", ".join(unique) if unique else "any"


def nsg_rules(nsg: Any) -> list[dict]:
    """The explicit and default rules of a network security group, in the
    policy rule format Cloud Visibility stores."""
    rules: list[dict] = []
    explicit = _list(_get(nsg, "security_rules"))
    default = _list(_get(nsg, "default_security_rules"))
    for rule in explicit + default:
        direction = _t(_get(rule, "direction")).lower()
        direction = {"ingress": "inbound", "egress": "outbound"}.get(direction, direction)
        protocol = _t(_get(rule, "protocol")).lower() or "all"
        if protocol == "*":
            protocol = "all"
        ports = [_t(_get(rule, "destination_port_range"))] + [
            _t(p) for p in _list(_get(rule, "destination_port_ranges"))
        ]
        ports = [p for p in dict.fromkeys(ports) if p]
        rules.append(
            {
                "rule_uid": _id(rule) or _t(_get(rule, "name")),
                "rule_name": _t(_get(rule, "name")),
                "direction": direction,
                "action": _t(_get(rule, "access")).lower(),
                "protocol": protocol,
                "source_selector": _selector(rule, "source_address_prefix", "source_address_prefixes"),
                "destination_selector": _selector(rule, "destination_address_prefix", "destination_address_prefixes"),
                "port_expression": ", ".join(ports) or "all",
                "priority": _get(rule, "priority"),
                "metadata": {"is_default": rule in default, "description": _t(_get(rule, "description"))},
            }
        )
    return rules


def nsg_resource(nsg: Any, subscription_id: str) -> dict | None:
    """A network security group with its rules and what it is applied to."""
    uid, group, name = _own_uid(nsg, "nsg", subscription_id)
    if not name:
        return None
    return _resource(
        uid,
        "network_security_group",
        name=name,
        region=_t(_get(nsg, "location")),
        status=_state(nsg) or "active",
        metadata={
            "resource_group": group,
            "policy_rules": nsg_rules(nsg),
            "subnet_ids": [rid_of(_ref(s)) for s in _list(_get(nsg, "subnets")) if _ref(s)],
            "nic_ids": [rid_of(_ref(n)) for n in _list(_get(nsg, "network_interfaces")) if _ref(n)],
        },
    )


# ── Map detail: NAT gateways, virtual machines, firewalls ────────────────────


def _vnet_of_subnet(subnet_uid: str) -> str:
    return rid_of(subnet_uid).rsplit("/", 1)[0] if subnet_uid else ""


def nat_gateway_resource(gateway: Any, subscription_id: str, public_ips: dict[str, str]) -> dict | None:
    uid, group, name = _own_uid(gateway, "nat_gateway", subscription_id)
    if not name:
        return None
    subnet_uids = [_ref(s) for s in _list(_get(gateway, "subnets")) if _ref(s)]
    addresses = [public_ips.get(_id(p).lower(), "") for p in _list(_get(gateway, "public_ip_addresses"))]
    return _resource(
        uid,
        "nat_gateway",
        name=name,
        region=_t(_get(gateway, "location")),
        status=_state(gateway),
        metadata={
            "resource_group": group,
            "sku": _t(_get(gateway, "sku", "name")),
            "idle_timeout_minutes": _get(gateway, "idle_timeout_in_minutes"),
            "public_ips": [a for a in dict.fromkeys(addresses) if a],
            "subnet_ids": [rid_of(s) for s in subnet_uids],
            "vnet_ids": list(dict.fromkeys(_vnet_of_subnet(s) for s in subnet_uids if _vnet_of_subnet(s))),
        },
    )


def nat_gateway_attachments(nat_resource: dict) -> list[dict]:
    meta = nat_resource.get("metadata") or {}
    return [
        {
            "provider": PROVIDER,
            "source_resource_uid": f"azure:vnet:{vnet_id}",
            "target_resource_uid": nat_resource["resource_uid"],
            "connection_type": "nat_gateway_attachment",
            "state": nat_resource.get("status") or "attached",
            "metadata": {},
        }
        for vnet_id in meta.get("vnet_ids") or []
    ]


def _interface(nic: Any, public_ips: dict[str, str]) -> dict:
    private: list[str] = []
    public: list[str] = []
    subnet_uid = ""
    primary_config = None
    for config in _list(_get(nic, "ip_configurations")):
        address = _t(_get(config, "private_ip_address"))
        if address and address not in private:
            private.append(address)
        public_address = public_ips.get(_t(_get(config, "public_ip_address", "id")).lower(), "")
        if public_address and public_address not in public:
            public.append(public_address)
        if _get(config, "primary") or primary_config is None:
            primary_config = config
    if primary_config is not None:
        subnet_uid = _ref(primary_config, "subnet")
        # The primary configuration's address goes first.
        first = _t(_get(primary_config, "private_ip_address"))
        if first in private:
            private.remove(first)
            private.insert(0, first)
    return {
        "id": rid_of(_ref(nic)) if _ref(nic) else _t(_get(nic, "name")),
        "name": _t(_get(nic, "name")) or resource_name(_id(nic)),
        "subnet_id": rid_of(subnet_uid) if subnet_uid else "",
        "vnet_id": _vnet_of_subnet(subnet_uid),
        "primary": bool(_get(nic, "primary")),
        "mac": _t(_get(nic, "mac_address")),
        "private_ips": private,
        "public_ips": public,
        # The Azure equivalent of the AWS source/destination check being off.
        "ip_forwarding": bool(_get(nic, "enable_ip_forwarding")),
        "accelerated_networking": bool(_get(nic, "enable_accelerated_networking")),
        "network_security_group": rid_of(_ref(nic, "network_security_group"))
        if _ref(nic, "network_security_group")
        else "",
    }


def vm_resources(nics: Any, subscription_id: str, public_ips: dict[str, str]) -> list[dict]:
    """Virtual machines, as seen through their network interfaces (the
    Network API lists NICs; the Compute API is not needed). A NIC attached
    to no virtual machine (a private endpoint, a scale set) is left out."""
    by_vm: dict[str, list[tuple[Any, dict]]] = {}
    for nic in _list(nics):
        vm_id = _t(_get(nic, "virtual_machine", "id"))
        if not vm_id:
            continue
        by_vm.setdefault(vm_id, []).append((nic, _interface(nic, public_ips)))
    found: list[dict] = []
    for vm_id, pairs in by_vm.items():
        uid = resource_uid(vm_id, subscription_id)
        if not uid:
            continue
        pairs.sort(key=lambda pair: (not pair[1]["primary"], pair[1]["name"]))
        interfaces = [interface for _nic, interface in pairs]
        primary = interfaces[0]
        found.append(
            _resource(
                uid,
                "vm",
                name=resource_name(vm_id),
                region=_t(_get(pairs[0][0], "location")),
                # The Network API does not tell the power state.
                status="",
                metadata={
                    "vm_id": rid_of(uid),
                    "resource_group": resource_parts(vm_id).get("resourcegroups", ""),
                    "vnet_id": primary["vnet_id"],
                    "subnet_id": primary["subnet_id"],
                    "private_ip": primary["private_ips"][0] if primary["private_ips"] else "",
                    "public_ip": next((ip for i in interfaces for ip in i["public_ips"]), ""),
                    "ip_forwarding": any(i["ip_forwarding"] for i in interfaces),
                    "network_security_group_ids": [
                        i["network_security_group"] for i in interfaces if i["network_security_group"]
                    ],
                    "interfaces": interfaces,
                },
            )
        )
    return found


def firewall_resource(firewall: Any, subscription_id: str, public_ips: dict[str, str]) -> dict | None:
    """An Azure Firewall: the managed appliance of a hub VNet."""
    uid, group, name = _own_uid(firewall, "firewall", subscription_id)
    if not name:
        return None
    configs = _list(_get(firewall, "ip_configurations"))
    subnet_uid = next((_ref(c, "subnet") for c in configs if _ref(c, "subnet")), "")
    private = [_t(_get(c, "private_ip_address")) for c in configs if _t(_get(c, "private_ip_address"))]
    return _resource(
        uid,
        "azure_firewall",
        name=name,
        region=_t(_get(firewall, "location")),
        status=_state(firewall),
        metadata={
            "resource_group": group,
            "sku": _t(_get(firewall, "sku", "name")),
            "tier": _t(_get(firewall, "sku", "tier")),
            "threat_intel_mode": _t(_get(firewall, "threat_intel_mode")),
            "firewall_policy": resource_name(_t(_get(firewall, "firewall_policy", "id"))),
            # The policy's Azure resource ID: the collector reads its DNAT rules by it.
            "firewall_policy_id": _t(_get(firewall, "firewall_policy", "id")),
            "private_ip": private[0] if private else "",
            "private_ips": private,
            "public_ips": _public_ips_of(configs, public_ips),
            "subnet_id": rid_of(subnet_uid) if subnet_uid else "",
            "vnet_id": _vnet_of_subnet(subnet_uid),
            "dnat_rules": firewall_dnat_rules(firewall),
        },
    )


def _texts(values: Any) -> list[str]:
    return [_t(v) for v in _list(values) if _t(v)]


def _priority(model: Any) -> int:
    return p if isinstance(p := _get(model, "priority"), int) else 0


def _dnat_row(rule: Any, *, collection: Any, protocols: Any, sources: list[str], source: str, **extra: Any) -> dict:
    """One DNAT rule, the same row for a classic rule and a firewall policy one."""
    return {
        "source": source,
        **extra,
        "collection": _t(_get(collection, "name")),
        "priority": _get(collection, "priority"),
        "action": _t(_get(collection, "action", "type")) or "Dnat",
        "name": _t(_get(rule, "name")),
        "protocols": _texts(protocols),
        "source_addresses": sources,
        "destination_addresses": _texts(_get(rule, "destination_addresses")),
        "destination_ports": _texts(_get(rule, "destination_ports")),
        "translated_address": _t(_get(rule, "translated_address")) or _t(_get(rule, "translated_fqdn")),
        "translated_port": _t(_get(rule, "translated_port")),
    }


def firewall_dnat_rules(firewall: Any) -> list[dict]:
    """The DNAT rules of an Azure Firewall's classic NAT rule collections,
    in priority order (``source`` "classic"). A firewall managed by a
    firewall policy keeps its rules in the policy's rule collection groups:
    ``firewall_policy_dnat_rules`` reads those."""
    rules: list[dict] = []
    for collection in sorted(_list(_get(firewall, "nat_rule_collections")), key=_priority):
        for rule in _list(_get(collection, "rules")):
            rules.append(
                _dnat_row(
                    rule,
                    collection=collection,
                    protocols=_get(rule, "protocols"),
                    sources=_texts(_get(rule, "source_addresses")),
                    source="classic",
                )
            )
    return rules


def firewall_policy_dnat_rules(groups: Any, policy_name: str) -> list[dict]:
    """The DNAT rules of one Azure Firewall Policy, from its rule collection
    groups (``firewall_policy_rule_collection_groups.list``), in the order
    the firewall applies them: group priority, then collection priority.
    Only NAT rule collections (``FirewallPolicyNatRuleCollection``) and
    their NAT rules are read; network and application rules are not. A rule
    that names IP groups lists them by name among its sources."""
    rules: list[dict] = []
    for group in sorted(_list(groups), key=_priority):
        collections = [
            c
            for c in _list(_get(group, "rule_collections"))
            if _t(_get(c, "rule_collection_type")) == "FirewallPolicyNatRuleCollection"
        ]
        for collection in sorted(collections, key=_priority):
            for rule in _list(_get(collection, "rules")):
                if _t(_get(rule, "rule_type")) not in ("", "NatRule"):
                    continue
                ip_groups = [resource_name(g) for g in _texts(_get(rule, "source_ip_groups"))]
                rules.append(
                    _dnat_row(
                        rule,
                        collection=collection,
                        protocols=_get(rule, "ip_protocols"),
                        sources=[*_texts(_get(rule, "source_addresses")), *[g for g in ip_groups if g]],
                        source="policy",
                        policy=policy_name,
                        collection_group=_t(_get(group, "name")),
                        group_priority=_get(group, "priority"),
                    )
                )
    return rules


# ── Services with endpoints: load balancers, application gateways, private endpoints ──


def interface_table(nics: Any, public_ips: dict[str, str]) -> dict[str, dict]:
    """Network interface resource ID (lower case) -> its ``_interface``
    record, for the services that name their interfaces by ID."""
    return {_id(nic).lower(): _interface(nic, public_ips) for nic in _list(nics) if _id(nic)}


def _nic_of(ip_configuration_id: str) -> str:
    """``…/networkInterfaces/N/ipConfigurations/C`` -> ``…/networkInterfaces/N`` (lower case)."""
    head, sep, _tail = _t(ip_configuration_id).lower().partition("/ipconfigurations/")
    return head if sep else ""


def _frontends(configs: Any, public_ips: dict[str, str]) -> tuple[list[dict | None], list[str]]:
    """``(endpoints, subnet uids)`` of frontend IP configurations: an
    endpoint per private address (a public one is in ``_public_ips_of``)."""
    endpoints: list[dict | None] = []
    subnets: list[str] = []
    for config in _list(configs):
        name = _t(_get(config, "name")) or resource_name(_id(config))
        endpoints.append(endpoint(f"Frontend {name}".strip(), "", None, [_t(_get(config, "private_ip_address"))]))
        subnet = _ref(config, "subnet")
        if subnet and subnet not in subnets:
            subnets.append(subnet)
    return endpoints, subnets


def _ports(start: Any, end: Any = None) -> str:
    """``443``, ``50000-50099``, or ``all`` for port 0 (the HA ports rule)."""
    if isinstance(end, int) and isinstance(start, int) and end != start:
        return f"{start}-{end}"
    return "all" if start in (0, None, "") else _t(start)


def _forwarding(rule: Any, frontend_port: str, label: str = "") -> dict:
    return {
        "name": _t(_get(rule, "name")),
        "protocol": _t(_get(rule, "protocol")),
        "frontend": resource_name(_t(_get(rule, "frontend_ip_configuration", "id"))),
        "frontend_port": frontend_port,
        "backend_port": _ports(_get(rule, "backend_port")),
        "label": label,
    }


def _forwarding_summary(rule: dict) -> str:
    """``TCP 443 -> 8443``, ``NAT TCP 50000-50099 -> 22``."""
    text = f"{rule['protocol']} {rule['frontend_port']} -> {rule['backend_port']}".strip()
    return f"{rule['label']} {text}".strip()


def load_balancer_resource(
    lb: Any, subscription_id: str, public_ips: dict[str, str], interfaces: dict[str, dict] | None = None
) -> dict | None:
    """An Azure Load Balancer: its frontends (private address and subnet,
    or public IP), backend pools, load-balancing and inbound NAT rules.

    A public load balancer sits in no subnet; it is placed in the VNet of
    its backends, through ``interfaces`` (``interface_table``) or the VNet
    an IP-based backend pool names."""
    uid, group, name = _own_uid(lb, LOAD_BALANCER_TYPE, subscription_id)
    if not name:
        return None
    configs = _list(_get(lb, "frontend_ip_configurations"))
    endpoints, subnet_uids = _frontends(configs, public_ips)
    public = _public_ips_of(configs, public_ips)
    pools = _list(_get(lb, "backend_address_pools"))
    backend_vnets: list[str] = []
    for pool in pools:
        refs = [_ref(pool, "virtual_network")]
        refs += [_ref(a, "virtual_network") for a in _list(_get(pool, "load_balancer_backend_addresses"))]
        for config in _list(_get(pool, "backend_ip_configurations")):
            interface = (interfaces or {}).get(_nic_of(_id(config))) or {}
            refs.append(f"azure:vnet:{interface['vnet_id']}" if interface.get("vnet_id") else "")
        backend_vnets += [rid_of(r) for r in refs if r]
    vnets = [_vnet_of_subnet(s) for s in subnet_uids] + backend_vnets
    rules = [_forwarding(r, _ports(_get(r, "frontend_port"))) for r in _list(_get(lb, "load_balancing_rules"))] + [
        _forwarding(
            r,
            _ports(_get(r, "frontend_port_range_start"), _get(r, "frontend_port_range_end"))
            if _get(r, "frontend_port_range_start")
            else _ports(_get(r, "frontend_port")),
            "NAT",
        )
        for r in [*_list(_get(lb, "inbound_nat_rules")), *_list(_get(lb, "inbound_nat_pools"))]
    ]
    sku = _t(_get(lb, "sku", "name"))
    scheme = "Public" if public or any(_get(c, "public_ip_address") for c in configs) else "Internal"
    vnet_id = vnets[0] if vnets else ""
    return service_record(
        PROVIDER,
        uid,
        LOAD_BALANCER_TYPE,
        rid_of(uid),
        name=name,
        region=_t(_get(lb, "location")),
        status=_state(lb),
        kind="Gateway load balancer" if sku.lower() == "gateway" else f"{scheme} load balancer",
        vpc_id=vnet_id,
        subnet_ids=[rid_of(s) for s in subnet_uids],
        endpoints=endpoints,
        public_ips=public,
        resource_group=group,
        vnet_id=vnet_id,
        scheme=scheme,
        sku=sku,
        tier=_t(_get(lb, "sku", "tier")),
        frontend_count=len(configs),
        backend_pool_count=len(pools),
        forwarding_rules=rules,
        rules=[_forwarding_summary(r) for r in rules],
    )


def application_gateway_resource(gateway: Any, subscription_id: str, public_ips: dict[str, str]) -> dict | None:
    """An Application Gateway: its frontends, the subnet its instances run
    in, its listeners (protocol, port, host names) and whether a web
    application firewall inspects its traffic. Certificates are not read."""
    uid, group, name = _own_uid(gateway, APPLICATION_GATEWAY_TYPE, subscription_id)
    if not name:
        return None
    configs = _list(_get(gateway, "frontend_ip_configurations"))
    endpoints, subnet_uids = _frontends(configs, public_ips)
    for config in _list(_get(gateway, "gateway_ip_configurations")):
        subnet = _ref(config, "subnet")
        if subnet and subnet not in subnet_uids:
            subnet_uids.append(subnet)
    ports = {_id(p).lower(): _get(p, "port") for p in _list(_get(gateway, "frontend_ports"))}
    public_frontends = {_id(c).lower() for c in configs if _get(c, "public_ip_address")}
    listeners: list[dict] = []
    for listener in [*_list(_get(gateway, "http_listeners")), *_list(_get(gateway, "listeners"))]:
        hosts = _texts(_get(listener, "host_names")) or _texts([_get(listener, "host_name")])
        frontend = _t(_get(listener, "frontend_ip_configuration", "id")).lower()
        listeners.append(
            {
                "name": _t(_get(listener, "name")),
                "protocol": _t(_get(listener, "protocol")),
                "port": ports.get(_t(_get(listener, "frontend_port", "id")).lower()),
                "host_names": hosts,
                "frontend": "public" if frontend in public_frontends else "private",
            }
        )
        endpoints += [
            endpoint(f"{listeners[-1]['protocol']} listener".strip(), host, listeners[-1]["port"]) for host in hosts
        ]
    waf = _get(gateway, "web_application_firewall_configuration")
    tier = _t(_get(gateway, "sku", "tier"))
    vnet_id = next((_vnet_of_subnet(s) for s in subnet_uids), "")
    return service_record(
        PROVIDER,
        uid,
        APPLICATION_GATEWAY_TYPE,
        rid_of(uid),
        name=name,
        region=_t(_get(gateway, "location")),
        # Running / Stopped, else how its last change went.
        status=_t(_get(gateway, "operational_state")) or _state(gateway),
        kind="Application gateway",
        vpc_id=vnet_id,
        subnet_ids=[rid_of(s) for s in subnet_uids],
        endpoints=endpoints,
        public_ips=_public_ips_of(configs, public_ips),
        resource_group=group,
        vnet_id=vnet_id,
        sku=_t(_get(gateway, "sku", "name")),
        tier=tier,
        capacity=_get(gateway, "sku", "capacity"),
        provisioning_state=_state(gateway),
        waf_enabled=bool(_get(waf, "enabled")) or bool(_t(_get(gateway, "firewall_policy", "id"))),
        waf_mode=_t(_get(waf, "firewall_mode")),
        firewall_policy=resource_name(_t(_get(gateway, "firewall_policy", "id"))),
        listener_details=listeners,
        listeners=[
            " ".join(p for p in (item["protocol"], _t(item["port"]), ", ".join(item["host_names"])) if p)
            for item in listeners
        ],
    )


def _target_type(resource_id: str) -> str:
    """``…/providers/Microsoft.Storage/storageAccounts/x`` -> ``Microsoft.Storage/storageAccounts``."""
    parts = [p for p in _t(resource_id).split("/") if p]
    lowered = [p.lower() for p in parts]
    if "providers" not in lowered:
        return ""
    index = len(lowered) - 1 - lowered[::-1].index("providers")
    return "/".join(parts[index + 1 : index + 3])


def private_endpoint_resource(pe: Any, subscription_id: str, interfaces: dict[str, dict] | None = None) -> dict | None:
    """A private endpoint: the address it gives a PaaS resource (a storage
    account, a database, another subscription's Private Link service) in a
    subnet, with that resource's ID, the sub-resources (group IDs) it
    reaches and the state of its connection. ``interfaces``
    (``interface_table``) give its network interface."""
    uid, group, name = _own_uid(pe, PRIVATE_ENDPOINT_TYPE, subscription_id)
    if not name:
        return None
    subnet_uid = _ref(pe, "subnet")
    automatic = _list(_get(pe, "private_link_service_connections"))
    manual = _list(_get(pe, "manual_private_link_service_connections"))
    connection = next(iter(automatic or manual), None)
    target = _t(_get(connection, "private_link_service_id"))
    endpoints: list[dict | None] = [
        endpoint("Private endpoint", _get(c, "fqdn"), None, _texts(_get(c, "ip_addresses")))
        for c in _list(_get(pe, "custom_dns_configs"))
    ]
    listed = unique_addresses(*[e["ip_addresses"] for e in endpoints if e])
    for config in _list(_get(pe, "ip_configurations")):
        address = _t(_get(config, "private_ip_address"))
        if address and address not in listed:
            endpoints.append(endpoint(f"Private endpoint {_t(_get(config, 'group_id'))}".strip(), "", None, [address]))
    known = interfaces or {}
    nic_ids = [_id(n) for n in _list(_get(pe, "network_interfaces")) if _id(n)]
    found = [known[n.lower()] for n in nic_ids if n.lower() in known]
    vnet_id = _vnet_of_subnet(subnet_uid)
    return service_record(
        PROVIDER,
        uid,
        PRIVATE_ENDPOINT_TYPE,
        rid_of(uid),
        name=name,
        region=_t(_get(pe, "location")),
        status=_state(pe),
        kind="Private endpoint",
        vpc_id=vnet_id,
        subnet_ids=[rid_of(subnet_uid)] if subnet_uid else [],
        security_group_ids=list(
            dict.fromkeys(i["network_security_group"] for i in found if i["network_security_group"])
        ),
        endpoints=endpoints,
        network_interface_ids=[rid_of(resource_uid(n)) for n in nic_ids if resource_uid(n)],
        interfaces=found,
        resource_group=group,
        vnet_id=vnet_id,
        target_id=target,
        target_name=resource_name(target),
        target_type=_target_type(target),
        group_ids=unique_addresses(*[_texts(_get(c, "group_ids")) for c in automatic + manual]),
        connection_state=_t(_get(connection, "private_link_service_connection_state", "status")),
        manual_approval=bool(manual) and not automatic,
    )
