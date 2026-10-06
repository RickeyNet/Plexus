"""Demo Azure discovery (no credentials needed).

The records have the shape the Cloud Visibility Azure collector returns, so
sample discovery exercises the same path to the Topology map as a live one:
a hub VNet with a VPN gateway, an ExpressRoute gateway and an Azure
Firewall, a production VNet peered to it that uses the hub's gateways and
sends its internet traffic through the firewall, a VNet in another region,
a site-to-site VPN with one connection down, an ExpressRoute circuit, a NAT
gateway, a virtual appliance that forwards traffic, and the network security
groups that decide what the database subnet accepts.
Addresses are from the documentation ranges.
"""

from __future__ import annotations

from typing import Any

SUBSCRIPTION = "sample"
_EAST = "eastus"
_WEST = "westus2"

HUB, PROD, WEST = (
    f"{SUBSCRIPTION}:rg-hub:hub-vnet",
    f"{SUBSCRIPTION}:rg-prod:prod-vnet",
    f"{SUBSCRIPTION}:rg-west:apps-west-vnet",
)
# A VNet of another subscription the hub is peered with; not collected.
SHARED = "11111111-2222-3333-4444-555555555555:rg-shared:shared-services-vnet"


def _res(
    uid: str, kind: str, name: str, region: str, *, cidr: str = "", status: str = "Succeeded", **meta: Any
) -> dict:
    return {
        "resource_uid": f"azure:{uid}",
        "resource_type": kind,
        "name": name,
        "region": region,
        "cidr": cidr,
        "status": status,
        "metadata": meta,
    }


def _conn(source: str, target: str, kind: str, state: str = "Succeeded", **meta: Any) -> dict:
    return {
        "source_resource_uid": f"azure:{source}",
        "target_resource_uid": f"azure:{target}",
        "connection_type": kind,
        "state": state,
        "metadata": meta,
    }


def _subnet(vnet: str, name: str, cidr: str, region: str = _EAST, **meta: Any) -> dict:
    return _res(
        f"subnet:{vnet}/{name}",
        "subnet",
        name,
        region,
        cidr=cidr,
        subnet_name=name,
        vnet_id=vnet,
        vnet_name=vnet.rsplit(":", 1)[-1],
        address_prefixes=[cidr],
        # References are resource uids, as the collector stores them.
        route_table=f"azure:route_table:{meta.pop('route_table')}" if meta.get("route_table") else "",
        network_security_group=f"azure:nsg:{meta.pop('nsg')}" if meta.get("nsg") else "",
        nat_gateway=f"azure:nat_gateway:{meta.pop('nat')}" if meta.get("nat") else "",
        delegations=meta.pop("delegations", []),
        service_endpoints=[],
        ip_configuration_count=meta.pop("used", 0),
    )


def _vm(
    rid: str,
    vnet: str,
    interfaces: list[tuple[str, str, str]],
    *,
    forwards: bool = False,
    nsg: str = "",
    region: str = _EAST,
) -> dict:
    """``interfaces`` are ``(subnet name, private IP, public IP)`` with the primary first."""
    name = rid.rsplit(":", 1)[-1]
    nics = [
        {
            "id": f"{rid}-nic{index}",
            "name": f"{name}-nic{index}",
            "subnet_id": f"{vnet}/{subnet}",
            "vnet_id": vnet,
            "primary": index == 0,
            "mac": "",
            "private_ips": [private],
            "public_ips": [public] if public else [],
            "ip_forwarding": forwards,
            "accelerated_networking": False,
            "network_security_group": nsg,
        }
        for index, (subnet, private, public) in enumerate(interfaces)
    ]
    return _res(
        f"vm:{rid}",
        "vm",
        name,
        region,
        status="",
        vm_id=rid,
        resource_group=rid.split(":")[1],
        vnet_id=vnet,
        subnet_id=nics[0]["subnet_id"],
        private_ip=nics[0]["private_ips"][0],
        public_ip=next((public for _s, _p, public in interfaces if public), ""),
        ip_forwarding=forwards,
        network_security_group_ids=[nsg] if nsg else [],
        interfaces=nics,
    )


def _rule(
    name: str, priority: int, direction: str, action: str, protocol: str, ports: str, source: str, destination: str
) -> dict:
    return {
        "rule_uid": f"{name}",
        "rule_name": name,
        "direction": direction,
        "action": action,
        "protocol": protocol,
        "source_selector": source,
        "destination_selector": destination,
        "port_expression": ports,
        "priority": priority,
        "metadata": {"is_default": priority >= 65000, "description": ""},
    }


# The rules Azure ends every network security group with.
_DEFAULT_RULES = [
    _rule("AllowVnetInBound", 65000, "inbound", "allow", "all", "all", "VirtualNetwork", "VirtualNetwork"),
    _rule("AllowAzureLoadBalancerInBound", 65001, "inbound", "allow", "all", "all", "AzureLoadBalancer", "*"),
    _rule("DenyAllInBound", 65500, "inbound", "deny", "all", "all", "*", "*"),
    _rule("AllowVnetOutBound", 65000, "outbound", "allow", "all", "all", "VirtualNetwork", "VirtualNetwork"),
    _rule("AllowInternetOutBound", 65001, "outbound", "allow", "all", "all", "*", "Internet"),
    _rule("DenyAllOutBound", 65500, "outbound", "deny", "all", "all", "*", "*"),
]


def _nsg(rid: str, rules: list[dict], subnets: list[str], nics: list[str] | None = None, region: str = _EAST) -> dict:
    return _res(
        f"nsg:{rid}",
        "network_security_group",
        rid.rsplit(":", 1)[-1],
        region,
        resource_group=rid.split(":")[1],
        policy_rules=[*rules, *_DEFAULT_RULES],
        subnet_ids=subnets,
        nic_ids=nics or [],
    )


def _route(name: str, prefix: str, next_hop_type: str, next_hop_ip: str = "") -> dict:
    return {"name": name, "prefix": prefix, "next_hop_type": next_hop_type, "next_hop_ip": next_hop_ip}


def _peering(source: str, target: str, name: str, remote: str, **flags: bool) -> dict:
    return _conn(
        f"vnet:{source}",
        f"vnet:{target}",
        "vnet_peering",
        "Connected",
        name=name,
        allow_virtual_network_access=True,
        allow_forwarded_traffic=flags.get("forwarded", True),
        allow_gateway_transit=flags.get("transit", False),
        use_remote_gateways=flags.get("remote_gateways", False),
        remote_address_space=[remote],
        peering_sync_level="FullyInSync",
    )


def build_sample() -> tuple[list[dict], list[dict]]:
    """``(resources, connections)`` of the demo Azure subscription."""
    vgw, ergw = f"{SUBSCRIPTION}:rg-hub:vgw-hub", f"{SUBSCRIPTION}:rg-hub:ergw-hub"
    firewall = f"{SUBSCRIPTION}:rg-hub:azfw-hub"
    lng_hq, lng_dr = f"{SUBSCRIPTION}:rg-hub:lng-hq", f"{SUBSCRIPTION}:rg-hub:lng-dr"
    circuit = f"{SUBSCRIPTION}:rg-hub:er-primary"
    rt_prod, nat_prod = f"{SUBSCRIPTION}:rg-prod:rt-prod", f"{SUBSCRIPTION}:rg-prod:nat-prod"
    nsg_app, nsg_db, nsg_mgmt = (
        f"{SUBSCRIPTION}:rg-prod:nsg-app",
        f"{SUBSCRIPTION}:rg-prod:nsg-db",
        f"{SUBSCRIPTION}:rg-hub:nsg-mgmt",
    )
    resources = [
        _res(
            f"vnet:{HUB}",
            "vnet",
            "hub-vnet",
            _EAST,
            cidr="10.230.0.0/16",
            resource_group="rg-hub",
            address_prefixes=["10.230.0.0/16"],
            dns_servers=[],
            subnet_count=4,
        ),
        _res(
            f"vnet:{PROD}",
            "vnet",
            "prod-vnet",
            _EAST,
            cidr="10.231.0.0/16",
            resource_group="rg-prod",
            address_prefixes=["10.231.0.0/16"],
            dns_servers=["10.230.2.5"],
            subnet_count=2,
        ),
        _res(
            f"vnet:{WEST}",
            "vnet",
            "apps-west-vnet",
            _WEST,
            cidr="10.232.0.0/16",
            resource_group="rg-west",
            address_prefixes=["10.232.0.0/16"],
            dns_servers=[],
            subnet_count=1,
        ),
        _subnet(HUB, "GatewaySubnet", "10.230.0.0/26", used=2),
        _subnet(HUB, "AzureFirewallSubnet", "10.230.1.0/26", used=1),
        _subnet(HUB, "hub-mgmt", "10.230.2.0/24", nsg=nsg_mgmt, used=1),
        _subnet(HUB, "hub-nva", "10.230.3.0/24", used=1),
        _subnet(PROD, "app", "10.231.10.0/24", route_table=rt_prod, nsg=nsg_app, nat=nat_prod, used=1),
        _subnet(PROD, "db", "10.231.20.0/24", route_table=rt_prod, nsg=nsg_db, used=1),
        _subnet(WEST, "web", "10.232.1.0/24", _WEST, used=1),
        _res(
            f"virtual_network_gateway:{vgw}",
            "virtual_network_gateway",
            "vgw-hub",
            _EAST,
            resource_group="rg-hub",
            gateway_type="Vpn",
            vpn_type="RouteBased",
            sku="VpnGw1",
            active_active=False,
            enable_bgp=True,
            public_ips=["203.0.113.201"],
            vnet_id=HUB,
            subnet_id=f"{HUB}/GatewaySubnet",
            bgp_asn="65515",
            bgp_peering_addresses=["10.230.0.62"],
        ),
        _res(
            f"virtual_network_gateway:{ergw}",
            "virtual_network_gateway",
            "ergw-hub",
            _EAST,
            resource_group="rg-hub",
            gateway_type="ExpressRoute",
            vpn_type="",
            sku="ErGw1AZ",
            active_active=False,
            enable_bgp=False,
            public_ips=[],
            vnet_id=HUB,
            subnet_id=f"{HUB}/GatewaySubnet",
            bgp_asn="",
            bgp_peering_addresses=[],
        ),
        _res(
            f"local_network_gateway:{lng_hq}",
            "local_network_gateway",
            "lng-hq",
            _EAST,
            resource_group="rg-hub",
            gateway_ip_address="198.51.100.20",
            fqdn="",
            address_prefixes=["10.10.0.0/16"],
            bgp_asn="65010",
            bgp_peering_addresses=["10.10.0.1"],
        ),
        _res(
            f"local_network_gateway:{lng_dr}",
            "local_network_gateway",
            "lng-dr",
            _EAST,
            resource_group="rg-hub",
            gateway_ip_address="198.51.100.30",
            fqdn="",
            address_prefixes=["10.20.0.0/16"],
            bgp_asn="",
            bgp_peering_addresses=[],
        ),
        _res(
            f"expressroute:{circuit}",
            "expressroute",
            "er-primary",
            _EAST,
            status="Provisioned",
            resource_group="rg-hub",
            service_provider="Equinix",
            peering_location="Washington DC",
            bandwidth_mbps=1000,
            circuit_provisioning_state="Enabled",
            service_provider_provisioning_state="Provisioned",
            sku_tier="Standard",
            sku_family="MeteredData",
            service_key="",
            peerings=[
                {
                    "type": "AzurePrivatePeering",
                    "state": "Enabled",
                    "azure_asn": "12076",
                    "peer_asn": "65010",
                    "primary_peer_prefix": "192.0.2.0/30",
                    "secondary_peer_prefix": "192.0.2.4/30",
                    "vlan": 310,
                }
            ],
        ),
        _res(
            f"route_table:{rt_prod}",
            "route_table",
            "rt-prod",
            _EAST,
            status="Succeeded",
            resource_group="rg-prod",
            disable_bgp_route_propagation=False,
            route_count=3,
            routes=[
                _route("to-internet-via-firewall", "0.0.0.0/0", "VirtualAppliance", "10.230.1.4"),
                _route("local", "10.231.0.0/16", "VnetLocal"),
                _route("drop-legacy", "10.99.0.0/16", "None"),
            ],
            route_summaries=[],
            subnet_ids=[f"{PROD}/app", f"{PROD}/db"],
        ),
        _res(
            f"nat_gateway:{nat_prod}",
            "nat_gateway",
            "nat-prod",
            _EAST,
            resource_group="rg-prod",
            sku="Standard",
            idle_timeout_minutes=4,
            public_ips=["203.0.113.80"],
            subnet_ids=[f"{PROD}/app"],
            vnet_ids=[PROD],
        ),
        _res(
            f"firewall:{firewall}",
            "azure_firewall",
            "azfw-hub",
            _EAST,
            resource_group="rg-hub",
            sku="AZFW_VNet",
            tier="Standard",
            threat_intel_mode="Alert",
            firewall_policy="hub-policy",
            private_ip="10.230.1.4",
            private_ips=["10.230.1.4"],
            public_ips=["203.0.113.70"],
            subnet_id=f"{HUB}/AzureFirewallSubnet",
            vnet_id=HUB,
        ),
        _vm(f"{SUBSCRIPTION}:rg-hub:vmx-hub-1", HUB, [("hub-nva", "10.230.3.10", "203.0.113.61")], forwards=True),
        _vm(f"{SUBSCRIPTION}:rg-hub:mgmt-jump", HUB, [("hub-mgmt", "10.230.2.5", "")]),
        _vm(f"{SUBSCRIPTION}:rg-prod:app-vm-1", PROD, [("app", "10.231.10.21", "")]),
        _vm(f"{SUBSCRIPTION}:rg-prod:db-vm-1", PROD, [("db", "10.231.20.31", "")]),
        _vm(f"{SUBSCRIPTION}:rg-west:web-vm-1", WEST, [("web", "10.232.1.11", "203.0.113.91")], region=_WEST),
        _nsg(
            nsg_app,
            [
                _rule("AllowHttpsFromCorp", 100, "inbound", "allow", "tcp", "443", "10.0.0.0/8", "*"),
                _rule("AllowSshFromMgmt", 110, "inbound", "allow", "tcp", "22", "10.230.2.0/24", "*"),
                _rule("DenyVnetInBound", 200, "inbound", "deny", "all", "all", "VirtualNetwork", "*"),
            ],
            [f"{PROD}/app"],
        ),
        _nsg(
            nsg_db,
            [
                # Only the application subnet reaches the database.
                _rule("AllowPostgresFromApp", 100, "inbound", "allow", "tcp", "5432", "10.231.10.0/24", "*"),
                _rule("AllowSshFromMgmt", 110, "inbound", "allow", "tcp", "22", "10.230.2.0/24", "*"),
                _rule("DenyVnetInBound", 200, "inbound", "deny", "all", "all", "VirtualNetwork", "*"),
                _rule("DenyInternetOutBound", 100, "outbound", "deny", "all", "all", "*", "Internet"),
            ],
            [f"{PROD}/db"],
        ),
        _nsg(
            nsg_mgmt,
            [_rule("AllowSshFromCorp", 100, "inbound", "allow", "tcp", "22", "10.0.0.0/8", "*")],
            [f"{HUB}/hub-mgmt"],
        ),
    ]
    connections = [
        _peering(HUB, PROD, "hub-to-prod", "10.231.0.0/16", transit=True),
        _peering(PROD, HUB, "prod-to-hub", "10.230.0.0/16", remote_gateways=True),
        _peering(PROD, WEST, "prod-to-west", "10.232.0.0/16"),
        _peering(WEST, PROD, "west-to-prod", "10.231.0.0/16"),
        _peering(HUB, SHARED, "hub-to-shared", "10.250.0.0/16", transit=True),
        _conn(
            f"vnet:{HUB}",
            f"virtual_network_gateway:{vgw}",
            "virtual_network_gateway_attachment",
            subnet_name="GatewaySubnet",
        ),
        _conn(
            f"vnet:{HUB}",
            f"virtual_network_gateway:{ergw}",
            "virtual_network_gateway_attachment",
            subnet_name="GatewaySubnet",
        ),
        _conn(f"vnet:{PROD}", f"nat_gateway:{nat_prod}", "nat_gateway_attachment"),
        _conn(f"vnet:{PROD}", f"route_table:{rt_prod}", "route_table_association", "attached", subnet_name="app"),
        _conn(
            f"virtual_network_gateway:{vgw}",
            f"local_network_gateway:{lng_hq}",
            "ipsec",
            name="hq-s2s",
            connection_type="IPsec",
            connection_status="Connected",
            connection_protocol="IKEv2",
            routing_weight=10,
            enable_bgp=True,
            use_policy_based_traffic_selectors=False,
            ingress_bytes_transferred=48213991,
            egress_bytes_transferred=39120044,
            express_route_gateway_bypass=False,
        ),
        _conn(
            f"virtual_network_gateway:{vgw}",
            f"local_network_gateway:{lng_dr}",
            "ipsec",
            name="dr-s2s",
            connection_type="IPsec",
            connection_status="NotConnected",
            connection_protocol="IKEv2",
            routing_weight=0,
            enable_bgp=False,
            use_policy_based_traffic_selectors=False,
            ingress_bytes_transferred=0,
            egress_bytes_transferred=0,
            express_route_gateway_bypass=False,
        ),
        _conn(
            f"virtual_network_gateway:{ergw}",
            f"expressroute:{circuit}",
            "expressroute",
            name="er-primary-connection",
            connection_type="ExpressRoute",
            connection_status="Connected",
            connection_protocol="",
            routing_weight=0,
            enable_bgp=False,
            use_policy_based_traffic_selectors=False,
            ingress_bytes_transferred=902113344,
            egress_bytes_transferred=771002911,
            express_route_gateway_bypass=False,
        ),
    ]
    return resources, connections
