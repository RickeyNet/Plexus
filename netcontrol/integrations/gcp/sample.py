"""Demo GCP discovery (no credentials needed).

The demo is written as the Compute Engine API answers it and reshaped by
``netcontrol.integrations.gcp.collect``, so sample discovery exercises the
same path to the Topology map as a live one: a hub network with global
routing, a Cloud Router that learns the on-premises ranges over BGP, an HA
VPN gateway with two tunnels to an external VPN gateway (one established,
one not), a Dedicated Interconnect with its VLAN attachment, a Cloud NAT
that serves the management subnet, a Meraki vMX-style appliance that a
static route hands branch traffic to, a production network peered to the
hub whose database subnet is guarded by firewall rules, and a peering to a
network of another project that is not collected. Load balancers and
Private Service Connect (``_load_balancing``) are listed in the networks'
details.
Addresses are from the documentation ranges.
"""

from __future__ import annotations

from typing import Any

from netcontrol.integrations.gcp.collect import assemble

PROJECT = "sample"
# A project the hub is peered with; not collected.
SHARED_PROJECT = "shared-services-prj"
_REGION = "us-central1"
_EU = "europe-west1"
_ZONE = "us-central1-a"
_BASE = "https://www.googleapis.com/compute/v1/projects"

HUB, PROD = f"{PROJECT}:hub-vpc", f"{PROJECT}:prod-vpc"
SHARED = f"{SHARED_PROJECT}:shared-vpc"


def _link(path: str, project: str = PROJECT) -> str:
    return f"{_BASE}/{project}/{path}"


def _network(name: str, project: str = PROJECT) -> str:
    return _link(f"global/networks/{name}", project)


def _regional(kind: str, name: str, region: str = _REGION) -> str:
    return _link(f"regions/{region}/{kind}/{name}")


def _subnet(name: str, network: str, cidr: str, region: str = _REGION, **extra: Any) -> dict:
    return {
        "name": name,
        "selfLink": _regional("subnetworks", name, region),
        "region": _link(f"regions/{region}"),
        "network": _network(network),
        "ipCidrRange": cidr,
        "gatewayAddress": cidr.rsplit(".", 1)[0] + ".1",
        "privateIpGoogleAccess": extra.pop("google_access", False),
        "secondaryIpRanges": extra.pop("secondary", []),
        "stackType": "IPV4_ONLY",
        "purpose": "PRIVATE",
    }


def _route(
    name: str, network: str, dest: str, priority: int = 1000, *, tags: list[str] | None = None, **hop: str
) -> dict:
    return {
        "name": name,
        "selfLink": _link(f"global/routes/{name}"),
        "network": _network(network),
        "destRange": dest,
        "priority": priority,
        "routeType": "STATIC",
        **({"tags": tags} if tags else {}),
        **hop,
    }


def _firewall(
    name: str,
    network: str,
    *,
    allowed: list[tuple[str, list[str]]] | None = None,
    denied: list[tuple[str, list[str]]] | None = None,
    priority: int = 1000,
    direction: str = "INGRESS",
    **fields: Any,
) -> dict:
    def entries(items: list[tuple[str, list[str]]] | None) -> list[dict]:
        return [{"IPProtocol": protocol, **({"ports": ports} if ports else {})} for protocol, ports in items or []]

    return {
        "name": name,
        "selfLink": _link(f"global/firewalls/{name}"),
        "network": _network(network),
        "direction": direction,
        "priority": priority,
        "allowed": entries(allowed),
        "denied": entries(denied),
        "disabled": False,
        **fields,
    }


def _instance(
    name: str,
    network: str,
    subnet: str,
    ip: str,
    *,
    external: str = "",
    forwards: bool = False,
    tags: list[str] | None = None,
    aliases: list[str] | None = None,
    machine: str = "e2-standard-2",
    zone: str = _ZONE,
) -> dict:
    region = zone.rsplit("-", 1)[0]
    return {
        "name": name,
        "selfLink": _link(f"zones/{zone}/instances/{name}"),
        "zone": _link(f"zones/{zone}"),
        "status": "RUNNING",
        "machineType": _link(f"zones/{zone}/machineTypes/{machine}"),
        "canIpForward": forwards,
        "tags": {"items": tags or []},
        "serviceAccounts": [{"email": f"{name}@{PROJECT}.iam.gserviceaccount.com"}],
        "networkInterfaces": [
            {
                "name": "nic0",
                "network": _network(network),
                "subnetwork": _regional("subnetworks", subnet, region),
                "networkIP": ip,
                "aliasIpRanges": [{"ipCidrRange": r, "subnetworkRangeName": "pods"} for r in aliases or []],
                "accessConfigs": [{"type": "ONE_TO_ONE_NAT", "name": "External NAT", "natIP": external}]
                if external
                else [],
            }
        ],
    }


def _peering(name: str, network: str, project: str = PROJECT) -> dict:
    return {
        "name": name,
        "network": _network(network, project),
        "state": "ACTIVE",
        "stateDetails": "[2026-09-01T10:00:00Z]: Connected.",
        "exchangeSubnetRoutes": True,
        "exportCustomRoutes": False,
        "importCustomRoutes": False,
    }


def _tunnel(name: str, interface: int, status: str, detail: str) -> dict:
    return {
        "name": name,
        "selfLink": _regional("vpnTunnels", name),
        "region": _link(f"regions/{_REGION}"),
        "status": status,
        "detailedStatus": detail,
        "peerIp": f"198.51.100.{20 + interface}",
        "ikeVersion": 2,
        "vpnGateway": _regional("vpnGateways", "ha-vpn-hub"),
        "vpnGatewayInterface": interface,
        "peerExternalGateway": _link("global/externalVpnGateways/hq-edge"),
        "peerExternalGatewayInterface": interface,
        "router": _regional("routers", "cr-hub"),
        # A live discovery never reads it either; here to show it is dropped.
        "sharedSecretHash": "AOxxdemo",
    }


def build_sample() -> tuple[list[dict], list[dict]]:
    """``(resources, connections)`` of the demo GCP project."""
    networks = [
        {
            "name": "hub-vpc",
            "selfLink": _network("hub-vpc"),
            "autoCreateSubnetworks": False,
            "routingConfig": {"routingMode": "GLOBAL"},
            "mtu": 1460,
            "subnetworks": [_regional("subnetworks", n) for n in ("hub-mgmt", "hub-nva")],
            "peerings": [_peering("hub-to-prod", "prod-vpc"), _peering("hub-to-shared", "shared-vpc", SHARED_PROJECT)],
        },
        {
            "name": "prod-vpc",
            "selfLink": _network("prod-vpc"),
            "autoCreateSubnetworks": False,
            "routingConfig": {"routingMode": "REGIONAL"},
            "mtu": 1460,
            "subnetworks": [_regional("subnetworks", n) for n in ("app", "db")],
            "peerings": [_peering("prod-to-hub", "hub-vpc")],
        },
    ]
    subnetworks = [
        _subnet("hub-mgmt", "hub-vpc", "10.240.1.0/24", google_access=True),
        _subnet("hub-nva", "hub-vpc", "10.240.2.0/24"),
        _subnet("hub-eu", "hub-vpc", "10.240.3.0/24", _EU),
        _subnet(
            "app",
            "prod-vpc",
            "10.241.10.0/24",
            google_access=True,
            secondary=[{"rangeName": "pods", "ipCidrRange": "10.241.128.0/20"}],
        ),
        _subnet("db", "prod-vpc", "10.241.20.0/24", google_access=True),
        # The NAT range of the database service attachment.
        {**_subnet("psc-nat", "prod-vpc", "10.241.30.0/24"), "purpose": "PRIVATE_SERVICE_CONNECT"},
    ]
    vmx = _link(f"zones/{_ZONE}/instances/vmx-hub-1")
    routes = [
        _route(
            "default-route-hub",
            "hub-vpc",
            "0.0.0.0/0",
            nextHopGateway=_link("global/gateways/default-internet-gateway"),
        ),
        _route(
            "default-route-prod",
            "prod-vpc",
            "0.0.0.0/0",
            nextHopGateway=_link("global/gateways/default-internet-gateway"),
        ),
        # Branch offices are reached over the appliance's AutoVPN.
        _route("branches-via-vmx", "hub-vpc", "10.99.0.0/16", 900, nextHopInstance=vmx),
        # Only instances tagged "lab" use the appliance for the lab range.
        _route("lab-via-vmx", "hub-vpc", "10.70.0.0/16", 900, tags=["lab"], nextHopInstance=vmx),
        # The disaster recovery site has no BGP: a static route over its tunnel.
        _route("dr-site", "hub-vpc", "10.20.0.0/16", 1000, nextHopVpnTunnel=_regional("vpnTunnels", "tunnel-hq-1")),
    ]
    firewalls = [
        _firewall(
            "hub-allow-internal", "hub-vpc", allowed=[("all", [])], sourceRanges=["10.240.0.0/16", "10.241.0.0/16"]
        ),
        _firewall(
            "hub-allow-onprem",
            "hub-vpc",
            allowed=[("tcp", ["22", "443"]), ("icmp", [])],
            sourceRanges=["10.10.0.0/16", "10.30.0.0/16"],
        ),
        _firewall("hub-allow-branches", "hub-vpc", allowed=[("all", [])], sourceRanges=["10.99.0.0/16"]),
        _firewall(
            "prod-allow-https-public",
            "prod-vpc",
            allowed=[("tcp", ["443"]), ("icmp", [])],
            sourceRanges=["0.0.0.0/0"],
            targetTags=["web"],
        ),
        _firewall(
            "prod-allow-postgres-from-app",
            "prod-vpc",
            allowed=[("tcp", ["5432"])],
            sourceRanges=["10.241.10.0/24"],
            targetTags=["db"],
        ),
        _firewall("prod-allow-from-hub", "prod-vpc", allowed=[("tcp", ["443"])], sourceRanges=["10.240.0.0/16"]),
        _firewall("prod-deny-ssh", "prod-vpc", denied=[("tcp", ["22"])], priority=900, sourceRanges=["0.0.0.0/0"]),
    ]
    router = {
        "name": "cr-hub",
        "selfLink": _regional("routers", "cr-hub"),
        "region": _link(f"regions/{_REGION}"),
        "network": _network("hub-vpc"),
        "bgp": {"asn": 64514, "advertiseMode": "CUSTOM", "advertisedGroups": ["ALL_SUBNETS"]},
        "interfaces": [
            {"name": "if-hq-0", "ipRange": "169.254.0.1/30", "linkedVpnTunnel": _regional("vpnTunnels", "tunnel-hq-0")},
            {"name": "if-hq-1", "ipRange": "169.254.1.1/30", "linkedVpnTunnel": _regional("vpnTunnels", "tunnel-hq-1")},
            {
                "name": "if-dc1",
                "ipRange": "169.254.10.1/29",
                "linkedInterconnectAttachment": _regional("interconnectAttachments", "ia-dc1-primary"),
            },
        ],
        "bgpPeers": [
            {
                "name": "hq-0",
                "interfaceName": "if-hq-0",
                "ipAddress": "169.254.0.1",
                "peerIpAddress": "169.254.0.2",
                "peerAsn": 65010,
            },
            {
                "name": "hq-1",
                "interfaceName": "if-hq-1",
                "ipAddress": "169.254.1.1",
                "peerIpAddress": "169.254.1.2",
                "peerAsn": 65010,
            },
            {
                "name": "dc1",
                "interfaceName": "if-dc1",
                "ipAddress": "169.254.10.1",
                "peerIpAddress": "169.254.10.2",
                "peerAsn": 65020,
            },
        ],
        "nats": [
            {
                "name": "nat-hub-mgmt",
                "sourceSubnetworkIpRangesToNat": "LIST_OF_SUBNETWORKS",
                "subnetworks": [
                    {"name": _regional("subnetworks", "hub-mgmt"), "sourceIpRangesToNat": ["ALL_IP_RANGES"]}
                ],
                "natIpAllocateOption": "AUTO_ONLY",
            }
        ],
    }
    status = {
        "network": _network("hub-vpc"),
        "bestRoutes": [
            {"destRange": "10.10.0.0/16", "nextHopIp": "169.254.0.2", "priority": 100, "routeType": "BGP"},
            {"destRange": "10.30.0.0/16", "nextHopIp": "169.254.10.2", "priority": 100, "routeType": "BGP"},
        ],
        "bgpPeerStatus": [
            {
                "name": "hq-0",
                "status": "UP",
                "state": "Established",
                "uptime": "12 days, 4 hours",
                "numLearnedRoutes": 1,
            },
            {"name": "hq-1", "status": "DOWN", "state": "Idle", "numLearnedRoutes": 0},
            {"name": "dc1", "status": "UP", "state": "Established", "uptime": "40 days", "numLearnedRoutes": 1},
        ],
        "natStatus": [{"name": "nat-hub-mgmt", "autoAllocatedNatIps": ["203.0.113.90"]}],
    }
    vpn_gateways = [
        {
            "name": "ha-vpn-hub",
            "selfLink": _regional("vpnGateways", "ha-vpn-hub"),
            "region": _link(f"regions/{_REGION}"),
            "network": _network("hub-vpc"),
            "vpnInterfaces": [{"id": 0, "ipAddress": "203.0.113.201"}, {"id": 1, "ipAddress": "203.0.113.202"}],
        }
    ]
    external_vpn_gateways = [
        {
            "name": "hq-edge",
            "selfLink": _link("global/externalVpnGateways/hq-edge"),
            "redundancyType": "TWO_IPS_REDUNDANCY",
            "interfaces": [{"id": 0, "ipAddress": "198.51.100.20"}, {"id": 1, "ipAddress": "198.51.100.21"}],
        }
    ]
    vpn_tunnels = [
        _tunnel("tunnel-hq-0", 0, "ESTABLISHED", "Tunnel is up and running."),
        _tunnel("tunnel-hq-1", 1, "NO_INCOMING_PACKETS", "No incoming packets from peer."),
    ]
    interconnect_attachments = [
        {
            "name": "ia-dc1-primary",
            "selfLink": _regional("interconnectAttachments", "ia-dc1-primary"),
            "region": _link(f"regions/{_REGION}"),
            "type": "DEDICATED",
            "bandwidth": "BPS_10G",
            "state": "ACTIVE",
            "operationalStatus": "OS_ACTIVE",
            "adminEnabled": True,
            "router": _regional("routers", "cr-hub"),
            "interconnect": _link("global/interconnects/ic-dc1"),
            "vlanTag8021q": 310,
            "cloudRouterIpAddress": "169.254.10.1/29",
            "customerRouterIpAddress": "169.254.10.2/29",
            "edgeAvailabilityDomain": "AVAILABILITY_DOMAIN_1",
            "mtu": 1440,
        }
    ]
    interconnects = [
        {
            "name": "ic-dc1",
            "selfLink": _link("global/interconnects/ic-dc1"),
            "interconnectType": "DEDICATED",
            "linkType": "LINK_TYPE_ETHERNET_10G_LR",
            "requestedLinkCount": 1,
            "provisionedLinkCount": 1,
            "location": _link("global/interconnectLocations/ord-zone1-7"),
            "operationalStatus": "OS_ACTIVE",
            "state": "ACTIVE",
            "adminEnabled": True,
        }
    ]
    instances = [
        _instance(
            "vmx-hub-1",
            "hub-vpc",
            "hub-nva",
            "10.240.2.10",
            external="203.0.113.61",
            forwards=True,
            machine="n2-standard-4",
        ),
        _instance("mgmt-jump", "hub-vpc", "hub-mgmt", "10.240.1.5", tags=["mgmt", "lab"]),
        _instance(
            "app-1",
            "prod-vpc",
            "app",
            "10.241.10.21",
            external="203.0.113.21",
            tags=["web"],
            aliases=["10.241.128.16/28"],
        ),
        _instance("db-1", "prod-vpc", "db", "10.241.20.31", tags=["db"]),
    ]
    lb = _load_balancing()
    return assemble(
        PROJECT,
        networks=networks,
        subnetworks=subnetworks,
        routes=routes,
        firewalls=firewalls,
        routers=[(router, status)],
        vpn_gateways=vpn_gateways,
        vpn_tunnels=vpn_tunnels,
        external_vpn_gateways=external_vpn_gateways,
        interconnect_attachments=interconnect_attachments,
        interconnects=interconnects,
        instances=instances,
        **lb,
    )


def _load_balancing() -> dict[str, list[dict]]:
    """The load balancers and Private Service Connect of the demo, as the
    ``assemble`` arguments: an internal passthrough Network Load Balancer in
    front of the database, published to the hub over a service attachment
    that a Private Service Connect endpoint in the hub connects to; a
    global external Application Load Balancer in front of the web tier
    (its network is known from its instance group only); and an endpoint
    for Google APIs in the hub. The health of the database backends; a
    Cloud SQL instance and a Memorystore for Redis instance on private
    service access in the production network."""
    prod = _network("prod-vpc")
    ilb = _regional("forwardingRules", "ilb-db")
    attachment = _regional("serviceAttachments", "sa-db")
    return {
        "forwarding_rules": [
            {
                "name": "ilb-db",
                "selfLink": ilb,
                "region": _link(f"regions/{_REGION}"),
                "IPAddress": "10.241.20.100",
                "IPProtocol": "TCP",
                "ports": ["5432"],
                "loadBalancingScheme": "INTERNAL",
                "network": prod,
                "subnetwork": _regional("subnetworks", "db"),
                "backendService": _regional("backendServices", "bs-db"),
                "serviceLabel": "db",
                "serviceName": f"db.ilb-db.il4.{_REGION}.lb.{PROJECT}.internal",
                "allowGlobalAccess": True,
                "networkTier": "PREMIUM",
            },
            {
                "name": "psc-db",
                "selfLink": _regional("forwardingRules", "psc-db"),
                "region": _link(f"regions/{_REGION}"),
                "IPAddress": "10.240.1.50",
                "network": _network("hub-vpc"),
                "subnetwork": _regional("subnetworks", "hub-mgmt"),
                "target": attachment,
                "loadBalancingScheme": "",
                "pscConnectionStatus": "ACCEPTED",
                "pscConnectionId": "71234567890123457",
            },
        ],
        "global_forwarding_rules": [
            {
                "name": "web-https",
                "selfLink": _link("global/forwardingRules/web-https"),
                "IPAddress": "203.0.113.80",
                "IPProtocol": "TCP",
                "portRange": "443-443",
                "loadBalancingScheme": "EXTERNAL_MANAGED",
                "target": _link("global/targetHttpsProxies/web-https-proxy"),
                "networkTier": "PREMIUM",
            },
            {
                "name": "pscgoogleapis",
                "selfLink": _link("global/forwardingRules/pscgoogleapis"),
                "IPAddress": "10.240.9.5",
                "network": _network("hub-vpc"),
                "target": "all-apis",
                "loadBalancingScheme": "",
                "pscConnectionStatus": "ACCEPTED",
            },
        ],
        "target_proxies": [
            {
                "name": "web-https-proxy",
                "selfLink": _link("global/targetHttpsProxies/web-https-proxy"),
                "urlMap": _link("global/urlMaps/web-map"),
            }
        ],
        "url_maps": [
            {
                "name": "web-map",
                "selfLink": _link("global/urlMaps/web-map"),
                "defaultService": _link("global/backendServices/bs-web"),
            }
        ],
        "backend_services": [
            {
                "name": "bs-web",
                "selfLink": _link("global/backendServices/bs-web"),
                "protocol": "HTTPS",
                "loadBalancingScheme": "EXTERNAL_MANAGED",
                "backends": [{"group": _link(f"zones/{_ZONE}/instanceGroups/ig-web")}],
            },
            {
                "name": "bs-db",
                "selfLink": _regional("backendServices", "bs-db"),
                "region": _link(f"regions/{_REGION}"),
                "protocol": "TCP",
                "loadBalancingScheme": "INTERNAL",
                "network": prod,
                "backends": [{"group": _link(f"zones/{_ZONE}/instanceGroups/ig-db")}],
            },
        ],
        "instance_groups": [
            {
                "name": name,
                "selfLink": _link(f"zones/{_ZONE}/instanceGroups/{name}"),
                "network": prod,
                "subnetwork": _regional("subnetworks", subnet),
                "size": 1,
            }
            for name, subnet in (("ig-web", "app"), ("ig-db", "db"))
        ],
        "backend_health": [
            {
                "backendService": _regional("backendServices", "bs-db"),
                "group": _link(f"zones/{_ZONE}/instanceGroups/ig-db"),
                "healthStatus": [
                    {
                        "instance": _link(f"zones/{_ZONE}/instances/db-1"),
                        "ipAddress": "10.241.20.31",
                        "port": 5432,
                        "healthState": "HEALTHY",
                    }
                ],
            }
        ],
        "cloud_sql_instances": [
            {
                "name": "orders-sql",
                "project": PROJECT,
                "region": _REGION,
                "gceZone": _ZONE,
                "databaseVersion": "POSTGRES_16",
                "state": "RUNNABLE",
                "instanceType": "CLOUD_SQL_INSTANCE",
                "connectionName": f"{PROJECT}:{_REGION}:orders-sql",
                "ipAddresses": [
                    {"type": "PRIVATE", "ipAddress": "10.241.200.3"},
                    {"type": "OUTGOING", "ipAddress": "203.0.113.85"},
                ],
                "settings": {
                    "tier": "db-custom-2-7680",
                    "availabilityType": "REGIONAL",
                    "ipConfiguration": {
                        "ipv4Enabled": False,
                        "privateNetwork": f"projects/{PROJECT}/global/networks/prod-vpc",
                        "pscConfig": {"pscEnabled": False},
                    },
                },
            }
        ],
        "memorystore_redis_instances": [
            {
                "name": f"projects/{PROJECT}/locations/{_REGION}/instances/sessions-redis",
                "locationId": _ZONE,
                "currentLocationId": _ZONE,
                "redisVersion": "REDIS_7_2",
                "host": "10.241.201.4",
                "port": 6379,
                "readEndpoint": "10.241.201.5",
                "readEndpointPort": 6379,
                "authorizedNetwork": f"projects/{PROJECT}/global/networks/prod-vpc",
                "connectMode": "PRIVATE_SERVICE_ACCESS",
                "reservedIpRange": "10.241.201.0/29",
                "state": "READY",
                "tier": "STANDARD_HA",
                "memorySizeGb": 5,
                "replicaCount": 1,
            }
        ],
        "service_attachments": [
            {
                "name": "sa-db",
                "selfLink": attachment,
                "region": _link(f"regions/{_REGION}"),
                "targetService": ilb,
                "natSubnets": [_regional("subnetworks", "psc-nat")],
                "connectionPreference": "ACCEPT_MANUAL",
                "enableProxyProtocol": False,
                "connectedEndpoints": [
                    {
                        "status": "ACCEPTED",
                        "endpoint": _regional("forwardingRules", "psc-db"),
                        "pscConnectionId": "71234567890123457",
                        "consumerNetwork": _network("hub-vpc"),
                    }
                ],
            }
        ],
    }
