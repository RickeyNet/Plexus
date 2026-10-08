"""Bundled demo FMC, in the shape ``collector.collect_fmc`` returns.

Lets the Cisco FMC part of the map be previewed (and tested) without an
FMC, with data in every section the normalizer draws:

  - ``ftdv-ravpn-1`` / ``ftdv-ravpn-2``, the FTDv instances of the demo AWS
    account (``netcontrol.integrations.aws.sample``, same private
    addresses), form the HA pair ``ftdv-ravpn-ha``: the remote access VPN
    headend, with the RA VPN, NAT and access control policies assigned to
    the pair rather than its members
  - ``ftd-branch-dc``, a standalone Firepower 1120 whose outside address is
    the AWS sample's customer gateway address and whose VPN peer is the AWS
    tunnel address, with sub-interfaces, a loopback, a VTI, two virtual
    routers, static routes, BGP, OSPF, EIGRP, policy-based routing and an
    ECMP zone
  - ``ftd-dc-cluster``, a two-unit Firepower 4112 cluster
  - two site-to-site VPN topologies (hub and spoke between the pair and the
    branch; point to point from the branch to an extranet AWS gateway)
  - one access control policy whose rules use port objects and block guest
    to inside, and a prefilter policy with one fastpath rule

All addresses are documentation / private ranges.
"""

from __future__ import annotations

from typing import Any

from netcontrol.integrations.fmc.collector import DEFAULT_OPTIONS

DOMAIN_UUID = "e276abec-e0f2-11e3-8169-6d9ed49b625f"
POLICY_ID = "005056B3-2C2D-0ed3-0000-004294967395"
NAT_POLICY_ID = "005056B3-2C2D-0ed3-0000-004294967501"
ACP_ID = "005056B3-2C2D-0ed3-0000-004294967601"
PREFILTER_ID = "005056B3-2C2D-0ed3-0000-004294967701"
DEVICE_1 = "4b2a7f8e-0001-4f6b-9c2d-ff0000000001"
DEVICE_2 = "4b2a7f8e-0002-4f6b-9c2d-ff0000000002"
DEVICE_3 = "4b2a7f8e-0003-4f6b-9c2d-ff0000000003"
DEVICE_4 = "4b2a7f8e-0004-4f6b-9c2d-ff0000000004"
DEVICE_5 = "4b2a7f8e-0005-4f6b-9c2d-ff0000000005"
HA_PAIR = "7d1c0a00-0001-4c2b-8a1d-ee0000000001"
CLUSTER = "7d1c0a00-0002-4c2b-8a1d-ee0000000002"
TOPOLOGY_HUB = "8e2d1b00-0001-4d3c-9b2e-dd0000000001"
TOPOLOGY_VGW = "8e2d1b00-0002-4d3c-9b2e-dd0000000002"
VR_GLOBAL = "9f3e2c00-0000-4e4d-ac3f-cc0000000000"
VR_GUEST = "9f3e2c00-0001-4e4d-ac3f-cc0000000001"
ZONE_OUTSIDE = "9e1b2c3d-0000-4a5b-8c9d-000000000011"
ZONE_INSIDE = "9e1b2c3d-0000-4a5b-8c9d-000000000012"
ZONE_GUEST = "9e1b2c3d-0000-4a5b-8c9d-000000000013"
ZONE_VTI = "9e1b2c3d-0000-4a5b-8c9d-000000000014"
ZONE_DMZ = "9e1b2c3d-0000-4a5b-8c9d-000000000015"
POOL_A = "a1b2c3d4-0000-4a5b-8c9d-00000000aa01"
POOL_B = "a1b2c3d4-0000-4a5b-8c9d-00000000aa02"
GROUP_POLICY = "c0ffee00-0000-4a5b-8c9d-000000000001"
AUTH_SERVER = "c0ffee00-0000-4a5b-8c9d-000000000002"

_MODEL_AWS = "Cisco Secure Firewall Threat Defense for AWS"
_MODEL_1120 = "Cisco Firepower 1120 Threat Defense"
_MODEL_4112 = "Cisco Firepower 4112 Threat Defense"


def _ref(kind: str, ident: str, name: str) -> dict:
    return {"id": ident, "type": kind, "name": name}


def _device(ident: str, name: str, mgmt: str, serial: str, *, model: str, health: str = "green") -> dict:
    return {
        "id": ident,
        "type": "Device",
        "name": name,
        "hostName": mgmt,
        "model": model,
        "modelId": "A",
        "modelNumber": "75",
        "modelType": "Sensor",
        "healthStatus": health,
        "sw_version": "7.4.1",
        "ftdMode": "ROUTED",
        "deploymentStatus": "DEPLOYED",
        "accessPolicy": _ref("AccessPolicy", ACP_ID, "Corp-ACP"),
        "metadata": {
            "readOnly": {"state": False},
            "deviceSerialNumber": serial,
            "domain": {"id": DOMAIN_UUID, "name": "Global", "type": "Domain"},
            "snortVersion": "3.1.53.100-1",
            "vdbVersion": "381",
            "inventoryData": {"cpuCores": "4", "cpuType": "Intel", "memoryInMB": "8192"},
        },
    }


def _interface(
    name: str,
    ifname: str,
    zone_id: str,
    zone: str,
    address: str,
    mask: str = "24",
    *,
    kind: str = "PhysicalInterface",
    **extra: Any,
) -> dict:
    item = {
        "id": f"{name}-{ifname}",
        "type": kind,
        "name": name,
        "ifname": ifname,
        "enabled": True,
        "mode": "NONE",
        "MTU": 1500,
        "securityZone": {"id": zone_id, "name": zone, "type": "SecurityZone"},
        "ipv4": {"static": {"address": address, "netmask": mask}},
    }
    item.update(extra)
    return item


def _session(
    user: str, device_id: str, device: str, assigned: str, public: str, profile: str, os_name: str, login: str
) -> dict:
    return {
        "type": "RAVpnSession",
        "username": user,
        "device": {"id": device_id, "name": device, "type": "Device"},
        "assignedIpv4Address": assigned,
        "publicIp": public,
        "connectionProfile": profile,
        "groupPolicy": "Corp-GP",
        "clientApplication": "AnyConnect 5.1.2.42",
        "clientOs": os_name,
        "protocol": "AnyConnect-Parent SSL-Tunnel DTLS-Tunnel",
        "loginTime": login,
        "duration": "2h:14m:05s",
        "bytesRx": 48211344,
        "bytesTx": 9123311,
    }


def _objects() -> dict[str, list[dict]]:
    def obj(kind: str, ident: str, name: str, value: str, description: str = "") -> dict:
        return {"id": ident, "type": kind, "name": name, "value": value, "description": description}

    return {
        "networks": [
            obj("Network", "net-0000", "any-ipv4", "0.0.0.0/0"),
            obj("Network", "net-0001", "Branch-LAN", "10.60.0.0/24", "Branch users"),
            obj("Network", "net-0002", "Branch-Voice", "10.60.20.0/24", "Branch phones"),
            obj("Network", "net-0003", "DC-Networks", "10.70.0.0/16", "Data center"),
            obj("Network", "net-0004", "AWS-Core-VPC", "10.200.0.0/16"),
            obj("Network", "net-0005", "AWS-Apps-VPC", "10.220.0.0/16"),
            obj("Network", "net-0006", "Partner-A", "172.16.10.0/24", "Partner A extranet"),
            obj("Network", "net-0007", "any-ipv6", "::/0"),
        ],
        "hosts": [
            obj("Host", "host-0001", "gw-branch-isp", "198.51.100.1", "Branch ISP router"),
            obj("Host", "host-0002", "gw-branch-core", "10.60.0.254", "Branch core switch"),
            obj("Host", "host-0003", "gw-aws-inside", "10.210.1.1", "AWS inside subnet router"),
            obj("Host", "host-0004", "guest-dns", "10.60.31.53"),
        ],
        "ranges": [obj("Range", "range-0001", "Partner-B-Range", "172.16.30.10-172.16.30.40")],
        "fqdns": [obj("FQDN", "fqdn-0001", "updates-cdn", "updates.example.com")],
        "groups": [
            {
                "id": "grp-0001",
                "type": "NetworkGroup",
                "name": "AWS-VPCs",
                "objects": [
                    _ref("Network", "net-0004", "AWS-Core-VPC"),
                    _ref("Network", "net-0005", "AWS-Apps-VPC"),
                ],
            },
            {
                "id": "grp-0002",
                "type": "NetworkGroup",
                "name": "Partner-Nets",
                "objects": [
                    _ref("Network", "net-0006", "Partner-A"),
                    _ref("Range", "range-0001", "Partner-B-Range"),
                ],
                "literals": [{"type": "Host", "value": "172.16.20.5"}],
            },
        ],
        "zones": [
            {"id": ZONE_OUTSIDE, "type": "SecurityZone", "name": "outside", "interfaceMode": "ROUTED"},
            {"id": ZONE_INSIDE, "type": "SecurityZone", "name": "inside", "interfaceMode": "ROUTED"},
            {"id": ZONE_GUEST, "type": "SecurityZone", "name": "guest", "interfaceMode": "ROUTED"},
            {"id": ZONE_VTI, "type": "SecurityZone", "name": "vti", "interfaceMode": "ROUTED"},
            {"id": ZONE_DMZ, "type": "SecurityZone", "name": "dmz", "interfaceMode": "ROUTED"},
        ],
        "interface_groups": [
            {"id": "ifg-0001", "type": "InterfaceGroup", "name": "Uplinks", "interfaceMode": "ROUTED"}
        ],
        "ports": [
            {"id": "port-0001", "type": "ProtocolPortObject", "name": "HTTP", "protocol": "TCP", "port": "80"},
            {"id": "port-0002", "type": "ProtocolPortObject", "name": "HTTPS", "protocol": "TCP", "port": "443"},
            {"id": "port-0003", "type": "ProtocolPortObject", "name": "DNS-UDP", "protocol": "UDP", "port": "53"},
            {"id": "port-0004", "type": "ProtocolPortObject", "name": "Rsync", "protocol": "TCP", "port": "873"},
        ],
        "port_groups": [
            {
                "id": "pgrp-0001",
                "type": "PortObjectGroup",
                "name": "Web-Ports",
                "objects": [
                    _ref("ProtocolPortObject", "port-0001", "HTTP"),
                    _ref("ProtocolPortObject", "port-0002", "HTTPS"),
                ],
            }
        ],
        "icmp": [{"id": "icmp-0001", "type": "ICMPV4Object", "name": "Echo-Request", "icmpType": "8"}],
    }


def _branch_interfaces() -> list[dict]:
    return [
        _interface(
            "GigabitEthernet1/1",
            "outside",
            ZONE_OUTSIDE,
            "outside",
            "198.51.100.10",
            "28",
            ipv6={"addresses": [{"address": "2001:db8:100::10", "prefix": "64"}]},
        ),
        _interface("GigabitEthernet1/2", "inside", ZONE_INSIDE, "inside", "10.60.0.1"),
        _interface(
            "GigabitEthernet1/2",
            "voice",
            ZONE_INSIDE,
            "inside",
            "10.60.20.1",
            kind="SubInterface",
            vlanId=20,
            subIntfId=20,
            description="Voice VLAN",
        ),
        _interface("GigabitEthernet1/3", "guest", ZONE_GUEST, "guest", "10.60.30.1"),
        _interface("Loopback1", "lo-router-id", ZONE_INSIDE, "inside", "10.60.255.1", "32", kind="LoopbackInterface"),
        _interface(
            "Tunnel1",
            "vti-aws",
            ZONE_VTI,
            "vti",
            "169.254.21.2",
            "30",
            kind="VTIInterface",
            tunnelId=1,
            tunnelType="STATIC",
            tunnelSource=_ref("PhysicalInterface", "GigabitEthernet1/1-outside", "GigabitEthernet1/1"),
            tunnelDestination="203.0.113.101",
        ),
    ]


def _cluster_interfaces() -> list[dict]:
    return [
        _interface(
            "Port-channel1",
            "inside",
            ZONE_INSIDE,
            "inside",
            "10.80.0.1",
            kind="EtherChannelInterface",
            etherChannelId=1,
        ),
        _interface(
            "Port-channel2", "dmz", ZONE_DMZ, "dmz", "10.80.10.1", kind="EtherChannelInterface", etherChannelId=2
        ),
    ]


def _static(ident: str, ifname: str, network: dict, gateway: dict, *, metric: int = 1, **extra: Any) -> dict:
    route = {
        "id": ident,
        "type": "IPv4StaticRoute",
        "interfaceName": ifname,
        "selectedNetworks": [network],
        "gateway": gateway,
        "metricValue": metric,
        "isTunneled": False,
    }
    route.update(extra)
    return route


def _routing() -> dict[str, dict[str, list[dict]]]:
    ha = {
        "virtual_routers": [],
        "static_v4": [
            {
                "vr": "Global",
                **_static(
                    "rt-ha-1", "outside", _ref("Network", "net-0000", "any-ipv4"), {"literal": {"value": "10.210.0.1"}}
                ),
            },
            {
                "vr": "Global",
                **_static(
                    "rt-ha-2",
                    "inside",
                    _ref("NetworkGroup", "grp-0001", "AWS-VPCs"),
                    {"object": _ref("Host", "host-0003", "gw-aws-inside")},
                ),
            },
        ],
        "static_v6": [],
        "bgp": [],
        "ospf": [],
        "eigrp": [],
        "pbr": [],
        "ecmp": [],
    }
    branch = {
        "virtual_routers": [
            {
                "id": VR_GLOBAL,
                "type": "VirtualRouter",
                "name": "Global",
                "interfaces": [
                    {"id": "GigabitEthernet1/1-outside", "name": "outside"},
                    {"id": "GigabitEthernet1/2-inside", "name": "inside"},
                    {"id": "GigabitEthernet1/2-voice", "name": "voice"},
                    {"id": "Loopback1-lo-router-id", "name": "lo-router-id"},
                    {"id": "Tunnel1-vti-aws", "name": "vti-aws"},
                ],
            },
            {
                "id": VR_GUEST,
                "type": "VirtualRouter",
                "name": "Guest",
                "description": "Guest Wi-Fi, kept apart from the corporate table",
                "interfaces": [{"id": "GigabitEthernet1/3-guest", "name": "guest"}],
            },
        ],
        "static_v4": [
            {
                "vr": "Global",
                **_static(
                    "rt-br-1",
                    "outside",
                    _ref("Network", "net-0000", "any-ipv4"),
                    {"object": _ref("Host", "host-0001", "gw-branch-isp")},
                    routeTracking=_ref("SLAMonitor", "sla-0001", "isp-sla"),
                ),
            },
            {
                "vr": "Global",
                **_static(
                    "rt-br-2",
                    "inside",
                    _ref("Network", "net-0003", "DC-Networks"),
                    {"literal": {"value": "10.60.0.254"}},
                    metric=10,
                ),
            },
            {
                "vr": "Global",
                **_static(
                    "rt-br-3",
                    "inside",
                    _ref("NetworkGroup", "grp-0002", "Partner-Nets"),
                    {"object": _ref("Host", "host-0002", "gw-branch-core")},
                ),
            },
            {
                "vr": "Guest",
                **_static(
                    "rt-br-4",
                    "guest",
                    _ref("Host", "host-0004", "guest-dns"),
                    {"literal": {"value": "10.60.30.254"}},
                ),
            },
        ],
        "static_v6": [
            {
                "vr": "Global",
                "id": "rt-br-6",
                "type": "IPv6StaticRoute",
                "interfaceName": "outside",
                "selectedNetworks": [_ref("Network", "net-0007", "any-ipv6")],
                "gateway": {"literal": {"value": "2001:db8:100::1"}},
                "metricValue": 1,
                "isTunneled": False,
            }
        ],
        "bgp": [
            {
                "vr": "Global",
                "id": "bgp-0001",
                "type": "bgp",
                "name": "AS65010",
                "asNumber": "65010",
                "routerId": "10.60.255.1",
                "addressFamilyIPv4": {
                    "neighbors": [
                        {
                            "ipv4Address": "169.254.21.1",
                            "remoteAs": "64512",
                            "neighborGeneral": {"enableAddress": True, "description": "AWS transit gateway, tunnel 1"},
                            "neighborAdvanced": {"neighborUpdateSource": {"name": "vti-aws"}},
                        }
                    ],
                    "networks": [
                        {"ipv4Address": _ref("Network", "net-0001", "Branch-LAN")},
                        {"ipv4Address": _ref("Network", "net-0002", "Branch-Voice")},
                    ],
                    "redistributeProtocols": [{"type": "RedistributeConnected"}],
                },
            }
        ],
        "ospf": [
            {
                "vr": "Global",
                "id": "ospf-0001",
                "type": "ospfv2route",
                "processId": 1,
                "processConfiguration": {"routerId": {"type": "IP_ADDRESS", "ipAddress": "10.60.255.1"}},
                "areas": [
                    {
                        "areaId": "0",
                        "areaType": "normal",
                        "areaNetworks": [
                            _ref("Network", "net-0001", "Branch-LAN"),
                            _ref("Network", "net-0002", "Branch-Voice"),
                        ],
                    }
                ],
            }
        ],
        "eigrp": [
            {
                "vr": "Global",
                "id": "eigrp-0001",
                "type": "eigrproute",
                "asNumber": 100,
                "networks": [_ref("Network", "net-0002", "Branch-Voice")],
            }
        ],
        "pbr": [
            {
                "vr": "",
                "id": "pbr-0001",
                "type": "PolicyBasedRoute",
                "ingressInterfaces": [{"name": "inside", "type": "PhysicalInterface"}],
                "forwardingActions": [
                    {
                        "sequence": 1,
                        "matchCriteriaAccessList": _ref("ExtendedAccessList", "acl-0001", "Voice-to-ISP"),
                        "forwardingAction": "SET_EGRESS_INTF",
                        "egressInterfaces": [{"name": "outside", "type": "PhysicalInterface"}],
                    }
                ],
            }
        ],
        "ecmp": [
            {
                "vr": "Global",
                "id": "ecmp-0001",
                "type": "ECMPZone",
                "name": "ecmp-inside",
                "interfaces": [{"name": "inside"}, {"name": "voice"}],
            }
        ],
    }
    cluster: dict[str, list[dict]] = {
        "virtual_routers": [],
        "static_v4": [],
        "static_v6": [],
        "bgp": [],
        "ospf": [],
        "eigrp": [],
        "pbr": [],
        "ecmp": [],
    }
    return {DEVICE_1: ha, DEVICE_2: ha, DEVICE_3: branch, DEVICE_4: cluster, DEVICE_5: cluster}


def _nat_rules() -> list[dict]:
    return [
        {
            "id": "nat-0001",
            "type": "FTDManualNatRule",
            "metadata": {"section": "BEFORE_AUTO", "index": 1},
            "natType": "STATIC",
            "originalSource": _ref("Network", "net-0001", "Branch-LAN"),
            "originalDestination": _ref("NetworkGroup", "grp-0001", "AWS-VPCs"),
            "translatedSource": _ref("Network", "net-0001", "Branch-LAN"),
            "translatedDestination": _ref("NetworkGroup", "grp-0001", "AWS-VPCs"),
            "sourceInterface": _ref("SecurityZone", ZONE_INSIDE, "inside"),
            "destinationInterface": _ref("SecurityZone", ZONE_OUTSIDE, "outside"),
            "enabled": True,
            "description": "No NAT towards AWS over the VPN",
        },
        {
            "id": "nat-0002",
            "type": "FTDAutoNatRule",
            "natType": "DYNAMIC",
            "originalNetwork": _ref("Network", "net-0001", "Branch-LAN"),
            "interfaceInTranslatedNetwork": True,
            "sourceInterface": _ref("SecurityZone", ZONE_INSIDE, "inside"),
            "destinationInterface": _ref("SecurityZone", ZONE_OUTSIDE, "outside"),
        },
    ]


def _access_rules() -> list[dict]:
    def rule(index: int, name: str, action: str, **fields: Any) -> dict:
        return {
            "id": f"acr-{index:04d}",
            "type": "AccessRule",
            "name": name,
            "action": action,
            "enabled": True,
            "logBegin": False,
            "logEnd": True,
            "sendEventsToFMC": True,
            "metadata": {"ruleIndex": index, "section": "Mandatory"},
            **fields,
        }

    return [
        rule(
            1,
            "Allow-VPN-Users-to-Apps",
            "ALLOW",
            sourceZones={"objects": [_ref("SecurityZone", ZONE_OUTSIDE, "outside")]},
            destinationZones={"objects": [_ref("SecurityZone", ZONE_INSIDE, "inside")]},
            destinationNetworks={"objects": [_ref("NetworkGroup", "grp-0001", "AWS-VPCs")]},
            destinationPorts={"literals": [{"type": "PortLiteral", "port": "443", "protocol": "6"}]},
            users={"objects": [{"name": "Employees", "type": "RealmUserGroup"}]},
            ipsPolicy={"name": "Balanced Security and Connectivity", "type": "IntrusionPolicy"},
        ),
        rule(
            2,
            "Allow-Branch-Web",
            "ALLOW",
            sourceZones={"objects": [_ref("SecurityZone", ZONE_INSIDE, "inside")]},
            destinationZones={"objects": [_ref("SecurityZone", ZONE_OUTSIDE, "outside")]},
            sourceNetworks={"objects": [_ref("Network", "net-0001", "Branch-LAN")]},
            # Two protocols: the rule is TCP 80, 443 and UDP 53.
            destinationPorts={
                "objects": [
                    _ref("PortObjectGroup", "pgrp-0001", "Web-Ports"),
                    _ref("ProtocolPortObject", "port-0003", "DNS-UDP"),
                ]
            },
            applications={"applications": [{"name": "HTTPS", "type": "Application"}]},
            urls={"urlCategoriesWithReputation": [{"category": {"name": "Business and Economy"}}]},
            filePolicy={"name": "Block-Malware", "type": "FilePolicy"},
        ),
        rule(
            3,
            "Block-Guest-to-Corp",
            "BLOCK",
            sourceZones={"objects": [_ref("SecurityZone", ZONE_GUEST, "guest")]},
            destinationZones={"objects": [_ref("SecurityZone", ZONE_INSIDE, "inside")]},
            logEnd=False,
            logBegin=True,
        ),
    ]


def _prefilter_rules() -> list[dict]:
    return [
        {
            "id": "pfr-0001",
            "type": "PrefilterRule",
            "name": "Fastpath-DC-Backup",
            "ruleType": "PREFILTER",
            "action": "FASTPATH",
            "enabled": True,
            "bidirectional": True,
            "metadata": {"ruleIndex": 1},
            "sourceInterfaces": {"objects": [_ref("SecurityZone", ZONE_INSIDE, "inside")]},
            # The data center is routed inside, through the branch core switch.
            "destinationInterfaces": {"objects": [_ref("SecurityZone", ZONE_INSIDE, "inside")]},
            "sourceNetworks": {"objects": [_ref("Network", "net-0001", "Branch-LAN")]},
            "destinationNetworks": {"objects": [_ref("Network", "net-0003", "DC-Networks")]},
            "destinationPorts": {"objects": [_ref("ProtocolPortObject", "port-0004", "Rsync")]},
            "logBegin": False,
            "logEnd": False,
        }
    ]


def build_sample_raw() -> dict[str, Any]:
    devices = [
        _device(DEVICE_1, "ftdv-ravpn-1", "10.210.2.11", "9A1DEMO00001", model=_MODEL_AWS),
        _device(DEVICE_2, "ftdv-ravpn-2", "10.210.2.12", "9A1DEMO00002", model=_MODEL_AWS, health="yellow"),
        _device(DEVICE_3, "ftd-branch-dc", "10.60.0.1", "JAD2DEMO0003", model=_MODEL_1120),
        _device(DEVICE_4, "ftd-dc-unit-1", "10.80.255.11", "FLM2DEMO0004", model=_MODEL_4112),
        _device(DEVICE_5, "ftd-dc-unit-2", "10.80.255.12", "FLM2DEMO0005", model=_MODEL_4112),
    ]
    pair_ref = _ref("DeviceHAPair", HA_PAIR, "ftdv-ravpn-ha")
    cluster_ref = _ref("DeviceCluster", CLUSTER, "ftd-dc-cluster")
    branch_ref = _ref("Device", DEVICE_3, "ftd-branch-dc")
    ha_pairs = [
        {
            "id": HA_PAIR,
            "type": "DeviceHAPair",
            "name": "ftdv-ravpn-ha",
            "primary": _ref("Device", DEVICE_1, "ftdv-ravpn-1"),
            "secondary": _ref("Device", DEVICE_2, "ftdv-ravpn-2"),
            "ftdHABootstrap": {
                "isEncryptionEnabled": True,
                "lanFailover": {
                    "logicalName": "failover-link",
                    "interfaceObject": {"name": "GigabitEthernet0/2", "type": "PhysicalInterface"},
                    "activeIP": "10.210.3.11",
                    "standbyIP": "10.210.3.12",
                    "subnetMask": "255.255.255.0",
                },
                "statefulFailover": {
                    "logicalName": "failover-link",
                    "interfaceObject": {"name": "GigabitEthernet0/2", "type": "PhysicalInterface"},
                },
            },
            "metadata": {
                "primaryStatus": {"currentStatus": "Active", "device": _ref("Device", DEVICE_1, "ftdv-ravpn-1")},
                "secondaryStatus": {"currentStatus": "Standby", "device": _ref("Device", DEVICE_2, "ftdv-ravpn-2")},
            },
        }
    ]
    ha_monitored = {
        HA_PAIR: [
            {
                "name": "outside",
                "monitorForFailures": True,
                "ipv4Configuration": {
                    "activeIPv4Address": "10.210.0.11",
                    "activeIPv4Mask": "24",
                    "standbyIPv4Address": "10.210.0.12",
                },
            },
            {
                "name": "inside",
                "monitorForFailures": True,
                "ipv4Configuration": {
                    "activeIPv4Address": "10.210.1.11",
                    "activeIPv4Mask": "24",
                    "standbyIPv4Address": "10.210.1.12",
                },
            },
        ]
    }
    clusters = [
        {
            "id": CLUSTER,
            "type": "DeviceCluster",
            "name": "ftd-dc-cluster",
            "controlDevice": {"deviceDetails": _ref("Device", DEVICE_4, "ftd-dc-unit-1")},
            "dataDevices": [{"deviceDetails": _ref("Device", DEVICE_5, "ftd-dc-unit-2")}],
        }
    ]
    policy = {
        "id": POLICY_ID,
        "type": "RAVpn",
        "name": "Corp-RAVPN",
        "description": "Employee and contractor remote access",
    }
    assignments = [
        {
            "id": "pa-0001",
            "type": "PolicyAssignment",
            "name": "Corp-RAVPN",
            "policy": _ref("RAVpn", POLICY_ID, "Corp-RAVPN"),
            # Assigned to the pair, not its members: the resolver maps it to both.
            "targets": [pair_ref],
        },
        {
            "id": "pa-0002",
            "type": "PolicyAssignment",
            "name": "Corp-ACP",
            "policy": _ref("AccessPolicy", ACP_ID, "Corp-ACP"),
            "targets": [pair_ref, branch_ref, cluster_ref],
        },
        {
            "id": "pa-0003",
            "type": "PolicyAssignment",
            "name": "Corp-NAT",
            "policy": _ref("FTDNatPolicy", NAT_POLICY_ID, "Corp-NAT"),
            "targets": [pair_ref, branch_ref],
        },
    ]
    pools = [
        {
            "id": POOL_A,
            "type": "IPv4AddressPool",
            "name": "RAVPN-Pool-Employees",
            "ipAddressRange": "10.220.0.1-10.220.3.254",
            "mask": "255.255.252.0",
            "description": "Employee VPN clients",
        },
        {
            "id": POOL_B,
            "type": "IPv4AddressPool",
            "name": "RAVPN-Pool-Contractors",
            "ipAddressRange": "10.220.8.1-10.220.8.254",
            "mask": "255.255.255.0",
            "description": "Contractor VPN clients",
        },
    ]
    policy_details = {
        POLICY_ID: {
            "connection_profiles": [
                {
                    "id": "cp-0001",
                    "type": "RaVpnConnectionProfile",
                    "name": "Employees",
                    "groupPolicy": {"id": GROUP_POLICY, "name": "Corp-GP", "type": "GroupPolicy"},
                    "ipv4AddressPool": [{"id": POOL_A, "name": "RAVPN-Pool-Employees", "type": "IPv4AddressPool"}],
                    "authenticationMethod": "AAA_AND_CLIENT_CERTIFICATE",
                    "primaryAuthenticationServer": {
                        "id": AUTH_SERVER,
                        "name": "ISE-RADIUS",
                        "type": "RadiusServerGroup",
                    },
                    "groupAlias": [{"name": "Employees", "enabled": True}],
                    "groupUrl": [{"url": "https://vpn.example.com/employees", "enabled": True}],
                },
                {
                    "id": "cp-0002",
                    "type": "RaVpnConnectionProfile",
                    "name": "Contractors",
                    "groupPolicy": {"id": GROUP_POLICY, "name": "Contractor-GP", "type": "GroupPolicy"},
                    "ipv4AddressPool": [{"id": POOL_B, "name": "RAVPN-Pool-Contractors", "type": "IPv4AddressPool"}],
                    "authenticationMethod": "AAA_ONLY",
                    "primaryAuthenticationServer": {
                        "id": AUTH_SERVER,
                        "name": "ISE-RADIUS",
                        "type": "RadiusServerGroup",
                    },
                    "groupAlias": [{"name": "Contractors", "enabled": True}],
                    "groupUrl": [],
                },
            ],
            "address_assignment": [
                {
                    "type": "RaVpnAddressAssignmentSetting",
                    "useAuthorizationServer": True,
                    "useDhcp": False,
                    "useLocalPools": True,
                }
            ],
            "access_interfaces": [
                {
                    "type": "RaVpnAccessInterfaceSettings",
                    "sslPort": 443,
                    "dtlsPort": 443,
                    "allowConnectionProfileSelection": True,
                    "accessInterfaceSettings": [
                        {
                            "accessInterface": {"id": ZONE_OUTSIDE, "name": "outside", "type": "SecurityZone"},
                            "enableSSL": True,
                            "enableIPSecIKEv2": True,
                            "enableDTLS": True,
                            "allowAnyConnectClientProfileDownload": True,
                        }
                    ],
                }
            ],
        }
    }
    # The pair is configured once: the collector reads the primary and
    # reuses its interfaces for the secondary, whose rows the normalizer
    # turns to the standby addresses of ``ha_monitored``.
    ha_interfaces = [
        _interface("GigabitEthernet0/0", "outside", ZONE_OUTSIDE, "outside", "10.210.0.11"),
        _interface("GigabitEthernet0/1", "inside", ZONE_INSIDE, "inside", "10.210.1.11"),
    ]
    interfaces = {
        DEVICE_1: ha_interfaces,
        DEVICE_2: [dict(i) for i in ha_interfaces],
        DEVICE_3: _branch_interfaces(),
        DEVICE_4: _cluster_interfaces(),
        DEVICE_5: _cluster_interfaces(),
    }
    sessions = [
        _session(
            "dana.reyes",
            DEVICE_1,
            "ftdv-ravpn-1",
            "10.220.0.14",
            "198.51.100.77",
            "Employees",
            "Windows 11",
            "2026-09-30T12:01:07Z",
        ),
        _session(
            "priya.nair",
            DEVICE_1,
            "ftdv-ravpn-1",
            "10.220.0.21",
            "203.0.113.140",
            "Employees",
            "macOS 14",
            "2026-09-30T13:40:52Z",
        ),
        _session(
            "sam.okafor",
            DEVICE_2,
            "ftdv-ravpn-2",
            "10.220.1.3",
            "192.0.2.88",
            "Employees",
            "Windows 11",
            "2026-09-30T09:12:30Z",
        ),
        _session(
            "ext.contractor1",
            DEVICE_2,
            "ftdv-ravpn-2",
            "10.220.8.10",
            "198.51.100.201",
            "Contractors",
            "Ubuntu 24.04",
            "2026-09-30T14:02:11Z",
        ),
    ]
    nat_policies = [{"id": NAT_POLICY_ID, "type": "FTDNatPolicy", "name": "Corp-NAT", "description": "Corporate NAT"}]
    access_policies = [
        {
            "id": ACP_ID,
            "type": "AccessPolicy",
            "name": "Corp-ACP",
            "description": "Corporate access control",
            "defaultAction": {"action": "BLOCK", "logBegin": True, "logEnd": False, "sendEventsToFMC": True},
            "prefilterPolicySetting": _ref("PrefilterPolicy", PREFILTER_ID, "Corp-Prefilter"),
        }
    ]
    prefilter_policies = [
        {
            "id": PREFILTER_ID,
            "type": "PrefilterPolicy",
            "name": "Corp-Prefilter",
            "defaultAction": {"action": "ANALYZE_TUNNELS"},
        }
    ]
    s2s_vpns = [
        {
            "id": TOPOLOGY_HUB,
            "type": "FTDS2SVpn",
            "name": "DC-to-AWS-Hub",
            "topologyType": "HUB_AND_SPOKE",
            "ikeV1Enabled": False,
            "ikeV2Enabled": True,
            "routeBased": False,
        },
        {
            "id": TOPOLOGY_VGW,
            "type": "FTDS2SVpn",
            "name": "Branch-to-AWS-VGW",
            "topologyType": "POINT_TO_POINT",
            "ikeV1Enabled": False,
            "ikeV2Enabled": True,
            "routeBased": True,
        },
    ]
    proposal = [{"id": "ipsec-0001", "name": "AES-GCM-256", "type": "IKEv2IPsecProposal"}]
    s2s_details = {
        TOPOLOGY_HUB: {
            "endpoints": [
                {
                    "id": "ep-0001",
                    "type": "EndPoint",
                    "name": "ftdv-ravpn-ha",
                    "peerType": "HUB",
                    "extranet": False,
                    "device": pair_ref,
                    "interface": {"id": "GigabitEthernet0/0-outside", "name": "outside", "type": "PhysicalInterface"},
                    "protectedNetworks": {"networks": [_ref("NetworkGroup", "grp-0001", "AWS-VPCs")]},
                },
                {
                    "id": "ep-0002",
                    "type": "EndPoint",
                    "name": "ftd-branch-dc",
                    "peerType": "SPOKE",
                    "extranet": False,
                    "device": branch_ref,
                    "interface": {"id": "GigabitEthernet1/1-outside", "name": "outside", "type": "PhysicalInterface"},
                    "protectedNetworks": {
                        "networks": [
                            _ref("Network", "net-0001", "Branch-LAN"),
                            _ref("Network", "net-0002", "Branch-Voice"),
                        ]
                    },
                },
            ],
            "ike": [{"type": "IkeSetting", "ikeV2Settings": {"authenticationType": "MANUAL_PRE_SHARED_KEY"}}],
            "ipsec": [{"type": "IPSecSetting", "cryptoMapType": "STATIC", "ikeV2IpsecProposal": proposal}],
        },
        TOPOLOGY_VGW: {
            "endpoints": [
                {
                    "id": "ep-0003",
                    "type": "EndPoint",
                    "name": "ftd-branch-dc",
                    "peerType": "PEER",
                    "extranet": False,
                    "device": branch_ref,
                    "interface": {"id": "Tunnel1-vti-aws", "name": "vti-aws", "type": "VTIInterface"},
                    "protectedNetworks": {"networks": [_ref("Network", "net-0001", "Branch-LAN")]},
                },
                {
                    "id": "ep-0004",
                    "type": "EndPoint",
                    "name": "AWS-VGW",
                    "peerType": "PEER",
                    "extranet": True,
                    "extranetInfo": {"name": "AWS-VGW", "ipAddress": "203.0.113.101", "isDynamicIP": False},
                    "device": {"name": "AWS-VGW", "type": "ExtranetDevice"},
                    "protectedNetworks": {"networks": [_ref("NetworkGroup", "grp-0001", "AWS-VPCs")]},
                },
            ],
            "ike": [{"type": "IkeSetting", "ikeV2Settings": {"authenticationType": "MANUAL_PRE_SHARED_KEY"}}],
            "ipsec": [{"type": "IPSecSetting", "cryptoMapType": "STATIC", "ikeV2IpsecProposal": proposal}],
        },
    }
    # The VTI's address is the branch's local end of the route-based tunnel;
    # its source interface is the outside one, whose address the AWS
    # customer gateway names.
    tunnel_status = [
        {
            "type": "TunnelStatus",
            "topology": _ref("FTDS2SVpn", TOPOLOGY_HUB, "DC-to-AWS-Hub"),
            "peerA": {"device": _ref("Device", DEVICE_1, "ftdv-ravpn-1"), "ipAddress": "10.210.0.11"},
            "peerB": {"device": branch_ref, "ipAddress": "198.51.100.10"},
            "status": "UP",
            "lastChange": "2026-09-30T08:00:00Z",
        },
        {
            "type": "TunnelStatus",
            "topology": _ref("FTDS2SVpn", TOPOLOGY_VGW, "Branch-to-AWS-VGW"),
            "peerA": {"device": branch_ref, "ipAddress": "198.51.100.10"},
            "peerB": {"ipAddress": "203.0.113.101"},
            "status": "DOWN",
            "lastChange": "2026-09-30T02:40:00Z",
        },
    ]
    health_alerts = [
        {
            "type": "HealthAlert",
            "status": "yellow",
            "moduleName": "Interface Status",
            "description": "Interface GigabitEthernet0/1 reports errors",
            "device": _ref("Device", DEVICE_2, "ftdv-ravpn-2"),
            "timestamp": "2026-09-30T11:20:00Z",
        },
        {
            "type": "HealthAlert",
            "status": "red",
            "moduleName": "Cluster/Failover Status",
            "description": "Data unit left the cluster",
            "device": _ref("Device", DEVICE_5, "ftd-dc-unit-2"),
            "timestamp": "2026-09-30T13:55:00Z",
        },
    ]
    deployable = [
        {
            "type": "DeployableDevice",
            "name": "ftd-branch-dc",
            "device": branch_ref,
            "version": "1727690400000",
            "upToDate": False,
        }
    ]
    return {
        "fmc": {
            "url": "https://10.210.2.20",
            "name": "",
            "version": "7.4.1 (build 172)",
            "domain": "Global",
            "domain_uuid": DOMAIN_UUID,
            "domains": [{"name": "Global", "uuid": DOMAIN_UUID}],
        },
        "timestamp": "2026-09-30T14:05:00+00:00",
        "devices": devices,
        "on_map": [d["id"] for d in devices],
        "ha_pairs": ha_pairs,
        "ha_monitored": ha_monitored,
        "clusters": clusters,
        "policies": [policy],
        "assignments": assignments,
        "policy_details": policy_details,
        "pools": pools,
        "objects": _objects(),
        "interfaces": interfaces,
        "routing": _routing(),
        "nat_policies": nat_policies,
        "nat_rules": {NAT_POLICY_ID: _nat_rules()},
        "access_policies": access_policies,
        "access_rules": {ACP_ID: _access_rules()},
        "access_rule_counts": {ACP_ID: 3},
        "prefilter_policies": prefilter_policies,
        "prefilter_rules": {PREFILTER_ID: _prefilter_rules()},
        "prefilter_rule_counts": {PREFILTER_ID: 1},
        "s2s_vpns": s2s_vpns,
        "s2s_details": s2s_details,
        "tunnel_status": tunnel_status,
        "health_alerts": health_alerts,
        "deployable": deployable,
        "sessions": sessions,
        "errors": [],
        "unsupported": [],
        "stats": {"requests": 0, "retries": 0, "rate_limited": 0},
        "options": dict(DEFAULT_OPTIONS),
    }
