"""Deterministic sample organization in raw-collector shape.

Lets operators preview the topology map (and tests exercise the full
normalize -> export pipeline) without a Meraki API key. The payload mirrors
what ``collector.collect_organization`` returns, so it flows through exactly
the same code as a live build.
"""

from __future__ import annotations

from typing import Any

SAMPLE_ORG_ID = "sample"

_BRANCH_CITIES = (
    "Atlanta", "Boston", "Chicago", "Dallas", "Denver", "Houston", "Miami", "Nashville",
    "Phoenix", "Portland", "Raleigh", "Seattle", "Tampa", "Austin", "Detroit", "Omaha",
)  # fmt: skip


def _mac(site: int, unit: int) -> str:
    return f"e0:55:3d:{site:02x}:{unit:02x}:01"


def _link(a_serial: str, a_port: str, b_serial: str, b_port: str) -> dict:
    return {
        "ends": [
            {"device": {"serial": a_serial}, "discovered": {"lldp": {"portId": a_port}}},
            {"device": {"serial": b_serial}, "discovered": {"lldp": {"portId": b_port}}},
        ],
        "lastReportedAt": "2026-01-01T00:00:00Z",
    }


def _rule(policy: str, protocol: str, src: str, dst: str, dst_port: str = "Any", comment: str = "") -> dict:
    return {
        "policy": policy,
        "protocol": protocol,
        "srcCidr": src,
        "srcPort": "Any",
        "destCidr": dst,
        "destPort": dst_port,
        "comment": comment,
        "syslogEnabled": False,
    }


_DEFAULT_RULE = _rule("allow", "Any", "Any", "Any", comment="Default rule")


def _nat_rules(idx: int) -> dict[str, Any]:
    """1:1 NAT, port forwarding, 1:Many NAT and the inbound firewall rules
    of a site: the first hub publishes a web server, an SSH bastion and a
    mail relay; every other site publishes nothing."""
    if idx != 0:
        return {
            "one_to_one_nat": {"rules": []},
            "port_forwarding": {"rules": []},
            "one_to_many_nat": {"rules": []},
            "inbound_firewall": {"rules": [dict(_DEFAULT_RULE)], "syslogDefaultRule": False},
        }
    return {
        "one_to_one_nat": {
            "rules": [
                {
                    "name": "Web server",
                    "publicIp": "198.51.100.150",
                    "lanIp": "10.0.10.80",
                    "uplink": "internet1",
                    "allowedInbound": [{"protocol": "tcp", "destinationPorts": ["443"], "allowedIps": ["any"]}],
                }
            ]
        },
        "port_forwarding": {
            "rules": [
                {
                    "name": "SSH bastion",
                    "lanIp": "10.0.10.22",
                    "uplink": "both",
                    "publicPort": "2222",
                    "localPort": "22",
                    "allowedIps": ["203.0.113.0/24"],
                    "protocol": "tcp",
                }
            ]
        },
        "one_to_many_nat": {
            "rules": [
                {
                    "publicIp": "198.51.100.151",
                    "uplink": "internet1",
                    "portRules": [
                        {
                            "name": "Mail relay",
                            "protocol": "tcp",
                            "publicPort": "25",
                            "localIp": "10.0.10.25",
                            "localPort": "25",
                            "allowedIps": ["any"],
                        }
                    ],
                }
            ]
        },
        "inbound_firewall": {
            "rules": [
                _rule("allow", "tcp", "Any", "10.0.10.80/32", "443", "Web server (1:1 NAT)"),
                _rule("deny", "Any", "Any", "Any", comment="Deny all other inbound"),
                dict(_DEFAULT_RULE),
            ],
            "syslogDefaultRule": False,
        },
    }


def _switch_acl(idx: int) -> dict[str, Any]:
    return {
        "rules": [
            {
                "comment": "Guest to servers",
                "policy": "deny",
                "ipVersion": "ipv4",
                "protocol": "any",
                "srcCidr": f"10.{idx}.30.0/24",
                "srcPort": "any",
                "dstCidr": f"10.{idx}.100.0/24",
                "dstPort": "any",
                "vlan": "any",
            },
            {
                "comment": "Default rule",
                "policy": "allow",
                "ipVersion": "any",
                "protocol": "any",
                "srcCidr": "any",
                "srcPort": "any",
                "dstCidr": "any",
                "dstPort": "any",
                "vlan": "any",
            },
        ]
    }


def build_sample_raw(branches: int = 10) -> dict[str, Any]:
    """Two VPN hubs plus ``branches`` spoke sites."""
    branches = max(1, min(int(branches), len(_BRANCH_CITIES)))
    names = ["HQ-DataCenter", "DR-DataCenter"] + [f"Branch-{c}" for c in _BRANCH_CITIES[:branches]]
    networks: list[dict] = []
    devices: list[dict] = []
    statuses: list[dict] = []
    uplinks: list[dict] = []
    vpn_statuses: list[dict] = []
    switch_ports: list[dict] = []
    networks_detail: dict[str, dict] = {}
    devices_detail: dict[str, dict] = {}

    for idx, name in enumerate(names):
        is_hub = idx < 2
        net_id = f"N_{1000 + idx}"
        networks.append(
            {
                "id": net_id,
                "name": name,
                "productTypes": ["appliance", "switch", "wireless"],
                "timeZone": "America/New_York",
                "tags": ["hub", "datacenter"] if is_hub else ["branch"],
                "url": f"https://dashboard.meraki.com/o/sample/n/{net_id}",
            }
        )
        mx = f"Q2MX-{idx:04d}-0001"
        switch_count = 3 if is_hub else 1 + idx % 2
        ap_count = 4 if is_hub else 2 + idx % 3
        switches = [f"Q2SW-{idx:04d}-{n:04d}" for n in range(1, switch_count + 1)]
        aps = [f"Q2AP-{idx:04d}-{n:04d}" for n in range(1, ap_count + 1)]
        # One branch is down and one is degraded so status colouring is visible.
        site_status = "offline" if idx == 5 else "online"

        def add_device(
            serial: str, model: str, label: str, product: str, unit: int, status: str, _net=net_id, _idx=idx
        ) -> None:
            lan_ip = f"10.{_idx}.0.{unit}"
            devices.append(
                {
                    "serial": serial,
                    "name": label,
                    "model": model,
                    "mac": _mac(_idx, unit),
                    "networkId": _net,
                    "productType": product,
                    "firmware": {
                        "appliance": "wired-18-2-11",
                        "switch": "switch-17-1-4",
                        "wireless": "wireless-31-1-4",
                    }[product],
                    "lanIp": lan_ip,
                    "tags": ["sample"],
                    "address": f"{100 + _idx} Main St",
                }
            )
            statuses.append(
                {
                    "serial": serial,
                    "status": status,
                    "lanIp": lan_ip,
                    "publicIp": f"198.51.100.{10 + _idx}",
                    "gateway": f"10.{_idx}.0.1",
                    "primaryDns": "10.0.0.53",
                    "lastReportedAt": "2026-01-01T00:00:00Z",
                }
            )
            devices_detail[serial] = {}

        add_device(mx, "MX250" if is_hub else "MX68", f"{name}-MX", "appliance", 1, site_status)
        for n, serial in enumerate(switches, start=1):
            status = "alerting" if (idx == 3 and n == 1) else site_status
            add_device(serial, "MS390-48" if is_hub else "MS120-24P", f"{name}-SW{n}", "switch", 10 + n, status)
        for n, serial in enumerate(aps, start=1):
            add_device(serial, "MR46", f"{name}-AP{n}", "wireless", 50 + n, site_status)

        links = [_link(mx, "3", switches[0], "24")]
        for n in range(1, len(switches)):
            links.append(_link(switches[n - 1], "23", switches[n], "24"))
        for n, serial in enumerate(aps, start=1):
            links.append(_link(switches[n % len(switches)], str(n), serial, "0"))

        detail: dict[str, Any] = {
            "link_layer": {"nodes": [], "links": links},
            "vlans": [
                {
                    "id": 10,
                    "name": "Data",
                    "subnet": f"10.{idx}.10.0/24",
                    "applianceIp": f"10.{idx}.10.1",
                    "dhcpHandling": "Run a DHCP server",
                },
                {
                    "id": 20,
                    "name": "Voice",
                    "subnet": f"10.{idx}.20.0/24",
                    "applianceIp": f"10.{idx}.20.1",
                    "dhcpHandling": "Run a DHCP server",
                },
                {
                    "id": 30,
                    "name": "Guest",
                    "subnet": f"10.{idx}.30.0/24",
                    "applianceIp": f"10.{idx}.30.1",
                    "dhcpHandling": "Run a DHCP server",
                },
                {
                    "id": 99,
                    "name": "Management",
                    "subnet": f"10.{idx}.0.0/24",
                    "applianceIp": f"10.{idx}.0.1",
                    "dhcpHandling": "Do not respond to DHCP requests",
                },
            ],
            "static_routes": [
                {
                    "name": "Lab",
                    "subnet": f"172.16.{idx}.0/24",
                    "gatewayIp": f"10.{idx}.0.11",
                    "enabled": True,
                    "inVpn": is_hub,
                }
            ],
            "site_to_site_vpn": {
                "mode": "hub" if is_hub else "spoke",
                "hubs": []
                if is_hub
                else [{"hubId": "N_1000", "useDefaultRoute": False}, {"hubId": "N_1001", "useDefaultRoute": False}],
                "subnets": [
                    {"localSubnet": f"10.{idx}.10.0/24", "useVpn": True},
                    {"localSubnet": f"10.{idx}.20.0/24", "useVpn": True},
                    {"localSubnet": f"10.{idx}.30.0/24", "useVpn": False},
                ],
            },
            "appliance_ports": [
                {
                    "number": 3,
                    "enabled": True,
                    "type": "trunk",
                    "vlan": 99,
                    "allowedVlans": "all",
                    "dropUntaggedTraffic": False,
                },
                {"number": 4, "enabled": True, "type": "access", "vlan": 10, "dropUntaggedTraffic": False},
            ],
            "l3_firewall": {
                "rules": [
                    {
                        "policy": "deny",
                        "protocol": "any",
                        "srcCidr": "VLAN(30).*",
                        "srcPort": "Any",
                        "destCidr": "10.0.0.0/8",
                        "destPort": "Any",
                        "comment": "Guest isolation",
                        "syslogEnabled": True,
                    },
                    {
                        "policy": "allow",
                        "protocol": "any",
                        "srcCidr": "Any",
                        "srcPort": "Any",
                        "destCidr": "Any",
                        "destPort": "Any",
                        "comment": "Default rule",
                        "syslogEnabled": False,
                    },
                ]
            },
            **_nat_rules(idx),
            "switch_acl": _switch_acl(idx),
            "stp": {"rstpEnabled": True, "stpBridgePriority": [{"stpPriority": 4096, "switches": [switches[0]]}]},
            "ssids": [
                {
                    "number": 0,
                    "name": "Corp",
                    "enabled": True,
                    "authMode": "8021x-radius",
                    "encryptionMode": "wpa-eap",
                    "ipAssignmentMode": "Bridge mode",
                    "useVlanTagging": True,
                    "defaultVlanId": 10,
                    "bandSelection": "Dual band operation",
                    "visible": True,
                },
                {
                    "number": 1,
                    "name": "Guest",
                    "enabled": True,
                    "authMode": "psk",
                    "encryptionMode": "wpa",
                    "ipAssignmentMode": "Bridge mode",
                    "useVlanTagging": True,
                    "defaultVlanId": 30,
                    "bandSelection": "Dual band operation",
                    "visible": True,
                },
            ],
        }
        if is_hub:
            detail["stacks"] = [{"id": f"stack-{idx}", "name": f"{name}-core-stack", "serials": switches[:2]}]
            detail["bgp"] = {
                "enabled": True,
                "asNumber": 65000 + idx,
                "ibgpHoldTimer": 240,
                "neighbors": [
                    {
                        "ip": f"10.{idx}.0.250",
                        "remoteAsNumber": 65100,
                        "receiveLimit": 150,
                        "allowTransit": True,
                        "ebgpHoldTimer": 180,
                        "ebgpMultihop": 2,
                    }
                ],
            }
            devices_detail[switches[0]]["routing_interfaces"] = [
                {
                    "name": "Servers",
                    "vlanId": 100,
                    "subnet": f"10.{idx}.100.0/24",
                    "interfaceIp": f"10.{idx}.100.1",
                    "defaultGateway": f"10.{idx}.0.1",
                }
            ]
            devices_detail[switches[0]]["routing_static_routes"] = [
                {"name": "Default", "subnet": "0.0.0.0/0", "nextHopIp": f"10.{idx}.0.1"}
            ]
        if idx == 0:
            # A non-Meraki core switch seen over LLDP - the kind of node that
            # correlates with Plexus inventory for SNMP/SSH enrichment.
            devices_detail[switches[0]]["lldp_cdp"] = {
                "ports": {
                    "48": {
                        "lldp": {
                            "systemName": "core-sw1.example.net",
                            "portId": "TenGigabitEthernet1/0/1",
                            "managementAddress": "10.0.0.2",
                            "systemDescription": "Cisco IOS XE Software, Catalyst 9500",
                        },
                        "cdp": {
                            "deviceId": "core-sw1.example.net",
                            "portId": "TenGigabitEthernet1/0/1",
                            "address": "10.0.0.2",
                            "platform": "cisco C9500-24Y4C",
                        },
                    }
                }
            }
        detail["clients"] = [
            {
                "mac": f"3c:22:fb:{idx:02x}:{n:02x}:{c:02x}",
                "ip": f"10.{idx}.{20 if c == 2 else 10}.{50 + n * 10 + c}",
                "vlan": 20 if c == 2 else 10,
                "switchport": str(c),
                "description": f"{'phone' if c == 2 else 'laptop'}-{idx}-{n}-{c}",
                "manufacturer": "Cisco" if c == 2 else "Dell",
                "status": "Online",
                "lastSeen": "2026-01-01T00:00:00Z",
                "recentDeviceSerial": serial,
                "recentDeviceName": f"{name}-SW{n}",
            }
            for n, serial in enumerate(switches, start=1)
            for c in (1, 2, 3)
        ] + [
            {
                "mac": f"a4:83:e7:{idx:02x}:{n:02x}:01",
                "ip": f"10.{idx}.30.{100 + n}",
                "vlan": 30,
                "description": f"guest-{idx}-{n}",
                "manufacturer": "Apple",
                "ssid": "Guest",
                "status": "Online",
                "lastSeen": "2026-01-01T00:00:00Z",
                "recentDeviceSerial": serial,
                "recentDeviceName": f"{name}-AP{n}",
            }
            for n, serial in enumerate(aps, start=1)
        ]
        networks_detail[net_id] = detail

        wan2_status = "active" if is_hub else ("failed" if idx == 3 else "ready")
        uplinks.append(
            {
                "serial": mx,
                "networkId": net_id,
                "uplinks": [
                    {
                        "interface": "wan1",
                        "status": "failed" if site_status == "offline" else "active",
                        "ip": f"198.51.100.{10 + idx}",
                        "gateway": "198.51.100.1",
                        "publicIp": f"198.51.100.{10 + idx}",
                        "primaryDns": "8.8.8.8",
                        "ipAssignedBy": "static",
                    },
                    {
                        "interface": "wan2",
                        "status": wan2_status,
                        "ip": f"203.0.113.{10 + idx}",
                        "gateway": "203.0.113.1",
                        "publicIp": f"203.0.113.{10 + idx}",
                        "primaryDns": "1.1.1.1",
                        "ipAssignedBy": "dhcp",
                    },
                ],
            }
        )
        reach = "unreachable" if site_status == "offline" else "reachable"
        peers = [
            {"networkId": f"N_{1000 + p}", "networkName": names[p], "reachability": "unreachable" if p == 5 else reach}
            for p in (range(len(names)) if is_hub else range(2))
            if p != idx
        ]
        vpn_statuses.append(
            {
                "networkId": net_id,
                "networkName": name,
                "deviceSerial": mx,
                "deviceStatus": site_status,
                "vpnMode": "hub" if is_hub else "spoke",
                "exportedSubnets": [
                    {"subnet": f"10.{idx}.10.0/24", "name": "Data"},
                    {"subnet": f"10.{idx}.20.0/24", "name": "Voice"},
                ],
                "merakiVpnPeers": peers,
                "thirdPartyVpnPeers": [{"name": "AWS-Transit", "publicIp": "192.0.2.50", "reachability": "reachable"}]
                if is_hub
                else [],
            }
        )
        for serial in switches:
            switch_ports.append(
                {
                    "serial": serial,
                    "ports": [
                        {
                            "portId": str(p),
                            "name": "Uplink" if p >= 23 else f"Access {p}",
                            "enabled": True,
                            "type": "trunk" if p >= 23 else "access",
                            "vlan": 99 if p >= 23 else 10,
                            "voiceVlan": None if p >= 23 else 20,
                            "allowedVlans": "all" if p >= 23 else "10,20",
                            "poeEnabled": p < 23,
                            "rstpEnabled": True,
                            "stpGuard": "disabled" if p >= 23 else "bpdu guard",
                        }
                        for p in range(1, 25)
                    ],
                }
            )

    return {
        "organization": {
            "id": SAMPLE_ORG_ID,
            "name": "Sample Organization (demo data)",
            "url": "https://dashboard.meraki.com/o/sample",
        },
        "networks": networks,
        "devices": devices,
        "org": {
            "device_statuses": statuses,
            "uplink_statuses": uplinks,
            "vpn_statuses": vpn_statuses,
            "third_party_vpn_peers": {
                "peers": [
                    {
                        "name": "AWS-Transit",
                        "publicIp": "192.0.2.50",
                        "privateSubnets": ["172.31.0.0/16"],
                        "ikeVersion": "2",
                        "networkTags": ["hub"],
                    }
                ]
            },
            "switch_ports": switch_ports,
            # Organisation-wide, applied to traffic leaving over AutoVPN.
            "vpn_firewall": {
                "rules": [
                    _rule(
                        "deny",
                        "Any",
                        "10.1.30.0/24,10.2.30.0/24",
                        "10.0.0.0/8",
                        comment="Block guest VLANs over the VPN",
                    ),
                    dict(_DEFAULT_RULE),
                ]
            },
        },
        "networks_detail": networks_detail,
        "devices_detail": devices_detail,
        "errors": [],
        "stats": {"requests": 0, "retries": 0, "rate_limited": 0},
        "options": {"sample": True},
    }
