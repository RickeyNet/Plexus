"""Bundled demo Panorama, in the shape ``collector.collect_panorama`` returns.

Lets the Palo Alto Panorama part of the map be previewed (and tested)
without a Panorama, with data in every section the normalizer draws:

  - device groups Shared > ``Corporate`` > ``Branches``, with address,
    service and group objects at every level (a dynamic address group too)
  - ``hq-fw-01`` / ``hq-fw-02``, a PA-5220 HA pair (active / passive) at HQ:
    zones trust, untrust, dmz, vpn and gp-vpn, static and BGP routes, an
    IPsec tunnel to the branch and one to an unmanaged partner peer at
    203.0.113.9 whose SA is down, and a GlobalProtect gateway with three
    users and the pool 10.252.0.0/22
  - ``branch-fw-01``, a PA-440 in the Branches device group with a guest
    sub-interface and the other end of the HQ tunnel
  - ``aws-vm-fw-01``, a PA-VM in the AWS sample's edge VPC
    (``netcontrol.integrations.aws.sample``: the instance ``pa-vm-edge-1``,
    same private addresses), whose shared policy is out of sync
  - security rules at every level, among them ``application-default``, a
    dynamic group, a disabled rule, a rule targeting the HQ pair only, and
    the intrazone / interzone default rules (interzone logged)
  - NAT: interface-address source NAT to untrust, a destination NAT for the
    DMZ web server, a bi-directional static NAT for the mail server and a
    no-NAT rule for the VPN

Public addresses are from the documentation ranges.
"""

from __future__ import annotations

import zlib
from typing import Any

from netcontrol.integrations.panorama.collector import DEFAULT_OPTIONS

HQ_1 = "013201000001"
HQ_2 = "013201000002"
BRANCH = "021201000101"
AWS_VM = "007954000201"

HQ_PUBLIC = "203.0.113.131"
BRANCH_PUBLIC = "198.51.100.134"
PARTNER_PEER = "203.0.113.9"
WEB_PUBLIC = "203.0.113.132"
MAIL_PUBLIC = "203.0.113.133"
GP_POOL = "10.252.0.0/22"

_FLAGS = (
    "A:active, ?:loose, C:connect, H:host, S:static, ~:internal, R:rip, O:ospf, B:bgp, "
    "Oi:ospf intra-area, Oo:ospf inter-area, O1:ospf ext-type-1, O2:ospf ext-type-2, E:ecmp, M:multicast"
)


def _device(
    serial: str,
    hostname: str,
    model: str,
    mgmt: str,
    version: str,
    *,
    ha_state: str = "",
    peer: str = "",
    policy: str = "In Sync",
) -> dict[str, Any]:
    device: dict[str, Any] = {
        "@name": serial,
        "serial": serial,
        "connected": "yes",
        "unsupported-version": "no",
        "hostname": hostname,
        "ip-address": mgmt,
        "model": model,
        "sw-version": version,
        "app-version": "8890-9112",
        "threat-version": "8890-9112",
        "uptime": "41 days, 3:12:08",
        "family": model.removeprefix("PA-").split("-")[0] if model != "PA-VM" else "vm",
        "multi-vsys": "no",
        "vsys": [{"@name": "vsys1", "display-name": "vsys1"}],
        "shared-policy-status": policy,
        "template-status": "In Sync",
    }
    if ha_state:
        device["ha"] = {"state": ha_state, "peer": {"serial": peer}}
    return device


def _member(serial: str, hostname: str) -> dict[str, Any]:
    return {"@name": serial, "serial": serial, "hostname": hostname, "connected": "yes", "vsys": [{"@name": "vsys1"}]}


def _rule(name: str, action: str, *, src_zones=("any",), dst_zones=("any",), **fields: Any) -> dict[str, Any]:
    rule = {
        "@name": name,
        "@uuid": f"{zlib.crc32(name.encode()):08x}-0000-4000-8000-000000000000",
        "from": list(src_zones),
        "to": list(dst_zones),
        "source": list(fields.pop("source", ["any"])),
        "destination": list(fields.pop("destination", ["any"])),
        "source-user": list(fields.pop("source_user", ["any"])),
        "category": ["any"],
        "application": list(fields.pop("application", ["any"])),
        "service": list(fields.pop("service", ["any"])),
        "action": action,
        "log-end": "yes",
    }
    for key, value in fields.items():
        rule[key.replace("_", "-")] = value
    return rule


def _target(*serials: str) -> dict[str, Any]:
    return {"devices": [{"@name": s} for s in serials], "negate": "no"}


def _objects() -> dict[str, dict[str, list[dict]]]:
    def address(name: str, value: str, kind: str = "ip-netmask", **extra: Any) -> dict:
        return {"@name": name, kind: value, **extra}

    def service(name: str, protocol: str, port: str) -> dict:
        return {"@name": name, "protocol": {protocol: {"port": port}}}

    return {
        "shared": {
            "address": [
                address("Blocked-Host-1", "192.0.2.66", description="Known command and control"),
                address("Blocked-Range", "192.0.2.200-192.0.2.220", "ip-range"),
                address("update-server", "updates.example.com", "fqdn"),
            ],
            "address-group": [{"@name": "Blocked-Destinations", "static": ["Blocked-Host-1", "Blocked-Range"]}],
            "service": [service("svc-tcp-8443", "tcp", "8443"), service("svc-telnet", "tcp", "23")],
            "service-group": [{"@name": "Web-Ports", "members": ["service-https", "svc-tcp-8443"]}],
            "application-group": [{"@name": "Web-Apps", "members": ["web-browsing", "ssl"]}],
        },
        "Corporate": {
            "address": [
                address("HQ-LAN", "10.150.10.0/24", tag=["hq"]),
                address("HQ-DMZ", "10.150.50.0/24", tag=["hq"]),
                address("web-server", "10.150.50.10"),
                address("web-public", WEB_PUBLIC),
                address("mail-server", "10.150.50.25"),
                address("mail-public", MAIL_PUBLIC),
                address("GP-Pool", GP_POOL),
                address("Branch-Networks", "10.151.0.0/16"),
                address("Partner-Net", "172.16.40.0/24"),
            ],
            "address-group": [
                {"@name": "HQ-Networks", "static": ["HQ-LAN", "HQ-DMZ"]},
                {"@name": "Quarantined-Hosts", "dynamic": {"filter": "'quarantine'"}},
            ],
            "service": [service("svc-ftp", "tcp", "21")],
            "service-group": [],
            "application-group": [],
        },
        "Branches": {
            "address": [address("Branch-LAN", "10.151.10.0/24"), address("Branch-Guest", "10.151.30.0/24")],
            "address-group": [],
            "service": [],
            "service-group": [],
            "application-group": [],
        },
    }


def _security_rules() -> dict[str, dict[str, list[dict]]]:
    return {
        "shared": {
            "pre": [_rule("Block-Known-Bad", "drop", destination=["Blocked-Destinations"], tag=["threat"])],
            "post": [],
        },
        "Corporate": {
            "pre": [
                _rule(
                    "Allow-HQ-to-Branch",
                    "allow",
                    src_zones=["trust"],
                    dst_zones=["vpn"],
                    source=["HQ-Networks"],
                    destination=["Branch-Networks"],
                ),
                _rule(
                    "Allow-Branch-to-HQ",
                    "allow",
                    src_zones=["vpn"],
                    dst_zones=["trust", "dmz"],
                    source=["Branch-Networks"],
                    destination=["HQ-Networks"],
                    service=["Web-Ports"],
                ),
                _rule(
                    "Allow-DMZ-Web",
                    "allow",
                    src_zones=["untrust", "trust"],
                    dst_zones=["dmz"],
                    destination=["web-public", "web-server"],
                    application=["Web-Apps"],
                    service=["application-default"],
                    target=_target(HQ_1, HQ_2),
                    profile_setting={"group": ["default"]},
                    description="Published web site, HQ only",
                ),
                _rule(
                    "Allow-Trust-DMZ-HTTPS",
                    "allow",
                    src_zones=["trust"],
                    dst_zones=["dmz"],
                    source=["HQ-LAN"],
                    destination=["HQ-DMZ"],
                    service=["service-https"],
                ),
                _rule(
                    "Users-Internet",
                    "allow",
                    src_zones=["trust"],
                    dst_zones=["untrust"],
                    source=["HQ-LAN"],
                    application=["web-browsing", "ssl", "dns"],
                    service=["application-default"],
                    profile_setting={"group": ["default"]},
                ),
                _rule(
                    "Legacy-FTP",
                    "allow",
                    src_zones=["trust"],
                    dst_zones=["dmz"],
                    source=["HQ-LAN"],
                    destination=["HQ-DMZ"],
                    service=["svc-ftp"],
                    disabled="yes",
                    description="Retired with the old file server",
                ),
                _rule(
                    "GP-Users-to-HQ",
                    "allow",
                    src_zones=["gp-vpn"],
                    dst_zones=["trust", "dmz"],
                    source=["GP-Pool"],
                    destination=["HQ-Networks"],
                    source_user=["corp\\vpn-users"],
                ),
            ],
            "post": [_rule("Deny-Telnet", "deny", service=["svc-telnet"], tag=["hygiene"])],
        },
        "Branches": {
            "pre": [
                _rule("Guest-Quarantine", "deny", src_zones=["guest"], source=["Quarantined-Hosts"]),
                _rule(
                    "Branch-Guest-Internet",
                    "allow",
                    src_zones=["guest"],
                    dst_zones=["untrust"],
                    source=["Branch-Guest"],
                    service=["service-http", "service-https"],
                ),
                _rule(
                    "Branch-Allow-HQ-In",
                    "allow",
                    src_zones=["vpn"],
                    dst_zones=["trust"],
                    source=["HQ-Networks", "GP-Pool"],
                    destination=["Branch-LAN"],
                ),
            ],
            "post": [
                _rule("Branch-Deny-Guest-to-LAN", "deny", src_zones=["guest"], dst_zones=["trust", "vpn"]),
            ],
        },
    }


def _nat_rule(name: str, *, src_zones, dst_zones, **fields: Any) -> dict[str, Any]:
    rule = {
        "@name": name,
        "from": list(src_zones),
        "to": list(dst_zones),
        "source": list(fields.pop("source", ["any"])),
        "destination": list(fields.pop("destination", ["any"])),
        "service": fields.pop("service", "any"),
        "to-interface": fields.pop("to_interface", "any"),
        "nat-type": "ipv4",
    }
    for key, value in fields.items():
        rule[key.replace("_", "-")] = value
    return rule


def _nat_rules() -> dict[str, dict[str, list[dict]]]:
    return {
        "shared": {"pre": [], "post": []},
        "Corporate": {
            "pre": [
                _nat_rule(
                    "No-NAT-VPN",
                    src_zones=["trust", "dmz"],
                    dst_zones=["vpn"],
                    description="Site-to-site traffic keeps its addresses",
                ),
                _nat_rule(
                    "Web-DNAT",
                    src_zones=["untrust"],
                    dst_zones=["untrust"],
                    destination=["web-public"],
                    service="service-https",
                    destination_translation={"translated-address": "web-server", "translated-port": "443"},
                    target=_target(HQ_1, HQ_2),
                ),
                _nat_rule(
                    "Mail-Static",
                    src_zones=["dmz"],
                    dst_zones=["untrust"],
                    source=["mail-server"],
                    source_translation={"static-ip": {"translated-address": "mail-public", "bi-directional": "yes"}},
                    target=_target(HQ_1, HQ_2),
                ),
                _nat_rule(
                    "Outbound-PAT",
                    src_zones=["trust", "dmz"],
                    dst_zones=["untrust"],
                    source_translation={
                        "dynamic-ip-and-port": {"interface-address": {"interface": "ethernet1/1"}},
                    },
                ),
            ],
            "post": [],
        },
        "Branches": {
            "pre": [
                _nat_rule(
                    "Branch-Outbound-PAT",
                    src_zones=["trust", "guest"],
                    dst_zones=["untrust"],
                    source_translation={
                        "dynamic-ip-and-port": {"interface-address": {"interface": "ethernet1/1"}},
                    },
                ),
            ],
            "post": [],
        },
    }


def _ethernet(name: str, ip: str, comment: str, *, units: list[dict] | None = None) -> dict:
    layer3: dict[str, Any] = {"ip": [{"@name": ip}], "interface-management-profile": "allow-ping"}
    if units:
        layer3["units"] = units
    return {"@name": name, "layer3": layer3, "comment": comment}


def _zone(name: str, *interfaces: str) -> dict:
    return {"@name": name, "network": {"layer3": list(interfaces)}}


def _static(name: str, destination: str, interface: str, gateway: str = "", metric: str = "10") -> dict:
    route: dict[str, Any] = {"@name": name, "destination": destination, "interface": interface, "metric": metric}
    if gateway:
        route["nexthop"] = {"ip-address": gateway}
    return route


def _vr(interfaces: list[str], routes: list[dict], protocol: dict | None = None) -> list[dict]:
    router: dict[str, Any] = {
        "@name": "default",
        "interface": interfaces,
        "routing-table": {"ip": {"static-route": routes}},
    }
    if protocol:
        router["protocol"] = protocol
    return [router]


def _ike(name: str, version: str, peer: str) -> dict:
    # Panorama answers with the pre-shared key too; the collector drops it.
    return {
        "@name": name,
        "protocol": {"version": version},
        "local-address": {"interface": "ethernet1/1", "ip": "$untrust-ip"},
        "peer-address": {"ip": peer},
    }


def _template_config() -> dict[str, dict[str, Any]]:
    hq_interfaces = ["ethernet1/1", "ethernet1/2", "ethernet1/3", "loopback.1", "tunnel.1", "tunnel.2", "tunnel.10"]
    return {
        "Global-Base": {
            "variable": [],
            "interface": {},
            "vsys": [],
            "virtual-router": [],
            "ike-gateway": [],
            "ipsec": [],
            "global-protect-gateway": [],
        },
        "HQ-Network": {
            "variable": [{"@name": "$untrust-ip", "type": {"ip-netmask": "203.0.113.2/28"}}],
            "interface": {
                "ethernet": [
                    _ethernet("ethernet1/1", "$untrust-ip", "Internet (ISP-A)"),
                    _ethernet("ethernet1/2", "10.150.10.1/24", "Corporate LAN"),
                    _ethernet("ethernet1/3", "10.150.50.1/24", "DMZ"),
                ],
                "loopback": {
                    "units": [{"@name": "loopback.1", "ip": [{"@name": "10.150.0.1/32"}], "comment": "Router ID"}]
                },
                "tunnel": {
                    "units": [
                        {"@name": "tunnel.1", "ip": [{"@name": "169.254.10.1/30"}], "comment": "To branch-fw-01"},
                        {"@name": "tunnel.2", "comment": "To the partner"},
                        {"@name": "tunnel.10", "comment": "GlobalProtect"},
                    ]
                },
            },
            "vsys": [
                {
                    "@name": "vsys1",
                    "zone": [
                        _zone("untrust", "ethernet1/1"),
                        _zone("trust", "ethernet1/2", "loopback.1"),
                        _zone("dmz", "ethernet1/3"),
                        _zone("vpn", "tunnel.1", "tunnel.2"),
                        _zone("gp-vpn", "tunnel.10"),
                    ],
                    "import": {"network": {"interface": hq_interfaces}},
                    "global-protect": {
                        "global-protect-gateway": [
                            {
                                "@name": "GP-HQ-Gateway",
                                "local-address": {"interface": "ethernet1/1", "ip": {"ipv4": "$untrust-ip"}},
                                "remote-user-tunnel": "tunnel.10",
                                "remote-user-tunnel-configs": [{"@name": "Employees", "ip-pool": [GP_POOL]}],
                            }
                        ]
                    },
                }
            ],
            "virtual-router": _vr(
                hq_interfaces,
                [
                    _static("default", "0.0.0.0/0", "ethernet1/1", "203.0.113.129"),
                    _static("to-branch", "10.151.0.0/16", "tunnel.1"),
                    _static("to-partner", "172.16.40.0/24", "tunnel.2"),
                ],
                {
                    "bgp": {
                        "enable": "yes",
                        "router-id": "10.150.0.1",
                        "local-as": "65150",
                        "peer-group": [
                            {
                                "@name": "ISP",
                                "peer": [
                                    {
                                        "@name": "isp-a",
                                        "enable": "yes",
                                        "peer-as": "64500",
                                        "peer-address": {"ip": "203.0.113.129"},
                                        "local-address": {"interface": "ethernet1/1", "ip": "$untrust-ip"},
                                    }
                                ],
                            }
                        ],
                    },
                    "ospf": {"enable": "no"},
                },
            ),
            "ike-gateway": [_ike("gw-branch", "ikev2", BRANCH_PUBLIC), _ike("gw-partner", "ikev1", PARTNER_PEER)],
            "ipsec": [
                {
                    "@name": "tun-branch",
                    "tunnel-interface": "tunnel.1",
                    "auto-key": {"ike-gateway": [{"@name": "gw-branch"}], "ipsec-crypto-profile": "default"},
                    "tunnel-monitor": {"enable": "yes", "destination-ip": "169.254.10.2"},
                },
                {
                    "@name": "tun-partner",
                    "tunnel-interface": "tunnel.2",
                    "auto-key": {
                        "ike-gateway": [{"@name": "gw-partner"}],
                        "ipsec-crypto-profile": "Suite-B-GCM-128",
                        "proxy-id": [
                            {
                                "@name": "partner",
                                "local": "10.150.10.0/24",
                                "remote": "172.16.40.0/24",
                                "protocol": {"any": ""},
                            }
                        ],
                    },
                },
            ],
            "global-protect-gateway": [
                {
                    "@name": "GP-HQ-Gateway-N",
                    "tunnel-interface": "tunnel.10",
                    "local-address": {"interface": "ethernet1/1", "ip": {"ipv4": "$untrust-ip"}},
                    "max-user": "500",
                }
            ],
        },
        "Branch-Network": {
            "variable": [{"@name": "$untrust-ip", "type": {"ip-netmask": "198.51.100.2/30"}}],
            "interface": {
                "ethernet": [
                    _ethernet("ethernet1/1", "$untrust-ip", "Internet (broadband)"),
                    _ethernet(
                        "ethernet1/2",
                        "10.151.10.1/24",
                        "Branch LAN",
                        units=[
                            {
                                "@name": "ethernet1/2.30",
                                "tag": "30",
                                "ip": [{"@name": "10.151.30.1/24"}],
                                "comment": "Guest Wi-Fi",
                            }
                        ],
                    ),
                ],
                "tunnel": {"units": [{"@name": "tunnel.1", "ip": [{"@name": "169.254.10.2/30"}], "comment": "To HQ"}]},
            },
            "vsys": [
                {
                    "@name": "vsys1",
                    "zone": [
                        _zone("untrust", "ethernet1/1"),
                        _zone("trust", "ethernet1/2"),
                        _zone("guest", "ethernet1/2.30"),
                        _zone("vpn", "tunnel.1"),
                    ],
                    "import": {"network": {"interface": ["ethernet1/1", "ethernet1/2", "ethernet1/2.30", "tunnel.1"]}},
                }
            ],
            "virtual-router": _vr(
                ["ethernet1/1", "ethernet1/2", "ethernet1/2.30", "tunnel.1"],
                [
                    _static("default", "0.0.0.0/0", "ethernet1/1", "198.51.100.133"),
                    _static("to-hq", "10.150.0.0/16", "tunnel.1"),
                    _static("to-gp-users", GP_POOL, "tunnel.1"),
                ],
            ),
            "ike-gateway": [_ike("gw-hq", "ikev2", HQ_PUBLIC)],
            "ipsec": [
                {
                    "@name": "tun-hq",
                    "tunnel-interface": "tunnel.1",
                    "auto-key": {"ike-gateway": [{"@name": "gw-hq"}], "ipsec-crypto-profile": "default"},
                    "tunnel-monitor": {"enable": "yes", "destination-ip": "169.254.10.1"},
                }
            ],
            "global-protect-gateway": [],
        },
        "AWS-Network": {
            "variable": [],
            "interface": {
                "ethernet": [
                    _ethernet("ethernet1/1", "10.210.0.13/24", "edge-outside-a (elastic IP 203.0.113.13)"),
                    _ethernet("ethernet1/2", "10.210.1.13/24", "edge-inside-a"),
                ]
            },
            "vsys": [
                {
                    "@name": "vsys1",
                    "zone": [_zone("untrust", "ethernet1/1"), _zone("trust", "ethernet1/2")],
                    "import": {"network": {"interface": ["ethernet1/1", "ethernet1/2"]}},
                }
            ],
            "virtual-router": _vr(
                ["ethernet1/1", "ethernet1/2"],
                [
                    _static("default", "0.0.0.0/0", "ethernet1/1", "10.210.0.1"),
                    _static("to-vpcs", "10.0.0.0/8", "ethernet1/2", "10.210.1.1"),
                ],
            ),
            "ike-gateway": [],
            "ipsec": [],
            "global-protect-gateway": [],
        },
    }


def _ifnet(name: str, zone: str, ip: str = "N/A", tag: str = "0") -> dict:
    return {"name": name, "zone": zone, "fwd": "vr:default", "vsys": "1", "dyn-addr": "", "tag": tag, "ip": ip}


def _hw(name: str, state: str, mac: str) -> dict:
    return {"name": name, "duplex": "full", "type": "0", "state": state, "st": f"10000/full/{state}", "mac": mac}


def _route(destination: str, nexthop: str, interface: str, flags: str, metric: str = "10") -> dict:
    return {
        "virtual-router": "default",
        "destination": destination,
        "nexthop": nexthop,
        "metric": metric,
        "flags": flags,
        "age": "",
        "interface": interface,
        "route-table": "unicast",
    }


def _hq_state(*, active: bool) -> dict[str, Any]:
    link = "up" if active else "down"
    suffix = "10" if active else "20"
    state: dict[str, Any] = {
        "interfaces": {
            "ifnet": [
                _ifnet("ethernet1/1", "untrust", f"{HQ_PUBLIC}/28"),
                _ifnet("ethernet1/2", "trust", "10.150.10.1/24"),
                _ifnet("ethernet1/3", "dmz", "10.150.50.1/24"),
                _ifnet("loopback.1", "trust", "10.150.0.1/32"),
                _ifnet("tunnel.1", "vpn", "169.254.10.1/30"),
                _ifnet("tunnel.2", "vpn"),
                _ifnet("tunnel.10", "gp-vpn"),
            ],
            "hw": [
                _hw("ethernet1/1", link, f"b4:0c:25:00:{suffix}:11"),
                _hw("ethernet1/2", link, f"b4:0c:25:00:{suffix}:12"),
                _hw("ethernet1/3", link, f"b4:0c:25:00:{suffix}:13"),
            ],
        },
        "routes": {
            "flags": _FLAGS,
            "entry": [
                _route("0.0.0.0/0", "203.0.113.129", "ethernet1/1", "A S"),
                _route("10.150.0.1/32", "0.0.0.0", "loopback.1", "A C", "0"),
                _route("10.150.10.0/24", "10.150.10.1", "ethernet1/2", "A C", "0"),
                _route("10.150.10.1/32", "0.0.0.0", "ethernet1/2", "A H", "0"),
                _route("10.150.50.0/24", "10.150.50.1", "ethernet1/3", "A C", "0"),
                _route("10.151.0.0/16", "0.0.0.0", "tunnel.1", "A S"),
                _route("169.254.10.0/30", "169.254.10.1", "tunnel.1", "A C", "0"),
                _route("172.16.40.0/24", "0.0.0.0", "tunnel.2", "A S"),
                _route("203.0.113.128/28", HQ_PUBLIC, "ethernet1/1", "A C", "0"),
            ],
        },
        "ha": {
            "enabled": "yes",
            "group": {
                "mode": "Active-Passive",
                "local-info": {
                    "state": "active" if active else "passive",
                    "priority": "100" if active else "110",
                    "mgmt-ip": "10.150.254.11/24" if active else "10.150.254.12/24",
                },
                "peer-info": {
                    "state": "passive" if active else "active",
                    "conn-status": "up",
                    "mgmt-ip": "10.150.254.12/24" if active else "10.150.254.11/24",
                },
                "running-sync": "synchronized",
            },
        },
    }
    if active:
        state["routes"]["entry"].append(_route("198.18.0.0/15", "203.0.113.129", "ethernet1/1", "A B", "0"))
        state["bgp_peers"] = [
            {
                "@peer": "isp-a",
                "@vr": "default",
                "peer-group": "ISP",
                "peer-router-id": "203.0.113.129",
                "remote-as": "64500",
                "status": "Established",
                "status-duration": "864000",
                "peer-address": "203.0.113.129:179",
                "local-address": f"{HQ_PUBLIC}:33012",
            }
        ]
        state["ipsec_sa"] = {
            "ntun": "1",
            "entries": [{"name": "tun-branch", "gateway": "gw-branch", "remote": BRANCH_PUBLIC, "local": HQ_PUBLIC}],
        }
        state["vpn_flow"] = {
            "num_ipsec": "2",
            "IPSec": [
                {
                    "name": "tun-branch",
                    "id": "1",
                    "state": "active",
                    "mon": "up",
                    "inner-if": "tunnel.1",
                    "outer-if": "ethernet1/1",
                    "localip": HQ_PUBLIC,
                    "peerip": BRANCH_PUBLIC,
                },
                {
                    "name": "tun-partner",
                    "id": "2",
                    "state": "init",
                    "mon": "off",
                    "inner-if": "tunnel.2",
                    "outer-if": "ethernet1/1",
                    "localip": HQ_PUBLIC,
                    "peerip": PARTNER_PEER,
                },
            ],
        }
        state["gp_users"] = [
            _gp_user("alex.kim", "LT-AKIM", "10.252.0.11", "198.51.100.141", "Microsoft Windows 11 Enterprise"),
            _gp_user("dana.reyes", "MBP-DREYES", "10.252.0.12", "198.51.100.142", "Apple macOS 15.1"),
            _gp_user("sam.okafor", "LT-SOKAFOR", "10.252.1.7", "198.51.100.143", "Microsoft Windows 11 Pro"),
        ]
    else:
        state["bgp_peers"] = None
        state["ipsec_sa"] = None
        state["vpn_flow"] = {"num_ipsec": "0"}
        state["gp_users"] = None
    return state


def _gp_user(username: str, computer: str, virtual_ip: str, public_ip: str, client: str) -> dict:
    return {
        "domain": "corp",
        "islocal": "no",
        "username": username,
        "computer": computer,
        "client": client,
        "vpn-type": "Device Level VPN",
        "virtual-ip": virtual_ip,
        "public-ip": public_ip,
        "tunnel-type": "IPSec",
        "login-time": "Oct.09 08:12:44",
        "lifetime": "2592000",
        "app-version": "6.2.4-71",
    }


def _branch_state() -> dict[str, Any]:
    return {
        "interfaces": {
            "ifnet": [
                _ifnet("ethernet1/1", "untrust", f"{BRANCH_PUBLIC}/30"),
                _ifnet("ethernet1/2", "trust", "10.151.10.1/24"),
                _ifnet("ethernet1/2.30", "guest", "10.151.30.1/24", "30"),
                _ifnet("tunnel.1", "vpn", "169.254.10.2/30"),
            ],
            "hw": [_hw("ethernet1/1", "up", "d4:f4:be:00:01:01"), _hw("ethernet1/2", "up", "d4:f4:be:00:01:02")],
        },
        "routes": {
            "flags": _FLAGS,
            "entry": [
                _route("0.0.0.0/0", "198.51.100.133", "ethernet1/1", "A S"),
                _route("10.150.0.0/16", "0.0.0.0", "tunnel.1", "A S"),
                _route("10.151.10.0/24", "10.151.10.1", "ethernet1/2", "A C", "0"),
                _route("10.151.30.0/24", "10.151.30.1", "ethernet1/2.30", "A C", "0"),
                _route(GP_POOL, "0.0.0.0", "tunnel.1", "A S"),
                _route("198.51.100.132/30", BRANCH_PUBLIC, "ethernet1/1", "A C", "0"),
            ],
        },
        "ipsec_sa": {
            "ntun": "1",
            "entries": [{"name": "tun-hq", "gateway": "gw-hq", "remote": HQ_PUBLIC, "local": BRANCH_PUBLIC}],
        },
        "vpn_flow": {
            "num_ipsec": "1",
            "IPSec": [
                {
                    "name": "tun-hq",
                    "id": "1",
                    "state": "active",
                    "mon": "up",
                    "inner-if": "tunnel.1",
                    "outer-if": "ethernet1/1",
                    "localip": BRANCH_PUBLIC,
                    "peerip": HQ_PUBLIC,
                }
            ],
        },
        "ha": {"enabled": "no"},
        "bgp_peers": None,
        "gp_users": None,
    }


def _aws_state() -> dict[str, Any]:
    return {
        "interfaces": {
            "ifnet": [
                _ifnet("ethernet1/1", "untrust", "10.210.0.13/24"),
                _ifnet("ethernet1/2", "trust", "10.210.1.13/24"),
            ],
            "hw": [_hw("ethernet1/1", "up", "0a:1b:2c:00:00:13"), _hw("ethernet1/2", "up", "0a:1b:2c:00:01:13")],
        },
        "routes": {
            "flags": _FLAGS,
            "entry": [
                _route("0.0.0.0/0", "10.210.0.1", "ethernet1/1", "A S"),
                _route("10.0.0.0/8", "10.210.1.1", "ethernet1/2", "A S"),
                _route("10.210.0.0/24", "10.210.0.13", "ethernet1/1", "A C", "0"),
                _route("10.210.1.0/24", "10.210.1.13", "ethernet1/2", "A C", "0"),
            ],
        },
        "ipsec_sa": None,
        "vpn_flow": {"num_ipsec": "0"},
        "ha": {"enabled": "no"},
        "bgp_peers": None,
        "gp_users": None,
    }


def build_sample_raw() -> dict[str, Any]:
    """A fresh copy of the demo Panorama's raw payloads."""
    devices = [
        _device(HQ_1, "hq-fw-01", "PA-5220", "10.150.254.11", "11.1.4-h7", ha_state="active", peer=HQ_2),
        _device(HQ_2, "hq-fw-02", "PA-5220", "10.150.254.12", "11.1.4-h7", ha_state="passive", peer=HQ_1),
        _device(BRANCH, "branch-fw-01", "PA-440", "10.151.254.11", "11.1.2-h3"),
        _device(AWS_VM, "aws-vm-fw-01", "PA-VM", "10.210.2.13", "11.1.4-h7", policy="Out of Sync"),
    ]
    stack_config = [
        {
            "@name": "HQ-Stack",
            "templates": ["HQ-Network", "Global-Base"],
            "devices": [{"@name": HQ_1}, {"@name": HQ_2}],
            "variable": [{"@name": "$untrust-ip", "type": {"ip-netmask": f"{HQ_PUBLIC}/28"}}],
        },
        {
            "@name": "Branch-Stack",
            "templates": ["Branch-Network", "Global-Base"],
            "devices": [{"@name": BRANCH}],
            "variable": [{"@name": "$untrust-ip", "type": {"ip-netmask": f"{BRANCH_PUBLIC}/30"}}],
        },
        {"@name": "AWS-Stack", "templates": ["AWS-Network", "Global-Base"], "devices": [{"@name": AWS_VM}]},
    ]
    return {
        "panorama": {
            "url": "https://10.210.2.30",
            "name": "",
            "hostname": "panorama-01",
            "version": "11.1.4-h7",
            "model": "Panorama",
            "serial": "000710000301",
            "ip": "10.210.2.30",
            "device_group": "",
        },
        "timestamp": "2026-10-09T08:30:00+00:00",
        "devices": devices,
        "on_map": [HQ_1, HQ_2, BRANCH, AWS_VM],
        "device_groups": [
            {
                "@name": "Corporate",
                "devices": [_member(HQ_1, "hq-fw-01"), _member(HQ_2, "hq-fw-02"), _member(AWS_VM, "aws-vm-fw-01")],
            },
            {"@name": "Branches", "devices": [_member(BRANCH, "branch-fw-01")]},
        ],
        "dg_parents": {"Corporate": "", "Branches": "Corporate"},
        "templates": [
            {"@name": "Global-Base", "description": "Management profiles shared by every firewall"},
            {"@name": "HQ-Network"},
            {"@name": "Branch-Network"},
            {"@name": "AWS-Network"},
        ],
        "template_stacks": [
            {"@name": s["@name"], "templates": list(s["templates"]), "devices": [dict(d) for d in s["devices"]]}
            for s in stack_config
        ],
        "stack_config": stack_config,
        "objects": _objects(),
        "security_rules": _security_rules(),
        "default_rules": {
            "shared": [
                {"@name": "intrazone-default", "action": "allow"},
                {"@name": "interzone-default", "action": "deny", "log-end": "yes"},
            ],
            "Corporate": [],
            "Branches": [],
        },
        "nat_rules": _nat_rules(),
        "template_config": _template_config(),
        "state": {
            HQ_1: _hq_state(active=True),
            HQ_2: _hq_state(active=False),
            BRANCH: _branch_state(),
            AWS_VM: _aws_state(),
        },
        "state_skipped": {},
        "errors": [],
        "unsupported": [],
        "stats": {"requests": 0, "retries": 0, "rate_limited": 0},
        "options": {**DEFAULT_OPTIONS, "username": "plexus-readonly"},
    }
