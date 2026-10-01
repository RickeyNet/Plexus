"""Bundled demo Cato account, in the shape ``collector.collect_account`` returns.

Lets the Cato part of the map be previewed (and tested) without an API key.
All addresses are documentation / private ranges.
"""

from __future__ import annotations

from typing import Any

from netcontrol.integrations.cato.collector import DEFAULT_OPTIONS


def _iface(ident: str, name: str, *, pop: str, ip: str, provider: str, role: str, up: int, down: int) -> dict:
    return {
        "id": ident,
        "name": name,
        "connected": bool(pop),
        "physicalPort": int(ident) if ident.isdigit() else None,
        "popName": pop or None,
        "tunnelUptime": 864000 if pop else None,
        "tunnelRemoteIP": ip or None,
        "type": "WAN",
        "tunnelRemoteIPInfo": {"ip": ip, "countryName": "United States", "city": "", "provider": provider},
        "info": {
            "id": ident,
            "name": name,
            "upBandwidth": up,
            "downBandwidth": down,
            "destType": "CATO",
            "wanRole": role,
        },
    }


def _socket(
    ident: str,
    name: str,
    serial: str,
    platform: str,
    *,
    connected: bool = True,
    role: str = "",
    primary: bool = True,
    pop: str = "",
    wans: list[dict] | None = None,
) -> dict:
    return {
        "id": ident,
        "name": name,
        "identifier": serial,
        "connected": connected,
        "haRole": role or None,
        "type": "SOCKET",
        "lastConnected": "2026-09-30T14:02:11Z",
        "connectedSince": "2026-09-20T03:15:00Z" if connected else None,
        "lastPopName": pop or None,
        "internalIP": None,
        "version": "22.0.19221",
        "osType": None,
        "osVersion": None,
        "socketInfo": {
            "id": ident,
            "serial": serial,
            "isPrimary": primary,
            "platform": platform,
            "version": "22.0.19221",
        },
        "interfaces": wans or [],
    }


def _site(
    ident: str,
    name: str,
    *,
    status: str = "connected",
    pop: str | None,
    city: str,
    conn_type: str = "SOCKET_X1500",
    is_ha: bool = False,
    devices: list[dict] | None = None,
    ipsec: dict | None = None,
    hosts: int = 0,
) -> dict:
    return {
        "id": ident,
        "connectivityStatus": status,
        "operationalStatus": "active",
        "lastConnected": "2026-09-30T14:02:11Z",
        "connectedSince": "2026-09-20T03:15:00Z" if status != "disconnected" else None,
        "popName": pop,
        "hostCount": hosts,
        "haStatus": {"readiness": "ready", "wanConnectivity": "ok", "keys": "ok", "routes": "ok"} if is_ha else None,
        "info": {
            "name": name,
            "type": "BRANCH" if ident != "1001" else "DATACENTER",
            "description": "Demo site",
            "countryCode": "US",
            "countryName": "United States",
            "countryStateName": "",
            "cityName": city,
            "address": "",
            "isHA": is_ha,
            "connType": conn_type,
            "interfaces": [
                {
                    "id": "1",
                    "name": "WAN 01",
                    "upBandwidth": 500,
                    "downBandwidth": 500,
                    "destType": "CATO",
                    "wanRole": "wan_1",
                },
                {
                    "id": "2",
                    "name": "WAN 02",
                    "upBandwidth": 100,
                    "downBandwidth": 100,
                    "destType": "CATO",
                    "wanRole": "wan_2",
                },
                {
                    "id": "5",
                    "name": "LAN 01",
                    "upBandwidth": None,
                    "downBandwidth": None,
                    "destType": "LAN",
                    "wanRole": None,
                },
            ]
            if devices
            else [],
            "sockets": [d["socketInfo"] for d in devices or []],
            "ipsec": ipsec,
        },
        "devices": devices or [],
    }


def _range(site: str, interface: str, name: str, subnet: str, vlan: str = "") -> dict:
    return {
        "entity": {"id": f"r-{site}-{subnet}", "name": f"{site} \\ {interface} \\ {name}", "type": "siteRange"},
        "description": "",
        "helperFields": {"subnet": subnet, "vlanTag": vlan},
    }


def _user(ident: str, name: str, pop: str, vpn_ip: str, public_ip: str, os_type: str, *, office: bool = False) -> dict:
    return {
        "id": ident,
        "name": name,
        "connectivityStatus": "connected",
        "operationalStatus": "active",
        "deviceName": f"LT-{name.split()[0].upper()}",
        "uptime": 5400,
        "lastConnected": "2026-10-01T12:40:00Z",
        "version": "5.14.5",
        "popName": pop,
        "remoteIP": public_ip,
        "internalIP": vpn_ip,
        "osType": os_type,
        "osVersion": "",
        "connectedInOffice": office,
        "remoteIPInfo": {"countryName": "United States", "city": "", "provider": "Example ISP"},
        "info": {
            "name": name,
            "status": "active",
            "email": f"{name.lower().replace(' ', '.')}@example.com",
            "origin": "LDAP",
            "authMethod": "SSO",
        },
    }


def build_sample_raw() -> dict[str, Any]:
    """A small account: an HA data center, two Socket branches (one down), an
    IPsec site and a few remote users, across two PoPs."""
    sites = [
        _site(
            "1001",
            "HQ-DataCenter",
            pop="Ashburn",
            city="Ashburn",
            conn_type="SOCKET_X1700",
            is_ha=True,
            hosts=412,
            devices=[
                _socket(
                    "5001",
                    "HQ-DataCenter",
                    "X1700-0001-AAAA",
                    "X1700",
                    role="PRIMARY",
                    pop="Ashburn",
                    wans=[
                        _iface(
                            "1",
                            "WAN 01",
                            pop="Ashburn",
                            ip="198.51.100.10",
                            provider="Example Fiber",
                            role="wan_1",
                            up=1000,
                            down=1000,
                        ),
                        _iface(
                            "2",
                            "WAN 02",
                            pop="Ashburn",
                            ip="203.0.113.10",
                            provider="Example Cable",
                            role="wan_2",
                            up=200,
                            down=500,
                        ),
                    ],
                ),
                _socket(
                    "5002",
                    "HQ-DataCenter",
                    "X1700-0002-BBBB",
                    "X1700",
                    role="SECONDARY",
                    primary=False,
                    pop="Ashburn",
                    wans=[
                        _iface(
                            "1",
                            "WAN 01",
                            pop="Ashburn",
                            ip="198.51.100.11",
                            provider="Example Fiber",
                            role="wan_1",
                            up=1000,
                            down=1000,
                        ),
                    ],
                ),
            ],
        ),
        _site(
            "1002",
            "Branch-Cleveland",
            pop="New York",
            city="Cleveland",
            hosts=38,
            devices=[
                _socket(
                    "5003",
                    "Branch-Cleveland",
                    "X1500-0003-CCCC",
                    "X1500",
                    pop="New York",
                    wans=[
                        _iface(
                            "1",
                            "WAN 01",
                            pop="New York",
                            ip="198.51.100.30",
                            provider="Example Cable",
                            role="wan_1",
                            up=100,
                            down=500,
                        ),
                        _iface("2", "WAN 02", pop="", ip="", provider="", role="wan_2", up=50, down=50),
                    ],
                )
            ],
        ),
        _site(
            "1003",
            "Branch-Denver",
            status="disconnected",
            pop=None,
            city="Denver",
            hosts=0,
            devices=[_socket("5004", "Branch-Denver", "X1500-0004-DDDD", "X1500", connected=False)],
        ),
        _site(
            "1004",
            "AWS-us-east-1",
            pop="Ashburn",
            city="Ashburn",
            conn_type="IPSEC_V2",
            ipsec={"isPrimary": True, "catoIP": "192.0.2.80", "remoteIP": "192.0.2.90", "ikeVersion": "2"},
        ),
    ]
    ranges = [
        _range("HQ-DataCenter", "LAN 01", "Servers", "10.50.10.0/24", "10"),
        _range("HQ-DataCenter", "LAN 01", "Users", "10.50.20.0/24", "20"),
        _range("Branch-Cleveland", "LAN 01", "Users", "10.60.20.0/24", "20"),
        _range("Branch-Denver", "LAN 01", "Users", "10.61.20.0/24", "20"),
        _range("AWS-us-east-1", "IPsec", "VPC", "172.31.0.0/16"),
    ]
    interfaces = [
        {
            "entity": {"id": "i-1001-5", "name": "HQ-DataCenter \\ LAN 01", "type": "networkInterface"},
            "description": "",
            "helperFields": {
                "interfaceName": "LAN 01",
                "siteId": "1001",
                "siteName": "HQ-DataCenter",
                "subnet": "10.50.1.0/24",
            },
        },
        {
            # Already listed as a range: must not be counted twice.
            "entity": {"id": "i-1002-5", "name": "Branch-Cleveland \\ LAN 01", "type": "networkInterface"},
            "description": "",
            "helperFields": {"interfaceName": "LAN 01", "siteId": "1002", "subnet": "10.60.20.0/24"},
        },
    ]
    users = [
        _user("9001", "Dana Reyes", "New York", "10.41.0.11", "198.51.100.201", "OS_WINDOWS"),
        _user("9002", "Sam Okafor", "Ashburn", "10.41.0.12", "198.51.100.202", "OS_MAC"),
        _user("9003", "Priya Nair", "Ashburn", "10.41.0.13", "198.51.100.10", "OS_WINDOWS", office=True),
    ]
    return {
        "account": {"id": "sample", "name": "Sample Cato Account"},
        "timestamp": "2026-10-01T13:00:00Z",
        "sites": sites,
        "users": users,
        "ranges": ranges,
        "interfaces": interfaces,
        "errors": [],
        "stats": {"requests": 0, "retries": 0, "rate_limited": 0},
        "options": dict(DEFAULT_OPTIONS),
    }
