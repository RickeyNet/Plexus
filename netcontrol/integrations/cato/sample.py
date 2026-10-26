"""Bundled demo Cato account, in the shape ``collector.collect_account`` returns.

Lets the Cato part of the map be previewed (and tested) without an API key.
All addresses are documentation / private ranges.
"""

from __future__ import annotations

from typing import Any

from netcontrol.integrations.cato.collector import DEFAULT_OPTIONS
from netcontrol.integrations.cato.site_config import build_sample_site_config


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
            "upstreamBandwidth": up,
            "downstreamBandwidth": down,
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
    ipsec: list[dict] | None = None,
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
        "haStatus": {"readiness": "ready", "wanConnectivity": "ok", "keepalive": "ok", "socketVersion": "ok"}
        if is_ha
        else None,
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
                    "upstreamBandwidth": 500,
                    "downstreamBandwidth": 500,
                    "destType": "CATO",
                    "wanRole": "wan_1",
                },
                {
                    "id": "2",
                    "name": "WAN 02",
                    "upstreamBandwidth": 100,
                    "downstreamBandwidth": 100,
                    "destType": "CATO",
                    "wanRole": "wan_2",
                },
                {
                    "id": "5",
                    "name": "LAN 01",
                    "upstreamBandwidth": None,
                    "downstreamBandwidth": None,
                    "destType": "LAN",
                    "wanRole": None,
                },
            ]
            if devices
            else [],
            "sockets": [d["socketInfo"] for d in devices or []],
            "ipsec": ipsec or [],
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
        "remoteIPInfo": {
            "ip": public_ip,
            "countryCode": "US",
            "countryName": "United States",
            "city": "Helena",
            "state": "Montana",
            "provider": "Example ISP",
        },
        "info": {
            "name": name,
            "status": "active",
            "email": f"{name.lower().replace(' ', '.')}@example.com",
            "phoneNumber": "",
            "origin": "LDAP",
            "authMethod": "SSO",
        },
        "recentConnections": [
            {
                "duration": 7200,
                "interfaceName": "Wi-Fi",
                "deviceName": f"LT-{name.split()[0].upper()}",
                "lastConnected": "2026-09-30T17:05:00Z",
                "popName": pop,
                "remoteIP": public_ip,
                "remoteIPInfo": {
                    "countryName": "United States",
                    "city": "Helena",
                    "state": "Montana",
                    "provider": "Example ISP",
                },
            }
        ],
    }


def _ref(ident: str, name: str) -> dict:
    return {"id": ident, "name": name}


def _endpoint(**fields: Any) -> dict:
    """A rule's source or destination: every list the query asks for, empty
    unless given (an empty one is any address)."""
    empty = (
        "ip subnet ipRange host site siteNetworkSubnet networkInterface floatingSubnet user usersGroup group "
        "systemGroup globalIpRange"
    )
    return {**{name: [] for name in empty.split()}, **fields}


def _fw_rule(
    index: int,
    name: str,
    action: str,
    *,
    source: dict | None = None,
    destination: dict | None = None,
    custom: list[dict] | None = None,
    **fields: Any,
) -> dict:
    """A firewall rule as ``policy { ... rules { rule } }`` returns it."""
    return {
        "id": f"rule-{name.lower().replace(' ', '-')}",
        "name": name,
        "description": "",
        "index": index,
        "enabled": True,
        "action": action,
        "section": _ref("s-1", "Demo rules"),
        "source": source or _endpoint(),
        "destination": destination or _endpoint(),
        "service": {"standard": [], "custom": custom or []},
        "connectionOrigin": "ANY",
        "country": [],
        "device": [],
        "deviceOS": [],
        "schedule": {"activeOn": "ALWAYS"},
        "exceptions": [],
        **fields,
    }


def _firewalls() -> tuple[dict, dict]:
    """The WAN firewall (a whitelist) and the Internet firewall (a blacklist)."""
    wan = [
        # Both ways: neither end may open a connection to the other.
        _fw_rule(
            1,
            "Isolate Denver from servers",
            "BLOCK",
            direction="BOTH",
            source=_endpoint(site=[_ref("1003", "Branch-Denver")]),
            destination=_endpoint(subnet=["10.50.10.0/24"]),
        ),
        _fw_rule(
            2,
            "Sites to HQ servers",
            "ALLOW",
            direction="TO",
            source=_endpoint(site=[_ref("1002", "Branch-Madison"), _ref("1004", "AWS-us-east-1")]),
            destination=_endpoint(siteNetworkSubnet=[_ref("r-HQ-DataCenter-10.50.10.0/24", "Servers")]),
            custom=[{"port": ["443"], "portRange": None, "protocol": "TCP"}],
        ),
        _fw_rule(
            3,
            "Remote users to HQ",
            "ALLOW",
            direction="TO",
            source=_endpoint(usersGroup=[_ref("g-1", "VPN Users")]),
            destination=_endpoint(site=[_ref("1001", "HQ-DataCenter")]),
        ),
        _fw_rule(4, "Any to any", "ALLOW", direction="TO"),
    ]
    internet = [
        _fw_rule(
            1,
            "Block malware category",
            "BLOCK",
            destination={"appCategory": [_ref("c-12", "Malware")]},
        ),
        _fw_rule(2, "Allow all", "ALLOW"),
    ]
    return (
        {"enabled": True, "rules": wan, "reduced": False},
        {"enabled": True, "rules": internet, "reduced": False},
    )


def _split_rule(index: int, name: str, action: str, *, users: list[dict] | None = None, **fields: Any) -> dict:
    """A Split Tunnel rule as ``policy { splitTunnel { policy { rules { rule } } } }``
    returns it: every field the query asks for, empty unless given."""
    destination = {"application": [], "globalIpRange": [], "domain": [], "fqdn": [], **fields.pop("destination", {})}
    groups = fields.pop("groups", [])
    return {
        "id": f"st-{index}",
        "name": name,
        "description": "",
        "index": index,
        "enabled": True,
        "section": _ref("sts-1", "Demo split tunnel"),
        "source": {"user": users or [], "usersGroup": groups},
        "platform": [],
        "country": [],
        "action": action,
        "destination": destination,
        "sourceNetwork": {"sourceNetworkType": "ANY"},
        "coverage": "ALL",
        "dnsExclusion": {"domain": []},
        "routingPriority": "TUNNEL",
        **fields,
    }


def _split_tunnel() -> dict:
    """The Split Tunnel policy: one user with exceptions, one routing only a
    range to Cato, a group rule for a platform no sample user runs, and a
    group rule for devices off the managed networks, which the configuration
    cannot decide and Dana's Client report does."""
    rules = [
        _split_rule(
            1,
            "Sam direct to the lab",
            "ROUTE_ALL_TO_CATO_EXCEPT",
            users=[_ref("9002", "Sam Okafor")],
            destination={"globalIpRange": [_ref("gr-1", "Lab-Pool")], "domain": ["updates.example.com"]},
        ),
        _split_rule(
            2,
            "Lee corporate only",
            "ROUTE_ONLY_SELECTED",
            users=[_ref("9004", "Lee Park")],
            destination={"globalIpRange": [_ref("gr-3", "Corp-Networks")]},
        ),
        _split_rule(
            3,
            "Contractors on Linux",
            "ROUTE_ALL_TO_CATO_EXCEPT",
            groups=[_ref("g-2", "Contractors")],
            platform=["LINUX"],
            destination={"fqdn": ["repo.example.com"]},
        ),
        _split_rule(
            4,
            "Contractors away from the office",
            "ROUTE_ALL_TO_CATO_EXCEPT",
            groups=[_ref("g-2", "Contractors")],
            sourceNetwork={"sourceNetworkType": "ANY_UNMANAGED_NETWORK"},
            destination={"globalIpRange": [_ref("gr-1", "Lab-Pool")]},
        ),
    ]
    return {"enabled": True, "rules": rules, "reduced": False}


def _client_report(user: dict, split: str, at: str, *, device: str = "", office: str = "Disabled") -> dict:
    """A user device's latest Client Connectivity Policy report, as
    ``client_reports.collect_client_reports`` stores it."""
    return {
        "user_id": user["id"],
        "user_name": user["name"],
        "device_name": device or user["deviceName"],
        "os_type": user["osType"],
        "split_tunnel_configuration": split,
        "office_mode": office,
        "trusted_networks": "Enabled",
        "src_ip": user["remoteIP"],
        "pop_name": user["popName"],
        "time": at,
        "event_count": 3,
    }


def _client_reports(users: list[dict]) -> dict:
    """Dana's report decides rule 4 ("Admin Defined", the one rule of that
    mode that may apply); Lee's agrees with his rule; Priya, in an office,
    reports "Disabled"; Sam's only report is from another device."""
    dana, sam, priya, lee = users
    rows = [
        _client_report(dana, "Admin Defined", "2026-10-01T12:40:05Z"),
        _client_report(priya, "Disabled", "2026-10-01T11:58:40Z", office="Enabled"),
        _client_report(lee, "Admin Defined", "2026-10-01T09:02:11Z"),
        _client_report(sam, "Admin Defined", "2026-09-28T08:15:00Z", device="LT-SAM-OLD"),
    ]
    return {"from": "2026-09-24T13:00:00Z", "to": "2026-10-01T13:00:00Z", "rows": rows}


def _rule(index: int, name: str, **fields: Any) -> dict:
    """A rule of a policy path tracing does not evaluate: the fields every
    rule has, and ``fields``."""
    return {
        "id": f"{name.lower().replace(' ', '-')}-{index}",
        "name": name,
        "description": "",
        "index": index,
        "enabled": True,
        "section": _ref("s-9", "Demo"),
        **fields,
    }


def _policy(*rules: dict, **fields: Any) -> dict:
    return {"enabled": True, "rules": list(rules), "reduced": False, **fields}


def _users(*users: dict, groups: list[dict] | None = None) -> dict:
    return {"user": list(users), "usersGroup": groups or []}


_LEE = _ref("9004", "Lee Park")
_ENGINEERING, _ALL_STAFF = _ref("ug-3", "Engineering"), _ref("ug-4", "All Staff")
_MADISON, _BRANCHES = _ref("1002", "Branch-Madison"), _ref("g-10", "Branch sites")
_TRACKING = {
    "alert": {"enabled": False, "frequency": "HOURLY", "mailingList": [], "subscriptionGroup": [], "webhook": []},
    "event": {"enabled": True},
}
_SCHEDULE = {"activeOn": "ALWAYS", "customRecurring": None, "customTimeframe": None}


def _other_policies() -> dict[str, Any]:
    """One or two rules of every policy path tracing does not evaluate, as
    ``policy.<field>.policy`` returns them."""
    lan_source = _endpoint(vlan=[], mac=[]) | {"subnet": ["10.60.20.0/24"]}
    return {
        "anti_malware_file_hash": _policy(
            _rule(
                1,
                "Block known dropper",
                action="BLOCK",
                fileName="invoice.exe",
                sha256="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                expirationDate="2027-01-01T00:00:00Z",
            )
        ),
        "application_control": _policy(
            _rule(
                1,
                "Block file sharing uploads",
                ruleType="APPLICATION",
                applicationRule={
                    "action": "BLOCK",
                    "severity": "HIGH",
                    "source": _endpoint(country=[]),
                    "application": {"application": [], "appCategory": [_ref("c-31", "File Sharing")]},
                    "schedule": _SCHEDULE,
                    "tracking": _TRACKING,
                },
                dataRule=None,
                fileRule=None,
            ),
            attributes={"dataControlEnabled": False},
        ),
        "app_tenant_restriction": _policy(
            _rule(
                1,
                "Corporate Microsoft 365 only",
                action="INJECT_HEADERS",
                severity="MEDIUM",
                application=_ref("office365", "Microsoft 365"),
                headers=[{"name": "Restrict-Access-To-Tenants", "value": "example.com"}],
                schedule=_SCHEDULE,
                source=_endpoint(country=[]),
            )
        ),
        "client_connectivity": _policy(
            _rule(
                1,
                "Engineering on managed devices",
                action="ALLOW",
                confidenceLevel="HIGH",
                connectionOrigin=["REMOTE"],
                platform=["WINDOWS", "MACOS"],
                country=[],
                device=[_ref("dp-1", "Corporate laptop")],
                source=_users(groups=[_ENGINEERING]),
                sourceRange=[],
            ),
            _rule(
                2,
                "Block everyone else from abroad",
                action="BLOCK",
                confidenceLevel="ANY",
                connectionOrigin=["ANY"],
                platform=[],
                country=[_ref("KP", "North Korea")],
                device=[],
                source=_users(),
                sourceRange=[],
            ),
        ),
        "dynamic_ip_allocation": _policy(
            _rule(
                1,
                "Engineering pool",
                platform=[],
                country=[],
                devicePostureProfile=[],
                range={"globalIpRange": [_ref("gr-4", "SDP-Engineering")]},
                source=_users(groups=[_ENGINEERING]),
            )
        ),
        "private_access": _policy(
            _rule(
                1,
                "Staff to the intranet",
                action={"action": "ALLOW"},
                connectionOrigin=["REMOTE"],
                connectionsOriginList=[],
                platform=[],
                applications={"application": [_ref("pa-1", "Intranet")]},
                country=[],
                device=[],
                schedule=_SCHEDULE,
                source={"user": [], "usersGroup": [_ALL_STAFF], "systemGroup": []},
                tracking=_TRACKING,
            )
        ),
        "remote_port_fwd": _policy(
            _rule(
                1,
                "Camera NVR",
                forwardIcmp=False,
                internalIp="10.60.20.40",
                restrictionType="ALLOW_LIST",
                externalIp=_ref("ip-1", "203.0.113.200"),
                externalPortRange={"from": 8443, "to": 8443},
                internalPortRange={"from": 443, "to": 443},
                remoteIPs={"ip": ["198.51.100.250"], "subnet": [], "ipRange": [], "globalIpRange": []},
                tracking=_TRACKING["alert"],
            )
        ),
        "sdp_static_ip_allocation": _policy(_rule(1, "Lee fixed address", ip="10.88.0.14", source={"user": [_LEE]})),
        "site_web_proxy": _policy(
            _rule(
                1,
                "HQ explicit proxy",
                allowedDestinationProtocol="BOTH",
                fqdn="proxy.example.com",
                port=8080,
                shouldAssociateWithAllSites=False,
                associatedSite=[_ref("1001", "HQ-DataCenter")],
                authenticationConfig={"method": "NONE", "kerberosConfig": None},
                webProxyTraffic=[
                    {"rule": _rule(1, "Proxy the web", action="PROXY", destination={}, source=_endpoint())}
                ],
            )
        ),
        "socket_bypass": _policy(
            _rule(
                1,
                "Backup to the local NAS",
                action={"port": [], "event": {"enabled": False}},
                site={"site": [], "group": [_BRANCHES]},
                source=lan_source,
                destination={"ip": ["10.60.20.50"], "subnet": [], "ipRange": [], "domain": [], "fqdn": []},
                service={"custom": [{"port": ["445"], "portRange": None, "protocol": "TCP"}], "simple": []},
                exception=[],
            )
        ),
        "socket_lan": _policy(
            _rule(
                1,
                "Madison LAN to LAN",
                direction="BOTH",
                transport="LAN",
                site={"site": [_MADISON], "group": []},
                source=lan_source,
                destination=_endpoint(vlan=[]) | {"subnet": ["10.60.30.0/24"]},
                service={"custom": [], "simple": []},
                nat={"enabled": False, "natType": "DYNAMIC_PAT"},
                firewall=[
                    {
                        "ruleType": "RULE",
                        "subPolicy": None,
                        "rule": _rule(1, "Allow printing", action="ALLOW", direction="TO"),
                    }
                ],
            ),
            _rule(
                2,
                "Every site routes guest traffic",
                direction="TO",
                transport="WAN",
                site={"site": [], "group": []},
                source=_endpoint(vlan=[30]),
                destination=_endpoint(),
                service={"custom": [], "simple": []},
                nat={"enabled": True, "natType": "DYNAMIC_PAT"},
                firewall=[],
            ),
        ),
        "terminal_server": _policy(
            _rule(
                1,
                "Citrix farm",
                allowedHostIP=_ref("gr-2", "Scanners"),
                excludeTraffic=[],
            )
        ),
        "tls_inspect": _policy(
            _rule(
                1,
                "Do not inspect banking",
                action="BYPASS",
                untrustedCertificateAction="BLOCK",
                connectionOrigin="ANY",
                connectionsOriginList=[],
                platform=[],
                country=[],
                devicePostureProfile=[],
                source=_endpoint(),
                application={"appCategory": [_ref("c-7", "Financial Services")], "tlsInspectCategory": []},
            ),
            attributes={"defaultRuleAction": "INSPECT", "defaultRuleUntrustedCertificateAction": "PROMPT"},
        ),
        "wan_network": _policy(
            _rule(
                1,
                "Voice first",
                ruleType="WAN",
                routeType="OPTIMIZED",
                bandwidthPriority=_ref("bp-1", "P10"),
                source=_endpoint(),
                destination=_endpoint(site=[_ref("1001", "HQ-DataCenter")]),
                application={"application": [_ref("teams", "Microsoft Teams")], "domain": [], "fqdn": []},
                configuration={
                    "activeTcpAcceleration": True,
                    "packetLossMitigation": True,
                    "preserveSourcePort": False,
                    "allocationIp": [],
                    "backhaulingSite": [],
                    "popLocation": [],
                    "primaryTransport": {
                        "transportType": "WAN",
                        "primaryInterfaceRole": "AUTOMATIC",
                        "secondaryInterfaceRole": "AUTOMATIC",
                    },
                    "secondaryTransport": {
                        "transportType": "AUTOMATIC",
                        "primaryInterfaceRole": "AUTOMATIC",
                        "secondaryInterfaceRole": "AUTOMATIC",
                    },
                },
                exceptions=[],
            )
        ),
        "ztna_always_on": _policy(
            _rule(
                1,
                "Always on for staff",
                action="ENFORCE",
                allowFailOpen=True,
                allowUserBypass=True,
                antiTamperMode="PROTECT",
                platform=["WINDOWS"],
                bypassDuration={"time": 30, "unit": "MINUTES"},
                devicePostureProfile=[],
                source=_users(groups=[_ALL_STAFF]),
            )
        ),
    }


def _objects() -> dict[str, Any]:
    """The groups, users groups, containers and custom applications rules
    name, as the collector returns them."""
    return {
        "groups": [
            {
                "id": "g-10",
                "name": "Branch sites",
                "description": "Every branch office",
                "membersCount": 2,
                "membersCountPerType": [{"type": "SITE", "membersCount": 2}],
                "members": [
                    {"id": "1002", "name": "Branch-Madison", "type": "SITE"},
                    {"id": "1003", "name": "Branch-Denver", "type": "SITE"},
                ],
            },
            {
                "id": "g-11",
                "name": "Printers",
                "description": "",
                "membersCount": 1,
                "membersCountPerType": [{"type": "HOST", "membersCount": 1}],
                "members": [{"id": "h-1", "name": "printer-1", "type": "HOST"}],
            },
        ],
        "user_groups": [
            {
                "id": "g-2",
                "name": "Contractors",
                "description": "Outside contractors",
                "membersCount": 1,
                "importType": "MANUAL",
                "directoryId": None,
                "members": [
                    {"id": "9001", "displayName": "Dana Reyes", "email": "dana.reyes@example.com", "userId": None}
                ],
            },
            {
                "id": "ug-3",
                "name": "Engineering",
                "description": "",
                "membersCount": 2,
                "importType": "LDAP",
                "directoryId": "cn=engineering",
                "members": [
                    {"id": "9002", "displayName": "Sam Okafor", "email": "sam.okafor@example.com", "userId": None},
                    {"id": "9004", "displayName": "Lee Park", "email": "lee.park@example.com", "userId": None},
                ],
            },
            {
                # More members than the collector reads: not read.
                "id": "ug-4",
                "name": "All Staff",
                "description": "",
                "membersCount": 1250,
                "importType": "LDAP",
                "directoryId": "cn=staff",
                "members": None,
            },
        ],
        "containers": [
            {
                "__typename": "IpAddressRangeContainer",
                "id": "c-1",
                "name": "Blocked ranges",
                "description": "Threat feed",
                "size": 120,
                "syncData": None,
                "syncDataAudit": None,
                "members": None,
            },
            {
                "__typename": "FqdnContainer",
                "id": "c-2",
                "name": "Blocked domains",
                "description": "",
                "size": 40,
                "syncData": None,
                "syncDataAudit": None,
                "members": None,
            },
        ],
        "custom_applications": [
            {
                "id": "ca-1",
                "name": "Payroll portal",
                "description": "",
                "category": [_ref("c-40", "Business")],
                "criteria": [
                    {
                        "protocol": "TCP",
                        "port": [8443],
                        "portRange": [],
                        "destination": {"domain": [], "fqdn": ["payroll.example.com"], "destinationIp": None},
                    }
                ],
            }
        ],
    }


def build_sample_raw() -> dict[str, Any]:
    """A small account: an HA data center, two Socket branches (one down), an
    IPsec site and a few remote users, across two PoPs, and the account's
    WAN and Internet firewall rules, Split Tunnel policy, a rule or two of
    every other policy, and the groups, users groups, containers and custom
    applications rules name."""
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
            "Branch-Madison",
            pop="New York",
            city="Madison",
            hosts=38,
            devices=[
                _socket(
                    "5003",
                    "Branch-Madison",
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
            ipsec=[
                {"isPrimary": False, "catoIP": "192.0.2.81", "remoteIP": "192.0.2.91", "ikeVersion": "2"},
                {"isPrimary": True, "catoIP": "192.0.2.80", "remoteIP": "192.0.2.90", "ikeVersion": "2"},
            ],
        ),
    ]
    ranges = [
        _range("HQ-DataCenter", "LAN 01", "Servers", "10.50.10.0/24", "10"),
        _range("HQ-DataCenter", "LAN 01", "Users", "10.50.20.0/24", "20"),
        _range("Branch-Madison", "LAN 01", "Users", "10.60.20.0/24", "20"),
        _range("Branch-Denver", "LAN 01", "Users", "10.61.20.0/24", "20"),
        _range("AWS-us-east-1", "IPsec", "VPC", "172.21.0.0/16"),
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
            "entity": {"id": "i-1002-5", "name": "Branch-Madison \\ LAN 01", "type": "networkInterface"},
            "description": "",
            "helperFields": {"interfaceName": "LAN 01", "siteId": "1002", "subnet": "10.60.20.0/24"},
        },
    ]
    users = [
        _user("9001", "Dana Reyes", "New York", "10.88.0.11", "198.51.100.201", "OS_WINDOWS"),
        _user("9002", "Sam Okafor", "Ashburn", "10.88.0.12", "198.51.100.12", "OS_MAC"),
        _user("9003", "Priya Nair", "Ashburn", "10.88.0.13", "198.51.100.10", "OS_WINDOWS", office=True),
        _user("9004", "Lee Park", "New York", "10.88.0.14", "198.51.100.204", "OS_WINDOWS"),
    ]
    wan_firewall, internet_firewall = _firewalls()
    return {
        "account": {"id": "sample", "name": "Sample Cato Account"},
        "timestamp": "2026-10-01T13:00:00Z",
        "sites": sites,
        "users": users,
        # The latest Client Connectivity Policy report of each user device.
        "client_reports": _client_reports(users),
        "ranges": ranges,
        "interfaces": interfaces,
        # Read, and no site has a BGP peer: the routes are the ranges.
        "bgp_peers": [],
        "wan_firewall": wan_firewall,
        "internet_firewall": internet_firewall,
        "split_tunnel": _split_tunnel(),
        # The sites' configuration and the account's DHCP and DNS settings.
        "site_config": build_sample_site_config(),
        # The account's global IP range objects (Networking > IP Ranges), as
        # ``object.globalIpRangeList`` returns them.
        "global_ip_ranges": [
            {
                "id": "gr-1",
                "name": "Lab-Pool",
                "description": "Lab desktop pool",
                "ipRange": "10.77.128.0-10.77.131.255",
                "subnet": "10.77.128.0/22",
            },
            {
                "id": "gr-2",
                "name": "Scanners",
                "description": "",
                "ipRange": "10.50.10.200-10.50.10.203",
                "subnet": None,
            },
            {
                "id": "gr-3",
                "name": "Corp-Networks",
                "description": "Every private network of the company",
                "ipRange": "10.0.0.0-10.255.255.255",
                "subnet": "10.0.0.0/8",
            },
            {
                "id": "gr-4",
                "name": "SDP-Engineering",
                "description": "Remote user addresses for engineering",
                "ipRange": "10.89.0.0-10.89.0.255",
                "subnet": "10.89.0.0/24",
            },
        ],
        **_other_policies(),
        # The sub-policies of the policies that have them.
        "wan_firewall_policies": [
            {"id": "p-1", "name": "Main", "description": "", "enabled": True, "policyLevel": "MAIN"},
            {"id": "p-2", "name": "Lab", "description": "Lab sites", "enabled": False, "policyLevel": "SUB_POLICY"},
        ],
        "internet_firewall_policies": [
            {"id": "p-3", "name": "Main", "description": "", "enabled": True, "policyLevel": "MAIN"}
        ],
        "socket_lan_policies": [
            {"id": "p-4", "name": "Main", "description": "", "enabled": True, "policyLevel": "MAIN"}
        ],
        **_objects(),
        "errors": [],
        "stats": {"requests": 0, "retries": 0, "rate_limited": 0},
        "options": dict(DEFAULT_OPTIONS),
    }
