"""Bundled demo Appgate SDP collective, in the shape ``collector.collect_appgate`` returns.

Lets the Appgate part of the map be previewed (and tested) without
credentials. All addresses are private or documentation ranges that no
other sample uses: the sites are 10.160.0.0/16 and 10.161.0.0/16, the
client pool 10.253.0.0/22, and the users connect from 198.51.100.160/28 and
203.0.113.160/28.
"""

from __future__ import annotations

import copy
from typing import Any

from netcontrol.integrations.appgate.collector import DEFAULT_OPTIONS

HQ_SITE = "6f1c2a50-0001-4c1e-9a10-000000000001"
AWS_SITE = "6f1c2a50-0002-4c1e-9a10-000000000002"
LAB_SITE = "6f1c2a50-0003-4c1e-9a10-000000000003"

CTRL_1 = "a7d30000-0001-4b2e-8c00-000000000001"
CTRL_2 = "a7d30000-0002-4b2e-8c00-000000000002"
GW_HQ_1 = "a7d30000-0003-4b2e-8c00-000000000003"
GW_HQ_2 = "a7d30000-0004-4b2e-8c00-000000000004"
GW_AWS_1 = "a7d30000-0005-4b2e-8c00-000000000005"
PORTAL_1 = "a7d30000-0006-4b2e-8c00-000000000006"
GW_LAB_1 = "a7d30000-0007-4b2e-8c00-000000000007"
CONNECTOR_1 = "a7d30000-0008-4b2e-8c00-000000000008"

POOL_V4 = "b1e00000-0001-4f00-9000-000000000001"
IDP_LOCAL = "c2f00000-0001-4f00-9000-000000000001"
IDP_OKTA = "c2f00000-0002-4f00-9000-000000000002"

COND_ADMIN = "d3a00000-0001-4f00-9000-000000000001"
COND_HOURS = "d3a00000-0002-4f00-9000-000000000002"

ENT_HQ_WEB = "e4b00000-0001-4f00-9000-000000000001"
ENT_HQ_SSH = "e4b00000-0002-4f00-9000-000000000002"
ENT_HQ_TELNET = "e4b00000-0003-4f00-9000-000000000003"
ENT_INTRANET = "e4b00000-0004-4f00-9000-000000000004"
ENT_AWS_APP = "e4b00000-0005-4f00-9000-000000000005"
ENT_LAB_ALL = "e4b00000-0006-4f00-9000-000000000006"

RINGFENCE_PRINTERS = "f5c00000-0001-4f00-9000-000000000001"

DANA_DEVICE = "0d4a0000-0001-4a00-8000-00000000da0a"
SAM_DEVICE = "0d4a0000-0002-4a00-8000-00000000005a"
PRIYA_DEVICE = "0d4a0000-0003-4a00-8000-00000000091a"
SCANNER_DEVICE = "0d4a0000-0004-4a00-8000-0000000005ca"

PEER_VERSION = 22
APPLIANCE_VERSION = "6.4.2-37201-release"


def _nic(name: str, address: str = "", netmask: int = 24, *, dhcp: bool = False, snat: bool = False) -> dict:
    return {
        "name": name,
        "enabled": True,
        "mtu": 1500,
        "ipv4": {
            "dhcp": {"enabled": dhcp, "dns": True, "routers": True, "ntp": False},
            "static": [{"address": address, "netmask": netmask, "snat": snat}] if address else [],
        },
        "ipv6": {"dhcp": {"enabled": False}, "static": []},
    }


def _appliance(
    ident: str,
    name: str,
    site: str,
    site_name: str,
    nics: list[dict],
    *,
    roles: tuple[str, ...],
    hostname: str,
    routes: list[dict] | None = None,
    suspended: bool = False,
    weight: int = 100,
    connector: dict | None = None,
) -> dict:
    appliance: dict[str, Any] = {
        "id": ident,
        "name": name,
        "notes": "",
        "tags": ["plexus-demo"],
        "hostname": hostname,
        "hostnameAliases": [],
        "site": site,
        "siteName": site_name,
        "activated": True,
        "pendingCertificateRenewal": False,
        "version": PEER_VERSION,
        "clientInterface": {
            "hostname": hostname,
            "httpsPort": 443,
            "dtlsPort": 443,
            "proxyProtocol": False,
            "allowSources": [{"address": "0.0.0.0", "netmask": 0}],
        },
        "adminInterface": {"hostname": hostname, "httpsPort": 8443} if "controller" in roles else None,
        "networking": {
            "hosts": [],
            "nics": nics,
            "dnsServers": ["10.160.1.53"],
            "dnsDomains": ["acme.example"],
            "routes": routes or [],
        },
        "controller": {"enabled": "controller" in roles},
        "gateway": {
            "enabled": "gateway" in roles,
            "suspended": suspended,
            "vpn": {"weight": weight, "localWeight": 0, "allowDestinations": []},
        },
        "logServer": {"enabled": "logServer" in roles, "retentionDays": 30},
        "logForwarder": {"enabled": False},
        "connector": connector or {"enabled": False},
        "portal": {"enabled": "portal" in roles},
        "metricsAggregator": {"enabled": False},
        "connectionBroker": {"enabled": False},
    }
    if appliance["adminInterface"] is None:
        del appliance["adminInterface"]
    return appliance


def _status(
    ident: str,
    name: str,
    site_name: str,
    status: str,
    *,
    sessions: int = 0,
    roles: dict[str, Any],
    ips: dict[str, list[str]],
    cpu: float = 8.0,
    memory: float = 31.0,
    disk: float = 22.0,
) -> dict:
    return {
        "id": ident,
        "name": name,
        "siteName": site_name,
        "online": status != "offline",
        "status": status,
        "applianceVersion": APPLIANCE_VERSION,
        "numberOfSessions": sessions,
        "cpu": cpu,
        "memory": memory,
        "disk": disk,
        "roles": roles,
        "upgrade": {"status": "idle"},
        "details": {
            "version": APPLIANCE_VERSION,
            "network": {
                "busiestNic": next(iter(ips), ""),
                "details": {
                    nic: {"ips": addresses, "status": "offline" if status == "offline" else "healthy"}
                    for nic, addresses in ips.items()
                },
            },
        },
    }


def _gateway_role(status: str, sessions: int, details: str = "") -> dict:
    return {
        "status": status,
        "details": details,
        "numberOfSessions": sessions,
        "sessionCounts": {"direct": sessions, "directViaNat": 0, "relayed": 0},
    }


def _firewall_rule(name: str, protocol: str, direction: str, subnets: list[str], ports: list[str]) -> dict:
    return {
        "name": name,
        "protocol": protocol,
        "direction": direction,
        "action": "allow",
        "subnets": subnets,
        "ports": ports,
        "types": ["0-255"] if protocol == "icmp" else [],
        "urls": [],
    }


_HQ_WEB_RULES = [
    _firewall_rule("HQ web servers", "tcp", "up", ["10.160.10.0/24"], ["443"]),
    _firewall_rule("HQ web servers", "icmp", "up", ["10.160.10.0/24"], []),
]
_HQ_SSH_RULES = [_firewall_rule("HQ admin SSH", "tcp", "up", ["10.160.10.0/24"], ["22"])]
_AWS_RULES = [
    _firewall_rule("AWS app tier", "tcp", "up", ["10.161.20.0/24"], ["8443", "443"]),
    _firewall_rule("AWS app tier", "tcp", "down", ["10.161.20.0/24"], ["443"]),
]


def _info(access: bool, **conditions: bool) -> dict:
    return {
        "access": access,
        "conditionLogic": "and",
        "conditionResults": {name.replace("_", " "): result for name, result in conditions.items()},
    }


def _gateway_session(
    site: str,
    tun_ip: str,
    public_ip: str,
    *,
    username: str,
    groups: list[str],
    os: str,
    connected: str,
    policies: list[str],
    infos: dict[str, dict],
    rules: list[dict],
) -> dict:
    return {
        "site": site,
        "primarySite": "HQ Data Center",
        "policyNames": policies,
        "userClaims": {"username": username, "groups": groups},
        "deviceClaims": {"os": {"family": os}},
        "systemClaims": {"tunIPv4": tun_ip, "clientSrcIP": public_ip, "connectTime": connected},
        "entitlementInfos": infos,
        "firewallRules": copy.deepcopy(rules),
        "vpn": {},
    }


def _dn(device: str, username: str, provider: str) -> str:
    return f"CN={device},CN={username},OU={provider}"


def _session(device: str, username: str, provider: str, hostname: str, os_family: str, os_name: str, **more) -> dict:
    return {
        "distinguishedName": _dn(device, username, provider),
        "deviceId": device,
        "username": username,
        "providerName": provider,
        "hostname": hostname,
        "osFamily": os_family,
        "osName": os_name,
        "clientVersion": "6.4.2",
        "clientType": "Desktop",
        "clientSupport": "Supported",
        **more,
    }


def build_sample_raw() -> dict[str, Any]:
    """A raw collection of a three-site collective: an HQ data center with two
    Controllers, two Gateways, a Portal and a Connector; an AWS site with one
    Gateway; a lab whose only Gateway is suspended. Four users are connected."""
    appliances = [
        _appliance(
            CTRL_1,
            "appgate-ctrl-1",
            HQ_SITE,
            "HQ Data Center",
            [_nic("eth0", "10.160.1.10")],
            roles=("controller", "logServer"),
            hostname="ctrl.acme.example",
            routes=[{"address": "0.0.0.0", "netmask": 0, "gateway": "10.160.1.1", "nic": "eth0"}],
        ),
        _appliance(
            CTRL_2,
            "appgate-ctrl-2",
            HQ_SITE,
            "HQ Data Center",
            [_nic("eth0", "10.160.1.11")],
            roles=("controller",),
            hostname="ctrl2.acme.example",
            routes=[{"address": "0.0.0.0", "netmask": 0, "gateway": "10.160.1.1", "nic": "eth0"}],
        ),
        _appliance(
            GW_HQ_1,
            "appgate-gw-hq-1",
            HQ_SITE,
            "HQ Data Center",
            [_nic("eth0", "10.160.1.21"), _nic("eth1", "10.160.10.21")],
            roles=("gateway",),
            hostname="gw-hq-1.acme.example",
            routes=[
                {"address": "0.0.0.0", "netmask": 0, "gateway": "10.160.1.1", "nic": "eth0"},
                {"address": "10.160.20.0", "netmask": 24, "gateway": "10.160.1.1", "nic": "eth0"},
            ],
        ),
        _appliance(
            GW_HQ_2,
            "appgate-gw-hq-2",
            HQ_SITE,
            "HQ Data Center",
            [_nic("eth0", "10.160.1.22")],
            roles=("gateway",),
            hostname="gw-hq-2.acme.example",
            routes=[{"address": "0.0.0.0", "netmask": 0, "gateway": "10.160.1.1", "nic": "eth0"}],
        ),
        _appliance(
            GW_AWS_1,
            "appgate-gw-aws-1",
            AWS_SITE,
            "AWS us-east-1",
            [_nic("eth0", "10.161.0.21")],
            roles=("gateway",),
            hostname="gw-aws-1.acme.example",
            routes=[{"address": "0.0.0.0", "netmask": 0, "gateway": "10.161.0.1", "nic": "eth0"}],
        ),
        _appliance(
            PORTAL_1,
            "appgate-portal-1",
            HQ_SITE,
            "HQ Data Center",
            [_nic("eth0", "10.160.1.30")],
            roles=("portal",),
            hostname="portal.acme.example",
        ),
        _appliance(
            GW_LAB_1,
            "appgate-gw-lab-1",
            LAB_SITE,
            "Branch Lab",
            [_nic("eth0", dhcp=True)],
            roles=("gateway",),
            hostname="gw-lab-1.acme.example",
            suspended=True,
        ),
        _appliance(
            CONNECTOR_1,
            "appgate-connector-1",
            HQ_SITE,
            "HQ Data Center",
            [_nic("eth0", "10.160.1.40")],
            roles=("connector",),
            hostname="connector.acme.example",
            connector={
                "enabled": True,
                "expressClients": [
                    {
                        "name": "Printer fleet",
                        "deviceId": "0d4a0000-0009-4a00-8000-0000000009f1",
                        "allowResources": [{"address": "10.160.30.0", "netmask": 24}],
                        "snatToResources": True,
                        "dnatToResource": False,
                    }
                ],
                "advancedClients": [],
            },
        ),
    ]
    appliance_status = [
        _status(
            CTRL_1,
            "appgate-ctrl-1",
            "HQ Data Center",
            "healthy",
            roles={
                "controller": {"status": "healthy", "details": "", "maintenanceMode": False},
                "logServer": {"status": "healthy", "details": ""},
            },
            ips={"eth0": ["10.160.1.10"]},
        ),
        _status(
            CTRL_2,
            "appgate-ctrl-2",
            "HQ Data Center",
            "healthy",
            roles={"controller": {"status": "healthy", "details": "", "maintenanceMode": False}},
            ips={"eth0": ["10.160.1.11"]},
        ),
        _status(
            GW_HQ_1,
            "appgate-gw-hq-1",
            "HQ Data Center",
            "healthy",
            sessions=3,
            roles={"gateway": _gateway_role("healthy", 3)},
            ips={"eth0": ["10.160.1.21"], "eth1": ["10.160.10.21"]},
            cpu=21.0,
        ),
        _status(
            GW_HQ_2,
            "appgate-gw-hq-2",
            "HQ Data Center",
            "warning",
            sessions=1,
            roles={"gateway": _gateway_role("warning", 1, "Memory usage above 85%")},
            ips={"eth0": ["10.160.1.22"]},
            memory=88.0,
        ),
        _status(
            GW_AWS_1,
            "appgate-gw-aws-1",
            "AWS us-east-1",
            "healthy",
            sessions=2,
            roles={"gateway": _gateway_role("healthy", 2)},
            ips={"eth0": ["10.161.0.21"]},
        ),
        _status(
            PORTAL_1,
            "appgate-portal-1",
            "HQ Data Center",
            "healthy",
            roles={"portal": {"status": "healthy", "details": ""}},
            ips={"eth0": ["10.160.1.30"]},
        ),
        _status(
            GW_LAB_1,
            "appgate-gw-lab-1",
            "Branch Lab",
            "offline",
            roles={"gateway": _gateway_role("offline", 0, "Appliance is not reachable")},
            ips={"eth0": []},
        ),
        _status(
            CONNECTOR_1,
            "appgate-connector-1",
            "HQ Data Center",
            "healthy",
            roles={"connector": {"status": "healthy", "details": ""}},
            ips={"eth0": ["10.160.1.40"]},
        ),
    ]
    sites = [
        {
            "id": HQ_SITE,
            "name": "HQ Data Center",
            "shortName": "hq",
            "notes": "Primary data center",
            "tags": ["datacenter"],
            "networkSubnets": ["10.160.10.0/24 # servers", "10.160.20.0/24 # users"],
            "entitlementBasedRouting": True,
            "defaultGateway": {"enabledV4": False, "enabledV6": False, "excludedSubnets": []},
            "ipPoolMappings": [],
            "vpn": {"snat": True, "routeVia": {}, "tls": {"enabled": True}, "quic": {"enabled": False}},
            "nameResolution": {
                "dnsResolvers": [
                    {
                        "name": "Corporate DNS",
                        "updateInterval": 13,
                        "servers": ["10.160.1.53"],
                        "matchDomains": ["acme.example"],
                    }
                ],
                "awsResolvers": [],
                "azureResolvers": [],
                "gcpResolvers": [],
            },
            "dnsForwarding": {"siteIpv4": "10.160.1.20", "dnsServers": ["10.160.1.53"]},
            "fallbackSite": None,
            "localSiteDetection": {"enabled": False, "publicIps": []},
        },
        {
            "id": AWS_SITE,
            "name": "AWS us-east-1",
            "notes": "",
            "tags": ["aws"],
            "networkSubnets": ["10.161.0.0/16"],
            "entitlementBasedRouting": True,
            "defaultGateway": {"enabledV4": False, "enabledV6": False, "excludedSubnets": []},
            "ipPoolMappings": [],
            "vpn": {"snat": False, "routeVia": {"ipv4": "10.161.0.5"}},
            "nameResolution": {
                "dnsResolvers": [],
                "awsResolvers": [
                    {
                        "name": "us-east-1 VPCs",
                        "regions": ["us-east-1"],
                        "updateInterval": 60,
                        "vpcs": ["vpc-0a161b00c0ffee001"],
                        "useIAMRole": True,
                    }
                ],
                "azureResolvers": [],
                "gcpResolvers": [],
            },
            "fallbackSite": HQ_SITE,
        },
        {
            "id": LAB_SITE,
            "name": "Branch Lab",
            "notes": "",
            "tags": [],
            "networkSubnets": ["10.160.200.0/24 # lab"],
            "entitlementBasedRouting": False,
            "defaultGateway": {"enabledV4": False, "enabledV6": False, "excludedSubnets": []},
            "ipPoolMappings": [],
            "vpn": {"snat": True, "routeVia": {}},
            "nameResolution": {"dnsResolvers": [], "awsResolvers": [], "azureResolvers": [], "gcpResolvers": []},
            "fallbackSite": None,
        },
    ]
    site_status = [
        {"id": HQ_SITE, "name": "HQ Data Center", "status": "healthy", "sessionCounts": {"total": 4}},
        {"id": AWS_SITE, "name": "AWS us-east-1", "status": "healthy", "sessionCounts": {"total": 2}},
        {"id": LAB_SITE, "name": "Branch Lab", "status": "noActiveGateways", "sessionCounts": {"total": 0}},
    ]
    conditions = [
        {
            "id": COND_ADMIN,
            "name": "Admin group",
            "expression": 'return claims.user.groups && claims.user.groups.indexOf("admins") > -1;',
            "repeatSchedules": [],
            "remedyLogic": "and",
            "remedyMethods": [],
        },
        {
            "id": COND_HOURS,
            "name": "Business hours",
            "expression": "var h = new Date().getHours(); return h >= 7 && h < 19;",
            "repeatSchedules": ["1h"],
            "remedyLogic": "and",
            "remedyMethods": [{"type": "DisplayMessage", "message": "Outside business hours"}],
        },
    ]

    def entitlement(ident: str, name: str, site: str, site_name: str, actions: list[dict], **more) -> dict:
        return {
            "id": ident,
            "name": name,
            "notes": "",
            "tags": [],
            "disabled": False,
            "site": site,
            "siteName": site_name,
            "conditionLogic": "and",
            "conditions": [],
            "actions": actions,
            "appShortcuts": [],
            **more,
        }

    def action(subtype: str, hosts: list[str], ports: list[str] | None = None, verdict: str = "allow") -> dict:
        found: dict[str, Any] = {"subtype": subtype, "action": verdict, "hosts": hosts}
        if subtype.startswith("icmp"):
            found["types"] = ["0-255"]
        else:
            found["ports"] = ports or []
        return found

    entitlements = [
        entitlement(
            ENT_HQ_WEB,
            "HQ web servers",
            HQ_SITE,
            "HQ Data Center",
            [action("tcp_up", ["10.160.10.0/24"], ["443"]), action("icmp_up", ["10.160.10.0/24"])],
        ),
        entitlement(
            ENT_HQ_SSH,
            "HQ admin SSH",
            HQ_SITE,
            "HQ Data Center",
            [action("tcp_up", ["10.160.10.0/24"], ["22"])],
            conditions=[COND_ADMIN],
        ),
        entitlement(
            ENT_HQ_TELNET,
            "HQ legacy telnet",
            HQ_SITE,
            "HQ Data Center",
            [action("tcp_up", ["10.160.10.0/24"], ["23"], "block")],
        ),
        entitlement(
            ENT_INTRANET,
            "Intranet by name",
            HQ_SITE,
            "HQ Data Center",
            [action("tcp_up", ["dns://intranet.acme.example"], ["443"])],
        ),
        entitlement(
            ENT_AWS_APP,
            "AWS app tier",
            AWS_SITE,
            "AWS us-east-1",
            [
                action("tcp_up", ["10.161.20.0/24"], ["8443"]),
                action("tcp_up", ["10.161.20.0/24"], ["443"]),
                action("tcp_down", ["10.161.20.0/24"], ["443"]),
            ],
            conditions=[COND_HOURS],
        ),
        entitlement(
            ENT_LAB_ALL,
            "Lab everything",
            LAB_SITE,
            "Branch Lab",
            [action("tcp_up", ["0.0.0.0/0"], ["1-65535"])],
            disabled=True,
        ),
    ]
    ringfence_rules = [
        {
            "id": RINGFENCE_PRINTERS,
            "name": "Block local printers",
            "notes": "",
            "tags": [],
            "actions": [
                {
                    "protocol": "tcp",
                    "direction": "down",
                    "action": "block",
                    "hosts": ["0.0.0.0/0"],
                    "ports": ["9100"],
                    "types": [],
                }
            ],
        }
    ]

    def policy(ident: str, name: str, kind: str, expression: str, granted: list[str], **more) -> dict:
        return {
            "id": ident,
            "name": name,
            "notes": "",
            "tags": [],
            "disabled": False,
            "type": kind,
            "expression": expression,
            "entitlements": granted,
            "entitlementLinks": [],
            "ringfenceRules": [],
            "ringfenceRuleLinks": [],
            "overrideSite": None,
            "applyFallbackSite": False,
            **more,
        }

    policies = [
        policy(
            "a0000000-0001-4000-8000-0000000000e1",
            "Employees",
            "Access",
            'return claims.user.groups.includes("employees");',
            [ENT_HQ_WEB, ENT_INTRANET, ENT_AWS_APP],
            ringfenceRules=[RINGFENCE_PRINTERS],
        ),
        policy(
            "a0000000-0002-4000-8000-0000000000e2",
            "Admins",
            "Access",
            'return claims.user.groups.includes("admins");',
            [ENT_HQ_SSH, ENT_HQ_TELNET],
        ),
        policy(
            "a0000000-0003-4000-8000-0000000000e3",
            "Device posture",
            "Device",
            "return claims.device.os.family !== undefined;",
            [],
        ),
        policy(
            "a0000000-0004-4000-8000-0000000000e4",
            "Lab testers",
            "Access",
            'return claims.user.groups.includes("lab");',
            [ENT_LAB_ALL],
            disabled=True,
            overrideSite=LAB_SITE,
        ),
    ]
    identity_providers = [
        {
            "id": IDP_LOCAL,
            "name": "local",
            "type": "LocalDatabase",
            "adminProvider": True,
            "ipPoolV4": POOL_V4,
            "ipPoolV6": None,
            "inactivityTimeoutMinutes": 0,
            "deviceLimitPerUser": 100,
        },
        {
            "id": IDP_OKTA,
            "name": "Okta SAML",
            "type": "Saml",
            "adminProvider": False,
            "ipPoolV4": POOL_V4,
            "ipPoolV6": None,
            "inactivityTimeoutMinutes": 60,
            "deviceLimitPerUser": 3,
            "redirectUrl": "https://acme.okta.example/app/appgate/sso/saml",
            "issuer": "http://www.okta.com/exk-acme",
        },
    ]
    ip_pools = [
        {
            "id": POOL_V4,
            "name": "Client pool v4",
            "ipVersion6": False,
            "ranges": [{"first": "10.253.0.1", "last": "10.253.3.254"}],
            "excludedRanges": [],
            "leaseTimeDays": 30,
            "total": 1022,
            "currentlyUsed": 4,
            "reserved": 0,
        }
    ]
    sessions = [
        _session(
            DANA_DEVICE,
            "dana.reyes",
            "Okta SAML",
            "DANA-LT14",
            "Windows",
            "Windows 11 Enterprise",
            geoIpLatitude=40.71,
            geoIpLongitude=-74.0,
        ),
        _session(SAM_DEVICE, "sam.okafor", "Okta SAML", "sam-mbp", "macOS", "macOS 15.6"),
        _session(PRIYA_DEVICE, "priya.nair", "Okta SAML", "PRIYA-DT02", "Windows", "Windows 11 Pro"),
        _session(SCANNER_DEVICE, "svc-scanner", "local", "scanner-01", "Linux", "Ubuntu 24.04"),
    ]
    employees = ["Employees", "Device posture"]
    session_details = {
        _dn(DANA_DEVICE, "dana.reyes", "Okta SAML"): {
            "deviceId": DANA_DEVICE,
            "username": "dana.reyes",
            "providerName": "Okta SAML",
            "data": {
                "appgate-gw-hq-1": _gateway_session(
                    "HQ Data Center",
                    "10.253.0.11",
                    "198.51.100.161",
                    username="dana.reyes",
                    groups=["employees"],
                    os="Windows",
                    connected="2026-10-01T07:45:12Z",
                    policies=employees,
                    infos={
                        "HQ web servers": _info(True),
                        "Intranet by name": _info(True),
                        "HQ admin SSH": _info(False, Admin_group=False),
                    },
                    rules=_HQ_WEB_RULES,
                ),
                "appgate-gw-aws-1": _gateway_session(
                    "AWS us-east-1",
                    "10.253.0.11",
                    "198.51.100.161",
                    username="dana.reyes",
                    groups=["employees"],
                    os="Windows",
                    connected="2026-10-01T07:45:14Z",
                    policies=employees,
                    infos={"AWS app tier": _info(True, Business_hours=True)},
                    rules=_AWS_RULES,
                ),
            },
        },
        _dn(SAM_DEVICE, "sam.okafor", "Okta SAML"): {
            "deviceId": SAM_DEVICE,
            "username": "sam.okafor",
            "providerName": "Okta SAML",
            "data": {
                "appgate-gw-hq-1": _gateway_session(
                    "HQ Data Center",
                    "10.253.0.12",
                    "198.51.100.162",
                    username="sam.okafor",
                    groups=["admins", "employees"],
                    os="macOS",
                    connected="2026-10-01T08:02:40Z",
                    policies=["Admins", *employees],
                    infos={
                        "HQ web servers": _info(True),
                        "Intranet by name": _info(True),
                        "HQ admin SSH": _info(True, Admin_group=True),
                        "HQ legacy telnet": _info(True),
                    },
                    rules=_HQ_WEB_RULES + _HQ_SSH_RULES,
                ),
            },
        },
        _dn(PRIYA_DEVICE, "priya.nair", "Okta SAML"): {
            "deviceId": PRIYA_DEVICE,
            "username": "priya.nair",
            "providerName": "Okta SAML",
            "data": {
                "appgate-gw-hq-2": _gateway_session(
                    "HQ Data Center",
                    "10.253.0.13",
                    "198.51.100.163",
                    username="priya.nair",
                    groups=["employees"],
                    os="Windows",
                    connected="2026-10-01T08:30:05Z",
                    policies=employees,
                    infos={"HQ web servers": _info(True), "Intranet by name": _info(True)},
                    rules=_HQ_WEB_RULES,
                ),
            },
        },
        _dn(SCANNER_DEVICE, "svc-scanner", "local"): {
            "deviceId": SCANNER_DEVICE,
            "username": "svc-scanner",
            "providerName": "local",
            "data": {
                "appgate-gw-aws-1": _gateway_session(
                    "AWS us-east-1",
                    "10.253.0.14",
                    "203.0.113.161",
                    username="svc-scanner",
                    groups=["scanners"],
                    os="Linux",
                    connected="2026-09-30T22:00:00Z",
                    policies=["Employees"],
                    infos={"AWS app tier": _info(True, Business_hours=True)},
                    rules=_AWS_RULES,
                ),
            },
        },
    }
    return {
        "collective": {
            "name": "Acme Appgate",
            "collective_name": "Acme Appgate",
            "collective_id": "0c011ec7-0001-4000-8000-00000000acde",
            "peer_version": PEER_VERSION,
            "controller": "10.160.1.10:8443",
        },
        "timestamp": "2026-10-01T09:30:00+00:00",
        "appliances": appliances,
        "appliance_status": appliance_status,
        "sites": sites,
        "site_status": site_status,
        "policies": policies,
        "entitlements": entitlements,
        "conditions": conditions,
        "ringfence_rules": ringfence_rules,
        "identity_providers": identity_providers,
        "ip_pools": ip_pools,
        "sessions": sessions,
        "sessions_source": "active-sessions",
        "session_details": session_details,
        "sessions_skipped": 0,
        "license": {"type": "Production", "users": 500, "portalUsers": 50, "sites": 10, "expiration": "2027-06-30"},
        "global_settings": {
            "collectiveName": "Acme Appgate",
            "collectiveId": "0c011ec7-0001-4000-8000-00000000acde",
            "inactivityTimeoutMinutes": 60,
            "spaMode": "TCP",
        },
        "errors": [],
        "stats": {"requests": 31, "retries": 0, "rate_limited": 0, "logins": 1},
        "options": dict(DEFAULT_OPTIONS),
    }
