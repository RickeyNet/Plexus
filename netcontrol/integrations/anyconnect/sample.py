"""Bundled demo FMC, in the shape ``collector.collect_fmc`` returns.

Lets the AnyConnect part of the map be previewed (and tested) without an
FMC. The two headends are the FTDv instances of the demo AWS account
(``netcontrol.integrations.aws.sample``): same private addresses, so loading
both samples joins them on the map. All addresses are documentation /
private ranges.
"""

from __future__ import annotations

from typing import Any

from netcontrol.integrations.anyconnect.collector import DEFAULT_OPTIONS

DOMAIN_UUID = "e276abec-e0f2-11e3-8169-6d9ed49b625f"
POLICY_ID = "005056B3-2C2D-0ed3-0000-004294967395"
DEVICE_1 = "4b2a7f8e-0001-4f6b-9c2d-ff0000000001"
DEVICE_2 = "4b2a7f8e-0002-4f6b-9c2d-ff0000000002"
DEVICE_3 = "4b2a7f8e-0003-4f6b-9c2d-ff0000000003"
ZONE_OUTSIDE = "9e1b2c3d-0000-4a5b-8c9d-000000000011"
ZONE_INSIDE = "9e1b2c3d-0000-4a5b-8c9d-000000000012"
POOL_A = "a1b2c3d4-0000-4a5b-8c9d-00000000aa01"
POOL_B = "a1b2c3d4-0000-4a5b-8c9d-00000000aa02"
GROUP_POLICY = "c0ffee00-0000-4a5b-8c9d-000000000001"
AUTH_SERVER = "c0ffee00-0000-4a5b-8c9d-000000000002"

_MODEL_AWS = "Cisco Secure Firewall Threat Defense for AWS"


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
        "accessPolicy": {"id": "acp-0001", "name": "Corp-ACP", "type": "AccessPolicy"},
        "metadata": {
            "readOnly": {"state": False},
            "deviceSerialNumber": serial,
            "domain": {"id": DOMAIN_UUID, "name": "Global", "type": "Domain"},
            "snortVersion": "3.1.53.100-1",
            "vdbVersion": "381",
            "inventoryData": {"cpuCores": "4", "cpuType": "Intel", "memoryInMB": "8192"},
        },
    }


def _interface(name: str, ifname: str, zone_id: str, zone: str, address: str, mask: str = "24") -> dict:
    return {
        "id": f"{name}-{ifname}",
        "type": "PhysicalInterface",
        "name": name,
        "ifname": ifname,
        "enabled": True,
        "mode": "NONE",
        "MTU": 1500,
        "securityZone": {"id": zone_id, "name": zone, "type": "SecurityZone"},
        "ipv4": {"static": {"address": address, "netmask": mask}},
    }


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


def build_sample_raw() -> dict[str, Any]:
    devices = [
        _device(DEVICE_1, "ftdv-ravpn-1", "10.210.2.11", "9A1DEMO00001", model=_MODEL_AWS),
        _device(DEVICE_2, "ftdv-ravpn-2", "10.210.2.12", "9A1DEMO00002", model=_MODEL_AWS, health="yellow"),
        _device(DEVICE_3, "ftd-branch-dc", "10.60.0.1", "JAD2DEMO0003", model="Cisco Firepower 1120 Threat Defense"),
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
            "policy": {"id": POLICY_ID, "type": "RAVpn", "name": "Corp-RAVPN"},
            "targets": [
                {"id": DEVICE_1, "type": "Device", "name": "ftdv-ravpn-1"},
                {"id": DEVICE_2, "type": "Device", "name": "ftdv-ravpn-2"},
            ],
        },
        {
            "id": "pa-0002",
            "type": "PolicyAssignment",
            "name": "Corp-ACP",
            "policy": {"id": "acp-0001", "type": "AccessPolicy", "name": "Corp-ACP"},
            "targets": [{"id": d["id"], "type": "Device", "name": d["name"]} for d in devices],
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
    interfaces = {
        DEVICE_1: [
            _interface("GigabitEthernet0/0", "outside", ZONE_OUTSIDE, "outside", "10.210.0.11"),
            _interface("GigabitEthernet0/1", "inside", ZONE_INSIDE, "inside", "10.210.1.11"),
        ],
        DEVICE_2: [
            _interface("GigabitEthernet0/0", "outside", ZONE_OUTSIDE, "outside", "10.210.0.12"),
            _interface("GigabitEthernet0/1", "inside", ZONE_INSIDE, "inside", "10.210.1.12"),
        ],
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
        "on_map": [DEVICE_1, DEVICE_2],
        "policies": [policy],
        "assignments": assignments,
        "policy_details": policy_details,
        "pools": pools,
        "interfaces": interfaces,
        "sessions": sessions,
        "errors": [],
        "stats": {"requests": 0, "retries": 0, "rate_limited": 0},
        "options": dict(DEFAULT_OPTIONS),
    }
