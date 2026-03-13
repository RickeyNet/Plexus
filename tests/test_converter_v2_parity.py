from __future__ import annotations

import json

from Firewall_converter.converter_v2.address_groups import convert_address_groups_v2
from Firewall_converter.converter_v2.addresses import convert_addresses_v2
from Firewall_converter.converter_v2.core.address_converter import AddressConverter
from Firewall_converter.converter_v2.core.address_group_converter import AddressGroupConverter
from Firewall_converter.converter_v2.core.interface_converter import InterfaceConverter
from Firewall_converter.converter_v2.core.policy_converter import PolicyConverter
from Firewall_converter.converter_v2.core.route_converter import RouteConverter
from Firewall_converter.converter_v2.core.service_converter import ServiceConverter
from Firewall_converter.converter_v2.core.service_group_converter import ServiceGroupConverter
from Firewall_converter.converter_v2.interfaces import convert_interfaces_v2
from Firewall_converter.converter_v2.policies import convert_policies_v2
from Firewall_converter.converter_v2.routes import convert_routes_v2
from Firewall_converter.converter_v2.service_groups import convert_service_groups_v2
from Firewall_converter.converter_v2.services import convert_services_v2


def _normalized(items: list[dict]) -> list[tuple[str, str, str, str, str]]:
    return sorted(
        (
            str(item.get("name", "")),
            str(item.get("description", "")),
            str(item.get("type", "")),
            str(item.get("subType", "")),
            str(item.get("value", "")),
        )
        for item in items
    )


def test_address_conversion_v2_matches_core_output_contract():
    fortigate_config = {
        "firewall_address": [
            {
                "HQ LAN": {
                    "subnet": ["10.10.0.0", "255.255.0.0"],
                    "comment": "Main office network",
                }
            },
            {
                "Branch Host": {
                    "subnet": ["192.168.77.10", "255.255.255.255"],
                    "comment": "Single host",
                }
            },
            {
                "DMZ_RANGE": {
                    "type": "iprange",
                    "start-ip": "172.16.1.10",
                    "end-ip": "172.16.1.20",
                    "comment": "DMZ pool",
                }
            },
        ]
    }

    baseline = AddressConverter(fortigate_config).convert()
    v2 = convert_addresses_v2(fortigate_config)

    assert _normalized(v2) == _normalized(baseline)


def _normalized_services(items: list[dict]) -> list[tuple[str, bool, str, str]]:
    return sorted(
        (
            str(item.get("name", "")),
            bool(item.get("isSystemDefined", False)),
            str(item.get("port", "")),
            str(item.get("type", "")),
        )
        for item in items
    )


def test_service_conversion_v2_matches_core_output_contract():
    fortigate_config = {
        "firewall_service_custom": [
            {
                "WEB_PLUS": {
                    "tcp-portrange": ["80", "443"],
                }
            },
            {
                "DNS_COMBINED": {
                    "tcp-portrange": "53",
                    "udp-portrange": "53",
                }
            },
            {
                "NTP_UDP_ONLY": {
                    "udp-portrange": "123",
                }
            },
        ]
    }

    baseline = ServiceConverter(fortigate_config).convert()
    v2 = convert_services_v2(fortigate_config)

    assert _normalized_services(v2) == _normalized_services(baseline)


def _normalized_routes(items: list[dict]) -> list[tuple[str, str, str, str, int | str, str, str]]:
    normalized: list[tuple[str, str, str, str, int | str, str, str]] = []
    for item in items:
        iface = item.get("iface", {})
        networks = item.get("networks", [{}])
        first_network = networks[0] if networks else {}
        gateway = item.get("gateway", {})
        normalized.append(
            (
                str(item.get("name", "")),
                str(iface.get("name", "")),
                str(first_network.get("name", "")),
                str(gateway.get("name", "")),
                item.get("metricValue", 1),
                str(item.get("ipType", "")),
                str(item.get("type", "")),
            )
        )
    return sorted(normalized)


def _canonical(value: object) -> object:
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        canonical_items = [_canonical(v) for v in value]
        return sorted(canonical_items, key=lambda item: json.dumps(item, sort_keys=True))
    return value


def test_route_conversion_v2_matches_core_output_contract():
    fortigate_config = {
        "router_static": [
            {
                64: {
                    "dst": ["10.0.20.0", "255.255.255.0"],
                    "gateway": "10.0.222.18",
                    "distance": 1,
                    "device": "port2",
                    "comment": "P5 Bear",
                }
            }
        ]
    }
    network_objects = [
        {
            "name": "Net_10_0_20_0_24",
            "description": "Dest network",
            "type": "networkobject",
            "subType": "NETWORK",
            "value": "10.0.20.0/24",
        },
        {
            "name": "Gateway_10_0_222_18",
            "description": "Gateway host",
            "type": "networkobject",
            "subType": "HOST",
            "value": "10.0.222.18",
        },
    ]
    interface_name_mapping = {"port2": "inside"}
    converted_interfaces = {
        "physical_interfaces": [
            {
                "name": "inside",
                "hardwareName": "Ethernet1/2",
                "type": "physicalinterface",
            }
        ],
        "subinterfaces": [],
        "etherchannels": [],
        "bridge_groups": [],
    }

    baseline = RouteConverter(
        fortigate_config=fortigate_config,
        network_objects=network_objects,
        interface_name_mapping=interface_name_mapping,
        converted_interfaces=converted_interfaces,
        debug=False,
    ).convert()
    v2 = convert_routes_v2(
        fortigate_config=fortigate_config,
        network_objects=network_objects,
        interface_name_mapping=interface_name_mapping,
        converted_interfaces=converted_interfaces,
        debug=False,
    )

    assert _normalized_routes(v2) == _normalized_routes(baseline)


def test_address_group_conversion_v2_matches_core_output_contract():
    fortigate_config = {
        "firewall_addrgrp": [
            {"Branch_Group": {"member": ["Host_A", "Host_B"]}},
        ]
    }
    address_object_names = {"Host_A", "Host_B"}

    baseline = AddressGroupConverter(
        fortigate_config=fortigate_config,
        address_object_names=address_object_names,
    ).convert()
    v2 = convert_address_groups_v2(
        fortigate_config=fortigate_config,
        address_object_names=address_object_names,
    )

    assert _canonical(v2) == _canonical(baseline)


def test_service_group_conversion_v2_matches_core_output_contract():
    fortigate_config = {
        "firewall_service_group": [
            {"Web_Services": {"member": ["HTTP", "DNS"]}},
        ]
    }
    service_name_mapping = {
        "HTTP": [("HTTP", "tcpportobject")],
        "DNS": [("DNS_TCP", "tcpportobject"), ("DNS_UDP", "udpportobject")],
    }

    baseline = ServiceGroupConverter(
        fortigate_config=fortigate_config,
        service_name_mapping=service_name_mapping,
        skipped_services=set(),
    ).convert()
    v2 = convert_service_groups_v2(
        fortigate_config=fortigate_config,
        service_name_mapping=service_name_mapping,
        skipped_services=set(),
    )

    assert _canonical(v2) == _canonical(baseline)


def test_policy_conversion_v2_matches_core_output_contract():
    fortigate_config = {
        "firewall_policy": [
            {
                10: {
                    "name": "Allow_Web",
                    "srcintf": ["inside"],
                    "dstintf": ["outside"],
                    "action": "accept",
                    "srcaddr": ["LAN_NET"],
                    "dstaddr": ["WAN_TARGET"],
                    "service": ["HTTPS"],
                }
            }
        ]
    }
    service_name_mapping = {"HTTPS": [("HTTPS", "tcpportobject")]}
    address_name_mapping = {"LAN_NET": "LAN_NET", "WAN_TARGET": "WAN_TARGET"}

    baseline = PolicyConverter(
        fortigate_config=fortigate_config,
        service_name_mapping=service_name_mapping,
        address_name_mapping=address_name_mapping,
        interface_name_mapping={"inside": "inside", "outside": "outside"},
    ).convert()
    v2 = convert_policies_v2(
        fortigate_config=fortigate_config,
        service_name_mapping=service_name_mapping,
        address_name_mapping=address_name_mapping,
        interface_name_mapping={"inside": "inside", "outside": "outside"},
    )

    assert _canonical(v2) == _canonical(baseline)


def test_interface_conversion_v2_matches_core_output_contract():
    fortigate_config = {
        "system_interface": [
            {
                "port2": {
                    "alias": "inside",
                    "ip": "10.0.1.1/24",
                    "allowaccess": "ping",
                    "status": "up",
                }
            }
        ]
    }

    baseline = InterfaceConverter(
        fortigate_config=fortigate_config,
        target_model="ftd-3120",
    ).convert()
    v2 = convert_interfaces_v2(
        fortigate_config=fortigate_config,
        target_model="ftd-3120",
    )

    assert _canonical(v2) == _canonical(baseline)


def test_address_group_flattening_reuses_nested_group_members():
    fortigate_config = {
        "firewall_addrgrp": [
            {"Nested": {"member": ["Host_A", "Host_B"]}},
            {"Parent": {"member": ["Nested", "Host_C", "Nested"]}},
        ]
    }

    groups = AddressGroupConverter(fortigate_config=fortigate_config).convert()
    parent = next(item for item in groups if item["name"] == "Parent")
    member_names = [obj["name"] for obj in parent["objects"]]

    assert member_names == ["Host_A", "Host_B", "Host_C"]


def test_service_group_flattening_reuses_nested_group_members():
    fortigate_config = {
        "firewall_service_group": [
            {"Nested": {"member": ["HTTPS"]}},
            {"Parent": {"member": ["Nested", "DNS", "Nested"]}},
        ]
    }
    mapping = {
        "HTTPS": [("HTTPS", "tcpportobject")],
        "DNS": [("DNS_TCP", "tcpportobject"), ("DNS_UDP", "udpportobject")],
    }

    groups = ServiceGroupConverter(
        fortigate_config=fortigate_config,
        service_name_mapping=mapping,
        skipped_services=set(),
    ).convert()
    parent = next(item for item in groups if item["name"] == "Parent")
    members = [(obj["name"], obj["type"]) for obj in parent["objects"]]

    assert members == [
        ("HTTPS", "tcpportobject"),
        ("DNS_TCP", "tcpportobject"),
        ("DNS_UDP", "udpportobject"),
    ]
