"""The pure rules of VRF and VLAN records and interface addresses
(``netcontrol.network_objects``), over invented configurations read by the
real platform parsers."""

from __future__ import annotations

import pytest
from netcontrol.custom_fields import CustomFieldError
from netcontrol.integrations.pathtrace.device_config import ConfigInterface, RunningConfig, VirtualAddress
from netcontrol.integrations.pathtrace.platforms import platform_of
from netcontrol.network_objects import (
    bindings_from_config,
    clean_description,
    clean_rd,
    clean_vid,
    clean_vlan_name,
    clean_vrf_name,
    port_vlan_modes,
    svi_vid,
    vlans_of_port,
)

IOS = """hostname edge-r1
vrf definition BLUE
 rd 65000:10
!
interface Vlan10
 vrf forwarding BLUE
 ip address 192.0.2.2 255.255.255.0
 ip address 198.51.100.1 255.255.255.0 secondary
 standby 1 ip 192.0.2.1
!
interface GigabitEthernet0/1
 ip address 203.0.113.1 255.255.255.252
!
interface GigabitEthernet0/2
 vrf forwarding RED
 no ip address
!
ip route vrf GREEN 0.0.0.0 0.0.0.0 192.0.2.254
ip route vrf BLUE 0.0.0.0 0.0.0.0 192.0.2.254
"""

JUNOS = """set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
set interfaces irb unit 20 family inet address 198.51.100.2/24 vrrp-group 1 virtual-address 198.51.100.1
set routing-instances CUST instance-type vrf
set routing-instances CUST interface irb.20
"""


# ── Validators ───────────────────────────────────────────────────────────────


def test_vrf_name_is_trimmed_and_limited():
    assert clean_vrf_name("  BLUE ") == "BLUE"
    for bad in ("", "   ", None, 7, "x" * 65):
        with pytest.raises(CustomFieldError):
            clean_vrf_name(bad)
    assert clean_vrf_name("x" * 64) == "x" * 64


def test_rd_vlan_name_and_description_may_be_empty_but_are_limited():
    assert clean_rd(" 65000:10 ") == "65000:10"
    assert clean_rd("") == "" and clean_rd(None) == ""
    assert clean_vlan_name(" users ") == "users" and clean_vlan_name("") == ""
    assert clean_description(" lab ") == "lab"
    with pytest.raises(CustomFieldError, match="Route distinguisher"):
        clean_rd("1" * 65)
    with pytest.raises(CustomFieldError, match="VLAN name"):
        clean_vlan_name("v" * 65)
    with pytest.raises(CustomFieldError, match="Description"):
        clean_description("d" * 501)


def test_vid_is_one_to_4094():
    assert clean_vid(1) == 1 and clean_vid(4094) == 4094
    for bad in (0, 4095, -1, True, "10", 1.5, None):
        with pytest.raises(CustomFieldError):
            clean_vid(bad)


# ── VLAN interfaces and ports ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "vid"),
    [
        ("Vlan10", 10),
        ("vlan 10", 10),
        ("VLAN.10", 10),
        ("irb.20", 20),
        ("IRB.20", 20),
        ("Vlan4094", 4094),
        ("Vlan4095", 0),
        ("Vlan0", 0),
        ("GigabitEthernet0/1", 0),
        ("irb", 0),
        ("vlan", 0),
        ("", 0),
    ],
)
def test_svi_vid(name, vid):
    assert svi_vid(name) == vid


def test_port_vlan_modes_and_vlans_of_port():
    assert port_vlan_modes(10, set(), 10) == ["access"]
    assert port_vlan_modes(0, {10, 20}, 20) == ["trunk"]
    assert port_vlan_modes(10, {10}, 10) == ["access", "trunk"]
    assert port_vlan_modes(0, {20}, 10) == []
    assert vlans_of_port(10, {20, 30}, {10, 20, 40}) == {10, 20}
    assert vlans_of_port(0, set(), {10}) == set()


# ── Bindings from a configuration ────────────────────────────────────────────


def test_ios_bindings_with_vrf_secondary_and_hsrp():
    rows, vrfs = bindings_from_config(platform_of("cisco_ios").config(IOS))
    by_address = {r["address"]: r for r in rows}
    assert [r["address"] for r in rows] == ["192.0.2.2", "198.51.100.1", "192.0.2.1", "203.0.113.1"]
    assert by_address["192.0.2.2"] == {
        "interface": "Vlan10",
        "interface_key": "vlan10",
        "address": "192.0.2.2",
        "prefix_length": 24,
        "network": "192.0.2.0/24",
        "vrf_name": "BLUE",
        "role": "primary",
        "protocol": "",
        "svi_vid": 10,
    }
    assert by_address["198.51.100.1"]["role"] == "secondary"
    assert by_address["198.51.100.1"]["network"] == "198.51.100.0/24"
    virtual = by_address["192.0.2.1"]
    assert (virtual["role"], virtual["protocol"], virtual["network"]) == ("virtual", "HSRP", "192.0.2.0/24")
    wan = by_address["203.0.113.1"]
    assert (wan["vrf_name"], wan["prefix_length"], wan["svi_vid"], wan["role"]) == ("", 30, 0, "primary")
    # An interface in a VRF counts without an address; a static route's VRF
    # with no interface in it counts 0.
    assert vrfs == {"BLUE": 1, "RED": 1, "GREEN": 0}


def test_junos_bindings():
    rows, vrfs = bindings_from_config(platform_of("juniper_junos").config(JUNOS))
    assert [(r["interface"], r["address"], r["role"], r["vrf_name"], r["svi_vid"]) for r in rows] == [
        ("ge-0/0/0.0", "192.0.2.1", "primary", "", 0),
        ("irb.20", "198.51.100.2", "primary", "CUST", 20),
        ("irb.20", "198.51.100.1", "virtual", "CUST", 20),
    ]
    assert rows[2]["protocol"] == "VRRP" and rows[2]["network"] == "198.51.100.0/24"
    assert vrfs == {"CUST": 1}


def test_unparsed_platform_has_no_parser():
    assert platform_of("paloalto_panos").config is None


def test_unusable_addresses_are_skipped_and_ipv6_has_its_own_primary():
    running = RunningConfig(
        interfaces=[
            ConfigInterface(
                name="Ethernet1",
                addresses=[
                    ("192.0.2.5", "192.0.2.0/24"),
                    ("not-an-ip", "192.0.2.0/24"),
                    ("192.0.2.6", "garbage"),
                    ("192.0.2.7", "2001:db8::/64"),
                    ("192.0.2.5", "192.0.2.0/24"),
                    ("2001:db8::1", "2001:db8::/64"),
                    ("2001:db8::2", "2001:db8::/64"),
                ],
                virtual=[
                    VirtualAddress("VRRP", "1", "203.0.113.9"),
                    VirtualAddress("vrrp", "2", "192.0.2.254"),
                    VirtualAddress("HSRP", "3", "bogus"),
                    VirtualAddress("HSRP", "4", "192.0.2.5"),
                ],
            ),
            ConfigInterface(name="  ", addresses=[("192.0.2.9", "192.0.2.0/24")]),
        ]
    )
    rows, vrfs = bindings_from_config(running)
    assert [(r["address"], r["role"], r["protocol"]) for r in rows] == [
        ("192.0.2.5", "primary", ""),
        ("2001:db8::1", "primary", ""),
        ("2001:db8::2", "secondary", ""),
        ("192.0.2.254", "virtual", "VRRP"),
    ]
    assert rows[1]["prefix_length"] == 64 and rows[1]["network"] == "2001:db8::/64"
    assert vrfs == {}
