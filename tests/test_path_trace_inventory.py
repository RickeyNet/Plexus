"""Tests for the forwarding data of inventory hosts (path tracing).

``parse_route_table`` reads the SSH route table captures the monitoring poll
stores; ``forwarding_for_host`` builds the forwarding block of a host from
them, its interfaces and its addresses. One real-looking capture per format.
"""

from __future__ import annotations

from netcontrol.integrations.pathtrace.inventory import (
    ACCESS_LISTS,
    EMPTY_CAPTURE,
    NO_CAPTURE,
    NOT_RECOGNISED,
    TRUNCATED,
    forwarding_for_host,
    interface_key,
    parse_route_table,
)

IOS = """\
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2
       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2
       ia - IS-IS inter area, * - candidate default, U - per-user static route
       o - ODR, P - periodic downloaded static route, H - NHRP, l - LISP
       a - application route
       + - replicated route, % - next hop override, p - overrides from PfR

Gateway of last resort is 10.0.0.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 10.0.0.1
      10.0.0.0/8 is variably subnetted, 7 subnets, 3 masks
C        10.0.0.0/24 is directly connected, GigabitEthernet0/0
L        10.0.0.2/32 is directly connected, GigabitEthernet0/0
C        10.1.10.0/24 is directly connected, Vlan10
L        10.1.10.1/32 is directly connected, Vlan10
O        10.2.0.0/16 [110/2] via 10.0.0.3, 00:01:02, GigabitEthernet0/0
                     [110/2] via 10.0.0.4, 00:01:02, GigabitEthernet0/1
O IA     10.3.0.0/24 [110/3] via 10.0.0.3, 00:01:02, GigabitEthernet0/0
S        10.9.0.0/16 is directly connected, Null0
B     172.16.0.0/16 [20/0] via 192.0.2.1, 1w2d
D EX  192.168.50.0/24
           [170/2816] via 10.0.0.5, 3d04h, GigabitEthernet0/0
      172.20.0.0/24 is subnetted, 1 subnets
S        172.20.1.0 [1/0] via 10.0.0.6

Routing Table: GUEST
Codes: L - local, C - connected, S - static

Gateway of last resort is not set

      10.0.0.0/8 is variably subnetted, 2 subnets, 2 masks
C        10.50.0.0/24 is directly connected, Vlan50
L        10.50.0.1/32 is directly connected, Vlan50
"""

NXOS = """\
IP Route Table for VRF "default"
'*' denotes best ucast next-hop
'**' denotes best mcast next-hop
'[x/y]' denotes [preference/metric]
'%<string>' in via output denotes VRF <string>

0.0.0.0/0, ubest/mbest: 1/0
    *via 10.0.0.1, [1/0], 1w2d, static
10.1.1.0/24, ubest/mbest: 1/0, attached
    *via 10.1.1.1, Vlan10, [0/0], 1w2d, direct
10.1.1.1/32, ubest/mbest: 1/0, attached
    *via 10.1.1.1, Vlan10, [0/0], 1w2d, local
10.2.0.0/16, ubest/mbest: 2/0
    *via 10.0.0.3, Eth1/1, [110/41], 2d03h, ospf-1, intra
    *via 10.0.0.4, Eth1/2, [110/41], 2d03h, ospf-1, intra
10.3.0.0/16, ubest/mbest: 1/0
    *via 192.0.2.1%default, [20/0], 1w1d, bgp-65000, external, tag 65001
10.4.0.0/16, ubest/mbest: 1/0
    *via Null0, [1/0], 1w2d, static

IP Route Table for VRF "tenant-a"
10.20.0.0/24, ubest/mbest: 1/0, attached
    *via 10.20.0.1, Vlan200, [0/0], 1w2d, direct
"""

ASA = """\
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
       V - VPN, i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1
       * - candidate default, U - per-user static route, o - ODR

Gateway of last resort is 203.0.113.1 to network 0.0.0.0

S*       0.0.0.0 0.0.0.0 [1/0] via 203.0.113.1, outside
C        10.1.0.0 255.255.255.0 is directly connected, inside
L        10.1.0.1 255.255.255.255 is directly connected, inside
S        10.0.0.0 255.0.0.0 [1/0] via 10.1.0.254, inside
O        10.70.0.0 255.255.0.0 [110/20] via 10.1.0.2, 0:01:23, inside
                                 [110/20] via 10.1.0.3, 0:01:23, inside
C        203.0.113.0 255.255.255.240 is directly connected, outside
L        203.0.113.2 255.255.255.255 is directly connected, outside
V        10.220.0.14 255.255.255.255 connected by VPN (advertised), outside
"""

EOS = """\
VRF: default
Codes: C - connected, S - static, K - kernel,
       O - OSPF, IA - OSPF inter area, E1 - OSPF external type 1,
       E2 - OSPF external type 2, N1 - OSPF NSSA external type 1,
       N2 - OSPF NSSA external type2, B - Other BGP Routes,
       B I - iBGP, B E - eBGP, R - RIP, I L1 - IS-IS level 1,
       I L2 - IS-IS level 2, O3 - OSPFv3, A B - BGP Aggregate,
       A O - OSPF Summary, NG - Nexthop Group Static Route,
       V - VXLAN Control Service, M - Martian,
       DH - DHCP client installed default route,
       DP - Dynamic Policy Route, L - VRF Leaked,
       G  - gRIBI, RC - Route Cache Route

Gateway of last resort:
 S        0.0.0.0/0 [1/0] via 10.0.0.1, Ethernet1

 C        10.0.0.0/31 is directly connected, Ethernet1
 C        10.1.1.0/24 is directly connected, Vlan10
 O        10.2.0.0/16 [110/20] via 10.0.0.3, Ethernet2
 B E      10.3.0.0/16 [200/0] via 10.0.0.5, Ethernet3
                              via 10.0.0.6, Ethernet4
"""


def _by_prefix(routes: list[dict]) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {}
    for item in routes:
        found.setdefault(f"{item['vrf']}|{item['prefix']}", []).append(item)
    return found


def test_ios_capture_reads_every_kind_of_route():
    routes, missing = parse_route_table(IOS, "cisco_ios")
    assert missing == []
    found = _by_prefix(routes)
    default = found["|0.0.0.0/0"][0]
    assert (default["kind"], default["next_hop"], default["metric"]) == ("default", "10.0.0.1", 0)
    vlan = found["|10.1.10.0/24"][0]
    assert (vlan["kind"], vlan["interface"], vlan["source"]) == ("connected", "Vlan10", "Connected")
    assert found["|10.1.10.1/32"][0]["source"] == "Local address"
    # Two equal-cost next hops on two lines.
    ospf = found["|10.2.0.0/16"]
    assert [(r["next_hop"], r["interface"]) for r in ospf] == [
        ("10.0.0.3", "GigabitEthernet0/0"),
        ("10.0.0.4", "GigabitEthernet0/1"),
    ]
    assert ospf[0]["kind"] == "dynamic" and ospf[0]["source"] == "OSPF" and ospf[0]["metric"] == 2
    assert found["|10.3.0.0/24"][0]["source"] == "OSPF inter area"
    assert found["|10.9.0.0/16"][0]["kind"] == "blackhole"
    bgp = found["|172.16.0.0/16"][0]
    assert (bgp["source"], bgp["next_hop"], bgp["interface"]) == ("BGP", "192.0.2.1", "")
    # A route whose next hop wraps onto the next line.
    eigrp = found["|192.168.50.0/24"][0]
    assert (eigrp["source"], eigrp["next_hop"], eigrp["interface"]) == (
        "EIGRP external",
        "10.0.0.5",
        "GigabitEthernet0/0",
    )
    # A classful "is subnetted" block gives the length of the lines under it.
    assert found["|172.20.1.0/24"][0]["next_hop"] == "10.0.0.6"
    # The routes of another VRF carry its name.
    assert found["GUEST|10.50.0.0/24"][0]["interface"] == "Vlan50"
    assert all(r["enabled"] and r["peer"] is None for r in routes)


def test_nxos_capture_reads_vrfs_and_best_next_hops():
    routes, missing = parse_route_table(NXOS, "cisco_nxos")
    assert missing == []
    found = _by_prefix(routes)
    assert found["|0.0.0.0/0"][0]["kind"] == "default" and found["|0.0.0.0/0"][0]["next_hop"] == "10.0.0.1"
    direct = found["|10.1.1.0/24"][0]
    assert (direct["kind"], direct["interface"], direct["next_hop"]) == ("connected", "Vlan10", "")
    assert found["|10.1.1.1/32"][0]["source"] == "Local address"
    ospf = found["|10.2.0.0/16"]
    assert [(r["next_hop"], r["interface"], r["source"], r["metric"]) for r in ospf] == [
        ("10.0.0.3", "Eth1/1", "OSPF", 41),
        ("10.0.0.4", "Eth1/2", "OSPF", 41),
    ]
    bgp = found["|10.3.0.0/16"][0]
    assert (bgp["next_hop"], bgp["source"], bgp["kind"]) == ("192.0.2.1", "BGP", "dynamic")
    assert found["|10.4.0.0/16"][0]["kind"] == "blackhole"
    assert found["tenant-a|10.20.0.0/24"][0]["interface"] == "Vlan200"


def test_asa_capture_reads_masks_and_nameifs():
    routes, missing = parse_route_table(ASA, "cisco_asa")
    assert missing == []
    found = _by_prefix(routes)
    default = found["|0.0.0.0/0"][0]
    assert (default["kind"], default["next_hop"], default["interface"]) == ("default", "203.0.113.1", "outside")
    assert found["|10.1.0.0/24"][0]["kind"] == "connected" and found["|10.1.0.0/24"][0]["interface"] == "inside"
    static = found["|10.0.0.0/8"][0]
    assert (static["kind"], static["next_hop"], static["interface"]) == ("static", "10.1.0.254", "inside")
    assert [r["next_hop"] for r in found["|10.70.0.0/16"]] == ["10.1.0.2", "10.1.0.3"]
    assert found["|203.0.113.0/28"][0]["interface"] == "outside"
    vpn = found["|10.220.0.14/32"][0]
    assert (vpn["kind"], vpn["source"], vpn["interface"]) == ("dynamic", "VPN client", "outside")


def test_eos_capture_reads_codes_and_continuations():
    routes, missing = parse_route_table(EOS, "arista_eos")
    assert missing == []
    found = _by_prefix(routes)
    assert found["|0.0.0.0/0"][0]["kind"] == "default" and found["|0.0.0.0/0"][0]["interface"] == "Ethernet1"
    assert found["|10.1.1.0/24"][0]["kind"] == "connected"
    bgp = found["|10.3.0.0/16"]
    assert [(r["next_hop"], r["interface"], r["source"]) for r in bgp] == [
        ("10.0.0.5", "Ethernet3", "BGP external"),
        ("10.0.0.6", "Ethernet4", "BGP external"),
    ]


def test_unknown_empty_and_truncated_captures_say_so():
    assert parse_route_table("inet.0: 12 destinations, 12 routes\n10.0.0.0/24  *[Direct/0] 1w2d\n", "juniper") == (
        [],
        [NOT_RECOGNISED],
    )
    assert parse_route_table("   \n", "cisco_ios") == ([], [EMPTY_CAPTURE])
    long = IOS + "\n" * (10001 - len(IOS))
    routes, missing = parse_route_table(long, "cisco_ios")
    assert routes and missing == [TRUNCATED]


def test_interface_names_match_across_abbreviations():
    assert interface_key("Eth1/1") == interface_key("Ethernet1/1") == "ethernet1/1"
    assert interface_key("Gi0/0") == interface_key("GigabitEthernet0/0")
    assert interface_key("Po10") == interface_key("port-channel10")
    assert interface_key("inside") == "inside"


def test_forwarding_for_host_joins_interfaces_routes_and_addresses():
    host = {"id": 7, "hostname": "core-sw1", "ip_address": "10.0.0.2", "device_type": "cisco_ios"}
    interfaces = [
        {"name": "GigabitEthernet0/0", "admin_state": "up", "oper_state": "up"},
        {"name": "GigabitEthernet0/1", "admin_state": "down", "oper_state": "down"},
        {"name": "Vlan10", "admin_state": "up", "oper_state": "up"},
    ]
    block = forwarding_for_host(host, ["192.0.2.77"], {"id": 3, "routes_text": IOS}, interfaces)
    assert set(block) == {"version", "interfaces", "routes", "vpn", "policies", "nat", "not_collected"}
    by_name = {i["name"]: i for i in block["interfaces"]}
    assert by_name["GigabitEthernet0/0"] == {
        "name": "GigabitEthernet0/0",
        "kind": "routed",
        "ip": "10.0.0.2",
        "cidr": "10.0.0.0/24",
        "zone": "",
        "vrf": "",
        "enabled": True,
    }
    assert by_name["GigabitEthernet0/1"]["enabled"] is False and by_name["GigabitEthernet0/1"]["cidr"] == ""
    assert by_name["Vlan10"]["kind"] == "svi" and by_name["Vlan10"]["ip"] == "10.1.10.1"
    # An interface only the route table names is listed too.
    assert by_name["Vlan50"]["cidr"] == "10.50.0.0/24"
    # An alias no interface holds is an interface named by the address.
    assert by_name["192.0.2.77"]["ip"] == "192.0.2.77" and by_name["192.0.2.77"]["cidr"] == ""
    assert any(r["prefix"] == "10.2.0.0/16" for r in block["routes"])
    assert block["policies"] == [] and block["nat"] == [] and block["vpn"] == []
    assert block["not_collected"] == [ACCESS_LISTS]


def test_forwarding_for_host_renames_route_interfaces_to_the_inventory_names():
    host = {"id": 9, "ip_address": "10.1.1.1", "device_type": "cisco_nxos"}
    block = forwarding_for_host(
        host, [], {"id": 1, "routes_text": NXOS}, [{"name": "Ethernet1/1", "admin_state": "up"}]
    )
    ospf = [r for r in block["routes"] if r["prefix"] == "10.2.0.0/16"]
    assert [r["interface"] for r in ospf] == ["Ethernet1/1", "Eth1/2"]
    by_name = {i["name"]: i for i in block["interfaces"]}
    assert by_name["Vlan10"]["ip"] == "10.1.1.1" and "10.1.1.1" not in by_name


def test_forwarding_for_host_without_a_capture():
    host = {"id": 1, "ip_address": "10.9.9.9", "device_type": "cisco_ios"}
    block = forwarding_for_host(host, [], None, [])
    assert block["routes"] == []
    assert block["interfaces"] == [
        {"name": "10.9.9.9", "kind": "", "ip": "10.9.9.9", "cidr": "", "zone": "", "vrf": "", "enabled": True}
    ]
    assert block["not_collected"] == [ACCESS_LISTS, NO_CAPTURE]
    unknown = forwarding_for_host(host, [], {"id": 2, "routes_text": "% Invalid input detected"}, [])
    assert unknown["not_collected"] == [ACCESS_LISTS, NOT_RECOGNISED]
