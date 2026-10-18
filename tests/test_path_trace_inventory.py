"""Tests for the forwarding data of inventory hosts (path tracing).

``parse_route_table`` reads the SSH route table captures the monitoring poll
stores; ``forwarding_for_host`` builds the forwarding block of a host from
them, its interfaces and its addresses. One real-looking capture per format.
"""

from __future__ import annotations

from netcontrol.integrations.pathtrace.inventory import (
    ACCESS_LISTS,
    CAPTURE_LIMIT,
    EMPTY_CAPTURE,
    NO_CAPTURE,
    NOT_RECOGNISED,
    TRUNCATED,
    forwarding_for_host,
    interface_key,
    parse_route_table,
    subnets_for_host,
)
from netcontrol.integrations.pathtrace.ios_config import IPV6_ACCESS_LISTS, parse_config
from netcontrol.integrations.pathtrace.model import INVENTORY_ORG_REF
from netcontrol.integrations.pathtrace.sweep import vlan_of

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
    long = IOS + "\n" * (CAPTURE_LIMIT + 1 - len(IOS))
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


# ── Running configurations (Config Backups) ──────────────────────────────────

CAT9300 = """\
Building configuration...

Current configuration : 9876 bytes
!
version 17.9
hostname core-sw1
!
vrf definition GUEST
 address-family ipv4
 exit-address-family
!
ip routing
!
object-group network SERVERS
 host 10.20.0.10
 10.20.1.0 255.255.255.0
 range 10.20.2.0 10.20.2.255
!
object-group service WEB
 tcp eq www
 tcp eq 443
 udp eq domain
!
interface GigabitEthernet1/0/1
 description Uplink to fw
 no switchport
 ip address 10.0.0.2 255.255.255.252
 ip access-group UPLINK-IN in
!
interface GigabitEthernet1/0/2
 description Guest uplink
 no switchport
 vrf forwarding GUEST
 ip address 10.99.0.2 255.255.255.252
!
interface GigabitEthernet1/0/3
 switchport access vlan 10
 shutdown
!
interface Loopback0
 ip address 10.255.0.1 255.255.255.255
!
interface Vlan10
 description Users
 ip address 10.1.10.2 255.255.255.0
 ip address 10.1.11.2 255.255.255.0 secondary
 ip helper-address 10.20.0.10
 ip access-group USERS-IN in
 standby version 2
 standby 10 ip 10.1.10.1
 standby 10 priority 110
 standby 10 preempt
!
interface Vlan20
 description Voice
 ip address 10.1.20.2 255.255.255.0
 ip access-group 10 out
 ipv6 traffic-filter VOICE6 in
 vrrp 20 address-family ipv4
  address 10.1.20.1 primary
!
interface Vlan30
 ip address 10.1.30.2 255.255.255.0
 ip access-group MISSING in
!
router ospf 1
 network 10.0.0.0 0.255.255.255 area 0
!
ip route 0.0.0.0 0.0.0.0 10.0.0.1 name DEFAULT
ip route 10.30.0.0 255.255.0.0 Null0
ip route 10.40.0.0 255.255.0.0 10.0.0.1 200 name FLOATING
ip route vrf GUEST 0.0.0.0 0.0.0.0 10.99.0.1 name GUEST-DEFAULT
ip route vrf GUEST 172.16.50.0 255.255.255.0 GigabitEthernet1/0/2 10.99.0.1
!
ip access-list extended USERS-IN
 remark Web to the servers
 10 permit object-group WEB 10.1.10.0 0.0.0.255 object-group SERVERS
 20 permit tcp any any established
 remark No telnet anywhere
 30 deny   tcp any any eq telnet log
 40 permit tcp 10.1.10.0 0.0.0.255 host 10.20.0.10 range 8000 8080
 50 permit udp any eq bootpc any eq bootps
 60 permit ip 10.1.10.0 0.0.0.255 10.0.0.0 0.255.0.255
 70 permit tcp any host 10.20.0.11 eq foo
 80 permit tcp any any gt 1023 time-range OFFICE
 90 permit icmp any any echo-reply
 100 deny   ip any any log
ip access-list extended UPLINK-IN
 10 permit tcp any 10.1.10.0 0.0.0.255 established
 20 permit ospf any any
 25 evaluate RETURN-TRAFFIC
 30 deny ip any any
!
access-list 10 remark Phones only
access-list 10 permit 10.1.20.0 0.0.0.255
access-list 10 deny   any log
!
end
"""

NXOS_CONFIG = """\
!Command: show running-config
version 9.3(8) Bios:version 05.45
hostname dc-leaf1
feature hsrp
feature interface-vlan
object-group ip address APP-SERVERS
  10 host 10.50.0.10
  20 10.50.1.0/24
object-group ip port APP-PORTS
  10 eq 8443
  20 range 9000 9100
ip access-list APP-IN
  statistics per-entry
  10 remark Apps only
  20 permit tcp 10.60.0.0/24 addrgroup APP-SERVERS portgroup APP-PORTS
  30 permit tcp 10.60.0.0 0.0.0.255 any eq 22
  40 deny ip any any
vrf context TENANT-A
  ip route 0.0.0.0/0 10.60.0.254
interface Vlan60
  no shutdown
  vrf member TENANT-A
  ip address 10.60.0.2/24
  ip access-group APP-IN in
  hsrp 60
    ip 10.60.0.1
interface Ethernet1/1
  no switchport
  ip address 10.0.1.1/31
  no shutdown
ip route 10.0.0.0/8 10.0.1.0
"""


def test_ios_config_reads_interfaces_access_lists_and_routes():
    config = parse_config(CAT9300)
    interfaces = {i.name: i for i in config.interfaces}
    vlan10 = interfaces["Vlan10"]
    assert vlan10.description == "Users" and vlan10.addresses == [
        ("10.1.10.2", "10.1.10.0/24"),
        ("10.1.11.2", "10.1.11.0/24"),
    ]
    assert vlan10.access_groups == {"in": "USERS-IN"}
    assert [(v.protocol, v.group, v.address) for v in vlan10.virtual] == [("HSRP", "10", "10.1.10.1")]
    assert [(v.protocol, v.address) for v in interfaces["Vlan20"].virtual] == [("VRRP", "10.1.20.1")]
    assert interfaces["GigabitEthernet1/0/2"].vrf == "GUEST"
    assert interfaces["GigabitEthernet1/0/3"].shutdown is True
    assert config.routing == ["OSPF"] and config.notes == [IPV6_ACCESS_LISTS]

    users = config.access_lists["USERS-IN"]
    # The service object group gives one entry per service, with the remark before it.
    web = [e for e in users if e.sequence == 10]
    assert [(e.protocol, e.dst_ports) for e in web] == [("tcp", "80"), ("tcp", "443"), ("udp", "53")]
    assert web[0].src == ["10.1.10.0/24"] and web[0].comment == "Web to the servers"
    assert web[0].dst == ["10.20.0.10/32", "10.20.1.0/24", "10.20.2.0/24"]
    by_sequence = {e.sequence: e for e in users}
    assert by_sequence[20].established is True and by_sequence[20].protocol == "tcp"
    assert by_sequence[30].action == "deny" and by_sequence[30].dst_ports == "23"
    assert by_sequence[30].comment == "No telnet anywhere" and by_sequence[40].comment == ""
    assert by_sequence[40].dst_ports == "8000-8080"
    assert (by_sequence[50].src_ports, by_sequence[50].dst_ports) == ("68", "67")
    # What cannot be evaluated is kept, never dropped.
    assert by_sequence[60].unresolved == ["wildcard mask 10.0.0.0 0.255.0.255"]
    assert by_sequence[70].unresolved == ["port foo"]
    assert by_sequence[80].dst_ports == "1024-65535" and by_sequence[80].unresolved == ["time-range OFFICE"]
    assert by_sequence[90].protocol == "icmp" and by_sequence[90].unresolved == []
    uplink = {e.sequence: e for e in config.access_lists["UPLINK-IN"]}
    assert uplink[20].protocol == "ospf" and uplink[25].unresolved == ["reflexive access list RETURN-TRAFFIC"]
    standard = config.access_lists["10"]
    assert [(e.action, e.src, e.comment) for e in standard] == [
        ("allow", ["10.1.20.0/24"], "Phones only"),
        ("deny", ["any"], ""),
    ]

    routes = {(r.vrf, r.prefix): r for r in config.static_routes}
    assert routes[("", "0.0.0.0/0")].next_hop == "10.0.0.1" and routes[("", "0.0.0.0/0")].name == "DEFAULT"
    assert routes[("", "10.30.0.0/16")].interface == "Null0"
    assert routes[("", "10.40.0.0/16")].distance == 200
    guest = routes[("GUEST", "172.16.50.0/24")]
    assert (guest.interface, guest.next_hop) == ("GigabitEthernet1/0/2", "10.99.0.1")


def test_nxos_config_reads_vrf_members_groups_and_vrf_context_routes():
    config = parse_config(NXOS_CONFIG)
    vlan = next(i for i in config.interfaces if i.name == "Vlan60")
    assert vlan.vrf == "TENANT-A" and vlan.addresses == [("10.60.0.2", "10.60.0.0/24")]
    assert [(v.protocol, v.address) for v in vlan.virtual] == [("HSRP", "10.60.0.1")]
    entries = config.access_lists["APP-IN"]
    assert [e.sequence for e in entries] == [20, 30, 40]
    assert entries[0].dst == ["10.50.0.10/32", "10.50.1.0/24"] and entries[0].dst_ports == "8443,9000-9100"
    assert entries[0].comment == "Apps only" and entries[1].src == ["10.60.0.0/24"]
    routes = {(r.vrf, r.prefix): r.next_hop for r in config.static_routes}
    assert routes == {("TENANT-A", "0.0.0.0/0"): "10.60.0.254", ("", "10.0.0.0/8"): "10.0.1.0"}


_GLOBAL_CAPTURE = """\
Codes: L - local, C - connected, S - static, O - OSPF
Gateway of last resort is 10.0.0.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 10.0.0.1
      10.0.0.0/8 is variably subnetted, 6 subnets, 3 masks
C        10.0.0.0/30 is directly connected, GigabitEthernet1/0/1
L        10.0.0.2/32 is directly connected, GigabitEthernet1/0/1
C        10.1.10.0/24 is directly connected, Vlan10
L        10.1.10.2/32 is directly connected, Vlan10
O        10.20.0.0/16 [110/2] via 10.0.0.1, 00:01:02, GigabitEthernet1/0/1
S        10.30.0.0/16 is directly connected, Null0
"""


def _backup(text: str = CAT9300) -> dict:
    return {"id": 11, "host_id": 7, "config_text": text}


def test_forwarding_for_host_with_a_configuration_backup():
    host = {"ip_address": "10.0.0.2", "device_type": "cisco_xe"}
    snmp = [{"name": "Vlan10", "admin_state": "up"}, {"name": "Vlan20", "admin_state": "down"}]
    block = forwarding_for_host(host, [], {"id": 3, "routes_text": _GLOBAL_CAPTURE}, snmp, config_backup=_backup())
    by_name = {i["name"]: i for i in block["interfaces"]}
    assert by_name["Vlan10"] == {
        "name": "Vlan10",
        "kind": "svi",
        "ip": "10.1.10.2",
        "cidr": "10.1.10.0/24",
        "zone": "Vlan10",
        "vrf": "",
        "enabled": True,
        "description": "Users",
    }
    # The HSRP address is an address of the device, on Vlan10.
    hsrp = by_name["Vlan10 (HSRP 10.1.10.1)"]
    assert (hsrp["ip"], hsrp["cidr"], hsrp["zone"], hsrp["kind"]) == ("10.1.10.1", "10.1.10.0/24", "Vlan10", "svi")
    assert by_name["Vlan10 (secondary 10.1.11.2)"]["cidr"] == "10.1.11.0/24"
    assert by_name["Vlan20"]["enabled"] is False and by_name["Vlan20 (VRRP 10.1.20.1)"]["enabled"] is False
    assert by_name["GigabitEthernet1/0/2"]["vrf"] == "GUEST"
    assert by_name["GigabitEthernet1/0/3"]["enabled"] is False

    routes = _by_prefix(block["routes"])
    # The capture holds the global table; the GUEST VRF comes from the configuration.
    assert [r["source"] for r in routes["|10.20.0.0/16"]] == ["OSPF"]
    assert "|10.40.0.0/16" not in routes  # a floating static route the table does not hold
    assert routes["GUEST|0.0.0.0/0"][0]["next_hop"] == "10.99.0.1"
    assert routes["GUEST|0.0.0.0/0"][0]["source"] == "Static route GUEST-DEFAULT"
    assert routes["GUEST|10.99.0.0/30"][0]["kind"] == "connected"
    assert routes["GUEST|172.16.50.0/24"][0]["interface"] == "GigabitEthernet1/0/2"

    policies = {p["name"]: p for p in block["policies"]}
    assert list(policies) == [
        "ACL UPLINK-IN in on GigabitEthernet1/0/1",
        "ACL USERS-IN in on Vlan10",
        "ACL 10 out on Vlan20",
        "ACL MISSING in on Vlan30",
    ]
    users = policies["ACL USERS-IN in on Vlan10"]
    assert (users["kind"], users["applies"], users["stateful"], users["default"]) == ("acl", "any", False, "deny")
    assert (users["interface"], users["direction"]) == ("Vlan10", "in")
    assert all(r["src_zones"] == ["Vlan10"] and r["dst_zones"] == [] for r in users["rules"])
    established = next(r for r in users["rules"] if r["index"] == 20)
    assert established["established"] is True and established["action"] == "allow"
    voice = policies["ACL 10 out on Vlan20"]
    assert voice["direction"] == "out" and voice["rules"][0]["dst_zones"] == ["Vlan20"]
    assert [r["index"] for r in voice["rules"]] == [1, 2]
    missing = policies["ACL MISSING in on Vlan30"]
    assert missing["default"] == "unknown"
    assert missing["rules"][0]["unresolved"] == ["access list MISSING (not in the configuration)"]
    # The access lists were read: only what the configuration uses and is not read is noted.
    assert block["not_collected"] == [IPV6_ACCESS_LISTS]


def test_forwarding_for_host_from_a_configuration_alone():
    host = {"ip_address": "10.0.0.2", "device_type": "cisco_ios"}
    block = forwarding_for_host(host, [], None, [], config_backup=_backup())
    routes = _by_prefix(block["routes"])
    assert routes["|10.1.10.0/24"][0]["kind"] == "connected" and routes["|10.1.11.0/24"][0]["interface"] == "Vlan10"
    assert routes["|0.0.0.0/0"][0]["kind"] == "default" and routes["|10.30.0.0/16"][0]["kind"] == "blackhole"
    assert routes["|10.40.0.0/16"][0]["kind"] == "static"
    # No capture: the routes OSPF learns are missing, and the table says so.
    assert block["not_collected"] == [IPV6_ACCESS_LISTS, "Routes learned by OSPF"]

    # A platform whose configuration is not read keeps today's behaviour.
    asa_host = {"ip_address": "10.0.0.2", "device_type": "cisco_asa"}
    asa = forwarding_for_host(asa_host, [], None, [], config_backup=_backup())
    assert asa["policies"] == [] and asa["not_collected"] == [ACCESS_LISTS, NO_CAPTURE]


def test_subnets_for_host_lists_vlans_connected_networks_and_static_routes():
    node = {"id": 7, "label": "core-sw1", "group_id": 3, "group_name": "HQ"}
    host = {"ip_address": "10.0.0.2", "device_type": "cisco_xe"}
    rows = subnets_for_host(node, forwarding_for_host(host, [], None, [], config_backup=_backup()))
    by_cidr = {r["cidr"]: r for r in rows}
    assert by_cidr["10.1.10.0/24"] == {
        "cidr": "10.1.10.0/24",
        "name": "VLAN 10 Users",
        "kind": "svi",
        "site_id": "3",
        "site_name": "HQ",
        "node_id": "7",
        "in_vpn": None,
        "org_ref": INVENTORY_ORG_REF,
        "provider": "inventory",
        "org_name": "Inventory",
    }
    assert vlan_of(by_cidr["10.1.10.0/24"]) == 10
    assert by_cidr["10.1.11.0/24"]["name"] == "VLAN 10 Users (secondary)"
    assert (by_cidr["10.1.30.0/24"]["kind"], by_cidr["10.1.30.0/24"]["name"]) == ("svi", "VLAN 30")
    assert by_cidr["10.0.0.0/30"]["kind"] == "connected"
    assert by_cidr["10.0.0.0/30"]["name"] == "GigabitEthernet1/0/1 Uplink to fw"
    assert (by_cidr["10.40.0.0/16"]["kind"], by_cidr["10.40.0.0/16"]["name"]) == (
        "static",
        "Static route via 10.0.0.1",
    )
    # No default route, no blackhole, no loopback or host address.
    assert not {"0.0.0.0/0", "10.30.0.0/16", "10.255.0.1/32"} & set(by_cidr)
