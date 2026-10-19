"""Tests for the Arista EOS, Cisco IOS-XR, Aruba AOS-CX and AOS-Switch
(ProCurve) readers of the path trace: their running configurations and
route table captures, the forwarding block of an inventory host built from
them, and one trace through an AOS-CX switch. One real-looking sample per
format.
"""

from __future__ import annotations

from netcontrol.integrations.pathtrace import aruba_config
from netcontrol.integrations.pathtrace.aruba_config import VLAN_ACCESS_LISTS, VSX
from netcontrol.integrations.pathtrace.inventory import forwarding_for_host, parse_route_table
from netcontrol.integrations.pathtrace.ios_config import (
    CLASSIFIER_POLICIES,
    IPV6_ACCESS_LISTS,
    MAC_ACCESS_LISTS,
    POLICY_BASED_ROUTES,
    PORT_ACCESS_LISTS,
    TRAFFIC_POLICIES,
    parse_config,
)
from netcontrol.integrations.pathtrace.platforms import platform_of
from netcontrol.integrations.pathtrace.route_tables import interface_key

from test_path_trace import _CATALYST_NODES, _ROUTER_CAPTURE, _ROUTER_CONFIG, _labels, _tracer


def _by_prefix(routes: list[dict]) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {}
    for item in routes:
        found.setdefault(f"{item['vrf']}|{item['prefix']}", []).append(item)
    return found


def _policies(block: dict) -> dict[str, dict]:
    return {p["name"]: p for p in block["policies"]}


def _interfaces(block: dict) -> dict[str, dict]:
    return {i["name"]: i for i in block["interfaces"]}


# ── Arista EOS ───────────────────────────────────────────────────────────────

EOS_CONFIG = """\
! Command: show running-config
! device: leaf1 (DCS-7050SX3-48YC8, EOS-4.28.3M)
!
! boot system flash:/EOS-4.28.3M.swi
!
transceiver qsfp default-mode 4x10G
!
hostname leaf1
!
spanning-tree mode mstp
!
vlan 10
   name Users
!
vlan 20
   name Tenant
!
vrf instance MGMT
!
vrf instance TENANT-A
!
interface Ethernet1
   description To spine1
   no switchport
   ip address 10.0.0.1/31
   ip access-group UPLINK-IN in
!
interface Ethernet2
   description Spare
   shutdown
!
interface Ethernet3
   switchport access vlan 10
   mac access-group MAC-FILTER in
!
interface Port-Channel10
   switchport mode trunk
!
interface Loopback0
   ip address 10.255.0.1/32
!
interface Management1
   vrf MGMT
   ip address 192.168.1.10/24
!
interface Vlan10
   description Users
   ip address 10.1.10.2/24
   ip address 10.1.11.2/24 secondary
   ip access-group USERS-IN in
   ip virtual-router address 10.1.10.1
!
interface Vlan20
   vrf TENANT-A
   ip address 10.20.0.2/24
   vrrp 20 priority-level 110
   vrrp 20 ipv4 10.20.0.1
   ipv6 access-group V6-IN in
   service-policy type pbr input STEER
!
ip virtual-router mac-address 00:1c:73:00:00:99
!
ip access-list USERS-IN
   counters per-entry
   10 remark Web to the servers
   20 permit tcp 10.1.10.0/24 10.20.0.0/24 eq https
   30 deny tcp any any eq telnet log
   40 permit udp 10.1.10.0 0.0.0.255 any eq domain ntp
   50 permit icmp any any
   60 permit ip 10.1.10.0/24 host 10.30.0.5
   70 deny ip any any
!
ip access-list UPLINK-IN
   10 permit tcp any 10.1.10.0/24 established
   20 permit ospf any any
   30 deny ip any any
!
ip access-list standard MGMT-ONLY
   10 permit 192.168.1.0/24
   20 deny any
!
ip route 0.0.0.0/0 10.0.0.0
ip route 10.9.0.0/16 Null0
ip route 10.40.0.0/16 10.0.0.0 200 tag 5 name FLOAT
ip route vrf MGMT 0.0.0.0/0 192.168.1.1
ip route vrf TENANT-A 0.0.0.0/0 10.20.0.254 name TENANT-DEFAULT
!
ip routing
ip routing vrf TENANT-A
no ip routing vrf MGMT
!
router bgp 65001
   router-id 10.255.0.1
   neighbor 10.0.0.0 remote-as 65000
   !
   vrf TENANT-A
      rd 10.255.0.1:20
!
router ospf 1
   network 10.0.0.0/31 area 0.0.0.0
!
end
"""

EOS_VRF_ALL = """\
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
 S        0.0.0.0/0 [1/0] via 10.0.0.0, Ethernet1

 C        10.0.0.0/31 is directly connected, Ethernet1
 C        10.1.10.0/24 is directly connected, Vlan10
 C        10.1.11.0/24 is directly connected, Vlan10
 O E2     10.5.0.0/16 [110/1] via 10.0.0.0, Ethernet1
 B E      10.6.0.0/16 [200/0] via 10.0.0.0, Ethernet1
 C        10.255.0.1/32 is directly connected, Loopback0
 S        10.9.0.0/16 is directly connected, Null0

VRF: TENANT-A
Codes: C - connected, S - static, K - kernel,
       O - OSPF, IA - OSPF inter area, E1 - OSPF external type 1

Gateway of last resort:
 S        0.0.0.0/0 [1/0] via 10.20.0.254, Vlan20

 C        10.20.0.0/24 is directly connected, Vlan20
 B I      10.21.0.0/16 [200/0] via 10.255.0.9, Vlan20
                               via 10.255.0.10, Vlan20
"""


def test_eos_config_reads_interfaces_varp_access_lists_and_routes():
    config = parse_config(EOS_CONFIG)
    interfaces = {i.name: i for i in config.interfaces}
    vlan10 = interfaces["Vlan10"]
    assert vlan10.addresses == [("10.1.10.2", "10.1.10.0/24"), ("10.1.11.2", "10.1.11.0/24")]
    assert vlan10.access_groups == {"in": "USERS-IN"} and vlan10.description == "Users"
    assert [(v.protocol, v.address) for v in vlan10.virtual] == [("VARP", "10.1.10.1")]
    vlan20 = interfaces["Vlan20"]
    assert vlan20.vrf == "TENANT-A" and [(v.protocol, v.group, v.address) for v in vlan20.virtual] == [
        ("VRRP", "20", "10.20.0.1")
    ]
    assert interfaces["Management1"].vrf == "MGMT" and interfaces["Ethernet2"].shutdown is True
    assert interfaces["Ethernet1"].access_groups == {"in": "UPLINK-IN"}
    assert "Port-Channel10" in interfaces and interfaces["Loopback0"].addresses == [("10.255.0.1", "10.255.0.1/32")]
    assert config.routing == ["BGP", "OSPF"]
    assert config.notes == [MAC_ACCESS_LISTS, IPV6_ACCESS_LISTS, POLICY_BASED_ROUTES]
    assert config.stateful is False

    users = {e.sequence: e for e in config.access_lists["USERS-IN"]}
    assert list(users) == [20, 30, 40, 50, 60, 70]
    assert users[20].comment == "Web to the servers" and users[20].dst_ports == "443"
    assert (users[20].src, users[20].dst) == (["10.1.10.0/24"], ["10.20.0.0/24"])
    assert users[30].action == "deny" and users[30].dst_ports == "23" and users[30].unresolved == []
    assert users[40].src == ["10.1.10.0/24"] and users[40].dst_ports == "53,123"
    assert users[60].dst == ["10.30.0.5/32"]
    uplink = {e.sequence: e for e in config.access_lists["UPLINK-IN"]}
    assert uplink[10].established is True and uplink[20].protocol == "ospf"
    assert [(e.action, e.src) for e in config.access_lists["MGMT-ONLY"]] == [
        ("allow", ["192.168.1.0/24"]),
        ("deny", ["any"]),
    ]

    routes = {(r.vrf, r.prefix): r for r in config.static_routes}
    assert routes[("", "0.0.0.0/0")].next_hop == "10.0.0.0"
    assert routes[("", "10.9.0.0/16")].interface == "Null0"
    floating = routes[("", "10.40.0.0/16")]
    assert (floating.distance, floating.name) == (200, "FLOAT")
    assert routes[("TENANT-A", "0.0.0.0/0")].name == "TENANT-DEFAULT"
    assert routes[("MGMT", "0.0.0.0/0")].next_hop == "192.168.1.1"


def test_eos_vrf_all_capture_reads_every_vrf():
    routes, missing = parse_route_table(EOS_VRF_ALL, "arista_eos")
    assert missing == []
    found = _by_prefix(routes)
    assert found["|0.0.0.0/0"][0]["kind"] == "default" and found["|0.0.0.0/0"][0]["interface"] == "Ethernet1"
    assert found["|10.1.11.0/24"][0]["interface"] == "Vlan10"
    assert found["|10.5.0.0/16"][0]["source"] == "OSPF external type 2"
    assert found["|10.6.0.0/16"][0]["source"] == "BGP external"
    assert found["|10.9.0.0/16"][0]["kind"] == "blackhole"
    assert found["TENANT-A|0.0.0.0/0"][0]["next_hop"] == "10.20.0.254"
    assert found["TENANT-A|10.20.0.0/24"][0]["kind"] == "connected"
    assert [(r["next_hop"], r["source"]) for r in found["TENANT-A|10.21.0.0/16"]] == [
        ("10.255.0.9", "BGP internal"),
        ("10.255.0.10", "BGP internal"),
    ]
    # Older releases print ``VRF name:``.
    older, _missing = parse_route_table(EOS_VRF_ALL.replace("VRF: TENANT-A", "VRF name: TENANT-A"), "arista_eos")
    assert "TENANT-A|10.20.0.0/24" in _by_prefix(older)


def test_eos_forwarding_block_binds_acls_and_adds_missing_vrfs():
    host = {"ip_address": "10.255.0.1", "device_type": "arista_eos"}
    capture = EOS_VRF_ALL.split("VRF: TENANT-A")[0]
    block = forwarding_for_host(
        host,
        [],
        {"id": 1, "routes_text": capture},
        [{"name": "Ethernet2", "admin_state": "down"}],
        config_backup={"config_text": EOS_CONFIG},
    )
    interfaces = _interfaces(block)
    assert interfaces["Vlan10"]["kind"] == "svi" and interfaces["Vlan10"]["zone"] == "Vlan10"
    varp = interfaces["Vlan10 (VARP 10.1.10.1)"]
    assert (varp["ip"], varp["cidr"], varp["zone"]) == ("10.1.10.1", "10.1.10.0/24", "Vlan10")
    assert interfaces["Vlan20 (VRRP 10.20.0.1)"]["vrf"] == "TENANT-A"
    assert interfaces["Management1"]["kind"] == "management" and interfaces["Ethernet2"]["enabled"] is False
    policies = _policies(block)
    assert list(policies) == ["ACL UPLINK-IN in on Ethernet1", "ACL USERS-IN in on Vlan10"]
    users = policies["ACL USERS-IN in on Vlan10"]
    assert (users["interface"], users["direction"], users["stateful"], users["default"]) == (
        "Vlan10",
        "in",
        False,
        "deny",
    )
    routes = _by_prefix(block["routes"])
    # The capture holds the global table; TENANT-A and MGMT come from the configuration.
    assert routes["|10.5.0.0/16"][0]["source"] == "OSPF external type 2"
    assert "|10.40.0.0/16" not in routes
    assert routes["TENANT-A|0.0.0.0/0"][0]["source"] == "Static route TENANT-DEFAULT"
    assert routes["TENANT-A|10.20.0.0/24"][0]["kind"] == "connected"
    assert routes["MGMT|192.168.1.0/24"][0]["interface"] == "Management1"
    assert block["not_collected"] == [MAC_ACCESS_LISTS, IPV6_ACCESS_LISTS, POLICY_BASED_ROUTES]


# ── Cisco IOS-XR ─────────────────────────────────────────────────────────────

XR_CONFIG = """\
Mon Oct 12 10:00:00.123 UTC
Building configuration...
!! IOS XR Configuration 7.5.2
!! Last configuration change at Mon Oct 12 09:58:01 2026 by admin
!
hostname xr-pe1
vrf CUST-A
 address-family ipv4 unicast
  import route-target
   65000:100
  !
 !
!
interface Loopback0
 ipv4 address 10.255.0.1 255.255.255.255
!
interface MgmtEth0/RP0/CPU0/0
 vrf MGMT
 ipv4 address 192.168.1.20 255.255.255.0
!
interface GigabitEthernet0/0/0/0
 description To core
 ipv4 address 10.0.0.2 255.255.255.252
 ipv4 access-group EDGE-IN ingress
!
interface GigabitEthernet0/0/0/1
 description Customer A
 vrf CUST-A
 ipv4 address 10.50.0.2 255.255.255.0
 ipv4 address 10.51.0.2 255.255.255.0 secondary
 ipv4 access-group CUST-OUT egress
 ipv6 access-group CUST6 ingress
!
interface GigabitEthernet0/0/0/2
 shutdown
!
object-group network ipv4 MGMT-HOSTS
 10.9.0.0/24
 host 10.9.1.10
!
object-group port SSH-PORTS
 eq 22
 range 8000 8080
!
ipv4 access-list EDGE-IN
 10 remark Management
 20 permit tcp net-group MGMT-HOSTS any port-group SSH-PORTS
 30 permit tcp 10.0.0.0 0.0.0.3 any eq 22
 40 permit ipv4 any 10.50.0.0/24 counter EDGE
 50 permit ipv4 any any nexthop1 ipv4 10.0.0.9
 60 deny ipv4 any any
!
ipv4 access-list CUST-OUT
 10 permit tcp any any established
 20 permit icmp any any
 30 deny ipv4 any any
!
router static
 address-family ipv4 unicast
  0.0.0.0/0 10.0.0.1
  10.9.0.0/16 Null0
  10.40.0.0/16 10.0.0.1 200
 !
 address-family ipv6 unicast
  ::/0 2001:db8::1
 !
 vrf CUST-A
  address-family ipv4 unicast
   0.0.0.0/0 GigabitEthernet0/0/0/1 10.50.0.254 description CUST-DEFAULT
  !
 !
 vrf MGMT
  address-family ipv4 unicast
   0.0.0.0/0 192.168.1.1
  !
 !
!
router ospf CORE
 area 0
  interface GigabitEthernet0/0/0/0
  !
 !
!
router bgp 65000
 bgp router-id 10.255.0.1
!
router vrrp
 interface GigabitEthernet0/0/0/1
  address-family ipv4
   vrrp 1
    priority 110
    address 10.50.0.1
   !
  !
 !
!
router hsrp
 interface GigabitEthernet0/0/0/0
  address-family ipv4
   hsrp 2
    address 10.0.0.3
   !
  !
 !
!
end
"""

XR_ROUTES = """\
Mon Oct 12 10:01:02.123 UTC

Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2, E - EGP
       i - ISIS, L1 - IS-IS level-1, L2 - IS-IS level-2
       ia - IS-IS inter area, su - IS-IS summary null, * - candidate default
       U - per-user static route, o - ODR, L - local, G  - DAGR, l - LISP
       A - access/subscriber, a - Application route
       M - mobile route, r - RPL, t - Traffic Engineering, (!) - FRR Backup path

Gateway of last resort is 10.0.0.1 to network 0.0.0.0

S*   0.0.0.0/0 [1/0] via 10.0.0.1, 2w0d
C    10.0.0.0/30 is directly connected, 2w0d, GigabitEthernet0/0/0/0
L    10.0.0.2/32 is directly connected, 2w0d, GigabitEthernet0/0/0/0
O    10.2.0.0/16 [110/2] via 10.0.0.1, 1d02h, GigabitEthernet0/0/0/0
               [110/2] via 10.0.0.5, 1d02h, GigabitEthernet0/0/0/0
O E2 10.5.0.0/16 [110/20] via 10.0.0.1, 1d02h, GigabitEthernet0/0/0/0
i L2 10.6.0.0/16 [115/20] via 10.0.0.1, 00:12:01, GigabitEthernet0/0/0/0
B    172.16.0.0/16 [200/0] via 10.255.0.2, 3d04h
S    10.9.0.0/16 is directly connected, 2w0d, Null0
L    10.255.0.1/32 is directly connected, 2w0d, Loopback0

VRF: CUST-A

Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path

Gateway of last resort is 10.50.0.254 to network 0.0.0.0

S*   0.0.0.0/0 [1/0] via 10.50.0.254, 1d02h, GigabitEthernet0/0/0/1
C    10.50.0.0/24 is directly connected, 1d02h, GigabitEthernet0/0/0/1
L    10.50.0.2/32 is directly connected, 1d02h, GigabitEthernet0/0/0/1
B    10.60.0.0/16 [200/0] via 10.255.0.2 (nexthop in vrf default), 3d04h
"""


def test_xr_config_reads_ipv4_interfaces_groups_router_static_and_vrrp():
    config = parse_config(XR_CONFIG)
    interfaces = {i.name: i for i in config.interfaces}
    edge = interfaces["GigabitEthernet0/0/0/0"]
    assert edge.addresses == [("10.0.0.2", "10.0.0.0/30")] and edge.access_groups == {"in": "EDGE-IN"}
    assert [(v.protocol, v.group, v.address) for v in edge.virtual] == [("HSRP", "2", "10.0.0.3")]
    cust = interfaces["GigabitEthernet0/0/0/1"]
    assert cust.vrf == "CUST-A" and cust.access_groups == {"out": "CUST-OUT"}
    assert cust.addresses == [("10.50.0.2", "10.50.0.0/24"), ("10.51.0.2", "10.51.0.0/24")]
    assert [(v.protocol, v.group, v.address) for v in cust.virtual] == [("VRRP", "1", "10.50.0.1")]
    assert interfaces["MgmtEth0/RP0/CPU0/0"].vrf == "MGMT" and interfaces["GigabitEthernet0/0/0/2"].shutdown
    assert config.routing == ["OSPF", "BGP"] and config.notes == [IPV6_ACCESS_LISTS]

    edge_in = {e.sequence: e for e in config.access_lists["EDGE-IN"]}
    assert edge_in[20].comment == "Management" and edge_in[20].src == ["10.9.0.0/24", "10.9.1.10/32"]
    assert edge_in[20].dst_ports == "22,8000-8080" and edge_in[20].unresolved == []
    assert edge_in[30].src == ["10.0.0.0/30"] and edge_in[30].dst_ports == "22"
    # ``ipv4`` is any IP protocol; a counter only counts.
    assert (edge_in[40].protocol, edge_in[40].dst, edge_in[40].unresolved) == ("ip", ["10.50.0.0/24"], [])
    # An ABF next hop redirects the flow: never decided.
    assert edge_in[50].unresolved == ["nexthop1 ipv4 10.0.0.9"]
    assert config.access_lists["CUST-OUT"][0].established is True

    routes = {(r.vrf, r.prefix): r for r in config.static_routes}
    assert set(routes) == {
        ("", "0.0.0.0/0"),
        ("", "10.9.0.0/16"),
        ("", "10.40.0.0/16"),
        ("CUST-A", "0.0.0.0/0"),
        ("MGMT", "0.0.0.0/0"),
    }
    assert routes[("", "10.40.0.0/16")].distance == 200 and routes[("", "10.9.0.0/16")].interface == "Null0"
    cust_default = routes[("CUST-A", "0.0.0.0/0")]
    assert (cust_default.interface, cust_default.next_hop, cust_default.name) == (
        "GigabitEthernet0/0/0/1",
        "10.50.0.254",
        "CUST-DEFAULT",
    )


def test_xr_capture_reads_uptimes_before_interfaces_and_vrfs():
    routes, missing = parse_route_table(XR_ROUTES, "cisco_xr")
    assert missing == []
    found = _by_prefix(routes)
    assert found["|0.0.0.0/0"][0]["kind"] == "default" and found["|0.0.0.0/0"][0]["interface"] == ""
    connected = found["|10.0.0.0/30"][0]
    assert (connected["kind"], connected["interface"]) == ("connected", "GigabitEthernet0/0/0/0")
    assert found["|10.0.0.2/32"][0]["source"] == "Local address"
    assert [r["next_hop"] for r in found["|10.2.0.0/16"]] == ["10.0.0.1", "10.0.0.5"]
    assert found["|10.5.0.0/16"][0]["source"] == "OSPF external type 2"
    assert found["|10.6.0.0/16"][0]["source"] == "IS-IS level 2"
    assert found["|10.9.0.0/16"][0]["kind"] == "blackhole"
    assert found["|10.255.0.1/32"][0]["interface"] == "Loopback0"
    assert found["CUST-A|10.50.0.0/24"][0]["interface"] == "GigabitEthernet0/0/0/1"
    assert found["CUST-A|10.60.0.0/16"][0]["next_hop"] == "10.255.0.2"


def test_xr_forwarding_block():
    host = {"ip_address": "10.0.0.2", "device_type": "cisco_xr"}
    snmp = [{"name": "Mg0/RP0/CPU0/0", "admin_state": "up"}, {"name": "TenGigE0/0/0/5", "admin_state": "up"}]
    capture = XR_ROUTES.split("VRF: CUST-A")[0]
    block = forwarding_for_host(
        host, [], {"id": 1, "routes_text": capture}, snmp, config_backup={"config_text": XR_CONFIG}
    )
    interfaces = _interfaces(block)
    assert interfaces["MgmtEth0/RP0/CPU0/0"]["kind"] == "management" and "Mg0/RP0/CPU0/0" not in interfaces
    assert interface_key("TenGigE0/0/0/5") == interface_key("Te0/0/0/5")
    assert interfaces["GigabitEthernet0/0/0/1 (VRRP 10.50.0.1)"]["cidr"] == "10.50.0.0/24"
    assert interfaces["GigabitEthernet0/0/0/0 (HSRP 10.0.0.3)"]["zone"] == "GigabitEthernet0/0/0/0"
    assert interfaces["GigabitEthernet0/0/0/2"]["enabled"] is False
    policies = _policies(block)
    assert list(policies) == ["ACL EDGE-IN in on GigabitEthernet0/0/0/0", "ACL CUST-OUT out on GigabitEthernet0/0/0/1"]
    out = policies["ACL CUST-OUT out on GigabitEthernet0/0/0/1"]
    assert out["direction"] == "out" and out["rules"][0]["dst_zones"] == ["GigabitEthernet0/0/0/1"]
    routes = _by_prefix(block["routes"])
    assert routes["CUST-A|0.0.0.0/0"][0]["interface"] == "GigabitEthernet0/0/0/1"
    assert routes["CUST-A|10.50.0.0/24"][0]["kind"] == "connected"
    assert routes["MGMT|0.0.0.0/0"][0]["next_hop"] == "192.168.1.1"
    assert "|10.40.0.0/16" not in routes and routes["|10.6.0.0/16"][0]["source"] == "IS-IS level 2"


# ── Aruba AOS-CX ─────────────────────────────────────────────────────────────

AOSCX_CONFIG = """\
Current configuration:
!
!Version ArubaOS-CX FL.10.13.1000
!export-password: default
hostname cx-core1
user admin group administrators password ciphertext AQBapWg...
!
!
vrf TENANT-A
ntp server pool.ntp.org minpoll 4 maxpoll 4 iburst
ntp enable
!
ssh server vrf mgmt
object-group ip address SERVERS
    10 10.20.0.10
    20 10.20.1.0/24
object-group port WEB
    10 eq 443
    20 range 8000 8080
access-list ip USERS-IN
    10 comment Web to the servers
    10 permit tcp 10.1.10.0/255.255.255.0 SERVERS group WEB
    20 deny tcp any any eq 23 log
    30 permit icmp any any count
    40 permit any 10.1.10.0/24 10.30.0.0/24
    50 permit udp any any range 1024 65535 dscp AF11
    60 deny any any any
access-list ip UPLINK-IN
    10 permit tcp any 10.1.10.0/24 established
    20 permit icmp any any
    30 deny any any any
access-list ipv6 USERS6-IN
    10 permit any any any
!
vlan 1
vlan 10
    name Users
    apply access-list ip VLAN10-BRIDGED in
vlan 20
    name Tenant
spanning-tree
interface mgmt
    no shutdown
    ip static 192.168.1.30/24
    default-gateway 192.168.1.1
interface lag 1
    no shutdown
    no routing
    vlan trunk native 1
    vlan trunk allowed all
    lacp mode active
interface 1/1/1
    no shutdown
    description To dc-rtr1
    ip address 10.0.0.1/30
    apply access-list ip UPLINK-IN in
interface 1/1/2
    no shutdown
    no routing
    vlan access 10
interface 1/1/3
    shutdown
interface vlan 10
    description Users
    ip address 10.1.10.2/24
    ip address 10.1.11.2/24 secondary
    active-gateway ip mac 12:00:00:00:01:00
    active-gateway ip 10.1.10.1
    apply access-list ip USERS-IN routed-in
    apply access-list ipv6 USERS6-IN routed-in
    ip helper-address 10.20.0.10
interface vlan 20
    vrf attach TENANT-A
    ip address 10.20.0.2/24
    vrrp 20 address-family ipv4
        address 10.20.0.1 primary
        no shutdown
    apply policy QOS-MARK routed-in
!
vsx
    inter-switch-link lag 256
    role primary
    keepalive peer 192.168.255.2 source 192.168.255.1
ip route 0.0.0.0/0 10.0.0.2
ip route 10.9.0.0/16 blackhole
ip route 10.8.0.0/16 reject
ip route 10.40.0.0/16 10.0.0.2 distance 200
ip route 0.0.0.0/0 10.20.0.254 vrf TENANT-A
router ospf 1
    router-id 10.255.0.1
    area 0.0.0.0
!
https-server vrf mgmt
"""

AOSCX_ROUTES = """\
Displaying ipv4 routes selected for forwarding

Origin Codes: C - connected, S - static, L - local
              R - RIP, B - BGP, O - OSPF
Type Codes:   E - External BGP, I - Internal BGP, V - VPN, EV - EVPN
              IA - OSPF internal area, E1 - OSPF external type 1
              E2 - OSPF external type 2

VRF: default

Prefix              Nexthop          Interface     VRF(egress)       Origin/  Distance/    Age
                                                                     Type     Metric
--------------------------------------------------------------------------------------------------------
0.0.0.0/0           10.0.0.2         1/1/1         -                 S        [1/0]        01h:02m:03s
10.0.0.0/30         -                1/1/1         -                 C        [0/0]        -
10.0.0.1/32         -                1/1/1         -                 L        [0/0]        -
10.1.10.0/24        -                vlan10        -                 C        [0/0]        -
10.1.10.2/32        -                vlan10        -                 L        [0/0]        -
10.2.0.0/16         10.0.0.2         1/1/1         -                 O        [110/20]     00h:10m:01s
                    10.0.0.6         vlan10        -                          [110/20]     00h:10m:01s
10.5.0.0/16         10.0.0.2         1/1/1         -                 O/E2     [110/1]      00h:10m:01s
172.16.0.0/16       10.255.0.2       1/1/1         -                 B/I      [200/0]      1d:02h:03m

Total Route Count : 8

VRF: TENANT-A

Prefix              Nexthop          Interface     VRF(egress)       Origin/  Distance/    Age
                                                                     Type     Metric
--------------------------------------------------------------------------------------------------------
0.0.0.0/0           10.20.0.254      vlan20        -                 S        [1/0]        01h:02m:03s
10.20.0.0/24        -                vlan20        -                 C        [0/0]        -
"""

AOSCX_OLD_ROUTES = """\
Displaying ipv4 routes selected for forwarding

'[x/y]' denotes [distance/metric]

0.0.0.0/0, vrf default
\tvia  10.0.0.2,  [1/0],  static
10.0.0.0/30, vrf default
\tvia  1/1/1,  [0/0],  connected
10.1.10.0/24, vrf default
\tvia  vlan10,  [0/0],  connected
10.2.0.0/16, vrf default, 2 unicast next-hops
\tvia  10.0.0.2,  [110/20],  ospf
\tvia  10.0.0.6,  [110/20],  ospf
10.20.0.0/24, vrf TENANT-A
\tvia  vlan20,  [0/0],  connected
"""


def test_aoscx_config_reads_interfaces_access_lists_and_routes():
    config = aruba_config.parse_config(AOSCX_CONFIG)
    interfaces = {i.name: i for i in config.interfaces}
    vlan10 = interfaces["vlan10"]
    assert vlan10.addresses == [("10.1.10.2", "10.1.10.0/24"), ("10.1.11.2", "10.1.11.0/24")]
    assert vlan10.access_groups == {"in": "USERS-IN"} and vlan10.description == "Users"
    assert [(v.protocol, v.address) for v in vlan10.virtual] == [("Active gateway", "10.1.10.1")]
    vlan20 = interfaces["vlan20"]
    assert vlan20.vrf == "TENANT-A" and [(v.protocol, v.group, v.address) for v in vlan20.virtual] == [
        ("VRRP", "20", "10.20.0.1")
    ]
    uplink = interfaces["1/1/1"]
    assert uplink.addresses == [("10.0.0.1", "10.0.0.0/30")] and uplink.access_groups == {"in": "UPLINK-IN"}
    assert interfaces["1/1/3"].shutdown is True and interfaces["1/1/2"].shutdown is False
    assert "lag1" in interfaces
    assert (interfaces["mgmt"].vrf, interfaces["mgmt"].addresses) == ("mgmt", [("192.168.1.30", "192.168.1.0/24")])
    assert config.routing == ["OSPF"] and config.stateful is False
    assert config.notes == [VLAN_ACCESS_LISTS, IPV6_ACCESS_LISTS, CLASSIFIER_POLICIES, VSX]

    users = {e.sequence: e for e in config.access_lists["USERS-IN"]}
    assert users[10].comment == "Web to the servers" and users[10].src == ["10.1.10.0/24"]
    assert users[10].dst == ["10.20.0.10/32", "10.20.1.0/24"] and users[10].dst_ports == "443,8000-8080"
    assert users[20].dst_ports == "23" and users[20].unresolved == []
    assert users[30].protocol == "icmp" and users[30].unresolved == []
    assert (users[40].protocol, users[40].src, users[40].dst) == ("any", ["10.1.10.0/24"], ["10.30.0.0/24"])
    assert users[50].dst_ports == "1024-65535" and users[50].unresolved == ["dscp AF11"]
    assert (users[60].action, users[60].src, users[60].dst) == ("deny", ["any"], ["any"])
    assert config.access_lists["UPLINK-IN"][0].established is True

    routes = {(r.vrf, r.prefix): r for r in config.static_routes}
    assert routes[("", "0.0.0.0/0")].next_hop == "10.0.0.2"
    assert routes[("", "10.9.0.0/16")].interface == "blackhole" and routes[("", "10.8.0.0/16")].interface == "reject"
    assert routes[("", "10.40.0.0/16")].distance == 200
    assert routes[("TENANT-A", "0.0.0.0/0")].next_hop == "10.20.0.254"
    assert routes[("mgmt", "0.0.0.0/0")].next_hop == "192.168.1.1"


def test_aoscx_route_captures_in_both_formats():
    routes, missing = parse_route_table(AOSCX_ROUTES, "aruba_aoscx")
    assert missing == []
    found = _by_prefix(routes)
    default = found["|0.0.0.0/0"][0]
    assert (default["kind"], default["next_hop"], default["interface"]) == ("default", "10.0.0.2", "1/1/1")
    connected = found["|10.1.10.0/24"][0]
    assert (connected["kind"], connected["interface"], connected["next_hop"]) == ("connected", "vlan10", "")
    assert found["|10.1.10.2/32"][0]["source"] == "Local address"
    ospf = found["|10.2.0.0/16"]
    assert [(r["next_hop"], r["interface"], r["metric"], r["source"]) for r in ospf] == [
        ("10.0.0.2", "1/1/1", 20, "OSPF"),
        ("10.0.0.6", "vlan10", 20, "OSPF"),
    ]
    assert found["|10.5.0.0/16"][0]["source"] == "OSPF external type 2"
    assert found["|172.16.0.0/16"][0]["source"] == "BGP internal"
    assert found["TENANT-A|0.0.0.0/0"][0]["interface"] == "vlan20"
    assert found["TENANT-A|10.20.0.0/24"][0]["kind"] == "connected"

    old, missing = parse_route_table(AOSCX_OLD_ROUTES, "aruba_aoscx")
    assert missing == []
    found = _by_prefix(old)
    assert found["|0.0.0.0/0"][0]["kind"] == "default" and found["|0.0.0.0/0"][0]["next_hop"] == "10.0.0.2"
    assert found["|10.0.0.0/30"][0]["interface"] == "1/1/1"
    assert [r["next_hop"] for r in found["|10.2.0.0/16"]] == ["10.0.0.2", "10.0.0.6"]
    assert found["TENANT-A|10.20.0.0/24"][0]["interface"] == "vlan20"


def test_aoscx_forwarding_block():
    host = {"ip_address": "10.0.0.1", "device_type": "aruba_aoscx"}
    snmp = [{"name": "1/1/1", "admin_state": "up"}, {"name": "vlan10", "admin_state": "up"}]
    capture = AOSCX_ROUTES.split("VRF: TENANT-A")[0]
    block = forwarding_for_host(
        host, [], {"id": 1, "routes_text": capture}, snmp, config_backup={"config_text": AOSCX_CONFIG}
    )
    interfaces = _interfaces(block)
    assert interfaces["vlan10"]["kind"] == "svi" and interfaces["1/1/1"]["kind"] == "routed"
    gateway = interfaces["vlan10 (Active gateway 10.1.10.1)"]
    assert (gateway["ip"], gateway["cidr"], gateway["zone"]) == ("10.1.10.1", "10.1.10.0/24", "vlan10")
    assert interfaces["vlan20 (VRRP 10.20.0.1)"]["vrf"] == "TENANT-A"
    assert interfaces["mgmt"]["kind"] == "management" and interfaces["1/1/3"]["enabled"] is False
    policies = _policies(block)
    assert list(policies) == ["ACL UPLINK-IN in on 1/1/1", "ACL USERS-IN in on vlan10"]
    routes = _by_prefix(block["routes"])
    assert routes["TENANT-A|0.0.0.0/0"][0]["next_hop"] == "10.20.0.254"
    assert routes["TENANT-A|10.20.0.0/24"][0]["interface"] == "vlan20"
    assert routes["mgmt|0.0.0.0/0"][0]["next_hop"] == "192.168.1.1"
    assert "|10.9.0.0/16" not in routes  # the capture holds the global table
    alone = forwarding_for_host(host, [], None, [], config_backup={"config_text": AOSCX_CONFIG})
    statics = _by_prefix(alone["routes"])
    assert statics["|10.9.0.0/16"][0]["kind"] == "blackhole" and statics["|10.8.0.0/16"][0]["kind"] == "blackhole"
    assert alone["not_collected"][-1] == "Routes learned by OSPF"


# ── Aruba AOS-Switch (ProCurve) ──────────────────────────────────────────────

AOS_SWITCH_CONFIG = """\
; J9850A Configuration Editor; Created on release #KB.16.10.0009
; Ver #14:01.4f.f8.1d.9b.3f.bf.bb.ef.7c.59.fc.6b.fb.9f.fc.ff.ff.37.ef:02
hostname "core-5406"
module A type j9990a
module B type j9990a
ip access-list extended "USERS-IN"
     10 remark "Web to the servers"
     10 permit tcp 10.1.10.0 0.0.0.255 10.20.0.0 0.0.0.255 eq 443
     20 deny tcp 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255 eq 23 log
     30 permit icmp 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255
     40 permit ip 10.1.10.0 0.0.0.255 host 10.30.0.5
     50 permit tcp any any precedence 5
     exit
ip access-list extended "Uplink In"
     10 permit tcp 0.0.0.0 255.255.255.255 10.1.10.0 0.0.0.255 established
     20 deny ip any any
     exit
ip access-list standard "MGMT"
     10 permit 192.168.1.0 0.0.0.255
     exit
ip routing
ip route 0.0.0.0 0.0.0.0 10.0.0.2
ip route 10.9.0.0 255.255.0.0 blackhole
ip route 10.40.0.0 255.255.0.0 10.0.0.2 distance 200
ip route 10.8.0.0 255.255.0.0 vlan 30
interface A1
   name "Uplink"
   exit
interface A2
   ip access-group "MGMT" in
   exit
router ospf
   area backbone
   exit
vlan 1
   name "DEFAULT_VLAN"
   untagged A1
   ip address 10.0.0.1 255.255.255.252
   ip access-group "Uplink In" in
   exit
vlan 10
   name "Users"
   untagged A3-A20
   ip address 10.1.10.2 255.255.255.0
   ip address 10.1.11.2 255.255.255.0
   ip helper-address 10.20.0.10
   ip access-group "USERS-IN" in
   vrrp vrid 10
      backup
      virtual-ip-address 10.1.10.1 255.255.255.0
      enable
      exit
   exit
vlan 30
   name "Voice"
   no ip address
   exit
vlan 40
   name "Printers"
   ip address 10.1.40.1 255.255.255.0
   ip access-group "MISSING" out
   exit
"""

AOS_SWITCH_ROUTES = """\

                                IP Route Entries

  Destination        Gateway         VLAN Type      Sub-Type   Metric     Dist.
  ------------------ --------------- ---- --------- ---------- ---------- -----
  0.0.0.0/0          10.0.0.2        1    static               1          1
  10.0.0.0/30        DEFAULT_VLAN    1    connected            1          0
  10.1.10.0/24       Users           10   connected            1          0
  10.1.11.0/24       Users           10   connected            1          0
  10.1.40.0/24       Printers        40   connected            1          0
  10.2.0.0/16        10.0.0.2        1    ospf      IntraArea  2          110
  10.9.0.0/16        blackhole            static               0          1
  127.0.0.0/8        reject               static               0          0
  127.0.0.1/32       lo0                  connected            1          0
"""


def test_aos_switch_config_reads_vlans_quoted_access_lists_and_routes():
    config = aruba_config.parse_config(AOS_SWITCH_CONFIG)
    interfaces = {i.name: i for i in config.interfaces}
    assert list(interfaces) == ["VLAN1", "VLAN10", "VLAN30", "VLAN40"]
    vlan1 = interfaces["VLAN1"]
    assert vlan1.aliases == ["DEFAULT_VLAN"] and vlan1.access_groups == {"in": "Uplink In"}
    vlan10 = interfaces["VLAN10"]
    # Every address after the first is a secondary one.
    assert vlan10.addresses == [("10.1.10.2", "10.1.10.0/24"), ("10.1.11.2", "10.1.11.0/24")]
    assert vlan10.aliases == ["Users"] and vlan10.access_groups == {"in": "USERS-IN"}
    assert [(v.protocol, v.group, v.address) for v in vlan10.virtual] == [("VRRP", "10", "10.1.10.1")]
    assert interfaces["VLAN30"].addresses == []
    assert config.routing == ["OSPF"] and config.notes == [PORT_ACCESS_LISTS]

    users = {e.sequence: e for e in config.access_lists["USERS-IN"]}
    assert users[10].comment == "Web to the servers" and users[10].dst_ports == "443"
    assert (users[10].src, users[10].dst) == (["10.1.10.0/24"], ["10.20.0.0/24"])
    # ``0.0.0.0 255.255.255.255`` is any.
    assert (users[20].src, users[20].dst, users[20].dst_ports) == (["any"], ["any"], "23")
    assert users[40].dst == ["10.30.0.5/32"]
    assert users[50].unresolved == ["precedence 5"]
    assert config.access_lists["Uplink In"][0].established is True
    assert config.access_lists["MGMT"][0].src == ["192.168.1.0/24"]

    routes = {r.prefix: r for r in config.static_routes}
    assert routes["0.0.0.0/0"].next_hop == "10.0.0.2" and routes["10.9.0.0/16"].interface == "blackhole"
    assert routes["10.40.0.0/16"].distance == 200 and routes["10.8.0.0/16"].interface == "VLAN30"


def test_aos_switch_route_capture():
    routes, missing = parse_route_table(AOS_SWITCH_ROUTES, "hp_procurve")
    assert missing == []
    found = _by_prefix(routes)
    default = found["|0.0.0.0/0"][0]
    assert (default["kind"], default["next_hop"], default["interface"]) == ("default", "10.0.0.2", "VLAN1")
    users = found["|10.1.10.0/24"][0]
    assert (users["kind"], users["interface"], users["next_hop"]) == ("connected", "VLAN10", "")
    ospf = found["|10.2.0.0/16"][0]
    assert (ospf["source"], ospf["metric"], ospf["interface"]) == ("OSPF IntraArea", 2, "VLAN1")
    assert found["|10.9.0.0/16"][0]["kind"] == "blackhole"
    assert not any(k.startswith("|127.") for k in found)


def test_aos_switch_forwarding_block_names_vlans_like_snmp():
    host = {"ip_address": "10.0.0.1", "device_type": "hp_procurve"}
    snmp = [{"name": "DEFAULT_VLAN", "admin_state": "up"}, {"name": "VLAN10", "admin_state": "up"}]
    block = forwarding_for_host(
        host,
        [],
        {"id": 1, "routes_text": AOS_SWITCH_ROUTES},
        snmp,
        config_backup={"config_text": AOS_SWITCH_CONFIG},
    )
    interfaces = _interfaces(block)
    assert "DEFAULT_VLAN" not in interfaces and interfaces["VLAN1"]["ip"] == "10.0.0.1"
    assert interfaces["VLAN10"]["kind"] == "svi" and interfaces["VLAN10"]["cidr"] == "10.1.10.0/24"
    assert interfaces["VLAN10 (VRRP 10.1.10.1)"]["zone"] == "VLAN10"
    assert interfaces["VLAN10 (secondary 10.1.11.2)"]["cidr"] == "10.1.11.0/24"
    policies = _policies(block)
    assert list(policies) == ["ACL Uplink In in on VLAN1", "ACL USERS-IN in on VLAN10", "ACL MISSING out on VLAN40"]
    assert policies["ACL MISSING out on VLAN40"]["default"] == "unknown"
    routes = _by_prefix(block["routes"])
    assert routes["|10.1.40.0/24"][0]["interface"] == "VLAN40"
    assert block["not_collected"] == [PORT_ACCESS_LISTS]


def test_platforms_read_the_four_dialects():
    for device_type in ("cisco_xr", "arista_eos", "aruba_aoscx", "hp_procurve", "aruba_osswitch"):
        platform = platform_of(device_type)
        assert platform.config is not None and platform.routes is not None and not platform.stateful
    assert platform_of("aruba_aoscx").config is aruba_config.parse_config
    assert platform_of("arista_eos").config is parse_config
    # A traffic policy on an EOS interface is noted.
    assert parse_config("interface Ethernet1\n   traffic-policy input EDGE\n").notes == [TRAFFIC_POLICIES]


# ── A trace through an AOS-CX switch ─────────────────────────────────────────

_CX_SWITCH = """\
!Version ArubaOS-CX FL.10.13.1000
hostname cx-core1
object-group ip address SERVERS
    10 10.20.0.0/24
access-list ip USERS-IN
    10 comment Web to the servers
    10 permit tcp 10.1.10.0/24 SERVERS eq 443
    20 deny tcp any any eq 23
    30 permit icmp any any
access-list ip UPLINK-IN
    10 permit tcp any 10.1.10.0/24 established
    20 permit icmp any any
    30 deny any any any
interface 1/1/1
    no shutdown
    description To dc-rtr1
    ip address 10.0.0.1/30
    apply access-list ip UPLINK-IN in
interface vlan 10
    description Users
    ip address 10.1.10.2/24
    active-gateway ip mac 12:00:00:00:01:00
    active-gateway ip 10.1.10.1
    apply access-list ip USERS-IN routed-in
ip route 0.0.0.0/0 10.0.0.2
"""


def test_aoscx_vlan_acl_decides_and_the_uplink_acl_lets_established_replies_in():
    from netcontrol.integrations.pathtrace.inventory import subnets_for_host
    from netcontrol.integrations.pathtrace.model import INVENTORY_ORG_REF

    nodes = [dict(_CATALYST_NODES[0], label="cx-core1", device_type="aruba_aoscx"), _CATALYST_NODES[1]]
    core = forwarding_for_host(
        {"ip_address": "10.0.0.1", "device_type": "aruba_aoscx"},
        [],
        None,
        [],
        config_backup={"config_text": _CX_SWITCH},
    )
    router = forwarding_for_host(
        {"ip_address": "10.0.0.2", "device_type": "cisco_ios"},
        [],
        {"id": 1, "routes_text": _ROUTER_CAPTURE},
        [],
        config_backup={"config_text": _ROUTER_CONFIG},
    )
    subnets = [*subnets_for_host(nodes[0], core), *subnets_for_host(nodes[1], router)]
    lldp = {"id": "lldp:7:8", "from": 7, "to": 8, "protocol": "lldp", "status": "up"}
    tracer = _tracer({}, hosts={7: core, 8: router}, extra_nodes=nodes, extra_edges=[lldp], subnets=subnets)
    source_node = tracer.graph_of[(INVENTORY_ORG_REF, "7")]
    assert source_node == 7 and tracer.ip_owner["10.1.10.1"] == [7]

    blocked = tracer.trace("10.1.10.0/24", "10.20.0.10", source_node=source_node, protocol="tcp", port=23)
    assert blocked["verdict"] == "blocked"
    [hop] = blocked["request"]["hops"]
    assert hop["provider"] == "inventory" and hop["in"] == "vlan10" and hop["out"] == "1/1/1"
    acl = next(i for i in hop["items"] if i["status"] == "blocked")
    assert acl["where"] == "ACL USERS-IN in on vlan10" and acl["rule"] == 20

    allowed = tracer.trace("10.1.10.0/24", "10.20.0.10", source_node=source_node, protocol="tcp", port=443)
    assert allowed["verdict"] == "allowed", allowed["summary"]
    assert _labels(allowed["request"]) == ["cx-core1", "dc-rtr1"] and _labels(allowed["reply"]) == [
        "dc-rtr1",
        "cx-core1",
    ]
    permit = next(i for i in allowed["request"]["hops"][0]["items"] if i["where"] == "ACL USERS-IN in on vlan10")
    assert permit["status"] == "ok" and permit["rule"] == 10 and "Web to the servers" in permit["text"]
    back = allowed["reply"]["hops"][1]
    assert back["in"] == "1/1/1" and back["out"] == "vlan10"
    uplink = next(i for i in back["items"] if i["where"] == "ACL UPLINK-IN in on 1/1/1")
    assert uplink["status"] == "ok" and uplink["rule"] == 10 and "established" in uplink["text"]

    # A connection opened from the servers is no established reply: the uplink ACL denies it.
    opened = tracer.trace("10.20.0.10", "10.1.10.5", protocol="tcp", port=22)
    assert opened["verdict"] == "blocked"
    denied = next(i for i in opened["request"]["hops"][1]["items"] if i["status"] == "blocked")
    assert denied["where"] == "ACL UPLINK-IN in on 1/1/1" and denied["rule"] == 30

    # The active gateway address answers on the switch.
    gateway = tracer.trace("10.20.0.10", "10.1.10.1", protocol="icmp")
    route = next(i for i in gateway["request"]["hops"][-1]["items"] if i["stage"] == "route")
    assert route["text"] == "10.1.10.1 is an address of this device (vlan10 (Active gateway 10.1.10.1))."
