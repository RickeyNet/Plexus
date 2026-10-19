"""Tests for the Cisco ASA / FTD configuration reader (path tracing).

``asa_config.parse_config`` reads an ASA 9.x running configuration, or an
FTD's LINA ``show running-config``, into a ``RunningConfig``;
``forwarding_for_host`` turns it into the forwarding block of an inventory
host, and the tracer walks a flow over it.
"""

from __future__ import annotations

from netcontrol.integrations.meraki.forwarding import ANY, INTERFACE
from netcontrol.integrations.pathtrace.asa_config import (
    CONTEXTS,
    ETHERTYPE_ACCESS_LISTS,
    INSPECTION,
    REMOTE_ACCESS_VPN,
    SECURITY_LEVELS,
    SITE_TO_SITE_VPN,
    parse_config,
)
from netcontrol.integrations.pathtrace.inventory import forwarding_for_host, subnets_for_host
from netcontrol.integrations.pathtrace.platforms import platform_of

from test_path_trace import _labels, _tracer
from test_path_trace_inventory import ASA as ASA_CAPTURE

ASA_CONFIG = """\
: Saved
:
: Serial Number: JAD12345678
: Hardware:   ASA5516, 8192 MB RAM
:
ASA Version 9.16(4)
!
hostname edge-fw1
names
!
interface GigabitEthernet0/0
 description Internet uplink
 nameif outside
 security-level 0
 ip address 10.0.0.1 255.255.255.248 standby 10.0.0.3
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 10.1.0.1 255.255.255.0 standby 10.1.0.2
!
interface GigabitEthernet0/2
 nameif dmz
 security-level 50
 ip address 10.2.0.1 255.255.255.0
!
interface GigabitEthernet0/3
 shutdown
 no nameif
 no security-level
 no ip address
!
interface GigabitEthernet0/4.20
 vlan 20
 nameif guest
 security-level 50
 ip address 10.3.0.1 255.255.255.0
!
interface Management0/0
 management-only
 nameif management
 security-level 100
 ip address 192.168.100.1 255.255.255.0
!
object network WEB-SERVER
 host 10.2.0.10
object network INSIDE-NET
 subnet 10.1.0.0 255.255.255.0
object network DHCP-RANGE
 range 10.1.0.100 10.1.0.131
object network CLOUD-APP
 fqdn v4 app.example.com
object network WEB-PUBLIC
 host 10.0.0.5
object service HTTPS-ALT
 service tcp destination eq 8443
object service HTTPS
 service tcp destination eq https
object-group network SERVERS
 description Server farm
 network-object host 10.2.0.10
 network-object 10.2.0.128 255.255.255.128
 network-object object WEB-SERVER
object-group network REMOTE-NETS
 network-object 172.16.0.0 255.240.0.0
object-group network APP-HOSTS
 network-object object CLOUD-APP
 network-object host 10.2.0.20
object-group service WEB-PORTS tcp
 port-object eq www
 port-object eq https
object-group service MIXED
 service-object tcp destination eq ssh
 service-object udp destination range 5000 5010
 service-object object HTTPS-ALT
object-group protocol TCPUDP
 protocol-object tcp
 protocol-object udp
object-group icmp-type PINGS
 icmp-object echo
 icmp-object echo-reply
access-list inside_in remark Web out
access-list inside_in extended permit tcp object INSIDE-NET any object-group WEB-PORTS
access-list inside_in extended permit object-group TCPUDP any any eq domain
access-list inside_in extended permit tcp any object-group MISSING-NETS eq 8443
access-list inside_in extended deny tcp any any eq sqlnet inactive
access-list inside_in extended permit tcp any host 10.2.0.10 eq ssh time-range WORK-HOURS
access-list inside_in extended permit icmp any any object-group PINGS
access-list inside_in extended permit object-group MIXED any object-group SERVERS
access-list inside_in extended permit tcp any object-group APP-HOSTS eq 9000
access-list inside_in extended permit tcp any range 1024 65535 interface dmz eq 8080
access-list inside_in extended deny ip any any log
access-list outside_in extended permit tcp any object WEB-SERVER eq https
access-list outside_in extended permit tcp any host 10.2.0.10 range 8000 8080 log 6 interval 300
access-list dmz_out extended permit tcp any any eq https
access-list dmz_out extended deny ip any any
access-list VPN-CRYPTO extended permit ip object INSIDE-NET object-group REMOTE-NETS
access-list SPLIT standard permit 10.1.0.0 255.255.255.0
access-list BPDU ethertype permit bpdu
access-group inside_in in interface inside
access-group outside_in in interface outside
access-group dmz_out out interface dmz
route outside 0.0.0.0 0.0.0.0 10.0.0.2 1
route inside 10.50.0.0 255.255.0.0 10.1.0.254 1 track 1
route outside 0.0.0.0 0.0.0.0 10.0.0.4 tunneled
router ospf 1
 network 10.1.0.0 255.255.255.0 area 0
!
object network INSIDE-NET
 nat (inside,outside) dynamic interface
object network WEB-SERVER
 nat (dmz,outside) static WEB-PUBLIC service tcp https 8443
object network DHCP-RANGE
 nat (inside,outside) static 10.0.0.6
nat (inside,outside) source static INSIDE-NET INSIDE-NET destination static REMOTE-NETS REMOTE-NETS no-proxy-arp route-lookup
nat (dmz,outside) source static CLOUD-APP CLOUD-APP
nat (inside,outside) after-auto source dynamic any interface description Hide the rest
crypto map OUTSIDE_MAP 10 match address VPN-CRYPTO
crypto map OUTSIDE_MAP 10 set peer 203.0.113.50
crypto map OUTSIDE_MAP interface outside
tunnel-group 203.0.113.50 type ipsec-l2l
!
class-map inspection_default
 match default-inspection-traffic
policy-map global_policy
 class inspection_default
  inspect dns
service-policy global_policy global
: end
"""

FTD_CONFIG = """\
NGFW Version 7.2.5
!
hostname branch-ftd1
!
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 198.51.100.2 255.255.255.0
!
interface GigabitEthernet0/1
 nameif inside
 security-level 0
 ip address 10.10.0.1 255.255.255.0
!
object-group network |acSrcNwGrp-268435457
 network-object 10.10.0.0 255.255.255.0
object-group service |acSvcg-268435458
 service-object tcp destination eq https
 service-object udp destination eq 443
access-list CSM_FW_ACL_ remark rule-id 268434432: PREFILTER POLICY: Default Tunnel and Priority Policy
access-list CSM_FW_ACL_ remark rule-id 268434432: RULE: DEFAULT TUNNEL ACTION RULE
access-list CSM_FW_ACL_ advanced permit ipinip any any rule-id 268434432
access-list CSM_FW_ACL_ remark rule-id 268435457: ACCESS POLICY: Branch - Mandatory
access-list CSM_FW_ACL_ remark rule-id 268435457: L4 RULE: Inside_DNS
access-list CSM_FW_ACL_ advanced permit udp ifc inside object-group |acSrcNwGrp-268435457 ifc outside any eq domain rule-id 268435457
access-list CSM_FW_ACL_ advanced trust tcp ifc inside any ifc outside host 198.51.100.53 eq 853 rule-id 268435457 event-log flow-end
access-list CSM_FW_ACL_ remark rule-id 268435458: L7 RULE: Inside_Web
access-list CSM_FW_ACL_ advanced permit object-group |acSvcg-268435458 ifc inside any ifc outside any rule-id 268435458
access-list CSM_FW_ACL_ remark rule-id 268434433: L4 RULE: DEFAULT ACTION RULE
access-list CSM_FW_ACL_ advanced deny ip any any rule-id 268434433 event-log flow-start
access-group CSM_FW_ACL_ global
route outside 0.0.0.0 0.0.0.0 198.51.100.1 1
nat (inside,outside) source dynamic any interface
webvpn
 enable outside
"""


def _entries(config, name):
    return config.access_lists[name]


def _policy(config, name):
    return next(p for p in config.policies if p.name == name)


# ── The parser ───────────────────────────────────────────────────────────────


def test_interfaces_take_their_nameif_as_zone_and_alias():
    config = parse_config(ASA_CONFIG)
    assert config.stateful is True and config.routing == ["OSPF"]
    by_name = {i.name: i for i in config.interfaces}
    outside = by_name["GigabitEthernet0/0"]
    # The standby address is the failover peer's: only the active one is kept.
    assert outside.addresses == [("10.0.0.1", "10.0.0.0/29")] and outside.virtual == []
    assert (outside.zone, outside.aliases, outside.description) == ("outside", ["outside"], "Internet uplink")
    assert by_name["GigabitEthernet0/4.20"].zone == "guest"
    unused = by_name["GigabitEthernet0/3"]
    assert unused.shutdown and unused.zone == "" and unused.addresses == []
    assert by_name["GigabitEthernet0/1"].access_groups == {"in": "inside_in"}
    assert by_name["GigabitEthernet0/2"].access_groups == {"out": "dmz_out"}


def test_extended_access_lists_resolve_objects_ports_and_options():
    config = parse_config(ASA_CONFIG)
    acl = _entries(config, "inside_in")
    web = acl[0]
    # Line numbers count the remark, as ``show access-list`` does.
    assert (web.sequence, web.action, web.protocol, web.src, web.dst) == (2, "allow", "tcp", ["10.1.0.0/24"], [ANY])
    assert web.dst_ports == "80,443" and web.comment == "Web out" and web.unresolved == []
    dns_tcp, dns_udp = acl[1], acl[2]
    assert (dns_tcp.protocol, dns_udp.protocol, dns_tcp.dst_ports, dns_tcp.sequence) == ("tcp", "udp", "53", 3)
    missing = acl[3]
    assert missing.dst == [ANY] and missing.unresolved == ["object-group MISSING-NETS"] and missing.dst_ports == "8443"
    sqlnet = acl[4]
    assert (sqlnet.action, sqlnet.dst_ports, sqlnet.enabled) == ("deny", "1521", False)
    timed = acl[5]
    assert timed.unresolved == ["time-range WORK-HOURS"] and timed.dst == ["10.2.0.10/32"]
    pings = acl[6]
    assert pings.protocol == "icmp" and pings.unresolved == ["ICMP types (object-group PINGS)"]
    # A service group gives one entry per service; the group's networks are resolved.
    mixed = [e for e in acl if e.sequence == 8]
    assert [(e.protocol, e.dst_ports) for e in mixed] == [("tcp", "22"), ("udp", "5000-5010"), ("tcp", "8443")]
    assert mixed[0].dst == ["10.2.0.10/32", "10.2.0.128/25"]
    # A group holding an FQDN object matches any address and is unresolved.
    fqdn = next(e for e in acl if e.sequence == 9)
    assert fqdn.dst == [ANY] and fqdn.unresolved == ["fqdn app.example.com (object CLOUD-APP)"]
    # ``interface NAMEIF`` is the interface's address; source ports are kept.
    own = next(e for e in acl if e.sequence == 10)
    assert (own.src_ports, own.dst, own.dst_ports, own.unresolved) == ("1024-65535", ["10.2.0.1/32"], "8080", [])
    last = acl[-1]
    assert (last.action, last.protocol, last.unresolved) == ("deny", ANY, [])
    outside = _entries(config, "outside_in")
    assert outside[0].dst == ["10.2.0.10/32"] and outside[0].dst_ports == "443"
    assert outside[1].dst_ports == "8000-8080" and outside[1].unresolved == []
    # Standard access lists filter routes and VPN tunnels, not traffic.
    assert "SPLIT" not in config.access_lists and "BPDU" not in config.access_lists


def test_object_ranges_cover_with_cidrs():
    config = parse_config(
        "object network DHCP-RANGE\n range 10.1.0.100 10.1.0.131\n"
        "access-list A extended permit ip object DHCP-RANGE any\n"
        "access-list A extended permit ip object NOPE any\n"
    )
    first, second = config.access_lists["A"]
    assert first.src == ["10.1.0.100/30", "10.1.0.104/29", "10.1.0.112/28", "10.1.0.128/30"]
    assert second.src == [ANY] and second.unresolved == ["object NOPE"]


def test_security_levels_leave_acl_interfaces_to_their_access_list():
    config = parse_config(ASA_CONFIG)
    levels = _policy(config, SECURITY_LEVELS)
    assert (levels.kind, levels.default, levels.stateful) == ("policy", "deny", True)
    rules = [(e.action, e.src_zones, e.dst_zones) for e in levels.entries]
    # Nothing passes through the management-only interface.
    assert rules[:2] == [("deny", ["management"], []), ("deny", [], ["management"])]
    # inside has an inbound access list, which decides.
    assert ("allow", ["inside"], []) in rules and ("allow", ["outside"], []) in rules
    # dmz (50) and guest (50) have none: out to outside (0) only; not to each other.
    assert ("allow", ["dmz"], ["outside"]) in rules and ("allow", ["guest"], ["outside"]) in rules
    assert ("deny", ["dmz"], ["guest"]) in rules
    # No intra-interface permit: nothing goes back out of the interface it came in by.
    assert ("deny", ["dmz"], ["dmz"]) in rules


def test_same_security_traffic_permits_equal_levels_and_hairpins():
    config = parse_config(
        "interface Gi0/0\n nameif a\n security-level 50\n ip address 10.0.1.1 255.255.255.0\n"
        "interface Gi0/1\n nameif b\n security-level 50\n ip address 10.0.2.1 255.255.255.0\n"
        "interface Gi0/2\n nameif c\n security-level 10\n ip address 10.0.3.1 255.255.255.0\n"
        "same-security-traffic permit inter-interface\n"
        "same-security-traffic permit intra-interface\n"
    )
    rules = [(e.action, e.src_zones, e.dst_zones) for e in _policy(config, SECURITY_LEVELS).entries]
    assert rules == [
        ("allow", ["a"], ["c", "b", "a"]),
        ("allow", ["b"], ["c", "a", "b"]),
        ("allow", ["c"], ["c"]),
    ]


def test_global_access_list_follows_the_interface_ones():
    config = parse_config(
        "interface Gi0/0\n nameif outside\n security-level 0\n ip address 10.0.0.1 255.255.255.0\n"
        "interface Gi0/1\n nameif inside\n security-level 100\n ip address 10.1.0.1 255.255.255.0\n"
        "access-list IN extended permit tcp any any eq 22\n"
        "access-list GLOBAL extended permit tcp any any eq 443\n"
        "access-group IN in interface inside\n"
        "access-group GLOBAL global\n"
    )
    inside = next(i for i in config.interfaces if i.zone == "inside")
    merged = inside.access_groups["in"]
    assert merged == "IN, then global GLOBAL"
    assert [e.dst_ports for e in config.access_lists[merged]] == ["22", "443"]
    glob = _policy(config, "Global ACL GLOBAL")
    assert (glob.kind, glob.default, glob.stateful) == ("acl", "deny", True)
    assert [(e.action, e.src_zones, e.dst_ports) for e in glob.entries] == [
        ("allow", ["inside"], ANY),
        ("allow", [], "443"),
    ]
    # With a global access list, an access list decides every interface.
    levels = _policy(config, SECURITY_LEVELS)
    assert [(e.action, e.src_zones) for e in levels.entries] == [
        ("deny", ["outside"]),
        ("allow", ["outside"]),
        ("deny", ["inside"]),
        ("allow", ["inside"]),
    ]


def test_static_routes_name_the_nameif():
    config = parse_config(ASA_CONFIG)
    routes = [(r.prefix, r.next_hop, r.interface, r.distance, r.vrf) for r in config.static_routes]
    assert routes == [
        ("0.0.0.0/0", "10.0.0.2", "outside", 1, ""),
        ("10.50.0.0/16", "10.1.0.254", "inside", 1, ""),
    ]


def test_nat_in_evaluation_order_like_the_fmc_reader():
    config = parse_config(ASA_CONFIG)
    by_index: dict[int, list[dict]] = {}
    for entry in config.nat:
        by_index.setdefault(entry["index"], []).append(entry)
    # Section 1: the identity twice NAT for the VPN.
    [exempt] = by_index[1]
    assert exempt["kind"] == "manual_before" and exempt["name"] == "Manual NAT rule 1"
    assert exempt["original_src"] == exempt["translated_src"] == ["10.1.0.0/24"]
    assert exempt["original_dst"] == exempt["translated_dst"] == ["172.16.0.0/12"]
    assert (exempt["src_interface"], exempt["dst_interface"]) == ("inside", "outside")
    # The FQDN twice NAT (rule 2) is not all addresses: noted, not emitted.
    assert 2 not in by_index
    assert "NAT rule 2 (its networks or services are not all addresses or single ports)" in config.notes
    # Section 2: static before dynamic, the fewer addresses first.
    web_out, web_in = by_index[3]
    assert (web_out["kind"], web_out["name"]) == ("auto", "WEB-SERVER")
    assert web_out["original_src"] == ["10.2.0.10/32"] and web_out["translated_src"] == ["10.0.0.5/32"]
    assert (web_out["src_interface"], web_out["dst_interface"], web_out["protocol"]) == ("dmz", "outside", "tcp")
    assert web_in["original_dst"] == ["10.0.0.5/32"] and web_in["translated_dst"] == ["10.2.0.10/32"]
    assert (web_in["original_port"], web_in["translated_port"]) == ("8443", "443")
    assert (web_in["src_interface"], web_in["dst_interface"]) == ("outside", "dmz")
    assert [e["name"] for e in by_index[4]] == ["DHCP-RANGE", "DHCP-RANGE"]
    [hide] = by_index[5]
    assert hide["name"] == "INSIDE-NET" and hide["translated_src"] == [INTERFACE] and hide["translated_dst"] == []
    # Section 3: after auto.
    [rest] = by_index[6]
    assert (rest["kind"], rest["name"], rest["original_src"]) == ("manual_after", "Hide the rest", [ANY])
    assert rest["translated_src"] == [INTERFACE]


def test_notes_name_what_is_not_read():
    config = parse_config(ASA_CONFIG)
    assert SITE_TO_SITE_VPN in config.notes and INSPECTION in config.notes
    assert ETHERTYPE_ACCESS_LISTS in config.notes
    assert CONTEXTS in parse_config("mode multiple\ncontext admin\n").notes


def test_ftd_advanced_entries_match_by_ifc_and_flag_snort_rules():
    config = parse_config(FTD_CONFIG)
    acl = config.access_lists["CSM_FW_ACL_"]
    tunnel, dns, dot, web_tcp, web_udp, default = acl
    assert (tunnel.protocol, tunnel.action, tunnel.unresolved) == ("ipip", "allow", [])
    assert (dns.src_zones, dns.dst_zones, dns.src, dns.dst_ports) == (["inside"], ["outside"], ["10.10.0.0/24"], "53")
    assert dns.name == "Inside_DNS" and dns.unresolved == []
    # ``trust`` passes without inspection.
    assert (dot.action, dot.dst, dot.dst_ports, dot.enabled) == ("allow", ["198.51.100.53/32"], "853", True)
    # An L7 rule is decided by Snort: a flow it matches is unknown.
    assert [(e.protocol, e.dst_ports) for e in (web_tcp, web_udp)] == [("tcp", "443"), ("udp", "443")]
    assert web_tcp.unresolved == ["FTD access control rule Inside_Web (conditions Snort decides)"]
    assert (default.action, default.unresolved, default.name) == ("deny", [], "DEFAULT ACTION RULE")
    glob = _policy(config, "Global ACL CSM_FW_ACL_")
    assert len(glob.entries) == len(acl) and glob.default == "deny"
    assert REMOTE_ACCESS_VPN in config.notes
    assert config.nat[0]["kind"] == "manual_before" and config.nat[0]["translated_src"] == [INTERFACE]


def test_asa_platform_reads_configuration_backups():
    platform = platform_of("cisco_asa")
    assert platform.config is parse_config and platform_of("cisco_ftd").config is parse_config


# ── The forwarding block ─────────────────────────────────────────────────────


def test_forwarding_block_of_an_asa_with_a_capture():
    host = {"ip_address": "10.1.0.1", "device_type": "cisco_asa"}
    block = forwarding_for_host(
        host, [], {"id": 1, "routes_text": ASA_CAPTURE}, [], config_backup={"config_text": ASA_CONFIG}
    )
    interfaces = {i["name"]: i for i in block["interfaces"]}
    inside = interfaces["GigabitEthernet0/1"]
    assert (inside["zone"], inside["ip"], inside["cidr"]) == ("inside", "10.1.0.1", "10.1.0.0/24")
    assert interfaces["GigabitEthernet0/0"]["zone"] == "outside"
    # ``show route`` names the nameif: its routes map to the configured interfaces.
    routes = {r["prefix"]: r for r in block["routes"]}
    assert routes["0.0.0.0/0"]["interface"] == "GigabitEthernet0/0"
    assert routes["10.70.0.0/16"]["interface"] == "GigabitEthernet0/1"
    assert not any(r["interface"] in ("inside", "outside") for r in block["routes"])
    bound = _named(block["policies"], "ACL inside_in in on inside")
    assert bound["interface"] in ("inside", "GigabitEthernet0/1")
    assert (bound["direction"], bound["stateful"], bound["default"]) == ("in", True, "deny")
    out = _named(block["policies"], "ACL dmz_out out on dmz")
    assert out["interface"] in ("dmz", "GigabitEthernet0/2") and out["direction"] == "out"
    levels = _named(block["policies"], SECURITY_LEVELS)
    assert levels["stateful"] and levels["interface"] == "" and levels["default"] == "deny"
    assert any(n["kind"] == "auto" for n in block["nat"]) and len(block["nat"]) == 7
    assert SITE_TO_SITE_VPN in block["not_collected"] and "Access lists" not in block["not_collected"]


def test_forwarding_block_of_an_asa_without_a_capture_adds_configured_routes():
    host = {"ip_address": "10.1.0.1", "device_type": "cisco_asa"}
    block = forwarding_for_host(host, [], None, [], config_backup={"config_text": ASA_CONFIG})
    routes = {r["prefix"]: r for r in block["routes"]}
    assert routes["0.0.0.0/0"]["kind"] == "default" and routes["0.0.0.0/0"]["interface"] == "GigabitEthernet0/0"
    assert routes["10.2.0.0/24"]["kind"] == "connected" and routes["10.2.0.0/24"]["interface"] == "GigabitEthernet0/2"
    assert "Routes learned by OSPF" in block["not_collected"]


# ── A trace through an ASA ───────────────────────────────────────────────────

_EDGE_ROUTER = """\
hostname edge-rtr1
!
interface GigabitEthernet0/0
 ip address 10.0.0.2 255.255.255.248
!
interface GigabitEthernet0/1
 description Partner
 ip address 172.16.5.1 255.255.255.0
!
ip route 10.1.0.0 255.255.0.0 10.0.0.1
ip route 10.2.0.0 255.255.0.0 10.0.0.1
ip route 10.3.0.0 255.255.0.0 10.0.0.1
!
end
"""

_NODES = [
    {"id": 7, "label": "edge-fw1", "ip": "10.1.0.1", "in_inventory": True, "device_type": "cisco_asa"},
    {"id": 8, "label": "edge-rtr1", "ip": "10.0.0.2", "in_inventory": True, "device_type": "cisco_ios"},
]


def _asa_hosts():
    # Without OSPF, the configured routes are all the routes: the default decides.
    static_only = ASA_CONFIG.replace("router ospf 1\n network 10.1.0.0 255.255.255.0 area 0\n", "")
    fw = forwarding_for_host(
        {"ip_address": "10.1.0.1", "device_type": "cisco_asa"}, [], None, [], config_backup={"config_text": static_only}
    )
    rtr = forwarding_for_host(
        {"ip_address": "10.0.0.2", "device_type": "cisco_ios"},
        [],
        None,
        [],
        config_backup={"config_text": _EDGE_ROUTER},
    )
    subnets = [*subnets_for_host(_NODES[0], fw), *subnets_for_host(_NODES[1], rtr)]
    lldp = {"id": "lldp:7:8", "from": 7, "to": 8, "protocol": "lldp", "status": "up"}
    return _tracer({}, hosts={7: fw, 8: rtr}, extra_nodes=_NODES, extra_edges=[lldp], subnets=subnets)


def _named(policies, label):
    """The rule set whose name starts with ``label`` (inventory may add the interface name)."""
    return next(p for p in policies if p["name"].startswith(label))


def _item(hop, where):
    return next(i for i in hop["items"] if i["where"].startswith(where))


def test_trace_through_an_asa():
    tracer = _asa_hosts()

    # (a) inside to outside on 443: the inbound ACL allows it; the replies pass statefully.
    allowed = tracer.trace("10.1.0.20", "172.16.5.10", source_node=7, protocol="tcp", port=443)
    assert allowed["verdict"] == "allowed", allowed["summary"]
    assert _labels(allowed["request"]) == ["edge-fw1", "edge-rtr1"]
    fw = allowed["request"]["hops"][0]
    assert fw["in"] == "GigabitEthernet0/1" and fw["out"] == "GigabitEthernet0/0"
    permit = _item(fw, "ACL inside_in in on inside")
    assert permit["status"] == "ok" and permit["rule"] == 2 and "Web out" in permit["text"]
    assert _item(fw, SECURITY_LEVELS)["status"] == "ok"
    back = next(h for h in allowed["reply"]["hops"] if h["label"] == "edge-fw1")
    assert _item(back, "ACL outside_in in on outside")["text"].startswith("Stateful")

    # (b) outside to inside: the outside ACL's implicit deny.
    blocked = tracer.trace("172.16.5.10", "10.1.0.20", protocol="tcp", port=22)
    assert blocked["verdict"] == "blocked"
    fw = blocked["request"]["hops"][1]
    denied = next(i for i in fw["items"] if i["status"] == "blocked")
    assert denied["where"].startswith("ACL outside_in in on outside")
    assert denied["text"] == "No rule matches: the default action denies it."

    # (c) An object group the configuration does not define: unknown.
    unknown = tracer.trace("10.1.0.20", "172.16.5.10", source_node=7, protocol="tcp", port=8443)
    assert unknown["verdict"] == "unknown"
    item = _item(unknown["request"]["hops"][0], "ACL inside_in in on inside")
    assert item["status"] == "unknown" and "object-group MISSING-NETS" in item["text"]

    # (d) dmz has no inbound ACL: the security levels let it out to a lower level...
    out = tracer.trace("10.2.0.20", "172.16.5.10", protocol="tcp", port=22)
    assert out["verdict"] == "allowed", out["summary"]
    level = _item(out["request"]["hops"][0], SECURITY_LEVELS)
    assert level["status"] == "ok" and "Security level 50 to a lower level" in level["text"]
    # ...and not up to inside (100), nor across to guest at the same level.
    up = tracer.trace("10.2.0.20", "10.1.0.20", protocol="tcp", port=22)
    assert up["verdict"] == "blocked"
    deny = next(i for i in up["request"]["hops"][0]["items"] if i["status"] == "blocked")
    assert deny["where"] == SECURITY_LEVELS and deny["text"] == "No rule matches: the default action denies it."
    across = tracer.trace("10.2.0.20", "10.3.0.20", protocol="tcp", port=22)
    deny = next(i for i in across["request"]["hops"][0]["items"] if i["status"] == "blocked")
    assert deny["where"] == SECURITY_LEVELS and "inter-interface" in deny["text"]
