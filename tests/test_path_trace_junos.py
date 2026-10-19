"""Tests for the Juniper Junos reader of path tracing.

``parse_config`` reads ``show configuration | display set`` backups (an SRX
with zones, policies and NAT; an EX / MX with firewall filters only);
``parse_routes`` reads ``show route`` captures; ``forwarding_for_host``
builds the forwarding block of a Junos host from them, and a trace through
an SRX decides by its filters and security policies.
"""

from __future__ import annotations

from netcontrol.integrations.meraki.forwarding import INTERFACE
from netcontrol.integrations.pathtrace.inventory import forwarding_for_host, parse_route_table, subnets_for_host
from netcontrol.integrations.pathtrace.junos_config import (
    GROUPS,
    HIERARCHICAL,
    IPSEC_VPNS,
    IPV6_FILTERS,
    SCREENS,
    SECURITY_POLICIES,
    parse_config,
    parse_routes,
)
from netcontrol.integrations.pathtrace.platforms import platform_of
from netcontrol.integrations.pathtrace.route_tables import LOCAL

from test_path_trace import _tracer

SRX = """\
## Last commit: 2026-09-01 10:00:00 UTC by admin
set version 22.4R3
set system host-name srx-edge1
set apply-groups node-defaults
set groups node-defaults system syslog file messages any notice
set interfaces ge-0/0/0 description "Internet uplink"
set interfaces ge-0/0/0 unit 0 family inet filter input UNTRUST-IN
set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
set interfaces ge-0/0/1 unit 0 description "Users"
set interfaces ge-0/0/1 unit 0 family inet address 10.10.0.2/24 vrrp-group 10 virtual-address 10.10.0.1
set interfaces ge-0/0/1 unit 0 family inet address 10.10.1.1/24
set interfaces ge-0/0/1 unit 0 family inet address 10.10.9.1/24 primary
set interfaces ge-0/0/1 unit 0 family inet filter output USERS-OUT
set interfaces ge-0/0/2 unit 0 family inet address 10.30.0.1/24
set interfaces ge-0/0/2 unit 0 family inet6 filter input V6-IN
set interfaces ge-0/0/3 disable
set interfaces ge-0/0/3 unit 0 family inet address 10.40.0.1/24
set interfaces ge-0/0/4 unit 0 family inet address 172.16.0.1/30
set interfaces irb unit 100 family inet address 10.100.0.1/24
set interfaces lo0 unit 0 family inet address 10.255.0.1/32
set interfaces st0 unit 0 family inet address 169.254.0.1/30
deactivate interfaces ge-0/0/4 unit 0 family inet filter
set routing-options static route 0.0.0.0/0 next-hop 192.0.2.254
set routing-options static route 10.50.0.0/16 next-hop 10.30.0.5
set routing-options static route 10.50.0.0/16 preference 20
set routing-options static route 10.60.0.0/16 qualified-next-hop 10.30.0.6 preference 200
set routing-options static route 192.168.99.0/24 discard
set routing-options static route 10.70.0.0/16 next-table GUEST.inet.0
set routing-instances GUEST instance-type virtual-router
set routing-instances GUEST interface ge-0/0/4.0
set routing-instances GUEST routing-options static route 0.0.0.0/0 next-hop 172.16.0.2
set routing-instances GUEST protocols ospf area 0.0.0.0 interface ge-0/0/4.0
set protocols bgp group isp neighbor 192.0.2.254 peer-as 64500
set policy-options prefix-list MGMT-NETS 10.10.9.0/24
set policy-options prefix-list MGMT-NETS 10.10.8.0/24
set firewall family inet filter UNTRUST-IN term replies from protocol tcp
set firewall family inet filter UNTRUST-IN term replies from tcp-established
set firewall family inet filter UNTRUST-IN term replies then accept
set firewall family inet filter UNTRUST-IN term counted from source-address 198.51.100.0/24
set firewall family inet filter UNTRUST-IN term counted then count from-partner
set firewall family inet filter UNTRUST-IN term counted then next term
set firewall family inet filter UNTRUST-IN term ping from protocol icmp
set firewall family inet filter UNTRUST-IN term ping from icmp-type echo-request
set firewall family inet filter UNTRUST-IN term ping then accept
set firewall family inet filter UNTRUST-IN term web from destination-address 192.0.2.10/32
set firewall family inet filter UNTRUST-IN term web from protocol tcp
set firewall family inet filter UNTRUST-IN term web from destination-port [ http https ]
set firewall family inet filter UNTRUST-IN term web then accept
set firewall family inet filter UNTRUST-IN term vpn from protocol udp
set firewall family inet filter UNTRUST-IN term vpn from destination-port 500
set firewall family inet filter UNTRUST-IN term vpn from destination-port 4500
set firewall family inet filter UNTRUST-IN term vpn then accept
set firewall family inet filter UNTRUST-IN term flagged from source-address 203.0.113.0/24
set firewall family inet filter UNTRUST-IN term flagged from tcp-flags syn
set firewall family inet filter UNTRUST-IN term flagged then discard
set firewall family inet filter UNTRUST-IN term last then log
set firewall family inet filter UNTRUST-IN term last then discard
set firewall family inet filter USERS-OUT term mgmt from source-prefix-list MGMT-NETS
set firewall family inet filter USERS-OUT term mgmt from protocol tcp
set firewall family inet filter USERS-OUT term mgmt from destination-port ssh
set firewall family inet filter USERS-OUT term mgmt then accept
set firewall family inet filter USERS-OUT term not-lab from source-address 10.0.0.0/8
set firewall family inet filter USERS-OUT term not-lab from source-address 10.99.0.0/16 except
set firewall family inet filter USERS-OUT term not-lab then reject
set firewall family inet filter USERS-OUT term rest then accept
set security screen ids-option untrust-screen icmp ping-death
set security ike gateway partner address 198.51.100.1
set security address-book global address web-server 10.30.0.10/32
set security address-book global address dns-servers range-address 10.30.0.53 to 10.30.0.54
set security address-book global address partner-fqdn dns-name partner.example.com
set security address-book global address-set dmz-servers address web-server
set security address-book global address-set dmz-servers address dns-servers
set security zones security-zone trust interfaces ge-0/0/1.0 host-inbound-traffic system-services ping
set security zones security-zone trust address-book address users 10.10.0.0/24
set security zones security-zone untrust screen untrust-screen
set security zones security-zone untrust interfaces ge-0/0/0.0
set security zones security-zone dmz interfaces ge-0/0/2.0
set applications application web-8080 protocol tcp
set applications application web-8080 destination-port 8080
set applications application app-range term t1 protocol udp
set applications application app-range term t1 destination-port 6000-6010
set applications application-set web-apps application junos-https
set applications application-set web-apps application web-8080
set security policies from-zone trust to-zone untrust policy allow-web match source-address users
set security policies from-zone trust to-zone untrust policy allow-web match destination-address any
set security policies from-zone trust to-zone untrust policy allow-web match application web-apps
set security policies from-zone trust to-zone untrust policy allow-web then permit
set security policies from-zone trust to-zone untrust policy allow-web then log session-init
set security policies from-zone trust to-zone untrust policy allow-web description "Users to the web"
set security policies from-zone trust to-zone untrust policy custom match source-address any
set security policies from-zone trust to-zone untrust policy custom match destination-address any
set security policies from-zone trust to-zone untrust policy custom match application app-not-defined
set security policies from-zone trust to-zone untrust policy custom then permit
set security policies from-zone trust to-zone dmz policy to-servers match source-address users
set security policies from-zone trust to-zone dmz policy to-servers match destination-address dmz-servers
set security policies from-zone trust to-zone dmz policy to-servers match application junos-dns-udp
set security policies from-zone trust to-zone dmz policy to-servers match application junos-ssh
set security policies from-zone trust to-zone dmz policy to-servers then permit
set security policies from-zone untrust to-zone dmz policy partner match source-address partner-fqdn
set security policies from-zone untrust to-zone dmz policy partner match destination-address web-server
set security policies from-zone untrust to-zone dmz policy partner match application junos-http
set security policies from-zone untrust to-zone dmz policy partner then permit
set security policies from-zone untrust to-zone dmz policy partner scheduler-name office-hours
set security policies from-zone dmz to-zone untrust policy new-app match source-address any
set security policies from-zone dmz to-zone untrust policy new-app match destination-address any
set security policies from-zone dmz to-zone untrust policy new-app match application junos-some-new-app
set security policies from-zone dmz to-zone untrust policy new-app then permit
set security policies global policy block-bad match source-address any
set security policies global policy block-bad match destination-address any
set security policies global policy block-bad match application junos-telnet
set security policies global policy block-bad match from-zone any
set security policies global policy block-bad match to-zone any
set security policies global policy block-bad then deny
set security policies default-policy deny-all
set security nat source pool out-pool address 192.0.2.100/32
set security nat source rule-set trust-out from zone trust
set security nat source rule-set trust-out to zone untrust
set security nat source rule-set trust-out rule no-nat-partner match source-address 10.10.0.0/24
set security nat source rule-set trust-out rule no-nat-partner match destination-address 198.51.100.0/24
set security nat source rule-set trust-out rule no-nat-partner then source-nat off
set security nat source rule-set trust-out rule users-out match source-address 10.10.0.0/24
set security nat source rule-set trust-out rule users-out match destination-address 0.0.0.0/0
set security nat source rule-set trust-out rule users-out then source-nat interface
set security nat source rule-set dmz-out from interface ge-0/0/2.0
set security nat source rule-set dmz-out to zone untrust
set security nat source rule-set dmz-out rule dmz-pool match source-address 10.30.0.0/24
set security nat source rule-set dmz-out rule dmz-pool then source-nat pool out-pool
set security nat destination pool web-pool address 10.30.0.10/32 port 8080
set security nat destination rule-set from-internet from zone untrust
set security nat destination rule-set from-internet rule web match destination-address 192.0.2.10/32
set security nat destination rule-set from-internet rule web match destination-port 80
set security nat destination rule-set from-internet rule web match protocol tcp
set security nat destination rule-set from-internet rule web then destination-nat pool web-pool
set security nat static rule-set statics from zone untrust
set security nat static rule-set statics rule mail match destination-address 192.0.2.25/32
set security nat static rule-set statics rule mail then static-nat prefix 10.30.0.25/32
set security nat static rule-set guest-statics from routing-instance GUEST
set security nat static rule-set guest-statics rule g1 match destination-address 192.0.2.26/32
set security nat static rule-set guest-statics rule g1 then static-nat prefix 172.16.0.2/32
"""

MX = """\
set interfaces xe-0/0/0 unit 0 family inet address 10.0.0.1/30
set interfaces xe-0/0/0 unit 0 family inet filter input-list [ EDGE-IN COMMON ]
set interfaces ae0 unit 100 description "Core VLAN 100"
set interfaces ae0 unit 100 family inet address 10.1.0.1/24
set interfaces ae0 unit 100 family inet filter input PROTECT
set routing-options static route 10.9.0.0/16 next-hop 10.0.0.2
set routing-options static route 10.8.0.0/16 reject
set protocols isis interface xe-0/0/0.0
set protocols ospf3 area 0 interface ae0.100
set firewall family inet6 filter V6 term t then accept
set firewall filter PROTECT term ssh from source-address 10.1.0.0/24
set firewall filter PROTECT term ssh from destination-address 10.1.0.1/32
set firewall filter PROTECT term ssh from protocol tcp
set firewall filter PROTECT term ssh from destination-port 22
set firewall filter PROTECT term ssh then accept
set firewall filter PROTECT term either from address 10.200.0.0/16
set firewall filter PROTECT term either from port 179
set firewall filter PROTECT term either then accept
set firewall filter PROTECT term high from destination-port-except 0-1023
set firewall filter PROTECT term high from protocol udp
set firewall filter PROTECT term high then accept
set firewall filter PROTECT term dscp from dscp ef
set firewall filter PROTECT term dscp then accept
set firewall filter PROTECT term pbr from source-address 10.1.0.128/25
set firewall filter PROTECT term pbr then routing-instance OTHER
set firewall filter EDGE-IN term bogons from source-prefix-list BOGONS
set firewall filter EDGE-IN term bogons then discard
set firewall filter COMMON term all then accept
"""

SHOW_ROUTE = """\

inet.0: 9 destinations, 10 routes (9 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

0.0.0.0/0          *[Static/5] 3w2d 04:11:20
                    >  to 192.0.2.254 via ge-0/0/0.0
10.10.0.0/24       *[Direct/0] 3w2d 04:11:25
                    >  via ge-0/0/1.0
10.10.0.2/32       *[Local/0] 3w2d 04:11:25
                       Local via ge-0/0/1.0
10.20.0.0/16       *[OSPF/10] 1d 02:00:00, metric 20
                    >  to 10.30.0.2 via ge-0/0/2.0
                       to 10.30.0.3 via ge-0/0/2.0
                    [Static/200] 3w2d 04:11:20
                    >  to 10.30.0.9 via ge-0/0/2.0
10.30.0.0/24       *[Direct/0] 3w2d 04:11:25
                    >  via ge-0/0/2.0
10.80.0.0/16        [Static/5] 00:00:10
                    >  to 10.30.0.8 via ge-0/0/2.0
172.20.0.0/16      *[BGP/170] 1w0d 00:00:00, localpref 100
                      AS path: 64500 I, validation-state: unverified
                    >  to 192.0.2.254 via ge-0/0/0.0
192.168.99.0/24    *[Static/5] 3w2d 04:11:20
                       Discard
10.111.0.0/16      *[Access-internal/12] 00:10:00
                    >  to 10.30.0.4 via ge-0/0/2.0

inet6.0: 2 destinations, 2 routes (2 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

::/0               *[Static/5] 1w0d 00:00:00
                    >  to 2001:db8::1 via ge-0/0/0.0

GUEST.inet.0: 2 destinations, 2 routes (2 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

0.0.0.0/0          *[Static/5] 1w0d 00:00:00
                    >  to 172.16.0.2 via ge-0/0/4.0
172.16.0.0/30      *[Direct/0] 1w0d 00:00:00
                    >  via ge-0/0/4.0

__juniper_private1__.inet.0: 1 destinations, 1 routes (1 active, 0 holddown, 0 hidden)

10.0.0.1/32        *[Direct/0] 1w0d 00:00:00
                    >  via lo0.16385

inet.3: 1 destinations, 1 routes (1 active, 0 holddown, 0 hidden)

10.255.0.9/32      *[LDP/9] 1w0d 00:00:00, metric 1
                    >  to 10.30.0.2 via ge-0/0/2.0
"""


def _interfaces(config):
    return {i.name: i for i in config.interfaces}


# ── parse_config: SRX ───────────────────────────────────────────────────────


def test_srx_interfaces_units_vrrp_zones_and_filters():
    config = parse_config(SRX)
    assert config.stateful is False
    found = _interfaces(config)
    assert {"ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0", "ge-0/0/3.0", "irb.100", "lo0.0", "st0.0"} <= set(found)
    uplink = found["ge-0/0/0.0"]
    assert uplink.addresses == [("192.0.2.1", "192.0.2.0/24")] and uplink.zone == "untrust"
    assert uplink.access_groups == {"in": "UNTRUST-IN"} and uplink.description == "Internet uplink"
    users = found["ge-0/0/1.0"]
    # The primary address comes first.
    assert users.addresses[0] == ("10.10.9.1", "10.10.9.0/24")
    assert {a for a, _c in users.addresses} == {"10.10.9.1", "10.10.0.2", "10.10.1.1"}
    assert [(v.protocol, v.group, v.address) for v in users.virtual] == [("VRRP", "10", "10.10.0.1")]
    assert users.zone == "trust" and users.access_groups == {"out": "USERS-OUT"} and users.description == "Users"
    assert found["ge-0/0/2.0"].zone == "dmz"
    assert found["ge-0/0/3.0"].shutdown is True and found["ge-0/0/2.0"].shutdown is False
    # The deactivated filter line is not in effect; the routing instance is the VRF.
    guest = found["ge-0/0/4.0"]
    assert guest.vrf == "GUEST" and guest.access_groups == {}


def test_srx_static_routes_protocols_and_notes():
    config = parse_config(SRX)
    routes = {(r.vrf, r.prefix, r.next_hop, r.interface, r.distance) for r in config.static_routes}
    assert routes == {
        ("", "0.0.0.0/0", "192.0.2.254", "", None),
        ("", "10.50.0.0/16", "10.30.0.5", "", 20),
        ("", "10.60.0.0/16", "10.30.0.6", "", 200),
        ("", "192.168.99.0/24", "", "null (discard)", None),
        ("GUEST", "0.0.0.0/0", "172.16.0.2", "", None),
    }
    assert config.routing == ["OSPF", "BGP"]
    for name in (GROUPS, IPV6_FILTERS, SCREENS, IPSEC_VPNS, "Static route to 10.70.0.0/16 (next table GUEST.inet.0)"):
        assert name in config.notes
    assert "NAT rule-set guest-statics (a routing instance context)" in config.notes


def test_srx_filter_terms_in_rule_terms():
    entries = parse_config(SRX).access_lists["UNTRUST-IN"]
    by_name: dict[str, list] = {}
    for entry in entries:
        by_name.setdefault(entry.name, []).append(entry)
    # A "next term" term only counts.
    assert list(by_name) == ["replies", "ping", "web", "vpn", "flagged", "last"]
    [replies] = by_name["replies"]
    assert (replies.sequence, replies.action, replies.protocol, replies.established) == (1, "allow", "tcp", True)
    [ping] = by_name["ping"]
    assert ping.protocol == "icmp" and ping.unresolved == []
    [web] = by_name["web"]
    assert (web.dst, web.dst_ports, web.protocol) == (["192.0.2.10/32"], "80,443", "tcp")
    [vpn] = by_name["vpn"]
    assert vpn.dst_ports == "500,4500" and vpn.protocol == "udp"
    [flagged] = by_name["flagged"]
    assert flagged.action == "deny" and flagged.unresolved == ["tcp-flags syn"]
    [last] = by_name["last"]
    assert last.action == "deny" and last.src == ["any"] and last.unresolved == []

    users_out = parse_config(SRX).access_lists["USERS-OUT"]
    mgmt = users_out[0]
    assert set(mgmt.src) == {"10.10.9.0/24", "10.10.8.0/24"} and mgmt.dst_ports == "22"
    not_lab = users_out[1]
    assert not_lab.action == "deny" and not_lab.unresolved == ["source-address 10.99.0.0/16 except"]
    assert users_out[2].action == "allow" and users_out[2].sequence == 3


def test_srx_security_policies_are_one_stateful_rule_set():
    config = parse_config(SRX)
    [policy] = config.policies
    assert policy.name == SECURITY_POLICIES and policy.stateful is True and policy.default == "deny"
    names = list(dict.fromkeys(e.name for e in policy.entries))
    # The zone-pair policies in order, then the global ones.
    assert names == ["allow-web", "custom", "to-servers", "partner", "new-app", "block-bad"]
    web = [e for e in policy.entries if e.name == "allow-web"]
    assert [(e.protocol, e.dst_ports) for e in web] == [("tcp", "443"), ("tcp", "8080")]
    assert all(e.src == ["10.10.0.0/24"] and e.src_zones == ["trust"] and e.dst_zones == ["untrust"] for e in web)
    assert web[0].comment == "Users to the web" and web[0].unresolved == []
    [custom] = [e for e in policy.entries if e.name == "custom"]
    assert custom.unresolved == ["application app-not-defined (not in the configuration)"]
    servers = [e for e in policy.entries if e.name == "to-servers"]
    assert {(e.protocol, e.dst_ports) for e in servers} == {("udp", "53"), ("tcp", "22")}
    assert set(servers[0].dst) == {"10.30.0.10/32", "10.30.0.53/32", "10.30.0.54/32"}
    [partner] = [e for e in policy.entries if e.name == "partner"]
    assert "scheduler office-hours" in partner.unresolved
    assert "address partner-fqdn (DNS name partner.example.com)" in partner.unresolved
    [block] = [e for e in policy.entries if e.name == "block-bad"]
    assert block.action == "deny" and block.src_zones == [] and block.dst_ports == "23"
    [unknown] = [e for e in policy.entries if e.name == "new-app"]
    assert unknown.unresolved == ["application junos-some-new-app (a predefined application Plexus does not know)"]


def test_srx_default_policy_permit_all():
    config = parse_config(SRX.replace("default-policy deny-all", "default-policy permit-all"))
    assert config.policies[0].default == "allow"


def test_srx_nat_in_the_order_the_srx_applies_it():
    entries = parse_config(SRX).nat
    kinds = [e["kind"] for e in entries]
    assert kinds == ["static_nat", "static_nat", "destination_nat", "source_nat", "source_nat", "source_nat"]
    inbound, reverse = entries[0], entries[1]
    assert (inbound["original_dst"], inbound["translated_dst"], inbound["src_interface"]) == (
        ["192.0.2.25/32"],
        ["10.30.0.25/32"],
        "untrust",
    )
    assert (reverse["original_src"], reverse["translated_src"], reverse["dst_interface"]) == (
        ["10.30.0.25/32"],
        ["192.0.2.25/32"],
        "untrust",
    )
    web = entries[2]
    assert (web["original_dst"], web["translated_dst"], web["protocol"]) == (
        ["192.0.2.10/32"],
        ["10.30.0.10/32"],
        "tcp",
    )
    assert (web["original_port"], web["translated_port"], web["src_interface"]) == ("80", "8080", "untrust")
    # An interface context comes before a zone one.
    dmz, off, out = entries[3], entries[4], entries[5]
    assert (dmz["src_interface"], dmz["dst_interface"], dmz["translated_src"]) == (
        "ge-0/0/2.0",
        "untrust",
        ["192.0.2.100/32"],
    )
    assert off["translated_src"] == off["original_src"] == ["10.10.0.0/24"]
    assert out["translated_src"] == [INTERFACE] and out["src_interface"] == "trust"


# ── parse_config: EX / MX, and what is not read ─────────────────────────────


def test_mx_filters_without_zones():
    config = parse_config(MX)
    assert config.policies == [] and config.nat == []
    found = _interfaces(config)
    assert found["ae0.100"].access_groups == {"in": "PROTECT"} and found["ae0.100"].description == "Core VLAN 100"
    # A filter list is one filter: its filters in order.
    assert found["xe-0/0/0.0"].access_groups == {"in": "EDGE-IN + COMMON"}
    combined = config.access_lists["EDGE-IN + COMMON"]
    assert [(e.sequence, e.name, e.action) for e in combined] == [(1, "bogons", "deny"), (2, "all", "allow")]
    assert combined[0].unresolved == ["prefix-list BOGONS (not in the configuration)"]
    protect = config.access_lists["PROTECT"]
    [ssh] = [e for e in protect if e.name == "ssh"]
    assert (ssh.src, ssh.dst, ssh.dst_ports) == (["10.1.0.0/24"], ["10.1.0.1/32"], "22")
    # "address" and "port" match either side: one entry per side, TCP and UDP.
    either = [e for e in protect if e.name == "either"]
    assert len(either) == 8
    assert {(e.protocol, tuple(e.src), tuple(e.dst), e.src_ports, e.dst_ports) for e in either} >= {
        ("tcp", ("10.200.0.0/16",), ("any",), "179", "any"),
        ("udp", ("any",), ("10.200.0.0/16",), "any", "179"),
    }
    [high] = [e for e in protect if e.name == "high"]
    assert high.dst_ports == "1024-65535" and high.protocol == "udp"
    [dscp] = [e for e in protect if e.name == "dscp"]
    assert dscp.unresolved == ["dscp ef"]
    [pbr] = [e for e in protect if e.name == "pbr"]
    assert pbr.action == "allow" and pbr.unresolved == ["routing-instance OTHER (filter-based forwarding)"]
    statics = {(r.prefix, r.interface) for r in config.static_routes}
    assert ("10.8.0.0/16", "null (reject)") in statics
    assert config.routing == ["IS-IS", "OSPFv3"] and IPV6_FILTERS in config.notes


def test_hierarchical_format_is_noted_not_read():
    config = parse_config("interfaces {\n    ge-0/0/0 {\n        unit 0;\n    }\n}\n")
    assert config.notes == [HIERARCHICAL] and config.interfaces == []


def test_platform_reads_junos():
    platform = platform_of("juniper_junos")
    assert platform.config is parse_config and platform.routes is parse_routes


# ── parse_routes ────────────────────────────────────────────────────────────


def test_show_route_reads_active_routes_of_inet0_and_instances():
    routes, missing = parse_route_table(SHOW_ROUTE, "juniper_junos")
    assert missing == []
    found = {(r["vrf"], r["prefix"]): r for r in routes}
    assert all(r["vrf"] in ("", "GUEST") for r in routes)
    assert ("", "::/0") not in found and ("", "10.0.0.1/32") not in found and ("", "10.255.0.9/32") not in found
    default = found[("", "0.0.0.0/0")]
    assert (default["kind"], default["next_hop"], default["interface"], default["metric"]) == (
        "default",
        "192.0.2.254",
        "ge-0/0/0.0",
        5,
    )
    direct = found[("", "10.10.0.0/24")]
    assert (direct["kind"], direct["source"], direct["interface"], direct["next_hop"]) == (
        "connected",
        "Connected",
        "ge-0/0/1.0",
        "",
    )
    local = found[("", "10.10.0.2/32")]
    assert (local["kind"], local["source"], local["interface"]) == ("connected", LOCAL, "ge-0/0/1.0")
    # Only the selected next hop of the active route.
    ospf = [r for r in routes if r["prefix"] == "10.20.0.0/16"]
    assert [(r["kind"], r["source"], r["next_hop"], r["metric"]) for r in ospf] == [
        ("dynamic", "OSPF", "10.30.0.2", 20)
    ]
    assert ("", "10.80.0.0/16") not in found  # not active
    assert found[("", "172.20.0.0/16")]["source"] == "BGP"
    assert found[("", "192.168.99.0/24")]["kind"] == "blackhole"
    assert found[("", "10.111.0.0/16")]["source"] == "Access-internal"
    guest = found[("GUEST", "0.0.0.0/0")]
    assert guest["next_hop"] == "172.16.0.2" and guest["interface"] == "ge-0/0/4.0"


# ── forwarding_for_host ─────────────────────────────────────────────────────


def _srx_block(capture: str | None = None) -> dict:
    return forwarding_for_host(
        {"ip_address": "192.0.2.1", "device_type": "juniper_junos"},
        [],
        {"id": 1, "routes_text": capture} if capture is not None else None,
        [],
        config_backup={"config_text": SRX},
    )


def test_forwarding_block_of_an_srx():
    block = _srx_block()
    by_name = {i["name"]: i for i in block["interfaces"]}
    assert by_name["ge-0/0/1.0"]["zone"] == "trust" and by_name["ge-0/0/1.0"]["ip"] == "10.10.9.1"
    assert by_name["ge-0/0/1.0 (VRRP 10.10.0.1)"]["cidr"] == "10.10.0.0/24"
    assert by_name["irb.100"]["zone"] == "irb.100"  # in no zone: its own name
    assert by_name["ge-0/0/3.0"]["enabled"] is False
    policies = {p["name"]: p for p in block["policies"]}
    filter_in = policies["ACL UNTRUST-IN in on untrust (ge-0/0/0.0)"]
    assert filter_in["stateful"] is False and filter_in["direction"] == "in" and filter_in["default"] == "deny"
    assert policies["ACL USERS-OUT out on trust (ge-0/0/1.0)"]["stateful"] is False
    security = policies[SECURITY_POLICIES]
    assert security["stateful"] is True and security["interface"] == "" and security["default"] == "deny"
    routes = {(r["vrf"], r["prefix"], r["kind"]) for r in block["routes"]}
    assert ("", "0.0.0.0/0", "default") in routes and ("GUEST", "0.0.0.0/0", "default") in routes
    assert ("", "192.168.99.0/24", "blackhole") in routes and ("", "10.30.0.0/24", "connected") in routes
    assert [n["kind"] for n in block["nat"]][:1] == ["static_nat"]
    assert "Routes learned by OSPF" in block["not_collected"] and "Routes learned by BGP" in block["not_collected"]
    assert SCREENS in block["not_collected"]


def test_forwarding_block_with_a_route_capture():
    block = _srx_block(SHOW_ROUTE)
    routes = {(r["vrf"], r["prefix"], r["kind"]) for r in block["routes"]}
    # The capture holds both tables: the configured routes are not added.
    assert ("", "10.50.0.0/16", "static") not in routes and ("", "10.20.0.0/16", "dynamic") in routes
    assert not any(n.startswith("Routes learned by") for n in block["not_collected"])


# ── Tracing through an SRX ──────────────────────────────────────────────────

_SRX_NODE = {
    "id": 9,
    "label": "srx-edge1",
    "ip": "192.0.2.1",
    "in_inventory": True,
    "device_type": "juniper_srx",
    "group_id": 3,
    "group_name": "HQ",
}


def _srx_tracer():
    block = _srx_block()
    subnets = subnets_for_host(_SRX_NODE, block)
    return _tracer({}, hosts={9: block}, extra_nodes=[_SRX_NODE], subnets=subnets)


def _item(direction: dict, where: str) -> dict:
    return next(i for hop in direction["hops"] for i in hop["items"] if i["where"] == where)


def test_srx_policies_decide_and_the_filter_lets_only_established_replies_in():
    tracer = _srx_tracer()

    # Trust to untrust on 443: the policy permits, the replies pass by state and the filter's established term.
    allowed = tracer.trace("10.10.0.20", "192.0.2.50", source_node=9, protocol="tcp", port=443)
    assert allowed["verdict"] == "allowed", allowed["summary"]
    [srx] = allowed["request"]["hops"]
    # The users' network is a second address of ge-0/0/1.0, in its zone.
    assert srx["in"] == "ge-0/0/1.0 (secondary 10.10.0.2)" and srx["out"] == "ge-0/0/0.0"
    permit = _item(allowed["request"], SECURITY_POLICIES)
    assert permit["status"] == "ok" and "allow-web" in permit["text"]
    assert (
        _item(allowed["reply"], SECURITY_POLICIES)["text"] == "Stateful: the reply of an allowed request is accepted."
    )
    reply_filter = _item(allowed["reply"], "ACL UNTRUST-IN in on untrust (ge-0/0/0.0)")
    assert reply_filter["status"] == "ok" and "established" in reply_filter["text"] and reply_filter["rule"] == 1

    # No policy from trust to dmz on 443: the default policy denies it.
    denied = tracer.trace("10.10.0.20", "10.30.0.10", source_node=9, protocol="tcp", port=443)
    assert denied["verdict"] == "blocked"
    default = _item(denied["request"], SECURITY_POLICIES)
    assert default["status"] == "blocked" and default["text"] == "No rule matches: the default action denies it."

    # An application the configuration does not define: unknown, never allowed.
    unknown = tracer.trace("10.10.0.20", "192.0.2.50", source_node=9, protocol="tcp", port=9000)
    assert unknown["verdict"] == "unknown"
    custom = _item(unknown["request"], SECURITY_POLICIES)
    assert custom["status"] == "unknown" and "app-not-defined" in custom["text"]

    # A connection opened from untrust is no established reply: the filter's last term discards it.
    opened = tracer.trace("192.0.2.50", "10.10.0.20", protocol="tcp", port=22)
    assert opened["verdict"] == "blocked"
    dropped = _item(opened["request"], "ACL UNTRUST-IN in on untrust (ge-0/0/0.0)")
    assert dropped["status"] == "blocked" and dropped["rule"] == 7
