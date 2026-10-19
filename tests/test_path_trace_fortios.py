"""Tests for the Fortinet FortiGate (FortiOS) reader of path tracing.

``fortios_config.parse_config`` reads ``show full-configuration`` backups
(one VDOM, or the root VDOM of several), ``parse_routes`` ``get router info
routing-table all`` captures; ``forwarding_for_host`` turns them into the
forwarding block of an inventory host, which the tracer walks.
"""

from __future__ import annotations

from netcontrol.integrations.meraki.forwarding import ANY, INTERFACE
from netcontrol.integrations.pathtrace import fortios_config
from netcontrol.integrations.pathtrace.engine import STATEFUL_REPLY
from netcontrol.integrations.pathtrace.fortios_config import (
    FIREWALL_POLICIES,
    IPSEC_TUNNELS,
    IPV6_POLICIES,
    LOCAL_IN_POLICIES,
    POLICY_ROUTES,
    SDWAN_RULES,
    parse_config,
    parse_routes,
)
from netcontrol.integrations.pathtrace.inventory import forwarding_for_host, parse_route_table, subnets_for_host
from netcontrol.integrations.pathtrace.platforms import platform_of

from test_path_trace import _labels, _tracer

FORTIGATE = """\
#config-version=FGT60F-7.2.8-FW-build1639-240313:opmode=0:vdom=0:user=admin
#conf_file_ver=1234567890
#buildno=1639
#global_vdom=1
config system global
    set alias "FortiGate-60F"
    set hostname "fgt-edge1"
    set timezone 04
end
config system settings
    set central-nat disable
    set ngfw-mode profile-based
end
config system interface
    edit "wan1"
        set vdom "root"
        set ip 203.0.113.2 255.255.255.252
        set allowaccess ping https ssh
        set type physical
        set alias "ISP-A"
        set role wan
        set snmp-index 1
    next
    edit "wan2"
        set vdom "root"
        set mode dhcp
        set allowaccess ping
        set type physical
        set role wan
        set snmp-index 2
    next
    edit "internal1"
        set vdom "root"
        set ip 10.1.20.1 255.255.255.0
        set allowaccess ping https ssh snmp
        set type physical
        set description "Printers"
        set role lan
        set snmp-index 3
    next
    edit "dmz"
        set vdom "root"
        set ip 172.16.0.1 255.255.255.0
        set allowaccess ping
        set type physical
        set role dmz
        set snmp-index 4
        set secondary-IP enable
        config secondaryip
            edit 1
                set ip 172.16.1.1 255.255.255.0
                set allowaccess ping
            next
        end
    next
    edit "internal2"
        set vdom "root"
        set type physical
        set status down
        set snmp-index 5
    next
    edit "lan-vl10"
        set vdom "root"
        set ip 10.1.10.2 255.255.255.0
        set allowaccess ping https
        set description "Users"
        set role lan
        set snmp-index 10
        set interface "internal1"
        set vlanid 10
        config vrrp
            edit 10
                set vrip 10.1.10.1
                set priority 200
            next
        end
    next
    edit "mgmt-vrf"
        set vdom "root"
        set ip 192.168.99.1 255.255.255.0
        set type loopback
        set vrf 5
        set snmp-index 11
    next
    edit "VPN-HQ"
        set vdom "root"
        set type tunnel
        set snmp-index 12
        set interface "wan1"
    next
end
config system zone
    edit "LAN"
        set intrazone allow
        set interface "lan-vl10" "internal1"
    next
end
config firewall address
    edit "all"
        set uuid 1b4c5a72-0000-51ee-0000-000000000001
    next
    edit "none"
        set uuid 1b4c5a72-0000-51ee-0000-000000000002
        set subnet 0.0.0.0 255.255.255.255
    next
    edit "USERS-NET"
        set uuid 1b4c5a72-0000-51ee-0000-000000000003
        set associated-interface "lan-vl10"
        set subnet 10.1.10.0 255.255.255.0
    next
    edit "PRINTERS-NET"
        set uuid 1b4c5a72-0000-51ee-0000-000000000004
        set type interface-subnet
        set subnet 10.1.20.0 255.255.255.0
        set interface "internal1"
    next
    edit "WEB-SRV"
        set uuid 1b4c5a72-0000-51ee-0000-000000000005
        set subnet 172.16.0.10 255.255.255.255
    next
    edit "DHCP-POOL"
        set uuid 1b4c5a72-0000-51ee-0000-000000000006
        set type iprange
        set start-ip 10.1.10.100
        set end-ip 10.1.10.131
    next
    edit "updates.example.com"
        set uuid 1b4c5a72-0000-51ee-0000-000000000007
        set type fqdn
        set fqdn "updates.example.com"
    next
    edit "Blocked-Countries"
        set uuid 1b4c5a72-0000-51ee-0000-000000000008
        set type geography
        set country "KP"
    next
    edit "ODD-HOSTS"
        set uuid 1b4c5a72-0000-51ee-0000-000000000009
        set type wildcard
        set wildcard 10.1.0.1 255.255.0.255
    next
    edit "PARTNER-NET"
        set uuid 1b4c5a72-0000-51ee-0000-000000000010
        set subnet 198.51.100.0 255.255.255.0
    next
end
config firewall addrgrp
    edit "INTERNAL"
        set uuid 1b4c5a72-0000-51ee-0000-000000000011
        set member "USERS-NET" "PRINTERS-NET"
    next
    edit "ALL-INTERNAL"
        set uuid 1b4c5a72-0000-51ee-0000-000000000012
        set member "INTERNAL" "DHCP-POOL"
    next
end
config firewall ippool
    edit "NAT-POOL"
        set startip 203.0.113.20
        set endip 203.0.113.23
    next
end
config firewall vip
    edit "web-vip"
        set uuid 1b4c5a72-0000-51ee-0000-000000000013
        set extip 203.0.113.10
        set mappedip "172.16.0.10"
        set extintf "wan1"
    next
    edit "rdp-fwd"
        set uuid 1b4c5a72-0000-51ee-0000-000000000014
        set extip 203.0.113.11
        set mappedip "172.16.0.20"
        set extintf "any"
        set portforward enable
        set extport 33890
        set mappedport 3389
    next
end
config firewall service custom
    edit "ALL"
        set category "General"
        set protocol IP
    next
    edit "HTTPS"
        set category "Web Access"
        set tcp-portrange 443
    next
    edit "DNS"
        set category "Network Services"
        set tcp-portrange 53
        set udp-portrange 53
    next
    edit "PING"
        set category "Network Services"
        set protocol ICMP
        set icmptype 8
        unset icmpcode
    next
    edit "WEB-ALT"
        set tcp-portrange 8000-8080 8443
    next
    edit "SRC-PINNED"
        set tcp-portrange 443:1024-65535
    next
    edit "ICMP-UNREACH"
        set protocol ICMP
        set icmptype 3
    next
end
config firewall service group
    edit "WEB"
        set member "HTTP" "HTTPS" "WEB-ALT"
    next
end
config firewall policy
    edit 10
        set name "Users to DMZ web"
        set uuid 6f0e9a8e-0000-51ee-0000-000000000010
        set srcintf "LAN"
        set dstintf "dmz"
        set action accept
        set srcaddr "INTERNAL"
        set dstaddr "WEB-SRV"
        set schedule "always"
        set service "WEB" "PING"
        set logtraffic all
        set comments "Intranet"
    next
    edit 15
        set name "Old printer access"
        set uuid 6f0e9a8e-0000-51ee-0000-000000000015
        set srcintf "LAN"
        set dstintf "dmz"
        set action accept
        set status disable
        set srcaddr "PRINTERS-NET"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
    next
    edit 20
        set name "Updates"
        set uuid 6f0e9a8e-0000-51ee-0000-000000000020
        set srcintf "LAN"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "updates.example.com"
        set schedule "always"
        set service "WEB-ALT"
        set nat enable
    next
    edit 25
        set name "Block countries"
        set uuid 6f0e9a8e-0000-51ee-0000-000000000025
        set srcintf "LAN"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "Blocked-Countries"
        set schedule "always"
        set service "ALL"
    next
    edit 30
        set name "Internet"
        set uuid 6f0e9a8e-0000-51ee-0000-000000000030
        set srcintf "LAN"
        set dstintf "wan1" "wan2"
        set action accept
        set srcaddr "ALL-INTERNAL"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set nat enable
    next
    edit 35
        set name "Partner via pool"
        set uuid 6f0e9a8e-0000-51ee-0000-000000000035
        set srcintf "dmz"
        set dstintf "wan1"
        set action accept
        set srcaddr "WEB-SRV"
        set dstaddr "PARTNER-NET"
        set schedule "always"
        set service "SRC-PINNED" "DNS"
        set nat enable
        set ippool enable
        set poolname "NAT-POOL"
    next
    edit 40
        set name "Published web"
        set uuid 6f0e9a8e-0000-51ee-0000-000000000040
        set srcintf "wan1"
        set dstintf "dmz"
        set action accept
        set srcaddr "all"
        set dstaddr "web-vip"
        set schedule "always"
        set service "HTTPS"
    next
    edit 45
        set name "Office hours RDP"
        set uuid 6f0e9a8e-0000-51ee-0000-000000000045
        set srcintf "any"
        set dstintf "dmz"
        set action accept
        set srcaddr "PARTNER-NET"
        set dstaddr "rdp-fwd"
        set schedule "office-hours"
        set service "RDP"
        set groups "vpn-users"
    next
    edit 50
        set name "Deny DMZ to LAN"
        set uuid 6f0e9a8e-0000-51ee-0000-000000000050
        set srcintf "dmz"
        set dstintf "LAN"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
config firewall policy6
    edit 1
        set srcintf "LAN"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
config firewall local-in-policy
    edit 1
        set intf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set service "SSH"
        set schedule "always"
    next
end
config vpn ipsec phase1-interface
    edit "VPN-HQ"
        set interface "wan1"
        set peertype any
        set proposal aes256-sha256
        set remote-gw 198.51.100.9
        set psksecret ENC fakefakefake
    next
end
config router static
    edit 1
        set gateway 203.0.113.1
        set device "wan1"
        set comment "ISP-A default"
    next
    edit 2
        set dst 10.99.0.0 255.255.0.0
        set blackhole enable
        set distance 254
    next
    edit 3
        set dst 10.50.0.0 255.255.0.0
        set device "VPN-HQ"
    next
    edit 4
        set dst 10.60.0.0 255.255.0.0
        set gateway 203.0.113.1
        set distance 20
        set device "wan1"
        set status disable
    next
    edit 5
        set dst 192.168.100.0 255.255.255.0
        set gateway 192.168.99.254
        set device "mgmt-vrf"
    next
end
config router policy
    edit 1
        set input-device "lan-vl10"
        set dst "10.200.0.0/255.255.0.0"
        set gateway 203.0.113.1
        set output-device "wan1"
    next
end
config router ospf
    set router-id 0.0.0.0
end
config router bgp
    set as 65010
    set router-id 10.1.10.2
    config neighbor
        edit "169.254.10.1"
            set remote-as 65000
            set interface "VPN-HQ"
        next
    end
end
"""

ROUTES = """\
fgt-edge1 # get router info routing-table all
Codes: K - kernel, C - connected, S - static, R - RIP, B - BGP
       O - OSPF, IA - OSPF inter area
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2
       i - IS-IS, L1 - IS-IS level-1, L2 - IS-IS level-2, ia - IS-IS inter area
       V - BGP VPNv4
       * - candidate default

Routing table for VRF=0
S*      0.0.0.0/0 [10/0] via 203.0.113.1, wan1, [1/0]
                  [10/0] via 198.51.100.254, wan2, [1/0]
S       10.50.0.0/16 [10/0] via VPN-HQ tunnel 198.51.100.9, [1/0]
S       10.99.0.0/16 [254/0] is a summary, Null, [1/0]
B       10.80.0.0/16 [20/0] via 169.254.10.1 (recursive is directly connected, VPN-HQ), 01:02:03, [1/0]
C       10.1.10.0/24 is directly connected, lan-vl10
C       10.1.20.0/24 is directly connected, internal1
C       172.16.0.0/24 is directly connected, dmz
C       172.16.1.0/24 is directly connected, dmz
C       198.51.100.0/24 is directly connected, wan2
C       203.0.113.0/30 is directly connected, wan1
O E2    10.70.0.0/16 [110/20] via 10.1.10.250, lan-vl10, 00:12:34, [1/0]

Routing table for VRF=5
C       192.168.99.0/24 is directly connected, mgmt-vrf
S       192.168.100.0/24 [10/0] via 192.168.99.254, mgmt-vrf, [1/0]
"""

MULTI_VDOM = """\
#config-version=FG100F-7.4.3-FW-build2573-240201:opmode=0:vdom=1:user=admin
config vdom
edit root
next
edit customer1
next
end
config global
config system global
    set hostname "fgt-core"
    set vdom-mode multi-vdom
end
config system interface
    edit "port1"
        set vdom "root"
        set ip 10.0.0.1 255.255.255.0
        set type physical
    next
    edit "port2"
        set vdom "customer1"
        set ip 10.9.0.1 255.255.255.0
        set type physical
    next
    edit "vdom-link0"
        set vdom "root"
        set type vdom-link
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set vdom "root"
        config gui-dashboard
            edit 1
                set name "Status"
                config widget
                    edit 1
                        set type sysinfo
                    next
                end
            next
        end
    next
end
end
config vdom
edit root
config system settings
    set opmode nat
end
config firewall address
    edit "LAN"
        set subnet 10.0.0.0 255.255.255.0
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "vdom-link0"
        set action accept
        set srcaddr "LAN"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
    next
end
config router static
    edit 1
        set gateway 10.0.0.254
        set device "port1"
    next
end
next
edit customer1
config firewall policy
    edit 7
        set srcintf "port2"
        set dstintf "port2"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
    next
end
config router static
    edit 1
        set gateway 10.9.0.254
        set device "port2"
    next
end
next
end
"""


def _by_name(config):
    return {i.name: i for i in config.interfaces}


# ── parse_config ─────────────────────────────────────────────────────────────


def test_platform_reads_fortigate_backups_and_captures():
    platform = platform_of("fortinet")
    assert platform.key == "fortios" and platform.stateful
    assert platform.config is fortios_config.parse_config and platform.routes is fortios_config.parse_routes


def test_interfaces_with_zones_vlans_secondaries_vrrp_vrfs_and_dhcp():
    config = parse_config(FORTIGATE)
    found = _by_name(config)
    assert list(found) == ["wan1", "wan2", "internal1", "dmz", "internal2", "lan-vl10", "mgmt-vrf", "VPN-HQ"]
    assert found["wan1"].addresses == [("203.0.113.2", "203.0.113.0/30")] and found["wan1"].aliases == ["ISP-A"]
    assert found["wan1"].zone == "" and found["wan1"].vrf == ""
    # A VLAN sub-interface keeps its own name; both LAN interfaces are in the LAN zone.
    vlan = found["lan-vl10"]
    assert vlan.addresses == [("10.1.10.2", "10.1.10.0/24")] and vlan.description == "Users" and vlan.zone == "LAN"
    assert [(v.protocol, v.group, v.address) for v in vlan.virtual] == [("VRRP", "10", "10.1.10.1")]
    assert found["internal1"].zone == "LAN" and found["internal1"].description == "Printers"
    assert found["dmz"].addresses == [("172.16.0.1", "172.16.0.0/24"), ("172.16.1.1", "172.16.1.0/24")]
    assert found["internal2"].shutdown and found["internal2"].addresses == []
    assert found["mgmt-vrf"].vrf == "5"
    # A DHCP address is not in the configuration.
    assert found["wan2"].addresses == []
    assert "Interface addresses learned by DHCP or PPPoE (wan2)" in config.notes


def test_policies_are_one_ordered_stateful_rule_set_ending_in_the_implicit_deny():
    config = parse_config(FORTIGATE)
    [policy] = config.policies
    assert (policy.name, policy.kind, policy.default, policy.stateful) == (FIREWALL_POLICIES, "policy", "deny", True)
    order = list(dict.fromkeys(e.sequence for e in policy.entries))
    assert order == [10, 15, 20, 25, 30, 35, 40, 45, 50, None]
    by_seq: dict = {}
    for entry in policy.entries:
        by_seq.setdefault(entry.sequence, []).append(entry)

    # A service group with HTTP, HTTPS and a custom range, and PING: one entry per protocol.
    web = by_seq[10]
    assert [(e.protocol, e.dst_ports) for e in web] == [("tcp", "80,443,8000-8080,8443"), ("icmp", ANY)]
    assert all(e.src == ["10.1.10.0/24", "10.1.20.0/24"] and e.dst == ["172.16.0.10/32"] for e in web)
    assert web[0].src_zones == ["LAN"] and web[0].dst_zones == ["dmz"] and web[0].action == "allow"
    assert web[0].name == "Users to DMZ web" and web[0].comment == "Intranet" and web[0].unresolved == []

    [disabled] = by_seq[15]
    assert not disabled.enabled and disabled.protocol == ANY and disabled.dst == [ANY]

    [fqdn] = by_seq[20]
    assert fqdn.dst == [ANY] and fqdn.unresolved == ["fqdn address updates.example.com (updates.example.com)"]

    # No action: deny, FortiOS's default. A geography address is unresolved.
    [countries] = by_seq[25]
    assert countries.action == "deny" and countries.unresolved == ["geography address Blocked-Countries (KP)"]

    # Nested groups and a range; two egress interfaces.
    [internet] = by_seq[30]
    assert internet.src == [
        "10.1.10.0/24",
        "10.1.20.0/24",
        "10.1.10.100/30",
        "10.1.10.104/29",
        "10.1.10.112/28",
        "10.1.10.128/30",
    ]
    assert internet.dst_zones == ["wan1", "wan2"] and internet.protocol == ANY and internet.dst_ports == ANY

    # Services of several protocols and source ports: one entry each (see the next test).
    assert len(by_seq[35]) == 3 and by_seq[35][0].src == ["172.16.0.10/32"]

    # A VIP as destination matches its mapped address.
    [published] = by_seq[40]
    assert published.dst == ["172.16.0.10/32"] and published.src_zones == ["wan1"] and published.dst_ports == "443"

    # "any" interface; a schedule and a user group are unresolved.
    [rdp] = by_seq[45]
    assert rdp.src_zones == [] and rdp.dst == ["172.16.0.20/32"] and rdp.dst_ports == "3389"
    assert rdp.unresolved == ["schedule office-hours", "users and groups (vpn-users)"]

    [deny] = by_seq[50]
    assert deny.action == "deny" and deny.dst_zones == ["LAN"]

    # The zone's intrazone allow comes after the policies.
    [intrazone] = by_seq[None]
    assert intrazone.action == "allow" and intrazone.src_zones == ["LAN"] and intrazone.dst_zones == ["LAN"]


def test_service_ports_source_ports_and_icmp_types():
    config = parse_config(FORTIGATE)
    entries = {e.sequence: [] for e in config.policies[0].entries}
    for entry in config.policies[0].entries:
        entries[entry.sequence].append((entry.protocol, entry.dst_ports, entry.src_ports))
    assert entries[35] == [("tcp", "443", "1024-65535"), ("tcp", "53", ANY), ("udp", "53", ANY)]
    assert entries[40] == [("tcp", "443", ANY)]
    unreach = parse_config(
        FORTIGATE.replace(
            'set service "HTTPS"\n    next\n    edit 45', 'set service "ICMP-UNREACH"\n    next\n    edit 45'
        )
    )
    [icmp] = [e for e in unreach.policies[0].entries if e.sequence == 40]
    assert icmp.protocol == "icmp" and icmp.unresolved == ["service ICMP-UNREACH (ICMP type 3)"]


def test_unknown_objects_negation_and_ipsec_are_unresolved():
    text = """\
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set action ipsec
        set srcaddr "NOPE"
        set dstaddr "all"
        set dstaddr-negate enable
        set schedule "always"
        set service "MADE-UP"
        set vpntunnel "HQ-P1"
    next
    edit 2
        set srcintf "port1"
        set dstintf "port2"
        set action accept
        set srcaddr "all"
        set internet-service enable
        set internet-service-name "Microsoft-Office365"
        set schedule "always"
    next
end
"""
    [first, second] = parse_config(text).policies[0].entries
    assert first.action == "allow" and first.src == [ANY]
    assert first.unresolved == [
        "address NOPE (not in the configuration)",
        "negated destination addresses",
        "policy-based IPsec VPN HQ-P1",
        "service MADE-UP (not in the configuration)",
    ]
    assert "Internet Service destinations" in second.unresolved


def test_a_backup_without_a_policy_table_leaves_the_default_unknown():
    config = parse_config(
        'config system interface\n    edit "port1"\n        set ip 10.0.0.1 255.255.255.0\n    next\nend\n'
    )
    assert config.policies[0].entries == [] and config.policies[0].default == "unknown"


def test_nat_from_vips_and_nat_enabled_policies():
    config = parse_config(FORTIGATE)
    vip, forward = config.nat[0], config.nat[1]
    assert (vip["kind"], vip["name"], vip["original_dst"], vip["translated_dst"], vip["src_interface"]) == (
        "vip",
        "web-vip",
        ["203.0.113.10/32"],
        ["172.16.0.10/32"],
        "wan1",
    )
    assert vip["protocol"] == ANY and vip["original_port"] == "" and not vip["translated_src"]
    assert (forward["protocol"], forward["original_port"], forward["translated_port"], forward["src_interface"]) == (
        "tcp",
        "33890",
        "3389",
        "",
    )
    snat = [n for n in config.nat if n["kind"] == "policy_nat"]
    assert [(n["name"], n["src_interface"], n["dst_interface"], n["translated_src"]) for n in snat] == [
        ("Updates", "LAN", "wan1", [INTERFACE]),
        ("Internet", "LAN", "wan1", [INTERFACE]),
        ("Internet", "LAN", "wan2", [INTERFACE]),
        ("Partner via pool", "dmz", "wan1", ["203.0.113.20/30"]),
    ]
    assert snat[3]["original_src"] == ["172.16.0.10/32"] and snat[3]["original_dst"] == ["198.51.100.0/24"]
    assert snat[3]["protocol"] == ANY
    assert [n["index"] for n in config.nat] == list(range(1, len(config.nat) + 1))


def test_an_earlier_policy_without_nat_is_an_identity_rule_in_front_of_a_nat_policy():
    text = """\
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "PEER"
        set schedule "always"
        set service "ALL"
    next
    edit 2
        set srcintf "port1"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
        set nat enable
    next
end
config firewall address
    edit "PEER"
        set subnet 192.0.2.0 255.255.255.0
    next
end
"""
    first, second = parse_config(text).nat
    assert first["original_dst"] == ["192.0.2.0/24"] and first["translated_src"] == first["original_src"] == [ANY]
    assert second["translated_src"] == [INTERFACE]


def test_central_nat_reads_the_central_snat_map():
    text = """\
config system settings
    set central-nat enable
end
config firewall address
    edit "LAN"
        set subnet 10.0.0.0 255.255.255.0
    next
end
config firewall ippool
    edit "POOL"
        set startip 198.51.100.10
        set endip 198.51.100.10
    next
end
config firewall central-snat-map
    edit 1
        set srcintf "port1"
        set dstintf "wan1"
        set orig-addr "LAN"
        set dst-addr "all"
        set nat-ippool "POOL"
    next
    edit 2
        set srcintf "port1"
        set dstintf "wan1"
        set orig-addr "all"
        set dst-addr "all"
        set orig-port 8080
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
        set nat enable
    next
end
"""
    config = parse_config(text)
    [entry] = config.nat
    assert (entry["kind"], entry["original_src"], entry["translated_src"]) == (
        "central_snat",
        ["10.0.0.0/24"],
        ["198.51.100.10/32"],
    )
    assert "Central SNAT rule 2 (matches on ports)" in config.notes


def test_static_routes_routing_protocols_and_notes():
    config = parse_config(FORTIGATE)
    routes = [(r.prefix, r.next_hop, r.interface, r.vrf, r.distance, r.name) for r in config.static_routes]
    assert routes == [
        ("0.0.0.0/0", "203.0.113.1", "wan1", "", 10, "ISP-A default"),
        ("10.99.0.0/16", "", "Null", "", 254, ""),
        ("10.50.0.0/16", "", "VPN-HQ", "", 10, ""),
        ("192.168.100.0/24", "192.168.99.254", "mgmt-vrf", "5", 10, ""),
    ]
    # OSPF is printed but has no network: it does not run.
    assert config.routing == ["BGP"]
    assert IPV6_POLICIES in config.notes and LOCAL_IN_POLICIES in config.notes
    assert IPSEC_TUNNELS in config.notes and POLICY_ROUTES in config.notes
    assert not any(n.startswith("Other VDOMs") for n in config.notes)


def test_sdwan_members_take_their_zone_and_sdwan_routes_use_each_member():
    text = """\
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.252
    next
    edit "wan2"
        set ip 198.51.100.2 255.255.255.252
    next
end
config system sdwan
    set status enable
    config zone
        edit "virtual-wan-link"
        next
    end
    config members
        edit 1
            set interface "wan1"
            set gateway 203.0.113.1
        next
        edit 2
            set interface "wan2"
            set gateway 198.51.100.1
        next
    end
    config service
        edit 1
            set name "O365"
            set dst "all"
            set priority-members 2 1
        next
    end
end
config router static
    edit 1
        set distance 1
        set sdwan-zone "virtual-wan-link"
    next
end
"""
    config = parse_config(text)
    assert {i.name: i.zone for i in config.interfaces} == {"wan1": "virtual-wan-link", "wan2": "virtual-wan-link"}
    assert [(r.prefix, r.next_hop, r.interface) for r in config.static_routes] == [
        ("0.0.0.0/0", "203.0.113.1", "wan1"),
        ("0.0.0.0/0", "198.51.100.1", "wan2"),
    ]
    assert SDWAN_RULES in config.notes


def test_multi_vdom_reads_the_root_vdom_and_notes_the_others():
    config = parse_config(MULTI_VDOM)
    assert [i.name for i in config.interfaces] == ["port1", "vdom-link0"]
    [entry] = config.policies[0].entries
    assert entry.sequence == 1 and entry.src == ["10.0.0.0/24"] and entry.dst_zones == ["vdom-link0"]
    assert [(r.prefix, r.next_hop) for r in config.static_routes] == [("0.0.0.0/0", "10.0.0.254")]
    assert "Other VDOMs (customer1)" in config.notes


def test_quoted_values_may_span_lines_and_hold_quotes():
    text = (
        "config firewall policy\n"
        "    edit 3\n"
        '        set name "Say \\"hi\\""\n'
        '        set comments "first line\nedit 99\nend"\n'
        '        set srcintf "port1"\n'
        '        set dstintf "port2"\n'
        "        set action accept\n"
        '        set srcaddr "all"\n'
        '        set dstaddr "all"\n'
        '        set service "ALL"\n'
        "    next\n"
        "end\n"
    )
    [entry] = parse_config(text).policies[0].entries
    assert entry.name == 'Say "hi"' and entry.comment == "first line\nedit 99\nend" and entry.action == "allow"


# ── parse_routes ─────────────────────────────────────────────────────────────


def test_parse_routes_reads_every_vrf_ecmp_recursive_tunnel_and_blackhole_routes():
    routes = parse_routes(ROUTES.split("\n"))
    found = [(r["vrf"], r["prefix"], r["kind"], r["next_hop"], r["interface"]) for r in routes]
    assert found == [
        ("", "0.0.0.0/0", "default", "203.0.113.1", "wan1"),
        ("", "0.0.0.0/0", "default", "198.51.100.254", "wan2"),
        ("", "10.50.0.0/16", "static", "", "VPN-HQ"),
        ("", "10.99.0.0/16", "blackhole", "", "Null"),
        ("", "10.80.0.0/16", "dynamic", "169.254.10.1", "VPN-HQ"),
        ("", "10.1.10.0/24", "connected", "", "lan-vl10"),
        ("", "10.1.20.0/24", "connected", "", "internal1"),
        ("", "172.16.0.0/24", "connected", "", "dmz"),
        ("", "172.16.1.0/24", "connected", "", "dmz"),
        ("", "198.51.100.0/24", "connected", "", "wan2"),
        ("", "203.0.113.0/30", "connected", "", "wan1"),
        ("", "10.70.0.0/16", "dynamic", "10.1.10.250", "lan-vl10"),
        ("5", "192.168.99.0/24", "connected", "", "mgmt-vrf"),
        ("5", "192.168.100.0/24", "static", "192.168.99.254", "mgmt-vrf"),
    ]
    bgp = next(r for r in routes if r["prefix"] == "10.80.0.0/16")
    assert bgp["source"] == "BGP" and bgp["metric"] == 0
    ospf = next(r for r in routes if r["prefix"] == "10.70.0.0/16")
    assert ospf["source"] == "OSPF external type 2" and ospf["metric"] == 20
    parsed, missing = parse_route_table(ROUTES, "fortinet")
    assert len(parsed) == len(routes) and missing == []


# ── forwarding_for_host ──────────────────────────────────────────────────────


def _block(capture: str | None = ROUTES) -> dict:
    return forwarding_for_host(
        {"ip_address": "10.1.10.2", "device_type": "fortinet"},
        [],
        {"id": 1, "routes_text": capture} if capture is not None else None,
        [],
        config_backup={"config_text": FORTIGATE},
    )


def test_forwarding_block_of_a_fortigate():
    block = _block()
    interfaces = {i["name"]: i for i in block["interfaces"]}
    assert interfaces["lan-vl10"]["zone"] == "LAN" and interfaces["internal1"]["zone"] == "LAN"
    assert interfaces["wan1"]["zone"] == "wan1" and interfaces["wan1"]["ip"] == "203.0.113.2"
    assert interfaces["lan-vl10 (VRRP 10.1.10.1)"]["zone"] == "LAN"
    assert interfaces["dmz (secondary 172.16.1.1)"]["cidr"] == "172.16.1.0/24"
    assert interfaces["mgmt-vrf"]["vrf"] == "5" and not interfaces["internal2"]["enabled"]
    # wan2's address is learned by DHCP: the capture gives its network.
    assert interfaces["wan2"]["cidr"] == "198.51.100.0/24"

    [policy] = block["policies"]
    assert (policy["name"], policy["stateful"], policy["default"], policy["applies"]) == (
        FIREWALL_POLICIES,
        True,
        "deny",
        "any",
    )
    assert policy["interface"] == "" and [r["index"] for r in policy["rules"]][:3] == [10, 10, 15]
    assert policy["rules"][0]["src_zones"] == ["LAN"] and policy["rules"][0]["dst_zones"] == ["dmz"]
    assert [n["kind"] for n in block["nat"]] == ["vip", "vip", "policy_nat", "policy_nat", "policy_nat", "policy_nat"]

    # The capture has VRF 0 and 5: the configured static routes are not added.
    assert not any(r["source"].startswith("Static route ISP") for r in block["routes"])
    assert any(r["kind"] == "blackhole" and r["prefix"] == "10.99.0.0/16" for r in block["routes"])
    assert IPSEC_TUNNELS in block["not_collected"] and "Access lists" not in block["not_collected"]


def test_forwarding_block_without_a_capture_uses_the_configured_routes():
    block = _block(None)
    routes = {(r["vrf"], r["prefix"], r["kind"]): r for r in block["routes"]}
    assert routes[("", "0.0.0.0/0", "default")]["next_hop"] == "203.0.113.1"
    assert routes[("", "10.99.0.0/16", "blackhole")]["interface"] == "Null"
    assert routes[("5", "192.168.100.0/24", "static")]["interface"] == "mgmt-vrf"
    assert routes[("", "10.1.10.0/24", "connected")]["interface"] == "lan-vl10"
    assert "Routes learned by BGP" in block["not_collected"]


# ── End to end ───────────────────────────────────────────────────────────────

_ISP_ROUTER = """\
hostname isp-rtr
!
interface GigabitEthernet0/0
 ip address 203.0.113.1 255.255.255.252
!
interface GigabitEthernet0/1
 description Partner
 ip address 198.51.100.1 255.255.255.0
!
ip route 203.0.113.8 255.255.255.248 203.0.113.2
ip route 10.0.0.0 255.0.0.0 203.0.113.2
!
end
"""
_E2E_CAPTURE = """\
Routing table for VRF=0
S*      0.0.0.0/0 [10/0] via 203.0.113.1, wan1, [1/0]
C       10.1.10.0/24 is directly connected, lan-vl10
C       10.1.20.0/24 is directly connected, internal1
C       172.16.0.0/24 is directly connected, dmz
C       203.0.113.0/30 is directly connected, wan1
"""


def _without(text: str, start: str, end: str) -> str:
    return text[: text.index(start)] + text[text.index(end) :]


# Without the policy route the default route is the only way out, and
# without the geography policy nothing unresolved stands before policy 30.
_E2E_CONFIG = _without(
    _without(FORTIGATE, "config router policy", "config router ospf"), "    edit 25\n", "    edit 30\n"
)
_NODES = [
    {"id": 21, "label": "fgt-edge1", "ip": "10.1.10.2", "in_inventory": True, "device_type": "fortinet"},
    {"id": 22, "label": "isp-rtr", "ip": "203.0.113.1", "in_inventory": True, "device_type": "cisco_ios"},
]


def _fortigate_and_router():
    """fgt-edge1 (LAN zone, a DMZ, wan1) linked to isp-rtr, which holds a
    partner network. Every network of both is in the subnet index."""
    fortigate = forwarding_for_host(
        {"ip_address": "10.1.10.2", "device_type": "fortinet"},
        [],
        {"id": 1, "routes_text": _E2E_CAPTURE},
        [],
        config_backup={"config_text": _E2E_CONFIG},
    )
    router = forwarding_for_host(
        {"ip_address": "203.0.113.1", "device_type": "cisco_ios"},
        [],
        None,
        [],
        config_backup={"config_text": _ISP_ROUTER},
    )
    subnets = [*subnets_for_host(_NODES[0], fortigate), *subnets_for_host(_NODES[1], router)]
    link = {"id": "lldp:21:22", "from": 21, "to": 22, "protocol": "lldp", "status": "up"}
    return _tracer({}, hosts={21: fortigate, 22: router}, extra_nodes=_NODES, extra_edges=[link], subnets=subnets)


def test_fortigate_policies_decide_translate_and_keep_state():
    tracer = _fortigate_and_router()

    # Users to the DMZ web server: policy 10 allows it; the replies pass by state.
    allowed = tracer.trace("10.1.10.0/24", "172.16.0.10", source_node=21, protocol="tcp", port=443)
    assert allowed["verdict"] == "allowed", allowed["summary"]
    [hop] = allowed["request"]["hops"]
    assert hop["in"] == "lan-vl10" and hop["out"] == "dmz"
    decided = next(i for i in hop["items"] if i["where"] == FIREWALL_POLICIES)
    assert decided["status"] == "ok" and decided["rule"] == 10 and "Users to DMZ web" in decided["text"]
    back = next(i for i in allowed["reply"]["hops"][0]["items"] if i["where"] == FIREWALL_POLICIES)
    assert back["text"] == STATEFUL_REPLY

    # No policy lets the users SSH to the DMZ: the implicit deny.
    denied = tracer.trace("10.1.10.0/24", "172.16.0.10", source_node=21, protocol="tcp", port=22)
    assert denied["verdict"] == "blocked"
    implicit = next(i for i in denied["request"]["hops"][0]["items"] if i["status"] == "blocked")
    assert (
        implicit["where"] == FIREWALL_POLICIES and implicit["text"] == "No rule matches: the default action denies it."
    )

    # To the partner network: policy 30 allows it and hides the source behind wan1.
    out = tracer.trace("10.1.10.0/24", "198.51.100.10", source_node=21, protocol="tcp", port=443)
    assert out["verdict"] == "allowed", out["summary"]
    assert _labels(out["request"]) == ["fgt-edge1", "isp-rtr"]
    edge = out["request"]["hops"][0]
    assert edge["out"] == "wan1"
    policy = next(i for i in edge["items"] if i["where"] == FIREWALL_POLICIES)
    assert policy["rule"] == 30 and policy["status"] == "ok"
    snat = next(i for i in edge["items"] if i["stage"] == "nat")
    # Source NAT is picked by interfaces, addresses and protocol, not port: policy 20
    # (an FQDN destination, so any) comes first and translates the same way.
    assert snat["where"].startswith("Policy NAT ") and snat["text"] == "Source 10.1.10.0/24 becomes 203.0.113.2."

    # From the partner network to the web VIP: translated, then matched by policy 40.
    published = tracer.trace("198.51.100.10", "203.0.113.10", source_node=22, protocol="tcp", port=443)
    assert published["verdict"] == "allowed", published["summary"]
    assert _labels(published["request"]) == ["isp-rtr", "fgt-edge1"]
    fgt = published["request"]["hops"][1]
    assert fgt["in"] == "wan1" and fgt["out"] == "dmz"
    dnat = next(i for i in fgt["items"] if i["stage"] == "nat")
    assert dnat["where"] == "Virtual IP web-vip" and dnat["text"] == "Destination 203.0.113.10 becomes 172.16.0.10."
    policy = next(i for i in fgt["items"] if i["where"] == FIREWALL_POLICIES)
    assert policy["rule"] == 40 and policy["status"] == "ok"
    reply = published["reply"]["hops"][0]
    assert any(i["stage"] == "nat" and "translated back" in i["text"] for i in reply["items"])
    assert any(i["text"] == STATEFUL_REPLY for i in reply["items"])

    # An FQDN address cannot be resolved: the flow it may match is unknown.
    fqdn = tracer.trace("10.1.10.0/24", "198.51.100.10", source_node=21, protocol="tcp", port=8443)
    assert fqdn["verdict"] == "unknown"
    unknown = next(i for i in fqdn["request"]["hops"][0]["items"] if i["status"] == "unknown")
    assert unknown["where"] == FIREWALL_POLICIES and unknown["rule"] == 20 and "updates.example.com" in unknown["text"]
