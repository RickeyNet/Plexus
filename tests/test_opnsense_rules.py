"""OPNsense phase 2 (rules): config.xml read for path tracing and the rule views.

``opnsense_config`` reads the firewall's ``config.xml`` (stored as the config
backup of its inventory host) into interfaces, aliases, filter rules in pf
evaluation order, NAT and routes, and as the ``RunningConfig`` the inventory
forwarding block is built from; ``opnsense.rules`` flags the rules and
compares two backups; the API serves both. Every name and address is
invented (documentation ranges, example.com); no firewall is contacted.
"""

from __future__ import annotations

import pytest
from netcontrol.integrations.meraki.forwarding import ANY, INTERFACE
from netcontrol.integrations.opnsense.rules import analyze, diff, parse_rule_stats
from netcontrol.integrations.pathtrace import opnsense_config
from netcontrol.integrations.pathtrace.engine import STATEFUL_REPLY
from netcontrol.integrations.pathtrace.inventory import forwarding_for_host, subnets_for_host
from netcontrol.integrations.pathtrace.opnsense_config import (
    AUTOMATIC_NAT,
    BOGONS,
    DEFAULT_DENY,
    DEFAULT_PASS_OUT,
    IPSEC,
    POLICY_ROUTES,
    evaluation_order,
    parse_config,
    parse_document,
    parse_xml,
)
from netcontrol.integrations.pathtrace.platforms import interface_addresses, platform_of

from test_meraki_topology import api  # noqa: F401 - the fixture is used by name
from test_path_trace import _labels, _tracer

RULE_WEB = "11111111-1111-4111-8111-000000000001"
RULE_SSH_DMZ = "11111111-1111-4111-8111-000000000002"
RULE_BLOCK_GUEST = "11111111-1111-4111-8111-000000000003"
RULE_ANY = "11111111-1111-4111-8111-000000000004"
RULE_SHADOWED = "11111111-1111-4111-8111-000000000005"
RULE_DISABLED = "11111111-1111-4111-8111-000000000006"
RULE_MISSING = "11111111-1111-4111-8111-000000000007"
RULE_WAN_WEB = "11111111-1111-4111-8111-000000000008"
RULE_FLOAT_BLOCK = "11111111-1111-4111-8111-000000000009"
RULE_FLOAT_LOG = "11111111-1111-4111-8111-00000000000a"
RULE_FQDN = "11111111-1111-4111-8111-00000000000b"
RULE_MVC = "22222222-2222-4222-8222-000000000001"

CONFIG = f"""<?xml version="1.0"?>
<opnsense>
  <version>25.7</version>
  <system>
    <hostname>fw-lab-1</hostname>
    <domain>example.com</domain>
    <webgui><protocol>https</protocol></webgui>
    <ssh><enabled>enabled</enabled></ssh>
  </system>
  <interfaces>
    <wan>
      <enable>1</enable><if>igb0</if><descr>WAN</descr>
      <ipaddr>203.0.113.2</ipaddr><subnet>29</subnet><gateway>WAN_GW</gateway>
      <blockpriv>1</blockpriv><blockbogons>1</blockbogons>
    </wan>
    <lan>
      <enable>1</enable><if>igb1</if><descr>LAN</descr>
      <ipaddr>192.0.2.1</ipaddr><subnet>25</subnet>
      <ipaddrv6>2001:db8:1::1</ipaddrv6><subnetv6>64</subnetv6>
    </lan>
    <opt1>
      <enable>1</enable><if>igb1_vlan20</if><descr>DMZ</descr>
      <ipaddr>192.0.2.129</ipaddr><subnet>26</subnet>
    </opt1>
    <opt2>
      <enable>1</enable><if>igb1_vlan30</if>
      <ipaddr>192.0.2.193</ipaddr><subnet>27</subnet>
    </opt2>
    <opt3>
      <if>igb2</if><descr>SPARE</descr>
    </opt3>
  </interfaces>
  <vlans>
    <vlan><if>igb1</if><tag>20</tag><descr>dmz</descr><vlanif>igb1_vlan20</vlanif></vlan>
    <vlan><if>igb1</if><tag>30</tag><descr>guests</descr><vlanif>igb1_vlan30</vlanif></vlan>
  </vlans>
  <virtualip>
    <vip><mode>ipalias</mode><interface>wan</interface><subnet>203.0.113.3</subnet><subnet_bits>29</subnet_bits></vip>
  </virtualip>
  <gateways>
    <gateway_item>
      <interface>wan</interface><gateway>203.0.113.1</gateway><name>WAN_GW</name>
      <defaultgw>1</defaultgw><ipprotocol>inet</ipprotocol>
    </gateway_item>
    <gateway_item>
      <interface>lan</interface><gateway>192.0.2.126</gateway><name>CORE_GW</name><ipprotocol>inet</ipprotocol>
    </gateway_item>
  </gateways>
  <staticroutes>
    <route><network>198.51.100.0/24</network><gateway>WAN_GW</gateway><descr>Partner</descr></route>
    <route><network>203.0.113.64/26</network><gateway>CORE_GW</gateway><descr>Campus</descr></route>
    <route><network>203.0.113.128/26</network><gateway>Null4</gateway></route>
    <route><network>203.0.113.192/26</network><gateway>CORE_GW</gateway><disabled>1</disabled></route>
  </staticroutes>
  <OPNsense>
    <Firewall>
      <Alias>
        <aliases>
          <alias uuid="33333333-3333-4333-8333-000000000001">
            <enabled>1</enabled><name>WebServers</name><type>host</type>
            <content>192.0.2.140
192.0.2.141</content><description>DMZ web</description>
          </alias>
          <alias uuid="33333333-3333-4333-8333-000000000002">
            <enabled>1</enabled><name>WebPorts</name><type>port</type>
            <content>80
443
8000:8080</content>
          </alias>
          <alias uuid="33333333-3333-4333-8333-000000000003">
            <enabled>1</enabled><name>AllServers</name><type>networkgroup</type>
            <content>WebServers
Mgmt</content>
          </alias>
          <alias uuid="33333333-3333-4333-8333-000000000004">
            <enabled>1</enabled><name>Mgmt</name><type>network</type>
            <content>192.0.2.0/28</content>
          </alias>
          <alias uuid="33333333-3333-4333-8333-000000000005">
            <enabled>1</enabled><name>Updates</name><type>host</type>
            <content>updates.example.com</content>
          </alias>
          <alias uuid="33333333-3333-4333-8333-000000000006">
            <enabled>1</enabled><name>Blocklist</name><type>urltable</type>
            <content>https://lists.example.com/drop.txt</content>
          </alias>
        </aliases>
      </Alias>
      <Filter>
        <rules>
          <rule uuid="{RULE_MVC}">
            <enabled>1</enabled><sequence>10</sequence><action>block</action><quick>1</quick>
            <interface>lan,opt1</interface><direction>in</direction><ipprotocol>inet</ipprotocol>
            <protocol>any</protocol><source_net>Blocklist</source_net><source_not>0</source_not>
            <destination_net>any</destination_net><destination_not>0</destination_not>
            <description>Automation: drop listed sources</description>
          </rule>
        </rules>
      </Filter>
    </Firewall>
  </OPNsense>
  <filter>
    <rule uuid="{RULE_FLOAT_BLOCK}">
      <type>block</type><interface>lan,opt2</interface><floating>yes</floating><quick>1</quick>
      <direction>in</direction><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any/></source><destination><address>192.0.2.150</address><port>23</port></destination>
      <descr>Floating: no telnet to the old box</descr>
    </rule>
    <rule uuid="{RULE_FLOAT_LOG}">
      <type>pass</type><interface>opt1</interface><floating>yes</floating>
      <direction>out</direction><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><network>lan</network></source><destination><address>WebServers</address><port>WebPorts</port></destination>
      <descr>Floating: web into the DMZ (out)</descr>
    </rule>
    <rule uuid="{RULE_WEB}">
      <type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><network>lan</network></source>
      <destination><address>WebServers</address><port>WebPorts</port></destination>
      <descr>Users to DMZ web</descr>
    </rule>
    <rule uuid="{RULE_SSH_DMZ}">
      <type>block</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any/></source><destination><network>opt1</network><port>22</port></destination>
      <descr>No SSH into the DMZ</descr>
    </rule>
    <rule uuid="{RULE_FQDN}">
      <type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><network>lan</network></source>
      <destination><address>Updates</address><port>8443</port></destination>
      <descr>Update server</descr>
    </rule>
    <rule uuid="{RULE_ANY}">
      <type>pass</type><interface>lan</interface><ipprotocol>inet46</ipprotocol>
      <source><any/></source><destination><any/></destination>
      <descr>Default allow LAN to any</descr>
    </rule>
    <rule uuid="{RULE_SHADOWED}">
      <type>block</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>udp</protocol>
      <source><network>lan</network></source><destination><any/></destination>
      <descr>Too late: block UDP</descr>
    </rule>
    <rule uuid="{RULE_DISABLED}">
      <type>pass</type><interface>opt2</interface><ipprotocol>inet</ipprotocol>
      <source><any/></source><destination><any/></destination>
      <disabled>1</disabled><descr>Guests to anywhere (off)</descr>
    </rule>
    <rule uuid="{RULE_BLOCK_GUEST}">
      <type>reject</type><interface>opt2</interface><ipprotocol>inet</ipprotocol>
      <source><network>opt2</network></source><destination><network>lan</network></destination>
      <descr>Guests never reach the LAN</descr>
    </rule>
    <rule>
      <type>pass</type><interface>opt2</interface><ipprotocol>inet</ipprotocol>
      <source><network>opt2</network></source><destination><any/></destination>
      <gateway>WAN_GW</gateway><descr>Guests out (policy route)</descr>
    </rule>
    <rule uuid="{RULE_MISSING}">
      <type>pass</type><interface>opt1</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><address>OldPartners</address></source><destination><any/></destination>
      <descr>Refers to a deleted alias</descr>
    </rule>
    <rule uuid="{RULE_WAN_WEB}">
      <type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any/></source><destination><address>192.0.2.140</address><port>443</port></destination>
      <descr>Published web server</descr><associated-rule-id>nat_web</associated-rule-id>
    </rule>
    <rule>
      <type>pass</type><interface>enc0</interface><ipprotocol>inet</ipprotocol>
      <source><any/></source><destination><any/></destination><descr>IPsec in</descr>
    </rule>
  </filter>
  <nat>
    <outbound>
      <mode>hybrid</mode>
      <rule>
        <interface>wan</interface><source><network>192.0.2.128/26</network></source>
        <destination><any/></destination><target>203.0.113.3</target><descr>DMZ leaves as .3</descr>
      </rule>
      <rule>
        <interface>wan</interface><source><network>Mgmt</network></source>
        <destination><network>198.51.100.0/24</network></destination><nonat>1</nonat><descr>No NAT to partner</descr>
      </rule>
    </outbound>
    <rule uuid="44444444-4444-4444-8444-000000000001">
      <interface>wan</interface><protocol>tcp</protocol><ipprotocol>inet</ipprotocol>
      <source><any/></source><destination><network>wanip</network><port>443</port></destination>
      <target>192.0.2.140</target><local-port>443</local-port><descr>Web</descr>
      <associated-rule-id>nat_web</associated-rule-id>
    </rule>
    <rule uuid="44444444-4444-4444-8444-000000000002">
      <interface>wan</interface><protocol>tcp</protocol><ipprotocol>inet</ipprotocol>
      <source><any/></source><destination><address>203.0.113.9</address><port>2222</port></destination>
      <target>192.0.2.141</target><local-port>22</local-port><descr>SSH jump</descr>
      <associated-rule-id>pass</associated-rule-id>
    </rule>
    <onetoone>
      <interface>wan</interface><external>203.0.113.4</external>
      <source><address>192.0.2.142</address></source><destination><any/></destination><descr>Mail</descr>
    </onetoone>
  </nat>
  <ipsec><phase1><ikeid>1</ikeid><remote-gateway>198.51.100.200</remote-gateway></phase1></ipsec>
</opnsense>
"""


@pytest.fixture(scope="module")
def document():
    found = parse_document(CONFIG)
    assert found is not None
    return found


def _rule(config, uuid: str):
    return next(r for r in config.rules if r.uuid == uuid)


# ── Reading config.xml ───────────────────────────────────────────────────────


def test_parse_xml_refuses_what_is_not_an_opnsense_config():
    assert parse_xml("hostname router1\n!") is None
    assert parse_xml("<pfsense></pfsense>") is None
    assert parse_xml("<opnsense><broken></opnsense>") is None
    doctype = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "boom">]><opnsense><system/></opnsense>'
    assert parse_xml(doctype) is None
    hidden = '<!-- <opnsense> --><!DOCTYPE x [<!ENTITY e "boom">]><opnsense><system/></opnsense>'
    assert parse_xml(hidden) is None
    assert parse_document("not xml") is None
    assert parse_config("not xml").notes


def test_platform_reads_opnsense_backups():
    assert platform_of("opnsense").config is parse_config
    assert interface_addresses("opnsense", CONFIG) == [
        "203.0.113.2",
        "203.0.113.3",
        "192.0.2.1",
        "2001:db8:1::1",
        "192.0.2.129",
        "192.0.2.193",
    ]


def test_interfaces_vlans_and_state(document):
    interfaces = document.interfaces
    assert list(interfaces) == ["wan", "lan", "opt1", "opt2", "opt3"]
    assert interfaces["wan"].upstream and interfaces["wan"].block_private
    assert interfaces["opt2"].description == "VLAN 30 on igb1 (guests)"
    assert not interfaces["opt3"].enabled
    assert interfaces["lan"].networks() == ["192.0.2.0/25", "2001:db8:1::/64"]
    assert document.hostname == "fw-lab-1.example.com"


def test_rules_are_in_pf_evaluation_order(document):
    tiers = [r.tier for r in document.rules]
    assert tiers[0] == "automation" and tiers[1:3] == ["floating", "floating"]
    assert set(tiers[3:]) == {"interface"}
    assert [r.number for r in document.rules] == list(range(1, len(document.rules) + 1))
    web = _rule(document, RULE_WEB)
    assert web.source.cidrs == ["192.0.2.0/25", "2001:db8:1::/64"]
    assert web.destination.cidrs == ["192.0.2.140/32", "192.0.2.141/32"]
    assert web.destination.port_expression == "80,443,8000-8080"
    assert web.destination.aliases == ["WebServers", "WebPorts"]
    # A rule without a uuid gets a stable key of what it matches.
    keyless = next(r for r in document.rules if r.description == "Guests out (policy route)")
    assert keyless.uuid == "" and keyless.key.startswith("interface|opt2|in|inet|any|pass|")


def test_quick_rules_first_then_the_others_in_reverse(document):
    float_block = _rule(document, RULE_FLOAT_BLOCK)
    lan = evaluation_order(document.rules, document, "lan", "in")
    assert lan[0].tier == "automation" and lan[1] is float_block
    assert [r.uuid for r in lan[2:4]] == [RULE_WEB, RULE_SSH_DMZ]
    # A floating rule without quick: evaluated after every quick rule.
    out = evaluation_order(document.rules, document, "opt1", "out")
    assert [r.uuid for r in out] == [RULE_FLOAT_LOG]
    assert not _rule(document, RULE_FLOAT_LOG).quick


def test_unresolved_aliases_and_missing_aliases(document):
    fqdn = _rule(document, RULE_FQDN)
    assert fqdn.destination.cidrs == [ANY]
    assert fqdn.destination.unresolved == ["alias Updates (host name updates.example.com)"]
    mvc = _rule(document, RULE_MVC)
    assert mvc.source.unresolved == ["urltable alias Blocklist"]
    missing = _rule(document, RULE_MISSING)
    assert missing.source.missing == ["OldPartners"]
    assert POLICY_ROUTES in document.notes and f"Firewall rules of {IPSEC}" in document.notes


# ── RunningConfig ────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def running():
    return parse_config(CONFIG)


def test_running_config_interfaces_and_access_lists(running):
    by_zone = {i.zone: i for i in running.interfaces}
    assert by_zone["lan"].name == "igb1" and by_zone["opt1"].name == "igb1_vlan20"
    assert by_zone["wan"].kind == "wan" and by_zone["wan"].addresses[1] == ("203.0.113.3", "203.0.113.0/29")
    assert by_zone["opt3"].shutdown
    assert running.stateful
    lan = running.access_lists[by_zone["lan"].access_groups["in"]]
    # The anti-lockout rule comes before the configured ones.
    assert lan[0].name == "Anti-lockout rule"
    assert lan[1].name == "Automation: drop listed sources" and lan[1].unresolved == ["urltable alias Blocklist"]
    assert lan[-1].name == DEFAULT_DENY and lan[-1].action == "deny"
    # The anti-lockout rule protects the LAN address.
    anti = next(e for e in lan if e.name == "Anti-lockout rule")
    assert anti.dst == ["192.0.2.1/32"] and anti.dst_ports == "443,80,22"
    web = next(e for e in lan if e.name == "Users to DMZ web")
    assert web.src == ["192.0.2.0/25"] and web.dst_ports == "80,443,8000-8080"
    # inet46: both families, any address.
    allow_all = next(e for e in lan if e.name == "Default allow LAN to any")
    assert allow_all.src == [ANY] and allow_all.action == "allow"
    # Only an interface a floating out rule names has an out list, ending in the default pass.
    assert by_zone["opt1"].access_groups["out"] == "opt1 out"
    assert running.access_lists["opt1 out"][-1].name == DEFAULT_PASS_OUT
    assert "out" not in by_zone["lan"].access_groups
    wan = running.access_lists["wan"]
    assert wan[0].name == "Port forward SSH jump (pass)" and wan[0].dst == ["192.0.2.141/32"]
    assert wan[0].dst_ports == "22"
    assert wan[1].name == "Block private networks"
    disabled = next(e for e in running.access_lists["opt2"] if e.name == "Guests to anywhere (off)")
    assert not disabled.enabled


def test_running_config_nat(running):
    kinds = [(n["kind"], n["name"]) for n in running.nat]
    assert kinds == [
        ("static_nat", "Mail"),
        ("destination_nat", "Port forward Web"),
        ("destination_nat", "Port forward SSH jump"),
        ("static_nat", "Mail"),
        ("source_nat", "Outbound NAT DMZ leaves as .3"),
        ("source_nat", "Outbound NAT No NAT to partner"),
        ("source_nat", f"{AUTOMATIC_NAT} on wan"),
    ]
    web = running.nat[1]
    assert web["original_dst"] == ["203.0.113.2/32"] and web["translated_dst"] == ["192.0.2.140/32"]
    assert web["original_port"] == "443" and web["src_interface"] == "wan"
    ssh = running.nat[2]
    assert ssh["original_port"] == "2222" and ssh["translated_port"] == "22"
    assert ssh["original_dst"] == ["203.0.113.9/32"]
    mail_in, mail_out = running.nat[0], running.nat[3]
    assert mail_in["original_dst"] == ["203.0.113.4/32"] and mail_in["translated_dst"] == ["192.0.2.142/32"]
    assert mail_out["translated_src"] == ["203.0.113.4/32"] and mail_out["dst_interface"] == "wan"
    no_nat = running.nat[5]
    assert no_nat["translated_src"] == no_nat["original_src"] == ["192.0.2.0/28"]
    automatic = running.nat[6]
    assert automatic["translated_src"] == [INTERFACE]
    assert automatic["original_src"] == ["192.0.2.0/25", "192.0.2.128/26", "192.0.2.192/27"]


def test_running_config_routes_and_notes(running):
    routes = {r.prefix: r for r in running.static_routes}
    assert routes["198.51.100.0/24"].next_hop == "203.0.113.1" and routes["198.51.100.0/24"].interface == "igb0"
    assert routes["203.0.113.64/26"].interface == "igb1"
    assert routes["203.0.113.128/26"].interface == "Null"
    assert "203.0.113.192/26" not in routes
    assert routes["0.0.0.0/0"].next_hop == "203.0.113.1"
    assert IPSEC in running.notes and BOGONS in running.notes and POLICY_ROUTES in running.notes


def test_automatic_mode_dynamic_wan_and_advanced_mode():
    text = """<opnsense><interfaces>
      <wan><enable>1</enable><if>vtnet0</if><ipaddr>dhcp</ipaddr></wan>
      <lan><enable>1</enable><if>vtnet1</if><ipaddr>192.0.2.1</ipaddr><subnet>24</subnet></lan>
    </interfaces></opnsense>"""
    found = parse_config(text)
    assert [n["kind"] for n in found.nat] == ["source_nat"]
    assert any(n.startswith("Routes learned by DHCP or PPPoE") for n in found.notes)
    assert not any(r.prefix == "0.0.0.0/0" for r in found.static_routes)
    advanced = parse_config(
        text.replace("<interfaces>", "<nat><outbound><mode>advanced</mode></outbound></nat><interfaces>")
    )
    assert advanced.nat == []
    # No rules on an interface: its list is the default deny alone.
    assert [e.name for e in found.access_lists["lan"]][-1] == DEFAULT_DENY


def test_legacy_aliases_and_interface_groups():
    text = """<opnsense>
      <interfaces>
        <lan><enable>1</enable><if>em1</if><ipaddr>192.0.2.1</ipaddr><subnet>24</subnet></lan>
        <opt1><enable>1</enable><if>em2</if><ipaddr>198.51.100.1</ipaddr><subnet>24</subnet></opt1>
      </interfaces>
      <ifgroups><ifgroupentry><ifname>INSIDE</ifname><members>lan opt1</members></ifgroupentry></ifgroups>
      <aliases><alias><name>Servers</name><type>host</type><address>192.0.2.10 192.0.2.20-192.0.2.21</address></alias></aliases>
      <filter>
        <rule><type>pass</type><interface>INSIDE</interface><ipprotocol>inet</ipprotocol>
          <source><any/></source><destination><address>Servers</address></destination></rule>
      </filter>
    </opnsense>"""
    document = parse_document(text)
    assert document is not None
    [rule] = document.rules
    assert rule.tier == "group" and rule.destination.cidrs == ["192.0.2.10/32", "192.0.2.20/31"]
    running = parse_config(text)
    assert running.access_lists["opt1"][0].dst == ["192.0.2.10/32", "192.0.2.20/31"]


# ── Analysis ─────────────────────────────────────────────────────────────────


def test_analyze_flags(document):
    stats = {RULE_WEB: {"evaluations": 10, "packets": 5}, RULE_SSH_DMZ: {"evaluations": 10, "packets": 0}}
    view = analyze(document, stats)
    rules = {r["uuid"]: r for r in view["rules"] if r["uuid"]}
    assert rules[RULE_ANY]["flags"] == ["any_any"]
    shadowed = rules[RULE_SHADOWED]
    assert "shadowed" in shadowed["flags"] and shadowed["shadowed_by"] == rules[RULE_ANY]["number"]
    assert shadowed["shadow"] == "conflicting"
    assert rules[RULE_DISABLED]["flags"] == ["disabled"]
    assert rules[RULE_MISSING]["flags"] == ["missing_alias"] and rules[RULE_MISSING]["missing_aliases"] == [
        "OldPartners"
    ]
    assert "unused" in rules[RULE_SSH_DMZ]["flags"] and rules[RULE_WEB]["stats"]["packets"] == 5
    assert "unused" not in rules[RULE_WEB]["flags"]
    # A rule with an unresolved alias is never claimed to shadow anything.
    assert rules[RULE_FQDN]["shadowed_by"] is None
    # The LAN rule and the IPsec rule pass anything.
    assert view["summary"]["any_any"] == 2 and view["summary"]["rules"] == len(document.rules)
    assert view["stats_available"]
    assert rules[RULE_WEB]["source"]["text"] == "lan net"
    assert analyze(document)["stats_available"] is False


def test_redundant_rule_and_disjoint_rules_are_told_apart():
    text = """<opnsense><interfaces>
      <lan><enable>1</enable><if>em1</if><ipaddr>192.0.2.1</ipaddr><subnet>24</subnet></lan>
    </interfaces><filter>
      <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
        <source><network>lan</network></source><destination><address>198.51.100.0/24</address><port>1-1024</port></destination><descr>a</descr></rule>
      <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
        <source><address>192.0.2.10</address></source><destination><address>198.51.100.7</address><port>443</port></destination><descr>b</descr></rule>
      <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
        <source><address>192.0.2.10</address></source><destination><address>198.51.100.7</address><port>8443</port></destination><descr>c</descr></rule>
      <rule><type>pass</type><interface>lan</interface><protocol>udp</protocol>
        <source><address>192.0.2.10</address></source><destination><address>198.51.100.7</address><port>443</port></destination><descr>d</descr></rule>
    </filter></opnsense>"""
    document = parse_document(text)
    assert document is not None
    rules = {r["description"]: r for r in analyze(document)["rules"]}
    assert rules["b"]["shadowed_by"] == 1 and rules["b"]["shadow"] == "redundant"
    assert rules["c"]["shadowed_by"] is None and rules["d"]["shadowed_by"] is None


def test_parse_rule_stats():
    body = {"status": "ok", "stats": {RULE_WEB: {"evaluations": "12", "packets": 0, "bytes": 0, "states": 0, "x": 1}}}
    assert parse_rule_stats(body) == {RULE_WEB: {"evaluations": 12, "packets": 0, "bytes": 0, "states": 0}}
    assert parse_rule_stats({RULE_WEB: {"packets": 3}}) == {RULE_WEB: {"packets": 3}}
    assert parse_rule_stats(None) == {} and parse_rule_stats({"stats": []}) == {}


def test_diff_between_two_backups(document):
    changed = (
        CONFIG.replace("<descr>Users to DMZ web</descr>", "<descr>Users to DMZ web servers</descr>")
        .replace(f'<rule uuid="{RULE_SHADOWED}">', '<rule uuid="55555555-5555-4555-8555-000000000001">')
        .replace("<content>192.0.2.0/28</content>", "<content>192.0.2.0/27</content>")
        .replace("<mode>hybrid</mode>", "<mode>advanced</mode>")
        .replace("<local-port>22</local-port>", "<local-port>2022</local-port>")
    )
    after = parse_document(changed)
    assert after is not None
    found = diff(document, after)
    [web] = [c for c in found["rules"]["changed"] if c["key"] == RULE_WEB]
    assert web["changes"] == [
        {"field": "description", "before": "Users to DMZ web", "after": "Users to DMZ web servers"}
    ]
    assert [r["uuid"] for r in found["rules"]["added"]] == ["55555555-5555-4555-8555-000000000001"]
    assert [r["uuid"] for r in found["rules"]["removed"]] == [RULE_SHADOWED]
    assert [a["name"] for a in found["aliases"]["changed"]] == ["Mgmt"]
    assert found["nat"]["outbound_mode"] == {"before": "hybrid", "after": "advanced"}
    [ssh] = found["nat"]["port_forwards"]["changed"]
    assert ssh["changes"] == [{"field": "local_port", "before": "22", "after": "2022"}]
    assert found["summary"]["rules"] == 3 and found["summary"]["aliases"] == 1
    assert diff(document, document)["summary"] == {"rules": 0, "aliases": 0, "nat": 0}


# ── Path trace through an OPNsense inventory host ────────────────────────────

_ISP_ROUTER = """\
hostname isp-rtr
!
interface GigabitEthernet0/0
 ip address 203.0.113.1 255.255.255.248
!
interface GigabitEthernet0/1
 description Partner
 ip address 198.51.100.1 255.255.255.0
!
ip route 192.0.2.0 255.255.255.0 203.0.113.2
ip route 203.0.113.8 255.255.255.248 203.0.113.2
!
end
"""
_NODES = [
    {"id": 31, "label": "fw-lab-1", "ip": "192.0.2.1", "in_inventory": True, "device_type": "opnsense"},
    {"id": 32, "label": "isp-rtr", "ip": "203.0.113.1", "in_inventory": True, "device_type": "cisco_ios"},
]


# The URL table rule would make every LAN flow unknown: here it sits on the spare interface.
_E2E_CONFIG = CONFIG.replace("<interface>lan,opt1</interface>", "<interface>opt3</interface>")


def _firewall_and_router():
    firewall = forwarding_for_host(
        {"ip_address": "192.0.2.1", "device_type": "opnsense"}, [], None, [], config_backup={"config_text": _E2E_CONFIG}
    )
    router = forwarding_for_host(
        {"ip_address": "203.0.113.1", "device_type": "cisco_ios"},
        [],
        None,
        [],
        config_backup={"config_text": _ISP_ROUTER},
    )
    subnets = [*subnets_for_host(_NODES[0], firewall), *subnets_for_host(_NODES[1], router)]
    link = {"id": "lldp:31:32", "from": 31, "to": 32, "protocol": "lldp", "status": "up"}
    return firewall, _tracer(
        {}, hosts={31: firewall, 32: router}, extra_nodes=_NODES, extra_edges=[link], subnets=subnets
    )


def test_forwarding_block_of_an_opnsense_host():
    firewall, _tracer_ = _firewall_and_router()
    interfaces = {i["name"]: i for i in firewall["interfaces"]}
    assert interfaces["igb1"]["zone"] == "lan" and interfaces["igb0"]["kind"] == "wan"
    names = [p["name"] for p in firewall["policies"]]
    assert "ACL lan in on lan (igb1)" in names and "ACL opt1 out out on opt1 (igb1_vlan20)" in names
    assert all(p["stateful"] for p in firewall["policies"])
    assert any(r["prefix"] == "0.0.0.0/0" and r["next_hop"] == "203.0.113.1" for r in firewall["routes"])
    assert "Access lists" not in firewall["not_collected"]


def test_trace_through_an_opnsense_host_shows_rule_nat_and_egress():
    _block, tracer = _firewall_and_router()

    # LAN to the DMZ web servers: rule "Users to DMZ web" allows it, the
    # floating out rule lets it out of the DMZ, the replies pass by state.
    allowed = tracer.trace("192.0.2.0/25", "192.0.2.140", source_node=31, protocol="tcp", port=443)
    assert allowed["verdict"] == "allowed", allowed["summary"]
    [hop] = allowed["request"]["hops"]
    assert hop["in"] == "igb1" and hop["out"] == "igb1_vlan20"
    decided = next(i for i in hop["items"] if i["where"] == "ACL lan in on lan (igb1)" and i["status"] == "ok")
    assert "Users to DMZ web" in decided["text"]
    back = next(i for i in allowed["reply"]["hops"][0]["items"] if i["text"] == STATEFUL_REPLY)
    assert back["status"] == "info"

    # SSH into the DMZ: blocked by the rule before the any rule.
    denied = tracer.trace("192.0.2.0/25", "192.0.2.150", source_node=31, protocol="tcp", port=22)
    assert denied["verdict"] == "blocked"
    blocked = next(i for i in denied["request"]["hops"][0]["items"] if i["status"] == "blocked")
    assert "No SSH into the DMZ" in blocked["text"]

    # To the partner network: allowed, out of wan, not translated (no-NAT rule
    # for Mgmt does not cover the users; the automatic rule hides them).
    out = tracer.trace("192.0.2.64/26", "198.51.100.10", source_node=31, destination_node=32, protocol="tcp", port=443)
    assert out["verdict"] == "allowed", out["summary"]
    assert _labels(out["request"]) == ["fw-lab-1", "isp-rtr"]
    edge = out["request"]["hops"][0]
    assert edge["out"] == "igb0"
    snat = next(i for i in edge["items"] if i["stage"] == "nat")
    assert snat["where"] == f"Source NAT {AUTOMATIC_NAT} on wan" and "203.0.113.2" in snat["text"]

    # From the partner network to the SSH jump host: the port forward
    # translates it and, its filter rule being "pass", lets it in itself.
    published = tracer.trace("198.51.100.10", "203.0.113.9", source_node=32, protocol="tcp", port=2222)
    assert published["verdict"] == "allowed", published["summary"]
    assert _labels(published["request"]) == ["isp-rtr", "fw-lab-1"]
    fw = published["request"]["hops"][1]
    assert fw["in"] == "igb0" and fw["out"] == "igb1_vlan20"
    dnat = next(i for i in fw["items"] if i["stage"] == "nat")
    assert dnat["where"] == "Destination NAT Port forward SSH jump"
    assert dnat["text"] == "Destination 203.0.113.9 becomes 192.0.2.141, port 22."
    rule = next(i for i in fw["items"] if i["where"] == "ACL wan in on wan (igb0)")
    assert rule["status"] == "ok" and "Port forward SSH jump (pass)" in rule["text"]
    reply = published["reply"]["hops"][0]
    assert any(i["stage"] == "nat" and "translated back" in i["text"] for i in reply["items"])

    # The guests never reach the LAN (a reject rule).
    guests = tracer.trace("192.0.2.200", "192.0.2.10", source_node=31, protocol="tcp", port=445)
    assert guests["verdict"] == "blocked"
    assert any("Guests never reach the LAN" in i["text"] for i in guests["request"]["hops"][0]["items"])


def test_module_is_server_side_only():
    """The parser runs where the forwarding blocks are built (the server), as
    the other platforms' parsers do: an exported map carries built blocks."""
    from netcontrol.integrations.pathtrace.offline import MODULES

    assert "netcontrol/integrations/pathtrace/opnsense_config.py" not in MODULES
    assert opnsense_config.__name__ == "netcontrol.integrations.pathtrace.opnsense_config"


# ── API ──────────────────────────────────────────────────────────────────────


def _seed(text_before: str, text_after: str) -> dict:
    import asyncio

    import routes.database as db_module

    async def run() -> dict:
        group_id = await db_module.create_group("Firewalls")
        host_id = await db_module.add_host(group_id, "fw-lab-1", "192.0.2.1", device_type="opnsense")
        other_id = await db_module.add_host(group_id, "sw-lab-1", "192.0.2.2")
        first = await db_module.create_config_backup(None, host_id, text_before, capture_method="opnsense-api")
        second = await db_module.create_config_backup(None, host_id, text_after, capture_method="opnsense-api")
        foreign = await db_module.create_config_backup(None, other_id, "hostname sw-lab-1")
        org = await db_module.create_meraki_org("fw-lab-1 source", provider="opnsense", base_url="https://192.0.2.1")
        assert org is not None
        stats = {RULE_WEB: {"packets": 4}, RULE_SSH_DMZ: {"packets": 0}}
        snapshot = {
            "nodes": [],
            "rule_stats": {"host_id": host_id, "collected_at": "2026-11-15T08:00:00+00:00", "rules": stats},
        }
        await db_module.create_meraki_snapshot(org["id"], snapshot)
        return {"host": host_id, "other": other_id, "first": first, "second": second, "foreign": foreign}

    return asyncio.run(run())


def test_rules_and_diff_endpoints(api):  # noqa: F811 - the imported fixture
    after = CONFIG.replace("<descr>Users to DMZ web</descr>", "<descr>Users to DMZ web servers</descr>")
    ids = _seed(CONFIG, after)

    found = api.get(f"/api/opnsense/hosts/{ids['host']}/rules")
    assert found.status_code == 200, found.text
    body = found.json()
    assert body["backup"]["id"] == ids["second"] and body["host"] == "fw-lab-1" and body["available"]
    assert body["stats_collected_at"] == "2026-11-15T08:00:00+00:00" and body["stats_available"]
    rules = {r["uuid"]: r for r in body["rules"] if r["uuid"]}
    assert rules[RULE_WEB]["description"] == "Users to DMZ web servers"
    assert "unused" in rules[RULE_SSH_DMZ]["flags"] and rules[RULE_WEB]["stats"] == {"packets": 4}
    # Only parsed rules: never the backup's text.
    assert "<opnsense>" not in found.text

    changed = api.get(
        f"/api/opnsense/hosts/{ids['host']}/rules/diff",
        params={"from_backup": ids["first"], "to_backup": ids["second"]},
    )
    assert changed.status_code == 200, changed.text
    assert [c["key"] for c in changed.json()["rules"]["changed"]] == [RULE_WEB]
    assert changed.json()["from_backup"]["id"] == ids["first"]

    # Another host's backup, a host that is not OPNsense, an unknown host.
    foreign = api.get(
        f"/api/opnsense/hosts/{ids['host']}/rules/diff",
        params={"from_backup": ids["foreign"], "to_backup": ids["second"]},
    )
    assert foreign.status_code == 404
    # Without the ids: the newest backup against the one before it.
    newest = api.get(f"/api/opnsense/hosts/{ids['host']}/rules/diff").json()
    assert (newest["from_backup"]["id"], newest["to_backup"]["id"]) == (ids["first"], ids["second"])
    # A host whose backup is no config.xml, or with too few backups: an empty view that says why.
    other = api.get(f"/api/opnsense/hosts/{ids['other']}/rules").json()
    assert other["available"] is False and other["rules"] == [] and "not an OPNsense" in other["message"]
    assert api.get(f"/api/opnsense/hosts/{ids['other']}/rules/diff").json()["available"] is False
    assert api.get("/api/opnsense/hosts/999999/rules").status_code == 404


def test_rule_stats_are_kept_with_their_host(monkeypatch):
    import asyncio

    from netcontrol.routes import opnsense_collection

    async def host(_snapshot):
        return {"id": 7}

    monkeypatch.setattr(opnsense_collection, "matching_host", host)
    snapshot: dict = {}
    raw = {
        "timestamp": "2026-11-15T08:00:00+00:00",
        "rule_stats": {"status": "ok", "stats": {RULE_WEB: {"packets": 1}}},
    }
    kept = asyncio.run(opnsense_collection.attach_rule_stats(raw, snapshot))
    assert (
        kept
        == snapshot["rule_stats"]
        == {
            "host_id": 7,
            "collected_at": "2026-11-15T08:00:00+00:00",
            "rules": {RULE_WEB: {"packets": 1}},
        }
    )
    assert asyncio.run(opnsense_collection.attach_rule_stats({"rule_stats": None}, {})) is None
