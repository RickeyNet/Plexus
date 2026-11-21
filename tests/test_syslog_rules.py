"""Syslog alert rules (``netcontrol.syslog_rules``): parsing, the built-in
rules against sample messages of each device family they cover, custom
rules, the engine (thresholds, dedup, suppression, switches, auto-resolve),
the configuration-change and re-poll triggers, the API and the migration.

Every message here is invented in the format of the device family it names;
hostnames, interfaces and addresses are made up (documentation ranges).
"""

from __future__ import annotations

import asyncio
import time

import netcontrol.routes.state as state
import pytest
import routes.database as db
from netcontrol import monitoring_repoll as repoll, syslog_rules as sr
from netcontrol.routes import config_backups, config_drift, metrics_engine
from netcontrol.routes.device_config import DeviceConfig, store_device_config

from mcp_helpers import CsrfClient, admin_client, user_client

PREFIX = "/api/monitoring/syslog-rules"

# ── Parsing ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("message", "tag", "raw_tag", "text"),
    [
        (
            "<187>123: *Mar  1 00:01:02.123: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
            "LINK-UPDOWN",
            "LINK-3-UPDOWN",
            "Interface GigabitEthernet0/1, changed state to down",
        ),
        (
            "000045: sw-a1: Jan 10 10:00:00.000 UTC: %SYS-5-CONFIG_I: Configured from console by ops on vty0 (192.0.2.50)",
            "SYS-CONFIG_I",
            "SYS-5-CONFIG_I",
            "Configured from console by ops on vty0 (192.0.2.50)",
        ),
        (
            "<165>1 2026-01-10T10:00:00.000Z edge-r1 - - - - %OSPFv3-5-ADJCHG: Process 1, Nbr 192.0.2.2 on Gi0/0 from FULL to DOWN",
            "OSPFV3-ADJCHG",
            "OSPFv3-5-ADJCHG",
            "Process 1, Nbr 192.0.2.2 on Gi0/0 from FULL to DOWN",
        ),
        (
            "RP/0/RSP0/CPU0:Jan 10 10:00:00 UTC: bgp[1052]: %ROUTING-BGP-5-ADJCHANGE : neighbor 192.0.2.9 Up",
            "ROUTING-BGP-ADJCHANGE",
            "ROUTING-BGP-5-ADJCHANGE",
            "neighbor 192.0.2.9 Up",
        ),
        ("%ASA-5-111008: User 'ops' executed the 'write memory' command.", "ASA-111008", "ASA-5-111008", None),
        (
            "<28>Jan 10 10:00:00 edge-j1 mib2d[1234]: SNMP_TRAP_LINK_DOWN: ifIndex 526, ifAdminStatus up(1), "
            "ifOperStatus down(2), ifName ge-0/0/1",
            "SNMP_TRAP_LINK_DOWN",
            "SNMP_TRAP_LINK_DOWN",
            None,
        ),
        (
            '<28>1 2026-01-10T10:00:00.000Z edge-j1 mgd 2201 UI_COMMIT_COMPLETED [junos@2636.1.1.1.2.18 user="o]ps"] '
            "commit complete",
            "UI_COMMIT_COMPLETED",
            "UI_COMMIT_COMPLETED",
            "commit complete",
        ),
        ("<14>Jan 10 10:00:00 host1 cron[99]: job started", "", "", None),
    ],
)
def test_the_tag_and_text_are_parsed(message, tag, raw_tag, text):
    parsed = sr.parse_syslog_message(message)
    assert (parsed.tag, parsed.raw_tag) == (tag, raw_tag)
    if text is not None:
        assert parsed.text == text
    assert not parsed.message.startswith("<")


@pytest.mark.parametrize(
    ("message", "program", "body"),
    [
        # RFC 5424 (OPNsense's default): APP-NAME, structured data skipped.
        (
            '<134>1 2026-01-10T10:00:00+00:00 fw-a.example.com dpinger 4242 - [meta sequenceId="5"] '
            "MONITOR: WAN_GW (Addr: 192.0.2.254 Alarm: none -> down RTT: 0.0 ms RTTd: 0.0 ms Loss: 100.0 %)",
            "dpinger",
            "MONITOR: WAN_GW (Addr: 192.0.2.254 Alarm: none -> down RTT: 0.0 ms RTTd: 0.0 ms Loss: 100.0 %)",
        ),
        ("<14>1 2026-01-10T10:00:00Z host1 - - - - started", "", "started"),
        # RFC 3164 with and without timestamp and host name.
        ("<6>Jan 10 10:00:00 fw-a kernel: carp: 3@vtnet1: BACKUP -> MASTER", "kernel", "carp: 3@vtnet1: BACKUP -> MASTER"),
        ("<6>Jan  9 10:00:00 fw-a charon[812]: 12[IKE] IKE_SA deleted", "charon", "12[IKE] IKE_SA deleted"),
        ("openvpn_client2[5511]: Initialization Sequence Completed", "openvpn_client2", "Initialization Sequence Completed"),
        # A Cisco message names no program.
        ("<187>123: *Mar  1 00:01:02.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down", "", None),
    ],
)
def test_the_program_and_body_are_parsed(message, program, body):
    parsed = sr.parse_syslog_message(message)
    assert parsed.program == program
    if body is not None:
        assert parsed.body == body


def test_a_tagged_message_keeps_its_tag_text_and_gets_a_program():
    parsed = sr.parse_syslog_message(
        "<28>Jan 10 10:00:00 edge-j1 mib2d[1234]: SNMP_TRAP_LINK_DOWN: ifIndex 526, ifAdminStatus up(1), "
        "ifOperStatus down(2), ifName ge-0/0/1"
    )
    assert (parsed.tag, parsed.program) == ("SNMP_TRAP_LINK_DOWN", "mib2d")
    assert parsed.text.startswith("ifIndex 526")


def test_opnsense_login_failures_count_for_auth_failure():
    rules = {r.key: r for r in sr.merge_rules([])}
    failed = sr.parse_syslog_message(
        "<36>1 2026-01-10T10:00:00+00:00 fw-a.example.com audit 3101 - - user ops could not authenticate for "
        "WebGui. [using OPNsense\\Auth\\Local + OPNsense\\Auth\\Services\\WebGui] at 198.51.100.7"
    )
    assert sr._evaluate(rules["auth_failure"], failed) == {"action": "raise", "instance": ""}
    assert [k for k, r in rules.items() if sr._evaluate(r, failed)] == ["auth_failure"]
    ok = sr.parse_syslog_message(
        "audit[3101]: user ops authenticated successfully for WebGui [using OPNsense\\Auth\\Local + "
        "OPNsense\\Auth\\Services\\WebGui] at 198.51.100.7"
    )
    assert [k for k, r in rules.items() if sr._evaluate(r, ok)] == []
    assert "OPNsense" in sr.BUILTIN_BY_KEY["auth_failure"].families
    assert "program:audit" in rules["auth_failure"].tags


def test_tags_are_compared_without_the_severity_digit():
    assert sr.normalize_tag("%LINK-3-UPDOWN") == "LINK-UPDOWN"
    assert sr.normalize_tag("link-5-updown") == "LINK-UPDOWN"
    assert sr.normalize_tag("ROUTING-BGP-5-ADJCHANGE") == "ROUTING-BGP-ADJCHANGE"
    assert sr.normalize_tag("ASA-6-113015") == "ASA-113015"
    assert sr.normalize_tag("UI_COMMIT_COMPLETED") == "UI_COMMIT_COMPLETED"
    # Not FACILITY-<0..7>-MNEMONIC: kept whole.
    for tag in ("LINK-8-UPDOWN", "-3-UPDOWN", "LINK-3-", "LINK-3-UP DOWN", "LINK-33-UPDOWN", "3-UPDOWN", "A-B"):
        assert sr.normalize_tag(tag) == tag
    # Only the last severity digit is dropped.
    assert sr.normalize_tag("A-1-B-2-C") == "A-1-B-C"


# ── Built-in rules against samples of each device family ─────────────────────

# (message, rule key, raise / clear, instance)
SAMPLES = [
    # link_flap: interface down transitions.
    (
        "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, changed state to down",
        "link_flap",
        "raise",
        "GigabitEthernet1/0/5",
    ),
    (
        "%LINEPROTO-5-UPDOWN: Line protocol on Interface TenGigabitEthernet1/1/1, changed state to down",
        "link_flap",
        "raise",
        "TenGigabitEthernet1/1/1",
    ),
    (
        "leaf-1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet49/1 (to-spine-1), changed state to down",
        "link_flap",
        "raise",
        "Ethernet49/1",
    ),
    (
        "%ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/12 is down (Link failure)",
        "link_flap",
        "raise",
        "Ethernet1/12",
    ),
    (
        "ifmgr[201]: %PKT_INFRA-LINK-3-UPDOWN : Interface GigabitEthernet0/0/0/3, changed state to Down",
        "link_flap",
        "raise",
        "GigabitEthernet0/0/0/3",
    ),
    (
        "%ASA-4-411002: Line protocol on Interface GigabitEthernet0/2, changed state to down",
        "link_flap",
        "raise",
        "GigabitEthernet0/2",
    ),
    (
        "mib2d[1234]: SNMP_TRAP_LINK_DOWN: ifIndex 530, ifAdminStatus up(1), ifOperStatus down(2), ifName xe-0/0/4",
        "link_flap",
        "raise",
        "xe-0/0/4",
    ),
    # ospf_neighbor.
    (
        "%OSPF-5-ADJCHG: Process 10, Nbr 198.51.100.2 on GigabitEthernet0/1 from FULL to DOWN, Neighbor Down: "
        "Dead timer expired",
        "ospf_neighbor",
        "raise",
        "198.51.100.2",
    ),
    (
        "%OSPF-5-ADJCHG: Process 10, Nbr 198.51.100.2 on GigabitEthernet0/1 from LOADING to FULL, Loading Done",
        "ospf_neighbor",
        "clear",
        "198.51.100.2",
    ),
    (
        "%ROUTING-OSPF-5-ADJCHG : Process 1, Nbr 198.51.100.3 on GigabitEthernet0/0/0/1 in area 0 from FULL to DOWN, "
        "Neighbor Down: dead timer expired",
        "ospf_neighbor",
        "raise",
        "198.51.100.3",
    ),
    (
        "%OSPF-5-ADJCHANGE: ospf-100 [4387] Nbr 198.51.100.4 on Ethernet1/1 went DOWN",
        "ospf_neighbor",
        "raise",
        "198.51.100.4",
    ),
    (
        "%OSPF-5-NBRSTATE: ospf-100 [4387] Process 100, Nbr 198.51.100.7 on Ethernet1/2 from FULL to DOWN, "
        "HoldTimerExpired",
        "ospf_neighbor",
        "raise",
        "198.51.100.7",
    ),
    (
        "%OSPF-5-NBRSTATE: ospf-100 [4387] Process 100, Nbr 198.51.100.7 on Ethernet1/2 from LOADING to FULL, "
        "LoadingDone",
        "ospf_neighbor",
        "clear",
        "198.51.100.7",
    ),
    (
        "%OSPF-5-ADJCHANGE: ospf-100 [4387] Nbr 198.51.100.4 on Ethernet1/1 went FULL",
        "ospf_neighbor",
        "clear",
        "198.51.100.4",
    ),
    (
        "Rib: %OSPF-4-OSPF_ADJACENCY_TEARDOWN: NGB 198.51.100.5, interface 198.51.100.1 adjacency dropped: "
        "nbr did not list our router ID, state was: FULL",
        "ospf_neighbor",
        "raise",
        "198.51.100.5",
    ),
    (
        "Rib: %OSPF-4-OSPF_ADJACENCY_ESTABLISHED: NGB 198.51.100.5, interface 198.51.100.1 adjacency established",
        "ospf_neighbor",
        "clear",
        "198.51.100.5",
    ),
    (
        "rpd[2001]: RPD_OSPF_NBRDOWN: OSPF neighbor 198.51.100.6 (realm ospf-v2 ge-0/0/0.0 area 0.0.0.0) state "
        "changed from Full to Down due to InActiveTimer",
        "ospf_neighbor",
        "raise",
        "198.51.100.6",
    ),
    (
        "rpd[2001]: RPD_OSPF_NBRUP: OSPF neighbor 198.51.100.6 (realm ospf-v2 ge-0/0/0.0 area 0.0.0.0) state "
        "changed from Loading to Full due to LoadDone",
        "ospf_neighbor",
        "clear",
        "198.51.100.6",
    ),
    # bgp_neighbor.
    ("%BGP-5-ADJCHANGE: neighbor 203.0.113.1 Down BGP Notification sent", "bgp_neighbor", "raise", "203.0.113.1"),
    ("%BGP-5-ADJCHANGE: neighbor 203.0.113.1 vpn vrf BLUE Up", "bgp_neighbor", "clear", "203.0.113.1"),
    ("%BGP-5-NBR_RESET: Neighbor 203.0.113.2 reset (Peer closed the session)", "bgp_neighbor", "raise", "203.0.113.2"),
    (
        "%BGP-5-ADJCHANGE: bgp-65010 [3311] (default) neighbor 203.0.113.3 Down - sent: holdtimer expired error",
        "bgp_neighbor",
        "raise",
        "203.0.113.3",
    ),
    (
        "%ROUTING-BGP-5-ADJCHANGE : neighbor 203.0.113.4 Down - Peer closing down the session",
        "bgp_neighbor",
        "raise",
        "203.0.113.4",
    ),
    (
        "Bgp: %BGP-5-ADJCHANGE: peer 203.0.113.5 (VRF default AS 65020) old state Established event Stop new "
        "state Idle",
        "bgp_neighbor",
        "raise",
        "203.0.113.5",
    ),
    (
        "Bgp: %BGP-5-ADJCHANGE: peer 203.0.113.5 (VRF default AS 65020) old state OpenConfirm event Established "
        "new state Established",
        "bgp_neighbor",
        "clear",
        "203.0.113.5",
    ),
    (
        "rpd[2001]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 203.0.113.6+179 (External AS 65030) changed state "
        "from Established to Idle (event RecvNotify) (instance master)",
        "bgp_neighbor",
        "raise",
        "203.0.113.6",
    ),
    (
        "rpd[2001]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 203.0.113.6+179 (External AS 65030) changed state "
        "from OpenConfirm to Established (event RecvKeepAlive) (instance master)",
        "bgp_neighbor",
        "clear",
        "203.0.113.6",
    ),
    # power_supply.
    (
        "%IOSXE_PEM-3-PEMFAIL: The PEM in slot P1 is switched off or encountering a failure condition.",
        "power_supply",
        "raise",
        "P1",
    ),
    ("%IOSXE_PEM-6-PEMOK: The PEM in slot P1 is functioning properly", "power_supply", "clear", "P1"),
    (
        "%PLATFORM_FEP-1-FRU_PS_SIGNAL_FAULTY: Switch 2: Signal is faulty on power supply B",
        "power_supply",
        "raise",
        "2/B",
    ),
    ("%PLATFORM_FEP-6-FRU_PS_SIGNAL_OK: Switch 2: Signal is now ok on power supply B", "power_supply", "clear", "2/B"),
    ("%PLATFORM-2-PS_FAIL: Power supply 2 failed or shut down (Serial number ABC0000X1)", "power_supply", "raise", "2"),
    ("%PLATFORM-2-PS_OK: Power supply 2 ok (Serial number ABC0000X1)", "power_supply", "clear", "2"),
    (
        "chassisd[1500]: CHASSISD_SNMP_TRAP10: SNMP trap generated: Power Supply failed (jnxContentsContainerIndex 2, "
        "jnxContentsL1Index 1, jnxContentsDescr PEM 1, jnxOperatingState/Temp 6)",
        "power_supply",
        "raise",
        "PEM 1",
    ),
    (
        "chassisd[1500]: CHASSISD_SNMP_TRAP10: SNMP trap generated: Power Supply OK (jnxContentsContainerIndex 2, "
        "jnxContentsL1Index 1, jnxContentsDescr PEM 1, jnxOperatingState/Temp 2)",
        "power_supply",
        "clear",
        "PEM 1",
    ),
    # fan.
    (
        "%IOSXE_PEM-3-FANFAIL: The fan in slot P2/0 is encountering a failure condition",
        "fan",
        "raise",
        "P2/0",
    ),
    ("%IOSXE_PEM-6-FANOK: The fan in slot P2/0 is functioning properly", "fan", "clear", "P2/0"),
    ("%PLATFORM-2-FANMOD_FAN_FAIL: Fan module 3 (Fan3(sys_fan3) fan) failed", "fan", "raise", "3"),
    ("%PLATFORM-2-FANMOD_FAN_OK: Fan module 3 (Fan3(sys_fan3) fan) ok", "fan", "clear", "3"),
    (
        "chassisd[1500]: CHASSISD_SNMP_TRAP7: SNMP trap generated: Fan/Blower Failed (jnxContentsContainerIndex 4, "
        "jnxContentsDescr Fan Tray 0 Fan 1, jnxOperatingState/Temp 6)",
        "fan",
        "raise",
        "Fan Tray 0 Fan 1",
    ),
    # auth_failure (no instance: failures from any source count together).
    (
        "%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: ops] [Source: 192.0.2.50] [localport: 22] "
        "[Reason: Login Authentication Failed] at 10:00:00 UTC Sat Jan 10 2026",
        "auth_failure",
        "raise",
        "",
    ),
    (
        "%SECURITY-LOGIN-4-AUTHEN_FAILED : Failed authentication attempt by user 'ops' from '192.0.2.50' on 'vty0'",
        "auth_failure",
        "raise",
        "",
    ),
    (
        "%AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed for user ops from 192.0.2.50 - dcos_sshd[4400]",
        "auth_failure",
        "raise",
        "",
    ),
    (
        "%ASA-6-113015: AAA user authentication Rejected : reason = Invalid password : local database : "
        "user = ops : user IP = 192.0.2.50",
        "auth_failure",
        "raise",
        "",
    ),
    (
        '%ASA-6-605004: Login denied from 192.0.2.50/40000 to outside:192.0.2.1/ssh for user "ops"',
        "auth_failure",
        "raise",
        "",
    ),
    (
        "sshd[3001]: SSHD_LOGIN_FAILED: Login failed for user 'ops' from host '192.0.2.50'",
        "auth_failure",
        "raise",
        "",
    ),
]


@pytest.mark.parametrize(("message", "key", "action", "instance"), SAMPLES)
def test_each_builtin_rule_matches_its_samples(message, key, action, instance):
    parsed = sr.parse_syslog_message(message)
    rules = {r.key: r for r in sr.merge_rules([])}
    found = {k: sr._evaluate(r, parsed) for k, r in rules.items()}
    assert found[key] == {"action": action, "instance": instance}
    # No other rule acts on it.
    assert [k for k, v in found.items() if v and k != key] == []


@pytest.mark.parametrize(
    "message",
    [
        # Shut down by an operator: not a flap.
        "%LINK-5-CHANGED: Interface GigabitEthernet0/3, changed state to administratively down",
        "%ETHPORT-5-IF_DOWN_ADMIN_DOWN: Interface Ethernet1/3 is down (Administratively down)",
        "mib2d[1234]: SNMP_TRAP_LINK_DOWN: ifIndex 531, ifAdminStatus down(2), ifOperStatus down(2), ifName ge-0/0/5",
        "%LINK-3-UPDOWN: Interface GigabitEthernet0/3, changed state to up",
        "%OSPF-5-ADJCHG: Process 1, Nbr 198.51.100.2 on Gi0/1 from EXSTART to EXCHANGE, Negotiation Done",
        "%SYS-5-CONFIG_I: Configured from console by ops on vty0 (192.0.2.50)",
    ],
)
def test_other_messages_raise_nothing(message):
    parsed = sr.parse_syslog_message(message)
    assert [r.key for r in sr.merge_rules([]) if sr._evaluate(r, parsed)] == []


def test_every_builtin_is_covered_by_a_sample():
    assert {key for _m, key, _a, _i in SAMPLES} == set(sr.BUILTIN_BY_KEY)
    for rule in sr.BUILTIN_RULES:
        assert rule.severity in sr.SEVERITIES and rule.families


@pytest.mark.parametrize(
    "message",
    [
        "%SYS-5-CONFIG_I: Configured from console by ops on vty0 (192.0.2.50)",
        "ConfigAgent: %SYS-5-CONFIG_I: Configured from console by ops on vty3 (192.0.2.50)",
        "%VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by ops on 192.0.2.50@pts/0",
        "config[65]: %MGBL-CONFIG-6-DB_COMMIT : Configuration committed by user 'ops'. Use 'show configuration "
        "commit changes 1000000021' to view the changes.",
        "%ASA-5-111008: User 'ops' executed the 'access-list OUTSIDE extended permit ip any any' command.",
        "%ASA-5-111010: User 'ops', running 'CLI' from IP 192.0.2.50, executed 'write memory'",
        "mgd[2201]: UI_COMMIT_COMPLETED: commit complete",
    ],
)
def test_configuration_change_messages(message):
    assert sr.is_config_change(sr.parse_syslog_message(message))


def test_a_show_command_is_no_configuration_change():
    parsed = sr.parse_syslog_message("%ASA-5-111010: User 'ops', running 'CLI' from IP 192.0.2.50, executed 'show run'")
    assert not sr.is_config_change(parsed)
    assert not sr.is_config_change(sr.parse_syslog_message("mgd[2201]: UI_COMMIT: User 'ops' requested 'commit'"))


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        ("%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down", "interface_down"),
        ("%SYS-5-RELOAD: Reload requested by ops on vty0 (192.0.2.50). Reload Reason: Reload Command.", "reload"),
        ("%ASA-5-199001: Reload command executed from Telnet (remote 192.0.2.50).", "reload"),
        ("%PLATFORM-2-PFM_SYSTEM_RESET: Manual system restart from Command Line Interface", "reload"),
        ("mgd[2201]: UI_REBOOT_EVENT: System going down IMMEDIATELY", "reload"),
        ("%SYS-5-RESTART: System restarted --", "restart"),
        ("%SYS-6-BOOTTIME: Time taken to reboot after reload =  194 seconds", "restart"),
        ("%ASA-6-199002: Startup completed. Beginning operation.", "restart"),
        ("snmpd[900]: SNMPD_TRAP_COLD_START: trap_generate_cold: SNMP trap: cold start", "restart"),
        ("%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up", ""),
    ],
)
def test_repoll_reasons(message, reason):
    assert sr.repoll_reason(sr.parse_syslog_message(message)) == reason


# ── Custom rules ─────────────────────────────────────────────────────────────


def _custom(**body) -> sr.Rule:
    return sr.draft_rule({"name": "custom", "severity": "warning", **body})


def test_custom_match_types():
    stp = sr.parse_syslog_message("%SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi1/0/7 with BPDU Guard enabled.")
    by_tag = _custom(match_type="tag", pattern="%SPANTREE-2-BLOCK_BPDUGUARD, OTHER_TAG")
    assert sr._evaluate(by_tag, stp) == {"action": "raise", "instance": ""}
    # The severity digit is not compared.
    assert sr._evaluate(_custom(match_type="tag", pattern="SPANTREE-BLOCK_BPDUGUARD"), stp)["action"] == "raise"
    assert sr._evaluate(_custom(match_type="contains", pattern="bpdu guard ENABLED"), stp)["action"] == "raise"
    assert sr._evaluate(_custom(match_type="contains", pattern="not in the message"), stp) is None
    by_regex = _custom(
        match_type="regex", pattern=r"BPDU on port (?P<instance>\S+)", clear_pattern=r"recovered on (\S+)"
    )
    assert sr._evaluate(by_regex, stp) == {"action": "raise", "instance": "Gi1/0/7"}
    clear = sr.parse_syslog_message(
        "%PM-4-ERR_RECOVER: Attempting to recover from bpduguard err-disable state on Gi1/0/7"
    )
    assert sr._evaluate(by_regex, clear) is None
    clear = sr.parse_syslog_message("%CUSTOM-5-OK: port recovered on Gi1/0/7")
    assert sr._evaluate(by_regex, clear) == {"action": "clear", "instance": "Gi1/0/7"}


@pytest.mark.parametrize(
    ("body", "error"),
    [
        ({"match_type": "regex", "pattern": "(?=lookahead)x"}, "not a valid regular expression"),
        ({"match_type": "regex", "pattern": r"(a)\1"}, "not a valid regular expression"),
        ({"match_type": "regex", "pattern": "ok", "clear_pattern": "(unclosed"}, "clear pattern"),
        ({"match_type": "tag", "pattern": " , "}, "at least one tag"),
        ({"match_type": "contains", "pattern": "  "}, "needs a pattern"),
        ({"match_type": "glob", "pattern": "x"}, "match_type"),
        ({"match_type": "contains", "pattern": "x", "severity": "major"}, "severity"),
        ({"match_type": "contains", "pattern": "x", "threshold_count": 0}, "threshold_count"),
        ({"match_type": "contains", "pattern": "x", "auto_resolve_minutes": -1}, "auto_resolve_minutes"),
        ({"match_type": "contains", "pattern": "x", "name": ""}, "name"),
        ({"match_type": "contains", "pattern": "x" * 501}, "longer than"),
    ],
)
def test_invalid_custom_rules_are_rejected(body, error):
    with pytest.raises(sr.RuleError) as exc:
        sr.clean_custom_rule({"name": "r", **body})
    assert error in exc.value.message


def test_a_tag_pattern_of_separators_only_is_rejected():
    with pytest.raises(sr.RuleError, match="at least one tag"):
        sr.clean_custom_rule({"name": "r", "match_type": "tag", "pattern": "%"})


# ── The engine ───────────────────────────────────────────────────────────────


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def engine(monkeypatch):
    """Monitoring on, every switch on, a fake clock, and re-polls and
    configuration changes recorded instead of run."""
    sr.reset_state()
    clock = _Clock()
    monkeypatch.setattr(sr, "_clock", clock)
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", True)
    monkeypatch.setattr(
        state,
        "EVENT_RECEIVER_CONFIG",
        {"syslog_alerts": True, "config_change_trigger": True, "repoll_trigger": True},
    )
    repolls: list[tuple[int, float, float]] = []
    changes: list[int] = []

    def fake_repoll(host_id, delay, *, min_interval=0.0):
        repolls.append((host_id, delay, min_interval))
        return True

    monkeypatch.setattr(sr, "schedule_repoll", fake_repoll)
    monkeypatch.setattr(sr, "note_config_change", changes.append)
    yield clock, repolls, changes
    sr.reset_state()


async def _host(name: str = "sw-1", ip: str = "192.0.2.10", device_type: str = "cisco_ios") -> tuple[int, int]:
    await db.init_db()
    group_id = await db.create_group(f"grp-{name}")
    return group_id, await db.add_host(group_id, name, ip, device_type)


async def _open(host_id: int) -> dict[str, dict]:
    return {a["dedup_key"]: a for a in await db.get_monitoring_alerts(host_id, acknowledged=False)}


DOWN = "%LINK-3-UPDOWN: Interface GigabitEthernet0/7, changed state to down"
PROTO_DOWN = "%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/7, changed state to down"


async def test_a_link_flaps_three_times_before_it_alerts(engine):
    clock, repolls, _changes = engine
    _gid, host_id = await _host()
    # One down logs two messages: one event.
    assert (await sr.process_syslog_batch([(host_id, DOWN), (host_id, PROTO_DOWN)]))["raised"] == 0
    clock.t += 60
    assert (await sr.process_syslog_batch([(host_id, DOWN)]))["raised"] == 0
    assert await _open(host_id) == {}
    clock.t += 60
    assert (await sr.process_syslog_batch([(host_id, DOWN)]))["raised"] == 1
    key = f"syslog:link_flap:{host_id}:GigabitEthernet0/7"
    alert = (await _open(host_id))[key]
    assert (alert["alert_type"], alert["metric"], alert["severity"]) == ("syslog", "syslog_link_flap", "warning")
    assert alert["message"].startswith(
        "Interface flapping on GigabitEthernet0/7 (3 times within 10 min): LINK-3-UPDOWN"
    )
    # A fourth down bumps the same alert.
    clock.t += 60
    await sr.process_syslog_batch([(host_id, DOWN)])
    assert (await _open(host_id))[key]["occurrence_count"] == 2
    # Every down asked for a re-poll (the scheduler drops repeats).
    assert repolls[0] == (host_id, sr.REPOLL_DELAY_SECONDS, sr.REPOLL_MIN_INTERVAL_SECONDS)


async def test_downs_spread_over_more_than_the_window_do_not_alert(engine):
    clock, _repolls, _changes = engine
    _gid, host_id = await _host()
    for _ in range(4):
        await sr.process_syslog_batch([(host_id, DOWN)])
        clock.t += 301  # 3 downs span 602 s > 600 s
    assert await _open(host_id) == {}


async def test_a_neighbor_down_raises_and_full_resolves_it(engine):
    _gid, host_id = await _host()
    down = "%OSPF-5-ADJCHG: Process 1, Nbr 198.51.100.2 on Gi0/1 from FULL to DOWN, Neighbor Down: Dead timer expired"
    other = "%OSPF-5-ADJCHG: Process 1, Nbr 198.51.100.3 on Gi0/2 from FULL to DOWN, Neighbor Down: Dead timer expired"
    up = "%OSPF-5-ADJCHG: Process 1, Nbr 198.51.100.2 on Gi0/1 from LOADING to FULL, Loading Done"
    out = await sr.process_syslog_batch([(host_id, down), (host_id, other)])
    assert out["raised"] == 2
    alerts = await _open(host_id)
    assert set(alerts) == {
        f"syslog:ospf_neighbor:{host_id}:198.51.100.2",
        f"syslog:ospf_neighbor:{host_id}:198.51.100.3",
    }
    assert {a["severity"] for a in alerts.values()} == {"critical"}
    out = await sr.process_syslog_batch([(host_id, up)])
    assert out["resolved"] == 1
    assert set(await _open(host_id)) == {f"syslog:ospf_neighbor:{host_id}:198.51.100.3"}
    resolved = [a for a in await db.get_monitoring_alerts(host_id, acknowledged=True)]
    assert [a["acknowledged_by"] for a in resolved] == ["auto-resolved"]


async def test_a_suppressed_rule_is_not_raised(engine):
    _gid, host_id = await _host()
    await db.create_alert_suppression("maint", "2099-01-01 00:00:00", host_id=host_id, metric="syslog_bgp_neighbor")
    out = await sr.process_syslog_batch([(host_id, "%BGP-5-ADJCHANGE: neighbor 203.0.113.1 Down Peer closed")])
    assert out["raised"] == 0 and await _open(host_id) == {}


async def test_nothing_is_raised_or_repolled_while_monitoring_is_off(engine, monkeypatch):
    _clock, repolls, changes = engine
    _gid, host_id = await _host()
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", False)
    config = "%SYS-5-CONFIG_I: Configured from console by ops on vty0 (192.0.2.50)"
    out = await sr.process_syslog_batch(
        [(host_id, "%BGP-5-NBR_RESET: Neighbor 203.0.113.2 reset"), (host_id, DOWN), (host_id, config)]
    )
    assert (out["raised"], out["repolls"]) == (0, 0) and repolls == [] and await _open(host_id) == {}
    # The configuration backup does not depend on monitoring.
    assert changes == [host_id]


@pytest.mark.parametrize("switch", ["syslog_alerts", "repoll_trigger", "config_change_trigger"])
async def test_each_switch_turns_its_behaviour_off(engine, monkeypatch, switch):
    _clock, repolls, changes = engine
    _gid, host_id = await _host()
    state.EVENT_RECEIVER_CONFIG[switch] = False
    batch = [
        (host_id, "%BGP-5-NBR_RESET: Neighbor 203.0.113.2 reset"),
        (host_id, DOWN),
        (host_id, "%SYS-5-CONFIG_I: Configured from console by ops on vty0 (192.0.2.50)"),
    ]
    out = await sr.process_syslog_batch(batch)
    assert (out["raised"] > 0) == (switch != "syslog_alerts")
    assert bool(repolls) == (switch != "repoll_trigger")
    assert bool(changes) == (switch != "config_change_trigger")


async def test_the_switches_default_on_without_the_settings(engine, monkeypatch):
    monkeypatch.setattr(state, "EVENT_RECEIVER_CONFIG", {})
    assert sr.receiver_flag("syslog_alerts") and sr.receiver_flag("repoll_trigger")


async def test_a_disabled_builtin_and_a_custom_rule(engine):
    _gid, host_id = await _host()
    await db.set_syslog_builtin_override("bgp_neighbor", False, "warning")
    await db.create_syslog_alert_rule(
        sr.clean_custom_rule(
            {"name": "BPDU guard", "match_type": "regex", "pattern": r"BPDU on port (\S+)", "severity": "info"}
        )
    )
    sr.invalidate_rules_cache()
    out = await sr.process_syslog_batch(
        [
            (host_id, "%BGP-5-NBR_RESET: Neighbor 203.0.113.2 reset"),
            (host_id, "%SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi1/0/7 with BPDU Guard enabled."),
        ]
    )
    assert out["raised"] == 1
    (alert,) = (await _open(host_id)).values()
    assert alert["metric"].startswith("syslog_custom_") and alert["severity"] == "info"
    assert alert["dedup_key"].endswith(f":{host_id}:Gi1/0/7")


async def test_auth_failures_are_counted_per_device(engine):
    clock, _repolls, _changes = engine
    _gid, host_id = await _host()
    for n in range(5):
        msg = f"%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: u{n}] [Source: 192.0.2.{50 + n}] [localport: 22]"
        out = await sr.process_syslog_batch([(host_id, msg)])
        clock.t += 10
    assert out["raised"] == 1
    assert list(await _open(host_id)) == [f"syslog:auth_failure:{host_id}:"]


async def test_alerts_without_a_new_match_resolve_after_their_time(engine):
    clock, _repolls, _changes = engine
    _gid, host_id = await _host()
    for _ in range(3):
        await sr.process_syslog_batch([(host_id, DOWN)])
        clock.t += 30
    await sr.process_syslog_batch([(host_id, "%BGP-5-NBR_RESET: Neighbor 203.0.113.2 reset")])
    assert len(await _open(host_id)) == 2
    assert await sr.resolve_expired_alerts() == 0
    conn = await db.get_db()
    try:
        await conn.execute(
            "UPDATE monitoring_alerts SET last_seen_at = datetime('now', '-31 minutes') WHERE host_id = ?", (host_id,)
        )
        await conn.commit()
    finally:
        await conn.close()
    # The flap resolves; a BGP neighbor waits for its Up message.
    assert await sr.resolve_expired_alerts() == 1
    assert [a["metric"] for a in (await _open(host_id)).values()] == ["syslog_bgp_neighbor"]


async def test_the_writer_hands_only_syslog_of_known_hosts_to_the_engine(monkeypatch):
    seen: list[list] = []

    async def fake(rows):
        seen.append(list(rows))
        raise RuntimeError("rule failure")  # logged, never raised

    monkeypatch.setattr(sr, "process_syslog_batch", fake)
    await metrics_engine._evaluate_syslog_rules(
        [
            ("192.0.2.10", 7, "syslog", "23", "info", "", DOWN, ""),
            ("203.0.113.99", None, "syslog", "23", "info", "", DOWN, ""),
            ("192.0.2.10", 7, "trap", "", "info", "1.3.6", "trap", ""),
        ]
    )
    assert seen == [[(7, DOWN)]]


async def test_the_source_matches_an_interface_address():
    _gid, host_id = await _host("sw-2", "192.0.2.20")
    await db.set_host_ip_aliases(host_id, "192.0.2.20", ["198.51.100.20"])
    metrics_engine._host_ip_cache.clear()
    assert await metrics_engine._resolve_host_id_cached("198.51.100.20") == host_id
    assert await metrics_engine._resolve_host_id_cached("203.0.113.20") is None


# ── Re-poll scheduling ───────────────────────────────────────────────────────


async def test_a_repoll_waits_out_its_minimum_interval(monkeypatch):
    import netcontrol.routes.monitoring as monitoring

    polled: list[int] = []

    async def fake_poll(host_id: int) -> dict:
        polled.append(host_id)
        return {}

    monkeypatch.setattr(monitoring, "poll_host_now", fake_poll)
    repoll._repoll_waiting.clear()
    repoll._last_scheduled.clear()
    assert repoll.schedule_repoll(51, 0.0, min_interval=60.0) is True
    await asyncio.gather(*list(repoll._background), return_exceptions=True)
    # Done, but within the minimum interval: not again.
    assert repoll.schedule_repoll(51, 0.0, min_interval=60.0) is False
    repoll._last_scheduled[51] -= 61
    assert repoll.schedule_repoll(51, 0.0, min_interval=60.0) is True
    await asyncio.gather(*list(repoll._background), return_exceptions=True)
    assert polled == [51, 51]


async def test_a_reload_repolls_later_than_a_link_down(engine):
    _clock, repolls, _changes = engine
    _gid, host_id = await _host()
    await sr.process_syslog_batch([(host_id, "%SYS-5-RELOAD: Reload requested by ops on vty0 (192.0.2.50).")])
    assert repolls == [(host_id, sr.RELOAD_REPOLL_DELAY_SECONDS, sr.REPOLL_MIN_INTERVAL_SECONDS)]


# ── Configuration change trigger ─────────────────────────────────────────────


@pytest.fixture
def config_runs(monkeypatch):
    """Short debounce and cooldown; runs recorded."""
    sr.reset_state()
    runs: list[tuple[int, float]] = []

    async def fake_run(host_id: int) -> dict:
        runs.append((host_id, time.monotonic()))
        return {}

    monkeypatch.setattr(sr, "run_config_change", fake_run)
    monkeypatch.setattr(sr, "CONFIG_DEBOUNCE_SECONDS", 0.05)
    monkeypatch.setattr(sr, "CONFIG_COOLDOWN_SECONDS", 0.3)
    yield runs
    for task in list(sr._config_tasks.values()):
        task.cancel()
    sr.reset_state()


async def _drain() -> None:
    while sr._config_tasks:
        await asyncio.gather(*list(sr._config_tasks.values()), return_exceptions=True)


async def test_a_burst_of_config_messages_is_one_run_after_the_last(config_runs):
    start = time.monotonic()
    for _ in range(3):
        sr.note_config_change(61)
        await asyncio.sleep(0.02)
    sr.note_config_change(62)
    await _drain()
    assert sorted(h for h, _t in config_runs) == [61, 62]
    first = next(t for h, t in config_runs if h == 61)
    # 3 notes 20 ms apart, then the 50 ms debounce after the last one.
    assert first - start >= 0.04 + 0.05 - 0.01


async def test_a_chatty_device_runs_at_most_once_per_cooldown(config_runs):
    sr.note_config_change(63)
    await _drain()
    # During the cooldown: several messages keep one pending run.
    for _ in range(4):
        sr.note_config_change(63)
        await asyncio.sleep(0.01)
    await _drain()
    times = [t for h, t in config_runs if h == 63]
    assert len(times) == 2
    assert times[1] - times[0] >= sr.CONFIG_COOLDOWN_SECONDS - 0.01


async def test_a_failing_run_is_logged(config_runs, monkeypatch, caplog):
    async def broken(_host_id: int) -> dict:
        raise RuntimeError("backup failed")

    monkeypatch.setattr(sr, "run_config_change", broken)
    sr.note_config_change(64)
    await _drain()
    assert "config change run for host 64 failed" in caplog.text


async def test_a_config_change_backs_up_and_checks_drift(monkeypatch):
    sr.reset_state()
    group_id, host_id = await _host("sw-3", "192.0.2.30")
    cred_id = await db.create_credential("svc", "svc-user", "not-a-real-secret")
    await db.create_config_backup_policy("nightly", group_id, cred_id)
    await db.create_config_baseline(host_id, "golden", "hostname sw-3\n")
    monkeypatch.setitem(state.CONFIG_DRIFT_CHECK_CONFIG, "enabled", True)

    async def cred_ok(*_args, **_kwargs):
        return {"username": "svc-user", "password": "", "secret": ""}

    backup_calls: list[dict] = []
    drift_calls: list[dict] = []

    async def fake_backup(host, _cred, **kwargs):
        backup_calls.append(kwargs)
        return await store_device_config(
            int(host["id"]),
            "hostname sw-3\nntp server 192.0.2.123\n",
            "",
            capture_method=kwargs["capture_method"],
            policy_id=kwargs.get("policy_id"),
        )

    async def fake_drift(host, _cred, **kwargs):
        drift_calls.append(kwargs)
        return DeviceConfig(1, "hostname sw-3\nntp server 192.0.2.123\n", "", created=False, reused=True)

    monkeypatch.setattr(config_backups, "require_credential_access", cred_ok)
    monkeypatch.setattr(config_backups, "get_device_config", fake_backup)
    monkeypatch.setattr(config_drift, "get_device_config", fake_drift)

    outcome = await sr.run_config_change(host_id)
    assert outcome["backup"] == "stored"
    assert outcome["drift"]["drifted"] is True
    assert backup_calls[0]["capture_method"] == "syslog"
    # The drift snapshot reuses the backup just taken: no second session.
    assert drift_calls == [{"capture_method": "drift", "max_age_seconds": sr.CONFIG_REUSE_SECONDS}]
    backup = await db.get_newest_host_config_backup(host_id)
    rows = await db.get_config_backups(host_id=host_id)
    assert backup is not None and [r["capture_method"] for r in rows] == ["syslog"]
    snapshot = await db.get_latest_config_snapshot(host_id)
    assert snapshot["capture_method"] == "syslog"
    assert (await db.get_config_drift_events(status="open", host_id=host_id))[0]["id"] == outcome["drift"]["event_id"]

    # Without a backup policy in the host's group there is nothing to run.
    _g2, other = await _host("sw-4", "192.0.2.40")
    assert (await sr.run_config_change(other))["backup"] == "no_policy"
    assert (await sr.run_config_change(999999))["backup"] == "no_host"


# ── API ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    sr.reset_state()
    return admin_client(monkeypatch, request)


def test_the_list_merges_builtin_and_custom_rules(admin):
    rules = admin.get(PREFIX).json()
    assert [r["key"] for r in rules] == [r.key for r in sr.BUILTIN_RULES]
    link = rules[0]
    assert (link["builtin"], link["enabled"], link["threshold_count"], link["auto_resolve_minutes"]) == (
        True,
        True,
        3,
        30,
    )
    assert "LINK-UPDOWN" in link["tags"] and link["families"]

    created = admin.post(
        PREFIX,
        json={
            "name": "BPDU guard",
            "match_type": "tag",
            "pattern": "SPANTREE-2-BLOCK_BPDUGUARD",
            "severity": "critical",
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert (body["builtin"], body["key"], body["metric"]) == (
        False,
        f"custom_{body['id']}",
        f"syslog_custom_{body['id']}",
    )
    assert [r["key"] for r in admin.get(PREFIX).json()][-1] == body["key"]


def test_custom_rule_crud_and_audit(admin):
    bad = admin.post(PREFIX, json={"name": "x", "match_type": "regex", "pattern": "(?!x)y"})
    assert bad.status_code == 400 and "regular expression" in bad.json()["error"]["message"]
    rule = admin.post(PREFIX, json={"name": "Err-disable", "match_type": "contains", "pattern": "err-disabled"}).json()
    updated = admin.put(f"{PREFIX}/{rule['id']}", json={"enabled": False, "threshold_count": 2})
    assert updated.status_code == 200, updated.text
    assert (updated.json()["enabled"], updated.json()["threshold_count"], updated.json()["pattern"]) == (
        False,
        2,
        "err-disabled",
    )
    assert admin.put(f"{PREFIX}/999999", json={"name": "y"}).status_code == 404
    deleted = admin.delete(f"{PREFIX}/{rule['id']}")
    assert deleted.status_code == 200 and deleted.json()["ok"] is True
    assert admin.delete(f"{PREFIX}/{rule['id']}").status_code == 404
    actions = [e["action"] for e in asyncio.run(db.get_audit_events(limit=50, category="monitoring"))]
    assert {"syslog_rule.created", "syslog_rule.updated", "syslog_rule.deleted"} <= set(actions)


def test_a_builtin_takes_only_enabled_and_severity(admin):
    resp = admin.patch(f"{PREFIX}/builtin/fan", json={"enabled": False, "severity": "critical"})
    assert resp.status_code == 200, resp.text
    assert (resp.json()["enabled"], resp.json()["severity"]) == (False, "critical")
    resp = admin.patch(f"{PREFIX}/builtin/fan", json={"enabled": True})
    assert (resp.json()["enabled"], resp.json()["severity"]) == (True, "critical")
    assert admin.patch(f"{PREFIX}/builtin/fan", json={"severity": "major"}).status_code == 400
    assert admin.patch(f"{PREFIX}/builtin/no_such_rule", json={"enabled": False}).status_code == 404
    # The override row is not a custom rule.
    rows = asyncio.run(db.list_syslog_alert_rules())
    assert [r["builtin_key"] for r in rows] == ["fan"]
    assert admin.put(f"{PREFIX}/{rows[0]['id']}", json={"name": "x"}).status_code == 404
    assert admin.delete(f"{PREFIX}/{rows[0]['id']}").status_code == 404
    events = asyncio.run(db.get_audit_events(limit=20, category="monitoring"))
    assert any(e["action"] == "syslog_rule.builtin_updated" for e in events)


def test_the_test_endpoint_explains_a_message(admin):
    resp = admin.post(
        f"{PREFIX}/test",
        json={
            "message": "<187>12: %LINK-3-UPDOWN: Interface GigabitEthernet0/9, changed state to down",
            "rule": {"name": "draft", "match_type": "regex", "pattern": r"Interface (\S+?),"},
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body["tag"], body["match_tag"], body["repoll"], body["config_change"]) == (
        "LINK-3-UPDOWN",
        "LINK-UPDOWN",
        "interface_down",
        False,
    )
    assert body["matches"] == [
        {
            "key": "link_flap",
            "name": "Interface flapping",
            "builtin": True,
            "enabled": True,
            "action": "raise",
            "instance": "GigabitEthernet0/9",
        }
    ]
    assert body["draft"] == {"action": "raise", "instance": "GigabitEthernet0/9"}
    bad = admin.post(
        f"{PREFIX}/test", json={"message": "x", "rule": {"name": "d", "match_type": "regex", "pattern": "("}}
    )
    assert bad.status_code == 400


def test_permissions(admin):
    reader = user_client(admin, "syslog-reader", features=["monitoring"])
    assert reader.get(PREFIX).status_code == 200
    assert reader.post(PREFIX, json={"name": "x", "match_type": "contains", "pattern": "y"}).status_code == 403
    assert reader.patch(f"{PREFIX}/builtin/fan", json={"enabled": False}).status_code == 403
    writer = user_client(admin, "syslog-writer", features=["monitoring", "monitoring.write"])
    assert writer.post(PREFIX, json={"name": "x", "match_type": "contains", "pattern": "y"}).status_code == 201
    outsider = user_client(admin, "syslog-outsider", features=["inventory"])
    assert outsider.get(PREFIX).status_code == 403


async def test_deleting_a_custom_rule_resolves_its_alerts(engine):
    _gid, host_id = await _host()
    row = await db.create_syslog_alert_rule(
        sr.clean_custom_rule({"name": "c", "match_type": "contains", "pattern": "boom"})
    )
    sr.invalidate_rules_cache()
    await sr.process_syslog_batch([(host_id, "%X-1-Y: boom")])
    assert len(await _open(host_id)) == 1
    await db.delete_syslog_alert_rule(row["id"])
    assert await sr.resolve_rule_alerts(sr.custom_rule_key(row["id"])) == 1
    assert await _open(host_id) == {}


# ── Migration ────────────────────────────────────────────────────────────────


async def test_the_migration_adds_the_table():
    await db.init_db()
    conn = await db.get_db(read_only=True)
    try:
        cursor = await conn.execute("SELECT version FROM schema_migrations WHERE version = 119")
        assert await cursor.fetchone() is not None
    finally:
        await conn.close()
    await db.set_syslog_builtin_override("fan", False, "warning")
    with pytest.raises(Exception):  # noqa: B017 - one override row per built-in (unique index)
        conn = await db.get_db()
        try:
            await conn.execute(
                "INSERT INTO syslog_alert_rules (builtin_key, created_at, updated_at) VALUES ('fan', '', '')"
            )
            await conn.commit()
        finally:
            await conn.close()
