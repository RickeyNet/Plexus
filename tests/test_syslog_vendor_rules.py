"""Built-in syslog rules and triggers on the formats of Fortinet FortiOS,
Palo Alto PAN-OS and HPE Aruba AOS-CX / AOS-Switch
(``netcontrol.syslog_vendor_formats``), plus the classic Cisco, ISR G2 and
Arista EOS power supply, fan and login failure forms.

Every message is invented, written in the vendor's documented format with
made-up names and documentation addresses.
"""

from __future__ import annotations

import time

import pytest
from netcontrol import syslog_rules as sr, syslog_vendor_formats as vf

import test_syslog_rules as base
from test_syslog_rules import _host, _open

# The engine fixture of the rule tests (monitoring on, a fake clock,
# re-polls and configuration changes recorded).
engine = base.engine

FGT_HDR = (
    'date=2026-01-10 time=10:00:00 devname="fw1" devid="FGT60F0000000001" eventtime=1768039200000000000 tz="+0000"'
)


def fgt(logid: str, subtype: str, level: str, logdesc: str, rest: str) -> str:
    """A FortiOS event log line (default format, no syslog header)."""
    return (
        f'<185>{FGT_HDR} logid="{logid}" type="event" subtype="{subtype}" level="{level}" vd="root" '
        f'logdesc="{logdesc}" {rest}'
    )


PAN_HDR = "<14>Jan 10 10:00:00 fw1 "
PAN_TIME = "2026/01/10 10:00:00"


def pan_system(subtype: str, eventid: str, severity: str, description: str, obj: str = "") -> str:
    """A PAN-OS SYSTEM log (default CSV format, BSD header)."""
    desc = '"' + description.replace('"', '""') + '"'
    return (
        f"{PAN_HDR}1,{PAN_TIME},012345678901,SYSTEM,{subtype},0,{PAN_TIME},,{eventid},{obj},0,0,general,"
        f"{severity},{desc},1001,0x0,0,0,0,0,,fw1,0,0,{PAN_TIME}"
    )


def pan_config(command: str, result: str, path: str = "") -> str:
    """A PAN-OS CONFIG log (default CSV format, BSD header)."""
    return (
        f"{PAN_HDR}1,{PAN_TIME},012345678901,CONFIG,0,0,{PAN_TIME},198.51.100.7,,{command},ops,Web,"
        f"{result},{path},,,1002,0x0,0,0,0,0,,fw1,,,0,{PAN_TIME}"
    )


def aoscx(event_id: int, severity: str, text: str, daemon: str = "hpe-intfd") -> str:
    return f"<190>Jan 10 10:00:00 sw-lab-1 {daemon}[1234]: Event|{event_id}|{severity}|AMM|1/1|{text}"


def aoss(event_id: str, facility: str, text: str) -> str:
    return f"<14>Jan 10 10:00:00 192.0.2.5 {event_id} {facility}: {text}"


def _found(message: str) -> dict:
    parsed = sr.parse_syslog_message(message)
    return {r.key: f for r in sr.merge_rules([]) if (f := sr.evaluate_rule(r, parsed))}


# ── Parsing ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("message", "tag", "raw_tag", "text", "program"),
    [
        # FortiOS: default format without a syslog header, with and without PRI.
        (
            fgt(
                "0100032002",
                "system",
                "alert",
                "Admin login failed",
                'user="ops" action="login" status="failed" msg="Administrator ops login failed from '
                'https(198.51.100.7) because of invalid password"',
            ),
            "FGT-0100032002",
            "Admin login failed",
            "Administrator ops login failed from https(198.51.100.7) because of invalid password",
            "",
        ),
        (
            fgt("0100044547", "system", "information", "Object attribute configured", 'action="Edit"')[5:],
            "FGT-0100044547",
            "Object attribute configured",
            'logid="0100044547" type="event" subtype="system" level="information" vd="root" '
            'logdesc="Object attribute configured" action="Edit"',
            "",
        ),
        # FortiOS in RFC 5424 format: the MSG carries the key=value line.
        (
            '<185>1 2026-01-10T10:00:00Z fw1 - - - - logid="0100020099" type="event" subtype="system" '
            'level="warning" logdesc="Interface status changed" msg="Link monitor: Interface wan1 was turned down"',
            "FGT-0100020099",
            "Interface status changed",
            "Link monitor: Interface wan1 was turned down",
            "",
        ),
        # A quote escaped inside msg.
        (
            fgt("0100032002", "system", "alert", "Admin login failed", r'msg="user \"ops\" failed"'),
            "FGT-0100032002",
            "Admin login failed",
            'user "ops" failed',
            "",
        ),
        # No logdesc: the tag stands in for it.
        ('logid="0100032009" type="event" msg="Fortigate started"', "FGT-0100032009", "FGT-0100032009", None, ""),
        # PAN-OS SYSTEM with a BSD header, a comma inside the quoted description.
        (
            pan_system(
                "routing",
                "routed-BGP-peer-left-established",
                "high",
                "BGP peer session left established state. peer name: isp-a, peer IP: 203.0.113.9.",
            ),
            "PAN-SYSTEM-ROUTED-BGP-PEER-LEFT-ESTABLISHED",
            "SYSTEM routing routed-BGP-peer-left-established",
            "BGP peer session left established state. peer name: isp-a, peer IP: 203.0.113.9.",
            "",
        ),
        # PAN-OS without PRI or header, a doubled quote in the description.
        (
            pan_system("auth", "auth-fail", "medium", 'failed authentication for user "ops"')[len(PAN_HDR) :],
            "PAN-SYSTEM-AUTH-FAIL",
            "SYSTEM auth auth-fail",
            'failed authentication for user "ops"',
            "",
        ),
        # PAN-OS IETF (RFC 5424) format.
        (
            "<14>1 2026-01-10T10:00:00+00:00 fw1 - - - - "
            + pan_system("port", "link-change", "informational", "ethernet1/3: Down 1Gb/s-full duplex")[len(PAN_HDR) :],
            "PAN-SYSTEM-LINK-CHANGE",
            "SYSTEM port link-change",
            "ethernet1/3: Down 1Gb/s-full duplex",
            "",
        ),
        (
            pan_config("commit", "Succeeded"),
            "PAN-CONFIG",
            "CONFIG",
            "commit,ops,Web,Succeeded,,,,1002,0x0,0,0,0,0,,fw1,,,0,2026/01/10 10:00:00",
            "",
        ),
        # Other log types group under their type.
        (
            f"{PAN_HDR}1,{PAN_TIME},012345678901,TRAFFIC,end,2561,{PAN_TIME},192.0.2.20,198.51.100.30",
            "PAN-TRAFFIC",
            "TRAFFIC",
            "end,2561,2026/01/10 10:00:00,192.0.2.20,198.51.100.30",
            "",
        ),
        # A truncated SYSTEM log keeps its type.
        (f"{PAN_HDR}1,{PAN_TIME},012345678901,SYSTEM,auth,0", "PAN-SYSTEM", "SYSTEM", None, ""),
        # AOS-CX.
        (
            aoscx(404, "LOG_INFO", "Link status for interface 1/1/7 is down"),
            "AOSCX-404",
            "Event|404|LOG_INFO",
            "Link status for interface 1/1/7 is down",
            "hpe-intfd",
        ),
        (
            "<190>1 2026-01-10T10:00:00.000+00:00 sw-lab-1 hpe-sshd 4321 - - Event|5210|LOG_ERR|AMM|1/1|"
            "User ops login failed",
            "AOSCX-5210",
            "Event|5210|LOG_ERR",
            "User ops login failed",
            "hpe-sshd",
        ),
        # AOS-Switch: host name or address before the event id, or none.
        (
            aoss("00077", "ports", "port 1/14 is now off-line"),
            "AOSS-00077",
            "00077 ports",
            "port 1/14 is now off-line",
            "ports",
        ),
        ("00419 auth: Invalid user name/password on SSH session", "AOSS-00419", "00419 auth", None, "auth"),
        ("<14>sw-lab-2 00064 system: System Booted", "AOSS-00064", "00064 system", "System Booted", "system"),
        # Facilities are written in either case and may start with a digit.
        (
            aoss("00331", "FFI", "port 5-Excessive link state transitions"),
            "AOSS-00331",
            "00331 FFI",
            "port 5-Excessive link state transitions",
            "FFI",
        ),
        ("sw-lab-2 00435 802.1x: Port 7 authentication timed out", "AOSS-00435", "00435 802.1x", None, "802.1x"),
    ],
)
def test_vendor_messages_are_tagged(message, tag, raw_tag, text, program):
    parsed = sr.parse_syslog_message(message)
    assert (parsed.tag, parsed.raw_tag, parsed.program) == (tag, raw_tag, program)
    if text is not None:
        assert parsed.text == text
    assert not parsed.message.startswith("<")


@pytest.mark.parametrize(
    "message",
    [
        # Not a vendor format, or a malformed one.
        "<14>Jan 10 10:00:00 host1 cron[99]: job started",
        "logid=abc type=event",
        "logid=",
        "Event|abc|LOG_INFO|x|y|text",
        "Event|404",
        "1,2026/01/10 10:00:00",
        "1,2026/01/10 10:00:00,012345678901,system,auth",
        "a, b / c",
        # A five-digit number later in another vendor's text is no AOS-Switch event id.
        "<38>Jan 10 10:00:00 host1 sshd[77]: Accepted publickey for ops from 192.0.2.50 port 50000 ssh2: RSA",
        "<14>Jan 10 10:00:00 host1 note 12345 words: text",
        "",
    ],
)
def test_other_messages_get_no_vendor_tag(message):
    parsed = sr.parse_syslog_message(message)
    assert not parsed.tag.startswith(("FGT-", "PAN-", "AOSCX-", "AOSS-"))


def test_cisco_and_junos_messages_keep_their_tags():
    for message, tag in [
        ("<187>123: *Mar  1 00:01:02.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down", "LINK-UPDOWN"),
        ("000045: sw-a1: Jan 10 10:00:00.000 UTC: %SYS-5-CONFIG_I: Configured from console by ops", "SYS-CONFIG_I"),
        ("mib2d[1234]: SNMP_TRAP_LINK_DOWN: ifIndex 526, ifAdminStatus up(1), ifName ge-0/0/1", "SNMP_TRAP_LINK_DOWN"),
    ]:
        assert sr.parse_syslog_message(message).tag == tag


@pytest.mark.parametrize(
    "message",
    [
        fgt("0100032002", "system", "alert", "Admin login failed", 'msg="' + "x" * 2000 + '"'),
        "logid=" + "1" * 2000,
        pan_system("auth", "auth-fail", "medium", "y," * 1000),
        f"{PAN_HDR}1,{PAN_TIME},012345678901,SYSTEM," + '"' * 2000,
        "Event|" * 400,
        aoscx(404, "LOG_INFO", "z|" * 1000),
        "<14>Jan 10 10:00:00 " + "a" * 2000 + " 00077 ports: x",
        "0" * 2000,
    ],
)
def test_long_lines_parse_in_linear_time(message):
    start = time.perf_counter()
    for _ in range(20):
        sr.parse_syslog_message(message)
    assert time.perf_counter() - start < 0.5


def test_quoted_csv_fields():
    assert vf._csv_fields('a,"b,c",d', 5) == [(0, "a"), (2, "b,c"), (8, "d")]
    assert vf._csv_fields('"x""y",z', 2) == [(0, 'x"y'), (7, "z")]
    # An unclosed quote runs to the end of the line.
    assert vf._csv_fields('a,"open', 5) == [(0, "a"), (2, "open")]
    assert vf._csv_fields("", 3) == [(0, "")]


# ── Built-in rules ───────────────────────────────────────────────────────────

FGT_LOGIN_FAILED = fgt(
    "0100032002",
    "system",
    "alert",
    "Admin login failed",
    'user="ops" status="failed" reason="passwd_invalid" msg="Administrator ops login failed from '
    'ssh(198.51.100.7) because of invalid password"',
)

# (message, rule key, raise / clear, instance)
SAMPLES = [
    # link_flap.
    (
        fgt(
            "0100020099",
            "system",
            "warning",
            "Interface status changed",
            'action="interface-stat-change" status="DOWN" msg="Link monitor: Interface wan1 was turned down"',
        ),
        "link_flap",
        "raise",
        "wan1",
    ),
    (
        pan_system("port", "link-change", "informational", "Port ethernet1/3: Down 1Gb/s-full duplex"),
        "link_flap",
        "raise",
        "ethernet1/3",
    ),
    (
        pan_system("port", "link-change", "informational", "ethernet1/4: Down 10Gb/s-full duplex"),
        "link_flap",
        "raise",
        "ethernet1/4",
    ),
    (
        pan_system("port", "link-change", "informational", "Port MGT: Down 1Gb/s-full duplex"),
        "link_flap",
        "raise",
        "MGT",
    ),
    (aoscx(404, "LOG_INFO", "Link status for interface 1/1/7 is down"), "link_flap", "raise", "1/1/7"),
    (aoss("00077", "ports", "port 1/14 is now off-line"), "link_flap", "raise", "1/14"),
    (aoss("00077", "ports", "ST1-CMDR: port 2/16 is now off-line"), "link_flap", "raise", "2/16"),
    # ospf_neighbor.
    (
        fgt(
            "0103020302",
            "router",
            "warning",
            "OSPF neighbor status changed",
            'msg="OSPF: %OSPF-5-ADJCHANGE: neighbor port1:192.0.2.1-192.0.2.2 Down "',
        ),
        "ospf_neighbor",
        "raise",
        "port1:192.0.2.1-192.0.2.2",
    ),
    (
        fgt(
            "0103020302",
            "router",
            "warning",
            "OSPF neighbor status changed",
            'msg="OSPF: %OSPF-5-ADJCHANGE: neighbor port1:192.0.2.1-192.0.2.2 Up"',
        ),
        "ospf_neighbor",
        "clear",
        "port1:192.0.2.1-192.0.2.2",
    ),
    (
        pan_system("routing", "routed-OSPF-neighbor-down", "high", "OSPF adjacency with neighbor has gone down."),
        "ospf_neighbor",
        "raise",
        "",
    ),
    (
        pan_system(
            "routing", "routed-OSPF-neighbor-full", "informational", "OSPF full adjacency established with neighbor."
        ),
        "ospf_neighbor",
        "clear",
        "",
    ),
    # bgp_neighbor.
    (
        fgt(
            "0103020300",
            "router",
            "warning",
            "BGP neighbor status changed",
            'msg="BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 203.0.113.9 Down Hold Timer Expired"',
        ),
        "bgp_neighbor",
        "raise",
        "203.0.113.9",
    ),
    (
        fgt(
            "0103020300",
            "router",
            "warning",
            "BGP neighbor status changed",
            'msg="BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 203.0.113.9 Up"',
        ),
        "bgp_neighbor",
        "clear",
        "203.0.113.9",
    ),
    (
        pan_system(
            "routing",
            "routed-BGP-peer-left-established",
            "high",
            "BGP peer session left established state. peer name: isp-a, peer IP: 203.0.113.10.",
        ),
        "bgp_neighbor",
        "raise",
        "203.0.113.10",
    ),
    (
        pan_system(
            "routing",
            "routed-BGP-peer-enter-established",
            "medium",
            "BGP peer session enters established state. peer name: isp-a, peer IP: 203.0.113.10.",
        ),
        "bgp_neighbor",
        "clear",
        "203.0.113.10",
    ),
    # power_supply.
    (
        fgt(
            "0100022105",
            "system",
            "critical",
            "Power supply failed",
            'action="ipmc-sensor-monitor" status="failure" msg="PSU [2] not detected"',
        ),
        "power_supply",
        "raise",
        "",
    ),
    (
        fgt("0100022104", "system", "notice", "Power supply restored", 'msg="PSU [2] restored"'),
        "power_supply",
        "clear",
        "",
    ),
    (pan_system("hw", "ps-failure", "critical", "Alarm on Power Supply #2"), "power_supply", "raise", "2"),
    (
        aoscx(304, "LOG_ERR", "PSU 1/2 faulted. Total fault count: 1", daemon="hpe-powerd"),
        "power_supply",
        "raise",
        "1/2",
    ),
    ("%PLATFORM_ENV-1-FRU_PS_SIGNAL_FAULTY: AC_OK signal on power supply is faulty.", "power_supply", "raise", ""),
    (
        "PowerManager: %PWRMGMT-3-PSU_STATUS_FAILED: PowerSupply2 has failed and has stopped providing power to "
        "the system.",
        "power_supply",
        "raise",
        "PowerSupply2",
    ),
    (
        "PowerManager: %PWRMGMT-4-INPUT_POWER_LOSS: PowerSupply2 has lost input power.",
        "power_supply",
        "raise",
        "PowerSupply2",
    ),
    (
        "PowerManager: %PWRMGMT-3-PSU_STATUS_OK: PowerSupply2 has recovered and is providing power to the system.",
        "power_supply",
        "clear",
        "PowerSupply2",
    ),
    # fan.
    ("%HARDWARE-2-FAN_ERROR: Fan 1 Failure.", "fan", "raise", "1"),
    ("%PLATFORM_ENV-1-FAN: Faulty fan detected.", "fan", "raise", ""),
    ("%PLATFORM_ENV-1-FRU_PS_FAN_FAILED: Power supply fan failure detected.", "fan", "raise", ""),
    ("%ENVMON-3-FAN_FAIL: Fan 2 is malfunctioning", "fan", "raise", "2"),
    ("%ENVMON-3-FAN_FAILED: Fan 1 is malfunctioning", "fan", "raise", "1"),
    ("%ENVMON-3-FAN_OK: Fan 2 functional now", "fan", "clear", "2"),
    ("Thermostat: %ENVMON-3-FANFAILED: Fan1/1 failure detected", "fan", "raise", "Fan1/1"),
    ("Thermostat: %ENVMON-3-FANOK: Fan1/1 has recovered", "fan", "clear", "Fan1/1"),
    (pan_system("hw", "fan-failure", "critical", "Alarm on Fan Tray #1"), "fan", "raise", "1"),
    # auth_failure.
    (FGT_LOGIN_FAILED, "auth_failure", "raise", ""),
    (
        pan_system(
            "auth",
            "auth-fail",
            "medium",
            "failed authentication for user 'ops'. Reason: Invalid username/password. From: 198.51.100.7.",
        ),
        "auth_failure",
        "raise",
        "",
    ),
    (aoscx(5210, "LOG_ERR", "User ops login failed", daemon="hpe-sshd"), "auth_failure", "raise", ""),
    (
        aoscx(5216, "LOG_ERR", "User ops login failed due to public key failure", daemon="hpe-sshd"),
        "auth_failure",
        "raise",
        "",
    ),
    (
        aoss(
            "00419", "auth", "Invalid user name/password on SSH session User ops is trying to login from 198.51.100.7"
        ),
        "auth_failure",
        "raise",
        "",
    ),
    (aoss("03345", "ssh", "User ops: Login failed for SSH session from 198.51.100.7"), "auth_failure", "raise", ""),
    # Arista EOS (and other hosts) through OpenSSH.
    (
        "<86>Jan 10 10:00:00 leaf-1 sshd[3001]: Failed password for ops from 198.51.100.7 port 4022 ssh2",
        "auth_failure",
        "raise",
        "",
    ),
    (
        "sshd[3001]: Failed password for invalid user guest from 198.51.100.7 port 4022 ssh2",
        "auth_failure",
        "raise",
        "",
    ),
    (
        "sshd[3001]: Failed keyboard-interactive/pam for ops from 198.51.100.7 port 4022 ssh2",
        "auth_failure",
        "raise",
        "",
    ),
]


@pytest.mark.parametrize(("message", "key", "action", "instance"), SAMPLES)
def test_each_vendor_form_matches_its_rule(message, key, action, instance):
    assert _found(message) == {key: {"action": action, "instance": instance}}


@pytest.mark.parametrize(
    "message",
    [
        # Interface up.
        fgt(
            "0100020099",
            "system",
            "warning",
            "Interface status changed",
            'status="UP" msg="Link monitor: Interface wan1 was turned up"',
        ),
        pan_system("port", "link-change", "informational", "ethernet1/3: Up 1Gb/s-full duplex"),
        aoscx(403, "LOG_INFO", "Link status for interface 1/1/7 is up"),
        aoss("00076", "ports", "port 1/14 is now on-line"),
        # Login success.
        fgt(
            "0100032001",
            "system",
            "information",
            "Admin login successful",
            'msg="Administrator ops logged in successfully from ssh(198.51.100.7)"',
        ),
        pan_system("auth", "auth-success", "informational", "authenticated for user 'ops'."),
        aoscx(5209, "LOG_INFO", "User ops logged in", daemon="hpe-sshd"),
        "sshd[3001]: Accepted password for ops from 198.51.100.7 port 4022 ssh2",
        # The authentication server's setup, not a login.
        pan_system("auth", "auth-fail", "informational", "Time clock does not match that on KDC server at 'kdc1'"),
        pan_system("auth", "auth-fail", "informational", "Server certificate: 'ldap1' is invalid for server 'x'"),
        # Other events of the same vendors.
        pan_system("hw", "ps-inserted", "informational", "Power Supply #2 inserted"),
        fgt(
            "0100022106",
            "system",
            "information",
            "Optional power supply not detected",
            'msg="Power Supply is not detected: PSU [1] LOST"',
        ),
        fgt("0103020300", "router", "warning", "BGP neighbor status changed", 'msg="BGP: neighbor status"'),
        "%ENVMON-3-FAN_TRAY_MISSING: Fan tray removed",
    ],
)
def test_near_misses_raise_nothing(message):
    assert _found(message) == {}


def test_the_families_name_the_new_vendors():
    for key in ("link_flap", "auth_failure"):
        assert {"Fortinet FortiOS", "Palo Alto PAN-OS", "HPE Aruba AOS-CX", "HPE Aruba AOS-Switch"} <= set(
            sr.BUILTIN_BY_KEY[key].families
        )
    for key in ("ospf_neighbor", "bgp_neighbor"):
        assert {"Fortinet FortiOS", "Palo Alto PAN-OS"} <= set(sr.BUILTIN_BY_KEY[key].families)
    assert "Arista EOS" in sr.BUILTIN_BY_KEY["power_supply"].families
    assert "Arista EOS" in sr.BUILTIN_BY_KEY["fan"].families
    assert "Arista EOS" in sr.BUILTIN_BY_KEY["auth_failure"].families


@pytest.mark.parametrize(
    ("tag", "owner"),
    [
        ("FGT-0100020099", "link_flap"),
        ("PAN-SYSTEM-LINK-CHANGE", "link_flap"),
        ("AOSCX-404", "link_flap"),
        ("AOSS-00077", "link_flap"),
        ("FGT-0103020302", "ospf_neighbor"),
        ("PAN-SYSTEM-ROUTED-OSPF-NEIGHBOR-FULL", "ospf_neighbor"),
        ("FGT-0103020300", "bgp_neighbor"),
        ("PAN-SYSTEM-ROUTED-BGP-PEER-ENTER-ESTABLISHED", "bgp_neighbor"),
        ("FGT-0100022104", "power_supply"),
        ("AOSCX-304", "power_supply"),
        ("PWRMGMT-PSU_STATUS_OK", "power_supply"),
        ("ENVMON-FANOK", "fan"),
        ("HARDWARE-FAN_ERROR", "fan"),
        ("FGT-0100032002", "auth_failure"),
        ("AOSS-03345", "auth_failure"),
        ("PAN-SYSTEM-AUTH-FAIL", "auth_failure"),
        ("FGT-0100044547", "config_change"),
        ("PAN-CONFIG", "config_change"),
        ("FGT-0100032138", "repoll"),
        ("AOSS-00064", "repoll"),
        ("PAN-TRAFFIC", ""),
        ("AOSCX-403", ""),
    ],
)
def test_tag_owner_knows_the_vendor_tags(tag, owner):
    assert sr.tag_owner(tag) == owner


# ── Triggers ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "message",
    [
        fgt("0100044544", "system", "information", "Path configured", 'cfgpath="system.dns" action="Edit"'),
        fgt("0100044545", "system", "information", "Object configured", 'cfgpath="firewall.address" action="Add"'),
        fgt("0100044546", "system", "information", "Attribute configured", 'cfgpath="system.global" action="Edit"'),
        fgt("0100044547", "system", "information", "Object attribute configured", 'cfgobj="h1" action="Delete"'),
        pan_config("commit", "Succeeded"),
        # The admin name in quotes (it holds a comma).
        f'{PAN_HDR}1,{PAN_TIME},012345678901,CONFIG,0,0,{PAN_TIME},198.51.100.7,,commit,"ops,admin",Web,Succeeded',
        # The end of the commit job in the SYSTEM log.
        pan_system("general", "general", "informational", "Commit job succeeded"),
        pan_system("general", "general", "informational", "Commit job succeeded for user ops"),
    ],
)
def test_vendor_configuration_changes(message):
    assert sr.is_config_change(sr.parse_syslog_message(message))


@pytest.mark.parametrize(
    "message",
    [
        # A candidate edit is no change of the running configuration yet.
        pan_config("set", "Succeeded", "vsys  vsys1  address  h1"),
        pan_config("edit", "Succeeded"),
        pan_config("commit", "Submitted"),
        pan_config("commit", "Failed"),
        pan_system("general", "general", "informational", "Commit job failed for user ops"),
        pan_system("general", "general", "informational", "Commit job enqueued for user ops"),
        # An execute command.
        fgt("0100044548", "system", "information", "Action performed", 'action="execute"'),
        aoscx(404, "LOG_INFO", "Link status for interface 1/1/7 is down"),
    ],
)
def test_vendor_messages_that_are_no_configuration_change(message):
    assert not sr.is_config_change(sr.parse_syslog_message(message))


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        (
            fgt(
                "0100020099",
                "system",
                "warning",
                "Interface status changed",
                'msg="Link monitor: Interface port3 was turned down"',
            ),
            "interface_down",
        ),
        (pan_system("port", "link-change", "informational", "Port ethernet1/3: MAC Down"), "interface_down"),
        (aoscx(404, "LOG_INFO", "Link status for interface 1/1/7 is down"), "interface_down"),
        (aoss("00077", "ports", "port 3 is now off-line"), "interface_down"),
        (
            fgt(
                "0100032138",
                "system",
                "critical",
                "Device rebooted",
                'msg="User ops rebooted the device from ssh(198.51.100.7)."',
            ),
            "reload",
        ),
        (
            fgt(
                "0100032200",
                "system",
                "critical",
                "Device shutdown",
                'msg="User ops shutdown the device from console."',
            ),
            "reload",
        ),
        (aoss("00063", "system", "System went down: 01/10/26 10:00:00"), "reload"),
        (fgt("0100032009", "system", "information", "FortiGate started", 'msg="Fortigate started"'), "restart"),
        (aoss("00064", "system", "System Booted"), "restart"),
        (aoss("00076", "ports", "port 3 is now on-line"), ""),
    ],
)
def test_vendor_repoll_reasons(message, reason):
    assert sr.repoll_reason(sr.parse_syslog_message(message)) == reason


# ── The engine ───────────────────────────────────────────────────────────────


async def test_fortios_login_failures_raise_after_five(engine):
    clock, _repolls, _changes = engine
    _gid, host_id = await _host("fw1", "192.0.2.21", "fortinet")
    failed = FGT_LOGIN_FAILED
    for _ in range(4):
        assert (await sr.process_syslog_batch([(host_id, failed)]))["raised"] == 0
        clock.t += 10
    assert (await sr.process_syslog_batch([(host_id, failed)]))["raised"] == 1
    alert = (await _open(host_id))[f"syslog:auth_failure:{host_id}:"]
    assert alert["message"].startswith("Repeated login failures (5 times within 5 min): Admin login failed: ")


async def test_a_panos_bgp_peer_raises_and_clears(engine):
    _clock, _repolls, _changes = engine
    _gid, host_id = await _host("fw2", "192.0.2.22", "paloalto_panos")
    down = pan_system(
        "routing",
        "routed-BGP-peer-left-established",
        "high",
        "BGP peer session left established state. peer name: isp-a, peer IP: 203.0.113.10.",
    )
    up = pan_system(
        "routing",
        "routed-BGP-peer-enter-established",
        "medium",
        "BGP peer session enters established state. peer name: isp-a, peer IP: 203.0.113.10.",
    )
    assert (await sr.process_syslog_batch([(host_id, down)]))["raised"] == 1
    key = f"syslog:bgp_neighbor:{host_id}:203.0.113.10"
    assert key in await _open(host_id)
    assert (await sr.process_syslog_batch([(host_id, up)]))["resolved"] == 1
    assert key not in await _open(host_id)


async def test_vendor_triggers_reach_the_engine(engine):
    clock, repolls, changes = engine
    _gid, host_id = await _host("sw-lab-1", "192.0.2.23", "aruba_aoscx")
    out = await sr.process_syslog_batch(
        [
            (host_id, aoscx(404, "LOG_INFO", "Link status for interface 1/1/7 is down")),
            (host_id, pan_config("commit", "Succeeded")),
            (host_id, pan_config("set", "Succeeded")),
        ]
    )
    assert (out["repolls"], out["config_changes"]) == (1, 1)
    assert repolls[0][0] == host_id and changes == [host_id]


async def test_explain_message_shows_the_vendor_tag(engine):
    await _host("sw-lab-3", "192.0.2.24")
    message = fgt(
        "0100044547", "system", "information", "Object attribute configured", 'msg="Edit firewall.address h1"'
    )
    out = await sr.explain_message(message)
    assert (out["tag"], out["match_tag"], out["text"]) == (
        "Object attribute configured",
        "FGT-0100044547",
        "Edit firewall.address h1",
    )
    assert out["config_change"] and out["matches"] == [] and out["repoll"] == ""
    out = await sr.explain_message(aoss("00077", "ports", "port 5 is now off-line"))
    assert out["match_tag"] == "AOSS-00077" and out["program"] == "ports" and out["repoll"] == "interface_down"
    assert [m["key"] for m in out["matches"]] == ["link_flap"]
    # A custom Tag rule takes the vendor tag.
    out = await sr.explain_message(
        aoscx(403, "LOG_INFO", "Link status for interface 1/1/7 is up"),
        {"match_type": "tag", "pattern": "AOSCX-403", "name": "up"},
    )
    assert out["draft"] == {"action": "raise", "instance": ""}
