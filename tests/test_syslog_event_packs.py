"""Syslog event rule packs (``netcontrol.syslog_rules``): the layer 2,
routing / tunnel neighbor and device health rules against sample messages,
their instances, thresholds and the messages that must not match.

Every message is invented in the form the Cisco references give (see
docs/syslog-rules.md "Event rule packs"); host names, interfaces, MAC
addresses and peer addresses are made up (documentation ranges).
"""

from __future__ import annotations

import pytest
from netcontrol import syslog_rules as sr

PACK_KEYS = {
    "stp_root_change",
    "stp_topology_change",
    "stp_guard",
    "port_err_disabled",
    "port_security",
    "storm_control",
    "mac_flap",
    "duplex_mismatch",
    "hsrp_state",
    "eigrp_neighbor",
    "isis_adjacency",
    "ipsec_tunnel",
    "ip_sla",
    "poe_fault",
    "optic_power",
    "aaa_server",
    "ntp_sync",
    "license_expiry",
    "certificate_expiry",
    "software_fault",
}

# (message, rule key, action, instance)
SAMPLES = [
    # ── Layer 2 ──
    (
        "%SPANTREE-5-ROOTCHANGE: Root Changed for vlan 10: New Root Port is Gi1/0/1. New Root Mac Address is "
        "0000.5e00.5301",
        "stp_root_change",
        "raise",
        "vlan 10",
    ),
    ("%SPANTREE-5-TOPOTRAP: Topology Change Trap for vlan 20", "stp_topology_change", "raise", "vlan 20"),
    (
        "%SPANTREE-2-ROOTGUARD_BLOCK: Root guard blocking port Gi1/0/3 on VLAN0010.",
        "stp_guard",
        "raise",
        "Gi1/0/3/VLAN0010",
    ),
    (
        "%SPANTREE-2-ROOTGUARD_UNBLOCK: Root guard unblocking port Gi1/0/3 on VLAN0010.",
        "stp_guard",
        "clear",
        "Gi1/0/3/VLAN0010",
    ),
    (
        "%SPANTREE-2-LOOPGUARD_BLOCK: Loop guard blocking port Te1/1/1 on VLAN0020.",
        "stp_guard",
        "raise",
        "Te1/1/1/VLAN0020",
    ),
    (
        "%SPANTREE-2-LOOPGUARD_UNBLOCK: Loop guard unblocking port Te1/1/1 on VLAN0020.",
        "stp_guard",
        "clear",
        "Te1/1/1/VLAN0020",
    ),
    (
        "%SPANTREE-2-BRIDGE_ASSURANCE_BLOCK: Bridge Assurance blocking port Po10 VLAN0030.",
        "stp_guard",
        "raise",
        "Po10",
    ),
    (
        "%SPANTREE-2-BRIDGE_ASSURANCE_UNBLOCK: Bridge Assurance unblocking port Po10 VLAN0030.",
        "stp_guard",
        "clear",
        "Po10",
    ),
    (
        "%PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/5, putting Gi1/0/5 in err-disable state",
        "port_err_disabled",
        "raise",
        "Gi1/0/5",
    ),
    (
        "%PM-SP-4-ERR_DISABLE: udld error detected on Gi4/1, putting Gi4/1 in err-disable state.",
        "port_err_disabled",
        "raise",
        "Gi4/1",
    ),
    (
        "%PM-4-ERR_DISABLE_VP: psecure-violation error detected on Gi1/0/6 vlan 20. Putting in err-disable state.",
        "port_err_disabled",
        "raise",
        "Gi1/0/6/20",
    ),
    (
        "%PORT_SECURITY-2-PSECURE_VIOLATION: Security violation occurred, caused by MAC address 0000.5e00.5302 on "
        "port GigabitEthernet1/0/7.",
        "port_security",
        "raise",
        "GigabitEthernet1/0/7",
    ),
    (
        "%STORM_CONTROL-3-FILTERED: A broadcast storm detected on Gi1/0/8. A packet filter action has been applied "
        "on the interface.",
        "storm_control",
        "raise",
        "Gi1/0/8",
    ),
    (
        "%STORM_CONTROL-3-SHUTDOWN: A packet storm was detected on Gi1/0/9. The interface has been disabled.",
        "storm_control",
        "raise",
        "Gi1/0/9",
    ),
    ("%STORM_CONTROL-2-SHUTDOWN: Storm control shut down Gi1/0/9", "storm_control", "raise", "Gi1/0/9"),
    (
        "%STORM_CONTROL-5-ABATED: A broadcast storm abated on Gi1/0/8. Packet filter does not apply on the interface.",
        "storm_control",
        "clear",
        "Gi1/0/8",
    ),
    (
        "%SW_MATM-4-MACFLAP_NOTIF: Host 0000.5e00.5303 in vlan 10 is flapping between port Gi1/0/10 and port Po1",
        "mac_flap",
        "raise",
        "vlan 10",
    ),
    (
        "%CDP-4-DUPLEX_MISMATCH: duplex mismatch discovered on GigabitEthernet0/1 (not full duplex), with sw-b "
        "GigabitEthernet0/2 (full duplex).",
        "duplex_mismatch",
        "raise",
        "GigabitEthernet0/1",
    ),
    # ── Routing and tunnel neighbors ──
    ("%HSRP-5-STATECHANGE: Vlan10 Grp 110 state Standby -> Active", "hsrp_state", "raise", "Vlan10/110"),
    ("%HSRP-6-STATECHANGE: Vlan10 Grp 110 state Active -> Speak", "hsrp_state", "raise", "Vlan10/110"),
    ("%STANDBY-6-STATECHANGE: Standby: 49: Vlan149 state Active-> Speak", "hsrp_state", "raise", "Vlan149/49"),
    (
        "%DUAL-5-NBRCHANGE: EIGRP-IPv4 100: Neighbor 192.0.2.2 (GigabitEthernet0/1) is down: holding time expired",
        "eigrp_neighbor",
        "raise",
        "192.0.2.2",
    ),
    (
        "%DUAL-5-NBRCHANGE: IP-EIGRP(0) 1: Neighbor 192.0.2.2 (GigabitEthernet0/1) is up: new adjacency",
        "eigrp_neighbor",
        "clear",
        "192.0.2.2",
    ),
    (
        "%EIGRP-5-NBRCHANGE_DUAL: eigrp-100 [4321] (default-base) IP-EIGRP(0) 100: Neighbor 198.51.100.9 "
        "(Ethernet1/1) is down: holding time expired",
        "eigrp_neighbor",
        "raise",
        "198.51.100.9",
    ),
    (
        "%CLNS-5-ADJCHANGE: ISIS: Adjacency to core-b (TenGigabitEthernet0/0/4) Down, hold time expired",
        "isis_adjacency",
        "raise",
        "core-b/TenGigabitEthernet0/0/4",
    ),
    (
        "%CLNS-5-ADJCHANGE: ISIS: Adjacency to core-b (TenGigabitEthernet0/0/4) Up, new adjacency",
        "isis_adjacency",
        "clear",
        "core-b/TenGigabitEthernet0/0/4",
    ),
    (
        "%ISIS-5-ADJCHANGE: isis-1 [4321] LAN adj L2 core-c over Ethernet1/2 - DOWN (Hold timer expired) on MT-0",
        "isis_adjacency",
        "raise",
        "core-c/Ethernet1/2",
    ),
    (
        "%ISIS-5-ADJCHANGE: isis-1 [4321] LAN adj L2 core-c over Ethernet1/2 - UP on MT-0",
        "isis_adjacency",
        "clear",
        "core-c/Ethernet1/2",
    ),
    (
        "%CRYPTO-5-SESSION_STATUS: Crypto session is DOWN. Peer 203.0.113.6:500 fvrf=name10 ivrf=name20 "
        "Description: branch-a Id: 203.0.113.6",
        "ipsec_tunnel",
        "raise",
        "203.0.113.6:500",
    ),
    (
        "%CRYPTO-5-SESSION_STATUS: Crypto tunnel is UP. Peer 203.0.113.6:500 Description: branch-a Id: branch-a",
        "ipsec_tunnel",
        "clear",
        "203.0.113.6:500",
    ),
    ("%TRACK-6-STATE: 100 ip sla 100 reachability Up -> Down", "ip_sla", "raise", "100 ip sla 100"),
    ("%TRACK-6-STATE: 100 ip sla 100 reachability Down -> Up", "ip_sla", "clear", "100 ip sla 100"),
    ("%TRACK-6-STATE: 7 ip sla 7 state Up -> Down", "ip_sla", "raise", "7 ip sla 7"),
    # ── Device health ──
    (
        "%ILPOWER-3-CONTROLLER_PORT_ERR: Controller port error, Interface Gi1/0/11: Power Controller reports power "
        "Imax error detected",
        "poe_fault",
        "raise",
        "Gi1/0/11",
    ),
    (
        "%ILPOWER-5-ILPOWER_POWER_DENY: Interface Gi1/0/12: inline power denied. Reason: insufficient power",
        "poe_fault",
        "raise",
        "Gi1/0/12",
    ),
    (
        "%ILPOWER-3-SHUT_OVERDRAWN: Interface Gi1/0/13 is shutdown as it is consuming more than the maximum "
        "configured power (15400) milliwatts.",
        "poe_fault",
        "raise",
        "Gi1/0/13",
    ),
    (
        "%ILPOWER-4-LOG_OVERDRAWN: Interface Gi1/0/14 is overdrawing power. it is consuming 16000 milliwatts where "
        "as maximum configured power is 15400 milliwatts.",
        "poe_fault",
        "raise",
        "Gi1/0/14",
    ),
    (
        "%ILPOWER-5-CLR_OVERDRAWN: Interface Gi1/0/14 is NOT overdrawing power. it is consuming 9000 milliwatts "
        "where as maximum configured value is 15400 milliwatts.",
        "poe_fault",
        "clear",
        "Gi1/0/14",
    ),
    ("%ILPOWER-5-POWER_GRANTED: Interface Gi1/0/12: Power granted", "poe_fault", "clear", "Gi1/0/12"),
    (
        "%SFF8472-5-THRESHOLD_VIOLATION: Te1/1/2: Rx power low alarm; Operating value: -40.0 dBm, Threshold "
        "value: -18.4 dBm.",
        "optic_power",
        "raise",
        "Te1/1/2",
    ),
    (
        "%SFF8472-3-THRESHOLD_VIOLATION: Gi1/1/1: Tx power high warning; Operating value: 1.2 dBm, Threshold "
        "value: 0.5 dBm.",
        "optic_power",
        "raise",
        "Gi1/1/1",
    ),
    (
        "%RADIUS-4-RADIUS_DEAD: RADIUS server 192.0.2.50:1812,1813 is not responding.",
        "aaa_server",
        "raise",
        "192.0.2.50:1812,1813",
    ),
    (
        "%RADIUS_AUDIT_MESSAGE-6-RADIUS_DEAD: R0/0: sessmgrd: RADIUS server 192.0.2.50:1812,1813 is not responding.",
        "aaa_server",
        "raise",
        "192.0.2.50:1812,1813",
    ),
    (
        "%RADIUS-4-RADIUS_ALIVE: RADIUS server 192.0.2.50:1812,1813 is being marked alive.",
        "aaa_server",
        "clear",
        "192.0.2.50:1812,1813",
    ),
    ("%NTP-4-UNSYNC: NTP sync is lost", "ntp_sync", "raise", ""),
    ("%NTP-5-PEERSYNC: NTP synced to peer 192.0.2.123", "ntp_sync", "clear", ""),
    ("%SMART_LIC-4-EVAL_WILL_EXPIRE_WARNING: Evaluation period will expire in 6 days.", "license_expiry", "raise", ""),
    ("%SMART_LIC-3-AUTHORIZATION_EXPIRED: Authorization period expired", "license_expiry", "raise", ""),
    (
        "%SMART_LIC-3-ID_CERT_EXPIRED_WARNING: This device's registration will expire in 29 days.",
        "license_expiry",
        "raise",
        "",
    ),
    ("%PKI-4-CERT_EXPIRY_WARNING: Certificate is expiring soon.", "certificate_expiry", "raise", ""),
    (
        "%PKI-2-CERT_RENEW_FAIL: Certificate renewal failed for trustpoint TP-EXAMPLE Reason : timed out",
        "certificate_expiry",
        "raise",
        "TP-EXAMPLE",
    ),
    (
        "%PKI-3-CERTIFICATE_INVALID_EXPIRED: Certificate chain validation has failed. The certificate SN: 1A2B3C has "
        "expired.",
        "certificate_expiry",
        "raise",
        "1A2B3C",
    ),
    (
        "%SYS-2-MALLOCFAIL: Memory allocation of 65536 bytes failed from 0x60103098, alignment 0",
        "software_fault",
        "raise",
        "",
    ),
    ("%PLATFORM-1-CRASHED: System previously crashed with the following message:", "software_fault", "raise", ""),
    (
        '%SYSMGR-2-SERVICE_CRASHED: Service "snmpd" (PID 28063) hasn\'t caught signal 11 (core will be saved).',
        "software_fault",
        "raise",
        "snmpd",
    ),
]


def _rules() -> dict[str, sr.Rule]:
    return {r.key: r for r in sr.merge_rules([])}


@pytest.mark.parametrize(("message", "key", "action", "instance"), SAMPLES)
def test_each_form_raises_or_clears_its_rule(message, key, action, instance):
    parsed = sr.parse_syslog_message("<187>12: sw-a1: Jan 10 10:00:00.000 UTC: " + message)
    rules = _rules()
    assert sr._evaluate(rules[key], parsed) == {"action": action, "instance": instance}
    # No other rule acts on the message.
    assert [k for k, r in rules.items() if sr._evaluate(r, parsed)] == [key]


def test_every_pack_rule_is_built_in_with_a_sample():
    assert {key for _m, key, _a, _i in SAMPLES} == PACK_KEYS
    assert PACK_KEYS <= set(sr.BUILTIN_BY_KEY)
    keys = [r.key for r in sr.BUILTIN_RULES]
    assert len(keys) == len(set(keys))
    for key in PACK_KEYS:
        rule = sr.BUILTIN_BY_KEY[key]
        assert rule.severity in sr.SEVERITIES and rule.families and rule.raise_on
        # An event without a clearing message resolves on its own.
        assert rule.clear_on or rule.auto_resolve_minutes > 0, key
        assert sr.tag_owner(next(iter(rule.raise_on[0].tags))) == key


@pytest.mark.parametrize(
    "message",
    [
        # HSRP moves that neither take nor leave the active role.
        "%HSRP-5-STATECHANGE: Vlan10 Grp 110 state Speak -> Standby",
        "%STANDBY-6-STATECHANGE: Standby: 49: Vlan149 state Listen -> Speak",
        # An EIGRP graceful restart resync.
        "%DUAL-5-NBRCHANGE: IP-EIGRP(0) 1: Neighbor 192.0.2.2 (FastEthernet1) is resync: graceful restart",
        # A tracked interface, not an IP SLA operation.
        "%TRACK-6-STATE: 1 interface Gi0/1 line-protocol Up -> Down",
        # Optic temperature, not light level.
        "%SFF8472-5-THRESHOLD_VIOLATION: Te1/1/2: Temperature high alarm; Operating value: 80.0 C, Threshold value: "
        "75.0 C.",
        # Informational messages of the same facilities.
        "%NTP-6-PEERREACH: Peer 192.0.2.123 is reachable",
        "%SMART_LIC-6-AUTH_RENEW_SUCCESS: Authorization renewal with the Cisco Smart Software Manager successful",
        "%ILPOWER-7-DETECT: Interface Gi1/0/12: Power Device detected: IEEE PD",
        "%PM-4-ERR_RECOVER: Attempting to recover from bpduguard err-disable state on Gi1/0/5",
        "%SPANTREE-2-ROOTGUARD_CONFIG_CHANGE: Root guard enabled on port Gi1/0/3.",
        "%UDLD-6-UDLD_PORT_RESET: UDLD reset interface Gi1/0/4",
        "%CRYPTO-6-AUTOGEN: Generated new 2048 bit key pair",
    ],
)
def test_near_misses_raise_nothing(message):
    parsed = sr.parse_syslog_message(message)
    assert [r.key for r in sr.merge_rules([]) if sr._evaluate(r, parsed)] == []


@pytest.fixture
def clean_counters():
    sr.reset_state()
    yield
    sr.reset_state()


def _track(rule: sr.Rule, message: str, at: float) -> tuple[bool, str] | None:
    return sr.track(rule, 1, sr.parse_syslog_message(message), at)


@pytest.mark.usefixtures("clean_counters")
def test_noisy_events_raise_only_at_their_threshold():
    rules = _rules()
    flap = "%SW_MATM-4-MACFLAP_NOTIF: Host 0000.5e00.5303 in vlan 10 is flapping between port Gi1/0/10 and port Po1"
    mac = rules["mac_flap"]
    assert (mac.threshold_count, mac.threshold_window_seconds) == (3, 600)
    assert _track(mac, flap, 1000.0) is None
    assert _track(mac, flap, 1060.0) is None
    assert _track(mac, flap, 1120.0) == (True, "vlan 10")
    # A move in another VLAN is counted apart.
    assert _track(mac, flap.replace("vlan 10", "vlan 11"), 1121.0) is None

    topo = rules["stp_topology_change"]
    tc = "%SPANTREE-5-TOPOTRAP: Topology Change Trap for vlan 20"
    results = [_track(topo, tc, 2000.0 + 30 * i) for i in range(5)]
    assert results[:4] == [None] * 4 and results[4] == (True, "vlan 20")


@pytest.mark.usefixtures("clean_counters")
def test_a_root_change_raises_at_once_and_resolves_on_time():
    rule = _rules()["stp_root_change"]
    assert rule.threshold_count == 1 and rule.auto_resolve_minutes == 60 and rule.clear_match is None
    message = "%SPANTREE-5-ROOTCHANGE: Root Changed for vlan 30: New Root Port is Po1. New Root Mac Address is x"
    assert _track(rule, message, 10.0) == (True, "vlan 30")
