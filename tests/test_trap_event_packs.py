"""SNMP trap event rule packs (``netcontrol.trap_rules``): the layer 2,
routing / tunnel neighbor and PoE trap rules and the registry entries they
use (``netcontrol.snmp_traps``), against traps built the way an agent
builds them from the OIDs and varbinds of each MIB.

Every trap is invented; interface indexes, MAC addresses and peer addresses
are made up (documentation ranges).
"""

from __future__ import annotations

import pytest
from netcontrol import snmp_traps, syslog_rules as sr, trap_rules as tr
from netcontrol.routes.snmp import SNMP_TRAP_OID, decode_snmp_trap
from netcontrol.snmp_traps import name_trap
from pyasn1.codec.ber import encoder
from pysnmp.proto import api

P2 = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]

PACK_KEYS = {
    "stp_root_change",
    "stp_topology_change",
    "port_err_disabled",
    "port_security",
    "mac_flap",
    "hsrp_state",
    "eigrp_neighbor",
    "isis_adjacency",
    "ipsec_tunnel",
    "ip_sla",
    "poe_fault",
}


class Raw(bytes):
    """A value sent as an OCTET STRING of raw bytes."""


def _value(value):
    if isinstance(value, P2.IpAddress):
        return value
    if isinstance(value, Raw):
        return P2.OctetString(bytes(value))
    if isinstance(value, int):
        return P2.Integer(value)
    return P2.OctetString(str(value))


def v2c(trap_oid: str, varbinds=()) -> bytes:
    pdu = P2.SNMPv2TrapPDU()
    P2.apiPDU.set_defaults(pdu)
    P2.apiPDU.set_varbinds(
        pdu,
        [
            ("1.3.6.1.2.1.1.3.0", P2.TimeTicks(4242)),
            (SNMP_TRAP_OID, P2.ObjectIdentifier(trap_oid)),
            *((oid, _value(value)) for oid, value in varbinds),
        ],
    )
    message = P2.Message()
    P2.apiMessage.set_defaults(message)
    P2.apiMessage.set_community(message, "trap-community")
    P2.apiMessage.set_pdu(message, pdu)
    return encoder.encode(message)


def named(data: bytes) -> snmp_traps.NamedTrap:
    trap = decode_snmp_trap(data)
    assert trap is not None
    return name_trap(trap)


def effect(data: bytes) -> tuple[str, str, str] | None:
    found = tr.effects(named(data))
    return (found[0][0].key, found[0][1], found[0][2]) if found else None


CISCO = "1.3.6.1.4.1.9.9"
ERR_CAUSE = f"{CISCO}.548.1.3.1.1.2"
HSRP_STATE = f"{CISCO}.106.1.2.1.1.15"
IKE = f"{CISCO}.171"
RTT = f"{CISCO}.42"
ISIS = "1.3.6.1.2.1.138"
CII = "1.3.6.1.4.1.9.10.118"
PETH = "1.3.6.1.2.1.105"
# The LSP ID of a neighbor with system ID 1920.0000.2002, pseudonode 0, fragment 0.
LSP_ID = Raw(bytes.fromhex("192000002002") + b"\x00\x00")


def hsrp(state: int) -> bytes:
    return v2c(f"{CISCO}.106.2.0.1", [(f"{HSRP_STATE}.12.110", state)])


def ike(trap: int) -> bytes:
    return v2c(
        f"{IKE}.2.0.{trap}",
        [(f"{IKE}.1.2.2.1.6.5", Raw(bytes([192, 0, 2, 1]))), (f"{IKE}.1.2.2.1.7.5", Raw(bytes([203, 0, 113, 9])))],
    )


def rtt(react_var: int, occurred: int) -> bytes:
    return v2c(
        f"{RTT}.2.0.5",
        [
            (f"{RTT}.1.2.1.1.3.10", "probe-a"),
            (f"{RTT}.1.2.19.1.2.10.1", react_var),
            (f"{RTT}.1.2.19.1.10.10.1", occurred),
        ],
    )


def isis(state: int) -> bytes:
    return v2c(
        f"{ISIS}.0.17",
        [
            (f"{ISIS}.1.10.1.1.0", 2),
            (f"{ISIS}.1.10.1.2.0", 4),
            (f"{ISIS}.1.10.1.3.0", LSP_ID),
            (f"{ISIS}.1.10.1.12.0", state),
        ],
    )


def cii(state: int) -> bytes:
    return v2c(
        f"{CII}.0.17",
        [(f"{CII}.1.3.2.1.2.1.4", 4), (f"{CII}.1.10.1.1.0", LSP_ID), (f"{CII}.1.10.1.9.0", state)],
    )


def fgt_vpn(trap: int, remote: str) -> bytes:
    fgt = "1.3.6.1.4.1.12356"
    varbinds = [(f"{fgt}.100.1.1.1.0", "FGEXAMPLE0000001"), (f"{fgt}.101.12.3.4.0", "to-branch-b")]
    if remote:
        varbinds.append((f"{fgt}.101.12.3.3.0", P2.IpAddress(remote)))
    return v2c(f"{fgt}.101.2.0.{trap}", varbinds)


def poe(status: int) -> bytes:
    return v2c(f"{PETH}.0.1", [(f"{PETH}.1.1.1.6.1.7", status)])


SAMPLES = [
    (v2c("1.3.6.1.2.1.17.0.1"), ("stp_root_change", "raise", "")),
    (v2c("1.3.6.1.2.1.17.0.2"), ("stp_topology_change", "raise", "")),
    (v2c(f"{CISCO}.548.0.2", [(f"{ERR_CAUSE}.12.0", 2)]), ("port_err_disabled", "raise", "ifIndex 12")),
    (v2c(f"{CISCO}.548.0.1.1", [(f"{ERR_CAUSE}.13.20", 9)]), ("port_err_disabled", "raise", "ifIndex 13 vlan 20")),
    (
        v2c(
            f"{CISCO}.315.0.0.1",
            [
                ("1.3.6.1.2.1.2.2.1.1.14", 14),
                ("1.3.6.1.2.1.31.1.1.1.1.14", "Gi1/0/14"),
                (f"{CISCO}.315.1.2.1.1.10.14", Raw(bytes.fromhex("00005e005304"))),
            ],
        ),
        ("port_security", "raise", "Gi1/0/14"),
    ),
    (
        v2c(f"{CISCO}.315.0.0.3", [(f"{CISCO}.315.1.2.1.1.18.15", 30)]),
        ("port_security", "raise", ""),
    ),
    (
        v2c(
            f"{CISCO}.215.2.0.2",
            [
                (f"{CISCO}.215.1.3.3.0", Raw(bytes.fromhex("00005e005303"))),
                (f"{CISCO}.215.1.3.4.0", 10),
                (f"{CISCO}.215.1.3.5.0", 3),
                (f"{CISCO}.215.1.3.6.0", 4),
            ],
        ),
        ("mac_flap", "raise", "vlan 10"),
    ),
    (hsrp(6), ("hsrp_state", "raise", "ifIndex 12 group 110")),
    (hsrp(4), ("hsrp_state", "raise", "ifIndex 12 group 110")),
    (
        v2c(
            f"{CISCO}.449.0.3",
            [(f"{CISCO}.449.1.4.1.1.2.0.100.7", 1), (f"{CISCO}.449.1.4.1.1.3.0.100.7", Raw(bytes([192, 0, 2, 2])))],
        ),
        ("eigrp_neighbor", "raise", "192.0.2.2"),
    ),
    (isis(1), ("isis_adjacency", "raise", "1920.0000.2002 circuit 4")),
    (isis(4), ("isis_adjacency", "raise", "1920.0000.2002 circuit 4")),
    (isis(3), ("isis_adjacency", "clear", "1920.0000.2002 circuit 4")),
    (cii(1), ("isis_adjacency", "raise", "1920.0000.2002 circuit 4")),
    (cii(3), ("isis_adjacency", "clear", "1920.0000.2002 circuit 4")),
    (ike(2), ("ipsec_tunnel", "raise", "203.0.113.9")),
    (ike(1), ("ipsec_tunnel", "clear", "203.0.113.9")),
    (rtt(7, 1), ("ip_sla", "raise", "probe 10")),
    (rtt(8, 1), ("ip_sla", "raise", "probe 10")),
    (rtt(8, 2), ("ip_sla", "clear", "probe 10")),
    (poe(4), ("poe_fault", "raise", "PoE port 1.7")),
    (poe(6), ("poe_fault", "raise", "PoE port 1.7")),
    (poe(3), ("poe_fault", "clear", "PoE port 1.7")),
    # Netgear NETGEAR-SWITCHING-MIB, per MST instance.
    (
        v2c("1.3.6.1.4.1.4526.10.1.0.10", [("1.3.6.1.4.1.4526.10.1.2.15.10.1.1.3", 3)]),
        ("stp_root_change", "raise", "instance 3"),
    ),
    (
        v2c("1.3.6.1.4.1.4526.10.1.0.11", [("1.3.6.1.4.1.4526.10.1.2.15.10.1.1.3", 3)]),
        ("stp_topology_change", "raise", "instance 3"),
    ),
    # FortiOS FORTINET-FORTIGATE-MIB: the remote gateway, else the phase 1 name.
    (fgt_vpn(302, "198.51.100.40"), ("ipsec_tunnel", "raise", "198.51.100.40")),
    (fgt_vpn(301, "198.51.100.40"), ("ipsec_tunnel", "clear", "198.51.100.40")),
    (fgt_vpn(302, ""), ("ipsec_tunnel", "raise", "to-branch-b")),
]


@pytest.mark.parametrize(("data", "expected"), SAMPLES)
def test_each_trap_raises_or_clears_its_rule(data, expected):
    assert effect(data) == expected


@pytest.mark.parametrize(
    "data",
    [
        hsrp(5),  # a router taking its normal standby role
        rtt(1, 1),  # a round trip time threshold, not reachability
        isis(2),  # initializing
        poe(2),  # searching
        poe(1),  # disabled by an operator
        v2c(f"{IKE}.2.0.3"),  # cikeSysFailure: not in the registry
    ],
)
def test_near_misses_act_on_nothing(data):
    assert effect(data) is None


def test_the_pack_traps_are_named_with_their_varbinds():
    trap = named(v2c(f"{CISCO}.548.0.2", [(f"{ERR_CAUSE}.12.0", 2)]))
    assert trap.name == "cErrDisableInterfaceEventRev1"
    assert trap.message == "cErrDisableInterfaceEventRev1: cErrDisableIfStatusCause bpduGuard"
    assert named(hsrp(6)).message == "cHsrpStateChange: cHsrpGrpStandbyState active"
    assert named(rtt(8, 1)).label("rttMonReactVar") == "connectionLoss"
    assert named(poe(4)).label("pethPsePortDetectionStatus") == "fault"
    assert tr.event_fields(named(ike(2)))[0] == "critical"
    assert tr.event_fields(named(ike(1)))[0] == "info"


def test_every_pack_rule_has_a_sample_and_registered_traps():
    keys = [r.key for r in tr.TRAP_RULES]
    assert len(keys) == len(set(keys))
    assert {expected[0] for _d, expected in SAMPLES} == PACK_KEYS
    names = {t.name for t in snmp_traps.TRAPS_BY_OID.values()}
    count = sum(len(table.TRAPS) for _family, table in snmp_traps.TABLES)
    assert len(snmp_traps.TRAPS_BY_OID) == count
    by_key = {r.key: r for r in tr.TRAP_RULES}
    for key in PACK_KEYS:
        rule = by_key[key]
        assert rule.severity in sr.SEVERITIES and rule.families
        assert set(rule.raise_on) <= names and set(rule.clear_on) <= names, key
        assert rule.clear_on or rule.auto_resolve_minutes > 0, key


def test_noisy_traps_raise_only_at_their_threshold():
    sr.reset_state()
    try:
        rules = {r.key: r for r in tr.merge_rules([])}
        topo = rules["stp_topology_change"]
        assert (topo.threshold_count, topo.threshold_window_seconds, topo.metric) == (
            5,
            600,
            "trap_stp_topology_change",
        )
        change = named(v2c("1.3.6.1.2.1.17.0.2"))
        results = [sr.track(topo, 1, change, 100.0 + 30 * i) for i in range(5)]
        assert results[:4] == [None] * 4 and results[4] == (True, "")
    finally:
        sr.reset_state()


def test_instance_helpers_without_their_varbinds():
    empty = named(v2c(f"{CISCO}.548.0.2"))
    assert tr._err_disabled_port(empty) == ""
    assert tr._hsrp_group(empty) == ""
    assert tr._isis_neighbor("isisPduLspId", "isisNotificationCircIfIndex")(empty) == ""
    assert tr._index_part("rttMonReactOccurred", "probe")(empty) == ""
    # An LSP ID that is not an octet string of at least 6 bytes names the circuit only.
    short = named(v2c(f"{ISIS}.0.17", [(f"{ISIS}.1.10.1.2.0", 4), (f"{ISIS}.1.10.1.3.0", Raw(b"\x01\x02"))]))
    assert tr._isis_neighbor("isisPduLspId", "isisNotificationCircIfIndex")(short) == "circuit 4"
