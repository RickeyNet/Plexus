"""SNMP traps of every supported vendor: decoding (pysnmp's BER codec), the
trap registry's names and varbind names (``netcontrol.snmp_traps``), the
trap rules (``netcontrol.trap_rules``: raise, clear, dedup, threshold,
re-poll and configuration-change triggers, switches, overrides), the intake
rules of the receiver's batch writer, the SNMPv2c inform response, the trap
rules API and the Events API filter.

Every trap datagram is invented and built with pysnmp the way an agent
builds it, from the OIDs and varbinds of the vendor's MIB; names, serial
numbers and addresses are made up (documentation ranges).
"""

from __future__ import annotations

import ipaddress
import re

import netcontrol.routes.metrics_engine as me
import netcontrol.routes.state as state
import pytest
import routes.database as db
from netcontrol import listener_sources as ls, snmp_traps, syslog_rules as sr, trap_rules as tr
from netcontrol.routes.snmp import SNMP_TRAP_OID, decode_snmp_trap, snmp_inform_response
from netcontrol.snmp_traps import name_trap
from pyasn1.codec.ber import decoder, encoder
from pysnmp.proto import api

from mcp_helpers import CsrfClient, admin_client, user_client

COMMUNITY = "trap-community"
P2 = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]
P1 = api.PROTOCOL_MODULES[api.SNMP_VERSION_1]
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
PREFIX = "/api/monitoring/trap-rules"


# ── Building PDUs ────────────────────────────────────────────────────────────


class Ip(str):
    """A value sent as an SNMP IpAddress."""


class Raw(bytes):
    """A value sent as an OCTET STRING of raw bytes."""


def _value(proto, value):
    if isinstance(value, Ip):
        return proto.IpAddress(str(value))
    if isinstance(value, Raw):
        return proto.OctetString(bytes(value))
    if isinstance(value, int):
        return proto.Integer(value)
    return proto.OctetString(str(value))


def v2c(trap_oid: str, varbinds=(), *, inform: bool = False, community: str = COMMUNITY, request_id: int = 7) -> bytes:
    pdu = P2.InformRequestPDU() if inform else P2.SNMPv2TrapPDU()
    P2.apiPDU.set_defaults(pdu)
    P2.apiPDU.set_request_id(pdu, request_id)
    P2.apiPDU.set_varbinds(
        pdu,
        [
            (SYS_UPTIME, P2.TimeTicks(4242)),
            (SNMP_TRAP_OID, P2.ObjectIdentifier(trap_oid)),
            *((oid, _value(P2, value)) for oid, value in varbinds),
        ],
    )
    message = P2.Message()
    P2.apiMessage.set_defaults(message)
    P2.apiMessage.set_community(message, community)
    P2.apiMessage.set_pdu(message, pdu)
    return encoder.encode(message)


def v1(enterprise: str, specific: int, varbinds=(), *, generic: int = 6, agent: str = "192.0.2.20") -> bytes:
    pdu = P1.TrapPDU()
    P1.apiTrapPDU.set_defaults(pdu)
    P1.apiTrapPDU.set_enterprise(pdu, enterprise)
    P1.apiTrapPDU.set_agent_address(pdu, agent)
    P1.apiTrapPDU.set_generic_trap(pdu, generic)
    P1.apiTrapPDU.set_specific_trap(pdu, specific)
    P1.apiTrapPDU.set_varbinds(pdu, [(oid, _value(P1, value)) for oid, value in varbinds])
    message = P1.Message()
    P1.apiMessage.set_defaults(message)
    P1.apiMessage.set_community(message, COMMUNITY)
    P1.apiMessage.set_pdu(message, pdu)
    return encoder.encode(message)


def named(data: bytes) -> snmp_traps.NamedTrap:
    trap = decode_snmp_trap(data)
    assert trap is not None
    return name_trap(trap)


def effect(data: bytes) -> tuple[str, str, str] | None:
    found = tr.effects(named(data))
    return (found[0][0].key, found[0][1], found[0][2]) if found else None


# ── Sample traps per vendor (OIDs from the vendors' MIBs) ────────────────────

IF = "1.3.6.1.2.1.2.2.1"
LINK_DOWN = v2c(
    "1.3.6.1.6.3.1.1.5.3",
    [(f"{IF}.1.12", 12), (f"{IF}.2.12", "GigabitEthernet1/0/12"), (f"{IF}.7.12", 1), (f"{IF}.8.12", 2)],
)
LINK_UP = v2c("1.3.6.1.6.3.1.1.5.4", [(f"{IF}.1.12", 12), (f"{IF}.7.12", 1), (f"{IF}.8.12", 1)])
LINK_SHUT = v2c("1.3.6.1.6.3.1.1.5.3", [(f"{IF}.1.13", 13), (f"{IF}.7.13", 2), (f"{IF}.8.13", 2)])
OSPF_NBR = "1.3.6.1.2.1.14.10.1"


def ospf_nbr(state_value: int) -> bytes:
    index = "198.51.100.2.0"
    return v2c(
        "1.3.6.1.2.1.14.16.2.2",
        [
            ("1.3.6.1.2.1.14.1.1.0", Ip("192.0.2.1")),
            (f"{OSPF_NBR}.1.{index}", Ip("198.51.100.2")),
            (f"{OSPF_NBR}.2.{index}", 0),
            (f"{OSPF_NBR}.3.{index}", Ip("198.51.100.22")),
            (f"{OSPF_NBR}.6.{index}", state_value),
        ],
    )


def bgp4(trap: str, peer_state: int) -> bytes:
    return v2c(
        trap,
        [
            ("1.3.6.1.2.1.15.3.1.7.203.0.113.2", Ip("203.0.113.2")),
            ("1.3.6.1.2.1.15.3.1.14.203.0.113.2", Raw(b"\x06\x04")),
            ("1.3.6.1.2.1.15.3.1.2.203.0.113.2", peer_state),
        ],
    )


CEFC = "1.3.6.1.4.1.9.9.117"


def cefc_module(status: int) -> bytes:
    return v2c(f"{CEFC}.2.0.1", [(f"{CEFC}.1.2.1.1.2.1001", status), (f"{CEFC}.1.2.1.1.4.1001", 1234)])


def envmon(trap: str, column: str, descr: str, value: int) -> bytes:
    return v2c(f"1.3.6.1.4.1.9.9.13.3.0.{trap}", [(f"{column}.2.2", descr), (f"{column}.3.2", value)])


ENVMON_SUPPLY = "1.3.6.1.4.1.9.9.13.1.5.1"
ENVMON_FAN = "1.3.6.1.4.1.9.9.13.1.4.1"


def cbgp2(trap: str, index: str, peer_state: int = 1, prev: int | None = None) -> bytes:
    varbinds = [
        ("1.3.6.1.4.1.9.9.187.1.2.5.1.17." + index, Raw(b"\x04\x00")),
        (f"1.3.6.1.4.1.9.9.187.1.2.5.1.3.{index}", peer_state),
    ]
    if prev is not None:
        varbinds.append((f"1.3.6.1.4.1.9.9.187.1.2.5.1.29.{index}", prev))
    return v2c(f"1.3.6.1.4.1.9.9.187.0.{trap}", varbinds)


V6_PEER = ipaddress.IPv6Address("2001:db8::7").packed
CBGP2_V4 = "1.4.198.51.100.7"
CBGP2_V6 = "2.16." + ".".join(str(b) for b in V6_PEER)


def cbgp_fsm(new: int, prev: int) -> bytes:
    return v2c(
        "1.3.6.1.4.1.9.9.187.0.1",
        [("1.3.6.1.2.1.15.3.1.2.192.0.2.30", new), ("1.3.6.1.4.1.9.9.187.1.2.1.1.8.192.0.2.30", prev)],
    )


JNX_CONTENTS = "1.3.6.1.4.1.2636.3.1.8.1"
JNX_FRU = "1.3.6.1.4.1.2636.3.1.15.1"


def jnx_fru(trap: str, fru_type: int, reason: int | None = None) -> bytes:
    index = "7.1.0.0"
    varbinds = [
        (f"{JNX_FRU}.1.{index}", 7),
        (f"{JNX_FRU}.5.{index}", "FPC: MPC7E @ 0/*/*"),
        (f"{JNX_FRU}.6.{index}", fru_type),
        (f"{JNX_FRU}.7.{index}", 0),
    ]
    if reason is not None:
        varbinds.append((f"{JNX_FRU}.10.{index}", reason))
    return v2c(trap, varbinds)


JNX_PSU = [
    (f"{JNX_CONTENTS}.1.2.1.0.0", 2),
    (f"{JNX_CONTENTS}.6.2.1.0.0", "PEM 0"),
    ("1.3.6.1.4.1.2636.3.1.13.1.6.2.1.0.0", 6),
]

PAN_OBJ = "1.3.6.1.4.1.25461.2.1.3.1"
PAN_TRAP = "1.3.6.1.4.1.25461.2.1.3.2.0"


def pan(event: int, obj: str, description: str) -> bytes:
    return v2c(
        f"{PAN_TRAP}.{event}",
        [
            (f"{PAN_OBJ}.3.0", "000000000000"),
            (f"{PAN_OBJ}.12.0", "fw-a"),
            (f"{PAN_OBJ}.301.0", obj),
            (f"{PAN_OBJ}.303.0", 5),
            (f"{PAN_OBJ}.304.0", description),
        ],
    )


def pan_config(cmd: str, result: str) -> bytes:
    return v2c(f"{PAN_TRAP}.2", [(f"{PAN_OBJ}.150.0", cmd), (f"{PAN_OBJ}.151.0", "ops"), (f"{PAN_OBJ}.153.0", result)])


AOSCX = "1.3.6.1.4.1.47196.4.1.1.3"


def vsf2(status: str) -> bytes:
    return v2c(
        f"{AOSCX}.15.0.1",
        [(f"{AOSCX}.15.1.2.1.1.2", 2), (f"{AOSCX}.15.1.2.1.2.2", "member"), (f"{AOSCX}.15.1.2.1.3.2", status)],
    )


def hp_psu(status: int) -> bytes:
    return v2c(
        "1.3.6.1.4.1.11.2.14.12.1.0.6",
        [("1.3.6.1.4.1.11.2.14.11.1.2.11.1.1.2", 2), ("1.3.6.1.4.1.11.2.14.11.1.2.11.1.2.2", status)],
    )


def boxs(trap: int, index_oid: str, event: int) -> bytes:
    return v2c(f"1.3.6.1.4.1.4526.10.43.0.{trap}", [(index_oid, 2), ("1.3.6.1.4.1.4526.10.43.2.1.0", event)])


FORTI_SERIAL = ("1.3.6.1.4.1.12356.100.1.1.1.0", "FGT60FTK0000TEST")
FORTI_NAME = ("1.3.6.1.2.1.1.5.0", "fw-b")

# (sample, trap name, a text the stored message contains, (rule, action, instance) or None)
SAMPLES = [
    # Standard MIBs
    (
        LINK_DOWN,
        "linkDown",
        "linkDown: ifIndex 12, ifDescr GigabitEthernet1/0/12, ifAdminStatus up, ifOperStatus down",
        ("link_down", "raise", "ifIndex 12"),
    ),
    (LINK_UP, "linkUp", "ifOperStatus up", ("link_down", "clear", "ifIndex 12")),
    (LINK_SHUT, "linkDown", "ifAdminStatus down", None),
    (
        v1("1.3.6.1.4.1.9.1.1", 0, [(f"{IF}.1.5", 5), (f"{IF}.7.5", 1), (f"{IF}.8.5", 2)], generic=2),
        "linkDown",
        "ifIndex 5",
        ("link_down", "raise", "ifIndex 5"),
    ),
    (v1("1.3.6.1.4.1.9.1.1", 0, generic=0), "coldStart", "coldStart: Agent started", ("device_restart", "raise", "")),
    (v2c("1.3.6.1.6.3.1.1.5.5"), "authenticationFailure", "SNMP message refused", ("snmp_auth_failure", "raise", "")),
    (ospf_nbr(1), "ospfNbrStateChange", "ospfNbrState down", ("ospf_neighbor", "raise", "198.51.100.22")),
    (ospf_nbr(8), "ospfNbrStateChange", "ospfNbrState full", ("ospf_neighbor", "clear", "198.51.100.22")),
    (ospf_nbr(4), "ospfNbrStateChange", "ospfNbrState twoWay", ("ospf_neighbor", "clear", "198.51.100.22")),
    (ospf_nbr(3), "ospfNbrStateChange", "ospfNbrState init", None),
    (
        bgp4("1.3.6.1.2.1.15.0.2", 1),
        "bgpBackwardTransNotification",
        "bgpPeerState idle",
        ("bgp_neighbor", "raise", "203.0.113.2"),
    ),
    (
        bgp4("1.3.6.1.2.1.15.0.1", 6),
        "bgpEstablishedNotification",
        "bgpPeerState established",
        ("bgp_neighbor", "clear", "203.0.113.2"),
    ),
    (
        v2c("1.3.6.1.2.1.68.0.1", [("1.3.6.1.2.1.68.1.3.1.7.3.1", Ip("192.0.2.254"))]),
        "vrrpTrapNewMaster",
        "vrrpOperMasterIpAddr 192.0.2.254",
        ("ha_switchover", "raise", "VRRP 3.1"),
    ),
    (v2c("1.3.6.1.2.1.17.0.2"), "topologyChange", "Spanning tree topology change", None),
    # net-snmp (OPNsense)
    (v2c("1.3.6.1.4.1.8072.4.0.1"), "nsNotifyStart", "net-snmp agent started", ("device_restart", "raise", "")),
    # Cisco
    (
        cefc_module(7),
        "cefcModuleStatusChange",
        "cefcModuleOperStatus failed",
        ("module", "raise", "entPhysicalIndex 1001"),
    ),
    (cefc_module(2), "cefcModuleStatusChange", "cefcModuleOperStatus ok", ("module", "clear", "entPhysicalIndex 1001")),
    (cefc_module(13), "cefcModuleStatusChange", "outOfServiceAdmin", None),
    (
        v2c(f"{CEFC}.2.0.4", [("1.3.6.1.2.1.47.1.1.1.1.4.1001", 1)]),
        "cefcFRURemoved",
        "entPhysicalContainedIn 1",
        ("module", "raise", "entPhysicalIndex 1001"),
    ),
    (
        envmon("9", ENVMON_SUPPLY, "Power Supply 2", 3),
        "ciscoEnvMonSuppStatusChangeNotif",
        "ciscoEnvMonSupplyStatusDescr Power Supply 2, ciscoEnvMonSupplyState critical",
        ("power_supply", "raise", "supply 2"),
    ),
    (
        envmon("9", ENVMON_SUPPLY, "Power Supply 2", 1),
        "ciscoEnvMonSuppStatusChangeNotif",
        "normal",
        ("power_supply", "clear", "supply 2"),
    ),
    (
        envmon("8", ENVMON_FAN, "Fan 2", 6),
        "ciscoEnvMonFanStatusChangeNotif",
        "notFunctioning",
        ("fan", "raise", "fan 2"),
    ),
    (
        envmon("7", "1.3.6.1.4.1.9.9.13.1.3.1", "Inlet", 2),
        "ciscoEnvMonTempStatusChangeNotif",
        "ciscoEnvMonTemperatureStatusDescr Inlet",
        None,
    ),
    (
        v2c(
            "1.3.6.1.4.1.9.9.13.3.0.7", [("1.3.6.1.4.1.9.9.13.1.3.1.2.4", "Inlet"), ("1.3.6.1.4.1.9.9.13.1.3.1.6.4", 2)]
        ),
        "ciscoEnvMonTempStatusChangeNotif",
        "ciscoEnvMonTemperatureState warning",
        ("temperature", "raise", "sensor 4"),
    ),
    (
        cbgp2("6", CBGP2_V4),
        "cbgpPeer2BackwardTransNotification",
        "cbgpPeer2State idle",
        ("bgp_neighbor", "raise", "198.51.100.7"),
    ),
    (
        cbgp2("6", CBGP2_V6),
        "cbgpPeer2BackwardTransNotification",
        "cbgpPeer2State idle",
        ("bgp_neighbor", "raise", "2001:db8::7"),
    ),
    (
        cbgp2("5", CBGP2_V4, 6),
        "cbgpPeer2EstablishedNotification",
        "established",
        ("bgp_neighbor", "clear", "198.51.100.7"),
    ),
    (cbgp_fsm(1, 6), "cbgpFsmStateChange", "cbgpPeerPrevState established", ("bgp_neighbor", "raise", "192.0.2.30")),
    (cbgp_fsm(6, 5), "cbgpFsmStateChange", "bgpPeerState established", ("bgp_neighbor", "clear", "192.0.2.30")),
    (cbgp_fsm(3, 2), "cbgpFsmStateChange", "bgpPeerState active", None),
    (
        v2c("1.3.6.1.4.1.9.9.500.0.0.6", [("1.3.6.1.4.1.9.9.500.1.2.1.1.1.1003", 3)]),
        "cswStackMemberRemoved",
        "cswSwitchNumCurrent 3",
        ("module", "raise", "switch 3"),
    ),
    (
        v2c("1.3.6.1.4.1.9.9.500.0.0.5", [("1.3.6.1.4.1.9.9.500.1.2.1.1.1.1003", 3)]),
        "cswStackNewMember",
        "cswSwitchNumCurrent 3",
        ("module", "clear", "switch 3"),
    ),
    (
        v2c("1.3.6.1.4.1.9.9.176.2.0.1", [("1.3.6.1.4.1.9.9.176.1.1.8.0", 6)]),
        "ciscoRFSwactNotif",
        "cRFStatusLastSwactReasonCode activeUnitFailed",
        ("ha_switchover", "raise", ""),
    ),
    (
        v2c(
            "1.3.6.1.4.1.9.9.41.2.0.1",
            [
                ("1.3.6.1.4.1.9.9.41.1.2.3.1.2.9", "SYS"),
                ("1.3.6.1.4.1.9.9.41.1.2.3.1.3.9", 6),
                ("1.3.6.1.4.1.9.9.41.1.2.3.1.4.9", "CONFIG_I"),
                ("1.3.6.1.4.1.9.9.41.1.2.3.1.5.9", "Configured from console by ops"),
            ],
        ),
        "clogMessageGenerated",
        "clogHistSeverity notice, clogHistMsgName CONFIG_I",
        None,
    ),
    # Juniper (a v1 trap of a notification under jnxChassisTraps: enterprise.0.specific)
    (
        v1("1.3.6.1.4.1.2636.4.1", 1, JNX_PSU),
        "jnxPowerSupplyFailure",
        "jnxContentsDescr PEM 0, jnxOperatingState down",
        ("power_supply", "raise", "PEM 0"),
    ),
    (
        v2c("1.3.6.1.4.1.2636.4.2.1", JNX_PSU[:2]),
        "jnxPowerSupplyOK",
        "jnxContentsDescr PEM 0",
        ("power_supply", "clear", "PEM 0"),
    ),
    (
        v2c("1.3.6.1.4.1.2636.4.1.24", JNX_PSU[:2]),
        "jnxPowerSupplyInputFailure",
        "PEM 0",
        ("power_supply", "raise", "PEM 0 input"),
    ),
    (v2c("1.3.6.1.4.1.2636.4.1.2", JNX_PSU[:2]), "jnxFanFailure", "PEM 0", ("fan", "raise", "PEM 0")),
    (v2c("1.3.6.1.4.1.2636.4.1.3", JNX_PSU[:2]), "jnxOverTemperature", "PEM 0", ("temperature", "raise", "PEM 0")),
    (
        jnx_fru("1.3.6.1.4.1.2636.4.1.10", 3, 2),
        "jnxFruOffline",
        "jnxFruType flexiblePicConcentrator",
        ("module", "raise", "FRU 7.1.0.0"),
    ),
    (jnx_fru("1.3.6.1.4.1.2636.4.1.10", 3, 7), "jnxFruOffline", "jnxFruOfflineReason cliCommand", None),
    (jnx_fru("1.3.6.1.4.1.2636.4.1.10", 13, 2), "jnxFruOffline", "jnxFruType fan", None),
    (
        jnx_fru("1.3.6.1.4.1.2636.4.1.11", 3),
        "jnxFruOnline",
        "jnxFruName FPC: MPC7E @ 0/*/*",
        ("module", "clear", "FRU 7.1.0.0"),
    ),
    (
        v2c(
            "1.3.6.1.4.1.2636.5.1.1.1.0.2",
            [
                ("1.3.6.1.4.1.2636.5.1.1.2.1.1.1.11.0.1.4.198.51.100.9", Raw(bytes([198, 51, 100, 9]))),
                ("1.3.6.1.4.1.2636.5.1.1.2.1.1.1.2.0.1.4.198.51.100.9", 1),
            ],
        ),
        "jnxBgpM2BackwardTransition",
        "jnxBgpM2PeerState idle",
        ("bgp_neighbor", "raise", "198.51.100.9"),
    ),
    (
        v2c("1.3.6.1.4.1.2636.4.14.0.4", [("1.3.6.1.4.1.2636.3.40.1.4.1.1.1.2.1", "VC0000000001")]),
        "jnxVccpMemberDown",
        "VC0000000001",
        ("module", "raise", "member 1"),
    ),
    (
        v2c("1.3.6.1.4.1.2636.3.39.1.14.1.0.1", [("1.3.6.1.4.1.2636.3.39.1.14.1.1.1.0", "1")]),
        "jnxJsChassisClusterSwitchover",
        "jnxJsChClusterSwitchoverInfoRedundancyGroup 1",
        ("ha_switchover", "raise", "redundancy group 1"),
    ),
    (v2c("1.3.6.1.4.1.2636.4.1.30"), "jnxDyingGasp", "power failure", ("device_restart", "raise", "")),
    # Arista
    (
        v2c("1.3.6.1.4.1.30065.4.1.0.2", [("1.3.6.1.4.1.30065.4.1.1.2.1.13.1.1.4.192.0.2.9", 1)]),
        "aristaBgp4V2BackwardTransitionNotification",
        "aristaBgp4V2PeerState idle",
        ("bgp_neighbor", "raise", "192.0.2.9"),
    ),
    # Fortinet
    (
        v2c("1.3.6.1.4.1.12356.100.1.3.0.108", [FORTI_SERIAL, FORTI_NAME]),
        "fnTrapFanFailure",
        "fnSysSerial FGT60FTK0000TEST, sysName fw-b",
        ("fan", "raise", ""),
    ),
    (
        v2c("1.3.6.1.4.1.12356.100.1.3.0.104", [FORTI_SERIAL, FORTI_NAME]),
        "fnTrapTempHigh",
        "fw-b",
        ("temperature", "raise", ""),
    ),
    (
        v2c("1.3.6.1.4.1.12356.100.1.3.0.106", [FORTI_SERIAL, ("1.3.6.1.4.1.12356.100.1.3.1.1.0", "PSU 2 failure")]),
        "fnTrapPowerSupply",
        "fnGenTrapMsg PSU 2 failure",
        None,
    ),
    (
        v2c("1.3.6.1.4.1.12356.101.2.0.401", [FORTI_SERIAL, FORTI_NAME]),
        "fgTrapHaSwitch",
        "fnSysSerial",
        ("ha_switchover", "raise", ""),
    ),
    (
        v2c("1.3.6.1.4.1.12356.101.2.0.404", [FORTI_SERIAL]),
        "fgTrapHaMemberDown",
        "FGT60FTK0000TEST",
        ("ha_switchover", "raise", "member FGT60FTK0000TEST"),
    ),
    (
        v2c("1.3.6.1.4.1.12356.101.2.0.405", [FORTI_SERIAL]),
        "fgTrapHaMemberUp",
        "FGT60FTK0000TEST",
        ("ha_switchover", "clear", "member FGT60FTK0000TEST"),
    ),
    # Palo Alto
    (
        pan(913, "PS2", "Power Supply #2 failed"),
        "panHWPsFailureTrap",
        "panSystemSeverity critical, panSystemDescription Power Supply #2 failed",
        ("power_supply", "raise", "PS2"),
    ),
    (pan(911, "PS2", "Power Supply #2 inserted"), "panHWPsInsertedTrap", "inserted", ("power_supply", "clear", "PS2")),
    (
        pan(1532, "", "BGP peer session left established: virtual router default, peer IP: 203.0.113.5"),
        "panROUTINGRoutedBGPPeerLeftEstablishedTrap",
        "peer IP: 203.0.113.5",
        ("bgp_neighbor", "raise", "203.0.113.5"),
    ),
    (
        pan(801, "", "HA Group 1: Moved from state Passive to state Active"),
        "panHAStateChangeTrap",
        "state Active",
        ("ha_switchover", "raise", ""),
    ),
    # HPE Aruba AOS-CX
    (
        vsf2("communication_failure"),
        "arubaWiredVsfv2MemberStatusChange",
        "arubaWiredVsfv2MemberStatus communication_failure",
        ("module", "raise", "member 2"),
    ),
    (vsf2("ready"), "arubaWiredVsfv2MemberStatusChange", "ready", ("module", "clear", "member 2")),
    (vsf2("booting"), "arubaWiredVsfv2MemberStatusChange", "booting", None),
    (
        v2c(
            f"{AOSCX}.11.2.0.1",
            [
                (f"{AOSCX}.11.2.1.1.1.1.2", 1),
                (f"{AOSCX}.11.2.1.1.2.1.2", 2),
                (f"{AOSCX}.11.2.1.1.4.1.2", "fault_input"),
            ],
        ),
        "arubaWiredPSUStateNotification",
        "arubaWiredPSUState fault_input",
        None,
    ),
    (v2c(f"{AOSCX}.7.3.1.4"), "keepAliveDown", "VSX keepalive failed", ("ha_switchover", "raise", "VSX keepalive")),
    (v2c(f"{AOSCX}.7.3.1.3"), "keepAliveUp", "VSX keepalive established", ("ha_switchover", "clear", "VSX keepalive")),
    # HPE Aruba AOS-Switch
    (
        hp_psu(4),
        "hpicfPowerSupplyStatusTrap",
        "hpicfPowerSupplySlotNum 2, hpicfPowerSupplyStatus faulted",
        ("power_supply", "raise", "supply 2"),
    ),
    (hp_psu(1), "hpicfPowerSupplyStatusTrap", "hpicfPowerSupplyStatus ok", ("power_supply", "clear", "supply 2")),
    # Netgear
    (
        boxs(1, "1.3.6.1.4.1.4526.10.43.1.6.1.1.1.3", 4),
        "boxsFanStateChange",
        "boxsItemStateChangeEvent failure",
        ("fan", "raise", "fan 1.3"),
    ),
    (
        boxs(1, "1.3.6.1.4.1.4526.10.43.1.6.1.1.1.3", 3),
        "boxsFanStateChange",
        "becomeoperational",
        ("fan", "clear", "fan 1.3"),
    ),
    (
        boxs(2, "1.3.6.1.4.1.4526.10.43.1.7.1.1.1.1", 5),
        "boxsPowSupplyStateChange",
        "losepower",
        ("power_supply", "raise", "supply 1.1"),
    ),
    (v2c("1.3.6.1.4.1.4526.10.1.0.9"), "fanFailureTrap", "Fan failed", ("fan", "raise", "")),
]


@pytest.mark.parametrize(("data", "name", "text", "expected"), SAMPLES)
def test_each_vendor_trap_is_named_and_classified(data, name, text, expected):
    trap = named(data)
    assert trap.name == name
    assert text in trap.message
    assert trap.message.startswith(f"{name}: ")
    assert effect(data) == expected


def test_the_stored_message_names_every_varbind_but_the_header():
    trap = named(LINK_DOWN)
    assert trap.message == "linkDown: ifIndex 12, ifDescr GigabitEthernet1/0/12, ifAdminStatus up, ifOperStatus down"
    assert trap.raw_tag == "linkDown" and trap.definition.mib == "IF-MIB"
    assert (trap.index("ifOperStatus"), trap.number("ifOperStatus"), trap.label("ifOperStatus")) == ("12", 2, "down")
    assert trap.get("sysName") is None and trap.label("sysName") == "" and trap.number("sysName") is None


def test_an_unknown_trap_is_stored_with_its_oid_and_varbinds():
    data = v2c("1.3.6.1.4.1.99999.0.1", [("1.3.6.1.4.1.99999.1.1.0", "disk full"), ("1.3.6.1.4.1.99999.1.2.0", 7)])
    trap = named(data)
    assert trap.definition is None and trap.name == "" and trap.raw_tag == "1.3.6.1.4.1.99999.0.1"
    assert trap.message == (
        "SNMP trap 1.3.6.1.4.1.99999.0.1: 1.3.6.1.4.1.99999.1.1.0 = disk full, 1.3.6.1.4.1.99999.1.2.0 = 7"
    )
    assert tr.event_fields(trap) == ("info", "1.3.6.1.4.1.99999.0.1", trap.message)
    assert tr.effects(trap) == [] and tr.repoll_delay(trap) is None
    # A known object in an unknown trap is still named.
    assert "ifDescr Gi0/1" in named(v2c("1.3.6.1.4.1.99999.0.2", [(f"{IF}.2.3", "Gi0/1")])).message
    empty = name_trap({"trap_oid": "", "varbinds": [("bad",), None]})
    assert empty.message == "SNMP trap (no trap OID)"


def test_values_are_shown_as_text():
    trap = named(
        v2c(
            "1.3.6.1.4.1.99999.0.3",
            [("1.3.6.1.4.1.99999.1.0", Raw(b"\xc0\x00\x02\x01")), ("1.3.6.1.4.1.99999.2.0", "x" * 300)],
        )
    )
    assert "1.3.6.1.4.1.99999.1.0 = 0xc0000201" in trap.message
    assert "x" * 197 + "..." in trap.message and "x" * 198 not in trap.message


def test_the_stored_severity_follows_the_rule():
    assert tr.event_fields(named(LINK_DOWN))[0] == "warning"
    assert tr.event_fields(named(LINK_UP))[0] == "info"
    assert tr.event_fields(named(cefc_module(7)))[0] == "critical"
    assert tr.event_fields(named(cefc_module(2)))[0] == "info"
    assert tr.event_fields(named(v2c("1.3.6.1.2.1.17.0.1")))[0] == "info"  # newRoot: the registry's


def test_the_repoll_delay():
    assert tr.repoll_delay(named(LINK_DOWN)) == sr.REPOLL_DELAY_SECONDS
    assert tr.repoll_delay(named(cefc_module(2))) == sr.REPOLL_DELAY_SECONDS
    assert tr.repoll_delay(named(v2c("1.3.6.1.4.1.2636.4.1.30"))) == sr.RELOAD_REPOLL_DELAY_SECONDS
    assert tr.repoll_delay(named(v2c("1.3.6.1.6.3.1.1.5.5"))) is None  # an auth failure is no state change
    assert tr.repoll_delay(named(LINK_SHUT)) is None


@pytest.mark.parametrize(
    ("data", "change"),
    [
        (
            v2c(
                "1.3.6.1.4.1.9.9.43.2.0.1",
                [
                    ("1.3.6.1.4.1.9.9.43.1.1.6.1.3.5", 1),
                    ("1.3.6.1.4.1.9.9.43.1.1.6.1.4.5", 2),
                    ("1.3.6.1.4.1.9.9.43.1.1.6.1.5.5", 3),
                ],
            ),
            True,
        ),
        (v2c("1.3.6.1.4.1.9.9.43.2.0.1", [("1.3.6.1.4.1.9.9.43.1.1.6.1.5.5", 4)]), False),  # a save to startup
        (v2c("1.3.6.1.4.1.9.9.43.2.0.2"), True),
        (v2c("1.3.6.1.4.1.2636.4.5.0.1", [("1.3.6.1.4.1.2636.3.18.1.7.1.5.3", "ops")]), True),
        (v2c("1.3.6.1.4.1.12356.101.6.0.1003", [FORTI_SERIAL]), True),
        (v2c(f"{AOSCX}.20.0.1", [(f"{AOSCX}.20.1.1.2.1", 2)]), True),
        (pan_config("commit", "Succeeded"), True),
        (pan_config("commit", "Submitted"), False),
        (pan_config("set", "Succeeded"), False),
        (LINK_DOWN, False),
    ],
)
def test_configuration_change_traps(data, change):
    assert tr.is_config_change(named(data)) is change


def test_the_registry_is_consistent():
    severities = set(sr.SEVERITIES)
    oid = re.compile(r"^1(\.\d+)+$")
    names = {t.name for t in snmp_traps.TRAPS_BY_OID.values()}
    count = sum(len(table.TRAPS) for _family, table in snmp_traps.TABLES)
    assert len(snmp_traps.TRAPS_BY_OID) == count  # no OID named twice
    for definition in snmp_traps.TRAPS_BY_OID.values():
        assert oid.match(definition.oid) and definition.severity in severities and definition.meaning
    for name, obj in snmp_traps.OBJECTS.items():
        assert oid.match(obj.oid), name
    # Every trap a rule or trigger names is in the registry (no typo).
    for rule in tr.TRAP_RULES:
        assert rule.severity in severities and rule.families
        assert set(rule.raise_on) <= names and set(rule.clear_on) <= names, rule.key
    assert set(tr.CONFIG_CHANGE) <= names
    # The APC PowerNet-MIB traps stay with their own handler.
    assert not any(o.startswith("1.3.6.1.4.1.318.") for o in snmp_traps.TRAPS_BY_OID)
    assert snmp_traps.lookup("1.3.6.1.4.1.2636.4.1.0.1").name == "jnxPowerSupplyFailure"
    assert snmp_traps.lookup("1.3.6.1.4.1.2636.4.1.0.999") is None


def test_the_peer_address_of_a_bgp_index():
    assert tr._address_from_index("203.0.113.2") == "203.0.113.2"
    assert tr._address_from_index(CBGP2_V6) == "2001:db8::7"
    assert tr._address_from_index("abc") == "abc"
    assert tr._address(b"\x01\x02") == "0102"
    assert tr._peer_value("x")(named(LINK_DOWN)) == ""
    bad_hex = name_trap(
        {"trap_oid": "1.3.6.1.4.1.2636.5.1.1.1.0.2", "varbinds": [("1.3.6.1.4.1.2636.5.1.1.2.1.1.1.11.1", "0xzz")]}
    )
    assert tr._JNX_BGP_PEER(bad_hex) == "0xzz"


# ── The inform ───────────────────────────────────────────────────────────────


def test_an_inform_is_decoded_and_answered():
    data = v2c(
        "1.3.6.1.6.3.1.1.5.3", [(f"{IF}.1.12", 12), (f"{IF}.7.12", 1), (f"{IF}.8.12", 2)], inform=True, request_id=31337
    )
    trap = decode_snmp_trap(data)
    assert (trap["pdu"], trap["request_id"], trap["version"], trap["trap_oid"]) == (
        "inform",
        31337,
        "v2c",
        "1.3.6.1.6.3.1.1.5.3",
    )
    response = snmp_inform_response(data)
    message, _rest = decoder.decode(response, asn1Spec=P2.Message())
    pdu = P2.apiMessage.get_pdu(message)
    assert pdu.isSameTypeWith(P2.ResponsePDU())
    assert int(P2.apiPDU.get_request_id(pdu)) == 31337 and int(P2.apiPDU.get_error_status(pdu)) == 0
    assert str(P2.apiMessage.get_community(message)) == COMMUNITY
    assert [str(oid) for oid, _v in P2.apiPDU.get_varbinds(pdu)] == [
        SYS_UPTIME,
        SNMP_TRAP_OID,
        f"{IF}.1.12",
        f"{IF}.7.12",
        f"{IF}.8.12",
    ]
    # A trap gets no answer; neither does a v1 trap, garbage or an SNMPv3 header.
    assert decode_snmp_trap(LINK_DOWN)["pdu"] == "trap"
    assert decode_snmp_trap(v1("1.3.6.1.4.1.9", 1))["request_id"] == 0
    for other in (LINK_DOWN, v1("1.3.6.1.4.1.9", 1), b"\x30\x03junk", bytes.fromhex("3006020103040100")):
        assert snmp_inform_response(other) is None


class _Transport:
    def __init__(self):
        self.sent: list[tuple[bytes, tuple]] = []

    def sendto(self, data: bytes, addr: tuple) -> None:
        self.sent.append((data, addr))


class _BusyWriter:
    def done(self) -> bool:
        return False


@pytest.fixture
def receiver(monkeypatch):
    """A trap receiver protocol with a recording transport, its queue
    drained by nobody, every source admitted by the listener guard."""
    monkeypatch.setattr(me, "_trap_event_writer_task", _BusyWriter())
    monkeypatch.setitem(ls.CONFIG, "policy", "any")
    ls.guard("trap").reset()
    me._trap_event_buffer.clear()
    protocol = me._TrapSyslogProtocol("trap")
    transport = _Transport()
    protocol.connection_made(transport)
    yield protocol, transport
    me._trap_event_buffer.clear()
    ls.guard("trap").reset()


def test_the_receiver_answers_an_inform_and_queues_it_named(receiver):
    protocol, transport = receiver
    data = v2c("1.3.6.1.6.3.1.1.5.3", [(f"{IF}.1.12", 12), (f"{IF}.7.12", 1), (f"{IF}.8.12", 2)], inform=True)
    protocol.datagram_received(data, ("192.0.2.40", 40162))
    assert len(transport.sent) == 1 and transport.sent[0][1] == ("192.0.2.40", 40162)
    ((source, event_type, _fac, severity, oid, message, raw, trap, _transport),) = me._trap_event_buffer
    assert (source, event_type, severity, oid) == ("192.0.2.40", "trap", "warning", "1.3.6.1.6.3.1.1.5.3")
    assert message == "linkDown: ifIndex 12, ifAdminStatus up, ifOperStatus down"
    assert raw == data.hex() and trap["pdu"] == "inform"
    # A plain trap gets no answer.
    protocol.datagram_received(LINK_DOWN, ("192.0.2.40", 40162))
    assert len(transport.sent) == 1


def test_an_inform_the_listener_guard_refuses_gets_no_answer(receiver, monkeypatch):
    protocol, transport = receiver
    monkeypatch.setitem(ls.CONFIG, "policy", "inventory")
    monkeypatch.setattr(ls, "_inventory_loaded_at", float("inf"))
    protocol.datagram_received(v2c("1.3.6.1.6.3.1.1.5.1", inform=True), ("203.0.113.66", 40162))
    assert transport.sent == [] and me._trap_event_buffer == []


def test_an_undecodable_trap_is_queued_as_before(receiver):
    protocol, _transport = receiver
    protocol.datagram_received(b"\x30\x03junk", ("192.0.2.41", 40162))
    ((_s, _t, _f, severity, _oid, message, _raw, trap, _tr),) = me._trap_event_buffer
    assert (severity, trap) == ("info", None) and message == "SNMP trap from 192.0.2.41 (6 bytes)"


# ── The engine ───────────────────────────────────────────────────────────────


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def engine(monkeypatch):
    """Monitoring on, every switch on, the group default community the
    traps', a fake clock, and re-polls and configuration changes recorded."""
    sr.reset_state()
    clock = _Clock()
    monkeypatch.setattr(sr, "_clock", clock)
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", True)
    monkeypatch.setitem(state.SNMP_DISCOVERY_CONFIG, "community", COMMUNITY)
    monkeypatch.setattr(
        state,
        "EVENT_RECEIVER_CONFIG",
        {"trap_alerts": True, "config_change_trigger": True, "repoll_trigger": True},
    )
    repolls: list[tuple[int, float, float]] = []
    changes: list[int] = []

    def fake_repoll(host_id, delay, *, min_interval=0.0):
        repolls.append((host_id, delay, min_interval))
        return True

    monkeypatch.setattr(tr, "schedule_repoll", fake_repoll)
    monkeypatch.setattr(sr, "schedule_repoll", lambda *_a, **_k: False)
    monkeypatch.setattr(sr, "note_config_change", changes.append)
    monkeypatch.setattr(me, "_trap_event_writer_task", _BusyWriter())
    me._trap_event_buffer.clear()
    me._host_ip_cache.clear()
    ls.guard("trap").reset()
    yield clock, repolls, changes
    me._trap_event_buffer.clear()
    ls.guard("trap").reset()
    sr.reset_state()


async def _host(name: str, ip: str, device_type: str = "cisco_ios") -> int:
    await db.init_db()
    group_id = await db.create_group(f"grp-{name}")
    return await db.add_host(group_id, name, ip, device_type)


async def _open(host_id: int) -> dict[str, dict]:
    return {a["dedup_key"]: a for a in await db.get_monitoring_alerts(host_id, acknowledged=False)}


async def _receive(source: str, *datagrams: bytes) -> None:
    """What the receiver does with each datagram, then one writer flush."""
    protocol = me._TrapSyslogProtocol("trap")
    for data in datagrams:
        protocol._handle_trap(data, source)
    await me._flush_trap_syslog_batch(me._take_trap_event_batch())


async def test_a_link_down_trap_raises_and_its_link_up_resolves(engine):
    _clock, repolls, _changes = engine
    host_id = await _host("trap-sw1", "192.0.2.50")
    await _receive("192.0.2.50", LINK_DOWN)
    key = f"trap:link_down:{host_id}:ifIndex 12"
    alert = (await _open(host_id))[key]
    assert (alert["alert_type"], alert["metric"], alert["severity"]) == ("trap", "trap_link_down", "warning")
    assert alert["message"] == (
        "Interface down on ifIndex 12: linkDown: ifIndex 12, ifDescr GigabitEthernet1/0/12, ifAdminStatus up, "
        "ifOperStatus down"
    )
    assert repolls == [(host_id, sr.REPOLL_DELAY_SECONDS, sr.REPOLL_MIN_INTERVAL_SECONDS)]
    # The stored event reads like the trap.
    stored = [e for e in await db.get_trap_syslog_events("trap", host_id) if e["source_ip"] == "192.0.2.50"]
    assert stored[0]["message"].startswith("linkDown: ifIndex 12") and stored[0]["oid"] == "1.3.6.1.6.3.1.1.5.3"
    # A repeat bumps the same alert; the link up resolves it.
    _clock.t += 60
    await _receive("192.0.2.50", LINK_DOWN)
    assert (await _open(host_id))[key]["occurrence_count"] == 2
    await _receive("192.0.2.50", LINK_UP)
    assert await _open(host_id) == {}


async def test_vendor_traps_raise_their_own_alert_family(engine):
    host_id = await _host("trap-r1", "192.0.2.51", "juniper_junos")
    await _receive(
        "192.0.2.51",
        v1("1.3.6.1.4.1.2636.4.1", 1, JNX_PSU),
        jnx_fru("1.3.6.1.4.1.2636.4.1.10", 3, 2),
        ospf_nbr(1),
        cbgp2("6", CBGP2_V6),
    )
    opened = await _open(host_id)
    assert {(a["metric"], a["severity"]) for a in opened.values()} == {
        ("trap_power_supply", "critical"),
        ("trap_module", "critical"),
        ("trap_ospf_neighbor", "critical"),
        ("trap_bgp_neighbor", "critical"),
    }
    assert f"trap:bgp_neighbor:{host_id}:2001:db8::7" in opened
    assert all(a["alert_type"] == "trap" for a in opened.values())


async def test_a_trap_clear_never_resolves_a_syslog_alert(engine):
    host_id = await _host("trap-sw2", "192.0.2.52")
    await sr.process_syslog_batch([(host_id, "%BGP-5-ADJCHANGE: neighbor 203.0.113.2 Down BGP Notification sent")])
    await _receive("192.0.2.52", bgp4("1.3.6.1.2.1.15.0.2", 1))
    assert {a["alert_type"] for a in (await _open(host_id)).values()} == {"syslog", "trap"}
    await _receive("192.0.2.52", bgp4("1.3.6.1.2.1.15.0.1", 6))
    assert [a["alert_type"] for a in (await _open(host_id)).values()] == ["syslog"]


async def test_snmp_authentication_failures_raise_one_alert_after_five(engine):
    clock, repolls, _changes = engine
    host_id = await _host("trap-sw3", "192.0.2.53")
    auth = v2c("1.3.6.1.6.3.1.1.5.5")
    for _ in range(4):
        await _receive("192.0.2.53", auth)
        clock.t += 10
    assert await _open(host_id) == {}
    # A burst within 5 seconds counts once.
    await _receive("192.0.2.53", auth, auth, auth)
    assert list(await _open(host_id)) == [f"trap:snmp_auth_failure:{host_id}:"]
    for _ in range(3):
        clock.t += 10
        await _receive("192.0.2.53", auth)
    assert len(await _open(host_id)) == 1 and repolls == []


async def test_a_config_change_trap_starts_the_backup_trigger(engine):
    _clock, repolls, changes = engine
    host_id = await _host("trap-r2", "192.0.2.54", "juniper_junos")
    await _receive("192.0.2.54", v2c("1.3.6.1.4.1.2636.4.5.0.1"), pan_config("commit", "Submitted"))
    assert changes == [host_id] and repolls == [] and await _open(host_id) == {}


async def test_the_intake_rules(engine):
    _clock, repolls, changes = engine
    host_id = await _host("trap-sw4", "192.0.2.55")
    # The wrong community: dropped (counted), nothing raised.
    wrong = v2c("1.3.6.1.6.3.1.1.5.3", [(f"{IF}.1.12", 12), (f"{IF}.7.12", 1)], community="guessed")
    await _receive("192.0.2.55", wrong)
    assert await _open(host_id) == {} and ls.guard("trap").stats()["dropped_community"] == 1
    assert [e for e in await db.get_trap_syslog_events("trap") if e["source_ip"] == "192.0.2.55"] == []
    # A source that is no inventory host (an extra network, the any policy):
    # stored, never acted on.
    await _receive("203.0.113.55", LINK_DOWN, v2c("1.3.6.1.4.1.2636.4.5.0.1"))
    assert len([e for e in await db.get_trap_syslog_events("trap") if e["source_ip"] == "203.0.113.55"]) == 2
    assert repolls == [] and changes == []
    # Monitoring off: alerts and re-polls stop, the configuration trigger does not.
    state.MONITORING_CONFIG["enabled"] = False
    await _receive("192.0.2.55", LINK_DOWN, v2c("1.3.6.1.4.1.9.9.43.2.0.2"))
    assert await _open(host_id) == {} and repolls == [] and changes == [host_id]


async def test_the_switches(engine, monkeypatch):
    _clock, repolls, changes = engine
    host_id = await _host("trap-sw5", "192.0.2.56")
    monkeypatch.setattr(state, "EVENT_RECEIVER_CONFIG", {"trap_alerts": False})
    await _receive("192.0.2.56", LINK_DOWN, v2c("1.3.6.1.4.1.9.9.43.2.0.2"))
    assert await _open(host_id) == {} and len(repolls) == 1 and changes == [host_id]
    monkeypatch.setattr(
        state, "EVENT_RECEIVER_CONFIG", {"trap_alerts": False, "repoll_trigger": False, "config_change_trigger": False}
    )
    assert await tr.process_trap_batch([(host_id, named(LINK_DOWN))]) == {
        "raised": 0,
        "resolved": 0,
        "repolls": 0,
        "config_changes": 0,
    }


async def test_a_disabled_or_suppressed_rule_raises_nothing(engine):
    host_id = await _host("trap-sw6", "192.0.2.57")
    await db.set_syslog_builtin_override("trap_link_down", False, "warning")
    sr.invalidate_rules_cache()
    await _receive("192.0.2.57", LINK_DOWN)
    assert await _open(host_id) == {}
    # The override of a trap rule does not touch the syslog rule of the same key.
    assert next(r for r in await sr.get_rules() if r.key == "fan").enabled
    await db.create_alert_suppression("maint", "2099-01-01 00:00:00", host_id=host_id, metric="trap_fan")
    await _receive("192.0.2.57", v2c("1.3.6.1.4.1.9.9.13.3.0.8", [(f"{ENVMON_FAN}.3.1", 3)]))
    assert await _open(host_id) == {}
    # A severity override applies to the alert.
    await db.set_syslog_builtin_override("trap_module", True, "warning")
    sr.invalidate_rules_cache()
    await _receive("192.0.2.57", cefc_module(7))
    assert [a["severity"] for a in (await _open(host_id)).values()] == ["warning"]


async def test_trap_alerts_resolve_after_their_time(engine):
    host_id = await _host("trap-sw7", "192.0.2.58")
    await _receive("192.0.2.58", v2c("1.3.6.1.6.3.1.1.5.1"), ospf_nbr(1))
    assert len(await _open(host_id)) == 2
    assert await tr.resolve_expired_alerts() == 0
    conn = await db.get_db()
    try:
        await conn.execute(
            "UPDATE monitoring_alerts SET last_seen_at = datetime('now', '-61 minutes') WHERE host_id = ?", (host_id,)
        )
        await conn.commit()
    finally:
        await conn.close()
    # The restart resolves; the OSPF neighbor waits for its Full trap.
    assert await tr.resolve_expired_alerts() == 1
    assert [a["metric"] for a in (await _open(host_id)).values()] == ["trap_ospf_neighbor"]


async def test_a_rule_failure_is_logged_not_raised(engine, monkeypatch, caplog):
    await _host("trap-sw8", "192.0.2.59")

    async def broken(_rows):
        raise RuntimeError("rules failed")

    monkeypatch.setattr(tr, "process_trap_batch", broken)
    await _receive("192.0.2.59", LINK_DOWN)
    assert "trap rule evaluation failed for 1 traps" in caplog.text
    assert len([e for e in await db.get_trap_syslog_events("trap") if e["source_ip"] == "192.0.2.59"]) == 1


async def test_a_decoded_trap_from_another_decoder_goes_through_unchanged(engine):
    """The interface a later decoder (SNMPv3) uses inside the batch writer:
    a dict of decode_snmp_trap's shape, named and stored by
    trap_event_fields, believed by the screening, acted on by the rules."""
    host_id = await _host("trap-sw9", "192.0.2.60")
    trap = {
        "version": "v2c",
        "community": COMMUNITY,
        "trap_oid": "1.3.6.1.4.1.9.9.117.2.0.1",
        "agent_address": "",
        "varbinds": [(f"{CEFC}.1.2.1.1.2.1001", "7")],
    }
    severity, oid, message = me.trap_event_fields(trap)
    assert (severity, oid, message) == (
        "critical",
        trap["trap_oid"],
        "cefcModuleStatusChange: cefcModuleOperStatus failed",
    )
    me._queue_trap_syslog_event("192.0.2.60", "trap", "", severity, oid, message, "", trap)
    await me._flush_trap_syslog_batch(me._take_trap_event_batch())
    assert list(await _open(host_id)) == [f"trap:module:{host_id}:entPhysicalIndex 1001"]


async def test_the_events_filter_returns_stored_traps():
    await db.init_db()
    await db.create_trap_syslog_events_batch(
        [
            ("198.51.100.70", None, "trap", "", "warning", "1.3.6.1.6.3.1.1.5.3", "linkDown: ifIndex 1", "", "udp"),
            ("198.51.100.70", None, "syslog", "", "info", "", "<14>hello", "", "udp"),
        ]
    )
    traps = [e for e in await db.get_trap_syslog_events("trap") if e["source_ip"] == "198.51.100.70"]
    assert [e["message"] for e in traps] == ["linkDown: ifIndex 1"]
    assert [e for e in await db.get_trap_syslog_events("snmp_trap") if e["source_ip"] == "198.51.100.70"] == []


# ── API ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    sr.reset_state()
    return admin_client(monkeypatch, request)


def test_the_trap_rules_api(admin):
    rules = admin.get(PREFIX).json()
    assert [r["key"] for r in rules] == [r.key for r in tr.TRAP_RULES]
    link = rules[0]
    assert (link["source"], link["metric"], link["builtin"], link["enabled"], link["severity"]) == (
        "trap",
        "trap_link_down",
        True,
        True,
        "warning",
    )
    assert link["tags"] == ["linkDown"] and link["clear_tags"] == ["linkUp"] and link["families"]
    # The syslog list is unchanged.
    assert all(r["source"] == "syslog" for r in admin.get("/api/monitoring/syslog-rules").json())

    patched = admin.patch(f"{PREFIX}/builtin/fan", json={"enabled": False, "severity": "critical"})
    assert patched.status_code == 200, patched.text
    assert (patched.json()["enabled"], patched.json()["severity"]) == (False, "critical")
    assert next(r for r in admin.get(PREFIX).json() if r["key"] == "fan")["enabled"] is False
    # The syslog fan rule keeps its own setting.
    assert next(r for r in admin.get("/api/monitoring/syslog-rules").json() if r["key"] == "fan")["enabled"] is True
    assert admin.patch(f"{PREFIX}/builtin/fan", json={"severity": "loud"}).status_code == 400
    assert admin.patch(f"{PREFIX}/builtin/nope", json={"enabled": False}).status_code == 404
    admin.patch(f"{PREFIX}/builtin/fan", json={"enabled": True, "severity": "warning"})

    reader = user_client(admin, "trap-reader", features=["monitoring"])
    assert reader.get(PREFIX).status_code == 200
    assert reader.patch(f"{PREFIX}/builtin/fan", json={"enabled": False}).status_code == 403
    outsider = user_client(admin, "trap-outsider", features=["inventory"])
    assert outsider.get(PREFIX).status_code == 403


def test_the_events_api_filters_on_the_stored_trap_type(admin):
    admin.raw.portal.call(
        db.create_trap_syslog_events_batch,
        [("198.51.100.71", None, "trap", "", "warning", "1.3.6.1.6.3.1.1.5.3", "linkDown: ifIndex 9", "", "udp")],
    )
    events = admin.get("/api/metrics/events", params={"event_type": "trap", "limit": 50}).json()
    found = [e for e in events if e["source_ip"] == "198.51.100.71"]
    assert [(e["event_type"], e["oid"], e["message"]) for e in found] == [
        ("trap", "1.3.6.1.6.3.1.1.5.3", "linkDown: ifIndex 9")
    ]
    syslog = admin.get("/api/metrics/events", params={"event_type": "syslog", "limit": 50}).json()
    assert not [e for e in syslog if e["source_ip"] == "198.51.100.71"]
