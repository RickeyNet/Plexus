"""Standard MIB traps every platform may send.

From the MIB texts: SNMPv2-MIB (RFC 3418), IF-MIB (RFC 2863), ENTITY-MIB (RFC 6933), ENTITY-STATE-MIB
(RFC 4268), BGP4-MIB (RFC 4273), OSPF-TRAP-MIB (RFC 4750), BRIDGE-MIB (RFC 4188),
VRRP-MIB (RFC 2787), VRRPV3-MIB (RFC 6527) and RMON-MIB (RFC 2819).
Generated from the MIBs (OIDs, object names, enumerations); the severity
and the one-line meaning are Plexus's. See docs/snmp-traps.md.
"""

from __future__ import annotations

from netcontrol.snmp_traps.model import TrapDef, TrapObject

OBJECTS: dict[str, TrapObject] = {
    "sysName": TrapObject("1.3.6.1.2.1.1.5"),
    "entStateAdmin": TrapObject(
        "1.3.6.1.2.1.131.1.1.1.2", {1: "unknown", 2: "locked", 3: "shuttingDown", 4: "unlocked"}
    ),
    "entStateAlarm": TrapObject("1.3.6.1.2.1.131.1.1.1.5"),
    "ospfRouterId": TrapObject("1.3.6.1.2.1.14.1.1"),
    "ospfRestartInterval": TrapObject("1.3.6.1.2.1.14.1.19"),
    "ospfRestartStatus": TrapObject(
        "1.3.6.1.2.1.14.1.21", {1: "notRestarting", 2: "plannedRestart", 3: "unplannedRestart"}
    ),
    "ospfRestartExitReason": TrapObject(
        "1.3.6.1.2.1.14.1.23", {1: "none", 2: "inProgress", 3: "completed", 4: "timedOut", 5: "topologyChanged"}
    ),
    "ospfNbrIpAddr": TrapObject("1.3.6.1.2.1.14.10.1.1"),
    "ospfNbrAddressLessIndex": TrapObject("1.3.6.1.2.1.14.10.1.2"),
    "ospfNbrRtrId": TrapObject("1.3.6.1.2.1.14.10.1.3"),
    "ospfNbrState": TrapObject(
        "1.3.6.1.2.1.14.10.1.6",
        {1: "down", 2: "attempt", 3: "init", 4: "twoWay", 5: "exchangeStart", 6: "exchange", 7: "loading", 8: "full"},
    ),
    "ospfVirtNbrArea": TrapObject("1.3.6.1.2.1.14.11.1.1"),
    "ospfVirtNbrRtrId": TrapObject("1.3.6.1.2.1.14.11.1.2"),
    "ospfVirtNbrState": TrapObject(
        "1.3.6.1.2.1.14.11.1.5",
        {1: "down", 2: "attempt", 3: "init", 4: "twoWay", 5: "exchangeStart", 6: "exchange", 7: "loading", 8: "full"},
    ),
    "ospfConfigErrorType": TrapObject(
        "1.3.6.1.2.1.14.16.1.2",
        {
            1: "badVersion",
            2: "areaMismatch",
            3: "unknownNbmaNbr",
            4: "unknownVirtualNbr",
            5: "authTypeMismatch",
            6: "authFailure",
            7: "netMaskMismatch",
            8: "helloIntervalMismatch",
            9: "deadIntervalMismatch",
            10: "optionMismatch",
            11: "mtuMismatch",
            12: "duplicateRouterId",
            13: "noError",
        },
    ),
    "ospfPacketType": TrapObject(
        "1.3.6.1.2.1.14.16.1.3", {1: "hello", 2: "dbDescript", 3: "lsReq", 4: "lsUpdate", 5: "lsAck", 6: "nullPacket"}
    ),
    "ospfPacketSrc": TrapObject("1.3.6.1.2.1.14.16.1.4"),
    "ospfIfIpAddress": TrapObject("1.3.6.1.2.1.14.7.1.1"),
    "ospfIfState": TrapObject(
        "1.3.6.1.2.1.14.7.1.12",
        {
            1: "down",
            2: "loopback",
            3: "waiting",
            4: "pointToPoint",
            5: "designatedRouter",
            6: "backupDesignatedRouter",
            7: "otherDesignatedRouter",
        },
    ),
    "ospfAddressLessIf": TrapObject("1.3.6.1.2.1.14.7.1.2"),
    "ospfVirtIfAreaId": TrapObject("1.3.6.1.2.1.14.9.1.1"),
    "ospfVirtIfNeighbor": TrapObject("1.3.6.1.2.1.14.9.1.2"),
    "ospfVirtIfState": TrapObject("1.3.6.1.2.1.14.9.1.7", {1: "down", 4: "pointToPoint"}),
    "bgpPeerLastError": TrapObject("1.3.6.1.2.1.15.3.1.14"),
    "bgpPeerState": TrapObject(
        "1.3.6.1.2.1.15.3.1.2",
        {1: "idle", 2: "connect", 3: "active", 4: "opensent", 5: "openconfirm", 6: "established"},
    ),
    "bgpPeerRemoteAddr": TrapObject("1.3.6.1.2.1.15.3.1.7"),
    "alarmIndex": TrapObject("1.3.6.1.2.1.16.3.1.1.1"),
    "alarmVariable": TrapObject("1.3.6.1.2.1.16.3.1.1.3"),
    "alarmSampleType": TrapObject("1.3.6.1.2.1.16.3.1.1.4", {1: "absoluteValue", 2: "deltaValue"}),
    "alarmValue": TrapObject("1.3.6.1.2.1.16.3.1.1.5"),
    "alarmRisingThreshold": TrapObject("1.3.6.1.2.1.16.3.1.1.7"),
    "alarmFallingThreshold": TrapObject("1.3.6.1.2.1.16.3.1.1.8"),
    "ifIndex": TrapObject("1.3.6.1.2.1.2.2.1.1"),
    "ifDescr": TrapObject("1.3.6.1.2.1.2.2.1.2"),
    "ifType": TrapObject("1.3.6.1.2.1.2.2.1.3"),
    "ifAdminStatus": TrapObject("1.3.6.1.2.1.2.2.1.7", {1: "up", 2: "down", 3: "testing"}),
    "ifOperStatus": TrapObject(
        "1.3.6.1.2.1.2.2.1.8",
        {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"},
    ),
    "vrrpv3OperationsMasterIpAddr": TrapObject("1.3.6.1.2.1.207.1.1.1.1.3"),
    "vrrpv3StatisticsNewMasterReason": TrapObject(
        "1.3.6.1.2.1.207.1.2.5.1.2", {0: "notMaster", 1: "priority", 2: "preempted", 3: "masterNoResponse"}
    ),
    "vrrpv3StatisticsProtoErrReason": TrapObject(
        "1.3.6.1.2.1.207.1.2.5.1.6",
        {0: "noError", 1: "ipTtlError", 2: "versionError", 3: "checksumError", 4: "vrIdError"},
    ),
    "ifName": TrapObject("1.3.6.1.2.1.31.1.1.1.1"),
    "ifAlias": TrapObject("1.3.6.1.2.1.31.1.1.1.18"),
    "entPhysicalDescr": TrapObject("1.3.6.1.2.1.47.1.1.1.1.2"),
    "entPhysicalName": TrapObject("1.3.6.1.2.1.47.1.1.1.1.7"),
    "vrrpOperMasterIpAddr": TrapObject("1.3.6.1.2.1.68.1.3.1.7"),
    "vrrpTrapPacketSrc": TrapObject("1.3.6.1.2.1.68.1.5"),
    "vrrpTrapAuthErrorType": TrapObject(
        "1.3.6.1.2.1.68.1.6", {1: "invalidAuthType", 2: "authTypeMismatch", 3: "authFailure"}
    ),
    "vrrpOperationsMasterIpAddr": TrapObject("1.3.6.1.2.1.68.1.7.1.7"),
    "vrrpNewMasterReason": TrapObject(
        "1.3.6.1.2.1.68.1.9", {0: "notmaster", 1: "priority", 2: "preempted", 3: "masterNoResponse"}
    ),
}

TRAPS: tuple[TrapDef, ...] = (
    TrapDef(
        "1.3.6.1.6.3.1.1.5.1", "coldStart", "SNMPv2-MIB", "warning", "Agent started: the device reloaded or powered on"
    ),
    TrapDef(
        "1.3.6.1.6.3.1.1.5.2",
        "warmStart",
        "SNMPv2-MIB",
        "warning",
        "Agent reinitialised itself with its configuration unchanged",
    ),
    TrapDef(
        "1.3.6.1.6.3.1.1.5.5",
        "authenticationFailure",
        "SNMPv2-MIB",
        "warning",
        "SNMP message refused: wrong community or credentials",
    ),
    TrapDef("1.3.6.1.6.3.1.1.5.3", "linkDown", "IF-MIB", "warning", "Interface went down"),
    TrapDef("1.3.6.1.6.3.1.1.5.4", "linkUp", "IF-MIB", "info", "Interface came up"),
    TrapDef(
        "1.3.6.1.2.1.47.2.0.1",
        "entConfigChange",
        "ENTITY-MIB",
        "info",
        "Physical entity table changed (a part was added or removed)",
    ),
    TrapDef(
        "1.3.6.1.2.1.131.0.2",
        "entStateOperDisabled",
        "ENTITY-STATE-MIB",
        "warning",
        "Physical entity operationally disabled",
    ),
    TrapDef(
        "1.3.6.1.2.1.131.0.1",
        "entStateOperEnabled",
        "ENTITY-STATE-MIB",
        "info",
        "Physical entity operationally enabled",
    ),
    TrapDef("1.3.6.1.2.1.15.0.1", "bgpEstablishedNotification", "BGP4-MIB", "info", "BGP session established"),
    TrapDef(
        "1.3.6.1.2.1.15.0.2",
        "bgpBackwardTransNotification",
        "BGP4-MIB",
        "critical",
        "BGP session left a higher state (session lost)",
    ),
    TrapDef("1.3.6.1.2.1.15.7.1", "bgpEstablished", "BGP4-MIB", "info", "BGP session established"),
    TrapDef(
        "1.3.6.1.2.1.15.7.2",
        "bgpBackwardTransition",
        "BGP4-MIB",
        "critical",
        "BGP session left a higher state (session lost)",
    ),
    TrapDef("1.3.6.1.2.1.14.16.2.2", "ospfNbrStateChange", "OSPF-TRAP-MIB", "warning", "OSPF neighbor state changed"),
    TrapDef(
        "1.3.6.1.2.1.14.16.2.3",
        "ospfVirtNbrStateChange",
        "OSPF-TRAP-MIB",
        "warning",
        "OSPF virtual neighbor state changed",
    ),
    TrapDef("1.3.6.1.2.1.14.16.2.16", "ospfIfStateChange", "OSPF-TRAP-MIB", "info", "OSPF interface state changed"),
    TrapDef(
        "1.3.6.1.2.1.14.16.2.1",
        "ospfVirtIfStateChange",
        "OSPF-TRAP-MIB",
        "info",
        "OSPF virtual interface state changed",
    ),
    TrapDef(
        "1.3.6.1.2.1.14.16.2.4",
        "ospfIfConfigError",
        "OSPF-TRAP-MIB",
        "warning",
        "OSPF packet with conflicting parameters received",
    ),
    TrapDef(
        "1.3.6.1.2.1.14.16.2.6", "ospfIfAuthFailure", "OSPF-TRAP-MIB", "warning", "OSPF packet failed authentication"
    ),
    TrapDef(
        "1.3.6.1.2.1.14.16.2.18",
        "ospfRestartStatusChange",
        "OSPF-TRAP-MIB",
        "info",
        "OSPF graceful restart state changed",
    ),
    TrapDef("1.3.6.1.2.1.17.0.1", "newRoot", "BRIDGE-MIB", "info", "This bridge became the new spanning tree root"),
    TrapDef("1.3.6.1.2.1.17.0.2", "topologyChange", "BRIDGE-MIB", "info", "Spanning tree topology change"),
    TrapDef("1.3.6.1.2.1.68.0.1", "vrrpTrapNewMaster", "VRRP-MIB", "warning", "VRRP router became master"),
    TrapDef("1.3.6.1.2.1.68.0.2", "vrrpTrapAuthFailure", "VRRP-MIB", "warning", "VRRP packet failed authentication"),
    TrapDef("1.3.6.1.2.1.207.0.1", "vrrpv3NewMaster", "VRRPV3-MIB", "warning", "VRRPv3 router became master"),
    TrapDef("1.3.6.1.2.1.207.0.2", "vrrpv3ProtoError", "VRRPV3-MIB", "warning", "VRRPv3 protocol error"),
    TrapDef("1.3.6.1.2.1.16.0.1", "risingAlarm", "RMON-MIB", "warning", "RMON alarm crossed its rising threshold"),
    TrapDef("1.3.6.1.2.1.16.0.2", "fallingAlarm", "RMON-MIB", "info", "RMON alarm crossed its falling threshold"),
)
