"""Palo Alto PAN-OS traps.

From the MIB texts: PAN-TRAPS (panCommonEventEventsV2 = 1.3.6.1.4.1.25461.2.1.3.2.0,
panCommonEventObjs = 1.3.6.1.4.1.25461.2.1.3.1, from PAN-COMMON-MIB and
PAN-GLOBAL-REG). PAN-TRAPS names one trap per system log event id (more than
600); the ones named here are the restart, authentication, configuration,
HA, hardware (slot, power supply, fan, disk), port and legacy routing-engine
BGP / OSPF events. Every other PAN-OS trap is stored under its OID; the
system log ones carry the same system log objects, so their varbinds are
named all the same.
Generated from the MIBs (OIDs, object names, enumerations); the severity
and the one-line meaning are Plexus's. See docs/snmp-traps.md.
"""

from __future__ import annotations

from netcontrol.snmp_traps.model import TrapDef, TrapObject

OBJECTS: dict[str, TrapObject] = {
    "panHostname": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.12"),
    "panConfigCmd": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.150"),
    "panConfigAdmin": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.151"),
    "panConfigClient": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.152"),
    "panConfigResult": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.153"),
    "panConfigPath": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.154"),
    "panReceiveTime": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.2"),
    "panSerial": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.3"),
    "panSystemEventId": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.300"),
    "panSystemObject": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.301"),
    "panSystemModule": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.302"),
    "panSystemSeverity": TrapObject(
        "1.3.6.1.4.1.25461.2.1.3.1.303",
        {0: "unused", 1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical"},
    ),
    "panSystemDescription": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.304"),
    "panEventType": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.4"),
    "panEventSubType": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.5"),
    "panHost": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.6"),
    "panVsys": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.7"),
    "panSeqno": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.8"),
    "panActionflags": TrapObject("1.3.6.1.4.1.25461.2.1.3.1.9"),
}

TRAPS: tuple[TrapDef, ...] = (
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.601", "panGeneralSystemStartTrap", "PAN-TRAPS", "warning", "System started"),
    TrapDef(
        "1.3.6.1.4.1.25461.2.1.3.2.0.602",
        "panGeneralSystemShutdownTrap",
        "PAN-TRAPS",
        "warning",
        "System shutting down",
    ),
    TrapDef(
        "1.3.6.1.4.1.25461.2.1.3.2.0.603", "panGeneralAuthFailTrap", "PAN-TRAPS", "warning", "Authentication failed"
    ),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.2", "panConfigTrap", "PAN-TRAPS", "info", "Configuration event"),
    TrapDef(
        "1.3.6.1.4.1.25461.2.1.3.2.0.801", "panHAStateChangeTrap", "PAN-TRAPS", "warning", "HA device changed state"
    ),
    TrapDef(
        "1.3.6.1.4.1.25461.2.1.3.2.0.800",
        "panHAPreemptTrap",
        "PAN-TRAPS",
        "warning",
        "HA device going passive due to preemption",
    ),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.803", "panHADataplaneDownTrap", "PAN-TRAPS", "critical", "HA dataplane down"),
    TrapDef(
        "1.3.6.1.4.1.25461.2.1.3.2.0.808", "panHAPathMonitorDownTrap", "PAN-TRAPS", "warning", "HA path monitor down"
    ),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.811", "panHAPathMonitorUpTrap", "PAN-TRAPS", "info", "HA path monitor up"),
    TrapDef(
        "1.3.6.1.4.1.25461.2.1.3.2.0.809", "panHALinkMonitorDownTrap", "PAN-TRAPS", "warning", "HA link monitor down"
    ),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.812", "panHALinkMonitorUpTrap", "PAN-TRAPS", "info", "HA link monitor up"),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.827", "panHASplitBrainTrap", "PAN-TRAPS", "critical", "HA split brain"),
    TrapDef(
        "1.3.6.1.4.1.25461.2.1.3.2.0.826", "panHAPeerSplitBrainTrap", "PAN-TRAPS", "critical", "HA peer split brain"
    ),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.805", "panHAHa1LinkChangeTrap", "PAN-TRAPS", "warning", "HA1 link changed"),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.806", "panHAHa2LinkChangeTrap", "PAN-TRAPS", "warning", "HA2 link changed"),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.901", "panHWSlotUpTrap", "PAN-TRAPS", "info", "Slot up"),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.906", "panHWSlotFailureTrap", "PAN-TRAPS", "critical", "Slot failed"),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.910", "panHWSlotRemovedTrap", "PAN-TRAPS", "warning", "Slot removed"),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.909", "panHWSlotInsertedTrap", "PAN-TRAPS", "info", "Slot inserted"),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.907", "panHWSlotPoweroffTrap", "PAN-TRAPS", "warning", "Slot powered off"),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.911", "panHWPsInsertedTrap", "PAN-TRAPS", "info", "Power supply inserted"),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.912", "panHWPsRemovedTrap", "PAN-TRAPS", "warning", "Power supply removed"),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.913", "panHWPsFailureTrap", "PAN-TRAPS", "critical", "Power supply failed"),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.914", "panHWFanInsertedTrap", "PAN-TRAPS", "info", "Fan tray inserted"),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.915", "panHWFanRemovedTrap", "PAN-TRAPS", "warning", "Fan tray removed"),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.916", "panHWFanFailureTrap", "PAN-TRAPS", "warning", "Fan tray failed"),
    TrapDef(
        "1.3.6.1.4.1.25461.2.1.3.2.0.902", "panHWInsufficientPowerTrap", "PAN-TRAPS", "warning", "Insufficient power"
    ),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.900", "panHWDiskErrorsTrap", "PAN-TRAPS", "warning", "Disk errors"),
    TrapDef("1.3.6.1.4.1.25461.2.1.3.2.0.1200", "panPORTLinkChangeTrap", "PAN-TRAPS", "info", "Port link changed"),
    TrapDef(
        "1.3.6.1.4.1.25461.2.1.3.2.0.1531",
        "panROUTINGRoutedBGPPeerEnterEstablishedTrap",
        "PAN-TRAPS",
        "info",
        "BGP peer entered Established",
    ),
    TrapDef(
        "1.3.6.1.4.1.25461.2.1.3.2.0.1532",
        "panROUTINGRoutedBGPPeerLeftEstablishedTrap",
        "PAN-TRAPS",
        "critical",
        "BGP peer left Established",
    ),
    TrapDef(
        "1.3.6.1.4.1.25461.2.1.3.2.0.1524",
        "panROUTINGRoutedOSPFNeighborFullTrap",
        "PAN-TRAPS",
        "info",
        "OSPF neighbor Full",
    ),
    TrapDef(
        "1.3.6.1.4.1.25461.2.1.3.2.0.1525",
        "panROUTINGRoutedOSPFNeighborDownTrap",
        "PAN-TRAPS",
        "critical",
        "OSPF neighbor down",
    ),
)
