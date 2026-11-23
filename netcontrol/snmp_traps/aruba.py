"""HPE Aruba AOS-CX and AOS-Switch traps.

From the MIB texts: AOS-CX: ARUBAWIRED-POWERSUPPLY-MIB, ARUBAWIRED-FAN-MIB, ARUBAWIRED-FANTRAY-MIB,
ARUBAWIRED-TEMPSENSOR-MIB, ARUBAWIRED-MODULE-MIB, ARUBAWIRED-VSF-MIB,
ARUBAWIRED-VSFv2-MIB, ARUBAWIRED-VSX-MIB and ARUBAWIRED-CONFIG-MIB. AOS-Switch
(ProCurve): HP-ICF-CHASSIS, HP-ICF-BASIC and HP-ICF-FAULT-FINDER-MIB.
Generated from the MIBs (OIDs, object names, enumerations); the severity
and the one-line meaning are Plexus's. See docs/snmp-traps.md.
"""

from __future__ import annotations

from netcontrol.snmp_traps.model import TrapDef, TrapObject

OBJECTS: dict[str, TrapObject] = {
    "hpicfPowerSupplySlotNum": TrapObject("1.3.6.1.4.1.11.2.14.11.1.2.11.1.1"),
    "hpicfPowerSupplyStatus": TrapObject(
        "1.3.6.1.4.1.11.2.14.11.1.2.11.1.2", {1: "ok", 2: "inserted", 3: "removed", 4: "faulted"}
    ),
    "hpicfSensorStatus": TrapObject(
        "1.3.6.1.4.1.11.2.14.11.1.2.6.1.4", {1: "unknown", 2: "bad", 3: "warning", 4: "good", 5: "notPresent"}
    ),
    "hpicfSensorDescr": TrapObject("1.3.6.1.4.1.11.2.14.11.1.2.6.1.7"),
    "hpicfSelfTestResultText": TrapObject("1.3.6.1.4.1.11.2.14.11.1.4.5.2"),
    "hpicfFfLogPhysEntity": TrapObject("1.3.6.1.4.1.11.2.14.11.1.7.2.1.3"),
    "hpicfFfLogFaultType": TrapObject(
        "1.3.6.1.4.1.11.2.14.11.1.7.2.1.4",
        {
            1: "badDriver",
            2: "badXcvr",
            3: "badCable",
            4: "tooLongCable",
            5: "overBandwidth",
            6: "bcastStorm",
            7: "partition",
            8: "misconfiguredSQE",
            9: "polarityReversal",
            10: "networkLoop",
            11: "lossOfLink",
            12: "portSecurityViolation",
            13: "backupLinkTransition",
            14: "meshingFault",
            15: "fanFault",
            16: "rpsFault",
            17: "stuck10MbFault",
            18: "lossOfStackMember",
            19: "hotSwapReboot",
            20: "duplexMismatchHDX",
            21: "duplexMismatchFDX",
            22: "flowcntlJumbosFault",
            23: "portSelftestFailure",
            24: "xcvrUnidentified",
            25: "xcvrUnsupported",
            26: "crfNotify",
            27: "crfThrottled",
            28: "crfBlocked",
            29: "xcvrNotYetSupported",
            30: "xcvrBRevOnly",
            31: "xcvrNotSupportedOnPort",
            32: "phyReadFailure",
            33: "linkFlap",
            34: "intel82566dmportprotect",
            35: "xcvrExceedQty",
            36: "xcvrClone",
            37: "xcvrCloneReminder",
            38: "bcastStormPerPort",
            39: "linkFlapPerPort",
            40: "rxNonStdPreamble",
            41: "mcastStorm",
            42: "mcastStormPerPort",
        },
    ),
    "hpicfFfLogAction": TrapObject(
        "1.3.6.1.4.1.11.2.14.11.1.7.2.1.5",
        {1: "none", 2: "warn", 3: "warnAndDisable", 4: "warnAndSpeedReduce", 5: "warnAndSpeedReduceAndDisable"},
    ),
    "hpicfFfLogSeverity": TrapObject(
        "1.3.6.1.4.1.11.2.14.11.1.7.2.1.6", {1: "informational", 2: "medium", 3: "critical"}
    ),
    "hpicfFfFaultInfoURL": TrapObject("1.3.6.1.4.1.11.2.14.11.1.7.3"),
    "arubaWiredVsfOperStatus": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.10.0.2.1"),
    "arubaWiredVsfMemberIndex": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.10.0.3.1.1"),
    "arubaWiredVsfMemberRole": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.10.0.3.1.2"),
    "arubaWiredVsfMemberStatus": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.10.0.3.1.3"),
    "arubaWiredPSUGroupIndex": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.11.2.1.1.1"),
    "arubaWiredPSUSlotIndex": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.11.2.1.1.2"),
    "arubaWiredPSUState": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.11.2.1.1.4"),
    "arubaWiredTempSensorName": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.11.3.1.1.5"),
    "arubaWiredTempSensorState": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.11.3.1.1.6"),
    "arubaWiredFanTrayName": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.11.4.1.1.3"),
    "arubaWiredFanTrayState": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.11.4.1.1.4"),
    "arubaWiredFanName": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.11.5.1.1.4"),
    "arubaWiredFanState": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.11.5.1.1.5"),
    "arubaWiredModuleUnrecognizedDescriptor": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.11.6.1.1.12"),
    "arubaWiredModuleName": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.11.6.1.1.4"),
    "arubaWiredModuleType": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.11.6.1.1.5"),
    "arubaWiredModuleState": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.11.6.1.1.6"),
    "arubaWiredVsfv2OperStatus": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.15.1.1.1"),
    "arubaWiredVsfv2MemberIndex": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.15.1.2.1.1"),
    "arubaWiredVsfv2MemberRole": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.15.1.2.1.2"),
    "arubaWiredVsfv2MemberStatus": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.15.1.2.1.3"),
    "arubaWiredConfigurationChangeSource": TrapObject(
        "1.3.6.1.4.1.47196.4.1.1.3.20.1.1.2", {1: "checkpoint", 2: "cli", 3: "internal", 4: "rest", 5: "snmp", 6: "ztp"}
    ),
    "arubaWiredConfigurationChangeTimestamp": TrapObject("1.3.6.1.4.1.47196.4.1.1.3.20.1.1.3"),
}

TRAPS: tuple[TrapDef, ...] = (
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.11.2.0.1",
        "arubaWiredPSUStateNotification",
        "ARUBAWIRED-POWERSUPPLY-MIB",
        "warning",
        "Power supply state changed",
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.11.5.0.1",
        "arubaWiredFanStateNotification",
        "ARUBAWIRED-FAN-MIB",
        "warning",
        "Fan state changed",
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.11.4.0.1",
        "arubaWiredFanTrayStateNotification",
        "ARUBAWIRED-FANTRAY-MIB",
        "warning",
        "Fan tray state changed",
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.11.3.0.1",
        "arubaWiredTempSensorStateNotification",
        "ARUBAWIRED-TEMPSENSOR-MIB",
        "warning",
        "Temperature sensor state changed",
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.11.6.0.1",
        "arubaWiredModuleStateNotification",
        "ARUBAWIRED-MODULE-MIB",
        "warning",
        "Module state changed",
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.11.6.0.2",
        "arubaWiredModuleInsertedNotification",
        "ARUBAWIRED-MODULE-MIB",
        "info",
        "Module inserted",
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.11.6.0.3",
        "arubaWiredModuleRemovedNotification",
        "ARUBAWIRED-MODULE-MIB",
        "warning",
        "Module removed",
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.11.6.0.4",
        "arubaWiredModuleUnrecognizedNotification",
        "ARUBAWIRED-MODULE-MIB",
        "warning",
        "Module not recognized",
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.10.1.1",
        "arubaWiredVsfMemberStatusChange",
        "ARUBAWIRED-VSF-MIB",
        "warning",
        "VSF stack member status changed",
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.10.1.2",
        "arubaWiredVsfFragmentStatusChange",
        "ARUBAWIRED-VSF-MIB",
        "warning",
        "VSF stack fragment became active or inactive",
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.15.0.1",
        "arubaWiredVsfv2MemberStatusChange",
        "ARUBAWIRED-VSFv2-MIB",
        "warning",
        "VSF stack member status changed",
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.15.0.2",
        "arubaWiredVsfv2FragmentStatusChange",
        "ARUBAWIRED-VSFv2-MIB",
        "warning",
        "VSF stack fragment became active or inactive",
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.7.3.1.1", "islUp", "ARUBAWIRED-VSX-MIB", "info", "VSX inter-switch link in sync"
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.7.3.1.2",
        "islDown",
        "ARUBAWIRED-VSX-MIB",
        "critical",
        "VSX inter-switch link out of sync",
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.7.3.1.3", "keepAliveUp", "ARUBAWIRED-VSX-MIB", "info", "VSX keepalive established"
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.7.3.1.4", "keepAliveDown", "ARUBAWIRED-VSX-MIB", "warning", "VSX keepalive failed"
    ),
    TrapDef(
        "1.3.6.1.4.1.47196.4.1.1.3.20.0.1",
        "arubaWiredConfigurationChangeNotification",
        "ARUBAWIRED-CONFIG-MIB",
        "info",
        "Running configuration changed",
    ),
    TrapDef(
        "1.3.6.1.4.1.11.2.14.12.1.0.3", "hpicfSensorTrap", "HP-ICF-CHASSIS", "warning", "Chassis sensor state changed"
    ),
    TrapDef(
        "1.3.6.1.4.1.11.2.14.12.1.0.6",
        "hpicfPowerSupplyStatusTrap",
        "HP-ICF-CHASSIS",
        "warning",
        "Internal power supply status changed",
    ),
    TrapDef(
        "1.3.6.1.4.1.11.2.14.12.1.0.4",
        "hpicfSelfTestTrap",
        "HP-ICF-BASIC",
        "warning",
        "Self test found a non-critical failure",
    ),
    TrapDef(
        "1.3.6.1.4.1.11.2.14.12.1.0.5",
        "hpicfFaultFinderTrap",
        "HP-ICF-FAULT-FINDER-MIB",
        "warning",
        "Fault Finder logged a fault",
    ),
)
