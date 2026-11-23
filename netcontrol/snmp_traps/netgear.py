"""Netgear managed and smart switch traps.

From the MIB texts: NETGEAR-SWITCHING-MIB and NETGEAR-BOXSERVICES-PRIVATE-MIB.
Generated from the MIBs (OIDs, object names, enumerations); the severity
and the one-line meaning are Plexus's. See docs/snmp-traps.md.
"""

from __future__ import annotations

from netcontrol.snmp_traps.model import TrapDef, TrapObject

OBJECTS: dict[str, TrapObject] = {
    "agentStpMstId": TrapObject("1.3.6.1.4.1.4526.10.1.2.15.10.1.1"),
    "boxServicesThermalShutdownSensor": TrapObject("1.3.6.1.4.1.4526.10.43.1.13"),
    "boxServicesThermalShutdownTemperature": TrapObject("1.3.6.1.4.1.4526.10.43.1.14"),
    "boxServicesTempUnitIndex": TrapObject("1.3.6.1.4.1.4526.10.43.1.15.1.1"),
    "boxServicesFansIndex": TrapObject("1.3.6.1.4.1.4526.10.43.1.6.1.1"),
    "boxServicesPowSupplyIndex": TrapObject("1.3.6.1.4.1.4526.10.43.1.7.1.1"),
    "boxServicesTempSensorIndex": TrapObject("1.3.6.1.4.1.4526.10.43.1.8.1.2"),
    "boxsItemStateChangeEvent": TrapObject(
        "1.3.6.1.4.1.4526.10.43.2.1",
        {1: "insertion", 2: "removal", 3: "becomeoperational", 4: "failure", 5: "losepower"},
    ),
    "boxsTemperatureChangeEvent": TrapObject(
        "1.3.6.1.4.1.4526.10.43.2.2", {1: "abovethreshold", 2: "belowthreshold", 3: "withinnormalrange"}
    ),
    "boxsTemperatureStatusCurrentEvent": TrapObject(
        "1.3.6.1.4.1.4526.10.43.2.3",
        {0: "low", 1: "normal", 2: "warning", 3: "critical", 4: "shutdown", 5: "notpresent", 6: "notoperational"},
    ),
    "boxsTemperatureStatusPreviousEvent": TrapObject(
        "1.3.6.1.4.1.4526.10.43.2.4",
        {0: "low", 1: "normal", 2: "warning", 3: "critical", 4: "shutdown", 5: "notpresent", 6: "notoperational"},
    ),
}

TRAPS: tuple[TrapDef, ...] = (
    TrapDef("1.3.6.1.4.1.4526.10.1.0.4", "linkFailureTrap", "NETGEAR-SWITCHING-MIB", "warning", "Link failure"),
    TrapDef("1.3.6.1.4.1.4526.10.1.0.9", "fanFailureTrap", "NETGEAR-SWITCHING-MIB", "warning", "Fan failed"),
    TrapDef(
        "1.3.6.1.4.1.4526.10.1.0.12",
        "powerSupplyStatusChangeTrap",
        "NETGEAR-SWITCHING-MIB",
        "warning",
        "Power supply status changed",
    ),
    TrapDef(
        "1.3.6.1.4.1.4526.10.1.0.13",
        "failedUserLoginTrap",
        "NETGEAR-SWITCHING-MIB",
        "warning",
        "User failed to log in (CLI or web)",
    ),
    TrapDef(
        "1.3.6.1.4.1.4526.10.1.0.14",
        "userLockoutTrap",
        "NETGEAR-SWITCHING-MIB",
        "warning",
        "User account locked after failed logins",
    ),
    TrapDef(
        "1.3.6.1.4.1.4526.10.1.0.10",
        "stpInstanceNewRootTrap",
        "NETGEAR-SWITCHING-MIB",
        "info",
        "This switch became the new STP root",
    ),
    TrapDef(
        "1.3.6.1.4.1.4526.10.1.0.11",
        "stpInstanceTopologyChangeTrap",
        "NETGEAR-SWITCHING-MIB",
        "info",
        "STP topology change",
    ),
    TrapDef(
        "1.3.6.1.4.1.4526.10.43.0.1",
        "boxsFanStateChange",
        "NETGEAR-BOXSERVICES-PRIVATE-MIB",
        "warning",
        "Fan state changed",
    ),
    TrapDef(
        "1.3.6.1.4.1.4526.10.43.0.2",
        "boxsPowSupplyStateChange",
        "NETGEAR-BOXSERVICES-PRIVATE-MIB",
        "warning",
        "Power supply state changed",
    ),
    TrapDef(
        "1.3.6.1.4.1.4526.10.43.0.3",
        "boxsTemperatureChange",
        "NETGEAR-BOXSERVICES-PRIVATE-MIB",
        "warning",
        "Temperature crossed a threshold",
    ),
    TrapDef(
        "1.3.6.1.4.1.4526.10.43.0.5",
        "boxsTemperatureStateChange",
        "NETGEAR-BOXSERVICES-PRIVATE-MIB",
        "warning",
        "System temperature state changed",
    ),
    TrapDef(
        "1.3.6.1.4.1.4526.10.43.0.4",
        "boxsThermalShutdown",
        "NETGEAR-BOXSERVICES-PRIVATE-MIB",
        "critical",
        "Thermal shutdown started",
    ),
)
