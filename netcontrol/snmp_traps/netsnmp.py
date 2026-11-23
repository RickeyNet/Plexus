"""net-snmp agent traps (OPNsense, Linux hosts).

From the MIB texts: NET-SNMP-AGENT-MIB and UCD-SNMP-MIB.
Generated from the MIBs (OIDs, object names, enumerations); the severity
and the one-line meaning are Plexus's. See docs/snmp-traps.md.
"""

from __future__ import annotations

from netcontrol.snmp_traps.model import TrapDef, TrapObject

OBJECTS: dict[str, TrapObject] = {}

TRAPS: tuple[TrapDef, ...] = (
    TrapDef("1.3.6.1.4.1.8072.4.0.1", "nsNotifyStart", "NET-SNMP-AGENT-MIB", "warning", "net-snmp agent started"),
    TrapDef(
        "1.3.6.1.4.1.8072.4.0.2", "nsNotifyShutdown", "NET-SNMP-AGENT-MIB", "warning", "net-snmp agent shutting down"
    ),
    TrapDef("1.3.6.1.4.1.8072.4.0.3", "nsNotifyRestart", "NET-SNMP-AGENT-MIB", "warning", "net-snmp agent restarted"),
    TrapDef("1.3.6.1.4.1.2021.251.1", "ucdStart", "UCD-SNMP-MIB", "warning", "UCD / net-snmp agent started"),
    TrapDef("1.3.6.1.4.1.2021.251.2", "ucdShutdown", "UCD-SNMP-MIB", "warning", "UCD / net-snmp agent shutting down"),
)
