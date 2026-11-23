"""Arista EOS traps (EOS sends the standard traps too).

From the MIB texts: ARISTA-BGP4V2-MIB and ARISTA-ENTITY-SENSOR-MIB.
Generated from the MIBs (OIDs, object names, enumerations); the severity
and the one-line meaning are Plexus's. See docs/snmp-traps.md.
"""

from __future__ import annotations

from netcontrol.snmp_traps.model import TrapDef, TrapObject

OBJECTS: dict[str, TrapObject] = {
    "entPhySensorValue": TrapObject("1.3.6.1.2.1.99.1.1.1.4"),
    "aristaBgp4V2PeerState": TrapObject(
        "1.3.6.1.4.1.30065.4.1.1.2.1.13",
        {1: "idle", 2: "connect", 3: "active", 4: "opensent", 5: "openconfirm", 6: "established"},
    ),
    "aristaBgp4V2PeerLocalPort": TrapObject("1.3.6.1.4.1.30065.4.1.1.2.1.6"),
    "aristaBgp4V2PeerRemotePort": TrapObject("1.3.6.1.4.1.30065.4.1.1.2.1.9"),
    "aristaBgp4V2PeerLastErrorCodeReceived": TrapObject("1.3.6.1.4.1.30065.4.1.1.3.1.1"),
    "aristaBgp4V2PeerLastErrorSubCodeReceived": TrapObject("1.3.6.1.4.1.30065.4.1.1.3.1.2"),
    "aristaBgp4V2PeerLastErrorReceivedText": TrapObject("1.3.6.1.4.1.30065.4.1.1.3.1.4"),
}

TRAPS: tuple[TrapDef, ...] = (
    TrapDef(
        "1.3.6.1.4.1.30065.4.1.0.1",
        "aristaBgp4V2EstablishedNotification",
        "ARISTA-BGP4V2-MIB",
        "info",
        "BGP session established",
    ),
    TrapDef(
        "1.3.6.1.4.1.30065.4.1.0.2",
        "aristaBgp4V2BackwardTransitionNotification",
        "ARISTA-BGP4V2-MIB",
        "critical",
        "BGP session left a higher state (session lost)",
    ),
    TrapDef(
        "1.3.6.1.4.1.30065.3.12.0.1",
        "aristaEntSensorAlarm",
        "ARISTA-ENTITY-SENSOR-MIB",
        "warning",
        "Sensor alarm state changed",
    ),
)
