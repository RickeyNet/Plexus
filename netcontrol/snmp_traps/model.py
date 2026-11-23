"""The two record types of the trap registry tables (``netcontrol.snmp_traps``)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class TrapObject:
    """A MIB object a trap carries as a varbind: its OID (a table column or
    a scalar, without the instance) and, for an enumerated INTEGER, the
    label of each value."""

    oid: str
    values: dict[int, str] = field(default_factory=dict, compare=False, hash=False)


@dataclass(frozen=True)
class TrapDef:
    """A named trap: its notification OID (``snmpTrapOID.0``), its MIB name
    and module, the severity its event is stored with and what it means."""

    oid: str
    name: str
    mib: str
    severity: str
    meaning: str
