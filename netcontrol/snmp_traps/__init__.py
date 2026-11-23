"""SNMP trap registry: a trap OID to its MIB name, meaning, stored severity
and the names of its varbinds.

The SNMP trap receiver (``netcontrol/routes/metrics_engine.py``) decodes a
v1 / v2c trap or inform (``netcontrol.routes.snmp.decode_snmp_trap``) and
stores it in ``trap_syslog_events``; ``name_trap`` here turns the decoded
trap into a ``NamedTrap``, whose ``message`` is the stored text::

    linkDown: ifIndex 12, ifDescr GigabitEthernet1/0/12, ifAdminStatus up, ifOperStatus down

An unknown trap is stored all the same, with its OID and its varbinds as
``oid = value``. A varbind whose OID falls under an object of any table is
named, whichever trap carries it, and an enumerated value is shown by its
label.

The tables, one module per vendor, are generated from the MIB texts (the
OIDs, object names and enumerations); the stored severity and the one-line
meaning are Plexus's. ``netcontrol.trap_rules`` acts on the named traps.
APC PowerNet-MIB traps are named by ``netcontrol.integrations.apc.traps``.
``docs/snmp-traps.md`` lists the traps per vendor and their sources.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netcontrol.snmp_traps import (
    arista,
    aruba,
    cisco,
    fortinet,
    juniper,
    netgear,
    netsnmp,
    paloalto,
    standard,
)
from netcontrol.snmp_traps.model import TrapDef, TrapObject

__all__ = [
    "OBJECTS",
    "TABLES",
    "TRAPS_BY_OID",
    "NamedTrap",
    "TrapDef",
    "TrapObject",
    "Varbind",
    "lookup",
    "name_trap",
]

# (family, table module): the order docs/snmp-traps.md lists them in.
TABLES = (
    ("Standard MIBs", standard),
    ("net-snmp (OPNsense)", netsnmp),
    ("Cisco", cisco),
    ("Juniper", juniper),
    ("Arista", arista),
    ("Fortinet", fortinet),
    ("Palo Alto", paloalto),
    ("HPE Aruba", aruba),
    ("Netgear", netgear),
)

TRAPS_BY_OID: dict[str, TrapDef] = {t.oid: t for _family, table in TABLES for t in table.TRAPS}
OBJECTS: dict[str, TrapObject] = {name: obj for _family, table in TABLES for name, obj in table.OBJECTS.items()}
_OBJECT_BY_OID: dict[str, str] = {obj.oid: name for name, obj in OBJECTS.items()}

# Varbinds every v2c trap carries that the text leaves out: sysUpTime.0,
# snmpTrapOID.0 and snmpTrapEnterprise.0 (SNMPv2-MIB).
_HEADER_OIDS = frozenset({"1.3.6.1.2.1.1.3.0", "1.3.6.1.6.3.1.1.4.1.0", "1.3.6.1.6.3.1.1.4.3.0"})

# Bounds on what one trap can make the naming do.
_MAX_VARBINDS = 64
_MAX_OID_PARTS = 128
_VALUE_MAX = 200


def lookup(trap_oid: str) -> TrapDef | None:
    """The named trap of an ``snmpTrapOID.0``, or None. A v1 trap of a MIB
    whose notification OID has no ``0`` before its last number (JUNIPER-MIB
    ``jnxPowerSupplyFailure`` is ``...2636.4.1.1``) arrives as
    ``enterprise.0.specific`` (RFC 3584): the ``0`` is dropped to find it."""
    found = TRAPS_BY_OID.get(trap_oid)
    if found is not None:
        return found
    head, _sep, last = trap_oid.rpartition(".")
    if head.endswith(".0") and last.isdigit():
        return TRAPS_BY_OID.get(f"{head[:-2]}.{last}")
    return None


def _object_of(oid: str) -> tuple[str, str]:
    """``(object name, instance index)`` of a varbind OID, ``("", "")`` when
    it is under no known object."""
    parts = oid.split(".")
    if len(parts) > _MAX_OID_PARTS:
        return "", ""
    for end in range(len(parts) - 1, 1, -1):
        name = _OBJECT_BY_OID.get(".".join(parts[:end]))
        if name is not None:
            return name, ".".join(parts[end:])
    return "", ""


def _printable(value: str) -> str:
    """A decoded value as text: pysnmp prints an octet string that is not
    plain text as ``0x<hex>``; one that decodes as printable UTF-8 is shown
    as that text. Whitespace is collapsed and the value capped."""
    text = str(value)
    if text.startswith("0x") and len(text) > 2 and len(text) % 2 == 0:
        try:
            raw = bytes.fromhex(text[2:])
            decoded = raw.decode("utf-8").rstrip("\x00")
            if decoded and decoded.isprintable():
                text = decoded
        except ValueError:
            pass
    text = " ".join(text.split())
    return text if len(text) <= _VALUE_MAX else text[: _VALUE_MAX - 3] + "..."


@dataclass(frozen=True)
class Varbind:
    """One varbind of a trap: its OID, the object it is under (``name``, ""
    when unknown) and the instance index after that object's OID, the value
    as decoded and its ``label`` (the enumeration label, else the value as
    printable text)."""

    oid: str
    name: str
    index: str
    value: str
    label: str

    @property
    def number(self) -> int | None:
        try:
            return int(self.value)
        except TypeError, ValueError:
            return None

    def text(self) -> str:
        return f"{self.name} {self.label}" if self.name else f"{self.oid} = {self.label}"


@dataclass(frozen=True)
class NamedTrap:
    """A decoded trap (``decode_snmp_trap``'s dict, ``trap``) with its
    registry entry (``definition``, None when unknown) and its named
    varbinds. ``raw_tag`` and ``text`` are what a trap alert message quotes
    (``netcontrol.syslog_rules.alert_message``)."""

    trap_oid: str
    definition: TrapDef | None
    varbinds: tuple[Varbind, ...]
    trap: dict = field(default_factory=dict, repr=False, compare=False)

    @property
    def name(self) -> str:
        return self.definition.name if self.definition else ""

    @property
    def raw_tag(self) -> str:
        return self.name or self.trap_oid

    @property
    def severity(self) -> str:
        return self.definition.severity if self.definition else "info"

    @property
    def text(self) -> str:
        """The varbinds, ``name label`` (``oid = value`` when unknown),
        without the header varbinds; the meaning when there is none."""
        parts = [vb.text() for vb in self.varbinds if vb.oid not in _HEADER_OIDS]
        if parts:
            return ", ".join(parts)
        return self.definition.meaning if self.definition else ""

    @property
    def message(self) -> str:
        """The stored event text: ``<name>: <text>``, or ``SNMP trap <oid>:
        <text>`` for an unknown trap."""
        head = self.name or f"SNMP trap {self.trap_oid or '(no trap OID)'}"
        text = self.text
        return f"{head}: {text}" if text else head

    def get(self, name: str) -> Varbind | None:
        """The first varbind under object ``name``."""
        return next((vb for vb in self.varbinds if vb.name == name), None)

    def label(self, name: str) -> str:
        found = self.get(name)
        return found.label if found else ""

    def number(self, name: str) -> int | None:
        found = self.get(name)
        return found.number if found else None

    def index(self, name: str) -> str:
        found = self.get(name)
        return found.index if found else ""


def name_trap(trap: dict) -> NamedTrap:
    """The ``NamedTrap`` of a decoded trap: the dict ``decode_snmp_trap``
    returns (``trap_oid``, ``varbinds`` as ``(oid, value text)``), or one of
    the same shape from another decoder."""
    trap_oid = str(trap.get("trap_oid") or "")
    varbinds: list[Varbind] = []
    for item in list(trap.get("varbinds") or [])[:_MAX_VARBINDS]:
        try:
            oid, value = str(item[0]), str(item[1])
        except IndexError, TypeError:
            continue
        name, index = _object_of(oid)
        label = _printable(value)
        if name:
            values = OBJECTS[name].values
            try:
                label = values.get(int(value), label) if values else label
            except ValueError:
                pass
        varbinds.append(Varbind(oid, name, index, value, label))
    return NamedTrap(trap_oid, lookup(trap_oid), tuple(varbinds), trap)
