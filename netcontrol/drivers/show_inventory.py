"""Hardware components read from a Cisco ``show inventory`` output.

One parser for every Cisco platform that prints the block form (IOS, IOS XE,
NX-OS, IOS XR, ASA, FTD)::

    NAME: "Slot 1 Supervisor", DESCR: "Cisco Catalyst 9400 Series Supervisor 1 Module"
    PID: C9400-SUP-1       , VID: V02  , SN: JAE0000A0AA

The label case varies (the ASA prints ``Name:``), as does the spacing
around the commas. A block whose PID line is missing, or whose serial is
empty or a placeholder, is no component. The category of a component is
told from its name, description and PID (``category_of``): the output has
no class column.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from netcontrol.routes.snmp import real_serial

_NAME_LINE = re.compile(r'^\s*NAME:\s*"(?P<name>.*?)"\s*,\s*DESCR:\s*"(?P<descr>.*)"\s*$', re.IGNORECASE)
_PID_LINE = re.compile(
    r"^\s*PID:\s*(?P<pid>[^,]*?)\s*,\s*VID:\s*(?P<vid>[^,]*?)\s*,\s*SN:\s*(?P<sn>\S*)\s*$", re.IGNORECASE
)

# Told from the text of a component, checked in this order. A pluggable
# optic: its PID or description starts with an optic family (Junos names
# them "Xcvr 0"; a line card PID or description may name SFP ports further
# in), its description says "transceiver", or its name is an interface's
# (Te1/1/1, TenGigabitEthernet1/1/1, Ethernet1/49).
_OPTIC_START = re.compile(r"^(?:GLC|Q?SFP\w*|OSFP|XFP|GBIC|CFP\d?|CPAK|CVR|XENPAK|X2|DWDM|QDD|XCVR)\b", re.IGNORECASE)
_TRANSCEIVER_WORD = re.compile(r"\btransceiver\b", re.IGNORECASE)
_INTERFACE_NAME = re.compile(
    r"^(?:Gi|Te|Tw|Twe|Fo|Hu|Fa|Et|Ethernet|\w+GigabitEthernet|\w+GigE)\s*\d+(?:/\d+)+$", re.IGNORECASE
)
_POWER = re.compile(r"\bpower\s*supply\b|\bPSU\b|\bPEM\b|^PWR-|\bpower\s+module\b", re.IGNORECASE)
_FAN = re.compile(r"\bfan", re.IGNORECASE)
# The chassis: named "Chassis" or "Rack 0" (IOS XR), a stack member
# ("Switch 2", the chassis of that member), or described as a chassis by a
# name that is not a slot, card or module's.
_CHASSIS_NAME = re.compile(r"^(?:chassis|rack)\s*\d*$|^switch\s*\d+$", re.IGNORECASE)
_CHASSIS_WORD = re.compile(r"\bchassis\b", re.IGNORECASE)
_PART_NAME = re.compile(r"slot|module|supervisor|card|engine|\d+/\d+", re.IGNORECASE)


@dataclass(frozen=True)
class InventoryBlock:
    """One NAME / DESCR / PID / VID / SN block with a real serial."""

    name: str
    descr: str
    pid: str
    vid: str
    serial: str


def parse_show_inventory(output: str | None) -> list[InventoryBlock]:
    """The blocks of a ``show inventory`` output that carry a serial, in
    the order printed."""
    blocks: list[InventoryBlock] = []
    pending: tuple[str, str] | None = None
    for line in (output or "").splitlines():
        named = _NAME_LINE.match(line)
        if named:
            pending = (named.group("name").strip(), named.group("descr").strip())
            continue
        pid = _PID_LINE.match(line)
        if pid and pending is not None:
            serial = real_serial(pid.group("sn"))
            if serial:
                blocks.append(
                    InventoryBlock(
                        name=pending[0],
                        descr=pending[1],
                        pid=pid.group("pid").strip(),
                        vid=pid.group("vid").strip(),
                        serial=serial,
                    )
                )
            pending = None
    return blocks


def is_transceiver_text(name: str, descr: str, model: str) -> bool:
    """Whether a component's text names a pluggable optic: its model (PID)
    or description starts with an optic family (SFP, QSFP, GLC- ...), its
    description or name says "transceiver", or its name is an interface's.
    Shared by this parser and the SNMP reader (``hardware_components``)."""
    return bool(
        _OPTIC_START.match(model)
        or _OPTIC_START.match(descr)
        or _TRANSCEIVER_WORD.search(descr)
        or _TRANSCEIVER_WORD.search(name)
        or _INTERFACE_NAME.match(name)
    )


def category_of(name: str, descr: str, pid: str) -> str:
    """``transceiver``, ``power_supply``, ``fan``, ``chassis``, ``module`` or
    ``other`` from a component's text: a transceiver by its PID or
    description (SFP, QSFP, GLC- ...) or an interface name; a power supply
    or fan by name; the chassis by its name ("Chassis", "Rack 0", a stack
    member's "Switch 2") or a chassis description on a name that is not a
    slot's; anything else with a PID is a module."""
    text = f"{name} {descr}"
    if is_transceiver_text(name, descr, pid):
        return "transceiver"
    if _POWER.search(text) or _POWER.search(pid):
        return "power_supply"
    if _FAN.search(text):
        return "fan"
    if _CHASSIS_NAME.match(name) or (_CHASSIS_WORD.search(descr) and not _PART_NAME.search(name)):
        return "chassis"
    return "module" if pid else "other"
