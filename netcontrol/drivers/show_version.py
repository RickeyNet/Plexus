"""Facts read from a device's ``show version`` output.

One parser for every caller that reads ``show version`` (inventory
discovery, the upgrade workflow): the OS the output reports (as a Plexus
``device_type``), the chassis model, the software version, the serial and
the hostname. Every fact comes from the output only; a field the output
does not carry is ``None``, never a guess from the vendor or the model.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from netcontrol.drivers.base import DriverCapabilityError, get_driver

# OS markers, checked in order: the more specific product first, since an
# FTD or ASA image also names "Cisco", and a 16.x Catalyst prints both
# "Cisco IOS Software" and "IOS-XE Software" on one line.
_OS_MARKERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bThreat Defense\b", re.IGNORECASE), "cisco_ftd"),
    (re.compile(r"Adaptive Security Appliance", re.IGNORECASE), "cisco_asa"),
    (re.compile(r"\bNX-OS\b|Nexus Operating System", re.IGNORECASE), "cisco_nxos"),
    (re.compile(r"\bIOS[ -]XR\b", re.IGNORECASE), "cisco_xr"),
    (re.compile(r"\bIOS[ -]XE\b|IOSXE", re.IGNORECASE), "cisco_xe"),
    (re.compile(r"Cisco IOS Software|\bIOS \(tm\)|Cisco Internetwork Operating System", re.IGNORECASE), "cisco_ios"),
    (re.compile(r"^Arista\s|Software image version:", re.IGNORECASE | re.MULTILINE), "arista_eos"),
    (
        re.compile(r"^\s*Junos:\s|\bJUNOS (?:Software Release|Base OS|OS Kernel)", re.IGNORECASE | re.MULTILINE),
        "juniper_junos",
    ),
)

# Version, per OS; the first group is the version.
_VERSION_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "cisco_xe": (
        re.compile(r"Cisco IOS XE Software, Version\s+(\S+)", re.IGNORECASE),
        re.compile(r"Cisco IOS Software.*?,\s*Version\s+([^,\s]+)", re.IGNORECASE),
    ),
    "cisco_ios": (re.compile(r"(?:Cisco IOS Software|IOS \(tm\)).*?,\s*Version\s+([^,\s]+)", re.IGNORECASE),),
    "cisco_nxos": (re.compile(r"^\s*(?:NXOS|system):\s+version\s+(\S+)", re.IGNORECASE | re.MULTILINE),),
    "cisco_xr": (re.compile(r"Cisco IOS XR Software,\s*Version\s+([^\s\[,]+)", re.IGNORECASE),),
    "cisco_asa": (re.compile(r"Adaptive Security Appliance Software Version\s+(\S+)", re.IGNORECASE),),
    "cisco_ftd": (re.compile(r"Threat Defense.*?Version\s+(\S+)", re.IGNORECASE),),
    "arista_eos": (re.compile(r"Software image version:\s*(\S+)", re.IGNORECASE),),
    "juniper_junos": (
        re.compile(r"^\s*Junos:\s*(\S+)", re.IGNORECASE | re.MULTILINE),
        re.compile(r"JUNOS (?:Software Release|Base OS boot) \[([^\]]+)\]", re.IGNORECASE),
    ),
}
# Any other output: the first "Version x.y..." on a line.
_GENERIC_VERSION = re.compile(r"\bVersion\s+(\d+\.\d+[\w.()\-]*)")

# Model, per OS.
_PROCESSOR_MODEL = re.compile(r"^\s*cisco\s+(\S+)\s+\([^)]*\)\s+processor", re.IGNORECASE | re.MULTILINE)
_MODEL_NUMBER = re.compile(r"^\s*Model\s+Number\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_MODEL_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    # A stack prints the active switch's "Model Number" first.
    "cisco_xe": (_MODEL_NUMBER, _PROCESSOR_MODEL),
    "cisco_ios": (_MODEL_NUMBER, _PROCESSOR_MODEL),
    "cisco_xr": (_PROCESSOR_MODEL,),
    "cisco_nxos": (
        re.compile(r"^\s*cisco\s+Nexus\S*\s+(C\S+)\s+[Cc]hassis", re.MULTILINE),
        re.compile(r"^\s*cisco\s+(Nexus\s*\S+)\s+[Cc]hassis", re.MULTILINE),
    ),
    "cisco_asa": (re.compile(r"^\s*Hardware:\s+([^,\s]+)", re.MULTILINE),),
    "cisco_ftd": (re.compile(r"^\s*Model\s*:\s*(.+?)\s*\(\d+\)", re.MULTILINE),),
    "arista_eos": (re.compile(r"^\s*Arista\s+(\S+)", re.MULTILINE),),
    "juniper_junos": (re.compile(r"^\s*Model:\s*(\S+)", re.MULTILINE),),
}

# Hostname, per OS. IOS / IOS XE / IOS XR: "<name> uptime is ...".
_UPTIME_HOSTNAME = re.compile(r"^\s*(\S+)\s+uptime is\s", re.MULTILINE)
_HOSTNAME_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "cisco_xe": (_UPTIME_HOSTNAME,),
    "cisco_ios": (_UPTIME_HOSTNAME,),
    "cisco_xr": (_UPTIME_HOSTNAME,),
    "cisco_nxos": (re.compile(r"^\s*Device name:\s*(\S+)", re.MULTILINE),),
    "cisco_asa": (re.compile(r"^\s*(?!failover\b)(\S+)\s+up\s+\d+\s+(?:day|hour|min|sec)", re.MULTILINE),),
    "cisco_ftd": (re.compile(r"^-+\[\s*(\S+)\s*\]-+", re.MULTILINE),),
    "arista_eos": (),
    "juniper_junos": (re.compile(r"^\s*Hostname:\s*(\S+)", re.MULTILINE),),
}
# "Kernel uptime is" (NX-OS) and "System uptime is" are not hostnames.
_NOT_HOSTNAMES = {"kernel", "system"}

# IOS / IOS XE serial lines the driver parser does not read: classic
# Catalyst prints "System serial number" (lower case), routers print only
# "Processor board ID".
_IOS_SERIALS = (
    re.compile(r"^\s*System Serial Number\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*Processor board ID\s+(\S+)", re.IGNORECASE | re.MULTILINE),
)


@dataclass(frozen=True)
class ShowVersionFacts:
    """What one ``show version`` output says; ``None`` where it says nothing."""

    os_device_type: str | None = None
    model: str | None = None
    software_version: str | None = None
    serial_number: str | None = None
    hostname: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def empty(self) -> bool:
        return not any(asdict(self).values())


def classify_show_version_os(output: str | None) -> str | None:
    """The Plexus ``device_type`` of the OS ``show version`` reports, or
    ``None`` when the output names no OS this parser recognizes."""
    text = output or ""
    for pattern, device_type in _OS_MARKERS:
        if pattern.search(text):
            return device_type
    return None


def _first(patterns: tuple[re.Pattern[str], ...], text: str) -> str | None:
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            value = match.group(1).strip().rstrip(",;")
            if value:
                return value
    return None


def _serial(os_type: str | None, text: str) -> str | None:
    if os_type:
        try:
            serial = get_driver(os_type).parse_serial_number(text)
        except DriverCapabilityError:
            serial = None
        if serial:
            return serial.strip()
    if os_type in ("cisco_ios", "cisco_xe"):
        return _first(_IOS_SERIALS, text)
    return None


def _hostname(os_type: str | None, text: str) -> str | None:
    for pattern in _HOSTNAME_PATTERNS.get(os_type or "", ()):
        for match in pattern.finditer(text):
            name = match.group(1).strip()
            if name and name.lower() not in _NOT_HOSTNAMES:
                return name
    return None


def parse_show_version(output: str | None) -> ShowVersionFacts:
    """Parse ``show version`` output into :class:`ShowVersionFacts`."""
    text = output or ""
    if not text.strip():
        return ShowVersionFacts()
    os_type = classify_show_version_os(text)
    version = _first(_VERSION_PATTERNS.get(os_type or "", ()), text) or _first((_GENERIC_VERSION,), text)
    return ShowVersionFacts(
        os_device_type=os_type,
        model=_first(_MODEL_PATTERNS.get(os_type or "", ()), text),
        software_version=version,
        serial_number=_serial(os_type, text),
        hostname=_hostname(os_type, text),
    )
