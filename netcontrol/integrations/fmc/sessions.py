"""Remote access VPN sessions read from the FTD itself.

The FMC health API for remote access VPN sessions (``health/ravpnsessions``)
exists on FMC 7.3 and later and needs the VPN permission. When it does not
answer, each headend is asked directly through the FMC's device command
relay (``devices/devicerecords/{id}/operational/commands``, Devices > Device
Management permission, FTD 6.6 and later), which runs ``show vpn-sessiondb``
on the device and returns its text. This module builds those requests and
turns the text back into session records of the shape the health API
returns, so the normaliser treats both the same.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

# ``show vpn-sessiondb`` with these parameters: the AnyConnect / Secure
# Client SSL and IKEv2 sessions. ``detail`` adds the client OS and version.
SESSION_COMMANDS: tuple[tuple[str, str], ...] = (
    ("show vpn-sessiondb", "detail anyconnect"),
    ("show vpn-sessiondb", "detail ra-ikev2-ipsec"),
)

# ``Label : value`` pairs; a line can hold two, separated by two or more spaces.
_PAIR_RE = re.compile(
    r"(?P<label>[A-Za-z][A-Za-z0-9 /]*?)\s*:\s(?P<value>.*?)(?=\s{2,}[A-Za-z][A-Za-z0-9 /]*?\s*:\s|\s*$)"
)
_USERNAME_RE = re.compile(r"^\s*Username\s*:")
_NO_SESSIONS_RE = re.compile(r"no active sessions", re.IGNORECASE)

# The first value of each label in a session block is kept: the top-level
# fields come first, then the per-tunnel blocks (AnyConnect-Parent, SSL-Tunnel,
# DTLS-Tunnel) repeat some of them.
_FIELDS = {
    "username": "username",
    "index": "index",
    "assigned ip": "assignedIp",
    "assigned ipv6": "assignedIpv6",
    "public ip": "publicIp",
    "protocol": "protocol",
    "license": "license",
    "encryption": "encryption",
    "hashing": "hashing",
    "bytes tx": "bytesTx",
    "bytes rx": "bytesRx",
    "group policy": "groupPolicy",
    "tunnel group": "tunnelGroup",
    "login time": "loginTime",
    "duration": "duration",
    "inactivity": "inactivity",
    "client os": "clientOs",
    "client os ver": "clientOsVersion",
    "client type": "clientType",
    "client ver": "clientApplication",
    "vlan": "vlan",
    "tunnel zone": "tunnelZone",
    "audt sess id": "auditSessionId",
    "security grp": "securityGroup",
}
_INT_FIELDS = ("bytesTx", "bytesRx", "index")

# What the FTD calls the client platforms.
_OS_NAMES = {
    "win": "Windows",
    "mac-intel": "macOS",
    "mac-arm": "macOS",
    "mac": "macOS",
    "linux-64": "Linux",
    "linux": "Linux",
    "apple-ios": "iOS",
    "android": "Android",
    "chromeos": "ChromeOS",
}


def command_path(base: str, device_id: str, command: str, parameter: str) -> str:
    """The relay request that runs ``command parameter`` on a device."""
    return (
        f"{base}/devices/devicerecords/{device_id}/operational/commands"
        f"?filter={quote(f'command:{command}', safe=':')}&parameter={quote(parameter)}"
    )


def command_output(body: Any) -> str:
    """The text a relay answer carries: ``items[].response`` (the documented
    shape), or the object's own ``response`` / ``output``, or a bare string."""
    if isinstance(body, str):
        return body
    if not isinstance(body, dict):
        return ""
    items = body.get("items")
    if isinstance(items, list):
        return "\n".join(command_output(item) for item in items if item)
    for key in ("response", "output", "result", "commandOutput", "text"):
        value = body.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            return "\n".join(str(v) for v in value)
    return ""


def parse_vpn_sessiondb(text: str) -> list[dict[str, Any]] | None:
    """The sessions in a ``show vpn-sessiondb [detail] <type>`` answer.

    Returns an empty list for *no active sessions*, and ``None`` when the
    text is not that command's output (an error line, an unsupported
    command), so the caller does not mistake a refusal for an empty VPN.
    """
    sessions: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in (text or "").splitlines():
        line = raw_line.rstrip()
        if _USERNAME_RE.match(line):
            current = {}
            sessions.append(current)
        if current is None or not line.strip():
            continue
        for match in _PAIR_RE.finditer(line):
            key = _FIELDS.get(match.group("label").strip().lower())
            if key is None or key in current:
                continue
            value = match.group("value").strip()
            if key in _INT_FIELDS:
                try:
                    current[key] = int(value)
                except ValueError:
                    current[key] = value
            else:
                current[key] = value
    if not sessions and not _NO_SESSIONS_RE.search(text or ""):
        return None
    return [s for s in sessions if s.get("username")]


def session_record(device_id: str, device_name: str, parsed: dict[str, Any]) -> dict[str, Any]:
    """A parsed session in the shape of a ``health/ravpnsessions`` item."""
    record: dict[str, Any] = {
        "type": "RAVpnSession",
        "source": "show vpn-sessiondb",
        "device": {"id": device_id, "name": device_name, "type": "Device"},
    }
    record.update(parsed)
    os_name = str(parsed.get("clientOs") or "").strip()
    os_version = str(parsed.get("clientOsVersion") or "").strip()
    if os_name:
        pretty = _OS_NAMES.get(os_name.lower(), os_name)
        record["clientOs"] = f"{pretty} {os_version}".strip() if os_version and os_version.lower() != "n/a" else pretty
    if parsed.get("tunnelGroup") and not parsed.get("connectionProfile"):
        record["connectionProfile"] = parsed["tunnelGroup"]
    if not parsed.get("clientApplication") and parsed.get("clientType"):
        record["clientApplication"] = parsed["clientType"]
    return record
