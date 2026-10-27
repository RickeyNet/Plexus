"""What a discovered host is called and which addresses are its own.

The discovery sweep names a host it learned no name for after its address
(``discovered-10-74-103-1``, ``snmp-...``, ``host-...``): a placeholder,
not a name anyone chose, which a later read of the device's own name may
replace. The SNMP discovery and the SSH inventory collection both record
the IPv4 addresses a device has on its interfaces as the host's aliases
(``host_ip_aliases``), so a neighbor or a Meraki record that names the
device by another of its addresses finds the same host.

Pure (no I/O).
"""

from __future__ import annotations

import ipaddress

__all__ = ["interface_ip", "is_placeholder_hostname", "placeholder_hostname"]


def placeholder_hostname(prefix: str, ip_address: str) -> str:
    """The name discovery gives a host it learned no name for: ``prefix``,
    a dash and the address with its dots as dashes."""
    return f"{prefix}-{ip_address.replace('.', '-')}"


def is_placeholder_hostname(hostname: str, ip_address: str) -> bool:
    """Whether ``hostname`` is a discovery placeholder for ``ip_address``:
    any non-empty prefix, a dash and the dashed address (case-insensitive),
    as ``placeholder_hostname`` writes it."""
    name = str(hostname or "").strip().lower()
    dashed = str(ip_address or "").strip().lower().replace(".", "-")
    if not name or not dashed:
        return False
    suffix = f"-{dashed}"
    return len(name) > len(suffix) and name.endswith(suffix)


def interface_ip(value: str) -> str:
    """``value`` as an IPv4 address a device holds on an interface, or ``""``
    for anything else (not an address, IPv6, loopback, link-local,
    multicast, unspecified)."""
    try:
        parsed = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""
    if parsed.version != 4:
        return ""
    if parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified:
        return ""
    return str(parsed)
