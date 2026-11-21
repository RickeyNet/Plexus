"""
net_guard.py -- Outbound-request (SSRF) validation for admin-configurable URLs.

Several integrations let an admin store a URL/host that Plexus then fetches
server-side (IPAM, DHCP, federation peers, webhook/Teams notifications, SIEM
sinks, identity providers). Without validation these are SSRF sinks: an
internal URL could be pointed at the cloud instance-metadata endpoint
(169.254.169.254) or used as an internal-network oracle/port-scanner.

These integrations legitimately target on-prem appliances on RFC1918 ranges,
and local sidecar agents on loopback, so a blanket private/loopback deny would
break normal use. The policy, in order:

1. ``ALWAYS_BLOCKED``: the cloud instance-metadata and platform addresses
   (169.254.169.254, the AWS IPv6 endpoint fd00:ec2::254, ...). Refused
   whatever else is configured: no ``APP_SSRF_ALLOW`` entry opens them, and
   an allow-listed *name* that resolves to one is refused too.
2. ``APP_SSRF_ALLOW=host1,10.0.0.5``: exact hostnames / IPs an admin trusts.
   They skip the rules below, and an allow-listed name that does not resolve
   is let through (it fails at connect time).
3. A name that does not resolve is refused (fail closed): the check cannot
   judge an address it does not know, and a resolver that fails now can
   answer differently at connect time.
4. Link-local, multicast, reserved and unspecified addresses are refused.
   Loopback and private ranges are permitted unless
   ``APP_SSRF_BLOCK_PRIVATE=true``.

``validate_outbound_url`` / ``validate_outbound_host`` return the addresses
they checked. ``outbound_http.send_request`` connects only to those
(pinning: the first that accepts the connection), so a second DNS answer
cannot move the request to another address after the check (DNS rebinding). Callers that open their own
connections (raw TCP/UDP SIEM sinks, git, the SSO clients) re-run the check
before each use but are not pinned; see docs/webhooks.md
(Outbound address check).
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any
from urllib.parse import urlsplit

from netcontrol.routes.state import _env_flag
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.net_guard")

_ALLOWED_SCHEMES = {"http", "https"}

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Cloud instance-metadata, credential and platform endpoints. Never a
# legitimate integration target, always the SSRF escalation target.
ALWAYS_BLOCKED: frozenset[IPAddress] = frozenset(
    ipaddress.ip_address(a)
    for a in (
        "169.254.169.254",  # AWS, Azure, GCP, Oracle, OpenStack instance metadata
        "fd00:ec2::254",  # AWS instance metadata over IPv6 (Nitro)
        "169.254.170.2",  # AWS ECS task metadata and credentials
        "169.254.170.23",  # AWS EKS Pod Identity agent
        "fd00:ec2::23",  # AWS EKS Pod Identity agent over IPv6
        "100.100.100.200",  # Alibaba Cloud instance metadata
        "168.63.129.16",  # Azure WireServer / platform endpoint
        "192.0.0.192",  # Oracle Cloud legacy instance metadata
    )
)


class OutboundRequestError(ValueError):
    """Raised when a target URL/host fails SSRF validation."""


def _allow_list() -> set[str]:
    raw = os.getenv("APP_SSRF_ALLOW", "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def _canonical(ip: IPAddress) -> IPAddress:
    """An IPv4-mapped IPv6 address (``::ffff:a.b.c.d``) as its IPv4 form."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def is_always_blocked(ip: IPAddress) -> bool:
    """Whether ``ip`` is a cloud metadata/platform address (``ALWAYS_BLOCKED``)."""
    return _canonical(ip) in ALWAYS_BLOCKED


def _ip_is_blocked(ip: IPAddress, *, block_private: bool) -> bool:
    # Loopback is judged first: ``::1`` lies in the reserved ``::/8`` block,
    # so ``is_reserved`` alone would refuse ``localhost`` on a dual-stack host.
    if is_always_blocked(ip):
        return True
    if ip.is_loopback:
        return block_private
    if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    if block_private and ip.is_private:
        return True
    return False


def _getaddrinfo(host: str) -> list[Any]:
    """The resolver the guard uses (tests replace it; no test asks real DNS)."""
    return socket.getaddrinfo(host, None)


def _resolve_ips(host: str) -> list[IPAddress]:
    """The addresses ``host`` resolves to, in resolver order without repeats;
    ``[]`` when it does not resolve."""
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = _getaddrinfo(host)
    except (OSError, UnicodeError) as exc:  # socket.gaierror is an OSError
        LOGGER.debug("net_guard: could not resolve host %r: %s", host, exc)
        return []
    ips: list[IPAddress] = []
    for info in infos:
        try:
            ip = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
        except ValueError, IndexError, TypeError:
            continue
        if ip not in ips:
            ips.append(ip)
    return ips


def validate_outbound_host(host: str, *, block_private: bool | None = None) -> list[IPAddress]:
    """Validate a bare hostname/IP (e.g. for a raw TCP/UDP SIEM sink).

    Returns the checked addresses (empty only for an allow-listed name that
    does not resolve). Raises ``OutboundRequestError`` when the host is
    refused."""
    host = (host or "").strip()
    if not host:
        raise OutboundRequestError("empty host")
    ips = _resolve_ips(host)
    for ip in ips:
        if is_always_blocked(ip):
            raise OutboundRequestError(
                f"host '{host}' resolves to a disallowed address ({ip}): a cloud metadata address, always refused"
            )
    if host.lower() in _allow_list():
        return ips
    if not ips:
        raise OutboundRequestError(
            f"host '{host}' does not resolve, so its address cannot be checked "
            "(an administrator can allow it with APP_SSRF_ALLOW)"
        )
    if block_private is None:
        block_private = _env_flag("APP_SSRF_BLOCK_PRIVATE", False)
    for ip in ips:
        if _ip_is_blocked(ip, block_private=block_private):
            raise OutboundRequestError(f"host '{host}' resolves to a disallowed address ({ip})")
    return ips


def validate_outbound_url(url: str, *, block_private: bool | None = None) -> list[IPAddress]:
    """Validate an http(s) URL. Returns the checked addresses of its host;
    raises ``OutboundRequestError`` on failure."""
    parts = urlsplit((url or "").strip())
    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        raise OutboundRequestError(f"URL scheme '{parts.scheme}' not allowed (use http/https)")
    host = parts.hostname
    if not host:
        raise OutboundRequestError("URL has no host")
    return validate_outbound_host(host, block_private=block_private)
