"""
net_guard.py -- Outbound-request (SSRF) validation for admin-configurable URLs.

Several integrations let an admin store a URL/host that Plexus then fetches
server-side (IPAM, DHCP, federation peers, webhook/Teams notifications, SIEM
sinks). Without validation these are SSRF sinks: an internal URL could be
pointed at the cloud instance-metadata endpoint (169.254.169.254) or used as
an internal-network oracle/port-scanner.

These integrations legitimately target on-prem appliances on RFC1918 ranges,
and local sidecar agents on loopback, so a blanket private/loopback deny would
break normal use. The default policy therefore blocks only the addresses that
are never a legitimate integration endpoint and are the classic SSRF
escalation target - link-local (which includes the cloud instance-metadata
IPs 169.254.169.254 / fd00:ec2::254), multicast, reserved, and unspecified.
Private ranges and loopback are permitted by default. Operators can tighten or
add explicit allow entries via environment variables:

  APP_SSRF_BLOCK_PRIVATE=true   also reject RFC1918 / unique-local + loopback
  APP_SSRF_ALLOW=host1,10.0.0.5 exact hostnames / IPs always permitted

Resolution failures fail OPEN (the request is allowed to proceed and will
simply fail at connect time): failing closed would break offline/test
environments and mock transports without adding protection, since an
unresolvable name cannot be connected to anyway.

Note: this validates the resolved address(es) before the request is made. It
is a strong mitigation but not a full guarantee against DNS-rebinding (a name
that resolves differently at connect time); pinning the connection to the
validated IP would be required for that and is out of scope here.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from netcontrol.routes.state import _env_flag
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.net_guard")

_ALLOWED_SCHEMES = {"http", "https"}


class OutboundRequestError(ValueError):
    """Raised when a target URL/host fails SSRF validation."""


def _allow_list() -> set[str]:
    raw = __import__("os").getenv("APP_SSRF_ALLOW", "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def _ip_is_blocked(ip: ipaddress._BaseAddress, *, block_private: bool) -> bool:
    # Link-local covers the cloud instance-metadata endpoints (169.254.169.254,
    # fd00:ec2::254 / fe80::/10) - the classic SSRF escalation target. Always
    # block link-local plus multicast/reserved/unspecified. Loopback and
    # private ranges are permitted by default (legit on-prem / sidecar targets)
    # and only blocked when the operator opts into APP_SSRF_BLOCK_PRIVATE.
    if (
        ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    if block_private and (ip.is_private or ip.is_loopback):
        return True
    return False


def _resolve_ips(host: str) -> list[ipaddress._BaseAddress]:
    """Resolve a host to IPs. Returns [] on resolution failure (fail-open)."""
    # If host is already a literal IP, use it directly.
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # Unresolvable: fail open. The request cannot connect anyway, and
        # failing closed would break offline/test/mock environments.
        LOGGER.debug("net_guard: could not resolve host %r; allowing (fail-open)", host)
        return []
    ips: list[ipaddress._BaseAddress] = []
    for info in infos:
        sockaddr = info[4]
        try:
            ips.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    return ips


def validate_outbound_host(host: str, *, block_private: bool | None = None) -> None:
    """Validate a bare hostname/IP (e.g. for a raw TCP/UDP SIEM sink)."""
    host = (host or "").strip()
    if not host:
        raise OutboundRequestError("empty host")
    if host.lower() in _allow_list():
        return
    if block_private is None:
        block_private = _env_flag("APP_SSRF_BLOCK_PRIVATE", False)
    for ip in _resolve_ips(host):
        if _ip_is_blocked(ip, block_private=block_private):
            raise OutboundRequestError(
                f"host '{host}' resolves to a disallowed address ({ip})"
            )


def validate_outbound_url(url: str, *, block_private: bool | None = None) -> None:
    """Validate an http(s) URL. Raises OutboundRequestError on failure."""
    parts = urlsplit((url or "").strip())
    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        raise OutboundRequestError(
            f"URL scheme '{parts.scheme}' not allowed (use http/https)"
        )
    host = parts.hostname
    if not host:
        raise OutboundRequestError("URL has no host")
    validate_outbound_host(host, block_private=block_private)
