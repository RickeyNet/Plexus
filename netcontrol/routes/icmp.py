"""
icmp.py -- Shared ICMP (ping) infrastructure.

Provides async ICMP liveness probes used by the monitoring poll loop
and the inventory discovery sweep.  Unlike snmp.py this module owns no
HTTP routes; it is a pure helper layer.

icmplib runs unprivileged on both Linux (via SOCK_DGRAM) and Windows
(via IcmpSendEcho2), so the Plexus process does not need to be elevated
to use it.  When elevated, callers can opt into raw-socket mode for a
small latency improvement by passing privileged=True.
"""
from __future__ import annotations

import asyncio
import socket

from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.icmp")

try:
    from icmplib import async_ping
    ICMP_AVAILABLE = True
except Exception:
    async_ping = None
    ICMP_AVAILABLE = False


async def ping_host(
    ip_address: str,
    *,
    count: int = 3,
    timeout: float = 2.0,  # noqa: ASYNC109 - forwarded to icmplib's own timeout
    privileged: bool = False,
) -> dict:
    """Send ICMP echo requests and return a normalized result dict.

    The result shape mirrors the fields already present on a monitoring
    poll record so callers can splat values directly into result dicts
    without translation:

        {
          "alive": bool,
          "rtt_ms": float | None,       # average RTT across replies
          "packet_loss_pct": float,     # 0.0–100.0
          "packets_sent": int,
          "packets_received": int,
          "error": str,                 # empty when no transport error
        }

    A host that responds to at least one echo is "alive" even if some
    packets were lost - partial loss is reflected in packet_loss_pct.
    """
    out = {
        "alive": False,
        "rtt_ms": None,
        "packet_loss_pct": 100.0,
        "packets_sent": count,
        "packets_received": 0,
        "error": "",
    }
    if not ICMP_AVAILABLE:
        out["error"] = "icmplib not installed"
        return out

    try:
        host = await async_ping(
            ip_address,
            count=count,
            timeout=timeout,
            privileged=privileged,
        )
    except Exception as exc:
        out["error"] = str(exc)
        return out

    out["alive"] = bool(host.is_alive)
    out["packets_sent"] = host.packets_sent
    out["packets_received"] = host.packets_received
    out["packet_loss_pct"] = round(host.packet_loss * 100.0, 1)
    if host.packets_received > 0:
        out["rtt_ms"] = round(float(host.avg_rtt), 2)
    return out


async def _probe_discovery_target_icmp(
    ip_address: str,
    timeout_seconds: float,
    hostname_prefix: str = "host",
) -> dict | None:
    """ICMP fallback for the discovery sweep.

    Returns a discovery-shaped dict when the host responds to ping,
    or None when it does not (so the caller's gather() can filter it
    out the same way the SNMP/TCP probes do).

    A successful ICMP probe yields the bare minimum: an IP, a reverse-
    DNS hostname when one resolves, and device_type="icmp_only" so the
    monitoring loop knows not to attempt SNMP/SSH against it.
    """
    result = await ping_host(ip_address, count=2, timeout=timeout_seconds)
    if not result["alive"]:
        return None

    try:
        # Reverse DNS blocks for the resolver timeout; keep it off the loop.
        hostname = (await asyncio.to_thread(socket.gethostbyaddr, ip_address))[0]
    except Exception:
        hostname = f"{hostname_prefix}-{ip_address.replace('.', '-')}"

    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "device_type": "icmp_only",
        "status": "online",
        "discovery": {
            "protocol": "icmp",
            "port": 0,
            "vendor": "unknown",
            "os": "unknown",
            "rtt_ms": result["rtt_ms"],
            "packet_loss_pct": result["packet_loss_pct"],
        },
    }
