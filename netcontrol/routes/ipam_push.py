"""ipam_push.py -- Push inventory host IP allocations to external IPAM sources."""

from __future__ import annotations

import ipaddress

import routes.database as db

from netcontrol.routes.ipam_adapters import IpamAdapterError, push_allocation_to_provider
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.ipam.push")


def _normalize_host_ip(ip_address: str) -> str:
    raw = str(ip_address or "").strip()
    if not raw:
        return ""
    try:
        if "/" in raw:
            return str(ipaddress.ip_interface(raw).ip)
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


async def push_inventory_host_allocation(
    *,
    hostname: str,
    ip_address: str,
    source_hint: str = "inventory",
) -> dict:
    """Best-effort push of host allocation details to enabled external IPAM sources.

    Returns a summary dictionary and never raises provider failures to callers.
    """
    address = _normalize_host_ip(ip_address)
    if not address:
        return {"attempted": 0, "pushed": 0, "failed": 0}

    try:
        sources = await db.list_ipam_sources(enabled_only=True)
    except Exception as exc:  # pragma: no cover - defensive logging
        LOGGER.warning(
            "IPAM push skipped: failed to list sources for host_ip=%s error=%s",
            address,
            type(exc).__name__,
        )
        return {"attempted": 0, "pushed": 0, "failed": 1}
    push_sources = [
        src
        for src in sources
        if src.get("provider") != "plexus" and bool(src.get("push_enabled"))
    ]

    attempted = 0
    pushed = 0
    failed = 0
    for src in push_sources:
        source_id = int(src.get("id") or 0)
        if source_id <= 0:
            continue
        attempted += 1
        try:
            auth_config = await db.get_ipam_source_auth_config(source_id)
            description = f"Synced from Plexus ({source_hint})"
            await push_allocation_to_provider(
                src,
                auth_config,
                address=address,
                dns_name=str(hostname or "").strip(),
                description=description,
            )
            pushed += 1
        except IpamAdapterError as exc:
            failed += 1
            LOGGER.warning(
                "IPAM push adapter error: source_id=%s provider=%s host_ip=%s reason=%s",
                source_id,
                src.get("provider"),
                address,
                exc,
            )
        except Exception as exc:  # pragma: no cover - defensive logging
            failed += 1
            LOGGER.warning(
                "IPAM push failed: source_id=%s provider=%s host_ip=%s error=%s",
                source_id,
                src.get("provider"),
                address,
                type(exc).__name__,
            )

    return {"attempted": attempted, "pushed": pushed, "failed": failed}
