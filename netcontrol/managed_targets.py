"""Which request-supplied addresses are inventory hosts a caller may use.

Some actions send a stored secret to whatever device answers at an address:
a job whose template or inputs use secret variables, or discovery signing
in with the Plexus service credential. An address typed into the request
may be a device the caller controls, so for a non-admin caller these
actions are confined to inventory hosts the caller may change (their
primary IP address). Admins and the server API token are not limited.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Any

import routes.database as db

from netcontrol.object_scope import readable_host_ids


def _address_key(value: object) -> str:
    """``value`` as a comparable address: the canonical IP text, else the
    trimmed lower-case string (so ``2001:DB8::1`` matches ``2001:db8::1``)."""
    text = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.lower()


async def unmanaged_addresses(addresses: Iterable[str], scope_or_request: Any) -> list[str]:
    """The entries of ``addresses`` that are not the primary IP address of
    an inventory host the caller (a request, or an ``ObjectScope``) may
    change. Any inventory host counts for an unrestricted scope. Order and
    duplicates of ``addresses`` are kept; blanks are skipped."""
    wanted = [str(a).strip() for a in addresses if str(a or "").strip()]
    if not wanted:
        return []
    writable = await readable_host_ids(scope_or_request, write=True)
    known = {
        _address_key(host.get("ip_address"))
        for host in await db.get_all_hosts()
        if host.get("ip_address") and (writable is None or int(host["id"]) in writable)
    }
    return [address for address in wanted if _address_key(address) not in known]
