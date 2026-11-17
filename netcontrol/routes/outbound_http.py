"""
outbound_http.py -- The one HTTP sender for admin-configured outbound targets.

Notification webhooks, Teams cards, SIEM HTTPS sinks and event webhooks all
POST to a URL an admin typed in. Each of them needs the same three things:
the SSRF pre-check from ``net_guard``, the TLS trust choice (system CAs, a
pinned PEM bundle, or verification off), and an ``httpx`` request that never
follows a redirect (a redirect would skip the SSRF check on its target).
They live here once and every sender imports them.
"""

from __future__ import annotations

import asyncio
import ssl
from typing import Any

import httpx

from netcontrol.routes.net_guard import OutboundRequestError, validate_outbound_url

__all__ = ["OutboundRequestError", "guard_url", "send_request", "tls_verify"]


async def guard_url(url: str) -> None:
    """SSRF pre-check. Raises ``OutboundRequestError`` for a disallowed target.

    Runs in a thread because the check resolves the host name."""
    await asyncio.to_thread(validate_outbound_url, url)


def tls_verify(verify: bool = True, ca_pem: str = "") -> Any:
    """The ``verify`` value for ``httpx``: ``False`` when verification is off,
    an ``SSLContext`` trusting only ``ca_pem`` when one is given, else
    ``True`` (the system trust store). Raises ``ssl.SSLError`` for a PEM
    bundle that does not parse."""
    if not verify:
        return False
    if (ca_pem or "").strip():
        return ssl.create_default_context(cadata=ca_pem)
    return True


async def send_request(
    method: str,
    url: str,
    *,
    content: bytes | str | None = None,
    json: Any = None,
    headers: dict[str, str] | None = None,
    verify: Any = True,
    timeout_s: float = 10.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> httpx.Response:
    """Guard ``url`` and send one request; redirects are never followed.

    Raises ``OutboundRequestError`` when the target is rejected and the
    ``httpx`` error on a transport failure. The caller judges the status.
    ``transport`` replaces the network layer (tests pass an
    ``httpx.MockTransport``)."""
    await guard_url(url)
    async with httpx.AsyncClient(
        timeout=timeout_s, verify=verify, follow_redirects=False, transport=transport
    ) as client:
        return await client.request(method.upper(), url, content=content, json=json, headers=headers)
