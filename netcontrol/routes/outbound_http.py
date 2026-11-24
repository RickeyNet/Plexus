"""
outbound_http.py -- The one HTTP sender for admin-configured outbound targets.

Notification webhooks, Teams cards, SIEM HTTPS sinks, event webhooks,
federation peers, secrets providers and the ChatOps adapters all send to a
URL an admin typed in. Each of them needs the same things: the SSRF
pre-check from ``net_guard``, the TLS trust choice (system CAs, a pinned PEM
bundle, or verification off), an ``httpx`` request that never follows a
redirect (a redirect would skip the SSRF check on its target), and a
connection to the address the check approved (``PinnedTransport``), so a
second DNS answer cannot send the request somewhere else. They live here
once and every sender imports them.
"""

from __future__ import annotations

import asyncio
import ssl
import urllib.request
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit

import httpx

from netcontrol.routes.net_guard import IPAddress, OutboundRequestError, validate_outbound_host, validate_outbound_url

__all__ = [
    "OutboundRequestError",
    "PinnedTransport",
    "ResponseTooLargeError",
    "guard_host",
    "guard_url",
    "send_request",
    "tls_verify",
]


class ResponseTooLargeError(httpx.HTTPError):
    """The target answered with more than the caller's ``max_bytes``."""


async def guard_url(url: str) -> list[IPAddress]:
    """SSRF pre-check. Returns the approved addresses of the URL's host;
    raises ``OutboundRequestError`` for a disallowed target.

    Runs in a thread because the check resolves the host name."""
    return await asyncio.to_thread(validate_outbound_url, url)


async def guard_host(host: str) -> list[IPAddress]:
    """``guard_url`` for a bare host name or address (an SMTP, syslog or
    directory server). Raises ``OutboundRequestError`` when it is refused."""
    return await asyncio.to_thread(validate_outbound_host, host)


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


# How many approved addresses of one name a request tries before giving up
# (each attempt may take the whole connect timeout).
MAX_PINNED_ADDRESSES = 3


class PinnedTransport(httpx.AsyncBaseTransport):
    """Sends each request for ``host`` to one of its approved addresses
    ``ips``: the first that accepts the connection (at most
    ``MAX_PINNED_ADDRESSES`` are tried, in order, so a name with an
    unreachable IPv6 answer still works over IPv4). Only a failed connect
    moves on to the next address; nothing was sent then.

    The request URL keeps its name for everything but the TCP connection:
    the ``Host`` header is the name, and for https the TLS server name (SNI)
    and the certificate check use the name too (httpcore's ``sni_hostname``
    extension). A request for any other host is refused: the sender never
    follows redirects, so one would only come from a bug."""

    def __init__(self, host: str, ips: Sequence[IPAddress], inner: httpx.AsyncBaseTransport) -> None:
        if not ips:
            raise ValueError("PinnedTransport needs at least one approved address")
        self._host = host.lower().rstrip(".")
        self._ips = [str(ip) for ip in ips][:MAX_PINNED_ADDRESSES]
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host.lower().rstrip(".") != self._host:
            raise OutboundRequestError(f"request to '{request.url.host}' does not match the checked host")
        extensions = dict(request.extensions)
        if request.url.scheme == "https":
            extensions.setdefault("sni_hostname", request.url.raw_host.decode("ascii"))
        for index, ip in enumerate(self._ips):
            pinned = httpx.Request(
                request.method,
                request.url.copy_with(host=ip),
                headers=request.headers,  # carries Host: <name>
                stream=request.stream,
                extensions=extensions,
            )
            try:
                return await self._inner.handle_async_request(pinned)
            except httpx.ConnectError, httpx.ConnectTimeout:
                if index == len(self._ips) - 1:
                    raise
        raise AssertionError("unreachable")  # pragma: no cover - the loop returns or raises

    async def aclose(self) -> None:
        await self._inner.aclose()


def _env_proxy_applies(url: str) -> bool:
    """Whether ``httpx`` would send ``url`` through a proxy from the
    environment (``HTTPS_PROXY`` and the like, minus ``NO_PROXY``). Such a
    request is not pinned: the proxy resolves and connects."""
    parts = urlsplit(url)
    proxies = urllib.request.getproxies()
    if not (proxies.get(parts.scheme.lower()) or proxies.get("all")):
        return False
    host = (parts.hostname or "").lower()
    for entry in str(proxies.get("no") or "").split(","):
        entry = entry.strip().lower().lstrip(".")
        if entry == "*" or (entry and (host == entry or host.endswith("." + entry))):
            return False
    return True


async def send_request(
    method: str,
    url: str,
    *,
    content: bytes | str | None = None,
    data: dict[str, Any] | None = None,
    json: Any = None,
    headers: dict[str, str] | None = None,
    verify: Any = True,
    timeout_s: float = 10.0,
    transport: httpx.AsyncBaseTransport | None = None,
    max_bytes: int | None = None,
    total_timeout_s: float | None = None,
) -> httpx.Response:
    """Guard ``url``, then send one request to an address the guard
    approved (``PinnedTransport``); redirects are never followed.

    Raises ``OutboundRequestError`` when the target is rejected and the
    ``httpx`` error on a transport failure. The caller judges the status.
    ``data`` is a form body (``application/x-www-form-urlencoded``).
    ``transport`` replaces the network layer (tests pass an
    ``httpx.MockTransport``); nothing is pinned then, as nothing connects.
    A request sent through an environment proxy is not pinned either.

    ``max_bytes`` bounds the decoded response body: it is read in chunks
    and ``ResponseTooLargeError`` (an ``httpx.HTTPError``) is raised past
    the limit, before the rest is read. ``timeout_s`` is httpx's timeout
    per connect / read / write, so a target that sends a byte now and
    then never trips it; ``total_timeout_s`` bounds the whole exchange
    (``TimeoutError``). A caller that reads a body it does not control
    in size passes both."""
    ips = await guard_url(url)
    if transport is None and ips and not _env_proxy_applies(url):
        host = httpx.URL(url).host
        transport = PinnedTransport(host, ips, httpx.AsyncHTTPTransport(verify=verify))
    async with httpx.AsyncClient(
        timeout=timeout_s, verify=verify, follow_redirects=False, transport=transport
    ) as client:
        request = client.build_request(
            method.upper(), url, content=content, data=data, json=json, headers=headers
        )
        async with asyncio.timeout(total_timeout_s):
            if max_bytes is None:
                return await client.send(request)
            return await _send_bounded(client, request, max_bytes)


async def _send_bounded(client: httpx.AsyncClient, request: httpx.Request, max_bytes: int) -> httpx.Response:
    """Send ``request`` and read at most ``max_bytes`` of decoded body."""
    streamed = await client.send(request, stream=True)
    try:
        body = bytearray()
        async for chunk in streamed.aiter_bytes():
            body += chunk
            if len(body) > max_bytes:
                raise ResponseTooLargeError(f"The response is larger than {max_bytes} bytes")
    finally:
        await streamed.aclose()
    # The body above is already decoded: drop the headers that describe
    # the bytes on the wire so the response is not decoded a second time.
    headers = [
        (name, value)
        for name, value in streamed.headers.multi_items()
        if name.lower() not in ("content-encoding", "content-length", "transfer-encoding")
    ]
    return httpx.Response(streamed.status_code, headers=headers, content=bytes(body), request=request)
