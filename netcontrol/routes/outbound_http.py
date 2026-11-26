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
from collections.abc import Iterable, Sequence
from typing import Any
from urllib.parse import urlsplit

import httpx

from netcontrol.routes.net_guard import IPAddress, OutboundRequestError, validate_outbound_host, validate_outbound_url
from netcontrol.telemetry import redact_text

__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DELIVERY_ERROR_MAX_CHARS",
    "DELIVERY_RESPONSE_MAX_BYTES",
    "ExchangeTimeoutError",
    "OutboundRequestError",
    "PinnedTransport",
    "ResponseTooLargeError",
    "delivery_error_text",
    "guard_host",
    "guard_url",
    "send_request",
    "tls_verify",
]


# The most decoded response body ``send_request`` reads when the caller
# names no limit of its own.
DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
# For a sender that only delivers (a notification, a log event, a webhook)
# and keeps the status and a short excerpt of the answer.
DELIVERY_RESPONSE_MAX_BYTES = 64 * 1024
# The most characters of a failed delivery such a sender keeps.
DELIVERY_ERROR_MAX_CHARS = 500
# Without a ``total_timeout_s`` the whole exchange gets this many times
# ``timeout_s``, and at least the floor.
TOTAL_TIMEOUT_FACTOR = 6
MIN_TOTAL_TIMEOUT_SECONDS = 30.0


class ResponseTooLargeError(httpx.HTTPError):
    """The target answered with more than the caller's ``max_bytes``."""


class ExchangeTimeoutError(httpx.TimeoutException, TimeoutError):
    """The whole exchange took longer than its deadline. Both an ``httpx``
    timeout, so a caller's transport-failure handling covers it, and a
    ``TimeoutError``."""


def delivery_error_text(exc: BaseException, secrets: Iterable[str] = ()) -> str:
    """What a sender keeps of a failed delivery for its status page, its
    test result and the audit trail: the exception's type and message. The
    message may quote the receiver's reply, and a receiver can echo what it
    was sent, so each of ``secrets`` (the secret values stored for the
    target) is removed by value, the rest gets the redaction of a log line
    (``telemetry.redact_text``), and the text is cut to
    ``DELIVERY_ERROR_MAX_CHARS``."""
    return redact_text(f"{type(exc).__name__}: {exc}", secrets)[:DELIVERY_ERROR_MAX_CHARS]


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
    max_bytes: int | None = DEFAULT_MAX_RESPONSE_BYTES,
    total_timeout_s: float | None = None,
    truncate: bool = False,
) -> httpx.Response:
    """Guard ``url``, then send one request to an address the guard
    approved (``PinnedTransport``); redirects are never followed.

    Raises ``OutboundRequestError`` when the target is rejected and the
    ``httpx`` error on a transport failure. The caller judges the status.
    ``data`` is a form body (``application/x-www-form-urlencoded``).
    ``transport`` replaces the network layer (tests pass an
    ``httpx.MockTransport``); nothing is pinned then, as nothing connects.
    A request sent through an environment proxy is not pinned either.

    ``max_bytes`` bounds the decoded response body
    (``DEFAULT_MAX_RESPONSE_BYTES`` unless the caller names a limit; ``None``
    reads it whole): it is read in chunks and ``ResponseTooLargeError`` (an
    ``httpx.HTTPError``) is raised past the limit, before the rest is read.
    With ``truncate`` the body is cut at the limit instead and the response
    is returned: for a sender that judges the status and keeps an excerpt,
    where a long answer to a delivered message is not a failure.

    ``timeout_s`` is httpx's timeout per connect / read / write, so a target
    that sends a byte now and then never trips it; ``total_timeout_s``
    bounds the whole exchange (``ExchangeTimeoutError``). Left out, it is
    ``TOTAL_TIMEOUT_FACTOR`` times ``timeout_s`` and at least
    ``MIN_TOTAL_TIMEOUT_SECONDS``."""
    deadline = (
        total_timeout_s
        if total_timeout_s is not None
        else max(MIN_TOTAL_TIMEOUT_SECONDS, timeout_s * TOTAL_TIMEOUT_FACTOR)
    )
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
        try:
            async with asyncio.timeout(deadline):
                if max_bytes is None:
                    return await client.send(request)
                return await _send_bounded(client, request, max_bytes, truncate)
        except TimeoutError as exc:
            # httpx's own timeouts are not ``TimeoutError``: this is the deadline.
            raise ExchangeTimeoutError(f"No complete answer within {deadline:g} seconds", request=request) from exc


async def _send_bounded(
    client: httpx.AsyncClient, request: httpx.Request, max_bytes: int, truncate: bool = False
) -> httpx.Response:
    """Send ``request`` and read at most ``max_bytes`` of decoded body: past
    it the response is refused, or cut there with ``truncate``."""
    streamed = await client.send(request, stream=True)
    try:
        body = bytearray()
        async for chunk in streamed.aiter_bytes():
            body += chunk
            if len(body) > max_bytes:
                if not truncate:
                    raise ResponseTooLargeError(f"The response is larger than {max_bytes} bytes")
                del body[max_bytes:]
                break
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
