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

TLS contexts and connection pools are reused across requests (see
``cached_ssl_context`` and ``_POOLED_TRANSPORTS``); every request is still
checked and pinned on its own.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import threading
import urllib.request
import weakref
from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import Any
from urllib.parse import urlsplit

import httpx

from netcontrol.bounded_map import BoundedDict
from netcontrol.client_cache import ClientCache, fingerprint
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
    "cached_ssl_context",
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
    bundle that does not parse.

    The context for a bundle is built once and shared (``cached_ssl_context``):
    loading the bundle is the slow part of a request, and the context is
    never changed after it is built."""
    if not verify:
        return False
    if (ca_pem or "").strip():
        return cached_ssl_context(("ca_pem", fingerprint(ca_pem)), lambda: ssl.create_default_context(cadata=ca_pem))
    return True


# Built TLS contexts, keyed by everything that shapes them (the trust choice,
# a hash of the CA bundle and of any client certificate and key). A context
# is only read once built, so one serves every connection that has the same
# settings; ``_POOLABLE_CONTEXTS`` marks the ones built here.
_SSL_CONTEXTS: BoundedDict = BoundedDict(64)
_SSL_CONTEXTS_LOCK = threading.Lock()
_POOLABLE_CONTEXTS: weakref.WeakSet[ssl.SSLContext] = weakref.WeakSet()


def cached_ssl_context(key: tuple[object, ...], build: Callable[[], ssl.SSLContext]) -> ssl.SSLContext:
    """The ``SSLContext`` cached under ``key``, built by ``build`` on the
    first call. ``key`` must name every input of ``build`` that shapes the
    context, with secrets and bundles as ``client_cache.fingerprint``
    hashes. A ``build`` that raises caches nothing."""
    with _SSL_CONTEXTS_LOCK:
        ctx = _SSL_CONTEXTS.get(key)
    if ctx is not None:
        return ctx
    built = build()
    with _SSL_CONTEXTS_LOCK:
        ctx = _SSL_CONTEXTS.get(key)
        if ctx is None:  # else another thread built it first
            ctx = _SSL_CONTEXTS[key] = built
            _POOLABLE_CONTEXTS.add(ctx)
    return ctx


def _system_trust_context() -> ssl.SSLContext:
    """What ``httpx`` builds for ``verify=True`` (its CA bundle, or the one
    ``SSL_CERT_FILE`` / ``SSL_CERT_DIR`` names), built once instead of per
    request."""
    env = (os.environ.get("SSL_CERT_FILE") or "", os.environ.get("SSL_CERT_DIR") or "")
    return cached_ssl_context(("httpx-default", *env), lambda: httpx.create_ssl_context(verify=True))


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
    follows redirects, so one would only come from a bug.

    Closing this transport closes ``inner``, unless ``on_close`` is given:
    then that runs instead, once (a pooled transport that outlives the
    request is handed back, not closed)."""

    def __init__(
        self,
        host: str,
        ips: Sequence[IPAddress],
        inner: httpx.AsyncBaseTransport,
        *,
        on_close: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        if not ips:
            raise ValueError("PinnedTransport needs at least one approved address")
        self._host = host.lower().rstrip(".")
        self._ips = [str(ip) for ip in ips][:MAX_PINNED_ADDRESSES]
        self._inner = inner
        self._on_close = on_close or inner.aclose
        self._closed = False

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
        if not self._closed:
            self._closed = True
            await self._on_close()


class _SharedPool:
    """A connection pool shared by pinned requests, and how many of them use
    it now. The cache retires a pool it drops (idle, past the entry limit or
    at shutdown); a retired pool is closed when its last request ends, so
    dropping a pool never cuts off a request in flight. Leased and released
    on the event loop only."""

    def __init__(self, verify: Any) -> None:
        self.transport = httpx.AsyncHTTPTransport(verify=verify)
        self._leases = 0
        self._retired = False

    def lease(self) -> None:
        self._leases += 1

    async def release(self) -> None:
        self._leases -= 1
        if self._retired and self._leases <= 0:
            await self.transport.aclose()

    async def retire(self) -> None:
        self._retired = True
        if self._leases <= 0:
            await self.transport.aclose()


# The connection pools behind pinned requests, reused across requests. A
# pool is keyed by everything a connection in it was opened with: the event
# loop, the scheme, the host name (the TLS server name and certificate
# check), the port, the exact approved addresses and the TLS context. So a
# pooled connection only ever serves the name it was verified for, under the
# same TLS settings, and only while today's check approves exactly the
# addresses it was opened to: a different answer gets a new pool. Headers,
# credentials and cookies stay per request (a new ``AsyncClient`` each time).
_POOLED_TRANSPORTS: ClientCache[_SharedPool] = ClientCache(
    "outbound_http",
    max_entries=64,
    max_idle_s=60.0,
    close=lambda pool: pool.retire(),
)


def _pool_key(url: httpx.URL, ips: Sequence[IPAddress], verify: Any) -> tuple[object, ...] | None:
    """The ``_POOLED_TRANSPORTS`` key for a pinned request, or ``None`` when
    its TLS choice is a context this module did not build (a caller's own,
    possibly changed later): such a request gets a transport of its own."""
    if not isinstance(verify, bool) and verify not in _POOLABLE_CONTEXTS:
        return None
    return (
        asyncio.get_running_loop(),
        url.scheme,
        url.host.lower().rstrip("."),
        url.port,
        tuple(str(ip) for ip in ips[:MAX_PINNED_ADDRESSES]),
        verify,
    )


def _pinned_transport(url: str, ips: Sequence[IPAddress], verify: Any) -> PinnedTransport:
    """A ``PinnedTransport`` for ``url`` over a pooled connection pool when
    one fits (``_pool_key``), else over a new one it owns."""
    parsed = httpx.URL(url)
    key = _pool_key(parsed, ips, verify)
    if key is None:
        return PinnedTransport(parsed.host, ips, httpx.AsyncHTTPTransport(verify=verify))
    pool = _POOLED_TRANSPORTS.get(key, key, lambda: _SharedPool(verify))
    # Held until the request's client closes (``PinnedTransport.aclose``).
    pool.lease()
    return PinnedTransport(parsed.host, ips, pool.transport, on_close=pool.release)


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
    if verify is True:
        # Same trust as httpx's own default, without reloading the bundle.
        verify = _system_trust_context()
    if transport is None and ips and not _env_proxy_applies(url):
        transport = _pinned_transport(url, ips, verify)
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
