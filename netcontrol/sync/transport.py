"""The HTTP JSON transport shared by the sync adapters and the IPAM / DHCP
provider adapters, and the value helpers they all use.

- ``request_json``: one guarded request (the SSRF pre-check of
  ``netcontrol.routes.outbound_http``), the JSON body back; a rejected
  target is raised as the caller's own error type.
- ``HttpJsonClient``: a connection to one API (base URL, auth, TLS trust)
  that paces its requests, retries 429 / 5xx with the shared back-off of
  ``netcontrol.integrations.http_common`` and raises ``SyncError`` with the
  status and a short excerpt of the body. The guard runs once, on the base
  URL, when the client opens; redirects are never followed.
- ``canonical_address`` / ``canonical_subnet`` / ``host_prefix_address``,
  ``coerce_list`` and ``nested_text``: normalising provider values.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

from netcontrol.integrations.http_common import RequestPacer, retry_delay
from netcontrol.routes import outbound_http
from netcontrol.routes.net_guard import OutboundRequestError

DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_ATTEMPTS = 3
BODY_EXCERPT = 300

Guard = Callable[[str], Awaitable[None]]


class SyncError(RuntimeError):
    """A connection, request or response problem; the message is safe to
    show (it never carries a credential)."""


# ── Values ───────────────────────────────────────────────────────────────────


def canonical_address(value: Any) -> str:
    """``192.0.2.10/24`` or ``192.0.2.10`` -> ``192.0.2.10``; ``""`` for an
    empty value. ``ValueError`` when it is not an address."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "/" in raw:
        return str(ipaddress.ip_interface(raw).ip)
    return str(ipaddress.ip_address(raw))


def canonical_subnet(value: Any) -> str:
    """``192.0.2.7/24`` -> ``192.0.2.0/24``; ``""`` for an empty value.
    ``ValueError`` when it is not a network."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    return str(ipaddress.ip_network(raw, strict=False))


def host_prefix_address(address: str) -> str:
    """An address with its host mask: ``/32`` for IPv4, ``/128`` for IPv6."""
    ip_obj = ipaddress.ip_address(address)
    return f"{address}/{ip_obj.max_prefixlen}"


def coerce_list(payload: Any, *keys: str) -> list[dict]:
    """The records of a list response: the payload itself when it is a list,
    else the first list under ``keys`` (default ``results``, ``data``,
    ``items``). Non-dict items are dropped."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in keys or ("results", "data", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def nested_text(value: Any, *keys: str) -> str:
    """The scalar at ``value[k1][k2]...`` as stripped text; ``""`` when a key
    is missing or the value is a dict, list or ``None``."""
    current = value
    for key in keys:
        current = current.get(key) if isinstance(current, dict) else None
    if isinstance(current, (dict, list)) or current is None:
        return ""
    return str(current).strip()


def clean_base_url(url: str, label: str = "API") -> str:
    """``https://host[:port][/path]`` without a trailing ``/``. A bare host is
    taken as https; plain http, an embedded user, a query or a fragment is
    refused (``ValueError``): the URL decides where the credentials go."""
    cleaned = (url or "").strip()
    if not cleaned:
        raise ValueError(f"{label} address is required")
    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"
    parts = urlsplit(cleaned)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"{label} address must be an https URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError(f"{label} address must not carry a user, a query or a fragment")
    try:
        port = parts.port
    except ValueError:
        raise ValueError(f"{label} address has an invalid port") from None
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port else "") + parts.path.rstrip("/")


# ── One request ──────────────────────────────────────────────────────────────


async def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    json_body: Any = None,
    auth: Any = None,
    verify: Any = True,
    timeout_s: float = DEFAULT_TIMEOUT_SECONDS,
    error_cls: type[Exception] = SyncError,
    json_content_only: bool = False,
) -> Any:
    """Guard ``url``, send one request and return its JSON body (``{}`` for
    an empty body, or with ``json_content_only`` for a non-JSON one). A
    rejected target raises ``error_cls("target URL rejected: ...")``; an
    HTTP error status raises ``httpx.HTTPStatusError``."""
    try:
        await outbound_http.guard_url(url)
    except OutboundRequestError as exc:
        raise error_cls(f"target URL rejected: {exc}") from exc
    async with httpx.AsyncClient(timeout=timeout_s, verify=verify, follow_redirects=False) as client:
        response = await client.request(method.upper(), url, headers=headers, params=params, json=json_body, auth=auth)
        response.raise_for_status()
        if not response.content:
            return {}
        if json_content_only and "json" not in (response.headers.get("content-type") or "").lower():
            return {}
        return response.json()


# ── A client for one API ─────────────────────────────────────────────────────


def _excerpt(response: httpx.Response) -> str:
    text = (response.text or "").strip().replace("\n", " ")
    return text[:BODY_EXCERPT] + ("..." if len(text) > BODY_EXCERPT else "")


class HttpJsonClient:
    """``async with HttpJsonClient(...) as client: await client.get(path)``.

    ``transport`` replaces the network (tests pass ``httpx.MockTransport``);
    ``guard`` is the SSRF check run on the base URL at open."""

    def __init__(
        self,
        base_url: str,
        *,
        headers: dict[str, str] | None = None,
        auth: Any = None,
        verify: Any = True,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        requests_per_second: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        guard: Guard | None = None,
        label: str = "API",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {"Accept": "application/json", **(headers or {})}
        self.auth = auth
        self.verify = verify
        self.timeout = timeout
        self.transport = transport
        self.guard = guard or outbound_http.guard_url
        self.label = label
        self._pacer = RequestPacer(requests_per_second)
        self._lock = asyncio.Lock()
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> HttpJsonClient:
        try:
            await self.guard(self.base_url)
        except OutboundRequestError as exc:
            raise SyncError(f"{self.label} address rejected: {exc}") from exc
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify,
            follow_redirects=False,
            transport=self.transport,
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def url(self, path: str) -> str:
        return path if path.startswith("https://") else f"{self.base_url}/{path.lstrip('/')}"

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        auth: Any = None,
    ) -> Any:
        """Send one request (retrying 429 and 5xx) and return the JSON body,
        ``{}`` when there is none. ``SyncError`` otherwise."""
        if self._client is None:
            raise RuntimeError("HttpJsonClient used outside 'async with'")
        url = self.url(path)
        if not url.startswith(self.base_url + "/"):
            raise SyncError(f"{self.label} request outside the connection address refused")
        attempt = 0
        while True:
            attempt += 1
            async with self._lock:
                await self._pacer.wait()
            try:
                response = await self._client.request(
                    method.upper(),
                    url,
                    params=params,
                    json=json_body,
                    data=data,
                    headers={**self.headers, **(headers or {})},
                    auth=auth if auth is not None else self.auth,
                )
            except httpx.HTTPError as exc:
                if attempt < MAX_ATTEMPTS:
                    await asyncio.sleep(retry_delay(attempt))
                    continue
                raise SyncError(f"{self.label} unreachable ({type(exc).__name__})") from exc
            status = response.status_code
            if (status == 429 or status >= 500) and attempt < MAX_ATTEMPTS:
                await asyncio.sleep(
                    retry_delay(attempt, rate_limited=status == 429, retry_after=response.headers.get("Retry-After"))
                )
                continue
            if status >= 400:
                raise SyncError(f"{self.label} answered HTTP {status}: {_excerpt(response)}".rstrip(": "))
            if not response.content:
                return {}
            try:
                return response.json()
            except ValueError as exc:
                raise SyncError(f"{self.label} answered with a body that is not JSON") from exc

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params=params)
