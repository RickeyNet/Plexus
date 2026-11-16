"""OPNsense API client - paced, read-only.

The API lives under ``https://<firewall>[:port]/api/<module>/<controller>/<command>``
and is authenticated with HTTP Basic: the API key is the user name and the
API secret the password (OPNsense "System: Access: Users", API keys). The
key and secret are sent only in the ``Authorization`` header, kept in
memory only and never stored or logged by this module.

Action names
------------
Since 24.7 the OPNsense router accepts an action both as ``camelCase`` and
as ``snake_case`` (``Mvc/Router.php`` turns ``get_routes`` into
``getRoutesAction``), and from 25.7 the privilege patterns of the access
control lists name the ``snake_case`` form (``api/diagnostics/interface/get_routes*``),
while 24.7 to 25.1 name the ``camelCase`` one. A user given only the
matching privilege is therefore refused (HTTP 403) on the other form.
:meth:`OpnsenseClient.get_first` tries the newer form first and falls back
to the older one on 403 or 404.

Scope
-----
Read-only: ``GET`` only, besides ``POST core/firmware/audit``, which starts
the built-in security audit (``pkg audit -F``), and ``POST
ipsec/sessions/search_phase2``, a search that reads the connection it lists
from the POST body. Neither changes a setting. The ARP / NDP tables
(``diagnostics/interface/search_arp``, ``search_ndp``; ``get_arp``,
``get_ndp`` on older releases) and the DHCP leases
(``dhcpv4/leases/search_lease``, ``dhcpv6/leases/search_lease``,
``kea/leases4/search``, ``kea/leases6/search``, ``dnsmasq/leases/search``)
are read with ``GET``; nothing that flushes a table or deletes a lease is
ever called.

Failures
--------
OPNsense answers a refused call with an HTML or JSON body; the ``message``
of a JSON body is kept as :attr:`OpnsenseApiError.detail`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from netcontrol.integrations.http_common import RequestPacer, retry_delay, validate_https_host

DEFAULT_TIMEOUT_SECONDS = 60.0
# The API is served by the firewall's own web server: a few requests a
# second keeps a collection from loading it.
DEFAULT_REQUESTS_PER_SECOND = 4.0
DEFAULT_MAX_RETRIES = 3

API_PATH = "/api"
USER_AGENT = "Plexus-OpnsenseTopology/1.0"

# The largest body read from the firewall (config.xml of a large firewall
# is a few megabytes).
MAX_BODY_BYTES = 32 * 1024 * 1024
_MAX_DETAIL_CHARS = 300


class OpnsenseApiError(RuntimeError):
    """An OPNsense API call failed.

    ``status_code`` is the HTTP status (``None`` when no answer came back or
    the answer could not be read). ``transport`` is true when the firewall
    could not be reached at all; ``detail`` is the message OPNsense answered
    with; ``path`` the API path that failed.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        detail: str = "",
        transport: bool = False,
        path: str = "",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail
        self.transport = transport
        self.path = path


def validate_base_url(url: str) -> str:
    """The firewall's web GUI address as ``https://host[:port]`` (a trailing
    ``/`` or ``/api`` is dropped). Raises ``ValueError`` otherwise."""
    return validate_https_host(url, "OPNsense", ignored_paths=(API_PATH,))


def split_credentials(secret: str) -> tuple[str, str]:
    """``(key, secret)`` of an entry's stored ``<API key>:<API secret>``,
    split on the first colon. Raises ``ValueError`` when either half is empty."""
    key, sep, value = (secret or "").strip().partition(":")
    key, value = key.strip(), value.strip()
    if not sep or not key or not value:
        raise ValueError("The OPNsense credential must be the API key and the API secret as key:secret")
    return key, value


def _detail(resp: httpx.Response | None) -> str:
    """The ``message`` (or ``errorMessage``) of a JSON error answer."""
    if resp is None or not resp.content:
        return ""
    try:
        body = resp.json()
    except ValueError:
        return ""
    if not isinstance(body, dict):
        return ""
    text = str(body.get("message") or body.get("errorMessage") or "").strip()
    return text[:_MAX_DETAIL_CHARS]


class OpnsenseClient:
    """Reusable OPNsense API session for one API key.

    Construct with the *decrypted* key and secret. Use as an async context
    manager, or call :meth:`close` when done.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        *,
        verify_tls: bool = True,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        requests_per_second: float = DEFAULT_REQUESTS_PER_SECOND,
        max_retries: int = DEFAULT_MAX_RETRIES,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = validate_base_url(base_url)
        self._auth = (api_key or "", api_secret or "")
        self._verify_tls = verify_tls
        self._timeout = timeout
        self._max_retries = max(0, int(max_retries))
        self._transport = transport  # injectable for tests (httpx.MockTransport)
        self._client: httpx.AsyncClient | None = None
        self._pacer = RequestPacer(requests_per_second)
        self._lock = asyncio.Lock()
        # Counters surfaced in the snapshot's collection report.
        self.stats = {"requests": 0, "retries": 0, "rate_limited": 0}

    async def __aenter__(self) -> OpnsenseClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # Redirects are never followed: the credentials must only ever
            # reach the validated firewall.
            self._client = httpx.AsyncClient(
                base_url=self.base_url + API_PATH,
                auth=httpx.BasicAuth(*self._auth),
                timeout=self._timeout,
                verify=self._verify_tls,
                follow_redirects=False,
                transport=self._transport,
                headers={"User-Agent": USER_AGENT},
            )
        return self._client

    async def _request(self, method: str, path: str, *, params: dict | None, body: dict | None) -> httpx.Response:
        """One call, answering the response. 429, 5xx and transport
        failures are retried with a backoff; anything else of 300 or more
        raises :class:`OpnsenseApiError`."""
        path = "/" + path.strip("/")
        attempt = 0
        while True:
            await self._pacer.wait()
            self.stats["requests"] += 1
            try:
                resp: httpx.Response | None = await self._ensure_client().request(
                    method,
                    path,
                    params=params,
                    json=body if method == "POST" else None,
                    headers={"Accept": "application/json, */*"},
                )
            except httpx.HTTPError:
                resp = None
            if resp is not None and resp.status_code < 300:
                if len(resp.content) > MAX_BODY_BYTES:
                    raise OpnsenseApiError(f"OPNsense {method} {path} answered with too large a body", path=path)
                return resp
            rate_limited = resp is not None and resp.status_code == 429
            retryable = resp is None or rate_limited or resp.status_code >= 500
            if not retryable or attempt >= self._max_retries:
                if resp is None:
                    raise OpnsenseApiError(
                        f"OPNsense {method} {path} failed: could not reach the firewall", transport=True, path=path
                    )
                raise OpnsenseApiError(
                    f"OPNsense {method} {path} -> HTTP {resp.status_code}",
                    status_code=resp.status_code,
                    detail=_detail(resp),
                    path=path,
                )
            attempt += 1
            self.stats["retries"] += 1
            if rate_limited:
                self.stats["rate_limited"] += 1
            retry_after = resp.headers.get("Retry-After") if resp is not None else None
            await asyncio.sleep(retry_delay(attempt, rate_limited=rate_limited, retry_after=retry_after))

    @staticmethod
    def _json(resp: httpx.Response, method: str, path: str) -> Any:
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            # OPNsense answers an unknown or refused action with its HTML
            # login or error page and HTTP 200 on some releases.
            raise OpnsenseApiError(
                f"OPNsense {method} /{path.strip('/')} answered with a body that is not JSON",
                status_code=resp.status_code,
                path="/" + path.strip("/"),
            ) from None

    async def get(self, path: str, params: dict | None = None) -> Any:
        """One ``GET`` under ``/api``, answering the parsed JSON body."""
        async with self._lock:
            resp = await self._request("GET", path, params=params, body=None)
        return self._json(resp, "GET", path)

    async def get_text(self, path: str) -> str:
        """One ``GET`` under ``/api``, answering the body as text (a file
        download such as ``config.xml``)."""
        async with self._lock:
            resp = await self._request("GET", path, params=None, body=None)
        return resp.text

    async def post(self, path: str, body: dict | None = None) -> Any:
        """One ``POST`` under ``/api`` (the security audit, and the IPsec
        phase 2 search, which reads its connection from the body)."""
        async with self._lock:
            resp = await self._request("POST", path, params=None, body=body or {})
        return self._json(resp, "POST", path)

    async def get_first(self, paths: tuple[str, ...] | list[str], params: dict | None = None) -> tuple[str, Any]:
        """``GET`` the first of ``paths`` that answers: the next is tried
        when one is refused (403) or unknown (404), or answers with a page
        that is not JSON. Answers ``(path, body)``; raises the error of the
        last path when none answers."""
        return await self._first(paths, lambda path: self.get(path, params))

    async def post_first(self, paths: tuple[str, ...] | list[str], body: dict | None = None) -> tuple[str, Any]:
        """``POST`` to the first of ``paths`` that answers, like
        :meth:`get_first`. Only for search calls that read their parameters
        from the POST body (``ipsec/sessions/search_phase2``): they change
        nothing."""
        return await self._first(paths, lambda path: self.post(path, body))

    @staticmethod
    async def _first(paths: tuple[str, ...] | list[str], call: Callable[[str], Awaitable[Any]]) -> tuple[str, Any]:
        last: OpnsenseApiError | None = None
        for path in paths:
            try:
                return path, await call(path)
            except OpnsenseApiError as exc:
                status = exc.status_code
                if status is None or not (status in (403, 404) or status < 300):
                    raise
                last = exc
        assert last is not None  # paths is never empty
        raise last

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
