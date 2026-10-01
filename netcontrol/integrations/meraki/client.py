"""Meraki Dashboard API v1 client - rate limited, paginating, read-only.

Unlike the FDM client (one session per device), a :class:`MerakiClient` talks
to the Meraki cloud on behalf of one API key. The Dashboard API enforces
**10 requests/second per organization** and answers bursts with HTTP 429 +
``Retry-After``; a topology build issues thousands of calls, so pacing is the
client's job rather than each caller's:

  - a concurrency cap (``max_concurrency``) bounds in-flight requests
  - a slot scheduler spaces request starts to ``requests_per_second``
  - 429s honour ``Retry-After``; 5xx and transport errors back off and retry

Scope
-----
Read-only. Only GET is issued - Plexus stays a non-mutating observer of the
Meraki organization.

Redirects
---------
Meraki may redirect ``api.meraki.com`` to a shard host. httpx drops the
``Authorization`` header on cross-origin redirects, and blindly re-sending an
API key to whatever ``Location`` says would leak it, so redirects (and
pagination ``Link`` URLs) are followed manually and only to hosts under the
same Meraki domain as the configured base URL.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

DEFAULT_BASE_URL = "https://api.meraki.com/api/v1"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_CONCURRENCY = 5
# Stay under the 10 req/s org budget so other API consumers (dashboards,
# scripts) sharing the organization aren't starved during a build.
DEFAULT_REQUESTS_PER_SECOND = 8.0
DEFAULT_MAX_RETRIES = 5

# Regional Dashboard API domains. A base URL must sit under one of these, and
# redirects/pagination links must stay under the *same* one.
MERAKI_API_DOMAINS = (
    "meraki.com",
    "meraki.cn",
    "meraki.in",
    "meraki.ca",
    "gov-meraki.com",
)

_MAX_RETRY_AFTER_SECONDS = 60.0
_MAX_REDIRECTS = 4
_MAX_PAGES = 2000


class MerakiApiError(RuntimeError):
    """A Dashboard API call failed.

    ``status_code`` is the HTTP status when the failure was an HTTP response
    (``None`` for transport-level errors), so callers can tell "not
    applicable to this network" (400/404) from "key lacks access" (401/403)
    from "couldn't reach Meraki".
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def meraki_domain_for(url: str) -> str | None:
    """Return the Meraki API domain ``url`` belongs to, or ``None``."""
    host = (urlsplit(url).hostname or "").lower()
    for domain in MERAKI_API_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return domain
    return None


def validate_base_url(url: str) -> str:
    """Normalise and validate a Dashboard API base URL.

    Raises ``ValueError`` unless it is https and under a known Meraki domain -
    the base URL decides where the API key is sent, so it is never free-form.
    """
    cleaned = (url or "").strip().rstrip("/") or DEFAULT_BASE_URL
    parts = urlsplit(cleaned)
    if parts.scheme != "https" or not meraki_domain_for(cleaned):
        raise ValueError("base URL must be an https Meraki Dashboard API URL")
    return cleaned


class MerakiClient:
    """Reusable Dashboard API session for one API key.

    Construct with the *decrypted* key (decryption is the caller's job - this
    module stays free of DB/crypto deps so it is trivially unit-testable).
    Use as an async context manager, or call :meth:`close` when done.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
        requests_per_second: float = DEFAULT_REQUESTS_PER_SECOND,
        max_retries: int = DEFAULT_MAX_RETRIES,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = validate_base_url(base_url)
        self._domain = meraki_domain_for(self._base_url)
        self._api_key = api_key
        self._timeout = timeout
        self._max_retries = max(0, int(max_retries))
        self._transport = transport  # injectable for tests (httpx.MockTransport)
        self._client: httpx.AsyncClient | None = None

        self._sem = asyncio.Semaphore(max(1, int(max_concurrency)))
        self._min_interval = 1.0 / max(0.1, float(requests_per_second))
        self._slot_lock = asyncio.Lock()
        self._next_slot = 0.0

        # Counters surfaced in the snapshot's collection report.
        self.stats = {"requests": 0, "retries": 0, "rate_limited": 0}

    async def __aenter__(self) -> MerakiClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    # ── HTTP plumbing ──────────────────────────────────────────────────────

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=False,
                transport=self._transport,
            )
        return self._client

    async def _wait_for_slot(self) -> None:
        """Space request starts so the org rate budget is never exceeded."""
        async with self._slot_lock:
            now = time.monotonic()
            start = max(now, self._next_slot)
            self._next_slot = start + self._min_interval
        delay = start - now
        if delay > 0:
            await asyncio.sleep(delay)

    def _url_for(self, path: str) -> str:
        if path.startswith("https://"):
            return path
        return f"{self._base_url}/{path.lstrip('/')}"

    def _check_trusted(self, url: str) -> None:
        if urlsplit(url).scheme != "https" or meraki_domain_for(url) != self._domain:
            raise MerakiApiError("Meraki API pointed at an untrusted host; refusing to send the API key")

    async def _send(self, url: str, params: dict[str, Any] | None) -> httpx.Response:
        """Issue one GET, following same-domain redirects with auth intact."""
        client = self._ensure_client()
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
            "User-Agent": "Plexus-MerakiTopology/1.0",
        }
        for _hop in range(_MAX_REDIRECTS + 1):
            self._check_trusted(url)
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
                url = str(resp.url.join(resp.headers["location"]))
                params = None  # the Location already carries the query string
                continue
            return resp
        raise MerakiApiError("Meraki API redirect loop")

    async def _request(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        """GET with pacing + retry. Returns the successful response."""
        url = self._url_for(path)
        attempt = 0
        while True:
            async with self._sem:
                await self._wait_for_slot()
                self.stats["requests"] += 1
                try:
                    resp = await self._send(url, params)
                except httpx.HTTPError as exc:
                    resp = None
                    transport_error: Exception | None = exc
                else:
                    transport_error = None

            if resp is not None and resp.status_code < 400:
                return resp

            retryable = resp is None or resp.status_code == 429 or resp.status_code >= 500
            if not retryable or attempt >= self._max_retries:
                if resp is None:
                    raise MerakiApiError(
                        f"Meraki GET {path} failed: {type(transport_error).__name__}"
                    ) from transport_error
                raise MerakiApiError(
                    f"Meraki GET {path} -> HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )

            attempt += 1
            self.stats["retries"] += 1
            delay = min(2.0**attempt, 30.0)
            if resp is not None and resp.status_code == 429:
                self.stats["rate_limited"] += 1
                try:
                    delay = float(resp.headers.get("Retry-After", delay))
                except ValueError:
                    pass
                delay = min(max(delay, 1.0), _MAX_RETRY_AFTER_SECONDS)
            await asyncio.sleep(delay)

    @staticmethod
    def _decode(resp: httpx.Response, path: str) -> Any:
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            raise MerakiApiError(f"Meraki GET {path} returned a non-JSON body") from exc

    # ── Request surface ────────────────────────────────────────────────────

    async def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """GET one resource and return the decoded JSON body."""
        return self._decode(await self._request(path, params), path)

    async def get_all(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        per_page: int | None = None,
    ) -> list[Any]:
        """GET a paginated list, following ``Link: rel=next`` to the end.

        Non-paginated endpoints (no Link header) return their single page. A
        dict-shaped page (some org endpoints wrap rows in ``{"items": [...]}``)
        contributes its ``items``.
        """
        query = dict(params or {})
        if per_page:
            query["perPage"] = per_page
        items: list[Any] = []
        url: str = path
        page_params: dict[str, Any] | None = query or None
        for _page in range(_MAX_PAGES):
            resp = await self._request(url, page_params)
            body = self._decode(resp, path)
            if isinstance(body, list):
                items.extend(body)
            elif isinstance(body, dict) and isinstance(body.get("items"), list):
                items.extend(body["items"])
            elif body is not None:
                items.append(body)
            next_url = (resp.links.get("next") or {}).get("url")
            if not next_url:
                break
            url = str(resp.url.join(next_url))
            page_params = None  # the next URL already carries the cursor
        return items

    # ── Teardown ───────────────────────────────────────────────────────────

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
