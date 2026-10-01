"""Cato Networks GraphQL API client - paced, read-only.

The Cato API is a single GraphQL endpoint authenticated with an
``x-api-key`` header. A collection issues only a handful of queries, but Cato
rate-limits each query type per account (a few requests per second at best),
so requests are sent one at a time with a minimum gap, and a rate-limit answer
is retried after a pause.

Scope
-----
Read-only. Only ``query`` documents are sent - never a ``mutation`` - so
Plexus stays a non-mutating observer of the Cato account.

Failures
--------
GraphQL reports most failures (unknown field, bad account ID, missing
permission) as HTTP 200 with an ``errors`` array, so both shapes are turned
into :class:`CatoApiError`. ``detail`` carries the message Cato returned,
which is what tells an operator why a query was refused.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

DEFAULT_BASE_URL = "https://api.catonetworks.com/api/v1/graphql2"
DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_REQUESTS_PER_SECOND = 1.0
DEFAULT_MAX_RETRIES = 4

# Regional endpoints are hosts under this domain (api.us1., api.eu1., ...).
CATO_API_DOMAIN = "catonetworks.com"

_MAX_RETRY_AFTER_SECONDS = 60.0
_MAX_DETAIL_CHARS = 300


class CatoApiError(RuntimeError):
    """A Cato API query failed.

    ``status_code`` is the HTTP status for HTTP-level failures (``None`` for
    transport errors and for GraphQL errors, which arrive as HTTP 200).
    ``graphql`` is true when Cato answered but refused the query; ``detail``
    is then Cato's own error message.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        graphql: bool = False,
        detail: str = "",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.graphql = graphql
        self.detail = detail


def is_cato_url(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host == CATO_API_DOMAIN or host.endswith("." + CATO_API_DOMAIN)


def validate_base_url(url: str) -> str:
    """Normalise and validate a Cato API URL.

    Raises ``ValueError`` unless it is https and under the Cato domain - the
    URL decides where the API key is sent, so it is never free-form.
    """
    cleaned = (url or "").strip().rstrip("/") or DEFAULT_BASE_URL
    if urlsplit(cleaned).scheme != "https" or not is_cato_url(cleaned):
        raise ValueError("base URL must be an https Cato API URL")
    return cleaned


def _is_rate_limit(message: str) -> bool:
    lowered = message.lower()
    return "rate limit" in lowered or "too many requests" in lowered


class CatoClient:
    """Reusable Cato API session for one API key.

    Construct with the *decrypted* key. Use as an async context manager, or
    call :meth:`close` when done.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        requests_per_second: float = DEFAULT_REQUESTS_PER_SECOND,
        max_retries: int = DEFAULT_MAX_RETRIES,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = validate_base_url(base_url)
        self._api_key = api_key
        self._timeout = timeout
        self._max_retries = max(0, int(max_retries))
        self._transport = transport  # injectable for tests (httpx.MockTransport)
        self._client: httpx.AsyncClient | None = None

        self._min_interval = 1.0 / max(0.1, float(requests_per_second))
        self._lock = asyncio.Lock()
        self._next_slot = 0.0

        # Counters surfaced in the snapshot's collection report.
        self.stats = {"requests": 0, "retries": 0, "rate_limited": 0}

    async def __aenter__(self) -> CatoClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # Redirects are never followed: the API key must only ever reach
            # the validated Cato host.
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=False,
                transport=self._transport,
            )
        return self._client

    async def _wait_for_slot(self) -> None:
        now = time.monotonic()
        start = max(now, self._next_slot)
        self._next_slot = start + self._min_interval
        if start > now:
            await asyncio.sleep(start - now)

    async def _post(self, name: str, query: str, variables: dict[str, Any]) -> httpx.Response | None:
        self.stats["requests"] += 1
        try:
            return await self._ensure_client().post(
                self._url,
                json={"query": query, "variables": variables, "operationName": name},
                headers={
                    "x-api-key": self._api_key,
                    "Accept": "application/json",
                    "User-Agent": "Plexus-CatoTopology/1.0",
                },
            )
        except httpx.HTTPError:
            return None

    async def query(self, name: str, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run one named GraphQL query and return its ``data`` object."""
        attempt = 0
        # One request at a time: Cato's limits are per query type and low.
        async with self._lock:
            while True:
                await self._wait_for_slot()
                resp = await self._post(name, query, variables or {})

                body: Any = None
                if resp is not None and resp.status_code < 400:
                    try:
                        body = resp.json()
                    except ValueError:
                        raise CatoApiError(f"Cato query {name} returned a non-JSON body") from None
                    errors = body.get("errors") if isinstance(body, dict) else None
                    if not errors:
                        data = body.get("data") if isinstance(body, dict) else None
                        return data if isinstance(data, dict) else {}
                    first = errors[0] if isinstance(errors, list) and errors else {}
                    detail = str((first.get("message") if isinstance(first, dict) else first) or "")
                    detail = detail[:_MAX_DETAIL_CHARS]
                    if not _is_rate_limit(detail) or attempt >= self._max_retries:
                        raise CatoApiError(f"Cato query {name} was refused", graphql=True, detail=detail)
                    rate_limited = True
                else:
                    rate_limited = resp is not None and resp.status_code == 429
                    retryable = resp is None or rate_limited or resp.status_code >= 500
                    if not retryable or attempt >= self._max_retries:
                        if resp is None:
                            raise CatoApiError(f"Cato query {name} failed: could not reach the API")
                        raise CatoApiError(
                            f"Cato query {name} -> HTTP {resp.status_code}",
                            status_code=resp.status_code,
                        )

                attempt += 1
                self.stats["retries"] += 1
                delay = min(2.0**attempt, 30.0)
                if rate_limited:
                    self.stats["rate_limited"] += 1
                    try:
                        delay = float(resp.headers.get("Retry-After", delay)) if resp is not None else delay
                    except ValueError:
                        pass
                    delay = min(max(delay, 2.0), _MAX_RETRY_AFTER_SECONDS)
                await asyncio.sleep(delay)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
