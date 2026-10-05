"""Cisco Secure Firewall Management Center (FMC) REST API client - paced, read-only.

The FMC API authenticates with a username and password once
(``POST /api/fmc_platform/v1/auth/generatetoken``, HTTP basic auth) and
answers with an ``X-auth-access-token`` header that every later request
carries. The token lives 30 minutes, far longer than a collection, so a
collection logs in once and only logs in again if the FMC answers 401.

FMC allows about 120 requests per minute per user, so requests are sent one
at a time with a minimum gap, and a rate-limit (429) or server error is
retried after a pause.

Scope
-----
Read-only. Only ``GET`` requests follow the login - Plexus stays a
non-mutating observer of the FMC and never deploys or edits a policy.

Failures
--------
An FMC error body is ``{"error": {"messages": [{"description": ...}]}}``;
its description is kept as ``FmcApiError.detail``, which is what tells an
operator why a request was refused (a missing role, an unknown domain).
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

DEFAULT_TIMEOUT_SECONDS = 60.0
# FMC's documented limit is 120 requests per minute per user.
DEFAULT_REQUESTS_PER_SECOND = 1.5
DEFAULT_MAX_RETRIES = 3

PLATFORM_PATH = "/api/fmc_platform/v1"
CONFIG_PATH = "/api/fmc_config/v1"
TOKEN_PATH = f"{PLATFORM_PATH}/auth/generatetoken"

# The largest page FMC serves.
PAGE_LIMIT = 1000
_MAX_PAGES = 200
_MAX_RETRY_AFTER_SECONDS = 60.0
_MAX_DETAIL_CHARS = 300


class FmcApiError(RuntimeError):
    """An FMC API request failed.

    ``status_code`` is the HTTP status for HTTP-level failures (``None`` for
    transport errors). ``detail`` is the description FMC answered with, when
    it gave one.
    """

    def __init__(self, message: str, *, status_code: int | None = None, detail: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail


def validate_base_url(url: str) -> str:
    """Normalise and validate the FMC address.

    Accepts ``https://host[:port]`` (a bare host is taken as https) and
    returns just that: the URL decides where the credentials are sent, so no
    path, query or embedded user is allowed, and ``http`` is refused.
    Raises ``ValueError`` otherwise.
    """
    cleaned = (url or "").strip()
    if not cleaned:
        raise ValueError("FMC address is required")
    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"
    parts = urlsplit(cleaned)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("FMC address must be an https URL")
    if parts.username or parts.password or parts.query or parts.fragment or parts.path.strip("/"):
        raise ValueError("FMC address must be the host only")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("FMC address has an invalid port") from None
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port else "")


def _error_detail(resp: httpx.Response | None) -> str:
    if resp is None:
        return ""
    try:
        body = resp.json()
    except ValueError:
        return ""
    error = body.get("error") if isinstance(body, dict) else None
    messages = error.get("messages") if isinstance(error, dict) else None
    first = messages[0] if isinstance(messages, list) and messages else None
    text = first.get("description") if isinstance(first, dict) else first
    return str(text or "").strip()[:_MAX_DETAIL_CHARS]


class FmcClient:
    """Reusable FMC API session for one set of credentials.

    Construct with the *decrypted* password. Use as an async context manager,
    or call :meth:`close` when done. ``login`` runs on the first request;
    call it directly to learn the domains the account can see.
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        verify_tls: bool = True,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        requests_per_second: float = DEFAULT_REQUESTS_PER_SECOND,
        max_retries: int = DEFAULT_MAX_RETRIES,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = validate_base_url(base_url)
        self._username = username
        self._password = password
        self._verify_tls = verify_tls
        self._timeout = timeout
        self._max_retries = max(0, int(max_retries))
        self._transport = transport  # injectable for tests (httpx.MockTransport)
        self._client: httpx.AsyncClient | None = None

        self._min_interval = 1.0 / max(0.1, float(requests_per_second))
        self._lock = asyncio.Lock()
        self._next_slot = 0.0
        self._token: str | None = None

        # What the login answered: the domains the account can see and the
        # one it lands in by default.
        self.domains: list[dict[str, str]] = []
        self.default_domain_uuid = ""
        # Counters surfaced in the snapshot's collection report.
        self.stats = {"requests": 0, "retries": 0, "rate_limited": 0}

    async def __aenter__(self) -> FmcClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # Redirects are never followed: the credentials must only ever
            # reach the validated FMC host.
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self._timeout,
                verify=self._verify_tls,
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

    # ── Login ──────────────────────────────────────────────────────────────

    async def login(self) -> None:
        """Obtain an access token and the list of domains. Raises
        :class:`FmcApiError` when the FMC refuses or cannot be reached."""
        await self._wait_for_slot()
        self.stats["requests"] += 1
        try:
            resp = await self._ensure_client().post(
                TOKEN_PATH,
                auth=(self._username, self._password),
                headers={"Accept": "application/json", "User-Agent": "Plexus-AnyConnectTopology/1.0"},
            )
        except httpx.HTTPError:
            raise FmcApiError("Could not reach the FMC") from None
        if resp.status_code in (401, 403):
            raise FmcApiError(
                f"FMC rejected the credentials (HTTP {resp.status_code})",
                status_code=resp.status_code,
                detail=_error_detail(resp),
            )
        if resp.status_code >= 400:
            raise FmcApiError(
                f"FMC login -> HTTP {resp.status_code}", status_code=resp.status_code, detail=_error_detail(resp)
            )
        token = resp.headers.get("X-auth-access-token", "").strip()
        if not token:
            raise FmcApiError("FMC login answered without an access token", status_code=resp.status_code)
        self._token = token
        self.default_domain_uuid = resp.headers.get("DOMAIN_UUID", "").strip()
        self.domains = _parse_domains(resp.headers.get("DOMAINS", ""))
        if self.default_domain_uuid and not any(d["uuid"] == self.default_domain_uuid for d in self.domains):
            self.domains.append({"name": "Global", "uuid": self.default_domain_uuid})

    def resolve_domain(self, wanted: str) -> dict[str, str]:
        """The domain ``wanted`` names (by UUID or name, ``Global/Branch`` or
        just ``Branch``); the Global / default domain when empty. Call after
        :meth:`login`."""
        wanted = (wanted or "").strip()
        if not wanted:
            for domain in self.domains:
                if domain["name"].lower() == "global" or domain["uuid"] == self.default_domain_uuid:
                    return domain
            if self.domains:
                return self.domains[0]
            raise FmcApiError("FMC login listed no domain")
        lowered = wanted.lower()
        for domain in self.domains:
            name = domain["name"].lower()
            if domain["uuid"].lower() == lowered or name == lowered or name.rsplit("/", 1)[-1] == lowered:
                return domain
        visible = ", ".join(d["name"] for d in self.domains) or "none"
        raise FmcApiError(f"FMC domain {wanted!r} not found", detail=f"The account can see: {visible}")

    # ── Requests ───────────────────────────────────────────────────────────

    async def _send(self, path: str, params: dict[str, Any] | None) -> httpx.Response | None:
        self.stats["requests"] += 1
        try:
            return await self._ensure_client().get(
                path,
                params=params,
                headers={
                    "X-auth-access-token": self._token or "",
                    "Accept": "application/json",
                    "User-Agent": "Plexus-AnyConnectTopology/1.0",
                },
            )
        except httpx.HTTPError:
            return None

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """One GET, returning the decoded JSON object (``{}`` for an empty body)."""
        attempt = 0
        relogin = True
        # One request at a time: the FMC limit is per user and low.
        async with self._lock:
            if self._token is None:
                await self.login()
            while True:
                await self._wait_for_slot()
                resp = await self._send(path, params)
                if resp is not None and resp.status_code < 400:
                    if not resp.content:
                        return {}
                    try:
                        body = resp.json()
                    except ValueError:
                        raise FmcApiError(f"FMC GET {path} returned a non-JSON body") from None
                    return body if isinstance(body, dict) else {}
                if resp is not None and resp.status_code == 401 and relogin:
                    # The token expired or the FMC restarted: log in once more.
                    relogin = False
                    await self.login()
                    continue
                rate_limited = resp is not None and resp.status_code == 429
                retryable = resp is None or rate_limited or resp.status_code >= 500
                if not retryable or attempt >= self._max_retries:
                    if resp is None:
                        raise FmcApiError(f"FMC GET {path} failed: could not reach the FMC")
                    raise FmcApiError(
                        f"FMC GET {path} -> HTTP {resp.status_code}",
                        status_code=resp.status_code,
                        detail=_error_detail(resp),
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

    async def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Every item of a paged collection (``expanded`` detail, pages of
        ``PAGE_LIMIT``)."""
        items: list[dict[str, Any]] = []
        offset = 0
        for _page in range(_MAX_PAGES):
            query = {"expanded": "true", "limit": PAGE_LIMIT, "offset": offset, **(params or {})}
            body = await self.get(path, query)
            page = [i for i in body.get("items") or [] if isinstance(i, dict)]
            items.extend(page)
            raw_paging = body.get("paging")
            paging: dict[str, Any] = raw_paging if isinstance(raw_paging, dict) else {}
            try:
                total = int(paging.get("count") or 0)
            except TypeError, ValueError:
                total = 0
            try:
                # The FMC may serve smaller pages than asked for.
                page_size = int(paging.get("limit") or 0) or PAGE_LIMIT
            except TypeError, ValueError:
                page_size = PAGE_LIMIT
            offset += len(page)
            if not page or (total and offset >= total) or (not total and len(page) < page_size):
                break
        return items

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._token = None


def _parse_domains(header: str) -> list[dict[str, str]]:
    """The ``DOMAINS`` login header: a JSON list of ``{name, uuid}``."""
    try:
        parsed = json.loads(header) if header else []
    except ValueError:
        return []
    found: list[dict[str, str]] = []
    for item in parsed if isinstance(parsed, list) else []:
        if not isinstance(item, dict):
            continue
        uuid = str(item.get("uuid") or item.get("id") or "").strip()
        name = str(item.get("name") or "").strip()
        if uuid:
            found.append({"name": name or uuid, "uuid": uuid})
    return found
