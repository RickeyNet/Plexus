"""Appgate SDP admin API client - paced, read-only.

The admin API lives under ``https://<controller>:8443/admin``. Every call
but ``GET /admin/version`` carries ``Accept:
application/vnd.appgate.peer-v<N>+json``, where ``N`` is the peer API
version, negotiated once from what ``/admin/version`` answers (the newest
version both sides speak, ``MAX_PEER_VERSION`` at most).

``POST /admin/login`` exchanges the admin user's name and password (with the
identity provider they sign in with, and a device ID that is stable per
Controller and user) for a bearer token. The token is sent only in the
``Authorization`` header and kept in memory only: it is never stored or
logged, ``POST /admin/logout`` is called when the client closes, and the
token is then forgotten. An expired token (HTTP 401) is replaced by signing
in again, once. The login API has no second factor: an admin user that
needs one cannot be used.

Lists are paged with ``range=<from>-<to>``; the answer carries
``totalCount``.

Scope
-----
Read-only: ``GET`` only, besides the login and the logout. Plexus never
changes anything on the collective.

Failures
--------
Appgate answers a failure with ``{"id": ..., "message": ...}``; the message
is kept as :attr:`AppgateApiError.detail`, which is what tells an operator
why a call was refused (a missing admin privilege, an unknown resource).
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any
from urllib.parse import urlsplit

import httpx

DEFAULT_TIMEOUT_SECONDS = 60.0
# The admin API is served by the Controllers that also run the collective;
# a few requests a second keeps a collection from loading them.
DEFAULT_REQUESTS_PER_SECOND = 4.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_PROVIDER_NAME = "local"

# The newest peer API version Plexus reads, and the oldest it understands.
MAX_PEER_VERSION = 25
MIN_PEER_VERSION = 17

ADMIN_PATH = "/admin"
USER_AGENT = "Plexus-AppgateTopology/1.0"
PAGE_SIZE = 500
MAX_LIST_ITEMS = 20_000

_MAX_RETRY_AFTER_SECONDS = 60.0
_MAX_DETAIL_CHARS = 300


class AppgateApiError(RuntimeError):
    """An Appgate admin API call failed.

    ``status_code`` is the HTTP status (``None`` when no answer came back,
    or for a check made by Plexus itself). ``transport`` is true when the
    Controller could not be reached at all; ``detail`` is the message
    Appgate answered with.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        detail: str = "",
        transport: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail
        self.transport = transport


def validate_base_url(url: str) -> str:
    """Normalise and validate the Controller's admin address.

    Accepts ``https://host[:port]`` (a bare host is taken as https, a
    trailing ``/`` or ``/admin`` is dropped) and returns just that: the URL
    decides where the password is sent, so no other path, no query and no
    embedded user is allowed, and ``http`` is refused. Raises
    ``ValueError`` otherwise.
    """
    cleaned = (url or "").strip()
    if not cleaned:
        raise ValueError("Appgate Controller address is required")
    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"
    parts = urlsplit(cleaned)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("Appgate Controller address must be an https URL")
    path = parts.path.rstrip("/")
    if path.lower() == ADMIN_PATH:
        path = ""
    if parts.username or parts.password or parts.query or parts.fragment or path.strip("/"):
        raise ValueError("Appgate Controller address must be the host only")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("Appgate Controller address has an invalid port") from None
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port else "")


def device_id(base_url: str, username: str) -> str:
    """The device ID Plexus signs in with: the same for every collection of
    one Controller and user, so the collective sees one admin device."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"plexus-appgate:{base_url}:{username}"))


def peer_accept(version: int) -> str:
    return f"application/vnd.appgate.peer-v{version}+json"


def _detail(resp: httpx.Response | None) -> str:
    """The ``message`` of an error answer (and the ``errors`` of a 422)."""
    if resp is None or not resp.content:
        return ""
    try:
        body = resp.json()
    except ValueError:
        return ""
    if not isinstance(body, dict):
        return ""
    parts = [str(body.get("message") or "").strip()]
    for error in body.get("errors") or []:
        if isinstance(error, dict):
            parts.append(f"{error.get('field') or ''} {error.get('message') or ''}".strip())
    return "; ".join(p for p in parts if p)[:_MAX_DETAIL_CHARS]


def _total(body: dict, page: list) -> int | None:
    """The number of items a paged list holds: ``totalCount``, else the
    ``/N`` of its ``range``."""
    try:
        if body.get("totalCount") is not None:
            return int(body["totalCount"])
    except TypeError, ValueError:
        pass
    found = str(body.get("range") or "")
    if "/" in found:
        try:
            return int(found.rsplit("/", 1)[1])
        except ValueError:
            return None
    return None


class AppgateClient:
    """Reusable Appgate admin API session for one admin user.

    Construct with the *decrypted* password. Use as an async context
    manager, or call :meth:`close` when done (it signs out).
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        provider_name: str = DEFAULT_PROVIDER_NAME,
        verify_tls: bool = True,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        requests_per_second: float = DEFAULT_REQUESTS_PER_SECOND,
        max_retries: int = DEFAULT_MAX_RETRIES,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = validate_base_url(base_url)
        self.username = (username or "").strip()
        self._password = password or ""
        self.provider_name = (provider_name or "").strip() or DEFAULT_PROVIDER_NAME
        self.device_id = device_id(self.base_url, self.username)
        self._verify_tls = verify_tls
        self._timeout = timeout
        self._max_retries = max(0, int(max_retries))
        self._transport = transport  # injectable for tests (httpx.MockTransport)
        self._client: httpx.AsyncClient | None = None
        self._token = ""

        self._min_interval = 1.0 / max(0.1, float(requests_per_second))
        self._lock = asyncio.Lock()
        self._next_slot = 0.0
        # The negotiated peer API version, and what /admin/version answered.
        self.peer_version: int | None = None
        self.version_info: dict[str, Any] = {}
        # The signed-in admin user as /admin/login describes it (no token).
        self.user: dict[str, Any] = {}
        # Counters surfaced in the snapshot's collection report.
        self.stats = {"requests": 0, "retries": 0, "rate_limited": 0, "logins": 0}

    async def __aenter__(self) -> AppgateClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # Redirects are never followed: the password and the token must
            # only ever reach the validated Controller.
            self._client = httpx.AsyncClient(
                base_url=self.base_url + ADMIN_PATH,
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

    async def _send(
        self, method: str, path: str, *, params: dict | None, body: dict | None, accept: str, auth: bool
    ) -> httpx.Response | None:
        headers = {"Accept": accept, "User-Agent": USER_AGENT}
        if auth and self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        self.stats["requests"] += 1
        try:
            return await self._ensure_client().request(method, path, params=params, json=body, headers=headers)
        except httpx.HTTPError:
            return None

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        body: dict | None = None,
        auth: bool = True,
        renew: bool = True,
    ) -> Any:
        """One call, answering the parsed JSON body (``None`` for an empty
        one). 429, 5xx and transport failures are retried with a backoff; a
        401 signs in again, once."""
        attempt = 0
        while True:
            accept = peer_accept(self.peer_version) if auth and self.peer_version else "application/json"
            await self._wait_for_slot()
            resp = await self._send(method, path, params=params, body=body, accept=accept, auth=auth)
            if resp is not None and resp.status_code < 300:
                if not resp.content:
                    return None
                try:
                    return resp.json()
                except ValueError:
                    raise AppgateApiError(
                        f"Appgate {method} {path} answered with a body that is not JSON", status_code=resp.status_code
                    ) from None
            if resp is not None and resp.status_code == 401 and auth and renew and self.username:
                # The token expired: sign in again, once.
                renew = False
                self._token = ""
                await self._login()
                continue
            rate_limited = resp is not None and resp.status_code == 429
            retryable = resp is None or rate_limited or resp.status_code >= 500
            if not retryable or attempt >= self._max_retries:
                if resp is None:
                    raise AppgateApiError(
                        f"Appgate {method} {path} failed: could not reach the Controller", transport=True
                    )
                raise AppgateApiError(
                    f"Appgate {method} {path} -> HTTP {resp.status_code}",
                    status_code=resp.status_code,
                    detail=_detail(resp),
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
                delay = min(max(delay, 1.0), _MAX_RETRY_AFTER_SECONDS)
            await asyncio.sleep(delay)

    # ── Version and login ──────────────────────────────────────────────────

    async def negotiate(self) -> int:
        """Read ``/admin/version`` (no sign-in needed) and pick the peer API
        version: the Controller's, ``MAX_PEER_VERSION`` at most. Raises
        :class:`AppgateApiError` when the Controller is too old or too new
        for Plexus."""
        async with self._lock:
            return await self._negotiate()

    async def _negotiate(self) -> int:
        if self.peer_version is not None:
            return self.peer_version
        found = await self._request("GET", "/version", auth=False)
        info = found if isinstance(found, dict) else {}
        try:
            peer = int(info.get("peerVersion"))
            lowest = int(info.get("lowestPeerVersionSupported") or peer)
        except TypeError, ValueError:
            raise AppgateApiError("Appgate /admin/version did not name a peer version") from None
        version = min(peer, MAX_PEER_VERSION)
        if version < max(lowest, MIN_PEER_VERSION):
            raise AppgateApiError(f"Appgate SDP peer version {version} is not supported")
        self.version_info = {k: v for k, v in info.items() if isinstance(v, (str, int, float, bool))}
        self.peer_version = version
        return version

    async def login(self) -> None:
        """Negotiate the version and sign in. Raises :class:`AppgateApiError`
        when the Controller refuses or cannot be reached."""
        async with self._lock:
            await self._login()

    async def _login(self) -> None:
        await self._negotiate()
        if not self.username:
            raise AppgateApiError("No Appgate admin user name is set", status_code=401)
        self.stats["logins"] += 1
        answer = await self._request(
            "POST",
            "/login",
            body={
                "providerName": self.provider_name,
                "username": self.username,
                "password": self._password,
                "deviceId": self.device_id,
            },
            renew=False,
        )
        answer = answer if isinstance(answer, dict) else {}
        user = answer.get("user") if isinstance(answer.get("user"), dict) else {}
        if user.get("needTwoFactorAuth"):
            raise AppgateApiError(
                "Appgate asks this admin user for a second factor: the API user must be exempt from admin MFA"
            )
        token = str(answer.get("token") or "")
        if not token:
            raise AppgateApiError("Appgate accepted the login but returned no token", status_code=401)
        self._token = token
        self.user = {k: v for k, v in user.items() if isinstance(v, (str, int, float, bool))}

    # ── Requests ───────────────────────────────────────────────────────────

    async def get(self, path: str, params: dict | None = None) -> Any:
        """One ``GET`` under ``/admin`` (signing in first when needed)."""
        async with self._lock:
            if not self._token:
                await self._login()
            return await self._request("GET", path, params=params)

    async def get_list(self, path: str, *, limit: int = MAX_LIST_ITEMS) -> list[dict]:
        """Every item of a paged list, following ``range``."""
        items: list[dict] = []
        start = 0
        while len(items) < limit:
            body = await self.get(path, {"range": f"{start}-{start + PAGE_SIZE - 1}"})
            if isinstance(body, list):
                items.extend(i for i in body if isinstance(i, dict))
                break
            body = body if isinstance(body, dict) else {}
            page = [i for i in body.get("data") or [] if isinstance(i, dict)]
            items.extend(page)
            total = _total(body, page)
            start += len(page)
            if not page or (total is not None and start >= total) or (total is None and len(page) < PAGE_SIZE):
                break
        return items[:limit]

    async def logout(self) -> None:
        """Sign out (best effort) and forget the token."""
        async with self._lock:
            if self._token:
                try:
                    await self._request("POST", "/logout", renew=False)
                except AppgateApiError:
                    pass
            self._token = ""

    async def close(self) -> None:
        if self._client is not None:
            await self.logout()
            await self._client.aclose()
            self._client = None
        self._token = ""
