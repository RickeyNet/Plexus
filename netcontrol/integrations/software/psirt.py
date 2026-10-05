"""Cisco PSIRT openVuln API client - paced, read-only.

Cisco publishes its security advisories through the openVuln API. A
registered application (an API console *client ID* and *client secret*)
gets a short-lived bearer token from Cisco's OAuth2 endpoint with the
client-credentials grant, then asks which advisories affect one software
version of one operating system::

    GET https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version=17.9.4a

The answer lists the advisories (ID, title, Security Impact Rating, CVSS
base score, CVEs, first fixed releases, publication URL). A version that no
advisory affects is answered with a *not found* error, which this client
turns into an empty list.

Cisco rate-limits the API (a handful of calls per second and per minute),
so requests are sent one at a time with a minimum gap and a rate-limit or
server error is retried after a pause. The hosts are fixed: credentials
only ever reach ``id.cisco.com`` and ``apix.cisco.com``, and redirects are
not followed.
"""

from __future__ import annotations

import asyncio
import html
import re
import time
from typing import Any

import httpx

TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
API_URL = "https://apix.cisco.com/security/advisories/v2"

# openVuln ``OSType`` values that can be queried by version.
OS_TYPES = ("ios", "iosxe", "iosxr", "nxos", "asa", "ftd", "fmc", "fxos")

DEFAULT_TIMEOUT_SECONDS = 30.0
# Well inside Cisco's published limits (5 per second, 30 per minute).
DEFAULT_REQUESTS_PER_SECOND = 0.4
DEFAULT_MAX_RETRIES = 3
_MAX_RETRY_AFTER_SECONDS = 60.0
_MAX_DETAIL_CHARS = 300
_MAX_SUMMARY_CHARS = 2000

_SIR_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}
_NOT_FOUND_CODES = {"NOT_FOUND", "NOT_FOUND_ERROR"}
_TAG_RE = re.compile(r"<[^>]+>")
_SPACE_RE = re.compile(r"\s+")


class PsirtApiError(RuntimeError):
    """A request Cisco PSIRT refused or could not answer.

    ``status_code`` is the HTTP status (0 when the request never reached
    Cisco) and ``detail`` the message Cisco returned, if any.
    """

    def __init__(self, message: str, *, status_code: int = 0, detail: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail


def _error_detail(resp: httpx.Response | None) -> str:
    if resp is None:
        return ""
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:_MAX_DETAIL_CHARS]
    if isinstance(body, dict):
        for key in ("errorMessage", "error_description", "error", "message"):
            if isinstance(body.get(key), str) and body[key]:
                return body[key][:_MAX_DETAIL_CHARS]
    return ""


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _plain_text(markup: Any, limit: int = _MAX_SUMMARY_CHARS) -> str:
    text = html.unescape(_TAG_RE.sub(" ", _text(markup)))
    text = _SPACE_RE.sub(" ", text).strip()
    return text[:limit]


def _strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return [_text(item) for item in value if _text(item)]
    return [_text(value)] if _text(value) else []


def normalize_advisory(raw: dict) -> dict[str, Any] | None:
    """One openVuln advisory in the tracker's advisory shape, or ``None``
    when it has no ID."""
    advisory_id = _text(raw.get("advisoryId"))
    if not advisory_id:
        return None
    cvss: float | None = None
    score = _text(raw.get("cvssBaseScore"))
    if score and score.upper() != "NA":
        try:
            cvss = float(score)
        except ValueError:
            cvss = None
    return {
        "advisory_id": advisory_id,
        "title": _text(raw.get("advisoryTitle")) or advisory_id,
        "severity": _SIR_SEVERITY.get(_text(raw.get("sir")).lower(), "medium"),
        "cvss": cvss,
        "cves": _strings(raw.get("cves")),
        "fixed_versions": _strings(raw.get("firstFixed")),
        "url": _text(raw.get("publicationUrl")),
        "published": _text(raw.get("firstPublished")),
        "updated": _text(raw.get("lastUpdated")),
        "summary": _plain_text(raw.get("summary")),
        "product_names": _strings(raw.get("productNames"))[:50],
        "bug_ids": _strings(raw.get("bugIDs"))[:50],
    }


class PsirtClient:
    """Reusable openVuln session for one client ID and secret.

    Construct with the *decrypted* secret. Use as an async context manager,
    or call :meth:`close` when done.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        requests_per_second: float = DEFAULT_REQUESTS_PER_SECOND,
        max_retries: int = DEFAULT_MAX_RETRIES,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = timeout
        self._max_retries = max(0, int(max_retries))
        self._transport = transport  # injectable for tests (httpx.MockTransport)
        self._client: httpx.AsyncClient | None = None
        self._token = ""
        self._token_expires = 0.0

        self._min_interval = 1.0 / max(0.05, float(requests_per_second))
        self._lock = asyncio.Lock()
        self._next_slot = 0.0

        self.stats = {"requests": 0, "retries": 0, "rate_limited": 0, "logins": 0}

    async def __aenter__(self) -> PsirtClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # Redirects are never followed: the credentials and token must
            # only ever reach the fixed Cisco hosts.
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=False,
                transport=self._transport,
                headers={"Accept": "application/json", "User-Agent": "Plexus-SoftwareTracker/1.0"},
            )
        return self._client

    async def _wait_for_slot(self) -> None:
        now = time.monotonic()
        start = max(now, self._next_slot)
        self._next_slot = start + self._min_interval
        if start > now:
            await asyncio.sleep(start - now)

    async def authenticate(self) -> str:
        """Fetch (or reuse) a bearer token. Raises :class:`PsirtApiError`
        when Cisco refuses the client ID and secret."""
        if self._token and time.monotonic() < self._token_expires:
            return self._token
        self.stats["requests"] += 1
        self.stats["logins"] += 1
        try:
            resp = await self._ensure_client().post(
                TOKEN_URL,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
        except httpx.HTTPError as exc:
            raise PsirtApiError(f"Cisco PSIRT login failed: {type(exc).__name__}") from exc
        if resp.status_code != 200:
            raise PsirtApiError(
                f"Cisco PSIRT refused the client credentials (HTTP {resp.status_code})",
                status_code=resp.status_code,
                detail=_error_detail(resp),
            )
        try:
            body = resp.json()
        except ValueError as exc:
            raise PsirtApiError("Cisco PSIRT login answered with something other than JSON") from exc
        token = _text((body or {}).get("access_token")) if isinstance(body, dict) else ""
        if not token:
            raise PsirtApiError("Cisco PSIRT login answered without an access token")
        try:
            lifetime = float((body or {}).get("expires_in") or 3600)
        except TypeError, ValueError:
            lifetime = 3600.0
        self._token = token
        # Renew a minute early so a token never expires mid-request.
        self._token_expires = time.monotonic() + max(60.0, lifetime - 60.0)
        return token

    async def _get(self, url: str, params: dict[str, str]) -> httpx.Response | None:
        self.stats["requests"] += 1
        try:
            return await self._ensure_client().get(
                url, params=params, headers={"Authorization": f"Bearer {self._token}"}
            )
        except httpx.HTTPError:
            return None

    async def advisories_by_version(self, os_type: str, version: str) -> list[dict[str, Any]]:
        """The advisories affecting ``version`` of ``os_type`` (an
        :data:`OS_TYPES` value), normalized; ``[]`` when there are none."""
        os_type = _text(os_type).lower()
        version = _text(version)
        if os_type not in OS_TYPES:
            raise PsirtApiError(f"Cisco PSIRT has no version query for {os_type or 'this platform'}")
        if not version:
            return []
        url = f"{API_URL}/OSType/{os_type}"
        attempt = 0
        relogin_done = False
        async with self._lock:
            while True:
                await self.authenticate()
                await self._wait_for_slot()
                resp = await self._get(url, {"version": version})
                if resp is not None and resp.status_code == 200:
                    try:
                        body = resp.json()
                    except ValueError as exc:
                        raise PsirtApiError("Cisco PSIRT answered with something other than JSON") from exc
                    return self._advisories_of(body)
                if resp is not None and resp.status_code == 404:
                    return []
                if resp is not None and resp.status_code == 401 and not relogin_done:
                    relogin_done = True
                    self._token = ""
                    continue
                retryable = resp is None or resp.status_code == 429 or resp.status_code >= 500
                if not retryable or attempt >= self._max_retries:
                    status = resp.status_code if resp is not None else 0
                    raise PsirtApiError(
                        f"Cisco PSIRT request failed (HTTP {status})" if status else "Cisco PSIRT is unreachable",
                        status_code=status,
                        detail=_error_detail(resp),
                    )
                attempt += 1
                self.stats["retries"] += 1
                pause = min(2.0**attempt, _MAX_RETRY_AFTER_SECONDS)
                if resp is not None and resp.status_code == 429:
                    self.stats["rate_limited"] += 1
                    try:
                        pause = min(float(resp.headers.get("Retry-After", pause)), _MAX_RETRY_AFTER_SECONDS)
                    except ValueError:
                        pass
                await asyncio.sleep(pause)

    @staticmethod
    def _advisories_of(body: Any) -> list[dict[str, Any]]:
        if isinstance(body, dict):
            if _text(body.get("errorCode")).upper() in _NOT_FOUND_CODES:
                return []
            raw = body.get("advisories")
        else:
            raw = body
        advisories = []
        for item in raw or []:
            if isinstance(item, dict):
                advisory = normalize_advisory(item)
                if advisory:
                    advisories.append(advisory)
        return advisories
