"""Cisco FTD on-box (FDM) REST API client - stateful OAuth2 session per device.

Unlike ``netcontrol.drivers.*`` (stateless command builders that touch no
network), an :class:`FdmClient` holds a live session to one FTD: it acquires a
bearer token, refreshes it before expiry, and reuses it across every call.

Why the reuse is not optional
-----------------------------
FDM caps each device at **5 concurrent HTTPS sessions, shared between the REST
API and the FDM web UI** (see the Cisco "Authenticating Your REST API Client"
guide).  Getting a fresh token per call - or even per poll cycle - churns
through that budget and can expire an operator's web-UI login out from under
them.  So the contract here is: *one client == one long-lived session per
host*.  The collector keeps a client per host for the app's lifetime and
reuses it; token refresh happens in-band via the refresh-token grant, which
does not open a new session.

Scope
-----
Read-only.  The client issues GETs against the ``operational`` / ``monitor``
resources plus (later phases) the config-export job flow.  It never calls
``POST /operational/deploy`` or mutates device configuration - Plexus stays a
non-mutating observer of FDM-managed firewalls.

Endpoints (FTD 7.4+, base ``https://<host>/api/fdm/latest``):
  - ``POST fdm/token``                          - OAuth2 token (password / refresh grant)
  - ``GET  operational/systeminfo/default``     - model, serial, version, uptime
  - ``GET  devices/default/operational/metrics``- CPU/mem/iface/connection snapshot
  - ``GET  monitor/trendingreports/{report}``   - cpu | memory | eps | throughput trends
  - ``GET  operational/diskusage/default``       - disk total/used/free
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

DEFAULT_API_VERSION = "latest"
DEFAULT_HTTPS_PORT = 443
DEFAULT_TIMEOUT_SECONDS = 30.0

# Refresh the access token this many seconds *before* its real expiry so a
# request never rides an about-to-die token (clock skew + flight time margin).
_TOKEN_EXPIRY_SKEW_SECONDS = 60.0

# FDM's password grant defaults to a 30-minute access token when the response
# omits ``expires_in``; mirror that so a malformed/short response still yields
# a sane refresh cadence rather than re-authing on every call.
_DEFAULT_ACCESS_TTL_SECONDS = 1800.0

_TRENDING_REPORTS = ("cpu", "memory", "eps", "throughput")


class FdmApiError(RuntimeError):
    """An FDM REST call failed - auth rejected, HTTP error, or bad payload.

    ``status_code`` is the HTTP status when the failure was an HTTP response
    (``None`` for transport-level errors), so callers can distinguish "device
    said no" (4xx/5xx) from "couldn't reach the device" (timeout/connect).
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class FdmClient:
    """One reusable OAuth2 session to a single FTD's FDM REST API.

    Construct with the *decrypted* username/password (credential decryption is
    the caller's job - this module stays free of DB/crypto deps so it is
    trivially unit-testable).  Use as an async context manager, or call
    :meth:`close` when done; either way the underlying httpx client is reused
    across calls for the client's lifetime.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        port: int = DEFAULT_HTTPS_PORT,
        api_version: str = DEFAULT_API_VERSION,
        verify_tls: bool = False,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        # FDM management certs are self-signed out of the box, so verify_tls
        # defaults to False; deployments that install a trusted cert can flip
        # it on per host.
        self._api_base = f"https://{host}:{port}/api/fdm/{api_version}"
        self._username = username
        self._password = password
        self._verify_tls = verify_tls
        self._timeout = timeout
        self._transport = transport  # injectable for tests (httpx.MockTransport)

        self._client: httpx.AsyncClient | None = None
        # Serialises token acquisition so concurrent requests on the same
        # client mint at most one token (no thundering-herd of grants, which
        # would each consume a session slot).
        self._token_lock = asyncio.Lock()
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        # Monotonic deadlines (time.monotonic), 0.0 == "none / expired".
        self._access_expiry = 0.0
        self._refresh_expiry = 0.0

    async def __aenter__(self) -> FdmClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    # ── HTTP plumbing ──────────────────────────────────────────────────────

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._api_base,
                timeout=self._timeout,
                verify=self._verify_tls,
                transport=self._transport,
            )
        return self._client

    # ── Token lifecycle ────────────────────────────────────────────────────

    async def _token_request(self, payload: dict[str, Any]) -> None:
        """POST a grant to ``fdm/token`` and store the resulting token set."""
        client = self._ensure_client()
        try:
            resp = await client.post("fdm/token", json=payload)
        except httpx.HTTPError as exc:
            raise FdmApiError(f"FDM token request failed: {exc}") from exc
        if resp.status_code != 200:
            raise FdmApiError(
                f"FDM token request rejected (HTTP {resp.status_code})",
                status_code=resp.status_code,
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise FdmApiError("FDM token response was not JSON") from exc

        token = data.get("access_token")
        if not token:
            raise FdmApiError("FDM token response missing access_token")

        now = time.monotonic()
        self._access_token = token
        self._refresh_token = data.get("refresh_token")
        self._access_expiry = now + float(data.get("expires_in", _DEFAULT_ACCESS_TTL_SECONDS))
        # refresh_expires_in is absent on some builds; 0.0 just means "don't
        # trust the refresh token", which forces a clean password re-auth.
        self._refresh_expiry = now + float(data.get("refresh_expires_in", 0) or 0)

    async def _ensure_token(self) -> str:
        """Return a currently-valid access token, refreshing/re-authing as needed."""
        async with self._token_lock:
            now = time.monotonic()
            if self._access_token and now < self._access_expiry - _TOKEN_EXPIRY_SKEW_SECONDS:
                return self._access_token

            # Access token missing or near expiry. Prefer a refresh-token grant
            # (cheaper, no new session); fall back to a full password grant if
            # we have no usable refresh token or the refresh itself fails.
            if self._refresh_token and now < self._refresh_expiry - _TOKEN_EXPIRY_SKEW_SECONDS:
                try:
                    await self._token_request(
                        {"grant_type": "refresh_token", "refresh_token": self._refresh_token}
                    )
                    return self._access_token  # type: ignore[return-value]
                except FdmApiError:
                    pass  # refresh token dead too - re-auth below

            await self._token_request(
                {
                    "grant_type": "password",
                    "username": self._username,
                    "password": self._password,
                }
            )
            return self._access_token  # type: ignore[return-value]

    def _invalidate_token(self) -> None:
        """Drop the cached access token so the next call re-authenticates."""
        self._access_token = None
        self._access_expiry = 0.0

    # ── Request surface ────────────────────────────────────────────────────

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        _retry_on_auth: bool = True,
    ) -> Any:
        """Issue an authenticated request and return the decoded JSON body.

        A 401 mid-session (e.g. the device rebooted and regenerated its token
        signing key) triggers exactly one forced re-auth + retry; a second 401
        surfaces as an :class:`FdmApiError` rather than looping.
        """
        token = await self._ensure_token()
        client = self._ensure_client()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        try:
            resp = await client.request(
                method, path.lstrip("/"), params=params, json=json_body, headers=headers
            )
        except httpx.HTTPError as exc:
            raise FdmApiError(f"FDM {method} {path} failed: {exc}") from exc

        if resp.status_code == 401 and _retry_on_auth:
            async with self._token_lock:
                self._invalidate_token()
            return await self.request(
                method, path, params=params, json_body=json_body, _retry_on_auth=False
            )

        if resp.status_code >= 400:
            raise FdmApiError(
                f"FDM {method} {path} -> HTTP {resp.status_code}",
                status_code=resp.status_code,
            )

        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError as exc:
            raise FdmApiError(f"FDM {method} {path} returned non-JSON body") from exc

    async def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params=params)

    # ── Read-only operational resources (FTD 7.4+) ─────────────────────────

    async def get_system_info(self) -> dict[str, Any]:
        """Chassis identity: model, serial, software version, uptime."""
        return await self.get("operational/systeminfo/default")

    async def get_operational_metrics(self) -> dict[str, Any]:
        """Point-in-time health snapshot.

        CPU (per-core), memory (lina/snort/system/swap), per-filesystem disk,
        interface packets/errors/traffic/status, connection-tracking stats,
        ASP drops, process health, temperature/fan/PSU sensors, Snort stats.
        This is the primary feed for the monitoring poll.
        """
        return await self.get("devices/default/operational/metrics")

    async def get_disk_usage(self) -> dict[str, Any]:
        return await self.get("operational/diskusage/default")

    async def get_trending_report(
        self, report: str, *, duration_minutes: int = 60
    ) -> dict[str, Any]:
        """Time-series trend for ``cpu``/``memory``/``eps``/``throughput``."""
        if report not in _TRENDING_REPORTS:
            raise ValueError(
                f"unknown trending report {report!r}; expected one of {_TRENDING_REPORTS}"
            )
        return await self.get(
            f"monitor/trendingreports/{report}", params={"time_duration": duration_minutes}
        )

    # ── Teardown ───────────────────────────────────────────────────────────

    async def close(self) -> None:
        """Close the HTTP client and forget the cached token.

        Note: we deliberately do *not* attempt a server-side token revoke here.
        The exact FDM revoke grant schema varies by build and a wrong payload
        would silently 4xx; since a reused client holds exactly one session for
        its lifetime, letting that single token age out on shutdown is cheaper
        and safer than guessing the revoke contract. If explicit revoke is
        wanted later, pin the schema against the on-box API Explorer first.
        """
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._access_token = None
        self._refresh_token = None
        self._access_expiry = 0.0
        self._refresh_expiry = 0.0
