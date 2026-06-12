"""Tests for the Cisco FDM REST client's token lifecycle and request surface.

All network I/O is faked with ``httpx.MockTransport`` so the suite needs no
real FTD.  The handler records every request, which lets us assert the
session-discipline contract that matters most for FDM: one token, reused -
never minted per call (FDM caps each device at 5 shared HTTPS sessions).
"""

from __future__ import annotations

import httpx
import pytest
from netcontrol.integrations.cisco_fdm.client import FdmApiError, FdmClient


class _FakeFdm:
    """Scriptable FDM endpoint backed by an httpx.MockTransport.

    Tracks how many times the token endpoint and each resource were hit so the
    tests can assert reuse vs re-auth behaviour.
    """

    def __init__(self) -> None:
        self.token_calls = 0
        self.metrics_calls = 0
        self.access_token = "access-1"
        self.expires_in = 1800
        # When set, the next single resource call returns 401 to simulate a
        # token rejected mid-session.
        self.fail_next_resource_once = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/fdm/token"):
            self.token_calls += 1
            # Hand out a fresh token id per grant so tests can see refreshes.
            self.access_token = f"access-{self.token_calls}"
            return httpx.Response(
                200,
                json={
                    "access_token": self.access_token,
                    "refresh_token": f"refresh-{self.token_calls}",
                    "expires_in": self.expires_in,
                    "refresh_expires_in": 86400,
                },
            )
        if path.endswith("/operational/systeminfo/default"):
            return httpx.Response(200, json={"model": "FPR-1140", "serialNumber": "JAD123"})
        if path.endswith("/operational/diskusage/default"):
            return httpx.Response(200, json={"total": 100, "used": 40, "free": 60})
        if path.endswith("/devices/default/operational/metrics"):
            self.metrics_calls += 1
            if self.fail_next_resource_once:
                self.fail_next_resource_once = False
                return httpx.Response(401, json={"error": {"message": "token expired"}})
            return httpx.Response(200, json={"cpu": {"percentUsed": 12}})
        return httpx.Response(404, json={"error": "not found"})


def _client(fake: _FakeFdm) -> FdmClient:
    return FdmClient(
        "ftd.example.com",
        "apiuser",
        "secret",
        transport=httpx.MockTransport(fake.handler),
    )


@pytest.mark.asyncio
async def test_token_acquired_once_and_reused_across_calls():
    fake = _FakeFdm()
    async with _client(fake) as client:
        await client.get_system_info()
        await client.get_operational_metrics()
        await client.get_disk_usage()  # 404 -> error, but token already cached

    # Three resource calls, but the password grant should have run exactly once:
    # the cached token is reused for every subsequent request.
    assert fake.token_calls == 1


@pytest.mark.asyncio
async def test_expired_access_token_triggers_refresh_grant():
    fake = _FakeFdm()
    # Token already "expired" the instant it's issued, forcing a refresh on the
    # second call. expires_in below the skew window guarantees re-acquisition.
    fake.expires_in = 1
    async with _client(fake) as client:
        await client.get_system_info()
        first_token = client._access_token
        await client.get_operational_metrics()
        second_token = client._access_token

    # A second grant ran (refresh), producing a new token id.
    assert fake.token_calls == 2
    assert first_token != second_token


@pytest.mark.asyncio
async def test_401_mid_session_forces_single_reauth_and_retries():
    fake = _FakeFdm()
    fake.fail_next_resource_once = True
    async with _client(fake) as client:
        result = await client.get_operational_metrics()

    # First metrics call 401s -> forced re-auth -> retry succeeds.
    assert result == {"cpu": {"percentUsed": 12}}
    assert fake.metrics_calls == 2  # original + retry
    assert fake.token_calls == 2    # initial grant + forced re-auth


@pytest.mark.asyncio
async def test_http_error_raises_fdm_api_error_with_status():
    fake = _FakeFdm()
    async with _client(fake) as client:
        with pytest.raises(FdmApiError) as excinfo:
            await client.get("operational/nonexistent")  # handler returns 404
    assert excinfo.value.status_code == 404


@pytest.mark.asyncio
async def test_token_response_without_access_token_is_an_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"refresh_token": "r"})  # no access_token

    client = FdmClient(
        "ftd.example.com", "u", "p", transport=httpx.MockTransport(handler)
    )
    try:
        with pytest.raises(FdmApiError, match="missing access_token"):
            await client.get_system_info()
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_unknown_trending_report_rejected_before_any_network_call():
    fake = _FakeFdm()
    async with _client(fake) as client:
        with pytest.raises(ValueError, match="unknown trending report"):
            await client.get_trending_report("bogus")
    # Rejected client-side: no token grant, no resource call.
    assert fake.token_calls == 0
