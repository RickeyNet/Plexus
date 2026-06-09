"""Tests for the FDM collector's poll cycle and handoff to the monitoring pipeline.

The FdmClient, credential store, and monitoring pipeline are all stubbed, so
these assert the collector's own logic: credential resolution, normalisation
of a mocked snapshot, error-result on API failure, the disabled-is-noop guard,
and that each polled host is handed to ``_process_poll_result``.
"""

from __future__ import annotations

import pytest

import netcontrol.integrations.cisco_fdm.collector as collector
import netcontrol.routes.state as state
from netcontrol.integrations.cisco_fdm.client import FdmApiError


class _FakeClient:
    def __init__(self, systeminfo=None, metrics=None, fail=None):
        self._systeminfo = systeminfo or {"uptime": 100}
        self._metrics = metrics or {"cpu": {"percentUsed": 42}}
        self._fail = fail

    async def get_system_info(self):
        if self._fail:
            raise self._fail
        return self._systeminfo

    async def get_operational_metrics(self):
        if self._fail:
            raise self._fail
        return self._metrics


def _patch_creds(monkeypatch):
    async def _fake_cred(_cred_id):
        return {"username": "apiuser", "password": "enc"}

    monkeypatch.setattr(collector.db, "get_credential_raw", _fake_cred)
    # decrypt is imported inside collect_host from routes.crypto
    import routes.crypto as crypto
    monkeypatch.setattr(crypto, "decrypt", lambda c: "secret")


@pytest.mark.asyncio
async def test_collect_host_normalises_mocked_snapshot(monkeypatch):
    _patch_creds(monkeypatch)
    fake = _FakeClient(metrics={"cpu": {"percentUsed": 55}})

    async def _fake_get_client(host, cred, password):
        assert password == "secret"
        return fake

    monkeypatch.setattr(collector, "_get_client", _fake_get_client)

    host = {"id": 3, "ip_address": "10.0.0.1", "fdm_credential_id": 1}
    res = await collector.collect_host(host)
    assert res["host_id"] == 3
    assert res["cpu_percent"] == 55.0
    assert res["poll_status"] == "ok"
    assert res["response_time_ms"] is not None


@pytest.mark.asyncio
async def test_collect_host_without_credential_is_error_result(monkeypatch):
    host = {"id": 4, "ip_address": "10.0.0.2", "fdm_credential_id": None}
    res = await collector.collect_host(host)
    assert res["poll_status"] == "error"
    assert "credential" in res["poll_error"]


@pytest.mark.asyncio
async def test_collect_host_api_error_becomes_error_result(monkeypatch):
    _patch_creds(monkeypatch)
    fake = _FakeClient(fail=FdmApiError("HTTP 503", status_code=503))
    monkeypatch.setattr(collector, "_get_client", lambda *a: _coro(fake))

    host = {"id": 5, "ip_address": "10.0.0.3", "fdm_credential_id": 1}
    res = await collector.collect_host(host)
    assert res["poll_status"] == "error"
    assert "503" in res["poll_error"]


@pytest.mark.asyncio
async def test_run_fdm_poll_once_disabled_is_noop(monkeypatch):
    monkeypatch.setitem(state.FDM_CONFIG, "enabled", False)
    out = await collector.run_fdm_poll_once()
    assert out == {"enabled": False, "hosts_polled": 0, "alerts_created": 0, "errors": 0}


@pytest.mark.asyncio
async def test_run_fdm_poll_once_polls_each_host_and_processes(monkeypatch):
    hosts = [
        {"id": 1, "hostname": "ftd-a", "ip_address": "10.0.0.1", "fdm_credential_id": 1},
        {"id": 2, "hostname": "ftd-b", "ip_address": "10.0.0.2", "fdm_credential_id": 1},
    ]

    async def _fake_get_fdm_hosts():
        return hosts

    async def _fake_get_alert_rules(enabled_only=True):
        return []

    monkeypatch.setattr(collector.db, "get_fdm_hosts", _fake_get_fdm_hosts)
    monkeypatch.setattr(collector.db, "get_alert_rules", _fake_get_alert_rules)

    async def _fake_collect(host):
        return {"host_id": host["id"], "poll_status": "ok"}

    monkeypatch.setattr(collector, "collect_host", _fake_collect)

    processed = []

    async def _fake_process(h, res, rules):
        processed.append(res["host_id"])
        return 1  # one alert each

    import netcontrol.routes.monitoring as monitoring
    monkeypatch.setattr(monitoring, "_process_poll_result", _fake_process)

    out = await collector.run_fdm_poll_once(force=True)
    assert out["hosts_polled"] == 2
    assert out["alerts_created"] == 2
    assert out["errors"] == 0
    assert sorted(processed) == [1, 2]


def _coro(value):
    async def _inner():
        return value
    return _inner()
