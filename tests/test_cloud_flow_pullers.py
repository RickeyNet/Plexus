"""Tests for cloud flow-log scheduled pullers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
import routes.database as db_module

import sys

import netcontrol.routes.cloud_flow_pullers as pullers_mod
import netcontrol.routes.cloud_visibility as cloud_visibility_module


async def _init(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_cloud_flow_pullers.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    return db_path


class _DummyRequest:
    def __init__(self, correlation_id: str = "test-corr-id"):
        self.cookies = {}
        self.state = type("State", (), {"correlation_id": correlation_id})()


# ───────────────────────────────────────────────────────────────────────────
# Window / cursor helpers
# ───────────────────────────────────────────────────────────────────────────


def test_window_defaults_to_lookback_when_no_cursor():
    start, end = pullers_mod._window({}, lookback_minutes=10)
    now = datetime.now(UTC)
    # start should be ~10 minutes ago
    assert (now - start).total_seconds() < 620  # ~10 min + margin
    assert (now - start).total_seconds() > 580
    assert (now - end).total_seconds() < 5


def test_window_uses_cursor_last_pull():
    ten_min_ago = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
    start, end = pullers_mod._window({"last_pull_end": ten_min_ago})
    now = datetime.now(UTC)
    assert abs((start - (now - timedelta(minutes=10))).total_seconds()) < 5
    assert (now - end).total_seconds() < 5


def test_window_clamps_to_24h_floor():
    old_time = (datetime.now(UTC) - timedelta(hours=48)).isoformat()
    start, end = pullers_mod._window({"last_pull_end": old_time})
    now = datetime.now(UTC)
    # Should be clamped to 24h ago, not 48h
    age_hours = (now - start).total_seconds() / 3600
    assert age_hours <= 24.1


# ───────────────────────────────────────────────────────────────────────────
# Cursor DB operations
# ───────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cursor_upsert_and_read(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider="aws", name="AWS Test")
    account_id = int(account["id"])

    # Initially no cursor
    assert await db_module.get_cloud_flow_sync_cursor(account_id) is None

    # Create
    now_iso = datetime.now(UTC).isoformat()
    await db_module.upsert_cloud_flow_sync_cursor(
        account_id, last_pull_end=now_iso, extra_json={"region": "us-east-1"},
    )
    cursor = await db_module.get_cloud_flow_sync_cursor(account_id)
    assert cursor is not None
    assert cursor["last_pull_end"] == now_iso

    # Update
    later_iso = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    await db_module.upsert_cloud_flow_sync_cursor(
        account_id, last_pull_end=later_iso,
    )
    cursor = await db_module.get_cloud_flow_sync_cursor(account_id)
    assert cursor["last_pull_end"] == later_iso


@pytest.mark.asyncio
async def test_list_cursors(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    a1 = await db_module.create_cloud_account(provider="aws", name="AWS-1")
    a2 = await db_module.create_cloud_account(provider="azure", name="Azure-1")
    now_iso = datetime.now(UTC).isoformat()
    await db_module.upsert_cloud_flow_sync_cursor(int(a1["id"]), last_pull_end=now_iso)
    await db_module.upsert_cloud_flow_sync_cursor(int(a2["id"]), last_pull_end=now_iso)

    cursors = await db_module.list_cloud_flow_sync_cursors()
    assert len(cursors) == 2
    providers = {c["provider"] for c in cursors}
    assert providers == {"aws", "azure"}


# ───────────────────────────────────────────────────────────────────────────
# AWS puller
# ───────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_aws_puller_missing_log_group(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(
        provider="aws", name="AWS No Group",
        auth_config_json={"access_key_id": "test"},
    )
    result = await pullers_mod.pull_aws_flow_logs(account)
    assert result["ok"] is False
    assert result["error"] == "missing_log_group_name"


@pytest.mark.asyncio
async def test_aws_puller_boto3_missing(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(
        provider="aws", name="AWS No Boto",
        auth_config_json={"log_group_name": "/aws/vpc/flow-logs"},
    )
    # Simulate boto3 not installed
    import builtins
    real_import = builtins.__import__

    def _block_boto3(name, *args, **kwargs):
        if name == "boto3":
            raise ImportError("no boto3")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _block_boto3)
    result = await pullers_mod.pull_aws_flow_logs(account)
    assert result["ok"] is False
    assert "boto3" in result["error"]


@pytest.mark.asyncio
async def test_aws_puller_success_with_mock(tmp_path, monkeypatch):
    """End-to-end AWS puller with mocked CloudWatch Logs."""
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(
        provider="aws", name="AWS Mock",
        auth_config_json={"log_group_name": "/aws/vpc/flow-logs", "access_key_id": "AKIA", "secret_access_key": "secret"},
        region_scope="us-east-1",
    )

    mock_records = [
        {"srcaddr": "10.0.0.1", "dstaddr": "10.0.0.2", "srcport": "443", "dstport": "12345",
         "protocol": "6", "bytes": "1000", "packets": "10", "action": "ACCEPT",
         "start": str(int(datetime.now(UTC).timestamp()))},
        {"srcaddr": "10.0.0.3", "dstaddr": "10.0.0.4", "srcport": "80", "dstport": "54321",
         "protocol": "6", "bytes": "2000", "packets": "20", "action": "REJECT",
         "start": str(int(datetime.now(UTC).timestamp()))},
    ]

    async def _mock_cw_query(client, log_group, start, end):
        return mock_records

    monkeypatch.setattr(pullers_mod, "_cw_insights_query", _mock_cw_query)

    # Stub boto3 + botocore so the import guard inside the puller passes
    fake_boto3 = MagicMock()
    fake_botocore_exc = type("module", (), {"BotoCoreError": Exception, "ClientError": Exception})()
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    monkeypatch.setitem(sys.modules, "botocore", MagicMock())
    monkeypatch.setitem(sys.modules, "botocore.exceptions", fake_botocore_exc)
    monkeypatch.setattr(pullers_mod, "_build_boto3_session", lambda auth: MagicMock())

    result = await pullers_mod.pull_aws_flow_logs(account)
    assert result["ok"] is True
    assert result["ingested"] == 2

    # Verify cursor was written
    cursor = await db_module.get_cloud_flow_sync_cursor(int(account["id"]))
    assert cursor is not None
    assert cursor["last_pull_end"] != ""


# ───────────────────────────────────────────────────────────────────────────
# Azure puller
# ───────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_azure_puller_missing_storage_config(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(
        provider="azure", name="Azure No Storage",
        auth_config_json={"subscription_id": "sub-123"},
    )
    result = await pullers_mod.pull_azure_flow_logs(account)
    assert result["ok"] is False
    assert result["error"] == "missing_storage_config"


# ───────────────────────────────────────────────────────────────────────────
# GCP puller
# ───────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_gcp_puller_missing_project_id(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(
        provider="gcp", name="GCP No Project",
        auth_config_json={},
    )
    result = await pullers_mod.pull_gcp_flow_logs(account)
    assert result["ok"] is False
    assert result["error"] == "missing_project_id"


# ───────────────────────────────────────────────────────────────────────────
# Dispatcher / all-accounts
# ───────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pull_all_skips_unconfigured_accounts(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    # Create accounts without flow-log config keys
    await db_module.create_cloud_account(provider="aws", name="AWS bare", auth_config_json={})
    await db_module.create_cloud_account(provider="azure", name="Azure bare", auth_config_json={})
    await db_module.create_cloud_account(provider="gcp", name="GCP bare", auth_config_json={})

    result = await pullers_mod.pull_flow_logs_all_accounts()
    assert result["accounts_processed"] == 0
    assert result["total_ingested"] == 0


@pytest.mark.asyncio
async def test_pull_all_processes_configured_accounts(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(
        provider="aws", name="AWS Configured",
        auth_config_json={"log_group_name": "/aws/vpc/flow-logs", "access_key_id": "AKIA", "secret_access_key": "secret"},
        region_scope="us-east-1",
    )

    async def _mock_cw_query(client, log_group, start, end):
        return [
            {"srcaddr": "10.0.0.5", "dstaddr": "10.0.0.6", "srcport": "22", "dstport": "9999",
             "protocol": "6", "bytes": "500", "packets": "5", "action": "ACCEPT",
             "start": str(int(datetime.now(UTC).timestamp()))},
        ]

    monkeypatch.setattr(pullers_mod, "_cw_insights_query", _mock_cw_query)

    fake_boto3 = MagicMock()
    fake_botocore_exc = type("module", (), {"BotoCoreError": Exception, "ClientError": Exception})()
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    monkeypatch.setitem(sys.modules, "botocore", MagicMock())
    monkeypatch.setitem(sys.modules, "botocore.exceptions", fake_botocore_exc)
    monkeypatch.setattr(pullers_mod, "_build_boto3_session", lambda auth: MagicMock())

    result = await pullers_mod.pull_flow_logs_all_accounts()
    assert result["accounts_processed"] == 1
    assert result["total_ingested"] == 1


# ───────────────────────────────────────────────────────────────────────────
# API routes
# ───────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_flow_sync_config_get_and_update(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    import netcontrol.routes.state as state

    # GET config
    result = await cloud_visibility_module.get_cloud_flow_sync_config_api()
    assert "config" in result
    assert "status" in result
    assert result["config"]["enabled"] is False
    assert result["status"]["last_run_at"] == ""

    # PUT config
    from netcontrol.routes.cloud_visibility import CloudFlowSyncConfigUpdate
    body = CloudFlowSyncConfigUpdate(enabled=True, interval_seconds=120)
    result = await cloud_visibility_module.update_cloud_flow_sync_config_api(
        _DummyRequest(), body,
    )
    assert result["ok"] is True
    assert result["config"]["enabled"] is True
    assert result["config"]["interval_seconds"] == 120

    # Verify state was updated
    assert state.CLOUD_FLOW_SYNC_CONFIG["enabled"] is True
    assert state.CLOUD_FLOW_SYNC_CONFIG["interval_seconds"] == 120


@pytest.mark.asyncio
async def test_flow_sync_cursors_api(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider="aws", name="AWS Cursor Test")
    now_iso = datetime.now(UTC).isoformat()
    await db_module.upsert_cloud_flow_sync_cursor(int(account["id"]), last_pull_end=now_iso)

    result = await cloud_visibility_module.get_cloud_flow_sync_cursors_api()
    assert result["count"] == 1
    assert result["cursors"][0]["last_pull_end"] == now_iso


@pytest.mark.asyncio
async def test_manual_pull_single_account(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(
        provider="aws", name="AWS Manual Pull",
        auth_config_json={"log_group_name": "/aws/vpc/flow-logs", "access_key_id": "AKIA", "secret_access_key": "secret"},
        region_scope="us-east-1",
    )

    async def _mock_cw_query(client, log_group, start, end):
        return [{"srcaddr": "10.1.0.1", "dstaddr": "10.1.0.2", "srcport": "443",
                 "dstport": "11111", "protocol": "6", "bytes": "3000",
                 "packets": "30", "action": "ACCEPT",
                 "start": str(int(datetime.now(UTC).timestamp()))}]

    monkeypatch.setattr(pullers_mod, "_cw_insights_query", _mock_cw_query)

    fake_boto3 = MagicMock()
    fake_botocore_exc = type("module", (), {"BotoCoreError": Exception, "ClientError": Exception})()
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    monkeypatch.setitem(sys.modules, "botocore", MagicMock())
    monkeypatch.setitem(sys.modules, "botocore.exceptions", fake_botocore_exc)
    monkeypatch.setattr(pullers_mod, "_build_boto3_session", lambda auth: MagicMock())

    result = await cloud_visibility_module.trigger_cloud_flow_sync_api(
        _DummyRequest(), account_id=int(account["id"]),
    )
    assert result["ok"] is True
    assert result["ingested"] == 1
    assert result["account_id"] == int(account["id"])
    assert result["status"]["scope"] == "account"
    assert result["status"]["source"] == "manual"
    assert result["status"]["account_name"] == "AWS Manual Pull"
    assert result["status"]["ingested"] == 1

    cfg = await cloud_visibility_module.get_cloud_flow_sync_config_api()
    assert cfg["status"]["account_id"] == int(account["id"])
    assert cfg["status"]["source"] == "manual"


@pytest.mark.asyncio
async def test_manual_pull_nonexistent_account(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    with pytest.raises(Exception) as exc_info:
        await cloud_visibility_module.trigger_cloud_flow_sync_api(
            _DummyRequest(), account_id=99999,
        )
    assert "404" in str(exc_info.value.status_code)


# ───────────────────────────────────────────────────────────────────────────
# State sanitizer
# ───────────────────────────────────────────────────────────────────────────


def test_sanitize_cloud_flow_sync_config():
    import netcontrol.routes.state as state

    # None → defaults
    cfg = state._sanitize_cloud_flow_sync_config(None)
    assert cfg["enabled"] is False
    assert cfg["interval_seconds"] == 300
    assert cfg["lookback_minutes"] == 15

    # Valid overrides
    cfg = state._sanitize_cloud_flow_sync_config({
        "enabled": True, "interval_seconds": 120, "lookback_minutes": 30,
    })
    assert cfg["enabled"] is True
    assert cfg["interval_seconds"] == 120
    assert cfg["lookback_minutes"] == 30

    # Clamping: below minimum
    cfg = state._sanitize_cloud_flow_sync_config({"interval_seconds": 10, "lookback_minutes": 1})
    assert cfg["interval_seconds"] == 60  # min
    assert cfg["lookback_minutes"] == 5   # min

    # Clamping: above maximum
    cfg = state._sanitize_cloud_flow_sync_config({"interval_seconds": 9999, "lookback_minutes": 9999})
    assert cfg["interval_seconds"] == 3600  # max
    assert cfg["lookback_minutes"] == 1440  # max
