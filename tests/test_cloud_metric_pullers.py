"""Tests for cloud traffic-metric scheduled pullers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
import routes.database as db_module

import sys

import netcontrol.routes.cloud_metric_pullers as pullers_mod
import netcontrol.routes.cloud_visibility as cloud_visibility_module


async def _init(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_cloud_metric_pullers.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    return db_path


class _DummyRequest:
    def __init__(self, correlation_id: str = "test-corr-id"):
        self.cookies = {}
        self.state = type("State", (), {"correlation_id": correlation_id})()


def test_window_defaults_to_lookback_when_no_cursor():
    start, end = pullers_mod._window({}, lookback_minutes=10)
    now = datetime.now(UTC)
    assert (now - start).total_seconds() < 620
    assert (now - start).total_seconds() > 580
    assert (now - end).total_seconds() < 5


def test_window_uses_cursor_last_pull():
    ten_min_ago = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
    start, end = pullers_mod._window({"last_pull_end": ten_min_ago})
    now = datetime.now(UTC)
    assert abs((start - (now - timedelta(minutes=10))).total_seconds()) < 5
    assert (now - end).total_seconds() < 5


@pytest.mark.asyncio
async def test_cursor_upsert_and_read(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider="aws", name="AWS Metric Test")
    account_id = int(account["id"])

    assert await db_module.get_cloud_traffic_metric_sync_cursor(account_id) is None

    now_iso = datetime.now(UTC).isoformat()
    await db_module.upsert_cloud_traffic_metric_sync_cursor(
        account_id, last_pull_end=now_iso, extra_json={"region": "us-east-1"}
    )
    cursor = await db_module.get_cloud_traffic_metric_sync_cursor(account_id)
    assert cursor is not None
    assert cursor["last_pull_end"] == now_iso


@pytest.mark.asyncio
async def test_list_cursors(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    a1 = await db_module.create_cloud_account(provider="aws", name="AWS-1")
    a2 = await db_module.create_cloud_account(provider="azure", name="Azure-1")
    now_iso = datetime.now(UTC).isoformat()
    await db_module.upsert_cloud_traffic_metric_sync_cursor(int(a1["id"]), last_pull_end=now_iso)
    await db_module.upsert_cloud_traffic_metric_sync_cursor(int(a2["id"]), last_pull_end=now_iso)

    cursors = await db_module.list_cloud_traffic_metric_sync_cursors()
    assert len(cursors) == 2
    providers = {c["provider"] for c in cursors}
    assert providers == {"aws", "azure"}


@pytest.mark.asyncio
async def test_aws_metric_puller_missing_resource_ids(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(
        provider="aws", name="AWS No Resource IDs", auth_config_json={"metric_namespace": "AWS/EC2"}
    )
    result = await pullers_mod.pull_aws_traffic_metrics(account)
    assert result["ok"] is False
    assert result["error"] == "missing_resource_ids"


@pytest.mark.asyncio
async def test_aws_metric_puller_success_with_mock(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(
        provider="aws",
        name="AWS Metric Mock",
        auth_config_json={
            "resource_ids": ["i-123"],
            "metric_names": ["NetworkIn"],
            "metric_namespace": "AWS/EC2",
            "access_key_id": "AKIA",
            "secret_access_key": "secret",
        },
        region_scope="us-east-1",
    )

    async def _mock_fetch(client, **kwargs):
        return [
            {
                "MetricName": "NetworkIn",
                "Namespace": "AWS/EC2",
                "Dimensions": [{"Name": "InstanceId", "Value": "i-123"}],
                "Timestamp": datetime.now(UTC).isoformat(),
                "Average": 1000.0,
                "Unit": "Bytes",
            }
        ]

    monkeypatch.setattr(pullers_mod, "_aws_cloudwatch_fetch", _mock_fetch)

    fake_boto3 = MagicMock()
    fake_botocore_exc = type("module", (), {"BotoCoreError": Exception, "ClientError": Exception})()
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    monkeypatch.setitem(sys.modules, "botocore", MagicMock())
    monkeypatch.setitem(sys.modules, "botocore.exceptions", fake_botocore_exc)
    monkeypatch.setattr(pullers_mod, "_build_boto3_session", lambda auth: MagicMock())

    result = await pullers_mod.pull_aws_traffic_metrics(account)
    assert result["ok"] is True
    assert result["ingested"] == 1

    cursor = await db_module.get_cloud_traffic_metric_sync_cursor(int(account["id"]))
    assert cursor is not None
    assert cursor["last_pull_end"] != ""


@pytest.mark.asyncio
async def test_pull_all_skips_unconfigured_accounts(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    await db_module.create_cloud_account(provider="aws", name="AWS bare", auth_config_json={})
    await db_module.create_cloud_account(provider="azure", name="Azure bare", auth_config_json={})
    await db_module.create_cloud_account(provider="gcp", name="GCP bare", auth_config_json={})

    result = await pullers_mod.pull_traffic_metrics_all_accounts()
    assert result["accounts_processed"] == 0
    assert result["total_ingested"] == 0


@pytest.mark.asyncio
async def test_traffic_sync_config_get_and_update(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    import netcontrol.routes.state as state

    result = await cloud_visibility_module.get_cloud_traffic_sync_config_api()
    assert "config" in result
    assert "status" in result
    assert result["config"]["enabled"] is False
    assert result["status"]["last_run_at"] == ""

    from netcontrol.routes.cloud_visibility import CloudTrafficSyncConfigUpdate

    body = CloudTrafficSyncConfigUpdate(enabled=True, interval_seconds=120)
    result = await cloud_visibility_module.update_cloud_traffic_sync_config_api(_DummyRequest(), body)
    assert result["ok"] is True
    assert result["config"]["enabled"] is True
    assert result["config"]["interval_seconds"] == 120

    assert state.CLOUD_TRAFFIC_METRIC_SYNC_CONFIG["enabled"] is True
    assert state.CLOUD_TRAFFIC_METRIC_SYNC_CONFIG["interval_seconds"] == 120


@pytest.mark.asyncio
async def test_traffic_sync_cursors_api(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider="aws", name="AWS Traffic Cursor Test")
    now_iso = datetime.now(UTC).isoformat()
    await db_module.upsert_cloud_traffic_metric_sync_cursor(int(account["id"]), last_pull_end=now_iso)

    result = await cloud_visibility_module.get_cloud_traffic_sync_cursors_api()
    assert result["count"] == 1
    assert result["cursors"][0]["last_pull_end"] == now_iso


@pytest.mark.asyncio
async def test_manual_traffic_pull_single_account(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(
        provider="aws",
        name="AWS Manual Metric Pull",
        auth_config_json={
            "resource_ids": ["i-123"],
            "metric_names": ["NetworkIn"],
            "metric_namespace": "AWS/EC2",
            "access_key_id": "AKIA",
            "secret_access_key": "secret",
        },
        region_scope="us-east-1",
    )

    async def _mock_fetch(client, **kwargs):
        return [
            {
                "MetricName": "NetworkIn",
                "Namespace": "AWS/EC2",
                "Dimensions": [{"Name": "InstanceId", "Value": "i-123"}],
                "Timestamp": datetime.now(UTC).isoformat(),
                "Average": 1000.0,
                "Unit": "Bytes",
            }
        ]

    monkeypatch.setattr(pullers_mod, "_aws_cloudwatch_fetch", _mock_fetch)

    fake_boto3 = MagicMock()
    fake_botocore_exc = type("module", (), {"BotoCoreError": Exception, "ClientError": Exception})()
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    monkeypatch.setitem(sys.modules, "botocore", MagicMock())
    monkeypatch.setitem(sys.modules, "botocore.exceptions", fake_botocore_exc)
    monkeypatch.setattr(pullers_mod, "_build_boto3_session", lambda auth: MagicMock())

    result = await cloud_visibility_module.trigger_cloud_traffic_sync_api(
        _DummyRequest(), account_id=int(account["id"])
    )
    assert result["ok"] is True
    assert result["ingested"] == 1
    assert result["account_id"] == int(account["id"])
    assert result["status"]["scope"] == "account"
    assert result["status"]["source"] == "manual"
    assert result["status"]["account_name"] == "AWS Manual Metric Pull"
    assert result["status"]["ingested"] == 1

    cfg = await cloud_visibility_module.get_cloud_traffic_sync_config_api()
    assert cfg["status"]["account_id"] == int(account["id"])
    assert cfg["status"]["source"] == "manual"


def test_sanitize_cloud_traffic_sync_config():
    import netcontrol.routes.state as state

    cfg = state._sanitize_cloud_traffic_metric_sync_config(None)
    assert cfg["enabled"] is False
    assert cfg["interval_seconds"] == 300
    assert cfg["lookback_minutes"] == 15

    cfg = state._sanitize_cloud_traffic_metric_sync_config(
        {"enabled": True, "interval_seconds": 120, "lookback_minutes": 30}
    )
    assert cfg["enabled"] is True
    assert cfg["interval_seconds"] == 120
    assert cfg["lookback_minutes"] == 30

    cfg = state._sanitize_cloud_traffic_metric_sync_config(
        {"interval_seconds": 10, "lookback_minutes": 1}
    )
    assert cfg["interval_seconds"] == 60
    assert cfg["lookback_minutes"] == 5
