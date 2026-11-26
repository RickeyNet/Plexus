"""Tests for cloud traffic-metric scheduled pullers."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import netcontrol.routes.cloud_metric_pullers as pullers_mod
import netcontrol.routes.cloud_visibility as cloud_visibility_module
import pytest
import routes.database as db_module


async def _init():
    await db_module.init_db()


class _DummyRequest:
    def __init__(self, correlation_id: str = "test-corr-id"):
        self.cookies = {}
        self.state = type("State", (), {"correlation_id": correlation_id})()


@pytest.mark.parametrize("use_service_principal", [True, False])
def test_azure_metrics_client_accepts_both_credential_types(monkeypatch, use_service_principal):
    identity = MagicMock()
    query = MagicMock()
    monkeypatch.setitem(sys.modules, "azure.identity", identity)
    monkeypatch.setitem(sys.modules, "azure.monitor.query", query)
    auth = {"tenant_id": " tenant ", "client_id": " client ", "client_secret": " fixture "}
    if not use_service_principal:
        auth = {}

    result = pullers_mod._build_azure_metrics_client(auth)

    if use_service_principal:
        identity.ClientSecretCredential.assert_called_once_with(
            tenant_id="tenant", client_id="client", client_secret="fixture"
        )
        identity.DefaultAzureCredential.assert_not_called()
        credential = identity.ClientSecretCredential.return_value
    else:
        identity.DefaultAzureCredential.assert_called_once_with()
        identity.ClientSecretCredential.assert_not_called()
        credential = identity.DefaultAzureCredential.return_value
    query.MetricsQueryClient.assert_called_once_with(credential)
    assert result is query.MetricsQueryClient.return_value


@pytest.mark.parametrize(
    ("metric_name", "expected"),
    [
        # GCP full metric types: "instance" must not match as "in"
        ("compute.googleapis.com/instance/network/sent_bytes_count", "out"),
        ("compute.googleapis.com/instance/network/received_bytes_count", "in"),
        ("compute.googleapis.com/instance/network/sent_packets_count", "out"),
        ("compute.googleapis.com/instance/network/received_packets_count", "in"),
        # AWS CloudWatch names
        ("NetworkIn", "in"),
        ("NetworkOut", "out"),
        ("NetworkPacketsIn", "in"),
        ("NetworkPacketsOut", "out"),
        # Azure Monitor names
        ("BytesIn", "in"),
        ("BytesOut", "out"),
        ("BytesReceivedRate", "in"),
        ("BytesSentRate", "out"),
        ("PacketsReceivedRate", "in"),
        ("PacketsSentRate", "out"),
        ("Network In Total", "in"),
        ("Network Out Total", "out"),
        ("TunnelIngressBytes", "in"),
        ("TunnelEgressPackets", "out"),
        ("IfEgressBytes", "out"),
        ("IfIngressBytes", "in"),
        ("CPUUtilization", ""),
        ("", ""),
    ],
)
def test_metric_direction(metric_name, expected):
    assert pullers_mod._metric_direction(metric_name) == expected


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
async def test_cursor_upsert_and_read():
    await _init()
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
async def test_list_cursors():
    await _init()
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
async def test_aws_metric_puller_missing_resource_ids():
    await _init()
    account = await db_module.create_cloud_account(
        provider="aws", name="AWS No Resource IDs", auth_config_json={"metric_namespace": "AWS/EC2"}
    )
    result = await pullers_mod.pull_aws_traffic_metrics(account)
    assert result["ok"] is False
    assert result["error"] == "missing_resource_ids"


@pytest.mark.asyncio
async def test_aws_metric_puller_success_with_mock(monkeypatch):
    await _init()
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
    monkeypatch.setitem(sys.modules, "botocore.config", type("module", (), {"Config": MagicMock()})())
    monkeypatch.setattr(pullers_mod, "_build_boto3_session", lambda auth: MagicMock())

    result = await pullers_mod.pull_aws_traffic_metrics(account)
    assert result["ok"] is True
    assert result["ingested"] == 1

    cursor = await db_module.get_cloud_traffic_metric_sync_cursor(int(account["id"]))
    assert cursor is not None
    assert cursor["last_pull_end"] != ""


@pytest.mark.asyncio
async def test_pull_all_skips_unconfigured_accounts():
    await _init()
    await db_module.create_cloud_account(provider="aws", name="AWS bare", auth_config_json={})
    await db_module.create_cloud_account(provider="azure", name="Azure bare", auth_config_json={})
    await db_module.create_cloud_account(provider="gcp", name="GCP bare", auth_config_json={})

    result = await pullers_mod.pull_traffic_metrics_all_accounts()
    assert result["accounts_processed"] == 0
    assert result["total_ingested"] == 0


@pytest.mark.asyncio
async def test_traffic_sync_config_get_and_update():
    await _init()
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
async def test_traffic_sync_cursors_api():
    await _init()
    account = await db_module.create_cloud_account(provider="aws", name="AWS Traffic Cursor Test")
    now_iso = datetime.now(UTC).isoformat()
    await db_module.upsert_cloud_traffic_metric_sync_cursor(int(account["id"]), last_pull_end=now_iso)

    result = await cloud_visibility_module.get_cloud_traffic_sync_cursors_api()
    assert result["count"] == 1
    assert result["cursors"][0]["last_pull_end"] == now_iso


@pytest.mark.asyncio
async def test_manual_traffic_pull_single_account(monkeypatch):
    await _init()
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
    monkeypatch.setitem(sys.modules, "botocore.config", type("module", (), {"Config": MagicMock()})())
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

    cfg = state._sanitize_cloud_traffic_metric_sync_config({"interval_seconds": 10, "lookback_minutes": 1})
    assert cfg["interval_seconds"] == 60
    assert cfg["lookback_minutes"] == 5


_AZ_RG = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers"
_NIC_ID = f"{_AZ_RG}/Microsoft.Network/networkInterfaces/nic-1"
_VM_ID = f"{_AZ_RG}/Microsoft.Compute/virtualMachines/vm-1"
_DISK_ID = f"{_AZ_RG}/Microsoft.Compute/disks/disk-1"
_NIC_METRICS = ["BytesReceivedRate", "BytesSentRate", "PacketsReceivedRate", "PacketsSentRate"]


def test_azure_resource_type():
    assert pullers_mod._azure_resource_type(_NIC_ID) == "microsoft.network/networkinterfaces"
    assert pullers_mod._azure_resource_type(_VM_ID) == "microsoft.compute/virtualmachines"
    assert pullers_mod._azure_resource_type("not-a-resource-id") == ""


def test_azure_metric_names_default_per_resource_type():
    assert pullers_mod._azure_metric_names(_NIC_ID, []) == _NIC_METRICS
    assert pullers_mod._azure_metric_names(_VM_ID, []) == ["Network In Total", "Network Out Total"]
    assert pullers_mod._azure_metric_names(_DISK_ID, []) == []
    # Configured names apply to every resource type.
    assert pullers_mod._azure_metric_names(_DISK_ID, ["Custom"]) == ["Custom"]


@pytest.mark.asyncio
async def test_azure_monitor_fetch_queries_each_resource_with_its_defaults():
    from types import SimpleNamespace

    calls: list[tuple[str, list[str]]] = []

    class _Client:
        def query_resource(self, resource_id, metric_names, timespan):
            calls.append((resource_id, list(metric_names)))
            point = SimpleNamespace(total=1024.0, average=None, maximum=None, timestamp=datetime.now(UTC))
            metric = SimpleNamespace(
                name=SimpleNamespace(value=metric_names[0], namespace="azure.monitor"),
                timeseries=[SimpleNamespace(data=[point])],
                unit="Bytes",
            )
            return SimpleNamespace(metrics=[metric])

    now = datetime.now(UTC)
    records = await pullers_mod._azure_monitor_fetch(
        _Client(),
        resource_ids=[_NIC_ID, _DISK_ID, _VM_ID],
        metric_names=[],
        start=now - timedelta(minutes=5),
        end=now,
    )
    # The disk has no default traffic metrics and is not queried.
    assert calls == [(_NIC_ID, _NIC_METRICS), (_VM_ID, ["Network In Total", "Network Out Total"])]
    assert [r["direction"] for r in records] == ["in", "in"]


@pytest.mark.asyncio
async def test_aws_metric_puller_reuses_its_client_and_rebuilds_after_expired_credentials(monkeypatch):
    import threading

    from netcontrol import cloud_sdk

    await _init()
    account = await db_module.create_cloud_account(
        provider="aws",
        name="AWS Metric Reuse",
        auth_config_json={"resource_ids": ["i-0example"], "role_arn": "arn:aws:iam::000000000000:role/example"},
        region_scope="us-east-1",
    )

    class _Expired(Exception):
        response = {"Error": {"Code": "ExpiredToken"}}

    loop_thread = threading.current_thread().name
    sessions: list[MagicMock] = []
    client_threads: list[str] = []
    fetched: list[object] = []
    fail_next = {"on": False}

    def build_session(auth):
        session = MagicMock()
        session.region_name = None
        n = len(sessions) + 1

        def client(service, region_name=None, config=None):
            client_threads.append(threading.current_thread().name)
            return f"{service}@{region_name}#{n}"

        session.client.side_effect = client
        sessions.append(session)
        return session

    async def _mock_fetch(client, **kwargs):
        fetched.append(client)
        if fail_next["on"]:
            fail_next["on"] = False
            raise _Expired()
        return []

    monkeypatch.setattr(pullers_mod, "_aws_cloudwatch_fetch", _mock_fetch)
    monkeypatch.setitem(sys.modules, "boto3", MagicMock())
    monkeypatch.setitem(sys.modules, "botocore", MagicMock())
    monkeypatch.setitem(
        sys.modules, "botocore.exceptions", type("module", (), {"BotoCoreError": _Expired, "ClientError": _Expired})()
    )
    monkeypatch.setitem(sys.modules, "botocore.config", type("module", (), {"Config": MagicMock()})())
    monkeypatch.setattr(pullers_mod, "_build_boto3_session", build_session)
    cloud_sdk._SDK_CLIENTS.discard()
    try:
        assert (await pullers_mod.pull_aws_traffic_metrics(account, lookback_minutes=5))["ok"] is True
        await db_module.upsert_cloud_traffic_metric_sync_cursor(int(account["id"]), last_pull_end="", extra_json={})
        fail_next["on"] = True
        assert (await pullers_mod.pull_aws_traffic_metrics(account, lookback_minutes=5))["ok"] is False
        await db_module.upsert_cloud_traffic_metric_sync_cursor(int(account["id"]), last_pull_end="", extra_json={})
        assert (await pullers_mod.pull_aws_traffic_metrics(account, lookback_minutes=5))["ok"] is True

        # One session and client for the first two cycles; the expired token
        # dropped them, so the third built new ones.
        assert fetched == ["cloudwatch@us-east-1#1", "cloudwatch@us-east-1#1", "cloudwatch@us-east-1#2"]
        assert len(sessions) == 2
        assert client_threads and loop_thread not in client_threads
    finally:
        cloud_sdk._SDK_CLIENTS.discard()
