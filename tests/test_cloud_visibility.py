"""Tests for cloud visibility account and topology foundation."""

import netcontrol.routes.cloud_visibility as cloud_visibility_module
import pytest
import routes.database as db_module
from fastapi import HTTPException
from netcontrol.routes.cloud_visibility import (
    CloudDiscoveryRequest,
    CloudFlowIngestRequest,
    CloudTrafficMetricIngestRequest,
    CloudValidationRequest,
    _build_sample_discovery_snapshot,
)


async def _init(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_cloud_visibility.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    return db_path


async def _add_host(group_name="core", hostname="core-sw1", ip="10.0.0.10"):
    db = await db_module.get_db()
    try:
        cur = await db.execute(
            "INSERT OR IGNORE INTO inventory_groups (name) VALUES (?)",
            (group_name,),
        )
        if cur.lastrowid:
            group_id = cur.lastrowid
        else:
            q = await db.execute("SELECT id FROM inventory_groups WHERE name = ?", (group_name,))
            group_id = (await q.fetchone())[0]

        cur = await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address) VALUES (?, ?, ?)",
            (group_id, hostname, ip),
        )
        await db.commit()
        return cur.lastrowid
    finally:
        await db.close()


class _DummyRequest:
    def __init__(self, correlation_id: str = "test-corr-id"):
        self.cookies = {}
        self.state = type("State", (), {"correlation_id": correlation_id})()


@pytest.mark.asyncio
async def test_cloud_account_crud(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)

    created = await db_module.create_cloud_account(
        provider="aws",
        name="AWS Prod",
        account_identifier="123456789012",
        region_scope="us-east-1",
        auth_type="api_keys",
        auth_config_json={"secret_ref": "aws-prod-readonly"},
        notes="Primary production account",
        enabled=1,
        created_by="admin",
    )
    assert created is not None
    assert created["provider"] == "aws"
    assert created["name"] == "AWS Prod"

    listed = await db_module.list_cloud_accounts(provider="aws")
    assert len(listed) == 1
    assert listed[0]["account_identifier"] == "123456789012"

    updated = await db_module.update_cloud_account(
        int(created["id"]),
        notes="Updated note",
        enabled=0,
        auth_config_json={"secret_ref": "aws-prod-updated"},
    )
    assert updated is not None
    assert updated["notes"] == "Updated note"
    assert updated["enabled"] == 0

    deleted = await db_module.delete_cloud_account(int(created["id"]))
    assert deleted
    assert await db_module.get_cloud_account(int(created["id"])) is None


@pytest.mark.asyncio
async def test_replace_cloud_snapshot_and_read_topology(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()
    account = await db_module.create_cloud_account(provider="azure", name="Azure Core")
    assert account is not None

    summary = await db_module.replace_cloud_discovery_snapshot(
        int(account["id"]),
        resources=[
            {
                "provider": "azure",
                "resource_uid": "azure:vnet:core",
                "resource_type": "vnet",
                "name": "core-vnet",
                "region": "centralus",
                "cidr": "10.50.0.0/16",
                "status": "connected",
            },
            {
                "provider": "azure",
                "resource_uid": "azure:er:primary",
                "resource_type": "expressroute",
                "name": "er-primary",
                "region": "centralus",
                "status": "up",
            },
        ],
        connections=[
            {
                "provider": "azure",
                "source_resource_uid": "azure:vnet:core",
                "target_resource_uid": "azure:er:primary",
                "connection_type": "expressroute_gateway",
                "state": "up",
            }
        ],
        hybrid_links=[
            {
                "provider": "azure",
                "host_id": host_id,
                "host_label": "core-sw1",
                "cloud_resource_uid": "azure:er:primary",
                "connection_type": "expressroute",
                "state": "up",
            }
        ],
    )
    assert summary["ok"]
    assert summary["resources"] == 2
    assert summary["connections"] == 1
    assert summary["hybrid_links"] == 1

    snapshot = await db_module.get_cloud_topology_snapshot(account_id=int(account["id"]))
    assert snapshot["summary"]["resource_count"] == 2
    assert snapshot["summary"]["connection_count"] == 1
    assert snapshot["summary"]["hybrid_link_count"] == 1

    resource_uids = {r["resource_uid"] for r in snapshot["resources"]}
    assert "azure:vnet:core" in resource_uids
    assert "azure:er:primary" in resource_uids


@pytest.mark.asyncio
async def test_sample_discovery_snapshot_builds_hybrid_links(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host(hostname="edge-rtr1", ip="10.0.0.20")
    account = await db_module.create_cloud_account(provider="gcp", name="GCP Shared")
    assert account is not None

    resources, connections, hybrid_links = await _build_sample_discovery_snapshot(
        account,
        connect_host_ids=[host_id],
        include_hybrid_links=True,
    )

    assert resources
    assert connections
    assert hybrid_links
    assert any(r["resource_type"] == "cloud_router" for r in resources)
    assert any(c["connection_type"] == "vpn_tunnel" for c in connections)
    assert any(int(link.get("host_id") or 0) == host_id for link in hybrid_links)


@pytest.mark.asyncio
async def test_discover_auto_falls_back_to_sample_when_live_unavailable(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host(hostname="wan-edge-1", ip="10.0.0.30")
    account = await db_module.create_cloud_account(provider="aws", name="AWS Shared")
    assert account is not None

    def _raise_unavailable(_account):
        raise cloud_visibility_module.CloudCollectorUnavailable("missing")

    monkeypatch.setattr(cloud_visibility_module, "collect_provider_snapshot", _raise_unavailable)

    result = await cloud_visibility_module.discover_cloud_account_api(
        int(account["id"]),
        _DummyRequest(),
        CloudDiscoveryRequest(mode="auto", connect_host_ids=[host_id], include_hybrid_links=True),
    )

    assert result["ok"] is True
    assert result["effective_mode"] == "sample"
    assert result["fallback_used"] is True
    assert "sample" in result["message"].lower()

    snapshot = await db_module.get_cloud_topology_snapshot(account_id=int(account["id"]))
    assert snapshot["summary"]["resource_count"] > 0
    assert snapshot["summary"]["connection_count"] > 0


@pytest.mark.asyncio
async def test_discover_live_uses_collector_snapshot(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host(hostname="wan-edge-2", ip="10.0.0.31")
    account = await db_module.create_cloud_account(provider="aws", name="AWS Live")
    assert account is not None

    def _collector(_account):
        return (
            [
                {
                    "provider": "aws",
                    "resource_uid": "aws:direct_connect:dxcon-123",
                    "resource_type": "direct_connect",
                    "name": "dx-primary",
                    "region": "us-east-1",
                    "status": "up",
                },
                {
                    "provider": "aws",
                    "resource_uid": "aws:vpc:vpc-123",
                    "resource_type": "vpc",
                    "name": "prod-core",
                    "region": "us-east-1",
                    "cidr": "10.10.0.0/16",
                    "status": "active",
                },
            ],
            [
                {
                    "provider": "aws",
                    "source_resource_uid": "aws:vpc:vpc-123",
                    "target_resource_uid": "aws:direct_connect:dxcon-123",
                    "connection_type": "direct_connect_gateway",
                    "state": "up",
                }
            ],
        )

    monkeypatch.setattr(cloud_visibility_module, "collect_provider_snapshot", _collector)

    result = await cloud_visibility_module.discover_cloud_account_api(
        int(account["id"]),
        _DummyRequest(),
        CloudDiscoveryRequest(mode="live", connect_host_ids=[host_id], include_hybrid_links=True),
    )

    assert result["ok"] is True
    assert result["effective_mode"] == "live"
    assert result["fallback_used"] is False

    snapshot = await db_module.get_cloud_topology_snapshot(account_id=int(account["id"]))
    assert snapshot["summary"]["resource_count"] == 2
    assert snapshot["summary"]["connection_count"] == 1
    assert snapshot["summary"]["hybrid_link_count"] >= 1
    assert any(link.get("host_id") == host_id for link in snapshot["hybrid_links"])


@pytest.mark.asyncio
async def test_discover_live_persists_cloud_policy_rules(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider="aws", name="AWS Policy Live")
    assert account is not None

    def _collector(_account):
        return (
            [
                {
                    "provider": "aws",
                    "resource_uid": "aws:sg:app-edge",
                    "resource_type": "security_group",
                    "name": "sg-app-edge",
                    "region": "us-east-1",
                    "status": "active",
                    "metadata": {
                        "policy_rules": [
                            {
                                "rule_uid": "aws:sg:app-edge:ingress:https",
                                "rule_name": "HTTPS ingress",
                                "direction": "inbound",
                                "action": "allow",
                                "protocol": "tcp",
                                "source_selector": "0.0.0.0/0",
                                "destination_selector": "self",
                                "port_expression": "443",
                            },
                            {
                                "rule_uid": "aws:sg:app-edge:egress:any",
                                "rule_name": "All egress",
                                "direction": "outbound",
                                "action": "allow",
                                "protocol": "all",
                                "source_selector": "self",
                                "destination_selector": "0.0.0.0/0",
                                "port_expression": "all",
                            },
                        ]
                    },
                }
            ],
            [],
        )

    monkeypatch.setattr(cloud_visibility_module, "collect_provider_snapshot", _collector)

    result = await cloud_visibility_module.discover_cloud_account_api(
        int(account["id"]),
        _DummyRequest(),
        CloudDiscoveryRequest(mode="live", include_hybrid_links=False),
    )

    assert result["ok"] is True
    assert result["summary"]["policy_rules"] == 2

    rules = await cloud_visibility_module.cloud_policy_rules_api(account_id=int(account["id"]), provider="aws")
    assert rules["count"] == 2
    assert {row["direction"] for row in rules["rules"]} == {"inbound", "outbound"}

    effective = await cloud_visibility_module.cloud_policy_effective_views_api(
        account_id=int(account["id"]),
        provider="aws",
    )
    assert effective["count"] == 1
    assert effective["resources"][0]["rule_count"] == 2
    assert effective["resources"][0]["public_ingress_count"] == 1
    assert effective["resources"][0]["open_egress_count"] == 1


@pytest.mark.asyncio
async def test_discover_live_unavailable_raises_503(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider="azure", name="Azure Live")
    assert account is not None

    def _raise_unavailable(_account):
        raise cloud_visibility_module.CloudCollectorUnavailable("missing")

    monkeypatch.setattr(cloud_visibility_module, "collect_provider_snapshot", _raise_unavailable)

    with pytest.raises(HTTPException) as exc_info:
        await cloud_visibility_module.discover_cloud_account_api(
            int(account["id"]),
            _DummyRequest(),
            CloudDiscoveryRequest(mode="live"),
        )
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_validate_live_returns_ready_when_collector_succeeds(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider="gcp", name="GCP Validate")
    assert account is not None

    def _collector(_account):
        return (
            [
                {
                    "provider": "gcp",
                    "resource_uid": "gcp:vpc:proj:core",
                    "resource_type": "vpc",
                    "name": "core-vpc",
                    "region": "us-central1",
                    "status": "active",
                }
            ],
            [],
        )

    monkeypatch.setattr(cloud_visibility_module, "collect_provider_snapshot", _collector)

    result = await cloud_visibility_module.validate_cloud_account_api(
        int(account["id"]),
        _DummyRequest(),
        CloudValidationRequest(mode="live"),
    )

    assert result["ok"] is True
    assert result["valid"] is True
    assert result["status"] == "ready"
    assert result["resource_sample_count"] == 1
    assert result["connection_sample_count"] == 0


@pytest.mark.asyncio
async def test_validate_live_returns_unavailable_when_deps_missing(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider="aws", name="AWS Validate")
    assert account is not None

    def _raise_unavailable(_account):
        raise cloud_visibility_module.CloudCollectorUnavailable("missing")

    monkeypatch.setattr(cloud_visibility_module, "collect_provider_snapshot", _raise_unavailable)

    result = await cloud_visibility_module.validate_cloud_account_api(
        int(account["id"]),
        _DummyRequest(),
        CloudValidationRequest(mode="live"),
    )

    assert result["ok"] is True
    assert result["valid"] is False
    assert result["status"] == "unavailable"
    assert isinstance(result["missing_dependencies"], list)


@pytest.mark.asyncio
async def test_ingest_cloud_flow_logs_normalized_and_query_stats(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider="aws", name="AWS Flow Logs")
    assert account is not None
    account_id = int(account["id"])

    ingest_result = await cloud_visibility_module.ingest_cloud_flow_logs_api(
        account_id,
        _DummyRequest(),
        CloudFlowIngestRequest(
            format="normalized",
            source="pytest",
            records=[
                {
                    "src_ip": "10.1.1.10",
                    "dst_ip": "10.2.2.20",
                    "src_port": 443,
                    "dst_port": 51514,
                    "protocol": "tcp",
                    "bytes": 4200,
                    "packets": 14,
                    "start_time": "2026-04-16T12:00:00Z",
                    "end_time": "2026-04-16T12:01:00Z",
                    "action": "accept",
                    "direction": "egress",
                },
                {
                    "src_ip": "10.1.1.10",
                    "dst_ip": "10.3.3.30",
                    "src_port": 443,
                    "dst_port": 443,
                    "protocol": 6,
                    "bytes": 1800,
                    "packets": 8,
                    "start_time": "2026-04-16T12:03:00Z",
                    "end_time": "2026-04-16T12:04:00Z",
                    "action": "accept",
                    "direction": "egress",
                },
            ],
        ),
    )

    assert ingest_result["ok"] is True
    assert ingest_result["ingested"] == 2
    assert ingest_result["summary"]["flow_count"] == 2
    assert ingest_result["summary"]["total_bytes"] == 6000
    assert ingest_result["summary"]["total_packets"] == 22

    summary = await cloud_visibility_module.cloud_flow_summary_api(
        account_id=account_id,
        provider="aws",
        hours=24,
    )
    assert summary["summary"]["flow_count"] == 2
    assert summary["summary"]["total_bytes"] == 6000

    talkers = await cloud_visibility_module.cloud_flow_top_talkers_api(
        account_id=account_id,
        provider="aws",
        hours=24,
        direction="src",
        limit=10,
    )
    assert talkers["count"] >= 1
    assert talkers["talkers"][0]["ip"] == "10.1.1.10"

    timeline = await cloud_visibility_module.cloud_flow_timeline_api(
        account_id=account_id,
        provider="aws",
        hours=24,
        bucket_minutes=5,
    )
    assert timeline["count"] >= 1

    events = await db_module.get_trap_syslog_events(event_type="cloud_flow", limit=20)
    assert any(e.get("source_ip") == f"cloud:aws:{account_id}" for e in events)


@pytest.mark.asyncio
async def test_ingest_cloud_flow_logs_aws_format(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider="aws", name="AWS VPC Flow Feed")
    assert account is not None

    result = await cloud_visibility_module.ingest_cloud_flow_logs_api(
        int(account["id"]),
        _DummyRequest(),
        CloudFlowIngestRequest(
            format="aws",
            records=[
                {
                    "srcaddr": "10.10.0.10",
                    "dstaddr": "10.20.0.20",
                    "srcport": 55231,
                    "dstport": 443,
                    "protocol": 6,
                    "packets": 11,
                    "bytes": 3300,
                    "start": 1713270000,
                    "end": 1713270060,
                    "action": "ACCEPT",
                    "flow-direction": "egress",
                    "vpc-id": "vpc-123",
                }
            ],
        ),
    )

    assert result["ok"] is True
    assert result["ingested"] == 1
    assert result["summary"]["action_breakdown"].get("accept") == 1


@pytest.mark.asyncio
async def test_ingest_cloud_traffic_metrics_normalized_and_query_stats(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider="azure", name="Azure Traffic Metrics")
    assert account is not None
    account_id = int(account["id"])

    ingest_result = await cloud_visibility_module.ingest_cloud_traffic_metrics_api(
        account_id,
        _DummyRequest(),
        CloudTrafficMetricIngestRequest(
            format="normalized",
            source="pytest",
            records=[
                {
                    "metric_name": "bytes_in",
                    "metric_namespace": "azure.monitor",
                    "resource_uid": "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Network/networkInterfaces/nic-a",
                    "statistic": "total",
                    "unit": "bytes",
                    "value": 120000,
                    "interval_start": "2026-04-20T12:00:00Z",
                    "interval_end": "2026-04-20T12:05:00Z",
                },
                {
                    "metric_name": "bytes_in",
                    "metric_namespace": "azure.monitor",
                    "resource_uid": "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Network/networkInterfaces/nic-a",
                    "statistic": "total",
                    "unit": "bytes",
                    "value": 80000,
                    "interval_start": "2026-04-20T12:05:00Z",
                    "interval_end": "2026-04-20T12:10:00Z",
                },
                {
                    "metric_name": "packets_out",
                    "metric_namespace": "azure.monitor",
                    "resource_uid": "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Network/networkInterfaces/nic-b",
                    "statistic": "total",
                    "unit": "count",
                    "value": 2300,
                    "interval_start": "2026-04-20T12:00:00Z",
                    "interval_end": "2026-04-20T12:05:00Z",
                },
            ],
        ),
    )

    assert ingest_result["ok"] is True
    assert ingest_result["ingested"] == 3
    assert ingest_result["summary"]["sample_count"] == 3
    assert ingest_result["summary"]["metric_count"] == 2
    assert ingest_result["summary"]["resource_count"] == 2

    summary = await cloud_visibility_module.cloud_traffic_metric_summary_api(
        account_id=account_id,
        provider="azure",
        hours=24,
    )
    assert summary["summary"]["sample_count"] == 3
    assert summary["summary"]["metric_count"] == 2
    assert summary["summary"]["resource_count"] == 2

    top_resources = await cloud_visibility_module.cloud_traffic_metric_top_resources_api(
        account_id=account_id,
        provider="azure",
        metric_name="bytes_in",
        hours=24,
        limit=10,
    )
    assert top_resources["count"] >= 1
    assert "nic-a" in top_resources["resources"][0]["resource_uid"]

    timeline = await cloud_visibility_module.cloud_traffic_metric_timeline_api(
        account_id=account_id,
        provider="azure",
        metric_name="bytes_in",
        hours=24,
        bucket_minutes=5,
    )
    assert timeline["count"] >= 1

    events = await db_module.get_trap_syslog_events(event_type="cloud_traffic_metric", limit=20)
    assert any(e.get("source_ip") == f"cloud:azure:{account_id}" for e in events)


@pytest.mark.asyncio
async def test_ingest_cloud_traffic_metrics_aws_format(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider="aws", name="AWS Traffic Metrics")
    assert account is not None

    result = await cloud_visibility_module.ingest_cloud_traffic_metrics_api(
        int(account["id"]),
        _DummyRequest(),
        CloudTrafficMetricIngestRequest(
            format="aws",
            records=[
                {
                    "Namespace": "AWS/EC2",
                    "MetricName": "NetworkIn",
                    "Dimensions": [{"Name": "InstanceId", "Value": "i-abc123"}],
                    "Timestamp": "2026-04-20T10:00:00Z",
                    "Value": 3210.5,
                    "Unit": "Bytes",
                    "Statistic": "Sum",
                }
            ],
        ),
    )

    assert result["ok"] is True
    assert result["ingested"] == 1
    assert result["summary"]["sample_count"] == 1
    assert result["summary"]["metric_count"] == 1
    assert result["summary"]["resource_count"] == 1


@pytest.mark.asyncio
async def test_sample_discovery_policy_rules_visible_via_api(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider="gcp", name="GCP Sample Policy")
    assert account is not None

    result = await cloud_visibility_module.discover_cloud_account_api(
        int(account["id"]),
        _DummyRequest(),
        CloudDiscoveryRequest(mode="sample", include_hybrid_links=False),
    )

    assert result["ok"] is True
    assert result["summary"]["policy_rules"] >= 2

    rules = await cloud_visibility_module.cloud_policy_rules_api(provider="gcp", account_id=int(account["id"]))
    assert rules["count"] >= 2
    assert any(row["action"] == "deny" for row in rules["rules"])

    effective = await cloud_visibility_module.cloud_policy_effective_views_api(
        provider="gcp",
        account_id=int(account["id"]),
    )
    assert effective["count"] >= 1
    assert effective["resources"][0]["rule_count"] >= 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "resource_types", "connection_types"),
    [
        ("aws", {"route_table", "internet_gateway", "nat_gateway"}, {"route_table_association", "route_next_hop", "internet_gateway_attachment"}),
        ("azure", {"route_table", "virtual_network_gateway", "local_network_gateway"}, {"route_table_association", "virtual_network_gateway_attachment", "ipsec"}),
        ("gcp", {"route_entry", "interconnect_attachment"}, {"route_table_association", "interconnect_attachment", "vpc_peering"}),
    ],
)
async def test_sample_discovery_snapshot_includes_phase_d_topology(tmp_path, monkeypatch, provider, resource_types, connection_types):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider=provider, name=f"{provider} Sample Topology")
    assert account is not None

    resources, connections, _hybrid_links = await _build_sample_discovery_snapshot(
        account,
        connect_host_ids=[],
        include_hybrid_links=False,
    )

    discovered_resource_types = {row["resource_type"] for row in resources}
    discovered_connection_types = {row["connection_type"] for row in connections}

    assert resource_types.issubset(discovered_resource_types)
    assert connection_types.issubset(discovered_connection_types)


@pytest.mark.asyncio
async def test_cloud_policy_rules_api_supports_action_direction_and_resource_filters(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    account = await db_module.create_cloud_account(provider="gcp", name="GCP Filtered Policy")
    assert account is not None

    result = await cloud_visibility_module.discover_cloud_account_api(
        int(account["id"]),
        _DummyRequest(),
        CloudDiscoveryRequest(mode="sample", include_hybrid_links=False),
    )

    assert result["ok"] is True

    deny_rules = await cloud_visibility_module.cloud_policy_rules_api(
        provider="gcp",
        account_id=int(account["id"]),
        action="deny",
    )
    assert deny_rules["count"] == 1
    deny_rule = deny_rules["rules"][0]
    assert deny_rule["action"] == "deny"

    resource_rules = await cloud_visibility_module.cloud_policy_rules_api(
        provider="gcp",
        account_id=int(account["id"]),
        resource_uid=deny_rule["resource_uid"],
        direction="inbound",
        action="deny",
    )
    assert resource_rules["count"] == 1
    assert resource_rules["rules"][0]["rule_uid"] == deny_rule["rule_uid"]
