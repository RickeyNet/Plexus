"""MCP monitoring and topology tools, including the stored-data path trace."""

from __future__ import annotations

import pytest
import routes.database as db
from netcontrol.mcp import registry

import pg_raw
from mcp_helpers import call, db_ctx

RTR_CONFIG = """\
hostname edge-rtr-01
interface GigabitEthernet0/0
 ip address 192.0.2.1 255.255.255.128
interface GigabitEthernet0/1
 ip address 192.0.2.129 255.255.255.128
"""


@pytest.fixture(autouse=True)
def _tools():
    registry.load_tools()


async def _hosts() -> dict[str, int]:
    group = await db.create_group("Campus", "")
    return {
        "rtr": await db.add_host(group, "edge-rtr-01", "192.0.2.1", "cisco_ios"),
        "sw": await db.add_host(group, "core-sw-01", "192.0.2.2", "cisco_ios"),
    }


# ── Monitoring ───────────────────────────────────────────────────────────────


async def _seed_alerts(ids: dict[str, int]) -> None:
    poll = await db.create_monitoring_poll(ids["rtr"], cpu_percent=95.0)
    await db.create_monitoring_alert(ids["rtr"], poll, "threshold", "cpu_percent", "CPU above 90%", "critical", 95, 90)
    acked = await db.create_monitoring_alert(
        ids["sw"], None, "threshold", "memory_percent", "Memory above 80%", "warning", 85, 80, dedup_key="m"
    )
    await pg_raw.execute("UPDATE monitoring_alerts SET acknowledged = 1 WHERE id = $1", acked)
    from netcontrol.integrations.meraki import alerts, alerts_sample as sample

    org = await db.create_meraki_org("Example Retail", org_id=sample.ORG_ID, api_key="k")
    event = alerts.from_assurance_alert(sample.assurance_alert(), org_ref=org["id"], org={"name": "Example Retail"})
    await db.apply_meraki_alert_events([event])


async def test_alerts_default_to_active():
    ids = await _hosts()
    await _seed_alerts(ids)
    ctx = await db_ctx()
    data, is_error = await call(ctx, "list_alerts", {})
    assert is_error is False
    inventory = [r for r in data["items"] if r["source"] == "inventory"]
    assert [r["host"]["hostname"] for r in inventory] == ["edge-rtr-01"]
    assert inventory[0]["severity"] == "critical" and inventory[0]["message"] == "CPU above 90%"
    assert inventory[0]["acknowledged"] is False

    data, _ = await call(ctx, "list_alerts", {"state": "all"})
    assert {r["host"]["hostname"] for r in data["items"] if r["source"] == "inventory"} == {
        "edge-rtr-01",
        "core-sw-01",
    }
    data, _ = await call(ctx, "list_alerts", {"state": "all", "host": "core-sw-01"})
    assert [r["message"] for r in data["items"]] == ["Memory above 80%"]
    data, _ = await call(ctx, "list_alerts", {"severity": "warning", "state": "all", "host": "edge-rtr-01"})
    assert data["items"] == []
    data, _ = await call(ctx, "list_alerts", {"state": "all", "until": "2020-01-01T00:00:00Z"})
    assert data["items"] == []


async def test_alerts_include_meraki_source():
    ids = await _hosts()
    await _seed_alerts(ids)
    data, _ = await call(await db_ctx(), "list_alerts", {})
    meraki = [r for r in data["items"] if r["source"] == "meraki"]
    assert len(meraki) == 1
    assert meraki[0]["organization"] == "Example Retail" and meraki[0]["status"] == "open"
    assert meraki[0]["message"]


async def test_health_summarises_history():
    ids = await _hosts()
    for n in range(100):
        await db.create_monitoring_poll(ids["rtr"], cpu_percent=float(n), memory_percent=50.0, response_time_ms=10.0)
    await db.create_monitoring_poll(ids["rtr"], poll_status="error", poll_error="timeout")
    data, is_error = await call(await db_ctx(), "get_device_health", {"host": "edge-rtr-01"})
    assert is_error is False
    assert data["host"]["hostname"] == "edge-rtr-01"
    assert data["polls_in_window"] == 101 and data["failed_polls_in_window"] == 1
    assert data["summary"]["cpu_percent"] == {"min": 0.0, "avg": 49.5, "max": 99.0, "samples": 100}
    assert data["summary"]["memory_percent"]["avg"] == 50.0
    assert "polled_at" in data["latest_poll"] and "if_details" not in data["latest_poll"]
    assert "polls" not in data and len(str(data)) < 4000


async def test_never_polled_is_no_data():
    await _hosts()
    ctx = await db_ctx()
    data, is_error = await call(ctx, "get_device_health", {"host": "edge-rtr-01"})
    assert is_error is False and data["no_data"] is True and "edge-rtr-01" in data["message"]
    data, _ = await call(ctx, "list_alerts", {})
    assert data["no_data"] is True
    data, _ = await call(ctx, "get_sla_status", {})
    assert data["no_data"] is True


async def test_get_sla_status():
    ids = await _hosts()
    await db.create_monitoring_poll(ids["rtr"], cpu_percent=5.0, response_time_ms=12.0)
    await db.create_sla_target("Core uptime", "uptime", 99.9, 99.5, host_id=ids["rtr"])
    await db.create_sla_target("Branch latency", "latency", 50, 80)
    ctx = await db_ctx()
    data, is_error = await call(ctx, "get_sla_status", {})
    assert is_error is False
    assert {t["name"] for t in data["targets"]} == {"Core uptime", "Branch latency"}
    core = next(t for t in data["targets"] if t["name"] == "Core uptime")
    assert core["metric"] == "uptime" and core["target_value"] == 99.9
    assert isinstance(core["breaching_hosts"], list)
    assert "period_days" in data["summary"] and "hosts" not in data["summary"]
    data, _ = await call(ctx, "get_sla_status", {"target": "branch"})
    assert [t["name"] for t in data["targets"]] == ["Branch latency"]


async def test_list_outages_shape():
    await _hosts()
    data, is_error = await call(await db_ctx(), "list_outages", {"since": "2026-01-01T00:00:00Z"})
    assert is_error is False
    assert data["items"] == [] and data["transitions"] == [] and data["transition_count"] == 0
    text, is_error = await call(
        await db_ctx(name="b2"), "list_outages", {"since": "2026-02-01T00:00:00Z", "until": "2026-01-01T00:00:00Z"}
    )
    assert is_error is True and "earlier" in text


# ── Topology ─────────────────────────────────────────────────────────────────


async def test_get_neighbors_from_both_ends():
    ids = await _hosts()
    await db.upsert_topology_link(
        ids["rtr"], "192.0.2.1", "Gi0/1", ids["sw"], "192.0.2.2", "core-sw-01", "Te1/0/1", "lldp", "cisco C9300"
    )
    ctx = await db_ctx()
    data, is_error = await call(ctx, "get_neighbors", {"host": "edge-rtr-01"})
    assert is_error is False
    (link,) = data["neighbors"]
    assert link["local_interface"] == "Gi0/1" and link["remote_device"] == "core-sw-01"
    assert link["remote_interface"] == "Te1/0/1" and link["protocol"] == "lldp"
    data, _ = await call(ctx, "get_neighbors", {"host": "core-sw-01"})
    (link,) = data["neighbors"]
    assert link["local_interface"] == "Te1/0/1" and link["remote_device"] == "edge-rtr-01"
    assert link["remote_interface"] == "Gi0/1"


async def test_get_interfaces():
    ids = await _hosts()
    await db.upsert_interface_inventory(ids["sw"], 1, "Gi1/0/1", "user port", "up", "up", 1000, "full", "", 20, "")
    await db.upsert_interface_inventory(ids["sw"], 2, "Te1/1/1", "uplink", "up", "down", 10000, "full", "", 0, "10,20")
    ctx = await db_ctx()
    data, is_error = await call(ctx, "get_interfaces", {"host": "core-sw-01"})
    assert is_error is False
    assert [i["name"] for i in data["interfaces"]] == ["Gi1/0/1", "Te1/1/1"]
    assert data["interfaces"][1]["oper_state"] == "down" and data["interfaces"][0]["access_vlan"] == 20
    assert "host_id" not in data["interfaces"][0]
    data, _ = await call(ctx, "get_interfaces", {"host": "core-sw-01", "name": "te1"})
    assert [i["name"] for i in data["interfaces"]] == ["Te1/1/1"]
    data, _ = await call(ctx, "get_interfaces", {"host": "edge-rtr-01"})
    assert data["no_data"] is True
    data, _ = await call(ctx, "get_neighbors", {"host": "edge-rtr-01"})
    assert data["no_data"] is True


async def test_list_topology_changes():
    ids = await _hosts()
    await pg_raw.execute(
        "INSERT INTO topology_changes (change_type, source_host_id, source_hostname, source_interface,"
        " target_device_name, target_interface, target_ip, protocol)"
        " VALUES ('removed', $1, 'edge-rtr-01', 'Gi0/1', 'core-sw-01', 'Te1/0/1', '192.0.2.2', 'lldp')",
        ids["rtr"],
    )
    ctx = await db_ctx()
    data, is_error = await call(ctx, "list_topology_changes", {})
    assert is_error is False
    (change,) = data["items"]
    assert change["kind"] == "link" and change["change_type"] == "removed"
    assert change["source_hostname"] == "edge-rtr-01"
    data, _ = await call(ctx, "list_topology_changes", {"until": "2020-01-01T00:00:00Z"})
    assert data["items"] == []


async def _seed_trace() -> dict[str, int]:
    ids = await _hosts()
    await db.create_config_backup(None, ids["rtr"], RTR_CONFIG)
    return ids


def _trace_over_http(monkeypatch, request, arguments: dict) -> dict:
    """Load the built-in Panorama sample (invented data) and trace through
    the MCP endpoint, as a client would."""
    import json

    from mcp_helpers import admin_client, create_token, enable_mcp
    from test_mcp_protocol import bare_client, rpc

    admin = admin_client(monkeypatch, request)
    assert admin.post("/api/sources/sample?provider=panorama").status_code == 201
    enable_mcp(admin)
    token = create_token(admin, categories=("topology",))
    result = rpc(bare_client(admin), token, "tools/call", {"name": "trace_path", "arguments": arguments})
    assert result["isError"] is False, result
    return json.loads(result["content"][0]["text"])


def test_trace_path_returns_hops_from_stored_data(monkeypatch, request):
    allowed = _trace_over_http(
        monkeypatch,
        request,
        {"source": "10.130.10.0/24", "destination": "10.131.10.0/24", "protocol": "tcp", "port": 443},
    )
    assert allowed["verdict"] == "allowed", allowed["summary"]
    assert len(allowed["request"]["hops"]) == 2 and len(allowed["reply"]["hops"]) == 2
    assert any("Allow-HQ-to-Branch" in item["text"] for item in allowed["request"]["hops"][0]["items"])


def test_trace_path_names_the_blocking_rule(monkeypatch, request):
    denied = _trace_over_http(
        monkeypatch,
        request,
        {"source": "10.130.10.0/24", "destination": "10.130.50.25", "protocol": "tcp", "port": 22},
    )
    assert denied["verdict"] == "blocked", denied["summary"]
    (hop,) = denied["request"]["hops"]
    blocked = next(item for item in hop["items"] if item["status"] == "blocked")
    assert "interzone-default" in blocked["text"]


async def test_trace_path_accepts_a_device_name():
    await _seed_trace()
    data, is_error = await call(await db_ctx(), "trace_path", {"source": "edge-rtr-01", "destination": "192.0.2.200"})
    assert is_error is False, data
    assert data["source"]["address"] == "192.0.2.1" and data["destination"]["address"] == "192.0.2.200"


def test_trace_path_never_collects(monkeypatch, request):
    import httpx
    import netmiko

    def _refuse(*args, **kwargs):
        raise AssertionError("the path trace must not contact a device or an API")

    monkeypatch.setattr(netmiko, "ConnectHandler", _refuse)
    monkeypatch.setattr(httpx.AsyncClient, "send", _refuse)
    traced = _trace_over_http(
        monkeypatch, request, {"source": "10.130.10.0/24", "destination": "10.131.10.0/24", "protocol": "tcp"}
    )
    assert traced["verdict"] in ("allowed", "blocked")


async def test_trace_unknown_endpoint_is_tool_error():
    await _seed_trace()
    ctx = await db_ctx()
    text, is_error = await call(ctx, "trace_path", {"source": "no-such-device", "destination": "192.0.2.200"})
    assert is_error is True and text.startswith("source: No host matches 'no-such-device'")
    text, is_error = await call(ctx, "trace_path", {"source": "192.0.2.10", "destination": "also-missing"})
    assert is_error is True and text.startswith("destination: No host matches")
    text, is_error = await call(ctx, "trace_path", {"source": "192.0.2.10", "destination": "x", "protocol": "gre"})
    assert is_error is True


async def test_hidden_without_category():
    monitoring_only = await db_ctx(categories=["monitoring"], name="m-bot")
    topology_only = await db_ctx(categories=["topology"], name="t-bot")
    monitoring = ("list_alerts", "get_device_health", "get_sla_status", "list_outages")
    topology = ("get_neighbors", "get_interfaces", "list_topology_changes", "trace_path")
    for name in monitoring:
        assert await call(topology_only, name, {}) == (f"Unknown tool: {name}", True)
        assert (await call(monitoring_only, name, {}))[0] != f"Unknown tool: {name}"
    for name in topology:
        assert await call(monitoring_only, name, {}) == (f"Unknown tool: {name}", True)
        assert (await call(topology_only, name, {}))[0] != f"Unknown tool: {name}"
