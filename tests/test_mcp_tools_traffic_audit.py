"""MCP traffic tools (MAC/IP location, flow rankings) and the audit log tool."""

from __future__ import annotations

import pytest
import routes.database as db
from netcontrol.mcp import registry

from mcp_helpers import call, db_ctx

MAC = "aa:bb:cc:dd:ee:ff"


@pytest.fixture(autouse=True)
def _tools():
    registry.load_tools()


async def _seed_macs() -> int:
    group = await db.create_group("Campus", "")
    host = await db.add_host(group, "access-sw-01", "192.0.2.10")
    await db.upsert_mac_entry(host, MAC, 20, "Gi1/0/5", 5, "192.0.2.77")
    await db.upsert_mac_entry(host, "00:00:5e:00:53:01", 30, "Gi1/0/6", 6, "192.0.2.78")
    await db.record_mac_history(MAC, host, "Gi1/0/5", 20, "192.0.2.77")
    return host


async def test_mac_formats_normalised():
    await _seed_macs()
    ctx = await db_ctx()
    for query in ("aa:bb:cc:dd:ee:ff", "aabb.ccdd.eeff", "AA-BB-CC-DD-EE-FF", "aabbccddeeff"):
        data, is_error = await call(ctx, "search_mac_or_ip", {"query": query})
        assert is_error is False, (query, data)
        (row,) = data["items"]
        assert row["mac_address"] == MAC and row["host"]["hostname"] == "access-sw-01"
        assert row["port"] == "Gi1/0/5" and row["vlan"] == 20 and row["source"] == "inventory"
        assert row["last_seen"]


async def test_search_by_ip():
    await _seed_macs()
    data, _ = await call(await db_ctx(), "search_mac_or_ip", {"query": "192.0.2.78"})
    assert [r["mac_address"] for r in data["items"]] == ["00:00:5e:00:53:01"]
    assert data["items"][0]["ip_address"] == "192.0.2.78"


async def test_mac_history_on_request():
    await _seed_macs()
    ctx = await db_ctx()
    data, _ = await call(ctx, "search_mac_or_ip", {"query": MAC})
    assert "history" not in data
    data, _ = await call(ctx, "search_mac_or_ip", {"query": "AABB.CCDD.EEFF", "history": True})
    assert data["history"][0]["port"] == "Gi1/0/5" and data["history"][0]["host"]["hostname"] == "access-sw-01"
    text, is_error = await call(ctx, "search_mac_or_ip", {"query": "192.0.2.77", "history": True})
    assert is_error is True and "MAC address" in text


async def test_unknown_mac_and_never_collected():
    ctx = await db_ctx()
    data, is_error = await call(ctx, "search_mac_or_ip", {"query": MAC})
    assert is_error is False and data["no_data"] is True
    await _seed_macs()
    data, _ = await call(ctx, "search_mac_or_ip", {"query": "02:00:00:00:00:99"})
    assert data["items"] == [] and "no_data" not in data


def _flow(host: int, src: str, dst: str, port: int, size: int) -> tuple:
    return ("192.0.2.10", host, "netflow_v9", src, dst, 40000, port, 6, size, 10, 0, 0, 1, 2, 0, 0, "", "")


async def test_top_talkers_kinds():
    host = await _seed_macs()
    await db.create_flow_records_batch(
        [
            _flow(host, "198.51.100.5", "203.0.113.9", 443, 9000),
            _flow(host, "198.51.100.5", "203.0.113.9", 443, 1000),
            _flow(host, "198.51.100.6", "203.0.113.10", 53, 500),
        ]
    )
    ctx = await db_ctx()
    data, is_error = await call(ctx, "get_top_talkers", {"kind": "talkers"})
    assert is_error is False
    assert data["items"][0]["ip"] == "198.51.100.5" and data["items"][0]["total_bytes"] == 10000
    data, _ = await call(ctx, "get_top_talkers", {"kind": "talkers", "direction": "destination"})
    assert data["items"][0]["ip"] == "203.0.113.9"
    data, _ = await call(ctx, "get_top_talkers", {"kind": "applications"})
    assert data["items"][0]["port"] == 443 and data["items"][0]["flow_count"] == 2
    data, _ = await call(ctx, "get_top_talkers", {"kind": "conversations", "limit": 1})
    assert data["items"] == [
        {"src_ip": "198.51.100.5", "dst_ip": "203.0.113.9", "total_bytes": 10000, "total_packets": 20, "flow_count": 2}
    ]
    data, _ = await call(ctx, "get_top_talkers", {"kind": "talkers", "exporter": "access-sw-01", "hours": 2})
    assert len(data["items"]) == 2 and data["exporter"]["hostname"] == "access-sw-01"
    text, is_error = await call(ctx, "get_top_talkers", {"kind": "talkers", "limit": 51})
    assert is_error is True


async def test_no_flow_data_is_no_data():
    data, is_error = await call(await db_ctx(), "get_top_talkers", {"kind": "talkers"})
    assert is_error is False and data["no_data"] is True and "flow" in data["message"]


async def _seed_audit() -> None:
    await db.add_audit_event("auth", "login.success", user="alice", detail="source=local")
    await db.add_audit_event("config", "backup.run", user="bob", detail="snmp-server community AuditLeak RO")
    await db.add_audit_event("auth", "login.failed", user="mallory", detail="bad password")


async def test_audit_filters():
    await _seed_audit()
    ctx = await db_ctx()
    data, is_error = await call(ctx, "search_audit_log", {"category": "auth"})
    assert is_error is False
    assert {(e["user"], e["action"]) for e in data["items"]} == {
        ("alice", "login.success"),
        ("mallory", "login.failed"),
    }
    assert set(data["items"][0]) == {"timestamp", "category", "action", "user", "detail"}
    data, _ = await call(ctx, "search_audit_log", {"user": "bob"})
    assert [e["action"] for e in data["items"]] == ["backup.run"]
    data, _ = await call(ctx, "search_audit_log", {"until": "2020-01-01T00:00:00Z", "since": "2019-01-01T00:00:00Z"})
    assert data["items"] == []
    data, _ = await call(ctx, "search_audit_log", {"since": "2020-01-01T00:00:00Z", "category": "config"})
    assert [e["user"] for e in data["items"]] == ["bob"]
    data, _ = await call(ctx, "search_audit_log", {"category": "auth", "limit": 1})
    assert len(data["items"]) == 1 and data["next_cursor"] == "1"


async def test_get_audit_events_keeps_its_old_behaviour():
    await _seed_audit()
    assert len(await db.get_audit_events(limit=10)) == 3
    assert len(await db.get_audit_events(limit=1)) == 1
    assert len(await db.get_audit_events(10, "auth")) == 2
    assert len(await db.get_audit_events(limit=10, user="bob")) == 1
    assert len(await db.get_audit_events(limit=10, until="2020-01-01 00:00:00")) == 0
    assert len(await db.get_audit_events(limit=10, category="auth", since="2020-01-01 00:00:00")) == 2
    assert len(await db.get_audit_events(limit=10, since="2999-01-01 00:00:00")) == 0


async def test_audit_detail_is_redacted_via_dispatch():
    await _seed_audit()
    data, _ = await call(await db_ctx(), "search_audit_log", {"user": "bob"})
    assert "AuditLeak" not in str(data) and "snmp-server community" in str(data)


async def test_audit_hidden_from_non_admin_owner():
    non_admin = await db_ctx(categories=["audit"], admin=False, features=["inventory"], name="plain")
    assert await call(non_admin, "search_audit_log", {}) == ("Unknown tool: search_audit_log", True)
    assert (await call(await db_ctx(categories=["audit"]), "search_audit_log", {}))[1] is False


async def test_feature_gating():
    mac_only = await db_ctx(categories=["traffic"], admin=False, features=["mac-tracking"], name="mac")
    assert {t.name for t in registry.visible_tools(mac_only)} == {"plexus_overview", "search_mac_or_ip"}
    flows_only = await db_ctx(categories=["traffic"], admin=False, features=["traffic-analysis"], name="flows")
    assert {t.name for t in registry.visible_tools(flows_only)} == {"plexus_overview", "get_top_talkers"}


async def test_hidden_without_category():
    ctx = await db_ctx(categories=["inventory"])
    for name in ("search_mac_or_ip", "get_top_talkers", "search_audit_log"):
        assert await call(ctx, name, {}) == (f"Unknown tool: {name}", True)
