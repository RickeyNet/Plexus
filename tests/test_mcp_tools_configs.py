"""MCP config tools: search, read, diff and drift over stored backups."""

from __future__ import annotations

import time

import pytest
import routes.database as db
from netcontrol.mcp import registry

import pg_raw
from mcp_helpers import call, db_ctx

RTR = """\
hostname edge-rtr-01
snmp-server community CfgToolSecret RO
interface GigabitEthernet0/0
 description uplink to core
 ip address 192.0.2.1 255.255.255.0
interface GigabitEthernet0/1
 description user access
 switchport access vlan 20
router bgp 65001
 neighbor 192.0.2.2 remote-as 65002
"""
RTR_OLD = RTR.replace(" switchport access vlan 20\n", " switchport access vlan 10\n")
SW = """\
hostname core-sw-01
interface Vlan20
 ip address 192.0.2.129 255.255.255.128
ntp server 192.0.2.5
"""
FW = """\
hostname edge-fw-01
snmp-server location Rack 12
ntp server 192.0.2.5
"""


@pytest.fixture(autouse=True)
def _tools():
    registry.load_tools()


async def _seed() -> dict[str, int]:
    group = await db.create_group("Campus", "")
    ids = {
        "rtr": await db.add_host(group, "edge-rtr-01", "192.0.2.1", "cisco_ios"),
        "sw": await db.add_host(group, "core-sw-01", "192.0.2.2", "cisco_ios"),
        "fw": await db.add_host(group, "edge-fw-01", "192.0.2.3", "cisco_asa"),
        "bare": await db.add_host(group, "no-backup-01", "192.0.2.4", "cisco_ios"),
    }
    ids["rtr_old"] = await db.create_config_backup(None, ids["rtr"], RTR_OLD)
    await pg_raw.execute("UPDATE config_backups SET captured_at = '2026-01-01 00:00:00' WHERE id = $1", ids["rtr_old"])
    ids["rtr_new"] = await db.create_config_backup(None, ids["rtr"], RTR)
    ids["sw_backup"] = await db.create_config_backup(None, ids["sw"], SW)
    ids["fw_backup"] = await db.create_config_backup(None, ids["fw"], FW)
    await db.create_config_backup(None, ids["fw"], "", status="failed", error_message="timeout")
    return ids


async def test_search_text_finds_devices_with_lines():
    ids = await _seed()
    data, is_error = await call(await db_ctx(), "search_configs", {"pattern": "snmp-server"})
    assert is_error is False
    assert {row["host"]["hostname"] for row in data["items"]} == {"edge-rtr-01", "edge-fw-01"}
    rtr = next(row for row in data["items"] if row["host"]["id"] == ids["rtr"])
    assert rtr["backup_id"] == ids["rtr_new"] and rtr["backup_time"]
    (match,) = rtr["matches"]
    assert match["line_number"] == 2
    assert match["lines"][0] == "hostname edge-rtr-01" and len(match["lines"]) == 3
    assert data["devices_searched"] == 3 and data["devices_without_backup"] == 1

    data, _ = await call(await db_ctx(name="b2"), "search_configs", {"pattern": "DESCRIPTION", "context_lines": 0})
    (row,) = data["items"]
    assert [m["line_number"] for m in row["matches"]] == [4, 7]
    assert row["matches"][0]["lines"] == [" description uplink to core"]


async def test_search_regex_and_filters():
    ids = await _seed()
    ctx = await db_ctx()
    data, is_error = await call(ctx, "search_configs", {"pattern": r"vlan \d+$", "mode": "regex"})
    assert is_error is False
    assert [row["host"]["id"] for row in data["items"]] == [ids["rtr"]]
    data, _ = await call(ctx, "search_configs", {"pattern": "ntp server", "vendor": "asa"})
    assert [row["host"]["id"] for row in data["items"]] == [ids["fw"]]
    data, _ = await call(ctx, "search_configs", {"pattern": "ntp server", "group": "nowhere"})
    assert data["items"] == []


async def test_search_only_looks_at_the_latest_backup():
    await _seed()
    data, _ = await call(await db_ctx(), "search_configs", {"pattern": "access vlan 10"})
    assert data["items"] == []


async def test_search_not_matching_lists_the_others():
    ids = await _seed()
    data, is_error = await call(await db_ctx(), "search_configs", {"pattern": "ntp server", "not_matching": True})
    assert is_error is False
    assert [row["host"]["id"] for row in data["items"]] == [ids["rtr"]]
    assert "matches" not in data["items"][0]


async def test_search_output_is_redacted_via_dispatch():
    await _seed()
    data, _ = await call(await db_ctx(), "search_configs", {"pattern": "snmp-server community"})
    text = str(data)
    assert "CfgToolSecret" not in text
    assert "snmp-server community ******** RO" in text


@pytest.mark.parametrize(
    "arguments",
    [
        {"pattern": "CfgToolSecret"},
        {"pattern": "snmp-server community cfgtool"},
        {"pattern": "^snmp-server community [A-D]", "mode": "regex"},
    ],
)
async def test_search_cannot_probe_a_secret(arguments):
    """The pattern is tested against masked text, so a hit or a miss says
    nothing about the secret itself."""
    await _seed()
    ctx = await db_ctx()
    data, is_error = await call(ctx, "search_configs", arguments)
    assert is_error is False and data["items"] == []
    inverse, _ = await call(ctx, "search_configs", {**arguments, "not_matching": True})
    assert len(inverse["items"]) == 3


async def test_search_context_never_returns_a_key_body():
    group = await db.create_group("Edge", "")
    host = await db.add_host(group, "pem-fw-01", "192.0.2.9", "fortinet")
    config = (
        "config vpn certificate local\n"
        '    set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----\n'
        "MIIFHzInventedBodyLine1\n"
        "InventedBodyLine2==\n"
        '-----END ENCRYPTED PRIVATE KEY-----"\n'
        "end\n"
        "ntp server 192.0.2.5\n"
    )
    await db.create_config_backup(None, host, config)
    ctx = await db_ctx()
    for pattern in ("PRIVATE KEY", "InventedBodyLine2", "certificate local", "ntp server"):
        data, _ = await call(ctx, "search_configs", {"pattern": pattern, "context_lines": 5})
        assert "InventedBodyLine" not in str(data)
    data, _ = await call(ctx, "search_configs", {"pattern": "ntp server"})
    assert data["items"][0]["matches"][0]["line_number"] == 7


@pytest.mark.parametrize(
    "pattern",
    ["(", "x" * 201, "(a+)+$", r"(?<=a)b", r"(a)\1"],
)
async def test_invalid_and_overlong_regex_is_tool_error(pattern):
    await _seed()
    started = time.monotonic()
    text, is_error = await call(await db_ctx(), "search_configs", {"pattern": pattern, "mode": "regex"})
    assert is_error is True
    assert isinstance(text, str) and ("Invalid pattern" in text or "pattern" in text)
    assert time.monotonic() - started < 5


async def test_get_config_latest_and_by_id():
    ids = await _seed()
    ctx = await db_ctx()
    data, is_error = await call(ctx, "get_device_config", {"host": "edge-rtr-01"})
    assert is_error is False
    assert data["backup_id"] == ids["rtr_new"] and data["host"]["hostname"] == "edge-rtr-01"
    assert "switchport access vlan 20" in data["config"] and data["lines"] == len(RTR.splitlines())
    assert "CfgToolSecret" not in data["config"]
    data, _ = await call(ctx, "get_device_config", {"host": "edge-rtr-01", "backup_id": ids["rtr_old"]})
    assert "switchport access vlan 10" in data["config"]
    text, is_error = await call(ctx, "get_device_config", {"host": "edge-rtr-01", "backup_id": ids["sw_backup"]})
    assert is_error is True and "does not belong" in text


async def test_get_config_section():
    await _seed()
    ctx = await db_ctx()
    data, is_error = await call(
        ctx, "get_device_config", {"host": "edge-rtr-01", "section": "interface GigabitEthernet0/1"}
    )
    assert is_error is False
    assert data["config"] == "interface GigabitEthernet0/1\n description user access\n switchport access vlan 20\n"
    data, _ = await call(ctx, "get_device_config", {"host": "edge-rtr-01", "section": "INTERFACE"})
    assert data["config"].count("interface GigabitEthernet") == 2 and "router bgp" not in data["config"]
    data, _ = await call(ctx, "get_device_config", {"host": "edge-rtr-01", "section": "router bgp"})
    assert data["config"] == "router bgp 65001\n neighbor 192.0.2.2 remote-as 65002\n"


async def test_unknown_section_lists_headers():
    await _seed()
    text, is_error = await call(await db_ctx(), "get_device_config", {"host": "edge-rtr-01", "section": "router ospf"})
    assert is_error is True
    assert "router bgp 65001" in text and "interface GigabitEthernet0/0" in text
    assert "CfgToolSecret" not in text


async def test_diff_defaults_to_last_two():
    ids = await _seed()
    data, is_error = await call(await db_ctx(), "diff_device_configs", {"host": "edge-rtr-01"})
    assert is_error is False
    assert data["from"]["backup_id"] == ids["rtr_old"] and data["to"]["backup_id"] == ids["rtr_new"]
    assert "- switchport access vlan 10" in data["diff"] and "+ switchport access vlan 20" in data["diff"]
    assert data["lines_added"] == 1 and data["lines_removed"] == 1
    assert "CfgToolSecret" not in data["diff"]
    swapped, _ = await call(
        await db_ctx(name="b2"),
        "diff_device_configs",
        {"host": "edge-rtr-01", "from_backup_id": ids["rtr_new"], "to_backup_id": ids["rtr_old"]},
    )
    assert "+ switchport access vlan 10" in swapped["diff"]


async def test_diff_single_backup_is_tool_error():
    await _seed()
    text, is_error = await call(await db_ctx(), "diff_device_configs", {"host": "core-sw-01"})
    assert is_error is True and "only one" in text.lower()


async def test_no_backups_is_no_data():
    group = await db.create_group("Lab", "")
    await db.add_host(group, "lab-sw-01", "192.0.2.50")
    ctx = await db_ctx()
    for name, args in (
        ("search_configs", {"pattern": "hostname"}),
        ("get_device_config", {"host": "lab-sw-01"}),
        ("diff_device_configs", {"host": "lab-sw-01"}),
    ):
        data, is_error = await call(ctx, name, args)
        assert is_error is False, (name, data)
        assert data["no_data"] is True and "config backups" in data["message"]


async def test_list_config_drift():
    ids = await _seed()
    snapshot = await db.create_config_snapshot(ids["rtr"], RTR)
    event = await db.create_config_drift_event(
        ids["rtr"], snapshot, None, "+snmp-server community DriftSecret RO\n-ntp server 192.0.2.5\n", 1, 1
    )
    ctx = await db_ctx()
    data, is_error = await call(ctx, "list_config_drift", {})
    assert is_error is False
    (row,) = data["items"]
    assert row["id"] == event and row["host"]["hostname"] == "edge-rtr-01" and row["status"] == "open"
    assert row["lines_added"] == 1 and "DriftSecret" not in row["diff"] and "-ntp server" in row["diff"]
    data, _ = await call(ctx, "list_config_drift", {"host": "core-sw-01"})
    assert data["items"] == []
    data, _ = await call(ctx, "list_config_drift", {"status": "resolved"})
    assert data["items"] == []
    data, _ = await call(ctx, "list_config_drift", {"until": "2020-01-01T00:00:00Z"})
    assert data["items"] == []
    text, is_error = await call(ctx, "list_config_drift", {"since": "yesterday"})
    assert is_error is True and "ISO 8601" in text


async def test_list_config_drift_needs_config_drift_feature():
    without = await db_ctx(categories=["configs"], admin=False, features=["config-backups"], name="no-drift")
    assert await call(without, "list_config_drift", {}) == ("Unknown tool: list_config_drift", True)
    assert (await call(without, "search_configs", {"pattern": "hostname"}))[1] is False
    with_drift = await db_ctx(
        categories=["configs"], admin=False, features=["config-backups", "config-drift"], name="drift"
    )
    assert (await call(with_drift, "list_config_drift", {}))[1] is False


async def test_hidden_without_category():
    ctx = await db_ctx(categories=["inventory"])
    for name in ("search_configs", "get_device_config", "diff_device_configs", "list_config_drift"):
        assert await call(ctx, name, {}) == (f"Unknown tool: {name}", True)
