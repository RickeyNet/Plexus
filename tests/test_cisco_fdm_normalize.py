"""Tests for FDM operational-JSON -> monitoring poll-result normalisation.

These pin the *logic* (aggregation, status counting, unit conversion, and the
safe-by-default behaviour on unknown shapes). The exact device field paths are
defensive and documented as needing validation against a real 7.4 FTD; what's
asserted here is that the normaliser never crashes and never manufactures a
false alert from data it doesn't recognise.
"""

from __future__ import annotations

from netcontrol.integrations.cisco_fdm.normalize import (
    base_result,
    build_poll_result,
    error_result,
)


def test_full_snapshot_maps_cpu_memory_uptime_and_interfaces():
    systeminfo = {"uptime": 123456}
    metrics = {
        "cpu": {"percentUsed": 37.4},
        "memory": {"usedBytes": 2 * 1048576, "totalBytes": 8 * 1048576},
        "interfaces": [
            {"name": "GigabitEthernet0/0", "operStatus": "up", "adminStatus": "up"},
            {"name": "GigabitEthernet0/1", "operStatus": "down", "adminStatus": "up"},
            {"name": "GigabitEthernet0/2", "operStatus": "down", "adminStatus": "down"},
        ],
    }
    res = build_poll_result(7, systeminfo, metrics)
    assert res["host_id"] == 7
    assert res["cpu_percent"] == 37.4
    assert res["memory_used_mb"] == 2.0
    assert res["memory_total_mb"] == 8.0
    assert res["memory_percent"] == 25.0
    assert res["uptime_seconds"] == 123456
    assert res["if_up_count"] == 1
    assert res["if_down_count"] == 1   # oper down but admin up
    assert res["if_admin_down"] == 1   # admin down counted separately
    assert res["poll_status"] == "ok"


def test_cpu_falls_back_to_averaging_per_core():
    metrics = {"cpu": {"cores": [{"percentUsed": 10}, {"percentUsed": 30}]}}
    res = build_poll_result(1, {}, metrics)
    assert res["cpu_percent"] == 20.0


def test_memory_percent_used_directly_when_no_byte_totals():
    metrics = {"memory": {"percentUsed": 61.5}}
    res = build_poll_result(1, {}, metrics)
    assert res["memory_percent"] == 61.5
    assert res["memory_used_mb"] is None
    assert res["memory_total_mb"] is None


def test_unknown_shape_degrades_to_none_and_zero_no_false_alerts():
    # A payload whose keys we don't recognise must NOT invent interface-down
    # counts (which would fire a bogus "interface down" alert).
    metrics = {"somethingElse": {"foo": "bar"}, "interfaces": "not-a-list"}
    res = build_poll_result(1, {}, metrics)
    assert res["cpu_percent"] is None
    assert res["memory_percent"] is None
    assert res["uptime_seconds"] is None
    assert res["if_up_count"] == 0
    assert res["if_down_count"] == 0
    assert res["if_admin_down"] == 0
    assert res["if_details"] == []
    assert res["poll_status"] == "ok"


def test_non_dict_payloads_are_tolerated():
    res = build_poll_result(1, None, ["unexpected"])
    assert res["poll_status"] == "ok"
    assert res["cpu_percent"] is None


def test_cpu_percent_clamped_to_0_100():
    assert build_poll_result(1, {}, {"cpu": {"percentUsed": 150}})["cpu_percent"] == 100.0
    assert build_poll_result(1, {}, {"cpu": {"percentUsed": -5}})["cpu_percent"] == 0.0


def test_interface_admin_status_unknown_is_not_counted_admin_down():
    metrics = {"interfaces": [{"name": "x", "operStatus": "down"}]}  # no adminStatus
    res = build_poll_result(1, {}, metrics)
    assert res["if_admin_down"] == 0
    assert res["if_down_count"] == 1


def test_error_result_marks_host_down():
    res = error_result(9, "connection refused")
    assert res["host_id"] == 9
    assert res["poll_status"] == "error"
    assert "connection refused" in res["poll_error"]


def test_base_result_has_all_monitoring_pipeline_keys():
    # The result dict must carry every key _process_poll_result reads.
    required = {
        "host_id", "cpu_percent", "memory_percent", "memory_used_mb",
        "memory_total_mb", "uptime_seconds", "if_up_count", "if_down_count",
        "if_admin_down", "if_details", "vpn_tunnels_up", "vpn_tunnels_down",
        "vpn_details", "route_count", "route_snapshot", "poll_status",
        "poll_error", "response_time_ms", "packet_loss_pct", "icmp_alive",
        "icmp_rtt_ms",
    }
    assert required.issubset(base_result(1).keys())
