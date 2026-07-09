"""Unit tests for the performance-batch helpers:

  * monitoring._suppression_active_local — in-memory equivalent of
    db.is_alert_suppressed used to preload suppressions once per poll cycle.
  * metrics_engine OID resolution cache — resolve_oids_for_device caches per
    device_type and clear_oid_cache() drops it (wired to vendor-OID writes).
"""

from __future__ import annotations

import asyncio

import pytest

# ── suppression matcher ──────────────────────────────────────────────────────
from netcontrol.routes.monitoring import _suppression_active_local as match


def test_global_suppression_all_metrics():
    rows = [{"host_id": None, "group_id": None, "metric": ""}]
    assert match(rows, host_id=5, metric="cpu", group_id=2) is True
    assert match(rows, host_id=99, metric="memory", group_id=None) is True


def test_global_suppression_specific_metric():
    rows = [{"host_id": None, "group_id": None, "metric": "cpu"}]
    assert match(rows, host_id=5, metric="cpu", group_id=2) is True
    assert match(rows, host_id=5, metric="memory", group_id=2) is False


def test_host_scoped_suppression():
    rows = [{"host_id": 5, "group_id": None, "metric": ""}]
    assert match(rows, host_id=5, metric="cpu", group_id=2) is True
    assert match(rows, host_id=6, metric="cpu", group_id=2) is False


def test_group_scoped_suppression():
    rows = [{"host_id": None, "group_id": 2, "metric": "cpu"}]
    assert match(rows, host_id=5, metric="cpu", group_id=2) is True
    assert match(rows, host_id=5, metric="cpu", group_id=3) is False
    # group_id None on the host never matches a group-scoped row
    assert match(rows, host_id=5, metric="cpu", group_id=None) is False


def test_no_rows_not_suppressed():
    assert match([], host_id=5, metric="cpu", group_id=2) is False


# ── route summary parsing + poll cadence ────────────────────────────────────

import netcontrol.routes.monitoring as mon


def test_parse_route_summary_count_ios():
    text = (
        "IP routing table name is default (0x0)\n"
        "Route Source    Networks    Subnets     Replicates  Overhead    Memory (bytes)\n"
        "connected       0           2           0           128         608\n"
        "static          0           1           0           64          304\n"
        "ospf 1          0           5           0           320         1520\n"
        "  Intra-area: 5 Inter-area: 0 External-1: 0 External-2: 0\n"
        "internal        3                                               1476\n"
        "Total           3           8           0           512         3908\n"
    )
    assert mon._parse_route_summary_count(text) == 11  # networks + subnets


def test_parse_route_summary_count_nxos():
    text = (
        "IP Route Table for VRF \"default\"\n"
        "Total number of routes: 42\n"
        "Total number of paths:  44\n"
    )
    assert mon._parse_route_summary_count(text) == 42


def test_parse_route_summary_count_unrecognized():
    assert mon._parse_route_summary_count("") is None
    assert mon._parse_route_summary_count("% Invalid input detected") is None
    assert mon._parse_route_summary_count("Total garbage here") is None


# ── dead-host poll backoff ───────────────────────────────────────────────────


def test_poll_backoff_schedule():
    mon._POLL_BACKOFF.clear()
    hid = 7001
    try:
        # first failure: retry next cycle
        mon._poll_backoff_record(hid, ok=False)
        assert mon._poll_backoff_should_skip(hid) is False
        # second failure: skip one cycle, then eligible again
        mon._poll_backoff_record(hid, ok=False)
        assert mon._poll_backoff_should_skip(hid) is True
        assert mon._poll_backoff_should_skip(hid) is False
        # third failure: skip two cycles
        mon._poll_backoff_record(hid, ok=False)
        assert [mon._poll_backoff_should_skip(hid) for _ in range(3)] == [True, True, False]
        # skip count caps at _POLL_BACKOFF_MAX_SKIP no matter how many failures
        for _ in range(20):
            mon._poll_backoff_record(hid, ok=False)
        assert mon._POLL_BACKOFF[hid][1] == mon._POLL_BACKOFF_MAX_SKIP
        # a successful poll clears the entry entirely
        mon._poll_backoff_record(hid, ok=True)
        assert hid not in mon._POLL_BACKOFF
        assert mon._poll_backoff_should_skip(hid) is False
    finally:
        mon._POLL_BACKOFF.clear()


# ── OID resolution cache ─────────────────────────────────────────────────────

import netcontrol.routes.metrics_engine as me


def test_resolve_oids_caches_per_device_type(monkeypatch):
    me.clear_oid_cache()
    calls = {"n": 0}

    async def fake_lookup(device_type):
        calls["n"] += 1
        return None  # force built-in map path

    monkeypatch.setattr(me.db, "get_vendor_oid_for_host", fake_lookup)

    async def _go():
        a = await me.resolve_oids_for_device("cisco_ios")
        b = await me.resolve_oids_for_device("cisco_ios")
        assert a == b
        assert calls["n"] == 1                     # second call served from cache
        # mutating the returned dict must not poison the cache
        a["cpu_oid"] = "TAINT"
        c = await me.resolve_oids_for_device("cisco_ios")
        assert c.get("cpu_oid") != "TAINT"
        me.clear_oid_cache()
        await me.resolve_oids_for_device("cisco_ios")
        assert calls["n"] == 2                      # cache cleared -> re-queried

    asyncio.run(_go())
    me.clear_oid_cache()
