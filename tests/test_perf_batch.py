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
