"""Config drift detection tests.

Covers:
  1. _compute_config_diff helper (identical, additions, removals, mixed)
  2. Database CRUD for baselines, snapshots, drift events
  3. _analyze_drift_for_host logic
  4. API endpoint behavior (baselines, events, summary)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import netcontrol.app as app_module
import pytest
import routes.database as db_module


# ── Helpers ──────────────────────────────────────────────────────────────────


class DummyRequest:
    def __init__(self):
        self.cookies = {}
        self.state = type("S", (), {"correlation_id": "test-corr"})()


# ═════════════════════════════════════════════════════════════════════════════
# 1. _compute_config_diff
# ═════════════════════════════════════════════════════════════════════════════


def test_diff_identical_configs():
    """Identical configs should produce empty diff."""
    config = "interface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n"
    diff_text, added, removed = app_module._compute_config_diff(config, config)
    assert diff_text == ""
    assert added == 0
    assert removed == 0


def test_diff_added_lines():
    """New lines in actual should show as additions."""
    baseline = "hostname sw1\n"
    actual = "hostname sw1\ninterface Gi0/1\n"
    diff_text, added, removed = app_module._compute_config_diff(baseline, actual)
    assert added == 1
    assert removed == 0
    assert "+interface Gi0/1" in diff_text


def test_diff_removed_lines():
    """Missing lines in actual should show as removals."""
    baseline = "hostname sw1\ninterface Gi0/1\n"
    actual = "hostname sw1\n"
    diff_text, added, removed = app_module._compute_config_diff(baseline, actual)
    assert added == 0
    assert removed == 1
    assert "-interface Gi0/1" in diff_text


def test_diff_mixed_changes():
    """Changed lines should show both additions and removals."""
    baseline = "hostname sw1\ninterface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n"
    actual = "hostname sw1\ninterface Gi0/1\n ip address 10.0.0.2 255.255.255.0\n"
    diff_text, added, removed = app_module._compute_config_diff(baseline, actual)
    assert added >= 1
    assert removed >= 1
    assert "-" in diff_text
    assert "+" in diff_text


def test_diff_empty_baseline():
    """Empty baseline vs non-empty actual should show all as additions."""
    diff_text, added, removed = app_module._compute_config_diff("", "line1\nline2\n")
    assert added == 2
    assert removed == 0


def test_diff_empty_actual():
    """Non-empty baseline vs empty actual should show all as removals."""
    diff_text, added, removed = app_module._compute_config_diff("line1\nline2\n", "")
    assert added == 0
    assert removed == 2


def test_diff_both_empty():
    """Both empty should produce empty diff."""
    diff_text, added, removed = app_module._compute_config_diff("", "")
    assert diff_text == ""
    assert added == 0
    assert removed == 0


# ═════════════════════════════════════════════════════════════════════════════
# 2. Database CRUD — config_baselines, config_snapshots, config_drift_events
# ═════════════════════════════════════════════════════════════════════════════


@pytest.fixture
async def drift_db(tmp_path, monkeypatch):
    """Set up a fresh SQLite DB with schema for drift tests."""
    db_path = str(tmp_path / "drift_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setattr(db_module, "DB_ENGINE", "sqlite")
    await db_module.init_db()

    # Insert a group and two hosts for FK references
    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (1, 'core')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, status) "
            "VALUES (100, 1, 'sw-core-01', '10.0.1.1', 'cisco_ios', 'online')"
        )
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, status) "
            "VALUES (200, 1, 'sw-dist-01', '10.0.1.2', 'cisco_ios', 'online')"
        )
        await db.commit()
    finally:
        await db.close()

    return db_path


@pytest.mark.asyncio
async def test_create_and_get_baseline(drift_db):
    """Create a baseline and retrieve it."""
    bid = await db_module.create_config_baseline(
        host_id=100, name="Golden v1", config_text="hostname sw1\n", source="manual", created_by="admin"
    )
    assert bid > 0
    bl = await db_module.get_config_baseline(bid)
    assert bl is not None
    assert bl["host_id"] == 100
    assert bl["name"] == "Golden v1"
    assert bl["config_text"] == "hostname sw1\n"
    assert bl["source"] == "manual"


@pytest.mark.asyncio
async def test_baseline_upsert_replaces(drift_db):
    """Creating a baseline for the same host should replace the old one."""
    bid1 = await db_module.create_config_baseline(host_id=100, config_text="v1")
    bid2 = await db_module.create_config_baseline(host_id=100, config_text="v2")
    bl = await db_module.get_config_baseline_for_host(100)
    assert bl["config_text"] == "v2"


@pytest.mark.asyncio
async def test_get_baselines_list(drift_db):
    """List baselines with join on hosts."""
    await db_module.create_config_baseline(host_id=100, name="A")
    await db_module.create_config_baseline(host_id=200, name="B")
    baselines = await db_module.get_config_baselines()
    assert len(baselines) == 2
    # Should have hostname from join
    hostnames = {b["hostname"] for b in baselines}
    assert "sw-core-01" in hostnames
    assert "sw-dist-01" in hostnames


@pytest.mark.asyncio
async def test_update_baseline(drift_db):
    """Update should change only specified fields."""
    bid = await db_module.create_config_baseline(host_id=100, name="Old", config_text="old config")
    await db_module.update_config_baseline(bid, name="New", config_text="new config")
    bl = await db_module.get_config_baseline(bid)
    assert bl["name"] == "New"
    assert bl["config_text"] == "new config"


@pytest.mark.asyncio
async def test_delete_baseline(drift_db):
    """Delete should remove the baseline."""
    bid = await db_module.create_config_baseline(host_id=100, config_text="x")
    await db_module.delete_config_baseline(bid)
    assert await db_module.get_config_baseline(bid) is None


@pytest.mark.asyncio
async def test_create_and_get_snapshot(drift_db):
    """Create a snapshot and retrieve it."""
    sid = await db_module.create_config_snapshot(host_id=100, config_text="running config here")
    assert sid > 0
    snap = await db_module.get_config_snapshot(sid)
    assert snap["host_id"] == 100
    assert snap["config_text"] == "running config here"
    assert snap["capture_method"] == "manual"


@pytest.mark.asyncio
async def test_get_snapshots_for_host(drift_db):
    """List snapshots should return newest first."""
    await db_module.create_config_snapshot(host_id=100, config_text="v1")
    await db_module.create_config_snapshot(host_id=100, config_text="v2")
    snaps = await db_module.get_config_snapshots_for_host(100)
    assert len(snaps) == 2
    # Should have config_length field (not full text)
    assert "config_length" in snaps[0]


@pytest.mark.asyncio
async def test_get_latest_snapshot(drift_db):
    """Latest snapshot should be the most recently created."""
    await db_module.create_config_snapshot(host_id=100, config_text="old")
    await db_module.create_config_snapshot(host_id=100, config_text="new")
    latest = await db_module.get_latest_config_snapshot(100)
    assert latest["config_text"] == "new"


@pytest.mark.asyncio
async def test_create_and_get_drift_event(drift_db):
    """Create a drift event and retrieve with host info."""
    sid = await db_module.create_config_snapshot(host_id=100, config_text="actual")
    bid = await db_module.create_config_baseline(host_id=100, config_text="baseline")
    eid = await db_module.create_config_drift_event(
        host_id=100, snapshot_id=sid, baseline_id=bid,
        diff_text="@@ -1 +1 @@\n-baseline\n+actual\n",
        diff_lines_added=1, diff_lines_removed=1,
    )
    assert eid > 0
    ev = await db_module.get_config_drift_event(eid)
    assert ev["host_id"] == 100
    assert ev["hostname"] == "sw-core-01"
    assert ev["status"] == "open"
    assert ev["diff_lines_added"] == 1


@pytest.mark.asyncio
async def test_list_drift_events_filtered(drift_db):
    """List events with status filter."""
    sid = await db_module.create_config_snapshot(host_id=100, config_text="x")
    eid1 = await db_module.create_config_drift_event(
        host_id=100, snapshot_id=sid, baseline_id=None, diff_text="diff1"
    )
    eid2 = await db_module.create_config_drift_event(
        host_id=100, snapshot_id=sid, baseline_id=None, diff_text="diff2"
    )
    await db_module.update_config_drift_event_status(eid1, "resolved", "admin")

    open_events = await db_module.get_config_drift_events(status="open")
    assert len(open_events) == 1
    assert open_events[0]["id"] == eid2

    resolved = await db_module.get_config_drift_events(status="resolved")
    assert len(resolved) == 1
    assert resolved[0]["resolved_by"] == "admin"


@pytest.mark.asyncio
async def test_drift_summary(drift_db):
    """Summary should count baselines and open drift."""
    await db_module.create_config_baseline(host_id=100, config_text="bl")
    await db_module.create_config_baseline(host_id=200, config_text="bl")
    sid = await db_module.create_config_snapshot(host_id=100, config_text="x")
    await db_module.create_config_drift_event(
        host_id=100, snapshot_id=sid, baseline_id=None, diff_text="diff"
    )
    summary = await db_module.get_config_drift_summary()
    assert summary["total_baselined"] == 2
    assert summary["drifted"] == 1
    assert summary["compliant"] == 1
    assert summary["open_events"] == 1


# ═════════════════════════════════════════════════════════════════════════════
# 3. _analyze_drift_for_host
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_analyze_no_baseline(drift_db, monkeypatch):
    """No baseline should return drifted=False with message."""
    monkeypatch.setattr(app_module, "db", db_module)
    result = await app_module._analyze_drift_for_host(100)
    assert result["drifted"] is False
    assert "No baseline" in result["diff_summary"]


@pytest.mark.asyncio
async def test_analyze_no_snapshot(drift_db, monkeypatch):
    """Baseline but no snapshot should return drifted=False."""
    monkeypatch.setattr(app_module, "db", db_module)
    await db_module.create_config_baseline(host_id=100, config_text="golden")
    result = await app_module._analyze_drift_for_host(100)
    assert result["drifted"] is False
    assert "No snapshot" in result["diff_summary"]


@pytest.mark.asyncio
async def test_analyze_compliant(drift_db, monkeypatch):
    """Matching config should return drifted=False."""
    monkeypatch.setattr(app_module, "db", db_module)
    config = "hostname sw1\ninterface Gi0/1\n"
    await db_module.create_config_baseline(host_id=100, config_text=config)
    await db_module.create_config_snapshot(host_id=100, config_text=config)
    result = await app_module._analyze_drift_for_host(100)
    assert result["drifted"] is False
    assert "compliance" in result["diff_summary"].lower()


@pytest.mark.asyncio
async def test_analyze_drifted(drift_db, monkeypatch):
    """Different config should return drifted=True and create an event."""
    monkeypatch.setattr(app_module, "db", db_module)
    await db_module.create_config_baseline(host_id=100, config_text="hostname sw1\n")
    await db_module.create_config_snapshot(host_id=100, config_text="hostname sw1-changed\n")
    result = await app_module._analyze_drift_for_host(100)
    assert result["drifted"] is True
    assert result["event_id"] is not None
    # Verify the event was created
    ev = await db_module.get_config_drift_event(result["event_id"])
    assert ev is not None
    assert ev["status"] == "open"
    assert ev["diff_lines_added"] >= 1


# ═════════════════════════════════════════════════════════════════════════════
# 4. API endpoint behavior (mocked DB)
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_api_get_drift_summary(monkeypatch):
    """GET /api/config-drift/summary should return summary dict."""
    expected = {"total_baselined": 5, "compliant": 3, "drifted": 2, "open_events": 4, "accepted_events": 1}
    monkeypatch.setattr(app_module.db, "get_config_drift_summary", AsyncMock(return_value=expected))
    result = await app_module.get_config_drift_summary()
    assert result == expected


@pytest.mark.asyncio
async def test_api_get_baseline_not_found(monkeypatch):
    """GET baseline with invalid ID should return 404."""
    monkeypatch.setattr(app_module.db, "get_config_baseline", AsyncMock(return_value=None))
    with pytest.raises(Exception) as exc_info:
        await app_module.get_config_baseline(999)
    assert "404" in str(exc_info.value) or "not found" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_api_update_drift_status_invalid(monkeypatch):
    """Invalid status should return 400."""
    monkeypatch.setattr(app_module.db, "get_config_drift_event", AsyncMock(return_value={"id": 1}))
    body = app_module.ConfigDriftStatusUpdate(status="invalid_status")
    req = DummyRequest()
    with pytest.raises(Exception) as exc_info:
        await app_module.update_config_drift_event_status(1, body, req)
    assert "400" in str(exc_info.value) or "must be" in str(exc_info.value).lower()
