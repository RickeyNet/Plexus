"""Tests for interface error/discard trending with root-cause correlation."""

import json

import pytest

import routes.database as db_module
from netcontrol.routes.metrics_engine import _classify_root_cause


# ── helpers ──────────────────────────────────────────────────────────────────

async def _init(tmp_path, monkeypatch):
    """Set up a fresh in-memory DB with all tables + migrations."""
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    return db_path


async def _add_host(group_name="default", hostname="sw1", ip="10.0.0.1"):
    """Insert a minimal host and return its id."""
    db = await db_module.get_db()
    try:
        cur = await db.execute(
            "INSERT OR IGNORE INTO inventory_groups (name) VALUES (?)",
            (group_name,),
        )
        if cur.lastrowid:
            gid = cur.lastrowid
        else:
            cur2 = await db.execute(
                "SELECT id FROM inventory_groups WHERE name = ?", (group_name,)
            )
            gid = (await cur2.fetchone())[0]

        cur = await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address) VALUES (?, ?, ?)",
            (gid, hostname, ip),
        )
        await db.commit()
        return cur.lastrowid
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Database function tests
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_upsert_and_fetch_interface_error_stats(tmp_path, monkeypatch):
    """upsert creates a row; second upsert shifts current→prev."""
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    # First upsert — creates the row
    await db_module.upsert_interface_error_stat(
        host_id, if_index=1, if_name="Gi1/0/1",
        in_errors=100, out_errors=50, in_discards=10, out_discards=5,
    )
    rows = await db_module.get_interface_error_stats_for_host(host_id)
    assert len(rows) == 1
    assert rows[0]["in_errors"] == 100
    assert rows[0]["prev_in_errors"] == 0  # no prev on first insert

    # Second upsert — current shifts to prev
    await db_module.upsert_interface_error_stat(
        host_id, if_index=1, if_name="Gi1/0/1",
        in_errors=200, out_errors=70, in_discards=15, out_discards=8,
    )
    rows = await db_module.get_interface_error_stats_for_host(host_id)
    assert len(rows) == 1
    assert rows[0]["in_errors"] == 200
    assert rows[0]["prev_in_errors"] == 100  # shifted from first upsert
    assert rows[0]["out_errors"] == 70
    assert rows[0]["prev_out_errors"] == 50


@pytest.mark.asyncio
async def test_create_and_get_error_event(tmp_path, monkeypatch):
    """create_interface_error_event stores a row; get_interface_error_event retrieves it."""
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    event_id = await db_module.create_interface_error_event(
        host_id=host_id, if_index=1, if_name="Gi1/0/1",
        event_type="spike", metric_name="if_in_errors",
        severity="warning", current_rate=25.5, baseline_rate=3.0,
        spike_factor=8.5, root_cause_hint="Suspect physical layer",
        root_cause_category="physical_layer",
        correlation_details=json.dumps({"config_changes": 0}),
    )
    assert event_id > 0

    event = await db_module.get_interface_error_event(event_id)
    assert event is not None
    assert event["host_id"] == host_id
    assert event["metric_name"] == "if_in_errors"
    assert event["severity"] == "warning"
    assert event["root_cause_category"] == "physical_layer"
    assert event["acknowledged"] == 0
    assert event["resolved_at"] is None
    # JOIN should populate hostname
    assert event["hostname"] == "sw1"


@pytest.mark.asyncio
async def test_get_interface_error_events_filters(tmp_path, monkeypatch):
    """get_interface_error_events respects host_id, severity, and unresolved_only filters."""
    await _init(tmp_path, monkeypatch)
    h1 = await _add_host(hostname="sw1", ip="10.0.0.1")
    h2 = await _add_host(hostname="sw2", ip="10.0.0.2")

    await db_module.create_interface_error_event(
        host_id=h1, if_index=1, if_name="Gi1/0/1",
        event_type="spike", metric_name="if_in_errors",
        severity="warning", current_rate=10, baseline_rate=1,
        spike_factor=10, root_cause_hint="test", root_cause_category="unknown",
    )
    eid2 = await db_module.create_interface_error_event(
        host_id=h2, if_index=2, if_name="Gi1/0/2",
        event_type="spike", metric_name="if_out_errors",
        severity="critical", current_rate=200, baseline_rate=5,
        spike_factor=40, root_cause_hint="test", root_cause_category="congestion",
    )

    # Filter by host
    h1_events = await db_module.get_interface_error_events(host_id=h1)
    assert len(h1_events) == 1
    assert h1_events[0]["hostname"] == "sw1"

    # Filter by severity
    critical = await db_module.get_interface_error_events(severity="critical")
    assert len(critical) == 1
    assert critical[0]["severity"] == "critical"

    # Unresolved only (all currently unresolved)
    unresolved = await db_module.get_interface_error_events(unresolved_only=True)
    assert len(unresolved) == 2

    # Resolve one and re-check
    await db_module.resolve_interface_error_event(eid2)
    unresolved = await db_module.get_interface_error_events(unresolved_only=True)
    assert len(unresolved) == 1


@pytest.mark.asyncio
async def test_acknowledge_error_event(tmp_path, monkeypatch):
    """acknowledge sets the acknowledged flag and user."""
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    eid = await db_module.create_interface_error_event(
        host_id=host_id, if_index=1, if_name="Gi1/0/1",
        event_type="spike", metric_name="if_in_errors",
        severity="warning", current_rate=10, baseline_rate=1,
        spike_factor=10, root_cause_hint="test", root_cause_category="unknown",
    )

    ok = await db_module.acknowledge_interface_error_event(eid, "admin")
    assert ok is True

    event = await db_module.get_interface_error_event(eid)
    assert event["acknowledged"] == 1
    assert event["acknowledged_by"] == "admin"


@pytest.mark.asyncio
async def test_acknowledge_nonexistent_returns_false(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    ok = await db_module.acknowledge_interface_error_event(99999, "admin")
    assert ok is False


@pytest.mark.asyncio
async def test_resolve_error_event(tmp_path, monkeypatch):
    """resolve sets resolved_at timestamp."""
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    eid = await db_module.create_interface_error_event(
        host_id=host_id, if_index=1, if_name="Gi1/0/1",
        event_type="spike", metric_name="if_in_errors",
        severity="warning", current_rate=10, baseline_rate=1,
        spike_factor=10, root_cause_hint="test", root_cause_category="unknown",
    )
    ok = await db_module.resolve_interface_error_event(eid)
    assert ok is True

    event = await db_module.get_interface_error_event(eid)
    assert event["resolved_at"] is not None


@pytest.mark.asyncio
async def test_resolve_nonexistent_returns_false(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    ok = await db_module.resolve_interface_error_event(99999)
    assert ok is False


@pytest.mark.asyncio
async def test_interface_error_summary_from_metric_samples(tmp_path, monkeypatch):
    """get_interface_error_summary aggregates from metric_samples."""
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    labels = json.dumps({"if_index": 1, "if_name": "Gi1/0/1"})
    rows = [
        (host_id, "if_in_errors", labels, 10.0),
        (host_id, "if_in_errors", labels, 20.0),
        (host_id, "if_in_errors", labels, 30.0),
    ]
    await db_module.create_metric_samples_batch(rows)

    summary = await db_module.get_interface_error_summary(host_id, days=1)
    assert len(summary) >= 1
    row = summary[0]
    assert row["metric_name"] == "if_in_errors"
    assert row["sample_count"] == 3
    assert row["avg_value"] == pytest.approx(20.0)
    assert row["max_value"] == pytest.approx(30.0)
    assert row["min_value"] == pytest.approx(10.0)


@pytest.mark.asyncio
async def test_interface_error_trending_filter_by_if_index(tmp_path, monkeypatch):
    """get_interface_error_trending can filter by if_index via labels_json LIKE."""
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    labels_1 = json.dumps({"if_index": 1, "if_name": "Gi1/0/1"})
    labels_2 = json.dumps({"if_index": 2, "if_name": "Gi1/0/2"})
    rows = [
        (host_id, "if_in_errors", labels_1, 10.0),
        (host_id, "if_in_errors", labels_2, 20.0),
    ]
    await db_module.create_metric_samples_batch(rows)

    # All interfaces
    all_samples = await db_module.get_interface_error_trending(host_id)
    assert len(all_samples) == 2

    # Filter to if_index=1
    filtered = await db_module.get_interface_error_trending(host_id, if_index=1)
    assert len(filtered) == 1
    assert json.loads(filtered[0]["labels_json"])["if_index"] == 1


@pytest.mark.asyncio
async def test_delete_old_interface_error_events(tmp_path, monkeypatch):
    """delete_old_interface_error_events removes events older than retention."""
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    eid = await db_module.create_interface_error_event(
        host_id=host_id, if_index=1, if_name="Gi1/0/1",
        event_type="spike", metric_name="if_in_errors",
        severity="warning", current_rate=10, baseline_rate=1,
        spike_factor=10, root_cause_hint="test", root_cause_category="unknown",
    )

    # With a high retention of 365 days, nothing should be deleted
    deleted = await db_module.delete_old_interface_error_events(retention_days=365)
    assert deleted == 0

    # Event still exists
    assert (await db_module.get_interface_error_event(eid)) is not None


# ═════════════════════════════════════════════════════════════════════════════
# Root-cause classification tests
# ═════════════════════════════════════════════════════════════════════════════


class TestClassifyRootCause:
    """Tests for _classify_root_cause heuristic."""

    def test_deployment_takes_priority(self):
        cat, hint = _classify_root_cause(
            metric_name="if_in_errors",
            config_changes=[{"detected_at": "2025-01-01"}],
            deployments=[{"name": "upgrade-v2"}],
            topology_changes=[],
            syslog_events=[],
            spike_factor=10.0,
        )
        assert cat == "deployment"
        assert "upgrade-v2" in hint

    def test_config_change_second_priority(self):
        cat, hint = _classify_root_cause(
            metric_name="if_in_errors",
            config_changes=[{"detected_at": "2025-01-01"}],
            deployments=[],
            topology_changes=[],
            syslog_events=[],
            spike_factor=10.0,
        )
        assert cat == "config_change"
        assert "config change" in hint.lower()

    def test_topology_third_priority(self):
        cat, hint = _classify_root_cause(
            metric_name="if_in_errors",
            config_changes=[],
            deployments=[],
            topology_changes=[{"change_type": "link_down"}],
            syslog_events=[],
            spike_factor=10.0,
        )
        assert cat == "topology"
        assert "link_down" in hint

    def test_physical_syslog_events(self):
        cat, hint = _classify_root_cause(
            metric_name="if_in_errors",
            config_changes=[],
            deployments=[],
            topology_changes=[],
            syslog_events=[{"message": "SFP module removed from Gi1/0/1"}],
            spike_factor=10.0,
        )
        assert cat == "physical_layer"
        assert "SFP" in hint or "Physical" in hint

    def test_in_errors_fallback_physical_layer(self):
        cat, hint = _classify_root_cause(
            metric_name="if_in_errors",
            config_changes=[],
            deployments=[],
            topology_changes=[],
            syslog_events=[],
            spike_factor=10.0,
        )
        assert cat == "physical_layer"
        assert "CRC" in hint or "cable" in hint.lower()

    def test_out_errors_fallback_congestion(self):
        cat, _ = _classify_root_cause(
            metric_name="if_out_errors",
            config_changes=[],
            deployments=[],
            topology_changes=[],
            syslog_events=[],
            spike_factor=10.0,
        )
        assert cat == "congestion"

    def test_in_discards_fallback_congestion(self):
        cat, _ = _classify_root_cause(
            metric_name="if_in_discards",
            config_changes=[],
            deployments=[],
            topology_changes=[],
            syslog_events=[],
            spike_factor=10.0,
        )
        assert cat == "congestion"

    def test_out_discards_fallback_congestion(self):
        cat, _ = _classify_root_cause(
            metric_name="if_out_discards",
            config_changes=[],
            deployments=[],
            topology_changes=[],
            syslog_events=[],
            spike_factor=10.0,
        )
        assert cat == "congestion"

    def test_unknown_metric_returns_unknown(self):
        cat, hint = _classify_root_cause(
            metric_name="some_other_metric",
            config_changes=[],
            deployments=[],
            topology_changes=[],
            syslog_events=[],
            spike_factor=7.5,
        )
        assert cat == "unknown"
        assert "7.5" in hint

    def test_syslog_without_physical_keywords_falls_through(self):
        """Syslog events without physical keywords should not match physical_layer."""
        cat, _ = _classify_root_cause(
            metric_name="if_in_errors",
            config_changes=[],
            deployments=[],
            topology_changes=[],
            syslog_events=[{"message": "User logged in successfully"}],
            spike_factor=10.0,
        )
        # Should fall through to metric-type heuristic
        assert cat == "physical_layer"
