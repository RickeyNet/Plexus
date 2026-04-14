"""Config drift event history DB tests."""

from __future__ import annotations

import pytest
import routes.database as db_module


@pytest.fixture
async def drift_history_db(tmp_path, monkeypatch):
    """Create a temporary DB with one host/baseline/snapshot/event."""
    db_path = str(tmp_path / "drift_history_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setattr(db_module, "DB_ENGINE", "sqlite")
    await db_module.init_db()

    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (1, 'core')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, status) "
            "VALUES (100, 1, 'sw-core-01', '10.0.1.1', 'cisco_ios', 'online')"
        )
        await db.commit()
    finally:
        await db.close()

    baseline_id = await db_module.create_config_baseline(host_id=100, config_text="hostname sw-core-01\n")
    snapshot_id = await db_module.create_config_snapshot(
        host_id=100,
        config_text="hostname sw-core-01\nsnmp-server community public RO\n",
    )
    event_id = await db_module.create_config_drift_event(
        host_id=100,
        snapshot_id=snapshot_id,
        baseline_id=baseline_id,
        diff_text="@@ -1 +1 @@\n-hostname sw-core-01\n+hostname sw-core-01\n+snmp-server community public RO\n",
        diff_lines_added=1,
        diff_lines_removed=0,
    )
    return {"event_id": event_id, "host_id": 100}


@pytest.mark.asyncio
async def test_create_and_list_drift_event_history(drift_history_db):
    """History entries should be returned newest-first with host context."""
    event_id = drift_history_db["event_id"]
    host_id = drift_history_db["host_id"]

    await db_module.create_config_drift_event_history(
        event_id=event_id,
        host_id=host_id,
        action="detected",
        from_status="",
        to_status="open",
        actor="system",
        details="+1 -0 lines changed",
    )
    await db_module.create_config_drift_event_history(
        event_id=event_id,
        host_id=host_id,
        action="status_change",
        from_status="open",
        to_status="accepted",
        actor="admin",
        details="bulk accept",
    )

    rows = await db_module.get_config_drift_event_history(event_id, limit=10)
    assert len(rows) == 2
    assert rows[0]["action"] == "status_change"
    assert rows[0]["to_status"] == "accepted"
    assert rows[0]["hostname"] == "sw-core-01"
    assert rows[1]["action"] == "detected"
    assert rows[1]["to_status"] == "open"


@pytest.mark.asyncio
async def test_drift_event_history_cascade_delete(drift_history_db):
    """Deleting a drift event should cascade-delete its history rows."""
    event_id = drift_history_db["event_id"]
    host_id = drift_history_db["host_id"]

    await db_module.create_config_drift_event_history(
        event_id=event_id,
        host_id=host_id,
        action="detected",
        from_status="",
        to_status="open",
        actor="system",
        details="initial",
    )
    pre = await db_module.get_config_drift_event_history(event_id, limit=10)
    assert len(pre) == 1

    db = await db_module.get_db()
    try:
        await db.execute("DELETE FROM config_drift_events WHERE id = ?", (event_id,))
        await db.commit()
    finally:
        await db.close()

    post = await db_module.get_config_drift_event_history(event_id, limit=10)
    assert post == []
