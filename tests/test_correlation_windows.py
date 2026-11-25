"""Correlation windows match rows stored the way the store writes times.

Timestamps are stored as UTC ``YYYY-MM-DD HH:MM:SS`` text and compared as
text in SQL. The alert and deployment correlations build their windows in
ISO form (``2026-03-10T09:30:00``, possibly with a fraction or ``+00:00``);
compared as text, every row stored on the window's first day sorted before
it (``" " < "T"``) and fell outside. The range readers now read each bound
in the stored form.

Every name and address below is invented.
"""

from __future__ import annotations

import functools
import json

import pytest
import routes.database as db_module
from routes.crypto import encrypt

from mcp_helpers import admin_client

ALERT_AT = "2026-03-10 10:00:00"
DRIFT_AT = "2026-03-10 09:50:00"
STARTED_AT = "2026-03-10 09:45:00"
FINISHED_AT = "2026-03-10 09:55:00"


async def _set(table: str, column: str, value: str, row_id: int) -> None:
    conn = await db_module.get_db()
    try:
        # Fixed table and column names from this module, value bound.
        await conn.execute(f"UPDATE {table} SET {column} = ? WHERE id = ?", (value, row_id))  # nosec B608
        await conn.commit()
    finally:
        await conn.close()


@pytest.fixture
def env(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    call = admin.raw.portal.call
    gid = call(functools.partial(db_module.create_group, "correlation-lab"))
    host_id = call(functools.partial(db_module.add_host, gid, "core-rtr1", "198.51.100.10"))
    cred_id = call(functools.partial(db_module.create_credential, "correlation-cred", "dev", encrypt("pw")))

    snapshot_id = call(functools.partial(db_module.create_config_snapshot, host_id, "hostname core-rtr1\n", "manual"))
    drift_id = call(
        functools.partial(
            db_module.create_config_drift_event, host_id, snapshot_id, None, "+ntp server 192.0.2.9\n", 1, 0
        )
    )
    call(_set, "config_drift_events", "detected_at", DRIFT_AT, drift_id)

    alert_id = call(functools.partial(db_module.create_monitoring_alert, host_id, None, "threshold", "cpu", "CPU high"))
    call(_set, "monitoring_alerts", "created_at", ALERT_AT, alert_id)

    dep_id = call(
        functools.partial(
            db_module.create_deployment,
            name="correlation-change",
            group_id=gid,
            credential_id=cred_id,
            proposed_commands="ntp server 192.0.2.9",
            host_ids=json.dumps([host_id]),
            created_by="admin",
        )
    )
    call(_set, "deployments", "started_at", STARTED_AT, dep_id)
    call(_set, "deployments", "finished_at", FINISHED_AT, dep_id)
    return {
        "admin": admin,
        "call": call,
        "host_id": host_id,
        "drift_id": drift_id,
        "alert_id": alert_id,
        "dep_id": dep_id,
    }


def test_alert_correlation_finds_a_deployment_and_drift_earlier_the_same_day(env):
    resp = env["admin"].get(f"/api/monitoring/alerts/{env['alert_id']}/correlation")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [d["id"] for d in body["related_deployments"]] == [env["dep_id"]]
    assert [e["id"] for e in body["related_drift_events"]] == [env["drift_id"]]


def test_deployment_correlation_finds_drift_and_alerts_in_its_window(env):
    resp = env["admin"].get(f"/api/deployments/{env['dep_id']}/correlation")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [e["id"] for e in body["drift_events"]] == [env["drift_id"]]
    assert [a["id"] for a in body["alerts"]] == [env["alert_id"]]


def test_range_readers_take_iso_bounds_with_a_zone_or_fraction(env):
    call, host_id = env["call"], env["host_id"]
    for start, end in (
        ("2026-03-10T09:40:00+00:00", "2026-03-10T10:10:00.123456+00:00"),
        ("2026-03-10T09:40:00Z", "2026-03-10T10:10:00Z"),
        # Another zone: 11:40 at +02:00 is 09:40 UTC.
        ("2026-03-10T11:40:00+02:00", "2026-03-10T12:10:00+02:00"),
    ):
        drift = call(db_module.get_config_drift_events_in_range, [host_id], start, end)
        alerts = call(db_module.get_monitoring_alerts_in_range, [host_id], start, end)
        assert [e["id"] for e in drift] == [env["drift_id"]], (start, end)
        assert [a["id"] for a in alerts] == [env["alert_id"]], (start, end)
    # A window that ends before the rows still excludes them.
    assert (
        call(db_module.get_config_drift_events_in_range, [host_id], "2026-03-10T09:00:00", "2026-03-10T09:30:00") == []
    )
