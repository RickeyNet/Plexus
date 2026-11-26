"""``reports`` shows reports, the audit and billing; ``reports.write`` starts
audit runs, changes audit schedules and overrides and changes billing. The
``created_by`` of a schedule and of an override is the caller. The MAC table
cleanup is for admins.

Every name below is invented test data.
"""

from __future__ import annotations

import pytest
from netcontrol.routes import state

from mcp_helpers import admin_client, user_client

AUDIT_WRITES = [
    ("post", "/api/audit/runs", None),
    ("post", "/api/audit/schedules", {"name": "nightly", "schedule": "@daily"}),
    ("put", "/api/audit/schedules/1", {"enabled": False}),
    ("delete", "/api/audit/schedules/1", None),
    ("post", "/api/audit/schedules/1/run-now", None),
    ("post", "/api/audit/overrides", {"rule_id": "config.drift"}),
    ("delete", "/api/audit/overrides/1", None),
]
BILLING_WRITES = [
    ("post", "/api/billing/circuits", {"name": "uplink", "host_id": 1, "if_index": 1}),
    ("put", "/api/billing/circuits/1", {"name": "uplink"}),
    ("delete", "/api/billing/circuits/1", None),
    ("post", "/api/billing/generate", {}),
    ("delete", "/api/billing/periods/1", None),
]


@pytest.fixture
def admin(monkeypatch, request):
    return admin_client(monkeypatch, request)


def _send(client, method: str, url: str, body):
    return getattr(client, method)(url) if body is None else getattr(client, method)(url, json=body)


def test_an_access_group_can_grant_the_write_level():
    assert "reports.write" in state.FEATURE_FLAGS
    assert "mac-tracking.write" not in state.FEATURE_FLAGS


@pytest.mark.parametrize(("method", "url", "body"), AUDIT_WRITES + BILLING_WRITES)
def test_the_read_level_changes_nothing(admin, method, url, body):
    reader = user_client(admin, "report-reader", features=["reports"])
    resp = _send(reader, method, url, body)
    assert resp.status_code == 403, resp.text
    assert "reports.write" in resp.text


def test_the_read_level_still_reads(admin):
    reader = user_client(admin, "report-reader", features=["reports"])
    for url in ("/api/audit/runs", "/api/audit/schedules", "/api/audit/overrides", "/api/billing/circuits"):
        assert reader.get(url).status_code == 200, url


def test_the_write_level_runs_the_audit_and_generates_billing(admin):
    writer = user_client(admin, "report-writer", features=["reports", "reports.write"])
    run = writer.post("/api/audit/runs")
    assert run.status_code == 201, run.text
    generated = writer.post("/api/billing/generate", json={})
    assert generated.status_code == 200, generated.text


def test_created_by_is_the_caller_not_the_request_body(admin):
    writer = user_client(admin, "report-writer", features=["reports", "reports.write"])
    schedule = writer.post(
        "/api/audit/schedules", json={"name": "nightly", "schedule": "@daily", "created_by": "someone-else"}
    )
    assert schedule.status_code == 201, schedule.text
    assert schedule.json()["created_by"] == "report-writer"
    override = writer.post(
        "/api/audit/overrides", json={"rule_id": "config.drift", "reason": "lab", "created_by": "someone-else"}
    )
    assert override.status_code == 201, override.text
    assert override.json()["created_by"] == "report-writer"


def test_the_mac_table_cleanup_is_for_admins(admin):
    for name, features in (
        ("mac-reader", ["mac-tracking"]),
        ("mac-collector", ["mac-tracking", "inventory", "inventory.write"]),
    ):
        resp = user_client(admin, name, features=features).post("/api/mac-tracking/cleanup?days=1")
        assert resp.status_code == 403, resp.text
        assert "Admin access required" in resp.text
    cleaned = admin.post("/api/mac-tracking/cleanup?days=30")
    assert cleaned.status_code == 200, cleaned.text
    assert cleaned.json() == {"removed": 0}
