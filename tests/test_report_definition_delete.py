"""A saved report definition is listed for every user with ``reports`` and
deleted only by the user who saved it or by an admin.

Every name below is invented test data.
"""

from __future__ import annotations

import pytest

from mcp_helpers import admin_client, user_client


@pytest.fixture
def admin(monkeypatch, request):
    return admin_client(monkeypatch, request)


def _save(client, name: str) -> int:
    resp = client.post("/api/reports", json={"name": name, "report_type": "availability"})
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _names(client) -> set[str]:
    return {r["name"] for r in client.get("/api/reports").json()["reports"]}


def test_only_the_creator_or_an_admin_deletes_a_saved_report(admin):
    owner = user_client(admin, "report-owner", features=["reports"])
    other = user_client(admin, "report-reader", features=["reports", "reports.write"])
    weekly = _save(owner, "weekly availability")
    monthly = _save(owner, "monthly availability")
    by_admin = _save(admin, "admin availability")

    # Another user sees the definitions and cannot delete them, with or
    # without the write level.
    assert {"weekly availability", "monthly availability", "admin availability"} <= _names(other)
    for report_id in (weekly, by_admin):
        resp = other.delete(f"/api/reports/{report_id}")
        assert resp.status_code == 403, resp.text
    assert {"weekly availability", "admin availability"} <= _names(owner)

    assert owner.delete(f"/api/reports/{weekly}").status_code == 200
    assert admin.delete(f"/api/reports/{monthly}").status_code == 200
    assert _names(admin) == {"admin availability"}
    assert owner.delete(f"/api/reports/{weekly}").status_code == 404
