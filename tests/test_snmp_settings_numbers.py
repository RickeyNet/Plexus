"""The SNMP settings routes answer 400, not a server error, when ``port``,
``timeout_seconds`` or ``retries`` is not a number, and keep what is stored.

Every name below is invented test data.
"""

from __future__ import annotations

import pytest

from mcp_helpers import admin_client

BAD_NUMBERS = [{"port": "x"}, {"port": None}, {"timeout_seconds": "slow"}, {"retries": [1]}]


@pytest.fixture
def admin(monkeypatch, request):
    return admin_client(monkeypatch, request)


@pytest.fixture
def group_id(admin) -> int:
    created = admin.post("/api/inventory", json={"name": "Lab"})
    assert created.status_code == 201, created.text
    return int(created.json()["id"])


def _refused(resp) -> None:
    assert resp.status_code == 400, resp.text
    assert "must be numbers" in resp.text


@pytest.mark.parametrize("bad", BAD_NUMBERS)
def test_the_discovery_settings_refuse_a_value_that_is_not_a_number(admin, bad):
    before = admin.get("/api/admin/snmp-discovery").json()
    _refused(admin.put("/api/admin/snmp-discovery", json={"enabled": True, **bad}))
    assert admin.get("/api/admin/snmp-discovery").json() == before


@pytest.mark.parametrize("bad", BAD_NUMBERS)
def test_a_shared_profile_refuses_a_value_that_is_not_a_number(admin, bad):
    _refused(admin.post("/api/admin/snmp-profiles", json={"name": "core", **bad}))
    created = admin.post("/api/admin/snmp-profiles", json={"name": "core", "port": 1161})
    assert created.status_code == 200, created.text
    _refused(admin.put(f"/api/admin/snmp-profiles/{created.json()['id']}", json={"name": "core", **bad}))


@pytest.mark.parametrize("bad", BAD_NUMBERS)
def test_a_group_profile_refuses_a_value_that_is_not_a_number(admin, group_id, bad):
    _refused(admin.put(f"/api/inventory/{group_id}/snmp-discovery-profile", json={"enabled": True, **bad}))


def test_a_number_too_large_to_be_a_port_is_refused(admin):
    # 1e400 reads as infinity; the test client cannot send it as ``json=``.
    raw = b'{"enabled": true, "port": 1e400}'
    _refused(admin.put("/api/admin/snmp-discovery", content=raw, headers={"Content-Type": "application/json"}))


def test_numbers_and_a_numeric_version_are_still_accepted(admin, group_id):
    body = {"enabled": True, "version": 3, "port": "1161", "timeout_seconds": 2, "retries": 1}
    for path in ("/api/admin/snmp-discovery", f"/api/inventory/{group_id}/snmp-discovery-profile"):
        saved = admin.put(path, json=body)
        assert saved.status_code == 200, saved.text
        assert (saved.json()["version"], saved.json()["port"], saved.json()["retries"]) == ("3", 1161, 1)
