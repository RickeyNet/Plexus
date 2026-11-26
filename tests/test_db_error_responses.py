"""Input the database refuses answers a client error, not 500.

A number past the column's range, a reference to a record that does not
exist and a name that is taken are caller mistakes: the API answers 4xx with
a general message (``netcontrol/db_errors.py`` and the handlers in
``netcontrol/app.py``). Day counts are bounded where they are declared.
"""

from __future__ import annotations

import asyncpg
import pytest
from netcontrol.db_errors import client_error_for

from mcp_helpers import admin_client

PAST_INT64 = 2**63
PAST_INT32 = 2**31


@pytest.fixture
def admin(monkeypatch, request):
    return admin_client(monkeypatch, request)


def _error(resp, status: int) -> dict:
    assert resp.status_code == status, f"answered {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    assert body["ok"] is False
    return body["error"]


# ── Numbers the column cannot hold ───────────────────────────────────────────


def test_path_id_past_the_column_range_is_422(admin):
    error = _error(admin.get(f"/api/hosts/{PAST_INT64}/custom-data"), 422)
    assert error == {"code": "validation_error", "message": "A value in the request is out of range"}


def test_a_handler_that_wraps_the_database_error_still_answers_422(admin):
    # Both topology routes catch every exception and raise their own 500.
    _error(admin.get(f"/api/topology/host/{PAST_INT64}"), 422)
    _error(admin.get("/api/topology", params={"group_id": PAST_INT64}), 422)


def test_body_integer_past_the_column_range_is_422(admin):
    _error(admin.post("/api/graph-trees", json={"name": "range tree", "sort_order": PAST_INT32}), 422)


# ── Missing parents and taken names ──────────────────────────────────────────


def test_host_in_a_group_that_does_not_exist_is_404(admin):
    resp = admin.post("/api/inventory/999999/hosts", json={"hostname": "edge-sw1", "ip_address": "192.0.2.92"})
    assert _error(resp, 404)["message"] == "Group not found"


def test_reference_to_a_record_that_does_not_exist_is_409(admin):
    resp = admin.post("/api/billing/circuits", json={"name": "wan-1", "host_id": 999999, "if_index": 1})
    error = _error(resp, 409)
    assert error["message"] == "The request refers to a record that does not exist or is still in use"
    # The table and constraint names stay in the log.
    assert "billing" not in resp.text and "constraint" not in resp.text


def test_second_record_with_a_taken_name_is_409(admin):
    body = {"name": "double", "expression": "a,2,*"}
    assert admin.post("/api/cdefs", json=body).status_code == 201
    error = _error(admin.post("/api/cdefs", json=body), 409)
    assert error == {"code": "http_error", "message": "A record with the same value already exists"}


def test_second_lab_environment_with_a_taken_name_is_409(admin):
    body = {"name": "staging"}
    assert admin.post("/api/lab/environments", json=body).status_code == 200
    error = _error(admin.post("/api/lab/environments", json=body), 409)
    assert error["message"] == "A lab environment with that name already exists"


# ── Day counts ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("path", "param"),
    [
        ("/api/availability/summary", "days"),
        ("/api/reports/export/availability", "days"),
        ("/api/reports/export/interface", "days"),
        ("/api/reports/export/ipam_forecast", "lookback_days"),
        ("/api/reports/export/ipam_forecast.pdf", "lookback_days"),
        ("/api/reports/export/ipam_history", "days"),
    ],
)
def test_day_count_is_bounded(admin, path, param):
    assert admin.get(path, params={param: PAST_INT32 - 1}).status_code == 422
    assert admin.get(path, params={param: 0}).status_code == 422
    assert admin.get(path, params={param: 30}).status_code == 200


# ── The mapping ──────────────────────────────────────────────────────────────


def test_other_database_errors_stay_server_errors(admin, monkeypatch):
    import routes.database as db

    async def broken():
        raise asyncpg.UndefinedTableError('relation "cdef_definitions" does not exist')

    monkeypatch.setattr(db, "list_cdef_definitions", broken)
    error = _error(admin.get("/api/cdefs"), 500)
    assert error == {"code": "internal_error", "message": "Internal server error"}


def test_other_database_errors_are_not_client_errors():
    assert client_error_for(asyncpg.UndefinedTableError("relation does not exist")) is None
    assert client_error_for(asyncpg.InterfaceError("connection is closed")) is None
    assert client_error_for(RuntimeError("boom")) is None
    # A wrong argument type is a server bug: the driver reports it with the
    # same class as a number out of range, told apart by its cause.
    wrong_type = asyncpg.DataError("invalid input for query argument $1")
    wrong_type.__cause__ = TypeError("an integer is required")
    assert client_error_for(wrong_type) is None
    # Only the error itself counts, not one met while handling another.
    later = RuntimeError("boom")
    later.__context__ = asyncpg.UniqueViolationError("duplicate key value")
    assert client_error_for(later) is None
