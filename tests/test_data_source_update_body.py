"""``PUT /api/data-sources/{ds_id}`` refuses a body that is not a JSON
object with a client error, before it looks the data source up."""

from __future__ import annotations

import pytest

from mcp_helpers import admin_client

JSON = {"Content-Type": "application/json"}


@pytest.fixture
def admin(monkeypatch, request):
    return admin_client(monkeypatch, request)


@pytest.mark.parametrize("raw", [b"", b"not json", b"[1, 2]", b'"name"'])
def test_a_body_that_is_not_a_json_object_is_a_client_error(admin, raw):
    resp = admin.put("/api/data-sources/999999999", content=raw, headers=JSON)
    assert resp.status_code == 422, resp.text
    assert resp.json()["error"]["code"] == "validation_error"


def test_a_json_object_still_reaches_the_lookup(admin):
    resp = admin.put("/api/data-sources/999999999", json={"name": "uplink"})
    assert resp.status_code == 404, resp.text
