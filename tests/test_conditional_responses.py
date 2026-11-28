"""Conditional GETs of the cached read endpoints (dashboard, topology, cloud
topology, software overview): an ETag on every answer, 304 without a body
when the caller already holds that body, a new body after a write, one ETag
per view (each caller's own), the authorization checks before any 304, and
cached bodies byte for byte what the handler's own return path writes."""

from __future__ import annotations

import asyncio
import datetime as dt
from decimal import Decimal

import netcontrol.app as app_module
import netcontrol.routes.cloud_visibility as cloud_visibility
import netcontrol.routes.software as software
import netcontrol.routes.topology as topology
import pytest
import routes.database as db_module
from fastapi.encoders import jsonable_encoder
from netcontrol import payload_cache
from netcontrol.routes import state
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client
from test_hot_handler_json_path import _route

ENDPOINTS = ["/api/dashboard", "/api/topology", "/api/cloud/topology", "/api/software/overview"]


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _group(admin: CsrfClient, name: str) -> int:
    resp = admin.post("/api/inventory", json={"name": name})
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _host(admin: CsrfClient, group_id: int, name: str, ip: str) -> int:
    resp = admin.post(f"/api/inventory/{group_id}/hosts", json={"hostname": name, "ip_address": ip})
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


@pytest.fixture
def two_sites(admin) -> dict[str, int]:
    """site-a and site-b, one host each, and a neighbor link between them."""
    ids = {"a": _group(admin, "site-a"), "b": _group(admin, "site-b")}
    ids["ha"] = _host(admin, ids["a"], "edge-a", "192.0.2.10")
    ids["hb"] = _host(admin, ids["b"], "edge-b", "198.51.100.20")
    asyncio.run(
        db_module.upsert_topology_link(
            ids["ha"], "192.0.2.10", "Gi0/1", ids["hb"], "198.51.100.20", "edge-b", "Gi0/2", "lldp"
        )
    )
    topology.invalidate_topology_cache()
    return ids


def _assert_not_modified(resp, etag: str) -> None:
    assert resp.status_code == 304, resp.text
    assert resp.content == b""
    assert resp.headers["etag"] == etag
    assert resp.headers["cache-control"] == payload_cache.API_CACHE_CONTROL
    # The HTTP middleware's headers are on a 304 too.
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-correlation-id"]


@pytest.mark.parametrize("path", ENDPOINTS)
def test_etag_then_not_modified(admin, path):
    first = admin.get(path)
    assert first.status_code == 200, first.text
    etag = first.headers["etag"]
    # Weak: the body is compressed after the handler.
    assert etag.startswith('W/"') and etag.endswith('"')
    assert first.headers["cache-control"] == "private, no-cache"
    _assert_not_modified(admin.get(path, headers={"If-None-Match": etag}), etag)
    # Another tag in the list, or the strong form of the same opaque tag, also matches.
    _assert_not_modified(admin.get(path, headers={"If-None-Match": f'W/"other", {etag[2:]}'}), etag)
    stale = admin.get(path, headers={"If-None-Match": 'W/"not-this-body"'})
    assert stale.status_code == 200 and stale.headers["etag"] == etag
    assert stale.content == first.content


def test_compressed_answer_keeps_its_etag(admin):
    resp = admin.get("/api/dashboard", headers={"Accept-Encoding": "gzip"})
    assert resp.status_code == 200
    if len(resp.content) >= 500:
        assert resp.headers["content-encoding"] == "gzip"
    again = admin.get("/api/dashboard", headers={"Accept-Encoding": "gzip", "If-None-Match": resp.headers["etag"]})
    _assert_not_modified(again, resp.headers["etag"])


def test_a_write_gives_a_new_body_and_etag(admin, two_sites):
    url = f"/api/topology?group_id={two_sites['a']}"
    before = admin.get(url)
    etag = before.headers["etag"]
    _host(admin, two_sites["a"], "edge-a2", "192.0.2.11")  # clears the graph cache
    after = admin.get(url, headers={"If-None-Match": etag})
    assert after.status_code == 200
    assert after.headers["etag"] != etag
    assert "edge-a2" in {node["label"] for node in after.json()["nodes"]}

    overview = admin.get("/api/software/overview")
    created = admin.post(
        "/api/software/advisories",
        json={"advisory_id": "etag-1", "platform": "ios", "affected_versions": ["15.2(7)E8"]},
    )
    assert created.status_code == 201, created.text
    changed = admin.get("/api/software/overview", headers={"If-None-Match": overview.headers["etag"]})
    assert changed.status_code == 200
    assert changed.headers["etag"] != overview.headers["etag"]


def test_each_caller_gets_its_own_body_and_etag(admin, two_sites):
    full = admin.get("/api/topology")
    assert {node["label"] for node in full.json()["nodes"]} >= {"edge-a", "edge-b"}
    scoped = user_client(admin, "site-a-viewer", features=["topology", "dashboard"], read_groups=[two_sites["a"]])
    own = scoped.get("/api/topology", headers={"If-None-Match": full.headers["etag"]})
    # Not a 304 against the admin's graph: the scoped caller's own body.
    assert own.status_code == 200
    assert "edge-b" not in {node["label"] for node in own.json()["nodes"]}
    assert own.headers["etag"] != full.headers["etag"]
    _assert_not_modified(
        scoped.get("/api/topology", headers={"If-None-Match": own.headers["etag"]}), own.headers["etag"]
    )

    # The dashboard: the admin's whole payload and a non-admin's view differ.
    admin_dashboard = admin.get("/api/dashboard")
    viewer = user_client(admin, "dashboard-viewer", features=["dashboard"])
    view = viewer.get("/api/dashboard", headers={"If-None-Match": admin_dashboard.headers["etag"]})
    assert view.status_code == 200
    assert set(view.json()) == {"stats"}
    assert view.headers["etag"] != admin_dashboard.headers["etag"]
    _assert_not_modified(
        viewer.get("/api/dashboard", headers={"If-None-Match": view.headers["etag"]}), view.headers["etag"]
    )
    limited = scoped.get("/api/dashboard", headers={"If-None-Match": admin_dashboard.headers["etag"]})
    assert limited.status_code == 200 and limited.headers["etag"] != admin_dashboard.headers["etag"]


def test_authorization_runs_before_the_conditional_check(admin, two_sites):
    group_b = f"/api/topology?group_id={two_sites['b']}"
    etags = {url: admin.get(url).headers["etag"] for url in [*ENDPOINTS, group_b]}

    anonymous = TestClient(app_module.app, raise_server_exceptions=False)
    for url, etag in etags.items():
        assert anonymous.get(url, headers={"If-None-Match": etag}).status_code == 401, url

    no_features = user_client(admin, "no-topology", features=["inventory"])
    for url, etag in etags.items():
        assert no_features.get(url, headers={"If-None-Match": etag}).status_code == 403, url

    scoped = user_client(admin, "site-a-only", features=["topology"], read_groups=[two_sites["a"]])
    out_of_scope = scoped.get(group_b, headers={"If-None-Match": etags[group_b]})
    assert out_of_scope.status_code == 404


def test_cached_bodies_are_what_the_handlers_write(admin):
    for path in ENDPOINTS:
        assert admin.get(path).status_code == 200, path
    cached = {
        "/api/dashboard": app_module._dashboard_cache.peek(app_module._DASHBOARD_KEY),
        "/api/topology": topology._TOPOLOGY_CACHE.peek(None),
        "/api/cloud/topology": cloud_visibility._snapshot_cache.peek((None, None)),
    }
    for path, payload in cached.items():
        assert payload is not None, path
        field = _route(path).response_field
        value, errors = field.validate(payload.value, {}, loc=("response",))
        assert not errors
        assert payload.body == field.serialize_json(value), path
        assert admin.get(path).content == payload.body, path
    overview = software._overview_cache.peek(("", "", ""))
    assert overview is not None
    assert overview.body == JSONResponse(jsonable_encoder(overview.value)).body
    assert admin.get("/api/software/overview").content == overview.body


def test_direct_json_matches_fastapi_for_dates_and_decimals():
    sample = {
        "polled_at": dt.datetime(2026, 11, 27, 8, 15, 0, 250000, tzinfo=dt.UTC),
        "naive": dt.datetime(2026, 11, 27, 8, 15),
        "day": dt.date(2026, 11, 27),
        "uptime": dt.timedelta(hours=5, seconds=3),
        "percent": Decimal("97.125"),
        "count": Decimal("12"),
        "rate": 1e-07,
        "label": "core-sw.example.com é",
        "rows": [{"ip": "203.0.113.5", "up": True, "ports": (1, 2)}, None],
    }
    for path in ("/api/dashboard", "/api/topology", "/api/cloud/topology"):
        field = _route(path).response_field
        value, _ = field.validate(sample, {}, loc=("response",))
        assert payload_cache.direct_json(sample) == field.serialize_json(value), path


def test_conditional_check_is_for_get_only():
    payload = payload_cache.JsonPayload({"ok": True})

    def request(method: str) -> Request:
        return Request(
            {
                "type": "http",
                "method": method,
                "path": "/api/example",
                "headers": [(b"if-none-match", payload.etag.encode())],
            }
        )

    assert payload_cache.json_response(request("GET"), payload).status_code == 304
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        resp = payload_cache.json_response(request(method), payload)
        assert resp.status_code == 200 and resp.body == payload.body, method
    # A direct call without a request gets the body.
    assert payload_cache.json_response(None, payload).status_code == 200


def test_a_write_with_if_none_match_is_unaffected(admin):
    group_id = _group(admin, "site-c")
    resp = admin.post(
        f"/api/inventory/{group_id}/hosts",
        json={"hostname": "edge-c", "ip_address": "203.0.113.30"},
        headers={"If-None-Match": "*"},
    )
    assert resp.status_code == 201, resp.text
    assert "etag" not in resp.headers
