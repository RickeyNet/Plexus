"""The largest list and graph responses go through FastAPI's direct-to-JSON
path: a handler with a return annotation is serialized by pydantic's core in
one step, while one without is walked by ``jsonable_encoder`` and then by
``json.dumps`` (about 17 times slower on a 2 MB list). A custom
``response_class`` (or a global ``default_response_class``) turns the direct
path off again, so both are checked here.
"""

from __future__ import annotations

import netcontrol.app as app_module
import pytest
from fastapi import routing
from fastapi.datastructures import DefaultPlaceholder

# path -> the JSON type of its body.
HOT_HANDLERS = {
    "/api/inventory": list,
    "/api/topology": dict,
    "/api/cloud/topology": dict,
    "/api/metrics/query": dict,
    "/api/mac-tracking/search": list,
    "/api/dashboard": dict,
}


def _route(path: str):
    """The route as FastAPI serves it: routes of an included router are not
    in ``app.routes`` themselves, so walk the contexts the OpenAPI build uses."""
    return next(
        ctx
        for ctx in routing.iter_route_contexts(app_module.app.routes)
        if ctx.path == path and "GET" in (ctx.methods or ())
    )


@pytest.mark.parametrize("path", sorted(HOT_HANDLERS))
def test_hot_handler_is_on_the_direct_json_path(path):
    route = _route(path)
    assert route.response_field is not None, f"{path} lost its return annotation"
    assert isinstance(route.response_class, DefaultPlaceholder), f"{path} sets a response class"


def _auth_client(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-json-path")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return client


def test_hot_handlers_answer_json_of_the_annotated_type(monkeypatch, request):
    """Every return path of each handler fits its annotation: a value that
    did not would be a 500 (``ResponseValidationError``), not a body."""
    client = _auth_client(monkeypatch, request)
    urls = {
        "/api/inventory": ["/api/inventory", "/api/inventory?include_hosts=true"],
        "/api/topology": ["/api/topology"],
        "/api/cloud/topology": ["/api/cloud/topology", "/api/cloud/topology?provider=aws"],
        "/api/metrics/query": [
            "/api/metrics/query?metric=cpu_percent",
            "/api/metrics/query?metric=cpu_percent&range=7d&step=hourly",
            "/api/metrics/query?metric=cpu_percent&range=1h&step=raw&host=1",
        ],
        "/api/mac-tracking/search": ["/api/mac-tracking/search", "/api/mac-tracking/search?query=aa:bb"],
        "/api/dashboard": ["/api/dashboard"],
    }
    for path, expected in HOT_HANDLERS.items():
        for url in urls[path]:
            resp = client.get(url)
            assert resp.status_code == 200, f"{url}: {resp.status_code} {resp.text[:200]}"
            assert resp.headers["content-type"].startswith("application/json"), url
            assert isinstance(resp.json(), expected), url
