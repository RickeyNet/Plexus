"""Regression tests for the Content-Security-Policy tightening.

The global security-headers middleware now sets ``script-src 'self'`` (no
``'unsafe-inline'`` and no CDN) for the whole app: the React bundle ships as
external hashed modules, so nothing in the SPA needs an inline script. The one
page that genuinely needs a looser policy -- the graph-export embed page, with
its inline bootstrap <script> and CDN ECharts -- sets its own CSP, and the
middleware must not clobber it (it uses setdefault).
"""

from __future__ import annotations

import pytest
import routes.database as db_module


@pytest.fixture
def client(tmp_path, monkeypatch, request):
    import netcontrol.app as app_module

    db_path = str(tmp_path / "csp.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-csp")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient
    c = TestClient(app_module.app, raise_server_exceptions=False)
    c.__enter__()
    request.addfinalizer(lambda: c.__exit__(None, None, None))
    return c


def test_global_csp_has_no_inline_script(client):
    resp = client.get("/api/health")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert csp, "expected a CSP header on every response"

    # Isolate the script-src directive.
    directives = {
        d.strip().split(" ", 1)[0]: d.strip()
        for d in csp.split(";")
        if d.strip()
    }
    script_src = directives.get("script-src", "")
    assert script_src == "script-src 'self'", script_src
    assert "'unsafe-inline'" not in script_src
    assert "cdn.jsdelivr.net" not in script_src

    # style-src intentionally keeps 'unsafe-inline' for dynamic style= attrs.
    assert "'unsafe-inline'" in directives.get("style-src", "")


def test_middleware_does_not_clobber_endpoint_csp(monkeypatch, client):
    """A route that sets its own CSP (the graph-export embed page) keeps it;
    the middleware only fills in a default when none is present."""
    from starlette.responses import HTMLResponse

    import netcontrol.app as app_module

    scoped = (
        "default-src 'self'; script-src 'self' 'unsafe-inline' "
        "https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'"
    )

    @app_module.app.get("/api/_csp_probe")
    async def _probe():  # pragma: no cover - registered for the test only
        return HTMLResponse("<b>ok</b>", headers={"Content-Security-Policy": scoped})

    resp = client.get("/api/_csp_probe")
    assert resp.headers.get("Content-Security-Policy") == scoped
