"""The SPA's unhashed files are revalidated on every load.

Only ``dist/assets`` is content-hashed. ``index.html`` names the current
bundle, so a browser that reuses an old copy after an upgrade keeps loading
the old bundle (and, for example, never offers a newly added theme).
"""

from __future__ import annotations

import netcontrol.app as app_module
import pytest
from starlette.requests import Request


async def test_index_and_root_files_are_sent_no_cache(tmp_path, monkeypatch):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html>", encoding="utf-8")
    (dist / "viewer-layout.js").write_text("// layout", encoding="utf-8")
    monkeypatch.setattr(app_module, "FRONTEND_DIST", str(dist))
    monkeypatch.setattr(app_module, "FRONTEND_INDEX", str(dist / "index.html"))

    # The root, a client-side route and a file in dist/ itself.
    for path in ("", "settings/appearance", "viewer-layout.js"):
        response = await app_module.serve_react_frontend(path)
        assert response.headers["cache-control"] == "no-cache", path
    assert (await app_module.serve_react_frontend("viewer-layout.js")).path.endswith("viewer-layout.js")


def _frontend_request(query: str = "") -> Request:
    return Request({"type": "http", "method": "GET", "path": "/frontend", "query_string": query.encode(), "headers": []})


async def test_legacy_frontend_prefix_redirects_to_the_same_route():
    response = await app_module.redirect_legacy_frontend_prefix(_frontend_request("tab=alerts"), "monitoring/alerts")
    assert response.status_code == 301
    assert response.headers["location"] == "/monitoring/alerts?tab=alerts"
    assert (await app_module.redirect_legacy_frontend_prefix(_frontend_request(), "")).headers["location"] == "/"


@pytest.mark.parametrize("path", ["/evil.example.com", "//evil.example.com", "\\evil.example.com", "a//b"])
async def test_legacy_frontend_prefix_never_redirects_off_the_site(path):
    """``/frontend//host`` used to answer ``Location: //host``, which a
    browser reads as another site."""
    response = await app_module.redirect_legacy_frontend_prefix(_frontend_request(), path)
    assert response.headers["location"] == "/"
