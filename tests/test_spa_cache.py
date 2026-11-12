"""The SPA's unhashed files are revalidated on every load.

Only ``dist/assets`` is content-hashed. ``index.html`` names the current
bundle, so a browser that reuses an old copy after an upgrade keeps loading
the old bundle (and, for example, never offers a newly added theme).
"""

from __future__ import annotations

import netcontrol.app as app_module


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
