"""Plugin framework (``netcontrol.plugins``): discovery and the allow-list,
version gating, failure isolation, the mounted router and its auth, plugin
migrations in their own namespace, and the ``/api/plugins`` manifest.

The example plugin under ``examples/plexus_plugin_example`` is imported from
its source directory and registered directly; nothing is pip-installed.
"""

from __future__ import annotations

import asyncio
import sys
import textwrap
from pathlib import Path

import netcontrol.app as app_module
import pytest
import routes.database as db
from fastapi import APIRouter
from netcontrol.plugins import PlexusPlugin, registry
from netcontrol.plugins.base import PluginError, validate_plugin
from netcontrol.plugins.registry import (
    STATUS_ACTIVE,
    STATUS_DISABLED,
    STATUS_FAILED,
    STATUS_LOADED,
    PluginRegistry,
    allow_list,
    check_version,
)
from netcontrol.routes.plugins import build_manifest, mount_plugin_routers
from netcontrol.routes.shared import supervise_task
from routes.migrations.runner import plugin_statement_violations, run_plugin_migrations
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

_EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "examples" / "plexus_plugin_example"
if str(_EXAMPLE_DIR) not in sys.path:
    sys.path.insert(0, str(_EXAMPLE_DIR))

import plexus_plugin_example  # noqa: E402

SPARES = "/api/plugins/example/spares"


class _FakeDist:
    version = "0.1.0"


class _FakeEntryPoint:
    """Stands in for an importlib.metadata.EntryPoint."""

    def __init__(self, name: str, target, value: str = ""):
        self.name = name
        self.value = value or f"{name}_pkg:plugin"
        self.dist = _FakeDist()
        self._target = target
        self.loaded = False

    def load(self):
        self.loaded = True
        if isinstance(self._target, BaseException):
            raise self._target
        return self._target


def _plugin(name: str = "other", **kw) -> PlexusPlugin:
    return PlexusPlugin(name=name, version="1.0.0", **kw)


@pytest.fixture
def example_registered():
    """The example plugin in the app's registry, its router mounted."""
    registry.reset()
    plexus_plugin_example.STATE.update(started=False, ticks=0)
    record = registry.register(plexus_plugin_example.plugin, source="test")
    assert record.status == STATUS_LOADED, record.errors
    mount_plugin_routers(app_module.app, app_module.require_feature_method)
    yield record
    registry.reset()


@pytest.fixture
def admin(monkeypatch, request, example_registered) -> CsrfClient:
    return admin_client(monkeypatch, request)


# ── Discovery and the allow-list ────────────────────────────────────────────


def test_allow_list_parses_env(monkeypatch):
    monkeypatch.setenv("PLEXUS_PLUGINS", " example, other ,example,, ")
    assert allow_list() == ["example", "other"]
    monkeypatch.delenv("PLEXUS_PLUGINS")
    assert allow_list() == []


def test_only_allow_listed_entry_points_are_imported():
    listed = _FakeEntryPoint("example", plexus_plugin_example.plugin)
    unlisted = _FakeEntryPoint("other", AssertionError("must not be imported"))
    reg = PluginRegistry()
    reg.discover(enabled=["example"], entry_points=[listed, unlisted])
    assert listed.loaded and not unlisted.loaded
    assert reg.get("example").status == STATUS_LOADED
    other = reg.get("other")
    assert other.status == STATUS_DISABLED and other.plugin is None and other.version == "0.1.0"


def test_installed_but_not_listed_loads_nothing(monkeypatch):
    monkeypatch.delenv("PLEXUS_PLUGINS", raising=False)
    ep = _FakeEntryPoint("example", plexus_plugin_example.plugin)
    reg = PluginRegistry()
    reg.discover(entry_points=[ep])
    assert not ep.loaded
    assert reg.get("example").status == STATUS_DISABLED


def test_env_allow_list_drives_discovery(monkeypatch):
    monkeypatch.setenv("PLEXUS_PLUGINS", "example")
    ep = _FakeEntryPoint("example", plexus_plugin_example.plugin)
    reg = PluginRegistry()
    reg.discover(entry_points=[ep])
    assert reg.get("example").status == STATUS_LOADED


def test_allow_listed_module_path_without_entry_point():
    reg = PluginRegistry()
    (record,) = reg.discover(enabled=["plexus_plugin_example"], entry_points=[])
    assert record.name == "example" and record.status == STATUS_LOADED


def test_allow_listed_but_missing_is_failed():
    reg = PluginRegistry()
    (record,) = reg.discover(enabled=["no_such_plexus_plugin_pkg"], entry_points=[])
    assert record.status == STATUS_FAILED
    assert record.errors and record.errors[0].startswith("import: ModuleNotFoundError")


def test_entry_point_name_must_match_plugin_name():
    reg = PluginRegistry()
    (record,) = reg.discover(enabled=["spares"], entry_points=[_FakeEntryPoint("spares", plexus_plugin_example.plugin)])
    assert record.status == STATUS_FAILED
    assert "declares plugin name 'example'" in record.errors[-1]


def test_duplicate_name_is_refused():
    reg = PluginRegistry()
    assert reg.register(_plugin("dup"), source="a").status == STATUS_LOADED
    second = reg.register(_plugin("dup"), source="b")
    assert second.status == STATUS_FAILED and "already registered" in second.errors[0]
    assert reg.get("dup").source == "a"


def test_feature_keys_are_added_and_removed():
    features: list[str] = ["inventory"]
    reg = PluginRegistry()
    reg.bind_feature_flags(features)
    reg.register(_plugin("gated"))
    assert features == ["inventory", "plugin:gated", "plugin:gated.write"]
    reg.reset()
    assert features == ["inventory"]


# ── Version gating ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("min_v", "max_v", "current", "ok"),
    [
        (None, None, "1.0.2", True),
        ("1.0.0", "1.9.9", "1.0.2", True),
        ("1.0.2", "1.0.2", "1.0.2", True),
        ("2.0.0", None, "1.0.2", False),
        (None, "1.0.1", "1.0.2", False),
        ("1.0.0", None, "1.0.2+edge.abc", True),
        ("2.0.0", None, "dev-build", True),  # an unparseable running version is not gated
    ],
)
def test_check_version(min_v, max_v, current, ok):
    plugin = _plugin(min_plexus_version=min_v, max_plexus_version=max_v)
    assert (check_version(plugin, current) is None) is ok


def test_bad_version_bound_is_an_error():
    assert "not a version" in check_version(_plugin(min_plexus_version="one"), "1.0.2")


def test_incompatible_plugin_is_failed_not_loaded():
    reg = PluginRegistry()
    features: list[str] = []
    reg.bind_feature_flags(features)
    record = reg.register(_plugin("future", min_plexus_version="999.0.0"))
    assert record.status == STATUS_FAILED
    assert record.errors[0].startswith("version: requires Plexus >= 999.0.0")
    assert record.plugin is None and features == []


# ── Declaration validation ───────────────────────────────────────────────────


def _page(blocks):
    return [{"id": "main", "title": "Main", "blocks": blocks}]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"name": "Bad-Name"}, "name must be"),
        ({"name": "x", "version": ""}, "version is required"),
        ({"pages": _page([{"type": "text", "id": "t", "text": "hi"}])}, "need a router"),
        (
            {
                "router": APIRouter(),
                "pages": _page(
                    [{"type": "table", "id": "t", "source": "../etc", "columns": [{"key": "a", "label": "A"}]}]
                ),
            },
            "relative to the plugin API",
        ),
        (
            {
                "router": APIRouter(),
                "pages": _page(
                    [
                        {
                            "type": "table",
                            "id": "t",
                            "source": "/api/admin/users",
                            "columns": [{"key": "a", "label": "A"}],
                        }
                    ]
                ),
            },
            "relative to the plugin API",
        ),
        (
            {
                "router": APIRouter(),
                "pages": _page(
                    [
                        {
                            "type": "form",
                            "id": "f",
                            "submit": "items",
                            "fields": [{"name": "a", "label": "A"}],
                            "refreshes": ["nope"],
                        }
                    ]
                ),
            },
            "refreshes unknown table",
        ),
        (
            {"router": APIRouter(), "pages": _page([{"type": "script", "id": "s", "text": "x"}])},
            "pages:",
        ),
        (
            {
                "router": APIRouter(),
                "pages": _page([{"type": "text", "id": "t", "text": "hi"}]),
                "navigation": [{"label": "Go", "page": "elsewhere"}],
            },
            "unknown page",
        ),
    ],
)
def test_invalid_declarations_are_refused(kwargs, message):
    fields = {"name": "ok", "version": "1.0.0", **kwargs}
    with pytest.raises(PluginError, match=message):
        validate_plugin(PlexusPlugin(**fields))


def test_example_declarations_are_valid():
    parsed = validate_plugin(plexus_plugin_example.plugin)
    assert [p.id for p in parsed.pages] == ["spares"]
    assert parsed.navigation[0].page == "spares"


# ── Failure isolation ────────────────────────────────────────────────────────


def test_broken_import_does_not_stop_the_others():
    broken = _FakeEntryPoint("broken", ImportError("missing dependency"))
    crashing = _FakeEntryPoint("crashing", SystemExit(3))
    good = _FakeEntryPoint("example", plexus_plugin_example.plugin)
    reg = PluginRegistry()
    reg.discover(enabled=["broken", "crashing", "example"], entry_points=[broken, crashing, good])
    assert reg.get("broken").status == STATUS_FAILED
    assert "ImportError: missing dependency" in reg.get("broken").errors[0]
    assert reg.get("crashing").status == STATUS_FAILED
    assert reg.get("example").status == STATUS_LOADED


def test_startup_failure_is_isolated():
    async def boom() -> None:
        raise RuntimeError("cannot reach backend")

    started: list[str] = []

    async def fine() -> None:
        started.append("fine")

    reg = PluginRegistry()
    reg.register(_plugin("boom", startup=boom))
    reg.register(_plugin("fine", startup=fine))
    asyncio.run(reg.start(db.get_db, supervise_task))
    assert reg.get("boom").status == STATUS_FAILED
    assert reg.get("boom").errors == ["startup: RuntimeError: cannot reach backend"]
    assert reg.get("fine").status == STATUS_ACTIVE and started == ["fine"]


def test_broken_plugin_does_not_stop_plexus(monkeypatch, request):
    async def boom() -> None:
        raise RuntimeError("startup exploded")

    registry.reset()
    request.addfinalizer(registry.reset)
    registry.register(_plugin("exploding", startup=boom))
    registry.register(_plugin("future", min_plexus_version="999.0.0"))
    admin = admin_client(monkeypatch, request)  # the app starts
    assert admin.get("/api/auth/status").status_code == 200
    plugins = {p["name"]: p for p in admin.get("/api/plugins").json()["plugins"]}
    assert plugins["exploding"]["status"] == STATUS_FAILED
    assert plugins["exploding"]["errors"] == ["startup: RuntimeError: startup exploded"]
    assert plugins["future"]["status"] == STATUS_FAILED


# ── Router, auth and lifecycle ───────────────────────────────────────────────


def test_router_requires_auth(admin):
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    assert anon.get(SPARES).status_code == 401


def test_admin_uses_the_plugin_api(admin):
    assert admin.get(SPARES).json() == []
    created = admin.post(SPARES, json={"part": "PSU-500W", "site": "Site A", "quantity": 2})
    assert created.status_code == 201, created.text
    assert created.json()["created_by"] == "admin"
    rows = admin.get(SPARES).json()
    assert [(r["part"], r["quantity"]) for r in rows] == [("PSU-500W", 2)]


def test_writes_need_csrf(admin):
    resp = admin.raw.post(SPARES, json={"part": "x"})
    assert resp.status_code == 403


def test_feature_key_gates_users(admin):
    nobody = user_client(admin, "no-plugin")
    assert nobody.get(SPARES).status_code == 403

    reader = user_client(admin, "reader", features=["plugin:example"])
    assert reader.get(SPARES).status_code == 200
    assert reader.post(SPARES, json={"part": "SFP"}).status_code == 403

    writer = user_client(admin, "writer", features=["plugin:example", "plugin:example.write"])
    assert writer.post(SPARES, json={"part": "SFP"}).status_code == 201


def test_plugin_feature_keys_offered_to_access_groups(admin):
    flags = admin.get("/api/admin/capabilities").json()["feature_flags"]
    assert "plugin:example" in flags and "plugin:example.write" in flags


def test_startup_hooks_and_background_task_run(admin, example_registered):
    assert example_registered.status == STATUS_ACTIVE
    assert plexus_plugin_example.STATE["started"] is True
    assert len(example_registered.tasks) == 1
    admin.raw.__exit__(None, None, None)  # lifespan shutdown
    assert plexus_plugin_example.STATE["started"] is False
    assert example_registered.tasks == []


def test_inactive_plugin_answers_503_and_unregistered_404(admin, example_registered):
    example_registered.status = STATUS_FAILED
    assert admin.get(SPARES).status_code == 503
    registry.reset()
    assert admin.get(SPARES).status_code == 404


def test_mounting_twice_adds_no_routes(example_registered):
    before = len(app_module.app.routes)
    assert mount_plugin_routers(app_module.app, app_module.require_feature_method) == []
    assert len(app_module.app.routes) == before


# ── Plugin migrations ────────────────────────────────────────────────────────


async def _fetch(sql: str, params: tuple = ()) -> list:
    conn = await db.get_db()
    try:
        cursor = await conn.execute(sql, params)
        return list(await cursor.fetchall())
    finally:
        await conn.close()


def test_plugin_migration_applied_in_its_namespace(admin):
    rows = asyncio.run(_fetch("SELECT plugin, version, description FROM plugin_schema_migrations"))
    assert [tuple(r) for r in rows] == [("example", 1, "Create plugin_example_spares")]
    tables = asyncio.run(
        _fetch("SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'plugin_example_%'")
    )
    assert [r[0] for r in tables] == ["plugin_example_spares"]
    # The core tracking table is untouched: plugin version 1 is not core version 1.
    core = asyncio.run(_fetch("SELECT description FROM schema_migrations WHERE version = 1"))
    assert all("plugin_example" not in r[0] for r in core)


def test_plugin_migrations_are_idempotent():
    async def run_twice() -> tuple[int, int]:
        conn = await db.get_db()
        try:
            first = await run_plugin_migrations(conn, "example", "plexus_plugin_example.migrations", "plugin_example_")
            second = await run_plugin_migrations(conn, "example", "plexus_plugin_example.migrations", "plugin_example_")
            return first, second
        finally:
            await conn.close()

    assert asyncio.run(run_twice()) == (1, 0)


@pytest.fixture
def bad_migrations(tmp_path, monkeypatch):
    pkg = tmp_path / "plexus_bad_plugin_migs"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "0001_touch_core.py").write_text(
        textwrap.dedent(
            """
            VERSION = 1
            DESCRIPTION = "reaches outside its namespace"

            async def up(db):
                await db.execute("ALTER TABLE hosts ADD COLUMN plugin_bad_x TEXT")
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    yield "plexus_bad_plugin_migs"
    for mod in [m for m in sys.modules if m.startswith("plexus_bad_plugin_migs")]:
        del sys.modules[mod]


def test_plugin_migration_outside_namespace_is_refused(bad_migrations):
    async def run() -> None:
        conn = await db.get_db()
        try:
            await run_plugin_migrations(conn, "bad", bad_migrations, "plugin_bad_")
        finally:
            await conn.close()

    with pytest.raises(PermissionError, match="refused: hosts"):
        asyncio.run(run())
    assert asyncio.run(_fetch("SELECT 1 FROM plugin_schema_migrations WHERE plugin = 'bad'")) == []
    cols = asyncio.run(
        _fetch("SELECT 1 FROM information_schema.columns WHERE table_name = 'hosts' AND column_name = 'plugin_bad_x'")
    )
    assert cols == []


def test_failed_migration_marks_plugin_failed(bad_migrations):
    reg = PluginRegistry()
    reg.register(_plugin("bad", migrations=bad_migrations))
    asyncio.run(reg.start(db.get_db, supervise_task))
    record = reg.get("bad")
    assert record.status == STATUS_FAILED and record.errors[0].startswith("migrations: PermissionError")


@pytest.mark.parametrize(
    ("sql", "bad"),
    [
        ("CREATE TABLE IF NOT EXISTS plugin_x_a (id INT REFERENCES hosts(id) ON DELETE CASCADE)", []),
        ("CREATE INDEX IF NOT EXISTS plugin_x_i ON plugin_x_a (id)", []),
        ("CREATE INDEX idx_a ON plugin_x_a (id)", ["idx_a"]),
        ("INSERT INTO plugin_x_a (id) VALUES (1) ON CONFLICT (id) DO NOTHING", []),
        ("INSERT INTO plugin_x_a (note) VALUES ('DROP TABLE users')", []),
        ("DROP TABLE users", ["users"]),
        ("UPDATE hosts SET hostname = 'x'", ["hosts"]),
        ('CREATE TABLE public."plugin_x_b" (id INT)', []),
    ],
)
def test_statement_guard(sql, bad):
    assert plugin_statement_violations(sql, "plugin_x_") == bad


# ── Manifest ─────────────────────────────────────────────────────────────────


def test_manifest_for_admin_has_details(admin):
    body = admin.get("/api/plugins").json()
    assert body["admin"] is True
    (entry,) = [p for p in body["plugins"] if p["name"] == "example"]
    assert entry["status"] == STATUS_ACTIVE
    assert entry["errors"] == [] and entry["source"] == "test"
    assert entry["feature"] == "plugin:example"
    assert entry["migrations_applied"] == 1 and entry["has_router"] is True
    assert entry["navigation"] == [{"label": "Spare Parts", "page": "spares"}]
    assert [b["type"] for b in entry["pages"][0]["blocks"]] == ["form", "table"]


def test_manifest_for_users_follows_the_feature(admin):
    assert user_client(admin, "no-plugin").get("/api/plugins").json() == {"admin": False, "plugins": []}
    body = user_client(admin, "reader", features=["plugin:example"]).get("/api/plugins").json()
    (entry,) = body["plugins"]
    assert entry["name"] == "example" and "errors" not in entry and "source" not in entry


def test_manifest_requires_auth(admin):
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    assert anon.get("/api/plugins").status_code == 401


def test_manifest_hides_inactive_plugins_from_users():
    reg = PluginRegistry()
    reg.register(_plugin("idle"))
    assert build_manifest(reg, is_admin=False, features={"plugin:idle"})["plugins"] == []
    reg.get("idle").status = STATUS_ACTIVE
    assert [p["name"] for p in build_manifest(reg, is_admin=False, features={"plugin:idle"})["plugins"]] == ["idle"]
