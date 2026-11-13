"""The MCP endpoint end to end: JSON-RPC requests against ``/mcp`` on the app."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import netcontrol.app as app_module
import pytest
from netcontrol.mcp import registry
from netcontrol.mcp.registry import Tool
from netcontrol.routes import state
from starlette.testclient import TestClient

from mcp_helpers import TOKENS, admin_client, admin_id, create_token, create_user, enable_mcp

URL = "/mcp/"
INIT = {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test-client", "version": "1"}}


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


def bare_client(admin) -> TestClient:
    """A client with no cookies on the running app's event loop (the MCP
    session manager lives on the loop the admin client started)."""
    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.portal = admin.raw.portal
    return client


def post(client, token: str | None, method: str, params: dict | None = None, url: str = URL):
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    return client.post(url, json=body, headers=headers)


def rpc(client, token: str, method: str, params: dict | None = None) -> dict:
    resp = post(client, token, method, params)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "error" not in data, data
    return data["result"]


def setup(monkeypatch, request, **token_kw):
    admin = admin_client(monkeypatch, request)
    enable_mcp(admin)
    return admin, bare_client(admin), create_token(admin, **token_kw)


def test_disabled_returns_404(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    token = create_token(admin)
    client = bare_client(admin)
    assert post(client, token, "tools/list").status_code == 404
    assert post(client, None, "tools/list").status_code == 404
    enable_mcp(admin)
    assert post(client, token, "tools/list").status_code == 200


def test_missing_and_bad_token_401(monkeypatch, request):
    _admin, client, token = setup(monkeypatch, request)
    for bad in (None, "", "plx_mcp_" + "x" * 43, token[:-1], "not-a-token"):
        resp = post(client, bad, "tools/list")
        assert resp.status_code == 401
        assert resp.json() == {"error": "unauthorized"}
        assert resp.headers["www-authenticate"] == "Bearer"


def test_app_api_token_rejected_on_mcp(monkeypatch, request):
    _admin, client, _token = setup(monkeypatch, request)
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "server-level-token")
    assert post(client, "server-level-token", "tools/list").status_code == 401
    resp = client.post(URL, json={}, headers={"X-API-Token": "server-level-token"})
    assert resp.status_code == 401


def test_mcp_token_rejected_on_api(monkeypatch, request):
    _admin, client, token = setup(monkeypatch, request)
    assert client.get(TOKENS, headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert client.get("/api/inventory", headers={"X-API-Token": token}).status_code == 401


def test_initialize_then_list_tools(monkeypatch, request):
    _admin, client, token = setup(monkeypatch, request)
    result = rpc(client, token, "initialize", INIT)
    assert result["serverInfo"]["name"] == "plexus"
    assert "tools" in result["capabilities"]
    assert "plexus_overview" in result.get("instructions", "")
    tools = rpc(client, token, "tools/list")["tools"]
    overview = next(t for t in tools if t["name"] == "plexus_overview")
    assert overview["inputSchema"]["type"] == "object"
    assert overview["description"]


def test_both_url_forms_work(monkeypatch, request):
    _admin, client, token = setup(monkeypatch, request)
    for url in ("/mcp", "/mcp/"):
        resp = post(client, token, "tools/list", url=url)
        assert resp.status_code == 200, (url, resp.status_code, resp.text)
        assert resp.history == []
    assert post(client, token, "tools/list", url="/mcp/other").status_code == 404


def test_list_tools_respects_categories(monkeypatch, request):
    async def _handler(ctx, args):
        return {"ok": True}

    monkeypatch.setattr(registry, "_TOOLS", dict(registry._TOOLS))
    schema = {"type": "object", "properties": {}, "additionalProperties": False}
    registry.register(Tool("throwaway_configs", "d", "configs", schema, _handler))
    registry.register(Tool("throwaway_inventory", "d", "inventory", schema, _handler))
    admin, client, inventory_token = setup(monkeypatch, request, categories=("inventory",))
    configs_token = create_token(admin, categories=("configs",), name="configs-bot")

    names = {t["name"] for t in rpc(client, inventory_token, "tools/list")["tools"]}
    assert "throwaway_inventory" in names and "throwaway_configs" not in names
    names = {t["name"] for t in rpc(client, configs_token, "tools/list")["tools"]}
    assert "throwaway_configs" in names and "throwaway_inventory" not in names

    hidden = rpc(client, inventory_token, "tools/call", {"name": "throwaway_configs", "arguments": {}})
    assert hidden["isError"] is True
    assert hidden["content"][0]["text"] == "Unknown tool: throwaway_configs"


def test_owner_features_gate_tools(monkeypatch, request):
    async def _handler(ctx, args):
        return {"ok": True}

    monkeypatch.setattr(registry, "_TOOLS", dict(registry._TOOLS))
    schema = {"type": "object", "properties": {}, "additionalProperties": False}
    registry.register(Tool("throwaway_inventory", "d", "inventory", schema, _handler))
    admin, client, _ = setup(monkeypatch, request)
    owner = create_user(admin, "no-features")
    token = create_token(admin, owner=owner, categories=("inventory",), name="limited-bot")
    names = {t["name"] for t in rpc(client, token, "tools/list")["tools"]}
    assert names == {"plexus_overview"}
    overview = rpc(client, token, "tools/call", {"name": "plexus_overview", "arguments": {}})
    assert json.loads(overview["content"][0]["text"])["categories"] == []


def test_call_overview(monkeypatch, request):
    admin, client, token = setup(monkeypatch, request, categories=("inventory", "configs"))
    result = rpc(client, token, "tools/call", {"name": "plexus_overview", "arguments": {}})
    assert result["isError"] is False
    data = json.loads(result["content"][0]["text"])
    assert set(data) >= {"categories", "devices", "sources"}
    assert set(data["categories"]) <= {"inventory", "configs"}
    assert isinstance(data["devices"]["total"], int)
    assert isinstance(data["devices"]["by_device_type"], dict)
    assert all({"name", "type", "status", "last_collected"} <= set(s) for s in data["sources"])
    assert admin.get(TOKENS).json()["tokens"][0]["call_count"] == 1


def test_call_unknown_tool_is_error_not_500(monkeypatch, request):
    _admin, client, token = setup(monkeypatch, request)
    result = rpc(client, token, "tools/call", {"name": "drop_all_tables", "arguments": {}})
    assert result["isError"] is True
    assert result["content"][0]["text"] == "Unknown tool: drop_all_tables"
    bad_args = rpc(client, token, "tools/call", {"name": "plexus_overview", "arguments": {"x": 1}})
    assert bad_args["isError"] is True


def test_no_csrf_needed(monkeypatch, request):
    _admin, client, token = setup(monkeypatch, request)
    resp = post(client, token, "tools/list")
    assert resp.status_code == 200
    assert "cookie" not in {k.lower() for k in resp.request.headers}
    assert "x-csrf-token" not in {k.lower() for k in resp.request.headers}


def test_session_cookie_does_not_authenticate_mcp(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    enable_mcp(admin)
    assert post(admin.raw, None, "tools/list").status_code == 401


def test_revoked_token_stops_immediately(monkeypatch, request):
    admin, client, token = setup(monkeypatch, request)
    assert post(client, token, "tools/list").status_code == 200
    token_id = admin.get(TOKENS).json()["tokens"][0]["id"]
    assert admin.delete(f"{TOKENS}/{token_id}").status_code == 200
    assert post(client, token, "tools/list").status_code == 401


def test_deleted_owner_stops_token(monkeypatch, request):
    admin, client, _ = setup(monkeypatch, request)
    owner = create_user(admin, "short-lived", role="admin")
    token = create_token(admin, owner=owner, name="orphan-bot")
    assert post(client, token, "tools/list").status_code == 200
    assert admin.delete(f"/api/admin/users/{owner}").status_code in (200, 204)
    assert post(client, token, "tools/list").status_code == 401
    assert admin_id(admin)


def test_repeated_bad_tokens_are_throttled_and_audited(monkeypatch, request):
    import asyncio

    import routes.database as db

    _admin, client, token = setup(monkeypatch, request)
    codes = [post(client, "plx_mcp_wrong", "tools/list").status_code for _ in range(25)]
    assert codes[0] == 401 and codes[-1] == 429
    assert post(client, token, "tools/list").status_code == 200
    events = asyncio.run(db.get_audit_events(limit=50, category="mcp"))
    assert len([e for e in events if e["action"] == "auth_failed"]) == 1


def test_get_is_not_served(monkeypatch, request):
    _admin, client, token = setup(monkeypatch, request)
    resp = client.get(URL, headers={"Authorization": f"Bearer {token}", "Accept": "text/event-stream"})
    assert resp.status_code in (400, 405)


# ── Registry guarantees ──────────────────────────────────────────────────────

_WRITE_PREFIXES = (
    "add_",
    "create_",
    "update_",
    "delete_",
    "set_",
    "upsert_",
    "insert_",
    "remove_",
    "save_",
    "revoke_",
    "touch_",
    "apply_",
    "purge_",
    "bulk_",
    "move_",
    "acknowledge_",
)


def test_registry_has_no_write_imports():
    tools_dir = Path(registry.__file__).parent / "tools"
    modules = sorted(tools_dir.glob("*.py"))
    assert len(modules) >= 2
    offenders = []
    for path in modules:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.ImportFrom):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.Attribute):
                names = [node.attr]
            offenders += [f"{path.name}:{name}" for name in names if name.startswith(_WRITE_PREFIXES)]
    assert offenders == []


def test_every_tool_has_a_closed_schema_and_known_category():
    from netcontrol.mcp.auth import CATEGORIES

    registry.load_tools()
    tools = registry.all_tools()
    assert any(t.name == "plexus_overview" and t.category is None for t in tools)
    for tool in tools:
        assert tool.category is None or tool.category in CATEGORIES, tool.name
        assert tool.input_schema.get("type") == "object", tool.name
        assert tool.input_schema.get("additionalProperties") is False, tool.name
        assert len(tool.description) >= 20, tool.name
