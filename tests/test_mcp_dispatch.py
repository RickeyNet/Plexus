"""The MCP tool registry and the dispatcher every tool call goes through."""

from __future__ import annotations

import json

import pytest
import routes.database as db
from netcontrol.mcp import dispatch, registry, settings
from netcontrol.mcp.auth import McpContext
from netcontrol.mcp.registry import Tool, ToolError
from netcontrol.routes import state

from mcp_helpers import call, db_ctx

SCHEMA = {
    "type": "object",
    "properties": {"host": {"type": "string"}, "limit": {"type": "integer"}},
    "required": ["host"],
    "additionalProperties": False,
}
NO_ARGS = {"type": "object", "properties": {}, "additionalProperties": False}


@pytest.fixture(autouse=True)
def _empty_registry(monkeypatch):
    """Throwaway tools only; no rate-limit state from another test."""
    monkeypatch.setattr(registry, "_TOOLS", {})
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


def _ctx(*, categories=("inventory",), features=("inventory",), admin=False) -> McpContext:
    return McpContext(
        token_id=1,
        token_name="bot",
        owner_id=1,
        owner_username="ai-reader",
        owner_is_admin=admin,
        categories=frozenset(categories),
        features=frozenset(features),
    )


def _tool(name="t", category="inventory", handler=None, schema=NO_ARGS, **kw) -> Tool:
    async def _default(ctx, args):
        return {"ok": True}

    return registry.register(
        Tool(name=name, description="d", category=category, input_schema=schema, handler=handler or _default, **kw)
    )


# ── Registry ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("tool_kw", "ctx_kw", "visible"),
    [
        ({}, {}, True),
        ({}, {"categories": ("configs",)}, False),
        ({}, {"features": ()}, False),
        ({}, {"features": (), "admin": True}, True),
        ({"admin_only": True}, {}, False),
        ({"admin_only": True}, {"admin": True}, True),
        ({"category": None}, {"categories": (), "features": ()}, True),
        ({"features": ("config-drift",)}, {}, False),
        ({"features": ("config-drift",)}, {"features": ("inventory", "config-drift")}, True),
        ({"category": "traffic", "features": ("mac-tracking",)}, {"categories": ("traffic",), "features": ()}, False),
        (
            {"category": "traffic", "features": ("mac-tracking",)},
            {"categories": ("traffic",), "features": ("mac-tracking",)},
            True,
        ),
    ],
)
def test_visibility_matrix(tool_kw, ctx_kw, visible):
    tool = _tool(**tool_kw)
    ctx = _ctx(**ctx_kw)
    assert registry.is_visible(tool, ctx) is visible
    assert (tool in registry.visible_tools(ctx)) is visible


def test_register_rejects_duplicates_and_unknown_category():
    _tool("one")
    with pytest.raises(ValueError):
        _tool("one")
    with pytest.raises(ValueError):
        _tool("two", category="passwords")
    assert [t.name for t in registry.all_tools()] == ["one"]


def test_category_features_cover_every_category():
    from netcontrol.mcp.auth import CATEGORIES

    assert set(registry.CATEGORY_FEATURES) == set(CATEGORIES)
    known = set(state.FEATURE_FLAGS)
    assert all(set(keys) <= known for keys in registry.CATEGORY_FEATURES.values())


# ── Dispatcher ───────────────────────────────────────────────────────────────


async def test_hidden_tool_same_error_as_missing():
    _tool("hidden", category="configs")
    ctx = await db_ctx(categories=["inventory"])
    hidden = await dispatch.call_tool(ctx, "hidden", {})
    missing = await dispatch.call_tool(ctx, "nope", {})
    assert hidden == ("Unknown tool: hidden", True)
    assert missing == ("Unknown tool: nope", True)


@pytest.mark.parametrize(
    ("arguments", "needle"),
    [
        ({"host": 5}, "host"),
        ({"host": "a", "surprise": 1}, "surprise"),
        ({}, "host"),
        ({"host": "a", "limit": "ten"}, "limit"),
        (None, "host"),
    ],
)
async def test_bad_arguments_are_tool_errors(arguments, needle):
    calls = []

    async def _handler(ctx, args):
        calls.append(args)
        return {}

    _tool("needs-host", handler=_handler, schema=SCHEMA)
    ctx = await db_ctx()
    text, is_error = await dispatch.call_tool(ctx, "needs-host", arguments)
    assert is_error is True
    assert needle in text
    assert calls == []


async def test_valid_arguments_reach_the_handler():
    async def _handler(ctx, args):
        return {"echo": args, "caller": ctx.token_name}

    _tool("needs-host", handler=_handler, schema=SCHEMA)
    ctx = await db_ctx()
    data, is_error = await call(ctx, "needs-host", {"host": "edge-rtr-01", "limit": 5})
    assert is_error is False
    assert data == {"echo": {"host": "edge-rtr-01", "limit": 5}, "caller": "ctx-bot"}


async def test_result_is_redacted():
    async def _handler(ctx, args):
        return {"line": "snmp-server community hunter2 RO", "api_key": "abc123"}

    _tool(handler=_handler)
    text, is_error = await dispatch.call_tool(await db_ctx(), "t", {})
    assert is_error is False
    assert "hunter2" not in text and "abc123" not in text
    assert "snmp-server community" in text


async def test_redaction_failure_withholds_result(monkeypatch):
    async def _handler(ctx, args):
        return {"line": "snmp-server community hunter2 RO"}

    def _boom(value):
        raise RuntimeError("no")

    _tool(handler=_handler)
    monkeypatch.setattr(dispatch.redact, "redact_value", _boom)
    text, is_error = await dispatch.call_tool(await db_ctx(), "t", {})
    assert (text, is_error) == ("Result withheld: redaction failed.", True)


async def test_tool_error_message_is_returned():
    async def _handler(ctx, args):
        raise ToolError("No host matches 'x'. Try search_hosts.")

    _tool(handler=_handler)
    assert await dispatch.call_tool(await db_ctx(), "t", {}) == ("No host matches 'x'. Try search_hosts.", True)


async def test_handler_exception_is_generic():
    async def _handler(ctx, args):
        raise RuntimeError("relation secret_table does not exist")

    _tool(handler=_handler)
    text, is_error = await dispatch.call_tool(await db_ctx(), "t", {})
    assert is_error is True
    assert text == "Tool failed. See the Plexus server log."
    assert "secret_table" not in text and "Traceback" not in text


async def test_handler_timeout_is_a_tool_error(monkeypatch):
    import asyncio

    async def _handler(ctx, args):
        await asyncio.sleep(5)

    _tool(handler=_handler)
    monkeypatch.setattr(dispatch, "HANDLER_TIMEOUT_SECONDS", 0.05)
    text, is_error = await dispatch.call_tool(await db_ctx(), "t", {})
    assert is_error is True and "timed out" in text


async def test_truncates_items_to_valid_json():
    async def _handler(ctx, args):
        rows = [{"n": i, "name": "コア・スイッチ-ñ-" + str(i)} for i in range(5000)]
        return dispatch.page(rows, 5000, None, 5000)

    _tool(handler=_handler)
    await settings.save_settings({"max_result_bytes": 10_000})
    text, is_error = await dispatch.call_tool(await db_ctx(), "t", {})
    assert is_error is False
    assert len(text.encode("utf-8")) <= 10_000
    data = json.loads(text)
    assert data["truncated"] is True and data["hint"]
    assert 0 < len(data["items"]) < 5000
    assert data["items"][0]["name"].startswith("コア")
    assert data["next_cursor"] == str(len(data["items"]))
    assert data["total"] == 5000


def test_oversized_row_is_skipped_so_paging_moves_on():
    rows = [{"c": "é" * 30_000}, {"c": "x"}]
    first = json.loads(dispatch._encode(dispatch.page(rows, None, None, 200), 10_000))
    assert first["items"] == [] and first["truncated"] is True
    assert first["skipped_oversized_row"] is True
    assert first["next_cursor"] == "1"
    second = json.loads(dispatch._encode(dispatch.page(rows, None, first["next_cursor"], 200), 10_000))
    assert second["items"] == [{"c": "x"}] and second["next_cursor"] is None


def test_oversized_last_row_ends_the_list():
    rows = [{"c": "x"}, {"c": "é" * 30_000}]
    last = json.loads(dispatch._encode(dispatch.page(rows, None, "1", 200), 10_000))
    assert last["items"] == [] and last["skipped_oversized_row"] is True
    assert last["next_cursor"] is None


async def test_oversize_non_list_result_is_replaced():
    async def _handler(ctx, args):
        return {"config": "interface Vlan10\n" * 5000}

    _tool(handler=_handler)
    await settings.save_settings({"max_result_bytes": 10_000})
    text, is_error = await dispatch.call_tool(await db_ctx(), "t", {})
    data = json.loads(text)
    assert data["truncated"] is True and data["hint"] and "config" not in data
    assert len(text.encode("utf-8")) <= 10_000


async def test_rate_limit():
    _tool()
    await settings.save_settings({"calls_per_minute": 3})
    ctx = await db_ctx()
    results = [await dispatch.call_tool(ctx, "t", {}) for _ in range(4)]
    assert [r[1] for r in results] == [False, False, False, True]
    assert results[3][0] == "Rate limit reached. Retry in a few seconds."
    other = await db_ctx(name="second-bot")
    assert (await dispatch.call_tool(other, "t", {}))[1] is False


async def test_audit_row_per_call():
    async def _handler(ctx, args):
        return {"items": [{"hostname": "edge-rtr-01-result-marker"}], "note": "x"}

    _tool("needs-host", handler=_handler, schema=SCHEMA)
    ctx = await db_ctx()
    await dispatch.call_tool(ctx, "needs-host", {"host": "edge-rtr-01"})
    await dispatch.call_tool(ctx, "needs-host", {})
    await dispatch.call_tool(ctx, "missing-tool", {})
    events = [e for e in await db.get_audit_events(limit=20, category="mcp") if e["action"] == "tool_call"]
    assert len(events) == 3
    assert all(e["user"] == "ctx-bot-owner" for e in events)
    details = [json.loads(e["detail"]) for e in reversed(events)]
    assert [d["outcome"] for d in details] == ["ok", "error", "denied"]
    assert details[0]["tool"] == "needs-host" and details[0]["token"] == "ctx-bot"
    assert details[0]["rows"] == 1 and details[0]["bytes"] > 0 and "duration_ms" in details[0]
    assert "edge-rtr-01" in details[0]["arguments"]
    assert all("result-marker" not in e["detail"] for e in events)


async def test_audit_arguments_are_redacted_and_bounded():
    schema = {
        "type": "object",
        "properties": {"pattern": {"type": "string"}, "password": {"type": "string"}},
        "additionalProperties": False,
    }
    _tool(schema=schema)
    ctx = await db_ctx()
    await dispatch.call_tool(ctx, "t", {"pattern": "x" * 2000, "password": "hunter2"})
    (event,) = [e for e in await db.get_audit_events(limit=5, category="mcp") if e["action"] == "tool_call"]
    detail = json.loads(event["detail"])
    assert "hunter2" not in event["detail"]
    assert len(detail["arguments"]) <= 500


async def test_touch_increments_call_count():
    _tool()
    ctx = await db_ctx()
    await dispatch.call_tool(ctx, "t", {})
    await dispatch.call_tool(ctx, "t", {})
    row = await db.get_mcp_token(ctx.token_id)
    assert row["call_count"] == 2 and row["last_used_at"] != ""


# ── Helpers handlers use ─────────────────────────────────────────────────────


def test_page_helper():
    rows = list(range(450))
    first = dispatch.page(rows, 500, None, 200)
    assert len(first["items"]) == 200 and first["total"] == 450 and first["next_cursor"]
    second = dispatch.page(rows, 500, first["next_cursor"], 200)
    third = dispatch.page(rows, 500, second["next_cursor"], 200)
    assert first["items"] + second["items"] + third["items"] == rows
    assert third["next_cursor"] is None
    assert len(dispatch.page(rows, 10, None, 200)["items"]) == 10
    assert len(dispatch.page(rows, None, None, 200)["items"]) == 200
    with pytest.raises(ToolError):
        dispatch.page(rows, 10, "not-a-cursor", 200)
    with pytest.raises(ToolError):
        dispatch.page(rows, 10, "-5", 200)


def test_no_data_shape():
    assert dispatch.no_data("config backups") == {
        "no_data": True,
        "message": "No data collected for config backups.",
    }


async def test_max_rows_setting_reaches_handlers():
    async def _handler(ctx, args):
        return dispatch.page_args(list(range(100)), args)

    _tool(handler=_handler)
    await settings.save_settings({"max_rows": 25})
    data, _ = await call(await db_ctx(), "t", {})
    assert len(data["items"]) == 25 and data["next_cursor"] == "25"


async def test_tool_error_text_is_redacted():
    async def _handler(ctx, args):
        raise ToolError("No such section. Lines seen:\nsnmp-server community hunter2 RO\nrouter bgp 65001")

    _tool(handler=_handler)
    text, is_error = await dispatch.call_tool(await db_ctx(), "t", {})
    assert is_error is True
    assert "hunter2" not in text and "router bgp 65001" in text


async def test_tool_error_is_withheld_when_redaction_fails(monkeypatch):
    async def _handler(ctx, args):
        raise ToolError("snmp-server community hunter2 RO")

    def _boom(text):
        raise RuntimeError("no")

    _tool(handler=_handler)
    monkeypatch.setattr(dispatch.redact, "redact_config_text", _boom)
    text, is_error = await dispatch.call_tool(await db_ctx(), "t", {})
    assert (text, is_error) == ("Result withheld: redaction failed.", True)
