"""The one path every MCP tool call takes.

``call_tool`` rate-limits the token, finds the tool (a hidden tool and a
missing one give the same answer), validates the arguments against the
tool's schema, runs the handler under a timeout, masks secrets, caps the
size, records the use and writes an audit event. It never raises: every
outcome is ``(text, is_error)``.

Handlers return plain data and do none of this themselves, so a new tool
cannot skip masking, the size cap or the audit trail.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import time
from typing import Any

import routes.database as db
from jsonschema import Draft202012Validator

from netcontrol.mcp import redact, registry
from netcontrol.mcp.auth import McpContext
from netcontrol.mcp.registry import ToolError
from netcontrol.mcp.settings import DEFAULTS, load_settings
from netcontrol.routes import state
from netcontrol.routes.shared import _audit
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.mcp")

HANDLER_TIMEOUT_SECONDS: float = 30
RATE_WINDOW_SECONDS = 60
_AUDIT_ARGUMENT_CHARS = 500
_TRUNCATION_HINT = "The result was cut to fit the size limit. Use a smaller limit, a filter, or a narrower query."

_max_rows: contextvars.ContextVar[int] = contextvars.ContextVar("mcp_max_rows", default=int(DEFAULTS["max_rows"]))


# ── Helpers for tool handlers ────────────────────────────────────────────────


def no_data(source: str) -> dict[str, Any]:
    """The answer when a data source has never been collected: said in
    words, so the model does not read an empty list as "nothing found"."""
    return {"no_data": True, "message": f"No data collected for {source}."}


def page(rows: list, limit: int | None, cursor: str | None, max_rows: int) -> dict[str, Any]:
    """One page of ``rows``. ``cursor`` is the opaque string a previous page
    returned as ``next_cursor``."""
    offset = 0
    if cursor not in (None, ""):
        try:
            offset = int(str(cursor))
        except ValueError:
            offset = -1
        if offset < 0:
            raise ToolError("Invalid cursor. Pass the next_cursor value from the previous page, or omit it.")
    size = max(1, min(int(limit) if limit else max_rows, max_rows))
    items = rows[offset : offset + size]
    end = offset + len(items)
    return {
        "items": items,
        "offset": offset,
        "next_cursor": str(end) if end < len(rows) else None,
        "total": len(rows),
    }


def max_rows() -> int:
    """The admin's list-row limit for the call in progress."""
    return _max_rows.get()


def page_args(rows: list, args: dict[str, Any]) -> dict[str, Any]:
    """``page`` driven by a tool's ``limit`` and ``cursor`` arguments."""
    return page(rows, args.get("limit"), args.get("cursor"), max_rows())


# ── Rate limit ───────────────────────────────────────────────────────────────


def rate_limited(key: str, limit: int, window: int = RATE_WINDOW_SECONDS) -> bool:
    """Count one event against ``key``'s sliding window; ``True`` when the
    window is already full. Kept in ``state.API_RATE_LIMIT_TRACKER`` (the
    API limiter's map, so its cleanup loop prunes these entries too)."""
    now = time.time()
    tracker = state.API_RATE_LIMIT_TRACKER
    stamps = [t for t in tracker.get(key, []) if now - t < window]
    if len(stamps) >= limit:
        tracker[key] = stamps
        return True
    stamps.append(now)
    tracker[key] = stamps
    return False


# ── Serialising and capping ──────────────────────────────────────────────────


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _size(text: str) -> int:
    return len(text.encode("utf-8"))


def _encode(result: Any, max_bytes: int) -> str:
    """``result`` as JSON within ``max_bytes``. A paged result loses items
    from the end until it fits (and its ``next_cursor`` is moved back to
    match); a first row too large on its own is skipped; anything else is
    replaced by a notice. Always valid JSON."""
    text = _dumps(result)
    if _size(text) <= max_bytes:
        return text
    if isinstance(result, dict) and isinstance(result.get("items"), list):
        items = result["items"]

        def _cut(count: int) -> str:
            cut = {**result, "items": items[:count], "truncated": True, "hint": _TRUNCATION_HINT}
            if "next_cursor" in result and isinstance(result.get("offset"), int):
                cut["next_cursor"] = str(result["offset"] + count)
            return _dumps(cut)

        low, high = 0, len(items)
        while low < high:  # the largest count that fits
            mid = (low + high + 1) // 2
            if _size(_cut(mid)) <= max_bytes:
                low = mid
            else:
                high = mid - 1
        text = _cut(low)
        offset, total = result.get("offset"), result.get("total")
        if low == 0 and items and isinstance(offset, int) and isinstance(total, int):
            # Not even the first row fits. Step over it, or a client that
            # follows next_cursor would ask for the same row for ever.
            skipped = {**result, "items": [], "truncated": True, "skipped_oversized_row": True}
            skipped["hint"] = "One row is larger than the size limit and was skipped. " + _TRUNCATION_HINT
            skipped["next_cursor"] = str(offset + 1) if offset + 1 < total else None
            text = _dumps(skipped)
        if _size(text) <= max_bytes:
            return text
    return _dumps({"truncated": True, "message": "Result too large. Narrow the query.", "hint": _TRUNCATION_HINT})


def _row_count(result: Any) -> int:
    if isinstance(result, dict) and isinstance(result.get("items"), list):
        return len(result["items"])
    if isinstance(result, list):
        return len(result)
    return 1


def _argument_error(tool: registry.Tool, arguments: dict[str, Any]) -> str | None:
    errors = sorted(Draft202012Validator(tool.input_schema).iter_errors(arguments), key=lambda e: list(e.path))
    if not errors:
        return None
    error = errors[0]
    where = ".".join(str(part) for part in error.path)
    detail = str(error.message)
    if len(detail) > 300:
        detail = detail[:300] + "..."
    return f"Invalid arguments for {tool.name}: {where + ': ' if where else ''}{detail}"


# ── The dispatcher ───────────────────────────────────────────────────────────


async def _record(ctx: McpContext, name: str, arguments: Any, outcome: str, rows: int, size: int, started: float):
    try:
        shown = _dumps(redact.redact_value(arguments))[:_AUDIT_ARGUMENT_CHARS]
    except Exception:
        shown = "(withheld)"
    detail = {
        "token": ctx.token_name,
        "tool": name[:100],
        "arguments": shown,
        "rows": rows,
        "bytes": size,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "outcome": outcome,
    }
    await _audit("mcp", "tool_call", user=ctx.owner_username, detail=json.dumps(detail))


async def call_tool(ctx: McpContext, name: str, arguments: dict[str, Any] | None) -> tuple[str, bool]:
    """Run one tool call for ``ctx``. Returns ``(text, is_error)``; on
    success ``text`` is JSON."""
    started = time.monotonic()
    name = str(name)
    args: Any = {} if arguments is None else arguments
    outcome, rows, text, found = "error", 0, "Tool failed. See the Plexus server log.", False
    try:
        limits = await load_settings()
        if rate_limited(f"mcp:{ctx.token_id}", int(limits["calls_per_minute"])):
            # One audit row per window, not one per refused call.
            if not rate_limited(f"mcp-limit-audit:{ctx.token_id}", 1):
                await _record(ctx, name, args, "rate_limited", 0, 0, started)
            return "Rate limit reached. Retry in a few seconds.", True

        tool = registry.get_tool(name)
        if tool is None or not registry.is_visible(tool, ctx):
            outcome, text = "denied", f"Unknown tool: {name}"
        else:
            found = True
            problem = _argument_error(tool, args)
            if problem:
                text = problem
            else:
                token = _max_rows.set(int(limits["max_rows"]))
                try:
                    result = await asyncio.wait_for(tool.handler(ctx, args), HANDLER_TIMEOUT_SECONDS)
                finally:
                    _max_rows.reset(token)
                result = redact.redact_result(result)
                text = _encode(result, int(limits["max_result_bytes"]))
                outcome, rows = "ok", _row_count(result)
    except ToolError as exc:
        # A tool's own message can quote device data, so it is masked too.
        try:
            text = redact.redact_config_text(str(exc)) or "The tool could not answer."
        except Exception:
            LOGGER.exception("mcp: redaction failed for the error of tool %s", name)
            text = "Result withheld: redaction failed."
    except redact.RedactionError:
        LOGGER.exception("mcp: redaction failed for tool %s", name)
        text = "Result withheld: redaction failed."
    except TimeoutError:
        text = "The tool timed out. Narrow the query and try again."
    except Exception:
        LOGGER.exception("mcp: tool %s failed", name)
        text = "Tool failed. See the Plexus server log."

    is_error = outcome != "ok"
    try:
        if found:
            await db.touch_mcp_token(ctx.token_id)
        await _record(ctx, name, args, outcome, rows, 0 if is_error else _size(text), started)
    except Exception:
        LOGGER.exception("mcp: could not record tool call %s", name)
    return text, is_error
