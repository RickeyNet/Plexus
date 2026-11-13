"""The MCP tool registry: what tools exist and who may see each one.

A tool module under ``netcontrol/mcp/tools/`` registers its tools at import
(``load_tools`` imports them all). A tool is listed for a caller, and
callable, only when ``is_visible`` says so; a tool that is not visible is
indistinguishable from one that does not exist.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from netcontrol.mcp.auth import CATEGORIES, McpContext


class ToolError(Exception):
    """A failure whose message is safe, and useful, to show to the model."""


Handler = Callable[[McpContext, dict[str, Any]], Awaitable[Any]]


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    category: str | None  # None = always available (plexus_overview)
    input_schema: dict[str, Any]  # JSON Schema, "additionalProperties": False
    handler: Handler
    features: tuple[str, ...] = ()  # feature keys needed beyond the category's own
    admin_only: bool = False


# The feature (from ``state._FEATURE_CATALOG``) a token's owner must hold for
# each category. ``traffic`` tools name theirs per tool; ``audit`` tools are
# ``admin_only`` because there is no audit feature key.
CATEGORY_FEATURES: dict[str, tuple[str, ...]] = {
    "inventory": ("inventory",),
    "configs": ("config-backups",),
    "compliance": ("compliance",),
    "monitoring": ("monitoring",),
    "topology": ("topology",),
    "software": ("software",),
    "traffic": (),
    "audit": (),
}

_TOOLS: dict[str, Tool] = {}
_loaded = False


def register(tool: Tool) -> Tool:
    if tool.category is not None and tool.category not in CATEGORIES:
        raise ValueError(f"Unknown category for tool {tool.name}: {tool.category}")
    if tool.name in _TOOLS:
        raise ValueError(f"Tool already registered: {tool.name}")
    _TOOLS[tool.name] = tool
    return tool


def all_tools() -> list[Tool]:
    return list(_TOOLS.values())


def get_tool(name: str) -> Tool | None:
    return _TOOLS.get(name)


def is_visible(tool: Tool, ctx: McpContext) -> bool:
    if tool.category is None:
        return True
    if tool.category not in ctx.categories:
        return False
    if tool.admin_only and not ctx.owner_is_admin:
        return False
    if ctx.owner_is_admin:
        return True
    needed = CATEGORY_FEATURES[tool.category] + tool.features
    return all(key in ctx.features for key in needed)


def visible_tools(ctx: McpContext) -> list[Tool]:
    return [tool for tool in all_tools() if is_visible(tool, ctx)]


def usable_categories(ctx: McpContext) -> list[str]:
    """The categories in which this caller can see at least one tool."""
    seen = {tool.category for tool in visible_tools(ctx)}
    return [category for category in CATEGORIES if category in seen]


def load_tools() -> None:
    """Import every module in ``netcontrol.mcp.tools`` once, so each registers."""
    global _loaded
    if _loaded:
        return
    from netcontrol.mcp import tools

    for module in pkgutil.iter_modules(tools.__path__):
        importlib.import_module(f"{tools.__name__}.{module.name}")
    _loaded = True
