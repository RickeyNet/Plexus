"""The MCP endpoint: the SDK server and the ASGI app that guards it.

``build_mcp_app`` returns the ASGI app ``netcontrol.app`` serves at ``/mcp``
and the context manager its lifespan enters. Per request the app:

1. answers 404 while AI access is switched off (the default);
2. resolves the ``Authorization: Bearer`` token into an ``McpContext`` or
   answers 401 (a session cookie or ``APP_API_TOKEN`` is never accepted);
3. hands the request to the SDK's Streamable HTTP transport, run stateless
   with plain JSON responses, so there is no stream to proxy and no session
   to keep.

The server offers tools only. ``tools/list`` returns what the caller's token
may see; ``tools/call`` goes through ``dispatch.call_tool``.

DNS-rebinding protection in the SDK is off: it guards unauthenticated local
servers, while every request here needs a bearer token and Plexus is served
under whatever internal host name the deployment uses.
"""

from __future__ import annotations

import contextlib
import contextvars
import json
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AbstractAsyncContextManager
from typing import Any

from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.types import ASGIApp, Receive, Scope, Send

from mcp import types
from netcontrol.mcp import registry
from netcontrol.mcp.auth import McpContext, extract_bearer, resolve_token
from netcontrol.mcp.dispatch import call_tool, rate_limited
from netcontrol.mcp.settings import load_settings
from netcontrol.routes.shared import _audit
from netcontrol.telemetry import configure_logging
from netcontrol.version import APP_VERSION

LOGGER = configure_logging("plexus.mcp")

INSTRUCTIONS = (
    "Read-only access to the network data Plexus has collected: inventory, device configurations, "
    "compliance, monitoring, topology, software and traffic. Call plexus_overview first to see which "
    "data categories this token can use and when each source was last collected."
)

# Bad tokens from one address in a minute before it is answered 429.
FAILED_AUTH_LIMIT = 20

_caller: contextvars.ContextVar[McpContext | None] = contextvars.ContextVar("mcp_caller", default=None)


def _require_caller() -> McpContext:
    ctx = _caller.get()
    if ctx is None:  # the ASGI guard always sets it; refuse rather than guess
        raise RuntimeError("MCP request reached a handler without an authenticated caller")
    return ctx


async def _on_list_tools(_ctx: Any, _params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
    caller = _require_caller()
    return types.ListToolsResult(
        tools=[
            types.Tool(name=tool.name, description=tool.description, input_schema=tool.input_schema)
            for tool in registry.visible_tools(caller)
        ]
    )


async def _on_call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
    text, is_error = await call_tool(_require_caller(), params.name, params.arguments)
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=is_error)


def _tool_input_schema(name: str) -> Mapping[str, Any] | None:
    """Schema lookup for the SDK's header validation: nothing for a tool
    the caller cannot see."""
    caller, tool = _caller.get(), registry.get_tool(name)
    if caller is None or tool is None or not registry.is_visible(tool, caller):
        return None
    return tool.input_schema


def _build_server() -> Server[Any]:
    return Server(
        "plexus",
        version=APP_VERSION,
        title="Plexus",
        instructions=INSTRUCTIONS,
        get_tool_input_schema=_tool_input_schema,
        on_list_tools=_on_list_tools,
        on_call_tool=_on_call_tool,
    )


async def _respond(send: Send, status: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> None:
    payload = json.dumps(body).encode("utf-8")
    raw = [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())]
    raw += [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    await send({"type": "http.response.start", "status": status, "headers": raw})
    await send({"type": "http.response.body", "body": payload})


class McpEndpoint:
    """The guard in front of the SDK transport (pure ASGI, so the response
    is passed through as it is produced)."""

    def __init__(self) -> None:
        self._server = _build_server()
        self._manager: StreamableHTTPSessionManager | None = None

    @contextlib.asynccontextmanager
    async def run(self) -> AsyncIterator[None]:
        """Run the transport for the life of the app. A session manager
        runs once, so each start of the app gets a new one."""
        registry.load_tools()
        manager = StreamableHTTPSessionManager(
            app=self._server,
            json_response=True,
            stateless=True,
            security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        )
        async with manager.run():
            self._manager = manager
            try:
                yield
            finally:
                self._manager = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        path = scope.get("path", "")
        root = scope.get("root_path", "")
        if root and path.startswith(root):
            path = path[len(root) :]
        if path not in ("", "/", "/mcp"):
            await _respond(send, 404, {"error": "not_found"})
            return
        if not (await load_settings())["enabled"] or self._manager is None:
            await _respond(send, 404, {"error": "not_found"})
            return

        if scope.get("method") != "POST":
            # Stateless JSON mode has no server-to-client stream to open (GET)
            # and no session to end (DELETE).
            await _respond(send, 405, {"error": "method_not_allowed"}, {"Allow": "POST"})
            return

        headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers", [])}
        caller = await resolve_token(extract_bearer(headers.get("authorization", "")))
        if caller is None:
            client = scope.get("client")
            address = str(client[0]) if client else "unknown"
            throttled = rate_limited(f"mcp-auth-fail:{address}", FAILED_AUTH_LIMIT)
            if not rate_limited(f"mcp-auth-audit:{address}", 1):
                await _audit("mcp", "auth_failed", detail=f"address={address}")
            if throttled:
                await _respond(send, 429, {"error": "too_many_requests"}, {"Retry-After": "60"})
            else:
                await _respond(send, 401, {"error": "unauthorized"}, {"WWW-Authenticate": "Bearer"})
            return

        token = _caller.set(caller)
        try:
            # The transport serves one path; hand it the request at its root.
            inner = dict(scope, path="/", raw_path=b"/", root_path="")
            await self._manager.handle_request(inner, receive, send)
        finally:
            _caller.reset(token)


def build_mcp_app() -> tuple[ASGIApp, Callable[[], AbstractAsyncContextManager[None]]]:
    """The ASGI app to serve at ``/mcp`` and the context manager the host
    app's lifespan must enter (a mounted app's own lifespan never runs)."""
    endpoint = McpEndpoint()
    return endpoint, endpoint.run
