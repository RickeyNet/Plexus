"""HTTP routes of the read-only GraphQL API.

``router`` (registered with the ``graphql`` feature gate):

* ``POST /api/graphql``: runs a query (``{"query", "variables",
  "operationName"}``). Queries only: a mutation or subscription is refused.
  Session callers send the CSRF header like every other POST; the server API
  token (``X-API-Token`` / Bearer) needs none.
* ``GET /api/graphql``: the GraphiQL page when the ``graphiql`` setting is
  on, else 404. A GET never runs a query.

``admin_router`` (admin only): ``GET/PUT /api/admin/graphql/settings``.

What a query may read is decided per field (``netcontrol.graphql_api``):
the features of the REST routes and the caller's object scope.
"""

from __future__ import annotations

import json
import re
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from graphql import GraphQLError
from strawberry.types.graphql import OperationType

from netcontrol.csp import script_hash_source
from netcontrol.graphql_api import limits, settings as graphql_settings
from netcontrol.graphql_api.context import GraphQLContext
from netcontrol.graphql_api.schema import schema
from netcontrol.object_scope import graphql_features, request_scope, scoped
from netcontrol.routes.shared import _audit, _corr_id, _session_user, caller_features

router = APIRouter()
admin_router = APIRouter(prefix="/api/admin/graphql")

GRAPHQL_PATH = "/api/graphql"


def _errors(errors: list[GraphQLError], status: int = 400) -> JSONResponse:
    return JSONResponse({"data": None, "errors": [e.formatted for e in errors]}, status_code=status)


@router.post(GRAPHQL_PATH)
@scoped("graphql")
async def graphql_query(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except ValueError:
        return _errors([GraphQLError("The body must be JSON")])
    if not isinstance(body, dict):
        return _errors([GraphQLError("The body must be a JSON object")])
    query = body.get("query")
    variables = body.get("variables")
    operation_name = body.get("operationName")
    if not isinstance(query, str) or not query.strip():
        return _errors([GraphQLError("query must be a non-empty string")])
    if variables is not None and not isinstance(variables, dict):
        return _errors([GraphQLError("variables must be an object")])
    if operation_name is not None and not isinstance(operation_name, str):
        return _errors([GraphQLError("operationName must be a string")])

    config = await graphql_settings.load_settings()
    problems = limits.check_document(schema._schema, query, variables, config, operation_name)
    if problems:
        return _errors(problems)

    scope = await request_scope(request)
    context = GraphQLContext(
        scope=scope,
        # A scoped caller keeps only the features whose resolvers filter by scope.
        features=graphql_features(await caller_features(request), scope),
        max_limit=int(config["max_limit"]),
        max_objects=limits.max_objects(config),
    )
    result = await schema.execute(
        query,
        variable_values=variables,
        context_value=context,
        operation_name=operation_name,
        allowed_operation_types=(OperationType.QUERY,),
    )
    payload: dict[str, Any] = {"data": result.data}
    if result.errors:
        payload["errors"] = [e.formatted for e in result.errors]
    # A request error (unknown operation, bad variables) leaves no data and
    # has no path; a field error keeps the rest of the data (200).
    request_error = bool(result.errors) and result.data is None and all(e.path is None for e in result.errors or [])
    status = 400 if request_error else 200
    return JSONResponse(payload, status_code=status)


# ── GraphiQL ─────────────────────────────────────────────────────────────────

# Pinned with Subresource Integrity (the versions and hashes strawberry's own
# GraphiQL page uses). The inline script reads the CSRF token from
# /api/auth/status and sends it on every query.
_GRAPHIQL_SCRIPT = """
(async function () {
  let csrf = "";
  try {
    const status = await fetch("/api/auth/status", { credentials: "same-origin" });
    csrf = (await status.json()).csrf_token || "";
  } catch (e) {}
  const fetcher = GraphiQL.createFetcher({ url: "/api/graphql", headers: { "X-CSRF-Token": csrf } });
  ReactDOM.createRoot(document.getElementById("graphiql")).render(
    React.createElement(GraphiQL, { fetcher: fetcher, defaultEditorToolsVisibility: true })
  );
})();
"""
_GRAPHIQL_HTML = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Plexus GraphQL</title>
<style>body {{ margin: 0; height: 100vh; }} #graphiql {{ height: 100vh; }}</style>
<link rel="stylesheet" crossorigin href="https://unpkg.com/graphiql@3.8.3/graphiql.min.css"
  integrity="sha384-Mq3vbRBY71jfjQAt/DcjxUIYY33ksal4cgdRt9U/hNPvHBCaT2JfJ/PTRiPKf0aM">
</head>
<body>
<div id="graphiql">Loading...</div>
<script crossorigin src="https://unpkg.com/react@18.2.0/umd/react.production.min.js"
  integrity="sha384-tMH8h3BGESGckSAVGZ82T9n90ztNXxvdwvdM6UoR56cYcf+0iGXBliJ29D+wZ/x8"></script>
<script crossorigin src="https://unpkg.com/react-dom@18.2.0/umd/react-dom.production.min.js"
  integrity="sha384-bm7MnzvK++ykSwVJ2tynSE5TRdN+xL418osEVF2DE/L/gfWHj91J2Sphe582B1Bh"></script>
<script crossorigin src="https://unpkg.com/graphiql@3.8.3/graphiql.min.js"
  integrity="sha384-HbRVEFG0JGJZeAHCJ9Xm2+tpknBQ7QZmNlO/DgZtkZ0aJSypT96YYGRNod99l9Ie"></script>
<script>{_GRAPHIQL_SCRIPT}</script>
</body>
</html>
"""
_GRAPHIQL_CSP = re.sub(
    r"\s+",
    " ",
    f"""default-src 'none';
    script-src https://unpkg.com {script_hash_source(_GRAPHIQL_SCRIPT)};
    style-src https://unpkg.com 'unsafe-inline';
    img-src 'self' data:;
    font-src https://unpkg.com data:;
    connect-src 'self';
    frame-ancestors 'none';
    base-uri 'none';
    form-action 'none'""",
)


@router.get(GRAPHQL_PATH)
@scoped("graphql")
async def graphiql_page() -> HTMLResponse:
    if not (await graphql_settings.load_settings())["graphiql"]:
        raise HTTPException(status_code=404, detail="Not found")
    return HTMLResponse(
        _GRAPHIQL_HTML,
        headers={"Content-Security-Policy": _GRAPHIQL_CSP, "Cache-Control": "no-store"},
    )


# ── Admin settings ───────────────────────────────────────────────────────────


@admin_router.get("/settings")
async def get_settings() -> dict[str, Any]:
    return await graphql_settings.load_settings()


@admin_router.put("/settings")
async def update_settings(body: dict[str, Any], request: Request) -> dict[str, Any]:
    try:
        merged = await graphql_settings.save_settings(body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await _audit(
        "graphql",
        "settings_update",
        user=_session_user(request),
        detail=json.dumps({key: merged[key] for key in sorted(body)}, sort_keys=True),
        correlation_id=_corr_id(request),
    )
    return merged
