"""GraphQL cost estimate and result-size limits (SECURITY_AUDIT finding 12 /
INB-3): nested lists without a limit are priced at what the resolver
returns (``max_limit``), variable defaults are seen, the resolvers cap
those lists at ``max_limit``, a hard cap on resolved list items backs the
estimate, and the documented example queries still fit the budget."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import routes.database as db
from graphql import parse
from netcontrol.graphql_api import limits
from netcontrol.graphql_api.context import GraphQLClientError, GraphQLContext
from netcontrol.graphql_api.schema import schema
from netcontrol.graphql_api.settings import DEFAULTS
from netcontrol.object_scope import UNRESTRICTED

from test_graphql_api import _gql, admin, world  # noqa: F401 - shared fixtures

DOCS = Path(__file__).resolve().parent.parent / "docs" / "graphql-api.md"
BUDGET = DEFAULTS["max_complexity"]

# The audit's query: hosts -> group -> hosts ... at depth 8, no aliases.
ALTERNATING = "{ groups(limit:1){ hosts{ group{ hosts{ group{ hosts{ group{ hosts{ id }}}}}}}}}"


def _cost(query: str, variables: dict | None = None, max_limit: int = DEFAULTS["max_limit"]) -> tuple[int, bool]:
    return limits.estimate_cost(schema._schema, parse(query), variables, BUDGET, max_limit)


def _errors(query: str, variables: dict | None = None) -> list[str]:
    settings = {**DEFAULTS, "introspection": True}
    return [e.message for e in limits.check_document(schema._schema, query, variables, settings)]


# ── Estimator ────────────────────────────────────────────────────────────────


def test_alternating_nested_lists_are_over_budget():
    assert _cost(ALTERNATING)[1] is True
    assert any("too complex" in m for m in _errors(ALTERNATING))


def test_nested_list_without_limit_is_priced_at_max_limit():
    q = "{ groups(limit: 2) { hosts { id } } }"
    assert _cost(q) == (2 + 2 * DEFAULTS["max_limit"], False)
    assert _cost(q, max_limit=50) == (2 + 2 * 50, False)
    # Lists that take no limit argument keep the fixed estimate.
    assert _cost("{ hosts(limit: 3) { interfaces { name } } }") == (3 + 3 * limits.UNBOUNDED_LIST_ESTIMATE, False)


def test_variable_default_limit_is_priced():
    q = "query($n: Int = 1000) { groups(limit: 1) { hosts(limit: $n) { group { hosts(limit: $n) { id } } } } }"
    assert _cost(q)[1] is True
    assert any("too complex" in m for m in _errors(q))
    small = "query($n: Int = 40) { groups(limit: 2) { hosts(limit: $n) { id } } }"
    assert _cost(small) == (2 + 2 * 40, False)
    # A value the request gives wins over the default.
    assert _cost(small, {"n": 3}) == (2 + 2 * 3, False)
    # A variable with no default and no value: the field's own default (none
    # for a nested list, so max_limit).
    assert _cost("query($n: Int) { groups(limit: 2) { hosts(limit: $n) { id } } }") == (
        2 + 2 * DEFAULTS["max_limit"],
        False,
    )


def test_documented_queries_fit_the_budget():
    text = DOCS.read_text(encoding="utf-8")
    queries = re.findall(r"```graphql\n(.*?)```", text, re.S)
    assert queries
    for query in queries:
        assert _errors(query) == [], query
    assert _errors('{ deviceRoles(name: "core") { hosts(limit: 100) { hostname } } }') == []


def test_nested_limit_arguments_describe_the_cap():
    arg = schema._schema.get_type("Group").fields["hosts"].args["limit"]
    assert "max_limit" in (arg.description or "")


# ── Resolvers ────────────────────────────────────────────────────────────────


def test_page_without_limit_returns_at_most_max_limit():
    ctx = GraphQLContext(scope=UNRESTRICTED, features=None, max_limit=10)
    rows = list(range(25))
    assert ctx.page(rows, None, 0, bounded=False) == list(range(10))
    assert ctx.page(rows, None, 20, bounded=False) == list(range(20, 25))


def test_object_cap_stops_resolution():
    ctx = GraphQLContext(scope=UNRESTRICTED, features=None, max_limit=1000, max_objects=5)
    ctx.count_objects(5)
    try:
        ctx.count_objects(1)
    except GraphQLClientError as exc:
        assert "too large" in str(exc)
    else:  # pragma: no cover - the cap must raise
        raise AssertionError("count_objects did not raise past max_objects")
    assert limits.max_objects(DEFAULTS) == BUDGET * limits.RESULT_OBJECTS_PER_COST


def _run(query: str, ctx: GraphQLContext):
    return asyncio.run(schema.execute(query, context_value=ctx))


def test_object_cap_fails_an_executing_query(world):  # noqa: F811
    query = "{ groups(limit: 10) { name hosts { hostname } } }"
    ok = _run(query, GraphQLContext(scope=UNRESTRICTED, features=None, max_limit=1000, max_objects=1000))
    assert ok.errors is None
    assert sum(len(g["hosts"]) for g in ok.data["groups"]) > 2

    capped = _run(query, GraphQLContext(scope=UNRESTRICTED, features=None, max_limit=1000, max_objects=2))
    assert capped.errors
    assert any("too large" in e.message for e in capped.errors)


def test_dynamic_group_members_read_hosts_once(world, monkeypatch):  # noqa: F811
    async def seed() -> None:
        for i in range(3):
            await db.create_dynamic_group(name=f"dg-{i}", description="", filter_def={"search": {"value": "edge"}})

    asyncio.run(seed())
    calls = 0
    real = db.get_all_hosts

    async def counting(*args, **kwargs):
        nonlocal calls
        calls += 1
        return await real(*args, **kwargs)

    monkeypatch.setattr(db, "get_all_hosts", counting)
    query = "{ dynamicGroups(limit: 10) { name members { hostname } again: members { hostname } } }"
    result = _run(query, GraphQLContext(scope=UNRESTRICTED, features=None, max_limit=1000, max_objects=1000))
    assert result.errors is None, result.errors
    assert [len(g["members"]) for g in result.data["dynamicGroups"]] == [2, 2, 2]
    assert calls == 1


def test_http_refuses_the_alternating_query(admin, world):  # noqa: F811
    body = _gql(admin, ALTERNATING, status=400)
    assert "too complex" in body["errors"][0]["message"]
