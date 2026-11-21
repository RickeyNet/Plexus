"""Query limits checked before a GraphQL query runs.

``check_document`` parses the query, runs the standard GraphQL validation
and then the limits of the ``graphql_api`` setting: maximum depth, maximum
aliases, maximum estimated cost and, unless the setting allows it, no
introspection. The depth and alias rules are strawberry's; the cost rule is
``estimate_cost``:

* every object a query resolves costs 1 (scalar fields of an object are
  free), each time it is resolved;
* a list field resolves as many objects as its ``limit`` argument when the
  query gives one (a literal, a variable's value, or the variable's default
  in the operation), else the argument's default when it has a number, else
  ``max_limit`` (a nested list with no limit returns at most ``max_limit``
  rows: ``GraphQLContext.page``), and multiplies what is selected under it;
* a list with no ``limit`` argument at all (a host's interfaces, tags,
  ports ...) is assumed to hold ``UNBOUNDED_LIST_ESTIMATE`` objects. Such
  lists hold one parent's own rows; the execution-time cap on resolved
  objects (``GraphQLContext.count_objects``) backs the estimate for them.

* a field in ``FIELD_WEIGHTS`` costs its weight per object instead of 1
  (rows that take extra reads to build, such as cables with both ends
  described).

So ``groups(limit: 100) { hosts(limit: 50) { id } }`` costs
100 + 100 * 50 = 5,100, ``groups(limit: 100) { hosts { id } }`` costs
100 + 100 * 1,000 with the default ``max_limit``, and
``cables(limit: 100) { id }`` costs 200.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from inspect import isawaitable
from typing import Any

from graphql import (
    DocumentNode,
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    GraphQLError,
    GraphQLNamedType,
    GraphQLObjectType,
    GraphQLResolveInfo,
    GraphQLSchema,
    InlineFragmentNode,
    IntValueNode,
    OperationDefinitionNode,
    SelectionSetNode,
    VariableNode,
    get_named_type,
    get_nullable_type,
    is_list_type,
    parse,
    specified_rules,
    validate,
)
from graphql.validation import NoSchemaIntrospectionCustomRule, ValidationContext, ValidationRule
from strawberry.extensions import SchemaExtension
from strawberry.extensions.max_aliases import create_validator as alias_validator
from strawberry.extensions.query_depth_limiter import create_validator as depth_validator

from netcontrol.graphql_api.settings import DEFAULTS

# Longest query text accepted, in characters.
MAX_QUERY_CHARS = 20_000
# What a list field with no ``limit`` argument is assumed to hold.
UNBOUNDED_LIST_ESTIMATE = 10
# ``Type.field`` -> what each object it resolves costs (default 1): cables
# (both ends described), circuits (with their terminations) and support
# contracts (with the hosts they cover).
FIELD_WEIGHTS: dict[str, int] = {
    "Query.cables": 2,
    "Host.cables": 2,
    "Query.circuits": 2,
    "Site.circuits": 2,
    "Tenant.circuits": 2,
    "CircuitProvider.circuits": 2,
    "CircuitType.circuits": 2,
    "Query.supportContracts": 2,
    "Host.supportContracts": 2,
}


class _OverBudget(Exception):
    pass


def _list_size(
    node: FieldNode,
    default: Any,
    variables: Mapping[str, Any],
    var_defaults: Mapping[str, Any],
    max_limit: int,
) -> int:
    """The rows a list field with a ``limit`` argument may return: the
    query's limit (a literal, else the variable's value, else the variable's
    default in the operation), else the argument's default, else
    ``max_limit`` (what ``GraphQLContext.page`` returns with no limit)."""
    for arg in node.arguments or ():
        if arg.name.value != "limit":
            continue
        value: Any = arg.value
        if isinstance(value, VariableNode):
            name = value.name.value
            value = variables[name] if name in variables else var_defaults.get(name)
        if isinstance(value, IntValueNode):
            return max(1, int(value.value))
        if isinstance(value, int) and not isinstance(value, bool):
            return max(1, value)
    if isinstance(default, int) and not isinstance(default, bool):
        return max(1, default)
    return max_limit


class _Estimator:
    def __init__(
        self,
        schema: GraphQLSchema,
        fragments: dict[str, FragmentDefinitionNode],
        variables: Mapping[str, Any],
        budget: int,
        max_limit: int,
        var_defaults: Mapping[str, Any],
    ) -> None:
        self.schema, self.fragments, self.variables, self.budget = schema, fragments, variables, budget
        self.max_limit, self.var_defaults = max_limit, var_defaults
        self.total = 0

    def _add(self, cost: int) -> None:
        self.total += cost
        if self.total > self.budget:
            raise _OverBudget

    def walk(
        self, selections: SelectionSetNode, parent: GraphQLNamedType | None, mult: int, seen: frozenset[str]
    ) -> None:
        for sel in selections.selections:
            if isinstance(sel, FieldNode):
                self._field(sel, parent, mult, seen)
            elif isinstance(sel, InlineFragmentNode):
                cond = self.schema.get_type(sel.type_condition.name.value) if sel.type_condition else parent
                self.walk(sel.selection_set, cond, mult, seen)
            elif isinstance(sel, FragmentSpreadNode):
                name = sel.name.value
                fragment = self.fragments.get(name)
                if fragment is None or name in seen:
                    continue
                cond = self.schema.get_type(fragment.type_condition.name.value)
                self.walk(fragment.selection_set, cond, mult, seen | {name})

    def _field(self, node: FieldNode, parent: GraphQLNamedType | None, mult: int, seen: frozenset[str]) -> None:
        if node.selection_set is None:
            return  # a scalar of a row already counted
        if node.name.value.startswith("__") or not isinstance(parent, GraphQLObjectType):
            self._add(mult)
            return
        field = parent.fields.get(node.name.value)
        if field is None:
            return
        child = mult
        if is_list_type(get_nullable_type(field.type)):
            limit_arg = field.args.get("limit")
            if limit_arg is None:
                child = mult * UNBOUNDED_LIST_ESTIMATE
            else:
                size = _list_size(node, limit_arg.default_value, self.variables, self.var_defaults, self.max_limit)
                child = mult * size
        self._add(child * FIELD_WEIGHTS.get(f"{parent.name}.{node.name.value}", 1))
        self.walk(node.selection_set, get_named_type(field.type), child, seen)


def estimate_cost(
    schema: GraphQLSchema,
    document: DocumentNode,
    variables: Mapping[str, Any] | None,
    budget: int,
    max_limit: int = DEFAULTS["max_limit"],
) -> tuple[int, bool]:
    """``(cost, over)``: the estimated cost of the costliest operation in
    ``document`` and whether it exceeds ``budget`` (the walk stops there).
    ``max_limit`` is what a list with a ``limit`` argument returns when the
    query gives none and the argument has no default."""
    fragments = {d.name.value: d for d in document.definitions if isinstance(d, FragmentDefinitionNode)}
    worst = 0
    for definition in document.definitions:
        if not isinstance(definition, OperationDefinitionNode):
            continue
        var_defaults = {
            v.variable.name.value: v.default_value
            for v in definition.variable_definitions or ()
            if v.default_value is not None
        }
        estimator = _Estimator(schema, fragments, variables or {}, budget, max_limit, var_defaults)
        root = schema.get_root_type(definition.operation)
        try:
            estimator.walk(definition.selection_set, root, 1, frozenset())
        except _OverBudget:
            return estimator.total, True
        worst = max(worst, estimator.total)
    return worst, False


def _cost_rule(budget: int, variables: Mapping[str, Any] | None, max_limit: int) -> type[ValidationRule]:
    class CostLimitRule(ValidationRule):
        def __init__(self, context: ValidationContext) -> None:
            super().__init__(context)
            cost, over = estimate_cost(context.schema, context.document, variables, budget, max_limit)
            if over:
                context.report_error(
                    GraphQLError(
                        f"Query is too complex: its estimated cost exceeds the limit of {budget} (see limit arguments)"
                    )
                )

    return CostLimitRule


def check_document(
    schema: GraphQLSchema,
    query: str,
    variables: Mapping[str, Any] | None,
    settings: Mapping[str, Any],
    operation_name: str | None = None,
) -> list[GraphQLError]:
    """The errors that stop ``query`` from running (``[]``: it may run)."""
    if len(query) > MAX_QUERY_CHARS:
        return [GraphQLError(f"Query is too long: at most {MAX_QUERY_CHARS} characters")]
    try:
        document = parse(query)
    except GraphQLError as exc:
        return [exc]
    errors = validate(schema, document, specified_rules)
    if errors:
        return list(errors)
    names = [d.name.value if d.name else None for d in document.definitions if isinstance(d, OperationDefinitionNode)]
    if operation_name is None and len(names) > 1:
        return [GraphQLError("Must provide operationName when the query has several operations")]
    if operation_name is not None and operation_name not in names:
        return [GraphQLError(f"Unknown operation named '{operation_name}'")]
    rules: list[type[ValidationRule]] = [
        depth_validator(int(settings["max_depth"]), None),
        alias_validator(int(settings["max_aliases"])),
        _cost_rule(int(settings["max_complexity"]), variables, int(settings["max_limit"])),
    ]
    if not settings.get("introspection"):
        rules.append(NoSchemaIntrospectionCustomRule)
    return list(validate(schema, document, rules))


# The resolved list items a query may produce, per unit of ``max_complexity``.
# Every object costs at least 1 in the estimate, so a query whose estimate
# is right stays under ``max_complexity`` objects; the factor leaves room
# for lists with no limit argument, which are only estimated.
RESULT_OBJECTS_PER_COST = 2


def max_objects(settings: Mapping[str, Any]) -> int:
    """The hard cap on list items one query may resolve (``ResultSizeLimit``)."""
    return int(settings["max_complexity"]) * RESULT_OBJECTS_PER_COST


class ResultSizeLimit(SchemaExtension):
    """Counts the items of every list a query resolves on the request's
    context (``GraphQLContext.count_objects``), which fails the query once
    the total passes the context's ``max_objects``: the hard backstop under
    ``estimate_cost``, so an estimate that is too low cannot turn into an
    exponentially large response."""

    def resolve(self, _next: Callable, root: Any, info: GraphQLResolveInfo, *args: Any, **kwargs: Any) -> Any:
        result = _next(root, info, *args, **kwargs)
        if not is_list_type(get_nullable_type(info.return_type)):
            return result
        count = getattr(info.context, "count_objects", None)
        if count is None:
            return result
        if isawaitable(result):

            async def counted() -> Any:
                value = await result
                if isinstance(value, list):
                    count(len(value))
                return value

            return counted()
        if isinstance(result, list):
            count(len(result))
        return result
