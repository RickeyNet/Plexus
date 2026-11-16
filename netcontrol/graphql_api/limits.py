"""Query limits checked before a GraphQL query runs.

``check_document`` parses the query, runs the standard GraphQL validation
and then the limits of the ``graphql_api`` setting: maximum depth, maximum
aliases, maximum estimated cost and, unless the setting allows it, no
introspection. The depth and alias rules are strawberry's; the cost rule is
``estimate_cost``:

* every object a query resolves costs 1 (scalar fields of an object are
  free), each time it is resolved;
* a list field resolves as many objects as its ``limit`` argument when the
  query gives one, else the argument's default when it has a number, else
  ``UNBOUNDED_LIST_ESTIMATE``, and multiplies what is selected under it.

So ``groups(limit: 100) { hosts(limit: 50) { id } }`` costs
100 + 100 * 50 = 5,100.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from graphql import (
    DocumentNode,
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    GraphQLError,
    GraphQLNamedType,
    GraphQLObjectType,
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
from strawberry.extensions.max_aliases import create_validator as alias_validator
from strawberry.extensions.query_depth_limiter import create_validator as depth_validator

# Longest query text accepted, in characters.
MAX_QUERY_CHARS = 20_000
# What a list without a numeric ``limit`` is assumed to hold.
UNBOUNDED_LIST_ESTIMATE = 10


class _OverBudget(Exception):
    pass


def _list_size(node: FieldNode, default: Any, variables: Mapping[str, Any]) -> int:
    for arg in node.arguments or ():
        if arg.name.value != "limit":
            continue
        value = arg.value
        if isinstance(value, IntValueNode):
            return max(1, int(value.value))
        if isinstance(value, VariableNode):
            given = variables.get(value.name.value)
            if isinstance(given, int) and not isinstance(given, bool):
                return max(1, given)
    if isinstance(default, int) and not isinstance(default, bool):
        return max(1, default)
    return UNBOUNDED_LIST_ESTIMATE


class _Estimator:
    def __init__(
        self,
        schema: GraphQLSchema,
        fragments: dict[str, FragmentDefinitionNode],
        variables: Mapping[str, Any],
        budget: int,
    ) -> None:
        self.schema, self.fragments, self.variables, self.budget = schema, fragments, variables, budget
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
            child = mult * _list_size(node, limit_arg.default_value if limit_arg else None, self.variables)
        self._add(child)
        self.walk(node.selection_set, get_named_type(field.type), child, seen)


def estimate_cost(
    schema: GraphQLSchema, document: DocumentNode, variables: Mapping[str, Any] | None, budget: int
) -> tuple[int, bool]:
    """``(cost, over)``: the estimated cost of the costliest operation in
    ``document`` and whether it exceeds ``budget`` (the walk stops there)."""
    fragments = {d.name.value: d for d in document.definitions if isinstance(d, FragmentDefinitionNode)}
    worst = 0
    for definition in document.definitions:
        if not isinstance(definition, OperationDefinitionNode):
            continue
        estimator = _Estimator(schema, fragments, variables or {}, budget)
        root = schema.get_root_type(definition.operation)
        try:
            estimator.walk(definition.selection_set, root, 1, frozenset())
        except _OverBudget:
            return estimator.total, True
        worst = max(worst, estimator.total)
    return worst, False


def _cost_rule(budget: int, variables: Mapping[str, Any] | None) -> type[ValidationRule]:
    class CostLimitRule(ValidationRule):
        def __init__(self, context: ValidationContext) -> None:
            super().__init__(context)
            cost, over = estimate_cost(context.schema, context.document, variables, budget)
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
        _cost_rule(int(settings["max_complexity"]), variables),
    ]
    if not settings.get("introspection"):
        rules.append(NoSchemaIntrospectionCustomRule)
    return list(validate(schema, document, rules))
