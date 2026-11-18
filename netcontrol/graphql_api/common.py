"""Helpers shared by the GraphQL type modules (``schema``, ``models``)."""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from decimal import Decimal
from typing import Any, cast

import strawberry
from strawberry.scalars import JSON
from strawberry.types import Info

from netcontrol.custom_fields import OBJECT_TYPE_SPECS, canonical_value
from netcontrol.graphql_api.context import GraphQLContext
from netcontrol.routes.custom_fields import can_read_type

# What a root list answers when the query gives no ``limit``.
DEFAULT_LIMIT = 100


def _ctx(info: Info) -> GraphQLContext:
    return info.context


def _text(row: dict, key: str) -> str:
    value = row.get(key)
    return "" if value is None else str(value)


def _opt_int(row: dict, key: str) -> int | None:
    value = row.get(key)
    return int(value) if value is not None and str(value).strip().lstrip("-").isdigit() else None


def _opt_text(value: Any) -> str | None:
    return None if value is None else str(value)


def _opt_float(value: Any) -> float | None:
    try:
        return None if value is None or value == "" else float(value)
    except TypeError, ValueError:
        return None


def _opt_number(value: Any) -> int | None:
    return _opt_int({"v": value}, "v")


def _text_list(value: Any) -> list[str]:
    return [str(v) for v in value] if isinstance(value, list | tuple) else []


# Annotation (as written, under ``from __future__ import annotations``) ->
# how a column value becomes that GraphQL scalar.
_COERCE: dict[str, Callable[[Any], Any]] = {
    "int": lambda v: int(v) if v is not None else 0,
    "int | None": _opt_number,
    "str": lambda v: "" if v is None else str(v),
    "str | None": _opt_text,
    "float": lambda v: float(v) if v is not None else 0.0,
    "float | None": _opt_float,
    "bool": bool,
    "list[str]": _text_list,
}


def make[T](cls: type[T], row: dict, **values: Any) -> T:
    """An instance of the strawberry type ``cls`` from a database ``row``:
    ``row`` goes to its private ``row`` field and every other declared
    attribute (the scalar allow-list) takes the column of the same name,
    coerced to the annotation; ``values`` override columns."""
    kwargs: dict[str, Any] = {}
    # The annotations as written (strawberry resolves ``field.type`` once the
    # schema is built).
    written = cls.__annotations__
    for field in dataclasses.fields(cls):  # type: ignore[arg-type]
        if not field.init:
            continue
        if field.name == "row":
            kwargs["row"] = row
        elif field.name in values:
            kwargs[field.name] = values[field.name]
        else:
            raw = row.get(field.name)
            if isinstance(raw, Decimal):
                raw = str(raw)
            kwargs[field.name] = _COERCE[str(written[field.name])](raw)
    return cls(**kwargs)


# ── Tags, custom fields and computed fields ──────────────────────────────────


@strawberry.type(description="A tag on an object.")
class Tag:
    id: int
    name: str
    color: str


@strawberry.type(description="A custom field value, as its canonical text.")
class CustomFieldValue:
    key: str
    value: str


def _field_text(value: Any) -> str:
    """A custom field value (typed by ``object_custom_data_bulk``) back as
    its canonical stored text."""
    if isinstance(value, bool):
        return canonical_value({"field_type": "boolean"}, value)
    if isinstance(value, int | float):
        return canonical_value({"field_type": "number"}, value)
    return "" if value is None else str(value)


@strawberry.type(description="An object with tags, custom fields and computed fields.")
class CustomData:
    """The tags, custom fields and computed fields of a type in
    ``netcontrol.custom_fields.OBJECT_TYPE_SPECS`` (``custom_type`` names
    it), batched per request (``GraphQLContext.custom_data``). The fields
    need the type's read feature (``can_read_type``) on top of the parent's
    gate."""

    row: strawberry.Private[dict]
    custom_type = ""

    def custom_row(self) -> dict:
        """The row as ``object_custom_data_bulk`` keys it (by ``id``)."""
        return self.row

    async def _custom_data(self, info: Info) -> dict:
        ctx = _ctx(info)
        spec = OBJECT_TYPE_SPECS[self.custom_type]
        if not can_read_type(ctx.features, spec):
            ctx.require(str(spec.read_feature))
        return await ctx.custom_data[self.custom_type].load(self.custom_row())

    @strawberry.field
    async def tags(self, info: Info) -> list[Tag]:
        data = await self._custom_data(info)
        return [Tag(id=int(t["id"]), name=str(t["name"]), color=str(t["color"])) for t in data["tags"]]

    @strawberry.field
    async def custom_fields(self, info: Info) -> list[CustomFieldValue]:
        data = await self._custom_data(info)
        return [CustomFieldValue(key=k, value=_field_text(v)) for k, v in data["custom_fields"].items()]

    @strawberry.field(description="The computed fields rendered for this object: {key: text}.")
    async def computed_fields(self, info: Info) -> JSON:
        return cast(JSON, dict((await self._custom_data(info))["computed_fields"]))
