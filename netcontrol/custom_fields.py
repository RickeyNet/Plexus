"""Custom fields and tags: the constants and value rules, with no I/O.

Values are stored as canonical text (``custom_field_values.value``) so that
equality filters compare like with like whatever the field type:

=========  ==================================  ==============================
Type       Stored form                         Accepted input
=========  ==================================  ==============================
text       as entered, trimmed                 at most ``TEXT_MAX`` characters
number     decimal string, no trailing zeros   any finite number
boolean    ``true`` or ``false``               bool, true/false, yes/no, 1/0
date       ``YYYY-MM-DD``                      a real calendar date
url        as entered, trimmed                 ``http``/``https`` with a host
select     one of the field's choices          a string in ``choices``
=========  ==================================  ==============================

An empty value (``None`` or blank text) canonicalises to ``""``, which the
storage layer treats as "no value" and never stores.

Used by the API (``netcontrol.routes.custom_fields``) and by tests directly.
"""

from __future__ import annotations

import re
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Literal, get_args
from urllib.parse import urlsplit

# The Literal types are what request bodies validate against; the tuples are
# derived from them so each set is written once.
ObjectType = Literal["host", "group", "prefix"]
FieldType = Literal["text", "number", "boolean", "date", "url", "select"]
TagColor = Literal["gray", "red", "orange", "yellow", "green", "teal", "blue", "purple"]
OBJECT_TYPES: tuple[str, ...] = get_args(ObjectType)
FIELD_TYPES: tuple[str, ...] = get_args(FieldType)
TAG_COLORS: tuple[str, ...] = get_args(TagColor)
FIELD_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,49}$")
TEXT_MAX = 1000
TAG_NAME_MAX = 50

_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_TRUE = {"true", "yes", "1"}
_FALSE = {"false", "no", "0"}


class CustomFieldError(ValueError):
    """A value a field does not accept. The message names the field."""


def _label(field: dict) -> str:
    return str(field.get("label") or field.get("key") or "Field")


def _number(raw: object) -> str | None:
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        return None
    try:
        value = Decimal(str(raw).strip())
    except InvalidOperation:
        return None
    if not value.is_finite():
        return None
    if value == 0:
        return "0"
    return format(value.normalize(), "f")


def _boolean(raw: object) -> str | None:
    if isinstance(raw, bool):
        return "true" if raw else "false"
    text = str(raw).strip().lower() if isinstance(raw, (int, str)) else ""
    if text in _TRUE:
        return "true"
    if text in _FALSE:
        return "false"
    return None


def _date(text: str) -> bool:
    if not _DATE_RE.fullmatch(text):
        return False
    try:
        date.fromisoformat(text)
    except ValueError:
        return False
    return True


def _url(text: str) -> bool:
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return False
    return parts.scheme.lower() in ("http", "https") and bool(host)


def canonical_value(field: dict, raw: object) -> str:
    """The stored text for ``raw`` in ``field``; ``""`` for no value.

    ``field`` needs ``field_type`` and, for ``select``, ``choices``; its
    ``label`` (or ``key``) starts every error message.
    """
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return ""
    label = _label(field)
    field_type = field.get("field_type")

    if field_type == "number":
        number = _number(raw)
        if number is None:
            raise CustomFieldError(f"{label} must be a number.")
        return number
    if field_type == "boolean":
        flag = _boolean(raw)
        if flag is None:
            raise CustomFieldError(f"{label} must be true or false.")
        return flag

    if not isinstance(raw, str):
        raise CustomFieldError(f"{label} must be text.")
    text = raw.strip()
    if field_type in ("text", "url") and len(text) > TEXT_MAX:
        raise CustomFieldError(f"{label} must be at most {TEXT_MAX} characters.")
    if field_type == "text":
        return text
    if field_type == "date":
        if not _date(text):
            raise CustomFieldError(f"{label} must be a date in the form YYYY-MM-DD.")
        return text
    if field_type == "url":
        if not _url(text):
            raise CustomFieldError(f"{label} must be an http or https URL with a host.")
        return text
    if field_type == "select":
        choices = [str(c) for c in field.get("choices") or []]
        if text not in choices:
            raise CustomFieldError(f"{label} must be one of: {', '.join(choices)}.")
        return text
    raise CustomFieldError(f"{label} has an unknown type '{field_type}'.")


def typed_value(field_type: str, stored: str) -> str | int | float | bool:
    """A stored value as JSON wants it: numbers and booleans typed, the rest
    text. A stored value that no longer parses comes back as text."""
    if field_type == "boolean":
        return stored == "true"
    if field_type == "number":
        try:
            return int(stored) if re.fullmatch(r"-?\d+", stored) else float(stored)
        except ValueError:
            return stored
    return stored


def clean_name(raw: object, label: str, limit: int) -> str:
    """A name trimmed; 1 to ``limit`` characters. ``label`` starts the error
    message (``"Tag name"``)."""
    name = raw.strip() if isinstance(raw, str) else ""
    if not name:
        raise CustomFieldError(f"{label} must not be empty.")
    if len(name) > limit:
        raise CustomFieldError(f"{label} must be at most {limit} characters.")
    return name


def clean_tag_name(raw: object) -> str:
    """A tag name trimmed; 1 to ``TAG_NAME_MAX`` characters."""
    return clean_name(raw, "Tag name", TAG_NAME_MAX)
