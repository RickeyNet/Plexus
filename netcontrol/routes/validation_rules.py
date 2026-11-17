"""Data validation rules admin API: ``/api/validation-rules``.

Registered in ``app.py`` behind ``require_admin``. Manage the rules, test a
value against a rule (saved or not yet saved), and list the stored objects
that break the enabled rules ("Check existing data"). Rule logic and
enforcement live in ``netcontrol.data_validation``; see
``docs/validation-rules.md``.
"""

from __future__ import annotations

from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from netcontrol.data_validation import (
    OBJECT_TYPES,
    RULE_TYPES,
    RuleError,
    check_value,
    clean_params,
    clean_rule,
    find_violations,
    invalidate_rules_cache,
    rule_fields,
)
from netcontrol.object_scope import request_scope
from netcontrol.routes.shared import _audit, _corr_id, _session_user

router = APIRouter()

PREFIX = "/api/validation-rules"
_RAW_MAX = 2000


class RuleBody(BaseModel):
    name: str = Field(max_length=_RAW_MAX)
    object_type: str = Field(max_length=50)
    field: str = Field(max_length=200)
    rule_type: str = Field(max_length=50)
    params: dict[str, Any] = Field(default_factory=dict)
    error_message: str = Field(default="", max_length=_RAW_MAX)
    description: str = Field(default="", max_length=_RAW_MAX)
    enabled: bool = True


class RuleUpdate(BaseModel):
    """Every property; one left out keeps its value."""

    name: str | None = Field(default=None, max_length=_RAW_MAX)
    object_type: str | None = Field(default=None, max_length=50)
    field: str | None = Field(default=None, max_length=200)
    rule_type: str | None = Field(default=None, max_length=50)
    params: dict[str, Any] | None = None
    error_message: str | None = Field(default=None, max_length=_RAW_MAX)
    description: str | None = Field(default=None, max_length=_RAW_MAX)
    enabled: bool | None = None


class RuleTest(BaseModel):
    """A saved rule (``rule_id``) or an unsaved definition (``rule_type``,
    ``params`` and optionally ``field`` and ``error_message``), and the
    value to check."""

    rule_id: int | None = None
    rule_type: str | None = Field(default=None, max_length=50)
    params: dict[str, Any] = Field(default_factory=dict)
    field: str = Field(default="value", max_length=200)
    error_message: str = Field(default="", max_length=_RAW_MAX)
    value: Any = None


def _invalid(exc: RuleError) -> HTTPException:
    """422 with the message and one message per rule property, the shape of
    ``custom_fields._invalid``."""
    return HTTPException(status_code=422, detail={"message": exc.message, "fields": exc.fields})


async def _rule_or_404(rule_id: int) -> dict:
    rule = await db.get_validation_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Validation rule not found")
    return rule


async def _audit_write(request: Request, action: str, detail: str) -> None:
    await _audit(
        "validation_rules", action, user=_session_user(request), detail=detail, correlation_id=_corr_id(request)
    )


def _object_type(value: str | None) -> str | None:
    if value is not None and value not in OBJECT_TYPES:
        raise HTTPException(status_code=400, detail=f"object_type must be one of: {', '.join(OBJECT_TYPES)}")
    return value


@router.get(PREFIX)
async def list_rules(object_type: str | None = Query(default=None, max_length=50)) -> dict:
    return {"rules": await db.list_validation_rules(_object_type(object_type))}


@router.get(f"{PREFIX}/fields")
async def list_rule_fields() -> dict:
    """The object types, rule types and the fields a rule may check on each
    object type (custom fields included)."""
    return {
        "object_types": list(OBJECT_TYPES),
        "rule_types": list(RULE_TYPES),
        "fields": {t: await rule_fields(t) for t in OBJECT_TYPES},
    }


@router.get(f"{PREFIX}/violations")
async def list_violations(request: Request, object_type: str | None = Query(default=None, max_length=50)) -> dict:
    """The stored objects that break enabled rules ("Check existing data")."""
    return await find_violations(await request_scope(request), _object_type(object_type))


@router.post(f"{PREFIX}/test")
async def test_rule(body: RuleTest) -> dict:
    """Check ``value`` against a rule: ``{"valid", "message"}``."""
    if body.rule_id is not None:
        rule = await _rule_or_404(body.rule_id)
    else:
        try:
            params = clean_params(body.rule_type or "", body.params)
        except RuleError as exc:
            raise _invalid(exc) from None
        rule = {
            "name": "test",
            "field": body.field.strip() or "value",
            "rule_type": body.rule_type,
            "params": params,
            "error_message": body.error_message.strip(),
        }
    message = check_value(rule, body.value)
    return {"valid": message is None, "message": message}


@router.get(f"{PREFIX}/{{rule_id}}")
async def get_rule(rule_id: int) -> dict:
    return await _rule_or_404(rule_id)


@router.post(PREFIX, status_code=201)
async def create_rule(body: RuleBody, request: Request) -> dict:
    try:
        clean = await clean_rule(body.model_dump())
    except RuleError as exc:
        raise _invalid(exc) from None
    try:
        rule = await db.create_validation_rule(clean, _session_user(request))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    invalidate_rules_cache()
    await _audit_write(
        request, "rule_create", f"id={rule['id']} name={rule['name']} {rule['object_type']}.{rule['field']}"
    )
    return rule


@router.put(f"{PREFIX}/{{rule_id}}")
async def update_rule(rule_id: int, body: RuleUpdate, request: Request) -> dict:
    current = await _rule_or_404(rule_id)
    sent = body.model_dump(exclude_unset=True, exclude_none=True)
    try:
        clean = await clean_rule({**current, **sent}, current=current)
    except RuleError as exc:
        raise _invalid(exc) from None
    try:
        rule = await db.update_validation_rule(rule_id, clean, _session_user(request))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if rule is None:
        raise HTTPException(status_code=404, detail="Validation rule not found")
    invalidate_rules_cache()
    await _audit_write(request, "rule_update", f"id={rule_id} name={rule['name']} enabled={rule['enabled']}")
    return rule


@router.delete(f"{PREFIX}/{{rule_id}}")
async def delete_rule(rule_id: int, request: Request) -> dict:
    rule = await _rule_or_404(rule_id)
    await db.delete_validation_rule(rule_id)
    invalidate_rules_cache()
    await _audit_write(request, "rule_delete", f"id={rule_id} name={rule['name']}")
    return {"ok": True}
