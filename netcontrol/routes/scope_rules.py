"""Object scope rules of access groups (admin only).

A scope rule extends an access group whose ``object_scope`` is ``groups``
beyond its inventory groups: the records of one model of the object scope
registry (``netcontrol.object_scope.MODELS``; ``*`` for every model) whose
tenant or site is the given one, read only or read and write. Rules of an
``all`` access group are kept but do not apply (its members are
unrestricted).

``router`` is registered in ``app.py`` behind ``require_admin``:

- ``GET /api/admin/object-scope/models`` - the registry (name, key
  attributes, shared, which rule attributes apply).
- ``GET /api/admin/access-groups/{group_id}/scope-rules`` - the rules.
- ``PUT /api/admin/access-groups/{group_id}/scope-rules`` - replace them
  (``{"rules": [{"model", "attribute", "value_id", "can_write"}]}``).

Errors: 404 unknown access group, 400 an unknown model, an attribute the
model has no key for, or an unknown tenant or site. Changes are audited
(category ``auth``, ``access_group.scope_rules``). Storage:
``routes.db.object_scope``; docs: ``docs/object-permissions.md``.
"""

from __future__ import annotations

import routes.database as db
import routes.db.object_scope as scope_db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from netcontrol import object_scope
from netcontrol.routes.shared import _audit, _corr_id, _session_user

router = APIRouter()

_MAX_RULES = 500


class ScopeRuleBody(BaseModel):
    model: str = Field(min_length=1, max_length=64)
    attribute: str = Field(min_length=1, max_length=16)
    value_id: int = Field(ge=1)
    can_write: bool = False


class ScopeRulesBody(BaseModel):
    rules: list[ScopeRuleBody] = Field(default_factory=list, max_length=_MAX_RULES)


def _validate(rule: ScopeRuleBody) -> dict:
    model = rule.model.strip()
    attribute = rule.attribute.strip().lower()
    if attribute not in scope_db.SCOPE_RULE_ATTRIBUTES:
        raise HTTPException(status_code=400, detail="attribute must be 'tenant' or 'site'")
    if model != "*":
        spec = object_scope.MODELS.get(model)
        if spec is None:
            raise HTTPException(status_code=400, detail=f"Unknown object scope model: {model}")
        if attribute not in spec.keys:
            raise HTTPException(status_code=400, detail=f"Model {model} has no {attribute} to filter on")
    return {"model": model, "attribute": attribute, "value_id": rule.value_id, "can_write": rule.can_write}


async def _require_access_group(group_id: int) -> dict:
    group = await db.get_access_group(int(group_id))
    if not group:
        raise HTTPException(status_code=404, detail="Access group not found")
    return group


@router.get("/api/admin/object-scope/models")
async def list_object_scope_models():
    return object_scope.model_catalog()


@router.get("/api/admin/access-groups/{group_id}/scope-rules")
async def get_access_group_scope_rules(group_id: int):
    await _require_access_group(group_id)
    return await scope_db.get_access_group_scope_rules(group_id)


@router.put("/api/admin/access-groups/{group_id}/scope-rules")
async def put_access_group_scope_rules(group_id: int, body: ScopeRulesBody, request: Request):
    group = await _require_access_group(group_id)
    rules = [_validate(r) for r in body.rules]
    try:
        saved = await scope_db.set_access_group_scope_rules(group_id, rules)
    except ValueError:
        # Attributes and the access group are checked above: what is left is
        # a tenant or site id that does not exist.
        raise HTTPException(status_code=400, detail="Unknown tenant or site in scope rules") from None
    summary = ",".join(
        f"{r['model']}:{r['attribute']}={r['value_id']}:{'rw' if r['can_write'] else 'r'}" for r in saved
    )
    await _audit(
        "auth",
        "access_group.scope_rules",
        user=_session_user(request),
        detail=f"access group id={group_id} '{group['name']}' scope_rules=[{summary}]",
        correlation_id=_corr_id(request),
    )
    return saved
