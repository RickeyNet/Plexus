"""Syslog alert rules API: ``/api/monitoring/syslog-rules``, and the
built-in SNMP trap rules: ``/api/monitoring/trap-rules`` (list, and the
``enabled`` / ``severity`` override of each; ``netcontrol.trap_rules``).

Registered in ``app.py`` with the monitoring routes' dependencies: reading
needs ``monitoring``, every write ``monitoring.write``. One merged list of
the built-in rules (only ``enabled`` and ``severity`` can be changed) and
the custom rules (full create, update, delete), and a test endpoint that
shows what a sample message would do. Rule logic and the engine live in
``netcontrol.syslog_rules``; see ``docs/syslog-rules.md``.

Object scope: the rules apply to every host and hold no host data. A
caller limited to selected inventory groups reads them but cannot change
them (like a global alert rule). The activity analysis (``/activity``,
``netcontrol.syslog_activity``) reads host messages: such a caller gets the
messages of their groups' hosts only, and none from unknown sources.
"""

from __future__ import annotations

from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from netcontrol import syslog_activity, syslog_rules as engine, trap_rules
from netcontrol.object_scope import group_filter, refuse_scoped, scope_exempt, scoped
from netcontrol.routes.shared import _audit, _corr_id, _session_user

router = APIRouter()

PREFIX = "/api/monitoring/syslog-rules"
_RULE_NOT_FOUND = "Syslog rule not found"
_MESSAGE_MAX = 4000


class BuiltinPatch(BaseModel):
    """A field left out keeps its value."""

    enabled: bool | None = None
    severity: str | None = Field(default=None, max_length=20)


class RuleTest(BaseModel):
    """A sample message and, optionally, an unsaved custom rule to try."""

    message: str = Field(max_length=_MESSAGE_MAX)
    rule: dict[str, Any] | None = None


def _bad(exc: engine.RuleError) -> HTTPException:
    return HTTPException(status_code=400, detail=exc.message)


async def _merged() -> list[engine.Rule]:
    engine.invalidate_rules_cache()
    return await engine.get_rules()


async def _payload(rule_key: str) -> dict:
    return next(r.payload() for r in await _merged() if r.key == rule_key)


@router.get(PREFIX)
@scope_exempt("Syslog alert rules apply to every host and hold no host data")
async def list_syslog_rules():
    return [r.payload() for r in await _merged()]


@router.get(PREFIX + "/activity")
@scoped("list")
async def syslog_rule_activity(request: Request, hours: int = Query(default=24, ge=1, le=168)):
    """What the rules matched in the syslog received in the last ``hours``
    and which messages no rule or trigger acted on."""
    return await syslog_activity.analyze(hours, **await group_filter(request))


@router.post(PREFIX, status_code=201)
@scoped("refused")
async def create_syslog_rule(body: dict, request: Request):
    await refuse_scoped(request)
    try:
        values = engine.clean_custom_rule(body)
    except engine.RuleError as exc:
        raise _bad(exc) from None
    user = _session_user(request)
    row = await db.create_syslog_alert_rule(values, user)
    engine.invalidate_rules_cache()
    await _audit(
        "monitoring",
        "syslog_rule.created",
        user=user,
        detail=f"rule_id={row['id']} name='{row['name']}' match_type={row['match_type']}",
        correlation_id=_corr_id(request),
    )
    return await _payload(engine.custom_rule_key(row["id"]))


@router.put(PREFIX + "/{rule_id}")
@scoped("refused")
async def update_syslog_rule(rule_id: int, body: dict, request: Request):
    await refuse_scoped(request)
    existing = await db.get_syslog_alert_rule(rule_id)
    if existing is None or existing["builtin_key"]:
        raise HTTPException(status_code=404, detail=_RULE_NOT_FOUND)
    try:
        values = engine.clean_custom_rule({**existing, **body})
    except engine.RuleError as exc:
        raise _bad(exc) from None
    row = await db.update_syslog_alert_rule(rule_id, values)
    engine.invalidate_rules_cache()
    if row is None:  # pragma: no cover - deleted between the two statements
        raise HTTPException(status_code=404, detail=_RULE_NOT_FOUND)
    await _audit(
        "monitoring",
        "syslog_rule.updated",
        user=_session_user(request),
        detail=f"rule_id={rule_id} name='{row['name']}' enabled={row['enabled']}",
        correlation_id=_corr_id(request),
    )
    return await _payload(engine.custom_rule_key(rule_id))


@router.delete(PREFIX + "/{rule_id}")
@scoped("refused")
async def delete_syslog_rule(rule_id: int, request: Request):
    await refuse_scoped(request)
    row = await db.delete_syslog_alert_rule(rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail=_RULE_NOT_FOUND)
    engine.invalidate_rules_cache()
    # Nothing raises or resolves the rule's alerts any more.
    resolved = await engine.resolve_rule_alerts(engine.custom_rule_key(rule_id))
    await _audit(
        "monitoring",
        "syslog_rule.deleted",
        user=_session_user(request),
        detail=f"rule_id={rule_id} name='{row['name']}' alerts_resolved={resolved}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "alerts_resolved": resolved}


@router.patch(PREFIX + "/builtin/{key}")
@scoped("refused")
async def patch_builtin_syslog_rule(key: str, body: BuiltinPatch, request: Request):
    await refuse_scoped(request)
    current = next((r for r in await _merged() if r.builtin and r.key == key), None)
    if current is None:
        raise HTTPException(status_code=404, detail=_RULE_NOT_FOUND)
    severity = current.severity if body.severity is None else body.severity
    if severity not in engine.SEVERITIES:
        raise HTTPException(status_code=400, detail=f"severity must be one of: {', '.join(engine.SEVERITIES)}.")
    enabled = current.enabled if body.enabled is None else body.enabled
    user = _session_user(request)
    await db.set_syslog_builtin_override(key, enabled, severity, user)
    engine.invalidate_rules_cache()
    await _audit(
        "monitoring",
        "syslog_rule.builtin_updated",
        user=user,
        detail=f"rule={key} enabled={enabled} severity={severity}",
        correlation_id=_corr_id(request),
    )
    return await _payload(key)


@router.post(PREFIX + "/test")
@scope_exempt("Tests a sample message against the rules; reads and changes no host data")
async def try_syslog_rules(body: RuleTest):
    try:
        return await engine.explain_message(body.message, body.rule)
    except engine.RuleError as exc:
        raise _bad(exc) from None


# ── SNMP trap rules (netcontrol.trap_rules, docs/snmp-traps.md) ─────────────
#
# Built-in only: the same payload as a built-in syslog rule (``source``
# ``trap``, ``tags`` / ``clear_tags`` the trap names), and the same override
# (``enabled``, ``severity``), stored under ``builtin_key`` ``trap_<key>``.

TRAP_PREFIX = "/api/monitoring/trap-rules"
_TRAP_RULE_NOT_FOUND = "Trap rule not found"


async def _trap_rules() -> list[engine.Rule]:
    engine.invalidate_rules_cache()
    return await trap_rules.get_rules()


@router.get(TRAP_PREFIX)
@scope_exempt("SNMP trap alert rules apply to every host and hold no host data")
async def list_trap_rules():
    return [r.payload() for r in await _trap_rules()]


@router.patch(TRAP_PREFIX + "/builtin/{key}")
@scoped("refused")
async def patch_builtin_trap_rule(key: str, body: BuiltinPatch, request: Request):
    await refuse_scoped(request)
    current = next((r for r in await _trap_rules() if r.key == key), None)
    if current is None:
        raise HTTPException(status_code=404, detail=_TRAP_RULE_NOT_FOUND)
    severity = current.severity if body.severity is None else body.severity
    if severity not in engine.SEVERITIES:
        raise HTTPException(status_code=400, detail=f"severity must be one of: {', '.join(engine.SEVERITIES)}.")
    enabled = current.enabled if body.enabled is None else body.enabled
    user = _session_user(request)
    await db.set_syslog_builtin_override(current.ref, enabled, severity, user)
    engine.invalidate_rules_cache()
    await _audit(
        "monitoring",
        "trap_rule.builtin_updated",
        user=user,
        detail=f"rule={key} enabled={enabled} severity={severity}",
        correlation_id=_corr_id(request),
    )
    return next(r.payload() for r in await _trap_rules() if r.key == key)
