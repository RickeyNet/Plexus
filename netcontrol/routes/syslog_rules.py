"""Syslog alert rules API: ``/api/monitoring/syslog-rules``, and the SNMP
trap rules: ``/api/monitoring/trap-rules`` (the built-in ones with their
``enabled`` / ``severity`` override, the custom ones with full create,
update, delete, and a test route; ``netcontrol.trap_rules``).

Registered in ``app.py`` with the monitoring routes' dependencies: reading
needs ``monitoring``, every write ``monitoring.write``. One merged list of
the built-in rules (only ``enabled`` and ``severity`` can be changed) and
the custom rules (full create, update, delete), and a test endpoint that
shows what a sample message would do. Rule logic and the engine live in
``netcontrol.syslog_rules``; see ``docs/syslog-rules.md``.

Object scope: the rules apply to every host and hold no host data. A
caller limited to selected inventory groups reads them but cannot change
them (like a global alert rule). The trap rule test reads a stored trap
only of a host the caller can read. The activity analysis (``/activity``,
``netcontrol.syslog_activity``) reads host messages: such a caller gets the
messages of their groups' hosts only, and none from unknown sources.
"""

from __future__ import annotations

from typing import Annotated, Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from netcontrol import syslog_activity, syslog_rules as engine, trap_rules
from netcontrol.object_scope import group_filter, refuse_scoped, require_object_host, scope_exempt, scoped
from netcontrol.routes.shared import _audit, _corr_id, _session_user
from netcontrol.snmp_traps import name_trap

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
    if existing is None or existing["builtin_key"] or existing["source"] != engine.ALERT_TYPE:
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
# The built-in rules: the same payload as a built-in syslog rule (``source``
# ``trap``, ``tags`` / ``clear_tags`` the trap names), and the same override
# (``enabled``, ``severity``), stored under ``builtin_key`` ``trap_<key>``.
# The custom rules: full create, update, delete (rows of
# ``syslog_alert_rules`` with ``source`` ``trap``; ``pattern`` /
# ``clear_pattern`` the traps, ``trap_match`` the varbind conditions and the
# instance), and a test route for a stored trap or an OID with varbinds.

TRAP_PREFIX = "/api/monitoring/trap-rules"
_TRAP_RULE_NOT_FOUND = "Trap rule not found"
_TRAP_EVENT_NOT_FOUND = "Trap event not found"
_OID_MAX = 300
_VALUE_MAX = 2000


class TrapTest(BaseModel):
    """A stored trap (``event_id``) or a trap OID with its varbinds, and,
    optionally, an unsaved custom trap rule to try."""

    event_id: int | None = None
    trap_oid: str = Field(default="", max_length=_OID_MAX)
    varbinds: list[tuple[Annotated[str, Field(max_length=_OID_MAX)], Annotated[str, Field(max_length=_VALUE_MAX)]]] = (
        Field(default_factory=list, max_length=64)
    )
    rule: dict[str, Any] | None = None


async def _trap_rules() -> list[engine.Rule]:
    engine.invalidate_rules_cache()
    return await trap_rules.get_rules()


async def _trap_payload(rule_key: str) -> dict:
    return next(r.payload() for r in await _trap_rules() if r.key == rule_key)


@router.get(TRAP_PREFIX)
@scope_exempt("SNMP trap alert rules apply to every host and hold no host data")
async def list_trap_rules():
    return [r.payload() for r in await _trap_rules()]


@router.post(TRAP_PREFIX, status_code=201)
@scoped("refused")
async def create_trap_rule(body: dict, request: Request):
    await refuse_scoped(request)
    try:
        values = trap_rules.clean_custom_trap_rule(body)
    except engine.RuleError as exc:
        raise _bad(exc) from None
    user = _session_user(request)
    row = await db.create_syslog_alert_rule(values, user, source=trap_rules.SOURCE)
    engine.invalidate_rules_cache()
    await _audit(
        "monitoring",
        "trap_rule.created",
        user=user,
        detail=f"rule_id={row['id']} name='{row['name']}' traps='{row['pattern']}'",
        correlation_id=_corr_id(request),
    )
    return await _trap_payload(engine.custom_rule_key(row["id"]))


async def _resolve_trap_rule_alerts(rule_id: int, reason: str) -> int:
    """Resolve the open alerts of a custom trap rule nothing raises or
    resolves any more (deleted or disabled)."""
    return await engine.resolve_rule_alerts(engine.custom_rule_key(rule_id), trap_rules.SOURCE, reason)


@router.put(TRAP_PREFIX + "/{rule_id}")
@scoped("refused")
async def update_trap_rule(rule_id: int, body: dict, request: Request):
    await refuse_scoped(request)
    existing = await db.get_syslog_alert_rule(rule_id)
    if existing is None or existing["builtin_key"] or existing["source"] != trap_rules.SOURCE:
        raise HTTPException(status_code=404, detail=_TRAP_RULE_NOT_FOUND)
    try:
        values = trap_rules.clean_custom_trap_rule({**existing, **body})
    except engine.RuleError as exc:
        raise _bad(exc) from None
    row = await db.update_syslog_alert_rule(rule_id, values, source=trap_rules.SOURCE)
    engine.invalidate_rules_cache()
    if row is None:  # pragma: no cover - deleted between the two statements
        raise HTTPException(status_code=404, detail=_TRAP_RULE_NOT_FOUND)
    resolved = 0
    if existing["enabled"] and not row["enabled"]:
        resolved = await _resolve_trap_rule_alerts(rule_id, "rule disabled")
    await _audit(
        "monitoring",
        "trap_rule.updated",
        user=_session_user(request),
        detail=f"rule_id={rule_id} name='{row['name']}' enabled={row['enabled']} alerts_resolved={resolved}",
        correlation_id=_corr_id(request),
    )
    return await _trap_payload(engine.custom_rule_key(rule_id))


@router.delete(TRAP_PREFIX + "/{rule_id}")
@scoped("refused")
async def delete_trap_rule(rule_id: int, request: Request):
    await refuse_scoped(request)
    row = await db.delete_syslog_alert_rule(rule_id, source=trap_rules.SOURCE)
    if row is None:
        raise HTTPException(status_code=404, detail=_TRAP_RULE_NOT_FOUND)
    engine.invalidate_rules_cache()
    resolved = await _resolve_trap_rule_alerts(rule_id, "rule deleted")
    await _audit(
        "monitoring",
        "trap_rule.deleted",
        user=_session_user(request),
        detail=f"rule_id={rule_id} name='{row['name']}' alerts_resolved={resolved}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "alerts_resolved": resolved}


@router.patch(TRAP_PREFIX + "/builtin/{key}")
@scoped("refused")
async def patch_builtin_trap_rule(key: str, body: BuiltinPatch, request: Request):
    await refuse_scoped(request)
    current = next((r for r in await _trap_rules() if r.builtin and r.key == key), None)
    if current is None:
        raise HTTPException(status_code=404, detail=_TRAP_RULE_NOT_FOUND)
    severity = current.severity if body.severity is None else body.severity
    if severity not in engine.SEVERITIES:
        raise HTTPException(status_code=400, detail=f"severity must be one of: {', '.join(engine.SEVERITIES)}.")
    enabled = current.enabled if body.enabled is None else body.enabled
    user = _session_user(request)
    await db.set_syslog_builtin_override(current.ref, enabled, severity, user, source=trap_rules.SOURCE)
    engine.invalidate_rules_cache()
    await _audit(
        "monitoring",
        "trap_rule.builtin_updated",
        user=user,
        detail=f"rule={key} enabled={enabled} severity={severity}",
        correlation_id=_corr_id(request),
    )
    return await _trap_payload(key)


@router.post(TRAP_PREFIX + "/test")
@scoped("host")
async def try_trap_rules(body: TrapTest, request: Request):
    """What the trap rules would do with a stored trap (``event_id``: one
    of a host the caller can read; an SNMPv3 trap or one cut at 1000 bytes
    cannot be decoded again) or with ``trap_oid`` and ``varbinds``."""
    if body.event_id is not None:
        event = await db.get_stored_trap_event(body.event_id)
        if event is None:
            raise HTTPException(status_code=404, detail=_TRAP_EVENT_NOT_FOUND)
        await require_object_host(request, event["host_id"], not_found=_TRAP_EVENT_NOT_FOUND)
        trap = trap_rules.decode_stored_trap(event["raw_data"])
        if trap is None:
            raise HTTPException(
                status_code=400,
                detail="This stored trap cannot be decoded again (SNMPv3, or larger than 1000 bytes): "
                "enter its trap OID and varbinds instead.",
            )
    elif body.trap_oid.strip():
        trap = {"trap_oid": body.trap_oid.strip().lstrip("."), "varbinds": [list(vb) for vb in body.varbinds]}
    else:
        raise HTTPException(status_code=400, detail="Give a stored trap (event_id) or a trap OID.")
    try:
        return await trap_rules.explain_trap(name_trap(trap), body.rule)
    except engine.RuleError as exc:
        raise _bad(exc) from None
