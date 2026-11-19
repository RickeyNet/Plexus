"""The Cato egress vs cloud allow-list check, run server-side, and the run,
store, alert and clear loop the Cato checks share.

``run_egress_check`` runs after every stored Cato collection and AWS, Azure
or GCP discovery (``netcontrol.routes.meraki_topology``, next to the
topology availability recording) and on demand (``POST
/api/monitoring/cato-egress/run``). It evaluates the latest snapshot of
every Cato account against the reachability engines of the collected cloud
accounts (``netcontrol.integrations.cato.egress_check``), stores the
findings (``routes.db.cato_egress``) and alerts on the warnings:

  - a finding whose public or private address is an inventory host's gets
    a monitoring alert on that host (``create_monitoring_alert``, alert
    type ``cato_egress``, deduplicated by finding while unacknowledged), and
    the alert-created hook hands it to the notification channels;
  - any other (most: ``monitoring_alerts`` rows need a host) goes straight
    to the notification channels, like the topology availability alerts.

A warning alerts once while it stays open. When its condition clears (the
finding is no longer reported, or is only informational now) its
monitoring alert is acknowledged as ``auto-resolved``. Informational
findings (data not collected, a rule that cannot be resolved) are listed,
never alerted. Best-effort: a failure is logged and never fails the
collection that triggered the run.

The loop (``run_check``), the alert (``_raise_alert``) and the two endpoint
bodies (``list_findings``, ``run_api``) take a ``CheckSpec``: the Cato
shared hosts vs Azure check (``netcontrol.routes.cato_shared_host_check``)
runs through them with its own name, alert type and lock.

Object scope: the findings are of Cato and cloud accounts, not inventory
hosts: a caller limited to selected inventory groups sees none (their alerts
on a matched host show in the monitoring alerts) and cannot run the check.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import routes.database as db
from fastapi import APIRouter, Query, Request

from netcontrol.integrations.cato import egress_check
from netcontrol.object_scope import refuse_scoped, request_scope, scoped
from netcontrol.routes import notification_channels
from netcontrol.routes.shared import _audit, _get_session
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.cato_egress")

ALERT_TYPE = "cato_egress"
_METRIC = "cato egress"

# A pure check: ``(cato snapshots, cloud engines) -> findings``.
CheckFn = Callable[[list[tuple[int, dict]], list[tuple[str, Any]]], list[dict]]
Inputs = Callable[[], Awaitable[tuple[list[tuple[int, dict]], list[tuple[str, Any]], set[str]]]]


@dataclass(frozen=True)
class CheckSpec:
    """What sets one Cato check's run apart: its rows (``name``, the
    ``check_name`` column), its alerts (``alert_type``, ``metric``, the
    message ``title`` and the dedup-key ``prefix``), its audit action, its
    log wording and logger, and its lock (one run at a time: collections
    finishing together queue behind it)."""

    name: str
    alert_type: str
    metric: str
    title: str
    prefix: str
    audit_action: str
    log_name: str
    logger: logging.Logger
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, compare=False)


EGRESS = CheckSpec(
    name="egress",
    alert_type=ALERT_TYPE,
    metric=_METRIC,
    title="Cato egress",
    prefix="cato_egress",
    audit_action="cato_egress.checked",
    log_name="cato egress",
    logger=LOGGER,
)


def dedup_key(finding_key: str, spec: CheckSpec = EGRESS) -> str:
    return f"{spec.prefix}:{finding_key}"


async def _host_of(finding: dict) -> dict | None:
    for address in (finding.get("public_ip"), finding.get("private_ip")):
        if address:
            host = await db.find_host_by_ip(str(address))
            if host:
                return host
    return None


async def _raise_alert(finding: dict, spec: CheckSpec = EGRESS) -> str:
    """Raise the alert of one warning finding. Returns how: ``monitoring``
    or ``notification``."""
    key = dedup_key(str(finding["key"]), spec)
    message = f"{spec.title} ({finding.get('cato_org_name') or ''}): {finding['message']}"
    host = await _host_of(finding)
    name = str(finding.get("resource_name") or finding.get("public_ip") or "")
    if host:
        await db.create_monitoring_alert(
            host_id=int(host["id"]),
            poll_id=None,
            alert_type=spec.alert_type,
            metric=spec.metric,
            message=message,
            severity="warning",
            dedup_key=key,
            hostname=str(host.get("hostname") or name),
        )
        return "monitoring"
    await notification_channels.on_alert_created(
        {
            "alert_id": key,
            "host_id": None,
            "hostname": name,
            "poll_id": None,
            "rule_id": None,
            "alert_type": spec.alert_type,
            "metric": spec.metric,
            "message": message,
            "severity": "warning",
            "value": None,
            "threshold": None,
            "dedup_key": key,
            "channel_ids": "",
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    return "notification"


async def _inputs() -> tuple[list[tuple[int, dict]], list[tuple[str, Any]], set[str]]:
    from netcontrol.routes.meraki_topology import PROVIDER_CATO, cloud_engines, latest_snapshots

    cato = [(org_ref, s) for org_ref, s in await latest_snapshots() if s.get("provider") == PROVIDER_CATO]
    clouds, failed = await cloud_engines()
    return cato, clouds, failed


async def run_check(spec: CheckSpec, trigger: str, check: CheckFn, inputs: Inputs) -> dict[str, Any]:
    """Run one check, store its findings and alert on the warnings. Never
    raises: a failure is logged and reported in ``error``."""
    log = spec.logger
    async with spec.lock:
        try:
            cato, clouds, failed = await inputs()
            # Evaluating the snapshots against the cloud engines is CPU-bound.
            findings = await asyncio.to_thread(check, cato, clouds)
            result = await db.apply_cato_egress_findings(findings, keep_providers=failed, check=spec.name)
        except Exception as exc:  # noqa: BLE001 - the collection that triggered it is stored
            log.warning("%s check (%s) failed: %s", spec.log_name, trigger, type(exc).__name__, exc_info=True)
            return {"ok": False, "error": type(exc).__name__, "findings": 0, "warnings": 0, "alerted": 0}
        alerted = 0
        for finding in result["alerts"]:
            try:
                via = await _raise_alert(finding, spec)
                await db.set_cato_egress_alert_via(str(finding["key"]), via, check=spec.name)
                alerted += 1
            except Exception as exc:  # noqa: BLE001 - delivery must never break the run
                log.warning("%s: alert for %s failed: %s", spec.log_name, finding["key"], type(exc).__name__)
        cleared = 0
        for row in result["clears"]:
            try:
                cleared += await db.resolve_monitoring_alerts(dedup_key(str(row["finding_key"]), spec))
            except Exception as exc:  # noqa: BLE001
                log.warning("%s: clearing %s failed: %s", spec.log_name, row["finding_key"], type(exc).__name__)
        warnings = sum(1 for f in findings if f["severity"] == egress_check.WARNING)
        if result["new"] or result["resolved"] or alerted:
            log.info(
                "%s check (%s): %s finding(s), %s warning(s), %s new, %s resolved, %s alert(s)",
                spec.log_name,
                trigger,
                len(findings),
                warnings,
                result["new"],
                result["resolved"],
                alerted,
            )
        return {
            "ok": True,
            "trigger": trigger,
            "cato_accounts": len(cato),
            "clouds": [provider for provider, _engine in clouds],
            "clouds_not_read": sorted(failed),
            "findings": len(findings),
            "warnings": warnings,
            "new": result["new"],
            "resolved": result["resolved"],
            "alerted": alerted,
            "alerts_cleared": cleared,
        }


async def run_egress_check(trigger: str = "manual") -> dict[str, Any]:
    """Run the egress check, store its findings and alert on the warnings.
    Never raises: a failure is logged and reported in ``error``."""
    return await run_check(EGRESS, trigger, egress_check.check, _inputs)


async def list_findings(
    request: Request, spec: CheckSpec, labels: dict[str, str], include_resolved: bool, limit: int
) -> dict[str, Any]:
    """The body of a check's findings endpoint: its rows with their
    ``kind_label`` (none for a caller limited to selected inventory groups)."""
    if (await request_scope(request)).restricted:
        return {"findings": []}
    findings = await db.list_cato_egress_findings(include_resolved=include_resolved, limit=limit, check=spec.name)
    for finding in findings:
        finding["kind_label"] = labels.get(str(finding.get("kind")), str(finding.get("kind")))
    return {"findings": findings}


async def run_api(request: Request, spec: CheckSpec, run: Callable[[str], Awaitable[dict[str, Any]]]) -> dict:
    """The body of a check's run endpoint: refused to a scoped caller, audited."""
    await refuse_scoped(request)
    result = await run("manual")
    session = _get_session(request)
    await _audit(
        "monitoring",
        spec.audit_action,
        user=session["user"] if session else "",
        detail=f"findings={result.get('findings')} warnings={result.get('warnings')} alerted={result.get('alerted')}",
    )
    return result


# ── API ─────────────────────────────────────────────────────────────────────


@router.get("/api/monitoring/cato-egress/findings")
@scoped("list")
async def list_cato_egress_findings_api(
    request: Request,
    include_resolved: bool = Query(default=False),
    limit: int = Query(default=1000, ge=1, le=10000),
):
    """The findings of the Cato egress vs cloud allow-list check (none for a
    caller limited to selected inventory groups)."""
    return await list_findings(request, EGRESS, egress_check.KIND_LABELS, include_resolved, limit)


@router.post("/api/monitoring/cato-egress/run")
@scoped("refused")
async def run_cato_egress_check_api(request: Request):
    """Run the check now (every account: refused to a scoped caller)."""
    return await run_api(request, EGRESS, run_egress_check)
