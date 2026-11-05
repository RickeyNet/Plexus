"""The Cato egress vs cloud allow-list check, run server-side.

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
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import routes.database as db
from fastapi import APIRouter, Query, Request

from netcontrol.integrations.cato import egress_check
from netcontrol.routes import notification_channels
from netcontrol.routes.shared import _audit, _get_session
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.cato_egress")

ALERT_TYPE = "cato_egress"
_METRIC = "cato egress"
# One run at a time: collections finishing together queue behind it.
_LOCK = asyncio.Lock()


def dedup_key(finding_key: str) -> str:
    return f"cato_egress:{finding_key}"


async def _host_of(finding: dict) -> dict | None:
    for address in (finding.get("public_ip"), finding.get("private_ip")):
        if address:
            host = await db.find_host_by_ip(str(address))
            if host:
                return host
    return None


async def _raise_alert(finding: dict) -> str:
    """Raise the alert of one warning finding. Returns how: ``monitoring``
    or ``notification``."""
    key = dedup_key(str(finding["key"]))
    message = f"Cato egress ({finding.get('cato_org_name') or ''}): {finding['message']}"
    host = await _host_of(finding)
    name = str(finding.get("resource_name") or finding.get("public_ip") or "")
    if host:
        await db.create_monitoring_alert(
            host_id=int(host["id"]),
            poll_id=None,
            alert_type=ALERT_TYPE,
            metric=_METRIC,
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
            "alert_type": ALERT_TYPE,
            "metric": _METRIC,
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


async def run_egress_check(trigger: str = "manual") -> dict[str, Any]:
    """Run the check, store its findings and alert on the warnings. Never
    raises: a failure is logged and reported in ``error``."""
    async with _LOCK:
        try:
            cato, clouds, failed = await _inputs()
            # Evaluating every source against every rule is CPU-bound.
            findings = await asyncio.to_thread(egress_check.check, cato, clouds)
            result = await db.apply_cato_egress_findings(findings, keep_providers=failed)
        except Exception as exc:  # noqa: BLE001 - the collection that triggered it is stored
            LOGGER.warning("cato egress check (%s) failed: %s", trigger, type(exc).__name__, exc_info=True)
            return {"ok": False, "error": type(exc).__name__, "findings": 0, "warnings": 0, "alerted": 0}
        alerted = 0
        for finding in result["alerts"]:
            try:
                via = await _raise_alert(finding)
                await db.set_cato_egress_alert_via(str(finding["key"]), via)
                alerted += 1
            except Exception as exc:  # noqa: BLE001 - delivery must never break the run
                LOGGER.warning("cato egress: alert for %s failed: %s", finding["key"], type(exc).__name__)
        cleared = 0
        for row in result["clears"]:
            try:
                cleared += await db.resolve_monitoring_alerts(dedup_key(str(row["finding_key"])))
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("cato egress: clearing %s failed: %s", row["finding_key"], type(exc).__name__)
        warnings = sum(1 for f in findings if f["severity"] == egress_check.WARNING)
        if result["new"] or result["resolved"] or alerted:
            LOGGER.info(
                "cato egress check (%s): %s finding(s), %s warning(s), %s new, %s resolved, %s alert(s)",
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


# ── API ─────────────────────────────────────────────────────────────────────


@router.get("/api/monitoring/cato-egress/findings")
async def list_cato_egress_findings_api(
    include_resolved: bool = Query(default=False),
    limit: int = Query(default=1000, ge=1, le=10000),
):
    """The findings of the Cato egress vs cloud allow-list check."""
    findings = await db.list_cato_egress_findings(include_resolved=include_resolved, limit=limit)
    for finding in findings:
        finding["kind_label"] = egress_check.KIND_LABELS.get(str(finding.get("kind")), str(finding.get("kind")))
    return {"findings": findings}


@router.post("/api/monitoring/cato-egress/run")
async def run_cato_egress_check_api(request: Request):
    """Run the check now."""
    result = await run_egress_check("manual")
    session = _get_session(request)
    await _audit(
        "monitoring",
        "cato_egress.checked",
        user=session["user"] if session else "",
        detail=f"findings={result.get('findings')} warnings={result.get('warnings')} alerted={result.get('alerted')}",
    )
    return result
