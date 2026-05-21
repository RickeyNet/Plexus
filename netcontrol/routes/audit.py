"""
audit.py -- Network audit report engine.

Runs a set of pluggable :class:`Rule` checks against the live inventory and
config baselines, producing :class:`Finding` rows that are persisted into
``audit_findings`` and surfaced through ``/api/audit/...`` endpoints.

Vertical slice (v1): config-drift rule pack only. VLAN / port-hygiene /
security packs are intentionally not wired here yet -- they slot in by
adding a class to ``_RULE_REGISTRY`` once their collectors are ready.

The orchestrator is patterned on ``reporting._report_scheduler_loop``:
a single background task polls for due runs (cron-style schedule) and
also services on-demand ``POST /api/audit/runs`` triggers.
"""
from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field

import routes.database as db
from fastapi import APIRouter, HTTPException, Query

from netcontrol.routes.shared import _compute_config_diff
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

LOGGER = configure_logging("plexus.audit")

router = APIRouter()

AUDIT_POLL_SECONDS = max(30, int(os.getenv("APP_AUDIT_POLL_SECONDS", "60")))


# ── Domain types ────────────────────────────────────────────────────────────

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    """One rule violation against one host."""

    rule_id: str
    category: str
    severity: str
    title: str
    detail: str = ""
    host_id: int | None = None
    cis_control: str = ""
    evidence: dict = field(default_factory=dict)


@dataclass
class AuditContext:
    """Per-run state passed to every rule.

    Rules read ``hosts`` (list of host dicts) and call back into ``db`` for
    anything else. Keeping the context small keeps rules independently
    testable.
    """

    run_id: int
    hosts: list[dict]


class Rule:
    """Base class for all audit rules.

    Subclasses set ``rule_id``, ``category``, ``default_severity`` and
    optionally ``cis_control``, then implement :meth:`evaluate`. Rules
    must be pure-ish: read from ``ctx`` and the DB, emit findings, never
    mutate inventory.
    """

    rule_id: str = ""
    category: str = ""
    default_severity: str = "info"
    cis_control: str = ""
    title: str = ""

    async def evaluate(self, ctx: AuditContext) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError


# ── Rule pack: configuration drift ──────────────────────────────────────────

class ConfigDriftRule(Rule):
    """Diff each host's most recent running-config snapshot against its
    baseline. Any added/removed lines (after volatile-metadata stripping
    inside ``_compute_config_diff``) produces a single finding per host
    with the diff body as evidence.
    """

    rule_id = "config.drift"
    category = "config"
    default_severity = "high"
    cis_control = "CIS Controls v8 4.2"
    title = "Running-config drift from baseline"

    async def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        for host in ctx.hosts:
            host_id = int(host["id"])
            baseline = await db.get_config_baseline_for_host(host_id)
            if not baseline or not (baseline.get("config_text") or "").strip():
                # No baseline yet -> informational finding so the user
                # knows this host is unaudited.
                findings.append(Finding(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity="info",
                    title="No config baseline captured",
                    detail=(
                        "This host has no config baseline; drift cannot "
                        "be evaluated until one is captured."
                    ),
                    host_id=host_id,
                    cis_control=self.cis_control,
                    evidence={"hostname": host.get("hostname", "")},
                ))
                continue

            snapshot = await db.get_latest_config_snapshot(host_id)
            if not snapshot or not (snapshot.get("config_text") or "").strip():
                findings.append(Finding(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity="medium",
                    title="No recent config snapshot",
                    detail=(
                        "Baseline exists but no running-config has been "
                        "captured. Run a config backup so drift can be "
                        "checked."
                    ),
                    host_id=host_id,
                    cis_control=self.cis_control,
                    evidence={"hostname": host.get("hostname", "")},
                ))
                continue

            diff_text, lines_added, lines_removed = _compute_config_diff(
                baseline["config_text"],
                snapshot["config_text"],
                baseline_label="baseline",
                actual_label="running",
            )
            if lines_added == 0 and lines_removed == 0:
                continue  # in compliance

            findings.append(Finding(
                rule_id=self.rule_id,
                category=self.category,
                severity=self.default_severity,
                title=self.title,
                detail=(
                    f"{lines_added} line(s) added, {lines_removed} line(s) "
                    f"removed vs. baseline."
                ),
                host_id=host_id,
                cis_control=self.cis_control,
                evidence={
                    "hostname": host.get("hostname", ""),
                    "lines_added": lines_added,
                    "lines_removed": lines_removed,
                    # Cap evidence size; the full diff is also accessible
                    # via the existing config-drift endpoints.
                    "diff_excerpt": diff_text[:8000],
                },
            ))
        return findings


# Rule registry. New rule classes are appended here once their
# collectors land.
_RULE_REGISTRY: list[type[Rule]] = [
    ConfigDriftRule,
]


# ── Orchestrator ────────────────────────────────────────────────────────────

async def _persist_finding(run_id: int, finding: Finding) -> None:
    """Insert one finding row."""
    conn = await db.get_db()
    try:
        await conn.execute(
            """INSERT INTO audit_findings
               (run_id, host_id, rule_id, category, severity, cis_control,
                title, detail, evidence_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                finding.host_id,
                finding.rule_id,
                finding.category,
                finding.severity,
                finding.cis_control,
                finding.title,
                finding.detail,
                json.dumps(finding.evidence, default=str),
            ),
        )
        await conn.commit()
    finally:
        await conn.close()


async def _create_run(trigger: str) -> int:
    conn = await db.get_db()
    try:
        cursor = await conn.execute(
            """INSERT INTO audit_runs (status, trigger)
               VALUES ('running', ?)""",
            (trigger,),
        )
        await conn.commit()
        return int(cursor.lastrowid)
    finally:
        await conn.close()


async def _finalize_run(
    run_id: int,
    status: str,
    host_count: int,
    severity_counts: dict[str, int],
    summary: dict,
    error_text: str = "",
) -> None:
    conn = await db.get_db()
    try:
        await conn.execute(
            """UPDATE audit_runs SET
                 status = ?,
                 finished_at = datetime('now'),
                 host_count = ?,
                 findings_total = ?,
                 findings_critical = ?,
                 findings_high = ?,
                 findings_medium = ?,
                 findings_low = ?,
                 findings_info = ?,
                 summary_json = ?,
                 error_text = ?
               WHERE id = ?""",
            (
                status,
                host_count,
                sum(severity_counts.values()),
                severity_counts.get("critical", 0),
                severity_counts.get("high", 0),
                severity_counts.get("medium", 0),
                severity_counts.get("low", 0),
                severity_counts.get("info", 0),
                json.dumps(summary, default=str),
                error_text,
                run_id,
            ),
        )
        await conn.commit()
    finally:
        await conn.close()


async def run_audit(trigger: str = "manual") -> int:
    """Execute one full audit run end-to-end. Returns the run_id.

    Each rule's exceptions are caught individually so one broken rule
    doesn't tank the whole run -- it lands a finding instead and the
    run continues.
    """
    run_id = await _create_run(trigger)
    severity_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    rules_executed: list[str] = []
    rules_failed: dict[str, str] = {}

    try:
        hosts = await db.get_all_hosts()
        ctx = AuditContext(run_id=run_id, hosts=hosts)

        for rule_cls in _RULE_REGISTRY:
            rule = rule_cls()
            try:
                findings = await rule.evaluate(ctx)
                rules_executed.append(rule.rule_id)
                for f in findings:
                    severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
                    await _persist_finding(run_id, f)
            except Exception as exc:
                LOGGER.warning(
                    "audit rule %s failed: %s",
                    rule.rule_id,
                    redact_value(str(exc)),
                )
                increment_metric("audit.rule.failed")
                rules_failed[rule.rule_id] = str(exc)[:500]

        summary = {
            "rules_executed": rules_executed,
            "rules_failed": rules_failed,
            "trigger": trigger,
        }
        await _finalize_run(
            run_id,
            status="success" if not rules_failed else "partial",
            host_count=len(hosts),
            severity_counts=severity_counts,
            summary=summary,
        )
        increment_metric("audit.run.completed")
        return run_id

    except Exception as exc:
        LOGGER.error("audit run %d failed: %s", run_id, exc, exc_info=True)
        increment_metric("audit.run.failed")
        await _finalize_run(
            run_id,
            status="failed",
            host_count=0,
            severity_counts=severity_counts,
            summary={"rules_executed": rules_executed, "rules_failed": rules_failed},
            error_text=str(exc)[:1000],
        )
        return run_id


# ── Background loop ─────────────────────────────────────────────────────────

async def _audit_run_loop() -> None:
    """Background polling loop for on-demand / scheduled audit runs.

    v1 only handles the on-demand queue (rows inserted with status
    ``queued`` by the API). Cron-style scheduling reuses the existing
    report scheduler pattern but is wired in a follow-up PR alongside
    the schedule UI.
    """
    while True:
        try:
            await asyncio.sleep(AUDIT_POLL_SECONDS)
            queued = await _claim_queued_run()
            if queued is not None:
                LOGGER.info("audit: starting queued run id=%d", queued)
                # Re-run using existing run row instead of creating a new one.
                await _execute_existing_run(queued, trigger="queued")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("audit loop failure: %s", redact_value(str(exc)))
            increment_metric("audit.loop.failed")
            await asyncio.sleep(AUDIT_POLL_SECONDS)


async def _claim_queued_run() -> int | None:
    """Atomically grab the oldest queued audit run, transition to running."""
    conn = await db.get_db()
    try:
        cursor = await conn.execute(
            "SELECT id FROM audit_runs WHERE status = 'queued' "
            "ORDER BY id ASC LIMIT 1"
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        run_id = int(row[0])
        await conn.execute(
            "UPDATE audit_runs SET status = 'running', started_at = datetime('now') "
            "WHERE id = ? AND status = 'queued'",
            (run_id,),
        )
        await conn.commit()
        return run_id
    finally:
        await conn.close()


async def _execute_existing_run(run_id: int, trigger: str) -> None:
    """Run rules against an audit_runs row that already exists."""
    severity_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    rules_executed: list[str] = []
    rules_failed: dict[str, str] = {}
    try:
        hosts = await db.get_all_hosts()
        ctx = AuditContext(run_id=run_id, hosts=hosts)
        for rule_cls in _RULE_REGISTRY:
            rule = rule_cls()
            try:
                findings = await rule.evaluate(ctx)
                rules_executed.append(rule.rule_id)
                for f in findings:
                    severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
                    await _persist_finding(run_id, f)
            except Exception as exc:
                LOGGER.warning(
                    "audit rule %s failed in run %d: %s",
                    rule.rule_id, run_id, redact_value(str(exc)),
                )
                rules_failed[rule.rule_id] = str(exc)[:500]
        await _finalize_run(
            run_id,
            status="success" if not rules_failed else "partial",
            host_count=len(hosts),
            severity_counts=severity_counts,
            summary={
                "rules_executed": rules_executed,
                "rules_failed": rules_failed,
                "trigger": trigger,
            },
        )
    except Exception as exc:
        LOGGER.error("audit run %d failed: %s", run_id, exc, exc_info=True)
        await _finalize_run(
            run_id,
            status="failed",
            host_count=0,
            severity_counts=severity_counts,
            summary={"rules_executed": rules_executed, "rules_failed": rules_failed},
            error_text=str(exc)[:1000],
        )


# ── API endpoints ───────────────────────────────────────────────────────────
#
# Auth is enforced at include_router level in app.py (Depends(require_auth)
# + feature gate), matching the reporting / mac_tracking pattern.


@router.post("/api/audit/runs", status_code=201)
async def trigger_audit_run():
    """Trigger an audit run synchronously and return the resulting row.

    Runs in-process. For very large fleets this should be flipped to a
    queued execution via the background loop, but for v1 sync keeps the
    UX simple ("click button -> see result").
    """
    run_id = await run_audit(trigger="manual")
    return await get_audit_run_detail(run_id)


@router.get("/api/audit/runs")
async def list_audit_runs(
    limit: int = Query(default=50, ge=1, le=500),
):
    conn = await db.get_db()
    try:
        cursor = await conn.execute(
            """SELECT id, status, trigger, started_at, finished_at, host_count,
                      findings_total, findings_critical, findings_high,
                      findings_medium, findings_low, findings_info
               FROM audit_runs
               ORDER BY id DESC
               LIMIT ?""",
            (limit,),
        )
        rows = await cursor.fetchall()
        cols = [
            "id", "status", "trigger", "started_at", "finished_at", "host_count",
            "findings_total", "findings_critical", "findings_high",
            "findings_medium", "findings_low", "findings_info",
        ]
        return {"runs": [dict(zip(cols, r)) for r in rows]}
    finally:
        await conn.close()


@router.get("/api/audit/runs/{run_id}")
async def get_audit_run_detail(run_id: int):
    conn = await db.get_db()
    try:
        cursor = await conn.execute(
            "SELECT * FROM audit_runs WHERE id = ?", (run_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="audit run not found")
        # column names from cursor.description
        cols = [d[0] for d in cursor.description]
        run = dict(zip(cols, row))
        # Parse summary_json if present
        try:
            run["summary"] = json.loads(run.get("summary_json") or "{}")
        except Exception:
            run["summary"] = {}
        return run
    finally:
        await conn.close()


@router.get("/api/audit/runs/{run_id}/findings")
async def list_audit_findings(
    run_id: int,
    severity: str | None = Query(default=None),
    host_id: int | None = Query(default=None),
):
    conn = await db.get_db()
    try:
        clauses = ["run_id = ?"]
        params: list = [run_id]
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if host_id is not None:
            clauses.append("host_id = ?")
            params.append(host_id)
        sql = (
            "SELECT id, run_id, host_id, rule_id, category, severity, "
            "cis_control, title, detail, evidence_json, created_at "
            "FROM audit_findings WHERE " + " AND ".join(clauses) +
            " ORDER BY CASE severity "
            "  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "  WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id ASC"
        )
        cursor = await conn.execute(sql, tuple(params))
        rows = await cursor.fetchall()
        cols = [d[0] for d in cursor.description]
        findings = []
        for r in rows:
            f = dict(zip(cols, r))
            try:
                f["evidence"] = json.loads(f.pop("evidence_json") or "{}")
            except Exception:
                f["evidence"] = {}
            findings.append(f)
        return {"findings": findings}
    finally:
        await conn.close()
