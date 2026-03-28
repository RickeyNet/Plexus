"""
baseline_alerting.py -- Statistical baseline deviation alerting

Provides:
  - Baseline computation from historical metric_samples data
  - Deviation detection using z-score against time-of-day baselines
  - Baseline alert rule CRUD API endpoints
  - Integration with the monitoring poll loop for live deviation checks
  - Background loop for periodic baseline recomputation
"""

import math
from datetime import UTC, datetime, timedelta

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

import netcontrol.routes.state as state
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.baseline_alerting")


# ═════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ═════════════════════════════════════════════════════════════════════════════

class BaselineAlertRuleCreate(BaseModel):
    name: str
    description: str = ""
    metric_name: str
    host_id: int | None = None
    group_id: int | None = None
    sensitivity: float = 2.0
    min_samples: int = 100
    learning_days: int = 14
    enabled: bool = True
    severity: str = "warning"
    cooldown_minutes: int = 30

class BaselineAlertRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    metric_name: str | None = None
    host_id: int | None = None
    group_id: int | None = None
    sensitivity: float | None = None
    min_samples: int | None = None
    learning_days: int | None = None
    enabled: bool | None = None
    severity: str | None = None
    cooldown_minutes: int | None = None


# ═════════════════════════════════════════════════════════════════════════════
# Baseline Computation
# ═════════════════════════════════════════════════════════════════════════════


def _compute_stats(values: list[float]) -> dict:
    """Compute mean, stddev, min, max, p95 from a list of values."""
    clean = [v for v in values if v is not None and not math.isnan(v) and not math.isinf(v)]
    if not clean:
        return {"avg": 0.0, "stddev": 0.0, "min": 0.0, "max": 0.0, "p95": 0.0, "count": 0}

    n = len(clean)
    avg = sum(clean) / n
    variance = sum((x - avg) ** 2 for x in clean) / n if n > 1 else 0.0
    stddev = math.sqrt(variance)
    sorted_vals = sorted(clean)
    p95_idx = int(n * 0.95)
    p95 = sorted_vals[min(p95_idx, n - 1)]

    return {
        "avg": round(avg, 4),
        "stddev": round(stddev, 4),
        "min": round(min(clean), 4),
        "max": round(max(clean), 4),
        "p95": round(p95, 4),
        "count": n,
    }


async def compute_baselines_for_host(host_id: int, metric_name: str,
                                       learning_days: int = 14) -> int:
    """Compute baselines for a host/metric, grouped by day-of-week and hour-of-day.

    Queries metric_samples for the past N days and aggregates by
    (day_of_week, hour_of_day) buckets.

    Returns number of baseline entries created/updated.
    """
    # Query raw samples from the learning window
    cutoff = (datetime.now(UTC) - timedelta(days=learning_days)).isoformat()
    ddb = await db.get_db()
    try:
        cursor = await ddb.execute(
            """SELECT value, collected_at FROM metric_samples
               WHERE host_id = ? AND metric_name = ? AND collected_at >= ?
               ORDER BY collected_at""",
            (host_id, metric_name, cutoff),
        )
        rows = await cursor.fetchall()
    finally:
        await ddb.close()

    if not rows:
        return 0

    # Group by (day_of_week, hour_of_day)
    buckets: dict[tuple[int, int], list[float]] = {}
    for row in rows:
        r = dict(row) if hasattr(row, "keys") else {"value": row[0], "collected_at": row[1]}
        try:
            ts = datetime.fromisoformat(r["collected_at"])
            dow = ts.weekday()  # 0=Monday
            hod = ts.hour
            val = float(r["value"])
            buckets.setdefault((dow, hod), []).append(val)
        except (ValueError, TypeError):
            continue

    # Also compute an "any day" baseline (day_of_week = -1) for each hour
    hour_buckets: dict[int, list[float]] = {}
    for (dow, hod), vals in buckets.items():
        hour_buckets.setdefault(hod, []).extend(vals)

    updated = 0

    # Upsert per-(dow, hod) baselines
    for (dow, hod), vals in buckets.items():
        stats = _compute_stats(vals)
        if stats["count"] < 3:
            continue
        await db.upsert_metric_baseline(
            host_id=host_id, metric_name=metric_name,
            day_of_week=dow, hour_of_day=hod,
            baseline_avg=stats["avg"], baseline_stddev=stats["stddev"],
            baseline_min=stats["min"], baseline_max=stats["max"],
            baseline_p95=stats["p95"], sample_count=stats["count"],
            learning_window_days=learning_days,
        )
        updated += 1

    # Upsert per-hour "any day" baselines
    for hod, vals in hour_buckets.items():
        stats = _compute_stats(vals)
        if stats["count"] < 3:
            continue
        await db.upsert_metric_baseline(
            host_id=host_id, metric_name=metric_name,
            day_of_week=-1, hour_of_day=hod,
            baseline_avg=stats["avg"], baseline_stddev=stats["stddev"],
            baseline_min=stats["min"], baseline_max=stats["max"],
            baseline_p95=stats["p95"], sample_count=stats["count"],
            learning_window_days=learning_days,
        )
        updated += 1

    LOGGER.info("baseline: computed %d entries for host=%d metric=%s (window=%dd)",
                updated, host_id, metric_name, learning_days)
    return updated


# ═════════════════════════════════════════════════════════════════════════════
# Deviation Detection
# ═════════════════════════════════════════════════════════════════════════════


async def check_baseline_deviation(host_id: int, metric_name: str,
                                     current_value: float,
                                     sensitivity: float = 2.0) -> dict | None:
    """Check if current_value deviates from the baseline.

    Returns deviation info dict if a deviation is detected, else None.
    Uses the specific (day_of_week, hour) baseline first, falls back to
    the any-day (day_of_week=-1) baseline.
    """
    now = datetime.now(UTC)
    dow = now.weekday()
    hod = now.hour

    # Try specific day+hour baseline first
    baseline = await db.get_metric_baseline(host_id, metric_name, dow, hod)
    if not baseline or baseline.get("sample_count", 0) < 10:
        # Fall back to any-day baseline
        baseline = await db.get_metric_baseline(host_id, metric_name, -1, hod)

    if not baseline or baseline.get("sample_count", 0) < 10:
        return None

    avg = baseline["baseline_avg"]
    stddev = baseline["baseline_stddev"]

    if stddev <= 0:
        # No variance — can't compute z-score
        return None

    z_score = (current_value - avg) / stddev

    if abs(z_score) > sensitivity:
        direction = "above" if z_score > 0 else "below"
        return {
            "host_id": host_id,
            "metric_name": metric_name,
            "current_value": round(current_value, 2),
            "baseline_avg": round(avg, 2),
            "baseline_stddev": round(stddev, 2),
            "z_score": round(z_score, 2),
            "sensitivity": sensitivity,
            "direction": direction,
            "deviation_pct": round(abs(current_value - avg) / avg * 100, 1) if avg != 0 else 0,
            "message": (
                f"{metric_name} at {round(current_value, 1)} is {round(abs(z_score), 1)} "
                f"sigma {direction} baseline of {round(avg, 1)} ± {round(stddev, 1)}"
            ),
        }

    return None


async def evaluate_baseline_alerts_for_poll(poll_result: dict, poll_id: int) -> int:
    """Evaluate all enabled baseline alert rules against a poll result.

    Called from the monitoring poll loop after threshold checks.
    Returns number of alerts created.
    """
    host_id = poll_result["host_id"]
    rules = await db.list_baseline_alert_rules(enabled_only=True)

    alerts_created = 0
    for rule in rules:
        # Check if rule applies to this host
        rule_host_id = rule.get("host_id")
        rule_group_id = rule.get("group_id")
        if rule_host_id and rule_host_id != host_id:
            continue
        # If rule has group_id, check the host's group
        if rule_group_id:
            host_info = await db.get_host(host_id)
            if host_info and host_info.get("group_id") != rule_group_id:
                continue

        metric_name = rule["metric_name"]
        sensitivity = rule.get("sensitivity", 2.0)
        min_samples = rule.get("min_samples", 100)

        # Get the current value from poll results
        current_value = poll_result.get(metric_name)
        if current_value is None:
            continue

        try:
            current_value = float(current_value)
        except (ValueError, TypeError):
            continue

        # Check deviation
        deviation = await check_baseline_deviation(
            host_id, metric_name, current_value, sensitivity
        )
        if not deviation:
            continue

        # Check cooldown
        cooldown_minutes = rule.get("cooldown_minutes", 30)
        dedup_key = f"{host_id}:baseline:{metric_name}"
        suppressed = await db.is_alert_suppressed(host_id, f"baseline_{metric_name}")
        if suppressed:
            continue

        # Create alert
        await db.create_monitoring_alert(
            host_id=host_id,
            poll_id=poll_id,
            alert_type="baseline_deviation",
            metric=f"baseline_{metric_name}",
            message=deviation["message"],
            severity=rule.get("severity", "warning"),
            value=current_value,
            dedup_key=dedup_key,
        )
        alerts_created += 1

    return alerts_created


# ═════════════════════════════════════════════════════════════════════════════
# Background Baseline Computation Loop
# ═════════════════════════════════════════════════════════════════════════════


async def run_baseline_computation_cycle():
    """Recompute baselines for all metrics referenced by active baseline alert rules."""
    rules = await db.list_baseline_alert_rules(enabled_only=True)
    if not rules:
        return

    # Collect unique (host_id | group, metric) pairs
    tasks_to_compute: list[tuple[int, str, int]] = []

    for rule in rules:
        metric = rule["metric_name"]
        learning_days = rule.get("learning_days", 14)

        if rule.get("host_id"):
            tasks_to_compute.append((rule["host_id"], metric, learning_days))
        elif rule.get("group_id"):
            hosts = await db.get_hosts_for_group(rule["group_id"])
            for h in hosts:
                tasks_to_compute.append((h["id"], metric, learning_days))
        else:
            # Global rule — compute for all hosts
            groups = await db.get_all_groups()
            for g in groups:
                hosts = await db.get_hosts_for_group(g["id"])
                for h in hosts:
                    tasks_to_compute.append((h["id"], metric, learning_days))

    # Deduplicate
    seen = set()
    unique_tasks = []
    for t in tasks_to_compute:
        key = (t[0], t[1])
        if key not in seen:
            seen.add(key)
            unique_tasks.append(t)

    total = 0
    for host_id, metric, days in unique_tasks:
        try:
            count = await compute_baselines_for_host(host_id, metric, days)
            total += count
        except Exception as exc:
            LOGGER.debug("baseline: computation error for host=%d metric=%s: %s",
                         host_id, metric, str(exc))

    if total > 0:
        LOGGER.info("baseline: recomputed %d baseline entries across %d host-metric pairs",
                     total, len(unique_tasks))


# ═════════════════════════════════════════════════════════════════════════════
# API Endpoints
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/api/baseline-rules")
async def list_rules(enabled_only: bool = Query(False)):
    return await db.list_baseline_alert_rules(enabled_only)


@router.get("/api/baseline-rules/{rule_id}")
async def get_rule(rule_id: int):
    rule = await db.get_baseline_alert_rule(rule_id)
    if not rule:
        raise HTTPException(404, "Baseline alert rule not found")
    return rule


@router.post("/api/baseline-rules", status_code=201)
async def create_rule(body: BaselineAlertRuleCreate, request: Request):
    user = getattr(request.state, "user", None)
    username = user.get("username", "") if user else ""
    rule_id = await db.create_baseline_alert_rule(
        **body.dict(), created_by=username,
    )
    return {"id": rule_id}


@router.put("/api/baseline-rules/{rule_id}")
async def update_rule(rule_id: int, body: BaselineAlertRuleUpdate):
    existing = await db.get_baseline_alert_rule(rule_id)
    if not existing:
        raise HTTPException(404, "Baseline alert rule not found")
    updates = {k: v for k, v in body.dict(exclude_unset=True).items() if v is not None}
    if updates:
        await db.update_baseline_alert_rule(rule_id, **updates)
    return await db.get_baseline_alert_rule(rule_id)


@router.delete("/api/baseline-rules/{rule_id}")
async def delete_rule(rule_id: int):
    existing = await db.get_baseline_alert_rule(rule_id)
    if not existing:
        raise HTTPException(404, "Baseline alert rule not found")
    await db.delete_baseline_alert_rule(rule_id)
    return {"deleted": True}


@router.get("/api/baselines")
async def get_baselines(
    host_id: int = Query(...),
    metric: str | None = Query(None),
):
    """View computed baselines for a host."""
    return await db.get_baselines_for_host(host_id, metric)


@router.post("/api/baselines/compute")
async def trigger_compute(
    host_id: int = Query(...),
    metric: str = Query(...),
    learning_days: int = Query(14, ge=1, le=90),
):
    """Trigger immediate baseline recomputation for a host/metric."""
    count = await compute_baselines_for_host(host_id, metric, learning_days)
    return {"baselines_computed": count, "host_id": host_id, "metric": metric}


@router.get("/api/baselines/{host_id}/{metric}/chart")
async def get_baseline_chart_data(host_id: int, metric: str):
    """Return baseline band data for chart overlay.

    Returns 24 entries (one per hour) with avg, min/max band, and p95.
    Uses "any day" baselines (day_of_week=-1) for simplicity.
    """
    baselines = await db.get_baselines_for_host(host_id, metric)

    # Filter to any-day baselines
    hourly = {}
    for b in baselines:
        if b.get("day_of_week") == -1:
            hourly[b["hour_of_day"]] = b

    chart_data = []
    for hour in range(24):
        b = hourly.get(hour)
        if b:
            chart_data.append({
                "hour": hour,
                "avg": b["baseline_avg"],
                "stddev": b["baseline_stddev"],
                "min": b["baseline_min"],
                "max": b["baseline_max"],
                "p95": b["baseline_p95"],
                "upper_band": round(b["baseline_avg"] + 2 * b["baseline_stddev"], 2),
                "lower_band": round(max(0, b["baseline_avg"] - 2 * b["baseline_stddev"]), 2),
                "sample_count": b["sample_count"],
            })
        else:
            chart_data.append({
                "hour": hour, "avg": None, "stddev": None,
                "min": None, "max": None, "p95": None,
                "upper_band": None, "lower_band": None, "sample_count": 0,
            })

    return chart_data
