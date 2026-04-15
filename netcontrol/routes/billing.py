"""
billing.py -- Bandwidth billing and 95th percentile reports.

Provides:
  - CRUD for billing circuits (interface + customer + commit rate)
  - 95th percentile calculation over configurable billing periods
  - Billing period generation with overage detection
  - CSV export for invoices
  - Overage alerting integration
"""

import csv
import io
import json
import logging
from datetime import datetime, timedelta, timezone

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.billing")

# ── Late-binding auth ────────────────────────────────────────────────────────
_require_auth = None
_require_admin = None


def init_billing(require_auth, require_admin):
    global _require_auth, _require_admin
    _require_auth = require_auth
    _require_admin = require_admin


# ── Pydantic models ─────────────────────────────────────────────────────────


class BillingCircuitCreate(BaseModel):
    name: str
    host_id: int
    if_index: int
    if_name: str = ""
    customer: str = ""
    description: str = ""
    commit_rate_bps: float = 0
    burst_limit_bps: float = 0
    billing_day: int = 1
    billing_cycle: str = "monthly"
    cost_per_mbps: float = 0
    currency: str = "USD"
    overage_enabled: int = 1


class BillingCircuitUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    customer: str | None = None
    if_name: str | None = None
    commit_rate_bps: float | None = None
    burst_limit_bps: float | None = None
    billing_day: int | None = None
    billing_cycle: str | None = None
    cost_per_mbps: float | None = None
    currency: str | None = None
    overage_enabled: int | None = None
    enabled: int | None = None


class BillingGenerateRequest(BaseModel):
    circuit_id: int | None = None
    customer: str | None = None
    period_start: str | None = None
    period_end: str | None = None


# ═════════════════════════════════════════════════════════════════════════════
# 95th Percentile Calculation Engine
# ═════════════════════════════════════════════════════════════════════════════


def calculate_95th_percentile(values: list[float]) -> float:
    """Calculate the 95th percentile using the burstable billing method.

    Standard telco 95th percentile: sort all 5-minute samples, discard top 5%,
    the highest remaining value is the billing rate.
    """
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    idx = int(len(sorted_vals) * 0.95)
    idx = min(idx, len(sorted_vals) - 1)
    return round(sorted_vals[idx], 2)


def _get_billing_period_range(
    billing_day: int,
    billing_cycle: str,
    target_start: str | None = None,
    target_end: str | None = None,
) -> tuple[str, str]:
    """Compute billing period start/end dates.

    If explicit target_start/end given, use those.
    Otherwise compute the most recent completed period.
    """
    if target_start and target_end:
        return target_start, target_end

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    if billing_cycle == "weekly":
        # End of last week
        end = now - timedelta(days=now.weekday())
        end = end.replace(hour=0, minute=0, second=0, microsecond=0)
        start = end - timedelta(days=7)
    else:
        # Monthly: billing day to billing day
        year, month = now.year, now.month
        day = min(billing_day, 28)  # safety for short months

        # Current period boundary
        try:
            current_boundary = datetime(year, month, day)
        except ValueError:
            current_boundary = datetime(year, month, 28)

        if now < current_boundary:
            # We're before this month's billing day → previous period
            end = current_boundary
            if month == 1:
                start = datetime(year - 1, 12, day)
            else:
                try:
                    start = datetime(year, month - 1, day)
                except ValueError:
                    start = datetime(year, month - 1, 28)
        else:
            # We're past this month's billing day → current period ending next month
            start = current_boundary
            if month == 12:
                end = datetime(year + 1, 1, day)
            else:
                try:
                    end = datetime(year, month + 1, day)
                except ValueError:
                    end = datetime(year, month + 1, 28)

            # But the "most recent completed" is the one before
            end = start
            if start.month == 1:
                start = datetime(start.year - 1, 12, day)
            else:
                try:
                    start = datetime(start.year, start.month - 1, day)
                except ValueError:
                    start = datetime(start.year, start.month - 1, 28)

    return (
        start.strftime("%Y-%m-%dT%H:%M:%S"),
        end.strftime("%Y-%m-%dT%H:%M:%S"),
    )


async def generate_billing_for_circuit(
    circuit: dict,
    period_start: str | None = None,
    period_end: str | None = None,
) -> dict:
    """Calculate 95th percentile billing for a single circuit over a period."""
    start, end = _get_billing_period_range(
        circuit["billing_day"],
        circuit["billing_cycle"],
        period_start,
        period_end,
    )

    # Fetch raw samples from interface_ts
    samples = await db.get_billing_samples_for_period(
        circuit["host_id"], circuit["if_index"], start, end,
    )

    if not samples:
        LOGGER.warning(
            "No samples for circuit %s (%s) period %s–%s",
            circuit["id"], circuit["name"], start, end,
        )

    in_values = [s["in_rate_bps"] for s in samples if s.get("in_rate_bps") is not None]
    out_values = [s["out_rate_bps"] for s in samples if s.get("out_rate_bps") is not None]

    p95_in = calculate_95th_percentile(in_values)
    p95_out = calculate_95th_percentile(out_values)
    # Billing uses the greater of in/out (standard burstable billing)
    p95_billing = max(p95_in, p95_out)

    max_in = round(max(in_values), 2) if in_values else 0
    max_out = round(max(out_values), 2) if out_values else 0
    avg_in = round(sum(in_values) / len(in_values), 2) if in_values else 0
    avg_out = round(sum(out_values) / len(out_values), 2) if out_values else 0

    commit = circuit["commit_rate_bps"]
    overage_bps = max(0, p95_billing - commit) if commit > 0 else 0
    cost_per_mbps = circuit["cost_per_mbps"]
    overage_cost = 0.0
    if circuit["overage_enabled"] and overage_bps > 0 and cost_per_mbps > 0:
        overage_mbps = overage_bps / 1_000_000
        overage_cost = round(overage_mbps * cost_per_mbps, 2)

    total_cost = overage_cost  # base cost is external; we track overage

    status = "generated"
    if commit > 0 and p95_billing > commit:
        status = "overage"

    period = await db.create_billing_period(
        circuit_id=circuit["id"],
        period_start=start,
        period_end=end,
        total_samples=len(samples),
        p95_in_bps=p95_in,
        p95_out_bps=p95_out,
        p95_billing_bps=p95_billing,
        max_in_bps=max_in,
        max_out_bps=max_out,
        avg_in_bps=avg_in,
        avg_out_bps=avg_out,
        commit_rate_bps=commit,
        overage_bps=overage_bps,
        overage_cost=overage_cost,
        total_cost=total_cost,
        status=status,
    )

    LOGGER.info(
        "Generated billing period %s for circuit %s: p95=%s bps, status=%s",
        period.get("id"), circuit["id"],
        _format_bps(p95_billing), status,
    )
    return period


def _format_bps(bps: float) -> str:
    """Human-readable bits-per-second formatting."""
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Mbps"
    if bps >= 1_000:
        return f"{bps / 1_000:.2f} Kbps"
    return f"{bps:.0f} bps"


# ═════════════════════════════════════════════════════════════════════════════
# API Endpoints — Billing Circuits
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/api/billing/circuits")
async def list_circuits(
    customer: str | None = Query(default=None),
    host_id: int | None = Query(default=None),
    enabled: bool = Query(default=False),
):
    circuits = await db.list_billing_circuits(customer, host_id, enabled)
    return {"circuits": circuits}


@router.get("/api/billing/circuits/{circuit_id}")
async def get_circuit(circuit_id: int):
    circuit = await db.get_billing_circuit(circuit_id)
    if not circuit:
        raise HTTPException(status_code=404, detail="Circuit not found")
    return circuit


@router.post("/api/billing/circuits", status_code=201)
async def create_circuit(payload: BillingCircuitCreate, request: Request):
    user = getattr(request.state, "user", None) or {}
    owner = user.get("username", "") if isinstance(user, dict) else ""
    circuit = await db.create_billing_circuit(
        name=payload.name,
        host_id=payload.host_id,
        if_index=payload.if_index,
        if_name=payload.if_name,
        customer=payload.customer,
        description=payload.description,
        commit_rate_bps=payload.commit_rate_bps,
        burst_limit_bps=payload.burst_limit_bps,
        billing_day=payload.billing_day,
        billing_cycle=payload.billing_cycle,
        cost_per_mbps=payload.cost_per_mbps,
        currency=payload.currency,
        overage_enabled=payload.overage_enabled,
        created_by=owner,
    )
    await _audit(request, "billing_circuit_created", {
        "circuit_id": circuit["id"], "name": payload.name,
    })
    return circuit


@router.put("/api/billing/circuits/{circuit_id}")
async def update_circuit(circuit_id: int, payload: BillingCircuitUpdate, request: Request):
    existing = await db.get_billing_circuit(circuit_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Circuit not found")
    updates = payload.model_dump(exclude_none=True)
    if not updates:
        return existing
    updated = await db.update_billing_circuit(circuit_id, **updates)
    await _audit(request, "billing_circuit_updated", {
        "circuit_id": circuit_id, "changes": list(updates.keys()),
    })
    return updated


@router.delete("/api/billing/circuits/{circuit_id}")
async def delete_circuit(circuit_id: int, request: Request):
    deleted = await db.delete_billing_circuit(circuit_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Circuit not found")
    await _audit(request, "billing_circuit_deleted", {"circuit_id": circuit_id})
    return {"status": "deleted"}


@router.get("/api/billing/customers")
async def list_customers():
    return {"customers": await db.get_billing_customers()}


# ═════════════════════════════════════════════════════════════════════════════
# API Endpoints — Billing Period Reports
# ═════════════════════════════════════════════════════════════════════════════


@router.post("/api/billing/generate")
async def generate_billing(payload: BillingGenerateRequest, request: Request):
    """Generate 95th percentile billing reports for one or all circuits."""
    results = []

    if payload.circuit_id:
        circuit = await db.get_billing_circuit(payload.circuit_id)
        if not circuit:
            raise HTTPException(status_code=404, detail="Circuit not found")
        if not circuit["enabled"]:
            raise HTTPException(status_code=400, detail="Circuit is disabled")
        period = await generate_billing_for_circuit(
            circuit, payload.period_start, payload.period_end,
        )
        results.append(period)
    else:
        # Generate for all enabled circuits (optionally filtered by customer)
        circuits = await db.list_billing_circuits(
            customer=payload.customer, enabled_only=True,
        )
        for circuit in circuits:
            try:
                period = await generate_billing_for_circuit(
                    circuit, payload.period_start, payload.period_end,
                )
                results.append(period)
            except Exception as exc:
                LOGGER.error("Billing generation failed for circuit %s: %s", circuit["id"], exc)
                results.append({
                    "circuit_id": circuit["id"],
                    "circuit_name": circuit["name"],
                    "error": "generation_failed",
                })

    await _audit(request, "billing_generated", {
        "count": len(results),
        "circuit_id": payload.circuit_id,
        "customer": payload.customer,
    })
    return {"periods": results, "count": len(results)}


@router.get("/api/billing/periods")
async def list_periods(
    circuit_id: int | None = Query(default=None),
    customer: str | None = Query(default=None),
    start_after: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    periods = await db.list_billing_periods(circuit_id, customer, start_after, limit)
    return {"periods": periods}


@router.get("/api/billing/periods/{period_id}")
async def get_period(period_id: int):
    period = await db.get_billing_period(period_id)
    if not period:
        raise HTTPException(status_code=404, detail="Billing period not found")
    return period


@router.delete("/api/billing/periods/{period_id}")
async def delete_period(period_id: int, request: Request):
    deleted = await db.delete_billing_period(period_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Billing period not found")
    await _audit(request, "billing_period_deleted", {"period_id": period_id})
    return {"status": "deleted"}


# ── Usage graph data for a billing period ────────────────────────────────────


@router.get("/api/billing/periods/{period_id}/usage")
async def get_period_usage(period_id: int):
    """Return time-series samples for the billing period (for usage graphs)."""
    period = await db.get_billing_period(period_id)
    if not period:
        raise HTTPException(status_code=404, detail="Billing period not found")

    circuit = await db.get_billing_circuit(period["circuit_id"])
    if not circuit:
        raise HTTPException(status_code=404, detail="Circuit not found")

    samples = await db.get_billing_samples_for_period(
        circuit["host_id"], circuit["if_index"],
        period["period_start"], period["period_end"],
    )

    return {
        "period": period,
        "circuit": circuit,
        "samples": samples,
        "p95_line": period["p95_billing_bps"],
        "commit_line": period["commit_rate_bps"],
    }


# ── CSV exports ──────────────────────────────────────────────────────────────


@router.get("/api/billing/export/periods")
async def export_periods_csv(
    customer: str | None = Query(default=None),
    circuit_id: int | None = Query(default=None),
    limit: int = Query(default=500, ge=1, le=10000),
):
    """Export billing periods as CSV for invoicing."""
    periods = await db.list_billing_periods(circuit_id, customer, limit=limit)
    if not periods:
        return StreamingResponse(
            io.StringIO(""),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=billing_report.csv"},
        )

    fieldnames = [
        "period_start", "period_end", "customer", "circuit_name",
        "hostname", "if_name",
        "p95_in_mbps", "p95_out_mbps", "p95_billing_mbps",
        "avg_in_mbps", "avg_out_mbps", "max_in_mbps", "max_out_mbps",
        "commit_rate_mbps", "overage_mbps", "overage_cost",
        "total_cost", "total_samples", "status",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for p in periods:
        writer.writerow({
            "period_start": p.get("period_start", ""),
            "period_end": p.get("period_end", ""),
            "customer": p.get("customer", ""),
            "circuit_name": p.get("circuit_name", ""),
            "hostname": p.get("hostname", ""),
            "if_name": p.get("if_name", ""),
            "p95_in_mbps": round(p.get("p95_in_bps", 0) / 1_000_000, 4),
            "p95_out_mbps": round(p.get("p95_out_bps", 0) / 1_000_000, 4),
            "p95_billing_mbps": round(p.get("p95_billing_bps", 0) / 1_000_000, 4),
            "avg_in_mbps": round(p.get("avg_in_bps", 0) / 1_000_000, 4),
            "avg_out_mbps": round(p.get("avg_out_bps", 0) / 1_000_000, 4),
            "max_in_mbps": round(p.get("max_in_bps", 0) / 1_000_000, 4),
            "max_out_mbps": round(p.get("max_out_bps", 0) / 1_000_000, 4),
            "commit_rate_mbps": round(p.get("commit_rate_bps", 0) / 1_000_000, 4),
            "overage_mbps": round(p.get("overage_bps", 0) / 1_000_000, 4),
            "overage_cost": p.get("overage_cost", 0),
            "total_cost": p.get("total_cost", 0),
            "total_samples": p.get("total_samples", 0),
            "status": p.get("status", ""),
        })

    csv_data = output.getvalue()
    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=billing_report.csv"},
    )


# ── Billing summary dashboard ────────────────────────────────────────────────


@router.get("/api/billing/summary")
async def billing_summary(customer: str | None = Query(default=None)):
    """High-level billing dashboard statistics."""
    circuits = await db.list_billing_circuits(customer=customer)
    periods = await db.list_billing_periods(customer=customer, limit=500)

    total_circuits = len(circuits)
    enabled_circuits = sum(1 for c in circuits if c.get("enabled"))
    total_periods = len(periods)
    overage_periods = sum(1 for p in periods if p.get("status") == "overage")
    total_overage_cost = sum(p.get("overage_cost", 0) for p in periods)

    # Group by customer
    by_customer: dict[str, dict] = {}
    for p in periods:
        cust = p.get("customer", "Unknown")
        if cust not in by_customer:
            by_customer[cust] = {"periods": 0, "overages": 0, "overage_cost": 0}
        by_customer[cust]["periods"] += 1
        if p.get("status") == "overage":
            by_customer[cust]["overages"] += 1
        by_customer[cust]["overage_cost"] += p.get("overage_cost", 0)

    return {
        "total_circuits": total_circuits,
        "enabled_circuits": enabled_circuits,
        "total_periods": total_periods,
        "overage_periods": overage_periods,
        "total_overage_cost": round(total_overage_cost, 2),
        "by_customer": by_customer,
    }
