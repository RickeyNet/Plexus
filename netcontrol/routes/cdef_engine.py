"""
cdef_engine.py -- Calculated Data Sources / CDEFs

Provides:
  - RPN (Reverse Polish Notation) expression evaluator (Cacti-compatible)
  - CDEF CRUD API endpoints
  - Built-in functions: SUM, AVG, MIN, MAX, ABS, PERCENTILE_95, NEGATE
  - Expression evaluation endpoint for testing
"""
from __future__ import annotations


import math
import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.cdef_engine")


# ═════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ═════════════════════════════════════════════════════════════════════════════

class CdefCreate(BaseModel):
    name: str
    description: str = ""
    expression: str

class CdefUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    expression: str | None = None

class CdefEvaluateRequest(BaseModel):
    expression: str
    data: dict[str, list[float]]  # {"a": [1,2,3], "b": [4,5,6]}


# ═════════════════════════════════════════════════════════════════════════════
# RPN Expression Evaluator (Cacti CDEF compatible)
# ═════════════════════════════════════════════════════════════════════════════

def _percentile(values: list[float], pct: float) -> float:
    """Calculate the Nth percentile of a list of values."""
    if not values:
        return 0.0
    sorted_vals = sorted(v for v in values if v is not None and not math.isnan(v))
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = int(k)
    c = f + 1
    if c >= len(sorted_vals):
        return sorted_vals[-1]
    d = k - f
    return sorted_vals[f] + d * (sorted_vals[c] - sorted_vals[f])


def evaluate_cdef_expression(expression: str, data_map: dict[str, list[float]]) -> list[float]:
    """Evaluate a CDEF RPN expression against data series.

    Supports:
      - Variable references: a, b, c, ... (map to data_map keys)
      - Numbers: 8, 100, 1000000
      - Operators: +, -, *, /, %
      - Aggregate functions: SUM, AVG, MIN, MAX, ABS, SQRT, LOG
      - Special: PERCENTILE_95, NEGATE, ADDNAN, UN, ISINF, LIMIT
      - Stack ops: DUP, POP, EXC (exchange top 2)

    RPN format: "a,b,+,8,*" means (a + b) * 8
    """
    expr = expression.strip()

    # Handle single aggregate functions applied to the first data series
    first_key = next(iter(data_map), None)
    first_data = data_map.get(first_key, []) if first_key else []

    if expr == "PERCENTILE_95":
        val = _percentile(first_data, 95)
        return [val] * max(len(first_data), 1)
    if expr == "AVG":
        clean = [v for v in first_data if v is not None and not math.isnan(v)]
        val = sum(clean) / len(clean) if clean else 0.0
        return [val] * max(len(first_data), 1)
    if expr == "MAX":
        clean = [v for v in first_data if v is not None and not math.isnan(v)]
        val = max(clean) if clean else 0.0
        return [val] * max(len(first_data), 1)
    if expr == "MIN":
        clean = [v for v in first_data if v is not None and not math.isnan(v)]
        val = min(clean) if clean else 0.0
        return [val] * max(len(first_data), 1)
    if expr == "SUM":
        clean = [v for v in first_data if v is not None and not math.isnan(v)]
        val = sum(clean)
        return [val] * max(len(first_data), 1)

    # Determine output length (max of all input series)
    max_len = max((len(v) for v in data_map.values()), default=1)
    if max_len == 0:
        max_len = 1

    tokens = [t.strip() for t in expr.split(",") if t.strip()]
    result: list[float] = []

    for i in range(max_len):
        stack: list[float] = []

        for token in tokens:
            # Check if it's a variable reference (single letter or data_map key)
            if token in data_map:
                series = data_map[token]
                val = series[i] if i < len(series) else 0.0
                stack.append(val if val is not None else 0.0)
            elif token.lstrip("-").replace(".", "", 1).isdigit():
                stack.append(float(token))
            elif token == "+":
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    stack.append(a + b)
            elif token == "-":
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    stack.append(a - b)
            elif token == "*":
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    stack.append(a * b)
            elif token == "/":
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    stack.append(a / b if b != 0 else 0.0)
            elif token == "%":
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    stack.append(a % b if b != 0 else 0.0)
            elif token.upper() == "ABS":
                if stack:
                    stack.append(abs(stack.pop()))
            elif token.upper() == "SQRT":
                if stack:
                    v = stack.pop()
                    stack.append(math.sqrt(max(v, 0)))
            elif token.upper() == "LOG":
                if stack:
                    v = stack.pop()
                    stack.append(math.log(v) if v > 0 else 0.0)
            elif token.upper() == "NEGATE":
                if stack:
                    stack.append(-stack.pop())
            elif token.upper() == "DUP":
                if stack:
                    stack.append(stack[-1])
            elif token.upper() == "POP":
                if stack:
                    stack.pop()
            elif token.upper() == "EXC":
                if len(stack) >= 2:
                    stack[-1], stack[-2] = stack[-2], stack[-1]
            elif token.upper() == "UN":
                # Is Unknown? Push 1 if top is NaN, else 0
                if stack:
                    v = stack.pop()
                    stack.append(1.0 if (v is None or math.isnan(v)) else 0.0)
            elif token.upper() == "ISINF":
                if stack:
                    v = stack.pop()
                    stack.append(1.0 if math.isinf(v) else 0.0)
            elif token.upper() == "ADDNAN":
                # Like + but treats NaN as 0
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    a = 0.0 if (a is None or math.isnan(a)) else a
                    b = 0.0 if (b is None or math.isnan(b)) else b
                    stack.append(a + b)
            elif token.upper() == "LIMIT":
                # LIMIT pops upper, lower, value → pushes value if in range, else NaN
                if len(stack) >= 3:
                    upper, lower, val = stack.pop(), stack.pop(), stack.pop()
                    stack.append(val if lower <= val <= upper else float('nan'))
            elif token.upper() == "IF":
                # IF pops b, a, cond → pushes a if cond != 0 else b
                if len(stack) >= 3:
                    b, a, cond = stack.pop(), stack.pop(), stack.pop()
                    stack.append(a if cond != 0 else b)
            else:
                # Unknown token — try as number or skip
                try:
                    stack.append(float(token))
                except ValueError:
                    pass

        result.append(stack[-1] if stack else 0.0)

    return result


# ═════════════════════════════════════════════════════════════════════════════
# API Endpoints
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/api/cdefs")
async def list_cdefs():
    return await db.list_cdef_definitions()


@router.get("/api/cdefs/{cdef_id}")
async def get_cdef(cdef_id: int):
    cdef = await db.get_cdef_definition(cdef_id)
    if not cdef:
        raise HTTPException(404, "CDEF not found")
    return cdef


@router.post("/api/cdefs", status_code=201)
async def create_cdef(body: CdefCreate, request: Request):
    user = getattr(request.state, "user", None)
    username = user.get("username", "") if user else ""
    cdef_id = await db.create_cdef_definition(
        name=body.name,
        expression=body.expression,
        description=body.description,
        created_by=username,
    )
    return {"id": cdef_id}


@router.put("/api/cdefs/{cdef_id}")
async def update_cdef(cdef_id: int, body: CdefUpdate):
    existing = await db.get_cdef_definition(cdef_id)
    if not existing:
        raise HTTPException(404, "CDEF not found")
    if existing.get("built_in"):
        raise HTTPException(403, "Cannot modify built-in CDEF")
    updates = {k: v for k, v in body.dict(exclude_unset=True).items() if v is not None}
    if updates:
        await db.update_cdef_definition(cdef_id, **updates)
    return await db.get_cdef_definition(cdef_id)


@router.delete("/api/cdefs/{cdef_id}")
async def delete_cdef(cdef_id: int):
    existing = await db.get_cdef_definition(cdef_id)
    if not existing:
        raise HTTPException(404, "CDEF not found")
    if existing.get("built_in"):
        raise HTTPException(403, "Cannot delete built-in CDEF")
    await db.delete_cdef_definition(cdef_id)
    return {"deleted": True}


@router.post("/api/cdefs/evaluate")
async def evaluate_cdef(body: CdefEvaluateRequest):
    """Test a CDEF expression against sample data."""
    try:
        result = evaluate_cdef_expression(body.expression, body.data)
        return {"expression": body.expression, "result": result}
    except Exception as exc:
        # Truncate to prevent leaking internal state on unexpected errors
        err_msg = str(exc)[:200]
        raise HTTPException(400, f"Expression evaluation error: {err_msg}")


# ── Data Source Endpoints (SNMP auto-discovered) ──────────────────────────


@router.get("/api/hosts/{host_id}/data-sources")
async def list_data_sources(host_id: int, ds_type: str | None = None):
    return await db.list_snmp_data_sources(host_id, ds_type)


@router.post("/api/hosts/{host_id}/data-sources/discover")
async def discover_data_sources(host_id: int):
    """Trigger SNMP table walk to discover interfaces and storage as data sources."""
    from netcontrol.routes.snmp import auto_discover_data_sources
    import netcontrol.routes.state as state

    host = await db.get_host(host_id)
    if not host:
        raise HTTPException(404, "Host not found")

    snmp_cfg = state._resolve_snmp_discovery_config(host.get("group_id"))
    if not snmp_cfg.get("enabled"):
        raise HTTPException(400, "SNMP not enabled for this host's group")

    result = await auto_discover_data_sources(
        host_id=host_id,
        ip_address=host["ip_address"],
        snmp_config=snmp_cfg,
    )
    return result


@router.put("/api/data-sources/{ds_id}")
async def update_data_source(ds_id: int, request: Request):
    body = await request.json()
    existing = await db.get_snmp_data_source(ds_id)
    if not existing:
        raise HTTPException(404, "Data source not found")
    await db.update_snmp_data_source(ds_id, **body)
    return await db.get_snmp_data_source(ds_id)


@router.delete("/api/data-sources/{ds_id}")
async def delete_data_source(ds_id: int):
    existing = await db.get_snmp_data_source(ds_id)
    if not existing:
        raise HTTPException(404, "Data source not found")
    await db.delete_snmp_data_source(ds_id)
    return {"deleted": True}
