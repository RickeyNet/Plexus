"""POST /api/cdefs/evaluate takes a bounded request and does bounded work.

The evaluator runs on the event loop at one step per token per data point,
so an unbounded expression over an unbounded series froze the server from
one small request.
"""

from __future__ import annotations

import netcontrol.routes.cdef_engine as cdef
import pytest
from fastapi import HTTPException
from pydantic import ValidationError


def test_request_model_bounds_each_dimension():
    ok = cdef.CdefEvaluateRequest(expression="a,b,+,8,*", data={"a": [1, 2], "b": [3, 4]})
    assert ok.data == {"a": [1.0, 2.0], "b": [3.0, 4.0]}

    with pytest.raises(ValidationError):
        cdef.CdefEvaluateRequest(expression="1," * cdef.MAX_EXPRESSION_CHARS, data={"a": [1]})
    with pytest.raises(ValidationError):
        cdef.CdefEvaluateRequest(expression="a", data={"a": [0.0] * (cdef.MAX_EVAL_POINTS + 1)})
    with pytest.raises(ValidationError):
        cdef.CdefEvaluateRequest(expression="a", data={f"s{i}": [1.0] for i in range(cdef.MAX_EVAL_SERIES + 1)})


def test_evaluator_refuses_more_than_the_step_budget():
    points = 1000
    tokens = cdef.MAX_EVAL_STEPS // points + 1
    with pytest.raises(ValueError, match="steps"):
        cdef.evaluate_cdef_expression(",".join(["1"] * tokens), {"a": [0.0] * points})
    # Just inside the budget still evaluates.
    result = cdef.evaluate_cdef_expression("a,8,*", {"a": [1.0] * points})
    assert result == [8.0] * points


async def test_route_answers_400_for_an_over_budget_expression():
    # Every field is inside its own limit; only the product is too large.
    body = cdef.CdefEvaluateRequest(expression=",".join(["a"] * 500), data={"a": [1.0] * 1000})
    with pytest.raises(HTTPException) as exc:
        await cdef.evaluate_cdef(body)
    assert exc.value.status_code == 400
    assert "steps" in exc.value.detail
