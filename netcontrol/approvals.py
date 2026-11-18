"""
approvals.py -- the shared pieces of Plexus's four-eyes approval workflows.

Deployments (``netcontrol/routes/deployments.py``) and jobs
(``netcontrol/routes/jobs.py``) both hold a change until someone other than
the person who asked for it approves or rejects it. They share the decision
body, the rule that the requester cannot decide their own request, and the
wording of the audit detail, so the two workflows read and behave alike.
"""

from __future__ import annotations

from fastapi import HTTPException
from pydantic import BaseModel, Field

# Longest approval comment accepted (the audit detail keeps the first 80).
APPROVAL_COMMENT_MAX = 2000
_AUDIT_COMMENT_CHARS = 80


class ApprovalDecision(BaseModel):
    """Approve, reject or deny a pending request, with an optional comment."""

    comment: str = Field(default="", max_length=APPROVAL_COMMENT_MAX)


def require_different_approver(approver: str, requester: str | None, *, requester_label: str = "creator") -> None:
    """403 when ``approver`` is the person who asked for the change
    (four-eyes). Self-approval is never allowed, admins included; an empty
    ``approver`` (the server API token) has no identity to compare."""
    if approver and approver == (requester or ""):
        raise HTTPException(status_code=403, detail=f"Approver must be different from {requester_label} (four-eyes)")


def decision_audit_detail(subject: str, comment: str) -> str:
    """The audit detail of an approval decision: ``subject`` plus the start
    of the comment, when there is one."""
    return subject + (f" comment={comment[:_AUDIT_COMMENT_CHARS]}" if comment else "")
