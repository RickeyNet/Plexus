"""Credential-isolation regression tests (SECURITY_ENHANCEMENTS.md pass 3).

The IDOR sweep routed every operational endpoint that consumes a
``credential_id`` through ``require_credential_access()`` in
netcontrol/routes/shared.py.  These tests pin the helper's policy matrix so
a refactor can't silently reopen the privilege escalation:

  - user credentials are strictly per-owner (admin role does NOT bypass)
  - unowned credentials are API-token-only
  - service credentials require the allow_service opt-in AND admin context
  - background/queue paths validate against the task submitter, fail closed
  - every allow/deny decision emits a ``credential`` audit event

Plus wiring regressions for endpoints that were found unvalidated after the
initial sweep (compliance remediation).
"""

from __future__ import annotations

import json

import netcontrol.routes.shared as shared
import pytest
from fastapi import HTTPException

# ── Fixtures: fake user/credential store ─────────────────────────────────────

ALICE = {"id": 10, "username": "alice", "role": "user"}
BOB = {"id": 20, "username": "bob", "role": "user"}
ROOT = {"id": 30, "username": "root", "role": "admin"}

CREDS = {
    1: {"id": 1, "owner_id": 10, "is_service": 0, "username": "alice-cred"},
    2: {"id": 2, "owner_id": 20, "is_service": 0, "username": "bob-cred"},
    3: {"id": 3, "owner_id": None, "is_service": 0, "username": "unowned-cred"},
    4: {"id": 4, "owner_id": None, "is_service": 1, "username": "svc-cred"},
}

ALICE_SESSION = {"user_id": 10, "user": "alice"}
BOB_SESSION = {"user_id": 20, "user": "bob"}
ADMIN_SESSION = {"user_id": 30, "user": "root"}
TOKEN_SESSION = {"auth_mode": "token"}


@pytest.fixture
def cred_env(monkeypatch):
    """Point shared.py's db lookups at the in-memory store and capture audits."""
    users_by_id = {u["id"]: u for u in (ALICE, BOB, ROOT)}
    users_by_name = {u["username"]: u for u in (ALICE, BOB, ROOT)}

    async def fake_get_credential_raw(cid):
        return CREDS.get(int(cid)) if cid is not None else None

    async def fake_get_user_by_id(uid):
        return users_by_id.get(int(uid))

    async def fake_get_user_by_username(name):
        return users_by_name.get(name)

    monkeypatch.setattr(shared.db, "get_credential_raw", fake_get_credential_raw)
    monkeypatch.setattr(shared.db, "get_user_by_id", fake_get_user_by_id)
    monkeypatch.setattr(shared.db, "get_user_by_username", fake_get_user_by_username)

    audits: list[dict] = []

    async def fake_audit(category, action, user="", detail="", correlation_id=""):
        audits.append({"category": category, "action": action, "user": user, "detail": detail})

    monkeypatch.setattr(shared, "_audit", fake_audit)
    return audits


async def _expect_denied(status: int, coro):
    with pytest.raises(HTTPException) as exc_info:
        await coro
    assert exc_info.value.status_code == status
    return exc_info.value


# ── Session (HTTP) path ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_owner_can_use_own_credential(cred_env):
    cred = await shared.require_credential_access(1, session=ALICE_SESSION)
    assert cred["id"] == 1
    assert cred_env[-1]["action"] == "use"
    assert cred_env[-1]["user"] == "alice"


@pytest.mark.asyncio
async def test_user_cannot_use_another_users_credential(cred_env):
    await _expect_denied(
        403, shared.require_credential_access(2, session=ALICE_SESSION)
    )
    assert cred_env[-1]["action"] == "use_denied"


@pytest.mark.asyncio
async def test_admin_role_does_not_bypass_ownership(cred_env):
    # Admins manage credentials via the CRUD endpoints, but may not *use*
    # another user's credential for device operations.
    await _expect_denied(
        403, shared.require_credential_access(1, session=ADMIN_SESSION)
    )


@pytest.mark.asyncio
async def test_unowned_credential_denied_for_regular_user(cred_env):
    await _expect_denied(
        403, shared.require_credential_access(3, session=ALICE_SESSION)
    )


@pytest.mark.asyncio
async def test_api_token_bypasses_ownership_with_audit_override(cred_env):
    cred = await shared.require_credential_access(2, session=TOKEN_SESSION)
    assert cred["id"] == 2
    assert cred_env[-1]["action"] == "use"
    assert "override=api-token" in cred_env[-1]["detail"]


@pytest.mark.asyncio
async def test_missing_and_unknown_credential(cred_env):
    await _expect_denied(400, shared.require_credential_access(None, session=ALICE_SESSION))
    await _expect_denied(404, shared.require_credential_access(999, session=ALICE_SESSION))


@pytest.mark.asyncio
async def test_no_session_no_submitter_is_unauthenticated(cred_env):
    await _expect_denied(401, shared.require_credential_access(1))


# ── Service credentials ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_service_credential_requires_opt_in_even_for_admin(cred_env):
    await _expect_denied(
        403, shared.require_credential_access(4, session=ADMIN_SESSION)
    )


@pytest.mark.asyncio
async def test_service_credential_with_opt_in_is_admin_only(cred_env):
    await _expect_denied(
        403,
        shared.require_credential_access(4, session=ALICE_SESSION, allow_service=True),
    )
    cred = await shared.require_credential_access(
        4, session=ADMIN_SESSION, allow_service=True
    )
    assert cred["id"] == 4
    assert "override=admin-service-cred" in cred_env[-1]["detail"]


# ── Submitter (queue/scheduler) path ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_submitter_owner_allowed(cred_env):
    cred = await shared.require_credential_access(1, submitter_username="alice")
    assert cred["id"] == 1
    assert cred_env[-1]["user"] == "alice"


@pytest.mark.asyncio
async def test_submitter_mismatch_fails_closed(cred_env):
    # A queued task submitted by bob may not execute with alice's credential.
    await _expect_denied(
        403, shared.require_credential_access(1, submitter_username="bob")
    )
    assert cred_env[-1]["action"] == "use_denied"


@pytest.mark.asyncio
async def test_deleted_submitter_fails_closed(cred_env):
    await _expect_denied(
        403, shared.require_credential_access(1, submitter_username="ghost")
    )


@pytest.mark.asyncio
async def test_service_credential_requires_admin_submitter(cred_env):
    await _expect_denied(
        403,
        shared.require_credential_access(4, submitter_username="alice", allow_service=True),
    )
    cred = await shared.require_credential_access(
        4, submitter_username="root", allow_service=True
    )
    assert cred["id"] == 4


# ── Endpoint wiring regressions ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_compliance_remediate_validates_credential(monkeypatch):
    """/api/compliance/remediate must route the user-supplied credential_id
    through require_credential_access before touching any device (this
    endpoint was the last unvalidated IDOR path found in pass 3)."""
    import netcontrol.routes.compliance as compliance

    async def fake_scan(_rid):
        return {"host_id": 1, "profile_id": 2, "findings": "[]"}

    async def fake_host(_hid):
        return {"id": 1, "hostname": "sw-01", "ip_address": "10.0.0.1"}

    async def fake_profile(_pid):
        return {"rules": json.dumps([{"name": "r1", "remediation": ["no ip http server"]}])}

    monkeypatch.setattr(compliance.db, "get_compliance_scan_result", fake_scan)
    monkeypatch.setattr(compliance.db, "get_host", fake_host)
    monkeypatch.setattr(compliance.db, "get_compliance_profile", fake_profile)
    monkeypatch.setattr(compliance, "_get_session", lambda _r: dict(ALICE_SESSION))

    captured: dict = {}

    class _Stop(Exception):
        pass

    async def fake_require(credential_id, **kwargs):
        captured["credential_id"] = credential_id
        captured.update(kwargs)
        raise _Stop()

    monkeypatch.setattr(compliance, "require_credential_access", fake_require)

    with pytest.raises(_Stop):
        await compliance.remediate_compliance_finding(
            compliance.ComplianceRemediateRequest(
                result_id=1, rule_name="r1", credential_id=9, dry_run=True
            ),
            request=None,
        )

    assert captured["credential_id"] == 9
    assert captured["session"] == ALICE_SESSION
