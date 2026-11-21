"""Job approval workflow: a playbook with ``approval_required`` launches jobs
into ``pending_approval``; a holder of ``jobs.approve`` other than the
requester approves (-> queued) or denies (-> denied) them."""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db_module
from netcontrol.approvals import ApprovalDecision, decision_audit_detail, require_different_approver
from routes.crypto import encrypt
from routes.runner import BasePlaybook, LogEvent, register_playbook


@register_playbook
class _ApprovalEcho(BasePlaybook):
    filename = "job_approvals_echo_test.py"
    display_name = "Job approvals echo (test)"
    description = "test only"
    tags: list[str] = []

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield LogEvent(level="info", message="ran")


# ── Shared approval helpers ─────────────────────────────────────────────────


def test_shared_approval_rules():
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        require_different_approver("alice", "alice", requester_label="requester")
    assert exc.value.status_code == 403
    assert "requester" in exc.value.detail
    require_different_approver("bob", "alice")
    # The API token has no user name: nothing to compare.
    require_different_approver("", "alice")
    assert decision_audit_detail("id=7", "") == "id=7"
    assert decision_audit_detail("id=7", "x" * 100) == "id=7 comment=" + "x" * 80
    with pytest.raises(ValueError):
        ApprovalDecision(comment="x" * 2001)


def test_jobs_approve_is_a_feature_key():
    from netcontrol import object_scope
    from netcontrol.routes import state

    assert "jobs.approve" in state.FEATURE_FLAGS
    assert "jobs.approve" in object_scope.SCOPE_ENFORCED_FEATURES


# ── HTTP ─────────────────────────────────────────────────────────────────────


@pytest.fixture
def env(monkeypatch, request):
    import netcontrol.app as app_module
    from netcontrol.routes import jobs as jobs_module
    from starlette.testclient import TestClient

    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    kicks: list[int] = []

    async def _no_queue():
        kicks.append(1)

    # Count queue kicks instead of running jobs: these tests check states.
    monkeypatch.setattr(jobs_module, "_process_job_queue", _no_queue)

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))

    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    admin_csrf = resp.json().get("csrf_token", "")
    for name in ("requester", "approver", "bystander"):
        r = client.post(
            "/api/admin/users",
            json={"username": name, "password": "password123", "role": "user"},
            headers={"X-CSRF-Token": admin_csrf},
        )
        assert r.status_code == 201, r.text

    async def _seed():
        users = {n: await db_module.get_user_by_username(n) for n in ("requester", "approver", "bystander")}
        runners = await db_module.create_access_group(
            "ja-runners", "", ["jobs", "jobs.write", "playbooks", "playbooks.write"]
        )
        approvers = await db_module.create_access_group(
            "ja-approvers", "", ["jobs", "jobs.write", "jobs.approve", "playbooks"]
        )
        await db_module.set_user_groups(users["requester"]["id"], [runners])
        await db_module.set_user_groups(users["bystander"]["id"], [runners])
        await db_module.set_user_groups(users["approver"]["id"], [approvers])
        cred = await db_module.create_credential("ja-cred", "dev", encrypt("pw"), owner_id=users["requester"]["id"])
        inv = await db_module.create_group("ja-group")
        host = await db_module.add_host(inv, "ja-sw1", "192.0.2.31")
        gated = await db_module.create_playbook("ja-gated", _ApprovalEcho.filename, approval_required=True)
        free = await db_module.create_playbook("ja-free", _ApprovalEcho.filename)
        return {"cred": cred, "host": host, "gated": gated, "free": free}

    ctx = asyncio.run(_seed())
    ctx["client"] = client
    ctx["admin"] = {"X-CSRF-Token": admin_csrf}
    ctx["kicks"] = kicks

    def login(user: str, password: str = "password123") -> dict:
        r = client.post("/api/auth/login", json={"username": user, "password": password})
        assert r.status_code == 200, r.text
        return {"X-CSRF-Token": r.json().get("csrf_token", "")}

    ctx["login"] = login
    return ctx


def _launch(ctx, headers, playbook):
    payload = {"playbook_id": playbook, "host_ids": [ctx["host"]], "credential_id": ctx["cred"]}
    return ctx["client"].post("/api/jobs/launch", json=payload, headers=headers)


def _job(job_id: int) -> dict:
    return asyncio.run(db_module.get_job(job_id))


def _pending_job(env) -> int:
    r = _launch(env, env["login"]("requester"), env["gated"])
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "pending_approval"
    return r.json()["job_id"]


def test_launch_of_gated_playbook_waits_for_approval(env):
    kicks_before = len(env["kicks"])
    job_id = _pending_job(env)
    job = _job(job_id)
    assert job["status"] == "pending_approval"
    assert job["approval_status"] == "pending"
    # The queue was not kicked and never picks a pending job.
    assert len(env["kicks"]) == kicks_before
    assert asyncio.run(db_module.get_next_queued_job()) is None
    queue = env["client"].get("/api/jobs/queue").json()
    assert all(j["id"] != job_id for j in queue["jobs"])

    # A playbook without the flag queues as before.
    r = _launch(env, env["login"]("requester"), env["free"])
    assert r.json()["status"] == "queued"
    assert _job(r.json()["job_id"])["approval_status"] == "not_required"


def test_approve_queues_the_job_and_records_the_decision(env):
    job_id = _pending_job(env)
    client = env["client"]
    headers = env["login"]("approver")

    listed = client.get("/api/jobs/approvals").json()
    assert [j["id"] for j in listed] == [job_id]
    assert listed[0]["playbook_name"] == "ja-gated"

    kicks_before = len(env["kicks"])
    r = client.post(f"/api/jobs/{job_id}/approve", json={"comment": "change ticket ok"}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "queued"
    assert len(env["kicks"]) == kicks_before + 1

    job = _job(job_id)
    assert job["status"] == "queued"
    assert job["approval_status"] == "approved"
    assert job["approved_by"] == "approver"
    assert job["approved_at"]
    assert job["approval_comment"] == "change ticket ok"
    assert asyncio.run(db_module.get_next_queued_job())["id"] == job_id

    events = asyncio.run(db_module.get_job_events(job_id))
    assert any("Approved by approver" in e["message"] for e in events)
    audit = asyncio.run(db_module.get_audit_events(limit=20, category="jobs"))
    assert any(e["action"] == "job.approved" and f"id={job_id}" in e["detail"] for e in audit)

    # Decided once only.
    again = client.post(f"/api/jobs/{job_id}/deny", json={}, headers=headers)
    assert again.status_code == 400
    assert client.get("/api/jobs/approvals").json() == []


def test_deny_is_terminal(env):
    job_id = _pending_job(env)
    headers = env["login"]("approver")
    r = env["client"].post(f"/api/jobs/{job_id}/deny", json={"comment": "not in the window"}, headers=headers)
    assert r.status_code == 200, r.text
    job = _job(job_id)
    assert job["status"] == "denied"
    assert job["approval_status"] == "denied"
    assert job["approved_by"] == "approver"
    assert job["approval_comment"] == "not in the window"
    assert job["finished_at"]
    assert asyncio.run(db_module.get_next_queued_job()) is None
    audit = asyncio.run(db_module.get_audit_events(limit=20, category="jobs"))
    assert any(e["action"] == "job.approval_denied" for e in audit)
    # Cancelling a denied job is refused; retrying it asks for approval again.
    requester = env["login"]("requester")
    assert env["client"].post(f"/api/jobs/{job_id}/cancel", headers=requester).status_code == 400
    retry = env["client"].post(f"/api/jobs/{job_id}/retry", headers=requester)
    assert retry.status_code == 201, retry.text
    assert retry.json()["status"] == "pending_approval"


def test_approval_needs_the_permission_and_another_person(env):
    job_id = _pending_job(env)
    client = env["client"]

    # Without jobs.approve: refused, and the list too.
    bystander = env["login"]("bystander")
    assert client.post(f"/api/jobs/{job_id}/approve", json={}, headers=bystander).status_code == 403
    assert client.get("/api/jobs/approvals").status_code == 403

    # The requester cannot approve their own job, even holding jobs.approve.
    async def _grant():
        user = await db_module.get_user_by_username("requester")
        group = await db_module.create_access_group("ja-self", "", ["jobs", "jobs.approve"])
        await db_module.set_user_groups(user["id"], [group])

    asyncio.run(_grant())
    requester = env["login"]("requester")
    r = client.post(f"/api/jobs/{job_id}/approve", json={}, headers=requester)
    assert r.status_code == 403
    assert "four-eyes" in r.text
    # Their own job is not listed as one they may approve.
    assert client.get("/api/jobs/approvals").json() == []
    assert _job(job_id)["status"] == "pending_approval"


def test_admin_cannot_approve_own_job(env):
    async def _admin_cred():
        admin = await db_module.get_user_by_username("admin")
        return await db_module.create_credential("ja-admin", "dev", encrypt("pw"), owner_id=admin["id"])

    cred = asyncio.run(_admin_cred())
    client = env["client"]
    admin = env["login"]("admin", "netcontrol")
    payload = {"playbook_id": env["gated"], "host_ids": [env["host"]], "credential_id": cred}
    r = client.post("/api/jobs/launch", json=payload, headers=admin)
    assert r.status_code == 201, r.text
    job_id = r.json()["job_id"]
    # Self-approval is never allowed, admins included (like deployments).
    denied = client.post(f"/api/jobs/{job_id}/approve", json={}, headers=admin)
    assert denied.status_code == 403
    ok = client.post(f"/api/jobs/{job_id}/approve", json={}, headers=env["login"]("approver"))
    assert ok.status_code == 200, ok.text


def test_cancel_pending_job_and_rerun_rules(env):
    job_id = _pending_job(env)
    requester = env["login"]("requester")
    client = env["client"]
    # Not finished: a live re-run waits for it.
    assert client.post(f"/api/jobs/{job_id}/rerun", headers=requester).status_code == 400
    r = client.post(f"/api/jobs/{job_id}/cancel", headers=requester)
    assert r.status_code == 200, r.text
    assert _job(job_id)["status"] == "cancelled"
    # A cancelled job cannot then be approved.
    approver = env["login"]("approver")
    assert client.post(f"/api/jobs/{job_id}/approve", json={}, headers=approver).status_code == 400
    # A live re-run of a gated job waits for approval again.
    requester = env["login"]("requester")
    rerun = client.post(f"/api/jobs/{job_id}/rerun", headers=requester)
    assert rerun.status_code == 201, rerun.text
    assert rerun.json()["status"] == "pending_approval"


def test_approval_required_flag_is_admin_only(env):
    client = env["client"]
    requester = env["login"]("requester")
    r = client.put(f"/api/playbooks/{env['gated']}", json={"approval_required": False}, headers=requester)
    assert r.status_code == 403
    # Sending the stored value is not a change.
    r = client.put(f"/api/playbooks/{env['gated']}", json={"approval_required": True}, headers=requester)
    assert r.status_code == 200, r.text

    admin = env["login"]("admin", "netcontrol")
    r = client.put(f"/api/playbooks/{env['free']}", json={"approval_required": True}, headers=admin)
    assert r.status_code == 200, r.text
    listed = {p["id"]: p for p in client.get("/api/playbooks").json()}
    assert listed[env["free"]]["approval_required"] is True
    assert client.get(f"/api/playbooks/{env['gated']}").json()["approval_required"] is True
