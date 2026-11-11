"""Host compliance scans run as background jobs.

``POST /api/compliance/scan-bulk`` and
``POST /api/compliance/assignments/{id}/scan-now`` validate in the request
(profile, credential ownership, hosts), then return ``202 {job_id}``; the
scan runs in the background and is polled at
``GET /api/compliance/scans/{job_id}``. Device I/O is replaced by patching
``_evaluate_host_compliance``.
"""

from __future__ import annotations

import asyncio
import threading

import netcontrol.app as app_module
import netcontrol.routes.compliance as compliance_module
import pytest
import routes.database as db_module
from netcontrol.routes import background_jobs


class _CsrfClient:
    def __init__(self, client, csrf):
        self._c, self._headers = client, {"X-CSRF-Token": csrf}

    def get(self, url, **kw):
        return self._c.get(url, **kw)

    def post(self, url, **kw):
        return self._c.post(url, headers=self._headers, **kw)


def _err_message(resp) -> str:
    body = resp.json()
    return (body.get("error") or {}).get("message") or body.get("detail") or ""


async def _seed() -> dict:
    admin = await db_module.get_user_by_username("admin")
    cred = await db_module.create_credential("scan-cred", "scanuser", "x", owner_id=admin["id"])
    unowned_cred = await db_module.create_credential("unowned-cred", "nobody", "x")
    group_id = await db_module.create_group("scan-group")
    empty_group_id = await db_module.create_group("scan-empty-group")
    host_ids = [
        await db_module.add_host(group_id, f"scan-sw{i}", f"192.0.2.{10 + i}") for i in range(1, 4)
    ]
    profile_id = await db_module.create_compliance_profile("scan-profile", rules="[]")
    assignment_id = await db_module.create_compliance_assignment(profile_id, group_id, cred)
    empty_assignment_id = await db_module.create_compliance_assignment(profile_id, empty_group_id, cred)
    # The credential check runs before the host lookup, so its group may be empty.
    other_group_id = await db_module.create_group("scan-other-group")
    unowned_assignment_id = await db_module.create_compliance_assignment(profile_id, other_group_id, unowned_cred)
    return {
        "cred": cred,
        "unowned_cred": unowned_cred,
        "host_ids": host_ids,
        "profile_id": profile_id,
        "assignment_id": assignment_id,
        "empty_assignment_id": empty_assignment_id,
        "unowned_assignment_id": unowned_assignment_id,
    }


@pytest.fixture
def scan_env(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-compliance-scan-jobs")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    compliance_module._running_assignment_scans.clear()

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    assert resp.status_code == 200, resp.text
    ctx = asyncio.run(_seed())
    ctx["api"] = _CsrfClient(client, resp.json().get("csrf_token", ""))
    return ctx


def _fake_evaluator(monkeypatch, *, fail_hostname: str | None = None, gate: threading.Event | None = None):
    """Patch the device evaluator: ``scan-sw1`` passes, the rest fail one rule.

    ``fail_hostname`` raises instead; with ``gate``, every host but the
    first waits until the gate is set.
    """

    async def fake(host, profile, credentials, **_kw):
        if gate is not None and host["hostname"] != "scan-sw1":
            # The gate is set from the test thread, not the app's event loop.
            await asyncio.to_thread(gate.wait, 30)
        if host["hostname"] == fail_hostname:
            raise RuntimeError("simulated connection failure")
        ok = host["hostname"] == "scan-sw1"
        return {
            "status": "compliant" if ok else "non-compliant",
            "total_rules": 2,
            "passed_rules": 2 if ok else 1,
            "failed_rules": 0 if ok else 1,
            "findings": "[]",
            "config_snippet": "",
        }

    monkeypatch.setattr(compliance_module, "_evaluate_host_compliance", fake)


def _wait_for_job(api, job_id: str) -> dict:
    job: dict = {}
    for _ in range(400):
        resp = api.get(f"/api/compliance/scans/{job_id}")
        assert resp.status_code == 200, resp.text
        job = resp.json()
        if job["status"] != "running":
            break
        threading.Event().wait(0.01)
    return job


def _audit_actions() -> list[dict]:
    return asyncio.run(db_module.get_audit_events(limit=50, category="compliance"))


def test_bulk_scan_returns_job_and_completes_with_results(scan_env, monkeypatch):
    _fake_evaluator(monkeypatch)
    api = scan_env["api"]
    started = api.post(
        "/api/compliance/scan-bulk",
        json={"profile_id": scan_env["profile_id"], "credential_id": scan_env["cred"], "host_ids": scan_env["host_ids"]},
    )
    assert started.status_code == 202, started.text
    body = started.json()
    assert body["status"] == "running" and body["job_id"]

    job = _wait_for_job(api, body["job_id"])
    assert job["status"] == "completed", job
    assert job["kind"] == "compliance-scan"
    progress = job["progress"]
    assert progress == {
        "hosts_total": 3,
        "hosts_done": 3,
        "violations": 2,
        "errors": 0,
        "profile_id": scan_env["profile_id"],
        "profile_name": "scan-profile",
        "assignment_id": None,
    }
    result = job["result"]
    assert result["hosts_scanned"] == 3 and result["violations"] == 2 and result["errors"] == 0
    assert "assignment_id" not in result
    rows = {r["hostname"]: r for r in result["results"]}
    assert set(rows) == {"scan-sw1", "scan-sw2", "scan-sw3"}
    assert rows["scan-sw1"]["status"] == "compliant" and rows["scan-sw1"]["passed_rules"] == 2
    assert rows["scan-sw2"]["status"] == "non-compliant" and rows["scan-sw2"]["failed_rules"] == 1
    for row in result["results"]:
        assert set(row) == {
            "host_id",
            "hostname",
            "status",
            "passed_rules",
            "failed_rules",
            "total_rules",
            "result_id",
        }
        assert isinstance(row["result_id"], int)

    audit = [e for e in _audit_actions() if e["action"] == "scan.bulk"]
    assert audit and "hosts_scanned=3" in audit[0]["detail"] and "scope=selected" in audit[0]["detail"]
    assert audit[0]["user"] == "admin"


def test_bulk_scan_counts_host_exception_as_error(scan_env, monkeypatch):
    _fake_evaluator(monkeypatch, fail_hostname="scan-sw2")
    api = scan_env["api"]
    started = api.post(
        "/api/compliance/scan-bulk",
        json={
            "profile_id": scan_env["profile_id"],
            "credential_id": scan_env["cred"],
            "host_ids": scan_env["host_ids"][:2],
        },
    )
    assert started.status_code == 202, started.text
    job = _wait_for_job(api, started.json()["job_id"])
    assert job["status"] == "completed", job
    assert job["error"] is None
    result = job["result"]
    assert result["hosts_scanned"] == 2 and result["errors"] == 1 and result["violations"] == 0
    failed = next(r for r in result["results"] if r["hostname"] == "scan-sw2")
    assert failed["status"] == "error" and failed["result_id"] is None and failed["total_rules"] == 0
    assert job["progress"]["errors"] == 1 and job["progress"]["hosts_done"] == 2


def test_scan_now_reports_progress_refuses_overlap_and_completes(scan_env, monkeypatch):
    gate = threading.Event()
    _fake_evaluator(monkeypatch, gate=gate)
    api = scan_env["api"]
    assignment_id = scan_env["assignment_id"]

    started = api.post(f"/api/compliance/assignments/{assignment_id}/scan-now")
    assert started.status_code == 202, started.text
    job_id = started.json()["job_id"]
    assert started.json()["status"] == "running"

    try:
        # The first host finishes; the others wait on the gate.
        job: dict = {}
        for _ in range(400):
            job = api.get(f"/api/compliance/scans/{job_id}").json()
            if job["progress"]["hosts_done"] >= 1:
                break
            threading.Event().wait(0.01)
        assert job["status"] == "running"
        assert job["progress"]["hosts_done"] == 1 and job["progress"]["hosts_total"] == 3
        assert job["progress"]["assignment_id"] == assignment_id

        again = api.post(f"/api/compliance/assignments/{assignment_id}/scan-now")
        assert again.status_code == 409, again.text
    finally:
        gate.set()

    job = _wait_for_job(api, job_id)
    assert job["status"] == "completed", job
    result = job["result"]
    assert result["assignment_id"] == assignment_id
    assert result["hosts_scanned"] == 3 and result["violations"] == 2 and result["errors"] == 0
    assert len(result["results"]) == 3

    assignment = asyncio.run(db_module.get_compliance_assignment(assignment_id))
    assert assignment["last_scan_at"]
    audit = [e for e in _audit_actions() if e["action"] == "assignment.scan_now"]
    assert audit and f"assignment_id={assignment_id}" in audit[0]["detail"]

    # The guard is released once the job finishes.
    rerun = api.post(f"/api/compliance/assignments/{assignment_id}/scan-now")
    assert rerun.status_code == 202, rerun.text
    assert _wait_for_job(api, rerun.json()["job_id"])["status"] == "completed"


def test_unknown_and_meraki_job_ids_are_404(scan_env):
    api = scan_env["api"]
    missing = api.get("/api/compliance/scans/nope")
    assert missing.status_code == 404
    assert _err_message(missing) == "Scan job not found (it may have expired)"

    meraki_job = background_jobs.create_job("meraki-compliance-scan")
    assert api.get(f"/api/compliance/scans/{meraki_job['job_id']}").status_code == 404
    host_job = background_jobs.create_job("compliance-scan")
    assert api.get(f"/api/compliance/meraki/scans/{host_job['job_id']}").status_code == 404
    assert api.get(f"/api/compliance/scans/{host_job['job_id']}").status_code == 200


def test_validation_errors_are_returned_synchronously(scan_env, monkeypatch):
    _fake_evaluator(monkeypatch)
    api = scan_env["api"]
    bulk = "/api/compliance/scan-bulk"

    unknown_profile = api.post(bulk, json={"profile_id": 999999, "credential_id": scan_env["cred"]})
    assert unknown_profile.status_code == 404

    no_hosts = api.post(
        bulk,
        json={"profile_id": scan_env["profile_id"], "credential_id": scan_env["cred"], "host_ids": [999999]},
    )
    assert no_hosts.status_code == 400 and _err_message(no_hosts) == "No hosts found to scan"

    denied = api.post(bulk, json={"profile_id": scan_env["profile_id"], "credential_id": scan_env["unowned_cred"]})
    assert denied.status_code == 403
    missing_cred = api.post(bulk, json={"profile_id": scan_env["profile_id"], "credential_id": 999999})
    assert missing_cred.status_code == 404 and _err_message(missing_cred) == "Credential not found"

    assert api.post("/api/compliance/assignments/999999/scan-now").status_code == 404
    empty = api.post(f"/api/compliance/assignments/{scan_env['empty_assignment_id']}/scan-now")
    assert empty.status_code == 400 and _err_message(empty) == "No hosts in the assigned group"
    denied_now = api.post(f"/api/compliance/assignments/{scan_env['unowned_assignment_id']}/scan-now")
    assert denied_now.status_code == 403
    # A rejected scan-now leaves no overlap guard behind.
    assert scan_env["unowned_assignment_id"] not in compliance_module._running_assignment_scans
