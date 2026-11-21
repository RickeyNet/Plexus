"""The feature-permission model (internal security review findings 1, 5 and 9).

- Playbook code (content, type, filename) is written by admins only; a
  write never replaces another playbook's module or a built-in one.
- Ansible jobs run for admins only: launch, retry, rerun and, when the
  queue starts the job, its launcher.
- ``<feature>.write`` gates the mutating routes of the feature routers;
  POST routes that only read stay open to read-only grants.
"""

from __future__ import annotations

import asyncio
import os

import pytest
import routes.database as db
from netcontrol.routes import jobs as jobs_module, playbooks as playbooks_module, state
from routes.crypto import encrypt
from routes.runner import BasePlaybook, LogEvent, register_playbook

from mcp_helpers import CsrfClient, admin_client, user_client

PLAYBOOKS = "/api/playbooks"


@register_playbook
class _PermEcho(BasePlaybook):
    filename = "feature_perm_echo_test.py"
    display_name = "Feature permission echo (test)"
    description = "test only"
    tags: list[str] = []

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield LogEvent(level="info", message="ran")


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


@pytest.fixture
def pb_dir(tmp_path, monkeypatch):
    """Playbook modules are written under a temporary project root."""
    monkeypatch.setattr(playbooks_module, "project_root", str(tmp_path))
    path = tmp_path / "templates" / "playbooks"
    path.mkdir(parents=True)
    return path


def _message(resp) -> str:
    """The error text of an /api error response."""
    return str(resp.json().get("error", {}).get("message", ""))


def _ok(resp, status: int = 200) -> dict:
    assert resp.status_code == status, resp.text
    return resp.json()


# ── Finding 1: playbook code is admin only ──────────────────────────────────


def test_non_admin_cannot_create_or_delete_playbooks(admin, pb_dir):
    writer = user_client(admin, "pb-writer", features=["playbooks", "playbooks.write"])
    body = {"name": "x", "filename": "x", "type": "python", "content": "import os\n"}
    assert writer.post(PLAYBOOKS, json=body).status_code == 403
    assert not (pb_dir / "x.py").exists()
    ansible = {**body, "type": "ansible", "content": "- hosts: localhost\n"}
    assert writer.post(PLAYBOOKS, json=ansible).status_code == 403

    created = _ok(admin.post(PLAYBOOKS, json=body), 201)
    assert (pb_dir / "x.py").read_text() == "import os\n"
    assert writer.delete(f"{PLAYBOOKS}/{created['id']}").status_code == 403
    assert writer.get(f"{PLAYBOOKS}/{created['id']}").status_code == 200
    _ok(admin.delete(f"{PLAYBOOKS}/{created['id']}"))


def test_non_admin_edits_metadata_but_not_code(admin, pb_dir):
    pid = _ok(
        admin.post(PLAYBOOKS, json={"name": "meta", "filename": "meta", "type": "python", "content": "A = 1\n"}),
        201,
    )["id"]
    writer = user_client(admin, "pb-editor", features=["playbooks", "playbooks.write"])
    reader = user_client(admin, "pb-reader", features=["playbooks"])
    url = f"{PLAYBOOKS}/{pid}"

    for change in ({"content": "import os\n"}, {"type": "ansible"}, {"filename": "other"}):
        resp = writer.put(url, json=change)
        assert resp.status_code == 403, change
        assert "admin" in _message(resp)
    assert (pb_dir / "meta.py").read_text() == "A = 1\n"

    # The editor sends every field on save: unchanged code (any line endings) is fine.
    same = {"name": "renamed", "description": "d", "tags": ["t"], "filename": "meta.py", "type": "python"}
    _ok(writer.put(url, json={**same, "content": "A = 1\r\n"}))
    row = _ok(admin.get(url))
    assert (row["name"], row["description"], row["content"]) == ("renamed", "d", "A = 1\n")

    # A read-only grant changes nothing.
    assert reader.put(url, json={"name": "nope"}).status_code == 403
    assert reader.get(PLAYBOOKS).status_code == 200

    # An admin changes the code of the module the row owns.
    _ok(admin.put(url, json={"content": "A = 2\n"}))
    assert (pb_dir / "meta.py").read_text() == "A = 2\n"


def test_writes_never_replace_another_playbooks_module(admin, pb_dir):
    def create(name: str) -> int:
        body = {"name": name, "filename": name, "type": "python", "content": f"N = '{name}'\n"}
        return _ok(admin.post(PLAYBOOKS, json=body), 201)["id"]

    create("first")
    second = create("second")
    # Renaming onto another row's module, or creating over it, is refused.
    assert admin.put(f"{PLAYBOOKS}/{second}", json={"filename": "first"}).status_code == 409
    body = {"name": "dup", "filename": "first", "type": "python", "content": "x = 1\n"}
    assert admin.post(PLAYBOOKS, json=body).status_code == 409
    assert (pb_dir / "first.py").read_text() == "N = 'first'\n"

    # A module on disk with no row (left by a deleted playbook) is not overwritten either.
    (pb_dir / "orphan.py").write_text("ORPHAN = 1\n")
    body = {"name": "orphan", "filename": "orphan", "type": "python", "content": "x = 1\n"}
    assert admin.post(PLAYBOOKS, json=body).status_code == 409
    assert (pb_dir / "orphan.py").read_text() == "ORPHAN = 1\n"

    # Built-in modules are never written, even by an admin editing their row.
    builtin = asyncio.run(db.create_playbook("NTP audit (test row)", "ntp_audit.py"))
    assert admin.put(f"{PLAYBOOKS}/{builtin}", json={"content": "x = 1\n"}).status_code == 409
    body = {"name": "copy", "filename": "ntp_audit", "type": "python", "content": "x = 1\n"}
    assert admin.post(PLAYBOOKS, json=body).status_code == 409
    assert not (pb_dir / "ntp_audit.py").exists()


def test_write_playbook_file_is_exclusive_unless_overwriting(pb_dir):
    playbooks_module.write_playbook_file("fresh", "A = 1\n")
    with pytest.raises(FileExistsError):
        playbooks_module.write_playbook_file("fresh", "A = 2\n")
    playbooks_module.write_playbook_file("fresh", "A = 3\n", overwrite=True)
    assert (pb_dir / "fresh.py").read_text() == "A = 3\n"
    with pytest.raises(FileExistsError):
        playbooks_module.write_playbook_file("vlan1_destroyer", "x = 1\n", overwrite=True)


def test_builtin_playbook_list_matches_the_shipped_modules():
    shipped = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates", "playbooks")
    for name in playbooks_module.BUILTIN_PLAYBOOK_FILES:
        assert os.path.isfile(os.path.join(shipped, name)), name


# ── Finding 5: Ansible jobs are admin only on retry, rerun and in the queue ─


@pytest.fixture
def job_env(admin, monkeypatch):
    async def _no_queue():
        return None

    monkeypatch.setattr(jobs_module, "_process_job_queue", _no_queue)
    runner = user_client(admin, "ansible-runner", features=["jobs", "jobs.write", "playbooks", "playbooks.write"])

    async def _seed() -> dict:
        user = await db.get_user_by_username("ansible-runner")
        cred = await db.create_credential("perm-cred", "dev", encrypt("pw"), owner_id=user["id"])
        group = await db.create_group("perm-group")
        host = await db.add_host(group, "perm-sw1", "192.0.2.41")
        playbook = await db.create_playbook("perm-echo", _PermEcho.filename)
        return {"cred": cred, "host": host, "playbook": playbook}

    ctx = asyncio.run(_seed())
    ctx["runner"] = runner
    return ctx


def test_retry_and_rerun_of_an_ansible_job_need_an_admin(admin, job_env):
    runner = job_env["runner"]
    launch = {"playbook_id": job_env["playbook"], "host_ids": [job_env["host"]], "credential_id": job_env["cred"]}
    job_id = _ok(runner.post("/api/jobs/launch", json=launch), 201)["job_id"]

    async def _turn_into_ansible() -> None:
        await db.finish_job(job_id, status="failed")
        await db.update_playbook(job_env["playbook"], type="ansible", content="- hosts: localhost\n")

    asyncio.run(_turn_into_ansible())
    for action in ("retry", "rerun"):
        resp = runner.post(f"/api/jobs/{job_id}/{action}")
        assert resp.status_code == 403, (action, resp.text)
        assert "admin" in _message(resp)
    assert runner.post("/api/jobs/launch", json=launch).status_code == 403
    _ok(admin.post(f"/api/jobs/{job_id}/retry"), 201)


def test_queue_does_not_start_an_ansible_job_of_a_non_admin(job_env, monkeypatch):
    # An earlier app shutdown (another test's client) leaves the queue draining.
    monkeypatch.setattr(jobs_module, "_shutting_down", False)

    async def _run() -> tuple[dict, list]:
        playbook = await db.create_playbook(
            "perm-ansible", "perm-ansible.yml", content="- hosts: all\n", type="ansible"
        )
        # Top priority, so the queue takes this job before any other queued one.
        job_id = await db.create_job(
            playbook,
            None,
            job_env["cred"],
            None,
            True,
            launched_by="ansible-runner",
            host_ids=[job_env["host"]],
            priority=4,
        )
        # Jobs other tests left queued or running must not hold the queue.
        conn = await db.get_db()
        try:
            await conn.execute(
                "UPDATE jobs SET status = 'cancelled' WHERE status IN ('queued', 'running') AND id <> ?", (job_id,)
            )
            await conn.commit()
        finally:
            await conn.close()
        await jobs_module._process_job_queue_inner()
        return await db.get_job(job_id), await db.get_job_events(job_id, 50)

    job, events = asyncio.run(_run())
    assert job["status"] == "failed"
    assert any("admins only" in (e.get("message") or "") for e in events)


def test_launcher_may_run_checks_the_launchers_role(job_env):
    ansible, python = {"type": "ansible"}, {"type": "python"}
    may = jobs_module._launcher_may_run
    assert asyncio.run(may(python, "ansible-runner")) is True
    assert asyncio.run(may(ansible, "ansible-runner")) is False
    assert asyncio.run(may(ansible, "admin")) is True
    assert asyncio.run(may(ansible, "no-such-user")) is False
    assert asyncio.run(may(ansible, None)) is False


# ── Finding 9: <feature>.write on the feature routers ───────────────────────

# (feature, method, path, body): a mutating route of each converted router.
WRITES = [
    ("templates", "post", "/api/templates", {"name": "t", "content": "x"}),
    ("credentials", "post", "/api/credentials", {"name": "c", "username": "u", "password": "p"}),
    ("jobs", "post", "/api/jobs/launch", {"playbook_id": 1, "host_ids": [1]}),
    ("inventory", "post", "/api/inventory", {"name": "g"}),
    ("inventory", "post", "/api/hosts/bulk-tags", {"host_ids": [1], "tags": ["x"]}),
    ("config-drift", "post", "/api/config-drift/analyze", {"host_id": 1}),
    ("config-drift", "post", "/api/intended-config/generate", {"host_ids": [1]}),
    ("config-backups", "post", "/api/config-backups/restore", {"backup_id": 1}),
    ("compliance", "post", "/api/compliance/scan", {"host_id": 1, "profile_id": 1}),
    ("risk-analysis", "post", "/api/risk-analysis/analyze-offline", {"proposed_commands": ["x"]}),
    ("deployments", "post", "/api/deployments", {"name": "d"}),
    ("graph-templates", "post", "/api/graph-templates", {"name": "g"}),
    ("graph-templates", "post", "/api/cdefs", {"name": "c", "expression": "a"}),
    ("floor-plan", "post", "/api/geo/sites", {"name": "s"}),
    ("upgrades", "post", "/api/upgrades/campaigns", {"name": "c"}),
    ("lab", "post", "/api/lab/environments", {"name": "e"}),
    ("monitoring", "post", "/api/oid-profiles", {"name": "o"}),
    ("monitoring", "post", "/api/baseline-rules", {"name": "b"}),
    ("monitoring", "post", "/api/interface-error-events/1/acknowledge", {}),
    ("playbooks", "put", "/api/playbooks/1", {"name": "p"}),
]


def test_read_only_grants_cannot_write(admin):
    # One user with the read key (and no write key) of every feature.
    reader = user_client(admin, "read-everything", features=sorted({w[0] for w in WRITES}))
    for feature, method, path, body in WRITES:
        resp = getattr(reader, method)(path, json=body)
        assert resp.status_code == 403, (feature, path, resp.text)
        assert f"{feature}.write" in _message(resp), (feature, path)


def test_write_grant_reaches_the_handler(admin):
    writer = user_client(admin, "tpl-writer", features=["templates", "templates.write"])
    _ok(writer.post("/api/templates", json={"name": "perm-template", "content": "hostname x"}), 201)
    inv = user_client(admin, "inv-writer", features=["inventory", "inventory.write"])
    _ok(inv.post("/api/inventory", json={"name": "perm-inv-group"}), 201)


def test_read_only_posts_stay_open_to_read_grants(admin):
    graphs = user_client(admin, "ro-graphs", features=["graph-templates"])
    result = _ok(graphs.post("/api/cdefs/evaluate", json={"expression": "a,2,*", "data": {"a": [1, 2]}}))
    assert result["result"] == [2, 4]

    drift = user_client(admin, "ro-drift", features=["config-drift"])
    _ok(drift.post("/api/intended-config/remediation", json={"host_ids": []}))

    # Approving needs jobs.approve, which is granted without jobs.write: the
    # router lets the request through to the handler (404: no such job), while
    # a write route of the same router is refused.
    approver = user_client(admin, "ro-approver", features=["jobs", "jobs.approve"])
    assert approver.post("/api/jobs/999999/approve", json={}).status_code == 404
    assert approver.post("/api/jobs/999999/deny", json={}).status_code == 404
    assert approver.post("/api/jobs/999999/cancel").status_code == 403
    assert approver.get("/api/jobs").status_code == 200
