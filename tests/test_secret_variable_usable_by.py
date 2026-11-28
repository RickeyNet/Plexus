"""Per-secret "usable by" rule on secret variables.

A secret variable's ``usable_by`` names the user roles and access groups
whose jobs may have it resolved; empty is open (every user who may run the
job). Admins and API token callers always pass; unattended system callers
(``user=None``) apply no rule. A secret the caller may not use reads exactly
like one that does not exist. Checked at launch (template references and
typed secret inputs), at retry and rerun (Run Live), and again against the
launcher when the queue starts the job.
"""

from __future__ import annotations

import asyncio
import json

import pytest
import routes.database as db_module
from netcontrol import job_inputs
from routes.crypto import encrypt
from routes.runner import BasePlaybook, LogEvent, register_playbook
from routes.secret_resolver import SecretResolutionError, may_use_secret, resolve_secrets, secret_rule

SECRET_VALUE = "Usable-By-Value-7"
HOST_IP = "192.0.2.57"


@register_playbook
class _UsableByEcho(BasePlaybook):
    filename = "secret_usable_by_echo_test.py"
    display_name = "Secret usable-by echo (test)"
    description = "test only"
    tags: list[str] = []

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield LogEvent(level="info", message="ran")


# ── Rule helpers ─────────────────────────────────────────────────────────────


def test_normalize_rule_accepts_roles_and_groups_and_refuses_the_rest():
    assert job_inputs.normalize_rule(None) == {"roles": [], "groups": []}
    assert job_inputs.normalize_rule("") == {"roles": [], "groups": []}
    assert job_inputs.normalize_rule('{"roles": ["user", "user"], "groups": [3]}') == {
        "roles": ["user"],
        "groups": [3],
    }
    with pytest.raises(job_inputs.JobInputError) as exc:
        job_inputs.normalize_rule({"roles": ["operator"], "groups": ["x"]}, "usable_by")
    assert set(exc.value.fields) == {"usable_by.roles", "usable_by.groups"}
    with pytest.raises(job_inputs.JobInputError):
        job_inputs.normalize_rule(["user"])


def test_rule_allows_matches_role_or_group_and_admins_always():
    open_rule = {"roles": [], "groups": []}
    by_role = {"roles": ["user"], "groups": []}
    by_group = {"roles": [], "groups": [7]}
    admin_only = {"roles": ["admin"], "groups": []}
    assert job_inputs.rule_allows(open_rule, role="user", group_ids=[])
    assert job_inputs.rule_allows(by_role, role="user", group_ids=[])
    assert job_inputs.rule_allows(by_group, role="user", group_ids=[1, 7])
    assert not job_inputs.rule_allows(by_group, role="user", group_ids=[1])
    assert not job_inputs.rule_allows(admin_only, role="user", group_ids=[7])
    assert job_inputs.rule_allows(admin_only, role="admin", group_ids=[])
    # An unknown user (no role, no groups) passes open rules only.
    assert job_inputs.rule_allows(open_rule, role="", group_ids=[])
    assert not job_inputs.rule_allows(by_role, role="", group_ids=[])


def test_playbook_permissions_still_decide_the_same_way():
    perms = job_inputs.normalize_permissions({"run": {"roles": ["user"]}, "commit": {"groups": [4]}})
    assert job_inputs.is_allowed(perms, "run", role="user", group_ids=[])
    assert not job_inputs.is_allowed(perms, "commit", role="user", group_ids=[])
    assert job_inputs.is_allowed(perms, "commit", role="user", group_ids=[4])
    assert job_inputs.is_allowed(perms, "commit", role="admin", group_ids=[])


def test_stored_rule_damage_reads_as_admin_only():
    assert secret_rule("") == {"roles": [], "groups": []}
    assert secret_rule("not json") == {"roles": ["admin"], "groups": []}
    row = {"usable_by": '{"roles": ["nobody"]}'}
    assert not may_use_secret(row, ("user", []))
    assert may_use_secret(row, ("admin", []))
    # A system caller applies no rule; a row without the column is open.
    assert may_use_secret(row, None)
    assert may_use_secret({}, ("user", []))


# ── HTTP and queue ───────────────────────────────────────────────────────────


def _msg(r) -> str:
    """The message of an /api/ error response (``{ok, error: {code, message}}``)."""
    return r.json()["error"]["message"]


@pytest.fixture
def env(monkeypatch, request):
    import netcontrol.app as app_module
    from netcontrol.routes import jobs as jobs_module
    from starlette.testclient import TestClient

    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    async def _no_queue():
        return None

    # The queue is run by hand.
    monkeypatch.setattr(jobs_module, "_process_job_queue", _no_queue)
    # An earlier app shutdown in this process leaves the queue draining.
    monkeypatch.setattr(jobs_module, "_shutting_down", False)

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))

    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    admin = {"X-CSRF-Token": resp.json().get("csrf_token", "")}
    for name in ("runner", "outsider"):
        r = client.post(
            "/api/admin/users", json={"username": name, "password": "password123", "role": "user"}, headers=admin
        )
        assert r.status_code == 201, r.text

    features = ["jobs", "jobs.write", "playbooks", "playbooks.write", "templates", "templates.write"]

    async def _seed():
        runner = await db_module.get_user_by_username("runner")
        outsider = await db_module.get_user_by_username("outsider")
        runners = await db_module.create_access_group("ub-runners", "", features)
        others = await db_module.create_access_group("ub-others", "", features)
        await db_module.set_user_groups(runner["id"], [runners])
        await db_module.set_user_groups(outsider["id"], [others])
        creds = {
            "runner": await db_module.create_credential("ub-cred", "dev", encrypt("pw"), owner_id=runner["id"]),
            "outsider": await db_module.create_credential("ub-cred2", "dev", encrypt("pw"), owner_id=outsider["id"]),
            "admin": await db_module.create_credential(
                "ub-cred3", "dev", encrypt("pw"), owner_id=(await db_module.get_user_by_username("admin"))["id"]
            ),
        }
        inv = await db_module.create_group("ub-group")
        host = await db_module.add_host(inv, "ub-sw1", HOST_IP, address_confirmed=True)
        rules = {
            "open_key": None,
            "role_key": {"roles": ["user"], "groups": []},
            "group_key": {"roles": [], "groups": [runners]},
            "admin_key": {"roles": ["admin"], "groups": []},
        }
        templates = {}
        for name, rule in rules.items():
            await db_module.create_secret_variable(name, encrypt(SECRET_VALUE), usable_by=rule)
            templates[name] = await db_module.create_template(f"ub-{name}", f"secret {{{{secret.{name}}}}}")
        templates["nope_missing"] = await db_module.create_template("ub-missing", "secret {{secret.nope_missing}}")
        playbook = await db_module.create_playbook(
            "ub-echo", _UsableByEcho.filename, input_schema=[{"name": "key", "type": "secret", "label": "Key"}]
        )
        return {"runners": runners, "creds": creds, "host": host, "templates": templates, "playbook": playbook}

    ctx = asyncio.run(_seed())
    ctx["client"] = client
    ctx["admin"] = admin

    def login(user: str, password: str = "password123") -> dict:
        r = client.post("/api/auth/login", json={"username": user, "password": password})
        assert r.status_code == 200, r.text
        return {"X-CSRF-Token": r.json().get("csrf_token", "")}

    ctx["login"] = login
    return ctx


def _launch(env, user: str, **body):
    headers = env["login"](user) if user != "admin" else env["login"]("admin", "netcontrol")
    cred = env["creds"].get(user, env["creds"]["runner"])
    payload = {"playbook_id": env["playbook"], "credential_id": cred, "host_ids": [env["host"]]}
    payload.update(body)
    return env["client"].post("/api/jobs/launch", json=payload, headers=headers)


def _secret_id(env, name: str) -> int:
    rows = env["client"].get("/api/secret-variables", headers=env["admin"]).json()
    return next(r["id"] for r in rows if r["name"] == name)


def test_api_validates_and_returns_the_rule(env):
    client, admin = env["client"], env["admin"]
    bad = [
        {"roles": ["operator"]},
        {"groups": ["x"]},
        {"groups": [999999]},
    ]
    for rule in bad:
        r = client.post(
            "/api/secret-variables", json={"name": "ub_bad", "value": "v1", "usable_by": rule}, headers=admin
        )
        assert r.status_code == 422, (rule, r.text)
    r = client.post(
        "/api/secret-variables",
        json={"name": "ub_new", "value": "v1", "usable_by": {"roles": ["user"], "groups": [env["runners"]]}},
        headers=admin,
    )
    assert r.status_code == 201, r.text
    var_id = r.json()["id"]
    got = client.get(f"/api/secret-variables/{var_id}", headers=admin).json()
    assert got["usable_by"] == {"roles": ["user"], "groups": [env["runners"]]}
    listed = {row["name"]: row["usable_by"] for row in client.get("/api/secret-variables", headers=admin).json()}
    # A secret created without a rule is open.
    assert listed["open_key"] == {"roles": [], "groups": []}
    assert listed["ub_new"] == got["usable_by"]

    r = client.put(f"/api/secret-variables/{var_id}", json={"usable_by": {"groups": [999999]}}, headers=admin)
    assert r.status_code == 422
    r = client.put(f"/api/secret-variables/{var_id}", json={"usable_by": {"roles": ["admin"]}}, headers=admin)
    assert r.status_code == 200, r.text
    assert client.get(f"/api/secret-variables/{var_id}", headers=admin).json()["usable_by"]["roles"] == ["admin"]
    # An update without the field leaves the rule; {} opens it.
    client.put(f"/api/secret-variables/{var_id}", json={"description": "d"}, headers=admin)
    assert client.get(f"/api/secret-variables/{var_id}", headers=admin).json()["usable_by"]["roles"] == ["admin"]
    client.put(f"/api/secret-variables/{var_id}", json={"usable_by": {}}, headers=admin)
    assert client.get(f"/api/secret-variables/{var_id}", headers=admin).json()["usable_by"] == {
        "roles": [],
        "groups": [],
    }


def test_rule_is_admin_only_to_change(env):
    r = env["client"].put(
        f"/api/secret-variables/{_secret_id(env, 'admin_key')}", json={"usable_by": {}}, headers=env["login"]("runner")
    )
    assert r.status_code == 403


@pytest.mark.parametrize("name", ["open_key", "role_key", "group_key"])
def test_runner_allowed_by_open_rule_role_or_group(env, name):
    r = _launch(env, "runner", template_id=env["templates"][name])
    assert r.status_code == 201, r.text
    r = _launch(env, "runner", inputs={"key": name})
    assert r.status_code == 201, r.text


def test_refusal_reads_like_a_missing_secret(env):
    from netcontrol.routes.jobs import SECRET_UNAVAILABLE

    templates = env["templates"]
    missing = _launch(env, "runner", template_id=templates["nope_missing"])
    refused = _launch(env, "runner", template_id=templates["admin_key"])
    # Not in the runner's access group.
    outsider = _launch(env, "outsider", template_id=templates["group_key"])
    for r in (missing, refused, outsider):
        assert r.status_code == 400, r.text
        assert _msg(r) == _msg(missing)
        assert SECRET_UNAVAILABLE in _msg(r)
    assert "admin_key" not in refused.text and "group_key" not in outsider.text

    missing_in = _launch(env, "runner", inputs={"key": "nope_missing"})
    refused_in = _launch(env, "runner", inputs={"key": "admin_key"})
    outsider_in = _launch(env, "outsider", inputs={"key": "group_key"})
    for r in (missing_in, refused_in, outsider_in):
        assert r.status_code == 422, r.text
        assert r.json()["detail"] == missing_in.json()["detail"]
    assert "does not exist or this job may not use it" in refused_in.json()["detail"]["fields"]["key"]


def test_admin_may_use_every_secret(env):
    r = _launch(env, "admin", template_id=env["templates"]["admin_key"])
    assert r.status_code == 201, r.text
    r = _launch(env, "admin", inputs={"key": "group_key"})
    assert r.status_code == 201, r.text


def test_api_token_and_system_callers_are_not_restricted(env):
    async def _check():
        token_caller = await job_inputs.user_permissions(None)
        assert token_caller == ("admin", [])
        lines = ["secret {{secret.admin_key}}"]
        assert await resolve_secrets(lines, user=token_caller) == [f"secret {SECRET_VALUE}"]
        # Unattended code (SNMP polling) passes no user: no rule applies.
        assert await resolve_secrets(lines) == [f"secret {SECRET_VALUE}"]
        with pytest.raises(SecretResolutionError) as exc:
            await resolve_secrets(lines, user=("user", []))
        assert exc.value.missing == ["admin_key"]
        # An API token launch is stored as "admin": that user is an admin here.
        assert (await job_inputs.launcher_permissions("admin"))[0] == "admin"
        assert await job_inputs.launcher_permissions("nobody") == ("", [])

    asyncio.run(_check())


def _stored_job(env, *, template: str | None = None, params: dict | None = None, status: str = "failed") -> int:
    async def _make():
        job_id = await db_module.create_job(
            env["playbook"],
            None,
            env["creds"]["runner"],
            env["templates"][template] if template else None,
            True,
            launched_by="runner",
            host_ids=[env["host"]],
            parameters=params,
        )
        if status != "queued":
            await db_module.finish_job(job_id, status=status)
        return job_id

    return asyncio.run(_make())


@pytest.mark.parametrize("action", ["retry", "rerun"])
def test_retry_and_rerun_apply_the_rule_to_the_caller(env, action):
    from netcontrol.routes.jobs import SECRET_UNAVAILABLE

    headers = env["login"]("runner")
    client = env["client"]
    for kwargs in ({"template": "admin_key"}, {"params": {"key": "{{secret.admin_key}}"}}):
        job_id = _stored_job(env, **kwargs)
        r = client.post(f"/api/jobs/{job_id}/{action}", headers=headers)
        assert r.status_code == 400, r.text
        assert SECRET_UNAVAILABLE in _msg(r)
        assert "admin_key" not in r.text
    allowed = _stored_job(env, template="group_key")
    r = client.post(f"/api/jobs/{allowed}/{action}", headers=headers)
    assert r.status_code == 201, r.text


def _run_queue_and_events(job_id: int) -> tuple[dict, str]:
    from netcontrol.routes import jobs as jobs_module

    asyncio.run(jobs_module._process_job_queue_inner())
    job = asyncio.run(db_module.get_job(job_id))
    events = asyncio.run(db_module.get_job_events(job_id))
    return job, json.dumps(events)


@pytest.mark.parametrize(
    "kwargs", [{"template": "group_key"}, {"params": {"key": "{{secret.group_key}}"}}], ids=["template", "input"]
)
def test_queue_rechecks_the_launcher_after_the_rule_is_tightened(env, kwargs):
    from netcontrol.routes.jobs import SECRET_UNAVAILABLE

    job_id = _stored_job(env, status="queued", **kwargs)
    r = env["client"].put(
        f"/api/secret-variables/{_secret_id(env, 'group_key')}",
        json={"usable_by": {"roles": ["admin"]}},
        headers=env["admin"],
    )
    assert r.status_code == 200, r.text
    job, events = _run_queue_and_events(job_id)
    assert job["status"] == "failed"
    assert SECRET_UNAVAILABLE in events
    assert "group_key" not in events
    assert SECRET_VALUE not in events


def test_queue_runs_a_job_the_launcher_may_still_use(env):
    job_id = _stored_job(env, template="group_key", status="queued")
    job, events = _run_queue_and_events(job_id)
    assert "Secret variables resolved successfully" in events
    assert job["status"] != "failed", events
    assert SECRET_VALUE not in events


# ── Security check ───────────────────────────────────────────────────────────


def _secret_warnings(env) -> list[str]:
    r = env["client"].get("/api/admin/security-check", headers=env["admin"])
    assert r.status_code == 200, r.text
    return [w for w in r.json()["warnings"] if "secret variable" in w]


def test_security_check_names_the_secrets_left_on_the_open_rule(env):
    (warning,) = _secret_warnings(env)
    assert warning.startswith("1 secret variable(s)") and "open_key" in warning
    # A rule an admin chose raises nothing, "every user" included.
    assert not any(name in warning for name in ("role_key", "group_key", "admin_key"))
    assert SECRET_VALUE not in warning

    r = env["client"].put(
        f"/api/secret-variables/{_secret_id(env, 'open_key')}",
        json={"usable_by": {"roles": ["admin"]}},
        headers=env["admin"],
    )
    assert r.status_code == 200, r.text
    assert _secret_warnings(env) == []

    r = env["client"].get("/api/admin/security-check", headers=env["login"]("runner"))
    assert r.status_code == 403, r.text


def test_security_check_warning_lists_ten_names_and_counts_the_rest(monkeypatch):
    from netcontrol.routes import admin as admin_module

    async def rows():
        return [{"name": f"key_{n:02d}", "usable_by": ""} for n in range(12)] + [
            {"name": "limited", "usable_by": '{"roles": ["admin"], "groups": []}'}
        ]

    monkeypatch.setattr(admin_module.db, "get_all_secret_variables", rows)

    (warning,) = asyncio.run(admin_module._secret_variable_warnings())

    assert warning.startswith("12 secret variable(s)")
    assert "key_09 and 2 more" in warning and "key_10" not in warning and "limited" not in warning
