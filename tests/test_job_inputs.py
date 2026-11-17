"""Typed job input forms, dry-run/commit mode and per-job permissions.

Covers netcontrol/job_inputs.py (schema rules, value coercion, permission
rules), the playbook schema/permission endpoints, the launch endpoint's
422 per-field errors, the dry-run default, secret redaction on the job
record and in the job log, run/commit permission denial, the admin bypass,
and the dry-run audit of the built-in playbooks.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

import pytest
import routes.database as db_module
from netcontrol import job_inputs
from netcontrol.job_inputs import JobInputError
from routes.crypto import encrypt
from routes.runner import BasePlaybook, LogEvent, get_playbook_class, register_playbook

# ── Test playbooks (registered once at import) ──────────────────────────────


@register_playbook
class _EchoInputs(BasePlaybook):
    """Logs every input, the secret one included, so redaction is visible."""

    filename = "job_inputs_echo_test.py"
    display_name = "Job inputs echo (test)"
    description = "test only"
    tags: list[str] = []

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield LogEvent(level="info", message=f"dry_run={self.dry_run} inputs={json.dumps(self.inputs)}")


@register_playbook
class _NoPreview(BasePlaybook):
    filename = "job_inputs_nopreview_test.py"
    display_name = "Job inputs no preview (test)"
    description = "test only"
    tags: list[str] = []
    supports_dry_run = False

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield LogEvent(level="info", message="ran")


SCHEMA = [
    {"name": "vlan", "type": "integer", "label": "VLAN", "required": True, "min": 2, "max": 4094},
    {"name": "descr", "type": "string", "label": "Description", "regex": "[a-z-]+", "default": "uplink"},
    {"name": "mode", "type": "choice", "label": "Mode", "choices": ["access", "trunk"], "default": "access"},
    {"name": "peer", "type": "ip", "label": "Peer"},
    {"name": "net", "type": "cidr", "label": "Network"},
    {"name": "key", "type": "secret", "label": "Key"},
]


# ── Schema rules ─────────────────────────────────────────────────────────────


def test_schema_reads_legacy_code_types():
    out = job_inputs.normalize_schema(
        [
            {"name": "port", "type": "int", "default": "2055"},
            {"name": "on", "type": "bool", "default": True},
            {"name": "ifs", "type": "list", "default": "Gi0/0, Gi0/1"},
        ]
    )
    assert [f["type"] for f in out] == ["integer", "boolean", "list"]
    assert [f["default"] for f in out] == [2055, True, ["Gi0/0", "Gi0/1"]]
    assert out[0]["label"] == "port"


def test_schema_errors_are_keyed_by_index_and_attribute():
    with pytest.raises(JobInputError) as exc:
        job_inputs.normalize_schema(
            [
                {"name": "ok", "type": "string"},
                {"name": "1bad", "type": "nope"},
                {"name": "pick", "type": "choice"},
                {"name": "pat", "type": "string", "regex": "("},
                {"name": "n", "type": "integer", "min": 5, "max": 1},
                {"name": "d", "type": "integer", "default": "x"},
                {"name": "h", "type": "host", "default": 3},
                {"name": "ok", "type": "string"},
            ]
        )
    fields = exc.value.fields
    assert set(fields) == {"1.name", "1.type", "2.choices", "3.regex", "4.max", "5.default", "6.default", "7.name"}


def test_schema_rejects_non_list_and_too_many_fields():
    with pytest.raises(JobInputError):
        job_inputs.normalize_schema({"name": "x"})
    with pytest.raises(JobInputError):
        job_inputs.normalize_schema("{not json")
    with pytest.raises(JobInputError):
        job_inputs.normalize_schema([{"name": f"f{i}"} for i in range(job_inputs.MAX_FIELDS + 1)])
    assert job_inputs.normalize_schema(None) == []
    assert job_inputs.normalize_schema('[{"name": "a"}]')[0]["type"] == "string"


def test_regex_runs_on_re2_in_linear_time():
    import time

    schema = job_inputs.normalize_schema([{"name": "p", "type": "text", "regex": "(a+)+b"}])
    started = time.monotonic()
    with pytest.raises(JobInputError) as exc:
        job_inputs.validate_inputs(schema, {"p": "a" * 5000 + "c"})
    assert time.monotonic() - started < 2
    assert "required format" in exc.value.fields["p"]


def test_regex_matches_the_whole_value_case_sensitively():
    schema = job_inputs.normalize_schema([{"name": "p", "type": "text", "regex": "[a-z]+|x"}])
    assert job_inputs.validate_inputs(schema, {"p": "abc"})["p"] == "abc"
    for bad in ("abc\n", "ABC", "abc1", "x-"):
        with pytest.raises(JobInputError):
            job_inputs.validate_inputs(schema, {"p": bad})


def test_regex_without_re2_support_is_refused():
    with pytest.raises(JobInputError) as exc:
        job_inputs.normalize_schema([{"name": "p", "type": "string", "regex": "(?=a)a"}])
    assert set(exc.value.fields) == {"0.regex"}
    # A pattern stored before this rule is reported on the field, not raised.
    stored = [{"name": "p", "type": "string", "label": "P", "regex": r"(a)\1"}]
    with pytest.raises(JobInputError) as exc:
        job_inputs.validate_inputs(stored, {"p": "aa"})
    assert "cannot use" in exc.value.fields["p"]


def test_builtin_code_schemas_are_valid():
    import templates.playbooks  # noqa: F401 - registers the built-ins

    cls = get_playbook_class("netflow_enable.py")
    schema = job_inputs.normalize_schema(cls.parameters_schema)
    types = {f["name"]: f["type"] for f in schema}
    assert types["collector_ip"] == "ip"
    assert types["collector_port"] == "integer"


# ── Value coercion ───────────────────────────────────────────────────────────


def test_validate_coerces_each_type():
    schema = job_inputs.normalize_schema(
        SCHEMA
        + [
            {"name": "notes", "type": "text"},
            {"name": "flag", "type": "boolean"},
            {"name": "tags", "type": "multichoice", "choices": ["a", "b", "c"], "max": 2},
            {"name": "ifs", "type": "list"},
            {"name": "host", "type": "host"},
            {"name": "grp", "type": "group"},
        ]
    )
    out = job_inputs.validate_inputs(
        schema,
        {
            "vlan": "120",
            "peer": " 2001:DB8::1 ",
            "net": "198.51.100.0/24",
            "key": "{{secret.snmp_key}}",
            "notes": "line one\nline two",
            "flag": "yes",
            "tags": "a, b, a",
            "ifs": ["Gi0/1", " ", "Gi0/2"],
            "host": "7",
            "grp": {"id": 3},
            "ignored": "x",
        },
    )
    assert out == {
        "vlan": 120,
        "descr": "uplink",
        "mode": "access",
        "peer": "2001:db8::1",
        "net": "198.51.100.0/24",
        "key": "snmp_key",
        "notes": "line one\nline two",
        "flag": True,
        "tags": ["a", "b"],
        "ifs": ["Gi0/1", "Gi0/2"],
        "host": 7,
        "grp": 3,
    }


def test_validate_reports_every_bad_field():
    schema = job_inputs.normalize_schema(SCHEMA)
    with pytest.raises(JobInputError) as exc:
        job_inputs.validate_inputs(
            schema,
            {"vlan": 1, "descr": "Has Caps", "mode": "hybrid", "peer": "192.0.2.300", "net": "192.0.2.0", "key": "!"},
        )
    assert set(exc.value.fields) == {"vlan", "descr", "mode", "peer", "net", "key"}
    assert "at least 2" in exc.value.fields["vlan"]


def test_validate_required_and_defaults():
    schema = job_inputs.normalize_schema(SCHEMA)
    with pytest.raises(JobInputError) as exc:
        job_inputs.validate_inputs(schema, {"vlan": "  "})
    assert exc.value.fields == {"vlan": "VLAN is required."}
    assert job_inputs.validate_inputs(schema, {"vlan": 10}) == {"vlan": 10, "descr": "uplink", "mode": "access"}


def test_validate_rejects_secret_reference_outside_secret_fields():
    schema = job_inputs.normalize_schema([{"name": "descr", "type": "string"}, {"name": "ifs", "type": "list"}])
    with pytest.raises(JobInputError) as exc:
        job_inputs.validate_inputs(schema, {"descr": "x {{secret.k}}", "ifs": ["{{ secret.k }}"]})
    assert set(exc.value.fields) == {"descr", "ifs"}


@pytest.mark.parametrize(
    "field,raw",
    [
        ({"name": "n", "type": "integer"}, "1.5"),
        ({"name": "n", "type": "integer"}, True),
        ({"name": "b", "type": "boolean"}, "maybe"),
        ({"name": "s", "type": "string", "max": 3}, "abcd"),
        ({"name": "s", "type": "string"}, {"x": 1}),
        ({"name": "l", "type": "list"}, 5),
        ({"name": "l", "type": "list", "min": 2}, "one"),
        ({"name": "m", "type": "multichoice", "choices": ["a"]}, ["b"]),
        ({"name": "h", "type": "host"}, "0"),
    ],
)
def test_coerce_rejects_bad_values(field, raw):
    (normalized,) = job_inputs.normalize_schema([field])
    with pytest.raises(ValueError):
        job_inputs.coerce_value(normalized, raw)


# ── Permission rules ─────────────────────────────────────────────────────────


def test_permissions_normalize_and_reject_bad_values():
    assert job_inputs.normalize_permissions(None) == {
        "run": {"roles": [], "groups": []},
        "commit": {"roles": [], "groups": []},
    }
    with pytest.raises(JobInputError) as exc:
        job_inputs.normalize_permissions({"run": {"roles": ["root"], "groups": ["x"]}, "commit": []})
    assert set(exc.value.fields) == {"run.roles", "run.groups", "commit"}


def test_permission_rules():
    open_ = job_inputs.normalize_permissions({})
    assert job_inputs.is_allowed(open_, "commit", role="user", group_ids=[])

    perms = job_inputs.normalize_permissions({"run": {"roles": ["user"]}, "commit": {"groups": [5]}})
    assert job_inputs.is_allowed(perms, "run", role="user", group_ids=[])
    assert not job_inputs.is_allowed(perms, "commit", role="user", group_ids=[1])
    assert job_inputs.is_allowed(perms, "commit", role="user", group_ids=[5])
    # Admins always pass.
    assert job_inputs.is_allowed(perms, "commit", role="admin", group_ids=[])

    # An empty commit rule falls back to the run rule.
    run_only = job_inputs.normalize_permissions({"run": {"groups": [9]}})
    assert job_inputs.effective_rule(run_only, "commit") == {"roles": [], "groups": [9]}
    assert not job_inputs.is_allowed(run_only, "commit", role="user", group_ids=[1])
    assert job_inputs.is_allowed(run_only, "commit", role="user", group_ids=[9])

    # Commit never passes without run.
    commit_only = job_inputs.normalize_permissions({"run": {"groups": [1]}, "commit": {"groups": [2]}})
    assert not job_inputs.is_allowed(commit_only, "commit", role="user", group_ids=[2])


async def test_user_permissions_token_caller_is_admin():
    assert await job_inputs.user_permissions(None) == ("admin", [])


# ── Secret inputs at run time ────────────────────────────────────────────────


async def test_secret_input_resolved_at_run_time_and_scrubbed_from_log():
    from netcontrol.routes import jobs as jobs_module

    await db_module.init_db()
    await db_module.create_secret_variable("snmp_key", encrypt("s3cr3t-value"))
    pb_id = await db_module.create_playbook("echo", _EchoInputs.filename)
    stored = await job_inputs.resolve_references(
        job_inputs.normalize_schema([{"name": "key", "type": "secret"}]), {"key": "snmp_key"}
    )
    assert stored == {"key": "{{secret.snmp_key}}"}
    job_id = await db_module.create_job(pb_id, None, parameters=stored)

    params, redact = await job_inputs.resolve_secret_inputs(stored)
    assert params == {"key": "s3cr3t-value"}
    assert redact == {"s3cr3t-value"}

    await jobs_module._run_job(job_id, _EchoInputs, [], {}, [], True, redact, params)
    events = await db_module.get_job_events(job_id)
    text = " ".join(e["message"] for e in events)
    assert "dry_run=True" in text
    assert "********" in text
    assert "s3cr3t-value" not in text
    job = await db_module.get_job(job_id)
    assert "s3cr3t-value" not in json.dumps(job)


async def test_resolve_references_reports_missing_objects():
    await db_module.init_db()
    schema = job_inputs.normalize_schema(
        [{"name": "h", "type": "host"}, {"name": "g", "type": "group"}, {"name": "k", "type": "secret"}]
    )
    with pytest.raises(JobInputError) as exc:
        await job_inputs.resolve_references(schema, {"h": 99999, "g": 99999, "k": "nope"})
    assert set(exc.value.fields) == {"h", "g", "k"}


# ── Dry-run audit of the built-in playbooks ──────────────────────────────────


class _FakeConn:
    """Records config writes; show commands return output that makes every
    built-in reach its change step (a VLAN 1 access port, an SNMP config)."""

    def __init__(self):
        self.writes: list[str] = []

    def send_command(self, cmd, **_kw):
        if "switchport" in cmd:
            return "Name: Gi0/1\nAdministrative Mode: static access\nAccess Mode VLAN: 1 (default)\n"
        if "engineID" in cmd or "engine" in cmd.lower():
            return "Local SNMP engineID: 800000090300AABBCCDDEEFF"
        return "snmp-server community example RO"

    def send_config_set(self, cmds, **_kw):
        self.writes.append("config")
        return ""

    def save_config(self, *_a, **_kw):
        self.writes.append("save")
        return ""


def _fake_connect(conn):
    @asynccontextmanager
    async def connect(pb, ip, hostname, device_type, credentials):
        yield conn, [pb.log_success(f"Connected to {hostname}", host=hostname)]

    return connect


@pytest.mark.parametrize(
    "filename,params,commands",
    [
        ("netflow_enable.py", {"collector_ip": "192.0.2.10", "collector_port": 2055}, None),
        ("snmpv3_configurator.py", {}, ["snmp-server group EXAMPLE v3 priv"]),
        ("template_configurator.py", {}, ["snmp-server location lab", "ntp server 192.0.2.1"]),
        ("vlan1_destroyer.py", {}, ["switchport access vlan 999"]),
    ],
)
async def test_builtin_playbooks_write_nothing_in_dry_run(monkeypatch, filename, params, commands):
    import importlib

    import templates.playbooks  # noqa: F401
    from routes.runner import execute_playbook

    cls = get_playbook_class(filename)
    assert cls.supports_dry_run is True
    module = importlib.import_module(cls.__module__)
    monkeypatch.setattr(module, "NETMIKO_AVAILABLE", True)
    host = {"id": 1, "hostname": "sw-test", "ip_address": "192.0.2.20", "device_type": "cisco_ios"}

    for dry_run, expect_writes in ((True, False), (False, True)):
        conn = _FakeConn()
        monkeypatch.setattr(module, "connect_device", _fake_connect(conn))
        await execute_playbook(cls, [host], {"username": "u", "password": "p"}, commands, dry_run, None, params)
        assert bool(conn.writes) is expect_writes, (filename, dry_run, conn.writes)


def test_ntp_audit_is_read_only():
    import inspect

    import templates.playbooks  # noqa: F401

    source = inspect.getsource(get_playbook_class("ntp_audit.py"))
    assert "send_config_set" not in source and "save_config" not in source


# ── HTTP: schema endpoints, launch, permissions ──────────────────────────────


def _msg(resp) -> str:
    body = resp.json()
    return (body.get("error") or {}).get("message") or str(body.get("detail") or "")


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

    # Queue only: these tests check what launch records, not the runner.
    monkeypatch.setattr(jobs_module, "_process_job_queue", _no_queue)

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))

    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    admin_csrf = resp.json().get("csrf_token", "")
    r = client.post(
        "/api/admin/users",
        json={"username": "operator", "password": "password123", "role": "user"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert r.status_code == 201, r.text

    async def _seed():
        op = await db_module.get_user_by_username("operator")
        admin = await db_module.get_user_by_username("admin")
        ops_group = await db_module.create_access_group("ops", "", ["jobs", "playbooks"])
        other_group = await db_module.create_access_group("netadmins", "", ["jobs", "playbooks"])
        await db_module.set_user_groups(op["id"], [ops_group])
        op_cred = await db_module.create_credential("op-cred", "dev", encrypt("pw"), owner_id=op["id"])
        admin_cred = await db_module.create_credential("admin-cred", "dev", encrypt("pw"), owner_id=admin["id"])
        inv = await db_module.create_group("ji-group")
        host = await db_module.add_host(inv, "ji-sw1", "192.0.2.21")
        await db_module.create_secret_variable("snmp_key", encrypt("s3cr3t-value"))
        echo = await db_module.create_playbook("echo", _EchoInputs.filename, input_schema=SCHEMA)
        nopreview = await db_module.create_playbook("nopreview", _NoPreview.filename)
        return {
            "ops_group": ops_group,
            "other_group": other_group,
            "op_cred": op_cred,
            "admin_cred": admin_cred,
            "host": host,
            "echo": echo,
            "nopreview": nopreview,
        }

    ctx = asyncio.run(_seed())
    ctx["client"] = client
    ctx["admin_csrf"] = admin_csrf

    def login(user: str, password: str) -> dict:
        resp = client.post("/api/auth/login", json={"username": user, "password": password})
        assert resp.status_code == 200, resp.text
        return {"X-CSRF-Token": resp.json().get("csrf_token", "")}

    ctx["login"] = login
    return ctx


def _launch(ctx, headers, *, cred, playbook=None, **body):
    payload = {"playbook_id": playbook or ctx["echo"], "host_ids": [ctx["host"]], "credential_id": cred}
    payload.update(body)
    return ctx["client"].post("/api/jobs/launch", json=payload, headers=headers)


def _job(job_id: int) -> dict:
    return asyncio.run(db_module.get_job(job_id))


def _set_permissions(ctx, headers, playbook_id, perms):
    r = ctx["client"].put(f"/api/playbooks/{playbook_id}/permissions", json=perms, headers=headers)
    assert r.status_code == 200, r.text


def test_schema_crud_and_form_endpoint(env):
    client = env["client"]
    headers = env["login"]("operator", "password123")

    form = client.get(f"/api/playbooks/{env['echo']}/input-schema").json()
    assert form["source"] == "stored"
    assert [f["name"] for f in form["schema"]] == [f["name"] for f in SCHEMA]
    assert form["supports_dry_run"] is True
    assert form["can_run"] is True and form["can_commit"] is True

    bad = client.put(
        f"/api/playbooks/{env['echo']}/input-schema",
        json={"schema": [{"name": "x", "type": "choice"}]},
        headers=headers,
    )
    assert bad.status_code == 422
    assert bad.json()["detail"]["fields"] == {"0.choices": "A choice field needs at least one choice."}

    ok = client.put(
        f"/api/playbooks/{env['echo']}/input-schema",
        json={"schema": [{"name": "vlan", "type": "int", "required": True}]},
        headers=headers,
    )
    assert ok.status_code == 200, ok.text
    listed = {p["id"]: p for p in client.get("/api/playbooks").json()}
    assert listed[env["echo"]]["input_schema"][0]["type"] == "integer"
    assert listed[env["nopreview"]]["supports_dry_run"] is False

    # Built-in playbooks expose their code schema.
    netflow = next(p for p in listed.values() if p["filename"] == "netflow_enable.py")
    assert netflow["input_schema_source"] == "code"

    # Setting permissions is admin only.
    denied = client.put(f"/api/playbooks/{env['echo']}/permissions", json={"run": {"roles": ["user"]}}, headers=headers)
    assert denied.status_code == 403


def test_launch_validation_returns_422_per_field(env):
    headers = env["login"]("operator", "password123")
    r = _launch(env, headers, cred=env["op_cred"], inputs={"vlan": "x", "peer": "nope", "key": "missing_key"})
    assert r.status_code == 422, r.text
    fields = r.json()["detail"]["fields"]
    assert set(fields) == {"vlan", "peer"}

    # Values valid, but the secret does not exist: the second pass reports it.
    r = _launch(env, headers, cred=env["op_cred"], inputs={"vlan": 10, "key": "missing_key"})
    assert r.status_code == 422
    assert set(r.json()["detail"]["fields"]) == {"key"}


def test_launch_defaults_to_dry_run_and_redacts_secret_on_record(env):
    headers = env["login"]("operator", "password123")
    r = _launch(
        env,
        headers,
        cred=env["op_cred"],
        inputs={"vlan": "120", "key": "{{secret.snmp_key}}", "net": "198.51.100.0/24"},
    )
    assert r.status_code == 201, r.text
    job = _job(r.json()["job_id"])
    assert job["dry_run"] == 1
    params = json.loads(job["parameters"])
    assert params == {
        "vlan": 120,
        "descr": "uplink",
        "mode": "access",
        "net": "198.51.100.0/24",
        "key": "{{secret.snmp_key}}",
    }
    assert "s3cr3t-value" not in json.dumps(job)

    # commit=true runs live; it wins over a legacy dry_run flag.
    r = _launch(env, headers, cred=env["op_cred"], inputs={"vlan": 5}, commit=True, dry_run=True)
    assert r.status_code == 201, r.text
    assert _job(r.json()["job_id"])["dry_run"] == 0


def test_commit_permission_denied_but_dry_run_allowed(env):
    admin_headers = {"X-CSRF-Token": env["admin_csrf"]}
    _set_permissions(env, admin_headers, env["echo"], {"commit": {"groups": [env["other_group"]]}})
    headers = env["login"]("operator", "password123")

    form = env["client"].get(f"/api/playbooks/{env['echo']}/input-schema").json()
    assert form["can_run"] is True and form["can_commit"] is False

    r = _launch(env, headers, cred=env["op_cred"], inputs={"vlan": 5}, commit=True)
    assert r.status_code == 403
    assert "dry run only" in _msg(r)

    r = _launch(env, headers, cred=env["op_cred"], inputs={"vlan": 5})
    assert r.status_code == 201, r.text
    # Re-running that dry run live is a commit too.
    asyncio.run(db_module.finish_job(r.json()["job_id"], "success"))
    rerun = env["client"].post(f"/api/jobs/{r.json()['job_id']}/rerun", headers=headers)
    assert rerun.status_code == 403


def test_run_permission_denied(env):
    admin_headers = {"X-CSRF-Token": env["admin_csrf"]}
    _set_permissions(env, admin_headers, env["echo"], {"run": {"groups": [env["other_group"]]}})
    headers = env["login"]("operator", "password123")
    r = _launch(env, headers, cred=env["op_cred"], inputs={"vlan": 5})
    assert r.status_code == 403
    assert "not allowed to run" in _msg(r)

    # Granting the operator's own group opens it again.
    admin_headers = env["login"]("admin", "netcontrol")
    _set_permissions(env, admin_headers, env["echo"], {"run": {"groups": [env["ops_group"]]}})
    headers = env["login"]("operator", "password123")
    assert _launch(env, headers, cred=env["op_cred"], inputs={"vlan": 5}).status_code == 201


def test_permissions_reject_unknown_access_group(env):
    r = env["client"].put(
        f"/api/playbooks/{env['echo']}/permissions",
        json={"run": {"groups": [987654]}},
        headers={"X-CSRF-Token": env["admin_csrf"]},
    )
    assert r.status_code == 422
    assert "groups" in r.json()["detail"]["fields"]


def test_admin_bypasses_permissions(env):
    admin_headers = {"X-CSRF-Token": env["admin_csrf"]}
    _set_permissions(
        env,
        admin_headers,
        env["echo"],
        {"run": {"groups": [env["other_group"]]}, "commit": {"groups": [env["other_group"]]}},
    )
    r = _launch(env, admin_headers, cred=env["admin_cred"], inputs={"vlan": 5}, commit=True)
    assert r.status_code == 201, r.text
    assert _job(r.json()["job_id"])["dry_run"] == 0


def test_playbook_without_preview_requires_commit(env):
    headers = env["login"]("operator", "password123")
    r = _launch(env, headers, cred=env["op_cred"], playbook=env["nopreview"])
    assert r.status_code == 422
    assert "commit" in r.json()["detail"]["fields"]
    r = _launch(env, headers, cred=env["op_cred"], playbook=env["nopreview"], commit=True)
    assert r.status_code == 201, r.text
