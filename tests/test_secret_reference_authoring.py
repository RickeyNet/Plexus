"""Who may write a ``{{secret.NAME}}`` reference.

Templates (and their per-device-type variants) and a playbook's input
schema are shared catalogue objects; a job resolves the secrets they name
for whoever runs it, and an admin passes every ``usable_by`` rule. So saving
text that references a secret variable is refused (403) when the saving user
may not use that secret themselves. A name that does not exist reads the
same as a refused one (as at launch), admins and the API token pass, and
saving an unchanged input schema again is not checked.

The first three tests drive the whole path: the non-admin's edit, then an
admin's queued job; the restricted value must never reach the playbook.
"""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db
from routes.crypto import encrypt
from routes.runner import BasePlaybook, LogEvent, register_playbook
from routes.secret_resolver import refused_secret_references

from mcp_helpers import admin_client, user_client

SECRET_VALUE = "Invented-Admin-Only-Value-31"
HOST_IP = "192.0.2.71"
CAPTURED: list[dict] = []


@register_playbook
class _AuthoringCapture(BasePlaybook):
    filename = "secret_authoring_capture_test.py"
    display_name = "Secret authoring capture (test)"
    description = "test only: records what the queue hands the playbook"
    tags: list[str] = []

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        CAPTURED.append(
            {
                "template_commands": list(template_commands or []),
                "by_device_type": {k: list(v) for k, v in (self.template_by_device_type or {}).items()},
                "parameters": dict(self.parameters or {}),
            }
        )
        yield LogEvent(level="info", message="captured")


@pytest.fixture
def env(monkeypatch, request):
    from netcontrol.routes import jobs as jobs_module

    async def _no_queue():
        return None

    monkeypatch.setattr(jobs_module, "_process_job_queue", _no_queue)
    monkeypatch.setattr(jobs_module, "_shutting_down", False)
    CAPTURED.clear()

    admin = admin_client(monkeypatch, request)
    editor = user_client(
        admin,
        "secret-editor",
        features=["templates", "templates.write", "playbooks", "playbooks.write", "jobs", "jobs.write"],
    )
    cred = admin.post("/api/credentials", json={"name": "authoring-admin", "username": "netops", "password": "pw-1"})
    assert cred.status_code == 201, cred.text

    async def _seed():
        group = await db.create_group("authoring-group")
        host = await db.add_host(group, "authoring-sw1", HOST_IP, address_confirmed=True)
        await db.create_secret_variable(
            "admin_key", encrypt(SECRET_VALUE), usable_by={"roles": ["admin"], "groups": []}
        )
        await db.create_secret_variable(
            "user_key", encrypt("Invented-User-Value-8"), usable_by={"roles": ["user"], "groups": []}
        )
        playbook = await db.create_playbook("authoring-capture", _AuthoringCapture.filename)
        template = await db.create_template("authoring-hardening", "hostname authoring-sw1")
        return host, playbook, template

    host, playbook, template = asyncio.run(_seed())
    return {
        "admin": admin,
        "editor": editor,
        "cred": int(cred.json()["id"]),
        "host": host,
        "playbook": playbook,
        "template": template,
    }


def _admin_launch(env, **extra) -> int:
    body = {"playbook_id": env["playbook"], "credential_id": env["cred"], "host_ids": [env["host"]], **extra}
    resp = env["admin"].post("/api/jobs/launch", json=body)
    assert resp.status_code == 201, resp.text
    return int(resp.json()["job_id"])


def _run_queue() -> dict:
    """Start the next queued job and wait for its playbook to finish."""
    from netcontrol.routes import jobs as jobs_module

    async def _go():
        await jobs_module._process_job_queue_inner()
        tasks = list(jobs_module._running_job_tasks.values())
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(_go())
    assert CAPTURED, "the queue did not start the playbook"
    return CAPTURED[-1]


# ── The whole path ───────────────────────────────────────────────────────────


def test_editor_cannot_put_a_restricted_secret_into_an_admins_queued_job(env):
    _admin_launch(env, template_id=env["template"])
    edit = env["editor"].put(
        f"/api/templates/{env['template']}",
        json={"name": "authoring-hardening", "content": "snmp-server community {{secret.admin_key}} RO"},
    )
    assert edit.status_code == 403, edit.text
    assert "admin_key" in edit.text
    captured = _run_queue()
    pushed = "\n".join(captured["template_commands"])
    assert SECRET_VALUE not in pushed


def test_editor_cannot_put_a_restricted_secret_into_a_new_variant(env):
    _admin_launch(env, template_id=env["template"])
    variant = env["editor"].post(
        "/api/templates",
        json={
            "name": "authoring-hardening",
            "content": "snmp-server community {{secret.admin_key}} RO",
            "device_type": "cisco_ios",
        },
    )
    assert variant.status_code == 403, variant.text
    captured = _run_queue()
    pushed = "\n".join(line for body in captured["by_device_type"].values() for line in body)
    pushed += "\n" + "\n".join(captured["template_commands"])
    assert SECRET_VALUE not in pushed


def test_editor_cannot_set_a_restricted_secret_as_an_input_default(env):
    schema = [{"name": "key", "type": "secret", "label": "Key", "default": "admin_key"}]
    put = env["editor"].put(f"/api/playbooks/{env['playbook']}/input-schema", json={"schema": schema})
    assert put.status_code == 403, put.text
    _admin_launch(env)
    captured = _run_queue()
    assert SECRET_VALUE not in captured["parameters"].values()


# ── Further save paths and what still passes ─────────────────────────────────


def test_playbook_update_refuses_a_restricted_secret_default(env):
    schema = [{"name": "key", "type": "secret", "label": "Key", "default": "admin_key"}]
    resp = env["editor"].put(f"/api/playbooks/{env['playbook']}", json={"input_schema": schema})
    assert resp.status_code == 403, resp.text
    stored = asyncio.run(db.get_playbook(env["playbook"]))
    assert not stored.get("input_schema")


def test_admin_may_save_any_reference_and_the_editor_may_resave_the_schema_unchanged(env):
    schema = [{"name": "key", "type": "secret", "label": "Key", "default": "admin_key"}]
    put = env["admin"].put(f"/api/playbooks/{env['playbook']}/input-schema", json={"schema": schema})
    assert put.status_code == 200, put.text
    saved = env["admin"].get(f"/api/playbooks/{env['playbook']}/input-schema").json()["schema"]
    # The playbook editor sends every field on save: an unchanged schema passes.
    resp = env["editor"].put(f"/api/playbooks/{env['playbook']}", json={"description": "new", "input_schema": saved})
    assert resp.status_code == 200, resp.text
    tpl = env["admin"].put(
        f"/api/templates/{env['template']}",
        json={"name": "authoring-hardening", "content": "snmp-server community {{secret.admin_key}} RO"},
    )
    assert tpl.status_code == 200, tpl.text
    # A template holding a reference the editor may not use cannot be saved by them.
    again = env["editor"].put(
        f"/api/templates/{env['template']}",
        json={"name": "authoring-hardening", "content": "snmp-server community {{secret.admin_key}} RW"},
    )
    assert again.status_code == 403, again.text


def test_editor_may_reference_a_secret_their_rule_allows(env):
    allowed = env["editor"].post(
        "/api/templates",
        json={"name": "authoring-allowed", "content": "snmp-server community {{secret.user_key}} RO"},
    )
    assert allowed.status_code == 201, allowed.text
    schema = [{"name": "key", "type": "secret", "label": "Key", "default": "user_key"}]
    put = env["editor"].put(f"/api/playbooks/{env['playbook']}/input-schema", json={"schema": schema})
    assert put.status_code == 200, put.text


def test_a_missing_name_and_a_refused_one_read_the_same(env):
    """The answer to a save does not tell a non-admin which restricted
    names exist; an admin may name a secret that is yet to be created."""

    def _save(client, name: str, secret: str):
        return client.post("/api/templates", json={"name": name, "content": f"key {{{{secret.{secret}}}}}"})

    refused = _save(env["editor"], "authoring-refused", "admin_key")
    missing = _save(env["editor"], "authoring-missing", "no_such_secret")
    assert refused.status_code == missing.status_code == 403
    assert refused.text.replace("admin_key", "NAME") == missing.text.replace("no_such_secret", "NAME")
    assert _save(env["admin"], "authoring-admin-missing", "no_such_secret").status_code == 201


def test_refused_secret_references(env):
    async def _check():
        texts = ["a {{secret.admin_key}} b {{ secret.user_key }}", "{{secret.no_such_secret}}"]
        assert await refused_secret_references(texts, ("user", [])) == ["admin_key", "no_such_secret"]
        assert await refused_secret_references([], ("user", []), names=["admin_key", "user_key"]) == ["admin_key"]
        assert await refused_secret_references(texts, ("admin", [])) == []
        assert await refused_secret_references(texts, None) == []
        # A caller with no role (no session) passes open rules only.
        assert await refused_secret_references(texts, ("", [])) == ["admin_key", "no_such_secret", "user_key"]

    asyncio.run(_check())
