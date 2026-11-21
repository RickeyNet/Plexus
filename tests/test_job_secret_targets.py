"""Secret variables and ad-hoc job targets (security audit finding 17).

A job whose template or inputs use secret variables may target an ad-hoc
address only for an admin, unless the address is an inventory host the
launcher may change. Checked at launch, retry, rerun and when the queue
starts the job. A secret that does not exist answers with one generic
message (no name), and job output scrubbing also masks the common
encodings of each secret value.
"""

from __future__ import annotations

import asyncio
import base64
import json
from urllib.parse import quote, quote_plus

import pytest
import routes.database as db_module
from routes.crypto import encrypt
from routes.runner import BasePlaybook, LogEvent, register_playbook
from routes.secret_resolver import MIN_REDACT_LENGTH, redact_values, redaction_forms

SECRET_VALUE = "Sup3r Secret/Key+1"
INVENTORY_IP = "192.0.2.41"
AD_HOC_IP = "203.0.113.9"


@register_playbook
class _SecretTargetsEcho(BasePlaybook):
    filename = "job_secret_targets_echo_test.py"
    display_name = "Job secret targets echo (test)"
    description = "test only"
    tags: list[str] = []

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield LogEvent(level="info", message="ran")


# ── Output scrubbing ─────────────────────────────────────────────────────────


def test_redaction_masks_common_encodings():
    raw = SECRET_VALUE.encode()
    b64 = base64.b64encode(raw).decode()
    encodings = [
        SECRET_VALUE,
        b64,
        b64.rstrip("="),
        base64.urlsafe_b64encode(raw).decode(),
        quote(SECRET_VALUE, safe=""),
        quote_plus(SECRET_VALUE),
        raw.hex(),
    ]
    for encoded in encodings:
        text = f"device said: {encoded} (end)"
        out = redact_values(text, {SECRET_VALUE})
        assert encoded not in out, encoded
        assert out == "device said: ******** (end)"


def test_redaction_skips_values_shorter_than_the_minimum():
    assert MIN_REDACT_LENGTH == 4
    assert redaction_forms("abc") == set()
    # A three-character value is not blanked all over the log.
    assert redact_values("vlan abc abc", {"abc"}) == "vlan abc abc"
    # Four characters is enough.
    assert redact_values("key abcd", {"abcd"}) == "key ********"
    assert all(len(form) >= MIN_REDACT_LENGTH for form in redaction_forms("abcd"))


def test_redaction_masks_the_longer_form_whole():
    # The base64 form contains no other form; the longest-first order means
    # neither is left half masked.
    value = "AAAAAAAA"
    out = redact_values(f"x {base64.b64encode(value.encode()).decode()} y {value}", {value})
    assert out == "x ******** y ********"


# ── HTTP ─────────────────────────────────────────────────────────────────────


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

    # These tests check what launch accepts; the queue is run by hand.
    monkeypatch.setattr(jobs_module, "_process_job_queue", _no_queue)

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))

    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    admin_csrf = resp.json().get("csrf_token", "")
    r = client.post(
        "/api/admin/users",
        json={"username": "runner", "password": "password123", "role": "user"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert r.status_code == 201, r.text

    async def _seed():
        runner = await db_module.get_user_by_username("runner")
        admin = await db_module.get_user_by_username("admin")
        group = await db_module.create_access_group(
            "st-runners", "", ["jobs", "jobs.write", "playbooks", "playbooks.write", "templates", "templates.write"]
        )
        await db_module.set_user_groups(runner["id"], [group])
        runner_cred = await db_module.create_credential("st-cred", "dev", encrypt("pw"), owner_id=runner["id"])
        admin_cred = await db_module.create_credential("st-admin-cred", "dev", encrypt("pw"), owner_id=admin["id"])
        inv = await db_module.create_group("st-group")
        host = await db_module.add_host(inv, "st-sw1", INVENTORY_IP)
        await db_module.create_secret_variable("core_key", encrypt(SECRET_VALUE))
        uses_secret = await db_module.create_template("st-secret", "username x secret {{secret.core_key}}")
        missing_secret = await db_module.create_template("st-missing", "username x secret {{secret.nope_missing}}")
        plain = await db_module.create_template("st-plain", "show version")
        playbook = await db_module.create_playbook(
            "st-echo",
            _SecretTargetsEcho.filename,
            input_schema=[{"name": "key", "type": "secret", "label": "Key"}],
        )
        return {
            "runner_cred": runner_cred,
            "admin_cred": admin_cred,
            "host": host,
            "uses_secret": uses_secret,
            "missing_secret": missing_secret,
            "plain": plain,
            "playbook": playbook,
        }

    ctx = asyncio.run(_seed())
    ctx["client"] = client
    ctx["admin"] = {"X-CSRF-Token": admin_csrf}

    def login(user: str, password: str = "password123") -> dict:
        r = client.post("/api/auth/login", json={"username": user, "password": password})
        assert r.status_code == 200, r.text
        return {"X-CSRF-Token": r.json().get("csrf_token", "")}

    ctx["login"] = login
    return ctx


def _launch(ctx, headers, *, cred, **body):
    payload = {"playbook_id": ctx["playbook"], "credential_id": cred}
    payload.update(body)
    return ctx["client"].post("/api/jobs/launch", json=payload, headers=headers)


def test_non_admin_may_not_send_template_secrets_to_an_ad_hoc_address(env):
    headers = env["login"]("runner")
    r = _launch(env, headers, cred=env["runner_cred"], template_id=env["uses_secret"], ad_hoc_ips=[AD_HOC_IP])
    assert r.status_code == 403, r.text
    detail = _msg(r)
    assert AD_HOC_IP in detail and "admin" in detail

    # A secret that does not exist gets the same refusal: no name oracle.
    r2 = _launch(env, headers, cred=env["runner_cred"], template_id=env["missing_secret"], ad_hoc_ips=[AD_HOC_IP])
    assert r2.status_code == 403
    assert _msg(r2) == detail


def test_non_admin_may_not_send_secret_inputs_to_an_ad_hoc_address(env):
    headers = env["login"]("runner")
    r = _launch(env, headers, cred=env["runner_cred"], ad_hoc_ips=[AD_HOC_IP], inputs={"key": "core_key"})
    assert r.status_code == 403, r.text
    r2 = _launch(env, headers, cred=env["runner_cred"], ad_hoc_ips=[AD_HOC_IP], inputs={"key": "nope_missing"})
    assert r2.status_code == 403
    assert _msg(r2) == _msg(r)


def test_non_admin_ad_hoc_without_secrets_or_to_an_inventory_address_is_allowed(env):
    headers = env["login"]("runner")
    r = _launch(env, headers, cred=env["runner_cred"], template_id=env["plain"], ad_hoc_ips=[AD_HOC_IP])
    assert r.status_code == 201, r.text
    # The ad-hoc address is an inventory host the runner may change.
    r = _launch(env, headers, cred=env["runner_cred"], template_id=env["uses_secret"], ad_hoc_ips=[INVENTORY_IP])
    assert r.status_code == 201, r.text
    # Inventory targets carry secrets as before.
    r = _launch(env, headers, cred=env["runner_cred"], template_id=env["uses_secret"], host_ids=[env["host"]])
    assert r.status_code == 201, r.text


def test_admin_may_send_secrets_to_an_ad_hoc_address(env):
    r = _launch(
        env,
        env["login"]("admin", "netcontrol"),
        cred=env["admin_cred"],
        template_id=env["uses_secret"],
        ad_hoc_ips=[AD_HOC_IP],
    )
    assert r.status_code == 201, r.text


def test_missing_secret_message_is_generic(env):
    from netcontrol.routes.jobs import SECRET_UNAVAILABLE

    headers = env["login"]("runner")
    r = _launch(env, headers, cred=env["runner_cred"], template_id=env["missing_secret"], host_ids=[env["host"]])
    assert r.status_code == 400, r.text
    assert SECRET_UNAVAILABLE in _msg(r)
    assert "nope_missing" not in r.text

    r = _launch(env, headers, cred=env["runner_cred"], host_ids=[env["host"]], inputs={"key": "nope_missing"})
    assert r.status_code == 422, r.text
    assert "nope_missing" not in r.text
    assert "does not exist or this job may not use it" in r.json()["detail"]["fields"]["key"]


def _stored_job(env, *, launched_by: str, cred: int, status: str = "failed") -> int:
    async def _make():
        job_id = await db_module.create_job(
            env["playbook"],
            None,
            cred,
            env["uses_secret"],
            True,
            launched_by=launched_by,
            ad_hoc_ips=[AD_HOC_IP],
        )
        if status != "queued":
            await db_module.finish_job(job_id, status=status)
        return job_id

    return asyncio.run(_make())


@pytest.mark.parametrize("action", ["retry", "rerun"])
def test_retry_and_rerun_recheck_secret_targets(env, action):
    headers = env["login"]("runner")
    job_id = _stored_job(env, launched_by="runner", cred=env["runner_cred"])
    r = env["client"].post(f"/api/jobs/{job_id}/{action}", headers=headers)
    assert r.status_code == 403, r.text
    assert AD_HOC_IP in _msg(r)

    admin_job = _stored_job(env, launched_by="admin", cred=env["admin_cred"])
    r = env["client"].post(f"/api/jobs/{admin_job}/{action}", headers=env["login"]("admin", "netcontrol"))
    assert r.status_code == 201, r.text


def test_queue_refuses_a_non_admin_job_sending_secrets_to_an_ad_hoc_address(env, monkeypatch):
    from netcontrol.routes import jobs as jobs_module

    # An earlier app shutdown in this process leaves the queue draining.
    monkeypatch.setattr(jobs_module, "_shutting_down", False)
    job_id = _stored_job(env, launched_by="runner", cred=env["runner_cred"], status="queued")
    asyncio.run(jobs_module._process_job_queue_inner())
    job = asyncio.run(db_module.get_job(job_id))
    assert job["status"] == "failed"
    events = asyncio.run(db_module.get_job_events(job_id))
    text = " ".join(e["message"] for e in events)
    assert AD_HOC_IP in text and "admin" in text
    assert SECRET_VALUE not in json.dumps(events)


def test_queue_recheck_allows_admins_and_inventory_addresses(env):
    from netcontrol.routes import jobs as jobs_module

    async def _check():
        refused = jobs_module._launcher_secret_targets_refused
        admin_job = {"launched_by": "admin", "ad_hoc_ips": json.dumps([AD_HOC_IP])}
        runner_inventory = {"launched_by": "runner", "ad_hoc_ips": json.dumps([INVENTORY_IP])}
        runner_ad_hoc = {"launched_by": "runner", "ad_hoc_ips": json.dumps([AD_HOC_IP])}
        unknown_user = {"launched_by": "nobody", "ad_hoc_ips": json.dumps([INVENTORY_IP])}
        return [await refused(job) for job in (admin_job, runner_inventory, runner_ad_hoc, unknown_user)]

    # An unknown launcher fails closed (no scope: no inventory host counts).
    assert asyncio.run(_check()) == [[], [], [AD_HOC_IP], [INVENTORY_IP]]
