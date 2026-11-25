"""Scrubbing secret values from job output.

A job's output is scrubbed of every resolved secret value, its common
encodings (``redaction_forms``) in any letter case, its JSON- and
backslash-escaped forms and, for a multi-line value, each of its lines. One
``SecretScrubber`` per job sees the events in order, so a value split across
two events is masked too. Scrubbing stays best effort (a hashed or otherwise
re-encoded value is not recognized).

The values scrubbed are the values pushed: each secret is fetched once
(``resolve_secret_bodies``), so a provider value that changes between two
fetches can never be pushed unscrubbed. The job's device credential (password
and enable secret) is scrubbed as well.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import routes.database as db
from netcontrol.routes import outbound_http, state
from netcontrol.secrets_providers import base, service
from routes.crypto import encrypt
from routes.runner import BasePlaybook, LogEvent, register_playbook
from routes.secret_resolver import SecretScrubber, redact_values, redaction_forms, resolve_secret_bodies

from mcp_helpers import admin_client

SECRET = 'Invented"Key\\42'
PLAIN_SECRET = "InventedPlainKey42"


def _stream(messages: list[str], secret: str) -> str:
    """What the job log holds: every event fed to one scrubber, then flushed."""
    scrubber = SecretScrubber({secret})
    return "".join(scrubber.feed(m) for m in messages) + scrubber.flush()


def test_value_split_across_two_events_is_scrubbed():
    joined = _stream(["sw1(config)#username netops secret Invented", "PlainKey42\n"], PLAIN_SECRET)
    assert PLAIN_SECRET not in joined
    assert joined == "sw1(config)#username netops secret ********\n"


def test_value_split_after_a_short_fragment_shows_none_of_it():
    scrubber = SecretScrubber({PLAIN_SECRET})
    first = scrubber.feed("secret Inv")
    second = scrubber.feed("entedPlainKey42 done")
    assert first == "secret "
    assert second == "******** done"


@pytest.mark.parametrize("value", [PLAIN_SECRET, SECRET])
def test_no_part_of_a_value_split_at_any_position_is_shown(value):
    # Every form (the value and each encoding), cut after every character.
    for form in sorted(redaction_forms(value)):
        for cut in range(1, len(form)):
            out = _stream([f"key: {form[:cut]}", f"{form[cut:]} end\n"], value)
            assert out == "key: ******** end\n", (form, cut, out)


def test_a_trailing_fragment_that_never_completes_is_released_by_the_next_event():
    scrubber = SecretScrubber({PLAIN_SECRET})
    assert scrubber.feed("hosts In") == "hosts "
    assert scrubber.feed("ventory ok\n") == "Inventory ok\n"
    assert scrubber.flush() == ""


def test_held_fragment_is_flushed_at_the_end_and_order_is_kept():
    scrubber = SecretScrubber({PLAIN_SECRET})
    out = [scrubber.feed("line one\n"), scrubber.feed("tail Invented"), scrubber.feed("not the rest\n")]
    assert out == ["line one\n", "tail ", "Inventednot the rest\n"]
    assert scrubber.feed("ends with Invent") == "ends with "
    assert scrubber.flush() == "Invent"
    assert scrubber.flush() == ""


def test_output_that_starts_no_value_is_not_delayed():
    scrubber = SecretScrubber({PLAIN_SECRET})
    assert scrubber.feed("hosts ok=4\n") == "hosts ok=4\n"
    assert scrubber.flush() == ""


def test_case_changed_value_is_scrubbed():
    out = redact_values(f"KEY: {PLAIN_SECRET.upper()}", {PLAIN_SECRET})
    assert PLAIN_SECRET.upper() not in out
    assert out == "KEY: ********"


def test_json_escaped_value_is_scrubbed():
    device_json = json.dumps({"community": SECRET})
    out = redact_values(device_json, {SECRET})
    assert json.dumps(SECRET)[1:-1] not in out
    assert out == '{"community": "********"}'


def test_multi_line_value_echoed_line_by_line_is_scrubbed():
    secret = "MIIBInventedKeyLineOne\nMIIBInventedKeyLineTwo"
    echo = "sw1(config)#MIIBInventedKeyLineOne\nsw1(config)#MIIBInventedKeyLineTwo\n"
    out = redact_values(echo, {secret})
    assert "MIIBInventedKeyLineOne" not in out and "MIIBInventedKeyLineTwo" not in out


# ── One fetch for the pushed value and the redaction set ─────────────────────


@pytest.fixture
def rotating_vault(monkeypatch):
    base.invalidate()
    service._FAILURES_AUDITED.clear()
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})

    async def no_guard(_url):
        return None

    monkeypatch.setattr(outbound_http, "guard_url", no_guard)
    calls = {"n": 0}

    def vault(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"data": {"data": {"value": f"invented-rotating-value-{calls['n']}"}}})

    monkeypatch.setattr(base, "HTTP_TRANSPORT", httpx.MockTransport(vault))
    yield calls
    base.invalidate()


def test_the_pushed_value_is_the_scrubbed_value(monkeypatch, request, rotating_vault):
    """With ``cache_ttl`` 0 every fetch may return a new value; the queue
    fetches once and scrubs exactly what it pushes."""
    admin = admin_client(monkeypatch, request)
    resp = admin.post(
        "/api/secrets-providers",
        json={
            "name": "rotating-vault",
            "provider_type": "vault",
            "config": {"url": "https://vault.example.com:8200"},
            "secrets": {"token": "test-vault-token-not-real"},
            "cache_ttl": 0,
        },
    )
    assert resp.status_code == 201, resp.text
    pid = int(resp.json()["id"])
    asyncio.run(
        db.create_secret_variable(
            "rotating", "", external={"provider_id": pid, "path": "network/rotating", "key": "value"}
        )
    )
    generic = ["snmp-server community {{secret.rotating}} RO"]
    variant = ["snmp-server community {{secret.rotating}} RW"]
    bodies, redact = asyncio.run(resolve_secret_bodies([generic, variant], user=("admin", [])))
    assert rotating_vault["n"] == 1
    assert bodies[0][0].split()[2] == bodies[1][0].split()[2]
    log_line = redact_values(f"sw1(config)#{bodies[0][0]}", redact)
    assert "invented-rotating-value" not in log_line


# ── Through the job queue ────────────────────────────────────────────────────

TEMPLATE_SECRET = "Invented-Template-Value-77"
DEVICE_PASSWORD = "Invented-Device-Password-9"
DEVICE_ENABLE = "Invented-Enable-Secret-3"


@register_playbook
class _EchoPlaybook(BasePlaybook):
    filename = "job_output_redaction_echo_test.py"
    display_name = "Job output redaction echo (test)"
    description = "test only: prints the values a careless playbook might print"
    tags: list[str] = []

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        line = (template_commands or [""])[0]
        cut = line.index(TEMPLATE_SECRET) + 8
        # The device echo arrives in two reads, split inside the value.
        yield LogEvent(level="info", message=line[:cut])
        yield LogEvent(level="info", message=line[cut:])
        yield LogEvent(level="info", message=f"password {credentials['password']}")
        yield LogEvent(level="info", message=f"enable {credentials['secret'].lower()}")
        yield LogEvent(level="info", message="last words Invented-Tem")


def test_queue_scrubs_split_values_and_the_device_credential(monkeypatch, request):
    from netcontrol.routes import jobs as jobs_module

    async def _no_queue():
        return None

    monkeypatch.setattr(jobs_module, "_process_job_queue", _no_queue)
    monkeypatch.setattr(jobs_module, "_shutting_down", False)
    admin = admin_client(monkeypatch, request)
    cred = admin.post(
        "/api/credentials",
        json={"name": "redaction-cred", "username": "netops", "password": DEVICE_PASSWORD, "secret": DEVICE_ENABLE},
    )
    assert cred.status_code == 201, cred.text

    async def _seed():
        group = await db.create_group("redaction-group")
        host = await db.add_host(group, "redaction-sw1", "192.0.2.91", address_confirmed=True)
        await db.create_secret_variable("tpl_secret", encrypt(TEMPLATE_SECRET))
        playbook = await db.create_playbook("redaction-echo", _EchoPlaybook.filename)
        template = await db.create_template("redaction-tpl", "snmp-server community {{secret.tpl_secret}} RO")
        return host, playbook, template

    host, playbook, template = asyncio.run(_seed())
    launch = admin.post(
        "/api/jobs/launch",
        json={
            "playbook_id": playbook,
            "credential_id": int(cred.json()["id"]),
            "host_ids": [host],
            "template_id": template,
        },
    )
    assert launch.status_code == 201, launch.text
    job_id = int(launch.json()["job_id"])

    async def _go():
        await jobs_module._process_job_queue_inner()
        tasks = list(jobs_module._running_job_tasks.values())
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return await db.get_job_events(job_id)

    events = asyncio.run(_go())
    log = "".join(e["message"] for e in events)
    assert "snmp-server community ********" in log
    assert TEMPLATE_SECRET not in log
    assert DEVICE_PASSWORD not in log
    assert DEVICE_ENABLE.lower() not in log
    # The fragment held at the end is written last, after the event it ended.
    messages = [e["message"] for e in events]
    assert messages.index("last words ") < messages.index("Invented-Tem")
