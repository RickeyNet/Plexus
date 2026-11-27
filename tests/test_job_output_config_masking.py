"""A job's output is read under the raw-config rule.

A job's log holds what the devices answered: a playbook that shows or
pushes configuration writes SNMP communities, TACACS+ keys and certificates
into it. It follows the rule of ``netcontrol.routes.config_visibility``: an
admin, the API token, or a user holding ``config-backups.write`` who may
change every target of the job reads it as written; every other reader
(the launcher included) gets the secrets masked, on
``GET /api/jobs/{id}/events``, on ``/ws/jobs/{id}`` (replay and live) and in
the ChatOps ``job`` reply.

Every secret, name and address below is invented.
"""

from __future__ import annotations

import functools
import json
from types import SimpleNamespace

import pytest
import routes.database as db_module
from netcontrol.mcp.redact import MASK, StreamRedactor, redact_log_events
from netcontrol.routes import jobs

from mcp_helpers import admin_client, user_client

COMMUNITY = "example-job-secret-0001"
TACACS_KEY = "example-job-secret-0002"
CERT_BODY = "ZXhhbXBsZWpvYnNlY3JldDAwMDM"
SECRETS = (COMMUNITY, TACACS_KEY, CERT_BODY)
RAW_FEATURES = ["config-backups", "config-backups.write"]
HOST = "edge-sw1"

# (level, message, host) as the job runner stores them.
EVENTS = [
    ("info", "Template has 2 command(s).", ""),
    ("info", f"Connecting to {HOST} (192.0.2.41) ...", HOST),
    ("info", f"Device output:\nsnmp-server community {COMMUNITY} RO\ntacacs server tac-a\n key 0 {TACACS_KEY}", HOST),
    ("info", "-----BEGIN CERTIFICATE-----", HOST),
    ("info", CERT_BODY, HOST),
    ("info", "-----END CERTIFICATE-----", HOST),
    ("success", f"Finished processing {HOST} (192.0.2.41).", HOST),
]


def _leaked(text: str) -> list[str]:
    return [s for s in SECRETS if s in text]


# ── The masker ───────────────────────────────────────────────────────────────


def test_each_message_is_masked_and_keeps_its_lines():
    masker = StreamRedactor()
    message = EVENTS[2][1]
    masked = masker.mask(HOST, message)
    assert _leaked(masked) == []
    assert masked.split("\n") == [
        "Device output:",
        f"snmp-server community {MASK} RO",
        "tacacs server tac-a",
        f" key 0 {MASK}",
    ]
    # Text with nothing to hide comes back as it is.
    assert masker.mask(HOST, "Config saved.") == "Config saved."


def test_a_block_opened_by_one_message_stays_masked_for_that_source_only():
    masker = StreamRedactor()
    assert masker.mask(HOST, "-----BEGIN CERTIFICATE-----") == MASK
    # Another host's line in between is not part of the block.
    assert masker.mask("core-sw2", "Config saved.") == "Config saved."
    assert masker.mask(HOST, CERT_BODY) == MASK
    assert masker.mask(HOST, f"{CERT_BODY}\n-----END CERTIFICATE-----\nhostname {HOST}") == (
        f"{MASK}\n{MASK}\nhostname {HOST}"
    )
    assert masker.mask(HOST, "Config saved.") == "Config saved."


def test_a_message_read_unmasked_still_opens_and_closes_a_block():
    masker = StreamRedactor()
    masker.advance(HOST, "-----BEGIN CERTIFICATE-----")
    assert masker.mask(HOST, CERT_BODY) == MASK
    masker.advance(HOST, "-----END CERTIFICATE-----")
    assert masker.mask(HOST, "Config saved.") == "Config saved."


def test_log_events_are_masked_as_copies():
    rows = [{"id": i, "level": lv, "message": msg, "host": host} for i, (lv, msg, host) in enumerate(EVENTS, 1)]
    masked = redact_log_events(rows)
    assert _leaked(json.dumps(masked)) == []
    assert [r["id"] for r in masked] == [r["id"] for r in rows]
    assert masked[0] == rows[0] and masked[-1] == rows[-1]
    assert rows[2]["message"] == EVENTS[2][1], "the stored rows were changed"


# ── The live stream ──────────────────────────────────────────────────────────


class _Socket:
    def __init__(self, raw: bool | None = None):
        self.state = SimpleNamespace()
        if raw is not None:
            self.state.raw_job_output = raw
        self.sent: list[dict] = []

    async def send_text(self, text: str) -> None:
        self.sent.append(json.loads(text))


async def test_live_lines_go_out_masked_to_viewers_without_the_raw_right(monkeypatch):
    job_id = 990001
    line = {"level": "info", "host": HOST, "timestamp": "2026-11-04T17:53:41Z"}
    # Written before anyone watches: the masker still learns the block is open.
    await jobs._broadcast_to_job_sockets(job_id, {**line, "message": "-----BEGIN CERTIFICATE-----"})

    raw, masked, unmarked = _Socket(raw=True), _Socket(raw=False), _Socket()
    monkeypatch.setitem(jobs._job_sockets, job_id, [raw, masked, unmarked])
    try:
        await jobs._broadcast_to_job_sockets(job_id, {**line, "message": CERT_BODY})
        await jobs._broadcast_to_job_sockets(job_id, {**line, "message": "-----END CERTIFICATE-----"})
        await jobs._broadcast_to_job_sockets(job_id, {**line, "message": f"snmp-server community {COMMUNITY} RO"})
        await jobs._broadcast_to_job_sockets(job_id, {**line, "message": "Config saved."})
        done = {"type": "job_complete", "job_id": job_id, "status": "done"}
        await jobs._broadcast_to_job_sockets(job_id, done)
    finally:
        await jobs._end_job_stream(job_id)

    assert [p.get("message") for p in raw.sent] == [
        CERT_BODY,
        "-----END CERTIFICATE-----",
        f"snmp-server community {COMMUNITY} RO",
        "Config saved.",
        None,
    ]
    for viewer in (masked, unmarked):
        assert _leaked(json.dumps(viewer.sent)) == []
        assert [p.get("message") for p in viewer.sent] == [
            MASK,
            MASK,
            f"snmp-server community {MASK} RO",
            "Config saved.",
            None,
        ]
        assert viewer.sent[-1] == done
    assert job_id not in jobs._job_output_maskers


# ── The routes ───────────────────────────────────────────────────────────────


@pytest.fixture
def env(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    call = admin.raw.portal.call
    gid = call(functools.partial(db_module.create_group, "job-masking"))
    host_id = call(functools.partial(db_module.add_host, gid, HOST, "192.0.2.41", "cisco_ios"))
    playbook = call(functools.partial(db_module.create_playbook, "Show config", "show_config.py"))
    return {"admin": admin, "call": call, "gid": gid, "host_id": host_id, "playbook": playbook}


def _finished_job(env, launched_by: str) -> int:
    call = env["call"]
    job_id = call(
        functools.partial(
            db_module.create_job, env["playbook"], None, None, None, True, launched_by=launched_by, host_ids=[env["host_id"]]
        )
    )
    call(functools.partial(db_module.add_job_events, job_id, EVENTS))
    call(functools.partial(db_module.finish_job, job_id, "success", 1))
    return job_id


def _replay(client, job_id: int) -> list[dict]:
    frames: list[dict] = []
    with client.raw.websocket_connect(f"/ws/jobs/{job_id}") as ws:
        while True:
            frame = ws.receive_json()
            if frame.get("type") == "job_complete":
                return frames
            frames.append(frame)


def test_the_launcher_without_the_raw_right_reads_masked_output(env):
    launcher = user_client(env["admin"], "job-launcher", features=["jobs", "jobs.write"])
    job_id = _finished_job(env, "job-launcher")

    resp = launcher.get(f"/api/jobs/{job_id}/events")
    assert resp.status_code == 200, resp.text
    assert _leaked(resp.text) == [], "job output returned device secrets to a user without config-backups.write"
    messages = [e["message"] for e in resp.json()]
    assert len(messages) == len(EVENTS)
    assert messages[0] == EVENTS[0][1] and messages[1] == EVENTS[1][1] and messages[-1] == EVENTS[-1][1]
    assert messages[2].split("\n")[1] == f"snmp-server community {MASK} RO"
    assert messages[3:6] == [MASK, MASK, MASK]

    frames = _replay(launcher, job_id)
    assert _leaked(json.dumps(frames)) == []
    assert [f["message"] for f in frames] == messages


def test_an_admin_and_a_holder_of_the_raw_right_read_output_as_written(env):
    holder = user_client(env["admin"], "job-raw", features=["jobs", "jobs.write", *RAW_FEATURES])
    job_id = _finished_job(env, "job-raw")
    written = [message for _level, message, _host in EVENTS]

    for client in (env["admin"], holder):
        resp = client.get(f"/api/jobs/{job_id}/events")
        assert resp.status_code == 200, resp.text
        assert [e["message"] for e in resp.json()] == written
        assert [f["message"] for f in _replay(client, job_id)] == written


def test_the_raw_right_without_write_access_to_the_targets_reads_masked_output(env):
    """``config-backups.write`` counts for the devices its holder may change."""
    reader = user_client(
        env["admin"], "job-scoped", features=["jobs", "jobs.write", *RAW_FEATURES], read_groups=[env["gid"]]
    )
    job_id = _finished_job(env, "job-scoped")

    resp = reader.get(f"/api/jobs/{job_id}/events")
    assert resp.status_code == 200, resp.text
    assert _leaked(resp.text) == []
    assert _leaked(json.dumps(_replay(reader, job_id))) == []
