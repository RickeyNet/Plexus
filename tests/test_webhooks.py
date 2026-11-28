"""Outbound event webhooks (``netcontrol.routes.webhooks``): object-change
events from the DB facade reach only the matching webhooks, filters narrow
them, the body is signed, 5xx responses are retried, SSRF-blocked targets are
refused, secrets never leave Plexus, and the audit hook still feeds the SIEM
forwarder alongside other subscribers."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import netcontrol.routes.webhooks as wh
import pytest
import routes.database as db
from routes.db import change_events

from mcp_helpers import CsrfClient, admin_client

HOOKS = "/api/admin/webhooks"
SECRET = "test-signing-secret"


# ── Local receiver ───────────────────────────────────────────────────────────


class Receiver:
    """A threaded HTTP server recording each request. ``statuses`` is the
    reply status per request in order; the last one repeats."""

    def __init__(self, statuses: tuple[int, ...] = (200,)):
        self.statuses = list(statuses)
        self.requests: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                outer.requests.append(
                    {"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body}
                )
                status = outer.statuses.pop(0) if len(outer.statuses) > 1 else outer.statuses[0]
                self.send_response(status)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            do_POST = do_PUT = do_PATCH = _handle

            def log_message(self, *args) -> None:  # silence
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/hook"

    def bodies(self) -> list[dict]:
        return [json.loads(r["body"]) for r in self.requests]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def receiver():
    made: list[Receiver] = []

    def make(*statuses: int) -> Receiver:
        r = Receiver(statuses or (200,))
        made.append(r)
        return r

    yield make
    for r in made:
        r.close()


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _wait(predicate, timeout_s: float = 6.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


async def _await(predicate, timeout_s: float = 6.0) -> bool:
    """Poll ``predicate`` (plain or async) until it is true or time runs out."""

    async def check() -> bool:
        result = predicate()
        return bool(await result if inspect.isawaitable(result) else result)

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if await check():
            return True
        await asyncio.sleep(0.05)
    return await check()


def _ok(resp, status: int = 200) -> dict:
    assert resp.status_code == status, resp.text
    return resp.json()


def _hook_body(url: str, **extra) -> dict:
    body = {
        "name": "inventory-hook",
        "url": url,
        "object_types": ["host"],
        "actions": ["create", "update", "delete"],
    }
    body.update(extra)
    return body


def _group(admin: CsrfClient, name: str) -> int:
    return int(_ok(admin.post("/api/inventory", json={"name": name}), 201)["id"])


def _host(admin: CsrfClient, gid: int, name: str, ip: str) -> int:
    body = {"hostname": name, "ip_address": ip, "device_type": "cisco_ios"}
    return int(_ok(admin.post(f"/api/inventory/{gid}/hosts", json=body), 201)["id"])


# ── Unit: matching, signing, payload ─────────────────────────────────────────


def _cfg(**over) -> wh.WebhookConfig:
    base = dict(
        id=1,
        name="t",
        enabled=True,
        url="http://192.0.2.10/hook",
        http_method="POST",
        content_type="application/json",
        object_types=("host",),
        actions=("create", "update", "delete"),
        filters={},
        headers={},
        body_template="",
        secret="",
        verify_tls=True,
        ca_bundle="",
        timeout_seconds=5.0,
        max_retries=2,
        concurrency=1,
    )
    base.update(over)
    return wh.WebhookConfig(**base)  # type: ignore[arg-type]


def _event(object_type="host", action="create", before=None, after=None) -> dict:
    return {
        "event": f"{object_type}.{action}",
        "object_type": object_type,
        "action": action,
        "object_id": "5",
        "timestamp": "2026-01-01T00:00:00Z",
        "user": "alice",
        "before": before,
        "after": after,
        "changes": {},
    }


def test_matches_type_action_and_filter():
    cfg = _cfg(actions=("delete",), filters={"group_id": ["3"]})
    assert not wh.matches(cfg, _event(after={"id": 5, "group_id": 3}))  # create not subscribed
    assert wh.matches(cfg, _event(action="delete", before={"id": 5, "group_id": 3}))
    assert not wh.matches(cfg, _event(action="delete", before={"id": 5, "group_id": 4}))
    assert not wh.matches(cfg, _event(object_type="vlan", action="delete", before={"id": 5, "group_id": 3}))
    assert not wh.matches(_cfg(enabled=False), _event(after={"id": 5}))
    # A group's own id answers a group_id filter.
    group_cfg = _cfg(object_types=("group",), filters={"group_id": ["7"]})
    assert wh.matches(group_cfg, _event(object_type="group", after={"id": 7, "name": "core"}))


def test_signature_is_hmac_sha256_of_body():
    body = b'{"event":"host.create"}'
    expected = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    assert wh.sign(SECRET, body) == expected
    headers = wh.build_headers(_cfg(secret=SECRET), "host.create", "d-1", body)
    assert headers["X-Plexus-Signature-256"] == expected
    assert headers["X-Plexus-Event"] == "host.create"
    assert headers["X-Plexus-Delivery"] == "d-1"
    assert "X-Plexus-Signature-256" not in wh.build_headers(_cfg(), "host.create", "d-1", body)


def test_payload_masks_secret_keys_and_template_renders():
    payload = wh.build_payload(_event(after={"id": 5, "name": "x", "api_key": "abc123"}), "d-2")
    assert payload["data"]["api_key"] != "abc123"
    assert payload["delivery_id"] == "d-2" and payload["user"] == "alice"
    body = wh.render_body(_cfg(body_template='{"text": "{{ payload.event }} {{ object_id }}"}'), payload)
    assert json.loads(body) == {"text": "host.create 5"}
    with pytest.raises(wh.TemplateRenderError):
        wh.render_body(_cfg(body_template="{{ missing.thing }}"), payload)


# ── Delivery through the running app ─────────────────────────────────────────


def test_host_changes_fire_only_matching_webhook(admin, receiver):
    hosts_rx, vlans_rx = receiver(), receiver()
    hook = _ok(admin.post(HOOKS, json=_hook_body(hosts_rx.url, secret=SECRET)), 201)
    _ok(admin.post(HOOKS, json=_hook_body(vlans_rx.url, name="vlan-hook", object_types=["vlan"])), 201)
    assert hook["secret"] == wh.REDACTION_MASK and hook["has_secret"] is True

    gid = _group(admin, "core")
    host_id = _host(admin, gid, "edge-r1", "192.0.2.10")
    _ok(admin.put(f"/api/hosts/{host_id}", json={"hostname": "edge-r2", "ip_address": "192.0.2.10"}))
    _ok(admin.delete(f"/api/hosts/{host_id}"))

    assert _wait(lambda: len(hosts_rx.requests) >= 3), hosts_rx.requests
    events = [b["event"] for b in hosts_rx.bodies()]
    assert events[:3] == ["host.create", "host.update", "host.delete"]
    create, update, delete = hosts_rx.bodies()[:3]
    assert create["object_id"] == str(host_id) and create["data"]["hostname"] == "edge-r1"
    assert create["user"] == "admin"
    assert update["changes"]["hostname"] == {"before": "edge-r1", "after": "edge-r2"}
    assert delete["snapshots"]["after"] is None and delete["data"]["hostname"] == "edge-r2"

    # Signed, identified, idempotent delivery ids.
    first = hosts_rx.requests[0]
    assert first["headers"]["X-Plexus-Event"] == "host.create"
    assert first["headers"]["X-Plexus-Signature-256"] == wh.sign(SECRET, first["body"])
    ids = {r["headers"]["X-Plexus-Delivery"] for r in hosts_rx.requests}
    assert len(ids) == len(hosts_rx.requests)

    time.sleep(0.3)
    assert vlans_rx.requests == []  # the vlan webhook saw none of it

    log = _ok(admin.get(f"{HOOKS}/{hook['id']}/deliveries"))["deliveries"]
    assert {d["event"] for d in log} >= {"host.create", "host.update", "host.delete"}
    assert all(d["status"] == "success" and d["status_code"] == 200 for d in log)


def test_group_filter_limits_deliveries(admin, receiver):
    rx = receiver()
    core, edge = _group(admin, "core"), _group(admin, "edge")
    _ok(admin.post(HOOKS, json=_hook_body(rx.url, actions=["create"], filters={"group_id": [core]})), 201)
    _host(admin, edge, "edge-r1", "192.0.2.20")
    _host(admin, core, "core-r1", "192.0.2.21")
    assert _wait(lambda: len(rx.requests) >= 1)
    time.sleep(0.3)
    assert [b["data"]["hostname"] for b in rx.bodies()] == ["core-r1"]


def test_ssrf_blocked_target_rejected(admin):
    resp = admin.post(HOOKS, json=_hook_body("http://169.254.169.254/latest/meta-data"))
    assert resp.status_code == 400 and "rejected" in resp.text
    assert admin.post(HOOKS, json=_hook_body("ftp://192.0.2.1/x")).status_code == 400


def test_validation_errors(admin, receiver):
    rx = receiver()
    bad = (
        {"object_types": ["toaster"]},
        {"actions": ["explode"]},
        {"http_method": "GET"},
        {"headers": {"X-Plexus-Event": "spoof"}},
        {"headers": {"X-Token": "a\r\nInjected: 1"}},
        {"body_template": "{% if %}"},
        {"ca_bundle": "not a pem"},
        {"filters": {"Group Id": [1]}},
    )
    for extra in bad:
        assert admin.post(HOOKS, json=_hook_body(rx.url, **extra)).status_code == 400, extra


def test_secret_and_headers_never_leak(admin, receiver):
    rx = receiver()
    body = _hook_body(rx.url, secret=SECRET, headers={"Authorization": "Bearer header-token-value"})
    hook = _ok(admin.post(HOOKS, json=body), 201)
    listing = admin.get(HOOKS).text
    one = admin.get(f"{HOOKS}/{hook['id']}").text
    for text in (listing, one):
        assert SECRET not in text and "header-token-value" not in text
    # Saving with the masks keeps both values.
    kept = {**body, "secret": wh.REDACTION_MASK, "headers": {"Authorization": wh.REDACTION_MASK}}
    _ok(admin.put(f"{HOOKS}/{hook['id']}", json=kept))
    _host(admin, _group(admin, "core"), "edge-r1", "192.0.2.30")
    assert _wait(lambda: len(rx.requests) >= 1)
    sent = rx.requests[0]
    assert sent["headers"]["Authorization"] == "Bearer header-token-value"
    assert sent["headers"]["X-Plexus-Signature-256"] == wh.sign(SECRET, sent["body"])
    assert SECRET.encode() not in sent["body"]
    log = admin.get(f"{HOOKS}/{hook['id']}/deliveries").text
    assert SECRET not in log and "header-token-value" not in log


def test_credential_events_carry_metadata_only(admin, receiver):
    rx = receiver()
    _ok(admin.post(HOOKS, json=_hook_body(rx.url, object_types=["credential"])), 201)
    resp = admin.post(
        "/api/credentials", json={"name": "lab-login", "username": "netops", "password": "pw-value-123", "secret": ""}
    )
    assert resp.status_code in (200, 201), resp.text
    assert _wait(lambda: len(rx.requests) >= 1)
    raw = rx.requests[0]["body"]
    assert b"pw-value-123" not in raw
    data = rx.bodies()[0]["data"]
    assert data["name"] == "lab-login" and "password" not in data and "secret" not in data


def test_test_send_and_redeliver(admin, receiver):
    rx = receiver()
    hook = _ok(admin.post(HOOKS, json=_hook_body(rx.url, secret=SECRET)), 201)
    result = _ok(admin.post(f"{HOOKS}/{hook['id']}/test"))
    assert result["ok"] is True and result["status_code"] == 200
    assert rx.bodies()[0]["event"] == "webhook.test"
    log = _ok(admin.get(f"{HOOKS}/{hook['id']}/deliveries"))["deliveries"]
    again = _ok(admin.post(f"{HOOKS}/{hook['id']}/deliveries/{log[0]['id']}/redeliver"))
    assert again["ok"] is True and again["delivery_id"] == result["delivery_id"]
    assert len(rx.requests) == 2
    assert rx.requests[0]["body"] == rx.requests[1]["body"]
    assert rx.requests[1]["headers"]["X-Plexus-Delivery"] == result["delivery_id"]
    assert admin.post(f"{HOOKS}/{hook['id']}/deliveries/999999/redeliver").status_code == 404


def test_webhook_changes_do_not_recurse_and_are_audited(admin, receiver):
    rx = receiver()
    hook = _ok(admin.post(HOOKS, json=_hook_body(rx.url, object_types=list(change_events.CHANGE_OBJECT_TYPES))), 201)
    _ok(admin.put(f"{HOOKS}/{hook['id']}", json=_hook_body(rx.url, name="renamed")))
    _ok(admin.delete(f"{HOOKS}/{hook['id']}"))
    time.sleep(0.4)
    assert rx.requests == []
    actions = {e["action"] for e in asyncio.run(db.get_audit_events(limit=50))}
    assert {"webhook.create", "webhook.update", "webhook.delete"} <= actions


def test_non_admin_is_refused(admin):
    from mcp_helpers import user_client

    plain = user_client(admin, "plain-user", features=["inventory"])
    assert plain.get(HOOKS).status_code == 403
    assert plain.post(HOOKS, json=_hook_body("http://192.0.2.1/x")).status_code == 403


# ── Retries (dispatcher without the app) ─────────────────────────────────────


async def _make_hook(url: str, **over) -> dict:
    values = {
        "name": over.pop("name", "retry-hook"),
        "url": url,
        "object_types_json": json.dumps(over.pop("object_types", ["host"])),
        "actions_json": json.dumps(["create", "update", "delete"]),
        "max_retries": over.pop("max_retries", 3),
        "concurrency": 1,
        "timeout_seconds": 5.0,
    }
    values.update(over)
    return await db.create_webhook(values)


@pytest.fixture
async def dispatcher(monkeypatch):
    monkeypatch.setattr(wh, "BACKOFF_BASE", 0.05)
    await wh.start_dispatcher()
    yield
    await wh.stop_dispatcher()


async def test_retries_on_5xx_then_succeeds(dispatcher, receiver):
    rx = receiver(503, 500, 200)
    hook = await _make_hook(rx.url)
    await wh.reload_webhooks()
    gid = await db.create_group("core")
    await db.add_host(gid, "edge-r1", "192.0.2.40")
    assert await _await(lambda: len(rx.requests) >= 3)
    ids = {r["headers"]["X-Plexus-Delivery"] for r in rx.requests}
    assert len(ids) == 1  # every attempt carries the same delivery id
    assert len({r["body"] for r in rx.requests}) == 1
    # The receiver sees the third request before the dispatcher records its
    # outcome, so wait for the delivery log too.
    expected = [(1, "retrying"), (2, "retrying"), (3, "success")]

    async def logged() -> list:
        return [(d["attempt"], d["status"]) for d in reversed(await db.list_webhook_deliveries(hook["id"]))]

    async def done() -> bool:
        return await logged() == expected

    await _await(done)
    assert await logged() == expected


async def test_retries_stop_at_max_and_4xx_is_not_retried(dispatcher, receiver):
    down = receiver(500)
    gone = receiver(404)
    a = await _make_hook(down.url, name="down", max_retries=1)
    b = await _make_hook(gone.url, name="gone", max_retries=3)
    await wh.reload_webhooks()
    await db.add_host(await db.create_group("core"), "edge-r1", "192.0.2.41")
    assert await _await(lambda: len(down.requests) >= 2 and len(gone.requests) >= 1)
    await asyncio.sleep(0.4)
    assert len(down.requests) == 2 and len(gone.requests) == 1
    assert [d["status"] for d in await db.list_webhook_deliveries(a["id"])][0] == "failed"
    assert [d["status"] for d in await db.list_webhook_deliveries(b["id"])] == ["failed"]


async def test_no_reads_when_nobody_subscribes(monkeypatch):
    calls: list = []
    real = change_events.fetch_object_snapshot

    async def counting(object_type, object_id):
        calls.append(object_type)
        return await real(object_type, object_id)

    monkeypatch.setattr(change_events, "fetch_object_snapshot", counting)
    await db.add_host(await db.create_group("core"), "edge-r1", "192.0.2.42")
    assert calls == []


# ── Audit hook fan-out (SIEM forwarder keeps its slot) ───────────────────────


async def test_audit_hook_feeds_siem_slot_and_extra_subscribers():
    primary: list[dict] = []
    extra: list[dict] = []

    async def siem(event):
        primary.append(event)

    async def other(event):
        extra.append(event)

    async def broken(event):
        raise RuntimeError("boom")

    db.set_audit_event_hook(siem)
    db.add_audit_event_hook(broken)
    db.add_audit_event_hook(other)
    db.add_audit_event_hook(other)  # idempotent
    try:
        await db.add_audit_event("system", "webhook.test", user="admin", detail="x")
    finally:
        db.set_audit_event_hook(None)
        db.remove_audit_event_hook(broken)
        db.remove_audit_event_hook(other)
    assert len(primary) == 1 and len(extra) == 1
    assert primary[0]["action"] == "webhook.test"


# ── Delivery log ─────────────────────────────────────────────────────────────

HEADER_VALUE = "Bearer header-token-value"
MASKED = "***"  # what telemetry.redact_text writes in place of a secret


class _Reply:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


async def _logged(monkeypatch, send) -> tuple[wh.DeliveryOutcome, dict]:
    """One delivery of a webhook with a secret and a custom header through
    ``send``; the outcome and the delivery log row it wrote."""
    rows: list[dict] = []

    async def add(**row):
        rows.append(row)

    monkeypatch.setattr(wh.db, "add_webhook_delivery", add)
    monkeypatch.setattr(wh, "send_request", send)
    cfg = _cfg(secret=SECRET, headers={"Authorization": HEADER_VALUE, "X-Tenant": "tenant-key-5150"})
    job = wh.DeliveryJob(1, "d-1", "host.create", "host", "7", "create", payload={"event": "host.create"})
    outcome = await wh.deliver_once(cfg, job, allow_retry=False)
    return outcome, rows[0]


def _holds_nothing_sent(text: str) -> bool:
    return not any(value in text for value in (SECRET, "header-token-value", "tenant-key-5150", "sha256="))


async def test_delivery_log_masks_what_the_receiver_quotes_back(monkeypatch):
    async def echo(method, url, *, headers, **kwargs):
        # A receiver that answers with the headers it got, and the token alone.
        return _Reply(401, json.dumps({"received": headers, "detail": "unknown token header-token-value"}))

    outcome, row = await _logged(monkeypatch, echo)

    assert row["status"] == "failed" and row["status_code"] == 401
    assert "X-Plexus-Event" in row["response_body"] and MASKED in row["response_body"]
    assert _holds_nothing_sent(row["response_body"])
    assert outcome.error == "HTTP 401"


async def test_delivery_log_masks_a_value_cut_by_the_length_limit(monkeypatch):
    async def long_reply(method, url, **kwargs):
        return _Reply(200, "x" * (wh.RESPONSE_KEEP - 6) + "tenant-key-5150 and more")

    _, row = await _logged(monkeypatch, long_reply)

    assert len(row["response_body"]) == wh.RESPONSE_KEEP
    assert "tenant" not in row["response_body"]


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (RuntimeError(f"peer said: bad Authorization {HEADER_VALUE!r} for tenant-key-5150"), "failed"),
        (wh.OutboundRequestError(f"redirect to https://rx.example.com/?token=x with {SECRET}"), "blocked"),
    ],
)
async def test_delivery_log_masks_the_error_text(monkeypatch, error, status):
    async def fail(method, url, **kwargs):
        raise error

    outcome, row = await _logged(monkeypatch, fail)

    assert row["status"] == status and row["error"] == outcome.error
    assert MASKED in row["error"] and _holds_nothing_sent(row["error"])
    assert len(row["error"]) <= wh.ERROR_KEEP
