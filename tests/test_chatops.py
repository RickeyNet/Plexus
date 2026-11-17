"""ChatOps: request signatures (valid, bad, replayed), the parser and the
dispatcher, identity mapping and permission checks, every command against
seeded data, the Slack / Webex / Teams formatters and endpoints, the admin
API and alert notifications through a bot."""

from __future__ import annotations

import base64
import hashlib
import hmac
import itertools
import json
import re
import time
from urllib.parse import urlencode

import pytest
import routes.database as db
from netcontrol.chatops import adapters, commands, dispatcher, notify, replies, signatures
from netcontrol.chatops.commands import ChatUser
from netcontrol.chatops.replies import Action, Reply
from netcontrol.routes import chatops as chatops_routes, notification_channels as nc, state

from mcp_helpers import CsrfClient, admin_client, user_client

ADMIN = "/api/admin/chatops"
SLACK_SECRET = "slack-signing-secret-example"
WEBEX_SECRET = "webex-webhook-secret-example"
TEAMS_TOKEN = base64.b64encode(b"teams-security-token-example").decode()
ALL = frozenset(c.name for c in commands.catalogue())


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})
    chatops_routes.reset_replay_guards()


@pytest.fixture
def no_job_queue(monkeypatch):
    """Queued jobs stay queued: the test checks the row, not a run."""
    import netcontrol.routes.jobs as jobs

    async def _idle():
        return None

    monkeypatch.setattr(jobs, "_process_job_queue", _idle)


# ── Signatures ───────────────────────────────────────────────────────────────


def _slack_sig(secret: str, ts: str, body: bytes) -> str:
    return "v0=" + hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()


def test_slack_signature_valid_bad_and_replayed():
    body = b"text=device+edge-rtr-01&user_id=U0EXAMPLE1"
    now = 1_800_000_000
    ts = str(now)
    sig = _slack_sig(SLACK_SECRET, ts, body)
    assert signatures.verify_slack(SLACK_SECRET, ts, body, sig, now=now)
    assert not signatures.verify_slack(SLACK_SECRET, ts, body + b"x", sig, now=now)
    assert not signatures.verify_slack("other-secret-value", ts, body, sig, now=now)
    assert not signatures.verify_slack(SLACK_SECRET, ts, body, "v0=" + "0" * 64, now=now)
    # Outside the five-minute window either way: a replay of an old request.
    assert not signatures.verify_slack(SLACK_SECRET, ts, body, sig, now=now + 301)
    assert not signatures.verify_slack(SLACK_SECRET, ts, body, sig, now=now - 301)
    assert signatures.verify_slack(SLACK_SECRET, ts, body, sig, now=now + 299)
    assert not signatures.verify_slack(SLACK_SECRET, "not-a-number", body, sig, now=now)
    assert not signatures.verify_slack("", ts, body, sig, now=now)


def test_webex_signature():
    body = b'{"resource":"messages"}'
    sig = hmac.new(WEBEX_SECRET.encode(), body, hashlib.sha1).hexdigest()
    assert signatures.verify_webex(WEBEX_SECRET, body, sig)
    assert signatures.verify_webex(WEBEX_SECRET, body, sig.upper())
    assert not signatures.verify_webex(WEBEX_SECRET, body + b" ", sig)
    assert not signatures.verify_webex(WEBEX_SECRET, body, "")
    assert not signatures.verify_webex("", body, sig)


def _teams_auth(body: bytes, token: str = TEAMS_TOKEN) -> str:
    digest = hmac.new(base64.b64decode(token), body, hashlib.sha256).digest()
    return "HMAC " + base64.b64encode(digest).decode()


def test_teams_signature():
    body = b'{"type":"message","text":"help"}'
    assert signatures.verify_teams(TEAMS_TOKEN, body, _teams_auth(body))
    assert not signatures.verify_teams(TEAMS_TOKEN, body + b"x", _teams_auth(body))
    assert not signatures.verify_teams(TEAMS_TOKEN, body, _teams_auth(body).replace("HMAC", "Bearer"))
    assert not signatures.verify_teams("not base64!", body, _teams_auth(body))
    assert not signatures.verify_teams(TEAMS_TOKEN, body, "")


def test_replay_guard_expires_and_caps():
    guard = signatures.ReplayGuard(ttl=10, size=3)
    assert guard.seen("a", now=0) is False
    assert guard.seen("a", now=5) is True
    assert guard.seen("a", now=11) is False  # expired, seen again as new
    for key in ("b", "c", "d"):
        guard.seen(key, now=12)
    assert guard.seen("a", now=12) is False  # pushed out by the size cap
    assert guard.seen("", now=12) is False


# ── Parser and formatters ────────────────────────────────────────────────────


def test_parse():
    assert dispatcher.parse("") == ("help", [])
    assert dispatcher.parse("/plexus") == ("help", [])
    assert dispatcher.parse("/plexus Device edge-rtr-01") == ("device", ["edge-rtr-01"])
    assert dispatcher.parse('plexus run "nightly backup"') == ("run", ["nightly backup"])
    assert dispatcher.parse("@plexus trace 192.0.2.1 198.51.100.7 tcp 443") == (
        "trace",
        ["192.0.2.1", "198.51.100.7", "tcp", "443"],
    )
    assert dispatcher.parse('alerts "unclosed') == ("alerts", ['"unclosed'])


def _sample_reply() -> Reply:
    return Reply(
        title="core_sw <!channel>",
        text="a *bold* claim & more",
        fields=[("Status", "up"), ("Owner", "<@U0EXAMPLE1>")],
        items=[f"item {n}" for n in range(30)],
        note="from stored data",
        actions=[Action("Acknowledge #7", "ack 7")],
    )


def test_slack_blocks_escape_and_buttons():
    body = replies.to_slack(_sample_reply())
    assert body["response_type"] == "ephemeral"
    text = json.dumps(body["blocks"])
    assert "<!channel>" not in text and "&lt;!channel&gt;" in text
    assert "<@U0EXAMPLE1>" not in text
    actions = next(b for b in body["blocks"] if b["type"] == "actions")
    assert actions["elements"][0]["value"] == "ack 7"
    items = next(b for b in body["blocks"] if "item 0" in b.get("text", {}).get("text", ""))
    assert "and 5 more" in items["text"]["text"]
    assert replies.to_slack(Reply(title="x", public=True))["response_type"] == "in_channel"


def test_webex_markdown_and_card():
    body = replies.to_webex(_sample_reply())
    assert body["markdown"].startswith("**core\\_sw \\<!channel\\>**")
    assert "\\*bold\\*" in body["markdown"]
    card = body["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard"
    assert card["actions"][0] == {"type": "Action.Submit", "title": "Acknowledge #7", "data": {"plexus_cmd": "ack 7"}}
    assert "attachments" not in replies.to_webex(Reply(title="plain"))


def test_teams_card_lists_commands_instead_of_buttons():
    body = replies.to_teams(_sample_reply())
    card = body["attachments"][0]["content"]
    assert "actions" not in card
    assert any("/plexus ack 7" in block.get("text", "") for block in card["body"])
    facts = next(b for b in card["body"] if b["type"] == "FactSet")["facts"]
    assert facts[0] == {"title": "Status", "value": "up"}
    error_card = replies.adaptive_card(replies.error("Not allowed"), submit=False)
    assert error_card["body"][0]["color"] == "attention"


def test_inbound_parsers():
    activity = {
        "id": "act-1",
        "text": "<at>Plexus</at>&nbsp;device <b>edge-rtr-01</b>",
        "from": {"id": "29:example", "aadObjectId": "00000000-0000-0000-0000-000000000001", "name": "Ana"},
    }
    inbound = adapters.teams_activity(activity)
    assert inbound.text == "device edge-rtr-01"
    assert inbound.identities == ["00000000-0000-0000-0000-000000000001", "29:example"]
    assert adapters.strip_mention("NetBot alerts", "group") == "alerts"
    assert adapters.strip_mention("Plexus alerts", "group") == "Plexus alerts"  # parse() drops it
    assert adapters.strip_mention("/plexus alerts", "group") == "/plexus alerts"
    assert adapters.strip_mention("alerts", "direct") == "alerts"
    assert adapters.is_bot_email("plexus@webex.bot")
    assert adapters.valid_slack_response_url("https://hooks.slack.com/commands/T0/1/abc")
    assert not adapters.valid_slack_response_url("https://hooks.slack.com.example.com/x")
    assert not adapters.valid_slack_response_url("http://hooks.slack.com/x")
    press = adapters.slack_interaction(
        {"type": "block_actions", "user": {"id": "U0EXAMPLE1"}, "actions": [{"value": "ack 3"}], "response_url": "u"}
    )
    assert press is not None and press.text == "ack 3"
    assert adapters.slack_interaction({"type": "view_submission"}) is None


# ── Dispatcher, identity and permissions ─────────────────────────────────────


async def _plexus_user(name: str, features: list[str] | None, role: str = "user") -> int:
    user_id = await db.create_user(name, "hash", "salt", role=role)
    if features is not None:
        group = await db.create_access_group(f"{name} access", "", features)
        await db.set_user_groups(user_id, [group])
    return user_id


async def _chat(platform: str, chat_id: str, user_id: int | None) -> ChatUser:
    if user_id is not None:
        await db.create_chatops_user_mapping(
            platform=platform, chat_user_id=chat_id, chat_label="", user_id=user_id, created_by="admin"
        )
    return await dispatcher.resolve_user(platform, [chat_id])


async def test_unmapped_user_gets_only_help():
    user = await _chat("slack", "U0NOBODY01", None)
    assert not user.mapped
    reply = await dispatcher.handle(user, "device edge-rtr-01", ALL)
    assert "not linked" in reply.text and "U0NOBODY01" in reply.text
    reply = await dispatcher.handle(user, "help", ALL)
    assert "not linked" in reply.text
    log = await db.list_chatops_command_log()
    assert [row["outcome"] for row in log] == ["ok", "unmapped"]
    assert log[1]["command"] == "device" and log[1]["username"] == ""
    events = [e for e in await db.get_audit_events(limit=50) if e["category"] == "chatops"]
    assert [e["action"] for e in events] == ["command", "command"]
    assert '"outcome": "unmapped"' in "".join(e["detail"] for e in events)


async def test_mapping_matches_email_ignoring_case_and_follows_user():
    user_id = await _plexus_user("ana", ["chatops", "inventory"])
    await db.create_chatops_user_mapping(
        platform="webex", chat_user_id="Ana@Example.com", chat_label="Ana", user_id=user_id, created_by="admin"
    )
    user = await dispatcher.resolve_user("webex", ["Y2lzY29zcGFyazovL3VzL1BFT1BMRS9leGFtcGxl", "ana@example.com"])
    assert user.mapped and user.username == "ana" and "inventory" in user.features
    other = await dispatcher.resolve_user("slack", ["ana@example.com"])
    assert not other.mapped


async def test_permissions_feature_bot_allowlist_and_scope():
    group = await db.create_group("Campus", "")
    await db.add_host(group, "edge-rtr-01", "192.0.2.1", "cisco_ios")
    no_chatops = await _chat("slack", "U0A", await _plexus_user("no-chatops", ["inventory"]))
    reply = await dispatcher.handle(no_chatops, "device edge-rtr-01", ALL)
    assert reply.ok is False and "ChatOps feature" in reply.text
    no_inventory = await _chat("slack", "U0B", await _plexus_user("no-inv", ["chatops"]))
    reply = await dispatcher.handle(no_inventory, "device edge-rtr-01", ALL)
    assert reply.ok is False and "inventory" in reply.text
    allowed = await _chat("slack", "U0C", await _plexus_user("reader", ["chatops", "inventory"]))
    reply = await dispatcher.handle(allowed, "device edge-rtr-01", ALL)
    assert reply.ok and reply.title == "edge-rtr-01 (192.0.2.1)"
    reply = await dispatcher.handle(allowed, "device edge-rtr-01", ALL - {"device"})
    assert reply.ok is False and "not enabled on this bot" in reply.text
    help_reply = await dispatcher.handle(allowed, "help", ALL)
    assert any(item.startswith("/plexus device") for item in help_reply.items)
    assert not any(item.startswith("/plexus alerts") for item in help_reply.items)

    scoped_id = await _plexus_user("scoped", None)
    scope_group = await db.create_access_group(
        "scoped access",
        "",
        ["chatops", "inventory"],
        object_scope="groups",
        inventory_scopes=[{"inventory_group_id": group, "can_write": False}],
    )
    await db.set_user_groups(scoped_id, [scope_group])
    scoped = await _chat("slack", "U0D", scoped_id)
    assert scoped.object_scoped
    reply = await dispatcher.handle(scoped, "device edge-rtr-01", ALL)
    assert reply.ok is False

    unknown = await dispatcher.handle(allowed, "reboot everything", ALL)
    assert unknown.ok is False and "Unknown command" in unknown.title
    outcomes = [row["outcome"] for row in await db.list_chatops_command_log(limit=50)]
    assert {"denied", "ok", "unknown"} <= set(outcomes)


async def test_rate_limit(monkeypatch):
    monkeypatch.setattr(dispatcher, "COMMANDS_PER_MINUTE", 2)
    user = await _chat("teams", "aad-1", await _plexus_user("busy", ["chatops", "jobs"]))
    assert (await dispatcher.handle(user, "jobs", ALL)).ok
    assert (await dispatcher.handle(user, "jobs", ALL)).ok
    limited = await dispatcher.handle(user, "jobs", ALL)
    assert limited.ok is False and limited.title == "Too many commands"


# ── Commands with seeded data ────────────────────────────────────────────────


async def _admin_chat(chat_id: str = "U0ADMIN001") -> ChatUser:
    return await _chat("slack", chat_id, await _plexus_user("chat-admin", None, role="admin"))


async def _seed_hosts() -> dict[str, int]:
    group = await db.create_group("Campus", "")
    return {
        "rtr": await db.add_host(group, "edge-rtr-01", "192.0.2.1", "cisco_ios"),
        "sw": await db.add_host(group, "core-sw-01", "192.0.2.2", "cisco_ios"),
    }


async def test_device_interfaces_and_status():
    ids = await _seed_hosts()
    await db.upsert_interface_inventory(ids["sw"], 1, "Gi1/0/1", "user port", "up", "up", 1000, "full", "", 20, "")
    await db.upsert_interface_inventory(ids["sw"], 2, "Te1/1/1", "uplink", "up", "down", 10000, "full", "", 0, "")
    await db.create_monitoring_poll(ids["rtr"], cpu_percent=42.0, memory_percent=61.0, response_time_ms=12.0)
    admin = await _admin_chat()

    reply = await dispatcher.handle(admin, "device 192.0.2.2", ALL)
    assert reply.title == "core-sw-01 (192.0.2.2)" and ("Group", "Campus") in reply.fields

    reply = await dispatcher.handle(admin, "interfaces core-sw-01", ALL)
    assert ("Up", "1") in reply.fields and ("Not up", "1") in reply.fields
    assert reply.items[0].startswith("Gi1/0/1  up/up  1G") and "10G" in reply.items[1]
    reply = await dispatcher.handle(admin, "int core-sw-01 te1", ALL)
    assert len(reply.items) == 1 and reply.items[0].startswith("Te1/1/1")
    reply = await dispatcher.handle(admin, "interfaces edge-rtr-01", ALL)
    assert "No data" in reply.text

    reply = await dispatcher.handle(admin, "status edge-rtr-01", ALL)
    assert ("CPU", "42.0%") in reply.fields and ("Memory", "61.0%") in reply.fields
    reply = await dispatcher.handle(admin, "status core-sw-01", ALL)
    assert "No data" in reply.text

    reply = await dispatcher.handle(admin, "device", ALL)
    assert reply.ok is False and "Usage" in reply.text
    reply = await dispatcher.handle(admin, "device no-such-device", ALL)
    assert reply.ok is False and "No host matches" in reply.text and "search_hosts" not in reply.text


async def test_alerts_and_ack():
    ids = await _seed_hosts()
    poll = await db.create_monitoring_poll(ids["rtr"], cpu_percent=95.0)
    alert_id = await db.create_monitoring_alert(
        ids["rtr"], poll, "threshold", "cpu_percent", "CPU above 90%", "critical", 95, 90
    )
    await db.create_monitoring_alert(
        ids["sw"], None, "threshold", "memory_percent", "Memory above 80%", "warning", 85, 80, dedup_key="m"
    )
    admin = await _admin_chat()
    reply = await dispatcher.handle(admin, "alerts", ALL)
    assert reply.title == "Active alerts (2)"
    assert any(f"#{alert_id} [CRITICAL] edge-rtr-01: CPU above 90%" in i for i in reply.items)
    assert Action(f"Acknowledge #{alert_id}", f"ack {alert_id}") in reply.actions
    reply = await dispatcher.handle(admin, "alerts core-sw-01 warning", ALL)
    assert len(reply.items) == 1 and "Memory above 80%" in reply.items[0]
    # Without ack enabled on the bot there are no buttons.
    reply = await dispatcher.handle(admin, "alerts", ALL - {"ack"})
    assert reply.actions == []

    reader = await _chat("slack", "U0READ001", await _plexus_user("watcher", ["chatops", "monitoring"]))
    reply = await dispatcher.handle(reader, f"ack {alert_id}", ALL)
    assert reply.ok is False and "monitoring.write" in reply.text
    assert (await dispatcher.handle(reader, "alerts", ALL)).actions == []

    reply = await dispatcher.handle(admin, f"ack #{alert_id}", ALL)
    assert reply.ok and reply.public and "acknowledged by chat-admin" in reply.title
    stored = await db.get_monitoring_alert(alert_id)
    assert stored["acknowledged"] and stored["acknowledged_by"] == "chat-admin"
    reply = await dispatcher.handle(admin, f"ack {alert_id}", ALL)
    assert "already acknowledged" in reply.title
    assert (await dispatcher.handle(admin, "ack 999999", ALL)).ok is False
    assert (await dispatcher.handle(admin, "ack abc", ALL)).ok is False


async def test_ip_lookup():
    await _seed_hosts()
    source = await db.get_or_create_builtin_ipam_source()
    await db.create_ipam_prefix(int(source["id"]), "198.51.100.0/24", description="Example servers")
    admin = await _admin_chat()
    reply = await dispatcher.handle(admin, "ip 198.51.100.0/24", ALL)
    assert reply.title == "Prefix 198.51.100.0/24"
    assert any("Example servers" in i for i in reply.items)
    reply = await dispatcher.handle(admin, "ip 198.51.100.9", ALL)
    assert reply.title == "Address 198.51.100.9" and ("Subnet", "198.51.100.0/24") in reply.fields
    reply = await dispatcher.handle(admin, "ip 203.0.113.50", ALL)
    assert "No IPAM subnet" in reply.text
    reply = await dispatcher.handle(admin, "ip not-an-ip", ALL)
    assert reply.ok is False


async def test_trace_without_data_explains():
    admin = await _admin_chat()
    reply = await dispatcher.handle(admin, "trace 192.0.2.10 198.51.100.20 tcp 443", ALL)
    assert reply.ok and reply.title == "Path 192.0.2.10 to 198.51.100.20"
    assert reply.text
    reply = await dispatcher.handle(admin, "trace 192.0.2.10 198.51.100.20 sideways", ALL)
    assert reply.ok is False and "Unexpected" in reply.text
    reply = await dispatcher.handle(admin, "trace 192.0.2.10", ALL)
    assert reply.ok is False and "Usage" in reply.text


def _job_id(reply: Reply) -> int:
    match = re.match(r"Job #(\d+) queued", reply.title)
    assert match, reply.title
    return int(match.group(1))


async def _seed_job(launched_by: str, *, permissions: dict | None = None) -> int:
    group = await db.create_group("Lab", "")
    host = await db.add_host(group, "lab-sw-01", "192.0.2.50", "cisco_ios")
    playbook = await db.create_playbook("Backup configs", "backup_configs.py", permissions=permissions)
    return await db.create_job(playbook, None, None, None, True, launched_by=launched_by, host_ids=[host])


async def test_jobs_job_and_presets(no_job_queue):
    admin = await _admin_chat()
    job_id = await _seed_job("chat-admin")
    reply = await dispatcher.handle(admin, "jobs", ALL)
    assert reply.items and reply.items[0].startswith(f"#{job_id} Backup configs")
    reply = await dispatcher.handle(admin, f"job {job_id}", ALL)
    assert reply.title == f"Job #{job_id}: Backup configs" and ("Mode", "dry run") in reply.fields

    other = await _chat("slack", "U0OTHER01", await _plexus_user("other", ["chatops", "jobs", "jobs.write"]))
    reply = await dispatcher.handle(other, f"job {job_id}", ALL)
    assert reply.ok is False and "you can view" in reply.text

    reply = await dispatcher.handle(other, "run", ALL)
    assert "No job presets" in reply.text
    from netcontrol.routes.jobs import job_clone_spec

    spec = job_clone_spec(await db.get_job(job_id))
    assert spec["host_ids"] and spec["parameters"] is None
    await db.create_chatops_job_preset(
        name="nightly backup",
        description="Back up the lab",
        spec=spec,
        source_job_id=job_id,
        playbook_name="Backup configs",
        commit=False,
        enabled=True,
        user="admin",
    )
    reply = await dispatcher.handle(other, "run", ALL)
    assert reply.items == ["nightly backup (dry run): Back up the lab"]
    reply = await dispatcher.handle(other, "run Nightly Backup", ALL)
    assert reply.ok and reply.public and reply.title.startswith("Job #")
    new_id = _job_id(reply)
    queued = await db.get_job(new_id)
    assert queued["launched_by"] == "other" and queued["dry_run"] and json.loads(queued["host_ids"]) == spec["host_ids"]
    reply = await dispatcher.handle(other, "run nightly backup", ALL - {"run"})
    assert reply.ok is False
    reply = await dispatcher.handle(other, "run unknown preset", ALL)
    assert reply.ok is False and "no approved job preset" in reply.text

    reader = await _chat("slack", "U0JOBREAD", await _plexus_user("job-reader", ["chatops", "jobs"]))
    reply = await dispatcher.handle(reader, "run nightly backup", ALL)
    assert reply.ok is False and "jobs.write" in reply.text


async def test_commit_preset_needs_confirm_and_playbook_permission(no_job_queue):
    job_id = await _seed_job("admin", permissions={"run": {"roles": ["admin"]}})
    from netcontrol.routes.jobs import job_clone_spec

    await db.create_chatops_job_preset(
        name="push vlan",
        description="",
        spec=job_clone_spec(await db.get_job(job_id)),
        source_job_id=job_id,
        playbook_name="Backup configs",
        commit=True,
        enabled=True,
        user="admin",
    )
    admin = await _admin_chat()
    reply = await dispatcher.handle(admin, "run push vlan", ALL)
    assert reply.title.startswith("Run 'push vlan' with commit?")
    assert reply.actions[0].command == "run push vlan confirm" and reply.actions[0].danger
    reply = await dispatcher.handle(admin, "run push vlan confirm", ALL)
    assert reply.ok and reply.title.startswith("Job #")
    queued = await db.get_job(_job_id(reply))
    assert not queued["dry_run"]

    operator = await _chat("slack", "U0OPER001", await _plexus_user("operator", ["chatops", "jobs", "jobs.write"]))
    reply = await dispatcher.handle(operator, "run push vlan confirm", ALL)
    assert reply.ok is False and "not allowed to run" in reply.text


# ── Alert notifications through a bot ────────────────────────────────────────


def test_chat_channel_types_sanitize():
    assert nc.sanitize_channel({"id": "s", "type": "slack", "chat_channel": "C0EXAMPLE"}).chat_channel == "C0EXAMPLE"
    assert nc.sanitize_channel({"id": "w", "type": "webex", "chat_channel": "Y2lzY29zcGFyazovL3JPT00"})
    assert nc.sanitize_channel({"id": "s", "type": "slack"}) is None
    cfg = nc.sanitize_channel({"id": "s", "type": "slack", "chat_channel": "C0EXAMPLE"})
    assert nc.channel_config_to_dict(cfg)["chat_channel"] == "C0EXAMPLE"


def test_alert_reply_shares_teams_facts():
    alert = {"alert_id": 7, "hostname": "edge-rtr-01", "severity": "critical", "metric": "cpu_percent", "value": 95}
    reply = notify.alert_reply(alert, can_ack=True)
    assert reply.fields == nc.alert_facts(alert)
    assert [f["name"] for f in nc.format_teams(alert)["sections"][0]["facts"]] == [k for k, _ in reply.fields]
    assert reply.actions == [Action("Acknowledge", "ack 7")] and reply.title == nc.alert_summary(alert)
    assert notify.alert_reply(alert, can_ack=False).actions == []


async def test_deliver_chat_alert_posts_with_bot_token(monkeypatch):
    from netcontrol.chatops import bots

    sent: list[tuple] = []

    async def _post(token, channel, body):
        sent.append((token, channel, body))

    async def _send(token, room, body, parent_id=""):
        sent.append((token, room, body))

    monkeypatch.setattr(adapters, "slack_post", _post)
    monkeypatch.setattr(adapters, "webex_send", _send)
    alert = {"alert_id": 9, "hostname": "edge-rtr-01", "severity": "warning", "metric": "cpu_percent"}
    with pytest.raises(RuntimeError):
        await notify.deliver_chat_alert("slack", "C0EXAMPLE", alert)
    await db.upsert_chatops_bot(
        "slack",
        name="Plexus",
        enabled=True,
        allowed_commands=["alerts", "ack"],
        signing_secret_enc=bots.encrypt_secret(SLACK_SECRET),
        bot_token_enc=bots.encrypt_secret("xoxb-example-token"),
        user="admin",
    )
    cfg = nc.sanitize_channel({"id": "chat", "type": "slack", "chat_channel": "C0EXAMPLE"})
    await nc.deliver(cfg, alert)
    token, channel, body = sent[-1]
    assert token == "xoxb-example-token" and channel == "C0EXAMPLE"
    assert body["response_type"] == "in_channel"
    assert next(b for b in body["blocks"] if b["type"] == "actions")["elements"][0]["value"] == "ack 9"
    await db.upsert_chatops_bot(
        "webex",
        name="Plexus",
        enabled=True,
        allowed_commands=["alerts"],
        signing_secret_enc=bots.encrypt_secret(WEBEX_SECRET),
        bot_token_enc=bots.encrypt_secret("webex-example-token"),
        user="admin",
    )
    await notify.deliver_chat_alert("webex", "room-1", alert)
    assert "attachments" not in sent[-1][2]  # ack not enabled: no button


async def test_slack_post_reports_api_errors(monkeypatch):
    class _Resp:
        status_code = 200

        @staticmethod
        def json():
            return {"ok": False, "error": "channel_not_found"}

    async def _send(*_a, **_k):
        return _Resp()

    monkeypatch.setattr(adapters, "send_request", _send)
    with pytest.raises(adapters.ChatDeliveryError, match="channel_not_found"):
        await adapters.slack_post("xoxb-example-token", "C0EXAMPLE", {"text": "x"})
    with pytest.raises(adapters.ChatDeliveryError):
        await adapters.slack_respond("https://attacker.example.com/hook", {"text": "x"})


# ── HTTP: admin API and inbound endpoints ────────────────────────────────────


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200):
    assert resp.status_code == status, resp.text
    return resp.json()


def _setup_bot(admin: CsrfClient, platform: str, secret: str, **extra) -> dict:
    body = {
        "name": "Plexus",
        "enabled": True,
        "allowed_commands": ["device", "alerts", "ack"],
        "signing_secret": secret,
    }
    return _ok(admin.put(f"{ADMIN}/bots/{platform}", json={**body, **extra}))


def _map(admin: CsrfClient, platform: str, chat_id: str, username: str = "admin") -> dict:
    users = _ok(admin.get("/api/admin/users"))
    user_id = next(int(u["id"]) for u in users if u["username"] == username)
    return _ok(
        admin.post(f"{ADMIN}/mappings", json={"platform": platform, "chat_user_id": chat_id, "user_id": user_id}), 201
    )


def _seed_host(admin: CsrfClient) -> None:
    gid = int(_ok(admin.post("/api/inventory", json={"name": "Campus"}), 201)["id"])
    body = {"hostname": "edge-rtr-01", "ip_address": "192.0.2.1", "device_type": "cisco_ios"}
    _ok(admin.post(f"/api/inventory/{gid}/hosts", json=body), 201)


def test_admin_api_secrets_mappings_and_access(admin):
    overview = _ok(admin.get(ADMIN))
    assert [p["platform"] for p in overview["platforms"]] == ["slack", "webex", "teams"]
    assert all(p["bot"] is None for p in overview["platforms"])
    assert "ack" in {c["name"] for c in overview["commands"]} and "ack" not in overview["default_commands"]

    assert admin.put(f"{ADMIN}/bots/slack", json={"allowed_commands": []}).status_code == 422  # secret required
    assert admin.put(f"{ADMIN}/bots/slack", json={"signing_secret": "short"}).status_code == 422
    assert admin.put(f"{ADMIN}/bots/irc", json={"signing_secret": SLACK_SECRET}).status_code == 404
    assert (
        admin.put(f"{ADMIN}/bots/slack", json={"signing_secret": SLACK_SECRET, "allowed_commands": ["rm"]}).status_code
        == 422
    )
    assert admin.put(f"{ADMIN}/bots/teams", json={"signing_secret": "not base64 !!"}).status_code == 422
    assert (
        admin.put(f"{ADMIN}/bots/teams", json={"signing_secret": TEAMS_TOKEN, "bot_token": "x" * 20}).status_code == 422
    )
    bot = _setup_bot(admin, "slack", SLACK_SECRET, bot_token="xoxb-example-token")
    assert bot["signing_secret_configured"] and bot["bot_token_configured"]
    text = json.dumps(_ok(admin.get(ADMIN)))
    assert SLACK_SECRET not in text and "xoxb-example-token" not in text
    # Saving without secrets keeps them; clear_bot_token drops the token.
    bot = _ok(admin.put(f"{ADMIN}/bots/slack", json={"enabled": True, "allowed_commands": ["device"]}))
    assert bot["signing_secret_configured"] and bot["bot_token_configured"] and bot["allowed_commands"] == ["device"]
    bot = _ok(admin.put(f"{ADMIN}/bots/slack", json={"allowed_commands": ["device"], "clear_bot_token": True}))
    assert not bot["bot_token_configured"]

    mapping = _map(admin, "slack", "U0EXAMPLE1")
    assert mapping["username"] == "admin"
    dup = admin.post(f"{ADMIN}/mappings", json={"platform": "slack", "chat_user_id": "u0example1", "user_id": 1})
    assert dup.status_code == 409
    bad = admin.post(f"{ADMIN}/mappings", json={"platform": "slack", "chat_user_id": "has space", "user_id": 1})
    assert bad.status_code == 422
    assert (
        admin.post(f"{ADMIN}/mappings", json={"platform": "slack", "chat_user_id": "U0X", "user_id": 99999}).status_code
        == 422
    )
    assert len(_ok(admin.get(f"{ADMIN}/mappings"))) == 1
    _ok(admin.delete(f"{ADMIN}/mappings/{mapping['id']}"))
    assert admin.delete(f"{ADMIN}/mappings/{mapping['id']}").status_code == 404

    reader = user_client(admin, "chat-reader", features=["chatops"])
    assert reader.get(ADMIN).status_code == 403
    assert reader.put(f"{ADMIN}/bots/slack", json={"signing_secret": SLACK_SECRET}).status_code == 403

    _ok(admin.delete(f"{ADMIN}/bots/slack"))
    assert admin.delete(f"{ADMIN}/bots/slack").status_code == 404


def test_admin_presets_from_job(admin):
    import asyncio

    job_id = asyncio.run(_seed_job("admin"))
    preset = _ok(
        admin.post(f"{ADMIN}/presets", json={"name": "nightly backup", "job_id": job_id, "description": "Lab"}), 201
    )
    assert preset["playbook_name"] == "Backup configs" and preset["targets"] == "1 hosts"
    assert preset["commit"] is False and preset["source_job_id"] == job_id
    assert admin.post(f"{ADMIN}/presets", json={"name": "Nightly Backup", "job_id": job_id}).status_code == 409
    assert admin.post(f"{ADMIN}/presets", json={"name": "x", "job_id": 999999}).status_code == 422
    assert admin.post(f"{ADMIN}/presets", json={"name": "!bad", "job_id": job_id}).status_code == 422
    assert admin.post(f"{ADMIN}/presets", json={"name": "go confirm", "job_id": job_id}).status_code == 422
    updated = _ok(admin.put(f"{ADMIN}/presets/{preset['id']}", json={"commit": True, "enabled": False}))
    assert updated["commit"] and not updated["enabled"]
    assert [p["name"] for p in _ok(admin.get(f"{ADMIN}/presets"))] == ["nightly backup"]
    _ok(admin.delete(f"{ADMIN}/presets/{preset['id']}"))
    assert admin.delete(f"{ADMIN}/presets/{preset['id']}").status_code == 404
    assert admin.put(f"{ADMIN}/presets/{preset['id']}", json={}).status_code == 404


_TRIGGERS = itertools.count(1)


def _slack_post(admin: CsrfClient, path: str, form: dict, *, secret: str = SLACK_SECRET, ts: str | None = None):
    # Slack gives every request its own trigger_id, so no two bodies match.
    body = urlencode({**form, "trigger_id": f"trigger-{next(_TRIGGERS)}"}).encode()
    stamp = ts or str(int(time.time()))
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Slack-Request-Timestamp": stamp,
        "X-Slack-Signature": _slack_sig(secret, stamp, body),
    }
    return admin.raw.post(path, content=body, headers=headers)


def test_slack_slash_command_endpoint(admin):
    form = {"text": "device edge-rtr-01", "user_id": "U0EXAMPLE1", "user_name": "ana", "response_url": ""}
    assert _slack_post(admin, chatops_routes.SLACK_COMMANDS_PATH, form).status_code == 404  # no bot yet
    _setup_bot(admin, "slack", SLACK_SECRET)
    _seed_host(admin)

    unmapped = _ok(_slack_post(admin, chatops_routes.SLACK_COMMANDS_PATH, form))
    assert "not linked" in json.dumps(unmapped) and "U0EXAMPLE1" in json.dumps(unmapped)

    _map(admin, "slack", "U0EXAMPLE1")
    answer = _ok(_slack_post(admin, chatops_routes.SLACK_COMMANDS_PATH, form))
    assert answer["response_type"] == "ephemeral" and "edge-rtr-01 (192.0.2.1)" in answer["text"]

    assert _slack_post(admin, chatops_routes.SLACK_COMMANDS_PATH, form, secret="wrong-secret-value").status_code == 401
    old = str(int(time.time()) - 600)
    assert _slack_post(admin, chatops_routes.SLACK_COMMANDS_PATH, form, ts=old).status_code == 401
    # The exact same signed request a second time is refused.
    body = urlencode(form).encode()
    stamp = str(int(time.time()))
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Slack-Request-Timestamp": stamp,
        "X-Slack-Signature": _slack_sig(SLACK_SECRET, stamp, body),
    }
    assert admin.raw.post(chatops_routes.SLACK_COMMANDS_PATH, content=body, headers=headers).status_code == 200
    assert admin.raw.post(chatops_routes.SLACK_COMMANDS_PATH, content=body, headers=headers).status_code == 401
    big = admin.raw.post(chatops_routes.SLACK_COMMANDS_PATH, content=b"x" * 70000, headers=headers)
    assert big.status_code == 413
    log = _ok(admin.get(f"{ADMIN}/log?platform=slack"))
    assert {row["outcome"] for row in log} == {"unmapped", "ok"}


def test_slack_button_press_acknowledges(admin, monkeypatch):
    responses: list[tuple[str, dict]] = []

    async def _respond(url, body):
        responses.append((url, body))

    monkeypatch.setattr(adapters, "slack_respond", _respond)
    _setup_bot(admin, "slack", SLACK_SECRET)
    _map(admin, "slack", "U0EXAMPLE1")

    async def _seed() -> int:
        group = await db.create_group("Edge", "")
        host = await db.add_host(group, "edge-fw-01", "192.0.2.9", "cisco_asa")
        return await db.create_monitoring_alert(host, None, "threshold", "cpu_percent", "CPU high", "critical", 99, 90)

    import asyncio

    alert_id = asyncio.run(_seed())
    payload = {
        "type": "block_actions",
        "user": {"id": "U0EXAMPLE1", "username": "ana"},
        "actions": [{"action_id": "plexus_cmd_0", "value": f"ack {alert_id}"}],
        "response_url": "https://hooks.slack.com/actions/T0/1/example",
    }
    resp = _slack_post(admin, chatops_routes.SLACK_INTERACTIVITY_PATH, {"payload": json.dumps(payload)})
    assert resp.status_code == 200
    assert responses and responses[0][0] == payload["response_url"]
    assert "acknowledged by admin" in responses[0][1]["text"] and responses[0][1]["replace_original"] is False
    alert = _ok(admin.get("/api/monitoring/alerts?acknowledged=true"))
    assert any(a["id"] == alert_id and a["acknowledged_by"] == "admin" for a in alert)


def _webex_post(admin: CsrfClient, payload: dict, secret: str = WEBEX_SECRET):
    body = json.dumps(payload).encode()
    sig = hmac.new(secret.encode(), body, hashlib.sha1).hexdigest()
    return admin.raw.post(
        chatops_routes.WEBEX_PATH, content=body, headers={"Content-Type": "application/json", "X-Spark-Signature": sig}
    )


def test_webex_webhook(admin, monkeypatch):
    sent: list[tuple] = []

    async def _text(token, message_id):
        return "Plexus device edge-rtr-01"

    async def _card(token, action_id):
        return "help"

    async def _send(token, room, body, parent_id=""):
        sent.append((token, room, body))

    async def _emails(token, person_id):
        return ["ana@example.com"]

    monkeypatch.setattr(adapters, "webex_message_text", _text)
    monkeypatch.setattr(adapters, "webex_card_command", _card)
    monkeypatch.setattr(adapters, "webex_send", _send)
    monkeypatch.setattr(adapters, "webex_person_emails", _emails)
    _setup_bot(admin, "webex", WEBEX_SECRET, bot_token="webex-example-token")
    _seed_host(admin)
    _map(admin, "webex", "ana@example.com")
    message = {
        "resource": "messages",
        "event": "created",
        "data": {
            "id": "msg1",
            "roomId": "room1",
            "roomType": "group",
            "personId": "p1",
            "personEmail": "ana@example.com",
        },
    }
    assert _webex_post(admin, message, secret="wrong-secret-value").status_code == 401
    assert _ok(_webex_post(admin, message)) == {"ok": True}
    token, room, body = sent[-1]
    assert token == "webex-example-token" and room == "room1" and "edge-rtr-01 (192.0.2.1)" in body["markdown"]
    assert _ok(_webex_post(admin, message))["duplicate"] is True
    assert len(sent) == 1
    from_bot = {**message, "data": {**message["data"], "id": "msg2", "personEmail": "plexus@webex.bot"}}
    assert _ok(_webex_post(admin, from_bot))["ignored"] is True
    # A card button: no e-mail in the event; the person is looked up.
    action = {
        "resource": "attachmentActions",
        "event": "created",
        "data": {"id": "act1", "roomId": "room1", "personId": "p1"},
    }
    assert _ok(_webex_post(admin, action)) == {"ok": True}
    assert "Plexus ChatOps commands" in sent[-1][2]["markdown"]


def _teams_post(admin: CsrfClient, activity: dict, token: str = TEAMS_TOKEN):
    body = json.dumps(activity).encode()
    return admin.raw.post(
        chatops_routes.TEAMS_PATH,
        content=body,
        headers={"Content-Type": "application/json", "Authorization": _teams_auth(body, token)},
    )


def test_teams_outgoing_webhook(admin):
    _setup_bot(admin, "teams", TEAMS_TOKEN)
    _seed_host(admin)
    _map(admin, "teams", "00000000-0000-0000-0000-000000000001")
    activity = {
        "type": "message",
        "id": "1700000000001",
        "text": "<at>Plexus</at> device edge-rtr-01",
        "from": {"id": "29:example", "aadObjectId": "00000000-0000-0000-0000-000000000001", "name": "Ana"},
    }
    other = base64.b64encode(b"some-other-security-token").decode()
    assert _teams_post(admin, activity, token=other).status_code == 401
    answer = _ok(_teams_post(admin, activity))
    card = answer["attachments"][0]["content"]
    assert answer["type"] == "message" and card["body"][0]["text"] == "edge-rtr-01 (192.0.2.1)"
    assert "Already answered" in json.dumps(_ok(_teams_post(admin, activity)))


def test_inbound_endpoints_need_no_session_but_a_bot(admin):
    for path in (chatops_routes.WEBEX_PATH, chatops_routes.TEAMS_PATH, chatops_routes.SLACK_INTERACTIVITY_PATH):
        assert admin.raw.post(path, content=b"{}", headers={"Content-Type": "application/json"}).status_code == 404


def test_notification_channel_api_accepts_chat_types(admin):
    body = {"name": "Slack NOC", "type": "slack", "chat_channel": "C0EXAMPLE", "severity_floor": "warning"}
    created = _ok(admin.post("/api/admin/notification-channels", json=body))
    assert created["type"] == "slack" and created["chat_channel"] == "C0EXAMPLE"
    assert admin.post("/api/admin/notification-channels", json={**body, "chat_channel": ""}).status_code == 400
