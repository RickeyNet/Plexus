"""ChatOps HTTP routes: the inbound bot endpoints and the admin settings API.

Inbound (``inbound_router``, no session, no CSRF, rate limited per source IP
as webhook paths): each platform's request signature is checked before the
body is used, and a platform without an enabled bot answers 404.

- ``POST /api/chatops/slack/commands``      Slack slash command (``/plexus``)
- ``POST /api/chatops/slack/interactivity`` Slack Block Kit button presses
- ``POST /api/chatops/webex``               Webex webhook (messages, card actions)
- ``POST /api/chatops/teams``               Teams outgoing webhook

Admin (``admin_router``, admin only): bots, user mappings, job presets and
the command log under ``/api/admin/chatops``. See docs/chatops.md.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import re
from typing import Any
from urllib.parse import parse_qs

import routes.database as db
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from netcontrol.chatops import adapters, bots, commands, dispatcher
from netcontrol.chatops.replies import Reply, to_slack, to_teams, to_webex
from netcontrol.chatops.signatures import (
    ReplayGuard,
    fresh_delivery_time,
    verify_slack,
    verify_teams,
    verify_webex,
)
from netcontrol.routes.shared import _audit, _corr_id, _session_user, read_bounded_body, supervise_task
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.chatops")

inbound_router = APIRouter()
admin_router = APIRouter()

SLACK_COMMANDS_PATH = "/api/chatops/slack/commands"
SLACK_INTERACTIVITY_PATH = "/api/chatops/slack/interactivity"
WEBEX_PATH = "/api/chatops/webex"
TEAMS_PATH = "/api/chatops/teams"
WEBHOOK_PATHS = frozenset({SLACK_COMMANDS_PATH, SLACK_INTERACTIVITY_PATH, WEBEX_PATH, TEAMS_PATH})
INBOUND_PATHS = {
    "slack": {"commands": SLACK_COMMANDS_PATH, "interactivity": SLACK_INTERACTIVITY_PATH},
    "webex": {"webhook": WEBEX_PATH},
    "teams": {"webhook": TEAMS_PATH},
}

MAX_BODY_BYTES = 64 * 1024
# Slack wants an answer within 3 s; Teams within 5 s. Slower commands
# answer later through Slack's response_url; Teams has no later channel.
SLACK_INLINE_SECONDS = 2.5
TEAMS_TIMEOUT_SECONDS = 4.5

# Platforms retry deliveries and a captured signed body can be resent.
_SLACK_SEEN = ReplayGuard()
_WEBEX_SEEN = ReplayGuard()
_TEAMS_SEEN = ReplayGuard()


def reset_replay_guards() -> None:
    for guard in (_SLACK_SEEN, _WEBEX_SEEN, _TEAMS_SEEN):
        guard.clear()


def _status(code: int, detail: str) -> JSONResponse:
    return JSONResponse(status_code=code, content={"detail": detail})


async def _signed_body(request: Request) -> bytes | JSONResponse:
    body = await read_bounded_body(request, MAX_BODY_BYTES)
    if body is None:
        return _status(413, "Payload Too Large")
    return body


# ── Slack ────────────────────────────────────────────────────────────────────


async def _slack_verified(request: Request) -> tuple[bots.BotConfig, bytes] | JSONResponse:
    bot = await bots.load_bot("slack")
    if bot is None:
        return _status(404, "Not Found")
    body = await _signed_body(request)
    if isinstance(body, JSONResponse):
        return body
    signature = request.headers.get("x-slack-signature", "")
    timestamp = request.headers.get("x-slack-request-timestamp", "")
    if not verify_slack(bot.signing_secret, timestamp, body, signature) or _SLACK_SEEN.seen(signature):
        return _status(401, "Unauthorized")
    return bot, body


def _form(body: bytes) -> dict[str, str]:
    parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    return {k: v[0] for k, v in parsed.items() if v}


async def _slack_later(task: asyncio.Task, response_url: str) -> None:
    try:
        reply = await task
        await adapters.slack_respond(response_url, {**to_slack(reply), "replace_original": False})
    except Exception as exc:  # noqa: BLE001 - logged; the user sees no answer
        LOGGER.warning("chatops slack: late reply failed: %s", type(exc).__name__)


@inbound_router.post(SLACK_COMMANDS_PATH, include_in_schema=False)
async def slack_commands(request: Request):
    verified = await _slack_verified(request)
    if isinstance(verified, JSONResponse):
        return verified
    bot, body = verified
    inbound = adapters.slack_slash(_form(body))
    user = await dispatcher.resolve_user("slack", inbound.identities, inbound.display_name)
    task = asyncio.create_task(dispatcher.handle(user, inbound.text, bot.allowed_commands))
    done, _ = await asyncio.wait({task}, timeout=SLACK_INLINE_SECONDS)
    if task in done:
        return to_slack(task.result())
    response_url = inbound.reply_to.get("response_url", "")
    if not adapters.valid_slack_response_url(response_url):
        return to_slack(await task)
    supervise_task(asyncio.create_task(_slack_later(task, response_url)), "chatops slack reply")
    return {"response_type": "ephemeral", "text": "Working on it..."}


@inbound_router.post(SLACK_INTERACTIVITY_PATH, include_in_schema=False)
async def slack_interactivity(request: Request, background: BackgroundTasks):
    verified = await _slack_verified(request)
    if isinstance(verified, JSONResponse):
        return verified
    bot, body = verified
    try:
        payload = json.loads(_form(body).get("payload") or "")
    except ValueError:
        return _status(400, "Bad Request")
    inbound = adapters.slack_interaction(payload) if isinstance(payload, dict) else None
    if inbound is None:
        return Response(status_code=200)

    async def _run() -> None:
        user = await dispatcher.resolve_user("slack", inbound.identities, inbound.display_name)
        reply = await dispatcher.handle(user, inbound.text, bot.allowed_commands)
        try:
            await adapters.slack_respond(
                inbound.reply_to.get("response_url", ""), {**to_slack(reply), "replace_original": False}
            )
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("chatops slack: button reply failed: %s", type(exc).__name__)

    background.add_task(_run)
    return Response(status_code=200)


# ── Webex ────────────────────────────────────────────────────────────────────


async def _webex_process(bot: bots.BotConfig, resource: str, data: dict[str, Any]) -> None:
    try:
        if resource == "messages":
            text = adapters.strip_mention(
                await adapters.webex_message_text(bot.bot_token, str(data.get("id") or "")),
                str(data.get("roomType") or ""),
            )
        else:
            text = await adapters.webex_card_command(bot.bot_token, str(data.get("id") or ""))
        person_id = str(data.get("personId") or "")
        identities = [person_id, str(data.get("personEmail") or "")]
        user = await dispatcher.resolve_user("webex", identities)
        if not user.mapped and not data.get("personEmail") and person_id:
            emails = await adapters.webex_person_emails(bot.bot_token, person_id)
            user = await dispatcher.resolve_user("webex", [person_id, *emails])
        reply = await dispatcher.handle(user, text, bot.allowed_commands)
        await adapters.webex_send(bot.bot_token, str(data.get("roomId") or ""), to_webex(reply))
    except Exception as exc:  # noqa: BLE001 - the webhook was already acknowledged
        LOGGER.warning("chatops webex: processing failed: %s", type(exc).__name__)


@inbound_router.post(WEBEX_PATH, include_in_schema=False)
async def webex_webhook(request: Request, background: BackgroundTasks):
    bot = await bots.load_bot("webex")
    if bot is None:
        return _status(404, "Not Found")
    body = await _signed_body(request)
    if isinstance(body, JSONResponse):
        return body
    if not verify_webex(bot.signing_secret, body, request.headers.get("x-spark-signature", "")):
        return _status(401, "Unauthorized")
    try:
        payload = json.loads(body)
    except ValueError:
        return _status(400, "Bad Request")
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        return _status(400, "Bad Request")
    data = payload["data"]
    resource = str(payload.get("resource") or "")
    if payload.get("event") != "created" or resource not in ("messages", "attachmentActions"):
        return {"ok": True, "ignored": True}
    if resource == "messages" and adapters.is_bot_email(str(data.get("personEmail") or "")):
        return {"ok": True, "ignored": True}
    # Replay: a delivery with no id or a signed time (data.created) more
    # than five minutes old is refused; a repeat inside that window is a
    # duplicate.
    data_id = str(data.get("id") or "")
    if not data_id or not fresh_delivery_time(data.get("created")):
        LOGGER.warning("chatops webex: refused a delivery with no id or an old, missing or bad time")
        return _status(400, "Bad Request")
    if _WEBEX_SEEN.seen(f"{resource}:{data_id}"):
        return {"ok": True, "duplicate": True}
    if not bot.bot_token:
        LOGGER.warning("chatops webex: no bot token stored; cannot read or answer messages")
        return {"ok": True, "ignored": True}
    background.add_task(_webex_process, bot, resource, data)
    return {"ok": True}


# ── Teams ────────────────────────────────────────────────────────────────────


@inbound_router.post(TEAMS_PATH, include_in_schema=False)
async def teams_webhook(request: Request):
    bot = await bots.load_bot("teams")
    if bot is None:
        return _status(404, "Not Found")
    body = await _signed_body(request)
    if isinstance(body, JSONResponse):
        return body
    if not verify_teams(bot.signing_secret, body, request.headers.get("authorization", "")):
        return _status(401, "Unauthorized")
    try:
        activity = json.loads(body)
    except ValueError:
        return _status(400, "Bad Request")
    if not isinstance(activity, dict):
        return _status(400, "Bad Request")
    inbound = adapters.teams_activity(activity)
    # Replay: an activity with no id or a signed timestamp more than five
    # minutes old is refused; a repeat inside that window is a duplicate.
    if not inbound.delivery_id or not fresh_delivery_time(activity.get("timestamp")):
        LOGGER.warning("chatops teams: refused an activity with no id or an old, missing or bad timestamp")
        return _status(400, "Bad Request")
    if _TEAMS_SEEN.seen(inbound.delivery_id):
        return to_teams(Reply(title="Already answered", ok=False))
    user = await dispatcher.resolve_user("teams", inbound.identities, inbound.display_name)
    try:
        reply = await asyncio.wait_for(
            dispatcher.handle(user, inbound.text, bot.allowed_commands), TEAMS_TIMEOUT_SECONDS
        )
    except TimeoutError:
        reply = Reply(
            title="Plexus is still working", text="That took too long for Teams. Try a narrower query.", ok=False
        )
    return to_teams(reply)


# ── Admin API ────────────────────────────────────────────────────────────────

_PRESET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$")
_CHAT_ID_RE = re.compile(r"^\S{1,200}$")


class BotUpdate(BaseModel):
    name: str = Field(default="", max_length=80)
    enabled: bool = True
    allowed_commands: list[str] = Field(default_factory=list, max_length=50)
    # Write-only. None keeps the stored value. Checked by hand so a rejected
    # value is never echoed in a validation error.
    signing_secret: str | None = None
    bot_token: str | None = None
    clear_bot_token: bool = False


class MappingCreate(BaseModel):
    platform: str
    chat_user_id: str = Field(max_length=200)
    chat_label: str = Field(default="", max_length=200)
    user_id: int


class PresetCreate(BaseModel):
    name: str = Field(max_length=80)
    description: str = Field(default="", max_length=300)
    job_id: int
    commit: bool = False
    enabled: bool = True


class PresetUpdate(BaseModel):
    description: str = Field(default="", max_length=300)
    commit: bool = False
    enabled: bool = True


def _platform(platform: str) -> str:
    platform = (platform or "").strip().lower()
    if platform not in dispatcher.PLATFORMS:
        raise HTTPException(status_code=404, detail="Unknown platform")
    return platform


def _command_view(command: commands.Command) -> dict[str, Any]:
    return {
        "name": command.name,
        "usage": command.usage,
        "summary": command.summary,
        "features": list(command.features),
        "write": command.write,
    }


async def _overview() -> dict[str, Any]:
    stored = {b["platform"]: b for b in await db.list_chatops_bots()}
    platforms = []
    for platform in dispatcher.PLATFORMS:
        info = bots.PLATFORM_INFO[platform]
        row = stored.get(platform)
        platforms.append(
            {
                "platform": platform,
                "label": info["label"],
                "secret_label": info["secret"],
                "has_bot_token": bool(info["token"]),
                "token_label": info.get("token_label", ""),
                "paths": INBOUND_PATHS[platform],
                "bot": bots.public_view(row) if row else None,
            }
        )
    return {
        "platforms": platforms,
        "commands": [_command_view(c) for c in commands.catalogue() if c.name != "help"],
        "default_commands": commands.default_allowed(),
    }


@admin_router.get("/api/admin/chatops")
async def chatops_overview():
    return await _overview()


def _check_secret(platform: str, value: str, label: str) -> str:
    value = value.strip()
    if not 8 <= len(value) <= 512:
        raise HTTPException(status_code=422, detail=f"The {label} must be 8 to 512 characters.")
    if platform == "teams" and label == "security token":
        try:
            base64.b64decode(value, validate=True)
        except binascii.Error, ValueError:
            raise HTTPException(
                status_code=422, detail="The Teams security token must be the base64 value Teams shows."
            )
    return value


@admin_router.put("/api/admin/chatops/bots/{platform}")
async def chatops_update_bot(platform: str, body: BotUpdate, request: Request):
    platform = _platform(platform)
    known = {c.name for c in commands.catalogue() if c.name != "help"}
    unknown = sorted(set(body.allowed_commands) - known)
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown commands: {', '.join(unknown)}")
    existing = await db.get_chatops_bot(platform)
    secret_enc: str | None = None
    if body.signing_secret:
        secret_enc = bots.encrypt_secret(
            _check_secret(platform, body.signing_secret, "security token" if platform == "teams" else "signing secret")
        )
    elif not existing or not existing.get("signing_secret_enc"):
        raise HTTPException(status_code=422, detail=f"Enter the {bots.PLATFORM_INFO[platform]['secret']}.")
    token_enc: str | None = None
    if body.clear_bot_token:
        token_enc = ""
    elif body.bot_token:
        if not bots.PLATFORM_INFO[platform]["token"]:
            raise HTTPException(status_code=422, detail="This platform has no bot token.")
        token_enc = bots.encrypt_secret(_check_secret(platform, body.bot_token, "bot token"))
    user = _session_user(request)
    allowed = [c.name for c in commands.catalogue() if c.name in set(body.allowed_commands)]
    row = await db.upsert_chatops_bot(
        platform,
        name=body.name.strip() or str(bots.PLATFORM_INFO[platform]["label"]),
        enabled=body.enabled,
        allowed_commands=allowed,
        signing_secret_enc=secret_enc,
        bot_token_enc=token_enc,
        user=user,
    )
    await _audit(
        "chatops",
        "bot.update",
        user=user,
        detail=(
            f"platform={platform} enabled={body.enabled} commands={','.join(allowed)} "
            f"secret_changed={secret_enc is not None} token_changed={token_enc is not None}"
        ),
        correlation_id=_corr_id(request),
    )
    return bots.public_view(row)


@admin_router.delete("/api/admin/chatops/bots/{platform}")
async def chatops_delete_bot(platform: str, request: Request):
    platform = _platform(platform)
    if not await db.delete_chatops_bot(platform):
        raise HTTPException(status_code=404, detail="No bot is configured for this platform")
    await _audit(
        "chatops",
        "bot.delete",
        user=_session_user(request),
        detail=f"platform={platform}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@admin_router.get("/api/admin/chatops/mappings")
async def chatops_list_mappings():
    return await db.list_chatops_user_mappings()


@admin_router.post("/api/admin/chatops/mappings", status_code=201)
async def chatops_create_mapping(body: MappingCreate, request: Request):
    platform = _platform(body.platform)
    chat_id = body.chat_user_id.strip()
    if not _CHAT_ID_RE.match(chat_id):
        raise HTTPException(status_code=422, detail="Enter the chat user id or e-mail, without spaces.")
    target = await db.get_user_by_id(body.user_id)
    if not target:
        raise HTTPException(status_code=422, detail="Choose an existing Plexus user.")
    user = _session_user(request)
    try:
        mapping_id = await db.create_chatops_user_mapping(
            platform=platform,
            chat_user_id=chat_id,
            chat_label=body.chat_label.strip(),
            user_id=int(target["id"]),
            created_by=user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    await _audit(
        "chatops",
        "mapping.create",
        user=user,
        detail=f"platform={platform} chat_user={chat_id} plexus_user={target['username']}",
        correlation_id=_corr_id(request),
    )
    return next(m for m in await db.list_chatops_user_mappings() if int(m["id"]) == mapping_id)


@admin_router.delete("/api/admin/chatops/mappings/{mapping_id}")
async def chatops_delete_mapping(mapping_id: int, request: Request):
    row = await db.delete_chatops_user_mapping(mapping_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Mapping not found")
    await _audit(
        "chatops",
        "mapping.delete",
        user=_session_user(request),
        detail=f"platform={row['platform']} chat_user={row['chat_user_id']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


def _preset_view(preset: dict) -> dict:
    spec = preset.get("spec") or {}
    targets = []
    if spec.get("host_ids"):
        targets.append(f"{len(spec['host_ids'])} hosts")
    if spec.get("inventory_group_id"):
        targets.append(f"group {spec['inventory_group_id']}")
    if spec.get("dynamic_group_id"):
        targets.append(f"dynamic group {spec['dynamic_group_id']}")
    if spec.get("ad_hoc_ips"):
        targets.append(f"{len(spec['ad_hoc_ips'])} addresses")
    return {
        "id": preset["id"],
        "name": preset["name"],
        "description": preset.get("description") or "",
        "playbook_name": preset.get("playbook_name") or "",
        "source_job_id": preset.get("source_job_id"),
        "targets": ", ".join(targets),
        "commit": bool(preset.get("commit")),
        "enabled": bool(preset.get("enabled")),
        "updated_at": preset.get("updated_at") or "",
        "updated_by": preset.get("updated_by") or "",
    }


@admin_router.get("/api/admin/chatops/presets")
async def chatops_list_presets():
    return [_preset_view(p) for p in await db.list_chatops_job_presets()]


@admin_router.post("/api/admin/chatops/presets", status_code=201)
async def chatops_create_preset(body: PresetCreate, request: Request):
    from netcontrol.routes.jobs import job_clone_spec

    name = body.name.strip()
    if not _PRESET_NAME_RE.match(name) or name.lower().endswith(" confirm"):
        raise HTTPException(
            status_code=422,
            detail="Use 1 to 80 letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit.",
        )
    job = await db.get_job(body.job_id)
    if not job:
        raise HTTPException(status_code=422, detail=f"There is no job #{body.job_id}.")
    user = _session_user(request)
    try:
        preset_id = await db.create_chatops_job_preset(
            name=name,
            description=body.description.strip(),
            spec=job_clone_spec(job),
            source_job_id=int(job["id"]),
            playbook_name=str(job.get("playbook_name") or ""),
            commit=body.commit,
            enabled=body.enabled,
            user=user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    await _audit(
        "chatops",
        "preset.create",
        user=user,
        detail=f"preset={name} job={body.job_id} commit={body.commit}",
        correlation_id=_corr_id(request),
    )
    preset = await db.get_chatops_job_preset(preset_id)
    return _preset_view(preset or {})


@admin_router.put("/api/admin/chatops/presets/{preset_id}")
async def chatops_update_preset(preset_id: int, body: PresetUpdate, request: Request):
    user = _session_user(request)
    preset = await db.update_chatops_job_preset(
        preset_id, description=body.description.strip(), commit=body.commit, enabled=body.enabled, user=user
    )
    if preset is None:
        raise HTTPException(status_code=404, detail="Preset not found")
    await _audit(
        "chatops",
        "preset.update",
        user=user,
        detail=f"preset={preset['name']} commit={body.commit} enabled={body.enabled}",
        correlation_id=_corr_id(request),
    )
    return _preset_view(preset)


@admin_router.delete("/api/admin/chatops/presets/{preset_id}")
async def chatops_delete_preset(preset_id: int, request: Request):
    preset = await db.get_chatops_job_preset(preset_id)
    if not preset or not await db.delete_chatops_job_preset(preset_id):
        raise HTTPException(status_code=404, detail="Preset not found")
    await _audit(
        "chatops",
        "preset.delete",
        user=_session_user(request),
        detail=f"preset={preset['name']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@admin_router.get("/api/admin/chatops/log")
async def chatops_command_log(
    limit: int = Query(default=200, ge=1, le=1000),
    platform: str = Query(default="", max_length=20),
    outcome: str = Query(default="", max_length=20),
):
    return await db.list_chatops_command_log(limit=limit, platform=platform, outcome=outcome)
