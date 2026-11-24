"""The one path every chat command takes, whatever the platform.

``handle`` parses ``/plexus <command> args``, maps the chat user to a Plexus
user (an unmapped user gets help and nothing else), rate-limits the chat
user, checks the bot's allowed commands and the user's features, runs the
command, and writes the command log row and an audit event. It never
raises: every outcome is a ``Reply``.
"""

from __future__ import annotations

import json
import shlex
import time

import routes.database as db

from netcontrol.chatops import commands
from netcontrol.chatops.commands import ChatUser, CommandError, Invocation
from netcontrol.chatops.replies import Reply, error
from netcontrol.mcp.dispatch import rate_limited
from netcontrol.object_scope import scope_for_user
from netcontrol.routes.shared import _audit
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.chatops")

PLATFORMS = ("slack", "webex", "teams")
COMMANDS_PER_MINUTE = 30
LOG_RETENTION_DAYS = 90
_PREFIXES = ("/plexus", "plexus", "@plexus")
_MAX_INPUT = 500
_prune_counter = 0


def parse(text: str) -> tuple[str, list[str]]:
    """``(command, args)`` from what the user typed. A leading ``/plexus``,
    ``plexus`` or ``@plexus`` is dropped; quotes group words; an empty line
    is ``help``."""
    text = (text or "").strip()[:_MAX_INPUT]
    try:
        words = shlex.split(text)
    except ValueError:
        words = text.split()
    while words and words[0].lower() in _PREFIXES:
        words = words[1:]
    if not words:
        return "help", []
    return words[0].lower(), words[1:]


async def resolve_user(platform: str, identities: list[str], display_name: str = "") -> ChatUser:
    """The chat identity (``identities[0]`` is the platform's user id; the
    rest are e-mail addresses) as a ``ChatUser``, mapped when a mapping
    matches any of them and the Plexus user still exists and may sign in:
    a disabled account, or one that must change its password first, is
    treated as unmapped, as its sessions and tokens are refused."""
    from netcontrol.routes.auth import _get_user_features

    chat_id = next((i for i in identities if i), "")
    mapping = await db.find_chatops_user_mapping(platform, identities)
    if mapping is None:
        return ChatUser(platform=platform, chat_user_id=chat_id, chat_user_name=display_name)
    user = await db.get_user_by_id(int(mapping["user_id"]))
    if not user or user.get("disabled") or user.get("must_change_password"):
        return ChatUser(platform=platform, chat_user_id=chat_id, chat_user_name=display_name)
    return ChatUser(
        platform=platform,
        chat_user_id=chat_id,
        chat_user_name=display_name,
        user=user,
        features=frozenset(await _get_user_features(user)),
        object_scoped=(await scope_for_user(user)).restricted,
    )


async def _record(user: ChatUser, command: str, args: list[str], outcome: str, detail: str, started: float) -> None:
    global _prune_counter
    duration = int((time.monotonic() - started) * 1000)
    arguments = " ".join(args)
    try:
        await db.add_chatops_command_log(
            platform=user.platform,
            chat_user_id=user.chat_user_id,
            chat_user_name=user.chat_user_name,
            username=user.username,
            command=command,
            arguments=arguments,
            outcome=outcome,
            detail=detail,
            duration_ms=duration,
        )
        _prune_counter += 1
        if _prune_counter % 200 == 1:
            await db.prune_chatops_command_log(LOG_RETENTION_DAYS)
    except Exception:
        LOGGER.exception("chatops: could not write the command log")
    audit_detail = {
        "platform": user.platform,
        "chat_user": user.chat_user_id[:200],
        "command": command[:60],
        "arguments": arguments[:300],
        "outcome": outcome,
        "duration_ms": duration,
    }
    await _audit(
        "chatops",
        "command",
        user=user.username or f"{user.platform}:{user.chat_user_id}"[:200],
        detail=json.dumps(audit_detail),
    )


async def handle(user: ChatUser, text: str, allowed_commands: list[str] | frozenset[str]) -> Reply:
    started = time.monotonic()
    name, args = parse(text)
    command = commands.get(name)
    allowed = frozenset(allowed_commands)
    if command is None:
        await _record(user, name, args, "unknown", "", started)
        return error(f"Unknown command: {name}", "Type /plexus help for the list of commands.")
    if command.name != "help" and rate_limited(f"chatops:{user.platform}:{user.chat_user_id}", COMMANDS_PER_MINUTE):
        await _record(user, command.name, args, "rate_limited", "", started)
        return error("Too many commands", "Wait a minute and try again.")
    inv = Invocation(user=user, allowed_commands=allowed)
    reason = commands.refusal(command, inv)
    if reason == "unmapped":
        await _record(user, command.name, args, "unmapped", "", started)
        return await commands.help_reply(inv, [])
    if reason:
        await _record(user, command.name, args, "denied", reason, started)
        return error("Not allowed", reason)
    try:
        reply = await command.handler(inv, args)
    except CommandError as exc:
        await _record(user, command.name, args, "error", str(exc), started)
        return error(f"/plexus {command.name}", str(exc))
    except Exception:
        LOGGER.exception("chatops: command %s failed", command.name)
        await _record(user, command.name, args, "error", "internal error", started)
        return error(f"/plexus {command.name}", "The command failed. See the Plexus server log.")
    await _record(user, command.name, args, "ok", "" if reply.ok else reply.title, started)
    return reply
