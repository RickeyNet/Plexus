"""Inbound payload parsing and outbound replies per platform.

Every outbound call goes through ``netcontrol.routes.outbound_http`` (SSRF
guard, no redirects). The hosts are fixed per platform (``slack.com``,
``webexapis.com``); a Slack ``response_url`` must be an https URL on
``slack.com`` before anything is sent to it. Teams replies in the HTTP
response of its outgoing webhook and has no outbound call.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from netcontrol.routes.outbound_http import OutboundRequestError, send_request

SLACK_API = "https://slack.com/api"
WEBEX_API = "https://webexapis.com/v1"
HTTP_TIMEOUT = 10.0
_ID_RE = re.compile(r"^[A-Za-z0-9_=-]{1,200}$")
_TAG_RE = re.compile(r"<[^>]{0,500}>")
_AT_RE = re.compile(r"<at>[^<]{0,200}</at>", re.IGNORECASE)


class ChatDeliveryError(RuntimeError):
    """A platform API call failed; the message names the platform and status."""


@dataclass
class Inbound:
    """One command received from a platform."""

    identities: list[str]
    display_name: str
    text: str
    # Where to answer: Slack response_url, Webex room / parent message.
    reply_to: dict[str, Any] = field(default_factory=dict)
    # A platform delivery id for the replay guard (Webex / Teams).
    delivery_id: str = ""


async def _call(method: str, url: str, token: str, *, json: Any = None, label: str) -> dict:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        resp = await send_request(method, url, json=json, headers=headers, timeout_s=HTTP_TIMEOUT)
    except OutboundRequestError as exc:
        raise ChatDeliveryError(f"{label}: target rejected ({exc})") from exc
    if resp.status_code >= 400:
        raise ChatDeliveryError(f"{label}: HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


# ── Slack ────────────────────────────────────────────────────────────────────


def slack_slash(form: dict[str, str]) -> Inbound:
    return Inbound(
        identities=[str(form.get("user_id") or "")],
        display_name=str(form.get("user_name") or ""),
        text=str(form.get("text") or ""),
        reply_to={"response_url": str(form.get("response_url") or "")},
    )


def slack_interaction(payload: dict[str, Any]) -> Inbound | None:
    """A Block Kit button press; ``None`` for anything else."""
    if payload.get("type") != "block_actions":
        return None
    actions = payload.get("actions") or []
    if not actions or not isinstance(actions[0], dict):
        return None
    user = payload.get("user") or {}
    return Inbound(
        identities=[str(user.get("id") or "")],
        display_name=str(user.get("username") or user.get("name") or ""),
        text=str(actions[0].get("value") or ""),
        reply_to={"response_url": str(payload.get("response_url") or "")},
    )


def valid_slack_response_url(url: str) -> bool:
    parts = urlsplit(url or "")
    host = (parts.hostname or "").lower()
    return parts.scheme == "https" and (host == "slack.com" or host.endswith(".slack.com"))


async def slack_respond(response_url: str, body: dict[str, Any]) -> None:
    """Answer a slash command or button later, through its ``response_url``."""
    if not valid_slack_response_url(response_url):
        raise ChatDeliveryError("slack: response_url is not a slack.com URL")
    await _call("POST", response_url, "", json=body, label="slack response_url")


async def slack_post(token: str, channel: str, body: dict[str, Any]) -> None:
    """``chat.postMessage`` to ``channel`` (an id such as ``C0123ABCD``)."""
    message = {k: v for k, v in body.items() if k != "response_type"}
    data = await _call(
        "POST", f"{SLACK_API}/chat.postMessage", token, json={"channel": channel, **message}, label="slack"
    )
    if not data.get("ok"):
        raise ChatDeliveryError(f"slack: {str(data.get('error') or 'not ok')[:80]}")


# ── Webex ────────────────────────────────────────────────────────────────────


def _webex_id(value: Any) -> str:
    text = str(value or "")
    if not _ID_RE.match(text):
        raise ChatDeliveryError("webex: invalid id in the webhook")
    return text


def is_bot_email(email: str) -> bool:
    """Messages from bots (this one included) are ignored."""
    return (email or "").lower().endswith("@webex.bot")


async def webex_message_text(token: str, message_id: str) -> str:
    data = await _call("GET", f"{WEBEX_API}/messages/{_webex_id(message_id)}", token, label="webex")
    return str(data.get("text") or "")


async def webex_card_command(token: str, action_id: str) -> str:
    """The command a card button carried (``inputs.plexus_cmd``)."""
    from netcontrol.chatops.replies import ACTION_KEY

    data = await _call("GET", f"{WEBEX_API}/attachment/actions/{_webex_id(action_id)}", token, label="webex")
    inputs = data.get("inputs") or {}
    return str(inputs.get(ACTION_KEY) or "") if isinstance(inputs, dict) else ""


async def webex_person_emails(token: str, person_id: str) -> list[str]:
    data = await _call("GET", f"{WEBEX_API}/people/{_webex_id(person_id)}", token, label="webex")
    return [str(e) for e in data.get("emails") or [] if e]


async def webex_send(token: str, room_id: str, body: dict[str, Any], parent_id: str = "") -> None:
    message = {"roomId": _webex_id(room_id), **body}
    if parent_id:
        message["parentId"] = _webex_id(parent_id)
    await _call("POST", f"{WEBEX_API}/messages", token, json=message, label="webex")


def strip_mention(text: str, room_type: str) -> str:
    """In a group space the message starts with the bot's name (the
    mention); drop that first word."""
    text = (text or "").strip()
    if room_type == "group" and text and not text.lower().startswith(("/plexus", "plexus")):
        parts = text.split(None, 1)
        return parts[1] if len(parts) > 1 else ""
    return text


# ── Teams ────────────────────────────────────────────────────────────────────


def teams_activity(activity: dict[str, Any]) -> Inbound:
    sender = activity.get("from") or {}
    raw = str(activity.get("text") or "")
    text = html.unescape(_TAG_RE.sub(" ", _AT_RE.sub(" ", raw))).replace("\xa0", " ")
    return Inbound(
        identities=[str(sender.get("aadObjectId") or ""), str(sender.get("id") or "")],
        display_name=str(sender.get("name") or ""),
        text=" ".join(text.split()),
        delivery_id=str(activity.get("id") or ""),
    )
