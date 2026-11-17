"""The platform-neutral reply and its Slack, Webex and Teams forms.

A command answers with a ``Reply``: a title, an optional paragraph, label /
value fields, bullet items, a footnote and action buttons that each run a
Plexus command (``ack 12``). Each platform renders it in its own format:

- Slack: Block Kit (``section`` / ``fields`` / ``context`` / ``actions``);
  a button's value is the command, sent back through interactivity.
- Webex: markdown, plus an Adaptive Card whose ``Action.Submit`` buttons
  carry ``{"plexus_cmd": "<command>"}`` when there are actions.
- Teams: an Adaptive Card. An outgoing webhook cannot receive card
  submissions, so actions are shown as the command to type.

Every value is escaped for the target markup; chat users and devices name
things, and a name must never become a link or a mention.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MAX_ITEMS = 25
MAX_FIELDS = 10
MAX_TEXT = 2800
MAX_ACTIONS = 5
ACTION_KEY = "plexus_cmd"

# Adaptive Card colour per alert severity / reply tone.
_CARD_COLOR = {"critical": "attention", "warning": "warning", "info": "accent", "error": "attention"}


@dataclass
class Action:
    label: str
    command: str
    danger: bool = False


@dataclass
class Reply:
    title: str
    text: str = ""
    fields: list[tuple[str, str]] = field(default_factory=list)
    items: list[str] = field(default_factory=list)
    note: str = ""
    actions: list[Action] = field(default_factory=list)
    ok: bool = True
    # Shown to the whole channel instead of only the caller (Slack).
    public: bool = False
    severity: str = ""

    def plain(self) -> str:
        """The reply as plain text (logs, fallbacks, notification bodies)."""
        lines = [self.title]
        if self.text:
            lines.append(self.text)
        lines += [f"{k}: {v}" for k, v in self.fields[:MAX_FIELDS]]
        lines += [f"- {item}" for item in self.items[:MAX_ITEMS]]
        if len(self.items) > MAX_ITEMS:
            lines.append(f"... and {len(self.items) - MAX_ITEMS} more")
        if self.note:
            lines.append(self.note)
        return _cap("\n".join(lines))


def error(title: str, text: str = "") -> Reply:
    return Reply(title=title, text=text, ok=False)


def _cap(text: str, limit: int = MAX_TEXT) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _items(reply: Reply) -> list[str]:
    items = list(reply.items[:MAX_ITEMS])
    if len(reply.items) > MAX_ITEMS:
        items.append(f"... and {len(reply.items) - MAX_ITEMS} more")
    return items


# ── Slack (Block Kit mrkdwn) ─────────────────────────────────────────────────


def slack_escape(text: Any) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def to_slack(reply: Reply) -> dict[str, Any]:
    """A slash-command / ``response_url`` / ``chat.postMessage`` body."""
    blocks: list[dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": _cap(f"*{slack_escape(reply.title)}*")}}
    ]
    if reply.text:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": _cap(slack_escape(reply.text))}})
    if reply.fields:
        blocks.append(
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": _cap(f"*{slack_escape(k)}*\n{slack_escape(v)}", 1900)}
                    for k, v in reply.fields[:MAX_FIELDS]
                ],
            }
        )
    items = _items(reply)
    if items:
        body = "\n".join(f"• {slack_escape(i)}" for i in items)
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": _cap(body)}})
    if reply.note:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": _cap(slack_escape(reply.note))}]})
    if reply.actions:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "action_id": f"{ACTION_KEY}_{n}",
                        "text": {"type": "plain_text", "text": a.label[:75]},
                        "value": a.command[:2000],
                        **({"style": "danger"} if a.danger else {"style": "primary"}),
                    }
                    for n, a in enumerate(reply.actions[:MAX_ACTIONS])
                ],
            }
        )
    return {
        "response_type": "in_channel" if reply.public else "ephemeral",
        "text": _cap(reply.plain(), 3000),
        "blocks": blocks,
    }


# ── Webex (markdown + Adaptive Card) ─────────────────────────────────────────

_WEBEX_SPECIAL = re.compile(r"([\\`*_\[\]<>#|~])")


def webex_escape(text: Any) -> str:
    return _WEBEX_SPECIAL.sub(r"\\\1", str(text))


def to_webex_markdown(reply: Reply) -> str:
    lines = [f"**{webex_escape(reply.title)}**"]
    if reply.text:
        lines.append(webex_escape(reply.text))
    lines += [f"- **{webex_escape(k)}**: {webex_escape(v)}" for k, v in reply.fields[:MAX_FIELDS]]
    lines += [f"- {webex_escape(i)}" for i in _items(reply)]
    if reply.note:
        lines.append(f"_{webex_escape(reply.note)}_")
    return _cap("\n".join(lines), 7000)


def to_webex(reply: Reply) -> dict[str, Any]:
    """The ``POST /v1/messages`` body without ``roomId``."""
    body: dict[str, Any] = {"markdown": to_webex_markdown(reply)}
    if reply.actions:
        body["attachments"] = [
            {"contentType": "application/vnd.microsoft.card.adaptive", "content": adaptive_card(reply, submit=True)}
        ]
    return body


# ── Adaptive Card (Webex attachments, Teams) ─────────────────────────────────


def card_escape(text: Any) -> str:
    """Adaptive Card TextBlocks render a markdown subset; keep values literal."""
    return _WEBEX_SPECIAL.sub(r"\\\1", str(text))


def adaptive_card(reply: Reply, *, submit: bool) -> dict[str, Any]:
    """An Adaptive Card 1.3 for ``reply``. With ``submit`` the actions are
    ``Action.Submit`` buttons; without, the command to type is listed."""
    color = _CARD_COLOR.get(reply.severity or ("" if reply.ok else "error"), "default")
    body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "text": card_escape(reply.title),
            "weight": "Bolder",
            "size": "Medium",
            "wrap": True,
            "color": color,
        }
    ]
    if reply.text:
        body.append({"type": "TextBlock", "text": _cap(card_escape(reply.text)), "wrap": True})
    if reply.fields:
        body.append(
            {
                "type": "FactSet",
                "facts": [{"title": str(k), "value": card_escape(v)} for k, v in reply.fields[:MAX_FIELDS]],
            }
        )
    items = _items(reply)
    if items:
        body.append({"type": "TextBlock", "text": _cap("\n".join(f"- {card_escape(i)}" for i in items)), "wrap": True})
    actions = reply.actions[:MAX_ACTIONS]
    if actions and not submit:
        hint = "  \n".join(f"{a.label}: `/plexus {card_escape(a.command)}`" for a in actions)
        body.append({"type": "TextBlock", "text": hint, "wrap": True, "isSubtle": True})
    if reply.note:
        body.append({"type": "TextBlock", "text": _cap(card_escape(reply.note)), "wrap": True, "isSubtle": True})
    card: dict[str, Any] = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.3",
        "body": body,
    }
    if actions and submit:
        card["actions"] = [
            {"type": "Action.Submit", "title": a.label[:60], "data": {ACTION_KEY: a.command}} for a in actions
        ]
    return card


def to_teams(reply: Reply) -> dict[str, Any]:
    """The synchronous answer to a Teams outgoing webhook."""
    return {
        "type": "message",
        "text": reply.title,
        "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "content": adaptive_card(reply, submit=False)}
        ],
    }


def render(platform: str, reply: Reply) -> dict[str, Any]:
    if platform == "slack":
        return to_slack(reply)
    if platform == "webex":
        return to_webex(reply)
    return to_teams(reply)
