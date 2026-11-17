"""Stored bot settings (``chatops_bots``) and their decrypted secrets.

One bot per platform. The signing secret checks inbound requests; the bot
token posts replies (Slack, Webex). Both are encrypted with
``routes.crypto`` and never returned by the API: the admin view shows only
whether each is set.
"""

from __future__ import annotations

from dataclasses import dataclass

import routes.database as db
from routes.crypto import decrypt, encrypt

from netcontrol.chatops import commands
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.chatops")

# The secret each platform signs with and whether it has a bot token.
PLATFORM_INFO: dict[str, dict[str, str | bool]] = {
    "slack": {"label": "Slack", "secret": "Signing secret", "token": True, "token_label": "Bot token (xoxb-)"},
    "webex": {"label": "Webex", "secret": "Webhook secret", "token": True, "token_label": "Bot access token"},
    "teams": {"label": "Microsoft Teams", "secret": "Outgoing webhook security token", "token": False},
}


@dataclass(frozen=True)
class BotConfig:
    platform: str
    name: str
    enabled: bool
    signing_secret: str
    bot_token: str
    allowed_commands: frozenset[str]


def _decrypt(value: str) -> str:
    if not value:
        return ""
    try:
        return decrypt(value) or ""
    except Exception:  # noqa: BLE001 - a key change makes the secret unreadable
        LOGGER.warning("chatops: a stored bot secret could not be decrypted")
        return ""


def encrypt_secret(value: str) -> str:
    return encrypt(value) if value else ""


async def load_bot(platform: str) -> BotConfig | None:
    """The enabled bot of ``platform`` with a signing secret, else ``None``
    (the inbound endpoint then answers 404)."""
    row = await db.get_chatops_bot(platform)
    if not row or not row.get("enabled"):
        return None
    secret = _decrypt(str(row.get("signing_secret_enc") or ""))
    if not secret:
        return None
    known = {c.name for c in commands.catalogue()}
    return BotConfig(
        platform=platform,
        name=str(row.get("name") or ""),
        enabled=True,
        signing_secret=secret,
        bot_token=_decrypt(str(row.get("bot_token_enc") or "")),
        allowed_commands=frozenset(c for c in row["allowed_commands"] if c in known),
    )


def public_view(row: dict) -> dict:
    """A bot row as the admin API shows it: no secrets, only whether set."""
    return {
        "platform": row["platform"],
        "name": row.get("name") or "",
        "enabled": bool(row.get("enabled")),
        "allowed_commands": list(row.get("allowed_commands") or []),
        "signing_secret_configured": bool(row.get("signing_secret_enc")),
        "bot_token_configured": bool(row.get("bot_token_enc")),
        "updated_at": row.get("updated_at") or "",
        "updated_by": row.get("updated_by") or "",
    }
