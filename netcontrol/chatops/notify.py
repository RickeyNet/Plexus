"""Alert notifications through the Slack and Webex ChatOps bots.

``notification_channels`` owns the queue, retries and stats; for a channel of
type ``slack`` or ``webex`` its driver calls ``deliver_chat_alert``, which
posts the alert with the bot's token and adds an **Acknowledge** button. The
button runs ``ack <alert id>`` through the normal command path, so the
person who presses it must be mapped to a Plexus user who may acknowledge
alerts, and ``ack`` must be enabled on the bot.
"""

from __future__ import annotations

from netcontrol.chatops import adapters, bots
from netcontrol.chatops.replies import Action, Reply, to_slack, to_webex
from netcontrol.routes.notification_channels import alert_facts, alert_summary


def alert_reply(alert: dict, *, can_ack: bool) -> Reply:
    actions = []
    alert_id = alert.get("alert_id")
    if can_ack and isinstance(alert_id, int) and alert_id > 0:
        actions.append(Action("Acknowledge", f"ack {alert_id}"))
    return Reply(
        title=alert_summary(alert),
        text=str(alert.get("message") or ""),
        fields=alert_facts(alert),
        note=f"Alert #{alert_id}" if alert_id else "",
        actions=actions,
        public=True,
        severity=str(alert.get("severity") or ""),
    )


async def deliver_chat_alert(platform: str, channel: str, alert: dict) -> None:
    """Post ``alert`` to ``channel`` with the bot of ``platform``. Raises on
    failure so the channel loop retries."""
    bot = await bots.load_bot(platform)
    if bot is None or not bot.bot_token:
        raise RuntimeError(f"{platform} ChatOps bot is not configured or has no bot token")
    reply = alert_reply(alert, can_ack="ack" in bot.allowed_commands)
    if platform == "slack":
        await adapters.slack_post(bot.bot_token, channel, to_slack(reply))
    elif platform == "webex":
        await adapters.webex_send(bot.bot_token, channel, to_webex(reply))
    else:  # pragma: no cover - sanitize_channel admits only the two
        raise ValueError(f"unsupported chat platform: {platform}")
