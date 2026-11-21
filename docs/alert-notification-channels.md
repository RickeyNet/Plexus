# Alert Notification Channels

Monitoring alerts (CPU/memory thresholds, interface/VPN down, route churn,
baseline deviations, and user-defined rules) can be delivered to external
on-call tooling so a 3 AM critical reaches a phone, not just an in-app toast.

Supported channel types:

- **Email (SMTP)** — STARTTLS or implicit TLS (SMTPS), optional auth, multiple
  recipients.
- **PagerDuty** — Events API v2 `trigger`. The alert's dedup key is reused as
  PagerDuty's dedup key so repeated alerts collapse onto one incident.
- **Webhook** — generic `POST` of a stable JSON body (`source:"plexus"`,
  severity, host, metric, value/threshold, message, dedup key), with an
  optional auth header.
- **Microsoft Teams** — posts a MessageCard to an incoming-webhook connector.
- **Slack** and **Webex** — posted by the [ChatOps](chatops.md) bot of that
  platform (its bot token) to a channel ID (Slack) or room ID (Webex), with
  the alert's facts and, when `ack` is an allowed command of the bot, an
  **Acknowledge** button that acknowledges the alert as the mapped Plexus
  user who presses it. Set up the bot first under **Settings → ChatOps**.

### Configuration

Channels are managed in the UI under **Settings → Notifications** (admin only),
or via the admin API:

| Method | Endpoint                                          | Description                          |
|--------|---------------------------------------------------|--------------------------------------|
| GET    | `/api/admin/notification-channels`                | List channels + defaults + live stats |
| POST   | `/api/admin/notification-channels`                | Create a channel                     |
| PUT    | `/api/admin/notification-channels/{id}`           | Update a channel                     |
| DELETE | `/api/admin/notification-channels/{id}`           | Delete a channel                     |
| POST   | `/api/admin/notification-channels/{id}/test`      | Deliver a synthetic probe alert      |
| PUT    | `/api/admin/notification-channels-defaults`       | Set the default channel set          |

Secrets (SMTP password, PagerDuty routing key, webhook auth value) are masked
as `••••••••` in API responses; submit the mask to keep the stored value.
The mask keeps a secret only while it goes to the same place: a save that
changes the SMTP server or port, turns SMTP encryption off, changes the
webhook URL's scheme, host or port, or turns certificate checks off is
refused with `400` until the secret is typed again. The secrets are stored
encrypted in the database.
The webhook and Teams URLs and an email channel's SMTP server pass the
outbound address guard ([webhooks.md](webhooks.md#outbound-address-check)):
the SMTP server when a new or changed one is saved (`400` naming the guard)
and before each message. A cloud metadata address is always refused, a
name that does not resolve too, and a private address when
`APP_SSRF_BLOCK_PRIVATE=true`; list a trusted SMTP relay in
`APP_SSRF_ALLOW` if needed.
Slack and Webex channels take `chat_channel` (the channel or room id); their
token is the ChatOps bot's, stored with the bot.

Meraki alerts (alert type `meraki_alert`, from the assurance-alert poll and
the Meraki webhook receiver) go through the same channels: on the matching
inventory host as a monitoring alert, otherwise straight to the default
channel set. See [meraki-alerts.md](meraki-alerts.md).

### Routing

- Each alert rule (**Monitoring → Rules**) can be assigned one or more channels.
- Alerts not tied to a rule — built-in thresholds, baseline deviations, route
  churn — use the **default** channel set.
- Each channel has a **severity floor**; alerts below it are dropped for that
  channel.
- Delivery is best-effort with a bounded per-channel queue (drop-oldest on
  overflow) and exponential-backoff retry, so a wedged endpoint never blocks
  alert creation. Repeated occurrences of the same alert are de-duplicated and
  do **not** re-notify.
