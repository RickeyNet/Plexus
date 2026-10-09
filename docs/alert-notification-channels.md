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
