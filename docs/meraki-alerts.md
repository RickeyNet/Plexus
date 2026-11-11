# Meraki Alerts (near real time)

Plexus learns about Meraki problems within about a minute, instead of at the
next hourly topology collection, through two ingest paths that share one
normaliser and one alert pipeline:

1. **Polling** (outbound only, on by default). Every 60 seconds Plexus reads
   the active assurance alerts of each Meraki organization you have added as a
   source. It works in every deployment, including one with no inbound
   internet access.
2. **Webhook receiver** (inbound, off by default). Meraki POSTs each alert to
   `https://<plexus>/api/webhooks/meraki` as it fires. It needs Plexus (or a
   proxy in front of it) to be reachable from the internet over HTTPS.

Both paths produce the same alert record, so the same Meraki alert arriving by
both paths is one Plexus alert, and a resolve from either path closes it.

Contents:

- [How it works](#how-it-works)
- [Scenario A: internal-only deployment (polling only)](#scenario-a-internal-only-deployment-polling-only)
- [Scenario B: internet-reachable deployment (webhook and polling)](#scenario-b-internet-reachable-deployment-webhook-and-polling)
- [Scenario C: internal deployment that still wants push](#scenario-c-internal-deployment-that-still-wants-push)
- [Scenario D: many networks, organizations and templates](#scenario-d-many-networks-organizations-and-templates)
- [Security model](#security-model)
- [Settings reference](#settings-reference)
- [API](#api)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)

## How it works

### The two paths

| | Polling | Webhook |
|---|---|---|
| Direction | Plexus to Meraki (HTTPS, outbound) | Meraki to Plexus (HTTPS, inbound) |
| Meraki call | `GET /organizations/{organizationId}/assurance/alerts` with `active=true`, `dismissed=false`, `resolved=false`, `perPage=300`, following the `Link` header for more pages | none; Meraki sends a JSON body to the HTTP server you configure |
| What arrives | Meraki's assurance (Health) alerts: categories `connectivity`, `device_health`, `configuration`, `experience_metrics` and `insights`, for example a device that is unreachable, CRC errors on a switch port, high channel utilization | the alert types you turn on per network under **Network-wide > Configure > Alerts** and send to the HTTP server, for example "APs went down", "Switch went down", "Settings changed", VPN connectivity changes, uplink failover |
| Latency | up to one poll interval (60 seconds by default) after Meraki raises the assurance alert | Meraki's documentation says on average within 90 seconds of the event; alerts with a threshold (for example "offline for 5 minutes") wait for it, and some take up to about 10 minutes |
| Resolve | an alert the poll reported before and no longer reports is resolved | a recovery event ("... came up", "... back online", "... recovered") closes the matching alert; an alert type with no recovery event is closed after 24 hours with no new event (`webhook_open_ttl_hours`) |
| Cost | one API call per organization per poll (more only when an organization has more than 300 active alerts) | none on the Meraki API |
| Setup | an API key on the source, nothing else | a shared secret in Plexus, an HTTP server and alert recipients in each Meraki network, public HTTPS reachability |

Polling does not need any change in the Meraki dashboard. The webhook path
reports what the Meraki alert settings send, and nothing else.

Plexus never changes anything in Meraki: the API client issues GET requests
only, and the webhook receiver is registered by hand in the Meraki dashboard.

### One alert record

Each poll row and each webhook is turned into the same record
(`netcontrol/integrations/meraki/alerts.py`): source organization, network,
device serial and name, alert type, title and message, severity, start and
resolve times, and the path it came from (`poll` or `webhook`). Severity is
mapped from Meraki's `alertLevel` (webhooks) or `severity` (assurance alerts):

| Meraki | Plexus |
|---|---|
| `critical` | critical |
| `warning` | warning |
| `informational` | info |
| anything else | warning |

Records are stored in the `meraki_alerts` table and listed under
**Monitoring > Availability > Meraki alerts**.

### Deduplication

The dedupe key is `meraki:<source id>:<subject>:<condition>`:

- the **subject** is the device serial (`d:Q2XX-AAAA-0001`), else the network
  (`n:N_...`), else the organization;
- the **condition** is the alert type with a trailing state word removed
  ("went down", "came up", "down", "up", "offline", "online", "recovered",
  "cleared" and similar) and known equivalents merged. Today one equivalence
  is known: the device-down family (`unreachable` from the poll,
  `stopped_reporting` from the "APs went down" webhook, and the
  "<devices> went down" / "<devices> came up" webhook types) is `device_down`.

So an AP that goes down is one alert whether the webhook or the poll reports
it first, and the "APs came up" webhook resolves it. An alert type that the
two paths name differently, and that is not in the equivalence list, stays two
alerts (see [Limitations](#limitations)).

A resolved alert is reopened only by an event that started after it was
resolved, so Meraki retrying an old delivery does not reopen it.

### Raising alerts

Alerts are raised on the server, never only in the browser, and once per
open alert (again only if the severity gets worse):

- **warning** and **critical** alerts are raised; **info** alerts are stored
  and listed only;
- when the alert's device is an inventory host (matched by serial number or
  host name, the same matching the topology map uses, or the host the
  topology map already matched to that device), Plexus creates a monitoring
  alert on the host (alert type `meraki_alert`, dedup key
  `meraki_alert:<key>`); it is listed under **Monitoring > Alerts** and the
  notification channels deliver it;
- otherwise the alert goes straight to the notification channels (see
  [alert-notification-channels.md](alert-notification-channels.md)) with the
  same event shape;
- when the alert resolves, its monitoring alert is acknowledged as
  `auto-resolved`.

Every step is best effort: a failure is logged with the exception type only
and never stops the poll loop or the webhook response.

### Overlap with the hourly availability alerts

The topology availability tracker
([meraki-topology.md](meraki-topology.md#availability-tracking)) raises
`topology_availability` alerts when a scheduled collection sees a Meraki
device, uplink or tunnel go down. A device that goes down can therefore be
reported by both features. Plexus avoids the duplicate notification for the
device-down case:

- if the tracker already alerted on the device, a later Meraki `device_down`
  alert is stored and listed with **Plexus: Already notified (availability)**
  and is not notified again;
- if a Meraki `device_down` alert was raised first, the tracker records the
  outage in the availability history but does not notify again.

Uplink and tunnel alerts have no such link: a WAN uplink failure can be
notified once by a Meraki alert (when Meraki sends one) and once by the next
collection. The two alert types are distinct (`meraki_alert` and
`topology_availability`), so notification channel rules can tell them apart.

## Scenario A: internal-only deployment (polling only)

Use this when Plexus has no inbound access from the internet. You get every
assurance alert within one poll interval. You do not get the webhook-only
alert types (for example "Settings changed", motion and sensor alerts, or
alert types that are not assurance alerts).

### Requirements

- Outbound HTTPS (TCP 443) from the Plexus host or container to the Meraki
  Dashboard API host of each organization's region. The default is
  `api.meraki.com`; an organization in another region uses that region's host
  (the source's **Base URL**, which must be under `meraki.com`, `meraki.cn`,
  `meraki.in`, `meraki.ca` or `gov-meraki.com`). Meraki can redirect API
  calls to a shard host under the same domain, so allow the domain, not one
  address. If you use an explicit proxy, set `HTTPS_PROXY` for the Plexus
  container.
- A Dashboard API key on each Meraki source. Read-only organization access is
  enough: Plexus only issues GET requests. The key must be able to read the
  organization's assurance alerts (OAuth scope
  `dashboard:general:telemetry:read` if you use an OAuth token).

### Steps

1. Add the Meraki organization under **Topology > Sources > Add Source**
   with its organization ID and API key (see
   [meraki-topology.md](meraki-topology.md#quick-start)). A source with an
   API key is polled automatically.
2. Open **Topology > Sources** as an administrator and expand
   **Meraki alerts**. Check that **Poll assurance alerts** is on and the
   interval suits you (60 seconds by default).
3. Click **Poll Now**. The organization's row shows **Last success** with the
   time, or **Last error** (for example `HTTP 401`).
4. Open **Monitoring > Availability**: active alerts are listed under
   **Meraki alerts**.

### Tuning the interval against the API budget

Meraki allows 10 requests per second per organization, shared by every
application that uses the organization's API keys (with a short burst
allowance), and 100 requests per second per source IP. A request over the
limit gets HTTP 429 with `Retry-After`, which the Plexus client honours.

The alert poll costs one request per organization per interval: at the
default 60 seconds that is about 0.02 requests per second, far below the
budget. The interval can be set from 30 seconds to one hour. The heavy
topology collection (hourly by default) shares the same budget, and other
tools that use the organization's API also count, so keep the poll interval
at 60 seconds or more unless you need faster detection.

A source that fails (401 or 403: the key is wrong or lacks access; 404: the
key cannot see the organization or the assurance endpoint is not available to
it; a timeout) is backed off: retried after two intervals, then four, and so
on, at most hourly for 401/403/404 and every ten minutes for other errors.
Other organizations keep being polled. **Poll Now** ignores the back-off.

## Scenario B: internet-reachable deployment (webhook and polling)

Use this when Meraki can reach Plexus over HTTPS. Webhooks add the alert
types that are not assurance alerts and usually arrive faster; keep polling on
as a backstop for missed or disabled webhook deliveries.

### 1. Set the shared secret in Plexus

1. In **Topology > Sources**, expand **Meraki alerts**.
2. Click **Generate** (or type a secret of 16 to 256 printable characters)
   and copy it with the copy button. The secret is stored encrypted and is
   never shown again.
3. Click **Set Secret**. The receiver turns on and **Copy URL** gives the
   receiver URL (`https://<this host>/api/webhooks/meraki`). The URL is built
   from the address your browser uses; if that is an internal name, replace
   the host with the public one Meraki will use.

Until a secret is set the receiver answers 404, the same as a path that does
not exist.

### 2. Create the HTTP server in the Meraki dashboard

In each network that should send alerts (or in its configuration template,
see [Scenario D](#scenario-d-many-networks-organizations-and-templates)):

1. Go to **Network-wide > Configure > Alerts**.
2. Under **Webhooks**, add an HTTP server:
   - **Name**: for example `Plexus`;
   - **URL**: the public receiver URL from step 1;
   - **Shared secret**: the secret from step 1;
   - **Payload template**: the default Meraki JSON template. Plexus reads the
     standard fields (`organizationId`, `networkId`, `deviceSerial`,
     `alertTypeId`, `alertLevel`, `occurredAt`, `alertData`) and the
     `sharedSecret` field in the body; a custom template that drops these
     fields or moves the secret into a header is not accepted.
3. Use **Send test webhook**. Meraki reports "Webhook test was successful!"
   and Plexus shows the time under **Last test webhook** (and **Last
   delivery**). A test delivery never creates an alert.
4. Choose the alerts: add the HTTP server as a recipient under **Default
   recipients** (every alert type you turn on) or on individual alert types,
   and turn on the alert types you want (device went down, uplink failover,
   VPN connectivity change, and so on). Alerts with a threshold ("offline for
   more than N minutes") are sent when the threshold passes.
5. Save.

### 3. TLS

Meraki only delivers webhooks to HTTPS URLs with a certificate from a
publicly trusted certificate authority. A self-signed certificate or one from
an internal CA is rejected. The receiver must answer within two seconds;
Plexus checks the secret and answers before it does the alert work. Meraki
retries a failed delivery up to two times (three attempts in all), and
disables an HTTP server whose deliveries keep failing (more than 100 failed
attempts in 24 hours) and emails the organization's administrators.

### 4. Expose only the receiver (nginx)

Do not expose the Plexus web UI to the internet. The bundled
`deploy/nginx.conf` serves everything on 443 for the internal audience. Add a
second, public listener that serves only the receiver path, on its own public
address or port with its own publicly trusted certificate, and keep the
firewall closing everything else (see `deploy/FIREWALL.md`):

```nginx
# deploy/nginx.conf is included in the http context (conf.d), so the zone can
# be declared at the top of the file.
limit_req_zone $binary_remote_addr zone=meraki_webhook:1m rate=20r/s;

server {
    # A public address (or a dedicated port) used for nothing else.
    listen 203.0.113.10:443 ssl;
    server_name hooks.example.com;

    ssl_certificate     /etc/nginx/certs/public-fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/public-key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Meraki webhook bodies are a few KB; Plexus refuses more than 256 KiB.
    client_max_body_size 256k;

    add_header X-Content-Type-Options nosniff always;
    add_header Strict-Transport-Security "max-age=31536000" always;

    location = /api/webhooks/meraki {
        limit_except POST { deny all; }
        limit_req zone=meraki_webhook burst=100 nodelay;
        # Optional source allowlist, see "Source IP allowlisting":
        # allow 198.51.100.0/24;
        # deny all;
        proxy_pass http://plexus:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection '';
        proxy_read_timeout 10s;
    }

    # Nothing else is served on the public listener.
    location / {
        return 404;
    }
}
```

Publish the extra address or port in `docker-compose.yml` (for example
`"203.0.113.10:443:443"` next to the existing mappings) and mount the public
certificate next to the internal one. With `FORWARDED_ALLOW_IPS: "*"` (set in
`docker-compose.yml`) Plexus sees the real sender address, so its own rate
limit applies per Meraki source IP.

Plexus also rate limits the receiver itself when API rate limiting is on (the
default): 600 deliveries per rate-limit window (60 seconds by default) per
source IP, counted separately from the anonymous API limit so a burst of
alerts is not rejected.

### 5. Verify

- **Send test webhook** in Meraki sets **Last test webhook** in Plexus.
- Unplug a lab access point (or wait for a real alert): the alert appears
  under **Monitoring > Availability > Meraki alerts** with **Via**
  `webhook`, and later `poll, webhook` when the poll sees it too.

## Scenario C: internal deployment that still wants push

Plexus stays internal, and something else that Meraki can reach forwards the
webhook path to it. Whatever you choose, forward only `POST
/api/webhooks/meraki`, keep the body limit, terminate TLS with a publicly
trusted certificate at the edge, and leave the shared secret check to Plexus
(the edge cannot verify it).

### Option 1: reverse proxy in a DMZ

A reverse proxy (nginx, HAProxy, a web application firewall) in the DMZ
accepts HTTPS from the internet and forwards the one path to Plexus over the
internal network.

1. Give the proxy a public name and a publicly trusted certificate.
2. Use the `location = /api/webhooks/meraki` block from Scenario B, with
   `proxy_pass` pointing at the internal Plexus address over HTTPS
   (`proxy_pass https://plexus.internal.example.com;`) and
   `proxy_ssl_verify on` with your internal CA.
3. Allow only the proxy to reach Plexus on 443 from the DMZ, and only the
   proxy's public listener to be reachable from the internet.
4. Set `X-Forwarded-For` on the proxy and trust it in Plexus
   (`FORWARDED_ALLOW_IPS` set to the proxy address) so the per-source-IP rate
   limit sees Meraki's addresses rather than the proxy's.

Trade-offs: the most control and no third party in the path; needs a DMZ, a
public certificate and a firewall change.

### Option 2: outbound-only tunnel

A tunnel agent next to Plexus opens an outbound connection to a tunnel
provider, which gives you a public HTTPS hostname and forwards requests back
through the tunnel (for example Cloudflare Tunnel or ngrok). No inbound
firewall rule is needed.

1. Run the agent on a host that can reach Plexus.
2. Route only the path `/api/webhooks/meraki` to Plexus; answer 404 for
   everything else (most providers support path rules).
3. Use the provider's public hostname as the Meraki HTTP server URL.

Trade-offs: quick and needs no inbound port; the provider terminates TLS and
sees the payloads (including the shared secret), and Plexus depends on the
provider's availability. Restrict the tunnel to the one path and keep the
agent's credentials as carefully as any other secret.

### Option 3: cloud relay

A small function in a cloud account you control (for example AWS Lambda
behind API Gateway, or Azure Functions) receives the webhook and forwards it
to Plexus over a private connection you already have (site-to-site VPN,
Direct Connect, ExpressRoute).

1. Expose the function on HTTPS with the provider's certificate.
2. Forward the body unchanged, with `Content-Type: application/json`, to
   `https://<internal plexus>/api/webhooks/meraki` over the private link.
3. Return the status Plexus returns, within two seconds.

Trade-offs: no public address on your network; you run and secure another
component, and deliveries fail while the private link is down (Meraki retries
twice, and polling still covers assurance alerts).

## Scenario D: many networks, organizations and templates

- **One receiver for everything.** Every network and organization uses the
  same receiver URL and the same shared secret. Plexus maps each delivery's
  `organizationId` to the Meraki source with that organization ID. A
  delivery for an organization with no source is acknowledged, counted
  (**for organizations with no source here**) and ignored; its content is
  not logged.
- **Configuration templates.** Networks bound to a configuration template
  take their alert settings from the template. Configure the HTTP server and
  recipients once in the template (**Organization > Configuration templates**,
  then the template's **Network-wide > Alerts**) instead of per network.
- **Many unbound networks.** The HTTP server and alert recipients are
  per-network settings in Meraki. Set them network by network in the
  dashboard, or script them with the Dashboard API (`networks/{networkId}/
  webhooks/httpServers` and `networks/{networkId}/alerts/settings`) using a
  key with write access that you run yourself. Plexus does not do this: its
  key is read-only by design.
- **Webhook-only organizations.** A source with an organization ID but no API
  key receives webhooks and is never polled. To stop polling a source that
  has a key, untick it in the **Poll** column of **Meraki alerts**; its
  webhooks are still accepted. To stop its webhooks, remove the HTTP server
  in Meraki.
- **Both paths together.** Keep polling on when webhooks are set up: it
  catches alerts whose deliveries failed, closes alerts that the webhook path
  has no recovery event for (when the poll also reported them), and costs one
  call per organization per interval. Deduplication keeps it to one Plexus
  alert and one notification.

## Security model

- **Shared secret in the body, not a signature.** Meraki puts the shared
  secret in the JSON body (`sharedSecret`); it does not sign the payload. The
  secret is what authenticates a delivery, so it only protects the receiver
  if TLS protects it in transit: use HTTPS end to end.
- **Comparison.** Plexus compares the secret with `hmac.compare_digest`
  (constant time). A wrong or missing secret gets `401 {"detail":
  "Unauthorized"}`, with no hint which part was wrong.
- **Storage.** The secret is encrypted at rest with the same key that
  encrypts Meraki API keys (`routes.crypto`), is never logged, and is never
  returned by the API; the settings only say `webhook_secret_configured`.
- **Hidden until configured.** With no secret, or with the receiver turned
  off, `POST /api/webhooks/meraki` answers `404 {"detail": "Not Found"}`, the
  same as a path that does not exist.
- **No session, no CSRF, only this path.** The receiver is exempt from
  session authentication and CSRF by exact path (`WEBHOOK_PATHS` in
  `netcontrol/app.py`); every other API path keeps both.
- **Input limits.** JSON only (`415` otherwise), at most 256 KiB (`413`), a
  JSON object (`400` otherwise), and a per-source-IP rate limit (`429`).
- **Rotating the secret.**
  1. Generate a new secret in Plexus and copy it, but do not save yet.
  2. In Meraki, update the HTTP server's shared secret in every network or
     template that uses it.
  3. Save the new secret in Plexus (**Rotate Secret**).
  Deliveries sent between steps 2 and 3 are rejected with 401; Meraki retries
  them twice, and polling covers the assurance alerts meanwhile. Keep the gap
  short, or do it in a quiet period.
- **Turning it off.** **Turn Off** keeps the secret but answers 404; **Clear
  Secret** removes it. Remove the HTTP server in Meraki as well, or Meraki
  will disable it after repeated failures.
- **Source IP allowlisting.** Meraki's webhook documentation asks receivers
  to allow Meraki's IP ranges through their firewall but does not list the
  ranges on that page. The Meraki dashboard's **Help > Firewall info** page
  lists the cloud address ranges for your organization; confirm with that
  page (or Cisco Meraki support) which ranges deliver webhooks in your region
  before you rely on an allowlist, and re-check it when Meraki announces
  changes. An allowlist is defence in depth on top of the shared secret, not
  a replacement.
- **What is logged.** Failures are logged with the exception type only.
  Rejected deliveries and deliveries for unknown organizations are counted,
  not logged with their content. The payload, the secret and the API key are
  never logged. Settings changes are audited (`monitoring` /
  `meraki_alerts.settings_updated`, with `secret=set|rotated|cleared|unchanged`
  but never the secret), and so is **Poll Now** (`meraki_alerts.polled`).

## Settings reference

Stored in the `meraki_alerts` auth setting; changed under **Topology >
Sources > Meraki alerts** or with `PUT /api/monitoring/meraki-alerts/settings`
(administrators only).

| Setting | Default | Meaning |
|---|---|---|
| `poll_enabled` | `true` | Poll the assurance alerts of every Meraki source with an API key |
| `interval_seconds` | `60` | Seconds between polls, 30 to 3600 |
| `excluded_sources` | `[]` | Source ids that are not polled (their webhooks are still accepted) |
| `webhook_enabled` | `false` | Receiver on; it also needs a secret, and setting a secret turns it on |
| `webhook_secret` | not set | Write-only shared secret, 16 to 256 printable characters, stored encrypted |
| `webhook_open_ttl_hours` | `24` | A webhook-only alert with no event for this long is resolved (1 to 720) |

Status, shown in the same panel and returned by the settings API: last poll
time and result, per-source last success and last error, last delivery, last
test webhook, accepted and rejected deliveries, deliveries for unknown
organizations, last processing error.

Retention: resolved alerts older than the monitoring retention
(`retention_days`, **Settings > Monitoring**) are deleted by the monitoring
retention cleanup.

## API

See the "Meraki alerts" section of [api-reference.md](api-reference.md) and
`AUTHORIZATION_MATRIX.md`:

- `GET /api/monitoring/meraki-alerts` (monitoring feature)
- `GET` / `PUT /api/monitoring/meraki-alerts/settings` (admin)
- `POST /api/monitoring/meraki-alerts/poll` (admin)
- `POST /api/webhooks/meraki` (Meraki only, shared secret)

## Troubleshooting

**Nothing arrives by polling.** Check the organization's row under **Meraki
alerts**: no row means the source has no organization ID, is a demo entry or
is not a Meraki source. **Last error** `no API key`, `HTTP 401` or `HTTP 403`
means the key is missing, wrong or lacks access to the organization;
`HTTP 404` means the key cannot see the organization (check the organization
ID) or the assurance alerts endpoint is not available to it; `Meraki API
unreachable` means the outbound HTTPS path is blocked (Scenario A
requirements). Fix it and click **Poll Now**, which skips the back-off. An
organization with no active assurance alerts lists nothing, which is normal.

**Nothing arrives by webhook.** Use **Send test webhook** in Meraki, then
look at **Last test webhook** and **Last delivery**:

- neither changes: the delivery does not reach Plexus. Check DNS, the public
  certificate (it must be publicly trusted), the firewall and the proxy path;
  `curl -i -X POST https://<public host>/api/webhooks/meraki -H
  'Content-Type: application/json' -d '{}'` from outside should return 401
  (receiver on) or 404 (receiver off), never a timeout;
- **rejected (wrong secret)** goes up: the secret in Meraki and in Plexus
  differ. Set them again;
- **for organizations with no source here** goes up: add the organization as
  a Meraki source with its organization ID;
- the test works but real alerts do not come: the HTTP server is not a
  recipient of those alert types, or the alert types are not turned on in
  that network (or its template).

**404 from the receiver.** No secret is set, or the receiver is turned off.
Set the secret or click **Turn On**. A proxy that answers 404 for the path
also looks like this; check the proxy's access log.

**401 from the receiver.** Wrong or missing `sharedSecret`. A custom payload
template that does not include the secret in the body always gets 401; use the
default template.

**Duplicate notifications.** Expected for one case: an alert type that the
poll and the webhook name differently and that is not in the equivalence
list (see [Deduplication](#deduplication)), or an uplink or tunnel failure
reported by both a Meraki alert and the hourly availability tracker. Both
alerts carry their alert type, so a notification rule can drop one of them.
If the same alert keeps notifying, check whether it resolves and reopens
(**Show resolved**): each new occurrence after a resolve is notified.

**Rate limiting.** Repeated `HTTP 429` in **Last error** means the
organization's API budget is used up by Plexus's collection and other tools
together: raise `interval_seconds`, or the topology collection interval, or
find the other consumer. A `429` from the receiver means one source IP sent
more than 600 deliveries in one rate-limit window; Meraki retries, and the
limit is reset after the window.

**Clock and time zones.** Plexus stores and shows times as UTC
(`YYYY-MM-DD HH:MM:SS`) and converts Meraki's ISO 8601 times (`occurredAt`,
`startedAt`, `resolvedAt`), which carry a zone, to UTC. A wrong clock on the
Plexus host makes `last_seen` and the 24-hour webhook expiry wrong, and can
stop a resolved alert from reopening on a new occurrence (a new occurrence
reopens only when it started after the stored resolve time). Keep the host on
NTP.

## Limitations

- **Equivalent types.** Cross-path deduplication merges the device-down
  family only. Other alert types merge only when both paths use the same type
  name after the state word is removed. Meraki publishes the webhook alert
  types per organization (`GET /organizations/{organizationId}/webhooks/
  alertTypes`) and the assurance types in its API reference; more
  equivalences can be added to `CONDITION_ALIASES` in
  `netcontrol/integrations/meraki/alerts.py` as they are confirmed.
- **Webhook recoveries.** Many webhook alert types have no recovery event.
  They stay open until a recovery-looking event of the same condition, a poll
  that reported them and no longer does, or the 24-hour expiry.
- **Test webhook detection.** Meraki does not document the test payload.
  Plexus treats a delivery as a test when its `alertId` is all zeros, its
  `alertData` has `"test": true`, or its type says "test"; any other test
  delivery is processed like a real alert (and expires after 24 hours).
  **Last delivery** shows any accepted delivery either way.
- **One subject per alert.** An assurance alert that names several devices is
  recorded against the first one (lowest `order`); the count is kept in the
  record's detail.
- **Info alerts are not notified.** They are listed only.
- **Uplink and tunnel overlap** with the hourly availability alerts is not
  suppressed (see [Overlap with the hourly availability
  alerts](#overlap-with-the-hourly-availability-alerts)).
- **Device availability history.** The poll does not call
  `devices/availabilities/changeHistory`. Device online and offline history is
  already recorded by the availability tracker from every collection, and the
  assurance `unreachable` alert already reports a device that goes down, so
  the second call per organization per poll would add little; it is a
  candidate if per-minute availability history is wanted.
- **Other vendors.** Near-real-time alert ingestion exists for Meraki only;
  see [vendor-monitoring-coverage.md](vendor-monitoring-coverage.md#vendor-alert-feeds).
