# Audit log

Plexus writes an audit event for sign-ins, account and settings changes,
and most create, change and delete actions in its features. Each event says
who did what and when. Events are stored in the database in a hash chain:
the database refuses to change or delete them, and a check can prove that
no event was changed, removed or inserted later. Use the audit log to answer
"who changed this?", for security reviews, and to feed a SIEM.

## Where to find it

This version has no audit log page in the web UI. You read the log in one
of these ways:

| Way | Where | Needs |
|---|---|---|
| Admin API | `GET /api/admin/audit-events` and `GET /api/admin/audit-events/verify` | Admin, or the server API token |
| SIEM forwarding | **Settings > SIEM** sends every new event to your SIEM | Admin |
| AI access | The `search_audit_log` tool ([ai-access.md](ai-access.md)) | A token owned by an admin, with the `audit` category |
| Deployment view | **Deployment Correlation** lists events whose detail names that deployment, inside its time window | The `deployments` feature |

**Field-by-field history.** The audit log says what was done, in text. For
the changed fields of a host, group, prefix, VLAN or other object, with
their values before and after, see the [change log](change-log.md).

**Not the CIS audit.** The `/audit` address opens **Compliance > CIS
Audit**. That tab is a different feature: it grades the inventory against
CIS-style checks (configuration drift, port hygiene, VLAN consistency and
security posture), with **Run audit now**, **Schedules**, **Suppressed
findings** and **Recent runs**. It needs the `reports` feature to read and
`reports.write` to run or change. This guide does not cover it.

## What an event contains

| Field | Meaning |
|---|---|
| `id` | Increasing number. |
| `timestamp` | UTC time, text `YYYY-MM-DD HH:MM:SS`. |
| `category` | The area, for example `auth` or `inventory`. |
| `action` | What happened, for example `login.success` or `user.create`. |
| `user` | The user name of the person or process. Empty for some system actions. |
| `detail` | Free text with the object and the change, for example `created user 'jdoe' role=user`. |
| `correlation_id` | The ID of the HTTP request, to match the event with the server log. |
| `prev_hash`, `row_hash` | The hash chain. See [Tamper evidence](#tamper-evidence). |

## Categories

The category names the area that wrote the event. Common categories:

| Category | Examples of what it records |
|---|---|
| `auth` | Sign-in success and failure (with `source=`), password change, idle-timeout sign-out, users, access groups, feature visibility |
| `credential` | Each allow or deny decision when a stored credential is used |
| `secrets_providers` | Secrets provider changes and tests, and every external secret that could not be resolved ([secrets-providers.md](secrets-providers.md#audit)) |
| `inventory`, `device_model`, `custom_fields`, `network_objects`, `ipam`, `dhcp`, `geolocation`, `circuits` | Inventory and IPAM records |
| `config`, `config-backups`, `config-drift`, `compliance` | Configuration templates, backups, drift and compliance |
| `jobs`, `deployments`, `upgrades`, `maintenance-windows`, `risk-analysis` | Jobs and change work |
| `monitoring`, `sla`, `topology`, `meraki_topology`, `cloud_visibility` | Monitoring and integrations |
| `software`, `billing`, `federation`, `lab`, `mac-tracking` | The feature of the same name |
| `system`, `admin_updates` | Server settings such as syslog and SIEM forwarding, and in-app updates |
| `mcp` | AI access: every tool call, token changes and failed sign-ins ([ai-access.md](ai-access.md#audit-trail)) |
| `chatops` | ChatOps: every command received from Slack, Webex or Teams, and bot, user mapping and job preset changes ([chatops.md](chatops.md#command-log-and-audit)) |

The list is not closed. A feature may add its own category; feature guides
name theirs, for example [device-model.md](device-model.md) (`device_model`)
and [custom-fields-and-tags.md](custom-fields-and-tags.md) (`custom_fields`).

## Reading and filtering

- **Admin API.** `GET /api/admin/audit-events?limit=N` returns the newest
  events first. `limit` is 1 to 1000, default 200. This endpoint has no
  other filter; filter the JSON yourself.
- **AI access.** `search_audit_log` filters by `category`, by exact `user`
  name and by time range (default: the last 24 hours), newest first, and
  reads at most 5,000 events per call.
- **SIEM.** Search and keep events in your SIEM. See
  [Forwarding to a SIEM](#forwarding-to-a-siem).

There is no CSV export. Use the API or a SIEM sink to take events out of
Plexus.

## Tamper evidence

Every event carries two hashes:

- `prev_hash` is the `row_hash` of the event before it. The first event has
  an empty `prev_hash`.
- `row_hash` is the SHA-256 of these fields, in this order, joined by a NUL
  byte (`\x00`) and encoded as UTF-8: `timestamp`, `category`, `action`,
  `user`, `detail`, `correlation_id`, `prev_hash`. A missing value counts as
  an empty string. The `id` is not part of the hash.

So changing an event breaks its own `row_hash`, and removing, inserting or
reordering events breaks the `prev_hash` link of the next one.

On PostgreSQL, database triggers also stop any `UPDATE` or `DELETE` on the
table with the error `audit immutable`. Plexus only ever inserts events.

### Verifying the chain

Call `GET /api/admin/audit-events/verify`. Plexus walks the whole log from
the first event and stops at the first problem:

```json
{ "ok": true, "total_rows": 18342, "first_break_id": null, "first_break_reason": null }
```

```json
{ "ok": false, "total_rows": 1207, "first_break_id": 1207, "first_break_reason": "prev_hash_mismatch" }
```

| `first_break_reason` | What it tells you |
|---|---|
| `row_hash_mismatch` | Event `first_break_id` was changed after it was written. |
| `prev_hash_mismatch` | The link before event `first_break_id` is broken: an earlier event was deleted, or an event was inserted or reordered. |

When `ok` is false, `total_rows` is the number of events checked up to and
including the break, not the size of the log.

To check events outside Plexus, recompute the hashes from the API output.
The API returns the newest events only, so start from the `prev_hash` of
the oldest event you hold:

```python
import hashlib

def check(events):  # events from /api/admin/audit-events, sorted by id
    expected_prev = events[0]["prev_hash"]
    for e in events:
        fields = [e["timestamp"], e["category"], e["action"], e["user"],
                  e["detail"] or "", e["correlation_id"] or "", e["prev_hash"] or ""]
        digest = hashlib.sha256("\x00".join(fields).encode("utf-8")).hexdigest()
        if e["prev_hash"] != expected_prev or digest != e["row_hash"]:
            return e["id"]
        expected_prev = e["row_hash"]
    return None
```

## Forwarding to a SIEM

**Settings > SIEM** sends each new event, right after it is stored, to one
or more sinks. Choose **Add Sink** and set:

| Field | Values |
|---|---|
| **Name**, **Enabled** | A label, and on or off. |
| **Protocol** | **UDP**, **TCP**, **TLS** (all three send syslog-framed messages) or **HTTPS** (HTTP POST). |
| **Format** | **CEF** or **JSON** (ECS-shaped JSON). Both carry the `row_hash`; JSON also carries `prev_hash`. |
| **Severity floor** | `debug`, `info`, `notice`, `warning`, `error` or `critical`. Events below the floor are not sent. |
| **Host**, **Port** | For `udp`, `tcp` and `tls`. |
| **URL**, **Bearer token (optional)** | For `https`. |
| **Verify TLS certificate**, **CA PEM (optional, pins trust)**, **Client cert PEM (mutual TLS)**, **Client key PEM** | TLS options. |

The bearer token and client key are stored encrypted and shown masked; saving
the mask keeps them, except when the save changes the protocol, host, port,
URL host, CA PEM or turns certificate checks off: then type them again. The
sink connects to the address the outbound check approved (see
[webhooks.md](webhooks.md#outbound-address-check)).

Events have no severity of their own; Plexus gives each one a severity for
this filter:

| Event | Severity |
|---|---|
| `auth` events whose action contains `fail`, `lock` or `denied` | `warning` |
| Category `security`, or an action that contains `tamper` | `critical` |
| An action that contains `delete` or `destroy` | `notice` |
| Everything else | `info` |

The sink table shows **State**, **Queue**, **Delivered**, **Dropped**,
**Last error** and **Last test** for each sink. The error text (also
written to the audit log by a test) can quote the receiver's reply: the
sink's token and client key are removed from it, other passwords and tokens
are masked as in the application log, and it is cut to 500 characters.
Forwarding is best effort:
each sink has a queue (default 1,000 events) and retries with back-off
(default 5 retries). When the queue is full, the oldest queued event is
dropped and counted. The database copy is always kept, so a SIEM outage
never loses events from Plexus itself.

## Rules worth knowing

- **No retention.** Audit events are never deleted. No retention setting
  or cleanup job touches them, and [DATA_RETENTION.md](../DATA_RETENTION.md)
  does not list them.
- **Best effort on write.** If writing an event fails, the action itself
  still completes and the server logs a warning. Each stored event is also
  noted in the application log at INFO level by its id, category, action
  and correlation id. The user and the detail are not written there: read
  them in the audit trail or a SIEM sink.
- **Order.** Writes are serialized (on PostgreSQL also across server worker
  processes), so the chain cannot fork.
- **Times are UTC.**

## Who can do what

| Action | Needs |
|---|---|
| Read events, verify the chain | Admin, or the server API token |
| Add, edit, delete or test a SIEM sink | Admin |
| Search with `search_audit_log` | An AI access token with the `audit` category, owned by an admin |
| See the CIS Audit tab | The `reports` feature |

## API

```
GET /api/admin/audit-events[?limit=200]
GET /api/admin/audit-events/verify
GET    /api/admin/siem-sinks
POST   /api/admin/siem-sinks
PUT    /api/admin/siem-sinks/{sink_id}
DELETE /api/admin/siem-sinks/{sink_id}
POST   /api/admin/siem-sinks/{sink_id}/test
```

An event from `GET /api/admin/audit-events` (invented values):

```json
{
  "id": 5120,
  "timestamp": "2026-11-02 14:05:31",
  "category": "auth",
  "action": "user.create",
  "user": "admin",
  "detail": "created user 'jdoe' role=user",
  "correlation_id": "3f2a9c1e",
  "prev_hash": "9b1c...e04a",
  "row_hash": "52d7...a91f"
}
```

See [api-reference.md](api-reference.md) for the general API rules.
