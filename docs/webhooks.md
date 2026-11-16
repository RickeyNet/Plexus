# Event Webhooks

An event webhook sends an HTTP request to a URL of your choice whenever an
object in Plexus is created, updated or deleted: a host is added, a prefix is
removed, a playbook run finishes. Receivers use it to keep another system in
step (a CMDB, a chat channel, an automation pipeline) without polling the API.

Webhooks are managed by admins under **Settings > Webhooks**, or through the
API (see [API reference](api-reference.md#event-webhooks)).

## What can trigger a webhook

| Object type     | Create                         | Update                                   | Delete                     |
|-----------------|--------------------------------|------------------------------------------|----------------------------|
| `host`          | host added (UI, API, import)   | host edited or moved to another group    | host or hosts deleted      |
| `group`         | inventory group added          | group renamed, re-described or moved     | group deleted              |
| `prefix`        | IPAM prefix added              | -                                        | prefix deleted             |
| `ip_address`    | IPAM address allocated         | -                                        | allocation deleted         |
| `vlan`          | VLAN added                     | VLAN edited                              | VLAN deleted               |
| `vrf`           | VRF added                      | VRF edited                               | VRF deleted                |
| `credential`    | credential added (metadata)    | credential edited (metadata)             | credential deleted         |
| `config_backup` | backup captured                | -                                        | backup deleted             |
| `job`           | job (playbook run) queued      | job started, finished or cancelled       | -                          |

Events come from the database layer, so a change made from the UI, the REST
API, a scheduled job or an import fires the same event. An update fires only
when the stored row actually changed. Deleting a group removes its hosts
without a `host.delete` event per host; subscribe to `group` to see it.

Each webhook chooses:

- **Objects** - one or more of the types above.
- **Actions** - any of `create`, `update`, `delete`.
- **Filters** (optional) - field name to allowed values, matched against the
  object before or after the change. The Settings page offers the common
  one, `group_id` (an inventory group; a group itself matches its own id):
  `{"group_id": [3, 7]}` sends only changes to hosts in groups 3 and 7. Any
  other field of the object works through the API, for example
  `{"device_type": ["cisco_ios"]}`.

## The request

```
POST /plexus-hook HTTP/1.1
Host: hooks.example.com
Content-Type: application/json
User-Agent: Plexus-Webhooks/1
X-Plexus-Event: host.update
X-Plexus-Delivery: 5f0c1f8e-3c9b-4a59-9d55-2f1f7e0f6a10
X-Plexus-Signature-256: sha256=8d2c...e41f
```

| Header                   | Meaning                                                                                      |
|--------------------------|----------------------------------------------------------------------------------------------|
| `X-Plexus-Event`         | `<object_type>.<action>`, or `webhook.test` for the Test button                              |
| `X-Plexus-Delivery`      | A UUID for this event and webhook. Every retry and redelivery repeats it: use it to de-duplicate |
| `X-Plexus-Signature-256` | `sha256=` and the hex HMAC-SHA256 of the raw body, keyed with the webhook's secret (only when a secret is set) |

Custom headers (for example `Authorization: Bearer ...`) are added as set on
the webhook. The method can be `POST`, `PUT` or `PATCH`, and the content type
can be changed (for a body template that is not JSON).

## The payload

Without a body template the body is this JSON document:

```json
{
  "event": "host.update",
  "delivery_id": "5f0c1f8e-3c9b-4a59-9d55-2f1f7e0f6a10",
  "timestamp": "2026-03-01T09:30:00Z",
  "object_type": "host",
  "object_id": "12",
  "action": "update",
  "user": "alice",
  "data": {"id": 12, "group_id": 3, "hostname": "edge-r2", "ip_address": "192.0.2.10", "device_type": "cisco_ios"},
  "snapshots": {
    "before": {"id": 12, "group_id": 3, "hostname": "edge-r1", "ip_address": "192.0.2.10", "device_type": "cisco_ios"},
    "after": {"id": 12, "group_id": 3, "hostname": "edge-r2", "ip_address": "192.0.2.10", "device_type": "cisco_ios"}
  },
  "changes": {"hostname": {"before": "edge-r1", "after": "edge-r2"}}
}
```

- `data` is the object after the change (before it, for a delete).
- `snapshots.before` is `null` for a create; `snapshots.after` is `null` for a
  delete. Each snapshot is the stored row (abridged above).
- `changes` lists only the fields an update changed; it is empty otherwise.
- `user` is the signed-in user (or `api-token`) whose request made the change,
  and `system` for changes made by background work.

**Secrets never appear.** Credential passwords and enable secrets, config
backup text and job input parameters are left out of every event, and the
whole payload then goes through the same secret masking as the AI access
(MCP) results, so a field whose name marks it as a secret is replaced with
`********`.

### Body templates

A webhook can render its own body with a Jinja2 template, in the same
sandbox (with the same time and size limits) as
[intended configuration](intended-config.md) templates. Every payload field
is a variable, and `payload` is the whole document. For a chat service:

```
{"text": "{{ user }} {{ action }}d {{ object_type }} {{ data.hostname | default(object_id) }}"}
```

To wrap the standard document: `{"source": "plexus", "body": {{ payload | tojson }}}`.
A template that fails to render is logged as a failed delivery and not retried.

## Verifying the signature

Compute the HMAC-SHA256 of the raw request body (the exact bytes, before any
JSON parsing) with the shared secret and compare it to the header in
constant time:

```python
import hashlib
import hmac


def verify(secret: str, body: bytes, header: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header or "")


# In a Flask receiver:
# ok = verify(SECRET, request.get_data(), request.headers.get("X-Plexus-Signature-256", ""))
```

## Delivery, retries and the log

- Each webhook has its own queue (1000 events) and sends at most
  **Concurrency** requests at once, so a slow receiver does not delay
  another webhook. When a queue is full the oldest pending event is dropped
  and counted.
- A request times out after **Timeout** seconds (default 10).
- A timeout, a connection error, HTTP 408, 429 or any 5xx is retried up to
  **Max retries** times (default 3) with doubling backoff starting at 2
  seconds. Any other 4xx is not retried. Any 2xx is success.
- Redirects are not followed.
- Every attempt is logged: time, event, object, attempt number, status
  (`success`, `retrying`, `failed`, `blocked`), HTTP status, latency, and the
  first 2000 characters of the response or the error. Open it with
  **Deliveries** on the webhook's row. **Redeliver** sends a logged body again
  with the same `X-Plexus-Delivery` id.
- Delivery log rows are kept 30 days (`APP_WEBHOOK_DELIVERY_RETENTION_DAYS`),
  see [Data retention](../DATA_RETENTION.md).
- **Test** sends a `webhook.test` event once, without retries, and shows the
  result.

Delivery is best effort: the object change is saved whether or not the
receiver answers, and events queued in memory are lost if Plexus restarts.

A saved change to a webhook takes effect at once in the process that saved
it and within 30 seconds in any other Plexus worker process.

## Security

- **Admin only.** Every webhook route requires the admin role (see
  [Authorization matrix](../AUTHORIZATION_MATRIX.md)).
- **SSRF guard.** The URL must be `http` or `https` and is checked by the
  same outbound guard as notification channels and SIEM sinks when it is
  saved and before every request: link-local addresses (cloud metadata
  endpoints), multicast and reserved ranges are refused, as are private and
  loopback ranges when `APP_SSRF_BLOCK_PRIVATE=true`.
- **Encrypted settings.** The signing secret and the custom header values are
  stored encrypted and come back from the API masked as `••••••••`. Saving
  with the mask keeps the stored value.
- **TLS.** Certificates are verified against the system trust store, or
  against the **CA bundle** (PEM) when one is set. Turning verification off
  is meant for lab receivers only.
- **Audited.** Creating, editing, deleting, testing and redelivering a
  webhook writes an audit event (`webhook.create`, `webhook.update`, ...).
  Webhook settings are not themselves an object type that fires webhooks,
  and deliveries write no audit events, so a webhook can never trigger
  itself.
