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
  first 2000 characters of the response or the error. The signing secret,
  the custom header values and the signature are replaced by `***` in the
  logged response and error, so a receiver that answers with what it was
  sent does not put them in the log; a short header value is replaced
  wherever the same text occurs. Open it with
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
  same outbound guard as notification channels, SIEM sinks, federation
  peers and identity providers when it is saved and before every request
  (see [Outbound address check](#outbound-address-check)).
- **Encrypted settings.** The signing secret and the custom header values are
  stored encrypted and come back from the API masked as `••••••••`. Saving
  with the mask keeps the stored value, unless the save changes where they
  are sent: a new scheme, host or port in the URL, certificate checks turned
  off, or another CA bundle. Then the save is refused with `400` naming the
  stored values to enter again (`signing secret`, `header <name>`), so an
  admin cannot point the webhook at another server and have Plexus send it
  the stored secrets. A path change on the same host keeps them.
- **TLS.** Certificates are verified against the system trust store, or
  against the **CA bundle** (PEM) when one is set. Turning verification off
  is meant for lab receivers only.
- **Audited.** Creating, editing, deleting, testing and redelivering a
  webhook writes an audit event (`webhook.create`, `webhook.update`, ...).

### Outbound address check

Every request Plexus sends to an address an admin typed in (event webhooks,
notification channels including the SMTP server of an email channel, SIEM
sinks, federation peers, secrets providers including the AWS Secrets
Manager endpoint URL, identity providers, the RADIUS, TACACS+ and LDAP
servers, the application syslog forwarder, sync connections, Git data
sources, and the topology source APIs: FMC, Panorama, Appgate, OPNsense,
Cato, Meraki and the FDM API of a Cisco FTD host) first passes one guard
(`netcontrol/routes/net_guard.py`):

1. **Cloud metadata addresses are always refused**: `169.254.169.254`,
   the AWS IPv6 endpoint `fd00:ec2::254`, the ECS and EKS credential
   endpoints (`169.254.170.2`, `169.254.170.23`, `fd00:ec2::23`),
   `100.100.100.200`, `168.63.129.16` and `192.0.0.192`. No
   `APP_SSRF_ALLOW` entry opens them, and a host name that resolves to one
   is refused even when it is allow-listed.
2. **`APP_SSRF_ALLOW`** (comma-separated host names or IP addresses) lists
   targets an admin trusts. They skip the rules below.
3. **A host name that does not resolve is refused** (`does not resolve`).
   The guard cannot judge an address it does not know. A target whose name
   only resolves on the receiving side (behind a proxy, or a split-horizon
   name) must be listed in `APP_SSRF_ALLOW`.
4. Link-local, multicast, reserved and unspecified addresses are refused;
   private and loopback ranges too when `APP_SSRF_BLOCK_PRIVATE=true`.
   A name with several addresses is refused when any of them is.

**The connection goes to the checked address.** HTTP requests sent through
the shared sender (event webhooks, notification webhooks and Teams cards,
SIEM HTTPS sinks, federation peers, secrets providers, the ChatOps bots)
connect only to the addresses the check approved: the first that accepts
the connection, trying at most three in order (so a name with an
unreachable IPv6 address still works over IPv4). The request keeps the
host name for the `Host` header, the TLS server name (SNI) and the
certificate check, so a second DNS answer (DNS rebinding) cannot send it
anywhere else. SIEM TCP and TLS sinks connect to the checked addresses
the same way; a UDP sink sends to the first one. A request that goes through an HTTP proxy from the
environment (`HTTPS_PROXY`, minus `NO_PROXY`) is not pinned: the proxy
resolves the name. The OIDC and SAML clients, sync connections and Git
data sources run the check before each request but open their own
connections, so they are not pinned.
  Webhook settings are not themselves an object type that fires webhooks,
  and deliveries write no audit events, so a webhook can never trigger
  itself.

**Checked before connecting, not pinned.** These open their own
connections, so the check runs before each one but the connection itself
resolves the name again:

- The topology source API clients (FMC, Panorama, Appgate, OPNsense,
  Cato, Meraki, FDM) check the source address when a collection opens
  its connection. A refused address fails that collection the same way as
  a device that cannot be reached, with a message that names the guard.
- The SMTP server of an email channel, before each message.
- The RADIUS, TACACS+ and LDAP servers, before each login. A refused
  server fails the login as an unreachable server does (local fallback
  applies when it is on).
- The application syslog forwarder host, when the forwarder starts.
- The AWS Secrets Manager endpoint URL, before each fetch. A custom
  endpoint URL also needs an explicit access key: the default credential
  chain (the server's own instance or task role) is only ever sent to AWS
  itself.

**Checked when saved.** Saving a topology source address, an email
channel's SMTP server, the syslog forwarder host, an enabled RADIUS,
TACACS+ or LDAP server, or a secrets provider address (Vault URL, Azure
vault URL and authority host, AWS endpoint URL) runs the same check and
answers `400` naming the guard when it refuses. A setting saved earlier
that the check now refuses is reported when it is used.
