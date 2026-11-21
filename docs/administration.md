# Administration

The **Settings** page is where an admin manages Plexus itself: user
accounts, roles and access groups, sign-in, log and event forwarding,
background discovery and polling, which features show in the menu, and
software updates. This guide walks through each Settings tab. Where a tab
has its own guide, this page gives a short summary and the link.

## Before you start

- **Admin role.** An admin sees all 15 tabs. Any other user sees only
  **Appearance**.
- **The first admin account** is created when the server first starts. See
  [deploy/DEPLOYMENT.md](../deploy/DEPLOYMENT.md) (first login) for how its
  password is set and how to recover it.
- Each tab has its own **Save** button. When you switch tabs with unsaved
  changes, Plexus asks **Discard changes** or **Keep editing**.

## The tabs at a glance

| Tab | What it controls |
|---|---|
| **Appearance** | Theme and background, for this browser only |
| **Users** | Local user accounts, their role, access groups and passwords |
| **Access Groups** | Which features (and devices) a group of users may use |
| **Authentication** | Login rules, sign-in provider, service credentials |
| **Logging** | Forwarding of the application log to syslog |
| **SIEM** | Forwarding of audit events to a SIEM |
| **Discovery** | Topology discovery and STP polling schedules, STP root policies |
| **Monitoring** | Polling switch, interval, retention, CPU and memory thresholds, alert escalation |
| **NetFlow** | The NetFlow, IPFIX and sFlow collector |
| **Syslog & Traps** | The receivers for device syslog messages (UDP, TCP and TLS) and SNMP traps, the syslog TLS certificate, and what a received syslog message triggers |
| **Notifications** | Alert notification channels |
| **Features** | Which features appear in the navigation |
| **Custom Fields & Tags** | Extra fields and tags for hosts, groups and IPAM prefixes |
| **Device Model** | Manufacturers, device types, roles and lifecycle statuses |
| **AI Access** | The read-only MCP endpoint and its tokens |
| **ChatOps** | Slack, Webex and Teams bots, chat user mappings, job presets and the command log ([chatops.md](chatops.md)) |
| **System** | Version, updates and job history retention |

## Users, roles and access groups

### Roles

There are two roles:

| Role | Can do |
|---|---|
| **Admin** | Everything: every feature, every Settings tab and every admin-only action. |
| **User** | Only the features granted by the user's access groups. No Settings tab except **Appearance**. |

A user who is in no access group has no features. (The **Users** tab shows
such a user as "No groups assigned (full default access)", but the server
grants nothing.)

### Creating a user

1. Open **Settings > Users** and choose **+ New User**.
2. In **Create User Account**, fill in **Username** (at least 3
   characters), **Display Name** (optional; when empty, the server uses the
   username with a capital first letter), **Password** and **Confirm Password** (at least 8 characters).
   **Show passwords** shows what you typed.
3. Choose a **Role** (**User** or **Admin**) and tick the **Access Groups**.
4. Choose **Create**.

Each user card shows the role, the creation date, the access groups and
**Effective Features** (choose **Show** to list them). "Limited to selected
inventory groups" marks a user whose access groups limit the devices they
see.

To change a user, choose **Edit**. **Edit User Account** has **Username**,
**Display Name**, **Role**, **Access Groups** and **Session never
expires**. That last box skips the idle timeout; use it only for read-only
kiosk accounts such as a NOC wall screen. **Reset Password** sets a new
password (at least 8 characters). **Delete** removes the account after you
confirm.

### Password rules

- At least 8 characters. Plexus checks no other complexity rule.
- A user changes their own password from the user menu, **Change
  Password**. The new password must differ from the current one. After 5
  wrong current passwords in 5 minutes, Plexus refuses further tries for a
  while.
- An account flagged for a password change (for example the first admin)
  sees **Password Change Required** and cannot close it.

### Access groups

An access group grants features. Open **Settings > Access Groups**, choose
**+ New Group**, and fill in **Group Name** (at least 2 characters),
**Description** and **Feature Access**. Feature Access is a grid with one
row per feature and two columns: **View** and **Modify**. Some features are
read only and have no **Modify** box ("Read-only feature: nothing to
modify"). **View** alone is read-only: creating, changing, deleting and
running anything in the feature (launching a job, restoring a backup,
executing a deployment) needs **Modify** as well. A user gets every feature
of every group they are in.

**Device access** chooses **All devices** or **Selected inventory groups**.
The second limits members to some inventory groups and closes many pages to
them. See [object-permissions.md](object-permissions.md).

For the full list of which endpoint needs which feature or role, see
[AUTHORIZATION_MATRIX.md](../AUTHORIZATION_MATRIX.md).

## API tokens

Plexus has two kinds of token. There are no per-user API tokens.

| Token | Where it is set | What it can do |
|---|---|---|
| Server API token | `APP_API_TOKEN` in the server's `.env` ([deploy/DEPLOYMENT.md](../deploy/DEPLOYMENT.md)) | Sent as `X-API-Token: <token>` or `Authorization: Bearer <token>`. Acts as an admin on every `/api/*` route and needs no CSRF token. Federation peers use it. |
| AI access (MCP) token | **Settings > AI Access** | Read-only access to the MCP endpoint only, limited to chosen categories and to what its owner may see. See [ai-access.md](ai-access.md). |

Treat the server API token like a root password. A request that carries it
skips the CSRF check, the per-IP API rate limit and the session limits (idle
timeout, sign-out on change). It is off unless set: `deploy/setup.sh` leaves
`APP_API_TOKEN` empty on a new install. To enable it, run setup with
`--with-api-token` (or `PLEXUS_ENABLE_API_TOKEN=true`, which
`deploy/bootstrap.sh` and the air-gap installer pass on), or put a long
random value in `.env` yourself (`python3 -c "import secrets;
print(secrets.token_urlsafe(48))"`) and run `docker compose up -d`. Clear the
line and restart to turn it off. Installs set up before this change keep the
token they have. `APP_REQUIRE_API_TOKEN=true` forces non-session API calls
to present it.

## Tab by tab

### Appearance

**Theme** and **Space Depth Intensity** (**Off**, **Low**, **Medium**,
**High**). Changes apply at once and are saved in this browser only.

### Authentication

- **Login Rules.** **Max attempts** (default 5) failed logins from one
  client IP within **Rate window (s)** (default 60) lock that IP out for
  **Lockout time (s)** (default 900). **Rate limit max** (default 10)
  refuses new attempts from an IP after that many failures in the window,
  without a lockout. **Idle timeout (s, 0 = off)** (default 1800, at most
  86400) signs out a session with no requests for that long. Choose
  **Save Login Rules**.
- **Per-username delay** (fixed, not on the tab). Failed password sign-ins
  also count against the username, from any address and whether or not
  the account exists. The first 3 failures cost nothing; each attempt
  after that waits 1 s, then 2, 4, 8, 16 and at most 30 s before the
  password is checked. It is a delay, never a lock: the right password
  still signs in, after at most 30 s. Parallel attempts for one username
  are spaced by the delay. A successful sign-in, or 15 minutes without a
  failure, clears it. An unknown username costs the same password hash
  and gets the same "Invalid username or password" as a wrong password.
- **Authentication.** **Auth Provider** is **Local**, **RADIUS**,
  **TACACS+** or **LDAP**, each with **Default Access Groups** for new
  users. **Default Credential** is the per-user fallback for jobs launched
  without a credential; **Service Credential** is the one Plexus uses for
  monitoring polls and scheduled discovery. Choose **Save Authentication**. Provider
  guides: [RADIUS](../RADIUS_CONFIGURATION_GUIDE.md),
  [TACACS+](../TACACS_CONFIGURATION_GUIDE.md), LDAP in
  [deploy/DEPLOYMENT.md](../deploy/DEPLOYMENT.md), and OIDC single sign-on,
  set up on this tab as well, in [sso-oidc.md](sso-oidc.md).
- **Server address check.** An enabled RADIUS, TACACS+ or LDAP server
  passes the outbound address guard
  ([webhooks.md](webhooks.md#outbound-address-check)) when a save turns it
  on or changes it (`400` naming the guard) and before each login (the
  login then fails as for an unreachable server). A cloud metadata address
  is always refused, a name that does not resolve too, and a private
  address when `APP_SSRF_BLOCK_PRIVATE=true`; list a trusted server in
  `APP_SSRF_ALLOW`.
- **Stored secrets.** The RADIUS and TACACS+ secrets, the LDAP bind
  password and the OIDC client secret are shown masked. Saving the mask
  keeps a secret only while its server stays the same: a new server or
  port, changed LDAP TLS settings, or a new OIDC issuer host needs the
  secret typed again (the save is refused with `400` otherwise). These
  secrets, the SNMP communities and v3 keys of SNMP profiles, the SIEM sink
  tokens and the notification channel secrets are stored encrypted in the
  database (`auth_settings`, with the key in `netcontrol.key`). Rows saved
  by an older release are encrypted the first time the server starts.
- **External accounts.** An LDAP, RADIUS, TACACS+, OIDC or SAML sign-in
  creates its Plexus account on first use and records the provider on it.
  It signs in to an existing account only when that account was created by
  (or already belongs to) the same provider, and for OIDC and SAML only
  with the subject bound to it. A local account, or one another provider
  manages, with the same username is never taken over: the sign-in is
  refused with "Invalid username or password" (SSO: the generic sign-in
  error) and audited as `auth` / `login.adopt_refused`. Local admins keep
  signing in with their local password (break-glass). An account created
  by an external sign-in before Plexus recorded providers, and not signed
  in through it since, looks like a local account and is refused too:
  delete it (the next sign-in recreates it with the default access groups)
  or set its provider with `PUT /api/admin/users/{id}` and
  `{"auth_provider": "ldap"}` (`local`, `ldap`, `radius`, `tacacs`, `oidc`
  or `saml`; API only). Changing the provider is how an admin hands an
  existing account to an external sign-in on purpose: it forgets the SSO
  subject bound to the account (the next OIDC or SAML sign-in binds its
  own), ends the account's open sessions and is audited as `auth` /
  `user.provider_change`. `GET /api/admin/users` shows each account's
  `auth_provider`.
- **Service Credentials.** **+ Add Service Credential** stores a **Name**,
  **Username**, **Password** and optional **Enable Secret** that only
  admins can create or change.

### Logging

Sends the Plexus application log to a syslog server. Tick **Enable Syslog
Forwarding**, then set **Host**, **Port** (1 to 65535), **Protocol** (UDP or
TCP), **Facility**, **Level** (the lowest level sent: DEBUG, INFO, WARNING,
ERROR or CRITICAL) and **App Name**. Choose **Save Syslog Settings**, then
**Send Test Message**. A host is required when forwarding is on, and it
passes the outbound address guard
([webhooks.md](webhooks.md#outbound-address-check)) when saved and when
the forwarder starts: a refused host is a `400` naming the guard.

Every line Plexus logs, to the console and to this forwarder, is redacted
first, and so are the before and after values in the change log. The value
under a secret key name is masked (`password`, `secret`, `token`,
`api_key`, `authorization`, `community`, `psk`, `private_key`,
`passphrase`, `routing_key`, `credential`, ...), in `key=value`,
`key: value` and JSON `"key": "value"` form, as are `password x` and
`secret 5 x` in device configuration, `Bearer` and `Basic` credentials and
`snmp-server community x`. A name that only references a secret stays
readable (`credential_id`, `token_count`, `community_list`,
`secret_variables`), and so do `true`, `false` and empty values.

### SIEM

Sends every audit event to one or more SIEM sinks over UDP, TCP, TLS or
HTTPS, in CEF or ECS JSON, with a severity floor per sink. See
[audit-log.md](audit-log.md#forwarding-to-a-siem).

### Discovery

- **Topology Discovery:** **Enable scheduled topology discovery** and
  **Interval (seconds)**, then **Save Schedule**. **Run Now** runs one
  discovery.
- **STP Polling:** **Enable scheduled STP polling**, **Poll all VLANs** (or
  one **VLAN ID**), **Interval (seconds)** and **Max VLANs** (1 to 256,
  default 64), then **Save Schedule**. **Run Now** polls once.
- **STP Root Policies:** per **Group** and **VLAN**, the **Expected Root
  Bridge ID** (for example `32768.aabb.ccdd.eeff`) and **Expected
  Hostname**, then **Save Policy**.

Both schedules are off by default with a 3600-second interval. The server
keeps both intervals between 300 and 86400 seconds, even though the form
accepts 60.

### Monitoring

**Enabled** (off by default), **Collect routes**, **Collect VPN**,
**Escalation enabled**, **Interval (s)** (default 300; 60 to 86400),
**Retention (days)** of raw poll results (default 30; 1 to 365), **CPU
threshold (%)** and **Memory threshold (%)** (default 90; 1 to 100),
**Cooldown (min)** (default 15; 1 to 1440), **Escalate after (min)**
(default 30; 5 to 1440) and **Escalation check (s)** (default 60; 30 to 3600). Choose **Save Monitoring
Settings**. **Poll Now** runs one poll with the saved settings. Retention of
other monitoring data is in [DATA_RETENTION.md](../DATA_RETENTION.md).

### NetFlow

Turns the flow collector on (**Enabled**), sets **NetFlow / IPFIX port**
(default 2055) and **sFlow port** (default 6343, 0 turns sFlow off), raw and
summary retention and the aggregation interval. Saving rebinds the
listeners without a restart. See [flow-collector.md](flow-collector.md).

### Syslog & Traps

The receivers for syslog messages and SNMP traps that devices send to
Plexus (not the **Logging** tab, which forwards Plexus's own log). Each
receiver has **Enabled** (off by default) and a **UDP port**: syslog 1514,
traps 10162. Both are unprivileged ports, because Plexus runs as a non-root
user. Choose **Save Receiver Settings**: each receiver is started, stopped or
moved to its new port right away, and an enabled receiver starts again with
Plexus. A port that cannot be bound (another program holds it) is logged and
the receiver shows **Stopped**.

Each receiver shows **Running on UDP** with its port, or **Stopped**, and since it
last started: **Received** messages, **Last message** and **Unreadable**
messages (ones that could not be parsed). Below them is the number of events
dropped since Plexus started because the write buffer was full.

Three switches set what a received syslog message does:

- **Raise alerts from syslog rules**: a message that matches a syslog alert
  rule raises a monitoring alert.
- **Back up the config on a change message**: a configuration-change
  message starts a config backup and drift check of the sending host.
- **Re-poll on link down or reload**: a link-down or reload message polls
  the sending host at once.

All three are on by default. Received events are listed in
[Monitoring > Events](monitoring.md#events).

Syslog can also arrive over TCP and TLS, whose source address cannot be
forged ([syslog-rules.md](syslog-rules.md#transports)):

- **Syslog over TCP**: **Enabled** (off by default) and a **TCP port**
  (1514; the same number as the UDP port is fine).
- **Syslog over TLS**: **Enabled** (off by default), a **TCP port** (6514)
  and **Require client certificates** (mutual TLS, off by default). It
  needs a server certificate, generated (self-signed) or uploaded with its
  key in the same section, and **Require client certificates** needs a
  stored client CA. The private key is encrypted at rest and never shown
  again. A new certificate or client CA restarts the TLS listener (open
  TLS connections drop).
- **Act on UDP messages** (on by default): off, syslog that arrived over
  UDP is stored but raises, resolves and triggers nothing. It can be
  turned off only while the TCP or TLS listener is on.

Each stream listener shows whether it runs and on which port, and since it
last started: received messages, errors, the last message, connections
open now and connections refused (over the limit of 1024, or 8 per source
address), and why an enabled TLS listener could not start. Saving is
refused (400) when the TCP and TLS listeners share a port, TLS is enabled
without a certificate, client certificates are required without a client
CA, or UDP actions are turned off without a TCP or TLS listener.

In Docker, `docker-compose.yml` publishes host port 162 to the trap
receiver's 10162 and 1514 to the syslog receiver's 1514, so devices send
traps to 162 and syslog to 1514. It also publishes 1514/tcp and 6514/tcp
for syslog over TCP and TLS. For devices that can only send syslog to
UDP 514, add `"514:1514/udp"` to the `plexus` service's `ports`. A port
changed here needs the matching container port in `docker-compose.yml`, and
the firewall must let the devices reach the host port
([deploy/FIREWALL.md](../deploy/FIREWALL.md)).

#### Listener sources

UDP source addresses can be forged, so the trap receiver, the syslog
receiver and the flow collector share one source allowlist and a
per-source rate limit (`netcontrol/listener_sources.py`):

| Setting | Default | Meaning |
|---|---|---|
| `policy` | `inventory` | `inventory`: a datagram is processed only when its source is an inventory host address (a host's primary IP or a recorded interface IP). `any`: every source, as before. |
| `extra_cidrs` | none | Networks (or single addresses) accepted in addition to the inventory hosts, up to 256. For a flow exporter or firewall that is not an inventory host. |
| `trap_rate_limit` | 100 | SNMP trap datagrams per second per source address. |
| `syslog_rate_limit` | 1000 | Syslog datagrams per second per source address. |
| `flow_rate_limit` | 5000 | NetFlow / IPFIX / sFlow datagrams per second per source address. |

A rate limit of 0 turns it off. A source may send a burst of two seconds'
worth of its limit. The settings have no Settings tab field yet: read and
change them with `GET` / `PUT /api/admin/listener-sources` (admin only; a
field left out keeps its saved value, an invalid network or policy is
refused with 422, and every change is audited as
`listener_sources.updated`):

```bash
curl http://localhost:8080/api/admin/listener-sources
curl -X PUT http://localhost:8080/api/admin/listener-sources \
  -H "Content-Type: application/json" \
  -d '{"extra_cidrs": ["198.51.100.0/24"]}'
```

The inventory addresses are cached in memory: loaded when a listener
starts, after every host add, edit or delete, and in the background at
most once a minute while datagrams arrive. A datagram never causes a
database query.

A dropped datagram is not parsed and not counted as **Received**. Each
listener counts its drops since Plexus started: `dropped_source` (not an
allowed source), `dropped_rate` (over the rate limit) and, for traps,
`dropped_community` (wrong SNMP community, see
[apc-ups.md](apc-ups.md#snmp-traps)). They are in the GET response above,
in `GET /api/admin/metrics/receivers/config` (`syslog_dropped_source`,
`trap_dropped_rate`, `trap_dropped_community`, ...) and in the flow
collector's `GET /api/flows/status` and `/api/admin/flows/config`. Drops are
logged at warning level at most once a minute per listener, with the count
since the last line.

**Upgrading:** sources that are not inventory hosts are dropped by default.
A device that sends syslog, traps or flows from an address Plexus does not
know (not its primary IP and not a recorded interface IP) is silent after
the upgrade until its address is added to the host (or recorded by
discovery), its network is added to `extra_cidrs`, or `policy` is set to
`any`. The drop counters and the log line name the case.

### Notifications

Email, PagerDuty, webhook and Microsoft Teams channels for monitoring
alerts, and which channels are the default. See
[alert-notification-channels.md](alert-notification-channels.md).

### Features

One checkbox per feature. Untick a feature and choose **Save Visibility**
to remove it from the navigation for every user, admins included. Hiding
does not disable the feature: its pages and API still work for users who
have it. Cloud Visibility and Federation are hidden on a fresh install.

### Custom Fields & Tags

Extra fields and tags for hosts, inventory groups and IPAM prefixes. See
[custom-fields-and-tags.md](custom-fields-and-tags.md).

### Device Model

The lists of manufacturers, device types, roles and lifecycle statuses
that hosts link to. See [device-model.md](device-model.md).

### AI Access

**Enable the MCP endpoint**, set its limits, and create or revoke tokens.
See [ai-access.md](ai-access.md).

### System

- **Current version** shows the **Version** and the **Git SHA**.
- **Update channel:** **Source** is **GitHub Releases (stable)**, **Edge
  (latest build of main)**, **Git (build a branch on the host)** or
  **Disabled (air-gapped)**. Release and Edge also take the **GitHub
  repository (owner/name)** and **Image repository**; Git takes **Remote**
  and **Branch**. Choose **Save channel settings**.
- **Check for updates:** **Check now** shows "Update available" or "Up to
  date", with release notes when there are any. **Install <version>** hands
  the upgrade to the host updater, which snapshots the database, runs
  `deploy/upgrade.sh`, waits for the health check and keeps a rollback
  target. Plexus restarts and the UI is away for a minute or two.
- **Update progress** shows the queued, running or last result, the log
  tail and **Roll back to previous**.
- **Job history:** **Job Retention (days)**, at least 30.

Install needs the host updater. Without it the tab says "Host updater not
installed". Only the version the last check reported can be installed. How
the updater works and how to roll back by hand: [deploy/DEPLOYMENT.md](../deploy/DEPLOYMENT.md),
section "Update from the web UI".

## Rules worth knowing

- **Sign-out on change.** Changing a user's role, renaming them, changing
  their access groups, or resetting their password signs that user out of
  all sessions. Renaming your own account signs you out too. Changing your
  own password signs out your other sessions only. The
  **Edit User Account** dialog always saves the access groups too, so
  saving it signs the user out even when only the display name changed.
  Deleting a user ends their open sessions at once.
- **Sign out ends every session of the account.** Signing out revokes the
  session on the server, so a copied cookie stops working. Plexus cannot
  revoke a single browser, so the account is signed out in every browser
  and device. Kiosk displays that share one account are signed out
  together when one of them signs out. It is audited as `auth` / `logout`.
- **You cannot** delete your own account, remove your own admin role, or
  delete the last admin.
- **Feature visibility is global.** It applies to all users. Use access
  groups to control who may use a feature.
- **Audit.** User, access group and feature visibility changes are written
  to the audit log under `auth`, syslog forwarding, syslog and trap
  receiver, and SIEM changes under `system`, and
  update actions under `admin_updates`. Login rule changes are not audited.
  See [audit-log.md](audit-log.md).

## Who can do what

| Action | Needs |
|---|---|
| Change **Appearance** | Any signed-in user |
| Change your own password | Any signed-in user |
| Every other Settings tab | Admin |
| Use the server API token | Whoever holds it (acts as admin) |

## API

All routes below need an admin (or the server API token). Writes from a
browser session need the CSRF token. See [api-reference.md](api-reference.md)
for the general rules.

```
GET    /api/admin/users
POST   /api/admin/users
PUT    /api/admin/users/{id}                 (username, display_name, role, session_never_expires, auth_provider)
PUT    /api/admin/users/{id}/password        {"new_password": "..."}
PUT    /api/admin/users/{id}/groups          {"group_ids": [2, 5]}
DELETE /api/admin/users/{id}
GET|PUT /api/admin/login-rules
GET|PUT /api/admin/feature-visibility        {"hidden": ["federation"]}
GET    /api/admin/updates/status
POST   /api/admin/updates/check | apply | rollback
GET|PUT /api/admin/metrics/receivers/config  {"syslog_enabled": true, "syslog_port": 1514}
POST   /api/admin/metrics/receivers/start    {"trap_port": 10162, "syslog_port": 1514}  (optional body)
POST   /api/admin/metrics/receivers/stop
GET|PUT|DELETE /api/admin/metrics/receivers/tls  {"cert_pem": "...", "key_pem": "...", "client_ca_pem": "..."}
POST   /api/admin/metrics/receivers/tls/generate {"common_name": "syslog.example.com", "sans": ["192.0.2.10"], "days": 825}
```

The receiver `PUT` also takes `syslog_tcp_enabled`, `syslog_tcp_port`,
`syslog_tls_enabled`, `syslog_tls_port`, `syslog_tls_require_client_cert`,
`syslog_tls_match_client_cert` (only with `syslog_tls_require_client_cert`
on: the client certificate must name the inventory host at the source
address) and `syslog_udp_actions`; the `GET` answer adds, for `syslog_tcp`
and `syslog_tls`, `<listener>_running`, `_listening_port`, `_received`,
`_errors`, `_last_message_at`, `_started_at`, `_connections`,
`_connections_refused` and `_error`, and for `syslog_tls`
`syslog_tls_connections_cert_refused` (connections closed because the
certificate did not name the host). The `tls` routes answer
`has_certificate`, `certificate` (`subject`, `issuer`, `not_before`,
`not_after`, `sha256_fingerprint`, `sans`, `self_signed`, or null),
`cert_pem`, `has_client_ca`, `client_ca` (`subject`, `not_after` of each
CA certificate) and `client_ca_pem`, never the private key. In the `PUT`,
`cert_pem` and `key_pem` go together (both left out: the certificate is
kept) and `client_ca_pem` on its own (`""` removes it). Changes are
audited as `syslog_tls.updated`, `syslog_tls.generated` and
`syslog_tls.deleted`.

A field left out of the receiver `PUT` keeps its saved value. `filterlog_evidence` (default on)
sums OPNsense firewall log lines per rule
([opnsense-topology.md](opnsense-topology.md#firewall-log-evidence)); the `GET` answer adds
`filterlog_received`, `filterlog_dropped` and `filterlog_unknown_source` since Plexus started. `start` and
`stop` turn both UDP receivers on or off and save that, the same as the
**Enabled** boxes; the ports in a `start` body are saved too. They leave
the syslog TCP and TLS listeners as they are.

```json
POST /api/admin/users
{ "username": "jdoe", "password": "<at least 8 characters>", "display_name": "J. Doe", "role": "user", "group_ids": [2] }
```

A short username or password, or a role other than `admin` or `user`,
gives `400`. An unknown group id gives `400` and the user is not created.
