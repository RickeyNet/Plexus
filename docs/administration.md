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
| **Notifications** | Alert notification channels |
| **Features** | Which features appear in the navigation |
| **Custom Fields & Tags** | Extra fields and tags for hosts, groups and IPAM prefixes |
| **Device Model** | Manufacturers, device types, roles and lifecycle statuses |
| **AI Access** | The read-only MCP endpoint and its tokens |
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
modify"). A user gets every feature of every group they are in.

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

Treat the server API token like a root password. `APP_REQUIRE_API_TOKEN=true`
forces non-session API calls to present it.

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
- **Authentication.** **Auth Provider** is **Local**, **RADIUS**,
  **TACACS+** or **LDAP**, each with **Default Access Groups** for new
  users. **Default Credential** is the per-user fallback for jobs launched
  without a credential; **Service Credential** is the one Plexus uses for
  monitoring polls and scheduled discovery. Choose **Save Authentication**. Provider
  guides: [RADIUS](../RADIUS_CONFIGURATION_GUIDE.md),
  [TACACS+](../TACACS_CONFIGURATION_GUIDE.md), LDAP in
  [deploy/DEPLOYMENT.md](../deploy/DEPLOYMENT.md), and OIDC single sign-on,
  set up on this tab as well, in [sso-oidc.md](sso-oidc.md).
- **Service Credentials.** **+ Add Service Credential** stores a **Name**,
  **Username**, **Password** and optional **Enable Secret** that only
  admins can create or change.

### Logging

Sends the Plexus application log to a syslog server. Tick **Enable Syslog
Forwarding**, then set **Host**, **Port** (1 to 65535), **Protocol** (UDP or
TCP), **Facility**, **Level** (the lowest level sent: DEBUG, INFO, WARNING,
ERROR or CRITICAL) and **App Name**. Choose **Save Syslog Settings**, then
**Send Test Message**. A host is required when forwarding is on.

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

- **Sign-out on change.** Changing a user's role, changing their access
  groups, or resetting their password signs that user out of all sessions.
  Changing your own password signs out your other sessions only. The
  **Edit User Account** dialog always saves the access groups too, so
  saving it signs the user out even when only the display name changed.
- **You cannot** delete your own account, remove your own admin role, or
  delete the last admin.
- **Feature visibility is global.** It applies to all users. Use access
  groups to control who may use a feature.
- **Audit.** User, access group and feature visibility changes are written
  to the audit log under `auth`, syslog and SIEM changes under `system`, and
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
PUT    /api/admin/users/{id}                 (username, display_name, role, session_never_expires)
PUT    /api/admin/users/{id}/password        {"new_password": "..."}
PUT    /api/admin/users/{id}/groups          {"group_ids": [2, 5]}
DELETE /api/admin/users/{id}
GET|PUT /api/admin/login-rules
GET|PUT /api/admin/feature-visibility        {"hidden": ["federation"]}
GET    /api/admin/updates/status
POST   /api/admin/updates/check | apply | rollback
```

```json
POST /api/admin/users
{ "username": "jdoe", "password": "<at least 8 characters>", "display_name": "J. Doe", "role": "user", "group_ids": [2] }
```

A short username or password, or a role other than `admin` or `user`,
gives `400`. An unknown group id gives `400` and the user is not created.
