# AWS and Azure Alerts

Plexus reads what AWS and Azure themselves say is wrong, every five minutes
by default, instead of waiting for the hourly discovery to see a state
change:

- **AWS**, per account and region: CloudWatch alarms in `ALARM` state, AWS
  Health issues and scheduled changes, and impaired EC2 status checks and
  scheduled instance events.
- **Azure**, per subscription: fired Azure Monitor alerts (the metric, log,
  activity log and Resource Health alert rules defined in the subscription)
  and Resource Health availability (a resource `Unavailable` or `Degraded`).

Both are providers of the vendor-neutral alert feed pipeline (the
`vendor_alerts` store, migration 0132) that the Cato events feed uses
([cato-alerts.md](cato-alerts.md)): the same store, the same alerting, the
same mutes and the same settings API. Nothing is pushed to Plexus: no
EventBridge rule, SNS topic, action group or inbound webhook is needed, so
it works behind NAT and without inbound access.

Contents:

- [Before you start](#before-you-start)
- [Permissions](#permissions)
- [How it works](#how-it-works)
- [What is read](#what-is-read)
- [Severity](#severity)
- [Raising and clearing alerts](#raising-and-clearing-alerts)
- [Settings reference](#settings-reference)
- [Cost and throttling](#cost-and-throttling)
- [API](#api)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)

## Before you start

- Add the account under **Cloud Visibility > Accounts** as for discovery
  ([cloud-visibility.md](cloud-visibility.md)). The feed uses the account's
  discovery credentials and region scope; nothing else is configured per
  account. Demo (sample) accounts and disabled accounts are not read.
- The cloud SDK the discovery uses must be installed on the Plexus server
  (`requirements-cloud.txt`): **boto3** for AWS, **azure-identity** for Azure
  (only for the token; the Azure reads are plain REST calls). Without it the
  account shows "boto3 is not installed" or "azure-identity is not
  installed" in the feed settings and is retried hourly.
- The settings are under **Cloud Visibility > Accounts > AWS alerts / Azure
  alerts** (administrators); the alerts are listed under **Monitoring >
  Availability > AWS alerts / Azure alerts**.

## Permissions

Read-only. Add these to the identity the discovery already uses.

**AWS** (IAM actions):

| Action | Part | Notes |
|---|---|---|
| `cloudwatch:DescribeAlarms` | CloudWatch alarms | Scoped to `*`: AWS returns composite alarms only to a permission scoped to `*` |
| `ec2:DescribeInstanceStatus` | EC2 status | |
| `health:DescribeEvents` | AWS Health | Needs a Business, Enterprise On-Ramp or Enterprise support plan (or their successors) |
| `health:DescribeAffectedEntities` | AWS Health | Names the affected resources |
| `ec2:DescribeRegions` | all | Only for a region scope of `all` (already needed by the discovery) |
| `sts:AssumeRole` | all | Only when the account uses an IAM role (already needed by the discovery) |

**Azure** (role on the subscription): **Reader** or **Monitoring Reader**
(both include `*/read`). The two actions used are
`Microsoft.AlertsManagement/alerts/read` and
`Microsoft.ResourceHealth/availabilityStatuses/read`.

## How it works

Every `interval_seconds` (300 by default) each account not opted out is read
by one app worker (a lease on its feed row), each part and region separately:

| Provider | Scope | Call |
|---|---|---|
| AWS | each region of the account's scope | `DescribeAlarms` (`StateValue=ALARM`, metric and composite alarms) |
| AWS | each region | `DescribeInstanceStatus` (running instances) |
| AWS | the account | Health `DescribeEvents` (`open` and `upcoming`, categories `issue` and `scheduledChange`), then `DescribeAffectedEntities` for up to 10 events per call, signed for `us-east-1` |
| Azure | the subscription | `GET .../providers/Microsoft.AlertsManagement/alerts?api-version=2019-03-01&monitorCondition=Fired&timeRange=30d&pageCount=250` |
| Azure | the subscription | `GET .../providers/Microsoft.ResourceHealth/availabilityStatuses?api-version=2025-05-01` |

These are **current-state** reads: each read of a scope (one region's
CloudWatch alarms, one subscription's Resource Health) returns everything
that is wrong in that scope now. So:

- An alert is **opened** the first time a read reports it.
- It is **resolved** when a later read of its scope, **read in full**, no
  longer reports it: the alarm left `ALARM` (or was deleted), the Health
  event closed, the status check passed, the Azure alert's monitor condition
  became `Resolved` or someone closed it, the resource is `Available` again.
- A scope whose read **failed** (a region refused, a throttled call) or was
  **read in part** (more than 10 API pages, or a next page on another host)
  resolves nothing; its alerts stay as they were. The other scopes go on: one
  failing region never hides another. The account shows **Reading, in part**
  with what failed; it is not backed off.
- When **every** scope of an account failed (bad credentials, no SDK), the
  poll fails and is backed off like any feed (an access problem up to hourly).
- A state that says nothing either way keeps the alert as it is:
  Resource Health `Unknown`, EC2 `initializing` / `insufficient-data`.

The Azure token is requested for `https://management.azure.com/.default`
from the account's credential (its service principal, else
`DefaultAzureCredential`); the reads go through the project's outbound HTTP
sender (SSRF guard, pinned address, no redirects), and a `nextLink` is only
followed to `management.azure.com`.

## What is read

**CloudWatch alarms.** One alert per alarm in `ALARM`: title the alarm name,
message its `StateReason`, start its `StateTransitionedTimestamp`. A metric
alarm names its resource through its dimensions (`InstanceId`, a Transit
Gateway, a NAT gateway, a DB identifier...); a composite alarm names none
and is an account-level alert. Log alarms are not read.

**AWS Health.** Open and upcoming issues and scheduled changes of the
account's regions (and of no region: global services). An affected resource
the topology tracker follows gets its own alert; the other affected
resources are listed (up to 20) in one alert for the event, which is also
the alert of an event that names no resource. Affected entities `RESOLVED`
or `UNIMPAIRED` are left out.

**EC2 status.** Per running instance: the system status check and the
instance status check `impaired` (critical), the attached EBS status
`impaired` (warning), and each scheduled event (reboot, maintenance,
retirement, stop) not yet `[Completed]` (warning, with its window).

**Azure Monitor alerts.** One alert per fired, not closed alert instance:
title the alert rule's name, message its description, the target resource.
Alerts of every monitor service are read (Platform metrics, Log Analytics,
Activity Log, Service Health, Resource Health alert rules...).

**Resource Health.** One alert per resource `Unavailable` or `Degraded`,
with Azure's summary, reason type and expected resolution time.

**Entity matching.** An alert whose resource is an entity the topology
availability tracker follows (an EC2 instance, Transit Gateway, NAT or
Direct Connect gateway, an Azure VM, VPN gateway, firewall, a managed
service such as a load balancer or an RDS instance) carries that entity's
type and id. That gives it the entity's site, its inventory host when the
tracker matched one (the alert is then a monitoring alert on that host),
and the entity's mutes. Other alerts are account-level and go to the
notification channels.

## Severity

| Source | Critical | Warning | Info (listed only) |
|---|---|---|---|
| CloudWatch alarm (no severity in AWS) | alarm name or description has the word "critical" | every other alarm in `ALARM` | |
| AWS Health | an `issue` of the account (`ACCOUNT_SPECIFIC`) or naming an affected resource | a public (service-wide) `issue`, a `scheduledChange` | (`accountNotification` is not read) |
| EC2 status | system or instance status check impaired | attached EBS impaired, a scheduled event | |
| Azure Monitor alert | `Sev0`, `Sev1` | `Sev2` | `Sev3`, `Sev4` |
| Resource Health | `Unavailable` | `Degraded` | |

## Raising and clearing alerts

As for every vendor alert feed ([cato-alerts.md](cato-alerts.md#raising-and-clearing-alerts)):
a new warning or critical alert is raised once, server-side, as a monitoring
alert (`vendor_alert`) on its inventory host, else to the notification
channels; it alerts again only if it gets worse, and is cleared
(`auto-resolved`) when it resolves.

- **Mutes.** A topology mute of the entity, or of its site, covers the alert
  (stored as muted, not raised).
- **No double notification.** An impaired EC2 status check and a Resource
  Health `Unavailable` / `Degraded` stand for their entity's availability:
  when the tracker already alerted the entity down or degraded the alert is
  recorded without a notification, and the tracker does not alert on an
  entity such an alert already notified.

## Settings reference

Stored in the `vendor_alert_feeds` auth setting, one entry per provider
(`aws`, `azure`); changed under **Cloud Visibility > Accounts** or with
`PUT /api/monitoring/vendor-alerts/{aws|azure}/settings` (admin, audited as
`vendor_alerts.settings_updated`).

| Setting | Default | Meaning |
|---|---|---|
| `poll_enabled` | `true` | Read on schedule |
| `interval_seconds` | `300` | 30 to 3600 |
| `excluded_sources` | `[]` | Account ids not read (their open alerts stay as they are) |
| `disabled_parts` | `[]` | Parts not read: AWS `cloudwatch`, `health`, `ec2_status`; Azure `monitor_alerts`, `resource_health`. The open alerts of a part switched off resolve at the next poll |

`open_ttl_hours` and `security_events` do not apply (no one-shot alerts, no
security events).

## Cost and throttling

- CloudWatch `DescribeAlarms` is limited to 9 requests per second per region
  and account (AWS default quota); one call per region per poll (100 alarms
  a page). CloudWatch API requests beyond the free tier are billed by AWS;
  see AWS pricing.
- Azure Resource Manager reads are throttled per subscription and service
  principal (a bucket of 250 reads refilled at 25 per second); a poll makes
  two reads per subscription, more for large subscriptions.
- At most 10 pages are read per scope and poll (1000 alarms per region,
  2500 Azure alerts, 1000 Health events); a larger scope is read in part and
  resolves nothing.
- A throttled call (AWS `Throttling`, ARM HTTP 429) fails its scope only; a
  poll where everything was throttled backs off up to ten minutes.

## API

The vendor alert feed API with `provider` `aws` or `azure`:

| Method | Path | Notes |
|---|---|---|
| GET | `/api/monitoring/vendor-alerts?provider=aws` | Monitoring access. The alerts, each with `muted`. Object scope: a scoped caller sees only the alerts raised on hosts it may read |
| GET | `/api/monitoring/vendor-alerts/aws/settings` | Admin. `config`, `parts`, `current_state`, the interval bounds, `status` and `sources` (per account: last poll, last success, last error, `feed_status`) |
| PUT | `/api/monitoring/vendor-alerts/aws/settings` | Admin, audited. Any of the settings above |
| POST | `/api/monitoring/vendor-alerts/aws/poll` | Admin, audited. Read every account now, ignoring back-off and the poll switch |

See [api-reference.md](api-reference.md#vendor-alert-feeds).

## Troubleshooting

- **"AWS Health needs a Business support plan or higher".** AWS answered
  `SubscriptionRequiredException`. The Health part is not asked again for
  24 hours; the CloudWatch and EC2 parts go on. Switch the part off
  (`health`) to drop the message.
- **Reading, in part.** Some scopes failed or were read in part; the error
  column names each (the region, the part, AWS's or Azure's error code).
  Their alerts are kept until a full read.
- **No access.** The credentials were refused (`AccessDenied`,
  `UnauthorizedOperation`, HTTP 401 / 403 from ARM, an expired session
  token): see [Permissions](#permissions). Retried hourly.
- **An alert does not show its instance or VM.** The resource is not
  tracked by the topology availability tracker (run a discovery, or the
  resource is not drawn on the map); the alert is account-level.

## Limitations

- Not checked against a live account: the boto3 response key names of
  `DescribeInstanceStatus` (`InstanceStatuses`, `Events`,
  `AttachedEbsStatus`); the `[Canceled]` prefix of a cancelled EC2 event
  (only `[Completed]` is documented); the region value AWS Health gives a
  global event; whether the Alerts Management `timeRange` applies to the
  start or the last change of an alert; the case of the Resource Health
  status `id` suffix; the matching of a CloudWatch dimension or Health
  entity to a managed service's resource uid.
- An Azure alert still fired after 30 days drops out of the read
  (`timeRange=30d`, the longest offered) and is resolved.
- Public clouds only: the AWS Health endpoint is the commercial partition's
  (`us-east-1`), the ARM host `management.azure.com` (no Azure Government
  or China).
- A part switched off resolves its alerts; switched on again, an alarm that
  stayed in `ALARM` meanwhile opens again and is notified again (it is read
  as open now, whenever it began).
- An Azure Monitor alert rule on Resource Health and the Resource Health part
  can report the same outage twice; switch one off.
- The open alerts of an account that is removed, disabled or opted out of
  the feed, and those of an AWS region taken out of the account's region
  scope, are resolved at the next poll cycle (nothing would read them clear).
  With polling switched off for the whole provider nothing is resolved.
- These alerts do not feed the availability history or uptime % (the
  discoveries do).
