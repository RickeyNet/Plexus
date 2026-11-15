# Monitoring

Monitoring polls every inventory host on a schedule, stores CPU, memory,
interface, VPN, route, response time and packet loss values, tracks when
hosts and interfaces go up and down, and raises alerts. The Monitoring page
shows the results and holds the alert configuration; the device detail page
shows one host. This guide explains how polling works and how to use both
pages.

Related guides: [SLA monitoring](sla-monitoring.md),
[Alert notification channels](alert-notification-channels.md),
[Vendor monitoring coverage](vendor-monitoring-coverage.md),
[Meraki alerts](meraki-alerts.md), [Software versions](software-versions.md),
[NetFlow / sFlow / IPFIX](flow-collector.md) and
[Graph templates](graph-templates.md).

## Where it is and what you need

- **Observe > Monitoring** in the sidebar. The tabs are **Devices**,
  **Alerts**, **Events**, **SLA**, **Availability**, **Capacity** and
  **Configure**. **Configure** has the sub-tabs **Alert Rules**,
  **Suppressions**, **SLA Targets**, **OID Profiles**, **Graph Templates**,
  **Host Templates** and **Graph Trees**.
- You need the `monitoring` feature to see the page and `monitoring.write`
  to change anything on it.
- An admin sets up polling:
  1. **Settings > Monitoring**: tick **Enabled** and click **Save
     Monitoring Settings**. Polling is off on a new install.
  2. **Inventory > SNMP Profiles**: create an SNMP profile and assign it to
     the inventory groups to poll over SNMP. A host can have its own
     profile, which overrides its group's (see
     [Discovery](discovery.md#set-up-snmp)).
  3. **Settings > Authentication > Service Credentials**: the service
     credential is used for the SSH part of the poll (VPN and routes).

## How a host is polled

Each cycle polls every host of every inventory group, up to 16 at a time,
with a limit of 90 seconds per host. A poll has three independent parts:

| Part | When it runs | What it reads |
|---|---|---|
| SNMP | The host's effective SNMP settings are enabled: its own SNMP profile, else its group's profile, else the group's legacy profile, else the global SNMP settings | CPU, memory, uptime, interface status, speed, traffic and error counters |
| SSH | A service credential is set | VPN tunnels (`show crypto isakmp sa`, or `show vpn-sessiondb summary` on an ASA) and the route table |
| ICMP | When the server can ping and ICMP is not switched off | Response time and packet loss (3 pings, 2 second timeout) |

Hosts with the platform `icmp_only` get the ping only. The CPU and memory
OIDs depend on the host's platform; the built-in list is on **Configure >
OID Profiles** under **Built-in Vendor OIDs**.

A poll is marked failed when the SSH session fails and SNMP returned no CPU
and no up interface, or when an ICMP-only host does not answer the ping.
When ICMP is not available, the response time is the time the poll took.

A host whose poll times out or raises an error is skipped for 1, 2, 4 and
then at most 8 cycles. **Poll Now** always polls every host.

### Metrics collected

Each poll writes these metric samples, which feed the charts, custom
dashboard panels and graph templates:

| Metric | Meaning |
|---|---|
| `cpu_percent`, `memory_percent` | CPU and memory use in % |
| `memory_used_mb`, `memory_total_mb` | Memory in MB |
| `uptime_seconds` | Device uptime |
| `response_time_ms`, `packet_loss_pct` | Ping round trip and loss |
| `if_up_count`, `if_down_count` | Interfaces up, and down but not admin down |
| `vpn_tunnels_up`, `vpn_tunnels_down` | VPN tunnels |
| `route_count` | Routes in the global table |
| `if_in_errors`, `if_out_errors`, `if_in_discards`, `if_out_discards` | Interface counters, with `_rate` versions per second |

Interface traffic is stored separately per interface and shown on the
device detail page.

## Using the Monitoring page

### Devices

The tiles show **Hosts**, **Avg CPU**, **Avg Mem**, **IF Up**, **IF Down**,
**VPN Up**, **VPN Down**, **Routes** and **Open Alerts**. Each host row
shows its last poll; **Detail** opens the device detail page and **History**
lists the last 50 polls. **Poll Now** polls every host now and shows the
progress per host. The tab refreshes every 60 seconds.

### Alerts

1. Filter by **Search alerts…**, severity (**Critical**, **Warning**,
   **Info**) and **Unacknowledged** / **Acknowledged** / **All**. **Route
   churn** shows only route table change alerts; their **Route history**
   button lists the stored route snapshots.
2. Click **Acknowledge** on an alert, or tick alerts and use **Acknowledge
   Selected** or **Acknowledge All** (all unacknowledged alerts the filters
   show).

A row shows the severity, **Escalated** when it was escalated, **Nx** when
the same condition was seen N times, the host, the metric, the message,
**Created** and **Last seen**, and the rule number when a rule raised it.

Alerts come from these sources:

| Source | Metric | Severity |
|---|---|---|
| CPU or memory at or above the threshold in **Settings > Monitoring** (default 90%) | `cpu`, `memory` | Warning, critical at 95% or more |
| Interfaces down but not admin down | `interface_down` | Warning |
| VPN tunnels down | `vpn_down` | Warning |
| Route table changed between full reads | `route_churn` | Warning, critical for a change of 10 routes or more |
| Alert rules | the rule's metric | the rule's severity |
| SLA targets (of hosts, and of integration entities such as OPNsense gateways) | `sla_<metric>` | see [SLA monitoring](sla-monitoring.md) |
| Baseline deviations, Meraki alerts, Cato egress findings, integration entities | various | see the linked guides |

While an alert is unacknowledged, the same condition on the same host only
raises its count and **Last seen**; a notification is sent only for a new
alert. After you acknowledge it, the next occurrence opens a new alert.
There is no **Resolve** button: an alert stays open until someone
acknowledges it. Meraki alerts, Cato egress findings and integration
entities acknowledge their own alerts as `auto-resolved` when the condition
clears.

**Escalation.** When **Escalation enabled** is on, an unacknowledged alert
that is not critical becomes critical (or the rule's escalation severity)
after **Escalate after (min)**, default 30. It is escalated once.

**Muting** applies only to integration entities (sites, uplinks, tunnels,
cloud links): see [Muting](meraki-topology.md#muting). For inventory hosts
use acknowledge and suppressions.

### Alert rules (Configure > Alert Rules)

1. Click **+ New Rule**.
2. Fill in **Name**, **Metric**, **Operator** (`>=`, `>`, `<=`, `<`, `==`,
   `!=`), **Value** and **Severity** (Warning or Critical).
3. Optionally set **Scope: Group** or **Scope: Host (overrides group)**.
   Without scope the rule applies to all hosts.
4. Tick **Notification Channels**, or leave all unticked to use the default
   channel set.
5. Click **Create**. **Edit**, **Disable** / **Enable** and delete are on
   each rule.

| Metric in the form | Value compared |
|---|---|
| CPU % | CPU use |
| Memory % | Memory use |
| Interfaces Down | Interfaces down but not admin down |
| VPN Tunnels Down | VPN tunnels down |
| Route Count | Routes in the global table |
| Uptime (seconds) | Device uptime |

A rule is checked against every poll of the hosts in its scope. A rule on a
metric the poll has no value for (for example CPU without SNMP) never fires.

### Suppressions (Configure > Suppressions)

Click **+ New Suppression** and fill in **Name**, **Starts At**, **Ends At**
(default: now to 2 hours from now), **Scope: Group**, **Scope: Host**,
**Metric (blank = all)** and **Reason**. While it is active, matching alerts
are not raised; the poll data is still stored. Each suppression shows
**Active**, **Scheduled** or **Expired**. Expired suppressions are deleted
by the retention cleanup.

### Events

The syslog messages and SNMP traps Plexus received, filtered by
**Severity**, **Type** (**Syslog** or **SNMP Trap**) and **Search**, with
the counts **Total Events**, **Critical+**, **Errors** and **Warnings**. The
receivers listen on UDP 10514 (syslog) and 10162 (traps); they are not
started with Plexus: an admin starts them with
`POST /api/admin/metrics/receivers/start`.

### Availability

Choose the **Period** (**Last 24h**, **Last 7 days**, **Last 30 days**).
**Polled hosts** shows **Hosts Tracked**, **Currently Up**, **Currently
Down**, **Avg Uptime** and **Outages**, and the sub-tabs **Hosts**,
**Outages** and **Transitions**, filtered by **Group**. Every poll records
a transition when a host (poll ok or failed) or an interface (up or down)
changes state; an outage with no end is **Ongoing**.

Below it, **Integrations and cloud** shows the same for the entities that
Meraki, Cato, FMC, Panorama, Appgate, OPNsense, AWS, Azure and GCP report; see
[Availability tracking](meraki-topology.md#availability-tracking). The
**Meraki alerts** and **Cato egress vs cloud allow-lists** panels follow.

### Capacity

Choose a **Metric** (CPU %, Memory %, Route Count, Interfaces Up, VPN
Tunnels Up), a **History** of 30, 90, 180 or 365 days, a **Group** and a
**Threshold**. Plexus fits a straight line through the daily averages of
each host, projects it forward, and lists in **Est. Date** when each rising
host reaches the threshold.

## The device detail page

Open it with **Detail** on the Devices tab or a tile on the Dashboard.
**← Devices** goes back. It uses the time range bar at the top right.

The info bar shows **Hostname**, **IP**, **Type**, **Liveness**, **CPU**,
**Memory**, **Interfaces** (up / down / admin down), **Uptime** and **Last
Poll**, and the matching IPAM subnet when there is one.

| Liveness | Meaning |
|---|---|
| Healthy (with the ping time) | Ping answered and the SNMP/SSH poll returned CPU |
| ICMP up, SNMP/SSH not responding | Ping answered, but no CPU came back: check credentials, ACLs or the SNMPv3 engine ID |
| Unreachable (no ICMP reply) | No ping reply |
| ICMP disabled | ICMP did not run |

| Tab | Shows |
|---|---|
| **Overview** | CPU %, Memory %, Response Time (ms) and Packet Loss (%) charts |
| **Interfaces** | Every interface with status, speed, in, out and utilization, traffic charts for the 12 busiest, and the interface addresses |
| **Interface Errors** | Error and discard counts, trend charts and error events |
| **Flow** | Flow records this device exported (hidden when Traffic Analysis is hidden) |
| **Alerts** | The last 50 alerts of the host; **Correlate** lists deployments and configuration drift in the 30 minutes before the alert |
| **Compliance** | The latest compliance scan results of the host |
| **Syslog** | The last 100 syslog messages from the host |

## Rules worth knowing

- **Defaults:** interval 300 seconds (60 to 86400; up to 5% random delay is
  added), CPU and memory thresholds 90%, poll history 30 days.
- **Retention:** polls, alerts and route snapshots are deleted after
  **Retention (days)** (1 to 365), checked at most once an hour after a poll
  cycle. Metric samples are kept 48 hours, hourly rollups 30 days and daily
  rollups 365 days; interface traffic and syslog / trap events 30 days;
  interface error events 90 days.
- **Poll Now** runs even when polling is not enabled.
- **Known gaps:** the **Cooldown (min)** of a rule and of **Settings >
  Monitoring**, and a rule's **Escalate After** time, are saved but the
  poller does not read them: repeats are folded by the open alert and
  escalation uses the global wait. Custom **OID Profiles** are stored, but
  the poller reads the built-in vendor OIDs and the overrides an admin adds
  through `/api/metrics/vendor-oids`.
- **Deleting a host** deletes its polls, alerts, metric samples and host
  graphs.

## Who can do what

| Action | Needs |
|---|---|
| See every Monitoring tab and the device detail page | `monitoring` |
| Poll Now, acknowledge alerts, manage rules and suppressions, mute entities | `monitoring.write` |
| OID profiles | `monitoring` |
| Settings > Monitoring, start the syslog and trap receivers, vendor OID overrides | Admin |
| Graph templates, host templates and graph trees | `graph-templates` |
| Device detail **Compliance** and **Flow** tabs | `compliance`, `traffic-analysis` |

Acknowledging, rules, suppressions, Poll Now and settings changes are
written to the audit log under `monitoring`.

## API

The full list is in [API reference](api-reference.md).

| Method and path | Purpose |
|---|---|
| `GET /api/monitoring/summary`, `GET /api/monitoring/polls` | Tiles and the latest poll per host |
| `GET /api/monitoring/polls/{host_id}/history?limit=` | Poll history of one host |
| `GET /api/monitoring/alerts?acknowledged=&severity=&host_id=` | Alerts |
| `POST /api/monitoring/alerts/{id}/acknowledge`, `POST /api/monitoring/alerts/bulk-acknowledge` | Acknowledge one, or up to 1000 |
| `GET/POST /api/monitoring/rules`, `PUT/DELETE /api/monitoring/rules/{id}` | Alert rules |
| `GET/POST /api/monitoring/suppressions`, `DELETE /api/monitoring/suppressions/{id}` | Suppressions |
| `POST /api/monitoring/poll-now` | Poll every host now |
| `GET /api/availability/summary?days=`, `/outages`, `/transitions` | Host availability |
| `GET/PUT /api/admin/monitoring` | Polling settings (admin) |

Create a rule for one group:

```json
POST /api/monitoring/rules
{
  "name": "Branch CPU high",
  "metric": "cpu",
  "operator": ">=",
  "value": 85,
  "severity": "warning",
  "group_id": 3,
  "channel_ids": ["ops-email"]
}
```

The answer is `{"id": 7}`. A missing name or metric, or an unknown
operator, gives `400`. Acknowledging several alerts takes
`{"alert_ids": [101, 102, 103]}` and answers
`{"ok": true, "acknowledged": 3}`.
