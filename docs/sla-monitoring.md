# SLA Monitoring - Usage Guide

Plexus reports uptime, latency, jitter and packet loss for every inventory host
it polls (Monitoring, **SLA** tab) and checks them against SLA targets you
define. This page explains where the numbers come from, how long they are kept,
and how targets are evaluated and alerted on.

## Where the numbers come from

Every monitoring poll (SNMP/SSH plus ICMP) stores one row in
`monitoring_polls` with the poll status, the response time and the packet
loss. For a host over a period:

| Metric | Computed as |
|---|---|
| Uptime % | polls with status `ok` / all polls x 100 |
| Latency | mean response time of the polls that measured one |
| Jitter | population standard deviation of those response times |
| Packet loss % | mean packet loss of the polls that measured it |

MTTR (alert to acknowledgement) and MTTD (first failed poll to alert) come from
the monitoring alerts of the period.

## Rollups and long windows

Raw polls are deleted after the monitoring **retention** (`retention_days`,
default 30 days). So that the SLA tab can still report 90 or 365 days, a
background job rolls the polls up into `sla_metrics`:

- **Hourly**: one row per host, metric (`uptime`, `latency`, `jitter`,
  `packet_loss`) and completed hour.
- **Daily**: one row per host, metric and completed UTC day, built from the
  hourly rows.

Each row stores the value plus the sample count, the sum and (for latency and
jitter) the sum of squares, so any window is recombined exactly: a 365-day
jitter is the standard deviation of every sample in the year, not an average
of daily jitters. A window is read from the daily rows for the whole days, the
hourly rows for the hours since the last daily rollup, and the raw polls for
the part not rolled up yet. The job never writes a period twice, and its first
run after an upgrade rolls up every poll still retained.

The job runs every `sla_rollup_interval_seconds` (default 3600, minimum 300)
while monitoring is enabled, first about two minutes after startup. Rollups and
the SLA status history are kept `sla_retention_days` (default 400, from 30 to
3650); the cleanup runs with the monitoring retention cleanup. Both settings
are keys of the monitoring configuration (`PUT /api/admin/monitoring`).

## SLA targets

Define targets under **Monitoring, Configure, SLA Targets**:

| Field | Meaning |
|---|---|
| Metric | `uptime`, `latency`, `jitter` or `packet_loss` |
| Target | the value the SLA promises |
| Warning | the threshold between *warning* and *breach* |
| Window (days) | the period the target is measured over, 1 to 365 (default 30) |
| Scope | one host, a group (its hosts and the hosts of all of its sub-groups) or global (every host) |

Uptime is higher-is-better; latency, jitter and packet loss are
lower-is-better:

| Status | Uptime | Latency, jitter, packet loss |
|---|---|---|
| Met | value >= Target | value <= Target |
| Warning | Warning <= value < Target | Target < value <= Warning |
| Breach | value < Warning | value > Warning |
| No data | no poll in the window | no measured sample in the window |

## Evaluation and alerts

After every rollup pass the server evaluates every enabled target for every
host it applies to, over the target's own window ending now, and stores:

- the latest status per target and host (`sla_target_status`), with the
  value, sample count, window and the time the status started, and
- one history row each time a status changes (`sla_target_status_history`).

A **warning** opens a monitoring alert of severity `warning`, a **breach** one
of severity `critical`, with alert type `sla_breach`, metric `sla_<metric>`
(`sla_uptime`, ...) and a message naming the target, the value, the target and
warning thresholds and the window. The alerts appear on the **Alerts** tab and
go to the notification channels like any other monitoring alert. While the
alert is unacknowledged, later passes only bump its occurrence count (no new
notification); a warning that turns into a breach escalates the open alert to
critical. Acknowledge the alert to be notified again on the next warn or
breach. An active alert suppression for the host, its group or globally, with
metric empty or `sla_<metric>`, silences the alert; the status is still
recorded.

An administrator can run a pass at once with **Evaluate Now** on the SLA
Targets tab (`POST /api/sla/evaluate`), for example after adding a target.

The **SLA** tab shows a compliance strip (hosts per worst target status), a
status badge per host and, in the host detail, each target's value, status and
recent status changes.

## API

| Method and path | Purpose |
|---|---|
| `GET /api/sla/summary?days=&group_id=` | Per-host and average uptime, latency, jitter, packet loss over `days` (1-365), MTTR/MTTD, plus `compliance` (`met`, `warn`, `breach`, `no_data`, `hosts`, `evaluated_at`) and each host's `sla_status` |
| `GET /api/sla/host/{id}?days=` | One point per day for a host |
| `GET /api/sla/targets`, `POST`, `PUT /{id}`, `DELETE /{id}` | Target CRUD; `window_days` 1-365, `metric` one of the four above (HTTP 400 otherwise) |
| `GET /api/sla/compliance?group_id=&host_id=&target_id=` | Latest status of every (target, host); `group_id` includes sub-groups |
| `GET /api/sla/compliance/history?target_id=&host_id=&limit=` | Status changes, newest first (`limit` 1-1000, default 100) |
| `POST /api/sla/evaluate` | Admin: roll up and evaluate now; returns the rollup and evaluation counts |
