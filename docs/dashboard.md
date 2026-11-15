# Dashboard

The Dashboard is the home page of Plexus. It shows the health of the polled
devices, what needs attention now, the state of the connected integration
sources, backups, recent events and open alerts on one page. You can also
build your own dashboards with metric charts.

## Where it is and what you need

- Open **Dashboard** at the top of the sidebar (the address `/`).
- You need the `dashboard` feature. Some panels read other features and are
  left out without them: integration sources need `topology`, the
  integration counts and problems need `monitoring`, **Top Talkers** needs
  `traffic-analysis` and **Backup Status** needs `config-backups`.
- Most panels show data only after devices are polled. See
  [Monitoring](monitoring.md) for how polling is set up.

The time range bar at the top right of the page has the presets **1h**,
**6h**, **24h**, **7d** and **30d**. The default is 6h and your choice is
remembered in your browser. The same range is used by custom dashboards, the
device detail page and Network Tools, Traffic Analysis.

## The panels, top to bottom

| Panel | What it shows | Data source |
|---|---|---|
| **Needs attention** / **All clear** | Every current problem, critical first. Each row names what is affected and opens the panel or page with the detail | Device polls, open alerts, latest backups, topology sources, integration entities |
| **Get started with Plexus** | A setup checklist, until every step it shows is done | Counts of sources, hosts, polled devices, SNMP profiles, backup policies, notification channels |
| **Integrations** | One card per connected Meraki, Cato, FMC, Panorama, Appgate, AWS, Azure or GCP source | Topology sources and their availability counts |
| **Overall Health** | A donut of polled devices per health bucket | Latest poll of each device |
| **Group Health** | One tile per inventory group with polled devices | Latest poll of each device |
| **Average Response Time** | The mean response time of all polled devices, with **Avg** and **Peak** | Metric `response_time_ms` |
| **Busiest Interfaces** | The 5 interfaces with the highest peak bandwidth, one line each (in + out) | Interface counters from SNMP polls |
| **Top Talkers** | The 10 IP addresses with the most bytes, by **Source** or **Destination** | NetFlow / sFlow collector |
| **Devices** | One tile per polled device, worst first, coloured by health. A tile opens the device detail page | Latest poll of each device |
| **Backup Status** | Hosts per backup state and a list of problem hosts | Configuration backups |
| **Recent Events** | Up to 50 deployments, configuration changes and alerts, filtered by **Deploy**, **Config** or **Alert** | Event annotations |
| Stat rings | **Total Hosts**, **Playbooks**, **Total Jobs**, and **Sources Healthy** (or **Entities Up** when there are no sources) | Inventory, jobs, topology sources |
| **Network Health Overview** | A table of polled devices with filters for group and status, and sort | Latest poll of each device |
| **Active Alerts** | Up to 20 open monitoring alerts, then up to 20 down or degraded integration entities | Unacknowledged alerts, integration availability |
| **Not set up yet** | The panels left out because what they need is not set up, with a link to set it up | Setup state |

A panel whose prerequisite is missing is not drawn. It is listed on the
**Not set up yet** card instead:

| Panels | Need |
|---|---|
| Overall Health, Group Health, Average Response Time, Busiest Interfaces, Devices, Device Health | Inventory devices polled over SNMP |
| Top Talkers | The NetFlow / sFlow collector switched on |
| Backup Status | A configuration backup policy |

A panel that is set up but has no data in the selected range says so and
offers a button for the next longer range.

## Using the page

1. **Work through the setup guide.** The **Get started with Plexus** card
   lists up to six steps: **Connect a source**, **Collect from it**, **Add or
   discover devices**, **Poll devices with SNMP**, **Create a backup policy**
   and **Add a notification channel**. Each step has a button that opens the
   page where it is done. Steps you cannot do (most are admin-only) are not
   shown. **Hide guide** hides the card; **Setup guide** in the page header
   brings it back.
2. **Triage from Needs attention.** Click a row to go to the detail. The
   tooltip of a row lists every affected item.
3. **Follow the counts.** Every count is a link to exactly what it counted:
   a donut slice or a group tile opens **Devices** or **Network Health
   Overview** with that filter selected, a backup count lists those hosts,
   and an integration count opens **Monitoring > Availability** filtered to
   its source, type and state.
4. **Mute an integration entity.** In **Active Alerts**, **Mute** on a down
   or degraded entity opens the mute dialog. See
   [Muting](meraki-topology.md#muting).
5. **Connect a source.** Administrators can use **Add source** in the
   header to connect Meraki, Cato, a firewall manager or a cloud account.

## What the results mean

### Device health

Every panel uses the same health rules, applied to the latest poll of each
device:

| Health | Rule | Colour |
|---|---|---|
| Down | The last poll failed | Red |
| Critical | CPU 90% or more, memory 95% or more, or packet loss 50% or more | Red |
| Warning | CPU 75% or more, memory 80% or more, packet loss 10% or more, or any interface down | Amber |
| Healthy | CPU or memory reported, and none of the above | Green |
| Unknown | No CPU or memory value | Grey |

The donut, the group tiles and the filters merge Critical and Down into one
bucket, **Critical / Down**.

### Needs attention rows

| Row | Severity |
|---|---|
| Devices unreachable, devices critical | Critical |
| Interfaces down | Warning |
| Backups failed | Critical |
| Critical alerts (severity `critical` or `error`) | Critical |
| Integration entities down | Critical |
| Integration entities degraded | Warning |
| Source collection failed | Critical |
| Source collected partially, not collected recently, with collection warnings | Warning |

**All clear** shows only when something is watched (devices, sources or
integration entities) and nothing is wrong.

### Backup states

| State | Meaning |
|---|---|
| success | The last backup succeeded within 7 days |
| stale | The last successful backup is older than 7 days |
| failed | The last backup attempt failed |
| never | A polled device has no backup |

### Source health (Integrations cards and Sources Healthy)

| Badge | Meaning |
|---|---|
| OK | The last collection succeeded, is recent and has no warnings |
| Collection failed | The last collection failed |
| Partial collection | The last collection got only part of the data |
| Overdue | No collection for twice the source's interval, or 24 hours when the interval is unknown. A source with scheduled collection off is never overdue |
| Warnings | The last collection reported warnings |
| Never collected | Nothing collected yet |

Disabled sources and demo sources are not judged.

## Custom dashboards

The dashboard switcher in the header (**Overview**, your dashboards, and
**Manage dashboards…**) and the **Manage** button open your own dashboards.

1. On **Dashboards**, click **+ New Dashboard**.
2. In **Create Dashboard**, enter a **Name**, an optional **Description**,
   and tick the **Template Variables** you want: `$group` and `$host`.
   **Create** opens the new dashboard.
3. Click **Edit**, then **+ Add Panel**. Fill in **Panel Title**, **Chart
   Type** (Line, Bar, Gauge, Heatmap, Table), **Metric** (for example
   `cpu_percent`), **Host (ID, "\*", or "$host")**, **Width (1-12)** and
   **Height (rows, 2-12)**, then **Add Panel**.
4. Click **Done** to leave edit mode. In edit mode each panel has **Edit**
   and **Remove**, and the header has **Delete Dashboard**.

| Chart type | Shows |
|---|---|
| Line | One line per host, with deployment, configuration and alert markers |
| Bar | The average per host |
| Gauge | The average of all samples |
| Heatmap | Hosts against time |
| Table | Every sample: host, time, value |

The metric names are the ones the monitoring poller records; see
[Metrics collected](monitoring.md#metrics-collected). With a `$host`
variable, the header shows a host list (**All Hosts** or one host) and a
panel whose host is `$host` follows it. The `$group` list (**All Groups**)
only filters panels whose saved query has a group, which the panel dialog
does not set; set it through the API.

There is no drag-and-drop layout: each panel has a width and height on a
12-column grid and the panels fill the grid one after another.

## Rules worth knowing

- **Refresh.** The page loads its data when you open it and does not refresh
  on a timer. Open it again to see new data. The server caches the summary
  for 10 seconds for all users.
- **Polled devices only.** The device panels and the backup **never** state
  count only devices that have a poll.
- **Response time** comes from ICMP when it is available, else from the
  time the poll took. See [Monitoring](monitoring.md).
- **Busiest Interfaces** and **Top Talkers** support 1h to 7d. With **30d**
  selected they show 7 days and say so.
- **Metric resolution.** Custom dashboard panels read raw samples for ranges
  up to 2 hours, hourly rollups up to 2 days, and daily rollups beyond.
- **Custom dashboards are personal.** A non-admin user sees and changes only
  the dashboards they created. An admin sees all of them. Deleting a
  dashboard deletes its panels.
- **Panel data needs `monitoring`.** Custom dashboard panels read
  `/api/metrics/query`, which needs the `monitoring` feature.

## Who can do what

| Action | Needs |
|---|---|
| Open the Dashboard | The `dashboard` feature |
| See integration sources | The `topology` feature |
| See integration entity counts and problems, mute from Active Alerts | The `monitoring` feature (muting needs `monitoring.write`) |
| See Top Talkers | The `traffic-analysis` feature |
| See Backup Status | The `config-backups` feature |
| Add source, most setup steps | Admin |
| Create a custom dashboard | The `dashboard` feature |
| View, change or delete a custom dashboard | Its owner, or an admin |
| See data in custom dashboard panels | The `monitoring` feature |

## API

All routes use the same session and CSRF rules as the rest of the Plexus
API. The full list is in [API reference](api-reference.md).

| Method and path | Purpose |
|---|---|
| `GET /api/dashboard` | The summary: `stats`, `groups`, `device_health`, `open_alerts`, `topology` |
| `GET /api/dashboard/top-interfaces?range=6h&limit=5` | Busiest interfaces with their samples; `range` 1h, 6h, 24h or 7d; `limit` 1-20 |
| `GET /api/annotations?start=&end=&categories=deployment,config,alert` | Events for the feed and chart markers |
| `GET /api/dashboards`, `POST`, `GET/PUT/DELETE /api/dashboards/{id}` | Custom dashboards |
| `POST /api/dashboards/{id}/panels`, `PUT/DELETE /api/dashboards/{id}/panels/{panel_id}` | Panels |
| `GET /api/metrics/query?metric=&host=&range=&step=&group=` | The data of a panel |

Create a dashboard with a host variable and add a panel:

```json
POST /api/dashboards
{
  "name": "Core switches",
  "description": "CPU of the core layer",
  "variables_json": "[{\"name\": \"host\", \"type\": \"host\", \"default\": \"*\"}]"
}
```

```json
POST /api/dashboards/4/panels
{
  "title": "CPU",
  "chart_type": "line",
  "metric_query_json": "{\"metric\": \"cpu_percent\", \"host\": \"$host\", \"group\": \"3\"}",
  "grid_w": 6,
  "grid_h": 4
}
```

Query a metric directly:

```
GET /api/metrics/query?metric=cpu_percent&host=12,13&range=24h
```

```json
{
  "metric": "cpu_percent",
  "step": "hourly",
  "range": "24h",
  "count": 48,
  "data": [
    { "host_id": 12, "hostname": "core-sw-01", "period_start": "2026-11-13 10:00:00", "val_avg": 23.5 }
  ]
}
```
