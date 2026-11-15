# Reports

The Reports page turns data Plexus already collects into tables you can
read on screen and download. It has three tabs:

- **Generate** runs a report now: availability, compliance, interface
  utilization or network documentation.
- **History** lists past report runs and their downloads.
- **Bandwidth Billing** computes 95th-percentile bandwidth figures per
  circuit for invoicing.

Network documentation reports have their own guide:
[network-documentation-usage.md](network-documentation-usage.md). This page
covers what is common to all reports and the other report types.

## Before you start

- You need the **Reports** feature. See [Who can do what](#who-can-do-what).
- Reports only read stored data. An availability report needs monitoring
  polls, an interface report needs interface counters, a compliance report
  needs compliance scans, and billing needs interface counters for the
  circuit's interface. If that data is missing, the report has no rows or
  shows zeros.

## Generating a report

1. Open **Reports** and stay on the **Generate** tab.
2. Choose a **Report Type**.
3. Choose a **Group**, or keep **All Groups**.
4. For **Availability** and **Interface Utilization**, set **Days** (the
   look-back window; default 30). Compliance and network documentation have
   no **Days** field.
5. Choose **Generate**.

The result shows "N rows · Run #ID" and a table with the first 200 rows.
To get all rows, choose **Export** and then **CSV**. For network
documentation the menu also offers **SVG**, **draw.io** and **PDF**.

A report with no data says "Report generated with 0 rows. No data found for
the selected criteria." and offers no download.

## Report types

| Report Type | One row per | Columns |
|---|---|---|
| **Availability** | Host in the scope | host id, hostname, IP address, platform (`device_type`), group, total polls, OK polls, `uptime_pct`, average and maximum latency (ms), average packet loss, average CPU, average memory, `outage_count` |
| **Compliance** | Stored compliance scan result | host id, hostname, IP address, platform, group, profile id and name, status, total, passed and failed rules, scan time |
| **Interface Utilization** | Interface that has samples in the window | hostname, IP address, interface index, name and speed (Mbps), samples, average and peak in/out (bps), average and peak utilization (%) |
| **Network Documentation** | Section entry | See [network-documentation-usage.md](network-documentation-usage.md) |

What the numbers mean:

- **`uptime_pct`** is OK polls divided by all polls in the window, times 100.
  A host with no polls in the window shows `0`.
- **`outage_count`** counts transitions of the host to `down` in the window.
- **Compliance** rows are every stored scan result for the hosts in scope,
  newest first, not only the latest scan per host.
- **Interface Utilization** uses the interface time-series counters.

## History

The **History** tab lists the 50 most recent report runs, from the
**Generate** tab, from schedules and from the API.

| Column | Meaning |
|---|---|
| **ID** | Run number. |
| **Type** | Report type. |
| **Status** | `running` while it runs, then `completed` or `error`. |
| **Rows** | Number of rows. |
| **Started** | Start time. |
| **Actions** | **CSV** and **Artifacts**, for completed runs only. |

**CSV** downloads the run's stored CSV file, or builds one from the stored
rows when the run kept no files. **Artifacts** lists the files the run kept,
each with a **Download** button. A run from the **Generate** tab keeps files
only for network documentation; other types show "No persisted artifacts
found for this run."

The History tab has no delete button.

## Scheduling a report

The web UI has no schedule editor. Create a report definition with a
schedule through the API (`POST /api/reports`, see [API](#api)). The
schedule text uses the same grammar as network documentation schedules,
described in
[network-documentation-usage.md](network-documentation-usage.md#api-scheduling);
the `@hourly`, `@daily`, `@weekly` and `@monthly` forms work as well.

A background task checks once a minute for definitions whose interval has
passed since their last run. A scheduled run always keeps files:

| Report type | Files kept |
|---|---|
| Any | CSV |
| `ipam_utilization`, `ipam_forecast` | CSV and PDF |
| `network_documentation` | CSV, SVG, draw.io and PDF |

Scheduled runs appear on the **History** tab like any other run. A
definition with an empty schedule or `off`, `none`, `disabled` or `manual`
never runs by itself.

## Bandwidth billing

Billing works on circuits. A circuit is one interface on one device, with a
commit rate and a price.

### Creating a circuit

1. Open the **Bandwidth Billing** tab and choose **+ New Circuit**.
2. Fill in **Circuit Name**, **Customer**, **Device** and **Interface
   Index** (the SNMP ifIndex). **Interface Name** is a label only.
3. Set **Commit Rate (bps)**, **Cost per Mbps**, **Currency**, **Billing
   Day** (1 to 28) and **Billing Cycle** (**Monthly** or **Weekly**).
   **Burst Limit (bps)** is stored but not used in the calculation.
4. Choose **Create**. The device and interface index cannot be changed
   later; the **Edit Billing Circuit** dialog says so. **Edit** can turn a circuit off with **Enabled**.

### Generating billing periods

1. Choose **Generate Billing**.
2. Pick one **Circuit**, or leave **All enabled circuits**.
3. Set **Period Start** and **Period End**, or leave both blank to use the
   most recent completed cycle. A single date is ignored.
4. Choose **Generate**. A message says how many periods were made and how
   many have an overage.

### How the figures are computed

- Plexus takes every in and out rate sample of the interface in the period.
  It sorts each list and drops the top 5%; the highest remaining value is the
  95th percentile (**P95 In**, **P95 Out**).
- **P95 Billing** is the higher of the two.
- **Overage** is P95 Billing minus the commit rate, when a commit rate is
  set. **Cost** is the overage in Mbps times **Cost per Mbps**. Plexus does
  not compute the base price of the commit.
- **Status** is `overage` (red) when P95 Billing is above the commit rate,
  otherwise `generated` (green).
- **View** opens **Billing Period Detail** with the sample count, the P95
  figures, the commit rate and a chart of inbound and outbound Mbps.

The cards at the top show **Total Circuits**, **Enabled**, **Billing
Periods**, **Overages** and **Total Overage Cost**. The **Customer** filter
narrows the circuits, the periods and the cards.

## Rules worth knowing

- **Run retention.** Report runs older than 120 days are deleted with their
  files. The server setting `APP_REPORT_RUN_RETENTION_DAYS` changes this (at
  least 7). The cleanup only runs after a scheduler cycle that ran at least
  one scheduled report.
- **Scheduler limits.** At most 10 due definitions run per cycle
  (`APP_REPORT_SCHEDULER_MAX_RUNS_PER_CYCLE`, 1 to 50).
  `APP_REPORT_SCHEDULER_ENABLED=false` turns schedules off.
- **Billing data age.** Billing reads the interface time-series counters,
  which Monitoring keeps for 30 days by default
  ([DATA_RETENTION.md](../DATA_RETENTION.md)). A period older than that has
  few or no samples.
- **Weekly cycles** end at the most recent Monday 00:00 UTC and start seven
  days before. **Monthly cycles** run from billing day to billing day.
- **Deleting a circuit** deletes all of its billing periods.
- **Cost column currency.** The periods table and the cards show the cost
  with a `$` sign whatever **Currency** says.
- **Audit.** Circuit changes and billing generation are written to the
  audit log under category `billing`. Report generation is not audited.

## Who can do what

| Action | Needs |
|---|---|
| Generate reports, see History, download CSV and files | The `reports` feature |
| Create or delete a scheduled report definition (API) | The `reports` feature |
| See billing circuits, periods and cards | The `reports` feature |
| Create, edit or delete a circuit, generate billing | Admin. These need `reports.write`, which an access group cannot grant because Reports is a read-only feature |

## API

All routes need the `reports` feature, a session with CSRF token on writes,
or the server API token. See [api-reference.md](api-reference.md) for the
general rules.

```
POST   /api/reports/generate
GET    /api/reports/runs[?report_id=&limit=]
GET    /api/reports/runs/{run_id}
GET    /api/reports/runs/{run_id}/csv
GET    /api/reports/runs/{run_id}/artifacts
GET    /api/reports/artifacts/{artifact_id}
GET    /api/reports
POST   /api/reports
DELETE /api/reports/{report_id}
GET    /api/reports/export/{availability|compliance|interface}[?group_id=&days=]
```

`GET`, `POST` and `DELETE /api/reports` manage scheduled report
definitions.

```json
POST /api/reports/generate
{
  "report_type": "availability",
  "parameters": { "group_id": 4, "days": 7 },
  "persist_artifacts": true
}
```

The answer has `run_id`, `report_type`, `row_count`, `artifact_count`,
`artifacts` and `rows`. An unknown `report_type` gives `400`.

The API also knows three IPAM types that the UI does not list:
`ipam_utilization` (`vrf_name`, `threshold_pct`), `ipam_forecast`
(`vrf_name`, `lookback_days`, `target_pct`, `min_points`) and `ipam_history`
(`address`, `hostname`, `vrf_name`, `days`, `limit`). Each also has a direct
export under `/api/reports/export/`.

Billing routes are under `/api/billing/`: `circuits`, `customers`,
`summary`, `periods`, `periods/{id}`, `periods/{id}/usage` and
`POST /api/billing/generate`:

```json
POST /api/billing/generate
{ "circuit_id": 2, "period_start": "2026-10-01T00:00:00Z", "period_end": "2026-11-01T00:00:00Z" }
```

The answer is `{"periods": [...], "count": 1}`. A disabled circuit gives
`400`, an unknown one `404`. The UI has no billing download;
`GET /api/billing/export/periods[?customer=&circuit_id=&limit=]` returns
the periods as `billing_report.csv` (default 500 rows, at most 10,000).
