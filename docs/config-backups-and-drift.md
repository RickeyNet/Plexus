# Configuration Backups and Drift

Plexus keeps a copy of each device's running configuration and tells you
when a device changes in a way you did not plan.

- A **backup** is a stored copy of a device's running configuration. Backup
  policies take backups on a schedule. You can view, compare, download,
  search and restore them.
- **Drift** is a difference between a device's running configuration and
  its **baseline**, the configuration you have approved for that device.
  Each difference Plexus finds is a **drift event** that you accept,
  resolve or revert.

What a device's configuration *should* be, rendered from templates, is a
separate tool: see [Intended configuration](intended-config.md).

## Where it is and what you need

Open **Configuration** in the sidebar. The page has four tabs:

| Tab | What it does | Feature needed |
|---|---|---|
| **Config Drift** | Baselines, snapshots and drift events | `config-drift` |
| **Intended** | [Intended configuration](intended-config.md) | `config-drift` |
| **Backups** | Backup policies and backup history | `config-backups` |
| **Config Search** | Search the text of stored backups | `config-backups` |

You only see the tabs your features allow.

Before you start you need:

- Devices in an inventory group. Plexus reads configurations over SSH; an
  OPNsense firewall is read over the API key of its OPNsense source.
- A credential that can log in to those devices and read the running
  configuration. Restore and revert also need the rights to change the
  configuration.

## One store for every capture

Every time a Plexus feature reads a device's configuration, the result is
stored as a backup. This includes backup policies, drift captures,
compliance scans, risk analysis, deployments, topology collection and
upgrades. The **History** list shows all of them; the method column tells
you which feature took each one.

A capture that is the same as the host's newest backup does not add a new
backup. Plexus marks the newest backup as checked again instead.

Where the platform supports it, Plexus also reads the configuration with
default settings included (`show running-config all`). That form is used
by **Config Search**; views, diffs and restores use the plain form.

## Backups

### Create a backup policy

A policy backs up every host in one inventory group on a fixed interval.
Devices are read over SSH with the policy's credential, except OPNsense
firewalls, which are read over the API key of their OPNsense source (see
[OPNsense firewalls](#opnsense-firewalls)).

1. Open **Configuration > Backups**. **Policies** is selected.
2. Click **New Policy**.
3. Fill in the **Create Backup Policy** dialog:

   | Field | Meaning |
   |---|---|
   | **Policy Name** | Required. |
   | **Inventory Group** | The group to back up. It cannot be changed later. |
   | **Credential** | The SSH login. Admins also see **Service credentials**. **None (API-backed devices only, such as OPNsense)** backs up the group's OPNsense firewalls only; every other host gets an `error` backup that says the policy has no credential. |
   | **Interval (hours)** | 1 to 168. Default 24. |
   | **Retention (days)** | 1 to 365. Default 30. |

4. Click **Create**.

A new policy is enabled. To pause it, open the policy's **⋯** menu, choose
**Edit** and set **Enabled** to **Disabled**.

### Take a backup now

Click **Run Now** on a policy card. Plexus backs up every host in the group
and shows a message such as `Backup complete: 12 saved, 1 errors, 3
unchanged (skipped)`. "Unchanged" hosts had the same configuration as their
newest backup, so no new backup was written. When hosts failed, the message
lists the first five by hostname, each with the reason; every failed host
also gets an `error` entry with that reason under **History**.

### View, compare and download

1. Click **History**. The list shows the newest 100 backups. Type in
   **Search…** to filter by hostname or IP address.
2. Click **View** to open the configuration. The dialog has two views:
   - **Config** shows the stored text, the capture time, method and status.
   - **Diff vs previous** compares it with the previous successful backup
     of the same host. Added lines are counted with `+`, removed lines
     with `-`.
3. In the **⋯** menu, **Download** saves one backup as a `.txt` file.
   **Download All** on the toolbar saves a ZIP file with one `.txt` file
   for each successful backup among the newest 500.

Files are named `hostname_ip_YYYYMMDD_HHMMSS.txt` (time in UTC).

**Device secrets.** A backup is the device's whole configuration: enable
and user passwords, SNMP communities, RADIUS and TACACS+ keys, pre-shared
keys. Who sees them:

- With `config-backups.write` (or as an admin), and write access to the
  device's group when your account is limited to groups, **Config**,
  **Diff vs previous** and **Config Search** show the text as captured, and
  **Download** and **Download All** are available.
- With `config-backups` only, the same views show every secret masked as
  `********` (the masking the AI access tools use, see
  [ai-access.md](ai-access.md)) and say so above the text. A change of a
  secret value alone does not show in the masked diff, since both sides
  read `********`. A search hit that matched only a secret value is left
  out, so a search cannot confirm a guessed value.
  **Download** and **Download All** are disabled (the API answers `403`).
- **Restore** always pushes the stored text as captured; it runs on the
  server and needs `config-backups.write` anyway.

Masking is pattern based: it covers the common vendor forms but cannot
promise to catch a secret in every syntax.

The same rule covers every other page that shows a device's configuration
or lines taken from it: config drift snapshots, baselines and drift diffs,
the revert job's command list, intended-config extra lines and remediation
commands, lab twins cloned from a host (and their runs and drift diffs),
risk analyses, and the drift events listed beside an alert or a deployment.
Without `config-backups.write` and write access to the device you read them
masked. A lab twin cloned by such a user is built from the masked text. A
baseline saved from a masked snapshot stores the captured lines, not the
mask. Intended-config remediation whose commands remove secret lines is
shown masked and is not turned into a deployment for such a user. The
compliance scan snippet and the audit drift evidence are stored masked for
everyone; checks and drift detection still run on the text as captured.

### Search all configurations

Open **Configuration > Config Search**, type the text and choose a
**Mode**:

| Mode | How it matches |
|---|---|
| **Full-text** | Word search. Every word must appear in the configuration. |
| **Substring** | The exact text, ignoring upper and lower case. |
| **Regex** | A regular expression, ignoring case. It must contain at least 3 literal characters. Lookarounds and backreferences are not supported. |

**Limit** sets the number of results (1 to 200, default 50). Each result is
one backup and shows its first matching line with one line before and
after it. **View Backup** and **View Diff** open the backup. The search
covers every successful backup you can see, not only the newest one per
device, so the same device can appear more than once.

### Restore a backup

1. In **History**, open the backup's **⋯** menu and choose **Restore**.
2. In **Restore from Backup**, choose a **Credential for SSH** and click
   **Restore**.

Plexus sends every line of the backup to the device in configuration mode.
It then reads the configuration again and compares it with the backup. The
result is either "Restore validated successfully" or the number of lines
that still differ, with the diff. Plexus does not send `no` commands, so
lines on the device that are not in the backup stay on the device and show
up in that diff. Restore does not save the configuration on the device;
save it yourself if the result is what you want.

### Backup results

| Item | Meaning |
|---|---|
| Status `success` (green) | The configuration was read and stored. |
| Status `error` (red) | The capture failed. The error text shows on the card. |
| Method | Which feature took the backup: `scheduled`, `manual` (**Run Now**), `syslog` (a configuration change message), `drift`, `restore`, `compliance`, `deployment`, `risk-analysis`, `topology`, `upgrade` or `opnsense-api` (an OPNsense firewall's config.xml, read by its topology collection; see [opnsense-topology.md](opnsense-topology.md#config-backup)). A policy's backup of an OPNsense firewall has the policy's method (`scheduled`, `manual`, `syslog`). |
| Summary strip | **Policies**, **Backups**, **Hosts** with a backup, **Last backup**. |

## Drift detection

### How drift is found

1. You set a baseline for a host.
2. A **snapshot** captures the host's running configuration.
3. Plexus compares the newest snapshot with the baseline. Lines that only
   change on their own, such as byte counts, timestamps and the NTP clock
   period, are ignored.
4. If there is any difference, Plexus opens a drift event with the diff.
   If an open event already has the same diff against the same baseline,
   no second event is opened.

A host has at most one baseline. Saving a new baseline replaces the old
one.

### Capture a snapshot

1. Open **Configuration > Config Drift** and click **Capture Snapshot**.
2. Choose a **Single Host** or **Or Entire Group**, and the
   **Credentials**. An OPNsense firewall is never read over SSH: its
   snapshot is its newest config.xml backup, so it needs no credential.
   **None (OPNsense firewalls only)** captures the OPNsense firewalls of
   the choice; any other host fails with a message that it needs a
   credential.
3. Click **Capture**.

A window shows progress for each host. After the capture Plexus runs the
drift comparison and reports how many hosts are compliant, drifted, or
skipped because they have no baseline. A host that has no baseline yet
gets the captured configuration as its baseline.

### Set a baseline yourself

1. Click **Set Baseline**.
2. Choose the **Host** and, if you like, a **Baseline Name**.
3. Paste the configuration into **Intended Configuration**, or click **Use
   Latest Snapshot** to fill it from the host's newest snapshot.
4. Click **Save Baseline**.

### Work with drift events

The list shows events with the status chosen in the filter (**Open**,
**Accepted** or **Resolved**). **Grouped** puts events with the same added
and removed lines together, so one change made on many devices is one
card. **Flat** shows each event on its own. **View Diff** shows the
change.

| Action | Where | What it does |
|---|---|---|
| **Accept** | Card button or **⋯** menu | The change was planned. The event's snapshot becomes the host's new baseline. |
| **Resolve** | **⋯** menu | The device is back in line. The baseline stays as it is. |
| **Revert** | **⋯** menu | Pushes the baseline back to the device. Asks for an **SSH Credential**, then **Revert Device**. |
| **Accept Group (n)** | Group card | Accepts every open event in the group. |
| **Accept All Open (n)** / **Resolve All Open (n)** | Toolbar | Acts on every open event in the current list. Shown when more than one event is open. |
| **Event Log** | **⋯** menu | The event's history: who did what and when. |

**Revert** does not push the whole baseline. Plexus builds commands from
the diff: lines missing from the device are added again, and lines that
are on the device but not in the baseline are removed with `no`. It then
captures the configuration again, compares it with the baseline and marks
the event resolved. A progress window shows each step. The event is marked
resolved even when the device still differs after the push; in that case
the window shows "Warning: device still shows drift after revert." Read
the window before you move on.

### OPNsense firewalls

A host with device type `opnsense` is never read over SSH. A backup policy
whose group holds one downloads its `config.xml` over the API key of the
OPNsense source whose firewall that host is (Plexus knows the pair from the
source's newest collection), with the privilege **Diagnostics:
Configuration History**. This works with or without a policy credential and
with the source's **Config backup** option on or off. The backup is stored
with the policy and the run's method. When it fails, the host gets an
`error` backup that says why: the host is not the firewall of any OPNsense
source yet (collect the source and import the firewall first), the source
has no API key, the firewall refused the download (the privilege is named),
or the answer was not a `config.xml`. The source's own collection, with
**Config backup** on, still stores a backup (method `opnsense-api`)
whenever `config.xml` changed. See
[OPNsense, Config backup](opnsense-topology.md#config-backup).

Its drift snapshot
is its newest config backup (stored by the OPNsense collection), and the
scheduled drift check takes a new snapshot when a newer backup differs.
Snapshots, baselines (a pasted one too) and drift diffs hold the
normalized `config.xml` without its `<revision>` stamp, so a save that
changes nothing is not drift. Every secret (password hashes, API key
secrets, private keys, pre-shared keys, SNMP communities, RADIUS and LDAP
secrets, TSIG keys and more) is shown as `[masked:1a2b3c4d]`: a changed
secret is still drift, its value never appears. **Revert** and **Restore**
are refused for these hosts. The backup view, compare and search mask the
same values. The full list of masked elements is in
[OPNsense, Config drift and masked secrets](opnsense-topology.md#config-drift-and-masked-secrets).

An OPNsense backup is stored encrypted: the backup row holds the masked
`config.xml`, and the file as collected is kept only encrypted with the
Plexus encryption key (`netcontrol.key`). **Download** and **Download
All** (with `config-backups.write`) decrypt it and return the file exactly
as collected. If the key is lost or replaced, the raw file cannot be
decrypted: the download answers `409` and says so (in **Download All**
the backup is left out and named in `NOT-INCLUDED.txt`), while the
masked view, compare, search and drift keep working. Back up
`netcontrol.key` with the database. Backups stored in plain text by an
older release are converted when the server starts.

Backups of other devices (read over SSH) are not encrypted: they are
stored as captured, and a database dump holds their secrets.

A new backup of an OPNsense firewall is also compared with the one before
it for risky rule changes: a rule that became any-to-any or shadowed
raises a monitoring alert. Unlike drift, this compares consecutive
backups, not a baseline, and the alert resolves on its own when a later
backup no longer has the rule that way. See
[Rule change alerts](opnsense-topology.md#rule-change-alerts).

### Drift results

| Item | Meaning |
|---|---|
| `open` (red) | Drift that nobody has handled. |
| `accepted` (amber) | The change was approved and became the baseline. |
| `resolved` (green) | Closed without changing the baseline, or closed by a revert. |
| `+n` / `-n` | Lines on the device that are not in the baseline / lines in the baseline that are missing from the device. |
| Summary strip | **Baselined** hosts, **Compliant** (baselined hosts with no open event), **Drifted** hosts, **Open events**. |

## Rules worth knowing

- **Backup schedule.** Plexus checks for due policies every minute. A
  policy runs when its interval has passed since its last run.
- **One run at a time.** **Run Now** on a policy that is already running
  gives an error.
- **Retention covers all backups.** After a scheduled run, Plexus deletes
  backups older than that policy's retention days for every host, not only
  the policy's own. The newest successful backup of each host is always
  kept. **Run Now** does not delete anything.
- **Deleting a policy** keeps its backups. Deleting the policy's inventory
  group or credential deletes the policy.
- **Policy credentials.** A scheduled run checks that the person who made
  the policy may still use the credential. If not, the policy's SSH hosts
  are skipped and the run counts one error; its OPNsense firewalls are
  still backed up. The edit dialog warns when the saved credential is not
  one you can use. **Run Now** checks that you may use it.
- **No credential.** A policy without a credential backs up OPNsense
  firewalls only; each SSH host of its group gets an `error` backup on
  every run. Choose **None** in the dialog, or send `"credential_id": null`
  to the API, to clear a policy's credential.
- **Drift needs snapshots.** The scheduled drift check compares each
  baselined host's newest snapshot with its baseline. It does not log in to
  devices. New drift is found only after a new snapshot is captured.
- **Drift schedule.** The scheduled check is off by default. When on, it
  runs every hour by default (5 minutes to 24 hours) and deletes snapshots
  and drift events older than 90 days by default (1 to 365), open events
  included. An admin changes this through the API; there is no screen for
  it.
- **Lists.** **History** shows the newest 100 backups and the drift list the
  newest 200 events per status.
- **Deleting a host** deletes its backups, snapshots, baseline and drift
  events.

## Who can do what

| Action | Needs |
|---|---|
| See backups, policies and search results (device secrets masked) | `config-backups` |
| See backups unmasked; download one backup or a ZIP of backups | `config-backups.write` (or admin), and write access to the device's group |
| Create, change, run or delete a policy; delete or restore a backup | `config-backups.write`, and a credential you may use |
| See baselines, snapshots and drift events | `config-drift` |
| Set baselines, capture snapshots, accept, resolve or revert drift | `config-drift`, and a credential you may use for captures and reverts |
| Change the drift check schedule or run it now | Admin |

A user limited to selected inventory groups sees only the hosts and
policies of those groups. Changes, runs, captures, restores and reverts
also need write access to the group. See [Object
permissions](object-permissions.md).

Changes are written to the [audit log](audit-log.md) under the
`config-backups` and `config-drift` categories.

## API

All routes use the same session and CSRF rules as the rest of the Plexus
API; see the [API reference](api-reference.md). Examples use invented
data.

```
GET    /api/config-backups/policies
POST   /api/config-backups/policies
PUT    /api/config-backups/policies/{id}
DELETE /api/config-backups/policies/{id}
POST   /api/config-backups/policies/{id}/run-now
GET    /api/config-backups?host_id=&policy_id=&status=&limit=
GET    /api/config-backups/{id}
GET    /api/config-backups/{id}/diff
GET    /api/config-backups/{id}/download
GET    /api/config-backups/download?host_id=&policy_id=&limit=
GET    /api/config-backups/search?q=&mode=&limit=&context_lines=
POST   /api/config-backups/restore
```

`interval_seconds` is kept between 3600 and 604800 and `retention_days`
between 1 and 365; a value outside is moved to the nearest bound.

```json
POST /api/config-backups/policies
{ "name": "Branch daily", "group_id": 4, "credential_id": 2, "interval_seconds": 86400, "retention_days": 30 }
```

`credential_id` is optional. Left out or `null`, the policy backs up
OPNsense firewalls only. On `PUT`, leaving it out keeps the credential and
`null` clears it:

```json
PUT /api/config-backups/policies/8
{ "credential_id": null }
```

```json
POST /api/config-backups/policies/7/run-now
{
  "ok": true, "backed_up": 12, "skipped": 3, "errors": 1,
  "failures": [
    { "host_id": 31, "hostname": "fw-branch-1", "ip_address": "192.0.2.21",
      "error": "This host is not the firewall of any OPNsense source: collect its OPNsense source (Map sources) and import the firewall into the inventory first, then run the policy again" }
  ]
}
```

`failures` names the hosts that failed, by hostname, each with the reason
stored on its `error` backup; at most 25, while `errors` counts them all.

Drift:

```
GET    /api/config-drift/baselines[?host_id=]
POST   /api/config-drift/baselines
POST   /api/config-drift/snapshots/capture-job          {"group_id", "credential_id"}
POST   /api/config-drift/snapshots/capture-single-job   {"host_id", "credential_id"}
POST   /api/config-drift/check                          {"host_id", "credential_id"}
       (capture and check: credential_id optional; left out or null, only
        OPNsense firewalls are captured, any other host answers 400)
GET    /api/config-drift/events?status=open&host_id=&limit=
PUT    /api/config-drift/events/{id}/status             {"status": "accepted"}
POST   /api/config-drift/events/bulk-accept             {"event_ids": [..]}
POST   /api/config-drift/events/bulk-resolve            {"event_ids": [..]}
POST   /api/config-drift/events/revert                  {"event_id", "credential_id"}
GET    /api/config-drift/summary
GET    /api/admin/config-drift
PUT    /api/admin/config-drift
POST   /api/admin/config-drift/run-now
```

`POST /api/config-drift/check` captures one host and compares it at once:

```json
{ "drifted": true, "event_id": 51, "diff_summary": "+2 -1 lines changed", "snapshot_id": 230, "host_id": 9, "hostname": "edge-rtr-01" }
```

Turn on the scheduled drift check:

```json
PUT /api/admin/config-drift
{ "enabled": true, "interval_seconds": 3600, "snapshot_retention_days": 90 }
```

Capture and revert jobs stream their output on `/ws/config-capture/{job_id}`
and `/ws/config-revert/{job_id}`.
