# Running jobs

A job runs one automation task against a set of devices and records what
happened. You use jobs for audits, configuration pushes and fixes. Every job
can run first as a dry run, which shows what the task would do without
changing the devices, and then live.

The terms used here (playbook, template, credential, job) are defined in
[Core concepts](core-concepts.md). How to write a playbook is in
[Writing playbooks](writing-playbooks.md). This guide shows how to manage
them and run them from the UI.

## Where it is

Open **Change > Delegator**. The page has four tabs. The UI uses its own
names for the core objects:

| Tab | What it holds | Core concept | Feature you need |
|---|---|---|---|
| **Assignments** | Jobs: launch, watch and history | Job | `jobs` |
| **Tasks** | Python and Ansible automation scripts | Playbook | `playbooks` |
| **Instructions** | Blocks of CLI commands a task pushes | Template | `templates` |
| **Credentials** | Device logins and secret variables | Credential | `credentials` |

You only see the tabs whose feature you have. Before you launch a job you
need:

- at least one task on the **Tasks** tab,
- a credential of your own on the **Credentials** tab, or a **Default
  Credential** set under **Settings > Authentication**,
- the target devices in the inventory, or their IP addresses,
- an instruction set, if the task pushes one.

## Managing tasks

On the **Tasks** tab, choose **+ New Task**.

| Field | Meaning |
|---|---|
| Type | **Python (Netmiko)** or **Ansible (YAML)**. It cannot be changed after the task is created. |
| Name | The name shown in lists and in the launch dialog. |
| Filename | Letters, digits, `_` and `-`. Plexus adds `.py` (Python) or `.yml` (Ansible). |
| Description | Free text. |
| Tags (comma-separated) | Labels you can search on. |
| Python Code / Ansible YAML | The script, in a code editor. A new task starts from an example. |

Choose **Create**. Use **Edit** to change a task and the delete button to
remove it. The search box filters by name, description, filename and tag.

## Managing instruction sets

On the **Instructions** tab, choose **+ New Instruction Set** and fill in
**Name**, **Description**, **Vendor** and **Config Content**. **Vendor** is
**Generic (all vendors)** or one platform. Two instruction sets with the same
name and different vendors are variants of one set: a job sends each host the
variant for its platform and falls back to the generic one. See
[Core concepts](core-concepts.md#templates).

Use **Expand** to see a long body and the copy button to copy it. Blank lines
and lines that start with `#` are not sent to devices.

## Managing credentials and secrets

On the **Credentials** tab there are two sub-tabs.

**Credentials:** choose **+ New Credential** and enter **Name**,
**Username**, **Password** and **Secret (Enable Password)**. If **Secret**
is empty, the password is also used as the enable secret. When you edit a
credential, leave **Password** or **Secret** blank to keep the stored value.

**Secret Variables:** choose **+ New Secret** and enter **Name**, **Value**
and **Description (optional)**. An instruction set uses the value with
`{{secret.NAME}}`. The name may use letters, digits, `_` and `-`, starts with
a letter or `_`, and is at most 64 characters. If you paste the full
`{{secret.NAME}}` reference, Plexus keeps only the name. The value is stored
encrypted and never shown again; **Edit** lets you replace it.

## Launching a job

1. On the **Assignments** tab, choose **+ Launch Job**.
2. **Task:** pick the task. Ansible tasks show `[Ansible]` after the name.
3. **Select Targets:** tick a group to select all its hosts, or tick single
   hosts. The search box filters groups and hosts by name, address and
   platform. The counter shows how many hosts are selected; **Clear**
   empties the selection.
4. **Ad-Hoc IP Addresses:** add devices that are not in the inventory, one
   per line or separated by commas (for example `192.0.2.50, 198.51.100.7`).
   They run as `cisco_ios`.
5. **Credential (optional):** pick one of your credentials. **None** uses
   the **Default Credential** from **Settings > Authentication**.
6. **Instructions (optional):** pick an instruction set if the task needs
   one. This field is hidden for Ansible tasks.
7. **Task Parameters:** if the task declares parameters, fill them in. A
   red `*` marks a required one.
8. **Priority:** **Low**, **Below Normal**, **Normal** (default), **High**
   or **Critical**.
9. **Depends On (Job IDs):** optional job numbers, for example `12, 15`.
10. **Dry Run (simulation):** ticked by default.
11. Choose **Launch**.

If **Dry Run (simulation)** is not ticked, Plexus asks you to confirm with
**Launch live**, because the job changes the devices. After launch the job
output opens.

## Watching a job

**View Output** on a job row opens the job window. It shows a **Dry run** or
**Live** badge, the status, and the log. While the job is queued or running
the log streams in and the window shows **Streaming**. An early log line
states the mode (`DRY-RUN` or `LIVE MODE`). When the job ends a `[Job Complete]` line appears. For the
stream protocol see [WebSocket usage](websocket-usage.md).

The buttons at the bottom of the window:

| Button | Shown when | What it does |
|---|---|---|
| **Copy Output** | There is output | Copies the log as text. |
| **Cancel Job** | Queued or running | Stops the job after you confirm. |
| **Retry** | Failed or cancelled | Starts a new job with the same task, targets, credential, instructions, parameters, priority and mode. Dependencies are not copied. |
| **Run Live** | A finished dry run | Starts the same new job as **Retry**, but live, after you confirm. |

The job row has **Cancel** and **Retry** buttons too.

## Reading the job list

Each row shows the task name, the inventory group, the start (or queue)
time, the status, `DRY RUN` for a dry run, and who launched it. A priority
badge appears when the priority is not Normal, and a `deps:` badge lists
the jobs it waits for.

| Status | Colour | Meaning |
|---|---|---|
| `queued` | Grey | Waiting for a free slot or for its dependencies. |
| `running` | Blue, with a live dot | Running now. |
| `success` | Green | Finished without the failures below. |
| `failed` | Red | A Python task raised an error or every host that reported failed. An Ansible task failed on any host. Or setup failed: no credential, a missing secret, no hosts. |
| `cancelled` | Grey | Stopped by a user. |

When jobs are queued or running, a **Queue** panel above the list shows
running jobs against the limit (for example `2/4 running`) and the queued
jobs with their priority.

Filters: the search box (task, group, status), the status list, **Dry+Live**
/ **Dry Run only** / **Live only**, and **All time**, **Today**, **Last 7
days** or **Last 30 days**.

## Rules worth knowing

- **Concurrency.** At most 4 jobs run at once. The server setting
  `APP_MAX_CONCURRENT_JOBS` changes this. Waiting jobs start by priority,
  then by queue time.
- **Dependencies.** A job with **Depends On** waits until every listed job
  has status `success`. If one fails or is cancelled, the job stays queued
  until you cancel it. While it waits at the front of the queue, the jobs
  behind it wait too.
- **Credentials are personal.** Each user sees and uses only the
  credentials they created; admins too. The default credential works only
  for the user who owns it.
- **Checks at launch.** Launch fails if no credential is available, if an
  instruction set uses a `{{secret.NAME}}` that does not exist, or if an
  ad-hoc address is invalid or reserved (loopback, link-local, multicast,
  broadcast, `0.0.0.0/8`).
- **Secrets in logs.** Secret values are removed from Python task output
  before it is stored.
- **After a live job.** When a live job succeeds, Plexus waits 15 seconds and
  re-polls the inventory hosts by SNMP if SNMP discovery is on for their
  group.
- **Server restart.** A job that was running when the server stopped is
  marked `failed` at the next start. It is not run again.
- **List size.** The list shows the 100 newest jobs. **Load older jobs**
  adds 100 more, up to 200. Search and filters cover only the loaded jobs.
- **Other users' jobs.** Everyone with the `jobs` feature sees all jobs in
  the list, but only the user who launched a job, or an admin, can open its
  output, cancel, retry or run it live.
- **Deleting a task.** A Python task whose file is still installed comes
  back the next time the task list loads.
- **No scheduling.** Jobs start when you launch them. There is no job
  schedule.
- **Retention.** Finished jobs (`success`, `failed`, `cancelled`) older
  than the retention period are deleted. The default and minimum is 30
  days. An admin sets it under **Settings > System > Job history**. The
  cleanup runs at startup and every 6 hours.

## Who can do what

| Action | Needs |
|---|---|
| See the job list, launch a Python task | `jobs` feature, plus `playbooks` to load the task list |
| Launch an Ansible task | Admin |
| Open output, cancel, retry, run live | The user who launched the job, or an admin |
| Create, edit and delete tasks | `playbooks` feature |
| Create, edit and delete instruction sets | `templates` feature |
| Manage your own credentials | `credentials` feature |
| Manage secret variables | Admin |
| Set job retention and the default credential | Admin |

Job actions are written to the audit log under `jobs`. Task, instruction set
and credential changes are written under `config`. See
[Audit log](audit-log.md).

## API

All routes follow the usual session and CSRF rules. The full list is in
[API reference](api-reference.md#jobs).

```
GET    /api/jobs?limit=100            (limit 1 to 200)
GET    /api/jobs/queue
GET    /api/jobs/{id}
GET    /api/jobs/{id}/events          (limit up to 100000)
POST   /api/jobs/launch
POST   /api/jobs/{id}/cancel
POST   /api/jobs/{id}/retry
POST   /api/jobs/{id}/rerun           (same job, live)
PATCH  /api/jobs/{id}/priority        (queued jobs only)
WS     /ws/jobs/{id}
```

Launch a dry run on two inventory hosts and one ad-hoc address:

```json
POST /api/jobs/launch
{
  "playbook_id": 3,
  "host_ids": [42, 43],
  "ad_hoc_ips": ["192.0.2.50"],
  "credential_id": 5,
  "template_id": 2,
  "dry_run": true,
  "priority": 3,
  "depends_on": [118],
  "parameters": { "vlan_id": 120 }
}
```

```json
{ "job_id": 121, "status": "queued" }
```

Give `host_ids`, `ad_hoc_ips` or `inventory_group_id` (a whole group).
`dry_run` defaults to `true` and `priority` to `2`; priority is clamped to 0
to 4. Unknown fields give `422`. A missing required parameter gives `400`.
