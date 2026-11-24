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

Open **Change > Delegator**. The page has five tabs. The UI uses its own
names for the core objects:

| Tab | What it holds | Core concept | Feature you need |
|---|---|---|---|
| **Assignments** | Jobs: launch, watch and history | Job | `jobs` |
| **Approvals** | Jobs waiting for your approval | Job | `jobs.approve` |
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

On the **Tasks** tab, an admin chooses **+ New Task**. Creating and deleting
tasks, and changing a task's code or filename, are admin only: a Python task
runs inside the Plexus server and an Ansible task on the Plexus host. A user
with the `playbooks` Modify permission can edit a task's name, description,
tags and run inputs. Plexus never saves a task over the file of a built-in
task or of another task; save a changed copy under a new filename.

| Field | Meaning |
|---|---|
| Type | **Python (Netmiko)** or **Ansible (YAML)**. It cannot be changed after the task is created. |
| Name | The name shown in lists and in the launch dialog. |
| Filename | Letters, digits, `_` and `-`. Plexus adds `.py` (Python) or `.yml` (Ansible). |
| Description | Free text. |
| Tags (comma-separated) | Labels you can search on. |
| Python Code / Ansible YAML | The script, in a code editor. A new task starts from an example. |
| Run inputs | The typed fields the launch dialog asks for. See [Run inputs](#run-inputs). |
| Who may run / Who may commit changes | Admins only. See [Run and commit permissions](#run-and-commit-permissions). |
| Require approval before jobs run | Admins only to change. See [Approvals](#approvals). |

Choose **Create**. Use **Edit** to change a task and the delete button to
remove it. The search box filters by name, description, filename and tag.

### Run inputs

A task can declare inputs: typed fields the launch dialog shows, checks and
passes to the run. Choose **Add field** under **Run inputs** and fill in:

| Setting | Meaning |
|---|---|
| Name | The variable name the task reads: letters, digits and `_`, starting with a letter or `_`. |
| Label | The text shown next to the field. Defaults to the name. |
| Type | One of the types below. |
| Help text | A line shown under the field. |
| Default | The value used when the field is left empty. Not available for host and group fields. |
| Choices | Choice and multiple choice fields: the allowed values, comma-separated. |
| Min / Max | Whole numbers: the value. One-line and multi-line text: the length. Multiple choice and lists: the number of items. |
| Pattern | One-line and multi-line text: a regular expression the whole value must match, checked by the server only. Patterns run on RE2, so they match in linear time; lookarounds and backreferences are refused. |
| Required | The field must have a value (or a default). |

| Type | Control | The task receives |
|---|---|---|
| Text (one line) | Text box, at most 1000 characters | The text, trimmed |
| Text (multi-line) | Text area, at most 20000 characters | The text |
| Whole number | Number box | A number |
| Yes / no | Checkbox | `true` or `false` |
| Choice | List | The chosen value |
| Multiple choice | Checkboxes | A list of the ticked values |
| List (comma-separated) | Text box | A list of the items |
| IP address | Text box, for example `192.0.2.10` | The address |
| Prefix (CIDR) | Text box, for example `192.0.2.0/24` | The prefix |
| Inventory host | List of inventory hosts | `{id, hostname, ip_address, device_type}` |
| Inventory group | List of inventory groups | `{id, name}` |
| Secret variable | List of secret variables (admins), or the name typed | The secret's value, at run time only |

Use **Move up**, **Move down** and **Remove field** to arrange the fields.
A field is checked when you leave it, and again by the server when you
launch; a bad value gives a message under the field and the job is not
queued.

A Python task can also declare its inputs in code (`parameters_schema`, see
[Writing playbooks](writing-playbooks.md#run-inputs-and-dry-run)). The built-in
**Enable NetFlow Export** task does. Its fields show under **Run inputs**
with a note; a change you save there overrides the code, and removing every
field goes back to the code version.

A secret input stores only the reference (`{{secret.NAME}}`) on the job. The
value is decrypted when the job starts and removed from the job log. A
secret reference typed into any other field is refused.

### Run and commit permissions

By default everyone with the `jobs` feature can run a task and commit its
changes. An admin can limit this on the task form:

- **Who may run**: tick **Every user (role: user)** or one or more access
  groups. Only those users can launch the task at all.
- **Who may commit changes**: the same choices. Users who may run but not
  commit can only launch a dry run. Nothing ticked means the same people who
  may run.

Admins and API token callers are always allowed. The launch dialog greys out
**Run and commit** for a user who may not commit. **Retry** of a live job
and **Run Live** count as a commit. The check is made by the server when the
job is launched; a refused launch answers `403`.

### Approvals

An admin can tick **Require approval before jobs run** on a task. Every job
from that task (launched, retried, run live, or started from a ChatOps
preset) then starts in status `pending_approval` instead of `queued`. The
queue never starts it. The task list shows an **Approval required** badge.

A user with the `jobs.approve` permission (an access group grants it; admins
always have it) opens the **Approvals** tab. It lists the jobs waiting for
them, oldest first, with the task, targets, mode (dry run or commit), inputs
and requester. Type an optional comment and choose:

- **Approve**: the job moves to `queued` and runs like any other job.
- **Deny**: after you confirm, the job ends as `denied` and never runs. The
  requester can **Retry** it, which asks for approval again.

Nobody can approve or deny a job they launched, admins included (the same
four-eyes rule as [deployments](deployments.md)). Your own jobs, and jobs
with a target outside your object scope, are not listed. The decision, who
made it, when and the comment are kept on the job, shown in the job window
and written to the job log and the audit log (`job.approved`,
`job.approval_denied`). A job waiting for approval can be cancelled by its
requester or an admin. No notification is sent; check the **Approvals** tab.

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
Each field has a **Show** button to check what you typed.

**External reference:** when a secrets provider is set up (HashiCorp Vault,
AWS Secrets Manager or Azure Key Vault), a credential or secret variable can
choose **External reference** instead of **Stored in Plexus** and name the
provider, the path and the key; Plexus reads the value from the store each
time it is used and keeps only the reference. Non-admin users see only the
providers an admin opened to personal credentials. See
[Secrets providers](secrets-providers.md).

**Secret Variables:** choose **+ New Secret** and enter **Name**, **Value**
and **Description (optional)**. An instruction set uses the value with
`{{secret.NAME}}`. The name may use letters, digits, `_` and `-`, starts with
a letter or `_`, and is at most 64 characters. If you paste the full
`{{secret.NAME}}` reference, Plexus keeps only the name. The value is stored
encrypted and never shown again; **Edit** lets you replace it.

### Who may use a secret variable

**Usable by** on the create and edit form limits whose jobs may have the
secret resolved. Tick **Admins only** to keep it to admins, or tick one or
more access groups to add their members; nothing ticked (the default) lets
every user who can run the job use it, and so does **Every user (role:
user)**. The list shows each secret's rule under **Usable by**.

- Admins and the server API token may always use every secret.
- A user the rule does not allow gets the same answer as for a secret that
  does not exist: launch, retry and **Run Live** are refused with "a
  secret variable that does not exist or that it may not use", and a
  secret input reads "the secret variable does not exist or this job may
  not use it". Neither names the secret.
- The rule is checked against the person who launched the job again when
  the job leaves the queue (jobs from ChatOps presets and approved jobs
  too). If an admin tightened the rule, or the launcher lost the role or
  access group, since launch, the job fails before it signs in, with the
  same message and no secret name in the job log. The server log names
  the secret for admins.
- A job launched with the server API token is stored as launched by
  `admin`; at the queue it counts as an admin only while an account named
  `admin` exists and is an admin, as for the other queue checks.
- Text that names a secret is checked against the user who saves it too:
  a template or device-type variant, a secret input's default, or a
  group's SNMP discovery profile that references a secret its saver may not
  use is refused (403). A job resolves these for whoever runs it, and an
  admin passes every rule, so the author must be allowed as well. As at
  launch, a name that does not exist reads the same as one the saver may
  not use; admins may name a secret that is yet to be created. Saving a
  playbook's input fields again unchanged, or keeping a group SNMP key as
  stored, is not checked again.
- Admin SNMPv3 profiles that reference a secret variable are admin settings
  and polling is not a user's job: the rule does not apply when they are
  used.

### Secret variables and ad-hoc targets

A job sends the value of every secret variable its instruction set (any
device-type variant) or its secret inputs use to each target. An ad-hoc
address can be any device, including one the person launching the job
controls, so:

- An admin (or the server API token) may send secrets to any target.
- Anyone else may send secrets only to inventory hosts they may change
  whose address an admin set or confirmed. An ad-hoc address counts when
  it is the address of such a host. Any other ad-hoc address is refused
  with `403` and the message names the address. Add the device to the
  inventory (and have an admin confirm its address), drop the secret from
  the instruction set, or ask an admin to run the job.
- An inventory host whose address a non-admin added or changed shows
  **Awaiting admin confirmation** on the Inventory page. A job of a
  non-admin that would send secrets to it fails when it leaves the queue,
  naming the address.
- The check runs at launch, retry and **Run Live**, and again when the job
  leaves the queue: a job whose launcher is no longer an admin, or whose
  address is no longer an inventory host, fails before it signs in.
- The refusal comes before any secret is looked up, so it is the same
  whether the secret exists. A secret that does not exist is reported as
  "a secret variable that does not exist or that it may not use", without
  its name. Admins see the names in the server log.

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
7. **Task Inputs:** if the task declares [run inputs](#run-inputs), fill
   them in. A `*` marks a required one. A field is checked when you leave it.
8. **Priority:** **Low**, **Below Normal**, **Normal** (default), **High**
   or **Critical**.
9. **Depends On (Job IDs):** optional job numbers, for example `12, 15`.
10. Choose **Run dry-run** to preview the changes, or **Run and commit** to
    make them.

**Run dry-run** is the default (Enter in the form does the same). It runs
Python tasks with `dry_run` set and Ansible tasks with `--check --diff`.
**Run and commit** asks you to confirm first, because the job changes the
devices. A task whose code cannot preview (`supports_dry_run = False`) shows
only **Run and commit**, with a warning. After launch the job output opens.

## Watching a job

**View Output** on a job row opens the job window. It shows a **Dry run** or
**Commit** badge, the status, the job's inputs (secret inputs by name only)
and the log. While the job is queued or running
the log streams in and the window shows **Streaming**. An early log line
states the mode (`DRY-RUN` or `LIVE MODE`). When the job ends a `[Job Complete]` line appears. For the
stream protocol see [WebSocket usage](websocket-usage.md).

The buttons at the bottom of the window:

| Button | Shown when | What it does |
|---|---|---|
| **Copy Output** | There is output | Copies the log as text. |
| **Cancel Job** | Awaiting approval, queued or running | Stops the job after you confirm. |
| **Retry** | Failed, cancelled or denied | Starts a new job with the same task, targets, credential, instructions, inputs, priority and mode. Dependencies are not copied. A task that requires approval asks for it again. |
| **Run Live** | A finished dry run | Starts the same new job as **Retry**, but live, after you confirm. |

The job row has **Cancel** and **Retry** buttons too. A job that needed
approval shows an **Approval** block: waiting, or who approved or denied it,
when, and the comment.

## Reading the job list

Each row shows the task name, the inventory group, the start (or queue)
time, the status, `DRY RUN` or `COMMIT` for the mode, and who launched it. A priority
badge appears when the priority is not Normal, and a `deps:` badge lists
the jobs it waits for.

| Status | Colour | Meaning |
|---|---|---|
| `pending_approval` | Amber | Waiting for approval (see [Approvals](#approvals)). It does not run until approved. |
| `queued` | Grey | Waiting for a free slot or for its dependencies. |
| `running` | Blue, with a live dot | Running now. |
| `success` | Green | Finished without the failures below. |
| `failed` | Red | A Python task raised an error or every host that reported failed. An Ansible task failed on any host. Or setup failed: no credential, a missing secret, no hosts. |
| `cancelled` | Grey | Stopped by a user. |
| `denied` | Red | Its approval was denied. It never ran. |

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
  instruction set uses a `{{secret.NAME}}` that does not exist, if an
  ad-hoc address is invalid or reserved (loopback, link-local, multicast,
  broadcast, `0.0.0.0/8`), if a non-admin sends secrets to an ad-hoc
  address (see [Secret variables and ad-hoc
  targets](#secret-variables-and-ad-hoc-targets)), if a run input is not
  valid (or names a host, group or secret that does not exist), if a
  secret's **Usable by** rule does not include you (see [Who may use a
  secret variable](#who-may-use-a-secret-variable)), or if the task's
  permissions refuse you.
- **Secrets in logs.** Secret values (from instruction sets and secret
  inputs) and the job credential's password and enable secret are removed
  from Python and Ansible task output before it is stored, in any letter
  case, together with their base64 (standard and URL-safe, with or
  without `=` padding), URL-encoded, hex and JSON- or backslash-escaped
  forms; each line of a multi-line value is removed on its own. A value
  split across two output events is removed too: an event that ends in the
  first characters of a value has them held back until the next event (or
  the end of the job). Values shorter than 4 characters are not removed
  (masking them would blank common text all over the log). This is best
  effort: a value the device changes in another way (wrapped, hashed, part
  of a longer encoded blob) is not recognized, so do not echo secrets back
  in commands.
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
- **Retention.** Finished jobs (`success`, `failed`, `cancelled`, `denied`) older
  than the retention period are deleted. The default and minimum is 30
  days. An admin sets it under **Settings > System > Job history**. The
  cleanup runs at startup and every 6 hours.

## Who can do what

| Action | Needs |
|---|---|
| See the job list and job output | `jobs` feature (View), plus `playbooks` to load the task list |
| Launch a Python task, cancel, retry, run live, change a queued job's priority | `jobs` Modify (`jobs.write`) and the task's run permission; for a job, also being the user who launched it, or an admin |
| Commit changes (run live, Run Live, retry a live job) | The task's commit permission |
| Launch, retry or run live an Ansible task | Admin (a queued Ansible job whose launcher is not an admin fails when it starts) |
| Set a task's run and commit permissions, and whether it requires approval | Admin |
| Approve or deny jobs (not your own) | `jobs.approve` (admins always); `jobs.write` is not needed |
| Create and delete tasks, change a task's code or filename | Admin |
| Edit a task's name, description, tags and run inputs | `playbooks` Modify (`playbooks.write`) |
| Create, edit and delete instruction sets | `templates` Modify (`templates.write`) |
| Manage your own credentials | `credentials` Modify (`credentials.write`) |
| Manage secret variables | Admin |
| Send secret variables to an ad-hoc address that is not an inventory host you may change, or to a host whose address awaits admin confirmation | Admin |
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
POST   /api/jobs/launch               (inputs, commit)
POST   /api/jobs/{id}/cancel
POST   /api/jobs/{id}/retry
POST   /api/jobs/{id}/rerun           (same job, live)
GET    /api/jobs/approvals            (jobs.approve)
POST   /api/jobs/{id}/approve         (jobs.approve; {comment?})
POST   /api/jobs/{id}/deny            (jobs.approve; {comment?})
PATCH  /api/jobs/{id}/priority        (queued jobs only)
WS     /ws/jobs/{id}
```

Task inputs and permissions (under the `playbooks` feature):

```
GET    /api/playbooks/{id}/input-schema   (form: schema, supports_dry_run, can_run, can_commit)
PUT    /api/playbooks/{id}/input-schema   {"schema": [...]}; [] goes back to the code schema
PUT    /api/playbooks/{id}/permissions    {"run": {...}, "commit": {...}} (admin only)
```

`POST` and `PUT /api/playbooks[/{id}]` also take `input_schema` and
(admins) `permissions`, and every playbook in `GET /api/playbooks` carries
`input_schema`, `input_schema_source`, `supports_dry_run`, `permissions`,
`can_run` and `can_commit`.

Launch a dry run on two inventory hosts and one ad-hoc address:

```json
POST /api/jobs/launch
{
  "playbook_id": 3,
  "host_ids": [42, 43],
  "ad_hoc_ips": ["192.0.2.50"],
  "credential_id": 5,
  "template_id": 2,
  "commit": false,
  "priority": 3,
  "depends_on": [118],
  "inputs": { "vlan_id": 120, "uplink": "198.51.100.0/24", "snmp_key": "snmp_v3_auth" }
}
```

```json
{ "job_id": 121, "status": "queued" }
```

Give `host_ids`, `ad_hoc_ips` or `inventory_group_id` (a whole group).
`commit` defaults to `false` (a dry run); the older `dry_run` flag still
works and `commit` wins when both are sent. `parameters` is the older name
for `inputs`. `priority` defaults to `2` and is clamped to 0 to 4. Unknown
fields give `422`. Invalid inputs give `422` with one message per field:

```json
{
  "ok": false,
  "error": { "code": "http_error", "message": "Some inputs are not valid." },
  "detail": {
    "message": "Some inputs are not valid.",
    "fields": { "vlan_id": "VLAN must be at most 4094.", "uplink": "Uplink must be a prefix in CIDR form, for example 192.0.2.0/24." }
  }
}
```

A dry run of a task without a dry-run mode gives `422` with a `commit`
field. A caller the task's permissions refuse gets `403`.
