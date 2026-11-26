# Compliance

Compliance checks device configurations against rules you define. A
**profile** is a named set of rules, such as "an NTP server is configured"
or "Telnet is not enabled". A **scan** reads a device's running
configuration, tests every rule of a profile against it and stores a
result. Use it to find devices that break your standards and, where a rule
carries fix commands, to correct them.

Meraki organizations are checked through the Dashboard API instead of a
running configuration: see [Meraki compliance](meraki-compliance.md).

## Where it is and what you need

Open **Compliance** in the sidebar. The page has these tabs:

| Tab | What it shows | Feature needed |
|---|---|---|
| **Profiles** | Profiles and their rules | `compliance` |
| **Assignments** | Profiles bound to inventory groups on a schedule | `compliance` |
| **Scan Results** | One row per host scan | `compliance` |
| **Host Status** | The newest result for each host and profile | `compliance` |
| **Meraki** | [Meraki compliance](meraki-compliance.md) | `compliance` |
| **CIS Audit** | The built-in CIS security audit | `reports` |

The buttons **Run Scan**, **New Profile** and **Load Built-in** are at the
top of the page. The **Search…** box filters the list in the current tab.

Before you start you need devices in an inventory group and a credential
that can log in to them over SSH and read the running configuration.

## Create a profile

1. Click **New Profile**.
2. Fill in **Create Compliance Profile**:

   | Field | Meaning |
   |---|---|
   | **Profile Name** | Required and unique. |
   | **Description** | Optional text. |
   | **Severity** | **Low**, **Medium**, **High** or **Critical**. Default Medium. It labels the profile; it does not change how rules are scored. |
   | **Rules (JSON array)** | The rules, written as JSON. See below. |

3. Click **Create**.

To start from ready-made profiles, click **Load Built-in**. It adds 13
profiles: CIS-style IOS hardening for the management, control and data
planes, port security, AAA, routing protocol authentication, encryption,
SNMP, general hygiene, and four Meraki baselines.

**Edit** opens the same form. **Assign** binds the profile to groups (see
below). The delete button removes the profile.

## How a rule is written and matched

Each rule is one JSON object:

```json
[
  { "name": "NTP configured", "type": "must_contain", "pattern": "ntp server" },
  { "name": "No Telnet", "type": "must_not_contain", "pattern": "transport input telnet" },
  { "name": "SSH version 2", "type": "regex_match", "pattern": "^ip ssh version 2$" },
  {
    "name": "Password encryption",
    "type": "must_contain",
    "pattern": "service password-encryption",
    "remediation": ["service password-encryption"]
  }
]
```

| Key | Meaning |
|---|---|
| `name` | Shown in the findings. Fixes are looked up by this name, so keep names unique within a profile. |
| `type` | `must_contain`, `must_not_contain`, `regex_match` or `meraki`. Default `must_contain`. |
| `pattern` | The text or regular expression to look for. |
| `remediation` | Optional. A list of configuration commands that fix a failure. |

How each type matches:

| Type | Passes when |
|---|---|
| `must_contain` | At least one configuration line contains the pattern, ignoring case. A line that starts with `no ` does not count, so `no service password-encryption` does not satisfy `service password-encryption`. A pattern that itself starts with `no ` does match such a line. |
| `must_not_contain` | No line matches in the way `must_contain` would. |
| `regex_match` | The regular expression matches the configuration. `^` and `$` match at the start and end of each line. Only the first 2,000,000 characters are searched. |
| `meraki` | Skipped by host scans. Used by [Meraki compliance](meraki-compliance.md). |

Rules worth knowing when you write them:

- Regular expressions use RE2 syntax: no lookarounds and no
  backreferences. A pattern that does not compile is refused when you save
  the profile.
- A rule with an empty `pattern` always passes.
- A rule with an unknown `type` always fails.
- The **Add a Meraki check** picker under the rules box adds a Meraki rule
  for you.

## Run a scan now

1. Click **Run Scan**.
2. Choose the **Scope**:

   | Scope | Scans | How it runs |
   |---|---|---|
   | **All Hosts** | Every host in the inventory | In the background |
   | **By Group** | Every host in the chosen **Group** | In the background |
   | **Single Host** | The chosen **Host** | Waits for the result |
   | **Meraki Organization** | See [Meraki compliance](meraki-compliance.md) | In the background |

3. Choose the **Compliance Profile** and the **Credential**.
4. Click **Scan All Hosts**, **Scan Group** or **Run Scan**.

A background scan shows a progress bar ("Scanning 4 of 20 hosts…") with
the number of non-compliant hosts and errors so far. Closing the dialog
does not stop the scan.

A scan started by hand uses the host's stored configuration when the
device was read in the last 15 minutes; otherwise it logs in to the device.
Every configuration a scan reads is also stored as a backup (see
[Configuration backups and drift](config-backups-and-drift.md)).

## Scan on a schedule

An **assignment** binds a profile to an inventory group, a credential and
an interval.

1. On **Profiles**, click **Assign** on the profile.
2. In **Assign Profile to Groups**, tick the **Inventory Groups**. Groups
   that already have this profile show "(already assigned)". **Select
   All** and **Deselect All** help with many groups.
3. Choose the **Credential** and the **Scan Interval (hours)** (1 to 168,
   default 24).
4. Click **Assign**.

On **Assignments**, each card shows the profile, the group and its host
count, **Enabled** or **Disabled**, the interval and the last scan time.

- **Scan Now** scans every host in the group in the background. The
  progress shows above the list, with **Show results** when it ends.
- **Disable** / **Enable** pauses or restarts the schedule.
- The delete button removes the assignment.

Scheduled scans only run when an admin has turned on the compliance
scheduler (see "Rules worth knowing"). **Scan Now** works either way.

## Read the results

**Scan Results** lists the newest 200 scans. **Host Status** shows only the
newest result for each host and profile, so you can see whether a device is
clean now. Both tables sort by any column; **Status** sorts worst first.

| Column | Meaning |
|---|---|
| **Status** | `compliant` (green): every rule passed. `non-compliant` (red): at least one rule failed. `error` (amber): the scan could not read the configuration, for example a login failure or a timeout. |
| **Host**, **IP** | The device. |
| **Profile** | The profile that was tested. |
| **Score** | Rules passed out of rules tested, for example `18/20 passed`. Meraki rules are not counted. |
| **Scanned** | When the scan ran. |

A result with failures has a **View N violation(s)** button. It opens
**Compliance Findings** with one row per rule: the result, the rule name and
type, and a detail such as `Missing: ntp server` or `Prohibited pattern
found: transport input telnet`.

## Fix a failed rule

A failed rule that has `remediation` commands shows **Fix** and **Preview**
in the findings. Other failed rules show "Manual fix required".

1. Choose the **Credential for remediation:**.
2. Click **Preview** to see the commands that will be sent in
   configuration mode.
3. Click **Fix** for one rule, or **Fix All** for every fixable rule.
   Confirm the dialog.

Plexus sends the commands, saves the configuration on the device, then
scans the host again against the same profile. The message tells you
whether the rule now passes and gives the new score. The findings window
then shows the new scan.

## Rules worth knowing

- **The scheduler is off by default.** Assignments are only scanned on
  their interval when an admin turns the compliance scheduler on with
  `PUT /api/admin/compliance`. There is no screen for this setting. The
  scheduler wakes every 300 seconds by default (60 to 86,400) and runs each
  assignment whose interval has passed.
- **Scheduled scans always read the device**; they do not reuse a stored
  configuration.
- **Retention.** Scan results older than 90 days by default (1 to 365) are
  deleted after each scheduler run. While the scheduler is off, nothing is
  deleted.
- **Assignment interval** is kept between 1 and 168 hours.
- **One profile per group once.** Assigning the same profile to the same
  group again gives an error.
- **One scan per assignment.** **Scan Now** on an assignment that is still
  scanning gives an error.
- **Scheduled credentials.** A scheduled scan checks that the person who
  made the assignment may still use the credential. If not, that
  assignment is skipped.
- **Timeouts.** A host that does not return its configuration within 300
  seconds gets an `error` result.
- **Load Built-in overwrites.** Loading the built-in profiles again resets
  the description, severity and rules of any profile with a built-in name.
  Copy a built-in profile under a new name before you change it.
- **Deleting a profile** deletes its assignments and all its scan results.
  Deleting an assignment keeps its scan results.
- **Object scope.** Compliance is not available to users limited to
  selected inventory groups. See [Object permissions](object-permissions.md).

## Who can do what

| Action | Needs |
|---|---|
| See profiles, assignments, results and status | `compliance` |
| Create, change or delete profiles and assignments; load built-in profiles | `compliance` |
| Run a scan or **Scan Now** | `compliance`, and a credential you may use |
| Push a fix | `compliance`, and a credential you may use |
| Turn the scheduler on or off, change its interval and retention, run it now | Admin |
| **CIS Audit** tab | `reports` |
| **CIS Audit**: run the audit, add, change, run or delete a schedule, mute a finding, remove an override | `reports.write` (**Modify** on Reports in the access group). Without it the buttons are not shown. A schedule and an override record the user who created them |

Changes, scans and fixes are written to the [audit log](audit-log.md)
under the `compliance` category.

## API

All routes use the same session and CSRF rules as the rest of the Plexus
API; see the [API reference](api-reference.md). Examples use invented
data.

```
GET    /api/compliance/profiles
POST   /api/compliance/profiles
PUT    /api/compliance/profiles/{id}
DELETE /api/compliance/profiles/{id}
POST   /api/compliance/profiles/load-builtin
GET    /api/compliance/assignments[?profile_id=&group_id=]
POST   /api/compliance/assignments
PUT    /api/compliance/assignments/{id}
DELETE /api/compliance/assignments/{id}
POST   /api/compliance/assignments/{id}/scan-now
POST   /api/compliance/scan
POST   /api/compliance/scan-bulk
GET    /api/compliance/scans/{job_id}
GET    /api/compliance/results?host_id=&profile_id=&assignment_id=&status=&limit=
GET    /api/compliance/results/{id}
GET    /api/compliance/status[?profile_id=]
GET    /api/compliance/summary
POST   /api/compliance/remediate
GET    /api/admin/compliance
PUT    /api/admin/compliance
POST   /api/admin/compliance/run-now
```

Scan some hosts in the background (an empty `host_ids` scans every host):

```json
POST /api/compliance/scan-bulk
{ "profile_id": 3, "credential_id": 2, "host_ids": [41, 42] }
```

```json
{ "job_id": "5f0c1d2e-0000-4000-8000-000000000001", "status": "running" }
```

Poll `GET /api/compliance/scans/{job_id}` until `status` is `completed`.

Preview a fix, then apply it with `"dry_run": false`:

```json
POST /api/compliance/remediate
{ "result_id": 812, "rule_name": "Password encryption", "credential_id": 2, "dry_run": true }
```

```json
{ "dry_run": true, "host": "access-sw-01", "ip_address": "192.0.2.10", "rule": "Password encryption",
  "commands": ["service password-encryption"], "message": "Would push 1 command(s) to access-sw-01" }
```

Turn on the scheduler:

```json
PUT /api/admin/compliance
{ "enabled": true, "interval_seconds": 300, "retention_days": 90 }
```
