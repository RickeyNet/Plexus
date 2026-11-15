# Maintenance windows

A maintenance window is a time period in which changes to production devices
are allowed. Plexus checks the windows when someone executes a deployment.
Depending on the window's policy, a deployment outside the window is blocked
or only logged with a warning. You use windows to keep staged changes inside
agreed change times.

## Where it is

Open **Change > Changes** and choose the **Maintenance** tab. The page is
called Change Management; its other tabs are described in
[Change management](change-management.md) and [Deployments](deployments.md).

You need the `deployments` feature to see the windows and
`deployments.write` to create, edit or delete them. Admins can do both. Scope
uses inventory groups, so create the groups first.

## Creating a window

1. Choose **+ New Window**.
2. Fill in the form:

| Field | Meaning |
|---|---|
| Name | Required. For example "Weekly core patching". |
| Description | Optional text shown under the name. |
| Start / End | Date and time in your browser's local time. Plexus stores them in UTC. |
| Recurrence | **One-shot**, **Daily** or **Weekly**. |
| Weekdays | Shown for **Weekly**. Pick at least one of **Mon** to **Sun**. |
| Policy | What happens to a change outside the window. See below. |
| Scope | Click inventory groups to select them. No group selected means the window is global. |
| Enabled | A disabled window is ignored. |

3. Choose **Create**.

**Edit** opens the same form with the saved values; choose **Save**. The
delete button removes the window after you confirm.

### Recurrence

| Recurrence | When the window is open |
|---|---|
| **One-shot** | Once, from **Start** to **End**. End must be after start. |
| **Daily** | Every day from the date of **Start**, at the time of day of **Start**, for the length **End** minus **Start**. |
| **Weekly** | Like Daily, but only on the selected weekdays. |

For Daily and Weekly, set **End** on the same day as **Start**, or on the
next day for a window that crosses midnight. If **End** is not after
**Start**, Plexus adds one day to the length. A recurring window has no last
date: disable or delete it to stop it.

### Policy

| Form option | List label | Effect |
|---|---|---|
| **Block changes outside window** | Block outside (red) | While the window is closed, deployments to its scope are blocked. This is the default. |
| **Warn outside window** | Warn outside (amber) | While the window is closed, deployments go ahead and a warning is written to the audit log. |
| **Allow inside window only (advisory)** | Allow inside (green) | While the window is open, deployments to its scope are allowed even if a block window is closed. When it is closed it has no effect. |

## How a deployment is checked

When a deployment is executed, Plexus takes every enabled window that is
global or includes the deployment's inventory group. It decides in this
order:

1. An open **Allow** window applies: the deployment runs.
2. An open **Block** window applies: the deployment runs (it is inside its
   window).
3. A closed **Block** window applies: the deployment is refused with
   `Blocked by maintenance window '<name>' (next opens <start>)`. The time
   shown is the window's stored **Start**.
4. A closed **Warn** window applies: the deployment runs and the audit log
   records `deployment.execute_outside_window`.
5. Otherwise the deployment runs.

A refused deployment is recorded as `deployment.execute_blocked` in the audit
log. The approval gate of a deployment is checked before the windows; see
[Deployments](deployments.md).

## Reading the list

| Column | Shows |
|---|---|
| Name | The name and description. |
| Window | Start and end in your local time. |
| Recurrence | One-shot, Daily or Weekly, with the weekdays. |
| Scope | The group names, or "All groups (global)". |
| Policy | The policy badge. |
| State | **Active** (green): the window is open now. **Idle**: enabled but closed now. **Disabled**: switched off. |

Open windows are listed first, then the rest by start time.

## Rules worth knowing

- **Only deployment execution is gated.** Windows do not affect jobs on the
  Delegator page ([Running jobs](jobs.md)), Lab simulations, monitoring
  alerts or SLA figures. To silence alerts during work, use the alert
  suppressions in [Monitoring](monitoring.md).
- **UTC.** Daily and weekly windows repeat at the same UTC time of day, and
  weekdays are UTC weekdays. Near midnight, or across a daylight saving
  change, the local time and day can differ from what you entered.
- **No windows, no limit.** With no windows, deployments run at any time.
  The deployment approval gate still applies.
- **Validation.** The API checks times, policy, recurrence and weekdays when
  a window is created. On update it checks only the policy and recurrence
  names; the form checks the rest.
- **Deleting a window** also removes its scope. Deployments are not
  changed.

## Who can do what

| Action | Needs |
|---|---|
| See windows | `deployments` feature |
| Create, edit, delete windows | `deployments.write` feature, or admin |
| Preview the verdict with `/check` | `deployments.write` feature, or admin (it is a POST) |

Window changes are written to the audit log under `maintenance-windows`
(`window.created`, `window.updated`, `window.deleted`). See
[Audit log](audit-log.md).

## API

All routes follow the usual session and CSRF rules. See also
[API reference](api-reference.md).

```
GET    /api/maintenance-windows
GET    /api/maintenance-windows/{id}
POST   /api/maintenance-windows
PUT    /api/maintenance-windows/{id}
DELETE /api/maintenance-windows/{id}
POST   /api/maintenance-windows/check
```

Create a weekly window, Tuesday and Thursday 22:00 to 02:00 UTC, for two
groups:

```json
POST /api/maintenance-windows
{
  "name": "Branch patching",
  "description": "Branch routers only",
  "start_at": "2026-12-01T22:00:00Z",
  "end_at": "2026-12-02T02:00:00Z",
  "recurrence": "weekly",
  "weekday_mask": 10,
  "policy": "block_outside_window",
  "enabled": true,
  "group_ids": [4, 7]
}
```

The answer is `{"id": <new id>}`. `weekday_mask` has one bit per day: 1 =
Monday, 2 = Tuesday, 4 = Wednesday, 8 = Thursday, 16 = Friday, 32 =
Saturday, 64 = Sunday. `policy` is `block_outside_window`,
`warn_outside_window` or `allow_changes`; `recurrence` is `none`, `daily` or
`weekly`. A timestamp without a zone is read as UTC.

List rows carry `scopes` (`group_id`, `group_name`), `group_ids` and
`is_active`. On `PUT`, a key that is left out is not changed, and
`group_ids` replaces the whole scope.

Ask what would happen to a change for some groups now:

```json
POST /api/maintenance-windows/check
{ "group_ids": [4] }
```

```json
{
  "allowed": false,
  "reason": "Blocked by maintenance window 'Branch patching' (next opens 2026-12-01T22:00:00Z)",
  "policy": "block_outside_window",
  "window": { "id": 3, "name": "Branch patching" },
  "warning": ""
}
```

The `window` object in a real answer holds the full window row.
