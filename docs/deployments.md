# Deployments

A **deployment** pushes a list of configuration commands to every host in
an inventory group. Plexus saves each host's configuration before the push,
checks the result after it, and can roll the hosts back to the saved
configuration. A deployment can need an admin's approval before it runs,
and it respects [maintenance windows](maintenance-windows.md).

## Where it is and what you need

Open **Change > Changes** in the sidebar, then the **Deployments** tab
(**Change Management > Deployments**). The tab needs the `deployments`
feature. See [Change management](change-management.md) for how deployments
fit with risk analysis and maintenance windows.

Before you start you need:

- An inventory group with the hosts to change.
- A credential that can log in to them over SSH and change and save the
  configuration.
- The commands, typed in or taken from a saved template (the `templates`
  feature).

## Create a deployment

1. Click **New Deployment**.
2. Fill in the **New Deployment** dialog:

   | Field | Meaning |
   |---|---|
   | **Name** | Required. 200 characters at most. |
   | **Description** | Optional. 2,000 characters at most. |
   | **Inventory Group** | Required. Every host in the group is changed. |
   | **Credential** | Required. Used for every step: captures, the push, checks and rollback. |
   | **Change Type** | **Template**, **Manual**, **Policy / ACL**, **Route** or **NAT**. A label only; it does not change what is pushed. |
   | **Template (optional)** | Take the commands from a template. |
   | **Linked Risk Analysis (optional)** | An approved [risk analysis](risk-analysis.md) of this change. |
   | **Proposed Commands** | One command per line. Leave empty when you chose a template. |

3. Click **Create Deployment**. The deployment is created with status
   `planning` and its details open. Nothing is sent to devices yet.

When you type commands, the template is ignored. When you use a template,
its lines are used as they are: blank lines and lines that start with `#`
are left out.

## The approval gate

A deployment needs approval before it can run when:

- the linked risk analysis has the level **high** or **critical**, or
- someone clicks **Request approval gate** in the deployment details.

Plexus also requires approval when the target inventory group, or the
group of any listed target host, is marked as a production environment
(no screen or API sets that mark today). Listing production hosts under a
non-production group does not avoid the gate. **Execute** checks the hosts'
groups again: if a host has moved into a production group since the
deployment was planned, Execute is refused with `403` and the deployment
waits for approval (`pending`). Deployments promoted from the
[Lab](lab-mode.md) follow the same rule.

To approve:

1. An admin who did not create the deployment opens **Details**.
2. Under **Approval gate**, the admin can type a comment.
3. The admin clicks **Approve** or **Reject** and confirms.

| Approval status | Meaning |
|---|---|
| `not_required` | No gate. **Execute** is available. |
| `pending` | Waiting for a decision. **Execute** is disabled. |
| `approved` | **Execute** is available. The details show who approved it, when, and the comment. |
| `rejected` | **Execute** stays disabled until approval is requested again. |

The creator of a deployment can never approve it (four-eyes rule). The
details page offers **Request approval gate** only on a deployment that has
no gate yet, so after a rejection ask again with
`POST /api/deployments/{id}/request-approval`.

## Run a deployment

1. Click **Execute** on the deployment, in the list or in **Details**.
2. Confirm. A window streams the progress.

Plexus first checks the approval gate, then the
[maintenance windows](maintenance-windows.md) that cover the group or the
group of any target host. A
window can block the deployment with a message such as `Blocked by
maintenance window 'Weekend change' (next opens ...)`.

The run has these steps:

| Step | What happens | If it fails |
|---|---|---|
| Pre-check | Plexus reads each host's configuration and saves it as the pre-deployment snapshot. It also records the host's recent CPU, memory, packet loss and response time. | The deployment stops before any change and ends `failed`. |
| Execute | Plexus sends the commands to each host in configuration mode and saves the configuration on the device. | The host is counted as failed; the others go on. |
| Post-check | Plexus reads each host's configuration again and compares it with the pre-deployment snapshot. The check passes whether or not lines changed; "no config diff detected" means the commands may already have been present. | The check is marked failed. The deployment status does not change. |

The deployment ends `completed` when every host took the commands, or
`failed` when at least one did not.

### Verification

After a `completed` run, Plexus waits 60 seconds and then checks each host
again:

- **Drift check:** the host's newest drift snapshot is compared with its
  baseline (see [Configuration backups and
  drift](config-backups-and-drift.md)). A host with no baseline passes.
  The deployment does not take a new snapshot for this check. A difference
  also opens a drift event, as any drift comparison does.
- **Metric health:** the average of the last 5 minutes of CPU percent,
  memory percent, packet loss percent and response time is compared with
  the pre-check values. A rise of more than 20 points in a percentage, or
  of more than 50% in response time, is a concern.

The deployment ends `verified` when every check passes, or
`verification_failed` when any check fails or shows a concern.

## Roll back

1. Open the deployment's **⋯** menu and choose **Rollback**, or click
   **Rollback** in **Details**.
2. Confirm. A window streams the progress.

For each host, Plexus reads the current configuration, compares it with
the pre-deployment snapshot, and sends only the difference: lines that were
removed are added again, and lines that were added are removed with `no`.
It then reads the configuration again and reports whether it now matches
the snapshot, or how many lines still differ. A host with no snapshot is
skipped.

Rollback is accepted for deployments in `completed`, `failed` or
`post-check` status. The page also shows **Rollback** for `verified` and
`verification_failed`, but the server refuses those with "Cannot rollback
deployment in 'verified' status". Because verification starts right after
a run completes, a successful deployment can in practice be rolled back
only in the first 60 seconds.

## Read the results

The list shows the newest 200 deployments. Filter by status or search by
name, group or description. The summary strip counts **Total**,
**Completed**, **Active** (pre-check, executing or post-check), **Rolled
back** and **Failed**.

| Status | Colour | Meaning |
|---|---|---|
| `planning` | Grey | Created, not run. |
| `pre-check` | Blue | Saving configurations before the push. |
| `executing` | Blue | Sending commands. |
| `post-check` | Blue | Reading configurations after the push. |
| `completed` | Green | Every host took the commands. Verification follows. |
| `verifying` | Blue | Waiting for, or running, the verification checks. |
| `verified` | Green | Every verification check passed. |
| `verification_failed` | Red | A drift check failed or a metric shows a concern. |
| `failed` | Red | A pre-check failed, at least one host failed, or a rollback failed. |
| `rolling-back` | Blue | Rollback is running. |
| `rolled-back` | Amber | Rollback ran on every host without an error. A host that still differs is reported only in the progress window; its rollback checkpoint still shows `passed`. |

A **Rollback:** badge next to the status shows `in_progress`, `completed` or
`failed`.

**Details** shows the commands, the **Pre-Deployment Checkpoints**, the
**Post-Deployment Checkpoints**, any **Rollback Checkpoints**, and a
**Verification** table with the pre and post value of each metric marked
**OK** or **Concern**. **Correlation** shows a timeline of the deployment's
checkpoints and the audit events around it.

## Rules worth knowing

- **Execute** is accepted in `planning` and `failed` status only. A
  deployment cannot run twice at the same time.
- Running a `failed` deployment again pushes the commands to every host
  again, including hosts that took them the first time.
- Each run adds new pre-deployment snapshots. Rollback uses the snapshot
  of the most recent run; the post-check compares with the snapshot of the
  first run.
- **Delete** is offered for `planning`, `completed`, `failed` and
  `rolled-back` deployments. It also deletes the checkpoints and snapshots.
  An active deployment cannot be deleted.
- Deleting the inventory group or the credential deletes the deployment.
- Commands: at most 10,000 lines of up to 4,000 characters each.
- Deployments created on this page target the whole group, so the
  **Correlation** timeline has no drift or alert events: those need a
  list of hosts, which only the API can set (`host_ids`).
- Execute and rollback use the credential as the deployment's creator, so
  an admin can run a deployment someone else created with that person's
  credential.

## Who can do what

| Action | Needs |
|---|---|
| See the deployment list and summary | `deployments` |
| Create a deployment | `deployments`, and a credential you may use |
| Open details or correlation, execute, roll back, delete | `deployments`, and be the creator or an admin |
| Request the approval gate | `deployments` |
| Approve or reject | Admin, and not the creator |

Users limited to selected inventory groups cannot use deployments. See
[Object permissions](object-permissions.md). Every action is written to the
[audit log](audit-log.md) under the `deployments` category.

## API

All routes use the same session and CSRF rules as the rest of the Plexus
API; see the [API reference](api-reference.md). Examples use invented
data.

```
GET    /api/deployments[?status=&group_id=&limit=]
GET    /api/deployments/summary
POST   /api/deployments
GET    /api/deployments/{id}
GET    /api/deployments/{id}/correlation
POST   /api/deployments/{id}/execute
POST   /api/deployments/{id}/request-approval
POST   /api/deployments/{id}/approve          {"comment": ""}
POST   /api/deployments/{id}/reject           {"comment": ""}
POST   /api/deployments/{id}/rollback
DELETE /api/deployments/{id}
GET    /api/deployments/job/{job_id}/status
WS     /ws/deployment/{job_id}
```

Create a deployment for two hosts of a group:

```json
POST /api/deployments
{
  "name": "Branch NTP update",
  "group_id": 4,
  "credential_id": 2,
  "change_type": "manual",
  "proposed_commands": ["ntp server 192.0.2.123"],
  "host_ids": [41, 42]
}
```

```json
{ "id": 17, "status": "planning", "requires_approval": false, "approval_status": "not_required" }
```

Execute it:

```json
POST /api/deployments/17/execute
{ "job_id": "0b6e7c1a-0000-4000-8000-000000000002", "deployment_id": 17 }
```

Errors: `403` when approval is missing or you are not the creator or an
admin, `409` when a maintenance window blocks the change or the deployment
is already running, `400` when the status does not allow the action.
