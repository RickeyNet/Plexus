# Change Management

The Change Management page brings together the tools for planning and
making configuration changes: a **risk analysis** scores a proposed change
before it is made, a **deployment** pushes it to devices, and **maintenance
windows** decide when that is allowed.

Plexus has no separate "change record". A change is described by a risk
analysis (optional) and the deployment that carries it out. The approvals
and states below belong to those two records.

## Where it is and what you need

Open **Change > Changes** in the sidebar. The page is called **Change
Management** and has three tabs:

| Tab | What it does | Feature needed | Guide |
|---|---|---|---|
| **Risk Analysis** | Scores a proposed change | `risk-analysis` | [Risk analysis](risk-analysis.md) |
| **Deployments** | Pushes, verifies and rolls back changes | `deployments` | [Deployments](deployments.md) |
| **Maintenance** | Time windows that allow or block deployments | `deployments`; changes need `deployments.write` or admin | [Maintenance windows](maintenance-windows.md) |

You only see the tabs your features allow. A risk analysis on live devices
needs a credential that can log in to them over SSH.

## How a change moves through Plexus

1. **Analyze.** Run a risk analysis of the commands against the target
   group. No change is sent to the devices.
2. **Approve the analysis.** Someone reviews the result and clicks
   **Approve Change**.
3. **Plan.** Create a deployment with the same commands and choose the
   approved analysis under **Linked Risk Analysis (optional)**. Only
   approved analyses are offered there.
4. **Approve the deployment.** When the linked analysis is **high** or
   **critical**, the deployment waits for an admin who did not create it.
5. **Wait for the window.** The deployment runs only when the maintenance
   windows of its group allow it.
6. **Execute, verify, roll back.** See [Deployments](deployments.md).

Steps 1 and 2 are optional. A deployment can be created without an
analysis.

Jobs started from the **Delegator** page are not part of this flow: they
have no approval gate and are not checked against maintenance windows. See
[Running jobs](jobs.md).

## States

| Record | States |
|---|---|
| Risk analysis | **Pending** until approved, then **Approved**. There is no reject. |
| Deployment | `planning`, `pre-check`, `executing`, `post-check`, `completed`, `verifying`, `verified`, `verification_failed`, `failed`, `rolling-back`, `rolled-back`. See [Deployments](deployments.md). |
| Deployment approval | `not_required`, `pending`, `approved`, `rejected`. |

## Rules worth knowing

- **Approving an analysis** needs only the `risk-analysis` feature. The
  creator may approve their own analysis. Approving a deployment needs an
  admin who is not its creator.
- **A linked analysis does not lock the commands.** Plexus does not check
  that the deployment's commands match the analysis.
- **Deleting an analysis** removes the link from any deployment that used
  it. The deployment and its approval are not changed.
- **Configurations an analysis reads** from devices are stored as backups
  with the method `risk-analysis`. See
  [Configuration backups and drift](config-backups-and-drift.md).
- **With no maintenance windows**, deployments run at any time. The
  approval gate still applies.

## Who can do what

| Action | Needs |
|---|---|
| Run, view, approve or delete risk analyses | `risk-analysis`; a live analysis also needs a credential you may use |
| Create deployments and request an approval gate | `deployments` |
| Execute, roll back or delete a deployment | `deployments`, and be its creator or an admin |
| Approve or reject a deployment | Admin, and not its creator |
| See maintenance windows | `deployments` |
| Create, change or delete maintenance windows | `deployments.write` or admin |

Users limited to selected inventory groups cannot use this page. See
[Object permissions](object-permissions.md). Actions are written to the
[audit log](audit-log.md) under `risk-analysis`, `deployments` and
`maintenance-windows`.

## API

Each tab's endpoints are in its own guide: `/api/risk-analysis/*` in
[Risk analysis](risk-analysis.md#api), `/api/deployments/*` in
[Deployments](deployments.md#api) and `/api/maintenance-windows/*` in
[Maintenance windows](maintenance-windows.md#api).

`POST /api/maintenance-windows/check` with `{"group_ids": [4]}` tells you
whether a deployment to those groups would be allowed now, without running
anything.
