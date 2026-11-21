# Lab mode

The Lab is a place to rehearse a configuration change before you make it on
a real device. A lab device (a "twin") holds a copy of a device's running
configuration. You apply proposed commands to the twin, read the resulting
diff and risk score, and keep a history of every attempt. Nothing is sent to
your production devices.

There are two ways to work:

- **Offline (config-only):** Plexus edits the stored configuration text.
  This always works and needs nothing extra.
- **Live:** Plexus starts a virtual network device in a container with
  containerlab, pushes the commands over SSH, and reads back the real
  running configuration. This needs containerlab on the Plexus server.

## Where it is

Open **Change > Lab / Digital Twin**. You need the `lab` feature.

The page has a list of **Environments** on the left. An environment groups
lab devices. Select one to see its devices, the device panel and its
topologies.

## Creating an environment

1. Choose **New environment**.
2. Enter a **Name** and an optional **Description**.
3. Tick **Shared (visible to all operators)** if other users should see and
   use it. Otherwise only you and admins can.
4. Choose **Create**.

**Delete environment** removes the environment with all its devices and
runs, after you confirm.

## Adding a lab device

Select the environment and choose **Add lab device**. There are two ways.

**Clone from inventory:** type the inventory host's numeric ID into **Or
clone from inventory host ID** and choose **Clone from inventory host ID**.
The twin gets the host's name, address, platform and the latest
configuration snapshot Plexus holds for it. If there is no snapshot, the twin
starts with an empty configuration. A cloned twin remembers its source host.
Because the twin holds the host's full running configuration, cloning also
needs the `config-drift` or `config-backups` feature (admins always pass);
without it the clone is refused with `403`.

**Blank device:** enter **Hostname** (required), **IP address**, **Device
type** (default `cisco_ios`) and optionally **Initial running config**, then
choose **Create blank**.

The **Devices** table shows:

| Column | Shows |
|---|---|
| Hostname | The twin's name. Click a row to open the device panel. |
| IP | The container's management address when one runs, else the stored address. |
| Type | The platform, for example `cisco_ios`. |
| Runtime | **offline** for a config-only twin; else **provisioning**, **running**, **stopped**, **destroyed** or **error**. |
| Config | Size of the stored configuration in bytes. |
| Runs | Number of simulation runs. |
| Source | `#<host id>` of the inventory host it was cloned from. |

## Simulating a change offline

In the device panel, under **Simulate change against device #<id>**:

1. Type the commands into **Proposed commands (one per line)**. Lines that
   start with `#` or `!` are skipped.
2. Tick **Persist resulting config back to lab device snapshot** if the
   twin should keep the result. Then the next simulation starts from it.
3. Choose **Run simulation**.

The text is edited the same way as in [Risk analysis](risk-analysis.md#how-the-change-is-simulated)
and scored with the same formula. Compliance rules are checked only for a
twin cloned from an inventory host, using the profiles assigned to that
host's group.

**Last result** shows the level, the score (0 to 1), the line counts, the
areas and the diff.

## Running a live device

The **Containerlab runtime** card controls a container for this twin. If
containerlab is not installed, the card says "containerlab unavailable on the
Plexus host" and only offline mode works.

1. **Node kind:** one of `arista_ceos`, `ceos`, `cvx`, `frr`, `linux`,
   `nokia_srlinux`, `sonic-vs`, `srl`, `vr-csr`, `vr-sros`, `vr-veos`,
   `vr-vmx`, `vr-xrv9k`.
2. **Container image:** the image to run, for example `frrouting/frr:latest`.
   You must have the image (and any vendor licence) yourself. A user who is
   not an admin may deploy only an image on the lab image allowlist (see
   below); any other image is refused with a message naming it.
3. **SSH credential ID (for live push):** the numeric ID of one of your
   credentials. It is needed only for live simulation.
4. Choose **Deploy live**. When the container is up, the card shows the node
   kind, image, management IP and lab name.

Then, under the simulation form, tick **Live mode (push to running
containerlab device)** and choose **Run live simulation**. Plexus reads the
running configuration, pushes the commands, reads it again and diffs the
two. The twin's stored configuration is replaced with the new one. The
result also shows **Device push output**.

**Refresh status** re-reads the container state. **Destroy runtime**
removes the container. **Runtime event log** lists runtime actions.

## Topologies (several devices)

The **Topologies (multi-device)** card links twins into one containerlab
lab, for testing routing or switching between devices.

1. Enter **New topology name**, an optional **Description** and an optional
   **Mgmt subnet (optional)** in CIDR form, and choose **Create**.
2. Click the topology row to open it.
3. Pick a twin under **- select a device to add -** and choose **Add
   member**. Each member needs a node kind and image. The UI sets them when
   you use **Deploy live** on the twin; destroy that single runtime before
   you add the twin.
4. Add links with **A device**, **A endpoint**, **B device**, **B
   endpoint** (default `eth1`) and **Add link**. Or choose **Show canvas**,
   click one node, then a second node, enter the endpoints and choose
   **Create link**.
5. Choose **Deploy topology**. **Refresh** and **Destroy topology** work as
   for one device.

Members and links cannot change while the topology runs, and a running
topology cannot be deleted.

## Lab image allowlist

containerlab runs some node kinds (`ceos`, the `vr-*` kinds) as privileged
containers, so the image of a live device runs with root rights on the lab
host. Admins choose which images other users may deploy:

- `GET /api/admin/lab-image-allowlist` answers `{"entries": [...]}`;
  `PUT` with `{"entries": [...]}` replaces the list (admin only, audited as
  `lab` / `image_allowlist.update`; `422` for an invalid entry, at most 200).
- An entry with a tag (`ghcr.io/nokia/srlinux:23.10.1`) allows that image
  only. An entry without a tag (`frrouting/frr`, `registry.example.com/team`)
  allows that repository with any tag and every repository below it, by
  whole path segments: `registry.example.com/team` allows
  `registry.example.com/team/frr:9` but not `registry.example.com/team-evil/x`.
  A registry with a trailing slash (`registry.example.com/`) allows all of
  its images. The registry host must match exactly; an image without one is
  on `docker.io`, and a one-part name such as `ceos` is `docker.io/library/ceos`.
- The list starts empty: until an admin adds entries, only admins can
  deploy live devices or topologies. Admins may deploy any image whose name
  passes the character check.
- **Deploy live** and **Deploy topology** both check it; a topology is
  refused when any member's image is not allowed, also when an admin set
  that image earlier.
- There is no settings page for the list yet; use the API.

## Checking drift from production

The **Drift from production** card compares a cloned twin with the latest
configuration snapshot of its source host. Choose **Run drift check**. Plexus
also checks every cloned twin once an hour.

| Badge | Meaning |
|---|---|
| **in sync** | The twin and the production snapshot are the same. |
| **drifted** | They differ. The card shows lines added and removed. |
| **no source** | The twin was not cloned, or the source host has no snapshot. |
| **error** | The check failed; the reason is shown. |
| **not yet checked** | No check has run. |

**Drift history** lists earlier checks. Re-clone a drifted twin before you
trust a simulation.

## Run history

**Run history** lists every run with **ID**, **When**, **By**, **Risk**,
**+/−** and **Status**. Click a run for its diff and commands.

| Status | Meaning |
|---|---|
| `simulated` | Offline run; the twin was not changed. |
| `applied` | Offline run saved to the twin. |
| `applied-live` | Live run; the twin holds the device's new configuration. |
| `promoted` | Turned into a deployment through the API. |

## How the Lab differs from real devices

- An offline run only edits text. It does not merge commands into sections
  and does not check syntax. Treat its diff as an estimate.
- A live run uses a container image, not your hardware. Platform, licence
  and feature differences remain.
- A twin is a snapshot. It does not follow production unless you clone
  again; the drift check tells you when it is out of date.
- Lab runs never change production. To make the change, create a
  [deployment](deployments.md) or run a [job](jobs.md).

## Rules worth knowing

- **Visibility.** You see your own environments and shared ones. Admins see
  all. Anyone who can see an environment can change or delete it.
- **Runtime lifetime.** A container started with **Deploy live** is
  destroyed 24 hours after it started. The server settings
  `PLEXUS_LAB_RUNTIME_TTL_SECONDS` (0 turns this off) and
  `PLEXUS_LAB_RUNTIME_TTL_INTERVAL_SECONDS` (check interval, default 15
  minutes) change this.
- **Drift schedule.** `PLEXUS_LAB_DRIFT_INTERVAL_SECONDS` (default 3600,
  minimum 60) sets the interval; `PLEXUS_LAB_DRIFT_ENABLED=false` turns the
  schedule off.
- **Files.** Containerlab files are kept under `PLEXUS_LAB_WORKDIR`
  (default `~/.plexus-labs`) on the server.
- **Deleting.** Deleting a twin or an environment does not stop its
  container. Choose **Destroy runtime** first.
- **Server restart.** At startup, when containerlab is available, Plexus
  re-checks containers it thought were running and marks missing ones
  **stopped**.

## Who can do what

| Action | Needs |
|---|---|
| Use the Lab | `lab` feature |
| See and change an environment | Its owner, any user when it is shared, or an admin |
| Run a live simulation | Access to the environment and ownership of the twin's credential |
| Clone an inventory host | Access to the environment, read access to the host, and `config-drift` or `config-backups` |
| Promote a run to a deployment (API) | Access to the environment, ownership of the credential, and `deployments` with Modify (`deployments.write`) |

Lab actions are written to the audit log under `lab`. See
[Audit log](audit-log.md).

## API

All routes follow the usual session and CSRF rules. See also
[API reference](api-reference.md).

```
GET/POST        /api/lab/environments
GET/PATCH/DELETE /api/lab/environments/{id}
POST            /api/lab/environments/{id}/devices
POST            /api/lab/environments/{id}/clone-host
GET/PATCH/DELETE /api/lab/devices/{id}
POST            /api/lab/devices/{id}/simulate
POST            /api/lab/devices/{id}/simulate-live
GET             /api/lab/devices/{id}/runs
GET             /api/lab/runs/{id}
POST            /api/lab/runs/{id}/apply-to-device
POST            /api/lab/runs/{id}/promote
GET             /api/lab/runtime
POST            /api/lab/devices/{id}/runtime/{deploy|destroy|refresh}
POST            /api/lab/devices/{id}/drift/check
GET/POST        /api/lab/environments/{id}/topologies
POST            /api/lab/topologies/{id}/{deploy|destroy|refresh}
```

Simulate offline and keep the result:

```json
POST /api/lab/devices/12/simulate
{
  "proposed_commands": ["interface GigabitEthernet0/2", " description uplink-b"],
  "apply_to_device": true
}
```

```json
{ "run_id": 88, "status": "applied", "risk_score": 0.05, "risk_level": "low",
  "diff_added": 2, "diff_removed": 0, "affected_areas": ["Interface"],
  "diff_text": "...", "post_config": "...", "risk_detail": { } }
```

`simulate` also takes `template_id` instead of `proposed_commands`.

Promote a run to a deployment in the planning state. It is not executed:

```json
POST /api/lab/runs/88/promote
{ "name": "Uplink B description", "credential_id": 5, "target_group_id": 4, "target_host_ids": [42] }
```

The answer is `{"ok": true, "deployment_id": <id>, "requires_approval":
<bool>, "approval_status": "pending" | "not_required"}`. Without
`target_group_id`, the source host's group and host are used. The
deployment is planned like `POST /api/deployments`: it needs approval when
the target group or the group of any target host is a production group
(see [Deployments](deployments.md#the-approval-gate)).
