# Object-level permissions

Access groups grant features (pages). Object-level permissions also decide
which devices a member sees: an access group either covers every device
(the default) or only the inventory groups it grants, each read only or
read and write.

## Model

- **Device access** of an access group (`access_groups.object_scope`):
  - `all` - every device. This is the default and how every access group
    behaved before.
  - `groups` - only the inventory groups in its grants.
- **Grants** (`access_group_inventory_scopes`): one per inventory group,
  `can_write` false (Read) or true (Read and write). A grant covers the
  inventory group **and all of its sub-groups**, including sub-groups created
  later. Grants are deleted with their access group or inventory group.
- **A user's scope**:
  - Admins, the server API token (`APP_API_TOKEN`) and any member of an
    access group with `all` are **unrestricted**: nothing changes for them.
  - Everyone else is **scoped**: they see the union of the grants of their
    access groups. A group is writable when any grant covering it has Read
    and write. A scoped user with no grants (or with no access group at all)
    sees no devices.

Answers to a scoped user:

| Situation | Answer |
|-----------|--------|
| Group or host outside the read scope | `404`, the same body an unknown id gets (nothing says it exists) |
| Write to a readable group or host that is not writable | `403 Read-only access to this inventory group` |
| Create a top-level group, or move a group to the top level | `403` (unrestricted accounts only) |
| Create a sub-group or host | Allowed inside a writable group |
| Move a host or group | Needs write on where it is and where it goes; a granted group whose parent is not writable cannot be moved |
| Lists, CSV export, Ansible inventory, SNMP assignments | Only readable groups and hosts. A group whose parent is hidden is listed as a top-level group, and its `path` starts at it |
| Bulk delete, move, tag, edit | Every host id must be writable, else nothing is changed (`404` when one is not readable, `403` when one is read only) |
| Grouped bulk add (`POST /api/inventory/hosts/bulk`) | Entries naming a group by `group_name` or `group_path` are refused (they may create top-level groups); an existing host the user cannot read is reported without its id or group |
| Discovery scan, sync and onboard | Need write on the group; a scan job of a group the user cannot read answers `404` |
| A record addressed by its own id (backup, backup policy, baseline, snapshot, drift event, intended configuration, capture job) | Resolved to its host or inventory group and checked the same way: `404` with the body an unknown id gets, `403` on a write when read only |
| Lists, counts, summaries, searches and exports of the configuration modules | Computed over readable hosts only, filtered in SQL before limits and counts, so totals never include hidden rows |
| Device actions and stored changes (capture, check, analyze, restore, revert, accept or resolve drift, baselines, deletes, generate) | Need write on the host's group (or, for a group action, on the group) |

## Fail-closed rule

Scope is enforced module by module. Until a module enforces it, a scoped
user must not reach it:

- `SCOPE_ENFORCED_FEATURES` in `netcontrol/object_scope.py` lists the
  feature keys whose modules enforce scope. Today that is `inventory`,
  `config-backups`, `config-drift` (which also covers intended
  configuration), `credentials` (per owner, so nothing to filter) and
  their `.write` keys.
- For a scoped user, the effective features (`_get_user_features`) keep only
  those keys, whatever their access groups grant. Every other feature gate
  (HTTP routes, WebSocket streams, the dashboard) answers `403`, and the
  sidebar hides those pages. `GET /api/auth/status` reports the reduced
  `feature_access`.
- MCP (AI access) tokens owned by a scoped user are refused with `403`
  (`{"error": "forbidden", "message": ...}`), since MCP tools read every
  device.
- Routes open to any signed-in user (`require_auth` only) return no host or
  inventory group rows: custom field and tag definitions, the device model
  catalogues, secret variable names, the user's own profile. The tag, field
  and catalogue lists carry usage counts over all devices.

### Pages a scoped account can use now

Inventory: groups, hosts, custom data and tags on hosts and groups, bulk
edit, CSV export, discovery into writable groups, SNMP assignments, the
Ansible dynamic inventory.

Configuration (with the `config-backups` and `config-drift` features):
Config Drift, Intended, Backups and Config Search. Settings pages that need
admin stay admin-only.

Credentials (with the `credentials` feature): a scoped account manages its
own credentials as any user does. Credentials are per owner and hold no
host or inventory group data, so nothing is filtered there. Capture, check,
restore and revert log in with a credential the user owns, so a scoped
account that should run them needs this feature too.

### Configuration modules

**Config Backups** (`netcontrol/routes/config_backups.py`):

- Backup lists, `summary` (policies, backups, hosts backed up, last
  backup), `latest-per-host`, `search` and the ZIP `download` cover the
  readable hosts only.
- A backup (`GET`, `diff`, `download`, `DELETE`, `restore`) belongs to its
  host: hidden host, `404 Backup not found`; delete and restore need write.
- A policy is a global record that targets one inventory group. A scoped
  user lists and reads it only when that group is readable, and creates,
  changes, deletes or runs it (`run-now`) only when the group is writable.
  Creating one for a hidden group answers `404 Inventory group not found`.

**Config Drift** (`netcontrol/routes/config_drift.py`):

- Drift events, baselines and `summary` cover readable hosts only;
  `snapshots?host_id=` of a hidden host is an empty list, as for an
  unknown host.
- A baseline, snapshot or drift event (and its `history`) belongs to its
  host: hidden host, `404` with the unknown-id message; changing, deleting,
  accepting, resolving and reverting need write.
- Capture (single, group, job), `check`, `analyze` and `analyze-group`
  need write on the host or group (analysis may open drift events). A
  hidden group answers `404 No hosts found in group`.
- Bulk accept and resolve: every event id must be known and writable, else
  nothing changes (`404` or `403`).
- Capture and revert jobs record the inventory groups they touch:
  `GET /api/config-drift/capture-job/{job_id}` and the WebSockets
  `/ws/config-capture/{job_id}` and `/ws/config-revert/{job_id}` answer
  "Job not found" when a host of the job is not readable.

**Intended configuration** (`netcontrol/routes/intended_config.py`,
`router`; the `admin_router` is admin-only):

- `hosts` rows and `counts` (hosts, generated, errors, compliance) cover
  readable hosts only; `hosts/{host_id}` and `hosts/{host_id}/variables`
  of a hidden host answer like an unknown one.
- Templates and contexts are global records. A template's `host_count`
  counts readable hosts only. A template or context that targets an
  inventory group (or, a context, a host) the user cannot read is hidden
  (`404` by id).
- `generate` stores intended configurations: with `host_ids` or
  `group_id` every host or the group must be writable; with neither it
  acts on the writable hosts only.

On the Configuration page, write controls (Run Now, policy Edit and
Delete, Restore, backup Delete, Accept, Resolve, Revert, Accept Group,
Regenerate) are disabled with the reason "Read-only access to this
inventory group" for hosts and groups outside `write_group_ids`; for rows
that carry only a host id (backups, drift events) the page looks the host
up in the inventory list. The capture, baseline and new policy pickers
offer writable groups and their hosts only. On the Inventory page, the
target group pickers (host group, parent group, bulk move, discovery
target) offer writable groups only, and "None (top level)" is disabled.

## Settings

Settings > Access Groups > New Group / Edit: **Device access** is All devices
or Selected inventory groups. For the second, each inventory group gets No
access, Read, or Read and write. The table shows each group's device access.
Settings > Users marks restricted users "Limited to selected inventory
groups". On the Inventory page, write controls of groups the user may only
read are disabled with the reason, and "+ New Group" (top level) is disabled
for scoped users.

## API

- `GET/POST/PUT /api/admin/access-groups`: the access group object carries
  `object_scope` (`all` | `groups`) and `inventory_scopes:
  [{inventory_group_id, can_write}]`. Create and update accept them; an
  unknown inventory group id is `400`; with `all` the grants are ignored and
  cleared. An update that leaves `object_scope` out keeps the scope and its
  grants. Create, update and delete are audited (`access_group.create`,
  `access_group.update` with the scope change, `access_group.delete`).
- `GET /api/admin/users`: each user carries `object_scope_restricted`.
- `GET /api/auth/status` (signed in) and the login response carry
  `object_scope: {restricted, write_group_ids}`. `write_group_ids` are
  expanded with sub-groups and empty when unrestricted.

## Enrolling another module

1. Enforce scope in every route of its routers with the helpers in
   `netcontrol/object_scope.py`:
   - `await request_scope(request)` - the caller's `ObjectScope` (cached on
     `request.state`); `ws_scope(session)` for WebSocket handlers.
   - `await require_group(request, group_id, write=...)`,
     `require_host(...)`, `require_hosts(...)` - the row(s), or `404`/`403`.
   - `scope.filter_groups(rows, key="id")`,
     `scope.filter_hosts(rows, key="group_id")`,
     `scope.can_read_group(id)`, `scope.can_write_group(id)` for lists,
     counts and summaries.
   - `require_object_host(request, host_id, not_found=..., write=...)` for
     a record addressed by its own id that belongs to a host.
   - `**await group_filter(request)` as keyword arguments of a `routes.db`
     reader that takes `group_ids` (built with
     `routes.db.inventory.group_ids_condition`), so lists and counts are
     filtered in SQL; it is empty for unrestricted callers.
   - `refuse_scoped(request)` for an action that cannot be confined.
2. Mark every route `@scoped("<kind>")` or `@scope_exempt("<reason: no host
   or group data>")`.
3. Add its routers to `SCOPE_ENFORCED_ROUTERS` and its feature key (and
   `<key>.write` when the feature has one) to `SCOPE_ENFORCED_FEATURES`.
4. `tests/test_object_scope_api.py` then requires every HTTP and
   WebSocket route of those routers to be marked (a WebSocket router of an
   enrolled module must be listed too), and drives every scoped GET route
   with a `group_id` or `host_id` path parameter with an out-of-scope id,
   expecting `404`.
5. Add the page to `SCOPED_ACCOUNT_PAGES` in
   `src/pages/Settings/accessGroupScope.ts` and this document.

## Not covered

Per-object grants on anything but inventory groups (sites, tenants, single
hosts); scope on monitoring, topology, reports, jobs, deployments, upgrades,
IPAM and MCP (scoped users are shut out of them instead).
