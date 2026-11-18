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

## Every feature, filtered

Every feature of the catalog is enrolled: a scoped user keeps every page
their access groups grant, and each shows only the objects in their scope
(multi-team and MSP use). `SCOPE_ENFORCED_FEATURES` in
`netcontrol/object_scope.py` lists them; a feature that is not listed (a
plugin's) stays closed to scoped users (fail closed): `_get_user_features`
drops it, so its HTTP routes, WebSockets and sidebar entry are refused.
MCP (AI access) tokens owned by a scoped user are still refused (`403`),
and ChatOps commands refuse scoped users.

### Records beyond hosts: the model registry

Records reach the scope through the **model registry**
(`object_scope.MODELS`). A model names the fields of its rows that place it:
an inventory group, a host, a tenant or a site (or a list of hosts or sites,
e.g. a circuit's terminations). For a scoped user a row is

- **readable** when any key is in scope: its group or host is in a granted
  group; its tenant is the tenant of such a host; its site holds such a host
  (its own site, its rack's or its floor plan placement's); or a **scope rule** grants the tenant
  or site for the model;
- **writable** when any key is writable: a writable group or host, the
  tenant of a host in a writable group, or a writable scope rule. A site
  reached only through a host is read only (sites are often shared); write
  on a site needs a scope rule;
- of a **shared** model (reference data: providers, provider networks,
  circuit, cluster and rack types and roles, templates, playbooks,
  compliance profiles, end-of-life notices, advisories, untenanted VRFs,
  VLANs and autonomous systems, global alert rules) readable when it has no
  key, and never changed (unrestricted users only). A row of any other model
  with no key (an untenanted prefix, a circuit with no tenant or
  termination) is visible to unrestricted users only.

### Scope rules

A scope rule extends an access group with **Selected inventory groups**
beyond its inventory groups: the records of one model (or every model,
`*`) whose **tenant** or **site** is the given one, Read or Read and write.
Rules live in `access_group_scope_rules` (migration 0111), are deleted with
the access group, and apply only while the group's device access is
Selected inventory groups. A rule naming a model without that key is
refused (`400`). Example: a team granted a customer's inventory group, plus
"Circuits, tenant = that customer, Read" to see the circuits that terminate
outside their devices.

### What each feature enforces

| Feature | Lists and details | Writes and actions |
|---------|-------------------|--------------------|
| Dashboard | Stats, recent jobs, groups, health and open alerts over the user's hosts and jobs (not cached); no topology problems | - |
| Monitoring (polls, alerts, rules, suppressions, SLA, availability, baselines, interface errors, metrics, Meraki alerts) | Per host, filtered in SQL before limits and counts; rules by target host or group (global rules shared); integration entities only when mapped to a readable host; Cato egress findings empty | Acknowledge, poll and compute need write on the host; a rule needs write on its target; global rules, OID profile changes, site mutes and Cato checks are refused |
| Jobs | A job is visible when every target host (or its group) is readable; dynamic group jobs to their launcher only | Launch, cancel, retry, rerun and priority need write on every target; ad-hoc IPs are refused |
| Playbooks, templates | Shared catalogue | Unrestricted users only |
| Deployments, maintenance windows, risk analysis | By group and hosts | Need write on the group and hosts; global windows unrestricted only |
| Compliance | Results, status, summary by host; assignments by group; profiles shared | Scans and remediation need write; Meraki compliance is hidden and refused |
| Upgrades | A campaign is visible when every device is a readable host; images shared | Campaign changes need write on every device; prestage backup files hidden |
| Topology, path trace, MAC tracking, traffic analysis | Links whose ends are visible (a neighbour matching a hidden host is dropped); path traces over the user's map without vendor or cloud snapshots; MAC and flow data of readable hosts | Discovery, collection and acknowledgements on writable groups; cleanup refused |
| Meraki and cloud sources, cloud visibility | Hidden (not tied to inventory groups) | Refused |
| Software, lifecycle | Devices of readable hosts; advisories and notices shared | Acknowledge needs write; refresh, settings and checks refused |
| IPAM, DHCP, VRFs, VLANs | Subnets of readable hosts and of the user's tenants; prefixes and IP addresses by tenant; VRFs and VLANs by tenant and site (untenanted ones shared); DHCP servers hidden | Admin only, as before |
| Organization, floor plans | Tenants of readable hosts, sites holding them, plus scope rules; regions and tenant groups shared with recounted totals | Organization writes admin only; floor plans need write on the site (scope rule) and host |
| Circuits | By tenant, or the sites and hosts of their terminations | Need write on the circuit; providers and types shared |
| Virtualization | Clusters by tenant, site or member host; VMs by tenant or their cluster | Need write; types and groups shared |
| Routing | Instances, peer groups and peerings by device; ASes by tenant (untenanted shared) | Need write on the device |
| DCIM | Racks, reservations, panels and feeds by tenant and site; ports, modules and placements by host; cables by tenant and ends; other devices in a visible rack show as occupied units; traces stop at hidden records (`restricted`) | Need write on the record (site writes through a scope rule) |
| Sync, secrets providers | Jobs, runs (entries of readable devices) and providers are read | Refused |
| Reports, audit, graphs, billing, lab | Reports need a group or host in scope (IPAM reports refused); audit findings, host graphs, billing circuits and lab twins by host; graph templates shared | Writes need write on the host; audit runs and schedules refused |
| GraphQL | Only the fields whose resolvers filter by scope (`GRAPHQL_SCOPED_FEATURES`: inventory and backups today) | Read-only API |

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
access, Read, or Read and write, and **Scope rules** add a tenant or site
for one record type (or every type), Read or Read and write. The table shows
each group's device access. Settings > Users marks restricted users "Limited
to selected inventory groups". On the Inventory page, write controls of
groups the user may only read are disabled with the reason, and "+ New
Group" (top level) is disabled for scoped users. A scoped account with no
writable grant or rule (`object_scope.read_only`) sees no write controls on
any page that gates writes with `canWriteFeature`.

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
  `object_scope: {restricted, write_group_ids, read_only}`.
  `write_group_ids` are expanded with sub-groups and empty when
  unrestricted; `read_only` is true for a scoped account with no writable
  grant or scope rule.
- `GET /api/admin/object-scope/models`: the model registry (name, keys,
  shared, which rule attributes apply).
- `GET/PUT /api/admin/access-groups/{id}/scope-rules`: the scope rules
  (`{"rules": [{model, attribute, value_id, can_write}]}`; `model` a
  registry name or `*`, `attribute` `tenant` or `site`). An unknown model,
  attribute, tenant or site is `400`; changes are audited
  (`access_group.scope_rules`).

## Enrolling another module

1. Enforce scope in every route of its routers with the helpers in
   `netcontrol/object_scope.py`:
   - `await request_scope(request)` - the caller's `ObjectScope` (cached on
     `request.state`); `ws_scope(session)` for WebSocket handlers.
   - `require_group`, `require_host`, `require_hosts`,
     `require_object_host`, `require_host_ids` for hosts and groups.
   - The row helpers over the model registry: `filter_rows(model, rows,
     request)`, `require_row(request, model, row, write=...)` (`404` /
     `403`), `require_new_row(request, model, values)` for creates and key
     changes, `require_model_write(request)` for shared catalogues,
     `can_access(...)`.
   - SQL pushdown for lists and counts: `**await group_filter(request)` for
     readers taking `group_ids`, `sql_condition(model, request, alias=...)`,
     `readable_host_ids(request)`.
   - `refuse_scoped(request)` for an action that cannot be confined.
   - A model the registry lacks: `register_model(ScopeModel(name, keys,
     shared=...))` in the route module.
2. Mark every route `@scoped("<kind>")` or `@scope_exempt("<reason>")`
   (kinds ending in `:live` contact a device, `:nodata` may answer `404` for
   a host with no stored data; `refused` and `admin` routes answer `403` to
   every scoped user).
3. Add its routers to `SCOPE_ENFORCED_ROUTERS` and its feature key (and
   `<key>.write`) to `SCOPE_ENFORCED_FEATURES`.
4. `tests/test_object_scope_api.py` then requires every HTTP and WebSocket
   route of those routers to be marked and drives every scoped GET route
   with a `group_id` or `host_id` path parameter with an out-of-scope id,
   expecting `404`; `tests/test_object_scope_features.py` holds the
   per-feature authorization matrix.

Other consumers use the same rules with a scope from `scope_for_user`:
`filter_rows(model, rows, scope)`, `can_access(scope, model, row)` and
`sql_condition(model, scope, alias=...)` (GraphQL resolvers, reports).

## Not covered

- MCP (AI access) and ChatOps stay closed to scoped users.
- GraphQL fields other than inventory and backups answer "Access denied"
  for scoped users until their resolvers filter by scope.
- Integration data with no inventory host (Meraki organizations and
  snapshots, cloud accounts, Cato egress findings, DHCP servers, upgrade
  prestage backup files) is hidden from scoped users.
- Some totals stay estate-wide: a tenant's usage counts, IPAM source
  counts, a sync run's summary counters, a site's floor and placement
  counts.
