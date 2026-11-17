# Dynamic groups

A dynamic group is a named, saved host filter. It does not hold a list of
hosts: each time it is used it resolves to the hosts that match its filter
at that moment. Define "every access switch at site X" once and reuse it as
a job target; a switch added to that site tomorrow is included the next time
the group is used.

Dynamic groups live on the Inventory page (**Dynamic Groups** in the page
header). The editor shows the hosts the filter matches as you build it.
**Save as dynamic group**, next to the inventory **Filter** menu, opens a new
dynamic group with the page's current search and filter already filled in.

## Criteria

A host must match every criterion that is set (AND). The values within one
criterion are alternatives (OR), except tags, which can require all or any of
the chosen tags.

| Criterion | Matches |
|---|---|
| Inventory groups | Hosts in the chosen groups; with **Include sub-groups** (the default) also in any group below them. |
| Manufacturer, device type, role, lifecycle status, site | The device model values (see [Device model](device-model.md)); **None** matches a host with no value. The same filters as the inventory Filter menu. |
| Region, tenant (`region_id`, `tenant_id`) | The region of the host's site, matching every region under the chosen one too, and the host's tenant (see [Locations and tenancy](locations-and-tenancy.md)); **None** matches a host with no region or no tenant. |
| Platforms | The host's driver (`device_type`, e.g. `cisco_ios`), ignoring case. |
| Status | The host's reachability status: `up`, `down` or `unknown`. |
| Tags | Hosts carrying all of the chosen tags (the inventory Filter menu's rule), or any of them. |
| Custom fields | Hosts holding the value (checked and normalised by the field, as in the inventory filter); `*` matches any value. See [Custom fields and tags](custom-fields-and-tags.md). |
| Hostname or IP | `contains` text (ignoring case), or a regular expression matched against the hostname or the IP address. |
| IP within prefixes | Hosts whose IP address is inside one of the networks, e.g. `192.0.2.0/24`, `2001:db8::/32`. |

Regular expressions run on RE2, like config search and compliance patterns,
so a pattern can never stall the server. RE2 has no lookarounds (`(?=`,
`(?!`, `(?<=`, `(?<!`) or backreferences (`\1`); a pattern using them is
refused when the group is saved or previewed.

A dynamic group needs at least one criterion: an empty filter is refused so
that a job never targets every host by accident.

## Object scope

Members and previews are always resolved among the hosts the caller may read
(see [Object permissions](object-permissions.md)). A user
limited to selected inventory groups sees only their own hosts in any dynamic
group, whoever defined it, and an inventory group outside their scope counts
as unknown in a filter they preview.

Definitions are shared. Users limited to selected inventory groups can list,
view and use dynamic groups but cannot create, change or delete them: a
dynamic group can be a job target, and a limited user must not be able to
change what another user's job runs against.

## Using a dynamic group

- **Jobs**: in **Launch Job**, pick a dynamic group instead of hosts. The job
  stores the dynamic group, not a host list, and resolves it when the queue
  starts the job, within the object scope of the user who launched it (the
  server API token is unrestricted; a launcher whose account no longer exists
  gets no hosts). Retry and re-run resolve it again. Deleting a dynamic group
  leaves jobs that targeted it with no target: they fail with "No hosts found"
  instead of running against something else. The job list shows the dynamic
  group's name.
- **GraphQL**: `dynamicGroups(name, limit, offset)` lists the groups (with the
  `inventory` feature); each has `members`, the hosts it matches now within
  the caller's scope.

Not (yet) available as targets:

- **Deployments** keep a fixed host list. A deployment is gated on its
  inventory group (maintenance windows, production approval) and rolls back
  on exactly the hosts it changed; a filter that resolves differently between
  execute and rollback would break that.
- **Config templates** have no targets of their own; they run through jobs,
  which do accept dynamic groups.
- **Access group grants** cannot name a dynamic group. Granting device access
  by a filter is a security-sensitive change (a host would gain or lose
  access when its tags or fields change) and is left as a follow-up.

## API

All routes need the `inventory` feature; changes also need `inventory.write`.

| Method and path | Purpose |
|---|---|
| `GET /api/dynamic-groups` | Every dynamic group with `member_count` (within your scope). |
| `POST /api/dynamic-groups` | Create: `{"name", "description", "filter"}`. 409 when the name is taken (ignoring case). |
| `GET /api/dynamic-groups/{id}` | One group with `member_count`. |
| `PUT /api/dynamic-groups/{id}` | Change the name, description or filter. |
| `DELETE /api/dynamic-groups/{id}` | Delete. |
| `GET /api/dynamic-groups/{id}/members` | `{"count", "hosts", "truncated"}`: the hosts it matches now. |
| `POST /api/dynamic-groups/preview` | `{"filter"}`: the hosts an unsaved filter matches, and the filter as it would be saved. |

A filter is a JSON object; every key is optional:

```json
{
  "groups": [12],
  "include_subgroups": true,
  "role_id": [3],
  "site_id": [5, null],
  "platforms": ["cisco_ios"],
  "statuses": ["up"],
  "tag_ids": [7, 8],
  "tag_match": "any",
  "custom_fields": {"tier": ["gold", "silver"], "owner": ["*"]},
  "search": {"mode": "regex", "value": "^access-sw[0-9]+\\.example\\.com$"},
  "prefixes": ["192.0.2.0/24"]
}
```

`manufacturer_id`, `device_type_id` and `lifecycle_status_id` take ids (or
`null` for "no value") like `role_id` and `site_id`. A filter that is not
valid answers 400 with a message per criterion in `detail.fields`.

Changes are recorded in the audit log (`dynamic_group.create`, `.update`,
`.delete`, category `inventory`).
