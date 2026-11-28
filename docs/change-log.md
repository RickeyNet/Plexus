# Change log

Plexus records every create, update and delete of the objects it tracks,
field by field: who made the change, when, from which request, and each
changed field's value before and after. Every object page shows its own
history in a **Changelog**, and **Change Management > Change Log** lists all
changes, with filters.

The change log is not the [audit log](audit-log.md). The audit log is a
tamper-evident record of actions in free text (sign-ins, settings, jobs and
more). The change log is the structured history of each object: it shows the
fields that changed, and it can be read per object.

## What is recorded

| Object type | `object_type` | Recorded when |
|---|---|---|
| Host | `host` | Created, edited (incl. device type, role, platform, serial, model and version, SNMP profile), moved to another group, deleted |
| Inventory group | `group` | Created, renamed or moved, deleted |
| IPAM prefix | `prefix` | A Plexus-defined prefix is created, edited or deleted |
| IP address | `ip_address` | A Plexus allocation is created, edited or deleted |
| VLAN | `vlan` | Created, edited, deleted |
| VRF | `vrf` | Created, edited, deleted |
| Credential | `credential` | Created, edited, deleted (name and username only) |
| Config backup | `config_backup` | Captured, deleted (metadata only) |
| Job | `job` | Launched, started, finished, cancelled |
| Region, site, tenant group, tenant | `region`, `site`, `tenant_group`, `tenant` | Created, edited (incl. a move to another parent), deleted ([locations-and-tenancy.md](locations-and-tenancy.md)) |

Changes are recorded in the database layer, so a change made through the
web UI, the REST API, a job, discovery, an import or an AI tool is recorded
the same way. A change made by a request names its user; a change made by
background work names `system`.

**Secrets are never recorded.** Credential passwords and enable secrets,
config backup text and job inputs are left out before anything is stored,
and any other field whose name looks secret (`password`, `secret`, `token`,
`api_key`, `authorization`) is masked as `***`.

Not recorded: objects synced from an external IPAM source (they are
replaced in bulk by each sync), a host's poll status and last-seen time,
and the VRF name rewritten on prefixes and addresses when a VRF is renamed
(the VRF's own rename is recorded).

## Each entry

| Field | Meaning |
|---|---|
| `action` | `create`, `update` or `delete` |
| `user` | Who made the change; `system` for background work, `api-token` for the server API token |
| `changed_at` | UTC time, `YYYY-MM-DD HH:MM:SS` |
| `correlation_id` | The request's `X-Correlation-ID` (the client's when it is 1 to 128 letters, digits, `.`, `_`, `:` or `-`, else generated); use it to find the request in the server logs and the audit log. Empty for background work |
| `object_label` | The object's name at the time (hostname, group name, subnet, address, `vid name` of a VLAN, VRF name). It stays readable after the object is deleted |
| `changes` | For an update: `{"field": {"before": x, "after": y}}` for each changed field |
| `before`, `after` | The object before and after the change: `before` is empty for a create, `after` for a delete |

An update that changes nothing (a save with the same values) is not
recorded.

## Who can see what

A user sees the changes of the object types they can read elsewhere:

| Object types | Needs |
|---|---|
| Hosts, inventory groups | `inventory` |
| Prefixes, IP addresses, VLANs, VRFs | `ipam` |
| Config backups | `config-backups` |
| Jobs | `jobs` |
| Regions, sites, tenant groups, tenants | `organization` |
| Credentials | Admin (credentials belong to their owners) |

A user whose access group is limited to selected inventory groups
([object-permissions.md](object-permissions.md)) sees only the changes of
hosts, groups and config backups in the groups they can read. The group is
the one the object belonged to after the change (before it, for a delete),
so a host moved out of the user's groups drops out of their view.

## Where to find it

- **Device detail > Changelog**: the history of that host.
- **IPAM > VLANs** and **IPAM > VRFs**: the detail panel of a VLAN or VRF
  ends with its changelog.
- **IPAM > Subnets**: the drilldown of a subnet ends with the changelog of
  the Plexus-defined prefix of that CIDR.
- **Inventory**: a group's **⋮** menu > **Changelog**.
- **Change Management > Change Log**: every change you may read, newest
  first, filtered by object type, action, user and date.

## API

Both endpoints need a signed-in user (or the server API token) and apply the
rules above.

`GET /api/changes` lists changes, newest first:

| Parameter | Meaning |
|---|---|
| `object_type` | One type from the table above |
| `object_id` | The object's id |
| `object_label` | The exact label, e.g. a prefix's CIDR `198.51.100.0/24` |
| `user` | The exact username |
| `action` | `create`, `update` or `delete` |
| `since`, `until` | ISO 8601 date or date-time (UTC), inclusive; a date-only `until` covers the whole day |
| `limit` | 1 to 500, default 50 |
| `offset` | Rows to skip, default 0 |

`GET /api/changes/{object_type}/{object_id}` is the history of one object
and takes the same `user`, `action`, `since`, `until`, `limit` and `offset`.

Answer:

```json
{
  "changes": [
    {
      "id": 41,
      "object_type": "host",
      "object_id": "12",
      "object_label": "edge-r2",
      "action": "update",
      "user": "alice",
      "correlation_id": "9f2c41aa07d3be10",
      "changed_at": "2026-01-02 03:04:05",
      "changes": {"hostname": {"before": "edge-r1", "after": "edge-r2"}},
      "before": {"id": 12, "hostname": "edge-r1", "ip_address": "192.0.2.10"},
      "after": {"id": 12, "hostname": "edge-r2", "ip_address": "192.0.2.10"}
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0,
  "object_types": ["host", "group"]
}
```

`object_types` lists the types this caller may read. A type the caller may
not read answers `403`; an unknown type, action or date answers `400`.

## Retention

Changes older than the change log retention are deleted every hour. Set it
under **Settings > System > Change log** (1 to 3650 days, default 90). It is
stored in the auth configuration as `change_log_retention_days`
(`PUT /api/admin/auth-config`; a request without the key keeps the saved
value).

## Storage

Table `object_changes` (migration 0095), indexed by object and time and by
time. The change hook (`routes/db/change_events.py`) feeds it from the same
events as the [event webhooks](webhooks.md); the recorder is
`netcontrol/routes/object_changes.py`.
