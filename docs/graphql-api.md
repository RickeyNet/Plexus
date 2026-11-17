# GraphQL API

Plexus serves a read-only GraphQL API at `/api/graphql`. One query can walk
the relations between inventory and IPAM objects, for example a host with its
group, interfaces, interface addresses, VRF and VLAN records, custom fields
and the metadata of its latest configuration backup, or a prefix with its
child prefixes, addresses, VLAN and VRF. It reads the same data as the REST
API and follows the same access rules. There are no mutations: changes go
through the REST API.

## Access

- **Feature.** A user needs the **GraphQL API** feature (`graphql`), granted
  through an access group (Settings > Users and Access). Admins and the
  server API token (`APP_API_TOKEN`) always have it.
- **Per field.** Each field also needs the feature its REST counterpart
  needs. A field the caller may not read answers `null` with an
  `Access denied for feature 'X'` error; the rest of the query still answers.

  | Fields | Feature |
  |--------|---------|
  | `hosts`, `host`, `groups`, `group`, their tags and custom fields | `inventory` |
  | `Host.interfaces`, `Host.interfaceAddresses`, `Host.vlans` | `reports` |
  | `prefixes`, `prefix`, `ipAddresses`, `vlans`, `vrfs`, and every `vrf` / `vlan` relation | `ipam` |
  | `Host.latestConfigBackup` | `config-backups` |

- **Object scope.** Hosts and inventory groups outside the caller's object
  scope ([Object permissions](object-permissions.md)) are left out of every
  list and relation; `host(id:)` and `group(id:)` answer `null` for them, and
  a group whose parent is hidden has `parent: null`. `graphql` is a
  scope-enforced feature, so a user limited to selected inventory groups
  may use the endpoint and sees only their groups' hosts.
  IPAM is not scope-enforced, so a scoped user never reads IPAM fields.
- **Authentication.** A browser session (cookie) or the server API token
  (`X-API-Token` or `Authorization: Bearer`). A session POST carries the
  `X-CSRF-Token` header like every other POST; the API token needs none.

## Sending a query

`POST /api/graphql` with a JSON body:

```json
{"query": "query($id: Int!) { host(id: $id) { hostname } }", "variables": {"id": 12}, "operationName": null}
```

```bash
curl -s https://plexus.example.com/api/graphql \
  -H "X-API-Token: $PLEXUS_API_TOKEN" -H "Content-Type: application/json" \
  -d '{"query": "{ hosts(group: \"site-a\", limit: 10) { hostname ipAddress } }"}'
```

The answer is `{"data": ..., "errors": [...]}`. A query that cannot run
(syntax error, unknown field, a limit exceeded, a mutation) answers `400`
with `data: null`; field errors answer `200` with the other fields filled.
Unexpected server errors are reported as `Internal error` without detail.
`GET /api/graphql` never runs a query.

### Examples

A host with its relations:

```graphql
query($id: Int!) {
  host(id: $id) {
    hostname
    ipAddress
    group { name path parent { name } }
    interfaces { name operState speedMbps addresses { address prefixLength vrfName } }
    interfaceAddresses { interface address role vrf { name rd } vlan { vid name } }
    vlans { vid name vlan { id siteName } }
    latestConfigBackup { capturedAt status configLength }
    tags { name }
    customFields { key value }
  }
}
```

A prefix tree with its addresses:

```graphql
{
  prefixes(within: "192.0.2.0/24", vrf: "BLUE") {
    prefix
    vrf { name rd }
    vlan { vid name }
    parent { prefix }
    children { prefix }
    ipAddresses(limit: 50) { address dnsName status }
  }
}
```

A group with its hosts, and VLAN and VRF records with their prefixes:

```graphql
{
  groups(name: "site-a") { path children { name } hosts(limit: 20) { hostname } }
  vlans(vid: 10) { name siteName prefixes { prefix } }
  vrfs(name: "BLUE") { name prefixes { prefix } }
}
```

## Schema

Root fields (filters combine with AND; every list takes `limit`, default
100, and `offset`):

| Field | Filters |
|-------|---------|
| `hosts` | `name` (part of the hostname, any case), `ip` (an address, or a network such as `198.51.100.0/24` to match hosts inside it), `groupId` (hosts directly in the group), `group` (group name or full path, any case), `deviceType`, `status`, `tags` (every tag, any case) |
| `host(id:)`, `group(id:)`, `prefix(id:)` | one object, `null` when unknown or not readable |
| `groups` | `name` (part of the name), `tags`; listed as a tree, parents first |
| `prefixes` | `prefix` (exact network), `within` (networks inside a network), `contains` (networks containing an address or network), `vrf` (`""` is the global VRF), `tags` |
| `ipAddresses` | `address`, `vrf` |
| `vlans` | `vid`, `name` (part), `siteId` |
| `vrfs` | `name` (part) |
| `dynamicGroups` | `name` (part); each has `members(limit, offset)`, the hosts its saved filter matches now within your scope (see [Dynamic groups](dynamic-groups.md)) |

Relations:

- `Host`: `group`, `interfaces` (each with its `addresses`),
  `interfaceAddresses` (each with `vrf` and `vlan` records), `vlans` (the
  VLANs the device defines, each with the `vlan` record it resolves to),
  `vrf` (the record of the host's management VRF), `latestConfigBackup`,
  `tags`, `customFields`.
- `Group`: `parent`, `children`, `hosts(name, limit, offset)`, `tags`,
  `customFields`.
- `Prefix`: `vrf`, `vlan` (the record its VLAN text names: a VLAN id at the
  prefix's site, else of no site, else the only one; or a unique VLAN name),
  `parent` and `children` (the nearest containing / directly contained
  prefixes of the same VRF), `ipAddresses` (the allocations of its IPAM
  source), `tags`, `customFields`.
- `VLAN`, `VRF`: `prefixes`.

Nested lists (`children`, `hosts`, `ipAddresses`, `prefixes`) take an
optional `limit` (none: every row) and `offset`.

With introspection enabled, `{ __schema { types { name } } }` or GraphiQL
shows the full schema with descriptions.

### What is never exposed

Every type lists its fields explicitly, so credentials, passwords, encrypted
fields, SNMP communities and profiles, API keys, IPAM source settings and
`metadata_json`, cloud instance ids and configuration text are not part of
the schema and cannot be queried. A backup exposes its metadata only
(`capturedAt`, `status`, `captureMethod`, `errorMessage`, `configLength`).

## Limits

Checked before a query runs; a query over a limit answers `400`.

| Limit | Default | Setting |
|-------|---------|---------|
| Query length | 20,000 characters | fixed |
| Depth (nested selections below the root field) | 8 | `max_depth` (2 to 20) |
| Aliases per document | 15 | `max_aliases` (0 to 200) |
| Estimated cost | 50,000 | `max_complexity` (100 to 1,000,000) |
| Largest `limit` argument | 1000 | `max_limit` (10 to 10,000) |
| Introspection (`__schema`, `__type`) | off | `introspection` |

The cost estimate counts each object the query resolves: a list resolves as
many objects as its `limit` argument (a variable counts with its value), its
default when it has one (100 for root lists) or 10 when it has none, and
multiplies what is selected under it. `groups(limit: 100) { hosts(limit: 50)
{ id } }` costs 100 + 100 × 50 = 5,100. Scalar fields are free. Give nested
lists a `limit` to keep large queries under the budget.

Reads are batched: each relation is loaded for all the objects of a step in
one query (data loaders), so a nested query runs a fixed number of database
queries whatever the number of rows.

## Settings and GraphiQL

`GET /api/admin/graphql/settings` and `PUT /api/admin/graphql/settings`
(admin, audited as `graphql` / `settings_update`) read and change the
`graphiql`, `introspection` and limit settings above; `422` for an unknown
key or a value out of bounds.

With `graphiql` on, `GET /api/graphql` (feature `graphql`) serves the
GraphiQL explorer. It loads GraphiQL and React from unpkg.com with pinned
versions and Subresource Integrity under its own Content-Security-Policy, so
the browser needs to reach unpkg.com (not available on air-gapped installs).
GraphiQL needs `introspection` on for completion and the docs pane. With
`graphiql` off it answers `404`.

## Known gaps

- Read only: no mutations or subscriptions.
- Custom field filters (`cf.<key>=` in REST) and device model filters
  (manufacturer, role, lifecycle status) are not offered yet; use `tags`.
- Prefixes come from the IPAM sources (local and synced); subnets the IPAM
  overview infers from inventory, cloud or topology data are not listed.
