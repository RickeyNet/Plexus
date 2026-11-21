# GraphQL API

Plexus serves a read-only GraphQL API at `/api/graphql`. One query can walk
the relations between inventory, IPAM and the other object models: a host
with its group, interfaces, VRF and VLAN records, custom fields, device type,
role, site, tenant, rack, ports, cables, circuits, clusters, BGP intent,
end-of-life notices and support contracts; a site with its racks, hosts and
circuits; a prefix with its child prefixes, addresses, VLAN and VRF. It reads
the same data as the REST API and follows the same access rules. There are
no mutations: changes go through the REST API.

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
  | `prefixes`, `prefix`, `ipAddresses`, `vlans`, `vrfs`, `namespaces`, `routeTargets`, `vlanGroups`, `rirs`, `aggregates`, and every `vrf` / `vlan` / `namespace` / `aggregate` relation | `ipam` |
  | `Host.latestConfigBackup` | `config-backups` |
  | `regions`, `sites`, `tenantGroups`, `tenants` and every `site` / `region` / `tenant` relation | `organization` |
  | `manufacturers`, `deviceTypes`, `deviceRoles`, `lifecycleStatuses`, `DeviceType.componentTemplates`, `Host.hardware` / `role` / `lifecycleStatus` | none beyond `graphql` (the catalogues are open to every signed-in user) |
  | `tags`, `customFields`, `computedFields` of a type | the feature of the type (as for custom data in REST) |
  | `circuitProviders`, `circuitTypes`, `circuits`, terminations | `circuits` |
  | `racks`, `rackRoles`, `cables`, `frontPorts`, `rearPorts`, `modules`, `powerPanels`, `powerFeeds`, `powerPorts`, `powerOutlets` | `dcim` |
  | `clusters`, `virtualMachines`, VM interfaces | `virtualization` |
  | `autonomousSystems`, `routingInstances`, `bgpPeerings` | `routing` |
  | `hardwareNotices`, `supportContracts` | `lifecycle` |
  | every relation that reaches a host (`Site.hosts`, `Rack.hosts`, `Cluster.hosts` ...) | `inventory` |

- **Object scope.** Hosts and inventory groups outside the caller's object
  scope ([Object permissions](object-permissions.md)) are left out of every
  list and relation; `host(id:)` and `group(id:)` answer `null` for them, and
  a group whose parent is hidden has `parent: null`. `graphql` is a
  scope-enforced feature, so a user limited to selected inventory groups
  may use the endpoint and sees only their groups' hosts.
  Every other model is filtered by the object scope model registry, as
  its REST routes are ([Object permissions](object-permissions.md)): a row
  is readable when any of its keys is reached by the caller's inventory
  groups (a host in them, the tenant of such a host, a site holding one) or
  by a scope rule of their access groups (a tenant or site, per model).
  So a circuit is readable through its tenant, the site or the host of a
  termination; a cable through a host or the site of either end; a
  cluster through its tenant, site or a member host, and its virtual
  machines with it; a contract through a device it covers; IPAM prefixes,
  addresses and route targets through their tenant, a VLAN group through
  its site or its region's sites. Rows with no key of shared reference
  models (regions, tenant groups, providers, circuit types, AS numbers,
  rack roles, VRFs, VLANs, namespaces, RIRs, aggregates, the device model
  catalogues, end-of-life notices, component templates) are read by every
  scoped caller. A relation to an object outside the scope reads `null`
  (or is left out of a list).
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
    children(limit: 20) { prefix }
    ipAddresses(limit: 50) { address dnsName status }
  }
}
```

A host's place in the world: its hardware, site, rack, cables, circuits,
cluster, BGP intent and lifecycle:

```graphql
query($id: Int!) {
  host(id: $id) {
    hostname
    hardware { model partNumber manufacturer { name } }
    role { name }
    lifecycleStatus { name }
    site { name region { name parent { name } } }
    tenant { name }
    rack { name } rackPosition rackFace
    cables { label a { type name host { hostname } } b { type name label } }
    circuitTerminations { termSide circuit { cid provider { name } } }
    clusters { name virtualMachines(limit: 20) { name vcpus } }
    bgpPeerings { remoteAddress remoteAsn remoteHost { hostname } }
    hardwareNotices { endOfSale endOfSupport }
    supportContracts { provider contractId endDate }
  }
}
```

A site with its racks, devices and circuits:

```graphql
{
  sites(name: "dc-a", limit: 5) {
    name status facility
    region { path }
    racks(limit: 20) { name uHeight hosts(limit: 50) { hostname } powerFeeds { name voltage amperage } }
    circuits(limit: 20) { cid status terminations { termSide host { hostname } } }
    clusters(limit: 10) { name hosts(limit: 20) { hostname } virtualMachines(limit: 50) { name primaryIp4 } }
  }
}
```

AS numbers with their routing instances and peerings, and contracts with
the devices they cover:

```graphql
{
  autonomousSystems(asn: 64512) {
    asn
    routingInstances { name host { hostname } peerings { remoteAddress remoteAsn status } }
  }
  supportContracts(provider: "example") { contractId endDate hosts(limit: 20) { hostname } }
}
```

IPAM namespaces, route targets and aggregates, with custom data:

```graphql
{
  vrfs(name: "BLUE") { name namespace { name } routeTargets { import { name } export { name } } }
  aggregates(contains: "192.0.2.0/24") { prefix rir { name } utilizationPct usedAddresses totalAddresses }
  sites(name: "dc-a") { name tags { name } customFields { key value } computedFields }
}
```

A group with its hosts, and VLAN and VRF records with their prefixes:

```graphql
{
  groups(name: "site-a") { path children { name } hosts(limit: 20) { hostname } }
  vlans(vid: 10) { name siteName prefixes(limit: 20) { prefix } }
  vrfs(name: "BLUE") { name prefixes(limit: 20) { prefix } }
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
| `regions`, `tenantGroups` | `name` (part); listed as a tree, parents first |
| `sites` | `name` (part), `regionId`, `tenantId`, `status` |
| `tenants` | `name` (part), `groupId` |
| `manufacturers`, `deviceRoles`, `lifecycleStatuses` | `name` (part) |
| `deviceTypes` | `model` (part), `manufacturerId`, `partNumber` (part) |
| `circuitProviders`, `circuitTypes` | `name` (part) |
| `circuits` | `cid` (part), `providerId`, `circuitTypeId`, `status`, `tenantId`, `siteId` and `hostId` (a termination there) |
| `racks` | `name` (part), `siteId`, `roleId`, `tenantId`, `status` |
| `rackRoles` | none |
| `cables` | `hostId` (either end), `status`, `type`, `tenantId` |
| `frontPorts`, `rearPorts` | `hostId`, `name` (part) |
| `modules` | `hostId`, `status`, `partNumber` (part) |
| `powerPanels` | `siteId` |
| `powerFeeds` | `powerPanelId`, `rackId`, `status` |
| `powerPorts`, `powerOutlets` | `hostId` |
| `clusters` | `name` (part), `siteId`, `tenantId` |
| `virtualMachines` | `name` (part), `clusterId`, `siteId` (the cluster's site), `tenantId`, `roleId`, `status` |
| `autonomousSystems` | `asn`, `tenantId` |
| `routingInstances` | `hostId`, `asn` (the local AS), `status` |
| `bgpPeerings` | `hostId`, `routingInstanceId`, `asn` (local or remote), `status` |
| `hardwareNotices` | `deviceTypeId`, `partNumber` (part) |
| `supportContracts` | `provider` (part), `hostId` (contracts covering the host) |
| `namespaces`, `rirs` | `name` (part) |
| `routeTargets` | `name` (part), `tenantId` |
| `vlanGroups` | `name` (part), `siteId`, `regionId` |
| `aggregates` | `rirId`, `tenantId`, `contains` (an address or network inside it) |
| `region(id:)`, `site(id:)`, `tenant(id:)`, `manufacturer(id:)`, `deviceType(id:)`, `circuit(id:)`, `rack(id:)`, `cable(id:)`, `cluster(id:)`, `virtualMachine(id:)`, `autonomousSystem(id:)`, `routingInstance(id:)`, `bgpPeering(id:)`, `hardwareNotice(id:)`, `supportContract(id:)` | one object, `null` when unknown or not readable |

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
- `Host` also: `hardware` (its device type), `role`, `lifecycleStatus`,
  `site`, `tenant`, `rack` with `rackPosition` and `rackFace`, `frontPorts`,
  `rearPorts`, `modules`, `powerPorts`, `powerOutlets`, `cables`,
  `circuitTerminations`, `clusters` (it is a hypervisor of),
  `routingInstances`, `bgpPeerings`, `hardwareNotices` (that apply to it by
  device type, part number or module), `supportContracts`.
- `Region`: `parent`, `children`, `sites`. `TenantGroup`: `parent`,
  `children`, `tenants`. `Tenant`: `group`, `sites`, `hosts`, `circuits`,
  `racks`, `clusters`, `virtualMachines`.
- `Site`: `region`, `tenant`, `hosts(name)`, `racks`, `powerPanels`,
  `circuits` (a termination there), `clusters`, `vlans`.
- `Manufacturer`: `deviceTypes`. `DeviceType`: `manufacturer`, `hosts`,
  `hardwareNotices`. `DeviceRole`: `hosts`, `virtualMachines`.
  `LifecycleStatus`: `hosts`.
- `CircuitProvider`: `circuits`, `networks`. `CircuitType`: `circuits`.
  `Circuit`: `provider`, `circuitType`, `tenant`, `terminations` (A then Z),
  each with `circuit`, `site`, `host`, `providerNetwork`.
- `Rack`: `site`, `role`, `tenant`, `hosts`, `powerFeeds`. `RackRole`:
  `racks`. `PowerPanel`: `site`, `powerFeeds`. `PowerFeed`: `powerPanel`,
  `rack`, `cable`. `FrontPort`: `host`, `rearPort`, `cable`. `RearPort`:
  `host`, `frontPorts`, `cable`. `Module`: `host`. `PowerPort`: `host`,
  `outlets`, `cable`. `PowerOutlet`: `host`, `powerPort`, `cable`.
- `Cable`: `a` and `b` (each a `CableEndpoint`: `type`, `recordId`, `name`,
  `label`, `host`), `tenant`.
- `Cluster`: `site`, `tenant`, `hosts` (the hypervisors),
  `virtualMachines(name)`. `VirtualMachine`: `cluster`, `role`, `tenant`,
  `interfaces` (each with `addresses`, `untaggedVlan`, `vrf`).
- `AutonomousSystem`: `tenant`, `routingInstances` (local AS), `peerings`
  (remote AS). `RoutingInstance`: `host`, `autonomousSystem`, `peerings`.
  `BgpPeering`: `routingInstance`, `host`, `remoteHost`,
  `remoteAutonomousSystem`.
- `HardwareNotice`: `deviceType`, `hosts`. `SupportContract`: `hosts`.
- IPAM model: `VRF.namespace`, `VRF.routeTargets` (`import`, `export`),
  `Prefix.namespace`, `Prefix.aggregate` (the most specific aggregate
  holding it), `VLAN.vlanGroup`, `VlanGroup` (`site`, `region`, `vlans`),
  `RIR.aggregates`, `Aggregate` (`rir`, `tenant`, with `prefixCount`,
  `totalAddresses` and `usedAddresses` as decimal text, `utilizationPct`),
  `RouteTarget.tenant`, `DeviceType.componentTemplates`.
- Custom data: every type that takes custom data (hosts, groups, prefixes,
  VRFs, VLANs, regions, sites, tenants, manufacturers, device types, device
  roles, circuit providers, circuits, clusters, virtual machines, AS
  numbers, BGP peerings, racks, cables) has `tags`, `customFields` (each
  value as its canonical text) and `computedFields` (a JSON object of each
  computed field's rendered text). They are read for all the objects of a
  query in one batch.

Nested lists of rows that can be many (`children`, `hosts`, `ipAddresses`,
`prefixes`, `sites`, `tenants`, `circuits`, `racks`, `clusters`,
`virtualMachines`, `deviceTypes`, `peerings`) take an optional `limit`
(none: at most `max_limit` rows, 1000 by default) and `offset`.

With introspection enabled, `{ __schema { types { name } } }` or GraphiQL
shows the full schema with descriptions.

### What is never exposed

Every type lists its fields explicitly, so credentials, passwords, encrypted
fields, SNMP communities and profiles, API keys, IPAM source settings and
`metadata_json`, cloud instance ids and configuration text are not part of
the schema and cannot be queried. Neither are a virtual machine's cloud
resource and account links, a cluster's cloud key, a circuit's billing link
or the created / updated stamps of the newer models. A backup exposes its metadata only
(`capturedAt`, `status`, `captureMethod`, `errorMessage`, `configLength`).

## Limits

Checked before a query runs; a query over a limit answers `400`.

| Limit | Default | Setting |
|-------|---------|---------|
| Query length | 20,000 characters | fixed |
| Depth (nested selections below the root field) | 8 | `max_depth` (2 to 20) |
| Aliases per document | 15 | `max_aliases` (0 to 200) |
| Estimated cost | 50,000 | `max_complexity` (100 to 1,000,000) |
| List items resolved while the query runs | 100,000 | twice `max_complexity` |
| Largest `limit` argument | 1000 | `max_limit` (10 to 10,000) |
| Introspection (`__schema`, `__type`) | off | `introspection` |

The cost estimate counts each object the query resolves: a list resolves as
many objects as its `limit` argument (a variable counts with its value, or
with its default in the operation when the request gives none), its default
when it has one (100 for root lists), else `max_limit` (1000 by default:
what a nested list returns without a `limit`), and multiplies what is
selected under it. A list that takes no `limit` (a host's interfaces, tags,
ports) counts 10. `groups(limit: 100) { hosts(limit: 50) { id } }` costs
100 + 100 × 50 = 5,100; `groups(limit: 100) { hosts { id } }` costs
100 + 100 × 1,000 and is over the default budget. Scalar fields are free. A few
fields cost 2 per object because each row takes more reads to build: cables
(both ends described), circuits (with their terminations) and support
contracts (with the hosts they cover), so `cables(limit: 100) { id }` costs
200. Give nested lists a `limit` to keep large queries under the budget.

The estimate is backed by a hard cap checked while the query runs: once the
lists it resolved hold more than twice `max_complexity` items in total
(100,000 by default), every further list answers `null` with a `Query result
is too large` error.

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
- Custom field filters (`cf.<key>=` in REST) and device model filters on
  `hosts` (manufacturer, role, lifecycle status) are not offered yet; use
  `tags`, or start from the catalogue (`deviceRoles(name: "core") { hosts(limit:
  100) { hostname } }`).
- Relationships between objects (custom data links) are not exposed.
- Floors, rack reservations, cluster types and groups, BGP peer groups and
  provider networks as root lists are not in the schema (their names are,
  as fields of the related objects). There is no platform catalogue: a
  virtual machine's `platform` is text.
- Prefixes come from the IPAM sources (local and synced); subnets the IPAM
  overview infers from inventory, cloud or topology data are not listed.
