# Locations and tenancy

Plexus models **where** things are and **who** they belong to:

- **Location hierarchy**: region > region ... > site > floor. Regions nest
  (Europe > Netherlands > Amsterdam) and hold sites; a site (the Floor Plans
  site) holds floors; a host belongs to one site.
- **Tenancy**: a tenant is the customer, business unit or department an
  object belongs to. Tenant groups file tenants and nest too
  (Customers > Retail). Hosts, sites, IPAM prefixes, IP addresses
  (allocations), VLANs and VRFs carry an optional tenant, and so do the
  records of later features that add a `tenant_id` column (circuits, virtual
  machines, routing objects, racks).

Open **Assets > Organization**. The page has four tabs:

| Tab | What it shows |
|-----|---------------|
| Regions | The region tree with the sites (status, facility, floors, hosts, tenant) under each region, and the sites in no region. Admins add regions (top level or **Add child**), edit, move and delete them. |
| Sites | Every site with its region, status, facility, time zone, tenant and host count. Selecting a site shows its change log. The add and edit dialog is the one the Floor Plans page uses. |
| Tenant groups | The group tree with each group's own tenants and the tenants of its sub-groups. |
| Tenants | Every tenant; selecting one shows its comments, how many objects of each kind it owns and its change log. |

## Regions

A region has a name, an optional parent region and a description. Names
are unique among the regions of the same parent, ignoring case (two
countries may each have a "North"). Moving a region under itself or under
one of its own descendants is refused (422 on `parent_id`); the parent
list in the dialog leaves those out.

A region that still holds child regions or sites cannot be deleted (409
naming what it holds): move or delete them first.

## Sites

Sites are the Floor Plans sites (`geo_sites`) with these fields added:

| Field | Values |
|-------|--------|
| Region | Any region, or none. |
| Status | `active` (default), `planned`, `staging`, `decommissioning`, `retired`. |
| Facility | Free text up to 100 characters: the data center or building. |
| Time zone | An IANA time zone name such as `Europe/Amsterdam` (checked against the IANA database the server ships with, the `tzdata` package), or empty. |
| Tenant | Any tenant, or none. |

An unknown status, time zone, region or tenant answers 422 with the field
named, shown under that field in the dialog. Sites are written through
`/api/geo/sites`, so creating or changing one needs the Floor Plans feature
(admins have every feature).

## Tenants and tenant groups

A tenant has a unique name (ignoring case), an optional group, a description
and comments. A tenant group has a unique name, an optional parent group and
a description; cycles are refused like for regions. A group that has child
groups cannot be deleted (409); deleting a group leaves its tenants in no
group.

Deleting a tenant keeps everything it owned and clears their tenant. The
tenant detail counts what it owns per kind: hosts, sites, prefixes, IP
addresses, VLANs and VRFs, plus every other table with a `tenant_id`
column. Those tables are discovered from the database schema, so the records
of features added later are counted without a code change.

## Assigning a tenant

| Object | Where |
|--------|-------|
| Host | Host dialog (next to the site) and the inventory **Bulk edit** (`tenant_id` in `set`). |
| Site | Site dialog (Floor Plans or Organization > Sites). |
| Prefix | **Define a Subnet**; in a subnet's drill-down an admin changes the tenant of each prefix record of the subnet. |
| IP address | The subnet drill-down's **Add IP Allocation** form; its tenant shows on the allocation. |
| VLAN, VRF | The VLAN and VRF dialogs; the lists have a **Tenant** column. |

The tenant select lists tenants only for users with the `organization`
feature; a user without it sees the field only when the record already has
a tenant, read only.

## Filtering by region and tenant

The inventory list and dynamic groups filter hosts by tenant and by region:

- `tenant_id=<id>` (repeatable) keeps the hosts of those tenants;
  `tenant_id=none` the hosts with no tenant.
- `region_id=<id>` (repeatable) keeps the hosts whose site is in that region
  **or in any region under it**; `region_id=none` the hosts with no site or
  whose site is in no region.

On the Inventory page the **Filter** menu has a **Region** and a **Tenant**
facet; each host row carries `region_ids` (its site's region and every region
above it, nearest first) so the browser filter matches descendants the same
way. Dynamic group definitions take the same `region_id` and `tenant_id`
criteria (see [dynamic-groups.md](dynamic-groups.md)).

## Access

| Action | Who |
|--------|-----|
| Read regions, the location tree, sites, tenant groups and tenants | Users with the `organization` feature (and admins). |
| Create, change or delete regions, tenant groups and tenants | Admins, like the other admin catalogues (device model, VRFs and VLANs). |
| Create, change or delete sites | Users with the `floor-plan` feature. |
| Set the tenant of a host | Users who may edit the host (inventory). |
| Set the tenant of a prefix, IP address, VLAN or VRF | Admins, like every IPAM write. |

An account limited to selected inventory groups sees the tenants of its
devices, the sites they stand in, and the tenants and sites its access
groups' scope rules grant; regions and tenant groups are read with counts
over those (see [object-level permissions](object-permissions.md)).

Every write is audited (category `organization`; sites `geolocation`).
Every create, update and delete of a region, site, tenant group and tenant
is in the change log and the event webhooks (object types `region`, `site`,
`tenant_group`, `tenant`), readable with the `organization` feature.

## API

See [api-reference.md](api-reference.md#locations-and-tenancy). In short:

- `GET /api/organization/regions`, `GET/PUT/DELETE /api/organization/regions/{id}`, `POST /api/organization/regions`
- `GET /api/organization/locations`: regions > sites > floors with host counts
- `GET /api/organization/sites`
- `GET/POST /api/organization/tenant-groups`, `GET/PUT/DELETE /api/organization/tenant-groups/{id}`
- `GET/POST /api/organization/tenants` (`group_id=` includes sub-groups), `GET/PUT/DELETE /api/organization/tenants/{id}`
- `PATCH /api/ipam/prefixes/{id}` and `PATCH /api/ipam/allocations/{id}` with `{"tenant_id": <id> | null}`

## Storage

Migration 0098 adds `regions`, `tenant_groups` and `tenants`, the site
columns `region_id`, `status`, `facility`, `time_zone` and `tenant_id`, and
`tenant_id` on `hosts`, `ipam_prefixes`, `ipam_allocations`, `vlans` and
`vrfs` (cleared when the tenant is deleted). Code: `routes/db/organization.py`
(storage), `netcontrol/organization.py` (rules), `netcontrol/routes/organization.py`
(API).
