# Custom Fields and Tags

Plexus lets you record information it has no built-in column for, on every
kind of object it keeps:

| Object type key | Object |
|---|---|
| `host`, `group` | Hosts and inventory groups |
| `prefix` | IPAM prefixes (any subnet the IPAM page lists) |
| `vrf`, `vlan` | VRFs and VLANs |
| `region`, `site`, `tenant` | Regions, sites and tenants |
| `manufacturer`, `device_type`, `device_role` | The device model catalogues |
| `circuit_provider`, `circuit` | Circuit providers and circuits |
| `cluster`, `virtual_machine` | Virtualization clusters and virtual machines |
| `autonomous_system`, `bgp_peering` | AS numbers and BGP peerings |
| `rack`, `cable` | DCIM racks and cables |

There are four tools for this:

- A **tag** is a short colored label such as `pci-scope` or `core`. An
  object can carry any number of tags.
- A **custom field** is a named, typed value such as "Owner" or "Contract
  end". An admin defines the field once; it then appears on every object of
  the types it applies to.
- A **computed field** is a read-only value an admin builds from an
  object's attributes with a template, such as a display name.
- A **relationship** links objects of two types, such as circuits to the
  VRFs they carry, one to one, one to many or many to many.

Tags and field values show on the object, can be used to filter the
Inventory and IPAM lists, are included in the inventory CSV export, and are
available through the REST API.

## Setting it up

An admin opens **Settings > Custom Fields & Tags**.

**New field** asks for:

| Setting | Meaning |
|---|---|
| Label | The name people see, for example "Owner". |
| Key | The name used in the API and in filters, for example `owner`. Lowercase letters, digits and `_`, starting with a letter, 50 characters at most. It cannot be changed later. |
| Type | One of the six types below. It cannot be changed later. |
| Applies to | Hosts, groups, IPAM prefixes, or any mix. |
| Choices | For the choice list type: one choice per line. |
| Required | A value must be given when the object's custom data is saved. |
| Default | Prefilled in the form for an object that has no value yet. |
| Description | Help text shown under the input. |
| Order | Position of the field in forms and in the CSV export. |

**New tag** asks for a name (50 characters at most, unique ignoring case), a
color and an optional description. Users who can edit the inventory can also
create a tag on the spot while tagging something.

## Field types

| Type | Accepts | Stored as |
|---|---|---|
| Text | Up to 1000 characters | The text, trimmed |
| Number | Any finite number | A plain decimal: `10.50` becomes `10.5` |
| Yes / No | Yes or no | `true` or `false` |
| Date | A calendar date | `YYYY-MM-DD` |
| URL | An `http` or `https` address | The address, trimmed |
| Choice list | One of the field's choices | The choice |

## Computed fields

**Settings > Custom Fields & Tags > Computed fields > New computed field**
asks for a label, a key (fixed once created), the object type (any but
prefix) and a Jinja2 template, rendered in the same sandbox as intended
configurations. The template sees:

| Name | Value |
|---|---|
| `obj` | The object's own attributes, as its table stores them (`obj.name`, `obj.id`, `obj.tenant_id` ...) |
| `custom_fields` | Its custom field values by key, typed |
| `tags` | Its tag names |

For example `{{ obj.name | upper }}-{{ custom_fields.owner }}`. The value is
trimmed and cut at 1,000 characters. A template that fails for an object
(an unknown attribute, a division by zero) shows an empty value and writes a
warning to the server log; it never fails the page or the API call. A
template that does not parse is refused when it is saved.

## Relationships

**Settings > Custom Fields & Tags > Relationships > New relationship** asks
for a label, a key (fixed once created), the source and destination object
types (any but prefix; both may be the same type) and the cardinality:

| Cardinality | Rule |
|---|---|
| Many to many | No limit |
| One to many | A destination has at most one source |
| One to one | Each object has at most one link of this relationship on each side |

Plexus checks the cardinality when a link is added and answers `409` when a
link would break it. The types and the cardinality are fixed once created;
the label and description can change. Deleting a relationship removes its
links.

Both sides list their links: the detail panel of a circuit shows the VRFs
it carries, and the VRF's panel shows the circuit.

## Using it

- **Hosts and groups:** open the host or group dialog in Inventory. The
  "Tags and custom fields" section is below the built-in inputs.
- **VRFs, VLANs, tenants, circuit providers, circuits, clusters, virtual
  machines, AS numbers, BGP peerings and racks:** the detail panel beside
  each list ends with the object's tags, custom fields, computed fields and
  relationships. **Edit tags and fields** and **Link** appear to users who
  may change that kind of object. Sites, regions, the device model
  catalogues and cables have no detail panel yet; use the API.
- **Several hosts at once:** select hosts in a group and choose **Tag…** to
  add or remove tags on all of them.
- **IPAM prefixes:** open a subnet on the IPAM page. The "Tags and Custom
  Fields" panel shows what is set; admins can edit it.
- **Filtering:** the **Filter** button beside the search box on the
  Inventory and IPAM pages narrows the list by tag and by field value.
  It combines with the text search.

## Rules worth knowing

- **Required** applies when an object's tags and custom fields are saved. It
  does not block other edits such as renaming a host, and objects that
  existed before the field was made required stay as they are until their
  custom data is next saved.
- **Defaults** are shown in the form, not written. The value is stored when
  someone saves the object's custom data.
- **Removing a choice** from a choice list leaves existing values alone.
  They keep showing, and have to be replaced with a current choice the next
  time that object's custom data is saved.
- **Removing an object type** from a field deletes the field's values on
  objects of that type. Plexus tells you how many and asks first.
- **Deleting a field or a tag** removes it from every object. The
  confirmation names how many objects are affected.
- **Deleting an object** of any type deletes its tags, values and
  relationship links with it, whichever way it is deleted (a database
  trigger, migration 0109). Moving a host to another group keeps them.
- **Changes to tags and values** are recorded in the object's change log
  (as `custom_fields` and `tags` in the diff) for the types the change log
  covers, and reach webhooks like any other update.
- **Validation rules** can check custom fields (`cf.<key>`) on the types
  they cover: hosts, groups, prefixes, VLANs and VRFs.
- **Prefixes are identified by subnet and VRF**, not by the source that
  reported them. Tags and values on a prefix therefore survive IPAM source
  resyncs, apply to the prefix whichever source lists it, and are kept if
  the prefix disappears for a while.

## Who can do what

| Action | Needs |
|---|---|
| See field definitions and tags | Any signed-in user |
| Create, change or delete a field | Admin |
| Rename, recolor or delete a tag | Admin |
| Create a tag | The Inventory feature |
| See or change a host's or group's tags and values | The Inventory feature |
| See a prefix's tags and values | The IPAM feature |
| Change a prefix's tags and values | Admin |
| See any other object's tags, values, computed fields and links | The feature that reads that object (VRFs and VLANs: IPAM; regions, sites and tenants: Organization; circuits: Circuits; clusters and VMs: Virtualization; AS numbers and peerings: Routing; racks and cables: DCIM; the device model catalogues: any signed-in user) |
| Change them, or link and unlink | The write feature of that object (`circuits.write`, `virtualization.write`, `routing.write`, `dcim.write`); admin for VRFs, VLANs, the organization and the device model catalogues |
| Link to another object | Also read access to the other object |
| Create, change or delete computed fields and relationships | Admin |

A user limited by object scope (inventory groups, plus tenant and site scope
rules) reaches exactly the objects the object scope
rules give them ([object permissions](object-permissions.md)), per object type: hosts and groups in their groups, a
circuit or VM by its tenant or site, and so on. Any other object answers
`404`, like an unknown id. Shared reference data with no tenant or site (the
device model catalogues, regions, providers, VRFs of no tenant) is readable
but only unrestricted users change its custom data (`403`). Relationship
lists leave out linked objects the user cannot read.

Every change is written to the audit log under the `custom_fields` category.

## CSV export

The inventory CSV export gains a `Tags` column (names joined with `; `) and
one column per field that applies to hosts, in field order. The same columns
set tags and values in a [bulk import](bulk-import.md).

## API

All routes are under the same session and CSRF rules as the rest of the
Plexus API. Examples use invented data.

### Definitions

```
GET    /api/custom-object-types
GET    /api/custom-fields[?object_type=<type key>]
POST   /api/custom-fields
PUT    /api/custom-fields/{id}[?confirm=true]
DELETE /api/custom-fields/{id}

GET    /api/tags
POST   /api/tags
PUT    /api/tags/{id}
DELETE /api/tags/{id}
```

Create a field:

```json
POST /api/custom-fields
{
  "key": "owner",
  "label": "Owner",
  "field_type": "select",
  "choices": ["network", "security"],
  "object_types": ["host", "prefix"],
  "required": false,
  "default_value": "",
  "description": "Team that answers for this object",
  "sort_order": 10
}
```

`PUT` takes the same body without `key` and `field_type`. If the change
removes an object type that still holds values, the answer is `409` with the
number affected; repeat the request with `?confirm=true` to go ahead.

Create a tag:

```json
POST /api/tags
{ "name": "pci-scope", "color": "red", "description": "In scope for PCI audits" }
```

Colors: `gray`, `red`, `orange`, `yellow`, `green`, `teal`, `blue`,
`purple`.

`GET /api/custom-object-types` lists every object type key with its label
and whether the caller may read (`readable`) and change (`writable`) it.

Computed fields and relationships:

```
GET    /api/computed-fields[?object_type=<type key>]
POST   /api/computed-fields
PUT    /api/computed-fields/{id}
DELETE /api/computed-fields/{id}
POST   /api/computed-fields/preview

GET    /api/relationships[?object_type=<type key>]
POST   /api/relationships
PUT    /api/relationships/{id}
DELETE /api/relationships/{id}
```

```json
POST /api/computed-fields
{ "key": "display", "label": "Display name", "object_type": "vrf", "template": "{{ obj.name | upper }}" }

POST /api/computed-fields/preview
{ "object_type": "vrf", "object_id": 7, "template": "{{ obj.rd }}" }
-> { "value": "65000:7", "error": null }

POST /api/relationships
{ "key": "carries", "label": "Carries", "source_type": "circuit", "destination_type": "vrf", "cardinality": "one-to-many" }
```

`PUT` on a computed field takes `label`, `template`, `description` and
`sort_order`; on a relationship `label` and `description`. The relationship
list carries `link_count`.

### An object's tags and values

```
GET /PUT  /api/hosts/{host_id}/custom-data
GET /PUT  /api/inventory/{group_id}/custom-data
GET /PUT  /api/ipam/prefix-custom-data?subnet=192.0.2.0/24&vrf=
POST      /api/hosts/bulk-tags
```

```json
GET /api/hosts/42/custom-data
{
  "tags": [{ "id": 3, "name": "pci-scope", "color": "red" }],
  "fields": { "owner": "network", "rack_units": 2, "monitored": true }
}
```

`PUT` replaces the object's tags and values in one step: the tags become
exactly `tag_ids`, and a field that is left out or sent as `null` is
cleared.

```json
PUT /api/hosts/42/custom-data
{ "tag_ids": [3, 5], "fields": { "owner": "security", "rack_units": 2, "monitored": null } }
```

A value that fails validation gives `400` and nothing is saved. The answer
names each field:

```json
{ "detail": { "message": "Check these fields: rack_units.", "fields": { "rack_units": "Rack units must be a number." } } }
```

A field key that does not exist or does not apply to the object, and a tag
id that does not exist, are rejected the same way.

Tag many hosts at once:

```json
POST /api/hosts/bulk-tags
{ "host_ids": [42, 43, 44], "add_tag_ids": [3], "remove_tag_ids": [5] }
```

At most 5,000 hosts per request. Host ids that do not exist are skipped; the
answer is `{"ok": true, "updated": <hosts changed>}`.

### Any other object

```
GET /PUT  /api/objects/{type}/{id}/custom-data
GET       /api/objects/{type}/lookup?q=
POST      /api/objects/{type}/{id}/relationships
DELETE    /api/objects/{type}/{id}/relationships/{link_id}
```

`{type}` is any type key but `prefix` (`host` and `group` work too, with the
same rules as their own routes). `PUT` takes the same body as the host
route. Both answer:

```json
GET /api/objects/vrf/7/custom-data
{
  "tags": [{ "id": 3, "name": "core", "color": "teal" }],
  "fields": { "owner": "network" },
  "computed_fields": { "display": "BLUE" },
  "relationships": [
    {
      "relationship": { "id": 2, "key": "carries", "label": "Carries", "source_type": "circuit",
                        "destination_type": "vrf", "cardinality": "one-to-many", "description": "" },
      "side": "destination",
      "peer_type": "circuit",
      "links": [{ "id": 11, "peer_id": 4, "peer_label": "CID-1001" }]
    }
  ]
}
```

Each relationship the type takes part in is listed (twice, once per side,
when both ends have the type). A link whose other object the caller cannot
read (its type's feature, or their object scope) is left out.

Link two objects (the object in the URL to `peer_id`; `side` is only needed
when both ends have the same type and defaults to `source`):

```json
POST /api/objects/circuit/4/relationships
{ "relationship_id": 2, "peer_id": 7 }
```

`lookup` returns up to 50 objects of the type whose name contains `q`, as
`{"id", "label"}`, for pickers.

### Lists and filters

`GET /api/inventory`, `GET /api/inventory/{group_id}/hosts`,
`GET /api/ipam/overview` and `GET /api/ipam/subnets/{subnet}` return `tags`
and `custom_fields` on each row. The subnet detail takes an optional `vrf=`
to name the prefix.

The inventory and overview lists accept filters:

- `tag=<name>` keeps rows that carry the tag. Repeat it to require several.
- `cf.<key>=<value>` keeps rows whose field has that value.

On `GET /api/inventory` the filters apply to hosts when `include_hosts=true`
(each group keeps its matching hosts, and groups left empty are dropped) and
to groups otherwise.

```
GET /api/inventory?include_hosts=true&tag=pci-scope&cf.owner=network
```

These lists of the other types also carry `tags` and `custom_fields` on
each row and take the same `tag=` and `cf.<key>=` filters:
`GET /api/ipam/vrfs`, `/api/ipam/vlans`, `/api/organization/regions`,
`/api/organization/sites`, `/api/organization/tenants`,
`/api/dcim/manufacturers`, `/api/dcim/device-types`, `/api/dcim/roles`,
`/api/circuits/providers`, `/api/circuits/circuits`,
`/api/virtualization/clusters`, `/api/virtualization/virtual-machines`,
`/api/routing/autonomous-systems`, `/api/routing/peerings`,
`/api/dcim/racks` and `/api/dcim/cables`. Their detail routes
(`GET .../{id}`, where one exists) add `tags`, `custom_fields` and
`computed_fields`.

An unknown field key, or a value the field's type does not accept, gives
`400`.

### Adding an object type

An object type is one entry in `_SPECS` in `netcontrol/custom_fields.py`
(key, label, table, read and write features), plus, in a migration, the two
statements `purge_trigger_sql(spec)` returns so deleting a row removes its
data. The generic API, the list helpers (`custom_list`,
`with_custom_data`) and the Settings pages pick the type up from there; the
frontend also needs its label in `OBJECT_TYPE_LABELS`
(`src/lib/customData.ts`) and its key in `ObjectType`
(`src/api/customData.ts`). Other code that serves objects, such as GraphQL,
reads everything for many objects at once with
`netcontrol.routes.custom_fields.object_custom_data_bulk`.
