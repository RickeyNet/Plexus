# Custom Fields and Tags

Plexus lets you record information it has no built-in column for, on three
kinds of object:

- **Hosts** in the inventory
- **Inventory groups**
- **IPAM prefixes** (any subnet the IPAM page lists)

There are two tools for this:

- A **tag** is a short colored label such as `pci-scope` or `core`. An
  object can carry any number of tags.
- A **custom field** is a named, typed value such as "Owner" or "Contract
  end". An admin defines the field once; it then appears on every object of
  the types it applies to.

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

## Using it

- **Hosts and groups:** open the host or group dialog in Inventory. The
  "Tags and custom fields" section is below the built-in inputs.
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
- **Deleting a host or a group** deletes its tags and values with it.
  Moving a host to another group keeps them.
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

Every change is written to the audit log under the `custom_fields` category.

## CSV export

The inventory CSV export gains a `Tags` column (names joined with `; `) and
one column per field that applies to hosts, in field order.

## API

All routes are under the same session and CSRF rules as the rest of the
Plexus API. Examples use invented data.

### Definitions

```
GET    /api/custom-fields[?object_type=host|group|prefix]
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

An unknown field key, or a value the field's type does not accept, gives
`400`.
