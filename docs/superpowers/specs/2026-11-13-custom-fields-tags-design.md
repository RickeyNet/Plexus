# Custom Fields and Tags: Design

Date: 2026-11-13
Status: implemented

## Goal

An operator who needs to record something Plexus has no column for (asset
owner, circuit id, support contract end date, "pci-scope") can do it without
a code change, on the three objects people ask about most: hosts, inventory
groups and IPAM prefixes.

Success means: an admin defines a field or a tag once, any user who can edit
the object fills it in, and the value is visible on the object, usable as a
filter in the Inventory and IPAM lists, present in the host CSV export and
readable and writable through the REST API.

## Decisions made

| Topic | Decision |
|---|---|
| Scope of v1 | Record, show, filter, export. No automation hooks. |
| Storage | Four generic tables keyed by `(object_type, object_key)`. No JSON columns, no per-object join tables. |
| Object types | `host`, `group`, `prefix`. The set is a constant, so adding a type later is one entry plus its UI. |
| Prefix identity | `subnet|vrf` (canonical CIDR, VRF name, empty VRF allowed), not the `ipam_prefixes` row id. |
| Field types | `text`, `number`, `boolean`, `date`, `url`, `select` (single choice). |
| Who defines | Admins define fields and manage tags. Users who can edit an object set its values and tags, and may create a new tag while tagging. |
| Tag colors | A fixed palette of named slots that the theme maps to colors, not free hex values. |

Why the prefix key is not a row id: every IPAM source sync deletes and
reinserts that source's `ipam_prefixes` rows (`replace_ipam_source_snapshot` in
`routes/db/ipam.py`), and the IPAM overview also lists subnets that have no
`ipam_prefixes` row at all (inferred from inventory, cloud and topology). A
`subnet|vrf` key survives resyncs, covers every subnet the IPAM page shows,
and gives one set of values for a prefix that several sources report.

## Out of scope

- Targeting playbooks or jobs by tag.
- Tags and fields in the MCP endpoint.
- Tags or fields on other objects (allocations, reservations, cloud
  resources, topology nodes, credentials).
- Importing vendor tags (AWS, Azure, GCP, Meraki) as Plexus tags.
- Multi-select fields, regex validation, numeric min/max, computed fields.
- Per-field permissions.

## Data model

Migration `0083_add_custom_fields_and_tags.py`, following the pattern of
migration 0082: the migration is the only definition of the tables (recent
migrations are not repeated in `SCHEMA`).

`tags`

| Column | Notes |
|---|---|
| `id` | primary key |
| `name` | 1 to 50 characters, trimmed. Unique index on `lower(name)`. |
| `color` | palette slot name, default `gray` |
| `description` | text, default empty |
| `created_by`, `created_at` | |

`tag_assignments`

| Column | Notes |
|---|---|
| `tag_id` | references `tags(id)`, cascade on delete |
| `object_type` | `host`, `group` or `prefix` |
| `object_key` | row id as text, or `subnet|vrf` |

Unique on `(tag_id, object_type, object_key)`. Index on
`(object_type, object_key)`.

`custom_fields`

| Column | Notes |
|---|---|
| `id` | primary key |
| `key` | `^[a-z][a-z0-9_]{0,49}$`, unique, fixed after creation |
| `label` | display name |
| `field_type` | one of the six types, fixed after creation |
| `choices_json` | list of strings, used by `select` only |
| `object_types_json` | which of the three object types the field applies to |
| `required` | 0 or 1 |
| `default_value` | canonical text, or empty |
| `description` | help text shown under the input |
| `sort_order` | integer, display order |
| `created_by`, `created_at`, `updated_at` | |

`custom_field_values`

| Column | Notes |
|---|---|
| `field_id` | references `custom_fields(id)`, cascade on delete |
| `object_type`, `object_key` | as in `tag_assignments` |
| `value` | canonical text |

Unique on `(field_id, object_type, object_key)`. Index on
`(object_type, object_key)`.

Values are stored as canonical text so that equality filters behave the same
on SQLite and Postgres:

| Type | Stored form | Validation |
|---|---|---|
| `text` | as entered, trimmed | at most 1000 characters |
| `number` | decimal string without trailing zeros | finite number |
| `boolean` | `true` or `false` | |
| `date` | `YYYY-MM-DD` | real calendar date |
| `url` | as entered, trimmed | `http` or `https` scheme with a host |
| `select` | one of the choices | must be in `choices_json` |

An empty value deletes the row; there is no stored empty string.

## Rules

- **Required** is enforced when an object's custom data is saved: the save is
  rejected if a required field that applies to the object has no value and
  no default. It does not block unrelated edits (renaming a host, a
  discovery sync) and existing objects are not retroactively invalid.
- **Default** is shown prefilled in the form for an object that has no stored
  value. It is not written until the user saves.
- **Editing a definition**: label, description, required, default, sort
  order, choices and applicable object types can change. Key and type
  cannot. Removing a choice leaves stored values as they are; they display
  unchanged and must be replaced with a valid choice at the next save of
  that object. Removing an object type from a field deletes that field's
  values on objects of that type, after a confirmation that names the count.
- **Deleting** a field deletes its values; deleting a tag deletes its
  assignments. Both confirmations name the number of objects affected.
- **Object deletion**: deleting a host or a group deletes its tag
  assignments and field values in the same transaction. This covers
  `remove_host`, `bulk_delete_hosts` and `delete_group`, including the hosts
  a group delete removes by cascade (a group with sub-groups cannot be
  deleted, so there are no descendant groups to clean up). Prefix data is
  never purged automatically, since a prefix that disappears from one sync
  commonly returns in the next.
- **Moving a host** between groups keeps its tags and values (the key is the
  host id).

## Backend

`routes/db/custom_fields.py`, re-exported through the `routes/database.py`
facade like the other `routes/db` modules:

- Definitions: list, get, create, update, delete for fields and for tags
  (tag list includes a usage count per object type).
- `get_object_data(object_type, object_key)` returns `{tags, fields}`.
- `get_object_data_bulk(object_type, object_keys)` returns the same per key
  in two queries, for list endpoints.
- `set_object_data(object_type, object_key, tag_ids, values)` replaces both
  in one transaction.
- `bulk_update_tags(object_type, object_keys, add_tag_ids, remove_tag_ids)`.
- `find_object_keys(object_type, tags, field_filters)` returns the keys that
  carry all the given tags and match all the given field values.
- `purge_object_data(db, object_type, object_keys)` takes an open connection
  so the inventory delete functions call it inside their own transaction.
- `prefix_key(subnet, vrf)` builds the canonical key (network address
  normalised with `ipaddress`); the only place that format is defined.

Validation and canonicalisation of values live in one pure module,
`netcontrol/custom_fields.py` (`canonical_value(field, raw)` returns the
stored form or raises with a message naming the field), used by the API and
by tests directly.

`netcontrol/routes/custom_fields.py`:

| Route | Access | Purpose |
|---|---|---|
| `GET /api/custom-fields` | any signed-in user | definitions, optional `object_type=` |
| `POST /api/custom-fields`, `PUT`/`DELETE /api/custom-fields/{id}` | admin | manage definitions |
| `GET /api/tags` | any signed-in user | tags with usage counts |
| `POST /api/tags` | `inventory` feature or admin | create a tag |
| `PUT`/`DELETE /api/tags/{id}` | admin | rename, recolor, delete |
| `GET`/`PUT /api/hosts/{id}/custom-data` | `inventory` feature | a host's tags and values |
| `GET`/`PUT /api/inventory/{group_id}/custom-data` | `inventory` feature | a group's tags and values |
| `GET`/`PUT /api/ipam/prefix-custom-data?subnet=&vrf=` | read: `ipam` feature; write: `ipam.write` and admin | a prefix's tags and values |
| `POST /api/hosts/bulk-tags` | `inventory` feature | add and remove tags on many hosts |

Object routes carry the same access as the inventory and IPAM routers they
sit beside. Prefix writes are admin-only because every other IPAM write is. All writes
record an audit event the way the neighbouring inventory and IPAM routes do.
`PUT` bodies are `{"tag_ids": [...], "fields": {"<key>": <value>}}`; a
validation failure returns 400 with one message per field.

Changes to existing endpoints:

- `GET /api/inventory` returns `tags` and `custom_fields` on each group, and
  on each host when `include_hosts=true`. It accepts `tag=` (repeatable, all
  must match) and `cf.<key>=<value>`; with a filter, groups are returned
  with only their matching hosts when `include_hosts=true`, and only
  matching groups otherwise.
- `GET /api/inventory/{group_id}/hosts` returns the same per host and
  accepts the same filters.
- `GET /api/ipam/overview` and `GET /api/ipam/subnets/{subnet}` return
  `tags` and `custom_fields` per subnet; the overview accepts the same
  filters.
- `GET /api/inventory/export/csv` adds a `Tags` column (names joined with
  `; `) and one column per field that applies to hosts, in `sort_order`.

The inline data comes from `get_object_data_bulk`, so each list endpoint
gains two queries regardless of size.

`AUTHORIZATION_MATRIX.md` gains the new routes. `tools/coverage_gate.py`
gains floors for `netcontrol/custom_fields.py` and
`netcontrol/routes/custom_fields.py`.

## Frontend

Shared, under `src/components/` and `src/api/`:

- `api/customData.ts`: types and calls for definitions, tags and object
  data.
- `TagChips`: read-only chips for list rows and detail views.
- `TagPicker`: add and remove tags, with type-ahead and "Create tag" when no
  tag matches and the user may create one.
- `CustomFieldsForm`: renders one labelled input per applicable field by
  type, shows defaults, required markers and per-field errors.
- `CustomDataFilter`: a filter control listing tags and filterable fields
  (`select` and `boolean` as choices, the rest as "has value").

Used in:

- `pages/Inventory/HostModal.tsx` and `GroupModal.tsx`: a "Tags and custom
  fields" section. Saved with the object: the modal saves the host or group,
  then its custom data.
- `pages/Inventory/Inventory.tsx`: chips on group headers and host rows,
  `CustomDataFilter` beside the search box, and "Add tags" / "Remove tags"
  in the bulk action bar for selected hosts.
- `pages/Ipam/Ipam.tsx`: chips on subnet rows, the form in the subnet detail
  view, `CustomDataFilter` beside the existing filters.
- `pages/Settings/`: a new "Custom Fields and Tags" tab (admin) with two
  tables, definitions and tags, each with create, edit and delete.

List filtering in the UI is done in the browser over the inline data, the
way the Inventory and IPAM search boxes already work; the server filters
exist for API clients.

## Testing

Backend:

- `tests/test_custom_fields_db.py`: definition CRUD, key and type rules,
  case-insensitive tag uniqueness, set and get of object data, bulk tag
  updates, `find_object_keys`, purge on host, bulk host and group delete
  (including the group's cascaded hosts), and prefix data
  surviving `replace_ipam_source_snapshot`.
- `tests/test_custom_fields_validation.py`: `canonical_value` for each type,
  valid and invalid.
- `tests/test_custom_fields_api.py`: access per route (anonymous, user
  without the feature, user with it, admin), required and default
  behaviour, list endpoints returning inline data, `tag=` and `cf.` filters,
  CSV columns, audit events.

Frontend (Vitest): `TagPicker`, `CustomFieldsForm` (each type, required,
errors) and the filter predicate used by `CustomDataFilter`.

CI steps that cover the change: `ruff check`, `mypy netcontrol templates`,
`bandit`, the `pytest` run with the coverage gates, and in the frontend job
`npm run lint`, `npm run typecheck`, `npm test`, `npm run build`. No new
dependency, so `requirements*.txt`, lock files and the workflow's install
steps are unchanged.

All sample data in tests and docs is invented and uses the documentation
address ranges.

## Documentation

- `docs/custom-fields-and-tags.md`: what the feature does, the field types,
  who can do what, the API with examples.
- A line in the README feature list.
