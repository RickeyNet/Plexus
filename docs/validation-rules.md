# Data Validation Rules

Data validation rules let an administrator require that values follow the
organisation's conventions: hostnames match a naming pattern, VLAN ids stay in
a range, every IPAM prefix has a description, a custom field such as `owner`
is always set. Rules are enforced on the server, so the API, the web UI and
anything else that saves through the REST API are held to the same rules.

Manage them in **Settings > Validation Rules** (admins only) or through
`/api/validation-rules`.

## What a rule is

| Property | Meaning |
| --- | --- |
| Name | Unique, ignoring case. Shown in error reports. |
| Applies to | `host`, `group` (inventory group), `prefix` (IPAM subnet), `ip_address` (IPAM address), `vlan` or `vrf`. |
| Field | A field of the object (below) or a custom field as `cf.<key>`. |
| Rule | `regex`, `length`, `numeric` or `required`, with its parameters. |
| Error message | Shown under the field when a value breaks the rule. Empty: a message is written for you. |
| Enabled | Only enabled rules are checked. |
| Description | Free text for other admins. |

Fields a rule can check:

| Object | Fields |
| --- | --- |
| Host | `hostname`, `ip_address`, `device_type`, `vrf_name`, `vlan_id`, `aws_instance_id`, custom fields |
| Inventory group | `name`, `description`, custom fields |
| IPAM prefix | `subnet`, `vrf`, `description`, `notes`, custom fields |
| IPAM address | `address`, `hostname`, `description` |
| VLAN | `vid`, `name`, `description` |
| VRF | `name`, `rd`, `description` |

Custom fields are those defined in **Settings > Custom Fields & Tags** for the
object type (see [Custom Fields and Tags](custom-fields-and-tags.md)).

## Rule types

| Type | Parameters | A value passes when |
| --- | --- | --- |
| `regex` | `pattern` | the pattern matches the **whole** value, case sensitively |
| `length` | `min` and/or `max` (whole numbers) | its length in characters is in range |
| `numeric` | `min` and/or `max` | it is a number in range |
| `required` | none | it is not empty (spaces only counts as empty) |

An empty value passes every rule except `required`, so a pattern on an
optional field only constrains the values that are set. Add a `required`
rule on the same field to forbid empty values.

Patterns run on RE2 (`routes/user_regex.py`), the engine config search,
compliance and job run inputs already use: matching takes time linear in the
value, so no pattern can stall the server. RE2 has no lookarounds (`(?=`,
`(?!`, `(?<=`, `(?<!`) or backreferences (`\1`); a rule using them is
refused when it is saved, with the reason under the Pattern field. The
pattern is anchored for you: `sw-[0-9]+` accepts `sw-12` but not `sw-12a`.

Example (all values invented):

```json
{
  "name": "Hostname convention",
  "object_type": "host",
  "field": "hostname",
  "rule_type": "regex",
  "params": {"pattern": "[a-z]{3}-(sw|rtr|fw)-[0-9]{2}\\.example\\.com"},
  "error_message": "Use site-role-nn.example.com, e.g. nyc-sw-01.example.com."
}
```

## Where rules are enforced

| Write | Route |
| --- | --- |
| Host create (single and bulk add) and edit | `POST /api/inventory/{group_id}/hosts`, `POST /api/inventory/hosts/bulk`, `POST /api/inventory/{group_id}/hosts/bulk`, `PUT /api/hosts/{host_id}` |
| Inventory group create and edit | `POST /api/inventory`, `PUT /api/inventory/{group_id}` |
| IPAM prefix create | `POST /api/ipam/prefixes` |
| IPAM address create | `POST /api/ipam/subnets/{subnet}/allocations` |
| VLAN create and edit | `POST /api/ipam/vlans`, `PUT /api/ipam/vlans/{id}` |
| VRF create and edit | `POST /api/ipam/vrfs`, `PUT /api/ipam/vrfs/{id}` |
| Custom field values | `PUT /api/hosts/{id}/custom-data`, `PUT /api/inventory/{id}/custom-data`, `PUT /api/ipam/prefix-custom-data` |

On an edit the stored values merged with the change are checked: a field the
request leaves out keeps its stored value, and that value must pass too. So
once a rule is enabled, an object that breaks it can only be saved again
after it is fixed. Use **Check existing data** (below) to find such objects
first.

A host or group save checks the object's own fields; its custom field values
are checked when they are saved (the form saves them right after the object).
A custom data save checks every custom field of the object type, a field
left empty as an empty value, so `required` rules on custom fields work.

In a bulk host add, an entry that breaks a rule is listed under `errors` with
the rule's message and the other entries are added.

**Not enforced:** discovery and discovery sync, SNMP and SSH collection,
cloud and Meraki imports, configuration parsing (which creates VRFs) and
external IPAM syncs. These run unattended with nobody to show an error to, so
rejecting their writes would fail silently. Objects they create are listed by
Check existing data.

## The error response

A save that breaks rules is refused with HTTP 422 and nothing is written. The
body carries the shape the app uses for every field error, with the
violations beside it:

```json
{
  "ok": false,
  "error": {"code": "http_error", "message": "Use site-role-nn.example.com, e.g. nyc-sw-01.example.com."},
  "detail": {
    "message": "Use site-role-nn.example.com, e.g. nyc-sw-01.example.com.",
    "fields": {"hostname": "Use site-role-nn.example.com, e.g. nyc-sw-01.example.com."},
    "violations": [
      {"field": "hostname", "rule": "Hostname convention", "message": "Use site-role-nn.example.com, e.g. nyc-sw-01.example.com."}
    ]
  }
}
```

`fields` is keyed by the request's field name (a custom field by its bare key
on a custom data save). The host, group, subnet, address, VLAN and VRF forms
show each message under its field.

## Testing a rule

The rule dialog has a **Try a value** box that checks a value against the
rule as the form holds it, before it is saved. The API takes a saved rule or
an unsaved definition:

```
POST /api/validation-rules/test
{"rule_id": 3, "value": "nyc-sw-01.example.com"}
{"rule_type": "numeric", "params": {"min": 100, "max": 199}, "field": "vid", "value": "250"}
-> {"valid": false, "message": "vid must be a number from 100 to 199."}
```

## Check existing data

Rules apply to saves from the moment they are enabled; objects saved earlier,
or created by discovery and syncs, are not changed. **Check existing data**
(`GET /api/validation-rules/violations?object_type=host`, the type optional)
lists every stored object that breaks an enabled rule, with each problem.
Hosts and groups are limited to those the caller may see. Only prefixes and
addresses defined in Plexus (the built-in IPAM source) are checked, not ones
synced from an external IPAM. At most 1000 objects are listed (`truncated`
says when there were more).

## API

All under `/api/validation-rules`, admin only:

| Method and path | Purpose |
| --- | --- |
| `GET /api/validation-rules?object_type=` | List rules |
| `GET /api/validation-rules/fields` | Object types, rule types and the fields of each type, custom fields included |
| `POST /api/validation-rules` | Create (`name`, `object_type`, `field`, `rule_type`, `params`, `error_message`, `description`, `enabled`) |
| `GET /api/validation-rules/{id}` | One rule |
| `PUT /api/validation-rules/{id}` | Change; properties left out keep their value |
| `DELETE /api/validation-rules/{id}` | Delete |
| `POST /api/validation-rules/test` | Check a value against a rule |
| `GET /api/validation-rules/violations` | Check existing data |

An invalid rule answers 422 with `detail.fields` naming the property
(`params.pattern` for a pattern RE2 refuses); a duplicate name 409. Every
create, change and delete is written to the audit log (category
`validation_rules`).

## For developers

`netcontrol/data_validation.py` is the one entry point:

```python
async def validate_object(object_type: str, values: dict[str, Any], *, existing: dict | None = None) -> list[dict]
```

returns `[{"field", "rule", "message"}]` (empty: valid). `values` uses the
field names above and `cf.<key>` for custom fields; on an update pass the
stored values as `existing` (a `None` in `values` keeps the stored value). A
rule whose field is in neither is not checked, so pass every field you write.
`require_valid` raises `ValidationFailed` (carrying `violations`), `enforce`
raises the HTTP 422 above, and `validation_http_error` builds it from a list.

Enabled rules are cached in memory; the admin API clears the cache on every
change and it expires after 30 seconds, so other worker processes pick up a
change within that time. Rules are stored in the `validation_rules` table
(migration 0096, `routes/db/validation_rules.py`).
