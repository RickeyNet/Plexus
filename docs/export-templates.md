# Export Templates

An export template turns a list of objects into a file in your own format: a
CSV another tool imports, a block of configuration, a hosts file, a report.
Each template is a [Jinja2](https://jinja.palletsprojects.com/) template bound
to one object type. It appears in the **Export** menu of that type's list, and
renders only the objects the person exporting may see.

Admins manage templates under **Settings > Data model > Export Templates**.

## Object types

| Object type | Key | Export menu | Read with feature | Filters a render takes |
|-------------|-----|-------------|-------------------|------------------------|
| Hosts | `host` | Inventory ("Export template") | `inventory` | `group_id`, the device filters (`manufacturer_id`, `device_type_id`, `role_id`, `lifecycle_status_id`, `site_id`, `tenant_id`, `region_id`), `tag`, `cf.<key>` |
| IPAM prefixes | `prefix` | IPAM ("Export prefixes") | `ipam` | `status`, `vrf`, `tag`, `cf.<key>` |
| IPAM IP addresses | `ip_address` | IPAM ("Export addresses") | `ipam` | `prefix` (the prefix's subnet), `status` |
| VLANs | `vlan` | IPAM > VLANs | `ipam` | `site_id` (an id or `none`), `vid`, `vlan_group_id`, `tag`, `cf.<key>` |
| Circuits | `circuit` | Circuits | `circuits` | `provider_id`, `circuit_type_id`, `status`, `tenant_id`, `site_id`, `host_id`, `q`, `tag`, `cf.<key>` |
| Sites | `site` | Organization > Sites | `organization` | `tag`, `cf.<key>` |

The objects come from the same list or export the type's own page uses, so
the filters behave as they do there. Hosts are the rows of the inventory CSV
export (group path, platform, device model names, tags and custom fields);
VLANs, circuits and sites are the rows of their list endpoints.

## What a template sees

| Variable | Value |
|----------|-------|
| `queryset` | The objects, a list of dicts. Each has the fields listed under the template editor (for hosts: `id`, `group_id`, `hostname`, `ip_address`, `model`, `software_version`, `platform`, `status`, `group`, `manufacturer`, `device_type`, `role`, `lifecycle_status`, `site`, `location_detail`, `tags`, `custom_fields`) |
| `now` | The UTC time, to the second (`{{ now.strftime('%Y-%m-%d') }}`) |
| `object_type` | The template's object type key |

The filters of intended configuration templates work here too: `netmask`,
`wildcard`, `network`, `prefixlen`, `nth_host` and `ip`.

## Fields of a template

- **Name**: unique per object type, ignoring case. It also names the file
  (characters other than letters, digits, `.`, `_` and `-` become `_`).
- **Object type**: one of the keys above.
- **Description**: shown in the Export menu.
- **MIME type**: the file's media type, `text/plain` by default (`text/csv`,
  `application/json`, `application/yaml` ...). The response adds
  `charset=utf-8`.
- **File extension**: without the dot (`csv`, `txt`, `cfg`); may be empty.
- **Download as a file**: on, the browser saves the file; off, it shows it.

## Examples

### Hosts as CSV

Name `hosts csv`, object type Hosts, MIME type `text/csv`, extension `csv`:

```jinja
hostname,ip_address,platform,site,tags
{% for h in queryset %}
{{ h.hostname }},{{ h.ip_address }},{{ h.platform }},{{ h.site }},{{ h.tags | join(';') }}
{% endfor %}
```

Rendered:

```text
hostname,ip_address,platform,site,tags
core-1,192.0.2.1,cisco_ios,Branch 1,core
edge-1,198.51.100.1,cisco_ios,Branch 2,edge;wan
```

Values that may hold a comma or a quote should be quoted, for example
`"{{ h.location_detail | replace('"', '""') }}"`.

### A VLAN configuration snippet

Name `vlan database`, object type VLANs, MIME type `text/plain`, extension
`cfg`:

```jinja
! Generated {{ now }} by Plexus
{% for v in queryset %}
vlan {{ v.vid }}
 name {{ v.name or ('VLAN' ~ v.vid) }}
{% endfor %}
```

Exported from IPAM > VLANs with the site filter set to one site, it renders
only that site's VLANs.

### A hosts file of IP addresses

Object type IPAM IP addresses, extension `txt`:

```jinja
{% for a in queryset if a.dns_name %}
{{ a.address }}  {{ a.dns_name }}
{% endfor %}
```

## Rendering and limits

Templates render in the same sandbox as intended configuration templates
(see [Intended Configuration](intended-config.md)): no access to Python
internals, files, the network or processes. A render stops with an error
when the output passes 1,048,576 characters, a `range` passes 10,000 items,
or the template runs 5 seconds without producing output.

A template that fails to render answers `400` with the message and the line,
for example `{"message": "The template did not render: 'dict object' has no
attribute 'nme'", "line": 3}`. Saving a template with a syntax error is
refused the same way.

A rendered file is served with `Content-Security-Policy: default-src 'none';
sandbox`, so an HTML or SVG export opened in the browser runs no script.

## Access

- Any signed-in user lists and reads the templates of the object types whose
  feature they hold, and renders them. A render returns only the objects
  their object scope allows (see [Object Permissions](object-permissions.md)).
  Accounts limited to selected inventory groups cannot export IPAM prefixes
  or IP addresses (`403`): those records carry no tenant to scope them by.
- Admins create, change, delete and preview templates.
- Writes and renders are written to the audit log under `export_templates`
  (`export_template_create`, `export_template_update`,
  `export_template_delete`, `export_template_render` with the object count).

## API

| Method | Path | Who | What |
|--------|------|-----|------|
| GET | `/api/export-templates` (`?object_type=`) | signed in | The templates of the types the caller reads |
| GET | `/api/export-templates/object-types` | signed in | Each type with its filters, fields and `readable` |
| GET | `/api/export-templates/{id}` | signed in | One template (404 when its type is not readable) |
| GET | `/api/export-templates/{id}/render?<filters>` | signed in | The rendered file |
| POST | `/api/export-templates` | admin | Create |
| PUT | `/api/export-templates/{id}` | admin | Replace |
| DELETE | `/api/export-templates/{id}` | admin | Delete |
| POST | `/api/export-templates/preview?<filters>` | admin | Render unsaved text with the first `limit` objects (default 20, at most 1000); returns `output`, `error`, `count` and `total` and stores nothing |

Create body:

```json
{
  "name": "hosts csv",
  "object_type": "host",
  "description": "Every host for the CMDB import",
  "template_text": "hostname,ip\n{% for h in queryset %}{{ h.hostname }},{{ h.ip_address }}\n{% endfor %}",
  "mime_type": "text/csv",
  "file_extension": "csv",
  "as_attachment": true
}
```

Render with filters:

```bash
curl -b cookies.txt -o hosts.csv \
  "https://plexus.example.com/api/export-templates/1/render?group_id=4&tag=core"
```
