# API Reference

### Help
The user guides shown under **Help**: the pages of `netcontrol/docs_catalog.py` and the front page `wiki/Home.md`. Any signed-in user.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/help` | `{home, sections: [{title, pages: [{name, title}]}]}`; a page whose file this install does not ship is left out |
| GET    | `/api/help/search?q=` | `{query, results: [{name, title, section, snippet}]}`: up to 25 pages holding every word of `q` (case-insensitive), pages whose title holds them first |
| GET    | `/api/help/pages/{name}` | `{name, title, section, source, source_url, headings: [{id, text, level}], html}`. The HTML escapes any HTML in the source; links between guides are `/help/<name>#<heading>`, links to other repository files go to GitHub. `404` for an unknown name |

### Authentication and single sign-on
OpenID Connect single sign-on next to the password login. See [sso-oidc.md](sso-oidc.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/auth/status` | Signed out, the body also holds `sso: {oidc: {enabled, label, primary}}` (`enabled` only when SSO is on and an issuer and client id are set). A cookie every other route refuses (deleted user, revoked, past the 24 h cap or idle) answers `authenticated: false` and is deleted. A user who must change their password gets `authenticated: true` with `must_change_password: true` |
| POST   | `/api/auth/logout` | Always `200 {ok: true}` and deletes the cookie. A valid session is also revoked on the server, which ends every session of that account (all browsers and devices); audited `logout`. A missing, invalid, expired or revoked cookie revokes nothing |
| GET    | `/api/auth/oidc/login?next=/path` | Public. Redirects (302) to the provider's authorization endpoint with `state`, `nonce` and an S256 `code_challenge`, setting the signed `oidc_tx` cookie (HttpOnly, SameSite=Lax, 600 s, path `/api/auth/oidc`). `next` is kept only when it is a same-site path, else `/`. When SSO is off or discovery fails, 303 to `/login?sso_error=disabled` or `provider`; `setup` when OIDC is enabled but no redirect URI is stored. The redirect URI sent is always the stored one, never derived from the request |
| GET    | `/api/auth/oidc/callback` | Public. On success sets the session cookie, drops `oidc_tx` and redirects (303) to `next`; audited `login.success` with `source=oidc`. On failure 303 to `/login?sso_error=<code>` with `code` one of `disabled`, `setup`, `state`, `provider`, `token`, `claims`, `account`, `denied`; a failure after the state check is audited `login.failure` naming the failed step and counted toward the per-IP login lockout; a request without the transaction cookie or while OIDC is off is logged only, and a state mismatch is audited (bounded per address) but not counted |
| GET    | `/api/admin/auth-config` | Admin. Includes `oidc` (see sso-oidc.md for the fields); `client_secret` is the mask when one is stored, else `""` |
| PUT    | `/api/admin/auth-config` | Admin. `oidc` is optional (omitted = keep the saved block); its `client_secret` set to the mask keeps the stored secret, `""` clears it (public client), any other value replaces it (stored encrypted). A blank `oidc.redirect_uri` is filled from the address of this request (scheme, host, `/api/auth/oidc/callback`) and stored; sign-in uses only the stored value. `400` when `oidc.enabled` and the issuer is empty or not https or the client id is empty, on a non-https `redirect_uri` (other than the value a blank one stores), more than 200 `group_mappings` or a `button_label` over 60 characters |
| POST   | `/api/admin/auth-config/oidc/test` | Admin. Optional body `{issuer, ca_cert_file}` (default: the saved values). Fetches discovery and the JWKS fresh. Returns `{ok, issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, algorithms, key_count, redirect_uri, configured, error}`. `redirect_uri` is the stored one; while none is stored, `configured` is false and `redirect_uri` is what a save would store |

### Object-level permissions
Access groups limited to selected inventory groups. See [object-permissions.md](object-permissions.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/auth/status` | Signed in, the body also holds `object_scope: {restricted, write_group_ids}` (ids expanded with sub-groups; empty when unrestricted). The login response carries the same field |
| GET    | `/api/admin/access-groups` | Admin. Each group carries `object_scope` (`all` or `groups`) and `inventory_scopes: [{inventory_group_id, can_write}]` |
| POST   | `/api/admin/access-groups` | Admin. Body `{name, description, feature_keys, object_scope?, inventory_scopes?}` (default `all`). Unknown inventory group id or `object_scope`: 400. With `all` the grants are ignored and cleared. Audited `access_group.create` |
| PUT    | `/api/admin/access-groups/{id}` | Admin. As create; `object_scope` left out keeps the scope and grants. Audited `access_group.update` with the scope change |
| DELETE | `/api/admin/access-groups/{id}` | Admin. Audited `access_group.delete` |
| GET    | `/api/admin/users` | Admin. Each user carries `object_scope_restricted` and `disabled` |
| PUT    | `/api/admin/users/{id}` | Admin. Body fields are optional: `username`, `display_name`, `role`, `session_never_expires`, `auth_provider`, `disabled`. `disabled: true` blocks every sign-in of the account, ends its sessions and refuses its MCP tokens; disabling your own account or the last enabled admin is refused (`400`). Audited `user.update` with what changed |

For a scoped user the inventory, config backup, config drift and intended configuration routes answer `404` (same body as an unknown id) for groups, hosts and records of hosts (backups, policies, baselines, snapshots, drift events, intended configurations, capture jobs) outside the read scope and `403 Read-only access to this inventory group` for writes to read-only ones (in the configuration modules: captures, checks, analyses, restores, reverts, status changes, baselines, deletes, policy changes and runs, generate). Lists, counts, summaries, searches, the CSV export, the backup ZIP download and the Ansible inventory hold readable rows only; `POST /api/intended-config/generate` with no ids acts on writable hosts only. Feature gates other than `inventory`, `config-backups` and `config-drift` answer `403`, and MCP tokens they own are refused with `403`.

### Dashboard
| Method | Endpoint         | Description                                          |
|--------|------------------|------------------------------------------------------|
| GET    | `/api/dashboard` | Stats for every holder of the `dashboard` feature; with `jobs` also recent jobs (a non-admin sees only their own); with `inventory` the inventory groups; with `monitoring` the monitoring summary, device health, open alerts and `topology`: entity counts by state (total, per provider, and `by_source`: one `{provider, org_ref, entity_type, up, degraded, down, unknown}` row per entity type of each source; the AWS, Azure and GCP accounts of one cloud share one `org_ref`) and the down / degraded integration entities, down first, newest first, at most 50 |
| GET    | `/api/health`    | Service health: `{ok, status}` for anyone (200 healthy, 503 degraded); uptime, counters/timing metrics and the database probe result only with a session or the API token. Callers share one database probe: a result is kept 2 seconds |
| GET    | `/api/version`   | Release number for anyone; the git SHA of the build only with a session or the API token |

### Inventory
| Method | Endpoint                      | Description                                      |
|--------|-------------------------------|--------------------------------------------------|
| GET    | `/api/inventory`              | List all groups (with host counts)               |
| POST   | `/api/inventory`              | Create group `{name, description}`               |
| GET    | `/api/inventory/{id}`         | Group detail with hosts                          |
| DELETE | `/api/inventory/{id}`         | Delete group and its hosts                       |
| GET    | `/api/inventory/{id}/hosts`   | List hosts in group                              |
| POST   | `/api/inventory/{id}/hosts`   | Add host `{hostname, ip_address, device_type, snmp_profile_id?}`; `snmp_profile_id` (default `""`: use the group's SNMP config) names the host's own SNMP profile; unknown: 400 `SNMP profile not found` |
| PUT    | `/api/hosts/{id}`             | Update a host `{hostname, ip_address, device_type, vrf_name?, vlan_id?, snmp_profile_id?, ...}`; `vrf_name`, `vlan_id` and `snmp_profile_id` are each left alone when absent or null and set (`""` clears) when sent |
| DELETE | `/api/hosts/{id}`             | Remove a host                                    |
| POST   | `/api/hosts/snmp-profile`     | `{host_ids, snmp_profile_id}`: give the hosts their own SNMP profile (`""`: back to the group's). Write access to every host. `{"ok": true, "updated": <n>}`; empty `host_ids` or an unknown profile: 400 |
| POST   | `/api/hosts/{id}/snmp-profile/test` | SNMP GET of the host's address with its effective SNMP config (own profile, else the group's). Write access to the host. `{success, target_ip, result?, error?}`, like the group test; 400 when SNMP is off for the host; 403 for a non-admin while the host's address awaits admin confirmation |
| POST   | `/api/admin/hosts/{id}/confirm-address` | Admin only. Confirm the host's address (`address_confirmed`), so shared secrets may go to it. Audited. `{ok, confirmed, already_confirmed}`; unknown host: 404 |
| POST   | `/api/admin/hosts/confirm-address` | Admin only. `{host_ids?, group_id?}`: confirm the addresses of those hosts and of every host of the group. Audited. `{ok, confirmed, already_confirmed}`; neither given: 400 |

Host rows carry `address_confirmed` (1: an admin or the API token set or confirmed the address; 0: a non-admin did, and no shared credential or SNMP secret is sent to it until an admin confirms it). They also carry `address_set_by`, the id of the user who last wrote the address, or null when no signed-in user did. Deferred work with a user's own credential (a scheduled backup or compliance scan, a syslog-triggered backup, a queued or approved job, a deployment executed or rolled back by someone other than the credential's owner) signs in only to a confirmed address or one the credential's owner set.

### VRFs, VLANs and interface addresses
Reads need the `ipam` feature, writes are admin only and audited (`network_objects`). See [vrfs-and-vlans.md](vrfs-and-vlans.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/ipam/vrfs` | `{"vrfs": [Vrf]}` by name. A Vrf: `id`, `name`, `rd`, `description`, `origin` (`manual`, `discovered`), `created_at`, `tenant_id`, `tenant_name`, `host_count`, `device_count`, `prefix_count`, `address_count` |
| POST   | `/api/ipam/vrfs` | `{name, rd?, description?, tenant_id?}`. `201` with the Vrf; `409` when a VRF has the name ignoring case |
| GET    | `/api/ipam/vrfs/{id}` | The Vrf plus `devices` (`host_id`, `hostname`, `interface_count`), `interfaces` (at most 2000 interface addresses), `truncated`, `prefixes` (`subnet`, `source`: the IPAM source's provider or `interface`) |
| PUT    | `/api/ipam/vrfs/{id}` | `{rd?, description?, tenant_id?}` (`tenant_id` null clears it); a `name` key gives `422` |
| DELETE | `/api/ipam/vrfs/{id}` | `{"ok": true}`; `409` with `detail = {message, affected}` while hosts, IPAM prefixes or allocations, interface addresses or devices use the name (`message` names them, `affected` is the total) |
| GET    | `/api/ipam/vlans` | `{"vlans": [Vlan]}` by site name then VLAN id; `site_id=<id>` or `site_id=none`, `vid=<n>`. A Vlan: `id`, `vid`, `name`, `site_id`, `site` (`{id, name}` or null), `description`, `origin`, `created_at`, `tenant_id`, `tenant_name`, `device_count`, `interface_count`, `prefix_count`, `name_mismatch` |
| POST   | `/api/ipam/vlans` | `{vid, name?, site_id?, description?, tenant_id?}`. `201` with the Vlan; `409` when the site (or no site) has the VLAN id; `400` with `detail.fields.site_id` for an unknown site |
| GET    | `/api/ipam/vlans/{id}` | The Vlan plus `devices` (`host_id`, `hostname`, `name`, `state`, `name_matches`), `interfaces` (`host_id`, `hostname`, `interface`, `mode`: `access` or `trunk`; at most 2000), `truncated`, `prefixes` (`network`, `vrf_name`, `host_id`, `hostname`, `interface`, `address`) |
| PUT    | `/api/ipam/vlans/{id}` | `{name?, site_id?, description?, tenant_id?}` (`site_id` null: no site; `tenant_id` null: no tenant); `409` when the move collides; a `vid` key gives `422` |
| DELETE | `/api/ipam/vlans/{id}` | `{"ok": true}` |
| POST   | `/api/ipam/interface-addresses/rebuild` | Admin. Reads the newest stored configuration of every host again: `{"ok": true, "hosts": <read>, "addresses": <stored>}` |
| GET    | `/api/hosts/{host_id}/interface-addresses` | `reports` feature, like `/api/hosts/{host_id}/interface-inventory`. `{host_id, addresses, vrfs}`: each address `host_id`, `hostname`, `interface`, `address`, `prefix_length`, `network`, `vrf_name`, `role` (`primary`, `secondary`, `virtual`), `protocol` (`HSRP`, `VRRP`, `GLBP` or `""`), `svi_vid`, `collected_at`, `vrf_id`, `vlan_id`; each VRF `name`, `vrf_id`, `interface_count` |

`GET /api/ipam/address/{ip}` adds `interfaces`: the interface addresses equal to the address (only those of `vrf` when it is given). `GET /api/ipam/subnets/{subnet}` adds `interfaces`: the interface addresses inside the subnet, at most 1024; with `vrf` empty or absent they come from every VRF (each row carries its `vrf_name`), with `vrf` only from that VRF.

### Routing (intended BGP state)
Reads need the `routing` feature, writes `routing.write` (admins have both); writes are audited (`routing`) and tracked in the change log. A refused write is `422` with `detail = {message, fields}`; a duplicate is `409`. Not available to accounts limited to selected inventory groups. See [routing.md](routing.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/routing/autonomous-systems` | `{"autonomous_systems": [AS]}` by number; `tenant_id`, `search`. An AS: `id`, `asn`, `description`, `tenant_id`, `tenant_name`, `rir`, `comments`, the stamps, `instance_count`, `peering_count` |
| POST   | `/api/routing/autonomous-systems` | `{asn, description?, tenant_id?, rir?, comments?}` (`asn` 1 to 4294967295, `65001`, `AS65001` or asdot `1.10`). `201`; `409` when the number exists |
| GET    | `/api/routing/autonomous-systems/{id}` | The AS plus `routing_instances` (local AS) and `peerings` (local or remote AS) |
| PUT    | `/api/routing/autonomous-systems/{id}` | `{description?, tenant_id?, rir?, comments?}`; an `asn` key gives `422` |
| DELETE | `/api/routing/autonomous-systems/{id}` | `{"ok": true}`; `409` with `detail = {message, affected, usage: {routing_instances, bgp_peerings, bgp_peer_groups}}` while an instance or peering uses it |
| GET    | `/api/routing/instances` | `{"routing_instances": [Instance]}`; `host_id`, `asn` (local), `status`, `tenant_id` (of the device or the AS), `search`. An Instance: `id`, `host_id`, `hostname`, `name`, `vrf_id`, `vrf_name`, `autonomous_system_id`, `asn`, `router_id`, `status` (`planned`, `active`, `decommissioned`), `description`, the stamps, `peering_count`, `peer_group_count` |
| POST   | `/api/routing/instances` | `{host_id, name, autonomous_system_id, vrf_id?, router_id?, status?, description?}`. `201`; `409` when the device has the name ignoring case |
| GET / PUT / DELETE | `/api/routing/instances/{id}` | GET adds `peer_groups` and `peerings`; PUT takes the create fields but `host_id` (`422`); DELETE takes its peer groups and peerings |
| GET    | `/api/routing/peer-groups` | `{"peer_groups": [PeerGroup]}`; `routing_instance_id`, `host_id`, `search`. A PeerGroup: `id`, `routing_instance_id`, `routing_instance_name`, `host_id`, `hostname`, `name`, `remote_asn_id`, `remote_asn`, `import_policy`, `export_policy`, `description`, the stamps, `peering_count` |
| POST   | `/api/routing/peer-groups` | `{routing_instance_id, name, remote_asn_id?, import_policy?, export_policy?, description?}`. `201`; `409` when the instance has the name |
| GET / PUT / DELETE | `/api/routing/peer-groups/{id}` | DELETE keeps its peerings, without a group |
| GET    | `/api/routing/peerings` | `{"peerings": [Peering]}`; `host_id`, `routing_instance_id`, `asn` (local or remote), `status`, `tenant_id`, `search`. A Peering: `id`, `routing_instance_id`, `routing_instance_name`, `host_id`, `hostname`, `local_asn`, `peer_group_id`, `peer_group_name`, `local_address`, `remote_address`, `remote_asn_id`, `remote_asn`, `remote_host_id`, `remote_hostname`, `status` (`planned`, `active`, `disabled`, `decommissioned`), `address_families` (list), `import_policy`, `export_policy`, `description`, the stamps |
| POST   | `/api/routing/peerings` | `{routing_instance_id, remote_address, remote_asn_id, local_address?, peer_group_id?, remote_host_id?, status?, address_families?, import_policy?, export_policy?, description?}`. Addresses are IPs of one family; the peer group must belong to the instance. `201`; `409` when the instance has a peering with the remote address |
| GET / PUT / DELETE | `/api/routing/peerings/{id}` | PUT takes the create fields but `routing_instance_id` (`422`) |
| GET    | `/api/routing/compliance` | `host_id?`, `state?`. `{rows, summary, hosts}`: a row per active peering (and per observed one of another status) and per unexpected neighbor, `state` one of `matched`, `down`, `missing`, `unexpected`, `asn_mismatch`, `no_data`, with `host_id`, `hostname`, `peering_id`, `routing_instance_id`, `routing_instance`, `status`, `remote_address`, `intended_remote_asn`, `observed_remote_asn`, `observed_state`, `discovered_at`, `detail`; `summary` counts per state; `hosts` `{host_id, hostname, has_data, last_discovered_at, counts}` |
| GET    | `/api/routing/suggestions` | `host_id`. `{host_id, hostname, has_data, routing_instances, proposed_instance, autonomous_systems: [{asn, autonomous_system_id}], peerings: [{remote_address, remote_asn, observed_state, established, status, remote_host_id, remote_hostname}]}`; creates nothing |
| POST   | `/api/routing/suggestions/accept` | `{host_id, routing_instance_id? \| new_instance?: {name, asn, router_id?, status?}, peerings: [{remote_address, remote_asn?, status (planned, active), remote_host_id?}]}`. Each remote address must be an observed neighbor without a peering; all is checked first. `201` with `{autonomous_systems, routing_instance, peerings}` created |

### Circuits
Reads need the `circuits` feature, writes `circuits.write` (admins have both); writes are audited (`circuits`) and tracked in the change log. A refused write is `422` with `detail = {message, fields}` (termination fields as `terminations.<A|Z>.<field>`); a duplicate is `409`. See [circuits.md](circuits.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/circuits/providers` | `{"providers": [Provider]}` by name. A Provider: `id`, `name`, `account`, `portal_url`, `noc_contact`, `admin_contact`, `comments`, the stamps (`created_by`, `created_at`, `updated_at`, `updated_by`), `circuit_count`, `network_count` |
| POST   | `/api/circuits/providers` | `{name, account?, portal_url?, noc_contact?, admin_contact?, comments?}`. `201`; `409` when the name is taken ignoring case |
| GET    | `/api/circuits/providers/{id}` | The Provider plus `networks` ([ProviderNetwork]) |
| PUT    | `/api/circuits/providers/{id}` | Any Provider field; left out keeps the value |
| DELETE | `/api/circuits/providers/{id}` | `{"ok": true}` (its networks go too); `409` with `detail = {message, affected, usage: {circuits, terminations}}` while it has circuits or terminations in its networks |
| GET    | `/api/circuits/provider-networks` | `{"provider_networks": [ProviderNetwork]}`; `provider_id=<id>`. A ProviderNetwork: `id`, `provider_id`, `provider_name`, `name`, `description`, the stamps, `termination_count` |
| POST   | `/api/circuits/provider-networks` | `{provider_id, name, description?}`. `201`; `409` when the provider has the name |
| GET / PUT / DELETE | `/api/circuits/provider-networks/{id}` | PUT `{name?, description?}` (another `provider_id` is `422`); DELETE `409` while terminations end in it |
| GET    | `/api/circuits/circuit-types` | `{"circuit_types": [CircuitType]}`: `id`, `name`, `description`, the stamps, `circuit_count` |
| POST   | `/api/circuits/circuit-types` | `{name, description?}`. `201`; `409` when the name is taken |
| GET / PUT / DELETE | `/api/circuits/circuit-types/{id}` | DELETE `409` while circuits use it |
| GET    | `/api/circuits/circuits` | `{"circuits": [Circuit]}` by provider then circuit ID; filters `provider_id`, `circuit_type_id`, `status`, `tenant_id`, `site_id`, `host_id` (a termination there), `q` (part of the circuit ID or description). A Circuit: `id`, `cid`, `provider_id`, `provider_name`, `circuit_type_id`, `circuit_type_name`, `status`, `tenant_id`, `tenant_name`, `install_date`, `termination_date`, `commit_rate_kbps`, `description`, `comments`, `billing_circuit_id`, `billing_circuit_name`, `billing_customer`, the stamps, `terminations` ([Termination], A first) |
| POST   | `/api/circuits/circuits` | `{cid, provider_id, circuit_type_id, status?, tenant_id?, install_date?, termination_date?, commit_rate_kbps?, description?, comments?, billing_circuit_id?, terminations?}`. A Termination: `term_side` (`A`, `Z`), exactly one of `site_id` / `provider_network_id`, `host_id?`, `interface_name?` (needs `host_id`), `port_speed_kbps?`, `upstream_speed_kbps?`, `xconnect_id?`, `pp_info?`, `description?`; read back with `id`, `circuit_id`, `site_name`, `provider_network_name`, `hostname` and the stamps. `201`; `409` when the provider has the circuit ID |
| GET    | `/api/circuits/circuits/{id}` | The Circuit plus `utilisation`: per termination on a device port with a commit rate, `term_side`, `host_id`, `interface_name`, `in_bps`, `out_bps`, `polled_at`, `commit_rate_kbps`, `in_pct_of_commit`, `out_pct_of_commit` (from the stored interface counters) |
| PUT    | `/api/circuits/circuits/{id}` | Any circuit field; `terminations` left out keeps them, a list replaces them (a side not listed is deleted) |
| DELETE | `/api/circuits/circuits/{id}` | `{"ok": true}`; its terminations go too |
| PUT    | `/api/circuits/circuits/{id}/terminations/{A\|Z}` | Create or change that side's termination (fields left out keep their value) |
| DELETE | `/api/circuits/circuits/{id}/terminations/{A\|Z}` | `{"ok": true}`; `404` when the side has none |
| GET    | `/api/circuits/hosts/{host_id}/circuits` | `{host_id, circuits}`: the Circuits with a termination on the device, each with `utilisation` |
| GET    | `/api/circuits/hosts/{host_id}/interfaces` | `{host_id, interfaces}`: the interface names Plexus knows for the device |
| GET    | `/api/circuits/choices` | `{hosts: [{id, hostname, ip_address}], sites: [{id, name}], tenants: [{id, name}]}` for the dialog's pickers |

### DCIM (racks, cables, patch panels, power)
Reads need the `dcim` feature, writes `dcim.write` (admins have both); writes are audited (`dcim`) and tracked in the change log. A refused value or broken rule is `422` with `detail = {message, fields}`; a duplicate name, an endpoint that already has a cable, or a delete of a record in use is `409`. See [dcim.md](dcim.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/dcim/{kind}` | A list of records; `kind` is `rack-roles`, `racks`, `rack-reservations`, `rear-ports`, `front-ports`, `modules`, `power-panels`, `power-feeds`, `power-ports` or `power-outlets`. Filters per kind (`site_id`, `floor_id`, `role_id`, `tenant_id`, `status`, `rack_id`, `host_id`, `type`, `rear_port_id`, `power_panel_id`, `power_port_id`) and `q` (name search). Rows carry display fields (`site_name`, `host_name`, `cable_id`, `cable_label`, counts) |
| POST   | `/api/dcim/{kind}` | Create; `201`. Racks: `{site_id, name, floor_id?, status?, role_id?, tenant_id?, u_height? (1-100, 42), desc_units?, width? (19/23), facility_id?, serial?, asset_tag?, description?, comments?}`; reservations `{rack_id, units: [int], user?, description?, tenant_id?}`; rear ports `{host_id, name, type?, positions?}`; front ports `{host_id, name, type?, rear_port_id, rear_port_position?}`; modules `{host_id, bay, module_type?, part_number?, serial?, asset_tag?, status?}`; panels `{site_id, name, floor_id?}`; feeds `{power_panel_id, name, rack_id?, status?, type?, supply?, phase?, voltage?, amperage?, max_utilization?}`; power ports `{host_id, name, maximum_draw?, allocated_draw?}`; outlets `{host_id, name, power_port_id?, feed_leg?}` |
| GET / PUT / DELETE | `/api/dcim/{kind}/{id}` | PUT changes the keys sent (the parent device, rack or panel is fixed); DELETE `409` while in use |
| GET    | `/api/dcim/racks/{id}/elevation` | `{rack, u_height, desc_units, units, faces: {front, rear}: [Block], unmounted, used_units, free_units, reservations}`; a Block is `{kind: device\|reservation\|empty, units, height, host_id?, name?, face?, mounted_here?}`, top first |
| GET    | `/api/dcim/racks/{id}/power` | `{feeds: [{id, name, type, status, available_power, allocated_draw, utilization}], capacity, allocated_draw, unfed_draw, utilization, port_count, ports}` (watts) |
| GET    | `/api/dcim/cables` | `[Cable]`; filters `host_id` (either end), `type`, `status`, `tenant_id`, `endpoint_type`, `q`. A Cable: `id`, `a_*`/`b_*` columns, `a` and `b` (endpoint with `type`, `id`, `host_id`, `name`, `host_name`, `label`), `status`, `type`, `label`, `color`, `length`, `length_unit`, `tenant_id`, `tenant_name`, `description`, the stamps |
| POST   | `/api/dcim/cables` | `{a: Endpoint, b: Endpoint, status?, type?, label?, color?, length?, length_unit?, tenant_id?, description?}`; an Endpoint is `{type, id}` or `{type: "interface", host_id, name}`. `201`; `409` when an end already has a cable; `422` for a bad pairing or an unknown end |
| GET / PUT / DELETE | `/api/dcim/cables/{id}` | PUT may change either end |
| GET    | `/api/dcim/trace` | `type` with `id`, or `type=interface&host_id=&name=`. `{start, steps: [{kind: cable\|internal, near, far, cable?, position?}], status: complete\|dead_end\|unconnected\|missing\|ambiguous\|loop, is_loop, destination, power_panel?}`; `404` for an unknown endpoint |
| GET    | `/api/dcim/hosts/{host_id}` | `{placement: {rack_id, rack_position, rack_face, height, rack_name, site_id, ...}, cables, counts}` |
| GET    | `/api/dcim/hosts/{host_id}/interfaces` | `{interfaces: [name]}` the interface names Plexus knows for the device |
| PUT    | `/api/dcim/hosts/{host_id}/placement` | `{rack_id?, rack_position?, rack_face?}`: mount, move or (`rack_id: null`) unrack; `422` when it does not fit, overlaps a device or reservation, or the rack is at another site. `PUT /api/hosts/{id}` accepts the same three keys |
| GET    | `/api/dcim/choices` | Every fixed choice set (statuses, port, cable and endpoint types, feed options) |

### Sync (NetBox, Nautobot, ServiceNow)
Reads need the `sync` feature; adding, editing, deleting and running jobs need `sync.write`; connections are admin only. A job that writes into Plexus (`import`, `bidirectional`) also needs admin, or only `inventory.write` when devices are its only object type, when it is saved and run for real (`403` otherwise). Every write and run is audited (`sync`). A refused value is `422` with `detail = {message, fields}`; a taken name, a connection used by jobs or a job already running is `409`. See [sync-framework.md](sync-framework.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/sync/catalog` | `{kinds: [{id, label, auth_types, notes}], object_types: [{id, label, key, fields, optional}], directions, conflict_policies, default_mappings: {kind: {object_type: {endpoint, paths, read_only, optional}}}, interval_min, interval_max}` |
| GET    | `/api/sync/connections` | `{"connections": [Connection]}`. A Connection: `id`, `name`, `kind` (`netbox`, `nautobot`, `servicenow`), `base_url`, `auth_type` (`token`, `basic`, `oauth`), `credential_id`, `credential_name`, `verify_tls`, `has_ca_pem`, `timeout_seconds`, `description`, `last_test_at`, `last_test_ok`, `last_test_message`, `job_count`, the stamps. Never a secret |
| GET    | `/api/sync/connections/{id}` | One Connection |
| POST   | `/api/sync/connections` | Admin. `{name, kind, base_url (https), auth_type, credential_id (a service credential), verify_tls?, ca_pem?, timeout_seconds? (5-300), description?}`. `201`; `409` for a taken name |
| PUT / DELETE | `/api/sync/connections/{id}` | Admin. PUT takes the POST body (`ca_pem: null` keeps the stored bundle, `""` removes it; the kind cannot change while jobs use it); DELETE `409` while jobs use it |
| POST   | `/api/sync/connections/{id}/test` | Admin. Signs in and reads one record: `{ok, message}` (also stored on the connection) |
| GET    | `/api/sync/jobs` | `{"jobs": [Job]}` (`?connection_id=`). A Job: `id`, `name`, `connection_id`, `connection_name`, `connection_kind`, `object_types`, `direction` (`import`, `export`, `bidirectional`), `conflict_policy` (`source_wins`, `plexus_wins`, `skip_conflicts`), `delete_missing`, `mappings`, `options` (`host_group`), `interval_minutes`, `enabled`, `description`, `last_run_id`, `last_run_status`, `last_run_at`, `last_attempt_at`, `running`, the stamps |
| GET    | `/api/sync/jobs/{id}` | One Job |
| POST   | `/api/sync/jobs` | `{name, connection_id, object_types: [sites\|manufacturers\|device_types\|vrfs\|vlans\|prefixes\|ip_addresses\|devices], direction?, conflict_policy?, delete_missing?, mappings?, host_group?, interval_minutes? (0 or 5-10080), enabled?, description?}`. `201`; `422` for a mapping that does not resolve against the connection's system |
| PUT / DELETE | `/api/sync/jobs/{id}` | PUT takes the POST body; DELETE removes the job with its runs (`409` while it runs) |
| POST   | `/api/sync/jobs/{id}/run` | `{dry_run: true}` (default) or `false`. `202` with the `running` Run; the run continues after the answer. `409` when the job is running |
| GET    | `/api/sync/runs` | `{"runs": [Run]}` newest first (`?job_id=`, `limit` up to 500). A Run: `id`, `job_id`, `job_name`, `dry_run`, `trigger` (`manual`, `schedule`), `status` (`running`, `success`, `partial`, `failed`), `started_by`, `started_at`, `finished_at`, `summary` (per object type: `remote_records`, `plexus_records`, `unchanged`, `create`, `update`, `delete`, `conflict`, `planned`, `applied`, `failed`, `skipped`, `fields`, `warnings?`, or `error`), `message` |
| GET    | `/api/sync/runs/{id}` | One Run |
| GET    | `/api/sync/runs/{id}/entries` | `{entries, total, limit, offset}` (`?object_type=&outcome=&limit=` up to 1000 `&offset=`). An entry: `id`, `object_type`, `key`, `action` (`create`, `update`, `delete`, `conflict`), `target` (`plexus`, `remote`), `changes` (`{field: {before, after}}`, a conflict `{field: {plexus, remote}}`), `outcome` (`planned`, `applied`, `failed`, `skipped`), `message` |

### Hardware lifecycle
Reads need the `lifecycle` feature, writes `lifecycle.write` (admins have both); writes are audited (`lifecycle`) and notices and contracts are tracked in the change log. A refused write is `422` with `detail = {message, fields}`; a duplicate device type, part number or contract ID is `409`. Dates are `YYYY-MM-DD` (`""` when unset). See [hardware-lifecycle.md](hardware-lifecycle.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/lifecycle/notices` | `{"notices": [Notice]}`; filters `device_type_id`, `q` (part of the model, part number or comments). A Notice: `id`, `device_type_id`, `device_type_model`, `device_type_part_number`, `manufacturer_name`, `part_number`, `end_of_sale`, `end_of_sw_maintenance`, `end_of_security_fixes`, `end_of_support`, `documentation_url`, `comments`, the stamps, `host_count` (devices it applies to), `stage` and `next` (`{milestone, label, date, days}` or null) as of today |
| POST   | `/api/lifecycle/notices` | `{device_type_id? \| part_number?, end_of_sale?, end_of_sw_maintenance?, end_of_security_fixes?, end_of_support?, documentation_url?, comments?}`: exactly one of `device_type_id` / `part_number`; a milestone may not be before an earlier one. `201`; `409` when the device type has a notice or the part number is taken ignoring case |
| GET    | `/api/lifecycle/notices/{id}` | The Notice plus `hosts`: `[{id, hostname, ip_address, via}]`, `via` listing `device_type`, `part_number` and/or `module` |
| PUT / DELETE | `/api/lifecycle/notices/{id}` | PUT takes any Notice field (left out keeps the value; send `device_type_id: null` with a `part_number` to switch); DELETE `{"ok": true}` |
| GET    | `/api/lifecycle/contracts` | `{"contracts": [Contract]}` by provider then contract ID; filters `host_id`, `state` (`covered`, `expiring`, `expired`, `not_started`), `q` (part of the provider, contract ID or support level). A Contract: `id`, `provider`, `contract_id`, `start_date`, `end_date`, `cost` (text with two decimals, or null), `currency`, `support_level`, `description`, `comments`, the stamps, `host_count`, `hosts` (`[{id, hostname, ip_address}]`), `state` |
| POST   | `/api/lifecycle/contracts` | `{provider, contract_id, start_date?, end_date?, cost?, currency?, support_level?, description?, comments?, host_ids?}`. `201`; `409` when the provider has the contract ID ignoring case; `422` with `fields.host_ids` for an unknown device |
| GET / PUT / DELETE | `/api/lifecycle/contracts/{id}` | PUT takes any Contract field; `host_ids` left out keeps the covered devices, a list replaces them |
| GET    | `/api/lifecycle/status` | `stage?`, `coverage?`, `q?`. `{summary: {devices, with_notice, past_end_of_support, by_stage, by_coverage}, devices: [Status], settings, stages, coverage_states}`; a Status: `host_id`, `hostname`, `ip_address`, `serial_number`, `model`, `device_type_id`, `device_type_model`, `manufacturer_name`, `lifecycle_status_name`, `notice_ids`, `stage` (`none`, `supported`, `end_of_sale`, `end_of_sw_maintenance`, `end_of_security_fixes`, `end_of_support`), `next`, `end_of_sale`, `days_to_end_of_sale`, `end_of_support`, `days_to_end_of_support`, `coverage` (`covered`, `expiring`, `expired`, `not_started`, `none`), `coverage_end`, `coverage_days`, `contracts` (`[{id, provider, contract_id, end_date, state}]`). The summary counts every device |
| GET    | `/api/lifecycle/status/export` | The filtered statuses as CSV (`hardware_lifecycle.csv`), user text guarded against formulas |
| GET    | `/api/lifecycle/hosts/{host_id}` | `{host_id, status: Status, notices: [Notice with via], contracts: [Contract]}`; `404` for an unknown device |
| GET    | `/api/lifecycle/choices` | `{hosts: [{id, hostname, ip_address}], device_types: [{id, manufacturer, model, part_number}], milestones: [{key, label}]}` for the dialogs' pickers |
| GET    | `/api/lifecycle/settings` | `{alerts_enabled, contract_warn_days, support_warn_days, last_check_at, last_check_alerts}` |
| PUT    | `/api/lifecycle/settings` | `{alerts_enabled?, contract_warn_days?, support_warn_days?}` (days 1 to 3650) |
| POST   | `/api/lifecycle/check` | Run the alert check now: `{ok, conditions, raised, cleared, resolved}`; `500` when it failed (details in the server log) |

### Hardware inventory
Components with a serial per host and their history ([hardware-inventory.md](hardware-inventory.md)). Reads need the `inventory` feature, the refresh `inventory.write`. Object scope: a host route answers `404` outside the caller's groups (the refresh `403` on a read-only group); the fleet lists keep the caller's readable hosts, and history of a deleted host is shown to unrestricted callers only. Times are UTC `YYYY-MM-DD HH:MM:SS`. A Component: `id`, `host_id`, `hostname`, `category` (`chassis`, `module`, `power_supply`, `fan`, `transceiver`, `other`), `slot`, `name`, `description`, `model`, `serial`, `hardware_rev`, `firmware_rev`, `software_rev`, `status` (`present`, `missing`, `removed`), `source` (`snmp`, `ssh`), `first_seen`, `last_seen`, `removed_at` (or null). An Event: `id`, `host_id` (null once the host is deleted), `hostname`, `occurred_at`, `event` (`baseline`, `installed`, `removed`, `replaced`, `moved`, `changed`), `category`, `slot`, `name`, `model`, `serial`, `previous_serial`, `previous_model`, `previous_slot`, `previous_host_id`, `previous_hostname`, `changes` (`{field: {before, after}}`, `{}` unless `changed`), `detail` (one sentence; the baseline count; it never names another host). For a caller limited to selected inventory groups, `previous_host_id` and `previous_hostname` are returned as `null` and `""` unless that host is readable to the caller (a deleted host: always cleared); this applies to all three routes that return events. The `event`, `category` and `status` filters take one value or a comma-separated list (`event=installed,removed,replaced,moved,changed`) matching any of them; an unknown value is `422`. `limit` is 1 to 500, `offset` 0 to 100,000; `total` counts the matching rows.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/hosts/{host_id}/hardware` | `{host_id, collected_at, source, state, message, components: [Component]}`; `state` is `ok`, `never` (no read yet) or `not_read` (the last attempt was not read: `message` says why); removed components included |
| GET    | `/api/hosts/{host_id}/hardware/events` | `event?`, `limit?`, `offset?`. `{total, events: [Event]}`, newest first |
| POST   | `/api/hosts/{host_id}/hardware/refresh` | Read the host now over SNMP with its effective SNMP profile and store the read: the body of `GET .../hardware` plus `new_events: [Event]`. `403` when the host's address awaits an admin's confirmation (admins may), `409` when SNMP is not enabled for the host, its device type is not read, it has no address, or another read of it is being stored; `502` when the device did not answer the read completely (nothing changed). Audited (`inventory` / `host.hardware_refresh`) |
| GET    | `/api/hardware/components` | `search?` (case-insensitive part of the serial, model, name, slot or hostname), `category?`, `status?`, `group_id?`, `limit?`, `offset?`. `{total, components: [Component]}` |
| GET    | `/api/hardware/components/export` | The same filters as CSV (`hardware_components.csv`, up to 50,000 rows); device text guarded against spreadsheet formulas |
| GET    | `/api/hardware/events` | `search?` (part of the serial, previous serial, model, hostname or slot), `event?`, `host_id?` (`404` outside the caller's scope), `category?`, `limit?`, `offset?`. `{total, events: [Event]}`, newest first |

`POST /api/hosts/{host_id}/fetch-serial` and `POST /api/groups/{group_id}/fetch-serials` also run `show inventory` on Cisco hosts and store the components (source `ssh`): the single-host response and each group result row carry `components` (the number stored; 0 for a driver without `show inventory`, a failed command or an empty list).

### Virtualization
Reads need the `virtualization` feature, writes `virtualization.write` (admins have both); the cloud sync is admin only. Writes are audited (`virtualization`) and tracked in the change log. A refused value is `422` with `detail = {message, fields}`; a duplicate name is `409`. See [virtualization.md](virtualization.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/virtualization/cluster-types` | `{"cluster_types": [ClusterType]}` by name: `id`, `name`, `description`, the stamps (`created_by`, `created_at`, `updated_at`, `updated_by`), `cluster_count` |
| POST   | `/api/virtualization/cluster-types` | `{name, description?}`. `201`; `409` when the name is taken ignoring case |
| GET / PUT / DELETE | `/api/virtualization/cluster-types/{id}` | PUT `{name?, description?}`; DELETE `409` while clusters have the type |
| GET / POST | `/api/virtualization/cluster-groups` | As cluster types (`{"cluster_groups": [...]}`) |
| GET / PUT / DELETE | `/api/virtualization/cluster-groups/{id}` | DELETE `409` while clusters are in the group |
| GET    | `/api/virtualization/clusters` | `{"clusters": [Cluster]}` by name; filters `cluster_type_id`, `cluster_group_id`, `site_id`, `tenant_id`, `search` (name or description). A Cluster: `id`, `name`, `cluster_type_id`, `cluster_type_name`, `cluster_group_id`, `cluster_group_name`, `site_id`, `site_name`, `tenant_id`, `tenant_name`, `description`, `comments`, `origin`, `cloud_key`, the stamps, `host_count`, `vm_count` |
| POST   | `/api/virtualization/clusters` | `{name, cluster_type_id, cluster_group_id?, site_id?, tenant_id?, description?, comments?}`. `201`; `422` naming an id that does not exist; `409` when the name is taken |
| GET    | `/api/virtualization/clusters/{id}` | The Cluster plus `hosts` (`id`, `hostname`, `ip_address`, `device_type`, `status`, `added_at`, `added_by`) and `virtual_machines` ([VM]) |
| PUT    | `/api/virtualization/clusters/{id}` | Any Cluster field; left out keeps the value, `null` clears a group, site or tenant |
| DELETE | `/api/virtualization/clusters/{id}` | `{"ok": true}`; `409` while it holds VMs |
| POST   | `/api/virtualization/clusters/{id}/hosts` | `{host_id}`: add a hypervisor host. `201` with `hosts`; `409` when a member already |
| DELETE | `/api/virtualization/clusters/{id}/hosts/{host_id}` | `{"ok": true}`; `404` when not a member |
| GET    | `/api/virtualization/hosts/{host_id}/clusters` | `{host_id, clusters}`: the clusters the host is a hypervisor of |
| GET    | `/api/virtualization/virtual-machines` | `{"virtual_machines": [VM]}` by name; filters `cluster_id`, `cluster_type_id`, `cluster_group_id`, `site_id` (the cluster's), `tenant_id`, `role_id`, `status`, `origin`, `search` (name, description, platform, primary IPs). A VM: `id`, `name`, `cluster_id`, `cluster_name`, `cluster_type_id`, `cluster_type_name`, `cluster_group_id`, `cluster_group_name`, `site_id`, `site_name`, `status`, `role_id`, `role_name`, `role_color`, `tenant_id`, `tenant_name`, `platform`, `vcpus`, `memory_mb`, `disk_gb`, `primary_ip4`, `primary_ip6`, `cloud_resource_id`, `cloud_account_id`, `cloud_resource_uid`, `cloud_provider`, `cloud_resource_type`, `cloud_resource_name`, `cloud_account_name`, `origin`, `description`, `comments`, the stamps, `interface_count` |
| POST   | `/api/virtualization/virtual-machines` | `{name, cluster_id, status?, role_id?, tenant_id?, platform?, vcpus?, memory_mb?, disk_gb?, primary_ip4?, primary_ip6?, cloud_resource_id?, description?, comments?}`. `cloud_resource_id` must be a compute instance (`422` otherwise) not mirrored by another VM (`409`). `201`; `409` when the cluster has the name |
| GET    | `/api/virtualization/virtual-machines/{id}` | The VM plus `interfaces` ([Interface]) |
| PUT    | `/api/virtualization/virtual-machines/{id}` | Any VM field; makes the VM `manual` (the cloud sync keeps its values) |
| DELETE | `/api/virtualization/virtual-machines/{id}` | `{"ok": true}`; its interfaces go too |
| GET    | `/api/virtualization/virtual-machines/{id}/interfaces` | `{"interfaces": [Interface]}`. An Interface: `id`, `vm_id`, `name`, `enabled`, `mac_address`, `mtu`, `mode`, `untagged_vlan_id`, `untagged_vlan_vid`, `untagged_vlan_name`, `vrf_id`, `vrf_name`, `description`, `addresses` (CIDR text), the stamps |
| POST   | `/api/virtualization/virtual-machines/{id}/interfaces` | `{name, enabled?, mac_address?, mtu?, mode?, untagged_vlan_id?, vrf_id?, description?, addresses?}`. `201`; `409` when the VM has the name |
| PUT / DELETE | `/api/virtualization/virtual-machines/{id}/interfaces/{interface_id}` | PUT any field; `addresses` given replace the set. Both make the VM `manual` |
| GET    | `/api/virtualization/tenants` | `{"tenants": [{id, name}]}` for the dialogs' tenant pickers |
| POST   | `/api/virtualization/sync-cloud` | Admin. `{account_id?}`: mirror the AWS, Azure and GCP compute instances as VMs now (one account, or all). `{ok, accounts, created, updated, unchanged, kept_manual, offline, skipped, failed}`; `404` for an unknown account |

### Locations and tenancy
Reads need the `organization` feature; region, tenant group and tenant writes are admin only. Writes are audited (`organization`) and tracked in the change log (`region`, `site`, `tenant_group`, `tenant`). A refused value is `422` with `detail = {message, fields}`; a duplicate name is `409`. See [locations-and-tenancy.md](locations-and-tenancy.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/organization/regions` | `{"regions": [Region]}` in tree order (siblings by name). A Region: `id`, `parent_id`, `name`, `description`, the stamps (`created_by`, `created_at`, `updated_by`, `updated_at`), `path` (names from the top joined with ` / `), `depth`, `child_count`, `site_count` (its own sites), `total_site_count` (with its descendants') |
| POST   | `/api/organization/regions` | `{name, parent_id?, description?}`. `201`; `409` when the parent has a region of the name ignoring case; `422` for an unknown parent |
| GET / PUT / DELETE | `/api/organization/regions/{id}` | PUT `{name?, parent_id?, description?}` (`parent_id` null: top level; itself or a descendant: `422`); DELETE `409` with `detail = {message, usage: {regions, sites}}` while it holds regions or sites |
| GET    | `/api/organization/locations` | `{regions, unassigned_sites}`: the top-level regions, each a Region plus `host_count` (hosts of its and its descendants' sites), `sites` and `children` (regions); a site `id`, `name`, `region_id`, `status`, `facility`, `time_zone`, `tenant_id`, `tenant_name`, `host_count`, `floors` (`id`, `name`, `floor_number`, `placed_device_count`) |
| GET    | `/api/organization/sites` | `{"sites": [...]}`: every site (the `/api/geo/sites` rows) with `region_name` and `tenant_name` |
| GET    | `/api/organization/tenant-groups` | `{"tenant_groups": [TenantGroup]}` in tree order: the Region fields with `tenant_count` and `total_tenant_count` instead of the site counts |
| POST   | `/api/organization/tenant-groups` | `{name, parent_id?, description?}`. `201`; `409` when the name is taken ignoring case |
| GET / PUT / DELETE | `/api/organization/tenant-groups/{id}` | PUT as regions; DELETE `409` while it has child groups, else `{"ok": true, "tenants": <left in no group>}` |
| GET    | `/api/organization/tenants` | `{"tenants": [Tenant]}` by name; `group_id=<id>` keeps the tenants of the group and its sub-groups. A Tenant: `id`, `name`, `group_id`, `group_name`, `description`, `comments`, the stamps |
| POST   | `/api/organization/tenants` | `{name, group_id?, description?, comments?}`. `201`; `409` when the name is taken ignoring case; `422` for an unknown group |
| GET    | `/api/organization/tenants/{id}` | The Tenant plus `counts`: rows it owns per kind (`hosts`, `prefixes`, `ip_addresses`, `vlans`, `vrfs`, `sites`, and every other table with a `tenant_id` column by table name) |
| PUT / DELETE | `/api/organization/tenants/{id}` | PUT `{name?, group_id?, description?, comments?}`; DELETE `{"ok": true, "released": counts}` (what it owned keeps existing with no tenant) |
| POST / PUT | `/api/geo/sites`, `/api/geo/sites/{id}` | `floor-plan` feature. Also take `region_id`, `status` (`active`, `planned`, `staging`, `decommissioning`, `retired`), `facility`, `time_zone` (IANA name or empty) and `tenant_id`; on PUT a key left out keeps its value and `null` clears a region or tenant. `422` naming each bad field |
| PATCH  | `/api/ipam/prefixes/{id}` | Admin. `{tenant_id}` (`null` clears); `{"ok": true, "prefix": ...}`; `400` naming `tenant_id` for an unknown tenant, `404` for an unknown prefix |
| PATCH  | `/api/ipam/allocations/{id}` | Admin. As prefixes, for an IP allocation |

Hosts: the create, update and bulk edit bodies take `tenant_id` (an unknown id is `400` naming it); host rows carry `tenant_id`, `tenant` (`{id, name}` or null) and `region_ids` (the site's region and the regions above it, nearest first). The inventory list and dynamic groups filter by `tenant_id=<id|none>` and `region_id=<id|none>` (a region includes the regions under it). `POST /api/ipam/prefixes` and `POST /api/ipam/subnets/{subnet}/allocations` take `tenant_id`; `GET /api/ipam/subnets/{subnet}` lists `prefixes` (`id`, `vrf`, `description`, `source_name`, `provider`, `tenant_id`, `tenant_name`) and each allocation's `tenant_id` and `tenant_name`.

### Source device import
Admin only (and the `topology` and `inventory` features). See [After adding a source](meraki-topology.md#after-adding-a-source).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/sources/{org_ref}/importable-devices` | The devices of the source's latest collection that have a usable management address: `devices` (each `key` (node id), `name`, `ip`, `model`, `serial`, `kind`, `site`, `platform`, `device_type` it would get, `capabilities` `{snmp_polling, config_backup}`, `existing` (the inventory host it already is, by address or by the collection's match, or null)), `reason` (why the list is empty, else `""`), `provider`, `provider_note`, `snapshot_id`, `collected_at`, `suggested_group_name`, `max_devices`, `monitoring_enabled`. One device per address, sorted by name |
| POST   | `/api/sources/{org_ref}/import-devices` | `{device_keys, group_id \| new_group_name, snmp_profile_id?, backup_credential_id?}`. Everything is validated before anything is written (keys of the latest collection, an existing group or a new top-level name not taken (409), an existing SNMP profile, a credential the caller may use, and a backup only for devices Config Backups can read). Adds the devices not in the inventory (never changes an existing host; those are reported under `skipped`), assigns the SNMP profile to the group unless it already has another (`kept`), and creates a daily backup policy for the group unless it has one (`exists`). Returns `group {id, name, created}`, `added`, `skipped`, `errors`, `counts`, `snmp_profile {status, profile_id, profile_name}`, `backup_policy {status, policy_id, name, interval_seconds, retention_days}`, `monitoring_enabled`. Audited. 409 when the source has never been collected |

### OPNsense firewall rules
Read-only views of an OPNsense firewall's filter rules, read from the `config.xml` its OPNsense collection stores as the config backup of its inventory host; the firewall is never contacted. Needs the `config-backups` feature and checks the caller's inventory group scope on the host (`404` outside it). Only parsed rules, aliases and NAT are returned, never the backup's text. See [opnsense-topology.md](opnsense-topology.md#firewall-rules-and-path-trace).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/opnsense/hosts/{host_id}/rules` | The rules of the host's newest successful backup in evaluation order: `host_id`, `host`, `available` (false, with an empty view and a `message`, when the host has no backup or it is no `config.xml`), `message`, `backup {id, captured_at, capture_method}`, `stats_collected_at` (when the rule counters were collected, null without), `stats_available`, `hostname`, `interfaces` (`key`, `device`, `description`, `enabled`, `addresses`, `dynamic`), `groups`, `tiers`, `rules`, `aliases` (`name`, `type`, `content`, `description`, `enabled`; credentials in a URL are masked), `nat {outbound_mode, port_forwards, outbound, one_to_one}`, `notes` (what the configuration uses that is not read), `summary` (rule count and the count of each flag). Each rule: `number` (the number a path trace names), `key` (its uuid, else a key of what it matches), `uuid`, `tier` (`automation`, `floating`, `group`, `interface`), `action`, `interfaces`, `zones` (interface keys, groups expanded; `["*"]` for every interface), `direction`, `family`, `protocol`, `quick`, `disabled`, `description`, `gateway`, `log`, `source` and `destination` (`text`, `port`, `any`, `negate`, `cidrs`, `ports`, `aliases`, `missing_aliases`, `unresolved`), `unresolved`, `flags` (`any_any`, `shadowed`, `disabled`, `missing_alias`, `unused`), `shadowed_by` (the number of the rule that takes its flows first), `shadow` (`redundant`: same action, `conflicting`: the opposite), `missing_aliases`, `stats` (`evaluations`, `packets`, `bytes`, `states`, `pf_rules`, or null; matched by the rule's pf `label`, else its uuid), `label` (the pf label the firewall's log lines and counters name the rule by: an MVC rule's uuid, a legacy rule's hash), `log_evidence` (null without firewall log lines in the window: `rule_key`, `passes`, `blocks` in the window, `passes_recent`, `blocks_recent` in the last hour, `last_seen`, `seen_on` (`igb1 in`), `flows` [`action`, `source`, `destination`, `protocol`, `destination_port`, `hits`, `last_seen`]). The view's `log_evidence`: `enabled` (the receiver switch), `received_at` (newest evidence of the host, null when none), `window_hours`, `recent_hours`, `bucket_seconds`, `unmatched` (the evidence of labels no rule of the backup has, each with `name`). `alias_tables`: the pf tables the collection read for the path trace, `read_at` (UTC, null when none) and `tables` by alias name (`entry_count`, `total`, `truncated`; never the entries), see [opnsense-topology.md](opnsense-topology.md#alias-tables). See [opnsense-topology.md](opnsense-topology.md#firewall-log-evidence) |
| GET    | `/api/opnsense/hosts/{host_id}/rules/diff` | `?from_backup=&to_backup=` (two successful backups of the host; both omitted: the newest against the one before it). `host_id`, `available` (false with a `message` when there are not two backups), `from_backup`, `to_backup`, `rules {added, removed, changed}` (a change: `key`, `number_before`, `number_after`, `moved`, `changes [{field, before, after}]`, `before`, `after`), `aliases {added, removed, changed}`, `nat {outbound_mode ({before, after} or null), port_forwards, outbound, one_to_one}` (each `{added, removed, changed}`), `summary {rules, aliases, nat}`. `404` for a backup of another host; `422` when a backup is no `config.xml` |

### Playbooks
| Method | Endpoint              | Description                                      |
|--------|-----------------------|--------------------------------------------------|
| GET    | `/api/playbooks`      | List all (with last run status). Each carries `input_schema` (the effective typed run inputs), `input_schema_source` (`stored`, `code`, `none`), `supports_dry_run`, `permissions` and, for the caller, `can_run` and `can_commit` |
| POST   | `/api/playbooks`      | Register `{name, filename, description, tags}`; optional `input_schema` and (admin only) `permissions`. A bad schema answers `422` with `detail.fields` keyed `<index>.<attr>` |
| PUT    | `/api/playbooks/{id}` | Update; same optional `input_schema` and (admin only) `permissions` |
| DELETE | `/api/playbooks/{id}` | Unregister                                       |
| GET    | `/api/playbooks/{id}/input-schema` | The run form: `schema`, `source`, `supports_dry_run`, `permissions`, `can_run`, `can_commit` |
| PUT    | `/api/playbooks/{id}/input-schema` | `{"schema": [...]}` replaces the stored schema (audited as `config` / `playbook.input_schema`); `[]` falls back to the code schema. Field types: `string`, `text`, `integer`, `boolean`, `choice`, `multichoice`, `list`, `ip`, `cidr`, `host`, `group`, `secret`; attributes `name`, `type`, `label`, `help`, `default`, `required`, `choices`, `min`, `max`, `regex`. See [jobs.md](jobs.md#run-inputs) |
| PUT    | `/api/playbooks/{id}/permissions` | Admin only (`403` otherwise), audited as `config` / `playbook.permissions`. `{"run": {"roles": [], "groups": []}, "commit": {...}}`: roles from `admin`, `user`; groups are access group ids (`422` for an unknown one). An empty rule allows everyone with `jobs`; an empty commit rule follows the run rule; admins always pass |

### Templates
| Method | Endpoint              | Description                             |
|--------|-----------------------|-----------------------------------------|
| GET    | `/api/templates`      | List all                                |
| POST   | `/api/templates`      | Create `{name, content, description}`   |
| GET    | `/api/templates/{id}` | Get one                                 |
| PUT    | `/api/templates/{id}` | Update `{name, content, description}`   |
| DELETE | `/api/templates/{id}` | Delete                                  |

### Git data sources
Admin only. Git repositories templates, Ansible playbooks and config contexts sync from (migration 0093). Writes and syncs are audited (category `config`, actions `git_source_create`, `git_source_update`, `git_source_delete`, `git_source_sync`). Templates, playbooks and intended configuration contexts now carry `git_source_id`, `git_source_name`, `git_path` and `git_commit`; one a source owns answers `409` to `PUT` and `DELETE` (a playbook's `input_schema` and `permissions` stay writable). See [git-data-sources.md](git-data-sources.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/git-sources` | `{"sources": [Source], "content_types": ["templates", "playbooks", "config_contexts"]}` by name. A Source: `id, name, remote_url, branch, credential_id, credential_name, provides, sync_interval_minutes, enabled, status` (`never`, `syncing`, `ok`, `warning`, `error`), `error, last_commit, last_attempt_at, last_synced_at, summary` (the newest successful sync's `{commit, counts, warnings}`), `object_counts, created_at, updated_at, updated_by` |
| POST   | `/api/git-sources` | `{name, remote_url, branch?, credential_id?, provides?, sync_interval_minutes?, enabled?}`. `remote_url` is `https://`, `ssh://` or `user@host:path` without credentials; `credential_id` a service credential; `sync_interval_minutes` `0` or 5 to 10080. `201` with the Source; `400` for a bad field, `409` for a taken name |
| GET    | `/api/git-sources/{id}` | The Source |
| PUT    | `/api/git-sources/{id}` | Full replace, same body and checks. A new `remote_url` discards the working copy |
| DELETE | `/api/git-sources/{id}` | Removes the records it owns, then the source: `{"ok": true, "removed": n, "detached": n}` (`detached`: kept because job history references them). `409` while it syncs |
| GET    | `/api/git-sources/{id}/objects` | `{"objects": {"templates": [...], "playbooks": [...], "config_contexts": [...]}}`: id, name, `git_path`, `git_commit` of each record it owns |
| POST   | `/api/git-sources/{id}/sync` | Sync now: `{ok, source, result}`. `result` is `{commit, counts: {<type>: {created, updated, unchanged, removed, detached}}, warnings: [{path, message}]}`, or `null` with `ok: false` when the fetch failed (the message is the Source's `error`; no record changed). `409` while a sync of it runs |

### Intended configuration
Everything needs the `config-drift` feature; the rows marked *Admin* need an administrator. Template and context writes and `generate` are audited (category `config`). Errors use the usual `{ok: false, error: {code, message}}` envelope: `400` for bad input, `404` for an unknown id, `409` when the name is taken ignoring case. See [intended-config.md](intended-config.md).

A Template: `id`, `name`, `kind` (`device` or `snippet`), `device_type` (`""`: any driver), `role_id`, `site_id`, `group_id` (null: any; always empty on a snippet), `template_text`, `description`, `enabled`, `created_at`, `updated_at`, `updated_by`, `host_count` (hosts whose stored intended configuration came from it). A Context: `id`, `name`, `weight` (0 to 100000), `data` (a JSON object), `description`, `enabled`, `device_type`, `role_id`, `site_id`, `group_id`, `host_id`, `created_at`, `updated_at`, `updated_by`. A Row: `host_id`, `hostname`, `ip_address`, `group_id`, `group_name`, `template_id`, `template_name`, `status` (`ok`, `error`), `error` (text or null), `compliance` (`compliant`, `non_compliant`, `unknown`), `missing_count`, `extra_count`, `backup_id`, `generated_at`, `changed_at`, `compared_at`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/intended-config/templates` | `{"templates": [Template]}` by name |
| POST   | `/api/intended-config/templates` | *Admin.* `{name, kind, device_type?, role_id?, site_id?, group_id?, template_text?, description?, enabled?}`. `201` with the Template. A Jinja syntax error gives `400` with `detail = {message, line}` |
| GET    | `/api/intended-config/templates/{id}` | The Template |
| PUT    | `/api/intended-config/templates/{id}` | *Admin.* Full replace, same body and checks |
| DELETE | `/api/intended-config/templates/{id}` | *Admin.* `{"ok": true}` |
| GET    | `/api/intended-config/contexts` | `{"contexts": [Context]}` by weight, then name |
| POST   | `/api/intended-config/contexts` | *Admin.* `{name, data, weight?, description?, enabled?, device_type?, role_id?, site_id?, group_id?, host_id?}`; `data` must be a JSON object of at most 65536 characters. `201` with the Context |
| GET    | `/api/intended-config/contexts/{id}` | The Context |
| PUT    | `/api/intended-config/contexts/{id}` | *Admin.* Full replace |
| DELETE | `/api/intended-config/contexts/{id}` | *Admin.* `{"ok": true}` |
| POST   | `/api/intended-config/preview` | *Admin.* `{host_id, template_id?, template_text?}`: renders `template_text` (under the named template's name when `template_id` is given too), else the named template, else the template the host selects. `{template_name, config_text, error}`; `error` is null or `{message, template, line}`. Stores nothing |
| GET    | `/api/intended-config/hosts/{host_id}/variables` | `{variables, contexts: [{id, name, weight}]}`: what the host's template sees and the contexts merged, in merge order |
| GET    | `/api/intended-config/hosts` | `?group_id=`, `?compliance=`, `?status=`. `{rows: [Row], counts: {hosts, generated, errors, compliant, non_compliant, unknown, no_template}}`; the counts cover every host whatever the filters |
| GET    | `/api/intended-config/hosts/{host_id}` | The Row plus `config_text`, `lines: [{text, missing}]`, `extra: [{path, text}]` and `backup: {id, captured_at}` (null when not compared). `404` when the host has no intended configuration |
| POST   | `/api/intended-config/generate` | `{host_ids?, group_id?}` (neither: every host). Renders and compares now: `{hosts, generated, changed, errors, no_template}` |
| GET    | `/api/intended-config/hosts/{host_id}/remediation` | A Remediation: `host_id`, `hostname`, `ip_address`, `device_type`, `group_id`, `template_name`, `backup` (`{id, captured_at}` or null), `state` (`ok`, `unsupported`, `unavailable`), `reason`, `platform`, `commands` (indented, removals first in each block), `added`, `removed`, `ignored`, `notes`. Stores and pushes nothing |
| POST   | `/api/intended-config/remediation` | Exactly one of `{host_ids}`, `{group_id}`, `{dynamic_group_id}` (at most 500 hosts): `{hosts: [Remediation], counts: {hosts, with_commands, unsupported, unavailable}}` |
| GET    | `/api/intended-config/remediation-ignores` | *Admin.* `{"rules": [{id, kind, pattern, device_type, description, enabled, created_at, updated_at, updated_by}]}` |
| POST   | `/api/intended-config/remediation-ignores` | *Admin.* `{kind, pattern, device_type?, description?, enabled?}`; `kind` is `exact`, `prefix` or `regex` (RE2: a lookaround or backreference is `400`). `201` with the rule |
| PUT    | `/api/intended-config/remediation-ignores/{id}` | *Admin.* Full replace |
| DELETE | `/api/intended-config/remediation-ignores/{id}` | *Admin.* `{"ok": true}` |
| POST   | `/api/deployments/intended-remediation` | Needs `deployments` too. The targets as above plus `credential_id`, `name?`, `description?`: one deployment per host with commands (change type `intended-remediation`), `{deployments: [{id, host_id, hostname, status, requires_approval, approval_status, commands}], skipped: [{host_id, hostname, reason}]}` |

### Export templates
Any signed-in user reads and renders the templates of the object types whose feature they hold (`host`: `inventory`; `prefix`, `ip_address`, `vlan`: `ipam`; `circuit`: `circuits`; `site`: `organization`); the rows marked *Admin* need an administrator. Writes and renders are audited (category `export_templates`). `400` for bad input or a template that fails, `404` for an unknown id or a type the caller does not read, `409` when the object type has a template of that name ignoring case. See [export-templates.md](export-templates.md).

An ExportTemplate: `id`, `name`, `object_type`, `description`, `template_text`, `mime_type`, `file_extension` (no dot; may be empty), `as_attachment`, `created_by`, `created_at`, `updated_by`, `updated_at`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/export-templates` | `?object_type=`. `{"templates": [ExportTemplate]}` by object type, then name |
| GET    | `/api/export-templates/object-types` | `{"object_types": [{key, label, feature, filters, fields, tags, readable}]}` |
| GET    | `/api/export-templates/{id}` | The ExportTemplate |
| GET    | `/api/export-templates/{id}/render` | The type's filters in the query string (see the guide). The rendered file with the template's `Content-Type` (plus `charset=utf-8`) and `Content-Disposition` (`attachment` or `inline`, `filename` from the name and extension). A template that fails gives `400` with `detail = {message, line}`; a scoped caller gets `403` for `prefix` and `ip_address` |
| POST   | `/api/export-templates` | *Admin.* `{name, object_type, template_text?, description?, mime_type?, file_extension?, as_attachment?}`. `201` with the ExportTemplate. A Jinja syntax error gives `400` with `detail = {message, line}` |
| PUT    | `/api/export-templates/{id}` | *Admin.* Full replace, same body and checks |
| DELETE | `/api/export-templates/{id}` | *Admin.* `{"ok": true}` |
| POST   | `/api/export-templates/preview` | *Admin.* `{object_type, template_text, limit?}` (default 20, at most 1000) and the type's filters in the query string: `{output, error, count, total}`; `error` is null or `{message, template, line}`. Stores nothing |

### Credentials
| Method | Endpoint                | Description                                   |
|--------|-------------------------|-----------------------------------------------|
| GET    | `/api/credentials`      | List all (passwords masked); an external reference shows as `ext_provider_id`, `ext_provider_name`, `ext_path`, `ext_key`, `ext_secret_key` |
| POST   | `/api/credentials`      | Create `{name, username, password, secret}`, or `{name, username, external: {provider_id, path, key?, secret_key?}}` to read the password from a secrets provider |
| PUT    | `/api/credentials/{id}` | Update; `external` replaces a stored password, a new `password` replaces a reference |
| DELETE | `/api/credentials/{id}` | Delete                                        |
| GET    | `/api/credentials/secrets-providers` | The enabled providers the caller may reference (`id`, `name`, `provider_type`): admins all, others those allowing personal credentials |

Service credentials (`/api/credentials/service`) and secret variables
(`/api/secret-variables`, `external: {provider_id, path, key?}` instead of
`value`) take the same reference. See
[secrets-providers.md](secrets-providers.md).

A secret variable also takes and returns `usable_by: {roles, groups}`: the
user roles (`user`, `admin`) and access group ids whose jobs may have it
resolved. Empty or left out on create is open (every user who may run the
job); left out on update keeps the rule, and `{}` opens it.
`{"roles": ["admin"]}` keeps the secret to admins. A bad role or
an access group id that does not exist answers `422` with
`{message, fields}`. Admins and the API token are always allowed. See
[jobs.md](jobs.md#who-may-use-a-secret-variable).

### Secrets providers
Reads need the `secrets-providers` feature. Create, update, delete and test
are admin only (an admin session or the server API token; others get
`403`). A provider's own secrets are
write-only (`secrets_set` lists which are stored); no route returns a
resolved value. Audited as `secrets_providers`. See
[secrets-providers.md](secrets-providers.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/secrets-providers` | `{providers: [{id, name, provider_type, description, enabled, allow_user_credentials, cache_ttl, config, secrets_set, credential_count, secret_variable_count, sdk: {status, missing}}], types: [...]}` |
| GET    | `/api/secrets-providers/{id}` | One provider |
| POST   | `/api/secrets-providers` | `{name, provider_type (vault, aws, azure), description?, enabled?, allow_user_credentials?, cache_ttl? (0-3600, 300), config, secrets}`; `201 {id}`, `409` taken name, `400` bad settings |
| PUT    | `/api/secrets-providers/{id}` | Any field but `provider_type`; a blank or missing secret keeps the stored one, unless the address or TLS settings change: then `400` until the secrets are sent again |
| DELETE | `/api/secrets-providers/{id}` | `409` while a credential or secret variable references it |
| POST   | `/api/secrets-providers/{id}/test` | `{path, key?}`: resolves without the cache; `{ok: true}` or `{ok: false, code, message}`, never the value |

### Jobs
| Method | Endpoint                | Description                |
|--------|-------------------------|----------------------------|
| GET    | `/api/jobs`             | List job history           |
| GET    | `/api/jobs/{id}`        | Job detail                 |
| GET    | `/api/jobs/{id}/events` | All log events for a job, for its launcher or an admin. Configuration secrets in the messages are masked (`********`) unless the caller is an admin, the API token, or holds `config-backups.write` with write access to every target of the job (`docs/jobs.md#device-secrets-in-job-output`) |
| POST   | `/api/jobs/launch`      | Launch a job (see below)   |
| POST   | `/api/jobs/{id}/retry`  | Same job again; a live job needs the task's commit permission |
| POST   | `/api/jobs/{id}/rerun`  | Same job, live; needs the task's commit permission |
| POST   | `/api/jobs/{id}/cancel` | Cancel a job awaiting approval, queued or running |
| GET    | `/api/jobs/approvals`   | Needs `jobs.approve`. Jobs in `pending_approval` the caller may decide, oldest first: within the caller's object scope (every target writable) and not launched by the caller. `limit` 1 to 500 (200). Same fields as `GET /api/jobs/{id}` |
| POST   | `/api/jobs/{id}/approve` | Needs `jobs.approve`. `{comment?}` (at most 2000 characters). A job in `pending_approval` moves to `queued` and runs as usual: `{ok, job_id, status: "queued", approval_status: "approved"}`. `400` when the job is not awaiting approval, `403` for the job's own requester (admins included), `409` when another decision or a cancel won |
| POST   | `/api/jobs/{id}/deny`   | Needs `jobs.approve`. `{comment?}`. The job ends in `denied` (terminal, never runs): `{ok, job_id, status: "denied", approval_status: "denied"}`; errors as for approve |
| WS     | `/ws/jobs/{id}`         | Real-time event stream. Like every `/ws/*` socket, a handshake whose `Origin` header names another host than the request's `Host` is closed unless the origin is listed in `APP_CORS_ORIGINS`; a client that sends no `Origin` (a script, not a browser) is not affected. Messages are masked as on `GET /api/jobs/{id}/events` |

**Launch payload:**
```json
{
  "playbook_id": 3,
  "inventory_group_id": 1,
  "credential_id": 1,
  "template_id": 1,
  "commit": false,
  "inputs": { "vlan_id": 120, "peer": "192.0.2.10" }
}
```

`commit` defaults to `false` (dry run: Python `dry_run=True`, Ansible
`--check --diff`); the legacy `dry_run` flag is still accepted and `commit`
wins. `inputs` (legacy name `parameters`) is checked against the task's
input schema: `422` with `detail.fields` (one message per field) for a bad
value or a host, group or secret that does not exist. A dry run of a task
with `supports_dry_run` false answers `422` (`fields.commit`). A caller the
task's run, or for a live run commit, permission refuses gets `403`. The job
record keeps the inputs in `parameters`, secret inputs as `{{secret.NAME}}`
references only, and the mode in `dry_run`.

A task with `approval_required` (`GET`/`POST`/`PUT /api/playbooks`, admin
only to change) launches, retries and re-runs jobs in status
`pending_approval` (`{"job_id": 7, "status": "pending_approval"}`), which the
queue never starts. A job row carries `approval_status` (`not_required`,
`pending`, `approved`, `denied`), `approved_by` (who decided, for an approval
or a denial), `approved_at` (UTC ISO 8601) and `approval_comment`. See
[jobs.md](jobs.md#approvals).

### Integration availability mutes
Mutes of the entities the integrations collect (Meraki, Cato, FMC, Panorama, Appgate, OPNsense, AWS, Azure, GCP). A muted entity is left off the Dashboard and raises no alert. See [meraki-topology.md](meraki-topology.md#muting).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/availability/topology/mutes` | `monitoring` feature. `mutes`: each with `id`, `provider`, `org_ref`, `scope` (`entity`, `site`), `entity_type`, `entity_id`, `site`, `reason`, `created_by`, `created_at` (UTC) |
| POST   | `/api/availability/topology/mutes` | `monitoring` feature, audited. `provider`, `org_ref`, `scope`, `reason` (1 to 500 characters) and, for `entity`, `entity_type` and `entity_id`, or for `site`, `site`. `404` when no tracked entity matches. Muting the same target again updates the reason. Returns `201` with `mute` and `acknowledged` (open host alerts acknowledged as `muted`) |
| DELETE | `/api/availability/topology/mutes/{id}` | `monitoring` feature, audited. `404` when absent |

### Integration entity metrics and SLA
Latency, jitter and loss reported by an integration for an entity (OPNsense gateways: dpinger RTT, RTT deviation as jitter, loss), and SLA targets of integration entities. See [sla-monitoring.md](sla-monitoring.md#targets-of-integration-entities).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/availability/topology/metrics` | `monitoring` feature. `provider`, `org_ref`, `entity_type`, `entity_id` (all required), `days` (1 to 365, default 7), `limit` (raw samples, 1 to 50000, default 5000). Returns `window_start`, `window_end` (UTC), `summary` (`avg_latency_ms`, `jitter_ms`, `avg_packet_loss_pct`, `avg_in_bps`, `avg_out_bps` and their `*_samples` counts, `traffic_in_samples` / `traffic_out_samples` for the traffic, over the window), `samples` (the raw samples still retained: `sampled_at`, `latency_ms`, `jitter_ms`, `loss_pct`, `in_bps`, `out_bps`, each `null` when not measured, oldest first) and `daily` (one row per UTC `day` with `latency`, `jitter`, `packet_loss`, `traffic_in`, `traffic_out` each `{avg, min, max, samples}` when measured that day; kept for `sla_retention_days`). `in_bps` / `out_bps` are the traffic received / sent through the entity in bits per second, averaged between two collections (OPNsense tunnels and OpenVPN servers) |
| GET    | `/api/sla/compliance?scope=topology` | Latest status of every (target, entity) of the targets that have a `provider`, worst first: `target_id`, `target_name`, `provider`, `org_ref`, `entity_type`, `entity_id`, `name`, `site`, `metric`, `value`, `target_value`, `warning_value`, `status`, `sample_count`, `window_days`, `window_start`, `window_end`, `evaluated_at`, `status_since`. Filters `provider`, `org_ref`, `entity_type`, `entity_id`, `target_id`. Without `scope` (or `scope=hosts`) the host rows as before |
| GET    | `/api/sla/compliance/history?scope=topology` | Status changes of those targets, newest first; filters `target_id`, `provider`, `org_ref`, `entity_id`, `limit` |

`POST /api/sla/targets` and `PUT /api/sla/targets/{id}` accept `provider` (a source type such as `opnsense`), `org_ref`, `entity_type` and `entity_id`: a target with a `provider` applies to the tracked entities of that provider (narrowed by the others when set) instead of hosts, and must not have `host_id` or `group_id` (400). `GET /api/sla/targets` returns these fields. `GET /api/availability/topology/summary` gives each entity `avg_latency_ms`, `jitter_ms`, `avg_packet_loss_pct`, `avg_in_bps`, `avg_out_bps` (window means, `null` without samples) and `sla_status` (the worst latest status of its targets, `null` without one). `POST /api/sla/evaluate` also returns `topology_evaluation` (counts as `evaluation`, plus `muted`).

`GET /api/availability/topology/summary` marks each entity with `muted` and `mute` (`id`, `scope`, `site`, `reason`, `created_by`, `created_at`, or null) and returns a `muted` total; its `up`, `degraded`, `down`, `unknown`, `avg_uptime_pct` and `total_outages` leave muted entities out. In `GET /api/dashboard`, `topology.entity_counts`, `by_provider` and `by_source` count a muted down or degraded entity under `muted`, and `problems` and `problem_count` leave it out.

`GET /api/monitoring/hosts/{host_id}/vendor-status` (`monitoring` feature, follows the host's object scope) returns the newest vendor-specific state the poll read from the host: `kind` (`apc_ups` for an APC Smart-UPS), `status` and `polled_at` (UTC), or `kind` `""` and an empty `status` when there is none. For a UPS, `status` has `model`, `firmware` (as the UPS reports it), `firmware_version`, `serial`, `output_status` / `output_status_label`, `battery_status` / `battery_status_label`, `battery_capacity_pct`, `runtime_minutes`, `output_load_pct`, `battery_needs_replacing`, `input_voltage_v`, `input_frequency_hz`, `output_voltage_v`, `last_transfer_cause` / `last_transfer_cause_label`, `battery_temperature_c`, `probe_temperature_c` (each `null` when the UPS does not report it) and the card's `nmc_model`, `nmc_firmware`, `nmc_application`, `nmc_application_firmware`, `nmc_serial`, `nmc_hardware`. See [apc-ups.md](apc-ups.md).

### Meraki alerts
Near-real-time Meraki alerts from the assurance-alert poll and the webhook receiver. See [meraki-alerts.md](meraki-alerts.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/monitoring/meraki-alerts` | `monitoring` feature. The alerts, open first then worst and newest; `include_resolved` (default false), `org_ref` (one source), `limit` (1 to 5000, default 500). Each row has `alert_key`, organization, network and device, `alert_type`, `condition`, `title`, `message`, `severity` (`critical`, `warning`, `info`), `status` (`open`, `resolved`), `started_at`, `resolved_at`, `last_seen` (UTC), `seen_via` (`poll`, `webhook`) and `alert_via` (how Plexus alerted: `monitoring`, `notification`, `topology`, `muted`, or empty) and `muted` (its device or network is muted) |
| GET    | `/api/monitoring/meraki-alerts/settings` | Admin. `config` (`poll_enabled`, `interval_seconds`, `webhook_enabled`, `webhook_secret_configured`, `excluded_sources`, `webhook_open_ttl_hours`), `webhook_active`, `webhook_path`, the interval bounds, `status` (last poll, last webhook, last test webhook, accepted / rejected / unknown-organization counts) and `sources` (each Meraki source with its last poll, last success and last error). The secret is never returned |
| PUT    | `/api/monitoring/meraki-alerts/settings` | Admin, audited. Any of `poll_enabled`, `interval_seconds` (30 to 3600), `webhook_enabled`, `webhook_secret` (16 to 256 printable characters; sets or rotates the secret and turns the receiver on unless `webhook_enabled` is false), `clear_webhook_secret`, `excluded_sources` (source ids not polled; their webhooks are still accepted), `webhook_open_ttl_hours`. Returns the same body as GET |
| POST   | `/api/monitoring/meraki-alerts/poll` | Admin, audited. Poll every enabled Meraki source now, ignoring back-off and the poll switch; returns per-source results |
| POST   | `/api/webhooks/meraki` | Meraki's webhook receiver (no session, no CSRF). JSON only, at most 256 KiB; `sharedSecret` in the body must match. `200 {"ok": true}` when accepted (the alert work runs after the response), `401` on a wrong or missing secret, `404` while the receiver is off, `400` / `413` / `415` on a malformed, oversized or non-JSON body, `429` when the source IP passes its rate limit |

### Vendor alert feeds
Near-real-time alerts read from a vendor's API feed, in one vendor-neutral store; the Cato events feed (`{provider}` `cato`) is the first. See [cato-alerts.md](cato-alerts.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/monitoring/vendor-alerts` | `monitoring` feature. The alerts, open first then worst and newest; `provider` (`cato`, `aws`, `azure`), `include_resolved` (default false), `org_ref` (one source), `limit` (1 to 5000, default 500). Each row has `provider`, `alert_key`, `org_ref`, `org_name`, the entity (`entity_type`, `entity_id`, `entity_name`, `site`, `serial`), `condition`, `event_type`, `event_sub_type`, `title`, `message`, `severity` (`critical`, `warning`, `info`), `status` (`open`, `resolved`), `auto_expire`, `started_at`, `resolved_at`, `last_seen` (UTC), `occurrences`, `alert_via` (`monitoring`, `notification`, `topology`, `muted`, or empty), `host_id` and `muted` (its entity or site is muted). Object scope: a scoped caller sees only the alerts raised on hosts it may read |
| GET    | `/api/monitoring/vendor-alerts/{provider}/settings` | Admin. `provider`, `label`, `description`, `current_state` (`true` for AWS and Azure: an alert closes when a complete read no longer reports it), `parts` (`key`, `label`, `enabled`: the parts that can be switched off, AWS `cloudwatch`, `health`, `ec2_status` and Azure `monitor_alerts`, `resource_health`; empty for Cato), `config` (`poll_enabled`, `interval_seconds`, `excluded_sources`, `open_ttl_hours`, `security_events`, and `disabled_parts` for a feed with parts), the interval bounds, `status` (last poll, whether it succeeded, how many sources failed) and `sources` (each source with `last_poll_at`, `last_ok_at`, `last_error`, `feed_status`: `ok`, `positioned`, `partial` (read, with a part refused or a region failed: `last_error` says which; not backed off), `refused`, `no_access`, `rate_limited`, `unreachable`, `error` or empty; `cursor_set`, `last_event_at`, `events_read`, `next_poll_at`). `404` for an unknown provider |
| PUT    | `/api/monitoring/vendor-alerts/{provider}/settings` | Admin, audited. Any of `poll_enabled`, `interval_seconds` (30 to 3600), `excluded_sources` (source ids not read), `open_ttl_hours` (1 to 720: a one-shot alert closes after this long), `security_events` (store the feed's IPS events as security events), `disabled_parts` (the part keys switched off; unknown keys are dropped; a part switched off resolves its open alerts at the next poll). Returns the same body as GET |
| POST   | `/api/monitoring/vendor-alerts/{provider}/poll` | Admin, audited. Read every source of the feed now, ignoring back-off and the poll switch (a source another app worker is reading is skipped); returns per-source results |

### Security events
The security events integrations read from a device, today the intrusion detection (Suricata) alerts of OPNsense firewalls. Stored and alerted on the server; see [opnsense-topology.md](opnsense-topology.md#ids-alerts) and [monitoring.md](monitoring.md#security).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/monitoring/security-events` | `monitoring` feature, read only. The events of the last `hours` (1 to 8760, default 24), newest first: `severity` (`critical`, `warning`, `info`, `unknown`), `action` (`blocked`, `allowed`), `q` (up to 200 characters: signature, signature id, category, source or destination address), `host_id` (one inventory host; `404` when unknown or outside the caller's scope), `org_ref` (one source), `provider` and `kind` (`ids_alert`), `limit` (1 to 500, default 100), `offset` (0 to 100000). Answers `events` (each with `id`, `provider`, `org_ref`, `source_name`, `host_id`, `hostname`, `kind`, `occurred_at` and `received_at` (UTC), `severity`, `priority`, `signature_id`, `signature`, `category`, `action`, `protocol`, `src_ip`, `src_port`, `dest_ip`, `dest_port`, `interface`, `flow_id`, `app_proto`), `total` (all matching), `counts` (per severity and `blocked`), `since`, `hours`, `limit`, `offset`. A scoped caller sees the events of the hosts it may read only; an event of a device that is no inventory host is left out for it. Invalid parameters answer `422` |

### SNMP trap rules
The built-in and custom SNMP trap alert rules. Reads need the `monitoring` feature, every POST, PUT, PATCH and DELETE `monitoring.write`; writes are audited (`trap_rule.*`). A caller limited to selected inventory groups reads the rules and cannot change them. See [snmp-traps.md](snmp-traps.md#custom-rules).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/monitoring/trap-rules` | The built-in rules, then the custom ones: `id` (null for a built-in), `key`, `source` (`trap`), `metric` (`trap_<key>`, `trap_custom_<id>`), `name`, `description`, `builtin`, `enabled`, `severity`, `match_type` (`builtin`, `trap`), `pattern` / `clear_pattern` (a custom rule's raising and clearing traps), `tags` / `clear_tags` (a built-in rule's trap names), `families`, `threshold_count`, `threshold_window_seconds`, `auto_resolve_minutes`, `created_by`, `created_at`, `updated_at`; a custom rule also `trap_match` (`conditions`, `clear_conditions`: each `object`, `op` (`equals`, `contains`, `regex`), `value`; `instance`: `object`, `part` (`value`, `index`)) |
| POST   | `/api/monitoring/trap-rules` | Create a custom rule: `name`, `pattern` (comma separated trap OIDs, `<OID>.*` prefixes or registry names), optional `clear_pattern`, `severity` (`info`, `warning`, `critical`), `enabled`, `threshold_count` (1 to 1000), `threshold_window_seconds` (1 to 86400), `auto_resolve_minutes` (0 to 10080), `trap_match` (at most 10 conditions per side; clearing conditions need a clearing trap). `201` with the rule; `400` with the reason when invalid |
| PUT    | `/api/monitoring/trap-rules/{id}` | Update a custom rule (fields left out keep their value). Disabling it resolves its open alerts. `404` for an unknown id or a syslog rule's id |
| DELETE | `/api/monitoring/trap-rules/{id}` | Delete a custom rule and resolve its open alerts: `{ok, alerts_resolved}` |
| PATCH  | `/api/monitoring/trap-rules/builtin/{key}` | `enabled`, `severity` of a built-in rule |
| POST   | `/api/monitoring/trap-rules/test` | `event_id` (a stored SNMPv1 / v2c trap of a host the caller can read; `400` when it cannot be decoded again, `404` when absent) or `trap_oid` with `varbinds` (`[[oid, value], ...]`, at most 64), and optionally `rule` (an unsaved custom rule). Answers `name`, `trap_oid`, `message`, `varbinds` (each `oid`, `name`, `index`, `value`, `label`), `matches` (each rule that raises or clears: `key`, `name`, `builtin`, `enabled`, `action`, `instance`), `draft`, `config_change`, `repoll`, and for a `clogMessageGenerated` trap `syslog_line` and `syslog` (what the syslog rules do with it, as `/api/monitoring/syslog-rules/test` answers) |

### Event webhooks
Outbound requests sent when a tracked object is created, updated or deleted. Admin only; every write is audited. Payload, headers and signature: see [webhooks.md](webhooks.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/admin/webhooks` | `webhooks` (each with `id`, `name`, `enabled`, `url`, `http_method`, `content_type`, `object_types`, `actions`, `filters`, `headers` (values masked), `has_secret`, `secret` (masked or empty), `body_template`, `verify_tls`, `ca_bundle`, `timeout_seconds`, `max_retries`, `concurrency`, `created_by`, `created_at`, `updated_at`), `stats` (per webhook: `queue_depth`, `delivered`, `failed`, `dropped_queue_full`, `last_error`, ...), `object_types` and `actions` (the accepted values) |
| GET    | `/api/admin/webhooks/{id}` | One webhook, as in the list; `404` when it does not exist |
| POST   | `/api/admin/webhooks` | `name` (unique), `url` (http/https, passes the SSRF guard), `object_types` (non-empty subset of `host`, `group`, `prefix`, `ip_address`, `vlan`, `vrf`, `credential`, `config_backup`, `job`), `actions` (non-empty subset of `create`, `update`, `delete`) and optional `enabled`, `http_method` (`POST`, `PUT`, `PATCH`), `content_type`, `filters` (field -> allowed values), `headers` (name -> value; `X-Plexus-*` and transport headers refused), `body_template` (Jinja2), `secret`, `verify_tls`, `ca_bundle` (PEM), `timeout_seconds` (1 to 60), `max_retries` (0 to 10), `concurrency` (1 to 10). `201` with the webhook; `400` with the reason on invalid input |
| PUT    | `/api/admin/webhooks/{id}` | Same body as POST, replacing the webhook. A `secret` of `null` or the mask keeps the stored secret, `""` clears it; a header value equal to the mask keeps that header's stored value |
| DELETE | `/api/admin/webhooks/{id}` | Deletes the webhook and its delivery log: `{"ok": true}` |
| POST   | `/api/admin/webhooks/{id}/test` | Sends one `webhook.test` event now, without retries: `ok`, `status` (`success`, `failed`, `blocked`), `status_code`, `latency_ms`, `error`, `delivery_id` |
| GET    | `/api/admin/webhooks/{id}/deliveries` | `deliveries`, newest attempt first; `limit` (1 to 1000, default 100). Each has `id`, `delivery_id`, `event`, `object_type`, `object_id`, `action`, `attempt`, `status` (`success`, `retrying`, `failed`, `blocked`), `status_code`, `latency_ms`, `response_body` (first 2000 characters), `error`, `created_at` |
| POST   | `/api/admin/webhooks/{id}/deliveries/{delivery_row_id}/redeliver` | Sends the logged body again once with the same `X-Plexus-Delivery` id; same result as test. `404` for a delivery of another webhook, `400` when the body was too large to keep |

### Change log
The recorded creates, updates and deletes of tracked objects, field by field; see [change-log.md](change-log.md). Any signed-in user; each object type needs the feature of its REST routes (hosts and groups `inventory`, prefixes, addresses, VLANs and VRFs `ipam`, config backups `config-backups`, jobs `jobs`, credentials admin), and accounts limited to selected inventory groups see only their groups' hosts, groups and config backups.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/changes` | `changes` (newest first; each with `id`, `object_type`, `object_id`, `object_label`, `action`, `user`, `correlation_id`, `changed_at`, `changes`, `before`, `after`), `total`, `limit`, `offset`, `object_types` (the readable types). Filters: `object_type`, `object_id`, `object_label`, `user`, `action`, `since`, `until` (ISO 8601, inclusive); `limit` (1 to 500, default 50), `offset`. `403` for a type the caller may not read, `400` for an unknown type, action or date |
| GET    | `/api/changes/{object_type}/{object_id}` | The history of one object, as above; takes `user`, `action`, `since`, `until`, `limit`, `offset` |

### GraphQL API

Read-only queries across inventory, IPAM, locations and tenancy, the device model, circuits, DCIM, virtualization, routing and hardware lifecycle with nested relations; see [GraphQL API](graphql-api.md) for the schema, the per-field features and the limits.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST   | `/api/graphql` | `graphql` feature. `{"query", "variables", "operationName"}`; answers `{"data", "errors"}`. Queries only. Each field also needs the feature of its REST counterpart (`inventory`, `reports`, `ipam`, `config-backups`, `organization`, `circuits`, `dcim`, `virtualization`, `routing`, `lifecycle`) and hosts and groups outside the caller's object scope are left out. `400` when the query cannot run (syntax, unknown field, mutation, depth, aliases, estimated cost, introspection while it is off, more than 20,000 characters); field errors answer `200` with the other fields. Session callers send `X-CSRF-Token` |
| GET    | `/api/graphql` | `graphql` feature. The GraphiQL page when the `graphiql` setting is on (own Content-Security-Policy, assets from unpkg.com with SRI), else `404`. Never runs a query |
| GET    | `/api/admin/graphql/settings` | Admin. `graphiql`, `introspection`, `max_depth`, `max_aliases`, `max_complexity`, `max_limit` |
| PUT    | `/api/admin/graphql/settings` | Admin, audited (`graphql` / `settings_update`). Any of `graphiql`, `introspection` (booleans), `max_depth` (2 to 20), `max_aliases` (0 to 200), `max_complexity` (100 to 1000000), `max_limit` (10 to 10000). Returns the merged settings; `422` on an unknown key or a value out of bounds |

### AI access (MCP)
A read-only Model Context Protocol endpoint for AI clients, and the admin routes that manage it. See [ai-access.md](ai-access.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST   | `/mcp` | The MCP endpoint (Streamable HTTP, JSON responses, stateless; `/mcp/` is the same). Authenticated only by `Authorization: Bearer <MCP token>`: no session cookie, no CSRF token, and `APP_API_TOKEN` is refused. `404` while AI access is off, `401 {"error": "unauthorized"}` with `WWW-Authenticate: Bearer` on a missing, unknown, revoked or expired token, `429` after 20 failed attempts from one address in a minute, `405` for any method but POST. Serves `initialize`, `ping`, `tools/list` (only the tools the token may use) and `tools/call`; tool failures are returned as MCP tool errors, never as HTTP 500 |
| GET    | `/api/admin/mcp/settings` | Admin. `enabled`, `max_result_bytes`, `max_rows`, `calls_per_minute` |
| PUT    | `/api/admin/mcp/settings` | Admin, audited. Any of `enabled` (boolean), `max_result_bytes` (10000 to 1000000), `max_rows` (10 to 1000), `calls_per_minute` (1 to 600). Returns the merged settings; `422` on an unknown key or a value out of bounds |
| GET    | `/api/admin/mcp/tokens` | Admin. `tokens` (each with `id`, `name`, `token_prefix`, `owner_user_id`, `owner_username`, `owner_role`, `categories`, `expires_at`, `created_at`, `created_by`, `last_used_at`, `call_count`, `revoked_at`; never the token or its hash) and `categories` (every category a token can be given) |
| POST   | `/api/admin/mcp/tokens` | Admin, audited. `name` (1 to 80 characters, unique), `owner_user_id`, `categories` (non-empty subset of the known categories), `expires_at` (`""` or `YYYY-MM-DD`). Returns `{"token", "record"}`; `token` is the only time the plaintext is returned. `422` on invalid input (including the `audit` category with a non-admin owner), `409` when the name is taken |
| DELETE | `/api/admin/mcp/tokens/{id}` | Admin, audited. Revokes the token: `{"revoked": true}`; `404` when it does not exist or is already revoked |

### ChatOps
Slack, Webex and Microsoft Teams bots. The inbound endpoints take no session or CSRF token and check the platform's signature; the admin routes are admin only and every write is audited (`chatops`). See [chatops.md](chatops.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST   | `/api/chatops/slack/commands` | Slack slash command (form body). `X-Slack-Signature` / `X-Slack-Request-Timestamp` checked (five-minute window, a repeated signature refused). Answers the Block Kit reply, or `Working on it...` and the reply later through `response_url` |
| POST   | `/api/chatops/slack/interactivity` | Slack button presses (`payload` form field, `block_actions`); same signature check. `200` at once, the result posted to `response_url` |
| POST   | `/api/chatops/webex` | Webex webhook for `messages` / `attachmentActions` `created`. `X-Spark-Signature` checked; `{"ok": true}` at once, the message fetched and answered in its room with the bot token. Messages from bots and repeated ids are ignored |
| POST   | `/api/chatops/teams` | Teams outgoing webhook. `Authorization: HMAC` checked; answers a message with an Adaptive Card |
| GET    | `/api/admin/chatops` | `platforms` (each with `label`, `secret_label`, `has_bot_token`, `paths` and `bot`: `name`, `enabled`, `allowed_commands`, `signing_secret_configured`, `bot_token_configured`, or `null`), `commands` (name, usage, summary, features, write) and `default_commands` |
| PUT    | `/api/admin/chatops/bots/{platform}` | `slack`, `webex` or `teams`. `name`, `enabled`, `allowed_commands`, `signing_secret` and `bot_token` (write-only, 8 to 512 characters; omitted or `null` keeps the stored value; the Teams token must be base64; required on first save), `clear_bot_token`. Returns the bot as in GET |
| DELETE | `/api/admin/chatops/bots/{platform}` | Removes the bot and its secrets; `404` when none |
| GET    | `/api/admin/chatops/mappings` | Mappings: `id`, `platform`, `chat_user_id`, `chat_label`, `user_id`, `username`, `role`, `created_by`, `created_at` |
| POST   | `/api/admin/chatops/mappings` | `platform`, `chat_user_id` (no spaces, compared ignoring case), `chat_label`, `user_id`. `201`; `409` when the chat identity is mapped; `422` for an unknown user |
| DELETE | `/api/admin/chatops/mappings/{id}` | Removes a mapping |
| GET    | `/api/admin/chatops/presets` | Job presets: `id`, `name`, `description`, `playbook_name`, `source_job_id`, `targets`, `commit`, `enabled`, `updated_at`, `updated_by` |
| POST   | `/api/admin/chatops/presets` | `name` (1 to 80 letters, digits, spaces, `.`, `-`, `_`, unique ignoring case), `job_id` (the job whose playbook, targets, credential, template and inputs are copied), `description`, `commit`, `enabled`. `201`; `409` on a taken name |
| PUT    | `/api/admin/chatops/presets/{id}` | `description`, `commit`, `enabled` |
| DELETE | `/api/admin/chatops/presets/{id}` | Deletes a preset |
| GET    | `/api/admin/chatops/log` | Newest commands first: `created_at`, `platform`, `chat_user_id`, `chat_user_name`, `username`, `command`, `arguments`, `outcome` (`ok`, `denied`, `unmapped`, `error`, `unknown`, `rate_limited`), `detail`, `duration_ms`. `limit` (1 to 1000, default 200), `platform`, `outcome` |

### Plugins
The plugin manifest and the routes of enabled plugins. See [plugin-development.md](plugin-development.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/plugins` | Any signed-in user. `{"admin", "plugins"}`; each plugin has `name`, `label`, `version`, `description`, `status` (`disabled`, `failed`, `loaded`, `active`), `feature` (`plugin:<name>`), `navigation` and `pages` (the declarative page definitions). Users get only active plugins whose feature they hold; admins and the API token get every plugin plus `source`, `min_plexus_version`, `max_plexus_version`, `errors`, `has_router`, `migrations`, `migrations_applied`, `background_tasks` |
| any    | `/api/plugins/<name>/...` | The plugin's own routes. Needs `plugin:<name>` (`plugin:<name>.write` for POST, PUT, PATCH, DELETE); `401` without a session, `403` without the feature or the CSRF token, `503` while the plugin is not active, `404` when it is not installed |
