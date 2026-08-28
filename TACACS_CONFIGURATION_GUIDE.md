# TACACS+ Configuration Guide for Plexus (Cisco ISE Device Admin)

This guide sets up TACACS+ login for Plexus end-to-end, with Cisco ISE as
the worked example:
- Why TACACS+ instead of RADIUS for Plexus login
- ISE-side configuration (network device, policy set, shell profile)
- Plexus app configuration in Settings
- Role mapping (ISE shell profile -> Plexus admin/user)
- Fallback behavior, validation, troubleshooting

## 1. What Plexus Supports Today

Plexus login supports four auth providers:
- `local` (SQLite/Postgres user database)
- `radius` (RADIUS PAP Access-Request, see `RADIUS_CONFIGURATION_GUIDE.md`)
- `tacacs` (TACACS+ authentication + exec authorization - this guide)
- `ldap` (LDAP/LDAPS bind with group-based role mapping)

The TACACS+ provider is the same protocol Cisco switches and routers use with
ISE "Device Administration" (RFC 8907). It speaks to ISE exactly like an IOS
device at login:

1. **Authentication** - `TAC_PLUS_AUTHEN` login, ASCII (interactive) or PAP.
2. **Authorization** - `service=shell cmd=` exec authorization. The reply's
   AV pairs (`priv-lvl`, plus any custom attribute) decide the Plexus role.

Both packets are obfuscated body-wide under the shared secret (RFC 8907 §4.5)
and travel over TCP/49. Compared with RADIUS-PAP that means the username and
all authorization data are hidden too, and off-path reply spoofing isn't
possible. The obfuscation is an MD5 keystream, not TLS - treat the Plexus ->
ISE path as a trusted management network, the same trust you already extend
to switch AAA traffic.

When TACACS+ succeeds, Plexus creates a local shadow user automatically so
sessions, roles and feature-access groups keep working in-app.

## 2. Prerequisites

- Cisco ISE with a **Device Administration** license and the TACACS+ service
  enabled on at least one PSN (Administration -> System -> Deployment ->
  node -> *Enable Device Admin Service*).
- TCP `49` open from the Plexus host to the ISE PSN(s).
- The Plexus host's source IP (post-NAT, if any) - ISE matches network
  devices by IP.
- A strong shared secret.
- At least one local `admin` account in Plexus for recovery (break-glass).
- `tacacs_plus` Python package present (it is in `requirements.txt` and the
  container image; Settings shows `tacacs` in the provider list when the
  import succeeded).

## 3. ISE-Side Setup

### 3.1 Network Device

Administration -> Network Resources -> Network Devices -> **Add**

- Name: `Plexus`
- IP address: Plexus host IP (use a /32; if Plexus runs in Docker with host
  networking or behind NAT, the IP ISE sees is what matters)
- Device Profile: `Cisco` is fine
- Network Device Group: create/choose a group such as `Device Type = Plexus`
  so policy can target it
- **TACACS Authentication Settings**: enable, set the shared secret

### 3.2 TACACS Profile (shell profile)

Work Centers -> Device Administration -> Policy Elements -> Results ->
**TACACS Profiles** -> Add

Create one profile per Plexus role:

| Profile name    | Common Tasks -> Default Privilege | Custom Attributes            |
|-----------------|-----------------------------------|------------------------------|
| `Plexus-Admin`  | 15                                | `plexus-role` = `admin` (MANDATORY) |
| `Plexus-User`   | 1                                 | `plexus-role` = `user` (MANDATORY)  |

The custom attribute is the explicit signal; `priv-lvl` is the fallback (see
§6). Either alone works; sending both is the least ambiguous.

### 3.3 Allowed Protocols

Work Centers -> Device Administration -> Policy Elements -> Results ->
**Allowed Protocols**. The default `Default Device Admin` set permits
PAP/ASCII, which is what Plexus uses. No EAP/CHAP needed.

### 3.4 Device Admin Policy Set

Work Centers -> Device Administration -> **Device Admin Policy Sets** -> Add

- Policy set condition: `DEVICE:Device Type EQUALS Device Type#All Device Types#Plexus`
  (or `Network Access:NetworkDeviceName EQUALS Plexus`)
- Allowed Protocols: `Default Device Admin`
- Authentication Policy: identity store = your AD join point (or ISE internal
  users for a pilot)
- Authorization Policy (top to bottom):
  1. `AD group = Network-Admins` -> Shell Profile `Plexus-Admin`
  2. `AD group = Network-Operators` -> Shell Profile `Plexus-User`
  3. Default -> **DenyAccess**

Rule 3 is what actually restricts who can log in: a user who authenticates
but hits DenyAccess gets an authorization FAIL, which Plexus treats as a
reject (never as "default role").

## 4. Plexus App Configuration (UI)

Settings -> Authentication:

1. `Auth Provider`: **TACACS+**
2. Fields:
   - `Enabled`: on
   - `Server`: ISE PSN IP/FQDN (one server; put a VIP/load balancer here if
     you need PSN failover, or rely on local fallback during outages)
   - `Port`: `49`
   - `Shared Secret`: as configured on the ISE network device
   - `Timeout (s)`: `3-5`
   - `Authentication Type`: `ASCII` (default, mirrors IOS login) or `PAP`.
     ISE accepts both; pick PAP only if a policy element requires it.
   - `Authorize (map ISE shell profile to role)`: **on** (recommended)
   - `Authorization Service`: `shell` (matches an unmodified ISE shell
     profile; change only if you built a custom TACACS service)
   - `Role Attribute`: `plexus-role`
   - `Admin priv-lvl`: `15` (`0` disables the priv-lvl rule)
   - `Default Role`: `user`
3. Fallback:
   - `Fallback to local`: recommended **on**
   - `Fallback on reject`: recommended **off**
4. Optional `Default Access Groups` for newly-created shadow users
5. **Save Authentication**

## 5. Fallback Behavior

Identical to the RADIUS/LDAP providers:

- `fallback_to_local` (on): ISE unreachable / timeout / protocol ERROR ->
  Plexus tries local credentials. Keeps you in during an ISE outage.
- `fallback_on_reject` (off): an explicit FAIL from ISE (bad password *or*
  authorization DenyAccess) is final. Leave off so ISE policy can't be
  bypassed with a stale local password.
- Break-glass: a real local `admin` password always works while
  `PLEXUS_BREAKGLASS_LOCAL_ADMIN` is true (default), regardless of fallback
  settings.

## 6. Role Mapping

With `Authorize` on, the role is re-evaluated on **every** login from the
authorization reply, in this order:

1. `<Role Attribute>` (default `plexus-role`) present with value `admin` or
   `user` -> that role.
2. `priv-lvl` >= `Admin priv-lvl` (default 15) -> `admin`.
3. Otherwise `Default Role`.

Because the ISE profile is authoritative, a user moved out of the admin AD
group is demoted on their next login (same semantics as LDAP). A local
promotion made in the Plexus UI does **not** survive the next TACACS+ login.

With `Authorize` off, Plexus only authenticates (RADIUS-style): every new
shadow user gets `Default Role`, and roles are then managed locally in
Plexus and never touched by TACACS+.

Plexus refuses to let an external identity claim a pre-existing **local**
admin account of the same username (see `upsert_external_user`); rename one
of them.

## 7. API-Based Configuration (Optional)

```bash
curl -s -X PUT https://plexus.example/api/admin/auth-config \
  -H "Content-Type: application/json" -b cookies.txt \
  -d '{
    "provider": "tacacs",
    "tacacs": {
      "enabled": true,
      "server": "ise-psn1.corp.local",
      "port": 49,
      "secret": "REPLACE_ME",
      "timeout": 5,
      "authen_type": "ascii",
      "authorize": true,
      "service": "shell",
      "role_attribute": "plexus-role",
      "admin_priv_lvl": 15,
      "default_role": "user",
      "fallback_to_local": true,
      "fallback_on_reject": false,
      "default_group_ids": []
    }
  }'
```

`GET /api/admin/auth-config` returns the secret masked as `••••••••`;
sending the mask back on `PUT` keeps the stored secret.

## 8. Validation Checklist

1. `GET /api/admin/capabilities` lists `tacacs` under `auth_providers`.
2. ISE: Operations -> TACACS -> Live Log shows the Plexus IP with
   *Authentication Passed* then *Authorization Passed* and the expected shell
   profile.
3. Plexus log (`plexus.auth`) shows
   `tacacs: user 'x' authorized by <server> (priv-lvl=15, role=admin)`.
4. Log in as an admin-group user -> Settings visible. Log in as an
   operator-group user -> `user` role. Log in as a user outside both groups ->
   `Invalid username or password` (ISE shows Authorization Failed).
5. Stop/block ISE -> local fallback works for a local account; break-glass
   admin works.

## 9. Security Recommendations

- Keep the Plexus -> ISE path on the management network; TACACS+ obfuscation
  is MD5-based (RFC 8907 §10.3) and not a substitute for a trusted segment.
- Use a long random shared secret unique to the Plexus network device.
- Leave `fallback_on_reject` off.
- Make rule order in the ISE authorization policy end in **DenyAccess**.
- Rotate the secret via the ISE network device page and Plexus Settings in
  the same change window; there is no secret overlap period.
- ISE TACACS+ live logs are your audit trail for *who logged into Plexus*;
  Plexus' own audit log records the resulting session with
  `auth_source=tacacs`.

## 10. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `TACACS+ authentication service unavailable` | TCP/49 blocked, wrong PSN, Device Admin service not enabled on that PSN, or the Plexus IP isn't a registered network device (ISE silently drops unknown clients). |
| ISE live log: *Invalid TACACS+ shared secret* / packet decode errors | Secret mismatch. |
| Auth passes in ISE, Plexus says invalid credentials | Authorization hit DenyAccess (no shell profile). Check the authz rule conditions and the Live Log's "Authorization Failed" detail. |
| Everyone lands as `user` | Shell profile lacks the `plexus-role` attribute *and* Default Privilege < `Admin priv-lvl`; or `Authorize` is off. |
| `tacacs: tacacs_plus library is not installed` | Package missing in this environment - `pip install -r requirements.txt` / rebuild the image. |
| Works with PAP, fails with ASCII (or vice versa) | ISE allowed-protocols or an ISE patch quirk; switch `Authentication Type`. Both are equivalent security-wise inside the obfuscated body. |
