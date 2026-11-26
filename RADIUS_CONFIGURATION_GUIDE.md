# RADIUS Configuration Guide for Plexus

This guide walks through setting up RADIUS authentication end-to-end:
- Network-side RADIUS server configuration
- Plexus app configuration in Settings
- Fallback behavior design
- Validation and troubleshooting

## 1. What Plexus Supports Today

Plexus login supports four auth providers:
- `local` (Plexus user database)
- `radius` (RADIUS Access-Request with local fallback options)
- `tacacs` (TACACS+ - the protocol switches use with Cisco ISE Device Admin;
  obfuscates the whole exchange and can assert the Plexus role from an ISE
  shell profile. Prefer it over RADIUS-PAP when ISE is the auth server -
  see `TACACS_CONFIGURATION_GUIDE.md`)
- `ldap` (LDAP/LDAPS bind with group-based role mapping)

When RADIUS auth succeeds, Plexus will create a local shadow user automatically if needed.
This allows sessions, roles, and feature access policies to continue working in-app.

RADIUS never grants the admin role. A RADIUS login signs in only to an account that
RADIUS created (or already manages). A login whose username matches a local account
(admin or not) or an account another provider (LDAP, TACACS+, OIDC, SAML) manages is
refused with "Invalid username or password" and audited as `auth` /
`login.adopt_refused`: a local account signs in with its local password instead. An
account created by a RADIUS login and later promoted to admin in **Settings → Users**
keeps signing in through RADIUS.

## 2. Prerequisites

Before enabling RADIUS in Plexus, ensure you have:
- A reachable RADIUS server (NPS, FreeRADIUS, ISE, etc.)
- UDP `1812` open between Plexus host and RADIUS server
- A configured RADIUS client entry for the Plexus server IP
- A shared secret configured on both sides
- At least one local `admin` account in Plexus for recovery

## 3. Network-Side RADIUS Setup (General)

Use your RADIUS platform to configure:
1. RADIUS client
- Name: `Plexus` (or similar)
- Client IP: IP of the Plexus server
- Shared Secret: strong random secret
- Auth Port: `1812`

2. Authentication policy
- Allow your intended users/groups
- Enable PAP-compatible authentication path (Plexus sends User-Password in standard RADIUS format)

3. Optional authorization policy
- Start with broad allow for pilot users
- Tighten by AD group or policy object after validation

## 4. Plexus App Configuration (UI)

In Plexus:
1. Go to `Settings` -> `Authentication Provider`
2. Set `Active Provider` to `RADIUS`
3. Configure these fields:
- `Enable RADIUS login path`: enabled
- `RADIUS Server`: IP/FQDN
- `Port`: `1812`
- `Shared Secret`: same as server-side client secret
- `Timeout (sec)`: recommended `3-5`
- `Require Message-Authenticator`: `ON` by default for a server that is
  being set up; mitigates Blast-RADIUS (CVE-2024-3596). Turn it off only
  when your RADIUS server cannot send the attribute (see Section 8): with
  it on, such a server fails every login as unreachable. A server set up
  before this default keeps the setting it had.

4. Configure fallback behavior:
- `Fallback to local auth when RADIUS is unavailable`: recommended `ON`
- `Allow fallback to local auth on RADIUS reject`: recommended `OFF`

5. Click `Save Auth Configuration`

## 5. Fallback Behavior Explained

Plexus supports two separate fallback controls:

1. `fallback_to_local` (recommended ON)
- If RADIUS times out/unreachable/errors, Plexus tries local auth
- Good for resilience during RADIUS outages

2. `fallback_on_reject` (recommended OFF)
- If RADIUS explicitly rejects credentials, Plexus can optionally try local
- Usually keep OFF to avoid bypassing centralized credential decisions

Recommended production posture:
- `fallback_to_local = true`
- `fallback_on_reject = false`

## 6. API-Based Configuration (Optional)

Admin API endpoint:
- `PUT /api/admin/auth-config`

Example payload:

```json
{
  "provider": "radius",
  "radius": {
    "enabled": true,
    "server": "192.0.2.20",
    "port": 1812,
    "secret": "replace-with-strong-secret",
    "timeout": 5,
    "enforce_message_authenticator": true,
    "fallback_to_local": true,
    "fallback_on_reject": false
  }
}
```

## 7. Validation Checklist

After enabling RADIUS, test these scenarios:
1. Valid RADIUS user
- Expected: login success, `auth_source = radius`

2. Invalid RADIUS password
- Expected with recommended config: login denied

3. RADIUS server down/unreachable
- Expected with `fallback_to_local=true`: local users can still login

4. Local admin break-glass account
- Confirm local admin can login during outage

## 8. Security Recommendations

- Keep `Require Message-Authenticator` on (Blast-RADIUS / CVE-2024-3596
  mitigation; on by default, off on a server set up before the default
  changed). Plexus then sends a Message-Authenticator in every
  Access-Request and rejects replies that omit or fail it. Requires a server
  updated after the July 2024 advisory (e.g. FreeRADIUS 3.0.27+/3.2.5+, or
  Microsoft NPS with the relevant update); enable the matching server-side
  option and verify a test login before rollout. While it is off,
  `GET /api/admin/security-check` warns.
- Use a long random shared secret
- Restrict UDP/1812 to only required hosts
- Keep at least one local admin account for recovery
- Keep `fallback_on_reject` disabled unless you have a strict business need
- Rotate shared secrets periodically

## 9. Troubleshooting

If login fails unexpectedly:
1. Verify network reachability to RADIUS server
- DNS resolution (if using hostname)
- Firewall ACL/NAT for UDP 1812

2. Verify secret and client IP mapping on RADIUS server
- Most failures are secret mismatch or wrong client IP

3. Check provider mode in Plexus
- Ensure `provider=radius` and `enabled=true`

4. Test local fallback intentionally
- Temporarily stop RADIUS service and confirm local login path

5. RADIUS accepts the password but Plexus answers "Invalid username or password"
- The audit log shows `login.adopt_refused`: the username matches a local account or
  one another provider manages (see section 1). Sign in to that account with its
  local password, or use a different username on one side. An account created by
  RADIUS before Plexus recorded providers is treated as local: delete it (the next
  login recreates it) or set its provider (`docs/administration.md`, Authentication).

## 10. Operational Rollout Plan

Use a phased rollout:
1. Pilot with a small admin group
2. Keep local fallback enabled
3. Verify logs and user experience
4. Expand to broader user groups
5. Revisit timeout and policies after stabilization
