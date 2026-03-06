# RADIUS Configuration Guide for Plexus

This guide walks through setting up RADIUS authentication end-to-end:
- Network-side RADIUS server configuration
- Plexus app configuration in Settings
- Fallback behavior design
- Validation and troubleshooting

## 1. What Plexus Supports Today

Plexus login supports two auth providers:
- `local` (SQLite user database)
- `radius` (RADIUS Access-Request with local fallback options)

When RADIUS auth succeeds, Plexus will create a local shadow user automatically if needed.
This allows sessions, roles, and feature access policies to continue working in-app.

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
    "server": "10.10.10.20",
    "port": 1812,
    "secret": "replace-with-strong-secret",
    "timeout": 5,
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

## 10. Operational Rollout Plan

Use a phased rollout:
1. Pilot with a small admin group
2. Keep local fallback enabled
3. Verify logs and user experience
4. Expand to broader user groups
5. Revisit timeout and policies after stabilization
