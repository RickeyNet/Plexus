# Authorization Matrix

All API endpoints and their required authentication/authorization levels.

## Legend

| Guard | Meaning |
|-------|---------|
| **public** | No authentication required |
| **auth** | Valid session cookie or API token |
| **feature(X)** | Authenticated + user has access to feature X |
| **admin** | Authenticated + `role == "admin"` |
| **ws-auth** | WebSocket with session cookie validated before `accept()` |

## Endpoints

### Public (no auth)

| Method | Path | Notes |
|--------|------|-------|
| GET | `/` | Frontend SPA |
| POST | `/api/auth/login` | Rate-limited (brute-force protection) |
| POST | `/api/auth/register` | Gated by `APP_ALLOW_SELF_REGISTER` env flag |
| GET | `/api/auth/status` | Returns current session info |
| GET | `/api/health` | Health check (uptime, metrics) |
| GET | `/favicon.ico` | Static |
| GET | `/static/*` | Static files |

### Auth-only (any authenticated user)

| Method | Path | Router |
|--------|------|--------|
| POST | `/api/auth/logout` | auth |
| PUT | `/api/auth/change-password` | auth |
| GET/PUT | `/api/auth/profile` | auth |
| GET | `/api/dashboard` | + feature("dashboard") |
| CRUD | `/api/graphs/*` | graph_export |
| CRUD | `/api/dashboards/*` | dashboards |
| CRUD | `/api/graph-templates/*` | graph_templates |
| CRUD | `/api/reporting/*` | reporting |
| CRUD | `/api/cdef/*` | cdef |
| CRUD | `/api/mac-tracking/*` | mac_tracking |
| GET | `/api/secret-variables`, `/api/secret-variables/names` | (list/names for template autocomplete) |
| CRUD | `/api/flow-collector/*` | flow_collector |
| CRUD | `/api/baseline-alerting/*` | baseline_alerting |

### Feature-gated (auth + feature flag)

| Feature | Paths | Router |
|---------|-------|--------|
| `inventory` | `/api/inventory/*` | inventory |
| `topology` | `/api/topology/*` | topology |
| `jobs` | `/api/jobs/*` | jobs |
| `templates` | `/api/templates/*` | templates |
| `credentials` | `/api/credentials/*` | credentials |
| `playbooks` | `/api/playbooks/*` | playbooks |
| `config-drift` | `/api/config-drift/*` | config_drift |
| `config-backups` | `/api/config-backups/*` | config_backups |
| `compliance` | `/api/compliance/*` | compliance |
| `risk-analysis` | `/api/risk-analysis/*` | risk_analysis |
| `deployments` | `/api/deployments/*` | deployments |
| `monitoring` | `/api/monitoring/*`, `/api/sla/*` | monitoring |
| `monitoring` | `/api/metrics/*` | metrics_engine |
| `upgrades` | `/api/upgrades/*` | upgrades |

### Admin-only

| Paths | Router |
|-------|--------|
| `/api/admin/*` | admin |
| POST/PUT/DELETE | `/api/secret-variables/*` | (admin enforced in handlers) |
| `/api/inventory/admin/*` | inventory_admin |
| `/api/topology/admin/*` | topology_admin |
| `/api/compliance/admin/*` | compliance_admin |
| `/api/monitoring/admin/*` | monitoring_admin |
| `/api/metrics/admin/*` | metrics_engine_admin |

### WebSocket (self-authenticated)

| Path | Auth check | Feature check |
|------|-----------|---------------|
| `/ws/jobs/{job_id}` | session cookie | `jobs` feature |
| `/ws/config-capture/{job_id}` | session cookie | `config-drift` feature |
| `/ws/config-revert/{job_id}` | session cookie | `config-drift` feature |
| `/ws/deployment/{job_id}` | session cookie | `deployments` feature |
| `/ws/upgrades/{campaign_id}` | session cookie | `upgrades` feature |

### CSRF Protection

All `POST/PUT/PATCH/DELETE` requests to `/api/*` require a valid `X-CSRF-Token`
header when authenticated via session cookie. API-token authenticated requests
are exempt (not susceptible to CSRF).

### Credential Access (IDOR protection)

| Operation | Own credential | Unowned (NULL owner) | Other user's credential |
|-----------|---------------|---------------------|------------------------|
| List | ✅ | ❌ (admin only) | ❌ (admin only) |
| Create | ✅ (auto-owned) | — | — |
| Update | ✅ | ❌ (admin only) | ❌ |
| Delete | ✅ | ❌ (admin only) | ❌ |

## Notes

- OpenAPI docs (`/docs`, `/redoc`, `/openapi.json`) disabled by default; enable with `APP_ENABLE_DOCS=true`
- `must_change_password` flag blocks all non-password-change API access
- Rate limiting: login has brute-force protection; all API endpoints have per-IP sliding window limits when `API_RATE_LIMIT.enabled=true`
