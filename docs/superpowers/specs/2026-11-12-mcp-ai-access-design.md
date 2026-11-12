# AI Access via MCP Server: Design

Date: 2026-11-12
Status: awaiting review

## Goal

A company running Plexus in its network can connect an AI client (Claude
Desktop, Claude Code, or any other MCP-capable client) to Plexus. The AI can
then read what Plexus has collected in order to diagnose an issue ("why can't
A reach B", "what changed before the outage") or produce a report ("which
devices have SNMPv2 configured", "which devices run a version with open
CVEs").

Success means: an admin enables the feature, creates a token, pastes a
connection snippet into an AI client, and the AI can answer those questions
using Plexus data, without any secret leaving Plexus and with every call
audited.

## Decisions made

| Topic | Decision |
|---|---|
| Access model | MCP server only. No chat UI in Plexus, no AI provider keys stored in Plexus. |
| Authentication | Scoped MCP tokens created by admins. Bearer header. |
| Data scope | Per-token data categories. Secret redaction always on. Credentials never exposed. |
| Tool reach | Stored data plus computed analysis (config search, config diff, offline path trace). No traffic to devices or vendor APIs. |
| Implementation | Official `mcp` Python SDK mounted in the existing FastAPI process. |

## Out of scope

- Built-in chat UI and storage of AI provider API keys.
- OAuth 2.1 (needed for cloud-hosted connectors such as claude.ai web).
- Write tools, and live checks (ping, SNMP poll, show commands, collector
  re-runs).
- Anonymising IP addresses and hostnames.
- MCP prompts and resources. The server offers tools only.

Consequence to document for users: clients running on a user's machine reach
Plexus directly. Cloud-hosted AI connectors do not work with this release,
because they need Plexus reachable from the internet and expect OAuth.

## Architecture

New package `netcontrol/mcp/`:

| Module | Responsibility |
|---|---|
| `server.py` | Builds the SDK server and returns the Streamable HTTP ASGI app, mounted at `/mcp` by `netcontrol/app.py`. Stateless mode, tools only. |
| `auth.py` | Validates the bearer token and builds the call context: token id, owner user, allowed categories. |
| `registry.py` | Tool registry. Each tool declares name, description, category, input schema and handler. |
| `dispatch.py` | The single path every tool call takes: category check, handler, redaction, size cap, audit. |
| `redact.py` | Masks secrets in config text and in structured rows. |
| `tools/<category>.py` | One module per category. Thin handlers over `routes/db/*`. |

Request flow:

1. Client sends a request to `/mcp` with `Authorization: Bearer plx_mcp_...`.
2. `auth.py` resolves the token to a call context, or returns HTTP 401.
3. `tools/list` returns only the tools in the context's effective categories.
4. `tools/call` goes through `dispatch.py`: check category, run handler, redact
   the result, apply size caps, write the audit event, return the result.

If the SDK turns out to conflict with the pinned Starlette version or fails
`pip-audit`, the fallback is a hand-written stateless JSON-RPC endpoint
implementing `initialize`, `ping`, `tools/list` and `tools/call` behind the
same `auth.py`, `registry.py` and `dispatch.py`. SDK 2.3.0 declares
`starlette>=0.27` with no upper bound, so no conflict is expected.

## Tokens

New table `mcp_tokens` (added through `routes/migrations`):

| Column | Notes |
|---|---|
| `id` | Primary key. |
| `name` | Admin-chosen label, unique. |
| `token_hash` | SHA-256 of the token. The plaintext is never stored. |
| `token_prefix` | First characters, for display and identification. |
| `owner_user_id` | The Plexus user the token acts as. |
| `categories` | List of allowed data categories. |
| `expires_at` | Optional. |
| `created_at`, `created_by` | |
| `last_used_at`, `call_count` | Updated on use. |
| `revoked_at` | Set on revoke. Revoked tokens are kept for audit history. |

Rules:

- Tokens are generated server-side with `secrets.token_urlsafe`, prefixed
  `plx_mcp_`, and shown once at creation.
- Lookup is by hash. Comparison uses `secrets.compare_digest`.
- Admin-only CRUD at `/api/admin/mcp-tokens` (list, create, revoke).
- MCP tokens and `APP_API_TOKEN` are separate: an MCP token is rejected on
  `/api/*`, and `APP_API_TOKEN` is rejected on `/mcp`.
- Effective access is the intersection of the token's categories and the
  owner's feature access. Admin owners pass all feature checks.
- A token stops working when it is revoked, expired, or its owner is disabled
  or deleted.
- Plexus has no per-user inventory visibility today (access is by feature
  only), so tools do not filter by inventory group. Feature access is
  re-read from the owner on every request, so removing a feature from the
  owner narrows the token immediately.

Category to feature mapping, defined in one table in `registry.py` using the
keys from `_FEATURE_CATALOG` in `netcontrol/routes/state.py`:

| Category | Owner must have feature |
|---|---|
| inventory | `inventory` |
| configs | `config-backups` (`list_config_drift` also needs `config-drift`) |
| compliance | `compliance` |
| monitoring | `monitoring` |
| topology | `topology` |
| software | `software` |
| traffic | `mac-tracking` for `search_mac_or_ip`, `traffic-analysis` for `get_top_talkers` |
| audit | Owner must be an admin (there is no audit feature key) |

`plexus_overview` needs no feature and reports only on categories the token
can use.

## Guardrails

- The feature is off by default. An admin setting enables `/mcp`; while off,
  the path returns 404.
- `/mcp` uses no cookies and is exempt from CSRF checks. It is not in
  `PUBLIC_PATHS`; it has its own token check.
- Existing rate-limit middleware applies, plus a per-token call limit.
- The registry contains no write tools. A test asserts that no tool handler
  imports a mutating function from `routes/db`.

## Tool catalog

All tools return compact JSON, support `limit` and `cursor` where they list,
and include a `source` field on rows that can come from different
integrations (CLI devices, Meraki, Cato, AWS, Azure, firewall managers).

| Category | Tool | Purpose |
|---|---|---|
| (always) | `plexus_overview` | Device counts per vendor, data sources with last collection time, categories this token holds. |
| inventory | `list_groups` | Groups and sites with host counts. |
| inventory | `search_hosts` | Find hosts by name, IP, vendor, model, group. |
| inventory | `get_host` | One host with identity, platform, group, addresses. |
| configs | `search_configs` | Text or regex search over the latest backup per device. Returns matching devices and matching lines with context. `not_matching` mode lists devices that lack the pattern. |
| configs | `get_device_config` | Latest or a specific backup. Optional `section` filter. |
| configs | `diff_device_configs` | Unified diff between two backups of one device. |
| configs | `list_config_drift` | Drift events with baseline and time filters. |
| compliance | `list_compliance_results` | Findings by profile, device, rule, status. |
| compliance | `get_compliance_summary` | Pass and fail counts per profile. |
| monitoring | `list_alerts` | Active and historical alerts with time, severity and device filters. |
| monitoring | `get_device_health` | Latest poll data and recent history for one device. |
| monitoring | `get_sla_status` | SLA targets and compliance. |
| monitoring | `list_outages` | Availability outages and state transitions in a time range. |
| topology | `get_neighbors` | Links for a device. |
| topology | `get_interfaces` | Interface inventory, state, errors, VLANs for a device. |
| topology | `list_topology_changes` | Link and spanning-tree changes in a time range. |
| topology | `trace_path` | Path between two endpoints using the existing path trace engine against stored data. |
| software | `list_software_versions` | Versions per device, with recent changes. |
| software | `list_advisories` | Advisories and CVEs with affected devices. |
| traffic | `search_mac_or_ip` | Where a MAC or IP was seen: device, port, VLAN, history. |
| traffic | `get_top_talkers` | Top talkers, applications or conversations for an exporter and time range. |
| audit | `search_audit_log` | Audit events by time, user, category. |

Handlers call existing read functions (for example `search_config_backups`,
`get_monitoring_alerts`, `get_topology_links_for_host`,
`list_software_advisories`, `search_mac_tracking`, `get_audit_events`). Where
a route module already wraps a query with shaping logic that the tool needs,
that logic is moved to a shared function and imported by both, not copied.

Never exposed by any tool: stored credentials, secret variables, integration
API keys, user accounts and password hashes, session data, authentication
provider configuration.

## Redaction

Always on. There is no setting or token option to disable it.

Config text:

- A pattern set per platform family masks the secret value and keeps the rest
  of the line, so the AI can still see that the feature is configured.
  Example: `snmp-server community ******** RO`.
- Covered: enable and user passwords and hashes, SNMP communities and v3
  auth/priv keys, TACACS and RADIUS keys, routing and first-hop protocol
  authentication keys, IPsec and IKE pre-shared keys, wireless PSKs, private
  key and certificate blocks, API tokens, Junos `$9$` values, Palo Alto
  `<phash>` and `<key>` values.

Structured rows:

- Keys matching a deny-list (`password`, `secret`, `token`, `api_key`,
  `community`, `psk`, `private_key` and variants) are masked recursively.
- Existing vendor scrubbers (`scrub_secrets` in the Meraki collector, the
  Appgate `scrub_*` functions) are reused.

Behaviour:

- Redaction runs in `dispatch.py` after the handler, so a new tool cannot
  skip it. Diff output and search match lines go through the same masker.
- Fail closed: if redaction raises, the tool returns an error and no content.
- Known limit, stated in the docs: pattern-based masking cannot guarantee it
  catches every secret in every vendor syntax. Admins who cannot accept that
  leave the `configs` category off the token.

## Limits

| Limit | Default | Behaviour when exceeded |
|---|---|---|
| Result size | 100 KB | Truncated, with `truncated: true` and a hint for narrowing the query. |
| List rows | 200 | Paged with `cursor`. |
| Calls per token | 120 per minute | Tool error asking the client to slow down. |
| Regex search | Pattern length cap and execution timeout | Tool error. |

The defaults are admin settings.

## Audit

- Every `tools/call` writes an event through `add_audit_event` with category
  `mcp`: token name, owner, tool, arguments, row count, bytes returned,
  duration, outcome. Result content is not logged.
- Token creation, revocation and failed authentication are logged.
- Repeated failed tokens from one address go through the existing lockout and
  rate-limit path.

## Errors

| Case | Response |
|---|---|
| Missing, unknown, expired or revoked token | HTTP 401 with a generic message. |
| Feature disabled | HTTP 404. |
| Tool outside the token's categories | Not listed. A direct call returns "unknown tool". |
| Not found, bad arguments, timeout | MCP tool error with a plain message that suggests the next step. No stack traces or SQL. |
| Data source never collected | Explicit "no data collected for this source", not an empty list. |

## Admin UI

New "AI Access" tab in Settings (`pages/Settings/AiAccessTab.tsx`), built
from the existing `SectionCard`, `FormFields` and `SaveBar` components, with
API calls in `src/api/settings.ts`.

- Master switch for the endpoint, and the limit settings.
- Token table: name, owner, categories, expiry, last used, call count,
  status. Actions: create and revoke. Revoke asks for confirmation naming
  the token.
- Create dialog: name, owner, category checklist, expiry. After saving, the
  token is shown once with a copy button and connection snippets for Claude
  Desktop, Claude Code and a generic MCP client.
- A notice on the tab: data returned by tools is sent to the AI provider the
  client uses. Secrets are masked; configs, IP addresses and hostnames are
  not.

## Documentation

- New `docs/ai-access.md`: overview, enabling, tokens, connecting clients,
  tool reference, redaction coverage and limits, data egress, troubleshooting.
- Updates: `docs/api-reference.md`, `AUTHORIZATION_MATRIX.md`,
  `SECURITY_ENHANCEMENTS.md`, `CHANGELOG.md`, in-app `PageHelp`.
- All examples use invented names and the documentation address ranges.

## Testing

Backend (invented sample data only):

- `tests/test_mcp_auth.py`: valid, expired, revoked, disabled owner, each
  token type on the wrong endpoint, feature disabled.
- `tests/test_mcp_redact.py`: a sample config per platform family, asserting
  every secret is masked and line structure is kept; the fail-closed case.
- `tests/test_mcp_dispatch.py`: category filtering, hidden tools, owner
  feature checks, size caps, rate limit, audit events.
- `tests/test_mcp_tools_<category>.py`: each tool against seeded data,
  including the "never collected" response.
- `tests/test_mcp_protocol.py`: `initialize`, `tools/list`, `tools/call`
  end to end as JSON-RPC requests against the mounted app.
- Registry test: every tool has a category, and no handler imports a
  mutating database function.

Frontend: Vitest coverage for the tab's helpers and the token dialog.

## CI and deployment

- `mcp` pinned in `requirements.txt`; `requirements-lock.txt` regenerated
  with hashes. Must pass `pip-audit` and the SBOM step.
- `netcontrol/mcp/` is already covered by `ruff check .`,
  `mypy netcontrol templates` and `bandit -r netcontrol`. It is added to
  `tools/coverage_gate.py` with a threshold.
- No new services or environment variables in `ci.yml`.
- The endpoint answers each request with a single JSON response (the SDK's
  JSON response mode), not a stream, so the existing nginx `location /`
  proxy block serves `/mcp` unchanged.

## Build order

1. Dependency, mount, `auth.py`, `mcp_tokens` table and admin API.
2. `registry.py`, `dispatch.py`, `redact.py`.
3. Tools per category (independent; can be built in parallel).
4. Admin UI tab.
5. Documentation.
