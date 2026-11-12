# AI Access via MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only MCP endpoint at `/mcp` so AI clients can query Plexus data for diagnosis and reporting, gated by admin-created scoped tokens.

**Architecture:** The official `mcp` SDK's low-level `Server` is mounted inside the existing FastAPI app in stateless JSON-response mode. A thin ASGI wrapper authenticates the bearer token into an `McpContext`; every tool call passes through one dispatcher that checks category and feature access, runs the handler, redacts secrets, caps size, and writes an audit event. Tools are thin handlers over the existing `routes/db/*` read functions.

**Tech Stack:** Python 3.14, FastAPI/Starlette, `mcp` 2.3.0 (low-level `Server`), PostgreSQL via the `routes.database` facade, React + TypeScript + Vitest.

**Spec:** `docs/superpowers/specs/2026-11-12-mcp-ai-access-design.md`

## Global Constraints

- **Never run `git commit` or `git push`.** Each task ends with a checkpoint, not a commit. The user commits.
- Read-only: no tool handler may import or call a mutating function from `routes.database` / `routes/db`.
- Redaction is always on. No setting, argument or token option disables it. Fail closed.
- Never exposed: stored credentials, secret variables, integration API keys, user accounts and password hashes, session data, auth provider config.
- No real environment data in code, tests, docs or samples. Use invented names and `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `example.com`.
- Reuse before writing: grep `netcontrol/`, `routes/`, `templates/` and frontend `src/` for an existing helper first. Where a route module already shapes a query result the tool needs, move that logic to a shared function and import it from both. Reuse `routes.crypto`, `routes.db.audit.add_audit_event` (via `netcontrol.routes.shared._audit`), `netcontrol.integrations.meraki.collector.scrub_secrets`, the Appgate `scrub_*` functions.
- Verify the way CI does: `pytest <files>` (the console script, not `python -m pytest`), `ruff check .`, `mypy netcontrol templates`, `bandit -q -c bandit.yaml -r netcontrol routes templates -ll -ii`. Frontend: `npm run lint`, `npm run typecheck`, `npm test`, `npm run build` in `netcontrol/static/frontend`.
- Tests need `PLEXUS_TEST_PG_URL`. Parallel workers must each use a distinct test database name.
- Token prefix `plx_mcp_`. Audit category `mcp`. Setting key `mcp_access`.
- Defaults: result size 100000 bytes, list rows 200, 120 calls per token per minute, feature disabled.
- Categories: `inventory`, `configs`, `compliance`, `monitoring`, `topology`, `software`, `traffic`, `audit`.

## Review Focus

1. **Owner loses access after the token is made** (feature removed, demoted from admin, disabled): the very next call must see the narrower tool list. Pinned in Task 3.
2. **Config with CRLF line endings, or a secret keyword inside a banner or description**: secrets still masked, non-secret lines byte-identical. Pinned in Task 5.
3. **Result over the size cap containing multibyte text**: response is still valid JSON with `truncated: true`, never cut mid-structure. Pinned in Task 6.
4. **Client sends wrong argument types, unknown arguments, or a hostile regex**: a tool error with a plain message, never HTTP 500. Pinned in Task 6 and Task 9.
5. **Name that matches several hosts** (same hostname in two groups, or a partial name): the tool returns the candidates and asks for a narrower query; it never silently picks one. Pinned in Task 8.

---

## File Structure

| File | Responsibility |
|---|---|
| `routes/migrations/0082_add_mcp_tokens.py` | `mcp_tokens` table. |
| `routes/db/mcp_tokens.py` | Token rows: create, list, lookup by hash, revoke, touch. |
| `netcontrol/mcp/__init__.py` | Package marker. |
| `netcontrol/mcp/settings.py` | Load and save the `mcp_access` setting with defaults. |
| `netcontrol/mcp/auth.py` | Token generation, hashing, bearer → `McpContext`. |
| `netcontrol/mcp/redact.py` | Config text and structured-row masking. |
| `netcontrol/mcp/registry.py` | `Tool`, `register`, `visible_tools`, category → feature table. |
| `netcontrol/mcp/dispatch.py` | `call_tool`: access check, validate, run, redact, cap, rate limit, audit. |
| `netcontrol/mcp/server.py` | SDK `Server`, ASGI auth wrapper, `build_mcp_app()`. |
| `netcontrol/mcp/tools/{overview,inventory,configs,compliance,monitoring,topology,software,traffic,audit}.py` | Tool handlers, one module per category. |
| `netcontrol/routes/mcp_tokens.py` | Admin API: tokens and settings. |
| `netcontrol/static/frontend/src/pages/Settings/AiAccessTab.tsx` (+ `aiAccess.ts`, `aiAccess.test.ts`, `McpTokenModal.tsx`) | Admin UI. |
| `docs/ai-access.md` | User documentation. |

---

### Task 1: Add the `mcp` dependency

**Files:**
- Modify: `requirements.txt`, `requirements-lock.txt`

- [ ] **Step 1:** Add `mcp==2.3.0` to `requirements.txt` with a one-line comment naming `netcontrol/mcp/` as its user.
- [ ] **Step 2:** Regenerate the lock file: `uv pip compile requirements.txt --universal --generate-hashes --python-version 3.14 -o requirements-lock.txt`
- [ ] **Step 3:** Install and audit: `pip install -r requirements.txt` then `pip-audit --progress-spinner off` and `pip-audit -r requirements-lock.txt -f cyclonedx-json -o sbom.cdx.json --progress-spinner off --no-deps`. Expected: no vulnerabilities, Starlette and Pydantic pins unchanged.
- [ ] **Step 4:** `python -c "from mcp.server.lowlevel import Server; import netcontrol.app"` exits 0.
- [ ] **Step 5:** If step 3 or 4 fails because of the SDK, **stop and report**. The spec's fallback (hand-written JSON-RPC endpoint) replaces Task 7's SDK usage only; do not loosen a pin or an audit rule.
- [ ] **Checkpoint:** report results. No commit.

---

### Task 2: `mcp_tokens` table and database functions

**Files:**
- Create: `routes/migrations/0082_add_mcp_tokens.py`, `routes/db/mcp_tokens.py`
- Modify: `routes/db/__init__.py` and `routes/database.py` (export the new functions the same way `routes/db/meraki_alerts.py` is exported)
- Test: `tests/test_mcp_tokens_db.py`

**Interfaces — Produces** (all in `routes/db/mcp_tokens.py`, re-exported on `routes.database`):

```python
async def create_mcp_token(*, name: str, token_hash: str, token_prefix: str, owner_user_id: int,
                           categories: list[str], expires_at: str, created_by: str) -> int
async def list_mcp_tokens() -> list[dict]            # never includes token_hash; adds owner_username
async def get_mcp_token_by_hash(token_hash: str) -> dict | None
async def get_mcp_token(token_id: int) -> dict | None
async def revoke_mcp_token(token_id: int) -> bool     # False if missing or already revoked
async def touch_mcp_token(token_id: int) -> None      # last_used_at = now, call_count += 1
```

Columns: `id SERIAL PK`, `name TEXT UNIQUE NOT NULL`, `token_hash TEXT UNIQUE NOT NULL`, `token_prefix TEXT`, `owner_user_id INTEGER NOT NULL`, `categories TEXT` (JSON list; functions return it as `list[str]`), `expires_at TEXT DEFAULT ''`, `created_at TEXT`, `created_by TEXT`, `last_used_at TEXT DEFAULT ''`, `call_count INTEGER DEFAULT 0`, `revoked_at TEXT DEFAULT ''`. Timestamps are UTC `YYYY-MM-DD HH:MM:SS` text, as in migration 0081. `VERSION = 82`.

- [ ] **Step 1: Write failing tests** in `tests/test_mcp_tokens_db.py`:
  - `test_create_and_lookup_by_hash`: created row is returned by `get_mcp_token_by_hash`, `categories == ["inventory", "configs"]`.
  - `test_list_omits_hash`: no row from `list_mcp_tokens()` has a `token_hash` key; `owner_username` present.
  - `test_duplicate_name_rejected`: second create with the same name raises.
  - `test_revoke_sets_revoked_at_once`: first call `True`, second `False`, row still listed.
  - `test_touch_increments`: `call_count == 2` after two touches, `last_used_at != ""`.
- [ ] **Step 2:** `pytest tests/test_mcp_tokens_db.py` → FAIL (module missing).
- [ ] **Step 3:** Write the migration and the functions.
- [ ] **Step 4:** `pytest tests/test_mcp_tokens_db.py` → PASS. `ruff check .` and `mypy netcontrol templates` clean.
- [ ] **Checkpoint.**

---

### Task 3: Settings and token authentication

**Files:**
- Create: `netcontrol/mcp/__init__.py`, `netcontrol/mcp/settings.py`, `netcontrol/mcp/auth.py`
- Test: `tests/test_mcp_auth.py`

**Interfaces — Consumes:** Task 2 functions; `db.get_auth_setting(key) -> dict | None` / `db.set_auth_setting(key, value)`; `db.get_user_by_id`; `_get_user_features(user)` (imported into `netcontrol/app.py` at line 80; import it from its defining module).

**Produces:**

```python
# settings.py
DEFAULTS = {"enabled": False, "max_result_bytes": 100_000, "max_rows": 200, "calls_per_minute": 120}
async def load_settings() -> dict            # DEFAULTS merged with stored "mcp_access"
async def save_settings(values: dict) -> dict # validates, stores, returns merged
# bounds: max_result_bytes 10_000..1_000_000, max_rows 10..1000, calls_per_minute 1..600

# auth.py
TOKEN_PREFIX = "plx_mcp_"
CATEGORIES = ("inventory", "configs", "compliance", "monitoring", "topology", "software", "traffic", "audit")

@dataclass(frozen=True)
class McpContext:
    token_id: int
    token_name: str
    owner_id: int
    owner_username: str
    owner_is_admin: bool
    categories: frozenset[str]   # as stored on the token
    features: frozenset[str]     # owner's current features

def generate_token() -> tuple[str, str, str]   # (plaintext, sha256 hex, display prefix = first 12 chars)
def hash_token(plaintext: str) -> str
def extract_bearer(authorization_header: str) -> str   # "" if absent; scheme is case-insensitive
async def resolve_token(plaintext: str) -> McpContext | None
```

`resolve_token` returns `None` when: the string lacks `TOKEN_PREFIX`, no row matches the hash, `revoked_at` is set, `expires_at` is past, or the owner is missing or disabled. It reads the owner and their features on every call (no caching across requests).

- [ ] **Step 1: Write failing tests** in `tests/test_mcp_auth.py`:
  - `test_generate_token_shape`: starts with `plx_mcp_`, `hash_token(plaintext) == returned hash`, two calls differ.
  - `test_extract_bearer_variants`: `"Bearer x"`, `"bearer x"`, `"  Bearer   x  "` → `"x"`; `""`, `"Basic x"` → `""`.
  - `test_resolve_valid_token`: context has the token's categories and `owner_is_admin` true for the bootstrap admin.
  - `test_resolve_rejects` parametrized: unknown token, wrong prefix, revoked, expired, disabled owner → `None`.
  - `test_feature_removed_narrows_immediately` (Review Focus 1): non-admin owner with `inventory`; resolve → `"inventory" in ctx.features`; remove the feature from the owner; resolve again → not in `ctx.features`.
  - `test_settings_defaults_and_bounds`: `load_settings()` on a fresh database equals `DEFAULTS`; `save_settings({"max_rows": 5})` raises `ValueError`.
- [ ] **Step 2:** `pytest tests/test_mcp_auth.py` → FAIL.
- [ ] **Step 3:** Implement. `generate_token` uses `secrets.token_urlsafe(32)`.
- [ ] **Step 4:** `pytest tests/test_mcp_auth.py` → PASS; ruff and mypy clean.
- [ ] **Checkpoint.**

---

### Task 4: Admin API for tokens and settings

**Files:**
- Create: `netcontrol/routes/mcp_tokens.py`
- Modify: `netcontrol/app.py` (register the router with `dependencies=[Depends(require_admin)]`, next to the other admin routers near line 2400)
- Test: `tests/test_mcp_admin_api.py`

**Interfaces — Produces** (HTTP):

| Method and path | Body | Response |
|---|---|---|
| `GET /api/admin/mcp/settings` | | settings dict |
| `PUT /api/admin/mcp/settings` | any subset of the settings keys | merged settings; 422 on out-of-bounds |
| `GET /api/admin/mcp/tokens` | | `{"tokens": [...], "categories": [...CATEGORIES]}` |
| `POST /api/admin/mcp/tokens` | `{"name", "owner_user_id", "categories": [...], "expires_at": "" or "YYYY-MM-DD"}` | `{"token": "<plaintext, shown once>", "record": {...}}` |
| `DELETE /api/admin/mcp/tokens/{id}` | | `{"revoked": true}`; 404 if missing or already revoked |

Validation: `name` 1–80 chars; `categories` non-empty subset of `CATEGORIES`; owner must exist and be enabled; a token in the `audit` category requires an admin owner (422 otherwise). Audit with `_audit("mcp", "token_create" | "token_revoke" | "settings_update", user=<admin>, detail=<token name / changed keys>)`. The plaintext token must not appear in any audit detail or log line.

- [ ] **Step 1: Write failing tests** using the `_auth_client` login pattern from `tests/test_api_hardening.py`:
  - `test_create_returns_plaintext_once`: POST response has `token` starting `plx_mcp_`; a following GET lists the record with no `token` and no `token_hash`.
  - `test_create_validation` parametrized: empty categories, unknown category, missing owner, `audit` with non-admin owner → 422.
  - `test_revoke_then_404`.
  - `test_non_admin_forbidden`: a non-admin session gets 403 on all five routes.
  - `test_settings_roundtrip_and_bounds`.
  - `test_audit_rows_written_without_plaintext`: audit events in category `mcp` exist for create and revoke, and none contains the plaintext token.
- [ ] **Step 2:** `pytest tests/test_mcp_admin_api.py` → FAIL.
- [ ] **Step 3:** Implement the router and register it.
- [ ] **Step 4:** `pytest tests/test_mcp_admin_api.py` → PASS; ruff, mypy, bandit clean.
- [ ] **Checkpoint.**

---

### Task 5: Redaction

**Files:**
- Create: `netcontrol/mcp/redact.py`
- Test: `tests/test_mcp_redact.py`

**Interfaces — Produces:**

```python
MASK = "********"
def redact_config_text(text: str) -> str
def redact_value(value: Any) -> Any     # recursive; dict keys on the deny-list are masked; every str is passed through redact_config_text
class RedactionError(Exception)
def redact_result(value: Any) -> Any    # redact_value, re-raising any failure as RedactionError
```

Rules:
- Line-based patterns keep everything except the secret value. Line endings and all other lines are preserved byte for byte.
- Cover, at minimum, these forms (one test sample each): IOS/NX-OS/ASA `enable secret|password`, `username … secret|password`, `snmp-server community`, `snmp-server user … auth … priv …`, `tacacs-server key` / `key` under `tacacs server` and `radius server`, `ip ospf message-digest-key … md5`, `ip ospf authentication-key`, `neighbor … password`, `key-string`, `standby … authentication`, `vrrp … authentication`, `crypto isakmp key`, `pre-shared-key`, `tunnel-group … ikev1|ikev2 … pre-shared-key`, `wpa-psk`, `passphrase`; Junos `"$9$…"` and `"$6$…"` / `"$1$…"` values and `secret "…"`; Palo Alto `<phash>…</phash>`, `<key>…</key>`, `<password>…</password>`, `<secret>…</secret>`, `<bind-password>…</bind-password>`; Fortinet/Arista `ENC …` and `password 7|8 …`; PEM blocks (`-----BEGIN … PRIVATE KEY-----` to the matching END → one `MASK` line); `crypto pki certificate` hex blocks.
- Deny-list for structured keys (case-insensitive substring): `password`, `passwd`, `secret`, `token`, `api_key`, `apikey`, `community`, `psk`, `private_key`, `passphrase`, `auth_key`, `priv_key`.
- For dicts that came from a vendor collector, apply `scrub_secrets` from the Meraki collector as well; do not copy its logic.

- [ ] **Step 1: Write failing tests** with invented sample configs (hostnames like `edge-rtr-01`, addresses from `192.0.2.0/24`):
  - `test_masks_each_family` parametrized over one sample per platform family: every known secret string in the sample is absent from the output; the keyword that proves the feature is configured (for example `snmp-server community`, `RO`) is still present.
  - `test_line_count_and_other_lines_unchanged`.
  - `test_crlf_preserved` (Review Focus 2): input with `\r\n` → output has the same number of `\r\n` and secrets masked.
  - `test_keyword_in_description_not_mangled` (Review Focus 2): `description uplink password reset pending` and a `banner motd` block mentioning "secret" pass through unchanged.
  - `test_pem_block_collapsed`.
  - `test_redact_value_nested`: `{"a": [{"api_key": "x", "name": "n"}]}` → `api_key` masked, `name` kept; a config string nested inside a dict is masked.
  - `test_redact_result_fails_closed`: monkeypatch `redact_value` to raise → `redact_result` raises `RedactionError`.
- [ ] **Step 2:** `pytest tests/test_mcp_redact.py` → FAIL.
- [ ] **Step 3:** Implement with precompiled patterns in one ordered table (pattern, replacement), so adding a vendor form is one line.
- [ ] **Step 4:** `pytest tests/test_mcp_redact.py` → PASS; ruff, mypy, bandit clean.
- [ ] **Checkpoint.**

---

### Task 6: Registry and dispatcher

**Files:**
- Create: `netcontrol/mcp/registry.py`, `netcontrol/mcp/dispatch.py`, `netcontrol/mcp/tools/__init__.py`
- Test: `tests/test_mcp_dispatch.py`

**Interfaces — Consumes:** `McpContext`, `load_settings`, `redact_result`, `RedactionError`, `touch_mcp_token`, `_audit`.

**Produces:**

```python
# registry.py
class ToolError(Exception): ...          # message is safe to show to the model

Handler = Callable[[McpContext, dict[str, Any]], Awaitable[Any]]

@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    category: str | None          # None = always available (plexus_overview)
    input_schema: dict[str, Any]  # JSON Schema, "additionalProperties": False
    handler: Handler
    features: tuple[str, ...] = ()   # extra feature keys beyond the category default
    admin_only: bool = False

CATEGORY_FEATURES: dict[str, tuple[str, ...]] = {
    "inventory": ("inventory",), "configs": ("config-backups",), "compliance": ("compliance",),
    "monitoring": ("monitoring",), "topology": ("topology",), "software": ("software",),
    "traffic": (), "audit": (),
}
def register(tool: Tool) -> Tool          # raises ValueError on duplicate name or unknown category
def all_tools() -> list[Tool]
def is_visible(tool: Tool, ctx: McpContext) -> bool
def visible_tools(ctx: McpContext) -> list[Tool]
def load_tools() -> None                  # imports every netcontrol.mcp.tools.* module once

# dispatch.py
async def call_tool(ctx: McpContext, name: str, arguments: dict[str, Any] | None) -> tuple[str, bool]
#   returns (json_text, is_error)
def no_data(source: str) -> dict          # {"no_data": True, "message": "No data collected for <source>."}
def page(rows: list, limit: int, cursor: str | None, max_rows: int) -> dict
#   {"items": [...], "next_cursor": str | None, "total": int}; cursor is an opaque offset string
```

`is_visible`: tool category is `None`, or (category in `ctx.categories` **and** (`ctx.owner_is_admin` or every key in `CATEGORY_FEATURES[category] + tool.features` is in `ctx.features`) **and** (not `tool.admin_only` or `ctx.owner_is_admin`)).

`call_tool` order: per-token rate limit → look up tool (missing or not visible → `("Unknown tool: <name>", True)`, identical text for both) → validate `arguments` against `input_schema` with `jsonschema` → handler with a 30 s timeout → `redact_result` → serialise → size cap → `touch_mcp_token` → audit. `ToolError` → its message. `RedactionError` → `"Result withheld: redaction failed."`. Any other exception → `"Tool failed. See the Plexus server log."` and `LOGGER.exception`. Nothing raises to the caller.

Size cap: if the JSON exceeds `max_result_bytes`, and the result is a dict with an `items` list, drop items from the end until it fits; otherwise replace the payload with `{"truncated": True, "message": "Result too large. Narrow the query."}`. A capped result always carries `"truncated": True` and a `"hint"`. The output is always valid JSON.

Rate limit: in-memory sliding window per `token_id` (same shape as `state.API_RATE_LIMIT_TRACKER`), limit from settings; over the limit → `("Rate limit reached. Retry in a few seconds.", True)`.

Audit: `_audit("mcp", "tool_call", user=ctx.owner_username, detail=json)` with `token`, `tool`, `arguments`, `rows`, `bytes`, `duration_ms`, `outcome` (`ok` | `error` | `denied` | `rate_limited`). Arguments are passed through `redact_value` and truncated to 500 chars. Result content is never logged.

- [ ] **Step 1: Write failing tests** (register throwaway tools inside the tests; reset the registry in a fixture):
  - `test_visibility_matrix` parametrized: category on token + feature present → visible; category missing → hidden; feature missing for non-admin → hidden; admin owner bypasses feature; `admin_only` hidden from non-admin; `category=None` always visible.
  - `test_hidden_tool_same_error_as_missing`: both return the identical `"Unknown tool: x"` text with `is_error`.
  - `test_bad_arguments_are_tool_errors` (Review Focus 4): wrong type, unknown extra key, missing required → `is_error` true, message names the argument, handler not called.
  - `test_result_is_redacted`: handler returns `{"line": "snmp-server community hunter2 RO"}` → output lacks `hunter2`.
  - `test_redaction_failure_withholds_result`.
  - `test_handler_exception_is_generic`: output has no traceback text and no exception message.
  - `test_truncates_items_to_valid_json` (Review Focus 3): 5,000 items of multibyte text with `max_result_bytes=10_000` → `json.loads` succeeds, `truncated is True`, `len(encoded) <= 10_000`.
  - `test_rate_limit`: with `calls_per_minute=3`, the fourth call returns the rate-limit error.
  - `test_audit_row_per_call`: one `mcp`/`tool_call` event per call; detail has the tool name and outcome and does not contain the handler's result text.
  - `test_touch_increments_call_count`.
  - `test_page_helper`: 450 rows, `limit=500`, `max_rows=200` → 200 items, `next_cursor` set, following the cursor yields the rest.
- [ ] **Step 2:** `pytest tests/test_mcp_dispatch.py` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `pytest tests/test_mcp_dispatch.py` → PASS; ruff, mypy clean.
- [ ] **Checkpoint.**

---

### Task 7: MCP server and mount

**Files:**
- Create: `netcontrol/mcp/server.py`, `netcontrol/mcp/tools/overview.py`
- Modify: `netcontrol/app.py` (mount, lifespan, middleware exemptions)
- Test: `tests/test_mcp_protocol.py`

**Interfaces — Consumes:** `resolve_token`, `extract_bearer`, `load_settings`, `visible_tools`, `call_tool`, `load_tools`.

**Produces:**

```python
# server.py
def build_mcp_app() -> tuple[ASGIApp, Callable[[], AbstractAsyncContextManager[None]]]
#   returns (asgi_app, run_session_manager)
```

Decisions:
- `Server("plexus", version=<netcontrol.version>, instructions=<two sentences: read-only Plexus network data; call plexus_overview first>, on_list_tools=..., on_call_tool=..., get_tool_input_schema=...)`.
- `server.streamable_http_app(streamable_http_path="/", json_response=True, stateless_http=True, transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))`. DNS-rebinding protection is off because every request needs a bearer token and Plexus is served under arbitrary internal hostnames.
- The returned app is wrapped by a pure ASGI class (not `BaseHTTPMiddleware`) that, per HTTP request: loads settings → `enabled` false → 404 JSON; `resolve_token(extract_bearer(...))` → `None` → 401 JSON `{"error": "unauthorized"}` with `WWW-Authenticate: Bearer`; otherwise stores the `McpContext` in a `contextvars.ContextVar` and calls the SDK app. Handlers read the context from that variable.
- `on_list_tools` maps `visible_tools(ctx)` to `types.Tool(name, description, inputSchema)`. `on_call_tool` returns `types.CallToolResult(content=[TextContent(type="text", text=json_text)], isError=is_error)`.
- `netcontrol/app.py`: `app.mount("/mcp", asgi_app)`; enter `run_session_manager()` inside the existing `lifespan` (a mounted app's own lifespan does not run). Confirm `/mcp` is not blocked by `require_auth`-style global checks, by the CSRF middleware (no cookie, bearer only), or by `APP_REQUIRE_API_TOKEN`; add an explicit path exemption only where a test proves it is needed. `APP_API_TOKEN` must not authenticate `/mcp`.
- Failed tokens: count through the same per-address path the API rate limiter uses, so repeated bad tokens are throttled; audit `_audit("mcp", "auth_failed", detail=<client address>)` at most once per address per minute.
- `plexus_overview` (category `None`, no arguments) returns `{"categories": [...usable by this token], "devices": {"total": n, "by_vendor": {...}}, "sources": [{"name", "last_collected", "status"}]}`. Reuse the query behind the dashboard source-health panel (`Dashboard/sourceHealth.ts` consumes it); if that shaping lives in a route module, move it to a shared function.

- [ ] **Step 1: Write failing tests** using `TestClient(app_module.app)`, a helper that enables the setting and creates a token through the Task 4 API, and a helper `rpc(client, token, method, params)` that POSTs JSON-RPC to `/mcp/` with `Accept: application/json, text/event-stream`:
  - `test_disabled_returns_404` (valid token, feature off).
  - `test_missing_and_bad_token_401`; `test_app_api_token_rejected_on_mcp`; `test_mcp_token_rejected_on_api` (`GET /api/admin/mcp/tokens` with the MCP bearer → 401).
  - `test_initialize_then_list_tools`: `initialize` succeeds with server name `plexus`; `tools/list` includes `plexus_overview`.
  - `test_list_tools_respects_categories`: register a throwaway `configs` tool; a token with only `inventory` does not list it.
  - `test_call_overview`: `tools/call` → `isError` false; the text parses as JSON with `categories`, `devices`, `sources`.
  - `test_call_unknown_tool_is_error_not_500`.
  - `test_no_csrf_needed`: the POSTs above carry no CSRF header and no cookie.
  - `test_revoked_token_stops_immediately`: call succeeds, revoke, next call 401.
  - `test_registry_has_no_write_imports`: for every module under `netcontrol/mcp/tools/`, parse with `ast` and assert no referenced `db.<name>` / imported name starts with `add_`, `create_`, `update_`, `delete_`, `set_`, `upsert_`, `insert_`, `remove_`, `save_`, `revoke_`, `touch_`.
- [ ] **Step 2:** `pytest tests/test_mcp_protocol.py` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `pytest tests/test_mcp_protocol.py tests/test_mcp_dispatch.py tests/test_mcp_auth.py tests/test_api_hardening.py` → PASS; ruff, mypy, bandit clean.
- [ ] **Step 5:** Manual check: start the app locally, enable the feature, create a token, connect with `claude mcp add --transport http plexus http://127.0.0.1:<port>/mcp/ --header "Authorization: Bearer <token>"`, confirm `plexus_overview` is listed and callable. Record the exact working URL form (with or without trailing slash) for the docs and the UI snippets; if the trailing slash matters, make both forms work.
- [ ] **Checkpoint.**

---

### Tasks 8–12: Tools (independent; run in parallel after Task 7)

Shared rules for every tool task:
- **Consumes:** `Tool`, `register`, `ToolError` from `registry.py`; `page`, `no_data` from `dispatch.py`; `McpContext`.
- Each module registers its tools at import. `load_tools()` already imports every module in `netcontrol/mcp/tools/`.
- Handlers take `(ctx, args)` and return plain JSON-serialisable data. They do **not** redact, cap, or audit; the dispatcher does.
- Host arguments are named `host` and accept a hostname, IP address, or numeric id. Use one shared resolver, added in Task 8: `async def resolve_host(ref: str) -> dict` in `netcontrol/mcp/tools/_hosts.py`, which raises `ToolError` listing up to 10 candidates when the reference matches more than one host, and `ToolError("No host matches '<ref>'. Try search_hosts.")` when none. Tasks 9–12 import it; if Task 8 has not landed, the worker creates `_hosts.py` to this exact signature.
- Time arguments are named `since` and `until`, ISO 8601, default window last 24 hours.
- When the underlying source has never been collected, return `no_data("<source>")`, not an empty list.
- Each returned row includes `source` where rows can come from more than one integration.
- Tests seed data through existing `db.*` write functions or `pg_raw`, call the tool through `dispatch.call_tool` with a context built in the test, and assert on parsed JSON. Each task's test file also asserts that each of its tools is hidden for a context lacking the category.
- Each worker uses its own test database name in `PLEXUS_TEST_PG_URL`.
- Verification per task: `pytest tests/test_mcp_tools_<name>.py tests/test_mcp_protocol.py::test_registry_has_no_write_imports`, `ruff check .`, `mypy netcontrol templates`.

### Task 8: Inventory tools and host resolver

**Files:** Create `netcontrol/mcp/tools/_hosts.py`, `netcontrol/mcp/tools/inventory.py`; Test `tests/test_mcp_tools_inventory.py`

| Tool | Arguments | Returns | Backed by |
|---|---|---|---|
| `list_groups` | none | groups with `id`, `name`, `parent`, `host_count` | `get_all_groups_with_hosts` |
| `search_hosts` | `query?`, `vendor?`, `group?`, `limit?`, `cursor?` | paged hosts: `id`, `hostname`, `ip_address`, `vendor`, `model`, `device_type`, `group`, `source` | `get_all_hosts`, `find_host_by_ip`, `find_hosts_by_hostname` |
| `get_host` | `host` | one host with identity, platform, group, alias addresses | `resolve_host`, `get_ip_aliases_for_hosts` |

- [ ] **Step 1: Failing tests:** `test_search_by_name_ip_vendor`; `test_get_host_by_each_reference_form`; `test_ambiguous_host_lists_candidates` (Review Focus 5: two hosts named `core-sw-01` in different groups → `is_error`, both ids in the message); `test_partial_name_multiple_matches_lists_candidates`; `test_no_match_suggests_search_hosts`; `test_host_rows_have_no_credential_fields` (no key containing `password`, `credential`, `secret`, `community`); `test_hidden_without_category`.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement. **Step 4:** run → PASS. **Checkpoint.**

### Task 9: Config tools

**Files:** Create `netcontrol/mcp/tools/configs.py`; Test `tests/test_mcp_tools_configs.py`

| Tool | Arguments | Returns | Backed by |
|---|---|---|---|
| `search_configs` | `pattern`, `mode` (`text` \| `regex`, default `text`), `not_matching?` (bool), `vendor?`, `group?`, `context_lines?` (0–5, default 1), `limit?`, `cursor?` | paged devices: `host`, `backup_time`, `matches: [{line_number, lines}]`; with `not_matching`, devices whose latest backup lacks the pattern (no `matches`) | `search_config_backups`, `get_latest_config_backups_per_host` |
| `get_device_config` | `host`, `backup_id?`, `section?` | `host`, `backup_id`, `backup_time`, `config` (text), `lines` | `get_latest_config_backup`, `get_config_backup` |
| `diff_device_configs` | `host`, `from_backup_id?`, `to_backup_id?` (defaults: previous successful and latest) | `from`, `to`, `diff` (unified) | `get_previous_successful_config_backup`; reuse the diff helper the Configuration backups route already uses |
| `list_config_drift` | `host?`, `since?`, `until?`, `status?`, `limit?`, `cursor?` | paged drift events | `get_config_drift_events`; `Tool.features=("config-drift",)` |

Decisions: `pattern` max 200 chars. Regex mode uses the same engine and limits `search_config_backups` already applies (the codebase standardised on RE2 in migration 0080); an invalid or rejected pattern becomes `ToolError("Invalid pattern: <reason>")`. `section` returns the block whose first line starts with the given text plus its indented children (for example `interface GigabitEthernet1/0/1`, `router bgp`); no match → `ToolError` listing the first 30 top-level section headers. Reuse an existing section parser from `netcontrol/integrations/pathtrace/ios_config.py` or `device_config.py` if one fits; otherwise put the new one in a shared module, not in the tool.

- [ ] **Step 1: Failing tests** (seed three hosts with invented configs, one containing `snmp-server community <secret> RO`): `test_search_text_finds_devices_with_lines`; `test_search_not_matching_lists_the_others`; `test_search_output_is_redacted_via_dispatch` (secret absent, `snmp-server community` present); `test_invalid_and_overlong_regex_is_tool_error` (Review Focus 4: `"("`, a 201-char pattern, and a nested-quantifier pattern each return `is_error` quickly and never raise); `test_get_config_section`; `test_unknown_section_lists_headers`; `test_diff_defaults_to_last_two`; `test_diff_single_backup_is_tool_error`; `test_no_backups_is_no_data`; `test_list_config_drift_needs_config_drift_feature`; `test_hidden_without_category`.
- [ ] **Step 2–4** as above. **Checkpoint.**

### Task 10: Compliance and software tools

**Files:** Create `netcontrol/mcp/tools/compliance.py`, `netcontrol/mcp/tools/software.py`; Test `tests/test_mcp_tools_compliance_software.py`

| Tool | Arguments | Returns | Backed by |
|---|---|---|---|
| `list_compliance_results` | `profile?`, `host?`, `status?` (`pass` \| `fail`), `limit?`, `cursor?` | paged findings: `host`, `profile`, `rule`, `status`, `detail`, `scanned_at`, `source` | compliance result readers in `routes/db/topology.py` and `list_meraki_compliance_results` |
| `get_compliance_summary` | `profile?` | pass/fail counts per profile and per source | existing compliance summary readers, `get_meraki_compliance_summary` |
| `list_software_versions` | `vendor?`, `version?`, `host?`, `changed_since?`, `limit?`, `cursor?` | paged devices: `host`, `platform`, `version`, `classification`, `open_advisories`, `source` | `list_software_versions`, `list_recent_version_changes`, `count_open_alerts_by_device` |
| `list_advisories` | `severity?`, `cve?`, `host?`, `limit?`, `cursor?` | paged advisories: `id`, `cve`, `severity`, `title`, `affected_hosts`, `fixed_in`, `source` | `list_software_advisories`, `get_software_advisory` |

Vendor parity: results must include every vendor the underlying readers cover (Cisco, Cato, AWS, Azure are the priority set per `AGENTS.md` "Vendor Monitoring Parity Standard" and `docs/vendor-monitoring-coverage.md`). Do not filter to CLI devices. A vendor with a documented advisory gap is reported in the result as `{"vendor": ..., "advisory_source": "none"}`, not omitted.

- [ ] **Step 1: Failing tests:** one happy-path test per tool against seeded rows; `test_results_span_vendors` (seeded Cisco and one cloud/SASE row both appear with `source`); `test_never_scanned_is_no_data`; `test_never_collected_software_is_no_data`; `test_hidden_without_category` for both categories.
- [ ] **Step 2–4** as above. **Checkpoint.**

### Task 11: Monitoring and topology tools

**Files:** Create `netcontrol/mcp/tools/monitoring.py`, `netcontrol/mcp/tools/topology.py`; Modify `netcontrol/routes/meraki_topology.py` only if the tracer builder must be made importable; Test `tests/test_mcp_tools_monitoring_topology.py`

| Tool | Arguments | Returns | Backed by |
|---|---|---|---|
| `list_alerts` | `host?`, `severity?`, `state?` (`active` \| `all`, default `active`), `since?`, `until?`, `limit?`, `cursor?` | paged alerts incl. Meraki alerts, each with `source` | `get_monitoring_alerts`, Meraki alert readers in `routes/db/meraki_alerts.py` |
| `get_device_health` | `host`, `hours?` (1–168, default 24) | latest poll, summary of history (min/avg/max per metric), interface error counters | `get_latest_monitoring_polls`, `get_monitoring_poll_history`, `get_interface_stats_for_host` |
| `get_sla_status` | `target?` | targets with current compliance and breaching hosts | `get_sla_targets`, `get_sla_summary`, `get_sla_compliance` |
| `list_outages` | `since?`, `until?`, `entity?`, `limit?`, `cursor?` | paged outages and transitions across vendors | `get_topology_outages`, `get_topology_transitions` |
| `get_neighbors` | `host` | links: local interface, remote device, remote interface, protocol | `get_topology_links_for_host` |
| `get_interfaces` | `host`, `name?` | interface inventory, state, VLANs, STP state | `get_interface_inventory_for_host`, `get_vlan_definitions_for_host`, `get_stp_port_states` |
| `list_topology_changes` | `since?`, `until?`, `limit?`, `cursor?` | paged link and STP changes | `get_topology_changes`, `get_stp_topology_events` |
| `trace_path` | `source`, `destination`, `protocol?`, `port?` | hops with device, ingress/egress interface, matched route and rule, and a verdict with the reason when blocked or unknown | the tracer the path-trace route builds (`_path_tracer()` / `_tracer_of()` at `netcontrol/routes/meraki_topology.py:1969-1980`) and `Tracer.trace` |

Decisions: `trace_path` must reuse the existing tracer construction. If `_path_tracer` cannot be imported cleanly from the route module, move the builder to `netcontrol/integrations/pathtrace/` and import it from both the route and the tool; do not copy it. The tool must not trigger any collection or device contact; if the tracer builder has a refresh path, the tool does not call it (assert with a test that patches the collectors to raise). `get_device_health` summarises history instead of returning raw polls.

- [ ] **Step 1: Failing tests:** one happy-path test per tool; `test_alerts_default_to_active`; `test_alerts_include_meraki_source`; `test_health_summarises_history` (seed 100 polls → response has min/avg/max, not 100 rows); `test_trace_path_returns_hops_from_stored_data`; `test_trace_path_never_collects` (collectors patched to raise → tool still answers); `test_trace_unknown_endpoint_is_tool_error`; `test_never_polled_is_no_data`; `test_hidden_without_category` for both categories.
- [ ] **Step 2–4** as above; also run the existing path-trace test files that cover any moved code. **Checkpoint.**

### Task 12: Traffic and audit tools

**Files:** Create `netcontrol/mcp/tools/traffic.py`, `netcontrol/mcp/tools/audit.py`; Test `tests/test_mcp_tools_traffic_audit.py`

| Tool | Arguments | Returns | Backed by | Access |
|---|---|---|---|---|
| `search_mac_or_ip` | `query` (MAC in any common format, or IP), `history?` (bool) | where seen: `host`, `port`, `vlan`, `first_seen`, `last_seen`, `source`; move history when asked | `search_mac_tracking`, `get_mac_history`, `search_meraki_clients` | `features=("mac-tracking",)` |
| `get_top_talkers` | `exporter?` (host), `kind` (`talkers` \| `applications` \| `conversations`), `since?`, `until?`, `limit?` (max 50) | ranked rows with bytes and packets | `get_flow_top_talkers`, `get_flow_top_applications`, `get_flow_top_conversations` | `features=("traffic-analysis",)` |
| `search_audit_log` | `category?`, `user?`, `since?`, `until?`, `limit?`, `cursor?` | paged events: `timestamp`, `category`, `action`, `user`, `detail` | `get_audit_events` | `admin_only=True` |

Decisions: normalise MAC input with the existing normaliser used by the MAC tracking routes. `get_audit_events` only filters by category and limit today; add optional `user`, `since`, `until` parameters to it (keeping current callers working) instead of filtering in the tool.

- [ ] **Step 1: Failing tests:** `test_mac_formats_normalised` (`aa:bb:cc:dd:ee:ff`, `aabb.ccdd.eeff`, `AA-BB-CC-DD-EE-FF` find the same row); `test_search_by_ip`; `test_top_talkers_kinds`; `test_no_flow_data_is_no_data`; `test_audit_filters`; `test_audit_hidden_from_non_admin_owner`; `test_audit_detail_is_redacted_via_dispatch`; `test_feature_gating` (`mac-tracking` without `traffic-analysis` shows only `search_mac_or_ip`); `test_hidden_without_category`.
- [ ] **Step 2–4** as above; also run `pytest tests/test_audit_chain.py`. **Checkpoint.**

---

### Task 13: Settings "AI Access" tab

**Files:**
- Create: `netcontrol/static/frontend/src/pages/Settings/AiAccessTab.tsx`, `McpTokenModal.tsx`, `aiAccess.ts`, `aiAccess.test.ts`
- Modify: `src/api/settings.ts` (types and calls), `src/pages/Settings/Settings.tsx` (add `{ key: 'ai-access', label: 'AI Access' }` to `ADMIN_TABS` only), `src/components/PageHelp.tsx`

**Interfaces — Consumes:** the five routes from Task 4.

**Produces** (`src/api/settings.ts`): `McpSettings`, `McpTokenRecord`, `getMcpSettings()`, `updateMcpSettings(values)`, `listMcpTokens()`, `createMcpToken(body)`, `revokeMcpToken(id)`.
(`aiAccess.ts`): `connectionSnippets(baseUrl: string, token: string): { label: string; text: string }[]` for Claude Code, Claude Desktop and a generic MCP client; `tokenStatus(record, now): 'active' | 'expired' | 'revoked'`; `validateTokenForm(form): Record<string, string>`.

Requirements:
- Follow `FRONTEND_STYLE.md`. Build from `SectionCard`, `FormFields`, `SaveBar`, `StatusLine` and the existing modal and table components; no new primitives.
- Card 1 "MCP endpoint": enable switch, the three limit fields with their bounds, the endpoint URL (from `window.location.origin` plus the path form recorded in Task 7 step 5).
- Card 2 "Tokens": table (name, owner, categories, expiry, last used, calls, status), "Create token" button, "Revoke" per active row. Revoke confirmation names the token. Empty state has a "Create token" action.
- Create modal: name, owner (existing users list), category checklist with a one-line description each, expiry date (optional). `audit` is disabled with an explanation unless the chosen owner is an admin. Validate on blur. After create, the modal switches to a "Copy your token" view: token with copy button, the snippets with copy buttons, and the sentence "This token is shown once. Store it now."
- Notice on the tab, exact copy: "Data returned by these tools is sent to the AI provider your client uses. Secrets in device configurations are masked. Configurations, IP addresses and hostnames are not."
- Every input has a visible label. Button labels are verb-first ("Create token", "Revoke token", "Copy token").

- [ ] **Step 1: Failing tests** in `aiAccess.test.ts`: `connectionSnippets` output contains the base URL and the token in each snippet and the Claude Code one starts with `claude mcp add`; `tokenStatus` for active, expired, revoked; `validateTokenForm` rejects empty name, no categories, and `audit` with a non-admin owner.
- [ ] **Step 2:** `npm test -- aiAccess` → FAIL.
- [ ] **Step 3:** Implement helpers, API calls, tab and modal.
- [ ] **Step 4:** In `netcontrol/static/frontend`: `npm run lint`, `npm run typecheck`, `npm test`, `npm run build` → all pass.
- [ ] **Step 5:** Run the app and exercise the tab in a browser: enable, create a token, copy it, revoke it, check a 375px-wide viewport and keyboard-only use.
- [ ] **Checkpoint.**

---

### Task 14: Documentation, coverage gate, final verification

**Files:**
- Create: `docs/ai-access.md`
- Modify: `docs/api-reference.md`, `AUTHORIZATION_MATRIX.md`, `SECURITY_ENHANCEMENTS.md`, `CHANGELOG.md`, `README.md` (feature list entry), `deploy/DEPLOYMENT.md` (note that `/mcp` is served through the existing proxy block), `tools/coverage_gate.py`

- [ ] **Step 1:** Write `docs/ai-access.md` with these sections: What it is; What the AI can and cannot see; Enabling the endpoint; Creating and revoking tokens; Connecting a client (Claude Code, Claude Desktop, generic MCP client, with the snippets from Task 13); Tool reference (one table per category: tool, arguments, what it answers); Secret masking (what is covered, and the statement that pattern-based masking cannot guarantee catching every secret in every vendor syntax, with the advice to leave `configs` off a token where that is unacceptable); Data sent to the AI provider; Limits; Audit trail; Not supported (cloud-hosted connectors, OAuth, write actions, live checks); Troubleshooting (401, 404, empty tool list, "no data collected", rate limit). Invented names and documentation address ranges only.
- [ ] **Step 2:** Update the other documents: the five admin routes and `/mcp` in `api-reference.md`; MCP token rows (admin-only management, category and feature rules) in `AUTHORIZATION_MATRIX.md`; a section in `SECURITY_ENHANCEMENTS.md` covering token hashing, token separation from `APP_API_TOKEN`, redaction, audit; a `CHANGELOG.md` entry.
- [ ] **Step 3:** Add `netcontrol/mcp/` modules to `DEFAULT_RULES` in `tools/coverage_gate.py` at thresholds a few points below the measured coverage from step 5 (floor 80.0 for `redact.py`, `auth.py`, `dispatch.py`, `registry.py`).
- [ ] **Step 4:** Check `.github/workflows/ci.yml` needs no change: `ruff check .`, `mypy netcontrol templates`, `bandit -r netcontrol routes templates` and the `pytest --cov=netcontrol --cov=routes` step already cover the new code. Change it only if something new is required.
- [ ] **Step 5:** Full CI-equivalent run, once: `ruff check .`; `mypy netcontrol templates`; `bandit -q -c bandit.yaml -r netcontrol routes templates -ll -ii`; `pip-audit --progress-spinner off`; `pytest --cov=netcontrol --cov=routes --cov-report=term-missing --cov-report=json:coverage.json --cov-fail-under=30`; `python tools/coverage_gate.py coverage.json`; frontend `npm audit`, `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`. All pass.
- [ ] **Step 6:** Grep every new and changed file for real environment identifiers seen during the work (addresses outside the documentation ranges, real hostnames, account or tenant ids) and replace any hit.
- [ ] **Step 7:** End-to-end check with a real MCP client against a local instance holding sample data: ask "which devices have SNMP configured" and "why can't <host A> reach <host B>"; confirm the answers come from `search_configs` and `trace_path`, that no secret appears in any tool result, and that the calls appear in the Audit page under category `mcp`.
- [ ] **Checkpoint:** final summary with a ready-to-use commit message.

---

## Execution Order

`1 → 2 → 3 → 4` and `5` (5 is independent of 2–4) `→ 6 → 7 →` then `8, 9, 10, 11, 12` in parallel, with `13` able to start any time after 4 `→ 14`.
