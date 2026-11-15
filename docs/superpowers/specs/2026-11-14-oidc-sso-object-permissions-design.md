# OIDC single sign-on and object-level permissions

Status: in implementation (design calls made by the assistant under the
"fewer questions, just build" rule; not yet reviewed by the owner).

Two independent parts. Part A adds a sign-in method. Part B restricts which
inventory objects a signed-in user may see and change.

## Part A: OIDC single sign-on

### Why

Plexus signs users in with a password checked locally or against RADIUS,
TACACS+ or LDAP. Organisations that standardise on an identity provider
(Entra ID, Okta, Keycloak, PingFederate, ADFS) want the browser sent there
instead. OpenID Connect covers all of them; SAML is not part of this slice.

### Behaviour

- OIDC is an **additional** sign-in method, not a value of
  `AUTH_CONFIG["provider"]`. The password form and its provider chain keep
  working (break-glass local admin included).
- Authorization code flow with PKCE (S256), `state` and `nonce`.
- `GET /api/auth/oidc/login?next=/path` (public): loads discovery, stores
  `{state, nonce, code_verifier, next}` in a signed cookie `oidc_tx`
  (itsdangerous, the app's signing secret, its own salt, 600 s, HttpOnly,
  SameSite=Lax, Secure as the session cookie, Path `/api/auth/oidc`), then
  302 to the authorization endpoint. `next` is kept only when it starts
  with one `/` and has no `//`, `\` or control characters; else `/`.
- `GET /api/auth/oidc/callback` (public): checks `state` against the cookie
  (constant time), exchanges the code at the token endpoint, validates the
  ID token, reads claims, provisions the user, sets the normal session
  cookie exactly as password login does, deletes `oidc_tx`, 303 to `next`.
  Any failure: audit `login.failure` (detail names the step, never a
  token), delete `oidc_tx`, 303 to `/login?sso_error=<code>` with a code
  from a fixed list (`disabled`, `state`, `provider`, `token`, `claims`,
  `account`, `denied`). The provider's `error_description` is logged
  (redacted, truncated), never echoed.
- Callback failures count toward the existing per-IP login rate limit and
  lockout.
- Sign-out stays local (no RP-initiated logout).

### ID token validation

- Signature against the provider's JWKS. Allowed algorithms: RS256/384/512,
  PS256/384/512, ES256/384/512, intersected with the discovery
  `id_token_signing_alg_values_supported` when present. Never `none` or
  HS*.
- `iss` equals the configured issuer exactly (discovery `issuer` must too);
  `aud` contains the client id; `azp`, when present, equals the client id;
  `exp`/`iat`/`nbf` with 60 s leeway; `nonce` equals the cookie's;
  `sub` non-empty.
- When a configured claim (username, display name, groups) is missing from
  the ID token and discovery names a `userinfo_endpoint`, userinfo is
  fetched with the access token; its `sub` must equal the ID token's, else
  failure.
- JWKS and discovery are cached in memory (1 hour); an unknown `kid` forces
  one JWKS refetch, at most once per 60 s.
- HTTP: `httpx`, 10 s timeout, no redirects followed, TLS verified
  (optional `ca_cert_file` for a private CA). Issuer and every endpoint
  from discovery must be `https`, except host `localhost` / `127.0.0.1` /
  `::1`.

### Accounts

- Username = the `username_claim` value, trimmed; 1 to 150 characters, no
  control characters, else failure `claims`. When `username_claim` is
  `email`, an `email_verified` claim that is `false` fails.
- Provisioning reuses `upsert_external_user(provider="oidc",
  sync_role=True)`, so its admin name-collision guard applies.
- `users.external_id` (new, migration 0088, text default `''`) stores
  `sub`. First OIDC login writes it. A later login whose `sub` differs from
  a non-empty stored value for an `oidc`-managed account fails `account`.
- Role: `admin` when any `admin_groups` value is in the groups claim, else
  `default_role`. Synced every login.
- Access groups: on first login `default_group_ids`. When `sync_groups` is
  on, every login sets the user's access groups to `default_group_ids`
  plus the `access_group_id` of every `group_mappings` entry whose `group`
  is in the claim. Unknown access-group ids are skipped with a warning.
- Groups claim may be a list of strings or one string. When the token
  signals group overage (`_claim_names` or `hasgroups`) and no groups
  arrive, role and access groups are left as they are for an existing
  user (new user: `default_role`, `default_group_ids`) and the audit
  detail says so.

### Configuration (`AUTH_CONFIG["oidc"]`, stored with the auth config)

`enabled` (false), `issuer`, `client_id`, `client_secret` (masked in API
responses like the other secrets; encrypted at rest with the helper the
Meraki webhook secret uses if that helper is general, else stored as the
RADIUS secret is and the summary says so), `token_auth_method`
(`client_secret_basic` | `client_secret_post`; an empty secret means a
public client), `scopes` (`openid profile email`; `openid` always
included), `username_claim` (`preferred_username`), `display_name_claim`
(`name`), `groups_claim` (`groups`), `admin_groups` (list of strings),
`default_role` (`user`), `default_group_ids`, `sync_groups` (false),
`group_mappings` (list of `{group, access_group_id}`, at most 200),
`button_label` (`Sign in with SSO`, at most 60), `primary` (false: when
true the login page leads with the SSO button and folds the password form
behind "Use a local account"; display only), `redirect_uri` (empty =
derived from the request: `X-Forwarded-Proto`/`Host` as the HTTPS redirect
middleware reads them, plus `/api/auth/oidc/callback`), `ca_cert_file`.

### API

- `GET /api/auth/status` signed out gains `sso: {oidc: {enabled, label,
  primary}}`.
- `GET/PUT /api/admin/auth-config` carry `oidc`. Saving with `enabled` and
  an empty or non-https issuer or empty client id is 400.
- `POST /api/admin/auth-config/oidc/test` *admin*: body optional `{issuer,
  ca_cert_file}` (defaults: saved). Fetches discovery and JWKS. `{ok,
  issuer, authorization_endpoint, token_endpoint, userinfo_endpoint,
  algorithms, key_count, redirect_uri, error}`.
- Audit: `login.success` with `source=oidc`; config saves as today.

### Frontend

- Login page: SSO button when enabled (plain navigation to
  `/api/auth/oidc/login`, carrying the current `next` if the page has
  one); `sso_error` codes shown as fixed sentences.
- Settings, Authentication tab: an OIDC section with the fields above, the
  redirect URI to register (read-only, copyable), group mappings editor,
  and "Test connection".

### Code layout

`netcontrol/oidc.py` holds the protocol with no FastAPI in it (discovery,
JWKS cache, PKCE, token exchange, ID token validation, claim reading) so it
is testable with a fake transport and locally generated keys. Routes live
in `netcontrol/routes/auth.py`. PyJWT (already locked, via `mcp`) becomes a
direct requirement `pyjwt[crypto]`.

## Part B: object-level permissions

### Why

Access groups grant features (pages). Every user with a feature sees every
device. Teams that own only some sites or tenants need accounts limited to
their inventory groups, read-only or read-write.

### Model (migration 0089)

- `access_groups.object_scope`: `all` (default; today's behaviour) or
  `groups`.
- `access_group_inventory_scopes(access_group_id, inventory_group_id,
  can_write)`: primary key on the first two, both deleted with their
  parent rows. A grant covers the inventory group **and its sub-groups**
  (`GROUP_SUBTREE_SQL`).
- A user's scope: admin, API token, or any membership in an access group
  with `object_scope = 'all'`: **unrestricted**. Otherwise **scoped**:
  the union of the grants of the user's access groups; an inventory group
  is writable when any covering grant has `can_write`. A scoped user with
  no grants sees nothing.

### Fail-closed rule

Scope is enforced module by module. Until a module enforces it, a scoped
user must not reach it:

- `SCOPE_ENFORCED_FEATURES` = `inventory`, `config-backups`,
  `config-drift` (and their `.write` keys where they exist).
- For a scoped user `_get_user_features` returns only keys in that set, so
  every other feature gate answers 403 and the sidebar hides those pages.
- MCP tokens owned by a scoped user are refused (403, message says why).
- WebSocket and SSE handlers in enforced modules check scope themselves.

Enrolling another module later = enforce scope in it, add its feature key
to the set, add it to the completeness test.

### Enforcement helper (`netcontrol/object_scope.py`)

```python
@dataclass(frozen=True)
class ObjectScope:
    unrestricted: bool
    read_groups: frozenset[int]    # expanded with sub-groups
    write_groups: frozenset[int]   # expanded with sub-groups
    def can_read_group(self, group_id: int | None) -> bool
    def can_write_group(self, group_id: int | None) -> bool
    def filter_groups(self, groups: list[dict], key: str = "id") -> list[dict]
    def filter_hosts(self, hosts: list[dict], key: str = "group_id") -> list[dict]

UNRESTRICTED: ObjectScope

async def scope_for_user(user: dict | None, *, token: bool = False) -> ObjectScope
async def request_scope(request) -> ObjectScope            # cached on request.state
async def ws_scope(session: dict) -> ObjectScope
async def require_group(request, group_id, *, write=False) -> dict     # the group row
async def require_host(request, host_id, *, write=False) -> dict       # the host row
async def require_hosts(request, host_ids, *, write=False) -> list[dict]
def scoped(kind: str)   # route decorator: records the route as scope-checked
def scope_exempt(reason: str)   # route decorator: route returns no host or group data
```

- Out of read scope: **404** with the same body an unknown id gives (no
  existence leak). In read scope but not writable on a write: **403**
  `"Read-only access to this inventory group"`.
- A row whose group id is `NULL` is visible to unrestricted users only.
- Creating a top-level inventory group needs an unrestricted user; a
  sub-group or host is created inside a writable group. Moving a host or
  group needs write on source and destination.
- Lists, counts, summaries, searches and exports in enforced modules are
  computed over readable hosts only. "All hosts" actions (generate all,
  check all) act on readable (or, for writes, writable) hosts.
- Global records of enforced modules that are not host data (intended
  config templates and contexts, backup policies' own fields, settings)
  stay under their existing gates and are `scope_exempt`; where such a
  record targets an inventory group, a scoped user sees and edits it only
  when that group is in scope.
- **Completeness test**: every route of every router registered under an
  enforced feature carries `scoped` or `scope_exempt`; the test fails
  otherwise. A second test drives every `scoped` GET route that has a
  host or group id path parameter with an out-of-scope id and expects 404.

### Enforced routers in this slice

`inventory` (`router`), `custom_fields.inventory_router`,
`device_model.inventory_router`, `ansible_inventory`, `config_backups`,
`config_drift` (HTTP and both WebSockets), `intended_config` (`router`).
Admin routers need no change (admins are unrestricted).

### API

- Access group object gains `object_scope` and `inventory_scopes:
  [{inventory_group_id, can_write}]`; create/update accept them (unknown
  inventory group id: 400; `inventory_scopes` ignored and cleared when
  `object_scope` is `all`).
- `GET /api/auth/status` and the login response gain `object_scope:
  {restricted: bool, write_group_ids: [int]}` (expanded ids; empty when
  unrestricted).
- Admin user payload gains `object_scope_restricted`.
- Audit: access group create/update/delete record the scope change.

### Frontend

- Access group dialog: "Device access" choice (All devices / Selected
  inventory groups) and, for the second, the inventory group tree with a
  Read / Read and write choice per granted group. The table shows a scope
  summary. A note lists which pages scoped accounts can use.
- Users tab marks restricted users.
- Inventory, Configuration pages: write controls are disabled with a
  reason for groups outside `write_group_ids`; nothing else changes
  because the server already returns only readable rows.

## Not in this slice

SAML; RP-initiated logout; SCIM; per-object grants on anything but
inventory groups (sites, tenants, single hosts); scope on monitoring,
topology, reports, jobs, deployments, upgrades, IPAM, MCP (scoped users
are shut out of them instead).

## Docs and CI

`docs/sso-oidc.md`, `docs/object-permissions.md`, `docs/api-reference.md`,
`AUTHORIZATION_MATRIX.md`, `README.md`, `CHANGELOG.md`, `TODO.md` SSO
line. `requirements.txt` gains `pyjwt[crypto]`; the lock file already
holds it. New `netcontrol` modules get floors in `tools/coverage_gate.py`.
