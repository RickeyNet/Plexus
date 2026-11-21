# Single sign-on with OpenID Connect

Plexus can send the browser to an OpenID Connect (OIDC) identity provider
(Entra ID, Okta, Keycloak, PingFederate, ADFS and others) instead of asking
for a password. SSO is an **additional** sign-in method: the password form,
its provider chain (local, RADIUS, TACACS+, LDAP) and the break-glass local
admin keep working whichever provider is selected.

The flow is the authorization code flow with PKCE (S256), `state` and
`nonce`. Plexus is a confidential client by default (`client_secret_basic`
or `client_secret_post`); with an empty client secret it acts as a public
client and relies on PKCE.

For a SAML 2.0 identity provider, see [sso-saml.md](sso-saml.md); both can
be on at once and share the account, role and access group rules below.

## 1. Register Plexus at the provider

Create a **web application** (OIDC, authorization code flow) and note:

| What | Value |
|------|-------|
| Redirect (callback) URI | `https://<plexus host>/api/auth/oidc/callback`. Settings > Authentication shows the exact value to register, with a Copy button. |
| Grant type | Authorization code (PKCE is always used) |
| Scopes | `openid` plus whatever carries the claims below, usually `profile email` (and `groups` on some providers) |
| Token endpoint authentication | `client_secret_basic` (default) or `client_secret_post`; none for a public client |
| ID token signing | RS256/384/512, PS256/384/512 or ES256/384/512. `none` and `HS*` are refused. |

The redirect URI is derived from the request (the scheme from
`X-Forwarded-Proto` as the HTTPS redirect middleware reads it, the `Host`
header, plus the callback path). Behind a proxy that rewrites the host
name, set **Redirect URI Override** to the public URL.

## 2. Configure Plexus

Settings > Authentication > **Single sign-on (OpenID Connect)**:

| Field | Default | Meaning |
|-------|---------|---------|
| Enabled | off | Offer SSO on the login page |
| Issuer | | The provider's issuer URL. It must equal the `issuer` of its discovery document (`<issuer>/.well-known/openid-configuration`) exactly and be `https` (plain `http` only on `localhost`, `127.0.0.1` or `::1`, for a lab). Every request to the provider (discovery, signing keys, token, userinfo) first passes the same outbound guard as webhooks: link-local addresses such as the cloud metadata endpoint are always refused, and private and loopback ranges too when `APP_SSRF_BLOCK_PRIVATE=true`. Each request connects to the address the guard checked, so a second DNS answer cannot redirect it. With that setting on and a provider on a private address, list its host name in `APP_SSRF_ALLOW` or sign-in fails with the `provider` error. |
| Client ID / Client Secret | | From the registration. The secret is stored encrypted (the same AES-256-GCM helper as stored credentials and the Meraki webhook secret) and is shown masked; empty means a public client. |
| Token Endpoint Auth | `client_secret_basic` | Or `client_secret_post` |
| Scopes | `openid profile email` | `openid` is always sent |
| Username Claim | `preferred_username` | Becomes the Plexus username (trimmed; 1 to 150 characters, no control characters). When it is `email`, an `email_verified` of `false` is refused. |
| Display Name Claim | `name` | |
| Groups Claim | `groups` | A list of strings or one string |
| Admin Groups | | Group claim values, one per line. A member gets the `admin` role. |
| Default Role | `user` | Role of everyone else |
| Default Access Groups | | Given to an account on its first SSO login |
| Sync access groups on every login | off | Sets the account's access groups to the defaults plus every mapped group present in the claim, on every login |
| Group Mappings | | Up to 200 pairs of group claim value and access group. Unknown access groups are skipped with a warning. |
| Button Label | `Sign in with SSO` | At most 60 characters |
| Lead with SSO on the login page | off | Display only: the SSO button comes first and the password form folds behind "Use a local account" |
| Redirect URI Override | | Empty = derived from the request |
| CA Certificate File | | A CA bundle path on the Plexus host for a provider behind a private CA; empty = system trust store |

**Test connection** fetches the discovery document and the signing keys of
the issuer in the form (fresh, not from cache) and shows the endpoints, the
allowed algorithms, the number of signing keys and the redirect URI.

Saving with SSO enabled and an empty or non-https issuer or an empty client
ID is refused (HTTP 400), as is a non-https redirect URI override.

## 3. Accounts, roles and groups

- The first SSO login of a username creates a local shadow account (random
  unusable password) managed by `oidc`. The provider's `sub` is stored on
  the account; a later login for that account with a different `sub` is
  refused, so someone who takes over the username at the provider cannot
  take over the Plexus account. An `oidc` account from before Plexus
  stored the `sub` binds it at its next login.
- An existing account is used only when it is managed by `oidc`. A local
  account (admin or not) or one managed by SAML, LDAP, RADIUS or TACACS+
  with the same username is never adopted, whatever the token maps: the
  login fails with the `account` error and the audit log records `auth` /
  `login.adopt_refused` (the same rule applies to every provider, see
  [administration.md](administration.md#authentication)).
- Role is re-synced on every login: promotion and demotion at the provider
  both reach Plexus.
- Without group sync, access groups are set once, at account creation.

### Group overage

Entra ID leaves the groups out of the token when a user is in too many
(over 200 in a JWT) and signals it with `_claim_names` / `hasgroups`.
When that happens and no groups arrive (from the token or from userinfo),
an existing account keeps its role and access groups and the audit entry
says so; a new account gets the default role and default access groups.
Assign app roles or limit the groups emitted to the application ("groups
assigned to the application") to avoid overage.

## Provider notes (invented example values)

**Entra ID.** App registrations > New registration > Web, redirect URI as
above. Issuer: `https://login.microsoftonline.com/<tenant id>/v2.0`.
Token configuration > Add groups claim (Security groups, or Groups assigned
to the application); the values are group object IDs, so put those IDs in
Admin Groups and Group Mappings. Use Username Claim `preferred_username`
(the UPN) or `email`.

**Okta.** Applications > Create App Integration > OIDC - Web Application.
Issuer: `https://example.okta.com/oauth2/default` (custom authorization
server) or `https://example.okta.com`. Add a `groups` claim to the ID token
(filter, for example, "Starts with: plexus-") and the `groups` scope.

**Keycloak.** Clients > Create client, OpenID Connect, Client
authentication on, Standard flow on. Issuer:
`https://idp.example.com/realms/<realm>`. Add a "Group Membership" mapper
named `groups` with "Full group path" off and "Add to ID token" on.

## Sign-in flow and failures

1. The SSO button goes to `GET /api/auth/oidc/login?next=<path>`. Plexus
   stores state, nonce, PKCE verifier, redirect URI and the return path in a
   signed, HttpOnly, SameSite=Lax cookie (`oidc_tx`, 10 minutes, path
   `/api/auth/oidc`) and redirects to the provider. `next` is kept only
   when it is a same-site path (one leading `/`, no `//`, `\` or control
   characters).
2. The provider redirects to `/api/auth/oidc/callback`. Plexus checks the
   state, exchanges the code, validates the ID token (signature against the
   JWKS, `iss`, `aud`, `azp`, `exp`/`iat`/`nbf` with 60 s leeway, `nonce`,
   `sub`), fetches userinfo only when a configured claim is missing (its
   `sub` must match), provisions the account and sets the normal session
   cookie.
3. On any failure the browser lands on `/login?sso_error=<code>` and the
   login page shows a fixed sentence for the code: `disabled`, `state`,
   `provider`, `token`, `claims`, `account`, `denied`. The provider's
   `error_description` is logged (redacted and truncated), never shown.
   The audit log records `login.failure` with `source=oidc` and the step
   that failed; tokens, codes, the client secret and the verifier are never
   logged or audited.

Callback failures count toward the same per-IP login rate limit and lockout
as wrong passwords, and a locked-out address is refused (`denied`).
Discovery and the JWKS are cached for an hour; a token signed with an
unknown key ID forces one JWKS refetch, at most once a minute. Outbound
calls use a 10 s timeout, do not follow redirects and verify TLS.

## Break-glass

SSO never replaces the password form. If the provider is down or
misconfigured, sign in with the local admin account (the break-glass path
stays on unless `PLEXUS_BREAKGLASS_LOCAL_ADMIN=false`) and fix or disable
SSO under Settings > Authentication. With "Lead with SSO" on, use the
"Use a local account" link.

## Not supported

SAML (see [sso-saml.md](sso-saml.md)); RP-initiated logout (signing out of Plexus does not sign out of the
provider); SCIM provisioning; fetching overage groups from
Microsoft Graph; the implicit and hybrid flows.
