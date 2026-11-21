# Single sign-on with SAML 2.0

Plexus can send the browser to a SAML 2.0 identity provider (Entra ID,
Okta, ADFS, Keycloak, PingFederate, Shibboleth and others) instead of asking
for a password. Like [OpenID Connect](sso-oidc.md), SAML is an
**additional** sign-in method: the password form, its provider chain
(local, RADIUS, TACACS+, LDAP), OIDC and the break-glass local admin keep
working. OIDC and SAML can be on at the same time; the login page then
shows both buttons.

The flow is SP-initiated Web Browser SSO: Plexus sends an `AuthnRequest`
over the HTTP-Redirect binding and receives the IdP's `Response` over the
HTTP-POST binding at its assertion consumer service (ACS). The **assertion
must be signed** by the IdP (a signed response alone is not enough).

Everything that does not depend on the protocol is shared with OIDC: the
account provisioning, the admin-group and access-group mapping, the session
cookie, the login lockout, the error codes and the button settings
(`netcontrol/sso.py`, `upsert_sso_user` in `netcontrol/routes/auth.py`).

## 1. Register Plexus at the IdP

Settings > Authentication > **Single sign-on (SAML 2.0)** shows the values
to register, each with a Copy button:

| What | Value |
|------|-------|
| SP entity ID (audience) | `https://<plexus host>/api/auth/saml/metadata` unless overridden |
| ACS URL (reply URL), HTTP-POST | `https://<plexus host>/api/auth/saml/acs` unless overridden |
| SP metadata | `GET https://<plexus host>/api/auth/saml/metadata` (no sign-in needed); most IdPs can import it |
| Signing | Sign the **assertion** (or response and assertion), RSA or ECDSA with SHA-256 or stronger. SHA-1 is refused. |
| Encryption | Off. Encrypted assertions are not supported. |
| NameID | A persistent or email NameID, or map a username attribute (a transient NameID needs one) |
| Attributes | Username (or email), display name and groups, as below |

The entity ID and ACS URL are derived from the request (the scheme from
`X-Forwarded-Proto`, the `Host` header). Behind a proxy that rewrites the
host name, set the **overrides** to the public URLs; both are then checked
against the assertion's audience and recipient.

**Use HTTPS.** The IdP posts the response to the ACS from its own site.
Plexus binds that POST to the browser that started the sign-in with a
signed `saml_tx` cookie, which the browser only sends on a cross-site POST
when it is `SameSite=None; Secure`, i.e. over HTTPS. On plain HTTP the
cookie is `SameSite=Lax` and only an IdP on the same site can complete a
sign-in.

## 2. Configure Plexus

Either import the IdP metadata (**Import from URL**, or paste the XML and
**Import pasted metadata**; the form fills in the entity ID, SSO URL and
signing certificates, then **Save**), or fill the fields by hand:

| Field | Default | Meaning |
|-------|---------|---------|
| Enabled | off | Offer SAML on the login page. Needs the entity ID, SSO URL and at least one certificate. |
| IdP Metadata URL | | Where to import the metadata from (`https`; redirects are not followed). The address passes the same outbound guard as webhooks (`APP_SSRF_BLOCK_PRIVATE`, `APP_SSRF_ALLOW`): link-local addresses such as the cloud metadata endpoint are always refused. Kept so the admin can re-import after a certificate rollover. |
| IdP Entity ID | | Must equal the `Issuer` of the IdP's assertions |
| IdP SSO URL | | The HTTP-Redirect `SingleSignOnService` location (`https`) |
| IdP Signing Certificates | | PEM blocks (or the bare base64 from metadata), up to 5 so a rollover can overlap. Stored as PEM; the form shows the saved certificates' SHA-256 fingerprints and expiry dates. An expired certificate is refused. |
| Username Attribute | empty | Attribute (`Name` or `FriendlyName`) that becomes the Plexus username. Empty uses the email attribute, else the NameID. Trimmed, 1 to 150 characters, no control characters. |
| Email Attribute | empty | Used as the username when the username attribute is empty or missing from the assertion. Plexus accounts have no separate email field. |
| Display Name Attribute | empty | |
| Groups Attribute | `groups` | Every value of the attribute is a group |
| Admin Groups, Default Role, Default Access Groups, Sync access groups, Group Mappings | | As for OIDC ([sso-oidc.md](sso-oidc.md#2-configure-plexus)), with groups attribute values instead of group claim values |
| Button Label | `Sign in with SAML` | At most 60 characters |
| Lead with SSO on the login page | off | Display only: the SSO buttons come first and the password form folds behind "Use a local account" |
| SP Entity ID / ACS URL Override | empty | Empty = derived from the request |
| CA Certificate File | | A CA bundle path on the Plexus host, for importing metadata from a host behind a private CA |

Saving with SAML enabled and no entity ID, SSO URL or certificate is
refused (HTTP 400), as is a certificate that does not parse, more than 5
certificates or a non-https URL.

## 3. Accounts, roles and groups

The same rules as OIDC ([sso-oidc.md](sso-oidc.md#3-accounts-roles-and-groups)),
with the account managed by `saml`:

- The first SAML sign-in of a username creates a local shadow account;
  the `NameID` is stored on the account (`users.external_id`) and a later
  sign-in for that account with another NameID is refused. With a
  transient NameID the account is bound to the username instead.
- An existing account is used only when it is managed by `saml`. A local
  account (admin or not) or one another provider manages is never
  adopted: the sign-in fails and is audited as `auth` / `login.adopt_refused`.
- Role is re-synced on every sign-in; access groups once, or on every
  sign-in with group sync.

## Sign-in flow and checks

1. The button goes to `GET /api/auth/saml/login?next=<path>`. Plexus
   creates a request ID, stores it with the return path in the signed,
   HttpOnly `saml_tx` cookie (10 minutes, path `/api/auth/saml`), and
   redirects to the IdP SSO URL with a deflated `SAMLRequest` and the
   return path as `RelayState`.
2. The IdP posts `SAMLResponse` and `RelayState` to `/api/auth/saml/acs`.
   Plexus refuses the response unless every check passes:
   - parsing: any DTD or entity declaration is refused (`defusedxml`
     first, then `lxml` with entity resolution, DTD loading and network
     access off), at most 1 MB;
   - status `Success`; the response's `InResponseTo` equals the request ID
     in this browser's cookie (IdP-initiated responses are refused); its
     `Destination`, when present, is the ACS URL;
   - exactly one assertion, directly in the response, and no encrypted
     assertion;
   - the assertion's own XML signature (`signxml`) verifies with one of the
     configured certificates, and its single reference is the assertion
     itself. Only the signed bytes are read from here on, so an element
     injected around or inside the signed assertion (signature wrapping)
     is never trusted;
   - `Issuer` is the IdP entity ID; `Conditions` `NotBefore` /
     `NotOnOrAfter` hold with 2 minutes of skew; an `Audience` is the SP
     entity ID;
   - a bearer `SubjectConfirmation` has `Recipient` = the ACS URL,
     `InResponseTo` = the request ID and an unexpired `NotOnOrAfter`;
   - the assertion ID has not been used before (replay cache below).
3. `RelayState` is kept only when it is a same-site path (one leading `/`,
   no `//`, `\` or control characters); anything else returns to `/`.
4. The account is provisioned and the browser gets the normal session
   cookie. On failure it lands on `/login?sso_error=<code>` with the same
   fixed sentences as OIDC (`disabled`, `state`, `provider`, `token`,
   `claims`, `account`, `denied`). The audit log records `login.failure`
   with `source=saml` and the step; the assertion is never logged.

Failures count toward the per-IP login rate limit and lockout like wrong
passwords. The ACS takes no CSRF token (the IdP's POST cannot carry one);
the signed response and the `saml_tx` cookie authenticate it.

### Replay cache

Every accepted assertion's issuer and ID (hashed) is stored in
`saml_assertion_ids` (migration 0111) until the assertion expires
(`NotOnOrAfter`, at most 24 hours, plus the skew). Posting the same
assertion again is refused (`token`), from any worker process. Expired rows
are pruned on each sign-in.

## Admin API

| Method | Path | Notes |
|--------|------|-------|
| GET/PUT | `/api/admin/auth-config` | The `saml` block holds the fields above (`idp_certs` as PEM). Omitting `saml` keeps the saved settings. |
| GET | `/api/admin/auth-config/saml/sp` | SP entity ID, ACS URL and metadata URL to register, and the saved certificates' fingerprints and expiry dates |
| POST | `/api/admin/auth-config/saml/metadata` | `{xml}` or `{url}` (plus optional `entity_id` to pick one IdP from an `EntitiesDescriptor`, `ca_cert_file`): answers the IdP entity ID, SSO URL and signing certificates. Saves nothing. |

## Provider notes (invented example values)

**Entra ID.** Enterprise applications > New application > Create your own
> Single sign-on > SAML. Identifier = the SP entity ID, Reply URL = the ACS
URL. Copy the "App Federation Metadata Url" into IdP Metadata URL. Add a
group claim (the values are group object IDs, so use those in Admin Groups
and Group Mappings); attributes arrive under long URIs such as
`http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`, so set
the Groups Attribute to that name.

**Okta.** Applications > Create App Integration > SAML 2.0. Single sign-on
URL = the ACS URL, Audience URI = the SP entity ID. Add attribute
statements `uid` and `displayName`, and a group attribute statement
`groups` (filter, for example, "Starts with: plexus-").

**Keycloak.** Clients > Create client > SAML, Client ID = the SP entity ID,
Valid redirect URIs = the ACS URL, "Sign assertions" on, "Encrypt
assertions" off. Add a "Group list" mapper named `groups` with "Full group
path" off. Metadata: `https://idp.example.com/realms/<realm>/protocol/saml/descriptor`.

## Break-glass

As for OIDC: SSO never replaces the password form. If the IdP is down or a
certificate rolled over, sign in with the local admin account and re-import
the metadata or disable SAML under Settings > Authentication.

## Not supported

IdP-initiated sign-in (unsolicited responses); encrypted assertions;
signed `AuthnRequest`s (requests are sent unsigned, which every IdP above
accepts by default); Single Logout; the HTTP-Artifact binding; SHA-1
signatures.
