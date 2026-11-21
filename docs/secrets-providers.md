# Secrets providers: Vault, AWS Secrets Manager and Azure Key Vault

Plexus keeps device credentials and `{{secret.NAME}}` secret variables
encrypted in its own database. A secrets provider lets them live in your
secret store instead: the credential or secret variable holds only a
**reference** (provider, path, key), and Plexus reads the value from the
store each time the secret is used. Rotate the password in the store and the
next job, poll or backup uses the new one; nothing is copied into Plexus.

Supported stores:

| Type | Reads | Authentication |
|---|---|---|
| HashiCorp Vault (and OpenBao) | KV secrets engine, version 2 or 1 | Token, or AppRole (role ID and secret ID) |
| AWS Secrets Manager | `GetSecretValue` (string or UTF-8 binary secrets) | Access key pair, or the server's default credential chain (instance or task role, environment), optionally followed by an assumed role |
| Azure Key Vault | Secrets (latest or a given version) | App registration with a client secret, or managed identity / environment through `azure-identity` |

Open **Settings > Secrets Providers** to add, edit, test and delete
providers. Credentials and secret variables (**Change > Delegator >
Credentials**) and service credentials (**Settings > Authentication**) then
offer **Stored in Plexus** or **External reference** in their forms.

## How it works

1. An admin adds a provider: its address and the credentials Plexus uses to
   read from it.
2. A credential or secret variable chooses **External reference** and names
   the provider, the **path** of the secret and the **key** inside it.
3. When something uses the secret (a job, a monitoring poll, a config
   backup, a `{{secret.NAME}}` in an instruction set), Plexus resolves the
   reference at that moment. Every feature reads credentials through the same
   two functions, so every feature supports references; none has a separate
   setting.
4. The value is kept in server memory for the provider's **cache** time
   (default 300 seconds, 0 to 3600, 0 to ask every time), so a job against 50
   devices asks the store once. Changing or deleting the provider empties its
   cache.

Values are never written to the Plexus database, the audit log, the server
log or any API response. The forms show the reference only.

## References

| Type | Path | Key |
|---|---|---|
| Vault | Path under the mount: `network/core-switches` reads `<mount>/data/network/core-switches` on KV v2 and `<mount>/network/core-switches` on KV v1 | A field of the secret. Blank works when the secret has exactly one field |
| AWS | The secret name or ARN | A key of a JSON secret. Blank: the whole secret string |
| Azure | The secret name, or `name/version` | A key of a JSON value. Blank: the whole value |

A credential has two keys: the **password key** and an optional **enable
secret key**. With the enable secret key blank, the enable secret is the
password (as for a stored credential with no secret). Both keys are read
from the same path.

Example: a Vault KV v2 secret at `secret/network/core-switches` with the
fields `password` and `enable` is the reference provider `corp-vault`, path
`network/core-switches`, password key `password`, enable secret key
`enable`.

## Adding a provider

**Settings > Secrets Providers > Add secrets provider**. Common fields:

| Field | Meaning |
|---|---|
| Name | Unique, shown in the credential forms |
| Type | Vault, AWS Secrets Manager or Azure Key Vault. Cannot change later |
| Cache values for | Seconds a resolved value is kept in server memory (0 to 3600) |
| Enabled | A disabled provider resolves nothing; credentials pointing at it fail |
| Allow personal credentials | Non-admin users may point their own credentials at this provider |

The provider's own secrets (Vault token, AppRole secret ID, AWS secret
access key and session token, Azure client secret) are write-only. They are
stored encrypted with the Plexus encryption key, never returned by the API,
and the edit form shows **Stored; leave blank to keep**. Each has a Show/Hide
button to check what you typed.

A stored secret is kept only while it goes to the same place. Changing the
address or the TLS settings (Vault address, TLS verification or CA bundle;
AWS region or endpoint URL; Azure vault URL, authority host or tenant ID)
needs the provider's secrets entered again in the same save; otherwise the
save is refused with a message naming them. Addresses must be `https://`
(`http://` only to `localhost`).

### HashiCorp Vault

| Setting | Default | Notes |
|---|---|---|
| Vault address | | `https://vault.example.com:8200` |
| KV mount | `secret` | The mount path of the KV engine |
| KV version | 2 | 1 for a KV v1 mount |
| Namespace | | Vault Enterprise namespace, sent as `X-Vault-Namespace` |
| Authentication | Token | **Token**: a token with read access. **AppRole**: role ID and secret ID; Plexus logs in and reuses the token for its lease (at most one hour) |
| AppRole mount | `approle` | |
| Verify the TLS certificate | on | |
| CA bundle | | PEM certificates to trust instead of the system store |

A minimal Vault policy for Plexus:

```hcl
path "secret/data/network/*" {
  capabilities = ["read"]
}
```

### AWS Secrets Manager

Needs `boto3`, which is in `requirements-cloud.txt` (the Docker image
installs it). Without it the provider shows **SDK not installed** and every
reference fails with `sdk_not_installed`.

| Setting | Notes |
|---|---|
| Region | For example `us-east-1` |
| Access key ID and secret access key | Optional. Blank: the default credential chain of the Plexus server |
| Session token | Optional, for temporary keys |
| Role ARN and external ID | Optional: Plexus calls `sts:AssumeRole` first |
| Endpoint URL | Optional, for a VPC interface endpoint. Needs an access key: with the default credential chain the request would be signed with the server's own role and sent to this address, so that is refused |

The identity needs `secretsmanager:GetSecretValue` on the secrets (and
`kms:Decrypt` for a customer managed key).

### Azure Key Vault

| Setting | Notes |
|---|---|
| Vault URL | `https://my-vault.vault.azure.net` (sovereign clouds work: the token scope follows the host) |
| Authentication | **App registration**: tenant ID, client ID and client secret, sent to Microsoft Entra ID over HTTPS, no SDK needed. **Managed identity / environment**: `DefaultAzureCredential` from `azure-identity` (in `requirements-cloud.txt`); without the package the provider shows **SDK not installed** |
| Authority host | Default `https://login.microsoftonline.com` |

The identity needs the **Key Vault Secrets User** role (or a `get` secret
access policy).

## Testing

**Test** on a provider row asks for a path and an optional key, resolves
that one reference without the cache, and answers **The reference resolved**
or the reason it did not. It never shows the value. Every test is audited.

| Code | Meaning | Next step |
|---|---|---|
| `sdk_not_installed` | `boto3` or `azure-identity` is missing on the server | Install `requirements-cloud.txt` |
| `auth_failed` | The store refused the provider's credentials | Check the token, AppRole or keys |
| `forbidden` | Authenticated, but no read access to that secret | Grant read access |
| `not_found` | No secret at that path | Check the path and mount |
| `key_not_found` | The secret has no such key, or several keys and none named | Check the key |
| `unreachable` | No connection, TLS failure, or an address the outbound guard refuses | Check the address, CA bundle and firewall |
| `invalid_reference` | The path is empty or has `.`/`..` segments or bad characters | Fix the path |
| `invalid_config` | A CA bundle that does not parse, stored settings that cannot be read, or an AWS endpoint URL without an access key | Save the provider again |
| `disabled` | The provider is disabled | Enable it |
| `provider_error` | Any other refusal from the store | See the HTTP status in the message |

Requests use the same outbound guard as webhooks and notification channels
(`APP_SSRF_BLOCK_PRIVATE`, `APP_SSRF_ALLOW`): link-local addresses such as
the cloud metadata endpoint are always refused, and redirects are not
followed. The AWS endpoint URL goes through `boto3`, which opens its own
connection: the guard checks it before each fetch, without pinning. Saving
a provider runs the guard on its address settings (Vault URL, Azure vault
URL and authority host, AWS endpoint URL) and answers `400` when it
refuses one.

## When a reference fails

- **Jobs, deployments, backups and other actions that check the credential
  first** stop with `502` and the reason, for example
  `The credential's external secret could not be resolved: corp-vault: no
  secret for 'network/core' (HTTP 404)`. A queued job fails with the same
  text in its events.
- **Background work** (monitoring, MAC collection, discovery with the
  service credential) gets an error where it would use the password; work
  that does not need the password, such as an SNMP poll, carries on.
- **`{{secret.NAME}}`** fails the job as an unresolved secret variable.

Every failure is written to the server log and to the audit log as
`secrets_provider.resolve_failed` with the provider, the credential or
secret variable id and the error code. The same failure for the same
reference is audited once every five minutes, so a failing poll loop cannot
flood the audit log.

## Who can do what

| Action | Needs |
|---|---|
| List providers and their settings | `secrets-providers` feature |
| Add, edit, delete and test providers | `secrets-providers.write` |
| Point your own credential at a provider | `credentials.write`, and the provider allows personal credentials (admins: any provider) |
| Point a service credential or secret variable at a provider | Admin |

The Settings page is for admins; the feature keys grant the same through the
API. Allowing personal credentials lets those users read any secret the
provider's identity can read, by pointing a credential at it and using it on
a device they control: allow it only on a provider whose identity reads just
the secrets meant for them.

A provider referenced by a credential or secret variable cannot be deleted
(`409`, with the counts); point them elsewhere first.

## API

All routes follow the usual session and CSRF rules; see
[API reference](api-reference.md#secrets-providers).

```
GET    /api/secrets-providers                 providers and the supported types
GET    /api/secrets-providers/{id}
POST   /api/secrets-providers                 {name, provider_type, description?, enabled?, allow_user_credentials?, cache_ttl?, config, secrets}
PUT    /api/secrets-providers/{id}            any of the above but provider_type; a blank secret keeps the stored one, except after an address or TLS change (400)
DELETE /api/secrets-providers/{id}            409 while referenced
POST   /api/secrets-providers/{id}/test       {path, key?} -> {ok} or {ok: false, code, message}
GET    /api/credentials/secrets-providers     the providers the caller may reference (id, name, type)
```

A credential or secret variable takes the reference as `external`:

```json
{"name": "core", "username": "netops",
 "external": {"provider_id": 3, "path": "network/core-switches", "key": "password", "secret_key": "enable"}}
```

Secret variables take `{"name", "description", "external": {"provider_id",
"path", "key"}}`. On update, `external` replaces a stored value, and a new
`password` (or `value`) replaces the reference. Lists return the reference
as `ext_provider_id`, `ext_provider_name`, `ext_path`, `ext_key` and, for
credentials, `ext_secret_key`.

## Audit

Category `secrets_providers`: `secrets_provider.create`, `.update`,
`.delete`, `.test` and `.resolve_failed`. The detail names the provider and
which secret fields changed, never a value. Credential and secret variable
changes stay under `config` and say when a reference was set or replaced.
See [Audit log](audit-log.md).

## Not covered

Integration sources and cloud accounts (Meraki, Cato, AWS, Azure, GCP
topology and the other API integrations) keep their own encrypted keys; they
do not take a secrets provider reference yet.
