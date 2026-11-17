"""Azure Key Vault secrets over the Key Vault REST API with ``httpx``.

The access token comes either from the client-credentials grant against
Microsoft Entra ID (tenant, client id, client secret; plain HTTP, no SDK) or
from ``azure-identity``'s ``DefaultAzureCredential`` (managed identity,
workload identity, environment), imported lazily as the cloud collectors do;
without the package that auth method fails with ``sdk_not_installed``.

A reference's ``path`` is the secret name, optionally ``name/version``; its
``key`` names a key of a JSON secret value (empty: the whole value).
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import ClassVar
from urllib.parse import urlencode, urlsplit

from netcontrol.secrets_providers.base import (
    AUTH_FAILED,
    INVALID_REFERENCE,
    PROVIDER_ERROR,
    SDK_NOT_INSTALLED,
    TOKEN_CACHE,
    SecretsProvider,
    SecretsProviderError,
    Setting,
    json_body,
    normalize_settings,
)

API_VERSION = "7.4"
_NAME_RE = re.compile(r"^[0-9A-Za-z-]{1,127}$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z]{1,64}$")
_TENANT_RE = re.compile(r"^[0-9A-Za-z.-]{1,128}$")
TOKEN_TTL_MAX = 3600


def vault_scope(vault_url: str) -> str:
    """The token scope for a vault: ``https://vault.azure.net/.default`` for
    ``https://name.vault.azure.net`` (and the sovereign-cloud suffixes)."""
    host = urlsplit(vault_url).hostname or ""
    suffix = host.split(".", 1)[1] if "." in host else host
    return f"https://{suffix}/.default"


class AzureKeyVaultProvider(SecretsProvider):
    provider_type = "azure"
    label = "Azure Key Vault"
    SETTINGS: ClassVar[tuple[Setting, ...]] = (
        Setting("vault_url", "url", required=True),
        Setting("auth_method", "choice", default="client_secret", choices=("client_secret", "default")),
        Setting("tenant_id", max_len=128),
        Setting("client_id", max_len=128),
        Setting("authority_host", "url", default="https://login.microsoftonline.com"),
        Setting("verify_tls", "bool", default=True),
        Setting("ca_pem", max_len=65536),
        Setting("timeout", "int", default=10, minimum=1, maximum=60),
    )
    SECRETS: ClassVar[tuple[str, ...]] = ("client_secret",)

    @classmethod
    def validate(cls, config: dict, secrets: dict) -> dict:
        config = normalize_settings(cls.SETTINGS, config)
        if config["auth_method"] == "client_secret":
            if not (config["tenant_id"] and config["client_id"] and secrets.get("client_secret")):
                raise ValueError("Client secret auth needs a tenant ID, a client ID and a client secret")
            if not _TENANT_RE.fullmatch(config["tenant_id"]):
                raise ValueError("tenant_id must be a tenant ID or domain")
        return config

    @classmethod
    def used_secrets(cls, config: dict) -> tuple[str, ...]:
        return cls.SECRETS if config.get("auth_method") == "client_secret" else ()

    @classmethod
    def sdk_modules(cls, config: dict) -> dict[str, str]:
        return {"azure.identity": "azure-identity"} if config.get("auth_method") == "default" else {}

    def _default_token_sync(self, scope: str) -> tuple[str, float]:
        try:
            from azure.identity import DefaultAzureCredential
        except ImportError as exc:
            raise SecretsProviderError(
                SDK_NOT_INSTALLED, f"{self.name}: the default Azure credential needs azure-identity"
            ) from exc
        try:
            token = DefaultAzureCredential().get_token(scope)
        except Exception as exc:
            raise SecretsProviderError(
                AUTH_FAILED, f"{self.name}: no Azure credential available ({type(exc).__name__})"
            ) from exc
        return str(token.token), float(token.expires_on) - time.time()

    async def _client_secret_token(self, scope: str) -> tuple[str, float]:
        url = f"{self.config['authority_host']}/{self.config['tenant_id']}/oauth2/v2.0/token"
        form = urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self.config["client_id"],
                "client_secret": self.secrets.get("client_secret", ""),
                "scope": scope,
            }
        )
        response = await self.http(
            "POST", url, headers={"Content-Type": "application/x-www-form-urlencoded"}, content=form
        )
        if response.status_code in (400, 401, 403):
            raise SecretsProviderError(
                AUTH_FAILED, f"{self.name}: Entra ID refused the client credentials (HTTP {response.status_code})"
            )
        if response.status_code >= 300:
            raise self.status_error(response)
        body = json_body(response, self.name)
        token = str(body.get("access_token") or "")
        if not token:
            raise SecretsProviderError(AUTH_FAILED, f"{self.name}: Entra ID returned no access token")
        try:
            lifetime = float(body.get("expires_in", 300))
        except TypeError, ValueError:
            lifetime = 300.0
        return token, lifetime

    async def _token(self) -> str:
        cached = TOKEN_CACHE.get(self.token_cache_key())
        if cached:
            return cached
        scope = vault_scope(str(self.config["vault_url"]))
        if self.config.get("auth_method") == "default":
            token, lifetime = await asyncio.to_thread(self._default_token_sync, scope)
        else:
            token, lifetime = await self._client_secret_token(scope)
        TOKEN_CACHE.set(self.token_cache_key(), token, min(lifetime - 60, TOKEN_TTL_MAX))
        return token

    async def fetch(self, path: str) -> str:
        name, _, version = path.strip().strip("/").partition("/")
        if not _NAME_RE.fullmatch(name) or (version and not _VERSION_RE.fullmatch(version)):
            raise SecretsProviderError(
                INVALID_REFERENCE, f"'{path}' is not a Key Vault secret name (letters, digits, hyphens)"
            )
        url = f"{self.config['vault_url']}/secrets/{name}" + (f"/{version}" if version else "")
        response = await self.http(
            "GET",
            f"{url}?api-version={API_VERSION}",
            headers={"Authorization": f"Bearer {await self._token()}", "Accept": "application/json"},
        )
        if response.status_code == 401:
            TOKEN_CACHE.discard(lambda k: k == self.token_cache_key())
        if response.status_code >= 300:
            raise self.status_error(response, path)
        value = json_body(response, self.name).get("value")
        if not isinstance(value, str):
            raise SecretsProviderError(PROVIDER_ERROR, f"{self.name}: '{path}' has no value")
        return value
