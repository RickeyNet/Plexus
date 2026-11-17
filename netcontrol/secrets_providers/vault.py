"""HashiCorp Vault (and OpenBao) KV secrets engine, version 2 or 1, over its
HTTP API with ``httpx`` (no ``hvac`` dependency).

Auth is a token or AppRole (``role_id`` plus a secret id, exchanged for a
token that is cached for its lease). Enterprise namespaces go in the
``X-Vault-Namespace`` header. A reference's ``path`` is relative to the
mount (``network/core`` reads ``<mount>/data/network/core`` on KV v2) and its
``key`` names a field of the secret.
"""

from __future__ import annotations

from typing import ClassVar

from netcontrol.secrets_providers.base import (
    AUTH_FAILED,
    FORBIDDEN,
    PROVIDER_ERROR,
    TOKEN_CACHE,
    SecretsProvider,
    SecretsProviderError,
    Setting,
    json_body,
    normalize_settings,
    url_path,
)

# AppRole tokens are re-used for their lease, at most this long.
TOKEN_TTL_MAX = 3600
TOKEN_TTL_DEFAULT = 300


class VaultProvider(SecretsProvider):
    provider_type = "vault"
    label = "HashiCorp Vault"
    SETTINGS: ClassVar[tuple[Setting, ...]] = (
        Setting("url", "url", required=True),
        Setting("mount", default="secret", required=True, max_len=256),
        Setting("kv_version", "choice", default=2, choices=(2, 1)),
        Setting("auth_method", "choice", default="token", choices=("token", "approle")),
        Setting("namespace", max_len=256),
        Setting("role_id", max_len=256),
        Setting("approle_mount", default="approle", max_len=256),
        Setting("verify_tls", "bool", default=True),
        Setting("ca_pem", max_len=65536),
        Setting("timeout", "int", default=10, minimum=1, maximum=60),
    )
    SECRETS: ClassVar[tuple[str, ...]] = ("token", "secret_id")

    @classmethod
    def validate(cls, config: dict, secrets: dict) -> dict:
        config = normalize_settings(cls.SETTINGS, config)
        if config["auth_method"] == "token" and not secrets.get("token"):
            raise ValueError("Token auth needs a Vault token")
        if config["auth_method"] == "approle" and not (config["role_id"] and secrets.get("secret_id")):
            raise ValueError("AppRole auth needs a role ID and a secret ID")
        return config

    @classmethod
    def used_secrets(cls, config: dict) -> tuple[str, ...]:
        return ("secret_id",) if config.get("auth_method") == "approle" else ("token",)

    def _headers(self, token: str = "") -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if token:
            headers["X-Vault-Token"] = token
        if self.config.get("namespace"):
            headers["X-Vault-Namespace"] = str(self.config["namespace"])
        return headers

    async def _token(self) -> str:
        if self.config.get("auth_method") != "approle":
            return self.secrets.get("token", "")
        cached = TOKEN_CACHE.get(self.token_cache_key())
        if cached:
            return cached
        url = f"{self.config['url']}/v1/auth/{url_path(str(self.config['approle_mount']))}/login"
        response = await self.http(
            "POST",
            url,
            headers=self._headers(),
            json_body={"role_id": self.config["role_id"], "secret_id": self.secrets.get("secret_id", "")},
        )
        if response.status_code in (400, 401, 403):
            raise SecretsProviderError(AUTH_FAILED, f"{self.name}: AppRole login failed (HTTP {response.status_code})")
        if response.status_code >= 300:
            raise self.status_error(response)
        auth = json_body(response, self.name).get("auth") or {}
        token = str(auth.get("client_token") or "")
        if not token:
            raise SecretsProviderError(AUTH_FAILED, f"{self.name}: AppRole login returned no token")
        lease = auth.get("lease_duration")
        ttl = int(lease) - 30 if isinstance(lease, int) and lease > 60 else TOKEN_TTL_DEFAULT
        TOKEN_CACHE.set(self.token_cache_key(), token, min(ttl, TOKEN_TTL_MAX))
        return token

    async def fetch(self, path: str) -> dict:
        mount = url_path(str(self.config["mount"]))
        secret = url_path(path)
        if int(self.config.get("kv_version", 2)) == 2:
            url = f"{self.config['url']}/v1/{mount}/data/{secret}"
        else:
            url = f"{self.config['url']}/v1/{mount}/{secret}"
        response = await self.http("GET", url, headers=self._headers(await self._token()))
        if response.status_code in (401, 403):
            # A revoked or expired AppRole token: log in again next time.
            TOKEN_CACHE.discard(lambda k: k == self.token_cache_key())
            if response.status_code == 403:
                raise SecretsProviderError(FORBIDDEN, f"{self.name}: permission denied for '{path}' (HTTP 403)")
        if response.status_code >= 300:
            raise self.status_error(response, path)
        data = json_body(response, self.name).get("data")
        if int(self.config.get("kv_version", 2)) == 2:
            data = (data or {}).get("data") if isinstance(data, dict) else None
        if not isinstance(data, dict):
            raise SecretsProviderError(PROVIDER_ERROR, f"{self.name}: '{path}' holds no key/value data")
        return data
