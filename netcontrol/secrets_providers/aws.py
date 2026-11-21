"""AWS Secrets Manager through ``boto3``, imported lazily as the cloud
collectors do (``requirements-cloud.txt``). Without it a resolution fails
with ``sdk_not_installed``.

Auth is an access key pair, or the default credential chain (instance or
task role, environment, profile) when no key is set, optionally followed by
``sts:AssumeRole``. A reference's ``path`` is the secret name or ARN; its
``key`` names a key of a JSON secret (empty: the whole ``SecretString``).
"""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

from netcontrol.routes.net_guard import OutboundRequestError, validate_outbound_url
from netcontrol.secrets_providers.base import (
    AUTH_FAILED,
    FORBIDDEN,
    INVALID_CONFIG,
    NOT_FOUND,
    PROVIDER_ERROR,
    SDK_NOT_INSTALLED,
    UNREACHABLE,
    SecretsProvider,
    SecretsProviderError,
    Setting,
    normalize_settings,
)

_NOT_FOUND_CODES = {"ResourceNotFoundException"}
_FORBIDDEN_CODES = {"AccessDeniedException", "AccessDenied", "KMSAccessDeniedException"}
_AUTH_CODES = {
    "UnrecognizedClientException",
    "InvalidSignatureException",
    "ExpiredTokenException",
    "InvalidClientTokenId",
    "SignatureDoesNotMatch",
}
_AUTH_EXCEPTIONS = {"NoCredentialsError", "PartialCredentialsError", "NoRegionError"}
_NETWORK_EXCEPTIONS = {"EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError", "ConnectionClosedError"}
# A custom endpoint receives a SigV4-signed request, with the session token
# when there is one. Signed with the server's own role (the default chain),
# that request would hand the role's token to whatever the endpoint names.
_ENDPOINT_NEEDS_KEY = "endpoint_url needs an explicit access key; the default credential chain is only sent to AWS"


class AwsSecretsManagerProvider(SecretsProvider):
    provider_type = "aws"
    label = "AWS Secrets Manager"
    SETTINGS: ClassVar[tuple[Setting, ...]] = (
        Setting("region", required=True, max_len=64),
        Setting("access_key_id", max_len=128),
        Setting("role_arn", max_len=2048),
        Setting("external_id", max_len=1224),
        Setting("endpoint_url", "url"),
        Setting("timeout", "int", default=10, minimum=1, maximum=60),
    )
    SECRETS: ClassVar[tuple[str, ...]] = ("secret_access_key", "session_token")
    # The endpoint (or the region's endpoint) receives the session token.
    DESTINATION_SETTINGS: ClassVar[tuple[str, ...]] = ("endpoint_url", "region")
    SDK_MODULES: ClassVar[dict[str, str]] = {"boto3": "boto3"}

    @classmethod
    def validate(cls, config: dict, secrets: dict) -> dict:
        config = normalize_settings(cls.SETTINGS, config)
        if config["access_key_id"] and not secrets.get("secret_access_key"):
            raise ValueError("An access key ID needs its secret access key (or clear both for the default chain)")
        if config["endpoint_url"] and not config["access_key_id"]:
            raise ValueError(_ENDPOINT_NEEDS_KEY)
        return config

    @classmethod
    def used_secrets(cls, config: dict) -> tuple[str, ...]:
        return cls.SECRETS if config.get("access_key_id") else ()

    def _error(self, exc: Exception, path: str) -> SecretsProviderError:
        error = (getattr(exc, "response", None) or {}).get("Error") or {}
        code = str(error.get("Code") or "")
        kind = type(exc).__name__
        if code in _NOT_FOUND_CODES:
            return SecretsProviderError(NOT_FOUND, f"{self.name}: no secret '{path}'")
        if code in _FORBIDDEN_CODES:
            return SecretsProviderError(FORBIDDEN, f"{self.name}: permission denied for '{path}' ({code})")
        if code in _AUTH_CODES or kind in _AUTH_EXCEPTIONS:
            return SecretsProviderError(AUTH_FAILED, f"{self.name}: authentication failed ({code or kind})")
        if kind in _NETWORK_EXCEPTIONS:
            return SecretsProviderError(UNREACHABLE, f"{self.name}: could not reach AWS ({kind})")
        return SecretsProviderError(PROVIDER_ERROR, f"{self.name}: request failed for '{path}' ({code or kind})")

    def _fetch_sync(self, path: str) -> str:
        try:
            import boto3
        except ImportError as exc:
            raise SecretsProviderError(
                SDK_NOT_INSTALLED, f"{self.name}: AWS Secrets Manager needs boto3 (requirements-cloud.txt)"
            ) from exc
        region = str(self.config["region"])
        session_kwargs: dict[str, Any] = {"region_name": region}
        if self.config.get("access_key_id"):
            session_kwargs["aws_access_key_id"] = self.config["access_key_id"]
            session_kwargs["aws_secret_access_key"] = self.secrets.get("secret_access_key", "")
            if self.secrets.get("session_token"):
                session_kwargs["aws_session_token"] = self.secrets["session_token"]
        client_kwargs: dict[str, Any] = {"region_name": region}
        endpoint_url = str(self.config.get("endpoint_url") or "")
        if endpoint_url:
            if not self.config.get("access_key_id"):
                raise SecretsProviderError(INVALID_CONFIG, f"{self.name}: {_ENDPOINT_NEEDS_KEY}")
            # boto3 opens its own connections, so the shared sender's check
            # runs here (not pinned).
            try:
                validate_outbound_url(endpoint_url)
            except OutboundRequestError as exc:
                raise SecretsProviderError(
                    UNREACHABLE, f"{self.name}: endpoint_url refused by the outbound address guard ({exc})"
                ) from exc
            client_kwargs["endpoint_url"] = endpoint_url
        try:
            from botocore.config import Config

            timeout = int(self.config.get("timeout", 10))
            client_kwargs["config"] = Config(
                connect_timeout=timeout, read_timeout=timeout, retries={"max_attempts": 2, "mode": "standard"}
            )
        except ImportError:
            pass
        try:
            session = boto3.session.Session(**session_kwargs)
            if self.config.get("role_arn"):
                assume: dict[str, Any] = {"RoleArn": self.config["role_arn"], "RoleSessionName": "plexus-secrets"}
                if self.config.get("external_id"):
                    assume["ExternalId"] = self.config["external_id"]
                creds = session.client("sts", region_name=region).assume_role(**assume)["Credentials"]
                session = boto3.session.Session(
                    region_name=region,
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                )
            response = session.client("secretsmanager", **client_kwargs).get_secret_value(SecretId=path)
        except SecretsProviderError:
            raise
        except Exception as exc:
            raise self._error(exc, path) from exc
        if response.get("SecretString") is not None:
            return str(response["SecretString"])
        binary = response.get("SecretBinary")
        if isinstance(binary, bytes | bytearray):
            try:
                return bytes(binary).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SecretsProviderError(PROVIDER_ERROR, f"{self.name}: '{path}' is binary, not text") from exc
        raise SecretsProviderError(PROVIDER_ERROR, f"{self.name}: '{path}' has no value")

    async def fetch(self, path: str) -> str:
        return await asyncio.to_thread(self._fetch_sync, path.strip())
