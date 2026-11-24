"""The secrets provider interface, its errors, key selection and the TTL cache.

A provider turns a reference (``path`` plus an optional ``key``) into one
string. ``SecretsProvider.resolve`` fetches the secret at ``path`` (a mapping
of keys to values, or one string), picks ``key`` out of it with
``select_key`` and keeps the result in a short in-memory cache
(``VALUE_CACHE``) keyed by the provider's id and version, so a job that opens
fifty SSH sessions asks the provider once.

Errors are ``SecretsProviderError`` with a ``code`` and a message that is
safe to show and to log: it names the provider, the path and the key, never
a value. ``SecretsProviderError`` subclasses ``RuntimeError``, the exception
``routes.crypto.decrypt`` raises, so callers that handle a credential they
cannot decrypt handle an external secret they cannot resolve the same way.
"""

from __future__ import annotations

import json
import re
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Hashable
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

import httpx

from netcontrol.routes.outbound_http import OutboundRequestError, send_request, tls_verify
from netcontrol.sso import is_allowed_url

# Error codes (``SecretsProviderError.code``), also returned by the test
# endpoint and written to the audit log.
SDK_NOT_INSTALLED = "sdk_not_installed"
INVALID_CONFIG = "invalid_config"
INVALID_REFERENCE = "invalid_reference"
AUTH_FAILED = "auth_failed"
FORBIDDEN = "forbidden"
NOT_FOUND = "not_found"
KEY_NOT_FOUND = "key_not_found"
UNREACHABLE = "unreachable"
PROVIDER_ERROR = "provider_error"
DISABLED = "disabled"
PROVIDER_MISSING = "provider_missing"
PERSONAL_NOT_ALLOWED = "personal_not_allowed"

PATH_MAX = 512
KEY_MAX = 256
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

# Replaces the network layer of every provider HTTP call when set (tests
# assign an ``httpx.MockTransport``).
HTTP_TRANSPORT: httpx.AsyncBaseTransport | None = None


class SecretsProviderError(RuntimeError):
    """A reference could not be resolved. ``str(exc)`` is safe to show."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class Reference:
    """Where a secret lives in a provider: ``path`` and, for a secret that
    holds several values, the ``key`` of the one wanted (``""``: the whole
    secret, or its only key)."""

    path: str
    key: str = ""


def check_reference(path: str, key: str = "") -> Reference:
    """The stripped reference, or ``ValueError`` with the reason."""
    path = (path or "").strip()
    key = (key or "").strip()
    if not path:
        raise ValueError("Enter the path of the secret")
    if len(path) > PATH_MAX or len(key) > KEY_MAX:
        raise ValueError(f"The path is at most {PATH_MAX} and the key at most {KEY_MAX} characters")
    if _CONTROL_RE.search(path) or _CONTROL_RE.search(key):
        raise ValueError("The path and key cannot contain control characters")
    return Reference(path, key)


def url_path(path: str) -> str:
    """``path`` as URL path segments, each percent-encoded. Raises
    ``SecretsProviderError`` for an empty path or a ``.``/``..`` segment."""
    segments = [s for s in path.strip("/").split("/")]
    if not segments or any(s in ("", ".", "..") for s in segments):
        raise SecretsProviderError(INVALID_REFERENCE, f"'{path}' is not a valid secret path")
    return "/".join(quote(s, safe="") for s in segments)


def _scalar(value: Any, what: str) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str | int | float):
        return str(value)
    raise SecretsProviderError(KEY_NOT_FOUND, f"{what} is not a single value; name one of its keys")


def select_key(raw: str | dict, key: str, path: str) -> str:
    """The value of ``key`` in the secret ``raw`` fetched from ``path``.

    ``raw`` is a mapping (a Vault secret) or a string (AWS, Azure). A string
    is the value itself when ``key`` is empty, else it must be a JSON object
    holding ``key``. A mapping with one key gives that key's value when
    ``key`` is empty. Errors name the path and key, never a value."""
    if isinstance(raw, str):
        if not key:
            return raw
        try:
            parsed: Any = json.loads(raw)
        except ValueError:
            parsed = None
        if not isinstance(parsed, dict):
            raise SecretsProviderError(
                KEY_NOT_FOUND, f"The secret at '{path}' is not a JSON object, so it has no key '{key}'"
            )
        raw = parsed
    if not key:
        if len(raw) == 1:
            return _scalar(next(iter(raw.values())), f"The secret at '{path}'")
        raise SecretsProviderError(KEY_NOT_FOUND, f"The secret at '{path}' holds {len(raw)} keys; name the one to use")
    if key not in raw:
        raise SecretsProviderError(KEY_NOT_FOUND, f"The secret at '{path}' has no key '{key}'")
    return _scalar(raw[key], f"Key '{key}' of the secret at '{path}'")


class TTLCache:
    """A small thread-safe map whose entries expire after their own TTL.

    At most ``max_entries`` live entries; the oldest is dropped first."""

    def __init__(self, max_entries: int = 1024, clock: Callable[[], float] = time.monotonic):
        self._items: dict[Hashable, tuple[float, Any]] = {}
        self._lock = threading.Lock()
        self.max_entries = max_entries
        self.clock = clock

    def get(self, key: Hashable) -> Any | None:
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            if item[0] <= self.clock():
                del self._items[key]
                return None
            return item[1]

    def set(self, key: Hashable, value: Any, ttl: float) -> None:
        if ttl <= 0:
            return
        with self._lock:
            self._items.pop(key, None)
            while len(self._items) >= self.max_entries:
                del self._items[next(iter(self._items))]
            self._items[key] = (self.clock() + ttl, value)

    def discard(self, match: Callable[[Hashable], bool]) -> None:
        """Drop every entry whose key ``match`` accepts."""
        with self._lock:
            for key in [k for k in self._items if match(k)]:
                del self._items[key]

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        return len(self._items)


# Resolved values and provider access tokens. Keys start with the provider
# id, so a provider's entries can be dropped when it changes.
VALUE_CACHE = TTLCache()
TOKEN_CACHE = TTLCache(max_entries=256)


def invalidate(provider_id: int | None = None) -> None:
    """Forget cached values and tokens of one provider (all when ``None``)."""
    if provider_id is None:
        VALUE_CACHE.clear()
        TOKEN_CACHE.clear()
        return
    for cache in (VALUE_CACHE, TOKEN_CACHE):
        cache.discard(lambda k: isinstance(k, tuple) and k[0] == provider_id)


@dataclass(frozen=True)
class Setting:
    """One non-secret provider setting: its kind, default and limits."""

    name: str
    kind: str = "str"  # str, url, bool, int or choice
    default: Any = ""
    required: bool = False
    choices: tuple[Any, ...] = ()
    minimum: int = 0
    maximum: int = 0
    max_len: int = 2048


def normalize_settings(settings: tuple[Setting, ...], raw: dict) -> dict:
    """``raw`` reduced to the known settings with their defaults, checked.
    Raises ``ValueError`` naming the first bad setting."""
    raw = raw if isinstance(raw, dict) else {}
    out: dict[str, Any] = {}
    for s in settings:
        value = raw.get(s.name, s.default)
        if value is None:
            value = s.default
        if s.kind == "bool":
            if not isinstance(value, bool):
                raise ValueError(f"{s.name} must be true or false")
        elif s.kind == "int":
            if isinstance(value, bool) or not isinstance(value, int) or not s.minimum <= value <= s.maximum:
                raise ValueError(f"{s.name} must be a whole number from {s.minimum} to {s.maximum}")
        elif s.kind == "choice":
            if value not in s.choices:
                raise ValueError(f"{s.name} must be one of: {', '.join(str(c) for c in s.choices)}")
        else:
            if not isinstance(value, str):
                raise ValueError(f"{s.name} must be text")
            value = value.strip()
            if len(value) > s.max_len:
                raise ValueError(f"{s.name} is at most {s.max_len} characters")
            if s.kind == "url" and value:
                parts = urlsplit(value)
                if parts.scheme not in ("http", "https") or not parts.hostname:
                    raise ValueError(f"{s.name} must be an http:// or https:// URL")
                # The provider's token or key goes to this address, so
                # plain http only to this machine (a local dev Vault).
                if not is_allowed_url(value):
                    raise ValueError(f"{s.name} must be an https:// URL (http:// only to localhost)")
                value = value.rstrip("/")
        if s.required and value in ("", None):
            raise ValueError(f"{s.name} is required")
        out[s.name] = value
    return out


class SecretsProvider(ABC):
    """One configured provider. ``config`` holds the normalized non-secret
    settings, ``secrets`` the provider's own auth secrets (decrypted).

    ``provider_id`` and ``version`` (the row's ``updated_at``) key the
    caches, so editing a provider drops its old values."""

    provider_type: ClassVar[str]
    label: ClassVar[str]
    SETTINGS: ClassVar[tuple[Setting, ...]]
    SECRETS: ClassVar[tuple[str, ...]]
    # Settings that decide where the secrets are sent (address, TLS checks):
    # changing one on update needs the secrets entered again
    # (service.prepare_provider, netcontrol.secret_fields).
    DESTINATION_SETTINGS: ClassVar[tuple[str, ...]] = ()
    # Python modules the provider imports lazily -> pip distribution name.
    SDK_MODULES: ClassVar[dict[str, str]] = {}

    def __init__(
        self,
        config: dict,
        secrets: dict | None = None,
        *,
        provider_id: int = 0,
        version: str = "",
        cache_ttl: int = 300,
        name: str = "",
    ):
        self.config = config
        self.secrets = {k: str(v) for k, v in (secrets or {}).items() if v}
        self.provider_id = provider_id
        self.version = version
        self.cache_ttl = cache_ttl
        self.name = name or self.label

    @classmethod
    def validate(cls, config: dict, secrets: dict) -> dict:
        """The normalized ``config``; raises ``ValueError`` when it, or the
        set of ``secrets`` it needs, is not usable."""
        return normalize_settings(cls.SETTINGS, config)

    @classmethod
    def used_secrets(cls, config: dict) -> tuple[str, ...]:
        """The secret fields the normalized ``config`` uses; others are dropped."""
        return cls.SECRETS

    @classmethod
    def sdk_modules(cls, config: dict) -> dict[str, str]:
        """The lazily imported modules ``config`` needs -> pip distribution."""
        return dict(cls.SDK_MODULES)

    @classmethod
    def sdk_missing(cls, config: dict) -> list[str]:
        """The pip distributions this configuration needs but cannot import."""
        import importlib.util

        missing = []
        for module, dist in cls.sdk_modules(config).items():
            try:
                found = importlib.util.find_spec(module) is not None
            except ImportError, ValueError:
                found = False
            if not found:
                missing.append(dist)
        return missing

    @abstractmethod
    async def fetch(self, path: str) -> str | dict:
        """The secret stored at ``path``: a mapping of keys to values, or
        one string. Raises ``SecretsProviderError``."""

    async def resolve(self, reference: Reference, *, use_cache: bool = True) -> str:
        """The value ``reference`` points at, from the cache when fresh."""
        cache_key = (self.provider_id, self.version, reference.path, reference.key)
        if use_cache:
            cached = VALUE_CACHE.get(cache_key)
            if cached is not None:
                return cached
        value = select_key(await self.fetch(reference.path), reference.key, reference.path)
        VALUE_CACHE.set(cache_key, value, self.cache_ttl)
        return value

    def token_cache_key(self) -> tuple:
        return (self.provider_id, self.version, "token")

    async def http(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        content: str | None = None,
    ) -> httpx.Response:
        """One request through the shared outbound sender (SSRF check, TLS
        choice, no redirects). Transport failures become ``unreachable``."""
        try:
            verify = tls_verify(bool(self.config.get("verify_tls", True)), str(self.config.get("ca_pem", "")))
        except Exception as exc:
            raise SecretsProviderError(INVALID_CONFIG, f"{self.name}: the CA bundle does not parse") from exc
        try:
            return await send_request(
                method,
                url,
                headers=headers,
                json=json_body,
                content=content,
                verify=verify,
                timeout_s=float(self.config.get("timeout", 10) or 10),
                transport=HTTP_TRANSPORT,
            )
        except OutboundRequestError as exc:
            raise SecretsProviderError(UNREACHABLE, f"{self.name}: the address is not allowed ({exc})") from exc
        except httpx.HTTPError as exc:
            raise SecretsProviderError(
                UNREACHABLE, f"{self.name}: could not reach {urlsplit(url).hostname} ({type(exc).__name__})"
            ) from exc

    def status_error(self, response: httpx.Response, path: str = "") -> SecretsProviderError:
        """The error for a refused HTTP answer (never echoes the body)."""
        status = response.status_code
        where = f" for '{path}'" if path else ""
        if status == 401:
            return SecretsProviderError(AUTH_FAILED, f"{self.name}: authentication failed (HTTP 401)")
        if status == 403:
            return SecretsProviderError(FORBIDDEN, f"{self.name}: permission denied{where} (HTTP 403)")
        if status == 404:
            return SecretsProviderError(NOT_FOUND, f"{self.name}: no secret{where} (HTTP 404)")
        return SecretsProviderError(PROVIDER_ERROR, f"{self.name}: request failed{where} (HTTP {status})")


def json_body(response: httpx.Response, name: str) -> dict:
    """The JSON object of ``response``, or ``provider_error``."""
    try:
        body = response.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        raise SecretsProviderError(PROVIDER_ERROR, f"{name}: the answer is not a JSON object")
    return body
