"""OpenID Connect relying party: the protocol, with no FastAPI in it.

Plexus signs a browser in through an OpenID Connect provider (Entra ID,
Okta, Keycloak, PingFederate, ADFS) with the authorization code flow, PKCE
(S256), ``state`` and ``nonce``. This module holds everything that talks to
the provider or checks what it returns, so it can be tested with a fake
``httpx`` transport and locally generated keys:

- discovery (``/.well-known/openid-configuration``) and the JWKS, both
  cached in memory for an hour; an unknown ``kid`` forces one JWKS refetch,
  at most once a minute;
- PKCE, ``state`` and ``nonce`` values and the authorization URL;
- the token exchange (``client_secret_basic``, ``client_secret_post`` or a
  public client);
- ID token validation (signature, algorithm allow-list, ``iss``, ``aud``,
  ``azp``, time claims with 60 s leeway, ``nonce``, ``sub``);
- userinfo, fetched only when a configured claim is missing, whose ``sub``
  must match the ID token's;
- claim reading: username, display name, groups and group overage.

Every failure raises :class:`OidcError` (a :class:`netcontrol.sso.SsoError`)
with a code from :data:`SSO_ERROR_CODES` and a short step description.
Neither ever holds a token, an authorization code, the client secret or the
PKCE verifier.

HTTP: ``httpx``, 10 s timeout, redirects not followed, TLS verified (with an
optional CA bundle for a private CA). The issuer and every endpoint from
discovery must be ``https``, except on a loopback host.

What does not depend on the protocol (URL and return-path rules, log-safe
text, username cleaning, the identity, the HTTP client) lives in
:mod:`netcontrol.sso` and is shared with SAML; it is re-exported here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote_plus, urlencode

import httpx
import jwt

from netcontrol.sso import (
    HTTP_TIMEOUT_SECONDS,
    MAX_RESPONSE_BYTES,
    SSO_ERROR_CODES,
    USERNAME_MAX_LENGTH,
    SsoError,
    SsoIdentity,
    clean_display_name,
    clean_username,
    group_values,
    is_allowed_url,
    log_safe,
    provider_request,
    safe_next,
)

__all__ = [
    "ALLOWED_ALGORITHMS",
    "CALLBACK_PATH",
    "CLIENT",
    "HTTP_TIMEOUT_SECONDS",
    "LOGIN_PATH",
    "MAX_RESPONSE_BYTES",
    "SSO_ERROR_CODES",
    "USERNAME_MAX_LENGTH",
    "OidcClient",
    "OidcError",
    "OidcIdentity",
    "ProviderMetadata",
    "is_allowed_url",
    "log_safe",
    "safe_next",
]

ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")
_EC_CURVES = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}

CACHE_TTL_SECONDS = 3600
JWKS_REFETCH_MIN_INTERVAL = 60
CLOCK_LEEWAY_SECONDS = 60

LOGIN_PATH = "/api/auth/oidc/login"
CALLBACK_PATH = "/api/auth/oidc/callback"
TOKEN_AUTH_METHODS = ("client_secret_basic", "client_secret_post")


class OidcError(SsoError):
    """An OpenID Connect sign-in step failed (see :class:`SsoError`)."""


# The identity is protocol-independent; the OIDC name stays for callers.
OidcIdentity = SsoIdentity


# ── Small pure helpers ───────────────────────────────────────────────────────


def new_state() -> str:
    return secrets.token_urlsafe(32)


def new_nonce() -> str:
    return secrets.token_urlsafe(32)


def new_code_verifier() -> str:
    """RFC 7636 verifier: 43 characters from the unreserved alphabet."""
    return secrets.token_urlsafe(32)


def code_challenge(verifier: str) -> str:
    """RFC 7636 S256 challenge: base64url(sha256(verifier)) without padding."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def scope_string(scopes: str) -> str:
    """The configured scopes, space separated, ``openid`` always first."""
    parts = [s for s in str(scopes or "").split() if s]
    rest = [s for s in dict.fromkeys(parts) if s != "openid"]
    return " ".join(["openid", *rest])


def derive_redirect_uri(configured: str, scheme: str, netloc: str) -> str:
    """The configured redirect URI, else ``<scheme>://<host>`` of the
    request plus the callback path."""
    if str(configured or "").strip():
        return str(configured).strip()
    return f"{scheme}://{netloc}{CALLBACK_PATH}"


def claim_groups(claims: dict, name: str) -> list[str]:
    """The groups claim as a list of strings (a single string becomes one
    group; anything else is ignored)."""
    if not name:
        return []
    return group_values(claims.get(name))


def groups_overage(claims: dict, name: str) -> bool:
    """True when the token says the groups did not fit in it (Entra ID
    ``_claim_names`` / ``hasgroups``)."""
    claim_names = claims.get("_claim_names")
    if isinstance(claim_names, dict) and (name in claim_names or "groups" in claim_names):
        return True
    return claims.get("hasgroups") in (True, "true", "True")


def read_username(claims: dict, name: str) -> str:
    """The username claim, trimmed. Raises ``claims`` when it is missing,
    empty, longer than 150 characters or holds a control character, and
    when it is the email while ``email_verified`` is false."""
    username = clean_username(claims.get(name), f"claim '{name}'", OidcError)
    if name == "email" and claims.get("email_verified") in (False, "false", "False"):
        raise OidcError("claims", "email is not verified at the provider")
    return username


# ── Data ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str = ""
    algorithms: tuple[str, ...] = ALLOWED_ALGORITHMS


@dataclass
class _JwksEntry:
    keys: list[dict]
    expires: float
    fetched: float


# ── Client ───────────────────────────────────────────────────────────────────


class OidcClient:
    """Talks to OpenID Connect providers and caches what they publish.

    ``transport`` replaces the network (tests pass ``httpx.MockTransport``);
    ``clock`` replaces ``time.monotonic`` for the cache timers.
    """

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._transport = transport
        self._clock = clock
        self._discovery: dict[tuple[str, str], tuple[float, ProviderMetadata]] = {}
        self._jwks: dict[tuple[str, str], _JwksEntry] = {}

    def clear_cache(self) -> None:
        self._discovery.clear()
        self._jwks.clear()

    # ── HTTP ──

    async def _send(
        self,
        what: str,
        code: str,
        ca_cert_file: str,
        method: str,
        url: str,
        *,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict:
        # Guarded and pinned on every request, not only discovery: the token,
        # JWKS and userinfo addresses come from the provider's own document.
        try:
            resp = await provider_request(
                method,
                url,
                ca_cert_file=ca_cert_file,
                transport=self._transport,
                error=OidcError,
                code=code,
                data=data,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            raise OidcError(code, f"{what} request failed ({type(exc).__name__})") from exc
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise OidcError(code, f"{what} response is too large")
        try:
            body = resp.json()
        except ValueError:
            body = None
        if resp.status_code != 200:
            detail = ""
            if isinstance(body, dict) and body.get("error"):
                detail = f": {log_safe(body.get('error'), 60)}"
                if body.get("error_description"):
                    detail += f" ({log_safe(body.get('error_description'))})"
            raise OidcError(code, f"{what} answered HTTP {resp.status_code}{detail}")
        if not isinstance(body, dict):
            raise OidcError(code, f"{what} did not return a JSON object")
        return body

    # ── Discovery and keys ──

    async def discover(self, issuer: str, ca_cert_file: str = "") -> ProviderMetadata:
        """The provider's metadata, from cache when fresh."""
        if not is_allowed_url(issuer):
            raise OidcError("provider", "the issuer must be an https URL")
        key = (issuer, ca_cert_file or "")
        now = self._clock()
        cached = self._discovery.get(key)
        if cached and cached[0] > now:
            return cached[1]
        url = issuer.rstrip("/") + "/.well-known/openid-configuration"
        doc = await self._send("discovery", "provider", ca_cert_file, "GET", url)
        if doc.get("issuer") != issuer:
            raise OidcError("provider", "discovery issuer does not match the configured issuer")
        endpoints = {}
        for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            value = doc.get(name)
            if not isinstance(value, str) or not is_allowed_url(value):
                raise OidcError("provider", f"discovery {name} is missing or not https")
            endpoints[name] = value
        userinfo = doc.get("userinfo_endpoint") or ""
        if userinfo and (not isinstance(userinfo, str) or not is_allowed_url(userinfo)):
            raise OidcError("provider", "discovery userinfo_endpoint is not https")
        algorithms: tuple[str, ...] = ALLOWED_ALGORITHMS
        advertised = doc.get("id_token_signing_alg_values_supported")
        if isinstance(advertised, list):
            algorithms = tuple(a for a in ALLOWED_ALGORITHMS if a in advertised)
            if not algorithms:
                raise OidcError("provider", "the provider signs ID tokens with no allowed algorithm")
        meta = ProviderMetadata(issuer=issuer, userinfo_endpoint=userinfo, algorithms=algorithms, **endpoints)
        self._discovery[key] = (now + CACHE_TTL_SECONDS, meta)
        return meta

    async def jwks(self, meta: ProviderMetadata, ca_cert_file: str = "", *, refresh: bool = False) -> list[dict]:
        """The signing keys. ``refresh`` refetches unless the last fetch was
        under a minute ago."""
        key = (meta.jwks_uri, ca_cert_file or "")
        now = self._clock()
        entry = self._jwks.get(key)
        if entry and entry.expires > now and not refresh:
            return entry.keys
        if entry and refresh and now - entry.fetched < JWKS_REFETCH_MIN_INTERVAL:
            return entry.keys
        doc = await self._send("JWKS", "provider", ca_cert_file, "GET", meta.jwks_uri)
        keys = doc.get("keys")
        if not isinstance(keys, list):
            raise OidcError("provider", "JWKS has no keys")
        usable = [k for k in keys if isinstance(k, dict) and k.get("kty") in ("RSA", "EC")]
        self._jwks[key] = _JwksEntry(keys=usable, expires=now + CACHE_TTL_SECONDS, fetched=now)
        return usable

    async def probe(self, issuer: str, ca_cert_file: str = "") -> tuple[ProviderMetadata, int]:
        """Fetch discovery and the JWKS fresh (the admin "Test connection"),
        refreshing the cache on the way. Returns the metadata and the number
        of usable signing keys."""
        self._discovery.pop((issuer, ca_cert_file or ""), None)
        meta = await self.discover(issuer, ca_cert_file)
        self._jwks.pop((meta.jwks_uri, ca_cert_file or ""), None)
        keys = await self.jwks(meta, ca_cert_file)
        return meta, len(keys)

    # ── Flow ──

    @staticmethod
    def authorization_url(
        meta: ProviderMetadata,
        *,
        client_id: str,
        redirect_uri: str,
        scopes: str,
        state: str,
        nonce: str,
        challenge: str,
    ) -> str:
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope_string(scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        sep = "&" if "?" in meta.authorization_endpoint else "?"
        return meta.authorization_endpoint + sep + urlencode(params)

    async def exchange_code(
        self,
        meta: ProviderMetadata,
        *,
        code: str,
        redirect_uri: str,
        client_id: str,
        client_secret: str,
        auth_method: str,
        code_verifier: str,
        ca_cert_file: str = "",
    ) -> dict:
        """Trade the authorization code for tokens. An empty secret means a
        public client (``client_id`` in the body, no authentication)."""
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        headers = {"Accept": "application/json"}
        if client_secret and auth_method != "client_secret_post":
            # RFC 6749 2.3.1: both parts form-encoded before base64.
            raw = f"{quote_plus(client_id)}:{quote_plus(client_secret)}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        else:
            form["client_id"] = client_id
            if client_secret:
                form["client_secret"] = client_secret
        tokens = await self._send(
            "token endpoint", "token", ca_cert_file, "POST", meta.token_endpoint, data=form, headers=headers
        )
        if not isinstance(tokens.get("id_token"), str) or not tokens["id_token"]:
            raise OidcError("token", "token response has no id_token")
        return tokens

    async def _signing_key(self, meta: ProviderMetadata, header: dict, ca_cert_file: str) -> Any:
        alg = header.get("alg")
        kid = header.get("kid")
        kty = "EC" if str(alg).startswith("ES") else "RSA"

        def pick(keys: list[dict]) -> dict | None:
            candidates = [
                k for k in keys if k.get("kty") == kty and k.get("use", "sig") == "sig" and k.get("alg", alg) == alg
            ]
            if kid is not None:
                matches = [k for k in candidates if k.get("kid") == kid]
                return matches[0] if len(matches) == 1 else None
            return candidates[0] if len(candidates) == 1 else None

        jwk = pick(await self.jwks(meta, ca_cert_file))
        if jwk is None:
            jwk = pick(await self.jwks(meta, ca_cert_file, refresh=True))
        if jwk is None:
            raise OidcError("token", "no matching signing key in the provider's JWKS")
        if kty == "EC" and jwk.get("crv") != _EC_CURVES.get(str(alg)):
            raise OidcError("token", "signing key curve does not match the algorithm")
        try:
            return jwt.PyJWK(jwk, algorithm=alg).key
        except (jwt.PyJWKError, jwt.InvalidKeyError, ValueError, TypeError) as exc:
            raise OidcError("token", "the provider's signing key could not be loaded") from exc

    async def validate_id_token(
        self,
        meta: ProviderMetadata,
        id_token: str,
        *,
        client_id: str,
        nonce: str,
        ca_cert_file: str = "",
    ) -> dict:
        """The ID token's claims once every check has passed."""
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.InvalidTokenError as exc:
            raise OidcError("token", "ID token is malformed") from exc
        alg = header.get("alg")
        if alg not in meta.algorithms:
            raise OidcError("token", f"ID token algorithm {log_safe(alg, 20)} is not allowed")
        key = await self._signing_key(meta, header, ca_cert_file)
        try:
            claims = jwt.decode(
                id_token,
                key,
                algorithms=[alg],
                audience=client_id,
                issuer=meta.issuer,
                leeway=CLOCK_LEEWAY_SECONDS,
                options={"require": ["iss", "aud", "exp", "iat", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise OidcError("token", "ID token has expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise OidcError("token", "ID token audience does not include the client id") from exc
        except jwt.InvalidIssuerError as exc:
            raise OidcError("token", "ID token issuer does not match") from exc
        except jwt.InvalidTokenError as exc:
            raise OidcError("token", f"ID token is invalid ({type(exc).__name__})") from exc
        azp = claims.get("azp")
        if azp is not None and azp != client_id:
            raise OidcError("token", "ID token azp is not the client id")
        token_nonce = claims.get("nonce")
        if not isinstance(token_nonce, str) or not hmac.compare_digest(token_nonce.encode(), nonce.encode()):
            raise OidcError("token", "ID token nonce does not match")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise OidcError("token", "ID token has no subject")
        return claims

    async def userinfo(self, meta: ProviderMetadata, access_token: str, ca_cert_file: str = "") -> dict:
        if not meta.userinfo_endpoint:
            return {}
        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
        return await self._send("userinfo", "claims", ca_cert_file, "GET", meta.userinfo_endpoint, headers=headers)

    async def complete_login(
        self,
        cfg: dict,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str,
        nonce: str,
        client_secret: str,
    ) -> OidcIdentity:
        """Everything after the provider redirected back with a code:
        exchange, validate, read claims (with userinfo when needed)."""
        ca = str(cfg.get("ca_cert_file") or "")
        client_id = str(cfg.get("client_id") or "")
        meta = await self.discover(str(cfg.get("issuer") or ""), ca)
        tokens = await self.exchange_code(
            meta,
            code=code,
            redirect_uri=redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            auth_method=str(cfg.get("token_auth_method") or "client_secret_basic"),
            code_verifier=code_verifier,
            ca_cert_file=ca,
        )
        claims = await self.validate_id_token(
            meta, tokens["id_token"], client_id=client_id, nonce=nonce, ca_cert_file=ca
        )

        username_claim = str(cfg.get("username_claim") or "preferred_username")
        display_claim = str(cfg.get("display_name_claim") or "")
        groups_claim = str(cfg.get("groups_claim") or "")
        wanted = [c for c in (username_claim, display_claim, groups_claim) if c]
        missing = [c for c in wanted if c not in claims]
        access_token = tokens.get("access_token")
        if missing and meta.userinfo_endpoint and isinstance(access_token, str) and access_token:
            info = await self.userinfo(meta, access_token, ca)
            if info.get("sub") != claims["sub"]:
                raise OidcError("claims", "userinfo subject does not match the ID token")
            merged = dict(claims)
            for name, value in info.items():
                merged.setdefault(name, value)
            claims = merged

        username = read_username(claims, username_claim)
        display = claims.get(display_claim) if display_claim else None
        display_name = clean_display_name(display)
        groups = claim_groups(claims, groups_claim)
        overage = not groups and groups_overage(claims, groups_claim)
        return OidcIdentity(
            sub=claims["sub"], username=username, display_name=display_name, groups=groups, overage=overage
        )


# The process-wide client; tests swap it for one with a fake transport.
CLIENT = OidcClient()
