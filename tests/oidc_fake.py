"""A fake OpenID Connect provider for the OIDC tests.

It answers discovery, JWKS, token and userinfo requests through an
``httpx.MockTransport``, signs ID tokens with keys generated here, and
checks the PKCE verifier against the challenge of the authorization request
it was shown. Every name, host and value is invented.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

ISSUER = "https://idp.example.com/tenant-a"
CLIENT_ID = "plexus-client"
CLIENT_SECRET = "s3cret-value"

_KEYS: dict[str, object] = {}


def rsa_key(name: str = "rsa-1"):
    """Cached RSA keys (generation is the slow part of these tests)."""
    if name not in _KEYS:
        _KEYS[name] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _KEYS[name]


def ec_key(name: str = "ec-1", curve: ec.EllipticCurve | None = None):
    if name not in _KEYS:
        _KEYS[name] = ec.generate_private_key(curve or ec.SECP256R1())
    return _KEYS[name]


def public_jwk(key, kid: str, alg: str | None = None) -> dict:
    if isinstance(key, rsa.RSAPrivateKey):
        jwk = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    else:
        jwk = ECAlgorithm.to_jwk(key.public_key(), as_dict=True)
    jwk["kid"] = kid
    jwk["use"] = "sig"
    if alg:
        jwk["alg"] = alg
    return jwk


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


class FakeIdP:
    def __init__(self, issuer: str = ISSUER):
        self.issuer = issuer
        self.discovery = {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/keys",
            "userinfo_endpoint": f"{issuer}/userinfo",
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "PS256"],
        }
        self.jwks = {"keys": [public_jwk(rsa_key(), "rsa-1", "RS256"), public_jwk(ec_key(), "ec-1")]}
        # After the first JWKS fetch the provider publishes this one instead
        # (key rotation), when set.
        self.rotated_jwks: dict | None = None
        self.calls: dict[str, int] = {"discovery": 0, "jwks": 0, "token": 0, "userinfo": 0}
        self.token_requests: list[httpx.Request] = []
        self.userinfo_requests: list[httpx.Request] = []
        self.userinfo: dict = {}
        self.token_status = 200
        self.token_body: dict | None = None
        # code -> what the authorization request carried
        self.codes: dict[str, dict] = {}
        # Claims for the next ID token, merged over the defaults.
        self.claims: dict = {}
        self.sign_kid = "rsa-1"
        self.sign_alg = "RS256"
        self.sign_key = None

    # ── tokens ──

    def default_claims(self, nonce: str) -> dict:
        now = int(time.time())
        return {
            "iss": self.issuer,
            "aud": CLIENT_ID,
            "sub": "subject-0001",
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
            "preferred_username": "alice",
            "name": "Alice Example",
            "groups": ["netops"],
        }

    def id_token(self, nonce: str = "n-1", *, drop: tuple[str, ...] = (), **overrides) -> str:
        claims = {**self.default_claims(nonce), **self.claims, **overrides}
        for name in drop:
            claims.pop(name, None)
        key = self.sign_key or (ec_key() if self.sign_alg.startswith("ES") else rsa_key())
        return jwt.encode(claims, key, algorithm=self.sign_alg, headers={"kid": self.sign_kid})

    def authorize(self, location: str, code: str = "code-1") -> dict:
        """Accept the authorization request Plexus redirected to; remember
        nonce and challenge for ``code``. Returns the request's parameters."""
        params = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
        self.codes[code] = params
        return params

    # ── transport ──

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == f"{self.issuer}/.well-known/openid-configuration":
            self.calls["discovery"] += 1
            return httpx.Response(200, json=self.discovery)
        if url == self.discovery["jwks_uri"]:
            self.calls["jwks"] += 1
            if self.rotated_jwks is not None and self.calls["jwks"] > 1:
                return httpx.Response(200, json=self.rotated_jwks)
            return httpx.Response(200, json=self.jwks)
        if url == self.discovery["token_endpoint"]:
            self.calls["token"] += 1
            self.token_requests.append(request)
            return self._token(request)
        if url == self.discovery["userinfo_endpoint"]:
            self.calls["userinfo"] += 1
            self.userinfo_requests.append(request)
            return httpx.Response(200, json=self.userinfo)
        return httpx.Response(404, json={"error": "not_found"})

    def _token(self, request: httpx.Request) -> httpx.Response:
        if self.token_body is not None or self.token_status != 200:
            return httpx.Response(self.token_status, json=self.token_body or {})
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        auth = self.codes.get(form.get("code", ""))
        if auth is None:
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": "unknown code"})
        if s256(form.get("code_verifier", "")) != auth.get("code_challenge"):
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": "PKCE check failed"})
        if form.get("redirect_uri") != auth.get("redirect_uri"):
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
        return httpx.Response(
            200,
            content=json.dumps(
                {"id_token": self.id_token(auth.get("nonce", "")), "access_token": "access-abc", "token_type": "Bearer"}
            ),
            headers={"Content-Type": "application/json"},
        )
