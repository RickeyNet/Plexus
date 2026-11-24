"""netcontrol/oidc.py: the OpenID Connect protocol without FastAPI.

A fake provider (tests/oidc_fake.py) answers through ``httpx.MockTransport``
and signs with keys generated in the test. Every value is invented.
"""

from __future__ import annotations

import base64
import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from netcontrol import oidc

from oidc_fake import CLIENT_ID, CLIENT_SECRET, ISSUER, FakeIdP, ec_key, public_jwk, rsa_key


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _client(idp: FakeIdP, clock: Clock | None = None) -> oidc.OidcClient:
    return oidc.OidcClient(transport=idp.transport(), clock=clock or Clock())


def _cfg(**over) -> dict:
    cfg = {
        "enabled": True,
        "issuer": ISSUER,
        "client_id": CLIENT_ID,
        "token_auth_method": "client_secret_basic",
        "scopes": "openid profile email",
        "username_claim": "preferred_username",
        "display_name_claim": "name",
        "groups_claim": "groups",
        "ca_cert_file": "",
    }
    cfg.update(over)
    return cfg


async def _validate(idp: FakeIdP, token: str, *, nonce: str = "n-1", client: oidc.OidcClient | None = None) -> dict:
    client = client or _client(idp)
    meta = await client.discover(ISSUER)
    return await client.validate_id_token(meta, token, client_id=CLIENT_ID, nonce=nonce)


async def _expect(code: str, coro) -> oidc.OidcError:
    with pytest.raises(oidc.OidcError) as info:
        await coro
    assert info.value.code == code
    return info.value


# ── pure helpers ─────────────────────────────────────────────────────────────


def test_pkce_challenge_is_unpadded_base64url_sha256():
    # SHA-256("abc") is the FIPS 180-2 test vector ba7816bf...f20015ad.
    assert oidc.code_challenge("abc") == "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
    verifier = oidc.new_code_verifier()
    assert 43 <= len(verifier) <= 128
    assert oidc.new_state() != oidc.new_state()
    assert oidc.new_nonce() != oidc.new_nonce()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/devices/7?tab=config", "/devices/7?tab=config"),
        ("/", "/"),
        (None, "/"),
        ("", "/"),
        ("devices", "/"),
        ("//evil.example.com/x", "/"),
        ("/a//b", "/"),
        ("/\\evil.example.com", "/"),
        ("/ok\r\nSet-Cookie: x", "/"),
        ("/tab\x00", "/"),
        ("https://evil.example.com/", "/"),
        ("/" + "a" * 3000, "/"),
    ],
)
def test_safe_next(value, expected):
    assert oidc.safe_next(value) == expected


def test_allowed_urls():
    assert oidc.is_allowed_url("https://idp.example.com")
    assert oidc.is_allowed_url("http://localhost:8080/realms/lab")
    assert oidc.is_allowed_url("http://127.0.0.1:9000")
    assert oidc.is_allowed_url("http://[::1]:9000")
    assert not oidc.is_allowed_url("http://idp.example.com")
    assert not oidc.is_allowed_url("ftp://idp.example.com")
    assert not oidc.is_allowed_url("")
    assert not oidc.is_allowed_url("https://")
    assert not oidc.is_allowed_url("http://[bad")


def test_scope_string_always_has_openid_first():
    assert oidc.scope_string("profile email") == "openid profile email"
    assert oidc.scope_string("email openid email") == "openid email"
    assert oidc.scope_string("") == "openid"


def test_group_claim_as_string_or_list():
    assert oidc.claim_groups({"groups": "netops"}, "groups") == ["netops"]
    assert oidc.claim_groups({"groups": ["a", "", 5, None, {"x": 1}]}, "groups") == ["a", "5"]
    assert oidc.claim_groups({"groups": 7}, "groups") == []
    assert oidc.claim_groups({"groups": ["a"]}, "") == []
    assert oidc.claim_groups({"groups": ""}, "groups") == []


def test_group_overage_signal():
    assert oidc.groups_overage({"_claim_names": {"groups": "src1"}}, "groups")
    assert oidc.groups_overage({"_claim_names": {"roles": "src1"}}, "roles")
    assert oidc.groups_overage({"hasgroups": True}, "groups")
    assert not oidc.groups_overage({"_claim_names": {"other": "src1"}}, "groups")
    assert not oidc.groups_overage({"groups": ["a"]}, "groups")


def test_read_username_rules():
    assert oidc.read_username({"preferred_username": "  alice  "}, "preferred_username") == "alice"
    for bad in ({}, {"u": ""}, {"u": "   "}, {"u": "a" * 151}, {"u": "al\nice"}, {"u": 5}):
        with pytest.raises(oidc.OidcError) as info:
            oidc.read_username(bad, "u")
        assert info.value.code == "claims"
    assert oidc.read_username({"email": "alice@example.com", "email_verified": True}, "email")
    assert oidc.read_username({"email": "alice@example.com", "email_verified": "true"}, "email")
    with pytest.raises(oidc.OidcError):
        oidc.read_username({"email": "alice@example.com", "email_verified": False}, "email")


def test_email_as_username_needs_a_verified_address():
    unmarked = {"email": "alice@example.com"}
    with pytest.raises(oidc.OidcError) as info:
        oidc.read_username(unmarked, "email")
    assert info.value.code == "claims" and "email_verified" in info.value.step
    # The setting is for providers that never send the claim...
    assert oidc.read_username(unmarked, "email", allow_unverified_email=True) == "alice@example.com"
    # ...never for an address the provider says is unverified.
    with pytest.raises(oidc.OidcError):
        oidc.read_username({**unmarked, "email_verified": False}, "email", allow_unverified_email=True)
    # Other claims are not email addresses to verify.
    assert oidc.read_username({"upn": "alice@example.com"}, "upn") == "alice@example.com"


def test_log_safe_redacts_and_truncates():
    text = oidc.log_safe("bad code eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl\r\nnext" + "x" * 500)
    assert "eyJ" not in text and "\n" not in text and len(text) <= 200
    assert "[redacted]" in text


def test_error_code_outside_list_becomes_provider():
    assert oidc.OidcError("bogus", "x").code == "provider"


# ── discovery and JWKS ───────────────────────────────────────────────────────


async def test_discovery_parses_and_caches():
    idp = FakeIdP()
    clock = Clock()
    client = _client(idp, clock)
    meta = await client.discover(ISSUER)
    assert meta.token_endpoint == f"{ISSUER}/token"
    assert meta.algorithms == ("RS256", "PS256", "ES256")
    await client.discover(ISSUER)
    assert idp.calls["discovery"] == 1
    clock.now += oidc.CACHE_TTL_SECONDS + 1
    await client.discover(ISSUER)
    assert idp.calls["discovery"] == 2
    client.clear_cache()
    await client.discover(ISSUER)
    assert idp.calls["discovery"] == 3


async def test_discovery_issuer_mismatch_is_refused():
    idp = FakeIdP()
    idp.discovery["issuer"] = "https://other.example.com"
    err = await _expect("provider", _client(idp).discover(ISSUER))
    assert "issuer" in err.step


async def test_http_issuer_is_refused():
    idp = FakeIdP("http://idp.example.com")
    await _expect("provider", _client(idp).discover("http://idp.example.com"))
    assert idp.calls["discovery"] == 0


async def test_loopback_http_issuer_is_allowed():
    idp = FakeIdP("http://localhost:8080/realms/lab")
    meta = await _client(idp).discover("http://localhost:8080/realms/lab")
    assert meta.issuer == "http://localhost:8080/realms/lab"


async def test_outbound_guard_refuses_a_link_local_issuer():
    # The cloud instance-metadata address: refused before any request.
    idp = FakeIdP("https://169.254.169.254")
    err = await _expect("provider", _client(idp).discover("https://169.254.169.254"))
    assert "not allowed" in err.step and idp.calls["discovery"] == 0


async def test_outbound_guard_covers_endpoints_named_by_discovery():
    # The discovery document is the provider's: an endpoint it names goes
    # through the guard like the issuer the admin typed.
    idp = FakeIdP()
    idp.discovery["jwks_uri"] = "https://169.254.169.254/keys"
    client = _client(idp)
    meta = await client.discover(ISSUER)
    err = await _expect("provider", client.jwks(meta))
    assert "not allowed" in err.step and idp.calls["jwks"] == 0


async def test_discovery_endpoint_must_be_https():
    idp = FakeIdP()
    idp.discovery["token_endpoint"] = "http://idp.example.com/token"
    await _expect("provider", _client(idp).discover(ISSUER))
    idp = FakeIdP()
    idp.discovery["userinfo_endpoint"] = "http://idp.example.com/userinfo"
    await _expect("provider", _client(idp).discover(ISSUER))
    idp = FakeIdP()
    del idp.discovery["jwks_uri"]
    await _expect("provider", _client(idp).discover(ISSUER))


async def test_discovery_without_an_allowed_algorithm_is_refused():
    idp = FakeIdP()
    idp.discovery["id_token_signing_alg_values_supported"] = ["HS256", "none"]
    await _expect("provider", _client(idp).discover(ISSUER))


async def test_discovery_http_errors():
    def handler(request):
        if request.url.path.endswith("/openid-configuration"):
            return httpx.Response(500, text="oops")
        return httpx.Response(404)

    client = oidc.OidcClient(transport=httpx.MockTransport(handler))
    err = await _expect("provider", client.discover(ISSUER))
    assert "HTTP 500" in err.step

    client = oidc.OidcClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="[1, 2]")))
    await _expect("provider", client.discover(ISSUER))

    big = httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * (oidc.MAX_RESPONSE_BYTES + 1)))
    await _expect("provider", oidc.OidcClient(transport=big).discover(ISSUER))

    def boom(request):
        raise httpx.ConnectError("refused")

    err = await _expect("provider", oidc.OidcClient(transport=httpx.MockTransport(boom)).discover(ISSUER))
    assert "ConnectError" in err.step


async def test_redirects_are_not_followed():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://elsewhere.example.com/"})

    await _expect("provider", oidc.OidcClient(transport=httpx.MockTransport(handler)).discover(ISSUER))
    assert len(calls) == 1


async def test_missing_ca_file_is_a_provider_error():
    client = oidc.OidcClient()
    await _expect("provider", client.discover(ISSUER, "Z:/no/such/ca-bundle.pem"))


async def test_jwks_must_hold_keys():
    idp = FakeIdP()
    idp.jwks = {"nope": []}
    client = _client(idp)
    meta = await client.discover(ISSUER)
    await _expect("provider", client.jwks(meta))


async def test_probe_fetches_fresh():
    idp = FakeIdP()
    client = _client(idp)
    meta, count = await client.probe(ISSUER)
    assert count == 2 and meta.jwks_uri.endswith("/keys")
    await client.probe(ISSUER)
    assert idp.calls == {"discovery": 2, "jwks": 2, "token": 0, "userinfo": 0}


# ── ID token validation ──────────────────────────────────────────────────────


async def test_valid_rs256_token():
    idp = FakeIdP()
    claims = await _validate(idp, idp.id_token())
    assert claims["sub"] == "subject-0001"


async def test_valid_es256_and_ps256_tokens():
    idp = FakeIdP()
    idp.sign_alg, idp.sign_kid = "ES256", "ec-1"
    assert (await _validate(idp, idp.id_token()))["sub"] == "subject-0001"
    idp = FakeIdP()
    idp.jwks = {"keys": [public_jwk(rsa_key(), "rsa-1")]}  # no "alg" on the key
    idp.sign_alg = "PS256"
    assert (await _validate(idp, idp.id_token()))["sub"] == "subject-0001"


async def test_alg_none_is_refused():
    idp = FakeIdP()
    claims = idp.default_claims("n-1")
    token = jwt.encode(claims, None, algorithm="none", headers={"kid": "rsa-1"})
    await _expect("token", _validate(idp, token))


async def test_hs256_is_refused_even_with_the_public_key_as_secret():
    idp = FakeIdP()
    token = jwt.encode(idp.default_claims("n-1"), "a-shared-secret-of-sufficient-length!!", algorithm="HS256")
    err = await _expect("token", _validate(idp, token))
    assert "not allowed" in err.step


async def test_algorithm_outside_discovery_list_is_refused():
    idp = FakeIdP()
    idp.discovery["id_token_signing_alg_values_supported"] = ["RS256"]
    idp.sign_alg, idp.sign_kid = "ES256", "ec-1"
    await _expect("token", _validate(idp, idp.id_token()))


async def test_key_alg_must_match_header():
    idp = FakeIdP()
    idp.sign_alg = "PS256"  # the rsa-1 key says RS256
    await _expect("token", _validate(idp, idp.id_token()))


async def test_ec_curve_must_match_algorithm():
    idp = FakeIdP()
    p384 = ec_key("ec-384", ec.SECP384R1())
    idp.jwks = {"keys": [public_jwk(p384, "ec-384")]}
    idp.sign_alg, idp.sign_kid, idp.sign_key = "ES256", "ec-384", p384
    # ES256 header over a P-384 key.
    token = jwt.encode(idp.default_claims("n-1"), p384, algorithm="ES384", headers={"kid": "ec-384"})
    header, payload, sig = token.split(".")
    forged = base64.urlsafe_b64encode(json.dumps({"alg": "ES256", "kid": "ec-384", "typ": "JWT"}).encode())
    forged_token = forged.rstrip(b"=").decode() + "." + payload + "." + sig
    err = await _expect("token", _validate(idp, forged_token))
    assert "curve" in err.step


async def test_malformed_token():
    await _expect("token", _validate(FakeIdP(), "not-a-jwt"))


async def test_wrong_audience():
    idp = FakeIdP()
    await _expect("token", _validate(idp, idp.id_token(aud="someone-else")))
    # A list holding only the client id is fine.
    assert await _validate(idp, idp.id_token(aud=[CLIENT_ID]))
    # Several audiences: azp must say the token was issued to this client.
    several = ["someone-else", CLIENT_ID]
    err = await _expect("token", _validate(idp, idp.id_token(aud=several)))
    assert "azp" in err.step
    assert await _validate(idp, idp.id_token(aud=several, azp=CLIENT_ID))
    await _expect("token", _validate(idp, idp.id_token(aud=several, azp="someone-else")))


async def test_wrong_azp():
    idp = FakeIdP()
    err = await _expect("token", _validate(idp, idp.id_token(azp="someone-else")))
    assert "azp" in err.step
    assert await _validate(idp, idp.id_token(azp=CLIENT_ID))


async def test_wrong_issuer():
    idp = FakeIdP()
    await _expect("token", _validate(idp, idp.id_token(iss="https://other.example.com")))


async def test_expired_and_leeway():
    idp = FakeIdP()
    now = int(time.time())
    err = await _expect("token", _validate(idp, idp.id_token(exp=now - 120, iat=now - 600)))
    assert "expired" in err.step
    # 30 s past exp is inside the 60 s leeway.
    assert await _validate(idp, idp.id_token(exp=now - 30, iat=now - 600))
    await _expect("token", _validate(idp, idp.id_token(nbf=now + 600)))
    await _expect("token", _validate(idp, idp.id_token(iat=now + 600)))


async def test_required_claims():
    idp = FakeIdP()
    await _expect("token", _validate(idp, idp.id_token(drop=("exp",))))
    await _expect("token", _validate(idp, idp.id_token(drop=("iat",))))
    await _expect("token", _validate(idp, idp.id_token(drop=("sub",))))
    await _expect("token", _validate(idp, idp.id_token(sub="")))


async def test_bad_nonce():
    idp = FakeIdP()
    await _expect("token", _validate(idp, idp.id_token("n-other"), nonce="n-1"))
    await _expect("token", _validate(idp, idp.id_token(drop=("nonce",))))


async def test_bad_signature():
    idp = FakeIdP()
    head, body, _ = idp.id_token().split(".")
    other = jwt.encode({"x": 1}, rsa_key("rsa-other"), algorithm="RS256").split(".")[2]
    await _expect("token", _validate(idp, f"{head}.{body}.{other}"))


async def test_unknown_kid_triggers_one_refetch():
    idp = FakeIdP()
    clock = Clock()
    client = _client(idp, clock)
    # Warm the cache with the old key set.
    assert await _validate(idp, idp.id_token(), client=client)
    assert idp.calls["jwks"] == 1
    # The provider rotates to a new key; a token signed with it arrives.
    new_key = rsa_key("rsa-2")
    idp.rotated_jwks = {"keys": [public_jwk(new_key, "rsa-2", "RS256")]}
    idp.sign_kid, idp.sign_key = "rsa-2", new_key
    # Right after a fetch the refetch is held back (at most once a minute).
    await _expect("token", _validate(idp, idp.id_token(), client=client))
    assert idp.calls["jwks"] == 1
    clock.now += oidc.JWKS_REFETCH_MIN_INTERVAL + 1
    assert await _validate(idp, idp.id_token(), client=client)
    assert idp.calls["jwks"] == 2
    # Another unknown kid within a minute does not refetch again.
    idp.sign_kid = "rsa-3"
    await _expect("token", _validate(idp, idp.id_token(), client=client))
    assert idp.calls["jwks"] == 2
    clock.now += oidc.JWKS_REFETCH_MIN_INTERVAL + 1
    await _expect("token", _validate(idp, idp.id_token(), client=client))
    assert idp.calls["jwks"] == 3


async def test_token_without_kid_uses_the_single_matching_key():
    idp = FakeIdP()
    token = jwt.encode(idp.default_claims("n-1"), rsa_key(), algorithm="RS256")
    assert await _validate(idp, token)
    idp.jwks = {"keys": [public_jwk(rsa_key(), "rsa-1", "RS256"), public_jwk(rsa_key("rsa-2"), "rsa-2", "RS256")]}
    await _expect("token", _validate(idp, token))


async def test_unloadable_key_is_a_token_error():
    idp = FakeIdP()
    idp.jwks = {"keys": [{"kty": "RSA", "kid": "rsa-1", "n": "!!", "e": "AQAB"}]}
    await _expect("token", _validate(idp, idp.id_token()))


# ── token exchange and the whole callback ────────────────────────────────────


async def _exchange(idp: FakeIdP, *, method: str, secret: str) -> httpx.Request:
    client = _client(idp)
    meta = await client.discover(ISSUER)
    idp.codes["code-1"] = {
        "nonce": "n-1",
        "code_challenge": oidc.code_challenge("v" * 43),
        "redirect_uri": "https://plexus.example.com/cb",
    }
    tokens = await client.exchange_code(
        meta,
        code="code-1",
        redirect_uri="https://plexus.example.com/cb",
        client_id=CLIENT_ID,
        client_secret=secret,
        auth_method=method,
        code_verifier="v" * 43,
    )
    assert tokens["access_token"] == "access-abc"
    return idp.token_requests[-1]


async def test_token_exchange_client_secret_basic():
    request = await _exchange(FakeIdP(), method="client_secret_basic", secret=CLIENT_SECRET)
    expected = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    assert request.headers["Authorization"] == f"Basic {expected}"
    body = request.content.decode()
    assert "client_secret" not in body and "grant_type=authorization_code" in body


async def test_token_exchange_client_secret_post_and_public():
    body = (await _exchange(FakeIdP(), method="client_secret_post", secret=CLIENT_SECRET)).content.decode()
    assert f"client_id={CLIENT_ID}" in body and f"client_secret={CLIENT_SECRET}" in body
    request = await _exchange(FakeIdP(), method="client_secret_basic", secret="")
    assert "Authorization" not in request.headers
    assert f"client_id={CLIENT_ID}" in request.content.decode()
    assert "client_secret" not in request.content.decode()


async def test_token_endpoint_error_is_logged_safely():
    idp = FakeIdP()
    idp.token_status = 400
    idp.token_body = {
        "error": "invalid_grant",
        "error_description": "code eyJhbGciOiJSUzI1NiJ9xxxxxxxxxxxxxxxxxxxx used",
    }
    client = _client(idp)
    meta = await client.discover(ISSUER)
    err = await _expect(
        "token",
        client.exchange_code(
            meta,
            code="c",
            redirect_uri="https://x.example.com/cb",
            client_id=CLIENT_ID,
            client_secret="",
            auth_method="client_secret_basic",
            code_verifier="v" * 43,
        ),
    )
    assert "invalid_grant" in err.step and "eyJ" not in err.step


async def test_token_response_without_id_token():
    idp = FakeIdP()
    idp.token_body = {"access_token": "a"}
    client = _client(idp)
    meta = await client.discover(ISSUER)
    await _expect(
        "token",
        client.exchange_code(
            meta,
            code="c",
            redirect_uri="https://x.example.com/cb",
            client_id=CLIENT_ID,
            client_secret="",
            auth_method="client_secret_post",
            code_verifier="v" * 43,
        ),
    )


async def _complete(idp: FakeIdP, nonce: str = "n-1", **cfg_over) -> oidc.OidcIdentity:
    verifier = "w" * 43
    idp.codes["code-9"] = {
        "nonce": nonce,
        "code_challenge": oidc.code_challenge(verifier),
        "redirect_uri": "https://plexus.example.com/cb",
    }
    return await _client(idp).complete_login(
        _cfg(**cfg_over),
        code="code-9",
        redirect_uri="https://plexus.example.com/cb",
        code_verifier=verifier,
        nonce=nonce,
        client_secret=CLIENT_SECRET,
    )


async def test_complete_login_reads_claims_from_the_id_token():
    idp = FakeIdP()
    ident = await _complete(idp)
    assert ident == oidc.OidcIdentity(
        sub="subject-0001", username="alice", display_name="Alice Example", groups=["netops"]
    )
    assert idp.calls["userinfo"] == 0


async def test_userinfo_fills_missing_claims():
    idp = FakeIdP()
    idp.claims = {"groups": None}
    idp.userinfo = {"sub": "subject-0001", "groups": "netops-admins", "name": "Ignored Name"}

    def no_groups(nonce, **kw):
        return FakeIdP.id_token(idp, nonce, drop=("groups",), **kw)

    idp.id_token = no_groups  # type: ignore[method-assign]
    ident = await _complete(idp)
    assert ident.groups == ["netops-admins"]
    assert ident.display_name == "Alice Example"  # the ID token wins
    assert idp.userinfo_requests[0].headers["Authorization"] == "Bearer access-abc"


async def test_userinfo_sub_mismatch_fails():
    idp = FakeIdP()
    idp.userinfo = {"sub": "subject-9999", "preferred_username": "mallory"}
    idp.id_token = lambda nonce, **kw: FakeIdP.id_token(idp, nonce, drop=("preferred_username",))  # type: ignore[method-assign]
    err = await _expect("claims", _complete(idp))
    assert "subject" in err.step


async def test_missing_username_without_userinfo_endpoint():
    idp = FakeIdP()
    del idp.discovery["userinfo_endpoint"]
    idp.id_token = lambda nonce, **kw: FakeIdP.id_token(idp, nonce, drop=("preferred_username",))  # type: ignore[method-assign]
    await _expect("claims", _complete(idp))


async def test_overage_is_reported_when_no_groups_arrive():
    idp = FakeIdP()
    del idp.discovery["userinfo_endpoint"]
    idp.id_token = lambda nonce, **kw: FakeIdP.id_token(  # type: ignore[method-assign]
        idp, nonce, drop=("groups",), _claim_names={"groups": "src1"}, _claim_sources={"src1": {"endpoint": "x"}}
    )
    ident = await _complete(idp)
    assert ident.overage is True and ident.groups == []


async def test_email_username_with_unverified_email_fails():
    idp = FakeIdP()
    idp.claims = {"email": "alice@example.com", "email_verified": False}
    await _expect("claims", _complete(idp, username_claim="email"))
    idp.claims = {"email": "alice@example.com", "email_verified": True}
    assert (await _complete(idp, username_claim="email")).username == "alice@example.com"
    # A provider that never sends email_verified needs the setting.
    idp.claims = {"email": "alice@example.com"}
    await _expect("claims", _complete(idp, username_claim="email"))
    allowed = await _complete(idp, username_claim="email", allow_unverified_email=True)
    assert allowed.username == "alice@example.com"


def test_authorization_url_carries_pkce_state_nonce():
    meta = oidc.ProviderMetadata(
        issuer=ISSUER,
        authorization_endpoint=f"{ISSUER}/authorize?tenant=a",
        token_endpoint=f"{ISSUER}/token",
        jwks_uri=f"{ISSUER}/keys",
    )
    url = oidc.OidcClient.authorization_url(
        meta,
        client_id=CLIENT_ID,
        redirect_uri="https://plexus.example.com/cb",
        scopes="profile",
        state="st",
        nonce="nn",
        challenge="ch",
    )
    assert url.startswith(f"{ISSUER}/authorize?tenant=a&")
    for part in (
        "response_type=code",
        "state=st",
        "nonce=nn",
        "code_challenge=ch",
        "code_challenge_method=S256",
        "scope=openid+profile",
    ):
        assert part in url
