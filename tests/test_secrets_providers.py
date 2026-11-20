"""External secrets providers: the key selection and TTL cache, each
provider against stand-ins (``httpx.MockTransport`` for Vault and Azure Key
Vault, a fake ``boto3`` module for AWS Secrets Manager; no SDK or network is
needed), failure handling, resolution through the credential and secret
variable choke points, and an API that never returns a value.

Every secret below is invented test data.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import types

import httpx
import pytest
import routes.database as db
import routes.secret_resolver as secret_resolver
from netcontrol.routes import outbound_http, state
from netcontrol.secrets_providers import base, service
from netcontrol.secrets_providers.aws import AwsSecretsManagerProvider
from netcontrol.secrets_providers.azure import AzureKeyVaultProvider, vault_scope
from netcontrol.secrets_providers.base import Reference, SecretsProviderError, TTLCache, select_key
from netcontrol.secrets_providers.vault import VaultProvider
from routes.crypto import decrypt, unavailable

from mcp_helpers import admin_client, user_client

API = "/api/secrets-providers"
VAULT_URL = "https://vault.example.com:8200"
FAKE_TOKEN = "test-vault-token-not-real"
FAKE_PASSWORD = "invented-device-password-1"
FAKE_ENABLE = "invented-enable-secret-2"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    """Fresh caches, no SSRF DNS lookups, no real network."""
    base.invalidate()
    service._FAILURES_AUDITED.clear()
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})

    async def no_guard(_url):
        return None

    monkeypatch.setattr(outbound_http, "guard_url", no_guard)
    monkeypatch.setattr(base, "HTTP_TRANSPORT", httpx.MockTransport(lambda r: httpx.Response(599)))
    yield
    base.invalidate()


class Recorder:
    """A MockTransport handler answering by (method, path)."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.routes.get((request.method, request.url.path))
        if answer is None:
            return httpx.Response(404, json={"errors": []})
        status, body = answer
        return httpx.Response(status, json=body)

    def count(self, path: str) -> int:
        return sum(1 for r in self.requests if r.url.path == path)


def _mock(monkeypatch, routes: dict) -> Recorder:
    recorder = Recorder(routes)
    monkeypatch.setattr(base, "HTTP_TRANSPORT", httpx.MockTransport(recorder))
    return recorder


def _vault(**config) -> VaultProvider:
    settings = {"url": VAULT_URL, **config}
    secrets = {"token": FAKE_TOKEN, "secret_id": "test-secret-id"}
    return VaultProvider(VaultProvider.validate(settings, secrets), secrets, provider_id=1, name="vault-test")


# ── Pure helpers ─────────────────────────────────────────────────────────────


def test_select_key_on_mappings_and_strings():
    assert select_key({"password": "a", "user": "b"}, "password", "p") == "a"
    assert select_key({"only": 5}, "", "p") == "5"
    assert select_key({"flag": True}, "flag", "p") == "true"
    assert select_key("plain-text", "", "p") == "plain-text"
    assert select_key('{"password": "x"}', "password", "p") == "x"
    with pytest.raises(SecretsProviderError) as several:
        select_key({"a": "1", "b": "2"}, "", "net/core")
    assert several.value.code == base.KEY_NOT_FOUND and "net/core" in str(several.value)
    with pytest.raises(SecretsProviderError, match="no key 'missing'"):
        select_key({"a": "1"}, "missing", "p")
    with pytest.raises(SecretsProviderError, match="not a JSON object"):
        select_key("plain-text", "password", "p")
    with pytest.raises(SecretsProviderError, match="not a single value"):
        select_key({"nested": {"x": 1}}, "nested", "p")


def test_errors_never_carry_values():
    with pytest.raises(SecretsProviderError) as err:
        select_key({"password": FAKE_PASSWORD, "other": "y"}, "missing", "p")
    assert FAKE_PASSWORD not in str(err.value)
    assert isinstance(err.value, RuntimeError)


def test_ttl_cache_expires_bounds_and_discards():
    now = [100.0]
    cache = TTLCache(max_entries=2, clock=lambda: now[0])
    cache.set("a", "1", 10)
    cache.set("zero", "x", 0)
    assert cache.get("a") == "1" and cache.get("zero") is None
    now[0] += 10
    assert cache.get("a") is None
    cache.set((1, "x"), "1", 60)
    cache.set((2, "y"), "2", 60)
    cache.set((3, "z"), "3", 60)
    assert cache.get((1, "x")) is None and len(cache) == 2
    cache.discard(lambda k: k[0] == 2)
    assert cache.get((2, "y")) is None and cache.get((3, "z")) == "3"
    cache.clear()
    assert len(cache) == 0


def test_reference_and_path_checks():
    assert base.check_reference(" net/core ", " password ") == Reference("net/core", "password")
    for bad in ("", "x" * 600, "bad\npath"):
        with pytest.raises(ValueError):
            base.check_reference(bad)
    assert base.url_path("network/core sw") == "network/core%20sw"
    for bad in ("../sys", "a/./b", "/"):
        with pytest.raises(SecretsProviderError) as err:
            base.url_path(bad)
        assert err.value.code == base.INVALID_REFERENCE


def test_settings_validation():
    with pytest.raises(ValueError, match="url is required"):
        VaultProvider.validate({}, {"token": "t"})
    with pytest.raises(ValueError, match="http"):
        VaultProvider.validate({"url": "ftp://vault.example.com"}, {"token": "t"})
    with pytest.raises(ValueError, match="needs a Vault token"):
        VaultProvider.validate({"url": VAULT_URL}, {})
    with pytest.raises(ValueError, match="role ID"):
        VaultProvider.validate({"url": VAULT_URL, "auth_method": "approle"}, {"secret_id": "s"})
    with pytest.raises(ValueError, match="kv_version"):
        VaultProvider.validate({"url": VAULT_URL, "kv_version": 3}, {"token": "t"})
    with pytest.raises(ValueError, match="verify_tls"):
        VaultProvider.validate({"url": VAULT_URL, "verify_tls": "yes"}, {"token": "t"})
    with pytest.raises(ValueError, match="timeout"):
        VaultProvider.validate({"url": VAULT_URL, "timeout": 0}, {"token": "t"})
    with pytest.raises(ValueError, match="at most"):
        VaultProvider.validate({"url": VAULT_URL, "namespace": "n" * 300}, {"token": "t"})
    with pytest.raises(ValueError, match="text"):
        VaultProvider.validate({"url": VAULT_URL, "namespace": 5}, {"token": "t"})
    cfg = VaultProvider.validate({"url": VAULT_URL + "/", "mount": None}, {"token": "t"})
    assert cfg["url"] == VAULT_URL and cfg["mount"] == "secret" and cfg["kv_version"] == 2
    with pytest.raises(ValueError, match="secret access key"):
        AwsSecretsManagerProvider.validate({"region": "us-east-1", "access_key_id": "test-key-id"}, {})
    with pytest.raises(ValueError, match="region is required"):
        AwsSecretsManagerProvider.validate({}, {})
    with pytest.raises(ValueError, match="tenant ID, a client ID"):
        AzureKeyVaultProvider.validate({"vault_url": "https://kv-test.vault.azure.net"}, {})
    with pytest.raises(ValueError, match="tenant_id"):
        AzureKeyVaultProvider.validate(
            {"vault_url": "https://kv-test.vault.azure.net", "tenant_id": "bad tenant", "client_id": "c"},
            {"client_secret": "s"},
        )
    default_auth = {"vault_url": "https://kv-test.vault.azure.net", "auth_method": "default"}
    assert AzureKeyVaultProvider.validate(default_auth, {})["auth_method"] == "default"
    assert vault_scope("https://kv-test.vault.azure.net") == "https://vault.azure.net/.default"
    assert vault_scope("https://kv-test.vault.usgovcloudapi.net") == "https://vault.usgovcloudapi.net/.default"


def test_prepare_provider_merges_and_drops_secrets():
    config, enc = service.prepare_provider("vault", {"url": VAULT_URL}, {"token": FAKE_TOKEN})
    assert FAKE_TOKEN not in enc and service.decode_secrets(enc) == {"token": FAKE_TOKEN}
    # Blank keeps the stored token.
    _, kept = service.prepare_provider("vault", config, {"token": ""}, enc)
    assert service.decode_secrets(kept) == {"token": FAKE_TOKEN}
    # A switch to AppRole drops the token it no longer uses.
    _, switched = service.prepare_provider(
        "vault", {**config, "auth_method": "approle", "role_id": "r"}, {"secret_id": "test-secret-id"}, enc
    )
    assert service.decode_secrets(switched) == {"secret_id": "test-secret-id"}
    # AWS without an access key uses the default chain and stores nothing.
    _, none = service.prepare_provider("aws", {"region": "us-east-1"}, {"secret_access_key": "x"})
    assert none == ""
    for bad_type, cfg, secrets, message in (
        ("nope", {}, {}, "provider_type"),
        ("vault", {"url": VAULT_URL}, {"bogus": "x"}, "Unknown secret"),
        ("vault", {"url": VAULT_URL}, ["token"], "must be an object"),
        ("vault", {"url": VAULT_URL}, {"token": 5}, "must be text"),
    ):
        with pytest.raises(ValueError, match=message):
            service.prepare_provider(bad_type, cfg, secrets)


# ── HashiCorp Vault ──────────────────────────────────────────────────────────


async def test_vault_kv2_token_namespace_and_cache(monkeypatch):
    path = "/v1/secret/data/network/core"
    rec = _mock(monkeypatch, {("GET", path): (200, {"data": {"data": {"password": FAKE_PASSWORD, "u": "x"}}})})
    now = [1000.0]
    monkeypatch.setattr(base.VALUE_CACHE, "clock", lambda: now[0])
    vault = _vault(namespace="team-a")
    vault.cache_ttl = 60
    assert await vault.resolve(Reference("network/core", "password")) == FAKE_PASSWORD
    assert await vault.resolve(Reference("network/core", "password")) == FAKE_PASSWORD
    assert rec.count(path) == 1
    sent = rec.requests[0]
    assert sent.headers["X-Vault-Token"] == FAKE_TOKEN and sent.headers["X-Vault-Namespace"] == "team-a"
    now[0] += 61
    await vault.resolve(Reference("network/core", "password"))
    assert rec.count(path) == 2
    # use_cache=False always asks.
    await vault.resolve(Reference("network/core", "password"), use_cache=False)
    assert rec.count(path) == 3


async def test_vault_kv1_approle_login_is_cached(monkeypatch):
    rec = _mock(
        monkeypatch,
        {
            ("POST", "/v1/auth/approle/login"): (
                200,
                {"auth": {"client_token": "approle-test-token", "lease_duration": 600}},
            ),
            ("GET", "/v1/kv/network/core"): (200, {"data": {"password": FAKE_PASSWORD}}),
            ("GET", "/v1/kv/network/edge"): (200, {"data": {"enable": FAKE_ENABLE}}),
        },
    )
    vault = _vault(mount="kv", kv_version=1, auth_method="approle", role_id="test-role")
    assert await vault.resolve(Reference("network/core")) == FAKE_PASSWORD
    assert await vault.resolve(Reference("network/edge", "enable")) == FAKE_ENABLE
    assert rec.count("/v1/auth/approle/login") == 1
    login = json.loads(rec.requests[0].content)
    assert login == {"role_id": "test-role", "secret_id": "test-secret-id"}
    assert rec.requests[1].headers["X-Vault-Token"] == "approle-test-token"


@pytest.mark.parametrize(
    ("status", "code"),
    [(403, base.FORBIDDEN), (404, base.NOT_FOUND), (401, base.AUTH_FAILED), (500, base.PROVIDER_ERROR)],
)
async def test_vault_refusals(monkeypatch, status, code):
    _mock(monkeypatch, {("GET", "/v1/secret/data/x"): (status, {"errors": ["denied"]})})
    with pytest.raises(SecretsProviderError) as err:
        await _vault().resolve(Reference("x", "password"))
    assert err.value.code == code


async def test_vault_approle_failures_and_bad_answers(monkeypatch):
    _mock(monkeypatch, {("POST", "/v1/auth/approle/login"): (400, {"errors": ["invalid secret id"]})})
    approle = _vault(auth_method="approle", role_id="r")
    with pytest.raises(SecretsProviderError) as err:
        await approle.resolve(Reference("x"))
    assert err.value.code == base.AUTH_FAILED
    _mock(monkeypatch, {("POST", "/v1/auth/approle/login"): (200, {"auth": {}})})
    with pytest.raises(SecretsProviderError, match="no token"):
        await approle.resolve(Reference("x"))
    _mock(monkeypatch, {("GET", "/v1/secret/data/x"): (200, {"data": None})})
    with pytest.raises(SecretsProviderError, match="no key/value data"):
        await _vault().resolve(Reference("x"))
    monkeypatch.setattr(base, "HTTP_TRANSPORT", httpx.MockTransport(lambda r: httpx.Response(200, content=b"not json")))
    with pytest.raises(SecretsProviderError, match="not a JSON object"):
        await _vault().resolve(Reference("x"))


async def test_unreachable_and_ssrf_and_bad_ca(monkeypatch):
    def refuse(_request):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(base, "HTTP_TRANSPORT", httpx.MockTransport(refuse))
    with pytest.raises(SecretsProviderError, match=r"could not reach vault\.example\.com ") as err:
        await _vault().resolve(Reference("x"))
    assert err.value.code == base.UNREACHABLE

    monkeypatch.undo()  # the real SSRF guard: link-local metadata addresses are refused
    blocked = VaultProvider({**_vault().config, "url": "http://169.254.169.254"}, {"token": "t"}, name="meta")
    with pytest.raises(SecretsProviderError) as ssrf:
        await blocked.resolve(Reference("x"))
    assert ssrf.value.code == base.UNREACHABLE and "not allowed" in str(ssrf.value)

    bad_ca = VaultProvider({**_vault().config, "ca_pem": "not a pem"}, {"token": "t"})
    with pytest.raises(SecretsProviderError) as ca:
        await bad_ca.resolve(Reference("x"))
    assert ca.value.code == base.INVALID_CONFIG


# ── AWS Secrets Manager ──────────────────────────────────────────────────────


class FakeClientError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class EndpointConnectionError(Exception):
    pass


def _fake_boto3(monkeypatch, secrets: dict, calls: list) -> None:
    class Client:
        def __init__(self, service_name, **kwargs):
            self.service_name = service_name
            calls.append(("client", service_name, kwargs.get("endpoint_url")))

        def get_secret_value(self, SecretId):
            calls.append(("get", SecretId))
            value = secrets[SecretId]
            if isinstance(value, Exception):
                raise value
            return value

        def assume_role(self, **kwargs):
            calls.append(("assume", kwargs))
            return {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"}}

    class Session:
        def __init__(self, **kwargs):
            calls.append(("session", sorted(kwargs)))

        def client(self, service_name, **kwargs):
            return Client(service_name, **kwargs)

    module = types.ModuleType("boto3")
    module.session = types.SimpleNamespace(Session=Session)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", module)


def _aws(**config) -> AwsSecretsManagerProvider:
    settings = {"region": "us-east-1", **config}
    secrets = {"secret_access_key": "test-secret-access-key"} if config.get("access_key_id") else {}
    return AwsSecretsManagerProvider(
        AwsSecretsManagerProvider.validate(settings, secrets), secrets, provider_id=2, name="aws-test"
    )


async def test_aws_json_key_binary_and_assume_role(monkeypatch):
    calls: list = []
    _fake_boto3(
        monkeypatch,
        {
            "network/core": {"SecretString": json.dumps({"password": FAKE_PASSWORD, "enable": FAKE_ENABLE})},
            "plain": {"SecretString": FAKE_PASSWORD},
            "binary": {"SecretBinary": FAKE_ENABLE.encode()},
            "image": {"SecretBinary": b"\xff\xfe"},
            "empty": {},
        },
        calls,
    )
    aws = _aws(access_key_id="test-key-id", role_arn="arn:aws:iam::123456789012:role/test", external_id="x")
    assert await aws.resolve(Reference("network/core", "enable")) == FAKE_ENABLE
    assert await aws.resolve(Reference("plain")) == FAKE_PASSWORD
    assert await aws.resolve(Reference("binary")) == FAKE_ENABLE
    assumed = [c for c in calls if c[0] == "assume"]
    assert assumed and assumed[0][1]["ExternalId"] == "x"
    assert ("session", ["aws_access_key_id", "aws_secret_access_key", "region_name"]) in calls
    for path, message in (("image", "binary"), ("empty", "no value")):
        with pytest.raises(SecretsProviderError, match=message):
            await aws.resolve(Reference(path))


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (FakeClientError("ResourceNotFoundException"), base.NOT_FOUND),
        (FakeClientError("AccessDeniedException"), base.FORBIDDEN),
        (FakeClientError("UnrecognizedClientException"), base.AUTH_FAILED),
        (FakeClientError("ThrottlingException"), base.PROVIDER_ERROR),
        (EndpointConnectionError("down"), base.UNREACHABLE),
    ],
)
async def test_aws_error_mapping(monkeypatch, error, code):
    _fake_boto3(monkeypatch, {"x": error}, [])
    with pytest.raises(SecretsProviderError) as err:
        await _aws(endpoint_url="https://secretsmanager.example.com").resolve(Reference("x"))
    assert err.value.code == code


async def test_aws_without_boto3_is_sdk_not_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", None)
    with pytest.raises(SecretsProviderError) as err:
        await _aws().resolve(Reference("x"))
    assert err.value.code == base.SDK_NOT_INSTALLED
    assert service.sdk_status("aws", {}) == {"status": base.SDK_NOT_INSTALLED, "missing": ["boto3"]}


# ── Azure Key Vault ──────────────────────────────────────────────────────────

KV_URL = "https://kv-test.vault.azure.net"
TOKEN_PATH = "/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token"


def _azure(**config) -> AzureKeyVaultProvider:
    settings = {
        "vault_url": KV_URL,
        "tenant_id": "00000000-0000-0000-0000-000000000000",
        "client_id": "11111111-1111-1111-1111-111111111111",
        **config,
    }
    secrets = {"client_secret": "test-client-secret"}
    return AzureKeyVaultProvider(
        AzureKeyVaultProvider.validate(settings, secrets), secrets, provider_id=3, name="azure-test"
    )


async def test_azure_client_secret_token_and_versions(monkeypatch):
    rec = _mock(
        monkeypatch,
        {
            ("POST", TOKEN_PATH): (200, {"access_token": "test-bearer", "expires_in": 3599}),
            ("GET", "/secrets/core-switches"): (200, {"value": json.dumps({"password": FAKE_PASSWORD})}),
            ("GET", "/secrets/core-switches/abc123"): (200, {"value": FAKE_ENABLE}),
        },
    )
    azure = _azure()
    assert await azure.resolve(Reference("core-switches", "password")) == FAKE_PASSWORD
    assert await azure.resolve(Reference("core-switches/abc123")) == FAKE_ENABLE
    assert rec.count(TOKEN_PATH) == 1
    form = dict(x.split("=") for x in rec.requests[0].content.decode().split("&"))
    assert form["grant_type"] == "client_credentials" and form["scope"] == "https%3A%2F%2Fvault.azure.net%2F.default"
    secret_call = rec.requests[1]
    assert secret_call.headers["Authorization"] == "Bearer test-bearer"
    assert secret_call.url.params["api-version"] == "7.4"


async def test_azure_failures(monkeypatch):
    _mock(monkeypatch, {("POST", TOKEN_PATH): (401, {"error": "invalid_client"})})
    with pytest.raises(SecretsProviderError) as auth:
        await _azure().resolve(Reference("x"))
    assert auth.value.code == base.AUTH_FAILED
    _mock(
        monkeypatch,
        {("POST", TOKEN_PATH): (200, {"access_token": "t", "expires_in": "bad"}), ("GET", "/secrets/x"): (200, {})},
    )
    with pytest.raises(SecretsProviderError, match="no value"):
        await _azure().resolve(Reference("x"))
    _mock(monkeypatch, {("POST", TOKEN_PATH): (200, {})})
    base.invalidate()
    with pytest.raises(SecretsProviderError, match="no access token"):
        await _azure().resolve(Reference("x"))
    with pytest.raises(SecretsProviderError) as name:
        await _azure().resolve(Reference("bad_name!"))
    assert name.value.code == base.INVALID_REFERENCE
    _mock(monkeypatch, {("POST", TOKEN_PATH): (200, {"access_token": "t"}), ("GET", "/secrets/gone"): (404, {})})
    base.invalidate()
    with pytest.raises(SecretsProviderError) as missing:
        await _azure().resolve(Reference("gone"))
    assert missing.value.code == base.NOT_FOUND


async def test_azure_default_credential_lazy_sdk(monkeypatch):
    monkeypatch.setitem(sys.modules, "azure.identity", None)
    provider = _azure(auth_method="default")
    with pytest.raises(SecretsProviderError) as err:
        await provider.resolve(Reference("x"))
    assert err.value.code == base.SDK_NOT_INSTALLED
    assert service.sdk_status("azure", {"auth_method": "default"})["status"] == base.SDK_NOT_INSTALLED
    assert service.sdk_status("azure", {"auth_method": "client_secret"})["status"] == "ok"

    scopes: list = []

    class DefaultAzureCredential:
        def get_token(self, scope):
            scopes.append(scope)
            return types.SimpleNamespace(token="test-managed-identity-token", expires_on=time.time() + 3600)

    identity = types.ModuleType("azure.identity")
    identity.DefaultAzureCredential = DefaultAzureCredential  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "azure", types.ModuleType("azure"))
    monkeypatch.setitem(sys.modules, "azure.identity", identity)
    rec = _mock(monkeypatch, {("GET", "/secrets/x"): (200, {"value": FAKE_PASSWORD})})
    assert await provider.resolve(Reference("x")) == FAKE_PASSWORD
    assert scopes == ["https://vault.azure.net/.default"]
    assert rec.requests[0].headers["Authorization"] == "Bearer test-managed-identity-token"


# ── API and the choke points (Postgres) ──────────────────────────────────────


def _vault_routes(password: str = FAKE_PASSWORD) -> dict:
    return {
        ("GET", "/v1/secret/data/network/core"): (
            200,
            {"data": {"data": {"password": password, "enable": FAKE_ENABLE}}},
        )
    }


def _create_vault(admin, name="corp-vault", **extra) -> int:
    body = {
        "name": name,
        "provider_type": "vault",
        "config": {"url": VAULT_URL, "namespace": "team-a"},
        "secrets": {"token": FAKE_TOKEN},
        **extra,
    }
    resp = admin.post(API, json=body)
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _audit_actions(category: str = "secrets_providers") -> list[str]:
    return [e["action"] for e in asyncio.run(db.get_audit_events(500, category))]


def test_provider_crud_never_returns_secrets(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    pid = _create_vault(admin)
    listing = admin.get(API)
    assert listing.status_code == 200 and FAKE_TOKEN not in listing.text
    row = next(p for p in listing.json()["providers"] if p["id"] == pid)
    assert row["secrets_set"] == ["token"] and row["config"]["namespace"] == "team-a"
    assert row["sdk"] == {"status": "ok", "missing": []} and row["enabled"] is True
    assert {t["type"] for t in listing.json()["types"]} == {"vault", "aws", "azure"}
    assert FAKE_TOKEN not in admin.get(f"{API}/{pid}").text
    assert admin.get(f"{API}/999").status_code == 404

    assert (
        admin.post(
            API,
            json={
                "name": "Corp-Vault",
                "provider_type": "vault",
                "config": {"url": VAULT_URL},
                "secrets": {"token": "t"},
            },
        ).status_code
        == 409
    )
    assert admin.post(API, json={"name": "x", "provider_type": "vault", "config": {}}).status_code == 400
    assert admin.post(API, json={"name": " ", "provider_type": "vault"}).status_code == 400
    assert (
        admin.post(
            API, json={"name": "x", "provider_type": "aws", "config": {"region": "r"}, "description": "d" * 600}
        ).status_code
        == 400
    )

    # A blank secret keeps the stored one; settings change.
    upd = admin.put(
        f"{API}/{pid}",
        json={
            "config": {"url": VAULT_URL, "mount": "kv"},
            "secrets": {"token": ""},
            "cache_ttl": 0,
            "allow_user_credentials": True,
            "description": "lab",
        },
    )
    assert upd.status_code == 200, upd.text
    after = admin.get(f"{API}/{pid}").json()
    assert after["config"]["mount"] == "kv" and after["secrets_set"] == ["token"] and after["cache_ttl"] == 0
    assert admin.put(f"{API}/{pid}", json={"provider_type": "aws"}).status_code == 400
    assert admin.put(f"{API}/{pid}", json={"name": "renamed", "enabled": False}).status_code == 200
    other = _create_vault(admin, name="second")
    assert admin.put(f"{API}/{other}", json={"name": "renamed"}).status_code == 409
    assert admin.delete(f"{API}/{other}").status_code == 200
    assert admin.delete(f"{API}/{other}").status_code == 404
    actions = _audit_actions()
    assert actions.count("secrets_provider.create") == 2 and "secrets_provider.delete" in actions
    assert "secrets_provider.update" in actions
    assert all(FAKE_TOKEN not in e["detail"] for e in asyncio.run(db.get_audit_events(500, "secrets_providers")))


def test_test_endpoint_reports_success_or_failure_only(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    pid = _create_vault(admin)
    _mock(monkeypatch, _vault_routes())
    ok = admin.post(f"{API}/{pid}/test", json={"path": "network/core", "key": "password"})
    assert ok.json() == {"ok": True} and FAKE_PASSWORD not in ok.text
    bad = admin.post(f"{API}/{pid}/test", json={"path": "network/core", "key": "missing"})
    assert bad.json()["ok"] is False and bad.json()["code"] == base.KEY_NOT_FOUND
    assert FAKE_PASSWORD not in bad.text and FAKE_ENABLE not in bad.text
    empty = admin.post(f"{API}/{pid}/test", json={"path": " "})
    assert empty.json()["code"] == base.INVALID_REFERENCE
    admin.put(f"{API}/{pid}", json={"enabled": False})
    assert admin.post(f"{API}/{pid}/test", json={"path": "network/core"}).json()["code"] == base.DISABLED
    assert admin.post(f"{API}/999/test", json={"path": "x"}).status_code == 404
    actions = _audit_actions()
    assert "secrets_provider.test" in actions and "secrets_provider.resolve_failed" in actions


def test_feature_gate(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    plain = user_client(admin, "no-secrets", features=["credentials"])
    assert plain.get(API).status_code == 403
    reader = user_client(admin, "sp-reader", features=["secrets-providers"])
    assert reader.get(API).status_code == 200
    assert reader.post(API, json={"name": "x", "provider_type": "vault"}).status_code == 403
    assert "secrets-providers.write" in state.FEATURE_FLAGS


def test_credential_reference_resolves_at_the_choke_points(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    pid = _create_vault(admin)
    rec = _mock(monkeypatch, _vault_routes())
    created = admin.post(
        "/api/credentials",
        json={
            "name": "core",
            "username": "netops",
            "external": {"provider_id": pid, "path": "network/core", "key": "password", "secret_key": "enable"},
        },
    )
    assert created.status_code == 201, created.text
    cid = int(created.json()["id"])
    listing = admin.get("/api/credentials")
    row = next(c for c in listing.json() if c["id"] == cid)
    assert row["ext_provider_name"] == "corp-vault" and row["ext_path"] == "network/core"
    assert row["ext_key"] == "password" and row["ext_secret_key"] == "enable"
    assert FAKE_PASSWORD not in listing.text

    stored = asyncio.run(db.get_credential_raw(cid, resolve_external=False))
    assert stored["password"] == "" and stored["secret"] == ""
    resolved = asyncio.run(db.get_credential_raw(cid))
    assert decrypt(resolved["password"]) == FAKE_PASSWORD and decrypt(resolved["secret"]) == FAKE_ENABLE

    from netcontrol.routes.shared import require_credential_access

    session = {"auth_mode": "token", "user": "api"}
    via_access = asyncio.run(require_credential_access(cid, session=session))
    assert decrypt(via_access["password"]) == FAKE_PASSWORD
    # The TTL cache: both reads above asked Vault once per key.
    assert rec.count("/v1/secret/data/network/core") == 2

    # A failure: consumers get a stand-in that decrypt refuses; strict paths 502.
    base.invalidate()
    _mock(monkeypatch, {})
    broken = asyncio.run(db.get_credential_raw(cid))
    with pytest.raises(RuntimeError, match="could not be resolved"):
        decrypt(broken["password"])
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        asyncio.run(require_credential_access(cid, session=session))
    assert exc.value.status_code == 502 and "corp-vault" in exc.value.detail
    assert "secrets_provider.resolve_failed" in _audit_actions()

    # Switching back to a stored password drops the reference.
    upd = admin.put(f"/api/credentials/{cid}", json={"password": "typed-test-password"})
    assert upd.status_code == 200
    plain = asyncio.run(db.get_credential_raw(cid))
    assert plain["ext_provider_id"] is None and decrypt(plain["secret"]) == "typed-test-password"
    # And to a reference again.
    again = admin.put(f"/api/credentials/{cid}", json={"external": {"provider_id": pid, "path": "network/core"}})
    assert again.status_code == 200
    assert asyncio.run(db.get_credential_raw(cid, resolve_external=False))["password"] == ""

    # A provider in use cannot be deleted.
    assert admin.delete(f"{API}/{pid}").status_code == 409


def test_credential_reference_validation_and_personal_rule(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    closed = _create_vault(admin, name="closed")
    opened = _create_vault(admin, name="open", allow_user_credentials=True)
    disabled = _create_vault(admin, name="off", allow_user_credentials=True, enabled=False)
    assert admin.post("/api/credentials", json={"name": "n", "username": "u"}).status_code == 400
    bad = {"name": "n", "username": "u", "external": {"provider_id": 999, "path": "p"}}
    assert admin.post("/api/credentials", json=bad).status_code == 404
    bad["external"] = {"provider_id": closed, "path": ""}
    assert admin.post("/api/credentials", json=bad).status_code == 400
    names = {p["name"] for p in admin.get("/api/credentials/secrets-providers").json()}
    assert names == {"closed", "open"}

    user = user_client(admin, "netops-user", features=["credentials", "credentials.write"])
    assert {p["name"] for p in user.get("/api/credentials/secrets-providers").json()} == {"open"}
    body = {"name": "mine", "username": "u", "external": {"provider_id": closed, "path": "network/core"}}
    denied = user.post("/api/credentials", json=body)
    assert denied.status_code == 403 and "personal" in denied.text
    body["external"]["provider_id"] = opened
    assert user.post("/api/credentials", json=body).status_code == 201
    assert disabled

    # Service credentials take references too.
    svc = admin.post(
        "/api/credentials/service",
        json={"name": "svc", "username": "u", "external": {"provider_id": closed, "path": "network/core"}},
    )
    assert svc.status_code == 201
    svc_id = int(svc.json()["id"])
    row = next(c for c in admin.get("/api/credentials/service").json() if c["id"] == svc_id)
    assert row["ext_provider_name"] == "closed"
    assert admin.put(f"/api/credentials/service/{svc_id}", json={"name": "svc2"}).status_code == 200
    assert asyncio.run(db.get_credential_raw(svc_id, resolve_external=False))["ext_provider_id"] == closed


def test_secret_variable_reference(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    pid = _create_vault(admin)
    _mock(monkeypatch, _vault_routes())
    created = admin.post(
        "/api/secret-variables",
        json={"name": "core_pw", "external": {"provider_id": pid, "path": "network/core", "key": "password"}},
    )
    assert created.status_code == 201, created.text
    vid = int(created.json()["id"])
    listing = admin.get("/api/secret-variables")
    row = next(v for v in listing.json() if v["id"] == vid)
    assert row["ext_provider_name"] == "corp-vault" and row["ext_key"] == "password"
    assert FAKE_PASSWORD not in listing.text

    lines = ["username netops secret {{secret.core_pw}}"]
    assert asyncio.run(secret_resolver.resolve_secrets(lines)) == [f"username netops secret {FAKE_PASSWORD}"]
    assert asyncio.run(secret_resolver.resolve_secrets(lines, redact=True)) == ["username netops secret ********"]
    assert asyncio.run(secret_resolver.build_redaction_set(lines)) == {FAKE_PASSWORD}

    base.invalidate()
    _mock(monkeypatch, {})
    with pytest.raises(secret_resolver.SecretResolutionError, match="core_pw"):
        asyncio.run(secret_resolver.resolve_secrets(lines))
    with pytest.raises(secret_resolver.SecretResolutionError):
        asyncio.run(secret_resolver.build_redaction_set(lines))

    assert admin.post("/api/secret-variables", json={"name": "empty"}).status_code == 400
    missing = {"name": "x", "external": {"provider_id": 999, "path": "p"}}
    assert admin.post("/api/secret-variables", json=missing).status_code == 404
    missing["external"] = {"provider_id": pid, "path": "bad\npath"}
    assert admin.post("/api/secret-variables", json=missing).status_code == 400

    # A stored value replaces the reference, and back.
    assert admin.put(f"/api/secret-variables/{vid}", json={"value": "typed-test-value"}).status_code == 200
    assert asyncio.run(secret_resolver.resolve_secrets(lines)) == ["username netops secret typed-test-value"]
    swap = admin.put(f"/api/secret-variables/{vid}", json={"external": {"provider_id": pid, "path": "network/core"}})
    assert swap.status_code == 200
    stored = asyncio.run(db.get_secret_variable_by_name("core_pw"))
    assert stored["enc_value"] == "" and stored["ext_provider_id"] == pid


def test_resolve_reference_failures_are_audited_once_per_interval(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    pid = _create_vault(admin)
    _mock(monkeypatch, {})
    for _ in range(3):
        with pytest.raises(SecretsProviderError):
            asyncio.run(service.resolve_reference(pid, "network/core", context="credential_id=1"))
    assert _audit_actions().count("secrets_provider.resolve_failed") == 1
    with pytest.raises(SecretsProviderError) as missing:
        asyncio.run(service.resolve_reference(999, "x"))
    assert missing.value.code == base.PROVIDER_MISSING
    # Settings that no longer decrypt are reported, not raised raw.
    with pytest.raises(SecretsProviderError) as broken:
        service.build_provider({"id": 1, "name": "b", "provider_type": "vault", "config_json": "{", "secret_enc": ""})
    assert broken.value.code == base.INVALID_CONFIG
    assert (
        service.public_provider(
            {"id": 1, "name": "b", "provider_type": "vault", "config_json": "{", "secret_enc": "garbage"}
        )["secrets_set"]
        == []
    )


def test_unavailable_stand_in_and_materialize_passthrough():
    with pytest.raises(RuntimeError, match="provider down"):
        decrypt(unavailable("provider down"))
    plain = {"id": 1, "password": "x"}
    assert asyncio.run(service.materialize_credential(plain)) is plain
    assert asyncio.run(service.materialize_credential(None)) is None
