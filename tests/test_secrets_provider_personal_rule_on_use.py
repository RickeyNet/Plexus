"""A secrets provider's "Allow personal credentials" switch holds on every
use of a credential, not only when its reference is saved.

A non-admin's own credential resolves through a provider only while the
provider is open to personal credentials: closing the provider, or demoting
the credential's owner, stops the stored reference from being read. An
admin's credential and a service credential are not personal.

Every name, token and address is invented; the vault is a mock transport.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
import routes.database as db
from fastapi import HTTPException
from netcontrol.routes import outbound_http, state
from netcontrol.secrets_providers import base, service

from mcp_helpers import admin_client, user_client

API = "/api/secrets-providers"
VAULT_URL = "https://vault.example.com:8200"
FAKE_TOKEN = "test-vault-token-not-real"
FAKE_PASSWORD = "invented-shared-password-9"
REFERENCE = {"path": "network/shared", "key": "", "secret_key": ""}


@pytest.fixture(autouse=True)
def vault_requests(monkeypatch):
    base.invalidate()
    service._FAILURES_AUDITED.clear()
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})

    async def no_guard(_url):
        return None

    monkeypatch.setattr(outbound_http, "guard_url", no_guard)
    requests: list[httpx.Request] = []

    def vault(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/v1/secret/data/network/shared":
            return httpx.Response(200, json={"data": {"data": {"password": FAKE_PASSWORD}}})
        return httpx.Response(404, json={"errors": []})

    monkeypatch.setattr(base, "HTTP_TRANSPORT", httpx.MockTransport(vault))
    yield requests
    base.invalidate()


def _create_vault(admin, **extra) -> int:
    body = {
        "name": "corp-vault",
        "provider_type": "vault",
        "config": {"url": VAULT_URL},
        "secrets": {"token": FAKE_TOKEN},
        "cache_ttl": 0,
        **extra,
    }
    resp = admin.post(API, json=body)
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _use(cred_id: int, username: str) -> dict:
    """What a job launch (or any route) gets for the owner's credential."""
    from netcontrol.routes.shared import require_credential_access

    async def _go():
        user = await db.get_user_by_username(username)
        return await require_credential_access(cred_id, session={"user": username, "user_id": user["id"]})

    return asyncio.run(_go())


def _set_role(username: str, role: str) -> int:
    async def _go():
        user = await db.get_user_by_username(username)
        await db.update_user_admin(user["id"], role=role)
        return int(user["id"])

    return asyncio.run(_go())


def test_closing_a_provider_stops_existing_personal_credentials(monkeypatch, request, vault_requests):
    admin = admin_client(monkeypatch, request)
    pid = _create_vault(admin, allow_user_credentials=True)
    user = user_client(admin, "netops-user", features=["credentials", "credentials.write"])
    created = user.post(
        "/api/credentials",
        json={"name": "mine", "username": "u", "external": {"provider_id": pid, "path": "network/shared"}},
    )
    assert created.status_code == 201, created.text
    cid = int(created.json()["id"])
    assert _use(cid, "netops-user")["password"]

    assert admin.put(f"{API}/{pid}", json={"allow_user_credentials": False}).status_code == 200
    vault_requests.clear()
    with pytest.raises(HTTPException) as exc:
        _use(cid, "netops-user")
    assert exc.value.status_code == 502
    assert "not open to personal credentials" in exc.value.detail
    assert not vault_requests, "the closed provider was still asked for a personal reference"

    # The unattended read of the row gets a stand-in that cannot be decrypted, never a value.
    from routes.crypto import decrypt

    row = asyncio.run(db.get_credential_raw(cid))
    with pytest.raises(Exception, match="not open to personal credentials"):
        decrypt(row["password"])
    assert not vault_requests

    # Opened again, the same reference resolves.
    assert admin.put(f"{API}/{pid}", json={"allow_user_credentials": True}).status_code == 200
    assert _use(cid, "netops-user")["password"]


def test_a_demoted_owner_stops_reading_a_closed_provider(monkeypatch, request, vault_requests):
    admin = admin_client(monkeypatch, request)
    pid = _create_vault(admin, allow_user_credentials=False)
    user_client(admin, "former-admin", features=["credentials", "credentials.write"])
    uid = _set_role("former-admin", "admin")
    cid = asyncio.run(
        db.create_credential("theirs", "u", "", "", owner_id=uid, external={"provider_id": pid, **REFERENCE})
    )
    # An admin's own credential is not a personal one: the closed provider serves it.
    assert _use(cid, "former-admin")["password"]

    _set_role("former-admin", "user")
    vault_requests.clear()
    with pytest.raises(HTTPException) as exc:
        _use(cid, "former-admin")
    assert exc.value.status_code == 502
    assert not vault_requests, "the closed provider was still asked for a non-admin's reference"


def test_a_service_credential_is_not_personal(monkeypatch, request, vault_requests):
    admin = admin_client(monkeypatch, request)
    pid = _create_vault(admin, allow_user_credentials=False)
    cid = asyncio.run(
        db.create_credential("svc", "svc-login", "", "", is_service=True, external={"provider_id": pid, **REFERENCE})
    )
    row = asyncio.run(service.materialize_credential(asyncio.run(db.get_credential_raw(cid, resolve_external=False))))
    from routes.crypto import decrypt

    assert decrypt(row["password"]) == FAKE_PASSWORD
