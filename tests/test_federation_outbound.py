"""Federation peers: the SSRF guard runs on every request (not only when the
URL is saved), and the stored peer token is not reused for a new destination.
DNS answers and the network are stand-ins; no real host is contacted."""

from __future__ import annotations

import socket

import httpx
import netcontrol.routes.federation as federation_module
import pytest
from netcontrol.routes import net_guard

from test_federation import _auth_client


def _resolve_to(address: str):
    def fake(host):
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (address, 0))]

    return fake


def _create_peer(client, **extra) -> int:
    body = {"name": "Site-R", "url": "https://peer-r.example.com", "api_token": "peer-token-1", **extra}
    resp = client.post("/api/federation/peers", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.mark.asyncio
async def test_peer_requests_rerun_the_guard(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    peer_id = _create_peer(client)
    seen: list[httpx.Request] = []
    monkeypatch.setattr(
        federation_module,
        "HTTP_TRANSPORT",
        httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(200, json={"version": "9.9"})),
    )

    resp = client.post(f"/api/federation/peers/{peer_id}/test")
    assert resp.json()["status"] == "ok"
    assert seen[0].headers["X-API-Token"] == "peer-token-1"

    # The name now answers with the cloud metadata address: refused before
    # anything (or the token) is sent.
    seen.clear()
    monkeypatch.setattr(net_guard, "_getaddrinfo", _resolve_to("fd00:ec2::254"))
    resp = client.post(f"/api/federation/peers/{peer_id}/test")
    assert resp.status_code == 200
    assert resp.json()["status"] == "error"
    assert "Peer URL rejected" in resp.json()["message"]
    resp = client.post(f"/api/federation/peers/{peer_id}/sync")
    assert resp.status_code == 502
    assert seen == []
    assert client.get(f"/api/federation/peers/{peer_id}").json()["last_sync_status"] == "error"


@pytest.mark.asyncio
async def test_unresolvable_peer_is_refused_at_save(monkeypatch, request):
    client = _auth_client(monkeypatch, request)

    def fail(host):
        raise socket.gaierror(socket.EAI_NONAME, "unknown")

    monkeypatch.setattr(net_guard, "_getaddrinfo", fail)
    resp = client.post("/api/federation/peers", json={"name": "Nowhere", "url": "https://gone.example.com"})
    assert resp.status_code == 422
    assert "does not resolve" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_new_destination_needs_the_token_again(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    peer_id = _create_peer(client)
    url = f"/api/federation/peers/{peer_id}"

    # Same destination: the stored token is kept.
    assert client.put(url, json={"name": "Site-R2", "url": "https://peer-r.example.com/"}).status_code == 200

    for change in (
        {"url": "https://attacker.example.com"},
        {"url": "https://peer-r.example.com:8443"},
        {"tls_verify": False},
    ):
        resp = client.put(url, json=change)
        assert resp.status_code == 400, change
        assert "cannot be reused" in resp.json()["error"]["message"] and "API token" in resp.json()["error"]["message"]
        assert "peer-token-1" not in resp.text

    resp = client.put(url, json={"url": "https://peer-r2.example.com", "api_token": "peer-token-2"})
    assert resp.status_code == 200
    assert resp.json()["url"] == "https://peer-r2.example.com"


@pytest.mark.asyncio
async def test_peer_without_token_may_move(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    resp = client.post("/api/federation/peers", json={"name": "Open", "url": "https://open.example.com"})
    peer_id = resp.json()["id"]
    resp = client.put(f"/api/federation/peers/{peer_id}", json={"url": "https://open2.example.com"})
    assert resp.status_code == 200


# ── A peer's answers are bounded ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oversized_peer_answer_fails_its_section_only(monkeypatch):
    """A peer that answers with more than the cap loses that section (the
    sync is Partial); the rest of the sync still runs."""
    monkeypatch.setattr(federation_module, "_PEER_RESPONSE_MAX_BYTES", 2048)
    asked: list[str] = []

    def answer(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.path)
        if request.url.path == "/api/inventory/hosts":
            return httpx.Response(200, json=[{"status": "up", "pad": "x" * 64}] * 200)
        if request.url.path == "/api/admin/capabilities":
            return httpx.Response(200, json={"version": "9" * 500})
        return httpx.Response(200, json=[])

    monkeypatch.setattr(federation_module, "HTTP_TRANSPORT", httpx.MockTransport(answer))
    peer = {"name": "Site-R", "url": "https://peer-r.example.com", "api_token_enc": "", "tls_verify": 1}

    data = await federation_module._fetch_peer_data(peer)

    assert list(data["errors"]) == ["hosts"]
    assert "larger than 2048 bytes" in data["errors"]["hosts"]
    assert data["devices"]["total"] == 0
    assert "/api/admin/capabilities" in asked
    # The version is stored and shown: kept short whatever the peer sends.
    assert data["version"] == "9" * 64
    assert federation_module._sync_status_from(data)[0] == "partial"


def test_peer_version_is_a_short_string():
    assert federation_module._peer_version({"version": "1.4.2"}) == "1.4.2"
    assert federation_module._peer_version({"version": ["a"] * 100}) == str(["a"] * 100)[:64]
    assert federation_module._peer_version({"version": None}, "unknown") == "unknown"
    assert federation_module._peer_version({}, "unknown") == "unknown"
    assert federation_module._peer_version(["not", "a", "dict"]) == ""
