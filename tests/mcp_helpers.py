"""Shared helpers for the MCP (AI access) tests: an admin session client, a
non-admin session client, and token creation through the admin API."""

from __future__ import annotations

import netcontrol.app as app_module
from starlette.testclient import TestClient

TOKENS = "/api/admin/mcp/tokens"
SETTINGS = "/api/admin/mcp/settings"


class CsrfClient:
    """A logged-in TestClient that adds the CSRF header to writes."""

    def __init__(self, client: TestClient, csrf: str):
        self.raw, self._csrf = client, csrf

    def _headers(self, kw: dict) -> dict:
        kw["headers"] = {**kw.pop("headers", {}), "X-CSRF-Token": self._csrf}
        return kw

    def get(self, url, **kw):
        return self.raw.get(url, **kw)

    def post(self, url, **kw):
        return self.raw.post(url, **self._headers(kw))

    def put(self, url, **kw):
        return self.raw.put(url, **self._headers(kw))

    def delete(self, url, **kw):
        return self.raw.delete(url, **self._headers(kw))


def admin_client(monkeypatch, request) -> CsrfClient:
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-mcp")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    assert resp.status_code == 200, resp.text
    return CsrfClient(client, resp.json().get("csrf_token", ""))


def create_user(
    admin: CsrfClient, username: str = "ai-reader", role: str = "user", features: list[str] | None = None
) -> int:
    """Create a user; with ``features``, in a new access group granting exactly those."""
    body: dict = {"username": username, "password": "password123", "role": role}
    if features:
        group = admin.post("/api/admin/access-groups", json={"name": f"{username} access", "feature_keys": features})
        assert group.status_code == 201, group.text
        body["group_ids"] = [int(group.json()["id"])]
    resp = admin.post("/api/admin/users", json=body)
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def user_client(admin: CsrfClient, username: str = "plain-user", features: list[str] | None = None) -> CsrfClient:
    """A second session, for a new non-admin user, on the same running app.
    ``features`` grants that user exactly those features."""
    create_user(admin, username, features=features)
    client = TestClient(app_module.app, raise_server_exceptions=False)
    resp = client.post("/api/auth/login", json={"username": username, "password": "password123"})
    assert resp.status_code == 200, resp.text
    return CsrfClient(client, resp.json().get("csrf_token", ""))


def admin_id(admin: CsrfClient) -> int:
    users = admin.get("/api/admin/users").json()
    return next(int(u["id"]) for u in users if u["username"] == "admin")


def create_token(admin: CsrfClient, *, owner: int | None = None, categories=("inventory",), name: str = "bot") -> str:
    """Create a token through the admin API and return its plaintext."""
    body = {
        "name": name,
        "owner_user_id": owner if owner is not None else admin_id(admin),
        "categories": list(categories),
        "expires_at": "",
    }
    resp = admin.post(TOKENS, json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def enable_mcp(admin: CsrfClient, **limits) -> None:
    resp = admin.put(SETTINGS, json={"enabled": True, **limits})
    assert resp.status_code == 200, resp.text


# ── Direct dispatcher access (no HTTP) ───────────────────────────────────────


async def db_ctx(*, categories=None, features=None, admin: bool = True, name: str = "ctx-bot"):
    """A real user and token row, and the ``McpContext`` for them.

    ``features`` (for a non-admin owner) are stated directly on the context;
    an admin owner passes every feature check.
    """
    import routes.database as db
    from netcontrol.mcp import auth

    owner = await db.create_user(f"{name}-owner", "hash", "salt", role="admin" if admin else "user")
    _, token_hash, prefix = auth.generate_token()
    cats = list(categories if categories is not None else auth.CATEGORIES)
    token_id = await db.create_mcp_token(
        name=name,
        token_hash=token_hash,
        token_prefix=prefix,
        owner_user_id=owner,
        categories=cats,
        expires_at="",
        created_by="admin",
    )
    return auth.McpContext(
        token_id=token_id,
        token_name=name,
        owner_id=owner,
        owner_username=f"{name}-owner",
        owner_is_admin=admin,
        categories=frozenset(cats),
        features=frozenset(features or ()),
    )


async def call(ctx, name: str, arguments: dict | None = None):
    """Call a tool through the dispatcher. Returns ``(parsed JSON or text, is_error)``."""
    import json

    from netcontrol.mcp import dispatch

    text, is_error = await dispatch.call_tool(ctx, name, arguments)
    try:
        return json.loads(text), is_error
    except ValueError:
        return text, is_error
