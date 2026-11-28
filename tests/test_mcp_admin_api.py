"""Admin API for MCP tokens and settings (``netcontrol.routes.mcp_tokens``)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
import routes.database as db
from netcontrol.mcp import auth as mcp_auth

from mcp_helpers import SETTINGS, TOKENS, admin_client, admin_id, create_user, user_client


def _in_days(days: int) -> str:
    """The UTC date ``days`` from now, in the form of a token's expiry."""
    return (datetime.now(UTC).date() + timedelta(days=days)).isoformat()


def _body(owner: int, **over) -> dict:
    return {
        "name": "report-bot",
        "owner_user_id": owner,
        "categories": ["inventory", "configs"],
        "expires_at": "",
        **over,
    }


def test_create_returns_plaintext_once(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    resp = admin.post(TOKENS, json=_body(admin_id(admin)))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["token"].startswith("plx_mcp_")
    assert data["record"]["name"] == "report-bot"
    assert "token_hash" not in data["record"]

    listing = admin.get(TOKENS)
    assert data["token"] not in listing.text
    body = listing.json()
    assert "audit" in body["categories"] and len(body["categories"]) == 8
    assert body["expiry_default_days"] == mcp_auth.TOKEN_DEFAULT_DAYS
    assert body["expiry_max_days"] == mcp_auth.TOKEN_MAX_DAYS
    (record,) = body["tokens"]
    assert record["name"] == "report-bot" and record["owner_username"] == "admin"
    assert "token" not in record and "token_hash" not in record


@pytest.mark.parametrize(
    "over",
    [
        {"categories": []},
        {"categories": ["inventory", "passwords"]},
        {"owner_user_id": 987654},
        {"name": ""},
        {"name": "n" * 81},
        {"expires_at": "next week"},
        {"expires_at": "2026-13-45"},
        {"expires_at": "2020-01-01"},
        {"expires_at": "2999-01-01"},
        {"categories": ["audit"], "owner_user_id": "non-admin"},
    ],
)
def test_create_validation(monkeypatch, request, over):
    admin = admin_client(monkeypatch, request)
    if over.get("owner_user_id") == "non-admin":
        over = {**over, "owner_user_id": create_user(admin)}
    assert admin.post(TOKENS, json=_body(admin_id(admin), **over)).status_code == 422
    assert admin.get(TOKENS).json()["tokens"] == []


def test_a_token_without_an_expiry_date_gets_the_default(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    before = _in_days(mcp_auth.TOKEN_DEFAULT_DAYS)
    record = admin.post(TOKENS, json=_body(admin_id(admin))).json()["record"]
    # Two dates only when the test runs across midnight UTC.
    assert record["expires_at"] in {before, _in_days(mcp_auth.TOKEN_DEFAULT_DAYS)}

    body = _body(admin_id(admin), name="no-field")
    del body["expires_at"]
    assert admin.post(TOKENS, json=body).json()["record"]["expires_at"] != ""


def test_expiry_date_limits(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    owner = admin_id(admin)
    # One day inside each limit, so midnight UTC during the test cannot flip a result.
    soon, late = _in_days(1), _in_days(mcp_auth.TOKEN_MAX_DAYS - 1)
    for name, expires in (("soon", soon), ("late", late)):
        resp = admin.post(TOKENS, json=_body(owner, name=name, expires_at=expires))
        assert resp.status_code == 200, resp.text
        assert resp.json()["record"]["expires_at"] == expires

    past = admin.post(TOKENS, json=_body(owner, name="past", expires_at=_in_days(-2)))
    assert past.status_code == 422 and "in the past" in past.text
    far = admin.post(TOKENS, json=_body(owner, name="far", expires_at=_in_days(mcp_auth.TOKEN_MAX_DAYS + 2)))
    assert far.status_code == 422 and f"at most {mcp_auth.TOKEN_MAX_DAYS} days" in far.text
    assert {t["name"] for t in admin.get(TOKENS).json()["tokens"]} == {"soon", "late"}


def test_duplicate_name_is_409(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    owner = admin_id(admin)
    assert admin.post(TOKENS, json=_body(owner)).status_code == 200
    assert admin.post(TOKENS, json=_body(owner)).status_code == 409


def test_audit_category_allowed_for_admin_owner(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    assert admin.post(TOKENS, json=_body(admin_id(admin), categories=["audit"])).status_code == 200


def test_revoke_then_404(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    token_id = admin.post(TOKENS, json=_body(admin_id(admin))).json()["record"]["id"]
    resp = admin.delete(f"{TOKENS}/{token_id}")
    assert resp.status_code == 200 and resp.json() == {"revoked": True}
    assert admin.delete(f"{TOKENS}/{token_id}").status_code == 404
    assert admin.delete(f"{TOKENS}/424242").status_code == 404
    assert admin.get(TOKENS).json()["tokens"][0]["revoked_at"] != ""


def test_non_admin_forbidden(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    user = user_client(admin)
    assert user.get(SETTINGS).status_code == 403
    assert user.put(SETTINGS, json={"enabled": True}).status_code == 403
    assert user.get(TOKENS).status_code == 403
    assert user.post(TOKENS, json=_body(1)).status_code == 403
    assert user.delete(f"{TOKENS}/1").status_code == 403


def test_settings_roundtrip_and_bounds(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    assert admin.get(SETTINGS).json() == {
        "enabled": False,
        "max_result_bytes": 100000,
        "max_rows": 200,
        "calls_per_minute": 120,
    }
    resp = admin.put(SETTINGS, json={"enabled": True, "max_rows": 50})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True and resp.json()["max_rows"] == 50
    assert admin.get(SETTINGS).json()["max_rows"] == 50
    assert admin.put(SETTINGS, json={"max_rows": 5}).status_code == 422
    assert admin.put(SETTINGS, json={"surprise": 1}).status_code == 422
    assert admin.get(SETTINGS).json()["max_rows"] == 50


def test_audit_rows_written_without_plaintext(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    created = admin.post(TOKENS, json=_body(admin_id(admin))).json()
    admin.delete(f"{TOKENS}/{created['record']['id']}")
    admin.put(SETTINGS, json={"enabled": True})
    events = asyncio.run(db.get_audit_events(limit=50, category="mcp"))
    actions = {e["action"] for e in events}
    assert {"token_create", "token_revoke", "settings_update"} <= actions
    assert all(e["user"] == "admin" for e in events)
    assert any("report-bot" in e["detail"] for e in events)
    assert any(f"expires={created['record']['expires_at']}" in e["detail"] for e in events)
    assert all(created["token"] not in str(e) for e in events)
