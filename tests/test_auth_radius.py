import netcontrol.app as app_module
import pytest


@pytest.mark.asyncio
async def test_authenticate_login_identity_local_provider(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "AUTH_CONFIG",
        {
            "provider": "local",
            "radius": {
                "enabled": False,
                "fallback_to_local": True,
                "fallback_on_reject": False,
            },
        },
    )

    async def fake_verify_user(username, password):
        if username == "admin" and password == "good":
            return {"id": 1, "username": "admin", "display_name": "Admin", "role": "admin"}
        return None

    monkeypatch.setattr(app_module, "verify_user", fake_verify_user)

    user, source, error = await app_module.authenticate_login_identity("admin", "good")

    assert user is not None
    assert source == "local"
    assert error is None


@pytest.mark.asyncio
async def test_authenticate_login_identity_radius_accept(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "AUTH_CONFIG",
        {
            "provider": "radius",
            "radius": {
                "enabled": True,
                "fallback_to_local": True,
                "fallback_on_reject": False,
            },
        },
    )

    async def fake_verify_radius_user(username, password):
        return True, "accept"

    async def fake_upsert_radius_user(username):
        return {"id": 2, "username": username, "display_name": username, "role": "user"}

    async def fake_verify_user(username, password):
        return None

    monkeypatch.setattr(app_module, "verify_radius_user", fake_verify_radius_user)
    monkeypatch.setattr(app_module, "upsert_radius_user", fake_upsert_radius_user)
    monkeypatch.setattr(app_module, "verify_user", fake_verify_user)

    user, source, error = await app_module.authenticate_login_identity("radius-user", "pass")

    assert user is not None
    assert user["username"] == "radius-user"
    assert source == "radius"
    assert error is None


@pytest.mark.asyncio
async def test_authenticate_login_identity_radius_reject_no_fallback(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "AUTH_CONFIG",
        {
            "provider": "radius",
            "radius": {
                "enabled": True,
                "fallback_to_local": True,
                "fallback_on_reject": False,
            },
        },
    )

    async def fake_verify_radius_user(username, password):
        return False, "reject"

    async def fake_verify_user(username, password):
        return {"id": 3, "username": username, "display_name": username, "role": "user"}

    monkeypatch.setattr(app_module, "verify_radius_user", fake_verify_radius_user)
    monkeypatch.setattr(app_module, "verify_user", fake_verify_user)

    user, source, error = await app_module.authenticate_login_identity("user", "bad")

    assert user is None
    assert source is None
    assert error == "Invalid username or password"


@pytest.mark.asyncio
async def test_authenticate_login_identity_radius_error_with_local_fallback(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "AUTH_CONFIG",
        {
            "provider": "radius",
            "radius": {
                "enabled": True,
                "fallback_to_local": True,
                "fallback_on_reject": False,
            },
        },
    )

    async def fake_verify_radius_user(username, password):
        return False, "error"

    async def fake_verify_user(username, password):
        return {"id": 4, "username": username, "display_name": username, "role": "user"}

    monkeypatch.setattr(app_module, "verify_radius_user", fake_verify_radius_user)
    monkeypatch.setattr(app_module, "verify_user", fake_verify_user)

    user, source, error = await app_module.authenticate_login_identity("fallback-user", "good")

    assert user is not None
    assert source == "local-fallback"
    assert error is None


@pytest.mark.asyncio
async def test_authenticate_login_identity_radius_reject_with_override_fallback(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "AUTH_CONFIG",
        {
            "provider": "radius",
            "radius": {
                "enabled": True,
                "fallback_to_local": True,
                "fallback_on_reject": True,
            },
        },
    )

    async def fake_verify_radius_user(username, password):
        return False, "reject"

    async def fake_verify_user(username, password):
        return {"id": 5, "username": username, "display_name": username, "role": "user"}

    monkeypatch.setattr(app_module, "verify_radius_user", fake_verify_radius_user)
    monkeypatch.setattr(app_module, "verify_user", fake_verify_user)

    user, source, error = await app_module.authenticate_login_identity("fallback-reject", "good")

    assert user is not None
    assert source == "local-fallback"
    assert error is None
