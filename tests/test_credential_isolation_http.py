"""End-to-end HTTP credential-isolation regression tests (TODO Batch 5).

``test_credential_isolation.py`` pins the *policy* of ``require_credential_access``
at the unit level plus one endpoint-wiring regression. This suite closes the
remaining gap called out in TODO Batch 5: prove over real HTTP that a caller
cannot drive a device operation with a ``credential_id`` they do not own, for
each endpoint hardened in the pass-3 IDOR sweep.

Method
------
Two accounts are created (alice, bob), each owning one user credential. Both are
admins on purpose: the router-level ``require_feature`` gate is bypassed for
admins (app.py), so every request reaches the credential check instead of being
turned away at the feature gate first -- and the credential helper still denies
cross-owner use for admins (admin role is NOT a bypass). So a 403 here proves
the ownership gate fired at the endpoint, and it proves the stronger property
that even an admin can't borrow another user's personal credential.

For every endpoint we assert two things, both of which fire *before* any device
I/O so the tests stay fast and never open a real SSH session:

  * bob's credential  -> 403 "You can only use your own credentials"
  * a bogus credential -> 404 "Credential not found"

The 404 control proves the credential is actually validated at the endpoint
(not an incidental 403 from some other guard).

lab_runtime is intentionally not in the table: its credential is bound to the
lab device (``runtime_credential_id``), not supplied in the request body, and
access is gated by ``_get_device_or_403`` before the credential check is even
reached -- that ownership path is covered by ``test_lab_runtime.py`` and the
helper policy in ``test_credential_isolation.py``.
"""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db_module

DENY_OWN = "You can only use your own credentials"
DENY_MISSING = "Credential not found"
BOGUS_CRED = 999999


def _err_message(resp) -> str:
    """Extract the human message from the app's error envelope.

    The global exception handler wraps HTTPException detail as
    ``{"ok": false, "error": {"code": ..., "message": ...}}`` rather than
    FastAPI's default ``{"detail": ...}``.
    """
    body = resp.json()
    return (body.get("error") or {}).get("message") or body.get("detail") or ""


async def _seed_shared_objects(bob_id: int, alice_id: int) -> dict:
    """Create the credentials + device-side objects the endpoints look up
    before (or at) the credential check. Runs against the same temp DB the
    app uses via the monkeypatched DB_PATH."""
    bob_cred = await db_module.create_credential("bob-cred", "bobdev", "x", owner_id=bob_id)
    alice_cred = await db_module.create_credential("alice-cred", "alicedev", "x", owner_id=alice_id)

    group_id = await db_module.create_group("iso-group")
    host_id = await db_module.add_host(group_id, "iso-sw1", "10.77.0.1")
    profile_id = await db_module.create_compliance_profile("iso-profile", rules="[]")
    backup_id = await db_module.create_config_backup(None, host_id, "hostname iso-sw1")
    playbook_id = await db_module.create_playbook(
        "iso-pb", "iso_pb.py", content="print('noop')", type="python"
    )
    return {
        "bob_cred": bob_cred,
        "alice_cred": alice_cred,
        "group_id": group_id,
        "host_id": host_id,
        "profile_id": profile_id,
        "backup_id": backup_id,
        "playbook_id": playbook_id,
    }


@pytest.fixture
def iso_env(tmp_path, monkeypatch, request):
    import netcontrol.app as app_module

    db_path = str(tmp_path / "cred_iso_http.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-cred-iso")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient
    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))

    # Bootstrap admin, then create the two test accounts (both admins).
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    admin_csrf = resp.json().get("csrf_token", "")
    for name in ("alice", "bob"):
        r = client.post(
            "/api/admin/users",
            json={"username": name, "password": "password123", "role": "admin"},
            headers={"X-CSRF-Token": admin_csrf},
        )
        assert r.status_code == 201, r.text

    async def _ids_and_seed():
        alice = await db_module.get_user_by_username("alice")
        bob = await db_module.get_user_by_username("bob")
        return await _seed_shared_objects(bob["id"], alice["id"])

    ctx = asyncio.run(_ids_and_seed())

    # Log in as alice (overwrites the admin session cookie on this client).
    resp = client.post("/api/auth/login", json={"username": "alice", "password": "password123"})
    assert resp.status_code == 200, resp.text
    ctx["csrf"] = resp.json().get("csrf_token", "")
    ctx["client"] = client
    return ctx


def _endpoints(ctx: dict, credential_id: int) -> list[tuple[str, dict]]:
    """(path, body) for one representative endpoint per IDOR-swept module,
    parameterized by the credential_id under test."""
    return [
        ("/api/risk-analysis/analyze", {"credential_id": credential_id}),
        (f"/api/hosts/{ctx['host_id']}/fetch-serial", {"credential_id": credential_id}),
        ("/api/config-drift/snapshots/capture",
         {"host_id": ctx["host_id"], "credential_id": credential_id}),
        ("/api/config-backups/restore",
         {"backup_id": ctx["backup_id"], "credential_id": credential_id}),
        ("/api/compliance/scan",
         {"host_id": ctx["host_id"], "profile_id": ctx["profile_id"],
          "credential_id": credential_id}),
        ("/api/deployments",
         {"name": "iso-dep", "group_id": ctx["group_id"], "credential_id": credential_id,
          "proposed_commands": ["hostname iso-sw1"]}),
        ("/api/upgrades/campaigns", {"name": "iso-camp", "credential_id": credential_id}),
        ("/api/jobs/launch",
         {"playbook_id": ctx["playbook_id"], "host_ids": [ctx["host_id"]],
          "credential_id": credential_id}),
    ]


def test_cannot_use_another_users_credential(iso_env):
    client, csrf = iso_env["client"], iso_env["csrf"]
    hdrs = {"X-CSRF-Token": csrf}
    for path, body in _endpoints(iso_env, iso_env["bob_cred"]):
        resp = client.post(path, json=body, headers=hdrs)
        assert resp.status_code == 403, f"{path}: expected 403, got {resp.status_code} {resp.text}"
        assert _err_message(resp) == DENY_OWN, f"{path}: {resp.text}"


def test_unknown_credential_is_validated_at_each_endpoint(iso_env):
    client, csrf = iso_env["client"], iso_env["csrf"]
    hdrs = {"X-CSRF-Token": csrf}
    for path, body in _endpoints(iso_env, BOGUS_CRED):
        resp = client.post(path, json=body, headers=hdrs)
        assert resp.status_code == 404, f"{path}: expected 404, got {resp.status_code} {resp.text}"
        assert _err_message(resp) == DENY_MISSING, f"{path}: {resp.text}"
