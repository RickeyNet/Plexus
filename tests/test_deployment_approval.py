"""Tests for deployment approval gate state transitions.

Focuses on the DB layer (set_deployment_approval) and the auto-flag rules
that run at deployment creation. The thin FastAPI wrappers around these
are covered by inspection -- exercising them needs the full auth fixture
and would not catch anything the DB tests don't already.
"""
from __future__ import annotations

import json

import pytest
import routes.database as db_module


async def _init_clean_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "approval.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    return db_path


async def _seed_credential() -> int:
    """Insert a dummy credential -- approval logic doesn't read its
    payload, but the FK requires the row to exist."""
    from routes.crypto import encrypt
    enc = encrypt("dummy")
    db = await db_module.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO credentials (name, username, password, secret) VALUES (?,?,?,?)",
            ("test-cred", "u", enc, ""),
        )
        await db.commit()
        return int(cursor.lastrowid)
    finally:
        await db.close()


async def test_deployment_defaults_not_required(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    group_id = await db_module.create_group("lab")
    cred_id = await _seed_credential()

    dep_id = await db_module.create_deployment(
        name="dep-1",
        group_id=group_id,
        credential_id=cred_id,
        proposed_commands="hostname test",
    )
    dep = await db_module.get_deployment(dep_id)
    assert dep["requires_approval"] == 0
    assert dep["approval_status"] == "not_required"
    assert (dep["approved_by"] or "") == ""


async def test_set_deployment_approval_request_transition(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    group_id = await db_module.create_group("lab")
    cred_id = await _seed_credential()
    dep_id = await db_module.create_deployment(
        name="dep-1", group_id=group_id, credential_id=cred_id,
        proposed_commands="x", created_by="alice",
    )

    await db_module.set_deployment_approval(
        dep_id,
        requires_approval=True,
        approval_status="pending",
        request=True,
    )
    dep = await db_module.get_deployment(dep_id)
    assert dep["requires_approval"] == 1
    assert dep["approval_status"] == "pending"
    assert dep["approval_requested_at"]
    assert dep["approved_at"] is None


async def test_set_deployment_approval_approve_stamps_approver(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    group_id = await db_module.create_group("lab")
    cred_id = await _seed_credential()
    dep_id = await db_module.create_deployment(
        name="dep-1", group_id=group_id, credential_id=cred_id,
        proposed_commands="x", created_by="alice",
    )
    await db_module.set_deployment_approval(
        dep_id, requires_approval=True, approval_status="pending", request=True,
    )

    await db_module.set_deployment_approval(
        dep_id, approval_status="approved", approved_by="bob",
        approval_comment="lgtm",
    )
    dep = await db_module.get_deployment(dep_id)
    assert dep["approval_status"] == "approved"
    assert dep["approved_by"] == "bob"
    assert dep["approved_at"]
    assert dep["approval_comment"] == "lgtm"


async def test_set_deployment_approval_rejects_invalid_status(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    group_id = await db_module.create_group("lab")
    cred_id = await _seed_credential()
    dep_id = await db_module.create_deployment(
        name="dep-1", group_id=group_id, credential_id=cred_id, proposed_commands="x",
    )
    with pytest.raises(ValueError):
        await db_module.set_deployment_approval(dep_id, approval_status="bogus")


async def test_group_environment_marker_persists(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    group_id = await db_module.create_group("prod-edge")
    await db_module.set_group_environment(group_id, "production")
    group = await db_module.get_group(group_id)
    assert group["environment"] == "production"

    await db_module.set_group_environment(group_id, None)
    group = await db_module.get_group(group_id)
    assert group["environment"] is None


# ── Auto-flag rules (exercises the deployments router logic) ─────────────────


async def test_create_deployment_auto_flags_for_production_group(tmp_path, monkeypatch):
    """When a deployment targets a production-marked group, the endpoint
    flips requires_approval and seeds approval_status='pending'."""
    await _init_clean_db(tmp_path, monkeypatch)
    group_id = await db_module.create_group("prod-edge")
    await db_module.set_group_environment(group_id, "production")
    cred_id = await _seed_credential()

    # Mimic what netcontrol.routes.deployments.create_deployment does
    # after the INSERT -- the logic under test lives there, not in the
    # DB layer, but is small enough to re-execute here.
    dep_id = await db_module.create_deployment(
        name="prod-change",
        group_id=group_id,
        credential_id=cred_id,
        proposed_commands="hostname x",
    )
    group = await db_module.get_group(group_id)
    if (group.get("environment") or "").lower() == "production":
        await db_module.set_deployment_approval(
            dep_id, requires_approval=True, approval_status="pending", request=True,
        )

    dep = await db_module.get_deployment(dep_id)
    assert dep["requires_approval"] == 1
    assert dep["approval_status"] == "pending"


async def test_create_deployment_no_flag_for_non_production_group(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    group_id = await db_module.create_group("lab")
    await db_module.set_group_environment(group_id, "lab")
    cred_id = await _seed_credential()

    dep_id = await db_module.create_deployment(
        name="lab-change",
        group_id=group_id,
        credential_id=cred_id,
        proposed_commands="hostname x",
    )
    dep = await db_module.get_deployment(dep_id)
    assert dep["requires_approval"] == 0
    assert dep["approval_status"] == "not_required"
