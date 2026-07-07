"""Regression test for the execute_deployment TOCTOU.

Two concurrent /execute calls previously both read status='planning' and both
pushed commands to the devices. claim_deployment_for_execute atomically flips
planning/failed -> pre-check; only the first caller wins.
"""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db_module


@pytest.fixture
def dep_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "toctou.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-toctou")
    asyncio.run(db_module.init_db())
    return db_path


async def _make_deployment(status: str = "planning") -> int:
    db = await db_module.get_db()
    try:
        cur = await db.execute("INSERT INTO inventory_groups (name) VALUES ('g')")
        gid = int(cur.lastrowid)
        cur = await db.execute(
            "INSERT INTO credentials (name, username, password) VALUES ('c', 'u', 'p')"
        )
        cid = int(cur.lastrowid)
        await db.commit()
    finally:
        await db.close()
    dep_id = await db_module.create_deployment(
        name="d", group_id=gid, credential_id=cid, proposed_commands="show ver",
    )
    if status != "planning":
        await db_module.update_deployment_status(dep_id, status)
    return dep_id


def test_first_claim_wins_second_loses(dep_db):
    async def _go():
        dep_id = await _make_deployment()
        first = await db_module.claim_deployment_for_execute(dep_id)
        second = await db_module.claim_deployment_for_execute(dep_id)
        assert first is True
        assert second is False
        dep = await db_module.get_deployment(dep_id)
        assert dep["status"] == "pre-check"

    asyncio.run(_go())


def test_failed_deployment_can_be_claimed(dep_db):
    async def _go():
        dep_id = await _make_deployment(status="failed")
        assert await db_module.claim_deployment_for_execute(dep_id) is True

    asyncio.run(_go())


def test_completed_deployment_cannot_be_claimed(dep_db):
    async def _go():
        dep_id = await _make_deployment(status="completed")
        assert await db_module.claim_deployment_for_execute(dep_id) is False

    asyncio.run(_go())
