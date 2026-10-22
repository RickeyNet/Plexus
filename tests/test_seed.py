"""The demo seed runs once per database (``routes.seed``)."""

from __future__ import annotations

import asyncio

import routes.database as db_module
from routes.seed import SEED_MARKER, database_is_fresh, seed


async def _count(table: str) -> int:
    db = await db_module.get_db(read_only=True)
    try:
        return (await (await db.execute(f"SELECT COUNT(*) FROM {table}")).fetchone())[0]  # noqa: S608 - fixed names
    finally:
        await db.close()


async def _delete_demo_groups() -> None:
    db = await db_module.get_db()
    try:
        await db.execute("DELETE FROM hosts")
        await db.execute("DELETE FROM inventory_groups")
        await db.commit()
    finally:
        await db.close()


def test_seed_runs_once_and_not_again_after_the_demo_groups_are_deleted(monkeypatch, capsys):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-seed")

    async def _run():
        await db_module.init_db()
        assert await database_is_fresh()
        await seed()
        assert await db_module.get_auth_setting(SEED_MARKER)
        groups = await _count("inventory_groups")
        playbooks = await _count("playbooks")
        assert groups and playbooks
        assert not await database_is_fresh()

        # The second run is a no-op on a seeded database.
        await seed()
        assert await _count("inventory_groups") == groups
        assert await _count("playbooks") == playbooks

        # Deleting the demo groups does not make the database fresh again.
        await _delete_demo_groups()
        assert await _count("inventory_groups") == 0
        assert not await database_is_fresh()
        await seed()
        assert await _count("inventory_groups") == 0
        return groups, playbooks

    asyncio.run(_run())
    out = capsys.readouterr().out
    assert out.count("[seed] Populating database ...") == 1
    assert out.count("[seed] Database already has data - skipping.") == 2


def test_a_database_seeded_before_the_marker_is_not_fresh(monkeypatch):
    """A database from an earlier version has playbooks but no marker: not fresh."""
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-seed")

    async def _run():
        await db_module.init_db()
        await seed()
        db = await db_module.get_db()
        try:
            await db.execute("DELETE FROM auth_settings WHERE key = ?", (SEED_MARKER,))
            await db.commit()
        finally:
            await db.close()
        await _delete_demo_groups()
        assert not await db_module.get_auth_setting(SEED_MARKER)
        assert not await database_is_fresh()

    asyncio.run(_run())
