"""INSERT OR IGNORE helpers in routes/db/graphs.py must not trust lastrowid.

After an ignored insert SQLite leaves ``cursor.lastrowid`` at the
connection's previous insert id, so a helper that branches on it alone
returns (or reports as "created") a row that belongs to someone else.
Postgres returns None, so these tests pass trivially there; on SQLite they
fail without the rowcount guard.
"""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db_module
import routes.db.graphs as graphs


@pytest.fixture
def graph_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "graphs.db"))
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-graphs")
    asyncio.run(db_module.init_db())


async def _make_hosts(n: int) -> list[int]:
    db = await db_module.get_db()
    try:
        cur = await db.execute("INSERT OR IGNORE INTO inventory_groups (name) VALUES (?)", ("graphs-test",))
        if cur.rowcount > 0 and cur.lastrowid:
            gid = int(cur.lastrowid)
        else:
            row = await (
                await db.execute("SELECT id FROM inventory_groups WHERE name = ?", ("graphs-test",))
            ).fetchone()
            gid = int(row[0])
        ids = []
        for i in range(n):
            cur = await db.execute(
                "INSERT INTO hosts (id, group_id, hostname, ip_address) VALUES (?, ?, ?, ?)",
                (9100 + i, gid, f"graphs-host-{i}", f"10.99.0.{i + 1}"),
            )
            ids.append(9100 + i)
        await db.commit()
        return ids
    finally:
        await db.close()


def test_create_host_graph_returns_existing_row_after_ignored_insert(graph_db):
    async def _run():
        host_a, host_b = await _make_hosts(2)
        tpl = await graphs.create_graph_template(name="cpu", scope="device")
        first = await graphs.create_host_graph(host_a, tpl["id"], title="first")
        # A later insert on the same connection makes SQLite's lastrowid stale.
        other = await graphs.create_host_graph(host_b, tpl["id"], title="other")
        assert other["id"] != first["id"]
        again = await graphs.create_host_graph(host_a, tpl["id"], title="ignored")
        return first, again

    first, again = asyncio.run(_run())
    assert again["id"] == first["id"]
    assert again["title"] == "first"


def test_create_data_source_profile_returns_existing_row_after_ignored_insert(graph_db):
    async def _run():
        host_a, host_b = await _make_hosts(2)
        first = await graphs.create_data_source_profile(host_a, profile_name="p", poll_interval=60)
        await graphs.create_data_source_profile(host_b, profile_name="p", poll_interval=120)
        again = await graphs.create_data_source_profile(host_a, profile_name="p", poll_interval=999)
        return first, again

    first, again = asyncio.run(_run())
    assert again["id"] == first["id"]
    assert again["poll_interval"] == 60


def test_apply_interface_graph_templates_reports_only_new_rows(graph_db):
    async def _run():
        (host_a,) = await _make_hosts(1)
        await graphs.create_graph_template(name="if-traffic", scope="interface", title_format="$interface")
        ifaces = [{"if_index": "1", "if_name": "Gi0/1"}, {"if_index": "2", "if_name": "Gi0/2"}]
        created = await graphs.apply_interface_graph_templates_to_host(host_a, ifaces)
        repeat = await graphs.apply_interface_graph_templates_to_host(host_a, ifaces)
        return created, repeat

    created, repeat = asyncio.run(_run())
    assert len(created) == 2
    assert repeat == []
