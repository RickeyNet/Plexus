"""Dashboard panel edits stay inside the dashboard named in the URL
(``netcontrol.routes.dashboards``, ``routes.db.metrics``): the owner check
runs on that dashboard, so a panel id from another dashboard must miss."""

from __future__ import annotations

import pytest
import routes.database as db

from mcp_helpers import CsrfClient, admin_client


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


async def _two_dashboards() -> tuple[dict, dict, dict]:
    mine = await db.create_dashboard("Mine", owner="admin")
    theirs = await db.create_dashboard("Theirs", owner="someone-else")
    panel = await db.create_dashboard_panel(theirs["id"], title="Their panel")
    return mine, theirs, panel


async def test_a_panel_of_another_dashboard_is_not_updated_or_deleted() -> None:
    mine, theirs, panel = await _two_dashboards()
    assert await db.update_dashboard_panel(mine["id"], panel["id"], title="Hijacked") is None
    assert await db.delete_dashboard_panel(mine["id"], panel["id"]) is False
    [kept] = (await db.get_dashboard(theirs["id"]))["panels"]
    assert kept["title"] == "Their panel"


async def test_a_panel_of_its_own_dashboard_is_updated_and_deleted() -> None:
    _, theirs, panel = await _two_dashboards()
    updated = await db.update_dashboard_panel(theirs["id"], panel["id"], title="Renamed")
    assert updated is not None and updated["title"] == "Renamed"
    assert await db.delete_dashboard_panel(theirs["id"], panel["id"]) is True
    assert (await db.get_dashboard(theirs["id"]))["panels"] == []


def test_the_api_answers_404_for_a_panel_of_another_dashboard(admin) -> None:
    mine = admin.post("/api/dashboards", json={"name": "Mine"}).json()
    other = admin.post("/api/dashboards", json={"name": "Other"}).json()
    panel = admin.post(f"/api/dashboards/{other['id']}/panels", json={"title": "Other panel"}).json()
    url = f"/api/dashboards/{mine['id']}/panels/{panel['id']}"
    assert admin.put(url, json={"title": "Hijacked"}).status_code == 404
    assert admin.delete(url).status_code == 404
    assert admin.get(f"/api/dashboards/{other['id']}").json()["panels"][0]["title"] == "Other panel"


def test_a_new_dashboard_belongs_to_its_creator(admin) -> None:
    """The owner is the session user (it used to be stored empty, which
    locked the creator out of their own dashboard)."""
    from mcp_helpers import user_client

    creator = user_client(admin, "dash-creator", features=["dashboard"])
    created = creator.post("/api/dashboards", json={"name": "Creator board"})
    assert created.status_code == 201, created.text
    assert created.json()["owner"] == "dash-creator"
    assert creator.get(f"/api/dashboards/{created.json()['id']}").status_code == 200
    assert [d["name"] for d in creator.get("/api/dashboards").json()["dashboards"]] == ["Creator board"]

    stranger = user_client(admin, "dash-stranger", features=["dashboard"])
    assert stranger.get(f"/api/dashboards/{created.json()['id']}").status_code == 403
    assert admin.get(f"/api/dashboards/{created.json()['id']}").status_code == 200
