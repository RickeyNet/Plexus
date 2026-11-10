"""HTTP tests for editing graph templates, their items and graph tree nodes.

Covers the guards the edit UI relies on:
  * items of a built-in template cannot be added, changed or removed
  * an item is only reachable through the template that owns it
  * a tree node is only reachable through its own tree
  * a node update clears a link on an explicit null and leaves omitted
    fields alone
  * a node cannot be parented outside its tree or under its own children
"""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import pytest
import routes.db.graphs as graphs


@pytest.fixture
def api(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-graph-templates")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    client.headers["X-CSRF-Token"] = resp.json().get("csrf_token", "")
    return client


def _new_template(api, name: str = "custom-cpu") -> int:
    resp = api.post("/api/graph-templates", json={"name": name})
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _new_tree(api, name: str = "sites") -> int:
    resp = api.post("/api/graph-trees", json={"name": name})
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _new_node(api, tree_id: int, **body) -> dict:
    resp = api.post(f"/api/graph-trees/{tree_id}/nodes", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ── Template items ───────────────────────────────────────────────────────────


def test_template_and_item_edit_round_trip(api):
    tid = _new_template(api)

    resp = api.put(f"/api/graph-templates/{tid}", json={"name": "custom-cpu-2", "stacked": True, "grid_w": 12})
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "custom-cpu-2"
    assert resp.json()["grid_w"] == 12

    resp = api.post(f"/api/graph-templates/{tid}/items", json={"metric_name": "cpu_percent", "label": "CPU"})
    assert resp.status_code == 201, resp.text
    item_id = resp.json()["id"]

    resp = api.put(f"/api/graph-templates/{tid}/items/{item_id}", json={"label": "CPU %", "color": "#336699"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["label"] == "CPU %"
    assert resp.json()["metric_name"] == "cpu_percent"

    # An empty body is a no-op, not a 404.
    resp = api.put(f"/api/graph-templates/{tid}/items/{item_id}", json={})
    assert resp.status_code == 200, resp.text
    assert resp.json()["label"] == "CPU %"

    assert api.delete(f"/api/graph-templates/{tid}/items/{item_id}").status_code == 200
    assert api.get(f"/api/graph-templates/{tid}").json()["items"] == []


def test_built_in_template_items_are_read_only(api):
    async def _seed() -> tuple[int, int]:
        tpl = await graphs.create_graph_template(name="shipped", built_in=True)
        item = await graphs.create_graph_template_item(tpl["id"], metric_name="cpu_percent", label="CPU")
        return tpl["id"], item["id"]

    tid, item_id = asyncio.run(_seed())

    assert api.post(f"/api/graph-templates/{tid}/items", json={"label": "x"}).status_code == 403
    assert api.put(f"/api/graph-templates/{tid}/items/{item_id}", json={"label": "x"}).status_code == 403
    assert api.delete(f"/api/graph-templates/{tid}/items/{item_id}").status_code == 403
    items = api.get(f"/api/graph-templates/{tid}").json()["items"]
    assert [i["label"] for i in items] == ["CPU"]


def test_item_is_scoped_to_its_template(api):
    owner = _new_template(api, "owner")
    other = _new_template(api, "other")
    item_id = api.post(f"/api/graph-templates/{owner}/items", json={"label": "keep"}).json()["id"]

    assert api.put(f"/api/graph-templates/{other}/items/{item_id}", json={"label": "x"}).status_code == 404
    assert api.delete(f"/api/graph-templates/{other}/items/{item_id}").status_code == 404
    assert api.put(f"/api/graph-templates/999999/items/{item_id}", json={"label": "x"}).status_code == 404
    assert api.get(f"/api/graph-templates/{owner}").json()["items"][0]["label"] == "keep"


# ── Host template links ──────────────────────────────────────────────────────


def test_host_template_link_and_unlink(api):
    tid = _new_template(api)
    resp = api.post("/api/host-templates", json={"name": "link-test-routers","device_types": '["cisco_ios"]'})
    assert resp.status_code == 201, resp.text
    hid = resp.json()["id"]

    assert api.post(f"/api/host-templates/{hid}/graph-templates/{tid}").status_code == 201
    # Linking twice is idempotent.
    assert api.post(f"/api/host-templates/{hid}/graph-templates/{tid}").status_code == 201
    linked = api.get(f"/api/host-templates/{hid}").json()["graph_templates"]
    assert [g["id"] for g in linked] == [tid]

    assert api.delete(f"/api/host-templates/{hid}/graph-templates/{tid}").status_code == 200
    assert api.delete(f"/api/host-templates/{hid}/graph-templates/{tid}").status_code == 404
    assert api.get(f"/api/host-templates/{hid}").json()["graph_templates"] == []


# ── Tree nodes ───────────────────────────────────────────────────────────────


def test_node_update_clears_on_null_and_keeps_omitted_fields(api):
    tree = _new_tree(api)
    root = _new_node(api, tree, title="Site A")
    child = _new_node(api, tree, title="Core", parent_node_id=root["id"], sort_order=5)
    assert child["parent_node_id"] == root["id"]

    resp = api.put(f"/api/graph-trees/{tree}/nodes/{child['id']}", json={"title": "Core switches"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["title"] == "Core switches"
    assert resp.json()["parent_node_id"] == root["id"]
    assert resp.json()["sort_order"] == 5

    resp = api.put(f"/api/graph-trees/{tree}/nodes/{child['id']}", json={"parent_node_id": None})
    assert resp.status_code == 200, resp.text
    assert resp.json()["parent_node_id"] is None
    assert resp.json()["title"] == "Core switches"

    # A null for a NOT NULL column is ignored rather than written.
    resp = api.put(f"/api/graph-trees/{tree}/nodes/{child['id']}", json={"title": None, "node_type": None})
    assert resp.status_code == 200, resp.text
    assert resp.json()["title"] == "Core switches"
    assert resp.json()["node_type"] == "header"


def test_node_parent_must_be_in_tree_and_acyclic(api):
    tree = _new_tree(api, "one")
    other_tree = _new_tree(api, "two")
    a = _new_node(api, tree, title="a")
    b = _new_node(api, tree, title="b", parent_node_id=a["id"])
    c = _new_node(api, tree, title="c", parent_node_id=b["id"])
    foreign = _new_node(api, other_tree, title="foreign")

    def put(node, parent):
        return api.put(f"/api/graph-trees/{tree}/nodes/{node['id']}", json={"parent_node_id": parent})

    assert put(a, a["id"]).status_code == 400  # itself
    assert put(a, c["id"]).status_code == 400  # its own grandchild
    assert put(a, foreign["id"]).status_code == 400  # another tree
    resp = api.post(f"/api/graph-trees/{tree}/nodes", json={"title": "x", "parent_node_id": foreign["id"]})
    assert resp.status_code == 400
    assert put(c, a["id"]).status_code == 200  # a legal move

    nodes = {n["id"]: n for n in api.get(f"/api/graph-trees/{tree}").json()["nodes"]}
    assert nodes[a["id"]]["parent_node_id"] is None
    assert nodes[c["id"]]["parent_node_id"] == a["id"]


def test_node_is_scoped_to_its_tree(api):
    tree = _new_tree(api, "one")
    other_tree = _new_tree(api, "two")
    node = _new_node(api, tree, title="keep")

    assert api.put(f"/api/graph-trees/{other_tree}/nodes/{node['id']}", json={"title": "x"}).status_code == 404
    assert api.delete(f"/api/graph-trees/{other_tree}/nodes/{node['id']}").status_code == 404
    assert api.delete(f"/api/graph-trees/999999/nodes/{node['id']}").status_code == 404
    assert [n["title"] for n in api.get(f"/api/graph-trees/{tree}").json()["nodes"]] == ["keep"]

    assert api.delete(f"/api/graph-trees/{tree}/nodes/{node['id']}").status_code == 200
    assert api.get(f"/api/graph-trees/{tree}").json()["nodes"] == []
