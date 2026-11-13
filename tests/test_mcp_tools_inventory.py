"""MCP inventory tools: ``list_groups``, ``search_hosts``, ``get_host``."""

from __future__ import annotations

import pytest
import routes.database as db
from netcontrol.mcp import registry

from mcp_helpers import call, db_ctx


@pytest.fixture(autouse=True)
def _tools():
    registry.load_tools()


async def _seed() -> dict[str, int]:
    campus = await db.create_group("Campus", "Main campus")
    core = await db.create_group("Core", "Campus core", parent_id=campus)
    branch = await db.create_group("Branch", "Branch offices")
    ids = {
        "core1": await db.add_host(core, "core-sw-01", "192.0.2.1", "cisco_ios"),
        "core2": await db.add_host(core, "core-sw-02", "192.0.2.2", "cisco_nxos"),
        "branch_dup": await db.add_host(branch, "core-sw-01", "198.51.100.1", "arista_eos"),
        "edge": await db.add_host(branch, "edge-fw-01", "198.51.100.254", "paloalto_panos"),
    }
    await db.update_host_device_info(ids["core1"], "C9300-48P", "17.9.4", "switch")
    await db.set_host_ip_aliases(ids["edge"], "198.51.100.254", ["203.0.113.7"])
    return ids


async def test_list_groups():
    await _seed()
    data, is_error = await call(await db_ctx(), "list_groups")
    assert is_error is False
    by_name = {g["name"]: g for g in data["items"]}
    assert by_name["Core"]["host_count"] == 2 and by_name["Core"]["parent"] == "Campus"
    assert by_name["Campus"]["parent"] is None and by_name["Branch"]["host_count"] == 2


async def test_search_by_name_ip_vendor():
    ids = await _seed()
    ctx = await db_ctx()
    data, _ = await call(ctx, "search_hosts", {"query": "core-sw"})
    assert {h["id"] for h in data["items"]} == {ids["core1"], ids["core2"], ids["branch_dup"]}
    row = next(h for h in data["items"] if h["id"] == ids["core1"])
    assert row["hostname"] == "core-sw-01" and row["ip_address"] == "192.0.2.1"
    assert row["device_type"] == "cisco_ios" and row["model"] == "C9300-48P"
    assert row["group"] == "Campus / Core" and row["source"] == "inventory"

    data, _ = await call(ctx, "search_hosts", {"query": "198.51.100.254"})
    assert [h["id"] for h in data["items"]] == [ids["edge"]]
    data, _ = await call(ctx, "search_hosts", {"query": "203.0.113.7"})
    assert [h["id"] for h in data["items"]] == [ids["edge"]]
    data, _ = await call(ctx, "search_hosts", {"vendor": "cisco"})
    assert {h["id"] for h in data["items"]} == {ids["core1"], ids["core2"]}
    data, _ = await call(ctx, "search_hosts", {"group": "branch", "vendor": "arista"})
    assert [h["id"] for h in data["items"]] == [ids["branch_dup"]]
    data, _ = await call(ctx, "search_hosts", {"query": "C9300"})
    assert [h["id"] for h in data["items"]] == [ids["core1"]]
    data, _ = await call(ctx, "search_hosts", {})
    assert data["total"] == 4
    data, _ = await call(ctx, "search_hosts", {"limit": 1})
    assert len(data["items"]) == 1 and data["next_cursor"] == "1"
    data, _ = await call(ctx, "search_hosts", {"query": "no-such-device"})
    assert data["items"] == [] and data["total"] == 0


async def test_get_host_by_each_reference_form():
    ids = await _seed()
    ctx = await db_ctx()
    for ref in (str(ids["edge"]), "edge-fw-01", "EDGE-FW-01", "198.51.100.254", "203.0.113.7", "edge-fw"):
        data, is_error = await call(ctx, "get_host", {"host": ref})
        assert is_error is False, (ref, data)
        assert data["id"] == ids["edge"] and data["hostname"] == "edge-fw-01"
        assert data["alias_addresses"] == ["203.0.113.7"]
        assert data["group"] == "Branch"
    data, _ = await call(ctx, "get_host", {"host": "core-sw-02"})
    assert data["id"] == ids["core2"] and data["alias_addresses"] == []


async def test_ambiguous_host_lists_candidates():
    ids = await _seed()
    text, is_error = await call(await db_ctx(), "get_host", {"host": "core-sw-01"})
    assert is_error is True
    assert f"id {ids['core1']}" in text and f"id {ids['branch_dup']}" in text
    assert "192.0.2.1" in text and "198.51.100.1" in text
    assert "Campus / Core" in text and "Branch" in text


async def test_partial_name_multiple_matches_lists_candidates():
    ids = await _seed()
    text, is_error = await call(await db_ctx(), "get_host", {"host": "core-sw"})
    assert is_error is True
    assert all(f"id {ids[key]}" in text for key in ("core1", "core2", "branch_dup"))
    assert "edge-fw-01" not in text


async def test_candidate_list_is_capped():
    group = await db.create_group("Access", "")
    for n in range(15):
        await db.add_host(group, f"access-sw-{n:02d}", f"192.0.2.{100 + n}")
    text, is_error = await call(await db_ctx(), "get_host", {"host": "access-sw"})
    assert is_error is True
    assert text.count("access-sw-") == 10 and "15 hosts match" in text


async def test_no_match_suggests_search_hosts():
    await _seed()
    ctx = await db_ctx()
    for ref in ("nothing-here", "203.0.113.200", "999999"):
        text, is_error = await call(ctx, "get_host", {"host": ref})
        assert is_error is True
        assert text == f"No host matches '{ref}'. Try search_hosts."


async def test_host_rows_have_no_credential_fields():
    await _seed()
    ctx = await db_ctx()
    listed, _ = await call(ctx, "search_hosts", {})
    one, _ = await call(ctx, "get_host", {"host": "edge-fw-01"})
    for row in [*listed["items"], one]:
        for key in row:
            assert not any(word in key.lower() for word in ("password", "credential", "secret", "community"))


async def test_hidden_without_category():
    await _seed()
    ctx = await db_ctx(categories=["configs"])
    for name in ("list_groups", "search_hosts", "get_host"):
        text, is_error = await call(ctx, name, {"host": "x"} if name == "get_host" else {})
        assert (text, is_error) == (f"Unknown tool: {name}", True)
    limited = await db_ctx(categories=["inventory"], admin=False, features=["topology"], name="no-inventory")
    assert (await call(limited, "list_groups"))[1] is True


@pytest.mark.parametrize(
    ("categories", "has_devices", "has_sources"),
    [
        (["configs"], False, False),
        (["audit"], False, False),
        (["inventory"], True, True),
        (["monitoring"], False, True),
        (["topology"], False, True),
    ],
)
async def test_overview_reports_only_on_usable_categories(categories, has_devices, has_sources):
    await _seed()
    data, is_error = await call(await db_ctx(categories=categories), "plexus_overview")
    assert is_error is False and data["categories"] == categories
    assert ("devices" in data) is has_devices
    assert ("sources" in data) is has_sources


async def test_overview_is_empty_when_the_owner_lost_every_feature():
    await _seed()
    ctx = await db_ctx(categories=["inventory", "topology"], admin=False, features=[], name="no-features")
    data, _ = await call(ctx, "plexus_overview")
    assert data == {"categories": []}
