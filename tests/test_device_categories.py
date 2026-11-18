"""Device categories (``netcontrol.device_categories``): the ``ups``
category of APC Smart-UPS hosts, from SNMP discovery, host creation, the
category route, the offline viewer and migration 0116."""

from __future__ import annotations

import importlib

import pytest
import routes.database as db
from netcontrol.device_categories import DEVICE_CATEGORIES, device_type_category
from netcontrol.integrations.meraki import unified
from netcontrol.routes.inventory import _VALID_CATEGORIES
from netcontrol.routes.snmp import _infer_device_category

from mcp_helpers import CsrfClient, admin_client

_migration = importlib.import_module("routes.migrations.0116_set_ups_device_category")

# An invented NMC2 card sysDescr (format of docs/apc-ups.md).
UPS_CARD = (
    "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.8.2 PN:apc_hw05_aos_682.bin "
    "AF1:v6.8.2 AN1:apc_hw05_sumx_682.bin MN:AP9631 HR:05 SN: ZA0000000001 MD:01/01/2020)"
)
PDU_CARD = UPS_CARD.replace("apc_hw05_sumx_682", "apc_hw05_rpdu2g_682")


# ── The shared list ──────────────────────────────────────────────────────────


def test_ups_is_a_category_everywhere_categories_are_listed():
    assert "ups" in DEVICE_CATEGORIES
    assert _VALID_CATEGORIES == {*DEVICE_CATEGORIES, ""}
    assert unified._VIEWER_KIND["ups"] == "ups"
    assert device_type_category("apc_ups") == "ups"
    assert device_type_category("cisco_ios") == device_type_category("") == ""


# ── SNMP discovery ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("model", "sys_descr", "device_type", "expected"),
    [
        # A discovered UPS card: its type decides, whatever the text says.
        ("", UPS_CARD, "apc_ups", "ups"),
        ("Smart-UPS SRT 3000", "", "apc_ups", "ups"),
        # A CDP / LLDP neighbor whose platform is a UPS card's sysDescr.
        (UPS_CARD, "", "unknown", "ups"),
        ("", UPS_CARD, "unknown", "ups"),
        # A PDU card is APC too, but not a UPS.
        ("", PDU_CARD, "unknown", ""),
        # Other devices are unchanged.
        ("C9300-48P", "", "cisco_xe", "switch"),
        ("", "", "fortinet", "firewall"),
    ],
)
def test_category_inference(model, sys_descr, device_type, expected):
    assert _infer_device_category(model, sys_descr, device_type) == expected


# ── Host creation and the category route ─────────────────────────────────────


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200):
    assert resp.status_code == status, resp.text
    return resp.json()


def _host_row(admin: CsrfClient, group_id: int, host_id: int) -> dict:
    return next(h for h in _ok(admin.get(f"/api/inventory/{group_id}/hosts")) if h["id"] == host_id)


def test_a_new_ups_host_is_a_ups_with_the_ups_role(admin):
    gid = int(_ok(admin.post("/api/inventory", json={"name": "power"}), 201)["id"])
    body = {"hostname": "ups-a1", "ip_address": "192.0.2.40", "device_type": "apc_ups"}
    ups = int(_ok(admin.post(f"/api/inventory/{gid}/hosts", json=body), 201)["id"])
    body = {"hostname": "sw-a1", "ip_address": "192.0.2.41", "device_type": "cisco_xe"}
    switch = int(_ok(admin.post(f"/api/inventory/{gid}/hosts", json=body), 201)["id"])
    row = _host_row(admin, gid, ups)
    assert row["device_category"] == "ups" and row["role"]["name"] == "UPS"
    assert _host_row(admin, gid, switch)["device_category"] == ""
    # The role can be changed away and back, like any other.
    patch = admin.raw.patch(
        f"/api/hosts/{switch}/category", json={"device_category": "ups"}, headers={"X-CSRF-Token": admin._csrf}
    )
    assert patch.status_code == 200, patch.text
    assert _host_row(admin, gid, switch)["device_category"] == "ups"
    bad = admin.raw.patch(
        f"/api/hosts/{switch}/category", json={"device_category": "battery"}, headers={"X-CSRF-Token": admin._csrf}
    )
    assert bad.status_code == 400


# ── Migration 0116 ───────────────────────────────────────────────────────────


async def _exec(sql: str, params: tuple = ()) -> None:
    conn = await db.get_db()
    try:
        await conn.execute(sql, params)
        await conn.commit()
    finally:
        await conn.close()


async def _run_migration() -> None:
    conn = await db.get_db()
    try:
        await _migration.up(conn)
    finally:
        await conn.close()


async def test_migration_sets_empty_ups_categories_only():
    gid = await db.create_group("power")
    blank = await db.add_host(gid, "ups-b1", "192.0.2.50", "apc_ups")
    chosen = await db.add_host(gid, "ups-b2", "192.0.2.51", "apc_ups")
    other = await db.add_host(gid, "srv-b1", "192.0.2.52", "linux")
    # Hosts as they were before 0116: no category, no role, no UPS role.
    await _exec("UPDATE hosts SET device_category = '', role_id = NULL")
    await _exec("UPDATE hosts SET device_category = 'server' WHERE id = ?", (chosen,))
    await _exec("DELETE FROM device_roles WHERE lower(name) = 'ups'")
    for _ in range(2):
        await _run_migration()
    rows = [await db.get_host(h) for h in (blank, chosen, other)]
    ups_role = [r for r in await db.list_device_roles() if r["name"].lower() == "ups"]
    assert len(ups_role) == 1 and ups_role[0]["color"] == "yellow"
    assert rows[0]["device_category"] == "ups" and rows[0]["role_id"] == ups_role[0]["id"]
    assert rows[1]["device_category"] == "server" and rows[1]["role_id"] is None
    assert rows[2]["device_category"] == "" and rows[2]["role_id"] is None
