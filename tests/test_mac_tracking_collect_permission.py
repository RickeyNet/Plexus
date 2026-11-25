"""Starting a MAC/ARP collection logs in to switches with the service
credential, so ``POST /api/mac-tracking/collect`` needs ``inventory.write``;
the read-only ``mac-tracking`` feature still shows the tables."""

from __future__ import annotations

from netcontrol.routes import mac_tracking

from mcp_helpers import admin_client, user_client


def test_read_only_user_cannot_start_a_collection(monkeypatch, request):
    started: list[int] = []

    async def fake_collect(host_id, *args, **kwargs):
        started.append(host_id)
        return {"errors": []}

    monkeypatch.setattr(mac_tracking, "collect_mac_arp_tables", fake_collect)
    admin = admin_client(monkeypatch, request)
    reader = user_client(admin, "mac-reader", features=["mac-tracking", "inventory"])

    assert reader.get("/api/mac-tracking/stats").status_code == 200
    for url in ("/api/mac-tracking/collect", "/api/mac-tracking/collect?host_id=1"):
        resp = reader.post(url)
        assert resp.status_code == 403, resp.text
        assert "inventory.write" in resp.text
    assert started == []


def test_inventory_writer_passes_the_gate(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    writer = user_client(admin, "mac-writer", features=["mac-tracking", "inventory", "inventory.write"])
    # Past the permission check: an unknown host is the next answer.
    resp = writer.post("/api/mac-tracking/collect?host_id=987654")
    assert resp.status_code == 404, resp.text
