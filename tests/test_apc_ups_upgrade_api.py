"""Upgrades API for APC Smart-UPS: firmware uploads, campaign kinds and the
Logic Reset confirmation. Hosts, names and addresses are invented."""

from __future__ import annotations

import asyncio
import io
import zipfile

import routes.database as db

from test_upgrades_images import image_client  # noqa: F401 - shared fixture


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buf.getvalue()


def _upload(client, name: str, data: bytes):
    return client.post("/api/upgrades/images", files={"file": (name, io.BytesIO(data), "application/octet-stream")})


def test_upload_enc_records_ups_id_and_version(image_client):  # noqa: F811
    client, images_dir = image_client
    resp = _upload(client, "SRT1025UPS_15-0.enc", b"enc-bytes")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body["model_pattern"], body["version"], body["platform"]) == ("1025", "15.0", "apc_ups")
    image = client.get(f"/api/upgrades/images/{body['id']}").json()
    assert "UPS ID 1025" in image["notes"]
    assert (images_dir / "SRT1025UPS_15-0.enc").is_file()


def test_upload_zip_extracts_the_enc(image_client):  # noqa: F811
    client, images_dir = image_client
    data = _zip_bytes({"SRT1025UPS_15-0/SRT1025UPS_15-0.enc": b"enc-bytes", "SRT1025UPS_15-0/readme.txt": b"r"})
    resp = _upload(client, "SRT1025UPS_15-0.zip", data)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["filename"] == "SRT1025UPS_15-0.enc"
    assert body["file_size"] == len(b"enc-bytes")
    assert sorted(p.name for p in images_dir.iterdir()) == ["SRT1025UPS_15-0.enc"]

    # The same .enc again (inside another zip) is a duplicate.
    again = _upload(client, "copy.zip", data)
    assert again.status_code == 409
    assert sorted(p.name for p in images_dir.iterdir()) == ["SRT1025UPS_15-0.enc"]


def test_upload_rejects_bad_ups_files(image_client):  # noqa: F811
    client, images_dir = image_client
    two = _zip_bytes({"SRT1025UPS_15-0.enc": b"a", "SRT1030UPS_16-0.enc": b"b"})
    resp = _upload(client, "bundle.zip", two)
    assert resp.status_code == 400
    assert "more than one .enc" in resp.text
    slip = _zip_bytes({"../../SRT1025UPS_15-0.enc": b"a"})
    assert _upload(client, "slip.zip", slip).status_code == 400
    renamed = _upload(client, "firmware.enc", b"a")
    assert renamed.status_code == 400
    assert list(images_dir.iterdir()) == []
    assert client.get("/api/upgrades/images").json() == []


def _ups_hosts() -> tuple[int, int, int]:
    async def setup() -> tuple[int, int, int]:
        group_id = await db.create_group("ups-upgrade-test")
        ups_a = await db.add_host(group_id, "ups-a.example.com", "192.0.2.21", device_type="apc_ups")
        ups_b = await db.add_host(group_id, "ups-b.example.com", "192.0.2.22", device_type="apc_ups")
        switch = await db.add_host(group_id, "sw-a.example.com", "192.0.2.23", device_type="cisco_xe")
        return ups_a, ups_b, switch

    return asyncio.run(setup())


def _campaign(client, host_ids: list[int], ad_hoc: list[str] | None = None):
    return client.post(
        "/api/upgrades/campaigns",
        json={
            "name": "UPS firmware",
            "image_map": {"1227": "SRTL1227UPS_01-2.enc"},
            "host_ids": host_ids,
            "ad_hoc_ips": ad_hoc or [],
        },
    )


def test_campaign_holds_one_kind_of_device(image_client):  # noqa: F811
    client, _ = image_client
    ups_a, _ups_b, switch = _ups_hosts()
    mixed = _campaign(client, [ups_a, switch])
    assert mixed.status_code == 400
    assert "not both" in mixed.text
    assert _campaign(client, [ups_a], ["198.51.100.30"]).status_code == 400
    ok = _campaign(client, [ups_a])
    assert ok.status_code == 200, ok.text

    # Editing a UPS campaign to add a switch is refused the same way.
    edit = client._client.patch(
        f"/api/upgrades/campaigns/{ok.json()['id']}",
        headers=client._headers(),
        json={"name": "UPS firmware", "image_map": {}, "host_ids": [ups_a, switch], "ad_hoc_ips": []},
    )
    assert edit.status_code == 400


def test_logic_reset_confirmation(image_client):  # noqa: F811
    client, _ = image_client
    ups_a, ups_b, _switch = _ups_hosts()
    created = _campaign(client, [ups_a, ups_b])
    assert created.status_code == 200, created.text
    campaign_id = created.json()["id"]
    devices = {d["host_id"]: d for d in client.get(f"/api/upgrades/campaigns/{campaign_id}").json()["devices"]}
    waiting, other = devices[ups_a], devices[ups_b]

    async def mark() -> None:
        await db.update_upgrade_device(
            waiting["id"], ups_id="1227", prestage_status="waiting", phase="awaiting_logic_reset"
        )
        await db.update_upgrade_device(other["id"], ups_id="1025", prestage_status="completed")

    asyncio.run(mark())

    url = f"/api/upgrades/campaigns/{campaign_id}/devices/{{}}/logic-reset-confirm"
    resp = client.post(url.format(waiting["id"]))
    assert resp.status_code == 200, resp.text
    assert resp.json()["confirmed_by"] == "admin"

    stored = asyncio.run(db.get_upgrade_device(waiting["id"]))
    assert stored is not None
    assert stored["logic_reset_confirmed_by"] == "admin"
    assert stored["logic_reset_confirmed_at"]
    assert stored["prestage_status"] == "completed"

    assert client.post(url.format(other["id"])).status_code == 400
    assert client.post(url.format(999999)).status_code == 404
    events = asyncio.run(db.get_audit_events(limit=20))
    assert any(e.get("action") == "logic_reset_confirm" for e in events)
