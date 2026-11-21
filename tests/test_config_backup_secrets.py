"""Config backups hold device secrets. A read-only ``config-backups`` user
gets the view, diff and search with the secrets masked
(``netcontrol.mcp.redact``) and no raw download; ``config-backups.write``
or an admin sees and downloads the backup as captured. Invented data only."""

from __future__ import annotations

import io
import zipfile

import pytest
import routes.database as db

from mcp_helpers import admin_client, user_client

SECRET = "Sup3rS3cret-community"
OLD = f"hostname edge-sw1\nsnmp-server community {SECRET} RO\nusername netops secret 0 OldPass-123\n"
NEW = f"hostname edge-sw1\nsnmp-server community {SECRET} RO\nusername netops secret 0 NewPass-456\n"


@pytest.fixture
def setup(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    group = admin.post("/api/inventory", json={"name": "lab"})
    assert group.status_code == 201, group.text
    host = admin.post(
        f"/api/inventory/{group.json()['id']}/hosts",
        json={"hostname": "edge-sw1", "ip_address": "192.0.2.40", "device_type": "cisco_ios"},
    )
    assert host.status_code == 201, host.text
    host_id = int(host.json()["id"])
    reader = user_client(admin, "backup-reader", features=["config-backups"])
    writer = user_client(admin, "backup-writer", features=["config-backups", "config-backups.write"])
    return admin, reader, writer, host_id


async def _backups(host_id: int) -> tuple[int, int]:
    first = await db.create_config_backup(None, host_id, OLD, capture_method="manual")
    second = await db.create_config_backup(None, host_id, NEW, capture_method="manual")
    return first, second


def _no_secret(text: str) -> None:
    assert SECRET not in text and "OldPass-123" not in text and "NewPass-456" not in text


@pytest.mark.asyncio
async def test_read_only_user_sees_masked_text_and_cannot_download(setup):
    admin, reader, _writer, host_id = setup
    _first, second = await _backups(host_id)

    detail = reader.get(f"/api/config-backups/{second}")
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["secrets_masked"] is True
    assert "snmp-server community ******** RO" in body["config_text"]
    assert "hostname edge-sw1" in body["config_text"]
    _no_secret(detail.text)

    diff = reader.get(f"/api/config-backups/{second}/diff")
    assert diff.status_code == 200, diff.text
    assert diff.json()["secrets_masked"] is True
    _no_secret(diff.text)
    # Only the password changed: both sides mask it the same way, so a
    # read-only user sees no change (and never either value).
    assert diff.json()["diff_lines_added"] == 0

    found = reader.get("/api/config-backups/search", params={"q": "community", "mode": "substring"})
    assert found.status_code == 200, found.text
    assert found.json()["results"] and all(r["secrets_masked"] for r in found.json()["results"])
    _no_secret(found.text)
    # A search that only matched the secret value is dropped.
    guess = reader.get("/api/config-backups/search", params={"q": SECRET, "mode": "substring"})
    assert guess.json()["results"] == []

    for url in (f"/api/config-backups/{second}/download", "/api/config-backups/download"):
        resp = reader.get(url)
        assert resp.status_code == 403, url
        assert "config-backups.write" in resp.json()["error"]["message"]
        _no_secret(resp.text)


@pytest.mark.asyncio
async def test_writer_and_admin_see_and_download_the_raw_backup(setup):
    admin, _reader, writer, host_id = setup
    _first, second = await _backups(host_id)

    for client in (writer, admin):
        detail = client.get(f"/api/config-backups/{second}").json()
        assert SECRET in detail["config_text"] and not detail.get("secrets_masked")
        assert "NewPass-456" in client.get(f"/api/config-backups/{second}/diff").text
        single = client.get(f"/api/config-backups/{second}/download")
        assert single.status_code == 200 and SECRET in single.text
        bulk = client.get("/api/config-backups/download")
        assert bulk.status_code == 200, bulk.text
        with zipfile.ZipFile(io.BytesIO(bulk.content)) as zf:
            assert any(SECRET in zf.read(name).decode() for name in zf.namelist())
        hits = client.get("/api/config-backups/search", params={"q": SECRET, "mode": "substring"}).json()
        assert hits["results"] and not any(r.get("secrets_masked") for r in hits["results"])
