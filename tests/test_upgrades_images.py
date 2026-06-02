"""Tests for upgrade software image upload and delete endpoints."""

from __future__ import annotations

import io

import netcontrol.app as app_module
import pytest
import routes.database as db_module
from netcontrol.routes import upgrades


class _AuthClient:
    def __init__(self, client, csrf_token: str):
        self._client = client
        self._csrf = csrf_token

    def _headers(self, extra=None):
        headers = {"X-CSRF-Token": self._csrf}
        if extra:
            headers.update(extra)
        return headers

    def get(self, url, **kw):
        return self._client.get(url, **kw)

    def post(self, url, **kw):
        kw.setdefault("headers", {})
        kw["headers"].update(self._headers())
        return self._client.post(url, **kw)

    def delete(self, url, **kw):
        kw.setdefault("headers", {})
        kw["headers"].update(self._headers())
        return self._client.delete(url, **kw)


@pytest.fixture
def image_client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "upgrade_images.db")
    images_dir = tmp_path / "software_images"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setattr(upgrades, "SOFTWARE_IMAGES_DIR", str(images_dir))
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-upgrades-images")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("APP_ALLOW_SELF_REGISTER", "true")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()

    resp = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "netcontrol",
    })
    csrf_token = resp.json().get("csrf_token", "")
    return _AuthClient(client, csrf_token), images_dir


def test_upload_and_delete_image(image_client):
    client, images_dir = image_client
    payload = b"fake-iosxe-image-bytes"
    resp = client.post(
        "/api/upgrades/images",
        files={"file": ("cat9k_iosxe.17.09.04a.SPA.bin", io.BytesIO(payload), "application/octet-stream")},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["filename"] == "cat9k_iosxe.17.09.04a.SPA.bin"
    assert body["file_size"] == len(payload)
    assert (images_dir / body["filename"]).is_file()

    listed = client.get("/api/upgrades/images")
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    delete_resp = client.delete(f"/api/upgrades/images/{body['id']}")
    assert delete_resp.status_code == 200, delete_resp.text
    assert not (images_dir / body["filename"]).exists()
    assert client.get("/api/upgrades/images").json() == []


def test_upload_rejects_duplicate_filename(image_client):
    client, _images_dir = image_client
    files = {
        "file": ("duplicate.bin", io.BytesIO(b"first"), "application/octet-stream"),
    }
    first = client.post("/api/upgrades/images", files=files)
    assert first.status_code == 200, first.text

    second = client.post(
        "/api/upgrades/images",
        files={"file": ("duplicate.bin", io.BytesIO(b"second"), "application/octet-stream")},
    )
    assert second.status_code == 409, second.text
    assert "already exists" in second.json()["detail"].lower()


def test_upload_rejects_invalid_filename(image_client):
    client, images_dir = image_client
    resp = client.post(
        "/api/upgrades/images",
        files={"file": ("bad name.bin", io.BytesIO(b"x"), "application/octet-stream")},
    )
    assert resp.status_code == 400, resp.text
    assert images_dir.exists() is False or list(images_dir.iterdir()) == []


def test_upload_returns_503_when_storage_not_writable(image_client, monkeypatch):
    client, _images_dir = image_client

    def _fail_verify() -> None:
        raise OSError("permission denied")

    monkeypatch.setattr(upgrades, "_verify_software_images_writable", _fail_verify)
    resp = client.post(
        "/api/upgrades/images",
        files={"file": ("test.bin", io.BytesIO(b"x"), "application/octet-stream")},
    )
    assert resp.status_code == 503, resp.text
    assert "unable to store" in resp.json()["detail"].lower()

