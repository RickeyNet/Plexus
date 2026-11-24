"""The "address changed, enter the secret again" rule
(``secret_fields.refuse_secret_reuse``) on every update path that keeps a
stored secret when the form sends it blank or masked: topology sources,
notification channels, SIEM sinks, event webhooks, IPAM sources, DHCP
servers and the RADIUS / TACACS+ / LDAP / OIDC settings (federation peers:
test_federation_outbound.py).

Without it, an admin who may edit an integration but not read its secret
could point it at a host they control and have Plexus present the secret.
Every name and address here is invented; nothing is contacted."""

from __future__ import annotations

import pytest
from netcontrol.secret_fields import SECRET_MASK, compared_tls_verify, url_origin

from mcp_helpers import CsrfClient, admin_client


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _refused(resp, *words: str) -> None:
    assert resp.status_code == 400, resp.text
    message = resp.json()["error"]["message"]
    assert "cannot be reused" in message, message
    for word in words:
        assert word in message, message


def test_url_origin_and_tls_comparison():
    assert url_origin("https://Hooks.Example.com/a/b?x=1") == "https://hooks.example.com:443"
    assert url_origin("https://hooks.example.com:443/other") == url_origin("https://hooks.example.com")
    assert url_origin("http://hooks.example.com") != url_origin("https://hooks.example.com")
    assert url_origin("https://[2001:db8::1]:8443/") == "https://2001:db8::1:8443"
    assert url_origin("") == ""
    # Turning verification off is a change; turning it on is not.
    assert compared_tls_verify(True, False) is False
    assert compared_tls_verify(False, True) is False
    assert compared_tls_verify(True, True) is True


def test_topology_source_key_needs_reentry_for_a_new_address(admin):
    created = admin.post(
        "/api/sources",
        json={
            "name": "Edge firewall",
            "provider": "opnsense",
            "org_id": "local",
            "base_url": "https://192.0.2.1:8443",
            "api_key": "key-value:secret-value",
        },
    )
    assert created.status_code == 201, created.text
    url = f"/api/sources/{created.json()['org']['id']}"

    # Same address, other settings: the key is kept.
    assert admin.put(url, json={"name": "Edge firewall 2", "base_url": "https://192.0.2.1:8443/"}).status_code == 200
    _refused(admin.put(url, json={"base_url": "https://203.0.113.9:8443"}), "API key")
    _refused(admin.put(url, json={"options": {"verify_tls": False}}), "verify_tls")
    moved = admin.put(url, json={"base_url": "https://203.0.113.9:8443", "api_key": "key-2:secret-2"})
    assert moved.status_code == 200, moved.text
    assert "secret-2" not in moved.text


def _channel(admin, **extra) -> dict:
    body = {
        "name": "ops hook",
        "type": "webhook",
        "webhook_url": "https://hooks.example.com/in",
        "webhook_auth_header": "Authorization",
        "webhook_auth_value": "Bearer channel-token",
        **extra,
    }
    resp = admin.post("/api/admin/notification-channels", json=body)
    assert resp.status_code == 200, resp.text
    return {**body, **resp.json()}


def test_notification_channel_secret_needs_reentry_for_a_new_address(admin):
    channel = _channel(admin)
    url = f"/api/admin/notification-channels/{channel['id']}"
    masked = {**channel, "webhook_auth_value": SECRET_MASK}

    assert admin.put(url, json={**masked, "webhook_url": "https://hooks.example.com/other-path"}).status_code == 200
    _refused(admin.put(url, json={**masked, "webhook_url": "https://collector.example.net/in"}), "webhook_auth_value")
    _refused(admin.put(url, json={**masked, "verify_tls": False}), "verify_tls")
    # Sending the value again is allowed.
    resent = {**channel, "webhook_url": "https://collector.example.net/in", "webhook_auth_value": "Bearer new"}
    assert admin.put(url, json=resent).status_code == 200

    smtp = _channel(
        admin,
        name="mail",
        type="email",
        smtp_host="mail.example.com",
        smtp_username="alerts",
        smtp_password="smtp-pass",
        mail_from="alerts@example.com",
        mail_to="noc@example.com",
    )
    smtp_url = f"/api/admin/notification-channels/{smtp['id']}"
    smtp_masked = {**smtp, "smtp_password": SECRET_MASK}
    _refused(admin.put(smtp_url, json={**smtp_masked, "smtp_host": "mx.example.net"}), "smtp_password")
    _refused(admin.put(smtp_url, json={**smtp_masked, "smtp_use_tls": False, "smtp_use_ssl": False}), "smtp_tls")
    assert admin.put(smtp_url, json={**smtp_masked, "mail_to": "oncall@example.com"}).status_code == 200


def test_siem_sink_token_needs_reentry_for_a_new_address(admin):
    body = {
        "name": "hec",
        "protocol": "https",
        "format": "json",
        "url": "https://siem.example.com:8088/services/collector",
        "bearer_token": "hec-token",
    }
    resp = admin.post("/api/admin/siem-sinks", json=body)
    assert resp.status_code == 200, resp.text
    sink = resp.json()
    url = f"/api/admin/siem-sinks/{sink['id']}"
    masked = {**body, "bearer_token": SECRET_MASK}

    assert admin.put(url, json={**masked, "name": "hec 2"}).status_code == 200
    _refused(admin.put(url, json={**masked, "url": "https://siem.example.net:8088/services/collector"}), "bearer_token")
    _refused(admin.put(url, json={**masked, "tls_verify": False}), "tls_verify")
    assert admin.put(url, json={**body, "url": "https://siem.example.net:8088/services/collector"}).status_code == 200


def test_event_webhook_secrets_need_reentry_for_a_new_address(admin):
    body = {
        "name": "inventory-hook",
        "url": "https://hooks.example.com/plexus",
        "object_types": ["host"],
        "actions": ["create"],
        "secret": "signing-secret",
        "headers": {"Authorization": "Bearer header-token"},
    }
    resp = admin.post("/api/admin/webhooks", json=body)
    assert resp.status_code == 201, resp.text
    url = f"/api/admin/webhooks/{resp.json()['id']}"
    masked = {**body, "secret": SECRET_MASK, "headers": {"Authorization": SECRET_MASK}}

    assert admin.put(url, json={**masked, "url": "https://hooks.example.com/plexus/v2"}).status_code == 200
    _refused(
        admin.put(url, json={**masked, "url": "https://hooks.example.net/plexus"}),
        "signing secret",
        "header Authorization",
    )
    _refused(admin.put(url, json={**masked, "verify_tls": False}), "verify_tls")
    # Only the header is kept: only it is named.
    resp = admin.put(url, json={**masked, "secret": "new-secret", "url": "https://hooks.example.net/plexus"})
    _refused(resp, "header Authorization")
    assert "signing secret" not in resp.json()["error"]["message"]
    assert admin.put(url, json={**body, "url": "https://hooks.example.net/plexus"}).status_code == 200


def test_directory_and_sso_secrets_need_reentry_for_a_new_server(admin):
    config = admin.get("/api/admin/auth-config").json()
    config["radius"].update({"server": "192.0.2.50", "secret": "radius-secret"})
    config["ldap"].update({"server": "ldap.example.com", "bind_password": "bind-pass", "use_ssl": True})
    config["oidc"].update(
        {"issuer": "https://idp.example.com/tenant-a", "client_id": "plexus", "client_secret": "oidc-secret"}
    )
    saved = admin.put("/api/admin/auth-config", json=config)
    assert saved.status_code == 200, saved.text
    masked = saved.json()
    assert masked["radius"]["secret"] == SECRET_MASK and masked["oidc"]["client_secret"] == SECRET_MASK

    # Unchanged servers: saving the masks keeps everything.
    assert admin.put("/api/admin/auth-config", json=masked).status_code == 200

    moved = {**masked, "radius": {**masked["radius"], "server": "203.0.113.50"}}
    _refused(admin.put("/api/admin/auth-config", json=moved), "RADIUS", "secret")
    moved = {**masked, "radius": {**masked["radius"], "port": 11812}}
    _refused(admin.put("/api/admin/auth-config", json=moved), "RADIUS")
    moved = {**masked, "ldap": {**masked["ldap"], "use_ssl": False}}
    _refused(admin.put("/api/admin/auth-config", json=moved), "LDAP", "bind password")
    moved = {**masked, "oidc": {**masked["oidc"], "issuer": "https://idp.example.net/tenant-a"}}
    _refused(admin.put("/api/admin/auth-config", json=moved), "OIDC", "client secret")

    resent = {**masked, "radius": {**masked["radius"], "server": "203.0.113.50", "secret": "radius-secret-2"}}
    assert admin.put("/api/admin/auth-config", json=resent).status_code == 200


def test_ipam_source_credentials_need_reentry_for_a_new_address(admin, monkeypatch):
    import netcontrol.routes.ipam as ipam_routes

    sent: list[tuple[str, dict]] = []

    async def fake_collect(source, auth_config):
        sent.append((str(source.get("base_url")), dict(auth_config or {})))
        return {"summary": {}}

    monkeypatch.setattr(ipam_routes, "collect_ipam_snapshot", fake_collect)
    created = admin.post(
        "/api/ipam/sources",
        json={
            "provider": "netbox",
            "name": "Lab NetBox",
            "base_url": "https://192.0.2.10",
            "auth_config": {"token": "invented-ipam-token-0010"},
        },
    )
    assert created.status_code == 201, created.text
    url = f"/api/ipam/sources/{created.json()['source']['id']}"

    # Same address, other settings: the token is kept.
    assert admin.put(url, json={"name": "Lab NetBox 2", "base_url": "https://192.0.2.10/"}).status_code == 200
    _refused(admin.put(url, json={"base_url": "https://203.0.113.66"}), "address", "API credentials")
    _refused(admin.put(url, json={"verify_tls": False}), "TLS verification", "API credentials")
    admin.post(f"{url}/validate")
    assert [address for address, _ in sent] == ["https://192.0.2.10/"]

    # Sent again, the credentials go with the new address.
    moved = admin.put(
        url, json={"base_url": "https://203.0.113.66", "auth_config": {"token": "invented-ipam-token-0011"}}
    )
    assert moved.status_code == 200, moved.text
    admin.post(f"{url}/validate")
    assert sent[-1] == ("https://203.0.113.66", {"token": "invented-ipam-token-0011"})


def test_dhcp_server_credentials_need_reentry_for_a_new_address(admin):
    created = admin.post(
        "/api/dhcp/servers",
        json={
            "provider": "kea",
            "name": "Lab Kea",
            "base_url": "https://192.0.2.10",
            "auth_type": "basic",
            "auth_config": {"username": "kea-reader", "password": "invented-dhcp-password-0010"},
        },
    )
    assert created.status_code == 200, created.text
    url = f"/api/dhcp/servers/{created.json()['id']}"

    assert admin.patch(url, json={"notes": "rack 4", "base_url": "https://192.0.2.10/"}).status_code == 200
    _refused(admin.patch(url, json={"base_url": "https://203.0.113.66"}), "address", "API credentials")
    _refused(admin.patch(url, json={"verify_tls": False}), "TLS verification", "API credentials")
    moved = admin.patch(
        url,
        json={
            "base_url": "https://203.0.113.66",
            "auth_config": {"username": "kea-reader", "password": "invented-dhcp-password-0011"},
        },
    )
    assert moved.status_code == 200, moved.text

    # A server with no stored credentials moves freely.
    bare = admin.post(
        "/api/dhcp/servers", json={"provider": "kea", "name": "Open Kea", "base_url": "https://192.0.2.11"}
    )
    assert bare.status_code == 200, bare.text
    assert (
        admin.patch(f"/api/dhcp/servers/{bare.json()['id']}", json={"base_url": "https://203.0.113.67"}).status_code
        == 200
    )
