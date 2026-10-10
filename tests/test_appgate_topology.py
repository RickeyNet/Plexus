"""Tests for the Appgate SDP topology integration.

Covers the pipeline with no network access:
  * AppgateClient  - peer version negotiation and the Accept header, the
                     login body and the bearer token, a stable device ID,
                     a 401 signs in again once, a 403 is not retried, a 429
                     is, ranged paging, sign-out on close, URL trust, an
                     admin user that needs MFA
  * collector      - option defaults, best-effort sections with their
                     errors, the pre-6.3 status and pre-session-list
                     fallbacks, the per-user details cap, the site filter,
                     secret scrubbing
  * normalize      - counts, node ids, kinds and models, boxes, tunnels and
                     management links, section titles, status mapping, the
                     subnet index
  * merge / export - the provider on merged nodes, node details
  * forwarding     - the Entitlements rule set of each Gateway, SNAT, the
                     users' routes and the split tunnel
  * HTTP API       - CRUD (the password stays write-only), sample, build
                     job, validation; and Path Mode traces through the sample
"""

from __future__ import annotations

import copy
import json
from urllib.parse import unquote

import httpx
import netcontrol.app as app_module
import pytest
from netcontrol.integrations.appgate import client as client_module
from netcontrol.integrations.appgate.client import (
    AppgateApiError,
    AppgateClient,
    device_id,
    validate_base_url,
)
from netcontrol.integrations.appgate.collector import (
    DEFAULT_OPTIONS,
    MAX_SESSION_DETAILS,
    collect_appgate,
    sanitize_options,
)
from netcontrol.integrations.appgate.forwarding import NO_DETAILS_NOTE, SPLIT_TUNNEL_NOTE, UNRESOLVED_USERS
from netcontrol.integrations.appgate.normalize import (
    COLLECTIVE_NODE_ID,
    COLLECTIVE_SITE_ID,
    USER_NODE_PREFIX,
    USERS_SITE_ID,
    build_snapshot,
)
from netcontrol.integrations.appgate.sample import (
    AWS_SITE,
    CONNECTOR_1,
    CTRL_1,
    CTRL_2,
    DANA_DEVICE,
    GW_AWS_1,
    GW_HQ_1,
    GW_HQ_2,
    GW_LAB_1,
    HQ_SITE,
    LAB_SITE,
    PORTAL_1,
    PRIYA_DEVICE,
    SAM_DEVICE,
    SCANNER_DEVICE,
    build_sample_raw,
)
from netcontrol.integrations.meraki.subnets import subnet_index
from netcontrol.integrations.meraki.unified import graph_to_snapshot, merge_meraki_into_graph, node_details
from netcontrol.integrations.pathtrace.engine import STATEFUL_REPLY, Tracer
from netcontrol.integrations.software.versions import snapshot_devices

BASE = "https://appgate.example.com:8443"
PASSWORD = "s3cret-admin-password"
P12 = "MIIKFAKEP12CERTIFICATE"
SHARED_SECRET = "radius-shared-secret"

# ── A fake Controller serving the sample ─────────────────────────────────────


class _FakeController:
    """A Controller's admin API serving the sample data, with knobs for
    failure cases."""

    def __init__(self) -> None:
        self.raw = build_sample_raw()
        self.peer_version = 22
        self.lowest = 18
        self.mfa = False
        self.logins: list[dict] = []
        self.logouts = 0
        self.tokens = 0
        self.token = ""
        self.calls: list[httpx.Request] = []
        self.fail: dict[str, int] = {}  # path -> HTTP status
        self.expire_once = False

    def _lists(self) -> dict[str, list]:
        raw = copy.deepcopy(self.raw)
        appliances = raw["appliances"]
        for appliance in appliances:
            # A real Controller answers with secrets that must never be kept.
            appliance["adminInterface"] = {"hostname": appliance["hostname"], "httpsPort": 8443, "httpsP12": P12}
            appliance["sshServer"] = {"enabled": True, "passwordAuthentication": True}
            appliance["logForwarder"] = {"enabled": True, "splunkClients": [{"url": "x", "token": "splunk-token"}]}
        for site in raw["sites"]:
            for resolver in site["nameResolution"].get("awsResolvers") or []:
                resolver["accessKeyId"] = "AKIAFAKE"
                resolver["secretAccessKey"] = "aws-secret"
        providers = raw["identity_providers"]
        providers.append(
            {
                "id": "c2f00000-0003-4f00-9000-000000000003",
                "name": "RADIUS",
                "type": "Radius",
                "hostnames": ["radius.acme.example"],
                "sharedSecret": SHARED_SECRET,
                "adminPassword": "ldap-admin-password",
                "ipPoolV4": providers[0]["ipPoolV4"],
            }
        )
        return {
            "/appliances": appliances,
            "/appliances/status": raw["appliance_status"],
            "/stats/appliances": raw["appliance_status"],
            "/sites": raw["sites"],
            "/sites/status": raw["site_status"],
            "/policies": raw["policies"],
            "/entitlements": raw["entitlements"],
            "/conditions": raw["conditions"],
            "/ringfence-rules": raw["ringfence_rules"],
            "/identity-providers": providers,
            "/ip-pools": raw["ip_pools"],
            "/stats/active-sessions/dn": raw["sessions"],
            "/on-boarded-devices": [
                {**s, "onBoardedAt": "2026-09-01T10:00:00Z", "lastSeenAt": "2026-10-01T08:00:00Z"}
                for s in raw["sessions"]
            ],
        }

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        path = request.url.path.removeprefix("/admin")
        accept = request.headers.get("Accept", "")
        if path == "/version":
            assert accept == "application/json" and "Authorization" not in request.headers
            return httpx.Response(
                200, json={"peerVersion": self.peer_version, "lowestPeerVersionSupported": self.lowest}
            )
        assert accept == f"application/vnd.appgate.peer-v{min(self.peer_version, 25)}+json", accept
        if path == "/login":
            body = json.loads(request.content)
            self.logins.append(body)
            if (body["username"], body["password"]) != ("plexus", PASSWORD):
                return httpx.Response(401, json={"id": "unauthorized", "message": "Invalid username or password"})
            self.tokens += 1
            self.token = f"token-{self.tokens}"
            return httpx.Response(
                200,
                json={
                    "token": self.token,
                    "expires": "2026-10-01T10:00:00Z",
                    "user": {"name": "plexus", "needTwoFactorAuth": self.mfa, "canAccessAuditLogs": True},
                },
            )
        if request.headers.get("Authorization") != f"Bearer {self.token}" or self.expire_once:
            self.expire_once = False
            return httpx.Response(401, json={"id": "unauthorized", "message": "Token expired"})
        if path == "/logout":
            self.logouts += 1
            self.token = ""
            return httpx.Response(204)
        if path in self.fail:
            return httpx.Response(self.fail[path], json={"id": "forbidden", "message": f"No access to {path}"})
        if path == "/global-settings":
            return httpx.Response(200, json=self.raw["global_settings"])
        if path == "/license":
            return httpx.Response(200, json=self.raw["license"])
        if path.startswith("/session-info/"):
            dn = unquote(path.removeprefix("/session-info/"))
            found = self.raw["session_details"].get(dn)
            return httpx.Response(200, json=found) if found else httpx.Response(404, json={"message": "No session"})
        items = self._lists().get(path)
        if items is None:
            return httpx.Response(404, json={"id": "not found", "message": "Not found"})
        first, last = (int(v) for v in request.url.params["range"].split("-"))
        page = items[first : last + 1]
        return httpx.Response(
            200,
            json={"data": page, "range": f"{first}-{first + len(page) - 1}/{len(items)}", "totalCount": len(items)},
        )


def _client(fake: _FakeController, **kwargs) -> AppgateClient:
    kwargs.setdefault("requests_per_second", 1000)
    return AppgateClient(BASE, "plexus", PASSWORD, transport=httpx.MockTransport(fake.handler), **kwargs)


@pytest.fixture
def no_sleep(monkeypatch):
    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(client_module.asyncio, "sleep", _no_sleep)


def _section(entity: dict, title: str) -> dict:
    return next(s for s in entity["sections"] if s["title"] == title)


def _titles(entity: dict) -> list[str]:
    return [s["title"] for s in entity["sections"]]


def _node(snapshot: dict, node_id: str) -> dict:
    return next(n for n in snapshot["nodes"] if n["id"] == node_id)


def _kv(entity: dict, title: str) -> dict[str, str]:
    return dict(_section(entity, title)["rows"])


def _table(entity: dict, title: str) -> list[dict[str, str]]:
    section = _section(entity, title)
    return [dict(zip(section["columns"], row, strict=False)) for row in section["rows"]]


def _user(device: str) -> str:
    return f"{USER_NODE_PREFIX}{device}"


def _a(ident: str) -> str:
    return f"a:{ident}"


# ── Client ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_client_negotiates_the_peer_version_and_sends_it_in_every_accept_header():
    fake = _FakeController()
    fake.peer_version = 30
    async with _client(fake) as client:
        assert await client.negotiate() == 25
        sites = await client.get_list("/sites")
    assert [s["name"] for s in sites] == ["HQ Data Center", "AWS us-east-1", "Branch Lab"]
    assert client.peer_version == 25
    # The handler asserts the Accept header of every call after /version.
    assert [r.url.path for r in fake.calls][:3] == ["/admin/version", "/admin/login", "/admin/sites"]


@pytest.mark.asyncio
async def test_client_refuses_a_peer_version_it_does_not_support():
    fake = _FakeController()
    fake.peer_version, fake.lowest = 16, 14
    async with _client(fake) as client:
        with pytest.raises(AppgateApiError) as excinfo:
            await client.login()
    assert str(excinfo.value) == "Appgate SDP peer version 16 is not supported"
    assert excinfo.value.status_code is None and not fake.logins


@pytest.mark.asyncio
async def test_client_logs_in_with_a_stable_device_id_and_sends_the_token_only_as_a_bearer_header():
    fake = _FakeController()
    async with _client(fake, provider_name="Okta SAML") as client:
        await client.get("/global-settings")
    [login] = fake.logins
    assert login == {
        "providerName": "Okta SAML",
        "username": "plexus",
        "password": PASSWORD,
        "deviceId": device_id(BASE, "plexus"),
    }
    # The same server and user always sign in as the same device.
    assert device_id(BASE, "plexus") == device_id(BASE, "plexus") != device_id(BASE, "other")
    settings = next(r for r in fake.calls if r.url.path == "/admin/global-settings")
    assert settings.headers["Authorization"] == "Bearer token-1"
    assert not any("token-1" in str(r.url) or PASSWORD in str(r.url) for r in fake.calls)
    login_request = next(r for r in fake.calls if r.url.path == "/admin/login")
    assert "Authorization" not in login_request.headers and login_request.method == "POST"


@pytest.mark.asyncio
async def test_client_signs_in_again_once_on_401():
    fake = _FakeController()
    async with _client(fake) as client:
        await client.login()
        fake.expire_once = True
        assert (await client.get("/global-settings"))["collectiveName"] == "Acme Appgate"
        assert len(fake.logins) == 2
        # A call refused again after the new login fails, after one more login only.
        fake.fail = {"/global-settings": 401}
        with pytest.raises(AppgateApiError) as excinfo:
            await client.get("/global-settings")
    assert excinfo.value.status_code == 401 and len(fake.logins) == 3


@pytest.mark.asyncio
async def test_client_does_not_retry_a_403(no_sleep):
    fake = _FakeController()
    fake.fail = {"/policies": 403}
    async with _client(fake) as client:
        with pytest.raises(AppgateApiError) as excinfo:
            await client.get_list("/policies")
    assert excinfo.value.status_code == 403 and excinfo.value.detail == "No access to /policies"
    assert sum(1 for r in fake.calls if r.url.path == "/admin/policies") == 1


@pytest.mark.asyncio
async def test_client_retries_rate_limits_and_server_errors(no_sleep):
    answers = iter([429, 503])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/admin/version":
            return httpx.Response(200, json={"peerVersion": 20, "lowestPeerVersionSupported": 17})
        if request.url.path == "/admin/login":
            return httpx.Response(200, json={"token": "t", "user": {"needTwoFactorAuth": False}})
        status = next(answers, 200)
        if status != 200:
            return httpx.Response(status, headers={"Retry-After": "120"})
        return httpx.Response(200, json={"collectiveName": "x"})

    async with AppgateClient(BASE, "u", "p", transport=httpx.MockTransport(handler), requests_per_second=1000) as c:
        assert await c.get("/global-settings") == {"collectiveName": "x"}
        assert c.stats["retries"] == 2 and c.stats["rate_limited"] == 1


@pytest.mark.asyncio
async def test_client_pages_lists_by_range():
    fake = _FakeController()
    fake.raw["sessions"] = [
        {"distinguishedName": f"CN=d{i},CN=u{i},OU=local", "username": f"u{i}"} for i in range(1203)
    ]
    async with _client(fake) as client:
        sessions = await client.get_list("/stats/active-sessions/dn")
    assert len(sessions) == 1203 and sessions[-1]["username"] == "u1202"
    ranges = [r.url.params["range"] for r in fake.calls if r.url.path == "/admin/stats/active-sessions/dn"]
    assert ranges == ["0-499", "500-999", "1000-1499"]


@pytest.mark.asyncio
async def test_client_signs_out_and_forgets_the_token_on_close():
    fake = _FakeController()
    client = _client(fake)
    await client.login()
    await client.close()
    assert fake.logouts == 1 and client._token == ""
    logout = next(r for r in fake.calls if r.url.path == "/admin/logout")
    assert logout.method == "POST" and logout.headers["Authorization"] == "Bearer token-1"


@pytest.mark.asyncio
async def test_client_refuses_an_admin_user_that_needs_mfa():
    fake = _FakeController()
    fake.mfa = True
    async with _client(fake) as client:
        with pytest.raises(AppgateApiError) as excinfo:
            await client.login()
    assert "the API user must be exempt from admin MFA" in str(excinfo.value)
    assert client._token == ""


def test_base_url_must_be_the_https_controller_host():
    assert validate_base_url("appgate.example.com") == "https://appgate.example.com"
    assert validate_base_url("https://appgate.example.com:8443/") == "https://appgate.example.com:8443"
    assert validate_base_url("https://appgate.example.com:8443/admin/") == "https://appgate.example.com:8443"
    for bad in (
        "",
        "http://appgate.example.com",
        "https://appgate.example.com/api",
        "https://u:p@host",
        "https://h?x=1",
    ):
        with pytest.raises(ValueError):
            validate_base_url(bad)


# ── Collector ────────────────────────────────────────────────────────────────


def test_sanitize_options_defaults_and_coerces():
    assert sanitize_options(None) == DEFAULT_OPTIONS
    opts = sanitize_options({"username": "  plexus ", "include_users": 0, "site_name_contains": " HQ ", "x": 1})
    assert opts == {**DEFAULT_OPTIONS, "username": "plexus", "include_users": False, "site_name_contains": "HQ"}
    assert list(DEFAULT_OPTIONS) == [
        "username",
        "verify_tls",
        "site_name_contains",
        "include_appliance_state",
        "include_entitlements",
        "include_users",
        "include_session_details",
        "inventory_enrich",
    ]


@pytest.mark.asyncio
async def test_collect_appgate_reads_every_part_and_reports_progress():
    fake = _FakeController()
    phases: list[dict] = []
    async with _client(fake) as client:
        raw = await collect_appgate(client, {"username": "plexus"}, phases.append)
    assert raw["collective"] == {
        "name": "Acme Appgate",
        "collective_name": "Acme Appgate",
        "collective_id": "0c011ec7-0001-4000-8000-00000000acde",
        "peer_version": 22,
        "controller": "appgate.example.com:8443",
    }
    assert len(raw["appliances"]) == 8 and len(raw["sites"]) == 3 and len(raw["appliance_status"]) == 8
    assert len(raw["entitlements"]) == 6 and len(raw["identity_providers"]) == 3
    assert len(raw["sessions"]) == 4 and set(raw["session_details"]) == {
        s["distinguishedName"] for s in raw["sessions"]
    }
    assert raw["sessions_source"] == "active-sessions" and raw["sessions_skipped"] == 0 and raw["errors"] == []
    assert raw["license"]["users"] == 500 and fake.logouts == 1
    order = list(dict.fromkeys(p["phase"] for p in phases))
    assert order == [
        "appgate version",
        "appgate appliances",
        "appgate sites",
        "appgate policy",
        "appgate pools",
        "appgate users",
        "appgate sessions",
        "collected",
    ]
    last = phases[-1]
    assert last["calls_done"] == last["calls_total"] == 6 + 2 + 2 + 4 + 1 + 4


@pytest.mark.asyncio
async def test_collect_appgate_scrubs_every_secret():
    fake = _FakeController()
    async with _client(fake) as client:
        raw = await collect_appgate(client, {"username": "plexus"})
    stored = json.dumps(raw)
    for secret in (P12, SHARED_SECRET, "ldap-admin-password", "AKIAFAKE", "aws-secret", "splunk-token", PASSWORD):
        assert secret not in stored
    assert "token-1" not in stored and "httpsP12" not in stored and "sshServer" not in stored
    appliance = raw["appliances"][0]
    assert appliance["logForwarder"] == {"enabled": True} and appliance["adminInterface"]["httpsPort"] == 8443
    radius = next(p for p in raw["identity_providers"] if p["name"] == "RADIUS")
    assert radius["hostnames"] == ["radius.acme.example"] and radius["ipPoolV4"]
    assert "sharedSecret" not in radius and "adminPassword" not in radius
    # The users keep their names: only resolver credentials lose ``username``.
    assert raw["sessions"][0]["username"]


@pytest.mark.asyncio
async def test_collect_appgate_is_best_effort_past_appliances_and_sites():
    fake = _FakeController()
    fake.fail = {"/entitlements": 403, "/sites/status": 500, "/ip-pools": 403, "/license": 404}
    async with _client(fake, max_retries=0) as client:
        raw = await collect_appgate(client, {"username": "plexus"})
    assert raw["entitlements"] is None and raw["site_status"] is None and raw["ip_pools"] is None
    assert raw["license"] is None and raw["policies"] is not None
    assert {e["path"]: e["status"] for e in raw["errors"]} == {
        "/entitlements": 403,
        "/sites/status": 500,
        "/ip-pools": 403,
        "/license": 404,
    }
    assert any(e["message"].endswith(": No access to /entitlements") for e in raw["errors"])
    snapshot = build_snapshot(raw)
    assert len(snapshot["collection"]["errors"]) == 4
    # Without the entitlements a Gateway's rule set is not collected.
    assert "Entitlements" in _node(snapshot, _a(GW_HQ_1))["forwarding"]["not_collected"]


@pytest.mark.asyncio
async def test_collect_appgate_fails_when_appliances_or_sites_are_unreadable():
    for path in ("/appliances", "/sites"):
        fake = _FakeController()
        fake.fail = {path: 403}
        async with _client(fake) as client:
            with pytest.raises(AppgateApiError) as excinfo:
                await collect_appgate(client, {"username": "plexus"})
        assert excinfo.value.status_code == 403


@pytest.mark.asyncio
async def test_collect_appgate_falls_back_to_the_old_status_and_device_lists():
    fake = _FakeController()
    fake.fail = {"/appliances/status": 404, "/stats/active-sessions/dn": 404}
    async with _client(fake) as client:
        raw = await collect_appgate(client, {"username": "plexus"})
    assert len(raw["appliance_status"]) == 8 and raw["errors"] == []
    assert raw["sessions_source"] == "on-boarded-devices" and len(raw["sessions"]) == 4
    # A registered device is not connected: there are no session details to read.
    assert raw["session_details"] is None
    assert not any(r.url.path.startswith("/admin/session-info") for r in fake.calls)
    snapshot = build_snapshot(raw)
    dana = _node(snapshot, _user(DANA_DEVICE))
    assert dana["status"] == "unknown" and _kv(dana, "Remote user")["Connection"] == "Registered, connection unknown"
    box = next(s for s in snapshot["sites"] if s["id"] == USERS_SITE_ID)
    assert _kv(box, "Remote users")["Registered devices (connection unknown)"] == "4"


@pytest.mark.asyncio
async def test_collect_appgate_caps_the_per_user_details(monkeypatch):
    import netcontrol.integrations.appgate.collector as collector_module

    monkeypatch.setattr(collector_module, "MAX_SESSION_DETAILS", 2)
    fake = _FakeController()
    async with _client(fake) as client:
        raw = await collect_appgate(client, {"username": "plexus"})
    assert len(raw["session_details"]) == 2 and raw["sessions_skipped"] == 2
    assert sum(1 for r in fake.calls if r.url.path.startswith("/admin/session-info/")) == 2
    snapshot = build_snapshot(raw)
    box = next(s for s in snapshot["sites"] if s["id"] == USERS_SITE_ID)
    assert _kv(box, "Remote users")["Skipped (over the cap)"] == "2"
    assert MAX_SESSION_DETAILS == 500


@pytest.mark.asyncio
async def test_collect_appgate_without_session_details_reads_no_session_info():
    fake = _FakeController()
    async with _client(fake) as client:
        raw = await collect_appgate(client, {"username": "plexus", "include_session_details": False})
    assert raw["session_details"] is None and len(raw["sessions"]) == 4
    assert not any(r.url.path.startswith("/admin/session-info") for r in fake.calls)


@pytest.mark.asyncio
async def test_collect_appgate_limits_to_sites_named_like():
    fake = _FakeController()
    async with _client(fake) as client:
        raw = await collect_appgate(client, {"username": "plexus", "site_name_contains": "aws"})
    assert [s["name"] for s in raw["sites"]] == ["AWS us-east-1"]
    # The site's Gateway, and the Controllers wherever they are.
    assert sorted(a["name"] for a in raw["appliances"]) == ["appgate-ctrl-1", "appgate-ctrl-2", "appgate-gw-aws-1"]
    assert {s["name"] for s in raw["appliance_status"]} == {"appgate-ctrl-1", "appgate-ctrl-2", "appgate-gw-aws-1"}
    snapshot = build_snapshot(raw)
    assert [s["name"] for s in snapshot["sites"] if not s["id"].startswith("__")] == ["AWS us-east-1"]
    # Controllers of a site that is not on the map join the collective's box.
    assert _node(snapshot, _a(CTRL_1))["site"] == COLLECTIVE_SITE_ID


# ── Normalize ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def snapshot() -> dict:
    return build_snapshot(build_sample_raw())


def test_snapshot_summary_counts_every_part(snapshot):
    summary = snapshot["summary"]
    assert snapshot["provider"] == "appgate" and snapshot["org"]["name"] == "Acme Appgate"
    assert summary["sites"] == 3 and summary["devices"] == 8 and summary["devices_by_kind"] == {"appliance": 8}
    assert summary["remote_users"] == 4 and summary["vpn_tunnels"] == 5 and summary["gateways"] == 4
    assert summary["vlans"] == 6 and summary["devices_by_status"] == {"online": 6, "alerting": 1, "offline": 1}
    assert snapshot["collection"]["sources"] == ["Appgate SDP API"]


def test_snapshot_nodes_have_the_contract_ids_kinds_and_models(snapshot):
    kinds = {n["id"]: (n["kind"], n["model"]) for n in snapshot["nodes"]}
    assert kinds[_a(GW_HQ_1)] == ("appliance", "Appgate Gateway")
    assert kinds[_a(CTRL_1)] == ("appliance", "Appgate Controller / LogServer")
    assert kinds[_a(CTRL_2)] == ("appliance", "Appgate Controller")
    assert kinds[_a(PORTAL_1)] == ("appliance", "Appgate Portal")
    assert kinds[_a(CONNECTOR_1)] == ("appliance", "Appgate Connector")
    assert kinds[COLLECTIVE_NODE_ID] == ("cloud", "Appgate SDP")
    assert kinds[_user(DANA_DEVICE)] == ("user", "Appgate Client")
    dana = _node(snapshot, _user(DANA_DEVICE))
    assert dana["label"] == "dana.reyes" and dana["ip"] == "10.253.0.11" and dana["site"] == USERS_SITE_ID
    assert _node(snapshot, COLLECTIVE_NODE_ID)["label"] == "Appgate Collective"
    assert all(n["x"] and n["y"] for n in snapshot["nodes"])


def test_snapshot_boxes_hold_their_appliances_gateways_first(snapshot):
    sites = {s["id"]: s for s in snapshot["sites"]}
    assert sites[COLLECTIVE_SITE_ID]["name"] == "Appgate SDP" and sites[COLLECTIVE_SITE_ID]["vpn_mode"] == "hub"
    assert sites[USERS_SITE_ID]["name"] == "Appgate clients" and sites[USERS_SITE_ID]["device_count"] == 4
    hq = [n["id"] for n in snapshot["nodes"] if n["site"] == HQ_SITE]
    assert hq[:2] == [_a(GW_HQ_1), _a(GW_HQ_2)] and len(hq) == 6
    assert [n["id"] for n in snapshot["nodes"] if n.get("site_sections")] == [
        _a(GW_AWS_1),
        _a(GW_LAB_1),
        _a(GW_HQ_1),
        _user(DANA_DEVICE),
    ]
    assert sites[HQ_SITE]["status"] == "alerting" and sites[LAB_SITE]["status"] == "offline"
    assert sites[AWS_SITE]["status"] == "online"


def test_snapshot_edges_tunnels_per_gateway_and_management_links(snapshot):
    tunnels = sorted((e["a"], e["b"]) for e in snapshot["edges"] if e["kind"] == "vpn")
    assert tunnels == sorted(
        [
            (_user(DANA_DEVICE), _a(GW_HQ_1)),
            (_user(DANA_DEVICE), _a(GW_AWS_1)),
            (_user(SAM_DEVICE), _a(GW_HQ_1)),
            (_user(PRIYA_DEVICE), _a(GW_HQ_2)),
            (_user(SCANNER_DEVICE), _a(GW_AWS_1)),
        ]
    )
    tunnel = next(e for e in snapshot["edges"] if e["a"] == _user(DANA_DEVICE))
    assert tunnel["label"] == "Appgate tunnel" and tunnel["a_port"] == "10.253.0.11"
    manage = {e["a"]: (e["label"], e["status"]) for e in snapshot["edges"] if e["kind"] == "manage"}
    assert manage[_a(CTRL_1)] == manage[_a(CTRL_2)] == ("Appgate Controller", "active")
    assert manage[_a(GW_HQ_1)] == ("Appgate peer link", "active")
    assert manage[_a(GW_LAB_1)] == ("Appgate peer link", "failed") and len(manage) == 8
    assert all(e["b"] == COLLECTIVE_NODE_ID for e in snapshot["edges"] if e["kind"] == "manage")


def test_snapshot_sections_follow_the_contract(snapshot):
    sites = {s["id"]: s for s in snapshot["sites"]}
    assert _titles(sites[HQ_SITE]) == [
        "Site overview",
        "Network ranges",
        "Protected resources",
        "Name resolution",
        "Site DNS forwarding",
    ]
    overview = _kv(sites[HQ_SITE], "Site overview")
    assert overview["Entitlement-based routing"] == "Yes" and overview["SNAT to gateway"] == "Yes"
    assert overview["Default gateway"] == "No" and overview["Gateways"] == "2" and overview["Sessions"] == "4"
    assert _kv(sites[AWS_SITE], "Site overview")["Fallback site"] == "HQ Data Center"
    assert _titles(_node(snapshot, _a(GW_HQ_1))) == [
        "Overview",
        "Interfaces",
        "Static routes",
        "Entitlements",
        "Connected users",
    ]
    assert _titles(_node(snapshot, _a(CONNECTOR_1))) == ["Overview", "Interfaces", "Connector clients"]
    assert _titles(_node(snapshot, COLLECTIVE_NODE_ID)) == [
        "Appgate Collective",
        "Appliances",
        "Sites",
        "Policies",
        "Entitlements",
        "Conditions",
        "Ringfence rules",
        "IP pools",
        "Identity providers",
    ]
    assert _titles(_node(snapshot, _user(DANA_DEVICE))) == [
        "Remote user",
        "Connecting from",
        "Connected to (Appgate)",
        "Entitlement results",
        "Firewall rules",
    ]
    assert _titles(sites[USERS_SITE_ID]) == ["Remote users", "Connected users"]


def test_snapshot_gateway_details(snapshot):
    gateway = _node(snapshot, _a(GW_HQ_1))
    overview = _kv(gateway, "Overview")
    assert overview["Roles"] == "Gateway" and overview["Status"] == "healthy"
    assert overview["Version"] == "6.4.2-37201-release" and overview["Peer version"] == "22"
    assert overview["Client interface"] == "gw-hq-1.acme.example:443" and overview["Source"] == "Appgate SDP API"
    assert overview["CPU"] == "21.0%" and overview["Sessions"] == "3"
    interfaces = _table(gateway, "Interfaces")
    assert [(i["Interface"], i["Address"], i["Subnet"], i["Status"]) for i in interfaces] == [
        ("eth0", "10.160.1.21", "10.160.1.0/24", "healthy"),
        ("eth1", "10.160.10.21", "10.160.10.0/24", "healthy"),
    ]
    assert _table(gateway, "Static routes")[1] == {
        "Destination": "10.160.20.0/24",
        "Gateway": "10.160.1.1",
        "Interface": "eth0",
    }
    entitlements = _table(gateway, "Entitlements")
    assert [r["Entitlement"] for r in entitlements] == [
        "HQ admin SSH",
        "HQ legacy telnet",
        "HQ web servers",
        "HQ web servers",
        "Intranet by name",
    ]
    ssh = entitlements[0]
    assert ssh["Conditions"] == "Admin group" and ssh["Policies"] == "Admins" and ssh["Status"] == "enabled"
    assert entitlements[1]["Action"] == "block" and entitlements[3]["Ports"] == "types 0-255"
    users = _table(gateway, "Connected users")
    assert [u["User"] for u in users] == ["dana.reyes", "sam.okafor"]
    assert users[0]["Entitlements"] == "2 / 3" and users[0]["Tunnel IP"] == "10.253.0.11"
    lab = _node(snapshot, _a(GW_LAB_1))
    assert _table(lab, "Entitlements")[0]["Status"] == "disabled"
    assert _table(_node(snapshot, _a(CONNECTOR_1)), "Connector clients") == [
        {
            "Client": "Printer fleet",
            "Type": "Express",
            "Resources": "10.160.30.0/24",
            "SNAT": "Yes",
            "Default gateway": "",
        }
    ]


def test_snapshot_status_mapping_and_a_suspended_gateway():
    raw = build_sample_raw()
    status = {s["id"]: s for s in raw["appliance_status"]}
    status[GW_LAB_1]["status"] = "healthy"
    status[CTRL_2]["status"] = "busy"
    status[PORTAL_1]["status"] = "n/a"
    raw["appliances"][-1]["activated"] = False  # the connector
    snapshot = build_snapshot(raw)
    assert _node(snapshot, _a(GW_HQ_2))["status"] == "alerting"  # warning
    assert _node(snapshot, _a(CTRL_2))["status"] == "alerting"  # busy
    assert _node(snapshot, _a(PORTAL_1))["status"] == "unknown"
    # A suspended Gateway that is up takes no new sessions: alerting.
    lab = _node(snapshot, _a(GW_LAB_1))
    assert lab["status"] == "alerting" and _kv(lab, "Overview")["Suspended"] == "Yes"
    connector = _node(snapshot, _a(CONNECTOR_1))
    assert connector["status"] == "unknown" and _kv(connector, "Overview")["Activated"] == "Not activated"
    # The sample's lab Gateway is offline, suspended or not.
    sample = build_snapshot(build_sample_raw())
    assert _node(sample, _a(GW_LAB_1))["status"] == "offline"


def test_snapshot_site_without_an_active_gateway():
    sample = build_snapshot(build_sample_raw())
    lab = next(s for s in sample["sites"] if s["id"] == LAB_SITE)
    assert _kv(lab, "Site overview")["Status"] == "noActiveGateways" and lab["status"] == "offline"
    raw = build_sample_raw()
    raw["appliances"] = [a for a in raw["appliances"] if a["id"] != GW_LAB_1]
    snapshot = build_snapshot(raw)
    lab = next(s for s in snapshot["sites"] if s["id"] == LAB_SITE)
    assert lab["device_count"] == 0 and _kv(lab, "Site overview")["Gateways"] == "0"
    # Its subnets have no owner, so they are not in the index.
    assert not any(e["cidr"] == "10.160.200.0/24" for e in subnet_index(snapshot))


def test_subnet_index_puts_the_network_ranges_on_the_first_gateway(snapshot):
    index = {(e["cidr"], e["node_id"]): e for e in subnet_index(snapshot)}
    owners = {cidr: node for cidr, node in index}
    assert owners == {
        "10.160.1.0/24": _a(GW_HQ_1),
        "10.160.10.0/24": _a(GW_HQ_1),
        "10.160.20.0/24": _a(GW_HQ_1),
        "10.160.200.0/24": _a(GW_LAB_1),
        "10.161.0.0/16": _a(GW_AWS_1),
        "10.161.0.0/24": _a(GW_AWS_1),
    }
    assert all(e["kind"] == "range" for e in index.values())
    assert index[("10.160.10.0/24", _a(GW_HQ_1))]["name"] == "servers"
    # Neither the users, their pool nor the collective own a subnet.
    assert not any(
        e["node_id"].startswith(USER_NODE_PREFIX) or e["node_id"] == COLLECTIVE_NODE_ID for e in index.values()
    )
    assert not any(e["cidr"].startswith("10.253.") for e in index.values())


def test_user_details(snapshot):
    dana = _node(snapshot, _user(DANA_DEVICE))
    assert _kv(dana, "Remote user")["Identity provider"] == "Okta SAML"
    assert _kv(dana, "Connecting from") == {"Public IP": "198.51.100.161", "Coordinates": "40.71, -74.0"}
    connected = _kv(dana, "Connected to (Appgate)")
    assert connected["Gateways"] == "appgate-gw-hq-1, appgate-gw-aws-1" and connected["Tunnel IP"] == "10.253.0.11"
    assert connected["Primary site"] == "HQ Data Center" and connected["Connected since"] == "2026-10-01T07:45:12Z"
    results = {r["Entitlement"]: r for r in _table(dana, "Entitlement results")}
    assert results["HQ admin SSH"]["Access"] == "No" and results["HQ admin SSH"]["Conditions"] == "Admin group: not met"
    assert results["AWS app tier"]["Site"] == "AWS us-east-1"
    assert _table(dana, "Firewall rules")[0]["Gateway"] == "appgate-gw-hq-1"


def test_users_sharing_a_name_are_told_apart_by_hostname():
    raw = build_sample_raw()
    raw["sessions"][1]["username"] = "dana.reyes"
    snapshot = build_snapshot(raw)
    labels = sorted(n["label"] for n in snapshot["nodes"] if n["kind"] == "user")
    assert labels == ["dana.reyes (DANA-LT14)", "dana.reyes (sam-mbp)", "priya.nair", "svc-scanner"]


def test_software_tracker_reads_every_appliance(snapshot):
    devices = snapshot_devices(snapshot, "appgate")
    assert len(devices) == 8 and {d["platform"] for d in devices} == {"appgate"}
    assert {d["version"] for d in devices} == {"6.4.2-37201-release"}


# ── Merge and export ─────────────────────────────────────────────────────────


def test_merge_marks_appgate_nodes_and_links(snapshot):
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(nodes, edges, [(7, snapshot)], host_node=lambda _id: None, resolve_external=lambda *_: None)
    gateway = nodes[f"meraki:7:{_a(GW_HQ_1)}"]
    assert gateway["device_type"] == "appgate" and gateway["device_category"] == "firewall"
    assert gateway["meraki"]["provider"] == "appgate" and gateway["meraki"]["site_name"] == "HQ Data Center"
    assert nodes[f"meraki:7:{COLLECTIVE_NODE_ID}"]["meraki"]["kind"] == "cloud"
    protocols = {e["protocol"] for e in edges if e.get("provider") == "appgate"}
    assert protocols == {"vpn", "management"} and len(edges) == len(snapshot["edges"])
    export = graph_to_snapshot({"nodes": list(nodes.values()), "edges": edges}, {7: snapshot}, {})
    assert any(n["label"] == "dana.reyes" for n in export["nodes"])


def test_node_details_report_the_provider_and_site(snapshot):
    details = node_details(snapshot, _a(GW_HQ_2))
    assert details["provider"] == "appgate" and details["site_name"] == "HQ Data Center"
    # Every appliance of the site shows its network ranges; the first Gateway the site's details.
    assert [s["title"] for s in details["site_addressing"]] == ["Network ranges"]
    assert details["site_sections"] == []
    assert node_details(snapshot, _a(GW_HQ_1))["site_sections"][0]["title"] == "Site overview"
    assert node_details(snapshot, _user(DANA_DEVICE))["site_addressing"] == []


# ── Forwarding ───────────────────────────────────────────────────────────────


def _fwd(snapshot: dict, node_id: str) -> dict:
    return _node(snapshot, node_id)["forwarding"]


def _set(block: dict, name: str = "Entitlements") -> dict:
    return next(p for p in block["policies"] if p["name"] == name)


def test_gateway_entitlements_rule_set(snapshot):
    rules = _set(_fwd(snapshot, _a(GW_HQ_1)))
    assert (rules["applies"], rules["default"], rules["kind"]) == ("any", "deny", "firewall")
    assert [(r["index"], r["name"], r["action"], r["protocol"], r["dst_ports"]) for r in rules["rules"]] == [
        (1, "HQ admin SSH", "allow", "tcp", "22"),
        (2, "HQ legacy telnet", "deny", "tcp", "23"),
        (3, "HQ web servers", "allow", "tcp", "443"),
        (4, "HQ web servers", "allow", "icmp", "any"),
        (5, "Intranet by name", "allow", "tcp", "443"),
    ]
    by_index = {r["index"]: r for r in rules["rules"]}
    # The sources are the tunnel addresses of the users the Gateway grants the entitlement to.
    assert by_index[1]["src"] == ["10.253.0.12/32"]
    assert by_index[3]["src"] == ["10.253.0.11/32", "10.253.0.12/32"] and by_index[3]["dst"] == ["10.160.10.0/24"]
    assert by_index[4]["comment"] == "ICMP types 0-255"
    # A host that is a name cannot be matched on addresses.
    assert by_index[5]["dst"] == ["any"] and by_index[5]["unresolved"] == ["host dns://intranet.acme.example"]


def test_gateway_lists_the_entitlements_no_connected_user_holds(snapshot):
    block = _fwd(snapshot, _a(GW_HQ_2))
    assert [r["name"] for r in _set(block)["rules"]] == ["HQ web servers", "HQ web servers", "Intranet by name"]
    assert "Entitlements no connected user holds: HQ admin SSH, HQ legacy telnet" in block["not_collected"]
    # The lab's only entitlement is disabled: an empty set that drops everything.
    assert _set(_fwd(snapshot, _a(GW_LAB_1)))["rules"] == []


def test_down_actions_swap_the_ends(snapshot):
    rules = _set(_fwd(snapshot, _a(GW_AWS_1)))["rules"]
    down = rules[-1]
    assert down["src"] == ["10.161.20.0/24"] and down["dst"] == ["10.253.0.11/32", "10.253.0.14/32"]
    assert down["comment"] == "(down: resource to client)" and down["dst_ports"] == "443"


def test_gateway_routes_users_and_nat(snapshot):
    block = _fwd(snapshot, _a(GW_HQ_1))
    assert [(i["name"], i["kind"]) for i in block["interfaces"]] == [
        ("eth0", "lan"),
        ("eth1", "lan"),
        ("Appgate client tunnel", "tunnel"),
    ]
    routes = {r["prefix"]: r for r in block["routes"]}
    assert routes["0.0.0.0/0"]["kind"] == "default" and routes["0.0.0.0/0"]["next_hop"] == "10.160.1.1"
    assert routes["10.160.20.0/24"]["kind"] == "static"
    user = routes["10.253.0.11/32"]
    assert user["peer"] == {"org_node": _user(DANA_DEVICE)} and user["source"] == "Appgate client session"
    [snat] = block["nat"]
    assert (snat["kind"], snat["name"], snat["original_src"], snat["translated_src"]) == (
        "interface_pat",
        "Gateway SNAT",
        ["10.253.0.0/22"],
        ["interface"],
    )
    aws = _fwd(snapshot, _a(GW_AWS_1))
    assert aws["nat"] == []
    assert "Clients are routed into the site via 10.161.0.5" in aws["not_collected"]
    assert (
        "Client tunnel addresses are not translated: the site must route 10.253.0.1-10.253.3.254 back to the gateway"
        in aws["not_collected"]
    )
    # The site's network subnet is a range the Gateway delivers to.
    assert next(r for r in aws["routes"] if r["prefix"] == "10.161.0.0/16")["kind"] == "connected"
    assert "Default route of eth0 comes from DHCP and was not read" in _fwd(snapshot, _a(GW_LAB_1))["not_collected"]
    assert "Connector client resources are not traced" in _fwd(snapshot, _a(CONNECTOR_1))["not_collected"]
    assert "forwarding" not in _node(snapshot, COLLECTIVE_NODE_ID)


def test_users_route_their_entitlements_and_split_tunnel(snapshot):
    block = _fwd(snapshot, _user(DANA_DEVICE))
    assert block["interfaces"][0]["name"] == "Appgate Client" and block["interfaces"][0]["cidr"] == "10.253.0.11/32"
    routes = [(r["prefix"], r["kind"], (r["peer"] or {}).get("org_node"), r["source"]) for r in block["routes"]]
    assert routes == [
        ("10.253.0.11/32", "connected", None, "Address given by Appgate"),
        ("10.160.10.0/24", "static", _a(GW_HQ_1), "Entitlement HQ web servers via appgate-gw-hq-1"),
        ("10.161.20.0/24", "static", _a(GW_AWS_1), "Entitlement AWS app tier via appgate-gw-aws-1"),
    ]
    assert block["not_collected"] == [SPLIT_TUNNEL_NOTE] and block["policies"] == []


def test_a_default_gateway_site_and_one_routed_by_subnet():
    raw = build_sample_raw()
    hq = next(s for s in raw["sites"] if s["id"] == HQ_SITE)
    hq["defaultGateway"] = {"enabledV4": True, "excludedSubnets": ["192.168.0.0/16"]}
    hq["entitlementBasedRouting"] = False
    block = _fwd(build_snapshot(raw), _user(SAM_DEVICE))
    routes = {r["prefix"]: r for r in block["routes"]}
    assert routes["0.0.0.0/0"]["kind"] == "default" and routes["0.0.0.0/0"]["peer"] == {"org_node": _a(GW_HQ_1)}
    assert routes["10.160.20.0/24"]["source"] == "Site HQ Data Center network subnet"
    assert SPLIT_TUNNEL_NOTE not in block["not_collected"]
    assert "192.168.0.0/16 is excluded from the default gateway HQ Data Center" in block["not_collected"]


def test_without_session_details_every_user_may_hold_an_entitlement():
    raw = build_sample_raw()
    raw["session_details"] = None
    snapshot = build_snapshot(raw)
    rules = _set(_fwd(snapshot, _a(GW_AWS_1)))["rules"]
    first = rules[0]
    assert first["src"] == ["any"] and first["unresolved"] == [UNRESOLVED_USERS, "condition Business hours"]
    dana = _node(snapshot, _user(DANA_DEVICE))
    assert dana["ip"] == "" and dana["forwarding"]["not_collected"] == [NO_DETAILS_NOTE]
    # Without them a user's gateways are not known: it hangs off the collective.
    assert [e["b"] for e in snapshot["edges"] if e["a"] == dana["id"]] == [COLLECTIVE_NODE_ID]


def test_allowed_destinations_are_a_rule_set_of_their_own():
    raw = build_sample_raw()
    gateway = next(a for a in raw["appliances"] if a["id"] == GW_AWS_1)
    gateway["gateway"]["vpn"]["allowDestinations"] = [{"address": "10.161.20.0", "netmask": 24, "nic": "eth0"}]
    snapshot = build_snapshot(raw)
    allowed = _set(_fwd(snapshot, _a(GW_AWS_1)), "Allowed destinations")
    assert allowed["default"] == "deny" and [r["dst"] for r in allowed["rules"]] == [["10.161.20.0/24"]]
    assert _table(_node(snapshot, _a(GW_AWS_1)), "Allowed destinations") == [
        {"Network": "10.161.20.0/24", "Interface": "eth0"}
    ]


# ── Path traces through the sample ───────────────────────────────────────────


@pytest.fixture(scope="module")
def tracer(snapshot) -> Tracer:
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(nodes, edges, [(3, snapshot)], host_node=lambda _id: None, resolve_external=lambda *_: None)
    subnets = [{"org_ref": 3, **s} for s in subnet_index(snapshot)]
    return Tracer({"nodes": list(nodes.values()), "edges": edges}, {3: snapshot}, {}, {}, subnets)


def _labels(direction: dict) -> list[str]:
    return [h["label"] for h in direction["hops"]]


def _policies(hop: dict) -> list[tuple[str, str, str]]:
    return [(i["status"], i["where"], i["text"]) for i in hop["items"] if i["stage"] == "policy"]


def _from(device: str) -> dict:
    return {"source_node": f"meraki:3:{_user(device)}"}


def test_trace_a_user_to_an_entitled_server_is_allowed(tracer):
    result = tracer.trace("10.253.0.11", "10.160.10.25", **_from(DANA_DEVICE), protocol="tcp", port=443)
    assert result["verdict"] == "allowed", result["summary"]
    assert _labels(result["request"]) == ["dana.reyes", "appgate-gw-hq-1"]
    assert all(h["provider"] == "appgate" for h in result["request"]["hops"])
    [(status, name, text)] = _policies(result["request"]["hops"][1])
    assert (status, name) == ("ok", "Entitlements") and text.startswith("Rule 3 HQ web servers")
    # The reply follows the Gateway's route to the user's tunnel address.
    reply = result["reply"]
    assert _labels(reply) == ["appgate-gw-hq-1", "dana.reyes"]
    assert _policies(reply["hops"][0]) == [("info", "Entitlements", STATEFUL_REPLY)]
    route = next(i for i in reply["hops"][0]["items"] if i["stage"] == "route")
    assert route["where"] == "Appgate client session" and "10.253.0.11/32" in route["text"]
    assert result["asymmetric"]["status"] == "no"


def test_trace_a_port_no_entitlement_covers_is_blocked_by_the_default_deny(tracer):
    result = tracer.trace("10.253.0.11", "10.160.10.25", **_from(DANA_DEVICE), protocol="tcp", port=22)
    assert result["verdict"] == "blocked"
    assert result["request"]["summary"].startswith(
        "Blocked at appgate-gw-hq-1, Entitlements: No rule matches: the default action denies it."
    )


def test_trace_an_admin_may_use_ssh(tracer):
    result = tracer.trace("10.253.0.12", "10.160.10.25", **_from(SAM_DEVICE), protocol="tcp", port=22)
    assert result["verdict"] == "allowed", result["summary"]
    [(status, _name, text)] = _policies(result["request"]["hops"][1])
    assert status == "ok" and text.startswith("Rule 1 HQ admin SSH")
    # The legacy telnet entitlement blocks.
    telnet = tracer.trace("10.253.0.12", "10.160.10.25", **_from(SAM_DEVICE), protocol="tcp", port=23)
    assert telnet["verdict"] == "blocked" and "Rule 2 HQ legacy telnet" in telnet["summary"]


def test_trace_to_the_internet_has_no_route_on_a_split_tunnel(tracer):
    result = tracer.trace("10.253.0.11", "8.8.8.8", **_from(DANA_DEVICE), protocol="tcp", port=443)
    assert result["verdict"] == "blocked" and _labels(result["request"]) == ["dana.reyes"]
    items = result["request"]["hops"][0]["items"]
    assert any(i["where"] == SPLIT_TUNNEL_NOTE for i in items)
    assert next(i for i in items if i["stage"] == "route")["text"] == "No route to 8.8.8.8."


def test_trace_a_service_account_to_the_aws_app_tier(tracer):
    result = tracer.trace("10.253.0.14", "10.161.20.10", **_from(SCANNER_DEVICE), protocol="tcp", port=8443)
    assert result["verdict"] == "allowed", result["summary"]
    assert _labels(result["request"]) == ["svc-scanner", "appgate-gw-aws-1"]
    [(status, _name, text)] = _policies(result["request"]["hops"][1])
    assert status == "ok" and text.startswith("Rule 1 AWS app tier")
    assert _labels(result["reply"]) == ["appgate-gw-aws-1", "svc-scanner"]


def test_trace_a_reply_back_to_a_users_tunnel_address(tracer):
    # A flow the resource opens to the client ("tcp_down"): the Gateway's /32 route
    # takes it over the tunnel to dana's tunnel address.
    result = tracer.trace("10.161.20.10", "10.253.0.11", protocol="tcp", port=443)
    assert result["verdict"] == "allowed", result["summary"]
    request = result["request"]
    assert _labels(request) == ["appgate-gw-aws-1", "dana.reyes"]
    [(status, _name, text)] = _policies(request["hops"][0])
    assert status == "ok" and text.startswith("Rule 3 AWS app tier")
    route = next(i for i in request["hops"][0]["items"] if i["stage"] == "route")
    assert route["where"] == "Appgate client session"
    assert request["hops"][-1]["items"][-1]["text"] == "10.253.0.11 is an address of this device (Appgate Client)."
    # Any other port from the server side is not opened by an entitlement.
    other = tracer.trace("10.161.20.10", "10.253.0.11", protocol="tcp", port=22)
    assert other["verdict"] == "blocked" and _labels(other["request"]) == ["appgate-gw-aws-1"]


# ── HTTP API ─────────────────────────────────────────────────────────────────


class _CsrfClient:
    def __init__(self, client, csrf):
        self._c, self._headers = client, {"X-CSRF-Token": csrf}

    def get(self, url, **kw):
        return self._c.get(url, **kw)

    def post(self, url, **kw):
        return self._c.post(url, headers=self._headers, **kw)

    def put(self, url, **kw):
        return self._c.put(url, headers=self._headers, **kw)

    def delete(self, url, **kw):
        return self._c.delete(url, headers=self._headers, **kw)


@pytest.fixture
def api(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-appgate")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    import netcontrol.routes.meraki_topology as routes_module
    from netcontrol.routes.topology import invalidate_topology_cache

    def forget() -> None:
        # The samples must not leak into the next test's map.
        routes_module._SNAPSHOT_CACHE.clear()
        routes_module._HOST_FORWARDING.clear()
        invalidate_topology_cache()

    forget()
    request.addfinalizer(forget)

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return _CsrfClient(client, resp.json().get("csrf_token", ""))


def _wait(api, job_id: str) -> dict:
    job: dict = {}
    for _ in range(400):
        job = api.get(f"/api/meraki/builds/{job_id}").json()
        if job["status"] != "running":
            break
    return job


def test_api_appgate_crud_keeps_the_password_write_only(api):
    listing = api.get("/api/meraki/orgs").json()
    assert listing["appgate_default_options"] == DEFAULT_OPTIONS and "panorama_default_options" in listing
    body = {
        "name": "Prod Appgate",
        "provider": "appgate",
        "org_id": "local",
        "base_url": "https://appgate.example.com:8443/admin/",
        "api_key": PASSWORD,
        "options": {"username": "plexus", "verify_tls": False, "include_users": 0},
    }
    created = api.post("/api/meraki/orgs", json=body)
    assert created.status_code == 201, created.text
    org = created.json()["org"]
    assert org["provider"] == "appgate" and org["has_api_key"] is True and org["org_id"] == "local"
    assert org["base_url"] == "https://appgate.example.com:8443"
    assert org["options"] == {**DEFAULT_OPTIONS, "username": "plexus", "verify_tls": False, "include_users": False}
    assert PASSWORD not in created.text and PASSWORD not in api.get("/api/meraki/orgs").text

    bad = {"name": "Evil", "provider": "appgate", "base_url": "http://appgate.example.com"}
    assert api.post("/api/meraki/orgs", json=bad).status_code == 400
    bad["base_url"] = "https://appgate.example.com/ui"
    assert api.post("/api/meraki/orgs", json=bad).status_code == 400
    unknown = api.post("/api/meraki/orgs", json={"name": "X", "provider": "zscaler"})
    assert unknown.status_code == 400 and "Provider must be meraki, cato, fmc, panorama or appgate" in unknown.text

    updated = api.put(f"/api/meraki/orgs/{org['id']}", json={"options": {"username": "ro"}})
    assert updated.json()["org"]["options"]["username"] == "ro" and updated.json()["org"]["has_api_key"] is True
    assert api.delete(f"/api/meraki/orgs/{org['id']}").status_code == 200


def test_api_appgate_sample_is_merged_into_the_topology(api):
    built = api.post("/api/meraki/sample?provider=appgate")
    assert built.status_code == 201, built.text
    assert built.json()["summary"]["remote_users"] == 4
    org_ref = built.json()["org_ref"]
    org = next(o for o in api.get("/api/meraki/orgs").json()["orgs"] if o["id"] == org_ref)
    assert org["name"] == "Sample Appgate SDP (demo data)" and org["base_url"] == "https://10.160.1.10:8443"
    assert org["options"]["username"] == "plexus-readonly" and org["org_id"] == "local"

    graph = api.get("/api/topology").json()
    ours = [n for n in graph["nodes"] if (n.get("meraki") or {}).get("provider") == "appgate"]
    assert {n["meraki"]["kind"] for n in ours} == {"appliance", "cloud", "user"}
    assert {"management", "vpn"} == {e["protocol"] for e in graph["edges"] if e.get("provider") == "appgate"}

    details = api.get(f"/api/meraki/nodes?org_ref={org_ref}&node_id={_a(GW_HQ_1)}").json()
    assert details["provider"] == "appgate" and "Entitlements" in [s["title"] for s in details["sections"]]
    subnets = api.get("/api/meraki/subnets").json()["subnets"]
    servers = next(s for s in subnets if s["cidr"] == "10.160.10.0/24")
    assert servers["provider"] == "appgate" and servers["kind"] == "range" and servers["node_id"] == _a(GW_HQ_1)
    hits = api.get("/api/topology/search/deep?q=dana.reyes").json()["results"]
    assert (org_ref, _user(DANA_DEVICE)) in [(h["org_ref"], h["node_id"]) for h in hits]
    source = next(s for s in api.get("/api/topology/sources").json()["sources"] if s["type"] == "appgate")
    assert source["demo"] and not source["can_collect"] and source["status"] == "success"
    export = api.get("/api/topology/export.html")
    assert export.status_code == 200 and "appgate-gw-hq-1" in export.text

    path = api.get(
        f"/api/topology/path?source=10.253.0.11&destination=10.160.10.25&protocol=tcp&port=443"
        f"&source_node=meraki:{org_ref}:{_user(DANA_DEVICE)}"
    )
    assert path.status_code == 200 and path.json()["verdict"] == "allowed", path.text
    # Rebuilding refreshes the same entry.
    assert api.post("/api/meraki/sample?provider=appgate").json()["org_ref"] == org_ref


def test_api_appgate_build_job_runs_the_collector_with_the_fake_controller(api, monkeypatch):
    import netcontrol.routes.meraki_topology as routes_module

    fake = _FakeController()
    fake.fail = {"/ringfence-rules": 403}
    real_client = routes_module.AppgateClient

    def _client_factory(base_url, username, password, **kwargs):
        assert (base_url, username, password) == (BASE, "plexus", PASSWORD)
        assert kwargs["provider_name"] == "local" and kwargs["verify_tls"] is False
        kwargs.update(transport=httpx.MockTransport(fake.handler), requests_per_second=1000)
        return real_client(base_url, username, password, **kwargs)

    monkeypatch.setattr(routes_module, "AppgateClient", _client_factory)
    body = {
        "name": "Prod Appgate",
        "provider": "appgate",
        "base_url": BASE,
        "api_key": PASSWORD,
        "options": {"username": "plexus", "verify_tls": False},
    }
    org = api.post("/api/meraki/orgs", json=body).json()["org"]
    job = _wait(api, api.post(f"/api/meraki/orgs/{org['id']}/build").json()["job_id"])
    assert job["status"] == "partial", job
    assert job["result"]["warning_count"] == 1 and job["result"]["summary"]["devices"] == 8
    snapshot = api.get(f"/api/meraki/snapshots/{job['result']['snapshot_id']}/data")
    assert snapshot.json()["provider"] == "appgate" and snapshot.json()["org"]["name"] == "Prod Appgate"
    for secret in (PASSWORD, "token-1", P12, SHARED_SECRET):
        assert secret not in snapshot.text
    assert fake.logouts >= 1

    checked = api.post(f"/api/meraki/orgs/{org['id']}/validate").json()
    assert checked == {
        "ok": True,
        "message": "Login OK: Appgate SDP peer v22, 3 sites, 8 appliances",
        "organizations": [{"id": "local", "name": "Prod Appgate"}],
    }
    api.put(f"/api/meraki/orgs/{org['id']}", json={"api_key": "wrong"})

    def _any_password(base_url, username, password, **kwargs):
        return real_client(base_url, username, password, **{**kwargs, "transport": httpx.MockTransport(fake.handler)})

    monkeypatch.setattr(routes_module, "AppgateClient", _any_password)
    checked = api.post(f"/api/meraki/orgs/{org['id']}/validate").json()
    assert checked["ok"] is False and checked["message"] == "Appgate rejected the login (HTTP 401)"


def test_api_appgate_needs_a_user_name(api):
    body = {"name": "No user", "provider": "appgate", "base_url": BASE, "api_key": PASSWORD}
    org = api.post("/api/meraki/orgs", json=body).json()["org"]
    checked = api.post(f"/api/meraki/orgs/{org['id']}/validate").json()
    assert checked == {"ok": False, "message": "Set the admin user name on this entry", "organizations": []}
    job = _wait(api, api.post(f"/api/meraki/orgs/{org['id']}/build").json()["job_id"])
    assert job["status"] == "failed" and job["error"] == "Set the admin user name on this entry"
