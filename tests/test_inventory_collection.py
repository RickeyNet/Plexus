"""The "All other devices (SSH)" topology source.

SSH is never opened: the API tests replace the per-host capture
(``inventory_collection._capture_host``), and the capture tests replace the
Netmiko session with a fake one.
"""

from __future__ import annotations

import asyncio
import time

import netcontrol.app as app_module
import netcontrol.routes.inventory_collection as collection
import netcontrol.routes.state as state
import pytest
import routes.database as db_module
from netcontrol.drivers import get_driver
from netcontrol.routes.audit import _parse_vlan_csv
from netcontrol.routes.route_capture import (
    _is_route_table,
    _parse_route_summary_count,
    _route_table_commands,
    assemble_route_text,
    read_route_table,
)
from ntc_templates.parse import parse_output

import pg_raw

_TABLE = """\
Codes: L - local, C - connected, S - static
Gateway of last resort is 10.0.0.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 10.0.0.1
C        10.1.10.0/24 is directly connected, Vlan10
"""
_VRFS = "Routing Table: GUEST\nC        10.99.0.0/30 is directly connected, GigabitEthernet1/0/2\n"
_CONFIG = "hostname core-sw1\n!\ninterface Vlan10\n ip address 10.1.10.1 255.255.255.0\n"


# ── Shared route helpers ─────────────────────────────────────────────────────


def test_route_helpers_are_shared_with_monitoring():
    import netcontrol.routes.monitoring as monitoring

    assert monitoring._is_route_table is _is_route_table
    assert monitoring._parse_route_summary_count is _parse_route_summary_count
    assert monitoring._route_table_commands is _route_table_commands
    assert _route_table_commands("cisco_nxos").all_vrfs == "show ip route vrf all"
    assert _route_table_commands("no_such_platform").table == "show ip route"
    assert not _is_route_table("% Invalid input detected at '^' marker.") and _is_route_table(_TABLE)


def test_assemble_route_text_matches_the_poll():
    text, count = assemble_route_text(_TABLE, _VRFS, None)
    assert text == _TABLE.strip() + "\n\n" + _VRFS.strip() and count == 2
    # The summary total wins; a rejected VRF command keeps the global table alone.
    assert assemble_route_text(_TABLE, "% Invalid input", 40) == (_TABLE.strip(), 40)
    assert assemble_route_text("", _VRFS, 7) == ("", 7)
    assert assemble_route_text("  ", "", None) == ("", 0)


class _FakeSsh:
    """A netmiko connection that answers each command from ``outputs``. With
    ``platform``, ``use_textfsm`` parses the answer through ntc-templates as
    Netmiko does (rows, or the raw text when no template parsed it)."""

    def __init__(self, outputs: dict[str, str], fail: tuple[str, ...] = (), platform: str | None = None):
        self.outputs, self.fail, self.platform = outputs, fail, platform
        self.sent: list[str] = []
        self.closed = False

    def send_command(self, command: str, read_timeout: float | None = None, use_textfsm: bool = False):
        self.sent.append(command)
        if command in self.fail:
            raise OSError("channel closed")
        output = self.outputs.get(command, "")
        if use_textfsm and self.platform and output:
            try:
                return parse_output(platform=self.platform, command=command, data=output) or output
            except Exception:  # no template for the command: Netmiko returns the text
                return output
        return output

    def disconnect(self) -> None:
        self.closed = True


def test_read_route_table_uses_the_summary_count():
    summary = "Route Source    Networks    Subnets\nTotal           3           9"
    fake = _FakeSsh({"show ip route summary": summary, "show ip route": _TABLE, "show ip route vrf *": _VRFS})
    text, count = read_route_table(fake, _route_table_commands("cisco_xe"), 30)
    assert fake.sent == ["show ip route summary", "show ip route", "show ip route vrf *"]
    assert count == 12 and text.endswith(_VRFS.strip())


def _fake_session(monkeypatch, fake: _FakeSsh, resolved: str | None = None):
    opened: list[str] = []

    def _open(host, _credential):
        opened.append(host["ip_address"])
        return fake, resolved or host["device_type"]

    monkeypatch.setattr(collection, "_open_netmiko_session", _open)
    return opened


def test_capture_reads_routes_and_configuration_in_one_session(monkeypatch):
    fake = _FakeSsh({"show ip route": _TABLE, "show running-config": _CONFIG})
    opened = _fake_session(monkeypatch, fake)
    outcome = collection._capture_host({"ip_address": "10.0.0.2", "device_type": "cisco_xe"}, {})
    assert opened == ["10.0.0.2"] and fake.closed
    assert outcome["routes"] == (_TABLE.strip(), 2) and outcome["config"] == _CONFIG and outcome["errors"] == []
    # Nothing but show commands is sent.
    assert all(command.startswith("show ") for command in fake.sent)


def test_capture_sends_a_type_without_a_driver_the_ios_commands_and_keeps_partial_reads(monkeypatch):
    # Aruba has no driver: the IOS commands, as the monitoring poll and Config Backups send.
    fake = _FakeSsh({"show ip route": _TABLE, "show running-config": _CONFIG})
    opened = _fake_session(monkeypatch, fake)
    outcome = collection._capture_host({"ip_address": "10.0.0.3", "device_type": "aruba_aoscx"}, {})
    assert opened == ["10.0.0.3"] and not outcome["skipped"]
    assert outcome["routes"] == (_TABLE.strip(), 2) and outcome["config"] == _CONFIG
    # The table commands too (a rejected or empty status table sends no switchport command).
    assert fake.sent == [
        "show ip route summary",
        "show ip route",
        "show ip route vrf *",
        "show running-config",
        "show vlan brief",
        "show interfaces status",
        "show cdp neighbors detail",
        "show lldp neighbors detail",
        "show mac address-table",
    ]
    assert outcome["errors"] == [] and all(outcome[part] is None for part in collection.TABLE_PARTS)

    # Junos: its own configuration command; a failed route read keeps the configuration.
    fake = _FakeSsh({"show configuration | display set": "set system host-name edge1"}, fail=("show route",))
    _fake_session(monkeypatch, fake)
    outcome = collection._capture_host({"ip_address": "10.0.0.4", "device_type": "juniper_junos"}, {})
    assert outcome["routes"] is None and outcome["config"] == "set system host-name edge1"
    assert outcome["errors"] and "Route table not read" in outcome["errors"][0]


# ── API ──────────────────────────────────────────────────────────────────────


class _CsrfClient:
    def __init__(self, client, csrf):
        self._c, self._headers = client, {"X-CSRF-Token": csrf}

    def get(self, url, **kw):
        return self._c.get(url, **kw)

    def post(self, url, **kw):
        return self._c.post(url, headers=self._headers, **kw)

    def put(self, url, **kw):
        return self._c.put(url, headers=self._headers, **kw)


@pytest.fixture
def api(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-inventory-collection")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    monkeypatch.setitem(state.AUTH_CONFIG, "service_credential_id", None)
    collection._running.clear()

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    # Startup seeds the demo inventory; these tests count their own hosts.
    asyncio.run(pg_raw.execute("DELETE FROM hosts"))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return _CsrfClient(client, resp.json().get("csrf_token", ""))


def _group(api, name: str) -> int:
    group = api.post("/api/inventory", json={"name": name, "description": ""})
    assert group.status_code in (200, 201), group.text
    return group.json()["id"]


def _host(api, group_id: int, hostname: str, ip: str, device_type: str = "cisco_xe") -> int:
    host = api.post(
        f"/api/inventory/{group_id}/hosts",
        json={"hostname": hostname, "ip_address": ip, "device_type": device_type},
    )
    assert host.status_code in (200, 201), host.text
    return host.json()["id"]


def _service_credential(api, monkeypatch) -> int:
    created = api.post(
        "/api/credentials/service", json={"name": "plexus-svc", "username": "svc", "password": "svc-password"}
    )
    assert created.status_code == 201, created.text
    monkeypatch.setitem(state.AUTH_CONFIG, "service_credential_id", created.json()["id"])
    return created.json()["id"]


def _source(api) -> dict:
    sources = api.get("/api/topology/sources").json()["sources"]
    assert [s["key"] for s in sources[:2]] == ["neighbors", "inventory"]
    return sources[1]


def _fake_capture(
    monkeypatch, *, fail: set[str] | None = None, config: str | None = _CONFIG, tables: dict[str, dict] | None = None
):
    """Replace the SSH capture: every host answers with ``_TABLE`` and
    ``config``, plus the table parts ``tables`` names for its hostname."""
    captured: list[str] = []

    def _capture(host, credential):
        assert credential.get("username")
        captured.append(host["hostname"])
        if host["hostname"] in (fail or set()):
            raise OSError("Authentication to device failed.")
        parts = (tables or {}).get(host["hostname"], {})
        return {"skipped": False, "routes": (_TABLE.strip(), 2), "config": config, "errors": [], **parts}

    monkeypatch.setattr(collection, "_capture_host", _capture)
    return captured


def _on_app_loop(api, fn, *args):
    """Run a database facade call on the TestClient's event loop, whose pools it uses."""
    return api._c.portal.call(fn, *args)


def _run(api, body: dict | None = None) -> dict:
    started = api.post("/api/topology/inventory/collect", json=body or {})
    assert started.status_code == 202, started.text
    assert started.json()["status"] == "running"
    job: dict = {}
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        job = api.get(f"/api/sources/builds/{started.json()['job_id']}").json()
        if job["status"] != "running":
            break
        time.sleep(0.02)
    assert job.get("kind") == collection.JOB_KIND, job
    return job


def test_source_entry_before_any_run(api, monkeypatch):
    source = _source(api)
    assert source["type"] == "inventory" and source["id"] is None
    assert source["name"] == "All other devices (SSH)"
    assert (source["status"], source["last_collected_at"], source["can_collect"]) == ("never", None, False)
    assert source["service_credential"] is False and source["service_credential_id"] is None
    assert source["collecting"] is False
    assert source["detail"] == "0 devices in inventory"

    group_id = _group(api, "core")
    _host(api, group_id, "pinger", "10.0.0.9", device_type="icmp_only")
    assert _source(api)["can_collect"] is False  # an icmp_only host is not collectable
    _host(api, group_id, "core-sw1", "10.0.0.2")
    service_id = _service_credential(api, monkeypatch)
    source = _source(api)
    assert source["can_collect"] is True and source["service_credential"] is True
    assert source["service_credential_id"] == service_id
    assert source["detail"] == "1 device in inventory"


def test_collection_stores_routes_and_configuration_for_the_tracer(api, monkeypatch):
    group_id = _group(api, "core")
    first = _host(api, group_id, "core-sw1", "10.0.0.2")
    second = _host(api, group_id, "core-sw2", "10.0.0.3", device_type="cisco_nxos")
    _service_credential(api, monkeypatch)
    captured = _fake_capture(monkeypatch)

    job = _run(api)
    assert job["status"] == "completed", job
    assert sorted(captured) == ["core-sw1", "core-sw2"]
    result = job["result"]
    assert {k: result[k] for k in ("hosts", "collected", "routes", "configs", "skipped", "warning_count")} == {
        "hosts": 2,
        "collected": 2,
        "routes": 2,
        "configs": 2,
        "skipped": 0,
        "warning_count": 0,
    }
    assert result["errors"] == [] and result["duration_seconds"] >= 0
    assert job["progress"]["hosts_done"] == 2 and job["progress"]["hosts_total"] == 2

    # What the tracer reads (run on the app's own event loop).
    routes = _on_app_loop(api, db_module.get_latest_route_snapshots_for_hosts, [first, second])
    configs = _on_app_loop(api, db_module.get_latest_config_texts_for_hosts, [first, second])
    assert set(routes) == {first, second} and routes[first]["routes_text"] == _TABLE.strip()
    assert routes[first]["route_count"] == 2
    assert set(configs) == {first, second} and configs[second]["config_text"] == _CONFIG

    source = _source(api)
    assert source["status"] == "success" and source["last_collected_at"]
    assert "+00:00" in source["last_collected_at"]
    assert source["detail"] == (
        "2 of 2 devices: 2 route tables, 2 configurations, 0 VLAN tables, 0 port tables, "
        "0 neighbor tables, 0 MAC tables"
    )
    assert source["warning_count"] == 0 and source["message"] == ""
    setting = _on_app_loop(api, db_module.get_auth_setting, collection.SETTING_KEY)
    assert setting["status"] == "success" and setting["scope"] == "all" and setting["collected"] == 2

    # A second run with the same text writes no new rows.
    def _counts() -> tuple[int, int]:
        return (
            asyncio.run(pg_raw.fetchval("SELECT COUNT(*) FROM route_snapshots")),
            asyncio.run(pg_raw.fetchval("SELECT COUNT(*) FROM config_backups WHERE capture_method = 'topology'")),
        )

    assert _counts() == (2, 2)
    again = _run(api)
    assert again["status"] == "completed" and again["result"]["collected"] == 2
    assert _counts() == (2, 2)


def test_a_failed_host_is_reported_and_the_run_is_partial(api, monkeypatch):
    group_id = _group(api, "core")
    _host(api, group_id, "core-sw1", "10.0.0.2")
    bad = _host(api, group_id, "core-sw2", "10.0.0.3")
    _service_credential(api, monkeypatch)
    _fake_capture(monkeypatch, fail={"core-sw2"})

    job = _run(api)
    assert job["status"] == "partial", job
    assert job["result"]["collected"] == 1 and job["result"]["warning_count"] == 1
    [error] = job["result"]["errors"]
    assert error["host_id"] == bad and error["hostname"] == "core-sw2" and error["ip_address"] == "10.0.0.3"
    assert "Authentication" in error["message"]
    source = _source(api)
    assert source["status"] == "partial" and source["warning_count"] == 1
    assert source["detail"].startswith("1 of 2 devices: 1 route table, 1 configuration, 0 VLAN tables")


def test_every_host_failing_fails_the_run(api, monkeypatch):
    _host(api, _group(api, "core"), "core-sw1", "10.0.0.2")
    _service_credential(api, monkeypatch)
    _fake_capture(monkeypatch, fail={"core-sw1"})
    job = _run(api)
    assert job["status"] == "failed" and "Authentication" in job["error"]
    source = _source(api)
    assert source["status"] == "failed" and source["message"] == job["error"]


def test_scope_by_group_and_by_host_ids(api, monkeypatch):
    core = _group(api, "core")
    branch = _group(api, "branch")
    _host(api, core, "core-sw1", "10.0.0.2")
    branch_host = _host(api, branch, "branch-rtr1", "10.9.0.1", device_type="cisco_ios")
    _service_credential(api, monkeypatch)
    captured = _fake_capture(monkeypatch)

    assert _run(api, {"group_id": branch})["result"]["hosts"] == 1
    assert captured == ["branch-rtr1"]
    setting = api.get("/api/topology/sources").json()["sources"][1]
    assert setting["detail"].startswith("1 of 1 device:")

    captured.clear()
    assert _run(api, {"host_ids": [branch_host], "group_id": core})["result"]["hosts"] == 1
    assert captured == ["branch-rtr1"]

    unknown = api.post("/api/topology/inventory/collect", json={"host_ids": [branch_host, 999999]})
    assert unknown.status_code == 400 and "999999" in unknown.json()["error"]["message"]
    assert api.post("/api/topology/inventory/collect", json={"group_id": 999999}).status_code == 404


def test_collect_needs_a_credential_and_a_collectable_host(api, monkeypatch):
    _fake_capture(monkeypatch)
    no_hosts = api.post("/api/topology/inventory/collect", json={})
    assert no_hosts.status_code == 400
    _host(api, _group(api, "core"), "core-sw1", "10.0.0.2")
    no_cred = api.post("/api/topology/inventory/collect", json={})
    assert no_cred.status_code == 400 and "No credential" in no_cred.json()["error"]["message"]

    # A user's own stored credential can be picked instead of the service one.
    own = api.post("/api/credentials", json={"name": "mine", "username": "netops", "password": "pw-123456"})
    assert own.status_code == 201, own.text
    job = _run(api, {"credential_id": own.json()["id"]})
    assert job["status"] == "completed"
    assert api.post("/api/topology/inventory/collect", json={"credential_id": 999999}).status_code == 404


def test_a_running_collection_is_not_started_twice(api, monkeypatch):
    _host(api, _group(api, "core"), "core-sw1", "10.0.0.2")
    _service_credential(api, monkeypatch)
    monkeypatch.setitem(collection._running, "job", "busy")
    assert _source(api)["collecting"] is True
    busy = api.post("/api/topology/inventory/collect", json={})
    assert busy.status_code == 409


def test_build_endpoint_returns_only_collection_jobs(api):
    from netcontrol.routes import background_jobs

    other = background_jobs.create_job("something-else")
    assert api.get(f"/api/sources/builds/{other['job_id']}").status_code == 404
    mine = background_jobs.create_job(collection.JOB_KIND, {"phase": "starting"})
    found = api.get(f"/api/sources/builds/{mine['job_id']}")
    assert found.status_code == 200 and found.json()["progress"]["phase"] == "starting"


def test_a_read_only_topology_user_cannot_collect(api, monkeypatch):
    _host(api, _group(api, "core"), "core-sw1", "10.0.0.2")
    _service_credential(api, monkeypatch)
    _fake_capture(monkeypatch)
    group = api.post("/api/admin/access-groups", json={"name": "Topology viewers", "feature_keys": ["topology"]})
    assert group.status_code == 201, group.text
    user = api.post(
        "/api/admin/users",
        json={"username": "viewer", "password": "viewer-password", "group_ids": [group.json()["id"]]},
    )
    assert user.status_code == 201, user.text

    login = api._c.post("/api/auth/login", json={"username": "viewer", "password": "viewer-password"})
    assert login.status_code == 200, login.text
    viewer = _CsrfClient(api._c, login.json().get("csrf_token", ""))
    assert viewer.get("/api/topology/sources").status_code == 200
    denied = viewer.post("/api/topology/inventory/collect", json={})
    assert denied.status_code == 403 and "topology.write" in denied.json()["error"]["message"]


# ── VLAN, port, neighbor and MAC tables ──────────────────────────────────────

_IOS_VLAN = """\
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi1/0/3, Gi1/0/4
99   MGMT                             active
1002 fddi-default                     act/unsup
1007 SW_MGMT_Sensors                  active    Gi1/0/5
2160 Cameras_2160                     active
"""

_IOS_STATUS = """\

Port         Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1      AP-Lobby           connected    trunk      a-full a-1000 10/100/1000BaseTX
Gi1/0/2                         notconnect   10           auto   auto 10/100/1000BaseTX
Gi1/0/3      Printer            connected    10         a-full  a-100 10/100/1000BaseTX
Gi1/0/4                         disabled     1            auto   auto 10/100/1000BaseTX
Te1/1/1      Uplink-core        connected    trunk        full    10G SFP-10GBase-SR
"""

_IOS_SWITCHPORT = """\
Name: Gi1/0/1
Switchport: Enabled
Administrative Mode: trunk
Operational Mode: trunk
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: dot1q
Negotiation of Trunking: On
Access Mode VLAN: 1 (default)
Trunking Native Mode VLAN: 1 (default)
Administrative Native VLAN tagging: enabled
Voice VLAN: none
Administrative private-vlan host-association: none
Operational private-vlan: none
Trunking VLANs Enabled: 1-5,10
Pruning VLANs Enabled: 2-1001
Capture Mode Disabled
Capture VLANs Allowed: ALL

Protected: false
Unknown unicast blocked: disabled
Appliance trust: none

Name: Gi1/0/3
Switchport: Enabled
Administrative Mode: static access
Operational Mode: static access
Negotiation of Trunking: Off
Access Mode VLAN: 10 (Printers)
Trunking Native Mode VLAN: 1 (default)
Voice VLAN: none
Trunking VLANs Enabled: ALL
Pruning VLANs Enabled: 2-1001

Protected: false

Name: Te1/1/1
Switchport: Enabled
Administrative Mode: trunk
Operational Mode: trunk
Access Mode VLAN: 1 (default)
Trunking Native Mode VLAN: 1 (default)
Voice VLAN: none
Trunking VLANs Enabled: ALL
Pruning VLANs Enabled: 2-1001

Protected: false
"""

_IOS_CDP = """\
-------------------------
Device ID: core-sw1.example.com
Entry address(es):
  IP address: 10.0.0.1
Platform: cisco C9500-48Y4C,  Capabilities: Router Switch IGMP
Interface: TenGigabitEthernet1/1/1,  Port ID (outgoing port): TenGigabitEthernet1/0/48
Holdtime : 150 sec

Version :
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)

advertisement version: 2
Native VLAN: 1
Duplex: full


Total cdp entries displayed : 1
"""

_IOS_LLDP = """\
------------------------------------------------
Local Intf: Te1/1/1
Chassis id: 00a1.b2c3.d4e5
Port id: Te1/0/48
Port Description: TenGigabitEthernet1/0/48
System Name: core-sw1

System Description:
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)

Time remaining: 101 seconds
System Capabilities: B,R
Enabled Capabilities: B,R
Management Addresses:
    IP: 10.0.0.1
Auto Negotiation - not supported
Physical media capabilities - not advertised
Media Attachment Unit type - not advertised
Vlan ID: - not advertised

------------------------------------------------
Local Intf: Gi1/0/1
Chassis id: 0011.2233.4455
Port id: eth0
Port Description: eth0
System Name: AP-Lobby

System Description:
Cisco AP Software, C9120AXI-B

Time remaining: 95 seconds
System Capabilities: B,W
Enabled Capabilities: B,W
Management Addresses:
    IP: 10.1.20.15
Auto Negotiation - supported, enabled
Physical media capabilities:
    1000baseT(FD)
Media Attachment Unit type: 30
Vlan ID: - not advertised

------------------------------------------------
Local Intf: Gi1/0/2
Chassis id: 10.1.30.7
Port id: 1
Port Description: 1
System Name: Polycom VVX 250

System Description:
Polycom;VVX-VVX_250;3111-48820-001,2;SIP/6.4.7.4560/05-Dec-24 01:01;UP/6.4.7.3828/05-Dec-24 01:26;

Time remaining: 110 seconds
System Capabilities: B,T
Enabled Capabilities: B,T
Management Addresses:
    IP: 10.1.30.7
Auto Negotiation - supported, enabled
Physical media capabilities:
    1000baseT(FD)
Media Attachment Unit type: 30
Vlan ID: 30


Total entries displayed: 3
"""

_IOS_MACS = """\
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  10    0050.56aa.0001    DYNAMIC     Gi1/0/3
  99    0050.56aa.0002    STATIC      Te1/1/1
Total Mac Addresses for this criterion: 2
"""

_NXOS_VLAN = """\

VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Eth1/3, Eth1/4
10   Servers                          active    Eth1/1, Eth1/2
2160 Cameras                          active
"""

_NXOS_STATUS = """\

--------------------------------------------------------------------------------
Port          Name               Status    Vlan      Duplex  Speed   Type
--------------------------------------------------------------------------------
mgmt0         --                 connected routed    full    1000    --
Eth1/1        server-a           connected 10        full    10G     10Gbase-SR
Eth1/2        --                 notconnec 1         auto    auto    10Gbase-SR
Eth1/49       uplink             connected trunk     full    40G     QSFP-40G-SR4
"""

# A Catalyst 9300 configuration: VLANs declared, few with an SVI.
_VLAN_CONFIG = """\
hostname access-sw1
!
vlan internal allocation policy ascending
!
vlan 99
 name MGMT
!
vlan 1007
 name SW_MGMT_Sensors
!
vlan 2160
 name Cameras_2160
vlan 300,310-311
!
interface Vlan99
 ip address 10.99.0.2 255.255.255.0
"""


def _parsed(platform: str, command: str, data: str) -> list[dict]:
    rows = parse_output(platform=platform, command=command, data=data)
    assert isinstance(rows, list) and rows, f"{platform} {command} not parsed"
    return rows


def test_ios_vlans_parse_with_extended_ids():
    driver = get_driver("cisco_ios")
    assert driver.vlan_show_command() == "show vlan brief"
    vlans = driver.parse_vlans(_parsed("cisco_ios", "show vlan brief", _IOS_VLAN))
    assert [v["vlan_id"] for v in vlans] == [1, 99, 1002, 1007, 2160]
    assert {"vlan_id": 1007, "name": "SW_MGMT_Sensors", "state": "active"} in vlans
    assert {"vlan_id": 1002, "name": "fddi-default", "state": "act/unsup"} in vlans


def test_ios_ports_merge_status_and_switchport():
    driver = get_driver("cisco_xe")
    status = _parsed("cisco_ios", driver.interface_status_show_command(), _IOS_STATUS)
    switchport = _parsed("cisco_ios", driver.interface_switchport_show_command(), _IOS_SWITCHPORT)
    ports = {p["name"]: p for p in driver.parse_interfaces(status, switchport)}
    assert list(ports) == ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4", "Te1/1/1"]
    assert ports["Gi1/0/1"] == {
        "name": "Gi1/0/1",
        "description": "AP-Lobby",
        "admin_state": "up",
        "oper_state": "up",
        "speed_mbps": 1000,
        "duplex": "full",
        "access_vlan": 0,
        "trunk_vlans": "1,2,3,4,5,10",
    }
    # "ALL" is stored as the literal range, which the VLAN search still matches.
    assert ports["Te1/1/1"]["trunk_vlans"] == "1-4094" and ports["Te1/1/1"]["speed_mbps"] == 10000
    assert 2160 in _parse_vlan_csv(ports["Te1/1/1"]["trunk_vlans"]) and _parse_vlan_csv("1-3,7") == {1, 2, 3, 7}
    # An access port keeps its VLAN and no trunk list; a shut port is admin down.
    assert (ports["Gi1/0/3"]["access_vlan"], ports["Gi1/0/3"]["trunk_vlans"]) == (10, "")
    assert ports["Gi1/0/3"]["speed_mbps"] == 100
    assert (ports["Gi1/0/4"]["admin_state"], ports["Gi1/0/4"]["oper_state"]) == ("down", "down")
    assert (ports["Gi1/0/2"]["oper_state"], ports["Gi1/0/2"]["duplex"], ports["Gi1/0/2"]["access_vlan"]) == (
        "down",
        "unknown",
        10,
    )


def test_ios_neighbors_parse_and_a_cdp_lldp_pair_is_one_link():
    driver = get_driver("cisco_ios")
    commands = dict(driver.neighbor_show_commands())
    cdp = driver.parse_neighbors("cdp", _parsed("cisco_ios", commands["cdp"], _IOS_CDP))
    lldp = driver.parse_neighbors("lldp", _parsed("cisco_ios", commands["lldp"], _IOS_LLDP))
    assert cdp == [
        {
            "local_interface": "TenGigabitEthernet1/1/1",
            "remote_device_name": "core-sw1.example.com",
            "remote_ip": "10.0.0.1",
            "remote_interface": "TenGigabitEthernet1/0/48",
            "protocol": "cdp",
            "remote_platform": "cisco C9500-48Y4C",
            "remote_capabilities": "Router Switch IGMP",
        }
    ]
    assert [(n["local_interface"], n["remote_device_name"], n["remote_interface"]) for n in lldp] == [
        ("Te1/1/1", "core-sw1", "Te1/0/48"),
        ("Gi1/0/1", "AP-Lobby", "eth0"),
        ("Gi1/0/2", "Polycom VVX 250", "1"),
    ]
    assert [n["remote_capabilities"] for n in lldp] == ["B,R", "B,W", "B,T"]
    # Same local port and neighbor (short vs long port name, domain suffix): the CDP row stays.
    merged = collection._merge_neighbors(lldp + cdp)
    assert [(n["protocol"], n["remote_device_name"]) for n in merged] == [
        ("cdp", "core-sw1.example.com"),
        ("lldp", "AP-Lobby"),
        ("lldp", "Polycom VVX 250"),
    ]
    assert merged[0]["remote_platform"] == "cisco C9500-48Y4C"


def test_nxos_vlans_and_ports_parse():
    driver = get_driver("cisco_nxos")
    assert driver.interface_status_show_command() == "show interface status"
    vlans = driver.parse_vlans(_parsed("cisco_nxos", driver.vlan_show_command(), _NXOS_VLAN))
    assert [(v["vlan_id"], v["name"]) for v in vlans] == [(1, "default"), (10, "Servers"), (2160, "Cameras")]
    ports = {
        p["name"]: p for p in driver.parse_interfaces(_parsed("cisco_nxos", "show interface status", _NXOS_STATUS), [])
    }
    assert ports["Eth1/1"]["speed_mbps"] == 10000 and ports["Eth1/1"]["access_vlan"] == 10
    assert ports["mgmt0"]["description"] == "" and ports["mgmt0"]["access_vlan"] == 0
    assert ports["Eth1/2"]["oper_state"] == "down"
    # No switchport row: a trunk's allowed VLANs stay unknown rather than assumed.
    assert ports["Eth1/49"]["access_vlan"] == 0 and ports["Eth1/49"]["trunk_vlans"] == ""


def test_platform_table_commands():
    assert get_driver("arista_eos").neighbor_show_commands() == [("lldp", "show lldp neighbors detail")]
    assert get_driver("juniper_junos").vlan_show_command() == "show vlans"
    assert get_driver("juniper_junos").neighbor_show_commands() == [("lldp", "show lldp neighbors")]
    assert [p for p, _ in get_driver("cisco_xr").neighbor_show_commands()] == ["cdp", "lldp"]
    for firewall in ("cisco_ftd", "fortinet", "paloalto_panos"):
        with pytest.raises(NotImplementedError):
            get_driver(firewall).vlan_show_command()
    # A type without a driver reads its tables with the Cisco IOS driver.
    assert collection._table_driver("aruba_aoscx") is not None
    assert type(collection._table_driver("aruba_aoscx")).__name__ == "CiscoIOSDriver"


def test_config_vlan_blocks_are_the_fallback():
    vlans = get_driver("cisco_ios").parse_config_vlans(_VLAN_CONFIG)
    assert vlans == [
        {"vlan_id": 99, "name": "MGMT", "state": "active"},
        {"vlan_id": 300, "name": "", "state": "active"},
        {"vlan_id": 310, "name": "", "state": "active"},
        {"vlan_id": 311, "name": "", "state": "active"},
        {"vlan_id": 1007, "name": "SW_MGMT_Sensors", "state": "active"},
        {"vlan_id": 2160, "name": "Cameras_2160", "state": "active"},
    ]


def test_capture_reads_every_table_in_the_same_session(monkeypatch):
    fake = _FakeSsh(
        {
            "show ip route": _TABLE,
            "show running-config": _VLAN_CONFIG,
            # Rejected: the VLANs come from the configuration.
            "show vlan brief": "% Invalid input detected at '^' marker.",
            "show interfaces status": _IOS_STATUS,
            "show interfaces switchport": _IOS_SWITCHPORT,
            "show cdp neighbors detail": _IOS_CDP,
            "show lldp neighbors detail": _IOS_LLDP,
            "show mac address-table": _IOS_MACS,
        },
        platform="cisco_ios",
    )
    _fake_session(monkeypatch, fake)
    outcome = collection._capture_host({"ip_address": "10.0.0.5", "device_type": "cisco_xe"}, {})
    assert outcome["errors"] == [] and fake.closed
    assert [v["vlan_id"] for v in outcome["vlans"]] == [99, 300, 310, 311, 1007, 2160]
    assert len(outcome["interfaces"]) == 5 and len(outcome["neighbors"]) == 3
    assert outcome["macs"] == [
        {"mac": "00:50:56:aa:00:01", "vlan": 10, "port": "Gi1/0/3", "type": "dynamic"},
        {"mac": "00:50:56:aa:00:02", "vlan": 99, "port": "Te1/1/1", "type": "static"},
    ]
    assert all(command.startswith("show ") for command in fake.sent)

    # Printed but not parsed: one error per table; a failed command: "not read".
    fake = _FakeSsh(
        {"show interfaces status": "Port  Weird  Layout", "show mac address-table": "garbage"},
        fail=("show cdp neighbors detail",),
        platform="cisco_ios",
    )
    _fake_session(monkeypatch, fake)
    outcome = collection._capture_host({"ip_address": "10.0.0.6", "device_type": "cisco_ios"}, {})
    assert outcome["interfaces"] is None and outcome["neighbors"] is None and outcome["macs"] is None
    assert "Port table not parsed" in outcome["errors"] and "MAC table not parsed" in outcome["errors"]
    assert any(e.startswith("Neighbor table not read (OSError") for e in outcome["errors"])

    # A firewall has no table commands: nothing more is sent, and no error.
    fake = _FakeSsh({"show route": _TABLE, "show running-config": _CONFIG})
    _fake_session(monkeypatch, fake)
    outcome = collection._capture_host({"ip_address": "10.0.0.7", "device_type": "cisco_ftd"}, {})
    assert all(outcome[part] is None for part in collection.TABLE_PARTS)
    assert not any("table" in command or "vlan" in command for command in fake.sent)


def _ports(*names: str) -> list[dict]:
    return [
        {
            "name": name,
            "description": "",
            "admin_state": "up",
            "oper_state": "up",
            "speed_mbps": 1000,
            "duplex": "full",
            "access_vlan": 10,
            "trunk_vlans": "",
        }
        for name in names
    ]


def test_replace_interface_inventory_by_name(api):
    host_id = _host(api, _group(api, "core"), "core-sw1", "10.0.0.2")
    # Rows the SNMP collector wrote (positive ifIndex).
    for if_index, name in ((10101, "Gi1/0/1"), (10102, "Gi1/0/9")):
        _on_app_loop(
            api,
            db_module.upsert_interface_inventory,
            host_id,
            if_index,
            name,
            "snmp",
            "up",
            "up",
            1000,
            "full",
            "123",
            1,
            "",
        )

    def _rows() -> dict[str, tuple[int, str, int]]:
        rows = _on_app_loop(api, db_module.get_interface_inventory_for_host, host_id)
        return {r["name"]: (r["if_index"], r["last_change"], r["access_vlan"]) for r in rows}

    assert (
        _on_app_loop(
            api, db_module.replace_interface_inventory_by_name, host_id, _ports("Gi1/0/1", "Gi1/0/2", "Gi1/0/3")
        )
        == 3
    )
    assert _rows() == {
        "Gi1/0/1": (10101, "123", 10),  # updated in place: ifIndex and last change kept
        "Gi1/0/2": (-1, "", 10),
        "Gi1/0/3": (-2, "", 10),
        "Gi1/0/9": (10102, "123", 1),  # an SNMP row is never deleted here
    }
    _on_app_loop(api, db_module.replace_interface_inventory_by_name, host_id, _ports("Gi1/0/3", "Gi1/0/4"))
    assert _rows() == {
        "Gi1/0/1": (10101, "123", 10),
        "Gi1/0/3": (-2, "", 10),
        "Gi1/0/4": (-3, "", 10),
        "Gi1/0/9": (10102, "123", 1),
    }


def test_collection_stores_the_tables_and_counts_them(api, monkeypatch):
    group_id = _group(api, "core")
    first = _host(api, group_id, "access-sw1", "10.0.0.2")
    second = _host(api, group_id, "core-sw1", "10.0.0.1")
    _service_credential(api, monkeypatch)
    ios = get_driver("cisco_ios")
    vlans = ios.parse_config_vlans(_VLAN_CONFIG)
    ports = ios.parse_interfaces(
        _parsed("cisco_ios", "show interfaces status", _IOS_STATUS),
        _parsed("cisco_ios", "show interfaces switchport", _IOS_SWITCHPORT),
    )
    neighbors = collection._merge_neighbors(
        ios.parse_neighbors("cdp", _parsed("cisco_ios", "show cdp neighbors detail", _IOS_CDP))
        + ios.parse_neighbors("lldp", _parsed("cisco_ios", "show lldp neighbors detail", _IOS_LLDP))
    )
    macs = ios.parse_mac_table(_parsed("cisco_ios", "show mac address-table", _IOS_MACS))
    # The core switch's neighbor and MAC tables were not read.
    tables = {
        "access-sw1": {"vlans": vlans, "interfaces": ports, "neighbors": neighbors, "macs": macs},
        "core-sw1": {"vlans": vlans[:2], "interfaces": ports[:1]},
    }
    _fake_capture(monkeypatch, tables=tables)
    asyncio.run(
        pg_raw.execute(
            "INSERT INTO vlan_definitions (host_id, vlan_id, name, state) VALUES ($1, 5, 'old', 'operational')", first
        )
    )

    job = _run(api)
    assert job["status"] == "completed", job
    result = job["result"]
    assert set(result) == {
        "hosts",
        "collected",
        "routes",
        "configs",
        "vlans",
        "interfaces",
        "neighbors",
        "macs",
        "skipped",
        "errors",
        "warning_count",
        "duration_seconds",
    }
    assert {k: result[k] for k in ("vlans", "interfaces", "neighbors", "macs")} == {
        "vlans": 2,
        "interfaces": 2,
        "neighbors": 1,
        "macs": 1,
    }
    setting = _on_app_loop(api, db_module.get_auth_setting, collection.SETTING_KEY)
    assert (setting["vlans"], setting["interfaces"], setting["neighbors"], setting["macs"]) == (2, 2, 1, 1)
    assert _source(api)["detail"] == (
        "2 of 2 devices: 2 route tables, 2 configurations, 2 VLAN tables, 2 port tables, 1 neighbor table, 1 MAC table"
    )

    # VLANs: the config's ones, and the one this read did not list is gone.
    stored = _on_app_loop(api, db_module.get_vlan_definitions_for_host, first)
    assert [(v["vlan_id"], v["name"]) for v in stored][-2:] == [(1007, "SW_MGMT_Sensors"), (2160, "Cameras_2160")]
    assert 5 not in {v["vlan_id"] for v in stored}
    # Ports, with a trunk the VLAN search finds through its literal range.
    found = api.get("/api/topology/search/hosts-by-vlan", params={"vlan_id": 2160}).json()["hosts"]
    by_host = {h["host_id"]: h for h in found}
    assert "trunk" in by_host[first]["roles"] and "definition" in by_host[first]["roles"]
    assert {"name": "Te1/1/1", "kind": "trunk"} in by_host[first]["ports"]
    # Links, resolved to the inventory host the neighbor is.
    links = asyncio.run(
        pg_raw.fetch(
            "SELECT target_device_name, target_host_id, protocol, target_capabilities FROM topology_links "
            "WHERE source_host_id = $1 ORDER BY target_device_name",
            first,
        )
    )
    assert [(r["target_device_name"], r["target_host_id"], r["protocol"], r["target_capabilities"]) for r in links] == [
        ("AP-Lobby", None, "lldp", "B,W"),
        ("Polycom VVX 250", None, "lldp", "B,T"),
        ("core-sw1.example.com", second, "cdp", "Router Switch IGMP"),
    ]
    # The map: the phone is an end device (off the map until asked for), the AP is not.
    graph = api.get("/api/topology").json()
    by_label = {n["label"]: n for n in graph["nodes"]}
    assert by_label["Polycom VVX 250"]["end_device"] is True
    assert by_label["Polycom VVX 250"]["device_category"] == "phone"
    assert by_label["AP-Lobby"]["end_device"] is False
    macs_stored = asyncio.run(pg_raw.fetchval("SELECT COUNT(*) FROM mac_address_table WHERE host_id = $1", first))
    assert macs_stored == 2

    # A run that reads no VLAN table keeps the stored VLANs and links.
    _fake_capture(monkeypatch)
    assert _run(api)["result"]["vlans"] == 0
    assert len(_on_app_loop(api, db_module.get_vlan_definitions_for_host, first)) == len(stored)
    assert asyncio.run(pg_raw.fetchval("SELECT COUNT(*) FROM topology_links WHERE source_host_id = $1", first)) == 3


# ── The device's own name and interface addresses, from its configuration ──

# A core switch the IP sweep onboarded by its management address, which it
# advertises another of its addresses from (CDP / LLDP, Meraki).
_IDENTITY_CONFIG = """\
hostname CCM-Core-9500
!
interface Loopback0
 ip address 10.255.0.1 255.255.255.255
!
interface Vlan14
 ip address 10.175.14.2 255.255.255.0
 ip address 10.175.15.2 255.255.255.0 secondary
 standby 1 ip 10.175.14.1
!
interface GigabitEthernet0/0
 vrf forwarding Mgmt-vrf
 ip address 10.74.103.1 255.255.255.0
!
interface Vlan1
 no ip address
 shutdown
"""

_JUNOS_IDENTITY = """\
set system host-name srx-edge1
set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.2/30
set interfaces irb unit 10 family inet address 10.10.0.1/24
set interfaces lo0 unit 0 family inet address 10.255.1.1/32
set interfaces lo0 unit 0 family inet address 127.0.0.1/32
set interfaces lo0 unit 0 family inet6 address 2001:db8::1/128
"""


def test_placeholder_hostnames():
    from netcontrol.routes.host_identity import is_placeholder_hostname, placeholder_hostname

    assert placeholder_hostname("discovered", "10.74.103.1") == "discovered-10-74-103-1"
    for name in (
        "discovered-10-74-103-1",
        "Discovered-10-74-103-1",
        "snmp-10-74-103-1",
        "host-10-74-103-1",
        "my-lab-10-74-103-1",
    ):
        assert is_placeholder_hostname(name, "10.74.103.1"), name
    for name in (
        "CCM-Core-9500",
        "-10-74-103-1",
        "10-74-103-1",
        "discovered-10-74-103-12",
        "discovered-10-74-103-2",
        "",
    ):
        assert not is_placeholder_hostname(name, "10.74.103.1"), name
    assert not is_placeholder_hostname("discovered-10-74-103-1", "")


def test_config_hostname_parsers():
    assert get_driver("cisco_xe").parse_config_hostname(_IDENTITY_CONFIG) == "CCM-Core-9500"
    assert get_driver("cisco_ios").parse_config_hostname("!\r\nhostname edge-rtr1\r\n!\r\n") == "edge-rtr1"
    assert get_driver("cisco_nxos").parse_config_hostname("switchname n9k-leaf1\n") == "n9k-leaf1"
    assert get_driver("cisco_ftd").parse_config_hostname(": Saved\nhostname fw-hq\n") == "fw-hq"
    # AOS-Switch quotes the name (a type without a driver is read with the IOS driver).
    assert collection._table_driver("hp_procurve").parse_config_hostname('hostname "Core SW 1"\n') == "Core SW 1"
    # Only a top-level line: not a word inside a banner or another block.
    assert get_driver("cisco_ios").parse_config_hostname("banner motd ^C\n hostname is a word\n^C\n") == ""
    assert get_driver("cisco_ios").parse_config_hostname("") == ""
    assert get_driver("juniper_junos").parse_config_hostname(_JUNOS_IDENTITY) == "srx-edge1"
    assert get_driver("juniper_junos").parse_config_hostname("system {\n    host-name mx-core1;\n}\n") == "mx-core1"
    assert get_driver("juniper_junos").parse_config_hostname(_IDENTITY_CONFIG) == ""
    fortigate = 'config system global\n    set alias "FGT"\n    set hostname "FGT-HQ"\nend\n'
    assert get_driver("fortinet").parse_config_hostname(fortigate) == "FGT-HQ"


def test_config_identity_reads_every_interface_address():
    # Primary, secondary, SVI, loopback and VRF addresses; never a shared HSRP address.
    assert collection._config_identity("cisco_xe", _IDENTITY_CONFIG) == (
        "CCM-Core-9500",
        ["10.255.0.1", "10.175.14.2", "10.175.15.2", "10.74.103.1"],
    )
    # Junos: IPv4 only, no 127/8.
    assert collection._config_identity("juniper_junos", _JUNOS_IDENTITY) == (
        "srx-edge1",
        ["198.51.100.2", "10.10.0.1", "10.255.1.1"],
    )
    # A platform whose configuration is not read: the addresses are unknown, not none.
    assert collection._config_identity("paloalto_panos", "hostname pa-1\n") == ("pa-1", None)


def test_capture_reports_the_resolved_type(monkeypatch):
    fake = _FakeSsh({"show ip route": _TABLE, "show running-config": _IDENTITY_CONFIG})
    _fake_session(monkeypatch, fake, resolved="cisco_xe")
    outcome = collection._capture_host({"ip_address": "10.74.103.1", "device_type": "autodetect"}, {})
    assert outcome["device_type"] == "cisco_xe" and outcome["config"] == _IDENTITY_CONFIG


def _hostnames() -> dict[int, str]:
    rows = asyncio.run(pg_raw.fetch("SELECT id, hostname FROM hosts"))
    return {int(r["id"]): r["hostname"] for r in rows}


def _aliases(api, *host_ids: int) -> dict[int, list[str]]:
    found: dict[int, list[str]] = {host_id: [] for host_id in host_ids}
    for row in _on_app_loop(api, db_module.get_ip_aliases_for_hosts, list(host_ids)):
        found[int(row["host_id"])].append(row["ip_address"])
    return {host_id: sorted(ips) for host_id, ips in found.items()}


def _record_pushes(monkeypatch) -> list[dict]:
    pushed: list[dict] = []

    async def _push(**kwargs):
        pushed.append(kwargs)
        return {"attempted": 0, "pushed": 0, "failed": 0}

    monkeypatch.setattr(collection, "push_inventory_host_allocation", _push)
    return pushed


def test_collection_names_a_placeholder_host_and_records_its_addresses(api, monkeypatch):
    group_id = _group(api, "core")
    placeholder = _host(api, group_id, "discovered-10-74-103-1", "10.74.103.1")
    chosen = _host(api, group_id, "core-a", "10.0.0.2")
    _service_credential(api, monkeypatch)
    pushed = _record_pushes(monkeypatch)
    _fake_capture(monkeypatch, config=_IDENTITY_CONFIG)

    job = _run(api)
    assert job["status"] == "completed", job
    assert job["result"]["configs"] == 2
    names = _hostnames()
    # The placeholder takes the configured name; a name a user chose stays.
    assert names[placeholder] == "CCM-Core-9500" and names[chosen] == "core-a"
    assert pushed == [{"hostname": "CCM-Core-9500", "ip_address": "10.74.103.1", "source_hint": "inventory-collection"}]
    # Every interface address but the host's own.
    aliases = _aliases(api, placeholder, chosen)
    assert aliases[placeholder] == ["10.175.14.2", "10.175.15.2", "10.255.0.1"]
    assert aliases[chosen] == ["10.175.14.2", "10.175.15.2", "10.255.0.1", "10.74.103.1"]


def test_a_configured_hostname_another_host_has_is_not_taken(api, monkeypatch):
    group_id = _group(api, "core")
    # Not collected (ICMP only), but it has the name already (in another case).
    holder = _host(api, group_id, "ccm-core-9500", "10.0.0.9", device_type="icmp_only")
    first = _host(api, group_id, "discovered-10-74-103-1", "10.74.103.1")
    second = _host(api, group_id, "scan-10-74-103-2", "10.74.103.2")
    _service_credential(api, monkeypatch)
    pushed = _record_pushes(monkeypatch)
    _fake_capture(monkeypatch, config=_IDENTITY_CONFIG)

    assert _run(api)["status"] == "completed"
    names = _hostnames()
    assert (names[first], names[second]) == ("discovered-10-74-103-1", "scan-10-74-103-2") and pushed == []
    # The aliases are still recorded.
    assert "10.175.14.2" in _aliases(api, first)[first]

    # With the name free, two hosts of one run reading it: one takes it.
    asyncio.run(pg_raw.execute("DELETE FROM hosts WHERE id = $1", holder))
    assert _run(api)["status"] == "completed"
    names = _hostnames()
    assert sorted((names[first], names[second])).count("CCM-Core-9500") == 1 and len(pushed) == 1


def test_no_configuration_read_leaves_the_name_and_aliases(api, monkeypatch):
    group_id = _group(api, "core")
    host_id = _host(api, group_id, "discovered-10-74-103-1", "10.74.103.1")
    _on_app_loop(api, db_module.set_host_ip_aliases, host_id, "10.74.103.1", ["10.175.14.2"])
    _service_credential(api, monkeypatch)
    pushed = _record_pushes(monkeypatch)
    _fake_capture(monkeypatch, config=None)

    job = _run(api)
    assert job["status"] == "completed" and job["result"]["configs"] == 0
    assert _hostnames()[host_id] == "discovered-10-74-103-1" and pushed == []
    assert _aliases(api, host_id)[host_id] == ["10.175.14.2"]

    # A configuration the platform's parser finds no address in keeps them too.
    _fake_capture(monkeypatch, config="hostname CCM-Core-9500\n!\nline vty 0 4\n login local\n")
    assert _run(api)["status"] == "completed"
    assert _hostnames()[host_id] == "CCM-Core-9500"
    assert _aliases(api, host_id)[host_id] == ["10.175.14.2"]
