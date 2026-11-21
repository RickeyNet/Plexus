"""Tests for the OPNsense clients part: ARP, NDP and DHCP leases read from a
firewall (``netcontrol.integrations.opnsense``) and fed into MAC tracking and
the DHCP leases of IPAM (``netcontrol.routes.opnsense_collection``).

Covers, with no network access (the fake firewall of
``test_opnsense_topology`` serves ``sample.sample_api_answers``):
  * collector  - the ARP / NDP tables and the lease backends read with GET
                 only, a missing backend skipped quietly, a refused call
                 naming its privilege (dropped for a Kea / Dnsmasq service
                 config.xml shows as off), the get_arp fallback, the option off
  * normalize  - MAC normalisation, incomplete and duplicate entries, lease
                 states, times and subnets per backend, delegated prefixes,
                 the snapshot tables and counts
  * sync       - leases into the firewall's ``opnsense`` DHCP server
                 (created once, replaced per collection, disabled = kept),
                 ARP / NDP into the inventory host's ``arp_table`` (skipped
                 with a warning while the firewall is no inventory host)
  * HTTP API   - a build feeding /api/dhcp/leases and MAC tracking; the
                 collection-fed server cannot be created or synced

Every name and address is invented (example.com, documentation ranges,
locally administered MACs).
"""

from __future__ import annotations

import copy

import httpx
import pytest
import routes.database as db
from netcontrol.integrations.opnsense import collector as collector_module
from netcontrol.integrations.opnsense.collector import (
    LEASE_BACKENDS,
    NO_LEASES_MESSAGE,
    PHASE_CLIENTS,
    collect_opnsense,
    lease_backends_off,
)
from netcontrol.integrations.opnsense.normalize import (
    arp_entries,
    build_snapshot,
    client_counts,
    dhcp_leases,
    ndp_entries,
)
from netcontrol.integrations.opnsense.sample import SAMPLE_CONFIG_XML, SAMPLE_URL, build_sample_raw
from netcontrol.routes import opnsense_collection
from netcontrol.routes.dhcp_adapters import is_collection_fed

from test_meraki_topology import api  # noqa: F401 - the fixture is used by name
from test_opnsense_topology import (
    FIREWALL,
    _client,
    _create,
    _FakeFirewall,
    _kv,
    _node,
    _table,
    _wait,
    no_sleep,  # noqa: F401 - the fixture is used by name
)

CLIENT_PATHS = {
    "diagnostics/interface/search_arp",
    "diagnostics/interface/search_ndp",
    *(paths[0] for _key, _name, paths, _privilege in LEASE_BACKENDS),
}


# ── Collector ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_collect_reads_arp_ndp_and_every_lease_backend(no_sleep):  # noqa: F811
    fake = _FakeFirewall()
    progress: list[dict] = []
    async with _client(fake) as client:
        raw = await collect_opnsense(client, {"include_firmware_audit": False}, progress.append)
    # ISC DHCPv6 is not on this firewall (404): skipped without a warning.
    assert raw["errors"] == []
    assert raw["clients"] == build_sample_raw()["clients"]
    assert set(raw["clients"]["leases"]) == {"isc4", "kea4", "kea6", "dnsmasq"}
    assert CLIENT_PATHS <= set(fake.paths())
    # Read-only: every client call is a GET (the fake asserts it too).
    assert all(r.method == "GET" for r in fake.calls if r.url.path.removeprefix("/api/") in CLIENT_PATHS)
    last = [p for p in progress if p["phase"] == PHASE_CLIENTS][-1]
    assert (last["arp"], last["ndp"], last["leases"]) == (6, 2, 8)
    assert progress[-1]["calls_done"] <= progress[-1]["calls_total"]


@pytest.mark.asyncio
async def test_collect_names_the_privilege_of_a_refused_table(no_sleep):  # noqa: F811
    fake = _FakeFirewall()
    fake.fail = {"diagnostics/interface/search_arp": 403, "kea/leases4/search": 403}
    # A 24.7 to 25.1 privilege also refuses the camelCase and get_arp forms.
    fake.fail.update(
        {
            "diagnostics/interface/searchArp": 403,
            "diagnostics/interface/get_arp": 403,
            "diagnostics/interface/getArp": 403,
        }
    )
    async with _client(fake) as client:
        raw = await collect_opnsense(client, {"include_firmware_audit": False, "config_backup": False})
    by_path = {e["path"]: e for e in raw["errors"]}
    assert set(by_path) == {"/diagnostics/interface/getArp", "/kea/leases4/search"}
    assert "Diagnostics: ARP Table" in by_path["/diagnostics/interface/getArp"]["message"]
    # The name OPNsense shows for the privilege (its Kea ACL, 24.7 to 25.7).
    assert by_path["/kea/leases4/search"]["message"].endswith("privilege needed: Services: DHCP: Kea(v4)")
    assert all(e["status"] == 403 and not e.get("info") for e in raw["errors"])
    assert raw["clients"]["arp"] is None and raw["clients"]["ndp"]
    assert set(raw["clients"]["leases"]) == {"isc4", "kea6", "dnsmasq"}


def _config_with(extra: str) -> str:
    """The sample config.xml with ``extra`` added to it."""
    return SAMPLE_CONFIG_XML.replace("</opnsense>", extra + "</opnsense>")


KEA4_ON = "<OPNsense><Kea><dhcp4><general><enabled>1</enabled></general></dhcp4></Kea></OPNsense>"
DNSMASQ_DHCP_ON = "<dnsmasq><enable>1</enable><dhcp_ranges><interface>opt2</interface></dhcp_ranges></dnsmasq>"


def test_lease_backends_off_reads_the_service_switches_of_config_xml():
    every = {"kea4", "kea6", "dnsmasq"}
    # A configuration that never set up Kea or Dnsmasq.
    assert lease_backends_off(SAMPLE_CONFIG_XML) == every
    assert lease_backends_off(_config_with(KEA4_ON)) == {"kea6", "dnsmasq"}
    assert lease_backends_off(_config_with(KEA4_ON.replace(">1<", ">0<"))) == every
    assert lease_backends_off(_config_with(KEA4_ON.replace("dhcp4", "dhcp6"))) == {"kea4", "dnsmasq"}
    assert lease_backends_off(_config_with(DNSMASQ_DHCP_ON)) == {"kea4", "kea6"}
    # Dnsmasq as a DNS forwarder only: enabled, no DHCP range.
    assert lease_backends_off(_config_with("<dnsmasq><enable>1</enable><dhcp_ranges/></dnsmasq>")) == every
    assert lease_backends_off(_config_with(DNSMASQ_DHCP_ON.replace(">1<", ">0<"))) == every
    # No OPNsense configuration: nothing is known to be off.
    assert lease_backends_off("<html>login</html>") == set()


@pytest.mark.asyncio
async def test_collect_drops_the_refused_lease_read_of_a_service_that_is_off(no_sleep):  # noqa: F811
    fake = _FakeFirewall()
    fake.fail = {"kea/leases4/search": 403, "kea/leases6/search": 403, "dnsmasq/leases/search": 403}
    # config.xml: Kea DHCPv4 runs, Kea DHCPv6 and Dnsmasq do not.
    fake.answers["core/backup/download/this"] = _config_with(KEA4_ON)
    async with _client(fake) as client:
        raw = await collect_opnsense(client, {"include_firmware_audit": False})
    refused = [e for e in raw["errors"] if e["scope"] == "clients"]
    assert [e["path"] for e in refused] == ["/kea/leases4/search"]
    assert refused[0]["status"] == 403 and "Services: DHCP: Kea(v4)" in refused[0]["message"]
    assert set(raw["clients"]["leases"]) == {"isc4"}


@pytest.mark.asyncio
async def test_collect_keeps_the_refused_lease_reads_without_config_xml(no_sleep):  # noqa: F811
    fake = _FakeFirewall()
    fake.fail = {"kea/leases6/search": 403, "dnsmasq/leases/search": 403}
    async with _client(fake) as client:
        raw = await collect_opnsense(client, {"include_firmware_audit": False, "config_backup": False})
    by_path = {e["path"]: e["message"] for e in raw["errors"]}
    assert set(by_path) == {"/kea/leases6/search", "/dnsmasq/leases/search"}
    assert by_path["/kea/leases6/search"].endswith("privilege needed: Services: DHCP: Kea(v6)")
    assert by_path["/dnsmasq/leases/search"].endswith("privilege needed: Services: Dnsmasq DNS/DHCP: Settings")


@pytest.mark.asyncio
async def test_collect_notes_no_leases_once_the_refused_idle_reads_are_dropped(no_sleep):  # noqa: F811
    fake = _FakeFirewall()
    for _key, _name, paths, _privilege in LEASE_BACKENDS:
        fake.answers.pop(paths[0], None)
    fake.fail = {"kea/leases4/search": 403, "kea/leases6/search": 403}
    async with _client(fake) as client:
        raw = await collect_opnsense(client, {"include_firmware_audit": False})
    (warning,) = [e for e in raw["errors"] if e["scope"] == "clients"]
    assert warning["info"] and warning["message"] == NO_LEASES_MESSAGE
    assert raw["clients"]["leases"] is None


@pytest.mark.asyncio
async def test_collect_falls_back_to_get_arp_and_notes_a_firewall_without_leases(no_sleep):  # noqa: F811
    fake = _FakeFirewall()
    arp = fake.answers.pop("diagnostics/interface/search_arp")["rows"]
    fake.answers["diagnostics/interface/get_arp"] = arp
    for _key, _name, paths, _privilege in LEASE_BACKENDS:
        fake.answers.pop(paths[0], None)
    async with _client(fake) as client:
        raw = await collect_opnsense(client, {"include_firmware_audit": False, "config_backup": False})
    assert raw["clients"]["arp"] == arp and raw["clients"]["leases"] is None
    (warning,) = raw["errors"]
    assert warning["info"] and warning["scope"] == "clients" and "No DHCP lease endpoint" in warning["message"]
    assert "diagnostics/interface/get_arp" in fake.paths()


@pytest.mark.asyncio
async def test_collect_skips_the_clients_when_the_option_is_off(no_sleep):  # noqa: F811
    fake = _FakeFirewall()
    async with _client(fake) as client:
        raw = await collect_opnsense(client, {"include_clients": False, "include_firmware_audit": False})
    assert raw["clients"] is None and not CLIENT_PATHS & set(fake.paths())
    snapshot = build_snapshot(raw)
    assert snapshot["summary"]["arp_entries"] is None and snapshot["summary"]["dhcp_leases"] is None
    assert "ARP table" not in [s["title"] for s in _node(snapshot, FIREWALL)["sections"]]


# ── Normalize ────────────────────────────────────────────────────────────────


def test_arp_and_ndp_entries_are_normalised():
    clients = build_sample_raw()["clients"]
    arp = {e["ip_address"]: e for e in arp_entries(clients)}
    # The incomplete entry (no MAC) is left out.
    assert sorted(arp) == ["192.0.2.10", "192.0.2.11", "192.0.2.140", "192.0.2.2", "203.0.113.1"]
    assert arp["192.0.2.140"]["interface_name"] == "DMZ" and arp["192.0.2.140"]["device"] == "vlan0.20"
    assert arp["192.0.2.2"]["type"] == "permanent"
    ndp = {e["ip_address"]: e for e in ndp_entries(clients)}
    # The link-local address loses its %scope.
    assert sorted(ndp) == ["2001:db8:10::10", "fe80::ff:fe00:5310"]
    assert {e["mac_address"] for e in ndp.values()} == {"02:00:5e:00:53:10"}
    duplicate = {"arp": [{"ip": "192.0.2.10", "mac": "02005E005310"}, {"ip": "192.0.2.10", "mac": "02:00:5e:00:53:99"}]}
    assert [e["mac_address"] for e in arp_entries(duplicate)] == ["02:00:5e:00:53:10"]


def test_dhcp_leases_of_every_backend():
    raw = build_sample_raw()
    leases = {lease["address"]: lease for lease in dhcp_leases(raw["clients"], raw["interfaces"])}
    # The delegated prefix is no address; the ISC lease of 192.0.2.10 wins over Kea's.
    assert sorted(leases) == [
        "192.0.2.10",
        "192.0.2.11",
        "192.0.2.140",
        "192.0.2.141",
        "192.0.2.200",
        "2001:db8:10::100",
    ]
    isc = leases["192.0.2.10"]
    assert (isc["mac_address"], isc["hostname"], isc["state"], isc["scope_subnet"]) == (
        "02:00:5e:00:53:10",
        "nas",
        "active",
        "192.0.2.0/25",
    )
    assert (isc["starts_at"], isc["ends_at"]) == ("2026-11-14T07:00:00+00:00", "2026-11-14T09:00:00+00:00")
    assert isc["metadata"]["backend"] == "isc4" and isc["metadata"]["interface"] == "LAN"
    static = leases["192.0.2.11"]
    assert static["state"] == "static" and static["mac_address"] == "02:00:5e:00:53:11" and static["ends_at"] == ""
    kea = leases["192.0.2.140"]
    assert (kea["hostname"], kea["state"], kea["scope_subnet"]) == ("web1.example.com", "active", "192.0.2.128/26")
    assert (kea["starts_at"], kea["ends_at"]) == ("2026-11-14T08:00:00+00:00", "2026-11-14T09:00:00+00:00")
    assert leases["192.0.2.141"]["state"] == "expired"
    assert leases["2001:db8:10::100"]["scope_subnet"] == "2001:db8:10::/64"
    dnsmasq = leases["192.0.2.200"]
    assert dnsmasq["scope_subnet"] == "192.0.2.192/27" and dnsmasq["metadata"]["reserved"] is False
    assert dhcp_leases({"leases": None}) == [] and dhcp_leases(None) == []


def test_snapshot_shows_the_client_tables_and_counts():
    snapshot = build_snapshot(build_sample_raw())
    summary = snapshot["summary"]
    assert (summary["arp_entries"], summary["ndp_entries"], summary["dhcp_leases"]) == (5, 2, 6)
    firewall = _node(snapshot, FIREWALL)
    arp = {r["IP address"]: r for r in _table(firewall, "ARP table")}
    assert arp["192.0.2.10"]["MAC address"] == "02:00:5e:00:53:10" and arp["192.0.2.10"]["Interface"] == "LAN"
    leases = {r["Address"]: r for r in _table(firewall, "DHCP leases")}
    assert leases["192.0.2.140"]["Server"] == "Kea DHCPv4" and leases["192.0.2.200"]["Server"] == "Dnsmasq DHCP"
    assert len(_table(firewall, "NDP table")) == 2
    counts = client_counts(build_sample_raw()["clients"])
    assert counts["lease_backends"] == {"ISC DHCPv4": 2, "Kea DHCPv4": 3, "Kea DHCPv6": 2, "Dnsmasq DHCP": 1}


# ── Sync into MAC tracking and IPAM ──────────────────────────────────────────


async def _opnsense_servers() -> list[dict]:
    return [s for s in await db.list_dhcp_servers() if s["provider"] == "opnsense"]


async def _forget_opnsense_servers() -> None:
    for server in await _opnsense_servers():
        await db.delete_dhcp_server(int(server["id"]))


@pytest.mark.asyncio
async def test_sync_replaces_the_leases_of_this_firewall_only(monkeypatch):
    await _forget_opnsense_servers()

    async def no_host(_snapshot):
        return None

    monkeypatch.setattr(opnsense_collection, "matching_host", no_host)
    raw = build_sample_raw()
    raw["firewall"]["name"] = "Edge firewall"
    snapshot = build_snapshot(raw)

    result = await opnsense_collection.sync_clients(raw, snapshot)
    assert result["leases_stored"] == 6 and result["arp_stored"] == 0
    (server,) = await _opnsense_servers()
    assert server["name"] == "Edge firewall (OPNsense)" and server["base_url"] == SAMPLE_URL
    assert server["last_sync_status"] == "success" and server["lease_count"] == 6
    assert is_collection_fed(server["provider"])
    section = _kv(_node(snapshot, FIREWALL), "Clients")
    assert section["ARP entries"] == "5" and section["Leases (Kea DHCPv4)"] == "3"
    assert section["MAC tracking"].startswith("Not stored") and "6 leases" in section["IPAM DHCP leases"]
    assert any("not added to MAC tracking" in e["message"] for e in snapshot["collection"]["errors"])

    # Another firewall's server is not touched.
    other = await db.create_dhcp_server(provider="opnsense", name="Other (OPNsense)", base_url="https://192.0.2.254")
    await db.replace_dhcp_server_snapshot(int(other["id"]), [], [{"address": "198.51.100.5"}])

    # The next collection replaces the leases: one gone, none duplicated.
    raw2 = copy.deepcopy(raw)
    raw2["clients"]["leases"]["dnsmasq"] = []
    await opnsense_collection.sync_clients(raw2, build_snapshot(raw2))
    stored = await db.list_dhcp_leases(server_id=int(server["id"]))
    assert len(stored) == 5 and "192.0.2.200" not in {r["address"] for r in stored}
    assert len(await _opnsense_servers()) == 2
    assert [r["address"] for r in await db.list_dhcp_leases(server_id=int(other["id"]))] == ["198.51.100.5"]

    # Leases not read at all leave the stored ones alone.
    raw3 = copy.deepcopy(raw)
    raw3["clients"]["leases"] = None
    assert (await opnsense_collection.sync_clients(raw3, build_snapshot(raw3)))["leases_stored"] is None
    assert len(await db.list_dhcp_leases(server_id=int(server["id"]))) == 5

    # A server disabled in IPAM keeps what it has.
    await db.update_dhcp_server(int(server["id"]), enabled=False)
    snapshot4 = build_snapshot(raw)
    assert (await opnsense_collection.sync_clients(raw, snapshot4))["leases_stored"] is None
    assert "disabled" in _kv(_node(snapshot4, FIREWALL), "Clients")["IPAM DHCP leases"]
    assert len(await db.list_dhcp_leases(server_id=int(server["id"]))) == 5
    await _forget_opnsense_servers()


@pytest.mark.asyncio
async def test_sync_stores_arp_and_ndp_on_the_inventory_host(monkeypatch):
    group_id = await db.create_group("OPNsense clients test")
    host_id = await db.add_host(group_id, "fw-clients.example.com", "192.0.2.1", "opnsense")
    switch_id = await db.add_host(group_id, "sw-clients.example.com", "192.0.2.5", "cisco_ios")
    # A switch saw the NAS's MAC without an IP: the firewall's ARP fills it in.
    await db.upsert_mac_entry(switch_id, "02:00:5e:00:53:10", 10, "Gi1/0/1")
    host = {"id": host_id, "hostname": "fw-clients.example.com", "ip_address": "192.0.2.1"}

    async def the_host(_snapshot):
        return host

    monkeypatch.setattr(opnsense_collection, "matching_host", the_host)
    raw = build_sample_raw()
    snapshot = build_snapshot(raw)
    result = await opnsense_collection.sync_clients(raw, snapshot)
    assert result["arp_stored"] == 7
    arp = {r["ip_address"]: r for r in await db.get_arp_table_for_host(host_id)}
    assert len(arp) == 7 and arp["192.0.2.140"]["interface_name"] == "DMZ"
    assert arp["2001:db8:10::10"]["mac_address"] == "02:00:5e:00:53:10"
    (mac_row,) = await db.get_mac_table_for_host(switch_id)
    assert mac_row["ip_address"] in ("192.0.2.10", "2001:db8:10::10", "fe80::ff:fe00:5310")
    assert _kv(_node(snapshot, FIREWALL), "Clients")["MAC tracking"].startswith("7 entries stored")
    # Collected again: upserted, not duplicated.
    await opnsense_collection.sync_clients(raw, build_snapshot(raw))
    assert len(await db.get_arp_table_for_host(host_id)) == 7
    await _forget_opnsense_servers()


# ── HTTP API ─────────────────────────────────────────────────────────────────


def test_api_build_feeds_dhcp_leases_and_mac_tracking(api, monkeypatch):  # noqa: F811
    import netcontrol.routes.meraki_topology as routes_module

    fake = _FakeFirewall()
    real_client = routes_module.OpnsenseClient

    def _client_factory(base_url, key, secret, **kwargs):
        kwargs.update(transport=httpx.MockTransport(fake.handler), requests_per_second=1000)
        return real_client(base_url, key, secret, **kwargs)

    monkeypatch.setattr(routes_module, "OpnsenseClient", _client_factory)
    org = _create(api, options={"include_firmware_audit": False, "config_backup": False}).json()["org"]

    # Not an inventory host yet: the leases are stored, the ARP table is not.
    job = _wait(api, api.post(f"/api/sources/{org['id']}/build").json()["job_id"])
    data = api.get(f"/api/sources/snapshots/{job['result']['snapshot_id']}/data").json()
    assert _kv(_node(data, FIREWALL), "Clients")["MAC tracking"].startswith("Not stored")
    (server,) = [s for s in api.get("/api/dhcp/servers").json()["servers"] if s["provider"] == "opnsense"]
    assert server["name"] == "Edge firewall (OPNsense)" and server["lease_count"] == 6
    leases = api.get(f"/api/dhcp/leases?server_id={server['id']}").json()["leases"]
    assert {lease["address"] for lease in leases} >= {"192.0.2.10", "2001:db8:10::100"}
    correlation = api.get(f"/api/dhcp/correlation?server_id={server['id']}").json()
    assert correlation["totals"]["known"] + correlation["totals"]["unknown"] == 6

    # The collection-fed server is neither synced nor created by hand.
    refused = api.post(f"/api/dhcp/servers/{server['id']}/sync")
    assert refused.status_code == 409 and "OPNsense" in refused.text
    assert api.post("/api/dhcp/servers", json={"provider": "opnsense", "name": "x"}).status_code == 400
    url = f"/api/dhcp/servers/{server['id']}"
    edited = api._c.patch(url, headers=api._headers, json={"provider": "opnsense", "notes": "kept"})
    assert edited.status_code == 200 and edited.json()["notes"] == "kept"
    assert api._c.patch(url, headers=api._headers, json={"provider": "kea"}).status_code == 400

    # Imported: the next build adds the ARP and NDP tables to MAC tracking.
    imported = api.post(
        f"/api/sources/{org['id']}/import-devices", json={"device_keys": [FIREWALL], "new_group_name": "Firewalls"}
    )
    assert imported.status_code == 200, imported.text
    (host,) = api.get(f"/api/inventory/{imported.json()['group']['id']}/hosts").json()
    _wait(api, api.post(f"/api/sources/{org['id']}/build").json()["job_id"])
    tables = api.get(f"/api/mac-tracking/host/{host['id']}").json()
    assert len(tables["arp_table"]) == 7
    assert len([s for s in api.get("/api/dhcp/servers").json()["servers"] if s["provider"] == "opnsense"]) == 1


def test_collector_paths_are_read_only_searches():
    """Nothing that flushes a table or changes a lease is ever named."""
    named = [
        *collector_module.PATH_ARP,
        *collector_module.PATH_NDP,
        *(p for _k, _n, paths, _v in LEASE_BACKENDS for p in paths),
    ]
    assert all(("search" in p or "get_" in p or "getA" in p or "getN" in p) for p in named)
    assert not any(word in p.lower() for p in named for word in ("flush", "del", "set", "add"))
