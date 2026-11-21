"""Tests for the OPNsense DNS names and DHCP reservations: Unbound host
overrides, Dnsmasq hosts, ISC DHCP static mappings and Kea reservations read
from config.xml (``netcontrol.integrations.opnsense.names``) and kept as the
allocations of the firewall's ``opnsense`` IPAM source
(``netcontrol.routes.opnsense_collection.store_names``).

Covers, with no network access:
  * parser    - every layout (MVC Unbound with aliases, legacy Unbound,
                Dnsmasq, ISC v4 / v6, Kea v4), disabled entries and
                services, wildcards, MX records, track6 suffixes, merging
                per address, no secret carried, no config.xml
  * collector - the names parsed from the downloaded config.xml, none with
                the Config backup option off
  * store     - the source created once, renamed, replaced per collection,
                kept when disabled, allocations under the firewall subnet
                (subnet drill-down, next-IP occupancy), nothing created for
                a firewall without names
  * IPAM      - the collection-fed source is never synced, validated,
                reconciled, pushed to or allocated into, cannot be created
                by hand or repointed, and still edits name / enabled and
                deletes; the scheduled sync skips it

Every name and address is invented (example.com, documentation ranges,
00:00:5e:00:53:xx MACs).
"""

from __future__ import annotations

import httpx
import pytest
import routes.database as db
from netcontrol.integrations.opnsense.collector import collect_opnsense
from netcontrol.integrations.opnsense.names import (
    ORIGIN_DNSMASQ,
    ORIGIN_ISC,
    ORIGIN_KEA,
    ORIGIN_UNBOUND,
    STATUS_ACTIVE,
    STATUS_RESERVED,
    ipam_allocations,
    names_from_config,
)
from netcontrol.integrations.opnsense.normalize import build_snapshot
from netcontrol.integrations.opnsense.sample import SAMPLE_CONFIG_XML, SAMPLE_URL, build_sample_raw
from netcontrol.routes import ipam_push, opnsense_collection
from netcontrol.routes.ipam_adapters import IpamAdapterError, collect_ipam_snapshot, push_allocation_to_provider
from netcontrol.routes.ipam_reconciliation import run_reconciliation

from test_meraki_topology import api  # noqa: F401 - the fixture is used by name
from test_opnsense_topology import (
    FIREWALL,
    _client,
    _create,
    _FakeFirewall,
    _kv,
    _node,
    _wait,
    no_sleep,  # noqa: F401 - the fixture is used by name
)

NAMES_XML = """
  <OPNsense>
    <unboundplus>
      <general><enabled>1</enabled></general>
      <hosts>
        <host uuid="10000000-0000-4000-8000-000000000001">
          <enabled>1</enabled><hostname>nas</hostname><domain>example.com</domain><rr>A</rr>
          <server>192.0.2.10</server><description>File server</description>
        </host>
        <host uuid="10000000-0000-4000-8000-000000000002">
          <enabled>1</enabled><hostname>printer</hostname><domain>example.com</domain><rr>AAAA</rr>
          <server>2001:db8:10::20</server><description/>
        </host>
        <host uuid="10000000-0000-4000-8000-000000000003">
          <enabled>0</enabled><hostname>old</hostname><domain>example.com</domain><rr>A</rr>
          <server>192.0.2.11</server>
        </host>
        <host uuid="10000000-0000-4000-8000-000000000004">
          <enabled>1</enabled><hostname>*</hostname><domain>lab.example.com</domain><rr>A</rr>
          <server>192.0.2.12</server>
        </host>
        <host uuid="10000000-0000-4000-8000-000000000005">
          <enabled>1</enabled><hostname>mail</hostname><domain>example.com</domain><rr>MX</rr>
          <mx>nas.example.com</mx><mxprio>10</mxprio><server/>
        </host>
      </hosts>
      <aliases>
        <alias uuid="20000000-0000-4000-8000-000000000001">
          <enabled>1</enabled><host>10000000-0000-4000-8000-000000000001</host>
          <hostname>files</hostname><domain/><description/>
        </alias>
        <alias uuid="20000000-0000-4000-8000-000000000002">
          <enabled>0</enabled><host>10000000-0000-4000-8000-000000000001</host>
          <hostname>hidden</hostname><domain/>
        </alias>
      </aliases>
    </unboundplus>
    <Kea>
      <dhcp4>
        <general><enabled>1</enabled></general>
        <subnets>
          <subnet4 uuid="30000000-0000-4000-8000-000000000001">
            <subnet>192.0.2.128/26</subnet>
            <option_data><domain_name>dmz.example.com</domain_name></option_data>
            <description>DMZ clients</description>
          </subnet4>
        </subnets>
        <reservations>
          <reservation uuid="40000000-0000-4000-8000-000000000001">
            <subnet>30000000-0000-4000-8000-000000000001</subnet><ip_address>192.0.2.140</ip_address>
            <hw_address>00:00:5E:00:53:40</hw_address><hostname>camera</hostname>
            <description>Lobby camera</description>
          </reservation>
        </reservations>
      </dhcp4>
    </Kea>
  </OPNsense>
  <dhcpd>
    <lan>
      <enable>1</enable><domain>office.example.com</domain>
      <staticmap><mac>00:00:5e:00:53:10</mac><ipaddr>192.0.2.10</ipaddr><hostname>nas</hostname>
        <descr>NAS reservation</descr></staticmap>
      <staticmap><mac>00:00:5e:00:53:11</mac><ipaddr>192.0.2.30</ipaddr><hostname>desk</hostname></staticmap>
      <staticmap><mac>00:00:5e:00:53:12</mac><ipaddr/><hostname>noaddr</hostname></staticmap>
    </lan>
    <opt2>
      <staticmap><mac>00:00:5e:00:53:13</mac><ipaddr>198.51.100.5</ipaddr><hostname>off</hostname></staticmap>
    </opt2>
  </dhcpd>
  <dhcpdv6>
    <lan>
      <enable>1</enable>
      <staticmap><duid>00:01:00:01:00:00:00:30</duid><ipaddrv6>2001:db8:10::30</ipaddrv6>
        <hostname>desk6</hostname></staticmap>
    </lan>
  </dhcpdv6>
  <dnsmasq>
    <enable>1</enable>
    <dhcp_ranges uuid="50000000-0000-4000-8000-000000000001">
      <interface>lan</interface><start_addr>192.0.2.50</start_addr><end_addr>192.0.2.59</end_addr>
    </dhcp_ranges>
    <hosts uuid="60000000-0000-4000-8000-000000000001">
      <host>tv</host><domain/><ip>192.0.2.60,2001:db8:10::60</ip><hwaddr>00:00:5e:00:53:60</hwaddr>
      <descr>Lounge TV</descr><aliases>tv-alias.example.com</aliases>
    </hosts>
    <hosts uuid="60000000-0000-4000-8000-000000000002">
      <host>*</host><domain>example.com</domain><ip>192.0.2.61</ip>
    </hosts>
    <hosts uuid="60000000-0000-4000-8000-000000000003">
      <host>wiki</host><domain>example.com</domain><ip>203.0.113.70,::70</ip>
    </hosts>
  </dnsmasq>
"""


def _config(extra: str = NAMES_XML) -> str:
    return SAMPLE_CONFIG_XML.replace("</opnsense>", extra + "</opnsense>")


def _by_address(found: dict) -> dict[str, dict]:
    return {r["address"]: r for r in found["records"]}


# ── Parser ───────────────────────────────────────────────────────────────────


def test_every_source_of_names_and_reservations_is_read():
    found = names_from_config(_config())
    assert found["counts"] == {ORIGIN_UNBOUND: 2, ORIGIN_DNSMASQ: 3, ORIGIN_ISC: 3, ORIGIN_KEA: 1}
    records = _by_address(found)
    assert set(records) == {
        "192.0.2.10",
        "2001:db8:10::20",
        "192.0.2.30",
        "2001:db8:10::30",
        "192.0.2.140",
        "192.0.2.60",
        "2001:db8:10::60",
        "203.0.113.70",
    }
    # An override and a static mapping of one address: one record, the DNS
    # record's names first, its alias next, the mapping's after.
    nas = records["192.0.2.10"]
    assert nas["names"] == ["nas.example.com", "files.example.com", "nas.office.example.com"]
    assert nas["origins"] == [ORIGIN_UNBOUND, ORIGIN_ISC] and nas["reserved"] is True
    assert nas["mac"] == "00:00:5e:00:53:10" and nas["interface"] == "lan"
    assert nas["description"] == "File server"
    assert records["2001:db8:10::20"]["names"] == ["printer.example.com"]
    assert records["2001:db8:10::20"]["reserved"] is False
    # ISC: the interface's domain; IPv6 without one: the system domain.
    assert records["192.0.2.30"]["names"] == ["desk.office.example.com"]
    assert records["2001:db8:10::30"]["duid"] == "00:01:00:01:00:00:00:30"
    assert records["2001:db8:10::30"]["names"] == ["desk6.example.com"]
    # Kea: the subnet's domain, the MAC normalised, the subnet kept.
    camera = records["192.0.2.140"]
    assert camera["names"] == ["camera.dmz.example.com"] and camera["mac"] == "00:00:5e:00:53:40"
    assert camera["subnet"] == "192.0.2.128/26" and camera["interface"] == "DMZ clients"
    # Dnsmasq: one record per address, qualified with the system domain.
    assert records["192.0.2.60"]["names"] == ["tv.example.com", "tv-alias.example.com"]
    assert records["192.0.2.60"]["reserved"] and records["2001:db8:10::60"]["reserved"]
    assert records["203.0.113.70"]["reserved"] is False


def test_disabled_wildcard_and_non_address_entries_are_left_out():
    records = _by_address(names_from_config(_config()))
    # A disabled override, a wildcard, an MX record, a mapping without an
    # address, a disabled DHCP interface, a partial IPv6 address.
    for address in ("192.0.2.11", "192.0.2.12", "192.0.2.61", "198.51.100.5", "::70"):
        assert address not in records
    assert all("hidden.example.com" not in r["names"] for r in records.values())


def test_services_that_are_off_serve_nothing():
    off = (
        NAMES_XML.replace("<general><enabled>1</enabled></general>", "<general><enabled>0</enabled></general>")
        .replace("<enable>1</enable><domain>office", "<domain>office")
        .replace("<dnsmasq>\n    <enable>1</enable>", "<dnsmasq>")
    )
    found = names_from_config(_config(off))
    assert found["counts"] == {ORIGIN_UNBOUND: 0, ORIGIN_DNSMASQ: 0, ORIGIN_ISC: 1, ORIGIN_KEA: 0}
    assert list(_by_address(found)) == ["2001:db8:10::30"]


def test_a_dnsmasq_host_is_no_reservation_without_a_dhcp_range_or_when_ignored():
    no_ranges = (
        NAMES_XML.replace("<interface>lan</interface>", "").split("<dhcp_ranges")[0]
        + (NAMES_XML.split("</dhcp_ranges>")[1])
    )
    assert _by_address(names_from_config(_config(no_ranges)))["192.0.2.60"]["reserved"] is False
    ignored = NAMES_XML.replace("<descr>Lounge TV</descr>", "<descr>Lounge TV</descr><ignore>1</ignore>")
    assert _by_address(names_from_config(_config(ignored)))["192.0.2.60"]["reserved"] is False


def test_a_track6_interface_keeps_its_suffix_mappings_out():
    config = _config().replace("<lan><if>igb1</if>", "<lan><if>igb1</if><ipaddrv6>track6</ipaddrv6>", 1)
    found = names_from_config(config)
    assert "2001:db8:10::30" not in _by_address(found)


def test_the_legacy_unbound_layout_is_read():
    legacy = """
  <unbound>
    <enable/>
    <hosts>
      <host>gw</host><domain>example.com</domain><ip>192.0.2.5</ip><descr>Gateway</descr>
      <aliases><item><host>router</host><domain/><descr/></item></aliases>
    </hosts>
    <hosts><host>mx</host><domain>example.com</domain><rr>MX</rr><ip/></hosts>
  </unbound>
"""
    (record,) = names_from_config(_config(legacy))["records"]
    assert record["address"] == "192.0.2.5" and record["names"] == ["gw.example.com", "router.example.com"]
    assert record["description"] == "Gateway" and record["origins"] == [ORIGIN_UNBOUND]


def test_no_secret_reaches_the_records_and_text_that_is_no_config_reads_nothing():
    found = names_from_config(_config())
    assert "$2y$" not in repr(found) and "password" not in repr(found)
    assert names_from_config("") is None and names_from_config("<html/>") is None
    assert names_from_config(SAMPLE_CONFIG_XML)["records"] == []


def test_records_become_allocations_with_status_and_metadata():
    found = names_from_config(_config())
    allocations = {a["address"]: a for a in ipam_allocations(found["records"], lambda a: "net-of-" + a)}
    nas = allocations["192.0.2.10"]
    assert nas["dns_name"] == "nas.example.com" and nas["status"] == STATUS_RESERVED
    assert nas["prefix_subnet"] == "net-of-192.0.2.10" and nas["description"] == "File server"
    assert nas["metadata"]["origins"] == ["Unbound host override", "ISC DHCP static mapping"]
    assert nas["metadata"]["names"][1:] == ["files.example.com", "nas.office.example.com"]
    assert nas["metadata"]["mac"] == "00:00:5e:00:53:10" and nas["metadata"]["dhcp_interface"] == "lan"
    assert allocations["2001:db8:10::20"]["status"] == STATUS_ACTIVE
    assert allocations["192.0.2.140"]["metadata"]["dhcp_subnet"] == "192.0.2.128/26"


# ── Collector ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_collect_parses_the_names_of_the_downloaded_config(no_sleep):  # noqa: F811
    fake = _FakeFirewall()
    fake.answers["core/backup/download/this"] = _config()
    async with _client(fake) as client:
        raw = await collect_opnsense(client, {"include_firmware_audit": False})
    assert len(raw["names"]["records"]) == 8 and raw["names"]["counts"][ORIGIN_KEA] == 1
    async with _client(fake) as client:
        raw = await collect_opnsense(client, {"include_firmware_audit": False, "config_backup": False})
    assert raw["names"] is None and raw["config_xml"] is None


# ── Store into IPAM ──────────────────────────────────────────────────────────


async def _opnsense_sources() -> list[dict]:
    return await db.list_ipam_sources(provider="opnsense")


async def _forget_opnsense_sources() -> None:
    for source in await _opnsense_sources():
        await db.delete_ipam_source(int(source["id"]))


def _raw_with_names(extra: str = NAMES_XML) -> dict:
    raw = build_sample_raw()
    raw["firewall"]["name"] = "Edge firewall"
    raw["names"] = names_from_config(_config(extra))
    return raw


@pytest.mark.asyncio
async def test_store_replaces_the_allocations_of_this_firewalls_source():
    await _forget_opnsense_sources()
    raw = _raw_with_names()
    snapshot = build_snapshot(raw)
    result = await opnsense_collection.store_names(raw, snapshot)
    assert "names" not in raw and result["stored"] == 8
    (source,) = await _opnsense_sources()
    assert source["name"] == "Edge firewall (OPNsense)" and source["base_url"] == SAMPLE_URL
    assert source["last_sync_status"] == "success" and source["allocation_count"] == 8
    assert source["prefix_count"] == 0 and source["push_enabled"] is False
    section = _kv(_node(snapshot, FIREWALL), "Names and reservations")
    assert section["Result"].startswith("8 addresses") and section["DHCP reservations"] == "6"
    assert section["Kea reservation"] == "1" and section["Outside the firewall's subnets"] == "1"

    stored = {a["address"]: a for a in await db.list_ipam_allocations_for_source(int(source["id"]))}
    assert stored["192.0.2.10"]["prefix_subnet"] == "192.0.2.0/25"
    assert stored["192.0.2.140"]["prefix_subnet"] == "192.0.2.128/26"
    assert stored["2001:db8:10::20"]["prefix_subnet"] == "2001:db8:10::/64"
    assert stored["203.0.113.70"]["prefix_subnet"] == ""

    # Shown under the firewall subnet, reserved, and never handed out.
    detail = await db.get_ipam_subnet_detail("192.0.2.0/25")
    row = next(a for a in detail["allocations"] if a["ip_address"] == "192.0.2.10")
    assert row["hostname"] == "nas.example.com" and row["status"] == "reserved"
    assert row["group_name"] == "Edge firewall (OPNsense)"
    assert "192.0.2.10" not in detail["available_preview"]
    pending = await db.allocate_next_ip(subnet="192.0.2.0/25", hostname="probe")
    assert pending["address"] not in {"192.0.2.10", "192.0.2.30", "192.0.2.60"}
    await db.update_pending_allocation_state(int(pending["id"]), state="released")

    # The next collection replaces them; a renamed source renames the row.
    raw2 = _raw_with_names(NAMES_XML.replace("<ipaddr>192.0.2.30</ipaddr>", "<ipaddr/>"))
    raw2["firewall"]["name"] = "Edge firewall 2"
    await opnsense_collection.store_names(raw2, build_snapshot(raw2))
    (source,) = await _opnsense_sources()
    assert source["name"] == "Edge firewall 2 (OPNsense)" and source["allocation_count"] == 7

    # Not read (no config.xml): the stored ones stay.
    raw3 = build_sample_raw()
    assert await opnsense_collection.store_names(raw3, build_snapshot(raw3)) is None
    assert (await _opnsense_sources())[0]["allocation_count"] == 7

    # Disabled in IPAM: kept as they are.
    await db.update_ipam_source(int(source["id"]), enabled=False)
    raw4 = _raw_with_names("")
    snapshot4 = build_snapshot(raw4)
    assert (await opnsense_collection.store_names(raw4, snapshot4))["stored"] is None
    assert "disabled" in _kv(_node(snapshot4, FIREWALL), "Names and reservations")["Result"]
    assert (await _opnsense_sources())[0]["allocation_count"] == 7

    # Enabled again and the firewall has none left: emptied, not deleted.
    await db.update_ipam_source(int(source["id"]), enabled=True)
    raw5 = _raw_with_names("")
    assert (await opnsense_collection.store_names(raw5, build_snapshot(raw5)))["stored"] == 0
    assert (await _opnsense_sources())[0]["allocation_count"] == 0
    await _forget_opnsense_sources()


@pytest.mark.asyncio
async def test_a_firewall_without_names_gets_no_source():
    await _forget_opnsense_sources()
    raw = _raw_with_names("")
    snapshot = build_snapshot(raw)
    assert (await opnsense_collection.store_names(raw, snapshot))["stored"] is None
    assert await _opnsense_sources() == []
    assert _kv(_node(snapshot, FIREWALL), "Names and reservations")["Result"] == "Nothing to store"


@pytest.mark.asyncio
async def test_after_collection_stores_the_names_and_drops_them_from_raw(monkeypatch):
    await _forget_opnsense_sources()

    async def no_host(_snapshot):
        return None

    monkeypatch.setattr(opnsense_collection, "matching_host", no_host)
    raw = _raw_with_names()
    raw["config_xml"] = _config()
    snapshot = build_snapshot(raw)
    await opnsense_collection.after_collection(raw, snapshot, 1)
    assert "names" not in raw and "config_xml" not in raw
    (source,) = await _opnsense_sources()
    assert source["allocation_count"] == 8
    await _forget_opnsense_sources()


# ── The collection-fed source in the IPAM paths ──────────────────────────────


@pytest.mark.asyncio
async def test_adapters_push_and_reconciliation_leave_the_source_alone(monkeypatch):
    await _forget_opnsense_sources()
    raw = _raw_with_names()
    await opnsense_collection.store_names(raw, build_snapshot(raw))
    (source,) = await _opnsense_sources()

    with pytest.raises(IpamAdapterError, match="collection_fed"):
        await collect_ipam_snapshot(source, {})
    with pytest.raises(IpamAdapterError, match="collection_fed"):
        await push_allocation_to_provider(source, {}, address="192.0.2.99")
    with pytest.raises(ValueError, match="OPNsense"):
        await run_reconciliation(int(source["id"]))

    # Push: never tried, even with push switched on behind the API's back.
    await db.update_ipam_source(int(source["id"]), push_enabled=True)
    tried: list[dict] = []

    async def record_push(src, *_args, **_kwargs):
        tried.append(src)

    monkeypatch.setattr(ipam_push, "push_allocation_to_provider", record_push)
    summary = await ipam_push.push_inventory_host_allocation(hostname="probe.example.com", ip_address="192.0.2.99")
    assert summary["attempted"] == 0 and tried == []
    await _forget_opnsense_sources()


@pytest.mark.asyncio
async def test_the_scheduled_sync_skips_the_source(monkeypatch):
    import asyncio

    import netcontrol.app as app_module
    import netcontrol.routes.state as state

    await _forget_opnsense_sources()
    raw = _raw_with_names()
    await opnsense_collection.store_names(raw, build_snapshot(raw))
    (before,) = await _opnsense_sources()

    contacted: list[dict] = []

    async def fake_collect(source, _auth):
        contacted.append(source)
        return {"prefixes": [], "allocations": [], "summary": {}}

    sleeps = 0

    async def one_round(_seconds):
        nonlocal sleeps
        sleeps += 1
        if sleeps > 1:
            raise asyncio.CancelledError

    monkeypatch.setattr(app_module, "collect_ipam_snapshot", fake_collect)
    monkeypatch.setattr(app_module.asyncio, "sleep", one_round)
    monkeypatch.setitem(state.IPAM_SYNC_CONFIG, "enabled", True)
    with pytest.raises(asyncio.CancelledError):
        await app_module._ipam_sync_loop()
    assert all(s.get("provider") != "opnsense" for s in contacted)
    (after,) = await _opnsense_sources()
    assert after["last_sync_status"] == "success" and after["allocation_count"] == before["allocation_count"]
    assert after["last_sync_message"] == before["last_sync_message"]
    await _forget_opnsense_sources()


def test_api_source_is_shown_and_guarded(api, monkeypatch):  # noqa: F811
    import netcontrol.routes.meraki_topology as routes_module

    fake = _FakeFirewall()
    fake.answers["core/backup/download/this"] = _config()
    real_client = routes_module.OpnsenseClient

    def _client_factory(base_url, key, secret, **kwargs):
        kwargs.update(transport=httpx.MockTransport(fake.handler), requests_per_second=1000)
        return real_client(base_url, key, secret, **kwargs)

    monkeypatch.setattr(routes_module, "OpnsenseClient", _client_factory)
    org = _create(api, options={"include_firmware_audit": False}).json()["org"]
    job = _wait(api, api.post(f"/api/sources/{org['id']}/build").json()["job_id"])
    data = api.get(f"/api/sources/snapshots/{job['result']['snapshot_id']}/data").json()
    assert _kv(_node(data, FIREWALL), "Names and reservations")["Result"].startswith("8 addresses")
    assert "names" not in data and "config_xml" not in data

    listed = api.get("/api/ipam/sources?provider=opnsense").json()["sources"]
    (source,) = listed
    assert source["name"] == "Edge firewall (OPNsense)" and source["allocation_count"] == 8
    url = f"/api/ipam/sources/{source['id']}"
    detail = api.get("/api/ipam/subnets/192.0.2.0/25").json()
    assert any(a["ip_address"] == "192.0.2.10" and a["status"] == "reserved" for a in detail["allocations"])

    # Never synced, validated, reconciled or allocated into; never created by hand.
    assert api.post(f"{url}/sync").status_code == 409
    assert api.post(f"{url}/validate").status_code == 409
    assert api.post(f"{url}/reconcile").status_code == 400
    allocate = api.post("/api/ipam/allocate", json={"subnet": "192.0.2.0/25", "source_id": source["id"]})
    assert allocate.status_code == 400
    assert api.post("/api/ipam/sources", json={"provider": "opnsense", "name": "x", "base_url": ""}).status_code == 400
    unchanged = api.get("/api/ipam/sources?provider=opnsense").json()["sources"][0]
    assert unchanged["last_sync_status"] == "success"

    # Only name, notes and enabled change; push and repointing are refused.
    assert api.put(url, json={"push_enabled": True}).status_code == 400
    assert api.put(url, json={"base_url": "https://198.51.100.9"}).status_code == 400
    assert api.put(url, json={"provider": "netbox"}).status_code == 400
    edited = api.put(url, json={"provider": "opnsense", "enabled": False, "notes": "kept"})
    assert edited.status_code == 200 and edited.json()["source"]["enabled"] is False

    # The next build keeps the disabled source's allocations; delete works.
    _wait(api, api.post(f"/api/sources/{org['id']}/build").json()["job_id"])
    assert api.get("/api/ipam/sources?provider=opnsense").json()["sources"][0]["allocation_count"] == 8
    assert api.delete(url).status_code == 200
    assert api.get("/api/ipam/sources?provider=opnsense").json()["sources"] == []
