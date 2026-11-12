"""Tests for the snapshot-to-inventory candidate extraction
(``netcontrol.integrations.inventory_import``) and the shared host address
check (``netcontrol.routes.host_identity.host_ip_problem``).

Pure: no database, no network. The snapshots are built by hand with
invented names and documentation address ranges, in the node shape every
provider's normalizer writes.
"""

from __future__ import annotations

import importlib

import pytest
from netcontrol.drivers import supports_config_capture
from netcontrol.integrations.inventory_import import (
    NO_DEVICES_REASON,
    NO_SNAPSHOT_REASON,
    PROVIDER_NOTES,
    capabilities,
    device_type_for,
    importable_devices,
)
from netcontrol.routes.host_identity import host_ip_problem


def _node(node_id: str, kind: str, label: str, ip: str = "", model: str = "", **fields) -> dict:
    node = {
        "id": node_id,
        "kind": kind,
        "label": label,
        "site": "site-1",
        "status": "online",
        "model": model,
        "serial": "",
        "mac": "",
        "ip": ip,
        "sections": [],
    }
    node.update(fields)
    return node


def _snapshot(*nodes: dict) -> dict:
    return {"sites": [{"id": "site-1", "name": "Branch One"}], "nodes": list(nodes), "edges": []}


# ── host_ip_problem ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("ip", ["192.0.2.10", "198.51.100.1", "203.0.113.254", "2001:db8::1"])
def test_unicast_addresses_have_no_problem(ip):
    assert host_ip_problem(ip) == ""


@pytest.mark.parametrize("ip", ["", "not-an-ip", "192.0.2.300", " 192.0.2.10"])
def test_non_addresses_are_invalid(ip):
    assert host_ip_problem(ip) == "invalid"


@pytest.mark.parametrize(
    "ip", ["127.0.0.1", "169.254.1.1", "fe80::1", "0.0.0.0", "224.0.0.5", "255.255.255.255", "::1"]
)
def test_reserved_addresses_are_reserved(ip):
    assert host_ip_problem(ip) == "reserved"


# ── Device types and capabilities ────────────────────────────────────────────


def test_capabilities_follow_the_driver():
    assert capabilities("icmp_only") == {"snmp_polling": False, "config_backup": False}
    assert capabilities("cisco_xe") == {"snmp_polling": True, "config_backup": True}
    # FTD and PAN-OS configuration lives in their manager: polled, not backed up.
    assert capabilities("cisco_ftd") == {"snmp_polling": True, "config_backup": False}
    assert capabilities("paloalto_panos") == {"snmp_polling": True, "config_backup": False}
    assert supports_config_capture("juniper_junos") and not supports_config_capture("no_such_driver")


@pytest.mark.parametrize(
    ("provider", "node", "expected"),
    [
        ("meraki", _node("d:Q2XX-0001", "switch", "sw1", model="MS390-48"), "icmp_only"),
        ("meraki", _node("x:N_1:core", "external", "core", model="Cisco NX-OS 10.2"), "cisco_nxos"),
        ("meraki", _node("x:N_1:edge", "external", "edge", model="Juniper Junos"), "juniper_junos"),
        ("meraki", _node("x:N_1:phone", "external", "phone", model="IP Phone"), "icmp_only"),
        ("cato", _node("d:1", "appliance", "socket", model="X1500"), "icmp_only"),
        ("fmc", _node("d:u-1", "appliance", "ftd1", model="Cisco Firepower 1120 Threat Defense"), "cisco_ftd"),
        ("fmc", _node("d:u-2", "appliance", "asa1", model="Cisco Adaptive Security Appliance"), "cisco_asa"),
        ("anyconnect", _node("d:u-3", "appliance", "ftd2", model="Threat Defense"), "cisco_ftd"),
        ("panorama", _node("d:0001", "appliance", "fw1", model="PA-440"), "paloalto_panos"),
        ("appgate", _node("a:1", "appliance", "gw1", model="Appgate Gateway"), "icmp_only"),
    ],
)
def test_device_type_per_provider(provider, node, expected):
    assert device_type_for(provider, node) == expected


# ── importable_devices ───────────────────────────────────────────────────────


def test_no_snapshot_gives_a_reason():
    assert importable_devices(None, "meraki") == {"devices": [], "reason": NO_SNAPSHOT_REASON}


def test_an_unknown_provider_gives_a_reason():
    found = importable_devices(_snapshot(_node("d:1", "appliance", "a", "192.0.2.1")), "aws")
    assert found["devices"] == [] and found["reason"]


def test_every_organization_provider_has_a_note():
    assert set(PROVIDER_NOTES) == {"meraki", "cato", "fmc", "panorama", "appgate"}


def test_only_devices_with_a_usable_address_are_candidates():
    snapshot = _snapshot(
        _node("d:SW-1", "switch", "branch-sw1", "192.0.2.11", "MS120-8"),
        _node("x:site-1:core", "external", "core-sw", "192.0.2.2", "Cisco NX-OS"),
        _node("w:SW-1:wan1", "wan", "WAN1", "198.51.100.10"),
        _node("p:peer", "vpn_peer", "peer", "203.0.113.5"),
        _node("d:AP-1", "wireless", "ap-no-ip", ""),
        _node("d:AP-2", "wireless", "ap-loopback", "127.0.0.1"),
        _node("d:AP-3", "wireless", "ap-junk", "dhcp"),
    )
    found = importable_devices(snapshot, "meraki")
    assert found["reason"] == ""
    assert [(d["key"], d["ip"]) for d in found["devices"]] == [
        ("d:SW-1", "192.0.2.11"),
        ("x:site-1:core", "192.0.2.2"),
    ]
    switch = found["devices"][0]
    assert switch["name"] == "branch-sw1" and switch["site"] == "Branch One"
    assert switch["platform"] == "meraki-ms" and switch["device_type"] == "icmp_only"
    assert switch["existing"] is None


def test_cato_ipsec_sites_and_users_are_not_devices():
    snapshot = _snapshot(
        _node("s:42", "appliance", "IPsec site", "203.0.113.20", "IPSEC_V2"),
        _node("cato:user:1", "user", "a user", "192.0.2.80", "Cato Client"),
        _node("d:9", "appliance", "socket-1", "192.0.2.1", "X1500"),
        _node("cato:cloud", "cloud", "Cato Cloud"),
    )
    found = importable_devices(snapshot, "cato")
    assert [d["key"] for d in found["devices"]] == ["d:9"]


def test_manager_nodes_and_users_are_not_devices():
    for provider, device in (
        ("fmc", _node("d:u-1", "appliance", "ftd-1", "192.0.2.21", "Cisco Firepower 2110 Threat Defense")),
        ("panorama", _node("d:0001", "appliance", "fw-1", "192.0.2.31", "PA-440")),
        ("appgate", _node("a:7", "appliance", "gw-1", "192.0.2.41", "Appgate Gateway")),
    ):
        snapshot = _snapshot(
            _node(provider, "cloud", "manager", "192.0.2.200", "Manager"),
            _node("u:x", "users", "users (3)"),
            device,
        )
        found = importable_devices(snapshot, provider)
        assert [d["key"] for d in found["devices"]] == [device["id"]], provider


def test_one_candidate_per_address_sorted_by_name():
    snapshot = _snapshot(
        _node("d:B", "appliance", "zeta", "192.0.2.5"),
        _node("d:A", "appliance", "Alpha", "192.0.2.6"),
        # The standby of an HA pair reporting the same management address.
        _node("d:C", "appliance", "zeta-standby", "192.0.2.5"),
    )
    found = importable_devices(snapshot, "panorama")
    assert [d["name"] for d in found["devices"]] == ["Alpha", "zeta"]


def test_existing_hosts_are_flagged_by_address_and_by_the_collection_match():
    hosts = [
        {"id": 1, "hostname": "fw-a", "ip_address": "192.0.2.21", "group_id": 3, "group_name": "Firewalls"},
        {"id": 2, "hostname": "fw-b", "ip_address": "198.51.100.9", "group_id": 3, "group_name": "Firewalls"},
    ]
    snapshot = _snapshot(
        _node("d:1", "appliance", "fw-a", "192.0.2.21", "PA-440"),
        # Matched by serial during the collection, listed under another address.
        _node("d:2", "appliance", "fw-b", "192.0.2.22", "PA-440", inventory={"host_id": 2}),
        _node("d:3", "appliance", "fw-c", "192.0.2.23", "PA-440", inventory={"host_id": 99}),
        _node("d:4", "appliance", "fw-d", "192.0.2.24", "PA-440"),
    )
    devices = {d["key"]: d for d in importable_devices(snapshot, "panorama", hosts)["devices"]}
    assert devices["d:1"]["existing"] == {
        "host_id": 1,
        "hostname": "fw-a",
        "ip_address": "192.0.2.21",
        "group_id": 3,
        "group_name": "Firewalls",
    }
    assert devices["d:2"]["existing"]["host_id"] == 2
    # A host the collection matched that is gone since is not "existing".
    assert devices["d:3"]["existing"] is None
    assert devices["d:4"]["existing"] is None


def test_a_snapshot_without_device_addresses_gives_a_reason():
    snapshot = _snapshot(_node("d:9", "appliance", "socket-1", "", "X1500"))
    assert importable_devices(snapshot, "cato") == {"devices": [], "reason": NO_DEVICES_REASON}


@pytest.mark.parametrize("provider", ["meraki", "cato", "fmc", "panorama", "appgate"])
def test_the_bundled_sample_of_every_provider_is_read(provider):
    """Every provider's own sample snapshot goes through without error and
    each candidate it yields has the full shape (vendor parity)."""
    raw = importlib.import_module(f"netcontrol.integrations.{provider}.sample").build_sample_raw()
    build = importlib.import_module(f"netcontrol.integrations.{provider}.normalize").build_snapshot
    snapshot = build(raw, None)
    found = importable_devices(snapshot, provider)
    assert found["devices"] or found["reason"] == NO_DEVICES_REASON
    for device in found["devices"]:
        assert set(device) == {
            "key",
            "name",
            "ip",
            "model",
            "serial",
            "kind",
            "site",
            "platform",
            "device_type",
            "capabilities",
            "existing",
        }
        assert host_ip_problem(device["ip"]) == ""
