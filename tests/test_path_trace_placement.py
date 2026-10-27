"""Placing a device whose own network was not collected on a LAN, from the
Meraki client table (``netcontrol.integrations.pathtrace.placement``)."""

from __future__ import annotations

from netcontrol.integrations.meraki.forwarding import interface, new_block
from netcontrol.integrations.pathtrace.placement import host_label, networks_to_read, place, placements


def _row(description: str, ip: str, last_seen: str, *, network: str = "N_HQ", org_ref: int = 1, **fields) -> dict:
    return {
        "org_ref": org_ref,
        "network_id": network,
        "network_name": "1000 - HQ",
        "mac_address": "aa:bb:cc:dd:ee:01",
        "ip_address": ip,
        "vlan": 400,
        "device_serial": "Q2XX-0001",
        "device_name": "HQ-AP-01",
        "description": description,
        "last_seen": last_seen,
        **fields,
    }


def _snapshots(behind: str = "50.173.129.34", device_name: str = "CCM_5CG4062LTK.corp.example") -> dict:
    mx = new_block()
    mx["interfaces"].append(interface("wan1", "wan", ip="50.173.129.34"))
    user = new_block()
    user["interfaces"].append(interface("Local network (direct)", "wan", behind_ip=behind))
    return {
        1: {
            "provider": "meraki",
            "nodes": [{"id": "d:MX", "kind": "appliance", "site": "N_HQ", "forwarding": mx}],
        },
        4: {
            "provider": "cato",
            "nodes": [
                {"id": "cato:user:25", "kind": "user", "site": "users", "device_name": device_name, "forwarding": user}
            ],
        },
    }


def _graph() -> dict:
    return {
        "nodes": [
            {"id": "meraki:1:d:MX", "meraki": {"org_ref": 1, "node_id": "d:MX"}},
            {"id": "meraki:4:cato:user:25", "meraki": {"org_ref": 4, "node_id": "cato:user:25", "provider": "cato"}},
        ]
    }


def test_host_label_is_the_first_dns_label_in_lower_case():
    assert host_label("CCM_5CG4062LTK.crosscountrymtg.local") == "ccm_5cg4062ltk"
    assert host_label(" CCM_PF2KFS52 ") == "ccm_pf2kfs52"
    assert host_label(None) == ""


def test_the_newest_row_of_the_network_that_names_the_device_places_it():
    rows = [
        _row("ccm_5cg4062ltk", "10.74.40.10", "2026-10-20T08:00:00+00:00"),
        _row("CCM_5CG4062LTK.corp.example", "10.74.40.134", "2026-10-23T09:00:00+00:00"),
        # Another network, another name, no address: never a match.
        _row("CCM_5CG4062LTK", "10.66.62.9", "2026-10-25T09:00:00+00:00", network="N_OTHER"),
        _row("CCM_5CG4062LTJ", "10.74.40.77", "2026-10-25T09:00:00+00:00"),
        _row("CCM_5CG4062LTK", "", "2026-10-26T09:00:00+00:00"),
    ]
    found = place("CCM_5CG4062LTK.crosscountrymtg.local", rows, [(1, "N_HQ")])
    assert found == {
        "ip": "10.74.40.134",
        "vlan": 400,
        "org_ref": 1,
        "network_id": "N_HQ",
        "network_name": "1000 - HQ",
        "device_name": "HQ-AP-01",
        "seen": "2026-10-23T09:00:00+00:00",
        "description": "CCM_5CG4062LTK.corp.example",
        "source": "Meraki",
    }
    assert place("CCM_5CG4062LTK", rows, [(2, "N_HQ")]) is None
    assert place("", rows, [(1, "N_HQ")]) is None


def test_placements_are_keyed_by_graph_node_and_need_the_network_of_the_device_that_answers():
    snapshots = _snapshots()
    assert networks_to_read(snapshots) == [(1, "N_HQ")]
    rows = [_row("CCM_5CG4062LTK", "10.74.40.134", "2026-10-23T09:00:00+00:00")]
    found = placements(_graph(), snapshots, rows)
    assert list(found) == ["meraki:4:cato:user:25"] and found["meraki:4:cato:user:25"]["ip"] == "10.74.40.134"

    # No Meraki device answers on the address: nothing to read, nothing placed.
    elsewhere = _snapshots(behind="192.0.2.9")
    assert networks_to_read(elsewhere) == [] and placements(_graph(), elsewhere, rows) == {}
    # A node that names no device is not placed.
    nameless = _snapshots(device_name="")
    assert networks_to_read(nameless) == [] and placements(_graph(), nameless, rows) == {}
