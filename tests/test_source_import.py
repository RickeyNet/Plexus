"""Tests for importing a topology source's devices into the inventory
(``netcontrol.routes.source_import``).

Covers, over HTTP with no network access:
  * listing    - the devices of the latest collection, for every provider's
                 bundled sample, and the reason when there are none
  * import     - a new group, devices already in the inventory skipped,
                 never changed, and a second import adding nothing
  * validation - unknown devices, group choice, unknown SNMP profile, a
                 backup asked for devices that cannot be backed up
  * follow-ups - the SNMP profile assigned to the group (an assignment
                 already there is kept), a daily backup policy created once
"""

from __future__ import annotations

import netcontrol.routes.source_import as source_import
import netcontrol.routes.state as state
import pytest
from netcontrol.integrations import inventory_import

from test_meraki_topology import _CsrfClient, api  # noqa: F401 - the fixture is used by name


@pytest.fixture(autouse=True)
def _fresh_snmp_state(monkeypatch):
    """SNMP profiles and their group assignments are process state: start empty."""
    monkeypatch.setattr(state, "SNMP_PROFILES", {})
    monkeypatch.setattr(state, "GROUP_SNMP_ASSIGNMENTS", {})


def _message(resp) -> str:
    body = resp.json()
    return str((body.get("error") or {}).get("message") or body.get("detail") or "")


def _sample(client, provider: str) -> int:
    built = client.post(f"/api/sources/sample?provider={provider}")
    assert built.status_code == 201, built.text
    return built.json()["org_ref"]


def _importable(client, org_ref: int) -> dict:
    resp = client.get(f"/api/sources/{org_ref}/importable-devices")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _import(client, org_ref: int, **body):
    return client.post(f"/api/sources/{org_ref}/import-devices", json=body)


def _profile(client, name: str) -> str:
    created = client.post("/api/admin/snmp-profiles", json={"name": name, "enabled": True, "community": "example-ro"})
    assert created.status_code == 200, created.text
    return created.json()["id"]


# ── Listing ──────────────────────────────────────────────────────────────────


def test_listing_needs_authentication_and_a_known_source(api):  # noqa: F811
    assert api.get("/api/sources/999999/importable-devices").status_code == 404
    api._c.cookies.clear()
    assert api.get("/api/sources/1/importable-devices").status_code == 401


def test_a_source_never_collected_lists_nothing_and_cannot_import(api):  # noqa: F811
    org = api.post(
        "/api/sources", json={"name": "Branch FMC", "provider": "fmc", "base_url": "https://fmc.example.com"}
    )
    org_ref = org.json()["org"]["id"]
    found = _importable(api, org_ref)
    assert found["devices"] == [] and found["snapshot_id"] is None
    assert found["reason"] == inventory_import.NO_SNAPSHOT_REASON
    refused = _import(api, org_ref, device_keys=["d:1"], new_group_name="Branch FMC")
    assert refused.status_code == 409


@pytest.mark.parametrize("provider", ["meraki", "cato", "fmc", "panorama", "appgate"])
def test_every_provider_lists_its_devices_or_says_why_not(api, provider):  # noqa: F811
    found = _importable(api, _sample(api, provider))
    assert found["provider"] == provider and found["snapshot_id"]
    assert found["provider_note"] and found["suggested_group_name"]
    assert found["max_devices"] > 0
    assert found["devices"] or found["reason"]
    for device in found["devices"]:
        # Nothing was imported, so a device is in the inventory only when a
        # seeded host has its address (the Meraki sample's LLDP neighbor
        # overlaps the dev-bootstrap seed).
        assert device["existing"] is None or device["existing"]["ip_address"] == device["ip"]
        assert set(device["capabilities"]) == {"snmp_polling", "config_backup"}
    assert "api_key" not in str(found)


# ── Import ───────────────────────────────────────────────────────────────────


def test_import_adds_new_devices_to_a_new_group_and_skips_existing_hosts(api):  # noqa: F811
    org_ref = _sample(api, "fmc")
    devices = _importable(api, org_ref)["devices"]
    assert len(devices) >= 3 and all(d["device_type"] == "cisco_ftd" for d in devices)

    # One device is in the inventory already, under another name and type.
    group = api.post("/api/inventory", json={"name": "Existing", "description": ""}).json()
    existing = api.post(
        f"/api/inventory/{group['id']}/hosts",
        json={"hostname": "kept-name", "ip_address": devices[0]["ip"], "device_type": "cisco_asa"},
    )
    assert existing.status_code == 201, existing.text
    listed = {d["key"]: d for d in _importable(api, org_ref)["devices"]}
    assert listed[devices[0]["key"]]["existing"]["host_id"] == existing.json()["id"]

    keys = [d["key"] for d in devices[:3]]
    done = _import(api, org_ref, device_keys=keys, new_group_name="  Firewalls   East ")
    assert done.status_code == 200, done.text
    result = done.json()
    assert result["group"]["name"] == "Firewalls East" and result["group"]["created"] is True
    assert result["counts"] == {"added": 2, "skipped": 1, "errors": 0}
    assert result["skipped"][0]["ip_address"] == devices[0]["ip"]
    assert result["snmp_profile"]["status"] == "none" and result["backup_policy"]["status"] == "none"

    hosts = api.get(f"/api/inventory/{result['group']['id']}/hosts").json()
    assert sorted(h["ip_address"] for h in hosts) == sorted(d["ip"] for d in devices[1:3])
    assert {h["device_type"] for h in hosts} == {"cisco_ftd"}
    # The existing host is untouched.
    kept = api.get(f"/api/inventory/{group['id']}/hosts").json()
    assert [(h["hostname"], h["device_type"]) for h in kept] == [("kept-name", "cisco_asa")]

    # Importing the same devices again into the same group adds nothing.
    again = _import(api, org_ref, device_keys=keys, group_id=result["group"]["id"])
    assert again.status_code == 200, again.text
    assert again.json()["counts"] == {"added": 0, "skipped": 3, "errors": 0}
    assert again.json()["group"]["created"] is False


def test_import_validates_before_writing(api):  # noqa: F811
    org_ref = _sample(api, "panorama")
    key = _importable(api, org_ref)["devices"][0]["key"]
    groups_before = len(api.get("/api/inventory").json())

    unknown = _import(api, org_ref, device_keys=[key, "d:not-in-snapshot"], new_group_name="PAN")
    assert unknown.status_code == 400 and "d:not-in-snapshot" in _message(unknown)
    assert _import(api, org_ref, device_keys=[key]).status_code == 400
    assert _import(api, org_ref, device_keys=[key], group_id=1, new_group_name="PAN").status_code == 400
    assert _import(api, org_ref, device_keys=[key], group_id=999999).status_code == 404
    assert _import(api, org_ref, device_keys=[], new_group_name="PAN").status_code == 422
    assert _import(api, org_ref, device_keys=[key], new_group_name="PAN", extra=1).status_code == 422
    no_profile = _import(api, org_ref, device_keys=[key], new_group_name="PAN", snmp_profile_id="nope")
    assert no_profile.status_code == 400
    # PAN-OS configuration lives in Panorama: Config Backups cannot read it.
    no_backup = _import(api, org_ref, device_keys=[key], new_group_name="PAN", backup_credential_id=1)
    assert no_backup.status_code == 400 and "Config Backups" in _message(no_backup)

    api.post("/api/inventory", json={"name": "Taken", "description": ""})
    taken = _import(api, org_ref, device_keys=[key], new_group_name="Taken")
    assert taken.status_code == 409
    # Nothing was written by any refused request.
    assert len(api.get("/api/inventory").json()) == groups_before + 1


def test_import_assigns_the_snmp_profile_and_keeps_an_existing_assignment(api):  # noqa: F811
    org_ref = _sample(api, "panorama")
    keys = [d["key"] for d in _importable(api, org_ref)["devices"]]
    read_only = _profile(api, "Read-only v2c")

    done = _import(api, org_ref, device_keys=keys[:1], new_group_name="PAN East", snmp_profile_id=read_only)
    assert done.status_code == 200, done.text
    snmp = done.json()["snmp_profile"]
    assert snmp == {"status": "assigned", "profile_id": read_only, "profile_name": "Read-only v2c"}
    group_id = done.json()["group"]["id"]
    assigned = api.get(f"/api/inventory/{group_id}/snmp-profile-assignment").json()
    assert assigned["snmp_profile_id"] == read_only

    other = _profile(api, "Other v2c")
    again = _import(api, org_ref, device_keys=keys[1:2], group_id=group_id, snmp_profile_id=other)
    assert again.json()["snmp_profile"]["status"] == "kept"
    assert api.get(f"/api/inventory/{group_id}/snmp-profile-assignment").json()["snmp_profile_id"] == read_only


def test_import_creates_one_backup_policy_for_devices_that_can_be_backed_up(api, monkeypatch):  # noqa: F811
    org_ref = _sample(api, "meraki")
    real = source_import.importable_devices

    def with_a_catalyst(snapshot, provider, hosts=None):
        # The bundled sample has no device of a platform Config Backups reads:
        # make its CDP/LLDP neighbor one, as a real IOS-XE switch would be.
        found = real(snapshot, provider, hosts)
        for device in found["devices"]:
            if device["key"].startswith("x:"):
                device["device_type"] = "cisco_xe"
                device["capabilities"] = inventory_import.capabilities("cisco_xe")
        return found

    monkeypatch.setattr(source_import, "importable_devices", with_a_catalyst)
    neighbor = next(d for d in _importable(api, org_ref)["devices"] if d["key"].startswith("x:"))
    assert neighbor["capabilities"]["config_backup"] is True

    credential = api.post("/api/credentials", json={"name": "netops", "username": "netops", "password": "pw-123456"})
    assert credential.status_code == 201, credential.text
    cred_id = credential.json()["id"]
    assert (
        _import(
            api, org_ref, device_keys=[neighbor["key"]], new_group_name="Core", backup_credential_id=999999
        ).status_code
        == 404
    )

    done = _import(api, org_ref, device_keys=[neighbor["key"]], new_group_name="Core", backup_credential_id=cred_id)
    assert done.status_code == 200, done.text
    backup = done.json()["backup_policy"]
    assert backup["status"] == "created" and backup["name"] == "Core daily backup"
    group_id = done.json()["group"]["id"]
    policies = api.get(f"/api/config-backups/policies?group_id={group_id}").json()
    assert [(p["id"], p["credential_id"], p["interval_seconds"]) for p in policies] == [
        (backup["policy_id"], cred_id, 86400)
    ]

    again = _import(api, org_ref, device_keys=[neighbor["key"]], group_id=group_id, backup_credential_id=cred_id)
    assert again.json()["backup_policy"]["status"] == "exists"
    assert len(api.get(f"/api/config-backups/policies?group_id={group_id}").json()) == 1
