"""Intended configuration remediation: the generator
(``netcontrol.intended_remediation``) across platforms, nested blocks,
removals and ignore rules; the preview and ignore-rule API
(``netcontrol.routes.intended_config``); deployments created from it
(``netcontrol.routes.deployments``), with feature and object-scope checks.
Invented names and documentation addresses only."""

from __future__ import annotations

import asyncio
import json

import pytest
import routes.database as db
from netcontrol import object_scope
from netcontrol.custom_fields import CustomFieldError
from netcontrol.intended_remediation import (
    PLATFORMS,
    clean_ignore_pattern,
    compile_ignore_rules,
    generate_remediation,
    negate,
)
from netcontrol.routes import state
from netcontrol.routes.device_config import store_device_config

from mcp_helpers import CsrfClient, admin_client, user_client
from test_object_scope_api import _error, _group, _scoped

BASE = "/api/intended-config"
IGNORES = f"{BASE}/remediation-ignores"
BULK = f"{BASE}/remediation"
DEPLOY = "/api/deployments/intended-remediation"

INTENDED = """hostname edge-r1
interface Gi0/1
 description uplink
 shutdown
router bgp 65000
 neighbor 192.0.2.1 remote-as 65001
 address-family ipv4
  network 198.51.100.0 mask 255.255.255.0
  neighbor 192.0.2.1 activate
interface Loopback0
 ip address 192.0.2.254 255.255.255.255
"""
RUNNING = """Building configuration...
version 17.3
hostname edge-r1
interface Gi0/1
 description old-link
 no shutdown
router bgp 65000
 neighbor 192.0.2.1 remote-as 65001
 neighbor 192.0.2.9 remote-as 65009
 address-family ipv4
  neighbor 192.0.2.1 activate
  neighbor 192.0.2.9 activate
 address-family ipv6
  neighbor 2001:db8::1 activate
logging host 203.0.113.5
end
"""
EXPECTED = [
    "interface Gi0/1",
    " no description old-link",
    " description uplink",
    " shutdown",
    "router bgp 65000",
    " no neighbor 192.0.2.9 remote-as 65009",
    " no address-family ipv6",
    " address-family ipv4",
    "  no neighbor 192.0.2.9 activate",
    "  network 198.51.100.0 mask 255.255.255.0",
    "interface Loopback0",
    " ip address 192.0.2.254 255.255.255.255",
]


# ── Generator ────────────────────────────────────────────────────────────────


def test_nested_blocks_removals_first_and_parents_before_children():
    result = generate_remediation(INTENDED, RUNNING, "cisco_ios")
    assert result.supported and result.platform == "Cisco IOS"
    assert result.commands == EXPECTED
    assert (result.added, result.removed) == (5, 4)
    # A top-level line only on the device is never removed: the template may cover part of the config.
    assert not any("logging" in c for c in result.commands)


def test_removing_a_parent_removes_its_block_without_its_children():
    intended = "router ospf 1\n network 192.0.2.0 0.0.0.255 area 0\n"
    running = "router ospf 1\n network 192.0.2.0 0.0.0.255 area 0\n area 5 stub\n  no-summary\n"
    assert generate_remediation(intended, running, "cisco_xe").commands == ["router ospf 1", " no area 5 stub"]


def test_missing_parent_brings_its_children_once():
    intended = "vlan 20\n name servers\ninterface Vlan20\n ip address 192.0.2.1 255.255.255.0\n no shutdown\n"
    result = generate_remediation(intended, "hostname edge-r1\n", "arista_eos")
    assert result.commands == [
        "vlan 20",
        " name servers",
        "interface Vlan20",
        " ip address 192.0.2.1 255.255.255.0",
        " no shutdown",
    ]
    assert result.removed == 0


def test_sibling_blocks_reenter_only_the_differing_level():
    intended = (
        "router bgp 65000\n address-family ipv4\n  network 192.0.2.0\n address-family ipv6\n  network 2001:db8::/32\n"
    )
    running = "router bgp 65000\n address-family ipv4\n address-family ipv6\n"
    assert generate_remediation(intended, running, "cisco_nxos").commands == [
        "router bgp 65000",
        " address-family ipv4",
        "  network 192.0.2.0",
        " address-family ipv6",
        "  network 2001:db8::/32",
    ]


def test_negating_a_no_line_and_the_platform_table():
    assert negate("shutdown") == "no shutdown"
    assert negate("no ip domain-lookup") == "ip domain-lookup"
    intended = "interface 1/1/1\n no shutdown\n"
    running = "interface 1/1/1\n shutdown\n description spare\n"
    # ``shutdown`` is removed by ``no shutdown``, which the addition already is.
    assert generate_remediation(intended, running, "aruba_aoscx").commands == [
        "interface 1/1/1",
        " no description spare",
        " no shutdown",
    ]
    for driver in ("cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos", "aruba_aoscx", "cisco_asa"):
        assert driver in PLATFORMS


def test_compliant_config_needs_nothing_and_dump_lines_are_skipped():
    running = "Building configuration...\nCurrent configuration : 120 bytes\nversion 17.3\n" + INTENDED + "end\n"
    result = generate_remediation(INTENDED, running, "cisco_ios")
    assert result.commands == [] and (result.added, result.removed) == (0, 0)
    asa = generate_remediation("hostname fw1\n", ": Saved\nASA Version 9.16\nhostname fw1\n", "cisco_asa")
    assert asa.commands == []


@pytest.mark.parametrize("driver", ["juniper_junos", "fortinet", "paloalto_panos", "cisco_xr", "", None])
def test_unsupported_platforms_get_no_commands(driver):
    result = generate_remediation(INTENDED, RUNNING, driver)
    assert not result.supported and result.commands == []
    assert "not supported" in result.reason


def test_banners_are_never_remediated_but_noted():
    intended = "hostname edge-r1\nbanner motd ^C\nAuthorized use only\n^C\n"
    running = "hostname edge-r1\nbanner motd ^C\nWelcome\n^C\n"
    result = generate_remediation(intended, running, "cisco_ios")
    assert result.commands == []
    assert result.notes and "Banner" in result.notes[0]
    same = generate_remediation(intended, intended, "cisco_ios")
    assert same.notes == []


def test_ignore_rules_drop_lines_and_their_blocks_from_both_sides():
    rules = [
        {"kind": "exact", "pattern": "description old-link", "device_type": "", "enabled": True},
        {"kind": "prefix", "pattern": "address-family ipv6", "device_type": "cisco_ios", "enabled": True},
        {"kind": "regex", "pattern": r"^neighbor 192\.0\.2\.9 ", "device_type": "", "enabled": True},
        {"kind": "regex", "pattern": "^interface Loopback", "device_type": "", "enabled": False},
        {"kind": "exact", "pattern": "shutdown", "device_type": "arista_eos", "enabled": True},
    ]
    result = generate_remediation(INTENDED, RUNNING, "cisco_ios", rules)
    assert result.commands == [
        "interface Gi0/1",
        " description uplink",
        " shutdown",
        "router bgp 65000",
        " address-family ipv4",
        "  network 198.51.100.0 mask 255.255.255.0",
        "interface Loopback0",
        " ip address 192.0.2.254 255.255.255.255",
    ]
    # description old-link, the ipv6 block (head and child) and the two 192.0.2.9 lines.
    assert result.ignored == 5


def test_ignore_rule_regex_uses_re2_and_rejects_unsafe_syntax():
    matches = compile_ignore_rules([{"kind": "regex", "pattern": "(a+)+b", "enabled": True}], "cisco_ios")
    assert matches("aaab") and not matches("a" * 5000 + "c")  # linear time, no backtracking blow-up
    with pytest.raises(CustomFieldError):
        clean_ignore_pattern("(?=lookahead)", "regex")
    with pytest.raises(CustomFieldError):
        clean_ignore_pattern("   ", "exact")
    assert clean_ignore_pattern("  ntp server  ", "prefix") == "ntp server"
    # A stored regex that no longer compiles is skipped, not an error.
    assert not compile_ignore_rules([{"kind": "regex", "pattern": "(?=x)", "enabled": True}], "")("x")


# ── API ──────────────────────────────────────────────────────────────────────

TEMPLATE = """hostname {{ host.name }}
interface Gi0/1
 description uplink
"""
BACKUP = """hostname {name}
interface Gi0/1
 description old-link
"""


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200) -> dict:
    assert resp.status_code == status, resp.text
    return resp.json()


def _host(admin: CsrfClient, group_id: int, name: str, ip: str, driver: str = "cisco_ios") -> int:
    body = {"hostname": name, "ip_address": ip, "device_type": driver}
    return int(_ok(admin.post(f"/api/inventory/{group_id}/hosts", json=body), 201)["id"])


@pytest.fixture
def lab(admin) -> dict[str, int]:
    """Groups A, B and C with one IOS host each, one Junos host in A, the
    template, backups for all but the backup-less host, generated."""
    t = {"A": _group(admin, "site-a"), "B": _group(admin, "site-b"), "C": _group(admin, "site-c")}
    t["hA"] = _host(admin, t["A"], "edge-a", "192.0.2.10")
    t["hB"] = _host(admin, t["B"], "edge-b", "198.51.100.20")
    t["hC"] = _host(admin, t["C"], "edge-c", "203.0.113.30")
    t["junos"] = _host(admin, t["A"], "edge-j", "192.0.2.11", "juniper_junos")
    t["nobackup"] = _host(admin, t["B"], "edge-n", "198.51.100.21")
    _ok(admin.post(f"{BASE}/templates", json={"name": "base", "kind": "device", "template_text": TEMPLATE}), 201)
    for key, name in (("hA", "edge-a"), ("hB", "edge-b"), ("hC", "edge-c"), ("junos", "edge-j")):
        asyncio.run(store_device_config(t[key], BACKUP.format(name=name), "", capture_method="topology"))
    _ok(admin.post(f"{BASE}/generate", json={"host_ids": [t[k] for k in ("hA", "hB", "hC", "junos", "nobackup")]}))
    t["cred"] = asyncio.run(db.create_credential("lab", "operator", "", is_service=True))
    return t


HOST_A_COMMANDS = ["interface Gi0/1", " no description old-link", " description uplink"]


def test_host_preview_states(admin, lab):
    row = _ok(admin.get(f"{BASE}/hosts/{lab['hA']}/remediation"))
    assert row["state"] == "ok" and row["commands"] == HOST_A_COMMANDS
    assert (row["added"], row["removed"], row["template_name"]) == (1, 1, "base")
    assert row["backup"]["id"] > 0
    junos = _ok(admin.get(f"{BASE}/hosts/{lab['junos']}/remediation"))
    assert junos["state"] == "unsupported" and junos["commands"] == [] and "juniper_junos" in junos["reason"]
    missing = _ok(admin.get(f"{BASE}/hosts/{lab['nobackup']}/remediation"))
    assert missing["state"] == "unavailable" and "backup" in missing["reason"]
    assert admin.get(f"{BASE}/hosts/999999/remediation").status_code == 404


def test_bulk_preview_by_hosts_group_and_dynamic_group(admin, lab):
    rows = _ok(admin.post(BULK, json={"host_ids": [lab["hA"], lab["junos"]]}))
    assert [r["state"] for r in rows["hosts"]] == ["ok", "unsupported"]
    assert rows["counts"] == {"hosts": 2, "with_commands": 1, "unsupported": 1, "unavailable": 0}
    group = _ok(admin.post(BULK, json={"group_id": lab["B"]}))
    assert {r["host_id"]: r["state"] for r in group["hosts"]} == {lab["hB"]: "ok", lab["nobackup"]: "unavailable"}
    dyn = _ok(admin.post("/api/dynamic-groups", json={"name": "site-c hosts", "filter": {"groups": [lab["C"]]}}), 201)
    by_dyn = _ok(admin.post(BULK, json={"dynamic_group_id": dyn["id"]}))
    assert [r["host_id"] for r in by_dyn["hosts"]] == [lab["hC"]]
    assert admin.post(BULK, json={"dynamic_group_id": 999999}).status_code == 404
    assert admin.post(BULK, json={}).status_code == 400
    assert admin.post(BULK, json={"host_ids": [lab["hA"]], "group_id": lab["A"]}).status_code == 400


def test_ignore_rules_api_is_admin_only_validated_and_applied(admin, lab):
    plain = user_client(admin, "drift-user", features=["config-drift"])
    assert plain.get(IGNORES).status_code == 403
    assert plain.post(IGNORES, json={"kind": "exact", "pattern": "x"}).status_code == 403
    assert admin.post(IGNORES, json={"kind": "regex", "pattern": "(?<=x)y"}).status_code == 400
    assert admin.post(IGNORES, json={"kind": "glob", "pattern": "x"}).status_code == 400
    assert admin.post(IGNORES, json={"kind": "exact", "pattern": "  "}).status_code == 400
    rule = _ok(admin.post(IGNORES, json={"kind": "regex", "pattern": "^description ", "description": "labels"}), 201)
    assert rule["enabled"] and rule["device_type"] == ""
    assert [r["id"] for r in _ok(admin.get(IGNORES))["rules"]] == [rule["id"]]
    row = _ok(admin.get(f"{BASE}/hosts/{lab['hA']}/remediation"))
    assert row["commands"] == [] and row["ignored"] == 2
    off = _ok(
        admin.put(f"{IGNORES}/{rule['id']}", json={"kind": "regex", "pattern": "^description ", "enabled": False})
    )
    assert off["enabled"] is False
    assert _ok(admin.get(f"{BASE}/hosts/{lab['hA']}/remediation"))["commands"] == HOST_A_COMMANDS
    assert admin.put(f"{IGNORES}/999999", json={"kind": "exact", "pattern": "x"}).status_code == 404
    _ok(admin.delete(f"{IGNORES}/{rule['id']}"))
    assert admin.delete(f"{IGNORES}/{rule['id']}").status_code == 404
    assert _ok(admin.get(IGNORES))["rules"] == []


def test_create_deployments_one_per_host_and_skips(admin, lab):
    body = {"host_ids": [lab["hA"], lab["hB"], lab["junos"], lab["nobackup"]], "credential_id": lab["cred"]}
    out = _ok(admin.post(DEPLOY, json=body))
    assert [d["host_id"] for d in out["deployments"]] == [lab["hA"], lab["hB"]]
    assert {s["host_id"] for s in out["skipped"]} == {lab["junos"], lab["nobackup"]}
    first = out["deployments"][0]
    assert first["status"] == "planning" and first["commands"] == 3
    dep = _ok(admin.get(f"/api/deployments/{first['id']}"))
    assert dep["change_type"] == "intended-remediation"
    assert dep["proposed_commands"].split("\n") == HOST_A_COMMANDS
    assert json.loads(dep["host_ids"]) == [lab["hA"]] and dep["group_id"] == lab["A"]
    assert dep["name"] == "Intended remediation: edge-a"
    # A compliant host is skipped with the reason.
    asyncio.run(
        store_device_config(
            lab["hA"], "hostname edge-a\ninterface Gi0/1\n description uplink\n", "", capture_method="topology"
        )
    )
    again = _ok(admin.post(DEPLOY, json={"host_ids": [lab["hA"]], "credential_id": lab["cred"], "name": "Fix"}))
    assert again["deployments"] == [] and "already matches" in again["skipped"][0]["reason"]


def test_production_group_deployment_needs_approval(admin, lab):
    asyncio.run(db.set_group_environment(lab["B"], "production"))
    out = _ok(admin.post(DEPLOY, json={"group_id": lab["B"], "credential_id": lab["cred"], "name": "Fix B"}))
    assert len(out["deployments"]) == 1
    assert out["deployments"][0]["requires_approval"] is True
    assert out["deployments"][0]["approval_status"] == "pending"
    assert _ok(admin.get(f"/api/deployments/{out['deployments'][0]['id']}"))["name"] == "Fix B: edge-b"


def test_deployment_creation_needs_both_features(admin, lab):
    body = {"host_ids": [lab["hA"]], "credential_id": lab["cred"]}
    drift_only = user_client(admin, "drift-only", features=["config-drift"])
    assert drift_only.post(DEPLOY, json=body).status_code == 403
    deploy_only = user_client(admin, "deploy-only", features=["deployments", "deployments.write"])
    resp = deploy_only.post(DEPLOY, json=body)
    assert resp.status_code == 403 and "config-drift" in resp.text
    assert deploy_only.get(f"{BASE}/hosts/{lab['hA']}/remediation").status_code == 403


def test_scoped_user_remediates_only_writable_hosts(admin, lab, monkeypatch):
    # Deployments are not scope-enforced, so a scoped user never holds the
    # feature today; enrol it here to check the write-scope gate itself.
    monkeypatch.setattr(object_scope, "SCOPE_ENFORCED_FEATURES", object_scope.SCOPE_ENFORCED_FEATURES | {"deployments"})
    grants = [{"inventory_group_id": lab["A"]}, {"inventory_group_id": lab["B"], "can_write": True}]
    scoped = _scoped(admin, "remediator", grants, ["config-drift", "deployments", "deployments.write", "credentials"])
    # Preview: read scope.
    assert _ok(scoped.get(f"{BASE}/hosts/{lab['hA']}/remediation"))["state"] == "ok"
    hidden = scoped.get(f"{BASE}/hosts/{lab['hC']}/remediation")
    assert hidden.status_code == 404
    assert hidden.json() == scoped.get(f"{BASE}/hosts/999999/remediation").json()
    assert scoped.post(BULK, json={"group_id": lab["C"]}).status_code == 404
    assert scoped.post(BULK, json={"host_ids": [lab["hA"], lab["hC"]]}).status_code == 404
    # Deployments: write scope; nothing is created when one host fails.
    cred = lab["cred"]
    read_only = scoped.post(DEPLOY, json={"host_ids": [lab["hA"]], "credential_id": cred})
    assert read_only.status_code == 403 and read_only.json() == _error(object_scope.READ_ONLY_DETAIL)
    assert scoped.post(DEPLOY, json={"host_ids": [lab["hB"], lab["hA"]], "credential_id": cred}).status_code == 403
    assert scoped.post(DEPLOY, json={"group_id": lab["A"], "credential_id": cred}).status_code == 403
    assert scoped.post(DEPLOY, json={"host_ids": [lab["hC"]], "credential_id": cred}).status_code == 404
    dyn = _ok(
        admin.post("/api/dynamic-groups", json={"name": "a and b", "filter": {"groups": [lab["A"], lab["B"]]}}), 201
    )
    assert scoped.post(DEPLOY, json={"dynamic_group_id": dyn["id"], "credential_id": cred}).status_code == 403
    assert asyncio.run(db.get_deployments(limit=50)) == []
    # A non-admin signs in with their own credential (service credentials are admin only).
    user = asyncio.run(db.get_user_by_username("remediator"))
    own = asyncio.run(db.create_credential("mine", "operator", "", owner_id=int(user["id"])))
    ok = _ok(scoped.post(DEPLOY, json={"host_ids": [lab["hB"]], "credential_id": own}))
    assert [d["host_id"] for d in ok["deployments"]] == [lab["hB"]]
