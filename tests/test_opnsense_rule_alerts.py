"""OPNsense rule change alerts: a new config backup that brings in an
any-to-any or shadowed rule raises an alert on the firewall's inventory
host; a later backup without it resolves the alert.

``rules.rule_change_findings`` compares two parsed configurations;
``opnsense_rule_alerts.alert_rule_changes`` runs from
``opnsense_collection.store_config_backup`` after a new backup was stored.
Every name and address is invented (documentation ranges, example.com); no
firewall is contacted.
"""

from __future__ import annotations

import routes.database as db
from netcontrol.integrations.opnsense.normalize import build_snapshot
from netcontrol.integrations.opnsense.rules import analyze, rule_change_findings
from netcontrol.integrations.opnsense.sample import SAMPLE_CONFIG_XML, build_sample_raw
from netcontrol.integrations.pathtrace.opnsense_config import parse_document
from netcontrol.routes import opnsense_collection, topology_availability as tracking
from netcontrol.routes.opnsense_collection import SECTION_CONFIG_BACKUP, _firewall, store_config_backup
from netcontrol.routes.opnsense_rule_alerts import ALERT_TYPE, dedup_key

from test_meraki_topology import api  # noqa: F401 - the fixture is used by name

R_WEB = "44444444-4444-4444-8444-000000000001"
R_SSH = "44444444-4444-4444-8444-000000000002"
R_BLOCK = "44444444-4444-4444-8444-000000000003"
R_ANY = "44444444-4444-4444-8444-000000000004"
R_TELNET = "44444444-4444-4444-8444-000000000005"
R_BLOCK_SSH = "44444444-4444-4444-8444-000000000006"


def _rule(
    uuid: str,
    action: str = "pass",
    *,
    protocol: str = "tcp",
    source: str = "<network>lan</network>",
    destination: str = "<any/>",
    descr: str = "",
    disabled: bool = False,
) -> str:
    proto = f"<protocol>{protocol}</protocol>" if protocol else ""
    off = "<disabled>1</disabled>" if disabled else ""
    return (
        f'<rule uuid="{uuid}"><type>{action}</type><interface>lan</interface><ipprotocol>inet</ipprotocol>'
        f"{proto}<source>{source}</source><destination>{destination}</destination><descr>{descr}</descr>{off}</rule>"
    )


WEB = _rule(R_WEB, destination="<address>198.51.100.10</address><port>443</port>", descr="Web to partner")
SSH = _rule(R_SSH, destination="<address>203.0.113.20</address><port>22</port>", descr="SSH to jump host")
BLOCK = _rule(R_BLOCK, "block", protocol="", source="<any/>", destination="<network>203.0.113.0/24</network>")
ANY = _rule(R_ANY, protocol="", source="<any/>", descr="Temporary allow all")
TELNET = _rule(R_TELNET, destination="<address>203.0.113.30</address><port>23</port>", descr="Telnet to lab")
BLOCK_SSH = _rule(R_BLOCK_SSH, "block", source="<any/>", destination="<address>203.0.113.20</address><port>22</port>")
WIDE_WEB = _rule(R_WEB, protocol="", source="<any/>", descr="Web to partner")


def _xml(*rules: str) -> str:
    return SAMPLE_CONFIG_XML.replace("<revision>", f"<filter>{''.join(rules)}</filter>\n  <revision>")


def _config(*rules: str):
    config = parse_document(_xml(*rules))
    assert config is not None
    return config


def _found(before: tuple[str, ...], after: tuple[str, ...]) -> dict:
    return rule_change_findings(_config(*before), _config(*after))


def _kinds(findings: list[dict]) -> list[tuple[str, str]]:
    return [(f["kind"], f["key"]) for f in findings]


BASE = (WEB, SSH, BLOCK)


# ── Findings ─────────────────────────────────────────────────────────────────


def test_the_base_configuration_has_no_finding():
    assert _found(BASE, BASE) == {"new": [], "gone": [], "summary": {"any_any": 0, "shadowed": 0}}


def test_a_new_any_to_any_rule():
    found = _found(BASE, (*BASE, ANY))
    (finding,) = found["new"]
    assert finding == {
        "kind": "any_any",
        "key": R_ANY,
        "number": 4,
        "interfaces": ["lan"],
        "direction": "in",
        "family": "inet",
        "protocol": "any",
        "action": "pass",
        "source": "any",
        "source_port": "any",
        "destination": "any",
        "destination_port": "any",
        "description": "Temporary allow all",
        "shadowed_by": None,
        "shadowed_by_key": None,
        "shadow": "",
    }
    assert found["gone"] == [] and found["summary"] == {"any_any": 1, "shadowed": 0}


def test_an_existing_rule_widened_to_any_to_any_shadows_the_rules_below_it():
    found = _found(BASE, (WIDE_WEB, SSH, BLOCK))
    assert _kinds(found["new"]) == [("any_any", R_WEB), ("shadowed", R_SSH), ("shadowed", R_BLOCK)]
    ssh, block = found["new"][1:]
    assert (ssh["shadowed_by"], ssh["shadowed_by_key"], ssh["shadow"]) == (1, R_WEB, "redundant")
    assert (block["shadowed_by"], block["shadow"], block["action"]) == (1, "conflicting", "block")
    assert found["summary"] == {"any_any": 1, "shadowed": 2}


def test_an_enabled_any_to_any_rule_is_new_and_a_disabled_one_never_is():
    disabled = _rule(R_ANY, protocol="", source="<any/>", disabled=True)
    assert _kinds(_found((*BASE, disabled), (*BASE, ANY))["new"]) == [("any_any", R_ANY)]
    # Disabled rules carry neither flag, in any position.
    assert _found(BASE, (*BASE, disabled))["new"] == []
    view = {
        r["key"]: r for r in analyze(_config(_rule(R_WEB, protocol="", source="<any/>", disabled=True), SSH))["rules"]
    }
    assert view[R_WEB]["flags"] == ["disabled"] and view[R_SSH]["flags"] == []
    telnet_off = _rule(R_TELNET, destination="<address>203.0.113.30</address><port>23</port>", disabled=True)
    assert _found(BASE, (*BASE, telnet_off))["new"] == []


def test_a_new_rule_shadowed_on_arrival():
    found = _found(BASE, (*BASE, TELNET))
    (finding,) = found["new"]
    assert (finding["kind"], finding["key"], finding["number"]) == ("shadowed", R_TELNET, 4)
    assert (finding["shadowed_by"], finding["shadowed_by_key"], finding["shadow"]) == (3, R_BLOCK, "conflicting")
    assert (finding["destination"], finding["destination_port"]) == ("203.0.113.30", "23")


def test_an_existing_rule_shadowed_by_a_new_rule_above_it():
    found = _found(BASE, (WEB, BLOCK_SSH, SSH, BLOCK))
    assert _kinds(found["new"]) == [("shadowed", R_SSH)]
    assert (found["new"][0]["number"], found["new"][0]["shadowed_by"]) == (3, 2)


def test_a_moved_rule():
    found = _found(BASE, (WEB, BLOCK, SSH))
    assert _kinds(found["new"]) == [("shadowed", R_SSH)]
    assert (found["new"][0]["shadowed_by_key"], found["new"][0]["shadow"]) == (R_BLOCK, "conflicting")


def test_gone_findings_are_numbered_as_before():
    found = _found((WIDE_WEB, SSH, BLOCK), BASE)
    assert found["new"] == []
    assert _kinds(found["gone"]) == [("any_any", R_WEB), ("shadowed", R_SSH), ("shadowed", R_BLOCK)]
    # A finding that stays is neither new nor gone.
    assert _found((*BASE, ANY), (WEB, SSH, BLOCK, TELNET, ANY))["gone"] == []


def test_findings_never_hold_alias_contents():
    feed = _rule(R_TELNET, "block", protocol="", source="<address>Feed</address>", destination="<any/>")
    text = _xml(*BASE, feed, ANY).replace(
        "<filter>",
        "<OPNsense><Firewall><Alias><aliases>"
        '<alias uuid="55555555-5555-4555-8555-000000000001"><enabled>1</enabled><name>Feed</name>'
        "<type>urltable</type><content>https://user:pw@lists.example.com/drop.txt</content></alias>"
        "</aliases></Alias></Firewall></OPNsense><filter>",
    )
    config = parse_document(text)
    assert config is not None and "Feed" in config.aliases
    found = rule_change_findings(_config(*BASE), config)
    assert _kinds(found["new"]) == [("any_any", R_ANY)]
    assert "lists.example.com" not in str(found) and "pw@" not in str(found)


# ── Store path ───────────────────────────────────────────────────────────────

ORG = 9301


async def _host(monkeypatch, n: int) -> dict:
    group = await db.create_group(f"opn-rule-alerts-{n}")
    host_id = await db.add_host(group, f"fw-rules-{n}.example.com", "192.0.2.1", "opnsense")
    host = await db.get_host(host_id)
    assert host is not None

    async def the_host(_snapshot, _hosts=None):
        return host

    monkeypatch.setattr(opnsense_collection, "matching_host", the_host)
    return host


async def _store(xml: str, org_ref: int = ORG) -> tuple[dict, dict]:
    snapshot = build_snapshot(build_sample_raw())
    result = await store_config_backup({"config_xml": xml}, snapshot, org_ref=org_ref)
    assert result is not None and result["stored"]
    firewall = _firewall(snapshot)
    assert firewall is not None
    section = dict(next(s for s in firewall["sections"] if s["title"] == SECTION_CONFIG_BACKUP)["rows"])
    return result, section


async def _open(host_id: int) -> dict[str, dict]:
    return {a["dedup_key"]: a for a in await db.get_monitoring_alerts(host_id=host_id, acknowledged=False)}


async def test_new_findings_alert_once_and_resolve_when_fixed(monkeypatch):
    host = await _host(monkeypatch, 1)
    host_id = int(host["id"])

    # The first backup: nothing to compare with.
    first, section = await _store(_xml(*BASE))
    assert first["created"] and first["rule_changes"]["compared"] is False
    assert section["Rule changes"] == "Nothing to compare with yet (first backup of this host)"
    assert await _open(host_id) == {}

    # Widened to any-to-any: three findings, three alerts.
    second, section = await _store(_xml(WIDE_WEB, SSH, BLOCK))
    assert second["rule_changes"]["alerted"] == 3
    assert section["Rule changes"] == "1 new any-to-any rule, 2 newly shadowed rules; alerts raised"
    alerts = await _open(host_id)
    any_key = dedup_key(host_id, "any_any", R_WEB)
    ssh_key = dedup_key(host_id, "shadowed", R_SSH)
    block_key = dedup_key(host_id, "shadowed", R_BLOCK)
    assert any_key == f"opnsense-rule:{host_id}:any_any:{R_WEB}"
    assert set(alerts) == {any_key, ssh_key, block_key}
    assert {k: (a["severity"], a["metric"], a["alert_type"]) for k, a in alerts.items()} == {
        any_key: ("warning", "opnsense_rule_any_any", ALERT_TYPE),
        ssh_key: ("info", "opnsense_rule_shadowed", ALERT_TYPE),
        block_key: ("warning", "opnsense_rule_shadowed", ALERT_TYPE),
    }
    assert alerts[any_key]["message"] == (
        'OPNsense fw-rules-1.example.com: new any-to-any pass rule #1 "Web to partner" on lan '
        "(pass any from any to any)"
    )
    assert alerts[block_key]["message"] == (
        "OPNsense fw-rules-1.example.com: rule #3 on lan (block any from any to 203.0.113.0/24) "
        "is now shadowed by rule #1, which takes every flow it matches first and does the opposite"
    )
    assert "<" not in "".join(a["message"] for a in alerts.values())

    # The same findings in the next backup (which adds a shadowed rule): only
    # the new one alerts; the open ones are not raised or bumped again.
    third, section = await _store(_xml(WIDE_WEB, SSH, BLOCK, TELNET))
    assert third["rule_changes"]["alerted"] == 1 and third["rule_changes"]["summary"] == {"any_any": 0, "shadowed": 1}
    assert section["Rule changes"] == "1 newly shadowed rule; alerts raised"
    alerts = await _open(host_id)
    assert set(alerts) == {any_key, ssh_key, block_key, dedup_key(host_id, "shadowed", R_TELNET)}
    assert all(a["occurrence_count"] == 1 for a in alerts.values())

    # Unchanged configuration: no new backup, nothing checked, nothing raised.
    same, section = await _store(_xml(WIDE_WEB, SSH, BLOCK, TELNET))
    assert same["created"] is False and same["rule_changes"] is None and "Rule changes" not in section
    assert len(await _open(host_id)) == 4

    # Fixed: every finding is gone and its alert resolved.
    fixed, section = await _store(_xml(*BASE))
    assert fixed["rule_changes"]["resolved"] == 4
    assert section["Rule changes"] == "No new any-to-any or shadowed rules; 4 earlier alerts resolved"
    assert await _open(host_id) == {}
    resolved = await db.get_monitoring_alerts(host_id=host_id, acknowledged=True)
    assert {a["acknowledged_by"] for a in resolved} == {"auto-resolved"}

    # Brought back later: alerted again.
    again, _section = await _store(_xml(*BASE, ANY))
    assert again["rule_changes"]["alerted"] == 1
    assert set(await _open(host_id)) == {dedup_key(host_id, "any_any", R_ANY)}


async def test_a_suppression_of_the_host_keeps_them_from_being_raised(monkeypatch):
    host = await _host(monkeypatch, 2)
    host_id = int(host["id"])
    await _store(_xml(*BASE))
    await db.create_alert_suppression(
        "change window", "2099-01-01 00:00:00", host_id=host_id, metric="opnsense_rule_any_any"
    )
    result, section = await _store(_xml(WIDE_WEB, SSH, BLOCK))
    assert (result["rule_changes"]["alerted"], result["rule_changes"]["muted"]) == (2, 1)
    assert set(await _open(host_id)) == {dedup_key(host_id, "shadowed", R_SSH), dedup_key(host_id, "shadowed", R_BLOCK)}
    assert section["Rule changes"].endswith("alerts raised, 1 muted or suppressed")


async def test_a_mute_of_the_firewall_covers_them(monkeypatch):
    host = await _host(monkeypatch, 3)
    host_id = int(host["id"])
    org = ORG + 3
    snapshot = build_snapshot(build_sample_raw())
    await tracking.record_snapshot_states("opnsense", org, snapshot)
    firewall = _firewall(snapshot)
    assert firewall is not None
    await db.create_topology_mute(
        "opnsense", org, "entity", entity_type="device", entity_id=firewall["id"], reason="change", created_by="admin"
    )
    await _store(_xml(*BASE), org)
    result, _section = await _store(_xml(*BASE, ANY), org)
    assert (result["rule_changes"]["alerted"], result["rule_changes"]["muted"]) == (0, 1)
    assert await _open(host_id) == {}


async def test_a_failing_check_still_stores_the_backup(monkeypatch):
    from netcontrol.routes import opnsense_rule_alerts

    host = await _host(monkeypatch, 4)

    async def broken(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(opnsense_rule_alerts, "_previous_text", broken)
    await _store(_xml(*BASE))
    result, section = await _store(_xml(*BASE, ANY))
    assert result["created"] and result["rule_changes"] is None
    assert section["Rule changes"] == "Not checked: see the server log"
    assert await _open(int(host["id"])) == {}


async def test_a_changed_secret_is_a_new_backup_but_no_rule_change(monkeypatch):
    """Backups are stored masked: the check compares the masked previous
    backup with the new file masked too, so neither a secret nor the
    masking makes a rule look changed."""
    host = await _host(monkeypatch, 5)
    secret_line = "<password>$2y$11$sample.hash.not.a.real.one.sample.hash.value000000</password>"
    assert secret_line in SAMPLE_CONFIG_XML
    await _store(_xml(*BASE, ANY))
    changed = _xml(*BASE, ANY).replace(
        secret_line, "<password>$2y$11$invented.changed.hash.for.tests.only.0000</password>"
    )
    result, section = await _store(changed)
    assert result["created"] and result["rule_changes"]["compared"] is True
    assert result["rule_changes"]["summary"] == {"any_any": 0, "shadowed": 0}
    assert section["Rule changes"] == "No new any-to-any or shadowed rules"
    stored = await db.get_config_backup(result["backup_id"])
    assert stored is not None and "invented.changed.hash" not in stored["config_text"]
    assert await _open(int(host["id"])) == {}


# ── API ──────────────────────────────────────────────────────────────────────


def test_the_diff_route_returns_the_findings_of_the_pair(api):  # noqa: F811 - the imported fixture
    import asyncio

    async def seed() -> tuple[int, int, int]:
        group = await db.create_group("opn-rule-alerts-api")
        host_id = await db.add_host(group, "fw-rules-api.example.com", "192.0.2.1", device_type="opnsense")
        first = await db.create_config_backup(None, host_id, _xml(*BASE), capture_method="opnsense-api")
        second = await db.create_config_backup(None, host_id, _xml(*BASE, ANY), capture_method="opnsense-api")
        return host_id, first, second

    host_id, first, second = asyncio.run(seed())
    found = api.get(f"/api/opnsense/hosts/{host_id}/rules/diff", params={"from_backup": first, "to_backup": second})
    assert found.status_code == 200, found.text
    findings = found.json()["findings"]
    assert [(f["kind"], f["key"]) for f in findings["new"]] == [("any_any", R_ANY)]
    assert findings["gone"] == [] and findings["summary"] == {"any_any": 1, "shadowed": 0}
