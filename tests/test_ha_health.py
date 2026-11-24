"""HA and redundancy state in the monitoring poll (netcontrol/ha_health.py
on netcontrol/snmp_health.py), and the device restart told from the polled
uptime (netcontrol/device_restart.py).

Invented rows shaped as each MIB defines them, in the documentation
address ranges; the wiring tests run the poll and the alert evaluation
against the test database. No device, SDK or network.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import routes.database as db
from netcontrol import (
    device_restart as dr,
    ha_health as ha,
    health_checks as hc,
    module_health as mh,
    monitoring_repoll,
    snmp_health as sh,
)

from snmp_health_fakes import SYS_UPTIME, Agent, add_host, evaluate, open_alerts, poll, res

DAY = 86400.0


def _classes(status: dict) -> dict[str, str]:
    return {i["index"]: i["class"] for i in status["items"]}


async def _read(source, agent: Agent, host_id: int = 1, check=ha.PEER) -> dict:
    return sh.select(check, await source.read(agent.get, agent.walk, host_id))


# ── Cisco ASA / FTD failover ─────────────────────────────────────────────────

CFW = ha.CFW_HW_STATUS_VALUE
CFW_DETAIL = ha.CFW_HW_STATUS_DETAIL
CFW_INFO = ha.CFW_HW_INFORMATION


async def test_a_healthy_failover_pair_and_its_link():
    agent = Agent({f"{CFW}.4": 2, f"{CFW}.6": 9, f"{CFW}.7": 10, f"{CFW}.1": 3})
    table = await ha.CISCO_FAILOVER.read(agent.get, agent.walk, 1)
    peers, link = sh.select(ha.PEER, table), sh.select(ha.LINK, table)
    # memory(1) is not a failover row: not an item, and no GET for it.
    assert _classes(peers) == {"1.6": sh.OK, "1.7": sh.OK}
    assert _classes(link) == {"1.4": sh.OK}
    assert [i["name"] for i in peers["items"]] == ["Primary unit", "Secondary unit"]
    assert agent.gets == []


async def test_a_failed_standby_unit_and_a_down_failover_link_alert():
    agent = Agent(
        {f"{CFW}.4": 3, f"{CFW}.6": 9, f"{CFW}.7": 4},
        {
            f"{CFW_INFO}.7": "Secondary unit",
            f"{CFW_DETAIL}.7": "Failed",
            f"{CFW_INFO}.4": "LAN Failover Interface",
            f"{CFW_DETAIL}.4": "FOLINK GigabitEthernet0/3",
        },
    )
    table = await ha.CISCO_FAILOVER.read(agent.get, agent.walk, 5)
    peers, link = sh.select(ha.PEER, table), sh.select(ha.LINK, table)
    assert [c["message"] for c in sh.alert_checks(ha.PEER, 5, peers)] == ["Secondary unit (Failed) is in error"]
    assert [c["dedup_key"] for c in sh.alert_checks(ha.PEER, 5, peers)] == ["5:ha_peer_down:1.7"]
    checks = sh.alert_checks(ha.LINK, 5, link)
    assert [(c["metric"], c["severity"]) for c in checks] == [("ha_link_down", "warning")]


async def test_an_asa_without_failover_raises_nothing_and_resolves():
    """An ASA reads its unit rows down with the detail "Failover Off" and the
    LAN interface "not Configured" when failover is off: not a fault."""
    agent = Agent(
        {f"{CFW}.4": 3, f"{CFW}.6": 3, f"{CFW}.7": 3},
        {f"{CFW_DETAIL}.4": "not Configured", f"{CFW_DETAIL}.6": "Failover Off", f"{CFW_DETAIL}.7": "Failover Off"},
    )
    table = await ha.CISCO_FAILOVER.read(agent.get, agent.walk, 6)
    peers, link = sh.select(ha.PEER, table), sh.select(ha.LINK, table)
    assert set(_classes(peers).values()) == {sh.ADMIN_DOWN} and set(_classes(link).values()) == {sh.ADMIN_DOWN}
    assert sh.alert_checks(ha.PEER, 6, peers) == [] and peers["down_count"] == 0
    assert sh.cleared_keys(ha.PEER, 6, peers, ["6:ha_peer_down:1.7"]) == ["6:ha_peer_down:1.7"]


async def test_a_failover_swaps_the_roles():
    agent = Agent({f"{CFW}.6": 9, f"{CFW}.7": 10})
    assert "role_changes" not in await ha.CISCO_FAILOVER.read(agent.get, agent.walk, 7)
    agent.rows = {f"{CFW}.6": 10, f"{CFW}.7": 9}
    table = await ha.CISCO_FAILOVER.read(agent.get, agent.walk, 7)
    assert table["role_changes"] == [
        {"name": "Primary unit", "from": "active", "to": "standby"},
        {"name": "Secondary unit", "from": "standby", "to": "active"},
    ]
    check = ha.role_change_check(7, table["role_changes"])
    assert check["message"] == "HA role changed: Primary unit active -> standby; Secondary unit standby -> active"
    assert (check["metric"], check["alert_type"], check["dedup_key"]) == (
        "ha_role_change",
        "event",
        "7:ha_role_change:event",
    )
    assert ha.role_change_check(7, []) is None


def test_the_role_change_message_names_five():
    changes = [{"name": f"VRRP group {n}", "from": "backup", "to": "master"} for n in range(7)]
    assert ha.role_changes_message(changes).endswith("VRRP group 4 backup -> master; 2 more")


# ── Cisco CISCO-RF-MIB redundancy peer ───────────────────────────────────────

RF = ha.RF_PEER_UNIT_STATE


def _rf(state: int, host_id: int = 1, now: float = 0.0) -> dict:
    table = sh.parse_table(ha.CISCO_RF_PEER, {f"{RF}.0": state}, {})
    return sh.select(ha.PEER, ha.settle(ha.CISCO_RF_PEER.key, ha.CISCO_RF_PEER.rules, host_id, table, now))


def test_a_chassis_that_never_had_a_standby_does_not_alert():
    assert _rf(2)["items"] == []
    assert _rf(2)["down_count"] == 0


def test_a_standby_seen_up_that_is_disabled_alerts_until_forgotten():
    assert _classes(_rf(9, host_id=2)) == {"2.0": sh.OK}
    down = _rf(2, host_id=2, now=60.0)
    assert [c["message"] for c in sh.alert_checks(ha.PEER, 2, down)] == [
        "Redundancy peer (standby supervisor or switch) is disabled (not present or not running)"
    ]
    assert _classes(_rf(8, host_id=2, now=120.0)) == {"2.0": sh.TRANSITIONAL}  # bulk sync: passing
    # A week after it was last seen working: forgotten, its alert resolves.
    later = _rf(2, host_id=2, now=ha.HA_MEMORY_SECONDS + 1.0)
    assert later["items"] == []
    assert sh.cleared_keys(ha.PEER, 2, later, ["2:ha_peer_down:2.0"]) == ["2:ha_peer_down:2.0"]


def test_every_rf_state_is_classified():
    assert set(ha.RF_STATES) == set(range(1, 18))


# ── Cisco stacks: CISCO-STACKWISE-MIB ────────────────────────────────────────

CSW_STATE = ha.CSW_SWITCH_STATE


async def test_stack_members_mismatch_removed_and_gone():
    agent = Agent({f"{CSW_STATE}.1000": 4, f"{CSW_STATE}.2000": 4, f"{CSW_STATE}.3000": 11})
    first = await _read(ha.CISCO_STACK_MEMBERS, agent, host_id=3)
    # Member 3000 was never seen ready (pre-provisioned): not an item.
    assert _classes(first) == {"3.1000": sh.OK, "3.2000": sh.OK}
    agent.rows = {f"{CSW_STATE}.1000": 4, f"{CSW_STATE}.2000": 6}
    agent.answers = {f"{mh.ENT_PHYSICAL_NAME}.2000": "Switch 2"}
    second = await _read(ha.CISCO_STACK_MEMBERS, agent, host_id=3)
    assert [c["message"] for c in sh.alert_checks(ha.PEER, 3, second)] == ["Switch 2 is software version mismatch"]
    # Member 2000 is pulled: gone from a table read completely.
    agent.rows = {f"{CSW_STATE}.1000": 4}
    third = await _read(ha.CISCO_STACK_MEMBERS, agent, host_id=3)
    gone = next(i for i in third["items"] if i["index"] == "3.2000")
    assert (gone["class"], gone["status"], gone["name"]) == (sh.DOWN, ha.GONE_STATUS, "Stack member (entity 2000)")
    assert set(ha.CSW_SWITCH_STATES) == set(range(1, 12))


async def test_stack_ring_and_ports():
    ring = ha.CSW_RING_REDUNDANT
    agent = Agent({f"{ring}.0": 2})
    # A single switch: never a redundant ring, never alerted.
    assert (await _read(ha.CISCO_STACK_RING, agent, check=ha.LINK))["items"] == []
    agent.rows = {f"{ring}.0": 1}
    await _read(ha.CISCO_STACK_RING, agent, check=ha.LINK)
    agent.rows = {f"{ring}.0": 2}
    broken = await _read(ha.CISCO_STACK_RING, agent, check=ha.LINK)
    assert [c["message"] for c in sh.alert_checks(ha.LINK, 1, broken)] == ["Stack ring is no longer a redundant ring"]

    port = ha.CSW_STACK_PORT_OPER
    agent = Agent({f"{port}.51": 1, f"{port}.52": 2, f"{port}.53": 3}, {f"{ha.IF_NAME}.53": "StackPort1/2"})
    ports = await _read(ha.CISCO_STACK_PORTS, agent, check=ha.LINK)
    assert _classes(ports) == {"4.51": sh.OK, "4.52": sh.ADMIN_DOWN, "4.53": sh.DOWN}
    assert [c["message"] for c in sh.alert_checks(ha.LINK, 1, ports)] == [
        "Stack port StackPort1/2 is shut down by the stack manager"
    ]


# ── Juniper ──────────────────────────────────────────────────────────────────


async def test_juniper_routing_engine_redundancy():
    state = ha.JNX_REDUNDANCY_STATE
    agent = Agent({f"{state}.9.1.0.0": 2, f"{state}.9.2.0.0": 3})
    assert set(_classes(await _read(ha.JUNIPER_REDUNDANCY, agent, host_id=4)).values()) == {sh.OK}
    # The routing engines switched over: a role change, not a fault.
    agent.rows = {f"{state}.9.1.0.0": 3, f"{state}.9.2.0.0": 2}
    table = await ha.JUNIPER_REDUNDANCY.read(agent.get, agent.walk, 4)
    assert [(c["from"], c["to"]) for c in table["role_changes"]] == [("master", "backup"), ("backup", "master")]
    # The backup is disabled, then pulled.
    agent.rows = {f"{state}.9.1.0.0": 4, f"{state}.9.2.0.0": 2}
    agent.answers = {f"{ha.JNX_REDUNDANCY_DESCR}.9.1.0.0": "Routing Engine 0"}
    disabled = await _read(ha.JUNIPER_REDUNDANCY, agent, host_id=4)
    assert [c["message"] for c in sh.alert_checks(ha.PEER, 4, disabled)] == ["Routing Engine 0 is disabled"]
    agent.rows = {f"{state}.9.2.0.0": 2}
    gone = await _read(ha.JUNIPER_REDUNDANCY, agent, host_id=4)
    assert _classes(gone) == {"6.9.2.0.0": sh.OK, "6.9.1.0.0": sh.DOWN}
    # A single routing engine that reads disabled was never seen working.
    agent = Agent({f"{state}.9.1.0.0": 4})
    assert (await _read(ha.JUNIPER_REDUNDANCY, agent, host_id=40))["items"] == []


def test_virtual_chassis_port_names():
    port = "vcp-255/1/0"
    index = f"1.{len(port)}." + ".".join(str(ord(c)) for c in port)
    assert ha.vc_port_name(index) == "Virtual Chassis member 1 port vcp-255/1/0"
    assert ha.vc_port_name("1.3.65") == "Virtual Chassis port 1.3.65"
    assert ha.vc_port_name("1") == "Virtual Chassis port 1"


async def test_virtual_chassis_ports():
    oper, admin = ha.JNX_VC_PORT_OPER, ha.JNX_VC_PORT_ADMIN
    agent = Agent({f"{oper}.0.1.65": 2, f"{oper}.1.1.65": 1})
    # A port never seen up (a standalone switch) is not an item.
    assert _classes(await _read(ha.JUNIPER_VC_PORTS, agent, check=ha.LINK)) == {"7.1.1.65": sh.OK}
    agent.rows = {f"{oper}.0.1.65": 2, f"{oper}.1.1.65": 2}
    down = await _read(ha.JUNIPER_VC_PORTS, agent, check=ha.LINK)
    assert [c["message"] for c in sh.alert_checks(ha.LINK, 1, down)] == ["Virtual Chassis member 1 port A is down"]
    # Shut by an operator: not a fault.
    agent.answers = {f"{admin}.1.1.65": 2}
    assert _classes(await _read(ha.JUNIPER_VC_PORTS, agent, check=ha.LINK)) == {"7.1.1.65": sh.ADMIN_DOWN}


# ── VRRP and HSRP ────────────────────────────────────────────────────────────

V3 = ha.VRRPV3_STATUS


async def test_a_vrrp_group_initializing_alerts_at_the_second_poll_when_its_interface_is_up():
    agent = Agent({f"{V3}.5.10.1": 1, f"{V3}.6.20.1": 3}, {f"{ha.IF_NAME}.5": "Vlan10", f"{ha.IF_ADMIN_STATUS}.5": 1})
    first = await _read(ha.VRRPV3_GROUPS, agent, check=ha.FHRP)
    assert _classes(first) == {"8.5.10.1": sh.TRANSITIONAL, "8.6.20.1": sh.OK}
    second = await _read(ha.VRRPV3_GROUPS, agent, check=ha.FHRP)
    assert [c["message"] for c in sh.alert_checks(ha.FHRP, 1, second)] == ["VRRP group 10 on Vlan10 is initializing"]
    # The interface is shut by an operator: resolved.
    agent.answers[f"{ha.IF_ADMIN_STATUS}.5"] = 2
    shut = await _read(ha.VRRPV3_GROUPS, agent, check=ha.FHRP)
    assert _classes(shut)["8.5.10.1"] == sh.ADMIN_DOWN
    assert shut["items"][0]["status"] == "initializing, interface admin down"


async def test_vrrp_rows_out_of_service_and_vrrp_v2():
    agent = Agent({f"{V3}.5.10.1": 1}, {f"{ha.VRRPV3_ROW_STATUS}.5.10.1": 2, f"{ha.IF_ADMIN_STATUS}.5": 1})
    for _ in range(2):
        status = await _read(ha.VRRPV3_GROUPS, agent, check=ha.FHRP)
    assert _classes(status) == {"8.5.10.1": sh.ADMIN_DOWN}
    v2 = ha.VRRP_OPER_STATE
    agent = Agent({f"{v2}.7.30": 1}, {f"{ha.VRRP_OPER_ADMIN_STATE}.7.30": 2})
    for _ in range(2):
        status = await _read(ha.VRRP_GROUPS, agent, check=ha.FHRP)
    assert _classes(status) == {"9.7.30": sh.ADMIN_DOWN}


async def test_backup_is_a_role_and_a_master_change_is_reported():
    agent = Agent({f"{V3}.5.10.1": 2})
    assert _classes(await _read(ha.VRRPV3_GROUPS, agent, check=ha.FHRP)) == {"8.5.10.1": sh.OK}
    agent.rows = {f"{V3}.5.10.1": 3}
    table = await ha.VRRPV3_GROUPS.read(agent.get, agent.walk, 1)
    assert table["role_changes"] == [{"name": "VRRP group 10", "from": "backup", "to": "master"}]
    # Through a fault and back is no role change.
    agent.rows = {f"{V3}.5.10.1": 1}
    await ha.VRRPV3_GROUPS.read(agent.get, agent.walk, 1)
    agent.rows = {f"{V3}.5.10.1": 2}
    assert "role_changes" not in await ha.VRRPV3_GROUPS.read(agent.get, agent.walk, 1)


async def test_hsrp_states():
    state = ha.HSRP_STANDBY_STATE
    agent = Agent({f"{state}.5.1": 6, f"{state}.6.2": 3, f"{state}.7.3": 2, f"{state}.8.4": 1})
    await _read(ha.HSRP_GROUPS, agent, check=ha.FHRP)
    status = await _read(ha.HSRP_GROUPS, agent, check=ha.FHRP)
    assert _classes(status) == {
        "10.5.1": sh.OK,
        "10.6.2": sh.OK,
        "10.7.3": sh.TRANSITIONAL,
        "10.8.4": sh.DOWN,
    }
    assert [i["name"] for i in status["items"]][:2] == ["HSRP group 1", "HSRP group 2"]
    assert set(ha.HSRP_STATES) == set(range(1, 7))


# ── Fortinet FortiGate HA ────────────────────────────────────────────────────

FG_SYNC = ha.FG_HA_STATS_SYNC_STATUS
FG_MODE = ha.FG_HA_SYSTEM_MODE


async def _fortigate(agent: Agent, host_id: int = 1, now: float = 0.0) -> dict:
    return sh.select(ha.PEER, await ha.FORTIGATE_HA.read(agent.get, agent.walk, host_id, now))


async def test_a_standalone_fortigate_never_alerts():
    agent = Agent({f"{FG_SYNC}.1": 0}, {FG_MODE: 1})
    status = await _fortigate(agent)
    assert status["items"] == [] and status["down_count"] == 0


async def test_a_member_out_of_sync_alerts_at_the_second_poll():
    agent = Agent({f"{FG_SYNC}.1": 1, f"{FG_SYNC}.2": 0}, {FG_MODE: 3, f"{ha.FG_HA_STATS_HOSTNAME}.2": "fw-b"})
    first = await _fortigate(agent, host_id=2)
    assert _classes(first) == {"13.1": sh.OK, "13.2": sh.TRANSITIONAL}
    second = await _fortigate(agent, host_id=2, now=60.0)
    assert [c["message"] for c in sh.alert_checks(ha.PEER, 2, second)] == ["fw-b is out of sync"]
    # Only the member out of sync is named (one GET with the mode).
    assert agent.gets[-1] == (FG_MODE, f"{ha.FG_HA_STATS_HOSTNAME}.2")


async def test_a_cluster_that_lost_a_member():
    agent = Agent({f"{FG_SYNC}.1": 1, f"{FG_SYNC}.2": 1}, {FG_MODE: 3})
    await _fortigate(agent, host_id=3)
    agent.rows = {f"{FG_SYNC}.1": 1}
    assert _classes(await _fortigate(agent, host_id=3, now=60.0))["13.0"] == sh.TRANSITIONAL
    status = await _fortigate(agent, host_id=3, now=120.0)
    assert [c["message"] for c in sh.alert_checks(ha.PEER, 3, status)] == ["HA cluster is 1 of 2 members"]
    # A week on, the smaller cluster is the cluster.
    assert "13.0" not in _classes(await _fortigate(agent, host_id=3, now=ha.HA_MEMORY_SECONDS + 1.0))
    # The member is back: one cluster of 2 again.
    agent.rows = {f"{FG_SYNC}.1": 1, f"{FG_SYNC}.2": 1}
    assert "13.0" not in _classes(await _fortigate(agent, host_id=3, now=ha.HA_MEMORY_SECONDS + 60.0))


async def test_fortigate_not_read_and_empty():
    assert await ha.FORTIGATE_HA.read(*_agent_fns(Agent({f"{FG_SYNC}.1": 1})), 1) is None  # mode not answered
    assert await ha.FORTIGATE_HA.read(*_agent_fns(Agent({f"{FG_SYNC}.1": 1}, silent_gets=True)), 1) is None
    assert await ha.FORTIGATE_HA.read(*_agent_fns(Agent({}, cut={FG_SYNC})), 1) is None
    assert sh.is_empty(await ha.FORTIGATE_HA.read(*_agent_fns(Agent({})), 1))


def _agent_fns(agent: Agent):
    return agent.get, agent.walk


# ── Palo Alto PAN-OS HA ──────────────────────────────────────────────────────

PAN_MODE = ha.PAN_SYS_HA_MODE


async def test_pan_os_ha_disabled_never_alerts_and_costs_one_walk():
    agent = Agent({f"{PAN_MODE}.0": "disabled"})
    assert (await _read(ha.PANOS_HA, agent))["items"] == []
    assert agent.gets == []


async def test_pan_os_peer_and_local_states():
    agent = Agent(
        {f"{PAN_MODE}.0": "active-passive"},
        {ha.PAN_SYS_HA_STATE: "active", ha.PAN_SYS_HA_PEER_STATE: "non-functional"},
    )
    status = await _read(ha.PANOS_HA, agent, host_id=8)
    assert [c["message"] for c in sh.alert_checks(ha.PEER, 8, status)] == ["HA peer is non-functional"]
    agent.answers = {ha.PAN_SYS_HA_STATE: "Suspended", ha.PAN_SYS_HA_PEER_STATE: "active"}
    status = await _read(ha.PANOS_HA, agent, host_id=8)
    assert _classes(status) == {"14.1": sh.DOWN, "14.2": sh.OK}
    # A peer not heard: down at the second poll; an unknown word passes.
    agent.answers = {ha.PAN_SYS_HA_STATE: "active", ha.PAN_SYS_HA_PEER_STATE: "unknown"}
    assert _classes(await _read(ha.PANOS_HA, agent, host_id=8))["14.2"] == sh.TRANSITIONAL
    assert _classes(await _read(ha.PANOS_HA, agent, host_id=8))["14.2"] == sh.DOWN
    agent.answers = {ha.PAN_SYS_HA_STATE: "something-new", ha.PAN_SYS_HA_PEER_STATE: "passive"}
    assert _classes(await _read(ha.PANOS_HA, agent, host_id=8)) == {"14.1": sh.TRANSITIONAL, "14.2": sh.OK}


async def test_pan_os_failover_is_a_role_change():
    agent = Agent(
        {f"{PAN_MODE}.0": "active-passive"}, {ha.PAN_SYS_HA_STATE: "active", ha.PAN_SYS_HA_PEER_STATE: "passive"}
    )
    await ha.PANOS_HA.read(agent.get, agent.walk, 9)
    agent.answers = {ha.PAN_SYS_HA_STATE: "passive", ha.PAN_SYS_HA_PEER_STATE: "active"}
    table = await ha.PANOS_HA.read(agent.get, agent.walk, 9)
    assert [(c["name"], c["to"]) for c in table["role_changes"]] == [
        ("This firewall's HA state", "passive"),
        ("HA peer", "active"),
    ]


async def test_pan_os_not_read_and_empty():
    assert sh.is_empty(await ha.PANOS_HA.read(*_agent_fns(Agent({})), 1))
    assert await ha.PANOS_HA.read(*_agent_fns(Agent({}, cut={PAN_MODE})), 1) is None
    agent = Agent({f"{PAN_MODE}.0": "active-active"}, silent_gets=True)
    assert await ha.PANOS_HA.read(agent.get, agent.walk, 1) is None


# ── HPE Aruba AOS-CX VSX and VSF ─────────────────────────────────────────────


async def test_vsx_not_configured_and_links():
    role = ha.VSX_DEVICE_ROLE
    agent = Agent({f"{role}.0": 3})
    assert (await _read(ha.ARUBA_VSX, agent, check=ha.LINK))["items"] == [] and agent.gets == []
    agent = Agent({f"{role}.0": 1}, {ha.VSX_ISL_OPER_STATE: 2, ha.VSX_KEEPALIVE_OPER_STATE: 6})
    first = await _read(ha.ARUBA_VSX, agent, check=ha.LINK)
    assert set(_classes(first).values()) == {sh.TRANSITIONAL}
    second = await _read(ha.ARUBA_VSX, agent, check=ha.LINK)
    assert [c["message"] for c in sh.alert_checks(ha.LINK, 1, second)] == [
        "VSX ISL is out of sync",
        "VSX keepalive is failed",
    ]
    agent.answers = {ha.VSX_ISL_OPER_STATE: 3}
    assert _classes(await _read(ha.ARUBA_VSX, agent, check=ha.LINK)) == {"12.1": sh.OK}
    assert sh.is_empty(await ha.ARUBA_VSX.read(*_agent_fns(Agent({})), 1))
    assert await ha.ARUBA_VSX.read(*_agent_fns(Agent({}, cut={role})), 1) is None
    assert await ha.ARUBA_VSX.read(*_agent_fns(Agent({f"{role}.0": 1}, silent_gets=True)), 1) is None


async def test_vsf_members():
    status_oid = ha.VSF_MEMBER_STATUS
    agent = Agent({f"{status_oid}.1": "ready", f"{status_oid}.2": "ready", f"{status_oid}.3": "not_present"})
    assert _classes(await _read(ha.ARUBA_VSF_MEMBERS, agent, host_id=11)) == {"11.1": sh.OK, "11.2": sh.OK}
    agent.rows = {f"{status_oid}.1": "ready", f"{status_oid}.2": "communication_failure", f"{status_oid}.4": "x"}
    status = await _read(ha.ARUBA_VSF_MEMBERS, agent, host_id=11)
    assert _classes(status) == {"11.1": sh.OK, "11.2": sh.DOWN, "11.4": sh.TRANSITIONAL}
    assert [c["message"] for c in sh.alert_checks(ha.PEER, 11, status)] == [
        "VSF member 2 is not communicating with the conductor"
    ]


# ── Several tables of one check, plans and the poll ──────────────────────────


def test_merging_the_tables_of_one_check():
    a = sh.select(
        ha.PEER,
        {
            "source": "a",
            "vendor": "Cisco",
            "items": [{"index": "2.0", "kind": ha.KIND_PEER, "name": "x", "class": sh.DOWN, "state": 2}],
        },
    )
    b = sh.select(ha.PEER, {"source": "b", "vendor": "Cisco", "items": []})
    empty = sh.select(ha.PEER, sh.empty_table("c", "Cisco"))
    merged = sh.merge(ha.PEER, [a, b, empty])
    assert merged["down_count"] == 1 and merged["source"] == "a, b" and merged["vendor"] == "Cisco"
    assert sh.merge(ha.PEER, [a, {}]) == {}
    assert sh.merge(ha.PEER, [empty, empty]) == empty
    assert sh.merge(ha.PEER, [a]) is a


@pytest.mark.parametrize(
    ("device_type", "keys"),
    [
        ("cisco_xe", {"ha_peer_health", "ha_link_health", "fhrp_health"}),
        ("cisco_asa", {"ha_peer_health", "ha_link_health"}),
        ("juniper_junos", {"ha_peer_health", "ha_link_health", "fhrp_health"}),
        ("paloalto_panos", {"ha_peer_health"}),
        ("fortinet", {"ha_peer_health", "fhrp_health"}),
        ("aruba_aoscx", {"ha_peer_health", "ha_link_health", "fhrp_health"}),
        ("arista_eos", {"fhrp_health"}),
        ("linux_host", {"fhrp_health"}),
    ],
)
def test_the_ha_checks_of_each_device_type(device_type, keys):
    ha_keys = {c.result_key for c in ha.CHECKS}
    plan = hc.plan_for_device(device_type)
    assert {c.result_key for c in ha.CHECKS for chain in plan if c.kind in chain.kinds} & ha_keys == keys


async def test_a_catalyst_merges_its_redundancy_peer_and_stack_members():
    agent = Agent(
        {f"{RF}.0": 9, f"{CSW_STATE}.1000": 4, f"{CSW_STATE}.2000": 5}, {f"{mh.ENT_PHYSICAL_NAME}.2000": "Switch 2"}
    )
    out = await hc.read_health(21, "cisco_xe", agent.get, agent.walk_table)
    assert _classes(out["ha_peer_health"]) == {"2.0": sh.OK, "3.1000": sh.OK, "3.2000": sh.DOWN}
    # The stack ring and ports answered nothing yet: link not read.
    assert out["ha_link_health"] == {}


async def test_one_stack_member_down_is_one_alert(monkeypatch):
    """The module check reads cefcModuleTable (entities of class module); a
    stack member is a chassis entity in cswSwitchInfoTable. A member in a
    version mismatch raises ha_peer_down alone. The switch answers no
    CISCO-RF-MIB: until that table is confirmed empty (third poll) the
    merged check is not read, so it raises nothing before."""
    group_id, host_id = await add_host("cisco_xe")
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    rows = {
        f"{SYS_UPTIME}.0": 4200,
        f"{mh.CEFC_MODULE_OPER_STATUS}.1001": 2,
        f"{mh.CEFC_MODULE_OPER_STATUS}.2001": 2,
        f"{CSW_STATE}.1000": 4,
        f"{CSW_STATE}.2000": 6,
    }
    agent = Agent(rows, {f"{mh.ENT_PHYSICAL_NAME}.2000": "Switch 2"})
    for _ in range(2):
        result = await poll(monkeypatch, host, agent)
        assert result["ha_peer_health"] == {}
        assert await evaluate(host_id, group_id, result) == 0
    result = await poll(monkeypatch, host, agent)
    assert await evaluate(host_id, group_id, result) == 1
    assert list(await open_alerts(host_id)) == [f"{host_id}:ha_peer_down:3.2000"]
    agent.rows[f"{CSW_STATE}.2000"] = 4
    await evaluate(host_id, group_id, await poll(monkeypatch, host, agent))
    assert await open_alerts(host_id) == {}


async def test_the_poll_raises_an_asa_failover_fault_and_a_role_change(monkeypatch):
    group_id, host_id = await add_host("cisco_asa")
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    agent = Agent({f"{SYS_UPTIME}.0": 4200, f"{CFW}.4": 2, f"{CFW}.6": 9, f"{CFW}.7": 10})
    await evaluate(host_id, group_id, await poll(monkeypatch, host, agent))
    assert await open_alerts(host_id) == {}
    agent.rows.update({f"{CFW}.6": 3, f"{CFW}.7": 9})
    agent.answers = {f"{CFW_INFO}.6": "Primary unit", f"{CFW_DETAIL}.6": "Failed"}
    result = await poll(monkeypatch, host, agent)
    assert result[ha.ROLE_CHANGES_KEY] == [{"name": "Secondary unit", "from": "standby", "to": "active"}]
    await evaluate(host_id, group_id, result)
    alerts = await open_alerts(host_id)
    assert set(alerts) == {f"{host_id}:ha_peer_down:1.6", f"{host_id}:ha_role_change:event"}
    assert alerts[f"{host_id}:ha_role_change:event"]["alert_type"] == "event"
    # A suppression on the role change metric silences it.
    changed = res(host_id, **{ha.ROLE_CHANGES_KEY: [{"name": "x", "from": "a", "to": "b"}]})
    muted = [{"metric": "ha_role_change", "host_id": host_id, "group_id": None}]
    assert await evaluate(host_id, group_id, changed, suppressions=muted) == 0


async def test_metric_samples_of_the_ha_checks():
    status = {"items": [], "down_count": 1}
    assert hc.metric_sample_rows({"host_id": 3, "ha_peer_health": status, "fhrp_health": {}}) == [
        (3, "ha_peer_down", "{}", 1.0)
    ]
    assert {"ha_peer_down", "ha_link_down", "fhrp_group_down"} <= set(hc.METRICS)


# ── Device restart from the uptime ───────────────────────────────────────────


@pytest.mark.parametrize(
    ("previous", "uptime", "elapsed", "expected"),
    [
        (86400, 120, 300.0, True),  # rebooted between two polls
        (86400, 86400 + 300, 300.0, False),  # running
        (86400, 86400 - 30, 60.0, False),  # within the clock slack
        (3600, 7200, 3 * 86400.0, True),  # came up during three days of failed polls
        (3600, 3 * 86400, 3 * 86400.0 - 3600, False),  # those days, no reboot
        (int(dr.WRAP_SECONDS) - 100, 200, 300.0, False),  # TimeTicks wrap
        (int(dr.WRAP_SECONDS) - 100, 5000, 300.0, True),  # near the wrap, but a reboot
        (int(dr.WRAP_SECONDS) - 3600, 600, None, False),  # wrap, no elapsed time known
        (86400, 600, None, True),  # went back, no elapsed time known
        (None, 600, 60.0, False),  # first poll
        (86400, None, 60.0, False),  # no uptime read
        (86400, -1, 60.0, False),
    ],
)
def test_the_restart_rule(previous, uptime, elapsed, expected):
    assert dr.restarted(previous, uptime, elapsed) is expected


def test_detect_and_the_alert():
    now = datetime(2026, 1, 2, 12, 0, tzinfo=UTC)
    before = now - timedelta(minutes=5)
    restart = dr.detect({"uptime_seconds": 864000}, 180, now, before)
    assert restart == {"uptime_seconds": 180, "previous_uptime_seconds": 864000, "restarted_at": "2026-01-02 11:57 UTC"}
    check = dr.alert_check(4, restart)
    assert check["message"] == (
        "Device or SNMP agent restarted about 2026-01-02 11:57 UTC (uptime 3 min, was 14400 min at the previous poll)"
    )
    assert (check["metric"], check["severity"], check["dedup_key"]) == (
        "device_restarted",
        "warning",
        "4:device_restarted:event",
    )
    assert dr.detect(None, 180, now, before) is None
    assert dr.detect({"uptime_seconds": None}, 180, now, before) is None
    assert dr.detect({"uptime_seconds": "x"}, 180, now, before) is None
    assert dr.detect({"uptime_seconds": 864000}, 864300, now, before) is None
    assert dr.alert_check(4, None) is None


def _poll_result(host_id: int, uptime: int | None) -> dict:
    return {
        **res(host_id),
        "memory_used_mb": None,
        "memory_total_mb": None,
        "uptime_seconds": uptime,
        "if_up_count": 1,
        "if_admin_down": 0,
        "vpn_tunnels_up": 0,
        "route_count": 0,
        "route_snapshot": "",
        "poll_status": "ok",
        "poll_error": "",
    }


async def test_a_restart_raises_one_alert_and_marks_the_hardware_stale(monkeypatch):
    from netcontrol.routes import monitoring

    group_id, host_id = await add_host("cisco_xe")
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    # First poll: nothing to compare with.
    assert await monitoring._process_poll_result(host, _poll_result(host_id, 864000), []) == 0
    # A failed poll with no uptime between does not hide the reading before it.
    await monitoring._process_poll_result(host, _poll_result(host_id, None), [])
    assert await monitoring._process_poll_result(host, _poll_result(host_id, 240), []) == 1
    alerts = await open_alerts(host_id)
    assert list(alerts) == [f"{host_id}:device_restarted:event"]
    assert alerts[f"{host_id}:device_restarted:event"]["message"].startswith("Device or SNMP agent restarted about ")
    assert monitoring_repoll.hardware_stale(host_id)
    # The next poll sees the uptime grow: no new alert, the open one stays.
    await monitoring._process_poll_result(host, _poll_result(host_id, 300), [])
    assert (await open_alerts(host_id))[f"{host_id}:device_restarted:event"]["occurrence_count"] == 1
    # Resolved an hour after the last restart seen (here: told it is old).
    assert await monitoring._resolve_expired_poll_events() == 0
    monkeypatch.setattr(dr, "RESOLVE_MINUTES", 0)
    assert await monitoring._resolve_expired_poll_events() == 1
    assert await open_alerts(host_id) == {}


async def test_a_suppressed_restart_raises_nothing():
    from netcontrol.routes import monitoring

    group_id, host_id = await add_host("cisco_xe")
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    await monitoring._process_poll_result(host, _poll_result(host_id, 864000), [])
    suppressions = [{"metric": "device_restarted", "host_id": host_id, "group_id": None}]
    await monitoring._process_poll_result(host, _poll_result(host_id, 60), [], suppressions=suppressions)
    assert await open_alerts(host_id) == {}
