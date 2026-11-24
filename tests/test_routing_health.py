"""BGP peer, OSPF, EIGRP and IS-IS neighbor and IP SLA state in the monitoring poll
(netcontrol/routing_health.py on netcontrol/snmp_health.py).

Invented peers and neighbors in the documentation address ranges; the
wiring tests run the poll and ``_evaluate_alerts_for_poll`` against the
test database. No device, SDK or network.
"""

from __future__ import annotations

import pytest
import routes.database as db
from netcontrol import health_checks, routing_health as rh, snmp_health as sh

from snmp_health_fakes import SYS_UPTIME, Agent, add_host, evaluate, open_alerts, poll, res

BGP4_STATE = rh.BGP4_PEERS.state_oid
BGP4_ADMIN = rh.BGP4_PEERS.admin_oid
BGP4_AS = rh.BGP4_PEERS.remote_as_oid
BGP4_TRANS = rh.BGP4_PEERS.transitions_oid
CISCO_STATE = rh.CISCO_BGP_PEERS.state_oid
OSPF_STATE = rh.OSPF_NBR_STATE

# InetAddress indexes: type, length, octets.
V4 = "1.4.192.0.2.1"
V6 = "2.16." + ".".join(str(b) for b in bytes.fromhex("20010db8000000000000000000000001"))


def _classes(status: dict) -> dict[str, str]:
    return {i["index"]: i["class"] for i in status["items"]}


# ── Index parsing ────────────────────────────────────────────────────────────


def test_inet_addresses_of_an_index():
    assert rh.inet_address([1, 4, 198, 51, 100, 7]) == ("198.51.100.7", 6)
    assert rh.inet_address([int(p) for p in V6.split(".")])[0] == "2001:db8::1"
    assert rh.inet_address([16, 2, 1, 2]) == ("0102", 4)  # an address type not decoded
    assert rh.inet_address([1, 4, 192, 0]) == ("", 4)  # cut short
    assert rh.inet_address([1, 4, 300, 0, 2, 1]) == ("", 6)  # not octets
    assert rh.inet_address([1]) == ("", 1)


def test_peer_names_per_table():
    assert rh.ipv4_index_name("203.0.113.9") == "203.0.113.9"
    assert rh.cisco_peer_name(V4) == "192.0.2.1"
    assert rh.cisco_peer_name(V6) == "2001:db8::1"
    assert rh.cisco_peer_name("9") == "9"
    # Juniper: routing instance, local address, remote address.
    assert rh.juniper_peer_name(f"0.1.4.192.0.2.2.{V4}") == "192.0.2.1"
    assert rh.arista_peer_name(f"1.{V6}") == "2001:db8::1"


# ── BGP ──────────────────────────────────────────────────────────────────────


def _bgp(rows: dict, values: dict, host_id: int = 1, source=rh.BGP4_PEERS) -> dict:
    return sh.select(rh.BGP, rh.settle_bgp(source.key, host_id, sh.parse_table(source, rows, values)))


def test_bgp_states_admin_stop_and_never_established():
    rows = {f"{BGP4_STATE}.192.0.2.{s}": s for s in range(1, 7)}
    rows[f"{BGP4_STATE}.198.51.100.1"] = 1  # stopped by an operator
    rows[f"{BGP4_STATE}.198.51.100.2"] = 3  # never established
    rows[f"{BGP4_STATE}.198.51.100.3"] = 2  # counter not answered
    values = {f"{BGP4_TRANS}.192.0.2.{s}": 4 for s in range(1, 6)}
    values.update(
        {
            f"{BGP4_ADMIN}.198.51.100.1": 1,
            f"{BGP4_TRANS}.198.51.100.2": 0,
            f"{BGP4_AS}.192.0.2.3": 64500,
        }
    )
    status = _bgp(rows, values)
    classes = _classes(status)
    assert [classes[f"192.0.2.{s}"] for s in range(1, 7)] == [sh.DOWN] * 5 + [sh.OK]
    assert classes["198.51.100.1"] == sh.ADMIN_DOWN
    assert classes["198.51.100.2"] == sh.TRANSITIONAL
    assert classes["198.51.100.3"] == sh.DOWN
    checks = {c["dedup_key"]: c for c in sh.alert_checks(rh.BGP, 4, status)}
    assert checks["4:bgp_peer_down:192.0.2.3"]["message"] == "BGP peer 192.0.2.3 (AS 64500) is active"
    assert checks["4:bgp_peer_down:192.0.2.3"]["severity"] == "critical"
    never = next(i for i in status["items"] if i["index"] == "198.51.100.2")
    assert never["status"] == "active, never established"


def test_a_peer_this_process_saw_up_alerts_even_after_the_counter_reset():
    up = {f"{BGP4_STATE}.192.0.2.1": 6}
    assert _classes(_bgp(up, {}, host_id=9)) == {"192.0.2.1": sh.OK}
    # The router reloaded: the counter is 0, but the peer was up before.
    down = {f"{BGP4_STATE}.192.0.2.1": 1}
    assert _classes(_bgp(down, {f"{BGP4_TRANS}.192.0.2.1": 0}, host_id=9)) == {"192.0.2.1": sh.DOWN}
    # Another host's memory is its own.
    assert _classes(_bgp(down, {f"{BGP4_TRANS}.192.0.2.1": 0}, host_id=10)) == {"192.0.2.1": sh.TRANSITIONAL}
    assert rh.settle_bgp("x", 1, {}) == {}


async def test_details_are_read_only_for_the_peers_not_established():
    agent = Agent({f"{CISCO_STATE}.{V4}": 6, f"{CISCO_STATE}.{V6}": 3}, {f"{rh.CISCO_BGP_PEERS.transitions_oid}.{V6}": 2})
    table = await rh.CISCO_BGP_PEERS.read(agent.get, agent.walk, 1)
    assert agent.gets == [tuple(f"{oid}.{V6}" for oid in rh.CISCO_BGP_PEERS.detail_oids)]
    status = sh.select(rh.BGP, table)
    assert [(i["name"], i["class"]) for i in status["items"]] == [
        ("BGP peer 192.0.2.1", sh.OK),
        ("BGP peer 2001:db8::1", sh.DOWN),
    ]


async def test_juniper_and_arista_peer_tables():
    jnx = f"0.1.4.192.0.2.2.{V4}"
    agent = Agent({f"{rh.JUNIPER_BGP_PEERS.state_oid}.{jnx}": 1}, {f"{rh.JUNIPER_BGP_PEERS.admin_oid}.{jnx}": 1})
    status = sh.select(rh.BGP, await rh.JUNIPER_BGP_PEERS.read(agent.get, agent.walk, 1))
    assert [(i["name"], i["class"]) for i in status["items"]] == [("BGP peer 192.0.2.1", sh.ADMIN_DOWN)]
    arista = f"1.{V6}"
    agent = Agent({f"{rh.ARISTA_BGP_PEERS.state_oid}.{arista}": 6})
    status = sh.select(rh.BGP, await rh.ARISTA_BGP_PEERS.read(agent.get, agent.walk, 1))
    assert [(i["name"], i["class"]) for i in status["items"]] == [("BGP peer 2001:db8::1", sh.OK)]


# ── OSPF ─────────────────────────────────────────────────────────────────────


def _ospf(rows: dict, host_id: int = 1, now: float = 1000.0, values: dict | None = None) -> dict:
    table = sh.parse_table(rh.OSPF_NEIGHBORS, rows, values or {})
    return sh.select(rh.OSPF, rh.settle_ospf(host_id, table, now=now))


def test_full_and_two_way_are_healthy():
    rows = {f"{OSPF_STATE}.192.0.2.{s}.0": s for s in (4, 8)}
    assert _classes(_ospf(rows)) == {"192.0.2.4.0": sh.OK, "192.0.2.8.0": sh.OK}
    assert set(rh.OSPF_STATES) == set(range(1, 9))


def test_a_neighbor_stuck_in_a_passing_state_is_down_at_the_second_poll():
    rows = {f"{OSPF_STATE}.192.0.2.5.0": 5, f"{OSPF_STATE}.192.0.2.8.0": 8}
    values = {f"{rh.OSPF_NBR_RTR_ID}.192.0.2.5.0": "198.51.100.5"}
    first = _ospf(rows, values=values)
    assert _classes(first)["192.0.2.5.0"] == sh.TRANSITIONAL
    second = _ospf(rows, values=values)
    assert _classes(second)["192.0.2.5.0"] == sh.DOWN
    assert [c["message"] for c in sh.alert_checks(rh.OSPF, 1, second)] == [
        "OSPF neighbor 192.0.2.5 (router ID 198.51.100.5) is exchange start"
    ]
    # Back to full: OK, and the next stall waits two polls again.
    _ospf({f"{OSPF_STATE}.192.0.2.5.0": 8})
    assert _classes(_ospf(rows))["192.0.2.5.0"] == sh.TRANSITIONAL


def test_a_healthy_neighbor_gone_from_the_table_is_down_until_forgotten():
    _ospf({f"{OSPF_STATE}.192.0.2.6.0": 8}, host_id=3, now=0.0)
    empty_row = {f"{OSPF_STATE}.192.0.2.7.0": 8}  # the table is read; 192.0.2.6 left it
    first = _ospf(empty_row, host_id=3, now=60.0)
    gone = next(i for i in first["items"] if i["index"] == "192.0.2.6.0")
    assert gone["class"] == sh.TRANSITIONAL and gone["status"] == rh.OSPF_GONE_STATUS
    second = _ospf(empty_row, host_id=3, now=120.0)
    assert [c["message"] for c in sh.alert_checks(rh.OSPF, 3, second)] == [
        "OSPF neighbor 192.0.2.6 is gone from the neighbor table"
    ]
    # A day after it was last seen healthy it is forgotten: its alert clears.
    later = _ospf(empty_row, host_id=3, now=rh.NEIGHBOR_MEMORY_SECONDS + 1.0)
    assert "192.0.2.6.0" not in _classes(later)
    assert sh.cleared_keys(rh.OSPF, 3, later, ["3:ospf_neighbor_down:192.0.2.6.0"]) == ["3:ospf_neighbor_down:192.0.2.6.0"]
    assert rh.settle_ospf(3, None) is None


# ── BGP peers in VRFs: cbgpPeer3Table ───────────────────────────────────────


async def test_cisco_vrf_peers_name_their_vrf():
    peer3 = rh.CISCO_BGP_VRF_PEERS
    vrf = f"3.{V4}"
    agent = Agent(
        {f"{peer3.state_oid}.0.{V6}": 6, f"{peer3.state_oid}.{vrf}": 3},
        {
            f"{peer3.remote_as_oid}.{vrf}": 64501,
            f"{peer3.transitions_oid}.{vrf}": 2,
            f"1.3.6.1.4.1.9.9.187.1.2.9.1.4.{vrf}": "blue",
        },
    )
    status = sh.select(rh.BGP, await peer3.read(agent.get, agent.walk, 1))
    assert [(i["name"], i["class"]) for i in status["items"]] == [
        ("BGP peer 2001:db8::1", sh.OK),
        ("BGP peer 192.0.2.1", sh.DOWN),
    ]
    assert [c["message"] for c in sh.alert_checks(rh.BGP, 1, status)] == ["BGP peer 192.0.2.1 (AS 64501, VRF blue) is active"]
    # The VRF table is tried first on a Cisco device; cbgpPeer2Table after it.
    chain = next(c for c in health_checks.plan_for_device("cisco_xe") if rh.KIND_BGP in c.kinds)
    assert chain.sources == (rh.CISCO_BGP_VRF_PEERS, rh.CISCO_BGP_PEERS, rh.BGP4_PEERS)


# ── EIGRP ────────────────────────────────────────────────────────────────────

EIGRP_ADDR = rh.EIGRP_PEER_ADDR


async def _eigrp(agent: Agent, host_id: int = 1) -> dict:
    return sh.select(rh.EIGRP, await rh.EIGRP_PEERS.read(agent.get, agent.walk, host_id))


async def test_an_eigrp_peer_gone_is_down_at_the_second_poll(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(rh.time, "monotonic", lambda: clock[0])
    agent = Agent(
        {
            f"{EIGRP_ADDR}.0.100.1": bytes([192, 0, 2, 1]),
            f"{EIGRP_ADDR}.0.100.2": bytes.fromhex("20010db8000000000000000000000002"),
            f"{EIGRP_ADDR}.0.100.3": "No Such Instance currently exists at this OID",
        }
    )
    first = await _eigrp(agent)
    assert [(i["index"], i["name"], i["class"]) for i in first["items"]] == [
        ("0.100.192.0.2.1", "EIGRP neighbor 192.0.2.1", sh.OK),
        ("0.100." + ".".join(str(b) for b in bytes.fromhex("20010db8000000000000000000000002")), "EIGRP neighbor 2001:db8::2", sh.OK),
    ]
    # The peer to 192.0.2.1 drops; it comes back later under another handle.
    del agent.rows[f"{EIGRP_ADDR}.0.100.1"]
    clock[0] = 60.0
    assert _classes(await _eigrp(agent))["0.100.192.0.2.1"] == sh.TRANSITIONAL
    clock[0] = 120.0
    second = await _eigrp(agent)
    assert [c["message"] for c in sh.alert_checks(rh.EIGRP, 1, second)] == [
        "EIGRP neighbor 192.0.2.1 (AS 100) is gone from the neighbor table"
    ]
    agent.rows[f"{EIGRP_ADDR}.0.100.9"] = bytes([192, 0, 2, 1])
    assert _classes(await _eigrp(agent))["0.100.192.0.2.1"] == sh.OK


async def test_eigrp_table_not_read_or_empty():
    assert sh.is_empty(await rh.EIGRP_PEERS.read(Agent({}).get, Agent({}).walk, 7))
    cut = Agent({}, cut={EIGRP_ADDR})
    assert await rh.EIGRP_PEERS.read(cut.get, cut.walk, 7) is None
    assert rh.address_text(None) == "" and rh.address_text(b"\x01\x02") == "0102"


# ── IS-IS ────────────────────────────────────────────────────────────────────

ISIS_STATE = rh.ISIS_ADJACENCIES.state_oid
ISIS_SYSID = rh.ISIS_ADJACENCIES.system_id_oid
SYSID_A = bytes.fromhex("00000c000001")
SYSID_B = bytes.fromhex("00000c000002")
KEY_A = "5.0.0.12.0.0.1"
KEY_B = "7.0.0.12.0.0.2"


async def test_isis_adjacencies_keyed_by_circuit_and_system_id():
    agent = Agent(
        {
            f"{ISIS_STATE}.5.1": 3,
            f"{ISIS_STATE}.5.2": 1,  # the same neighbor at another level, down
            f"{ISIS_STATE}.6.1": 2,
            f"{ISIS_STATE}.7.1": 9,  # a state the MIB does not list
            f"{ISIS_STATE}.8.1": "No Such Instance currently exists at this OID",
            f"{ISIS_SYSID}.5.1": SYSID_A,
            f"{ISIS_SYSID}.5.2": SYSID_A,
            f"{ISIS_SYSID}.7.1": SYSID_B,
        }
    )
    first = sh.select(rh.ISIS, await rh.ISIS_ADJACENCIES.read(agent.get, agent.walk, 1))
    assert _classes(first) == {KEY_A: sh.TRANSITIONAL, "6.1": sh.TRANSITIONAL, KEY_B: sh.TRANSITIONAL}
    second = sh.select(rh.ISIS, await rh.ISIS_ADJACENCIES.read(agent.get, agent.walk, 1))
    assert [c["message"] for c in sh.alert_checks(rh.ISIS, 1, second)] == [
        "IS-IS neighbor 0000.0c00.0001 (circuit 5) is down",
        "IS-IS adjacency 6.1 (circuit 6) is initializing",
    ]


async def test_isis_reads_fall_back_and_cut_walks():
    assert sh.is_empty(await rh.CISCO_ISIS_ADJACENCIES.read(Agent({}).get, Agent({}).walk, 2))
    for cut in (ISIS_STATE, ISIS_SYSID):
        agent = Agent({f"{ISIS_STATE}.5.1": 3}, cut={cut})
        assert await rh.ISIS_ADJACENCIES.read(agent.get, agent.walk, 2) is None
    chain = next(c for c in health_checks.plan_for_device("cisco_xr") if rh.KIND_ISIS in c.kinds)
    assert chain.sources == (rh.ISIS_ADJACENCIES, rh.CISCO_ISIS_ADJACENCIES)
    assert rh.system_id_text(SYSID_B) == "0000.0c00.0002"


# ── IP SLA ───────────────────────────────────────────────────────────────────

SENSE = rh.RTT_LATEST_SENSE


async def _ip_sla(agent: Agent, host_id: int = 1) -> dict:
    return sh.select(rh.IP_SLA, await rh.IP_SLA_PROBES.read(agent.get, agent.walk, host_id))


async def test_ip_sla_probes_alert_at_the_second_failed_poll():
    agent = Agent(
        {f"{SENSE}.10": 4, f"{SENSE}.11": 3, f"{SENSE}.12": 1, f"{SENSE}.13": 4, f"{SENSE}.14": 0},
        {
            f"{rh.RTT_ADMIN_TAG}.10": "wan-primary",
            f"{rh.RTT_ECHO_TARGET}.10": bytes([198, 51, 100, 1]),
            f"{rh.RTT_OPER_STATE}.10": 6,
            f"{rh.RTT_OPER_STATE}.13": 5,  # inactive: its last result is stale
        },
    )
    first = await _ip_sla(agent, host_id=4)
    assert _classes(first) == {"10": sh.TRANSITIONAL, "11": sh.TRANSITIONAL, "12": sh.OK, "13": sh.ADMIN_DOWN, "14": sh.TRANSITIONAL}
    second = await _ip_sla(agent, host_id=4)
    assert [(c["message"], c["severity"]) for c in sh.alert_checks(rh.IP_SLA, 4, second)] == [
        ("IP SLA 10 (wan-primary, target 198.51.100.1) is timing out", "critical"),
        ("IP SLA 11 is over its threshold", "warning"),
    ]
    # Every sense code the TC lists is classified.
    assert set(rh.RTT_SENSES) == set(range(0, 39))
    # All probes removed: the table read empty clears them at once.
    agent.rows = {}
    assert (await _ip_sla(agent, host_id=4))["items"] == []
    assert sh.is_empty(await rh.IP_SLA_PROBES.read(agent.get, agent.walk, 4))


def test_forget_all_clears_every_neighbor_memory():
    rh._EIGRP_MEMORY.seen[1] = {"0.1.192.0.2.1": ("x", "", 0.0)}
    rh._IP_SLA_MEMORY.pending[1] = {"10"}
    rh.forget_all()
    assert rh._EIGRP_MEMORY.seen == {} and rh._IP_SLA_MEMORY.pending == {}


# ── Wiring ───────────────────────────────────────────────────────────────────


async def test_the_poll_raises_and_resolves_per_peer(monkeypatch):
    group_id, host_id = await add_host("cisco_xe")
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    rows = {
        f"{SYS_UPTIME}.0": 4200,
        f"{BGP4_STATE}.192.0.2.1": 3,
        f"{BGP4_STATE}.192.0.2.2": 6,
        f"{OSPF_STATE}.192.0.2.9.0": 8,
    }
    answers = {f"{BGP4_TRANS}.192.0.2.1": 7}
    agent = Agent(rows, answers)
    result = await poll(monkeypatch, host, agent)
    # cbgpPeer2Table answered empty: BGP4-MIB was read instead.
    assert CISCO_STATE in agent.walks and BGP4_STATE in agent.walks
    assert result["bgp_health"]["down_count"] == 1 and result["ospf_health"]["down_count"] == 0
    assert await evaluate(host_id, group_id, result) == 1
    assert list(await open_alerts(host_id)) == [f"{host_id}:bgp_peer_down:192.0.2.1"]

    # The peer is shut down by an operator: resolved.
    agent.answers[f"{BGP4_ADMIN}.192.0.2.1"] = 1
    result = await poll(monkeypatch, host, agent)
    await evaluate(host_id, group_id, result)
    assert await open_alerts(host_id) == {}


async def test_an_ospf_neighbor_gone_raises_and_returns(monkeypatch):
    group_id, host_id = await add_host("linux_host")  # any SNMP type reads the standard MIBs
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    agent = Agent({f"{SYS_UPTIME}.0": 1, f"{OSPF_STATE}.192.0.2.9.0": 8, f"{OSPF_STATE}.192.0.2.10.0": 8})
    await evaluate(host_id, group_id, await poll(monkeypatch, host, agent))
    del agent.rows[f"{OSPF_STATE}.192.0.2.9.0"]
    for _ in range(2):
        await evaluate(host_id, group_id, await poll(monkeypatch, host, agent))
    assert list(await open_alerts(host_id)) == [f"{host_id}:ospf_neighbor_down:192.0.2.9.0"]
    # A poll that cut the table short keeps it.
    agent.cut.add(OSPF_STATE)
    result = await poll(monkeypatch, host, agent)
    assert result["ospf_health"] == {}
    await evaluate(host_id, group_id, result)
    assert len(await open_alerts(host_id)) == 1
    agent.cut.clear()
    agent.rows[f"{OSPF_STATE}.192.0.2.9.0"] = 8
    await evaluate(host_id, group_id, await poll(monkeypatch, host, agent))
    assert await open_alerts(host_id) == {}


async def test_the_only_neighbor_gone_raises_on_the_second_empty_poll(monkeypatch):
    """A branch router with one adjacency: when it drops, the neighbor table
    is empty. That is a reading at once (Plexus has the neighbor in memory):
    pending at the first empty poll, an alert at the second, resolved at the
    first poll that sees it healthy again (the table is still walked)."""
    group_id, host_id = await add_host("cisco_xe")
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    agent = Agent({f"{SYS_UPTIME}.0": 1, f"{OSPF_STATE}.198.51.100.2.0": 8})
    await evaluate(host_id, group_id, await poll(monkeypatch, host, agent))
    del agent.rows[f"{OSPF_STATE}.198.51.100.2.0"]
    first = await poll(monkeypatch, host, agent)
    assert [i["class"] for i in first["ospf_health"]["items"]] == [sh.TRANSITIONAL]
    assert await evaluate(host_id, group_id, first) == 0
    second = await poll(monkeypatch, host, agent)
    await evaluate(host_id, group_id, second)
    assert [a["message"] for a in (await open_alerts(host_id)).values()] == [
        "OSPF neighbor 198.51.100.2 is gone from the neighbor table"
    ]
    agent.rows[f"{OSPF_STATE}.198.51.100.2.0"] = 8
    agent.walks.clear()
    back = await poll(monkeypatch, host, agent)
    assert OSPF_STATE in agent.walks
    await evaluate(host_id, group_id, back)
    assert await open_alerts(host_id) == {}


async def test_an_empty_neighbor_table_with_nothing_in_memory_follows_the_generic_rule():
    agent = Agent({})
    assert sh.is_empty(await rh.OSPF_NEIGHBORS.read(agent.get, agent.walk, 1))
    cut = Agent({}, cut={OSPF_STATE})
    assert await rh.OSPF_NEIGHBORS.read(cut.get, cut.walk, 1) is None
    assert sh.is_empty(await rh.BGP4_PEERS.read(agent.get, agent.walk, 1))


@pytest.mark.parametrize("device_type", ["apc_ups", "icmp_only"])
def test_no_routing_read_for_a_ups_or_a_ping_only_host(device_type):
    assert health_checks.plan_for_device(device_type) == ()
