"""BGP peer and OSPF neighbor state read by the monitoring poll over SNMP.

Two checks on the shared ``snmp_health`` shape, critical as the built-in
BGP and OSPF syslog rules: ``bgp_peer_down`` (one alert per peer) and
``ospf_neighbor_down`` (one alert per neighbor). Which tables a device type
reads is ``health_checks.DEVICE_PLANS``; the standard MIBs are read from any
SNMP-polled device type.

What counts as down:

* BGP: a configured peer not in ``established(6)``. A peer an operator
  stopped (BGP4-MIB / CISCO-BGP4-MIB admin status ``stop(1)``, Juniper /
  Arista ``halted(1)``) is not a fault, and resolves its alert. A peer that
  has never been established is not alerted either: neither the device's
  ``FsmEstablishedTransitions`` counter (since its BGP process started) nor
  this Plexus process has seen it up. That covers a peer configured ahead
  of its turn-up and a decommissioned one left in the configuration; once
  a peer has been up, it alerts until it is up again, is shut down
  (``neighbor ... shutdown`` is the per-peer way to silence it), or is
  removed from the configuration. A suppression on ``bgp_peer_down``
  silences a whole host.
* OSPF (OSPF-MIB ``ospfNbrTable``): ``full(8)`` and ``twoWay(4)`` are
  healthy. Two DROTHER routers on a broadcast segment stay in 2-way by
  design, and the neighbor table does not say the network type without
  another walk, so 2-way is taken as healthy on every link (a
  point-to-point adjacency stuck at 2-way is not detected). Every other
  state (down, attempt, init, exchangeStart, exchange, loading) is down
  when a neighbor is seen in it at two polls in a row: one poll may catch
  an adjacency forming. A dynamic neighbor whose adjacency drops leaves
  the table after its dead interval, so a neighbor this process has seen
  healthy and that is gone from a table read completely is down too ("gone
  from the neighbor table", also after two polls). It is remembered for
  ``NEIGHBOR_MEMORY_SECONDS`` (24 hours) after it was last seen healthy;
  then it is forgotten and its alert resolves. The memory is the process's:
  a restart forgets it (an open "gone" alert resolves at the next poll).

Sources, checked against the MIB texts:

  BGP4-MIB (RFC 4273, bgp = 1.3.6.1.2.1.15), bgpPeerTable indexed by the
  peer's IPv4 address:
    bgpPeerState                      .3.1.2   idle(1) connect(2) active(3)
                                               opensent(4) openconfirm(5) established(6)
    bgpPeerAdminStatus                .3.1.3   stop(1) start(2)
    bgpPeerRemoteAs                   .3.1.9
    bgpPeerFsmEstablishedTransitions  .3.1.15
  CISCO-BGP4-MIB (1.3.6.1.4.1.9.9.187) cbgpPeer2Table, IPv4 and IPv6 peers,
  indexed by cbgpPeer2Type.cbgpPeer2RemoteAddr (InetAddress):
    cbgpPeer2State .1.2.5.1.3, cbgpPeer2AdminStatus .1.2.5.1.4,
    cbgpPeer2RemoteAs .1.2.5.1.11, cbgpPeer2FsmEstablishedTransitions .1.2.5.1.18
  BGP4-V2-MIB-JUNIPER (jnxBgpM2 1.3.6.1.4.1.2636.5.1.1), jnxBgpM2PeerTable
  indexed by routing instance, local and remote InetAddress:
    jnxBgpM2PeerState .2.1.1.1.2, jnxBgpM2PeerStatus .2.1.1.1.3 (halted(1)),
    jnxBgpM2PeerRemoteAs .2.1.1.1.13, jnxBgpM2PeerFsmEstablishedTrans .2.6.1.1.5
  ARISTA-BGP4V2-MIB (aristaBgp4V2 1.3.6.1.4.1.30065.4.1), indexed by
  instance and remote InetAddress:
    aristaBgp4V2PeerRemoteAs .1.2.1.10, aristaBgp4V2PeerAdminStatus .1.2.1.12
    (halted(1)), aristaBgp4V2PeerState .1.2.1.13,
    aristaBgp4V2PeerFsmEstablishedTransitions .1.7.1.5
  OSPF-MIB (RFC 4750, ospf = 1.3.6.1.2.1.14), ospfNbrTable indexed by
  ospfNbrIpAddr.ospfNbrAddressLessIndex:
    ospfNbrRtrId .10.1.3, ospfNbrState .10.1.6

Not read: OSPFv3-MIB ospfv3NbrTable (a second neighbor table under the same
metric; not yet), peers in Cisco VRFs that only an SNMP context shows.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Any

from netcontrol import snmp_health as sh
from netcontrol.routes.snmp import snmp_int
from netcontrol.snmp_health import DOWN, OK, TRANSITIONAL, HealthCheck, TableSource

KIND_BGP = "bgp_peer"
KIND_OSPF = "ospf_neighbor"

BGP = HealthCheck(
    metric="bgp_peer_down",
    result_key="bgp_health",
    kind=KIND_BGP,
    severity="critical",
    noun="BGP peer",
)
OSPF = HealthCheck(
    metric="ospf_neighbor_down",
    result_key="ospf_health",
    kind=KIND_OSPF,
    severity="critical",
    noun="OSPF neighbor",
)
CHECKS = (BGP, OSPF)

# How long a healthy OSPF neighbor gone from the table is remembered.
NEIGHBOR_MEMORY_SECONDS = 24 * 3600

# Per-host memory of this process: BGP peers seen established,
# ``{host_id: {(source key, index)}}``; OSPF neighbors seen healthy,
# ``{host_id: {index: (name, monotonic time last seen)}}``; and the OSPF
# neighbors not healthy at the last poll, ``{host_id: {index}}``.
_BGP_SEEN_UP: dict[int, set[tuple[str, str]]] = {}
_OSPF_SEEN: dict[int, dict[str, tuple[str, float]]] = {}
_OSPF_PENDING: dict[int, set[str]] = {}


def forget_all() -> None:
    """Drop the per-host memory (tests; host ids restart with the database)."""
    _BGP_SEEN_UP.clear()
    _OSPF_SEEN.clear()
    _OSPF_PENDING.clear()


# ── Index parsing ────────────────────────────────────────────────────────────


def inet_address(parts: list[int]) -> tuple[str, int]:
    """An InetAddressType.InetAddress pair of a table index (the address
    length-prefixed): its text, and how many index parts it took."""
    if len(parts) < 2:
        return "", len(parts)
    addr_type, length = parts[0], parts[1]
    raw = parts[2 : 2 + length]
    used = 2 + length
    if len(raw) != length or any(not 0 <= b <= 255 for b in raw):
        return "", len(parts)
    data = bytes(raw)
    if addr_type in (1, 3) and length >= 4:  # ipv4, ipv4z
        return str(ipaddress.IPv4Address(data[:4])), used
    if addr_type in (2, 4) and length >= 16:  # ipv6, ipv6z
        return str(ipaddress.IPv6Address(data[:16])), used
    return data.hex(), used


def _parts(index: str) -> list[int]:
    return [int(p) for p in index.split(".") if p.isdigit()]


def ipv4_index_name(index: str) -> str:
    """BGP4-MIB / OSPF-MIB: the row index starts with an IPv4 address."""
    return ".".join(index.split(".")[:4])


def cisco_peer_name(index: str) -> str:
    """cbgpPeer2Type.cbgpPeer2RemoteAddr."""
    return inet_address(_parts(index))[0] or index


def juniper_peer_name(index: str) -> str:
    """instance.localType.localAddr.remoteType.remoteAddr: the remote."""
    parts = _parts(index)[1:]
    _local, used = inet_address(parts)
    return inet_address(parts[used:])[0] or index


def arista_peer_name(index: str) -> str:
    """instance.remoteType.remoteAddr."""
    return inet_address(_parts(index)[1:])[0] or index


# ── BGP ──────────────────────────────────────────────────────────────────────

BGP_STATES: dict[int, tuple[str, str]] = {
    1: ("idle", DOWN),
    2: ("connect", DOWN),
    3: ("active", DOWN),
    4: ("opensent", DOWN),
    5: ("openconfirm", DOWN),
    6: ("established", OK),
}
# stop(1) / halted(1): an operator stopped the peer.
BGP_ADMIN_STOPPED = 1


@dataclass(frozen=True)
class PeerTable(TableSource):
    """A BGP peer table: the read, then the never-established rule."""

    admin_oid: str = ""
    remote_as_oid: str = ""
    transitions_oid: str = ""

    async def read(self, get: sh.Get, walk: sh.Walk, host_id: int) -> dict[str, Any] | None:
        return settle_bgp(self.key, host_id, await sh.read_table(self, get, walk))


def _peer_table(key: str, vendor: str, state: str, admin: str, remote_as: str, transitions: str, index_name) -> PeerTable:
    return PeerTable(
        key=key,
        vendor=vendor,
        state_oid=state,
        states=BGP_STATES,
        kinds=frozenset({KIND_BGP}),
        detail_oids=(admin, remote_as, transitions),
        admin_off=lambda v: snmp_int(v.get(admin)) == BGP_ADMIN_STOPPED,
        model=lambda v: f"AS {snmp_int(v.get(remote_as))}" if snmp_int(v.get(remote_as)) is not None else "",
        index_name=lambda i: f"BGP peer {index_name(i)}",
        row_fields=lambda v: {"established_transitions": snmp_int(v.get(transitions))},
        admin_oid=admin,
        remote_as_oid=remote_as,
        transitions_oid=transitions,
    )


BGP4_PEERS = _peer_table(
    "bgp4_mib",
    "BGP4-MIB",
    "1.3.6.1.2.1.15.3.1.2",
    "1.3.6.1.2.1.15.3.1.3",
    "1.3.6.1.2.1.15.3.1.9",
    "1.3.6.1.2.1.15.3.1.15",
    ipv4_index_name,
)
CISCO_BGP_PEERS = _peer_table(
    "cisco_bgp4_peer2",
    "Cisco",
    "1.3.6.1.4.1.9.9.187.1.2.5.1.3",
    "1.3.6.1.4.1.9.9.187.1.2.5.1.4",
    "1.3.6.1.4.1.9.9.187.1.2.5.1.11",
    "1.3.6.1.4.1.9.9.187.1.2.5.1.18",
    cisco_peer_name,
)
JUNIPER_BGP_PEERS = _peer_table(
    "juniper_bgp4_v2",
    "Juniper",
    "1.3.6.1.4.1.2636.5.1.1.2.1.1.1.2",
    "1.3.6.1.4.1.2636.5.1.1.2.1.1.1.3",
    "1.3.6.1.4.1.2636.5.1.1.2.1.1.1.13",
    "1.3.6.1.4.1.2636.5.1.1.2.6.1.1.5",
    juniper_peer_name,
)
ARISTA_BGP_PEERS = _peer_table(
    "arista_bgp4_v2",
    "Arista",
    "1.3.6.1.4.1.30065.4.1.1.2.1.13",
    "1.3.6.1.4.1.30065.4.1.1.2.1.12",
    "1.3.6.1.4.1.30065.4.1.1.2.1.10",
    "1.3.6.1.4.1.30065.4.1.1.7.1.5",
    arista_peer_name,
)


def settle_bgp(source_key: str, host_id: int, table: dict[str, Any] | None) -> dict[str, Any] | None:
    """The never-established rule: a peer not up that neither the device's
    counter nor this process has seen established is passing, not down.
    Remembers the peers seen established."""
    if not table:
        return table
    seen = _BGP_SEEN_UP.setdefault(host_id, set())
    for item in table.get("items") or []:
        key = (source_key, str(item["index"]))
        if item["class"] == OK:
            seen.add(key)
        elif item["class"] == DOWN and item.get("established_transitions") == 0 and key not in seen:
            item["class"] = TRANSITIONAL
            item["status"] = f"{item['status']}, never established"
    return table


# ── OSPF ─────────────────────────────────────────────────────────────────────

OSPF_NBR_RTR_ID = "1.3.6.1.2.1.14.10.1.3"
OSPF_NBR_STATE = "1.3.6.1.2.1.14.10.1.6"
OSPF_STATES: dict[int, tuple[str, str]] = {
    1: ("down", DOWN),
    2: ("attempt", DOWN),
    3: ("init", DOWN),
    4: ("2-way", OK),
    5: ("exchange start", DOWN),
    6: ("exchange", DOWN),
    7: ("loading", DOWN),
    8: ("full", OK),
}
OSPF_GONE_STATE = 1
OSPF_GONE_STATUS = "gone from the neighbor table"


@dataclass(frozen=True)
class NeighborTable(TableSource):
    """The OSPF neighbor table: the read, then the two-poll and gone rules."""

    async def read(self, get: sh.Get, walk: sh.Walk, host_id: int) -> dict[str, Any] | None:
        return settle_ospf(host_id, await sh.read_table(self, get, walk))


OSPF_NEIGHBORS = NeighborTable(
    key="ospf_mib",
    vendor="OSPF-MIB",
    state_oid=OSPF_NBR_STATE,
    states=OSPF_STATES,
    kinds=frozenset({KIND_OSPF}),
    detail_oids=(OSPF_NBR_RTR_ID,),
    model=lambda v: f"router ID {sh.text(v.get(OSPF_NBR_RTR_ID))}" if sh.text(v.get(OSPF_NBR_RTR_ID)) else "",
    index_name=lambda i: f"OSPF neighbor {ipv4_index_name(i)}",
)


def settle_ospf(host_id: int, table: dict[str, Any] | None, now: float | None = None) -> dict[str, Any] | None:
    """The two-poll rule and the gone rule (see the module docstring).
    Remembers the neighbors seen healthy and the ones not healthy now.

    The neighbor table is dynamic: a table read empty is a reading at once
    when the host has neighbors in memory (its last neighbor left it), and
    goes through the rules like any other; with none in memory it stays an
    empty table (``health_checks`` decides when that means "no neighbors")."""
    if table is None:
        return None
    if sh.is_empty(table):
        if not (_OSPF_SEEN.get(host_id) or _OSPF_PENDING.get(host_id)):
            return table
        table = {"source": table["source"], "vendor": table["vendor"], "items": []}
    now = time.monotonic() if now is None else now
    seen = _OSPF_SEEN.setdefault(host_id, {})
    pending = _OSPF_PENDING.get(host_id, set())
    items: list[dict[str, Any]] = table.get("items") or []
    not_healthy: set[str] = set()
    present = {str(i["index"]) for i in items}
    for item in items:
        index = str(item["index"])
        if item["class"] == OK:
            seen[index] = (item["name"], now)
            continue
        not_healthy.add(index)
        if item["class"] == DOWN and index not in pending:
            item["class"] = TRANSITIONAL
    for index, (name, last_seen) in list(seen.items()):
        if index in present:
            continue
        if now - last_seen > NEIGHBOR_MEMORY_SECONDS:
            del seen[index]
            continue
        not_healthy.add(index)
        items.append(
            {
                "index": index,
                "kind": KIND_OSPF,
                "name": name,
                "model": "",
                "status": OSPF_GONE_STATUS,
                "state": OSPF_GONE_STATE,
                "class": DOWN if index in pending else TRANSITIONAL,
                "severity": None,
            }
        )
    _OSPF_PENDING[host_id] = not_healthy
    table["items"] = items
    return table

