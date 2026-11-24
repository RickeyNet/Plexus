"""Routing neighbor and probe state read by the monitoring poll over SNMP.

Five checks on the shared ``snmp_health`` shape: ``bgp_peer_down`` (one
alert per peer), ``ospf_neighbor_down``, ``eigrp_neighbor_down`` and
``isis_adjacency_down`` (one per neighbor), all critical as the built-in
BGP and OSPF syslog rules; and ``ip_sla_down`` (one per IP SLA operation,
critical when the probe gets no answer, warning when it is over its own
threshold). Which tables a device type reads is
``health_checks.DEVICE_PLANS``; the standard MIBs are read from any
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
  silences a whole host. On Cisco, cbgpPeer3Table lists the peers of every
  VRF without an SNMP context (its index starts with the VRF id; the
  message names the VRF).
* OSPF (OSPF-MIB ``ospfNbrTable``): ``full(8)`` and ``twoWay(4)`` are
  healthy. Two DROTHER routers on a broadcast segment stay in 2-way by
  design, and the neighbor table does not say the network type without
  another walk, so 2-way is taken as healthy on every link (a
  point-to-point adjacency stuck at 2-way is not detected). Every other
  state (down, attempt, init, exchangeStart, exchange, loading) is down
  when a neighbor is seen in it at two polls in a row: one poll may catch
  an adjacency forming.
* EIGRP (CISCO-EIGRP-MIB ``cEigrpPeerTable``): the table lists the
  established peers only; a peer declared down leaves it. So a peer is
  down when it was seen and is gone.
* IS-IS (ISIS-MIB ``isisISAdjTable``, else CISCO-IETF-ISIS-MIB
  ``ciiISAdjTable`` on older Cisco software): ``up(3)`` is healthy;
  ``down(1)``, ``initializing(2)`` and ``failed(4)`` are down at the second
  poll in a row.
* Gone (OSPF, EIGRP, IS-IS): a dynamic neighbor whose adjacency drops
  leaves the table, so a neighbor this process has seen healthy and that
  is gone from a table read completely is down ("gone from the neighbor
  table", also after two polls). It is remembered for
  ``NEIGHBOR_MEMORY_SECONDS`` (24 hours) after it was last seen healthy;
  then it is forgotten and its alert resolves. The memory is the
  process's: a restart forgets it (an open "gone" alert resolves at the
  next poll). EIGRP and IS-IS neighbors are keyed by address or system ID,
  not by the table's handle, which changes when an adjacency forms again.
* IP SLA (CISCO-RTTMON-MIB ``rttMonLatestRttOperSense``): the sense code of
  the latest operation of each probe. ``ok`` is healthy; timeouts, no
  connection, drops, errors and ``overThreshold(3)`` are down at the second
  poll in a row; a probe that is not running (``rttMonCtrlOperState`` not
  ``active(6)``) is not an alert.

Sources, checked against the MIB texts:

  BGP4-MIB (RFC 4273, bgp = 1.3.6.1.2.1.15), bgpPeerTable indexed by the
  peer's IPv4 address:
    bgpPeerState                      .3.1.2   idle(1) connect(2) active(3)
                                               opensent(4) openconfirm(5) established(6)
    bgpPeerAdminStatus                .3.1.3   stop(1) start(2)
    bgpPeerRemoteAs                   .3.1.9
    bgpPeerFsmEstablishedTransitions  .3.1.15
  CISCO-BGP4-MIB (1.3.6.1.4.1.9.9.187, cbgpPeer .1.2):
    cbgpPeer3Table .9.1, every VRF, indexed by
    cbgpPeer3VrfId.cbgpPeer3Type.cbgpPeer3RemoteAddr: cbgpPeer3VrfName .4,
    cbgpPeer3State .5, cbgpPeer3AdminStatus .6, cbgpPeer3RemoteAs .13,
    cbgpPeer3FsmEstablishedTransitions .20
    cbgpPeer2Table .5.1, IPv4 and IPv6 peers, indexed by
    cbgpPeer2Type.cbgpPeer2RemoteAddr (InetAddress): cbgpPeer2State .3,
    cbgpPeer2AdminStatus .4, cbgpPeer2RemoteAs .11,
    cbgpPeer2FsmEstablishedTransitions .18
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
  CISCO-EIGRP-MIB (ciscoEigrpMIB 1.3.6.1.4.1.9.9.449), cEigrpPeerTable .1.4.1.1
  indexed by cEigrpVpnId.cEigrpAsNumber.cEigrpHandle:
    cEigrpPeerAddr .3 (InetAddress)
  ISIS-MIB (RFC 4444, isisMIB 1.3.6.1.2.1.138), isisISAdjTable .1.6.1.1
  indexed by isisCircIndex.isisISAdjIndex; CISCO-IETF-ISIS-MIB
  (ciscoIetfIsisMIB 1.3.6.1.4.1.9.10.118), ciiISAdjTable .1.6.1.1, the same
  columns:
    AdjState .2  down(1) initializing(2) up(3) failed(4)
    AdjNeighSysID .6  (6 octets)
  CISCO-RTTMON-MIB (ciscoRttMonMIB 1.3.6.1.4.1.9.9.42, rttMonCtrl .1.2),
  indexed by rttMonCtrlAdminIndex:
    rttMonCtrlAdminTag .1.1.3, rttMonEchoAdminTargetAddress .2.1.2,
    rttMonCtrlOperState .9.1.10 (active(6)),
    rttMonLatestRttOperSense .10.1.2 (CISCO-RTTMON-TC-MIB RttResponseSense)

Not read: OSPFv3-MIB ospfv3NbrTable (a second neighbor table under the same
metric; not yet); IPsec tunnels (CISCO-IPSEC-FLOW-MONITOR-MIB lists active
tunnels only, so a tunnel that failed cannot be told from an idle one whose
security associations expired: docs/vendor-monitoring-coverage.md).
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Any

from netcontrol import snmp_health as sh
from netcontrol.routes.snmp import oid_sort_key, snmp_int
from netcontrol.snmp_health import DOWN, OK, TRANSITIONAL, HealthCheck, TableSource

KIND_BGP = "bgp_peer"
KIND_OSPF = "ospf_neighbor"
KIND_EIGRP = "eigrp_neighbor"
KIND_ISIS = "isis_adjacency"
KIND_IP_SLA = "ip_sla"

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
EIGRP = HealthCheck(
    metric="eigrp_neighbor_down",
    result_key="eigrp_health",
    kind=KIND_EIGRP,
    severity="critical",
    noun="EIGRP neighbor",
)
ISIS = HealthCheck(
    metric="isis_adjacency_down",
    result_key="isis_health",
    kind=KIND_ISIS,
    severity="critical",
    noun="IS-IS adjacency",
)
IP_SLA = HealthCheck(
    metric="ip_sla_down",
    result_key="ip_sla_health",
    kind=KIND_IP_SLA,
    severity="critical",
    noun="IP SLA",
    severity_from_device=True,
)
CHECKS = (BGP, OSPF, EIGRP, ISIS, IP_SLA)

# How long a healthy neighbor gone from its table is remembered.
NEIGHBOR_MEMORY_SECONDS = 24 * 3600

# Per-host memory of this process: BGP peers seen established,
# ``{host_id: {(source key, index)}}``. The neighbor tables keep theirs in a
# ``NeighborMemory`` each.
_BGP_SEEN_UP: dict[int, set[tuple[str, str]]] = {}


def forget_all() -> None:
    """Drop the per-host memory (tests; host ids restart with the database)."""
    _BGP_SEEN_UP.clear()
    for memory in (_OSPF_MEMORY, _EIGRP_MEMORY, _ISIS_MEMORY, _IP_SLA_MEMORY):
        memory.forget()


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
    """instance.remoteType.remoteAddr (Arista; cbgpPeer3Table: the VRF id
    first)."""
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


def _peer_model(remote_as: str, vrf_name: str):
    """``"AS 64500, VRF blue"``: the remote AS, and the VRF where the table
    names one."""

    def model(values: dict[str, Any]) -> str:
        asn = snmp_int(values.get(remote_as))
        vrf = sh.text(values.get(vrf_name)) if vrf_name else ""
        return ", ".join(p for p in (f"AS {asn}" if asn is not None else "", f"VRF {vrf}" if vrf else "") if p)

    return model


def _peer_table(
    key: str,
    vendor: str,
    state: str,
    admin: str,
    remote_as: str,
    transitions: str,
    index_name,
    vrf_name: str = "",
) -> PeerTable:
    return PeerTable(
        key=key,
        vendor=vendor,
        state_oid=state,
        states=BGP_STATES,
        kinds=frozenset({KIND_BGP}),
        detail_oids=(admin, remote_as, transitions, *((vrf_name,) if vrf_name else ())),
        admin_off=lambda v: snmp_int(v.get(admin)) == BGP_ADMIN_STOPPED,
        model=_peer_model(remote_as, vrf_name),
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
# cbgpPeer3Table: the peers of every VRF (the default one too).
CISCO_BGP_VRF_PEERS = _peer_table(
    "cisco_bgp4_peer3",
    "Cisco",
    "1.3.6.1.4.1.9.9.187.1.2.9.1.5",
    "1.3.6.1.4.1.9.9.187.1.2.9.1.6",
    "1.3.6.1.4.1.9.9.187.1.2.9.1.13",
    "1.3.6.1.4.1.9.9.187.1.2.9.1.20",
    arista_peer_name,
    vrf_name="1.3.6.1.4.1.9.9.187.1.2.9.1.4",
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


# ── Neighbor rules: two polls, and gone from the table ──────────────────────


class NeighborMemory:
    """The per-host memory of one dynamic table (OSPF, EIGRP, IS-IS, IP
    SLA) and its rules: a row down is a fault only when it was not healthy
    at the previous poll either (one poll may catch an adjacency forming);
    with ``gone``, a row this process has seen healthy and that left a table
    read completely is down too (``gone_status``), under the same two-poll
    rule, until ``NEIGHBOR_MEMORY_SECONDS`` after it was last seen healthy.
    The memory is the server process's: a restart forgets it."""

    def __init__(self, kind: str, gone_status: str = "", gone_state: int = 0) -> None:
        self.kind = kind
        self.gone = bool(gone_status)
        self.gone_status = gone_status
        self.gone_state = gone_state
        # ``{host_id: {index: (name, model, monotonic time last seen)}}``
        self.seen: dict[int, dict[str, tuple[str, str, float]]] = {}
        # ``{host_id: {index}}``: the rows not healthy at the last poll.
        self.pending: dict[int, set[str]] = {}

    def forget(self) -> None:
        self.seen.clear()
        self.pending.clear()

    def settle(self, host_id: int, table: dict[str, Any] | None, now: float | None = None) -> dict[str, Any] | None:
        """The two-poll rule and the gone rule, on a parsed table. A table
        read empty is a reading at once when the host has rows in memory
        (its last neighbor left it); with none it stays an empty table
        (``health_checks`` decides when that means "no items")."""
        if table is None:
            return None
        if sh.is_empty(table):
            if not (self.seen.get(host_id) or self.pending.get(host_id)):
                return table
            table = {"source": table["source"], "vendor": table["vendor"], "items": []}
        now = time.monotonic() if now is None else now
        seen = self.seen.setdefault(host_id, {})
        pending = self.pending.get(host_id, set())
        items: list[dict[str, Any]] = table.get("items") or []
        not_healthy: set[str] = set()
        present = {str(i["index"]) for i in items}
        for item in items:
            index = str(item["index"])
            if item["class"] == OK:
                if self.gone:
                    seen[index] = (item["name"], item.get("model", ""), now)
                continue
            not_healthy.add(index)
            if item["class"] == DOWN and index not in pending:
                item["class"] = TRANSITIONAL
        for index, (name, model, last_seen) in list(seen.items()):
            if index in present:
                continue
            if now - last_seen > NEIGHBOR_MEMORY_SECONDS:
                del seen[index]
                continue
            not_healthy.add(index)
            items.append(
                {
                    "index": index,
                    "kind": self.kind,
                    "name": name,
                    "model": model,
                    "status": self.gone_status,
                    "state": self.gone_state,
                    "class": DOWN if index in pending else TRANSITIONAL,
                    "severity": None,
                }
            )
        self.pending[host_id] = not_healthy
        table["items"] = items
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
GONE_STATUS = OSPF_GONE_STATUS

_OSPF_MEMORY = NeighborMemory(KIND_OSPF, OSPF_GONE_STATUS, OSPF_GONE_STATE)


@dataclass(frozen=True)
class NeighborTable(TableSource):
    """A dynamic table read on the shared shape, then its neighbor rules
    (``NEIGHBOR_RULES[key]``)."""

    async def read(self, get: sh.Get, walk: sh.Walk, host_id: int) -> dict[str, Any] | None:
        return NEIGHBOR_RULES[self.key].settle(host_id, await sh.read_table(self, get, walk))


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
    """The OSPF neighbor table's two-poll and gone rules (``NeighborMemory``)."""
    return _OSPF_MEMORY.settle(host_id, table, now)


# ── EIGRP: CISCO-EIGRP-MIB cEigrpPeerTable ──────────────────────────────────

EIGRP_PEER_ADDR = "1.3.6.1.4.1.9.9.449.1.4.1.1.3"
_EIGRP_MEMORY = NeighborMemory(KIND_EIGRP, GONE_STATUS)


def address_text(data: bytes | None) -> str:
    """An InetAddress value: IPv4 or IPv6 text, else hex; "" for none."""
    if not data:
        return ""
    if len(data) == 4:
        return str(ipaddress.IPv4Address(data))
    if len(data) == 16:
        return str(ipaddress.IPv6Address(data))
    return data.hex()


@dataclass(frozen=True)
class EigrpPeers:
    """cEigrpPeerTable lists the established peers only, indexed by
    cEigrpVpnId.cEigrpAsNumber.cEigrpHandle; a peer declared down is
    removed. One walk of the peer address column. A peer's item is keyed by
    VPN, AS and address (``vpn.as.<address octets>``): the handle changes
    when the adjacency forms again. Every row is healthy; a peer seen and
    then gone is down (``NeighborMemory``)."""

    key: str = "cisco_eigrp_peer"
    vendor: str = "Cisco"
    kinds: frozenset[str] = frozenset({KIND_EIGRP})

    async def read(self, get: sh.Get, walk: sh.Walk, host_id: int) -> dict[str, Any] | None:
        walked = await sh.walk_column(walk, EIGRP_PEER_ADDR)
        if walked is None:
            return None
        rows = sh.rows_by_index(walked, EIGRP_PEER_ADDR)
        if not rows:
            return _EIGRP_MEMORY.settle(host_id, sh.empty_table(self.key, self.vendor))
        items: dict[str, dict[str, Any]] = {}
        for index, raw in sorted(rows.items(), key=lambda kv: oid_sort_key(kv[0])):
            vpn, asn = (index.split(".") + ["", ""])[:2]
            data = sh.octets(raw)
            if not data or not vpn.isdigit() or not asn.isdigit():
                continue
            key = ".".join([vpn, asn, *(str(b) for b in data)])
            items[key] = {
                "index": key,
                "kind": KIND_EIGRP,
                "name": f"EIGRP neighbor {address_text(data)}",
                "model": f"AS {asn}",
                "status": "up",
                "state": 1,
                "class": OK,
                "severity": None,
            }
        table = {"source": self.key, "vendor": self.vendor, "items": list(items.values())}
        return _EIGRP_MEMORY.settle(host_id, table)


EIGRP_PEERS = EigrpPeers()


# ── IS-IS: ISIS-MIB / CISCO-IETF-ISIS-MIB adjacency table ───────────────────

ISIS_STATES: dict[int, tuple[str, str]] = {
    1: ("down", DOWN),
    2: ("initializing", DOWN),
    3: ("up", OK),
    4: ("failed", DOWN),
}
_ISIS_MEMORY = NeighborMemory(KIND_ISIS, GONE_STATUS)


def system_id_text(data: bytes) -> str:
    """An IS-IS system ID (6 octets) as ``0000.0c00.0001``."""
    hexed = data.hex()
    return ".".join(hexed[i : i + 4] for i in range(0, len(hexed), 4))


@dataclass(frozen=True)
class IsisAdjacencies:
    """An IS-IS adjacency table indexed by circuit and adjacency index: two
    walks (state, neighbor system ID). An adjacency's item is keyed by
    circuit and neighbor system ID (``circuit.<6 octets>``), as the
    adjacency index is assigned anew when an adjacency forms again; two
    adjacencies to one neighbor on one circuit (level 1 and level 2) are one
    item at the worse state. up(3) is healthy; down, initializing and
    failed are down at the second poll in a row; an adjacency seen up that
    left the table is down too (``NeighborMemory``)."""

    key: str
    vendor: str
    state_oid: str
    system_id_oid: str
    kinds: frozenset[str] = frozenset({KIND_ISIS})

    async def read(self, get: sh.Get, walk: sh.Walk, host_id: int) -> dict[str, Any] | None:
        walked = await sh.walk_column(walk, self.state_oid)
        if walked is None:
            return None
        rows = sh.rows_by_index(walked, self.state_oid)
        if not rows:
            return _ISIS_MEMORY.settle(host_id, sh.empty_table(self.key, self.vendor))
        ids = await sh.walk_column(walk, self.system_id_oid)
        if ids is None:
            return None
        system_ids = sh.rows_by_index(ids, self.system_id_oid)
        items: dict[str, dict[str, Any]] = {}
        for index, raw in sorted(rows.items(), key=lambda kv: oid_sort_key(kv[0])):
            state = snmp_int(raw)
            if state is None:
                continue
            circuit, _, _adjacency = index.partition(".")
            data = sh.octets(system_ids.get(index))
            if data:
                key = ".".join([circuit, *(str(b) for b in data)])
                name = f"IS-IS neighbor {system_id_text(data)}"
            else:
                key, name = index, f"IS-IS adjacency {index}"
            label, klass = ISIS_STATES.get(state, (f"state {state}", TRANSITIONAL))
            item = {
                "index": key,
                "kind": KIND_ISIS,
                "name": name,
                "model": f"circuit {circuit}",
                "status": label,
                "state": state,
                "class": klass,
                "severity": None,
            }
            previous = items.get(key)
            if previous is None or (previous["class"] == OK and klass != OK):
                items[key] = item
        table = {"source": self.key, "vendor": self.vendor, "items": list(items.values())}
        return _ISIS_MEMORY.settle(host_id, table)


ISIS_ADJACENCIES = IsisAdjacencies(
    key="isis_mib",
    vendor="ISIS-MIB",
    state_oid="1.3.6.1.2.1.138.1.6.1.1.2",
    system_id_oid="1.3.6.1.2.1.138.1.6.1.1.6",
)
CISCO_ISIS_ADJACENCIES = IsisAdjacencies(
    key="cisco_ietf_isis",
    vendor="Cisco",
    state_oid="1.3.6.1.4.1.9.10.118.1.6.1.1.2",
    system_id_oid="1.3.6.1.4.1.9.10.118.1.6.1.1.6",
)


# ── IP SLA: CISCO-RTTMON-MIB ────────────────────────────────────────────────

RTT_ADMIN_TAG = "1.3.6.1.4.1.9.9.42.1.2.1.1.3"
RTT_ECHO_TARGET = "1.3.6.1.4.1.9.9.42.1.2.2.1.2"
RTT_OPER_STATE = "1.3.6.1.4.1.9.9.42.1.2.9.1.10"
RTT_LATEST_SENSE = "1.3.6.1.4.1.9.9.42.1.2.10.1.2"
# rttMonCtrlOperState: a probe not active(6) is stopped or not yet
# started (orderlyStop(2), immediateStop(3), pending(4), inactive(5)):
# its last result is stale.
RTT_NOT_RUNNING = frozenset({2, 3, 4, 5})
_FAILING = "failing"
# CISCO-RTTMON-TC-MIB RttResponseSense.
RTT_SENSES: dict[int, tuple[str, str]] = {
    0: ("not yet run", TRANSITIONAL),
    1: ("ok", OK),
    2: ("disconnected", DOWN),
    3: ("over its threshold", DOWN),
    4: ("timing out", DOWN),
    5: ("busy", TRANSITIONAL),
    6: ("not connected", DOWN),
    7: ("dropping operations", DOWN),
    8: (f"{_FAILING} (sequence error)", DOWN),
    9: (f"{_FAILING} (verify error)", DOWN),
    10: ("application specific", TRANSITIONAL),
    11: (f"{_FAILING} (DNS server timeout)", DOWN),
    12: (f"{_FAILING} (TCP connect timeout)", DOWN),
    13: (f"{_FAILING} (HTTP transaction timeout)", DOWN),
    14: (f"{_FAILING} (DNS query error)", DOWN),
    15: (f"{_FAILING} (HTTP error)", DOWN),
    16: (f"{_FAILING} (error)", DOWN),
    17: (f"{_FAILING} (MPLS LSP echo send error)", DOWN),
    18: (f"{_FAILING} (MPLS LSP unreachable)", DOWN),
    19: (f"{_FAILING} (MPLS LSP malformed request)", DOWN),
    20: (f"{_FAILING} (MPLS LSP reachable, not the FEC)", DOWN),
    21: ("ok", OK),
    **{s: (f"{_FAILING} (responder control error)", DOWN) for s in range(22, 30)},
    30: ("ok", OK),
    **{s: (f"{_FAILING} (statistics retrieval error)", DOWN) for s in range(31, 39)},
}
# Over its threshold is a warning; a probe that gets no answer is critical.
RTT_SEVERITIES = {s: "critical" for s, (_label, klass) in RTT_SENSES.items() if klass == DOWN and s != 3}
RTT_SEVERITIES[3] = "warning"
_IP_SLA_MEMORY = NeighborMemory(KIND_IP_SLA)


def _ip_sla_model(values: dict[str, Any]) -> str:
    parts = []
    tag = sh.text(values.get(RTT_ADMIN_TAG))
    if tag:
        parts.append(tag)
    target = address_text(sh.octets(values.get(RTT_ECHO_TARGET)))
    if target:
        parts.append(f"target {target}")
    return ", ".join(parts)


IP_SLA_PROBES = NeighborTable(
    key="cisco_rttmon",
    vendor="Cisco",
    state_oid=RTT_LATEST_SENSE,
    states=RTT_SENSES,
    kinds=frozenset({KIND_IP_SLA}),
    detail_oids=(RTT_ADMIN_TAG, RTT_ECHO_TARGET, RTT_OPER_STATE),
    admin_off=lambda v: snmp_int(v.get(RTT_OPER_STATE)) in RTT_NOT_RUNNING,
    model=_ip_sla_model,
    index_name=lambda i: f"IP SLA {i}",
    severities=RTT_SEVERITIES,
)

NEIGHBOR_RULES: dict[str, NeighborMemory] = {
    OSPF_NEIGHBORS.key: _OSPF_MEMORY,
    IP_SLA_PROBES.key: _IP_SLA_MEMORY,
}
