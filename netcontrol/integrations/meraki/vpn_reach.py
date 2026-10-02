"""Whether a Meraki appliance's VPN carries traffic for a subnet behind it.

A Meraki vMX in a cloud VPC is where the cloud's routing hands traffic for
the branches to Meraki. ``VpnCarrier`` answers, from a snapshot, what the
cloud cannot: does AutoVPN (or a non-Meraki tunnel of the appliance) join
the appliance to the site that owns the far address, and does the appliance
advertise the cloud address so the far site has a route back.

It is the *carrier* ``netcontrol.integrations.aws.reachability`` takes for
an instance: ``carry`` returns ``(status, where, text)`` steps, and the VPN
carries the traffic when every step is ``ok``. Pure (no I/O).
"""

from __future__ import annotations

import ipaddress
from collections import deque
from typing import Any

from netcontrol.integrations.meraki.subnets import _cell, _cidr, _rows, subnet_index

OK, BLOCKED, UNKNOWN = "ok", "blocked", "unknown"
# Tunnel states the Dashboard reports for a tunnel that is not up.
_DOWN = ("unreachable", "failed")
_Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Step = tuple[str, str, str]


class VpnCarrier:
    """The VPN of one appliance (``node_id``) of a Meraki snapshot.
    ``subnets`` is the snapshot's ``subnet_index`` when already built."""

    def __init__(self, snapshot: dict[str, Any], node_id: str, subnets: list[dict] | None = None) -> None:
        self._snapshot = snapshot
        self._subnets = subnets
        self._nodes = {n["id"]: n for n in snapshot.get("nodes") or [] if isinstance(n, dict)}
        self._node = self._nodes.get(node_id) or {"id": node_id}
        sites = {s["id"]: s for s in snapshot.get("sites") or []}
        self._site = sites.get(self._node.get("site") or "") or {}
        self._site_names = {site_id: site.get("name") or site_id for site_id, site in sites.items()}
        model = str(self._node.get("model") or "").strip()
        self.name = f"Meraki {model or 'appliance'} {self._node.get('label') or node_id}".replace("  ", " ")

    def _tunnels(self, kind: str) -> dict[str, list[str]]:
        """Devices joined by tunnels of ``kind`` that are up."""
        joined: dict[str, list[str]] = {}
        for edge in self._snapshot.get("edges") or []:
            if edge.get("kind") == kind and str(edge.get("status") or "").lower() not in _DOWN:
                joined.setdefault(edge["a"], []).append(edge["b"])
                joined.setdefault(edge["b"], []).append(edge["a"])
        return joined

    def _path(self, targets: set[str]) -> list[str] | None:
        """Devices from the appliance to one of ``targets`` over AutoVPN tunnels that are up."""
        tunnels = self._tunnels("vpn")
        start = self._node["id"]
        parent: dict[str, str | None] = {start: None}
        queue = deque([start])
        while queue:
            at = queue.popleft()
            if at in targets:
                path = []
                step: str | None = at
                while step is not None:
                    path.append(step)
                    step = parent[step]
                return path[::-1]
            for peer in tunnels.get(at, []):
                if peer not in parent:
                    parent[peer] = at
                    queue.append(peer)
        return None

    def _label(self, node_id: str) -> str:
        return str((self._nodes.get(node_id) or {}).get("label") or node_id)

    def _far_side(self, outside: _Network) -> Step:
        """Is the appliance joined to the site that owns ``outside``."""
        where = f"{self.name}, VPN"
        if self._subnets is None:
            self._subnets = subnet_index(self._snapshot)
        owners: list[dict] = []
        longest = -1
        for entry in self._subnets:
            net = ipaddress.ip_network(entry["cidr"])
            if net.version != outside.version or not net.supernet_of(outside) or net.prefixlen < longest:
                continue
            if net.prefixlen > longest:
                owners, longest = [], net.prefixlen
            owners.append(entry)
        if not owners:
            return (
                UNKNOWN,
                where,
                f"{outside} is not a subnet of a site in this Meraki organization, so whether the appliance "
                "has a route to it is not known.",
            )
        refusals: list[Step] = []
        for entry in owners:
            site = entry.get("site_name") or "its site"
            if entry["site_id"] == self._node.get("site") and entry["kind"] != "peer":
                return OK, where, f"{entry['cidr']} is a subnet of the appliance's own site."
            if entry["kind"] == "peer":
                peer = entry["node_id"]
                if peer in self._tunnels("vpn3p").get(self._node["id"], []):
                    return (
                        OK,
                        where,
                        f"{entry['cidr']} is behind {self._label(peer)}, which the appliance has a tunnel to.",
                    )
                refusals.append(
                    (
                        BLOCKED,
                        where,
                        f"{entry['cidr']} is behind the non-Meraki peer {self._label(peer)}, and the appliance has no "
                        "tunnel of its own to it that is up. Such a route is not passed on over AutoVPN.",
                    )
                )
                continue
            targets = {n["id"] for n in self._nodes.values() if n.get("site") == entry["site_id"]}
            path = self._path({t for t in targets if self._nodes[t].get("kind") == "appliance"} or {entry["node_id"]})
            if path is None:
                refusals.append((BLOCKED, where, f"No AutoVPN tunnel that is up joins the appliance to {site}."))
            elif entry.get("in_vpn") is False:
                refusals.append((BLOCKED, where, f"{entry['cidr']} is not advertised into the VPN at {site}."))
            elif entry.get("in_vpn") is None:
                refusals.append(
                    (UNKNOWN, where, f"Whether {site} advertises {entry['cidr']} into the VPN was not collected.")
                )
            else:
                hops = " → ".join(self._label(n) for n in path)
                return OK, where, f"{entry['cidr']} at {site} is reached over AutoVPN: {hops}."
        return refusals[0]

    def _near_side(self, inside: _Network) -> Step:
        """Does the appliance advertise ``inside`` so that other sites route to it."""
        where = f"{self.name}, VPN local subnets"
        rows = _rows(self._site.get("sections") or [], "VPN local subnets")
        advertised: bool | None = None
        longest = -1
        for row in rows:
            cidr = _cidr(_cell(row, 0))
            if not cidr:
                continue
            net = ipaddress.ip_network(cidr)
            if net.version == inside.version and net.supernet_of(inside) and net.prefixlen > longest:
                advertised, longest = _cell(row, 1) == "Yes", net.prefixlen
        if not rows:
            return UNKNOWN, where, "The VPN settings of the appliance's network were not collected."
        if advertised is None:
            return (
                UNKNOWN,
                where,
                f"{inside} is not among the subnets the appliance advertises into AutoVPN. Other sites have a "
                "route to it only if they send all their traffic to this appliance (default route).",
            )
        if not advertised:
            return (
                BLOCKED,
                where,
                f"{inside} is excluded from the VPN at the appliance, so other sites have no route to it.",
            )
        return OK, where, f"The appliance advertises {inside} into AutoVPN, so other sites have a route back."

    def carry(self, inside: _Network, outside: _Network) -> list[Step]:
        """Steps deciding whether the VPN carries traffic between ``inside``
        (an address behind the appliance) and ``outside`` (one at another site)."""
        return [self._far_side(outside), self._near_side(inside)]
