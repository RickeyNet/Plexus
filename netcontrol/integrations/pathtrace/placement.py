"""Where a device whose own network was not collected sits on a LAN.

A node's forwarding block may have an interface into the device's own
network that Plexus does not collect (a Cato remote user's traffic that the
Split Tunnel policy sends out of the device directly), with ``behind_ip``,
the public address that network sits behind. When a Meraki appliance answers
on that address, the device is on that appliance's network, and Meraki's
client table of the network may list it: its local address is then known.

The match is by name only, and both conditions are required: the first DNS
label of the name the device reports (the node's ``device_name``) equals the
first label of the client's description (the name the client reports to
Meraki), ignoring case; and the client row is in the network of a device that
answers on the public address. Of several matching rows the newest is taken.

Pure (no I/O): the API handler loads the client rows.
"""

from __future__ import annotations

from typing import Any

from netcontrol.integrations.meraki.forwarding import is_address
from netcontrol.integrations.meraki.normalize import _s
from netcontrol.integrations.pathtrace.engine import graph_refs

SOURCE = "Meraki"


def host_label(name: Any) -> str:
    """The first DNS label of a host name, lower case: ``ccm_5cg4062ltk`` of
    ``CCM_5CG4062LTK.crosscountrymtg.local``."""
    return _s(name).strip().split(".", 1)[0].strip().lower()


def _behind(snapshot: dict) -> list[tuple[str, str, str]]:
    """``(node id, public address, device name)`` of every node of a
    snapshot that has an interface with ``behind_ip``."""
    found: list[tuple[str, str, str]] = []
    for node in snapshot.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        for interface in (node.get("forwarding") or {}).get("interfaces") or []:
            if isinstance(interface, dict) and is_address(interface.get("behind_ip")):
                found.append((str(node["id"]), str(interface["behind_ip"]), _s(node.get("device_name")).strip()))
                break
    return found


def _answering(snapshots: dict[int, dict], address: str) -> list[tuple[int, str]]:
    """The (organization, network) of every Meraki device with an interface
    on ``address``."""
    found: list[tuple[int, str]] = []
    for org_ref, snapshot in snapshots.items():
        if str(snapshot.get("provider") or "meraki") != "meraki":
            continue
        for node in snapshot.get("nodes") or []:
            if not isinstance(node, dict) or not node.get("site"):
                continue
            interfaces = (node.get("forwarding") or {}).get("interfaces") or []
            if any(isinstance(i, dict) and i.get("ip") == address for i in interfaces):
                network = (int(org_ref), str(node["site"]))
                if network not in found:
                    found.append(network)
    return found


def networks_to_read(snapshots: dict[int, dict]) -> list[tuple[int, str]]:
    """The (organization, network) pairs whose client rows ``placements``
    needs: those of the devices that answer on a ``behind_ip`` of a node
    that names its device."""
    found: list[tuple[int, str]] = []
    for snapshot in snapshots.values():
        for _node_id, address, device_name in _behind(snapshot):
            if device_name:
                found.extend(n for n in _answering(snapshots, address) if n not in found)
    return found


def place(device_name: str, rows: list[dict], networks: list[tuple[int, str]]) -> dict[str, Any] | None:
    """The newest client row of ``networks`` whose description names the
    device, as a placement, else ``None``."""
    wanted = host_label(device_name)
    if not wanted:
        return None
    best: dict | None = None
    for row in rows:
        if (int(row.get("org_ref") or 0), _s(row.get("network_id"))) not in networks:
            continue
        if host_label(row.get("description")) != wanted or not is_address(row.get("ip_address")):
            continue
        if best is None or _s(row.get("last_seen")) > _s(best.get("last_seen")):
            best = row
    if best is None:
        return None
    return {
        "ip": _s(best.get("ip_address")).strip(),
        "vlan": best.get("vlan"),
        "org_ref": int(best.get("org_ref") or 0),
        "network_id": _s(best.get("network_id")),
        "network_name": _s(best.get("network_name")),
        "device_name": _s(best.get("device_name")),
        "seen": _s(best.get("last_seen")),
        "description": _s(best.get("description")),
        "source": SOURCE,
    }


def placements(graph: dict, snapshots: dict[int, dict], rows: list[dict]) -> dict[Any, dict]:
    """Graph node -> placement for every node with an interface with
    ``behind_ip`` whose device the client rows place (``place``)."""
    nodes = {n["id"]: n for n in graph.get("nodes") or [] if isinstance(n, dict)}
    graph_of, _refs_of = graph_refs(nodes)
    found: dict[Any, dict] = {}
    for org_ref, snapshot in snapshots.items():
        for node_id, address, device_name in _behind(snapshot):
            gid = graph_of.get((int(org_ref), node_id))
            if gid is None or not device_name:
                continue
            placed = place(device_name, rows, _answering(snapshots, address))
            if placed is not None:
                found[gid] = placed
    return found
