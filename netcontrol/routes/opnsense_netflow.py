"""
opnsense_netflow.py -- An OPNsense firewall's NetFlow in the flow collector.

OPNsense exports NetFlow v5 / v9 (Reporting > NetFlow) through ``ng_netflow``
and ``samplicate``, which sends from the address of whichever interface
routes to the collector: often not the address the firewall has in the
inventory. Its records name interfaces by the FreeBSD kernel interface
index (``ng_netflow`` takes the receiving interface's ``if_index`` and the
route lookup's for the output), which no flow view could name.

Called by ``opnsense_collection.after_collection`` for every collection,
``sync_flow_export`` uses what the collection already read (no extra API
call, no extra privilege):

  - the interface addresses (``interfaces_info``) become the IP aliases of
    the firewall's inventory host (``host_ip_aliases``, replaced, as the
    SNMP discovery and the configuration collection record them), from
    which the flow collector's exporter cache resolves a flow source to its
    host (``flow_collector.sync_exporter_hosts`` refreshes the cache and
    relinks the stored exporter rows);
  - the ``link#N`` gateways of the connected routes (``get_routes``) give
    the kernel index of each interface with an address
    (``opnsense_routes.interface_indexes``), which is stored with the
    device and the OPNsense name (``LAN``, ``WAN``) in
    ``flow_interface_names`` for the flow views;
  - the firewall's "Flow export" section says whether Plexus receives flows
    from it (the exporter rows of its host) and what was stored.

The firewall's NetFlow configuration itself (``diagnostics/netflow/getconfig``)
is not read: it needs the "Diagnostics: Netflow configuration" privilege,
which the documented API user does not have.

Best-effort: a failure is logged and noted in the section.
"""

from __future__ import annotations

from typing import Any

import routes.database as db

from netcontrol.integrations.meraki.normalize import _add, kv_section
from netcontrol.integrations.pathtrace.opnsense_routes import interface_indexes, live_address
from netcontrol.routes import flow_collector
from netcontrol.routes.opnsense_collection import _firewall, live_interfaces, matching_host
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.opnsense")

SECTION_FLOW_EXPORT = "Flow export"
NAMES_SOURCE = "opnsense"
NOT_IMPORTED = "Not linked: import the firewall into the inventory"


def interface_index_names(raw: dict) -> list[dict[str, Any]]:
    """``{if_index, device, name}`` of each interface whose kernel index
    the collected routing table gives: the name is the interface's OPNsense
    description (``LAN``), else the route's interface description, else
    the identifier (``opt1``), else the device."""
    names: dict[str, str] = {}
    for row in raw.get("interfaces") or []:
        if isinstance(row, dict) and row.get("device"):
            name = str(row.get("description") or "").strip() or str(row.get("identifier") or "").strip()
            if name:
                names.setdefault(str(row["device"]), name)
    for route in raw.get("routes") or []:
        if isinstance(route, dict) and route.get("netif") and route.get("intf_description"):
            names.setdefault(str(route["netif"]), str(route["intf_description"]).strip())
    return [
        {"if_index": index, "device": device, "name": names.get(device) or device}
        for index, device in sorted(interface_indexes(raw.get("routes")).items())
    ]


def interface_alias_addresses(raw: dict) -> list[str]:
    """The usable addresses of the collected interfaces (no link-local,
    loopback or multicast), in order."""
    found: list[str] = []
    for _key, _device, addresses in live_interfaces(raw.get("interfaces")):
        for value in addresses:
            pair = live_address(str(value))
            if pair is not None and pair[0] not in found:
                found.append(pair[0])
    return found


def _collector_text() -> str:
    config = flow_collector.FLOW_COLLECTOR_CONFIG
    if config.get("enabled"):
        return f"Listening on UDP {config.get('netflow_port', 2055)}"
    return "Off: enable the flow collector in Settings"


async def _exporter_rows(host_id: int) -> list[tuple[str, Any]]:
    """One row per flow type and source address Plexus received from the host."""
    exporters = [e for e in await db.list_flow_exporters() if e.get("host_id") == host_id]
    if not exporters:
        return [("Flows received", "None yet: set this collector as a NetFlow destination (Reporting, NetFlow)")]
    rows: list[tuple[str, Any]] = [("Flows received", "Yes")]
    for exporter in exporters:
        packets = int(exporter.get("packets_received") or 0)
        rows.append(
            (
                f"{exporter.get('flow_type')} from {exporter.get('exporter_ip')}",
                f"{packets:,} packets, last seen {exporter.get('last_seen') or '-'}",
            )
        )
    return rows


async def _store(host: dict, raw: dict) -> tuple[int | None, int | None]:
    """Record the interface addresses and the index names of the host.
    ``None`` for a part that was not collected."""
    host_id = int(host["id"])
    aliases = names = None
    addresses = interface_alias_addresses(raw)
    if addresses:
        primary = str(host.get("ip_address") or "").strip()
        aliases = await db.set_host_ip_aliases(host_id, primary, addresses)
    if isinstance(raw.get("routes"), list) and raw["routes"]:
        names = await db.replace_flow_interface_names(host_id, NAMES_SOURCE, interface_index_names(raw))
    await flow_collector.sync_exporter_hosts()
    return aliases, names


async def sync_flow_export(raw: dict, snapshot: dict) -> dict[str, Any]:
    """Record the firewall's interface addresses and interface index names
    for the flow collector and add the "Flow export" section. Returns what
    was stored: ``host_id`` (``None``: not an inventory host),
    ``aliases`` and ``interface_names`` (counts, ``None`` when not
    stored)."""
    result: dict[str, Any] = {"host_id": None, "aliases": None, "interface_names": None}
    rows: list[tuple[str, Any]] = []
    try:
        host = await matching_host(snapshot)
        if host is None:
            rows.append(("Result", NOT_IMPORTED))
        else:
            result["host_id"] = int(host["id"])
            result["aliases"], result["interface_names"] = await _store(host, raw)
            rows += await _exporter_rows(int(host["id"]))
            if result["interface_names"] is not None:
                rows.append(("Interface names", f"{result['interface_names']} interface indexes named"))
            if result["aliases"] is not None:
                rows.append(("Exporter addresses", f"{len(interface_alias_addresses(raw))} interface addresses"))
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: flow export state not stored: %s", type(exc).__name__)
        rows.append(("Result", "Not stored: see the server log"))
    rows += [("Collector", _collector_text()), ("Source", "Plexus flow collector")]
    firewall = _firewall(snapshot)
    if firewall is not None:
        _add(firewall["sections"], kv_section(SECTION_FLOW_EXPORT, rows))
    return result
