"""
topology.py -- Topology visualization, discovery, and change-tracking routes.
"""

import asyncio
import json

import routes.database as db
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

import netcontrol.routes.state as state
from netcontrol.routes.snmp import _discover_neighbors, _snmp_walk  # noqa: F401
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

LOGGER = configure_logging("plexus.topology")

# Two routers: one for topology-feature routes, one for admin routes
router = APIRouter()
admin_router = APIRouter()


# ── Helpers ──────────────────────────────────────────────────────────────────


def _normalize_link_key(
    source_host_id: int,
    source_interface: str,
    target_device_name: str,
    target_interface: str,
) -> tuple:
    """Normalize a link key so minor SNMP string variations don't cause false
    change detections (case, domain suffix, whitespace)."""
    # Strip domain suffixes (e.g. "switch1.domain.local" → "switch1")
    tgt = target_device_name.strip().lower().split(".")[0]
    return (
        source_host_id,
        source_interface.strip().lower(),
        tgt,
        target_interface.strip().lower(),
    )


async def _record_topology_changes(
    host: dict,
    old_link_keys: set[tuple],
    new_link_keys: set[tuple],
    new_neighbors: list[dict],
    old_links: list[dict],
) -> None:
    """Compare old vs new link keys and record added/removed changes."""
    hostname = host.get("hostname", "")

    # Links that were removed (present before, gone now)
    removed_keys = old_link_keys - new_link_keys
    for key in removed_keys:
        _src_id, src_iface, tgt_name, tgt_iface = key
        # Find protocol from old links (compare normalized)
        protocol = ""
        target_ip = ""
        for ol in old_links:
            if _normalize_link_key(ol["source_host_id"], ol["source_interface"],
                                   ol["target_device_name"], ol["target_interface"]) == key:
                protocol = ol.get("protocol", "")
                target_ip = ol.get("target_ip", "")
                break
        await db.insert_topology_change(
            change_type="removed",
            source_host_id=host["id"],
            source_hostname=hostname,
            source_interface=src_iface,
            target_device_name=tgt_name,
            target_interface=tgt_iface,
            target_ip=target_ip,
            protocol=protocol,
        )

    # Links that were added (not present before, present now)
    added_keys = new_link_keys - old_link_keys
    for key in added_keys:
        _src_id, src_iface, tgt_name, tgt_iface = key
        protocol = ""
        target_ip = ""
        for n in new_neighbors:
            if _normalize_link_key(n["source_host_id"], n["local_interface"],
                                   n["remote_device_name"], n["remote_interface"]) == key:
                protocol = n.get("protocol", "")
                target_ip = n.get("remote_ip", "")
                break
        await db.insert_topology_change(
            change_type="added",
            source_host_id=host["id"],
            source_hostname=hostname,
            source_interface=src_iface,
            target_device_name=tgt_name,
            target_interface=tgt_iface,
            target_ip=target_ip,
            protocol=protocol,
        )


def _weathermap_color(utilization_pct: float) -> str:
    """Map utilization % to a hex color: green → yellow → orange → red."""
    pct = max(0, min(100, utilization_pct))
    if pct < 1:
        return "#808080"    # grey — idle / no traffic
    if pct < 25:
        return "#00cc00"    # green
    if pct < 50:
        return "#92d050"    # light green
    if pct < 60:
        return "#ffff00"    # yellow
    if pct < 70:
        return "#ffc000"    # amber
    if pct < 80:
        return "#ff8000"    # orange
    if pct < 90:
        return "#ff4000"    # red-orange
    return "#ff0000"        # red — near saturation


def _weathermap_width(utilization_pct: float) -> int:
    """Map utilization % to an edge width (1–8)."""
    pct = max(0, min(100, utilization_pct))
    if pct < 10:
        return 1
    if pct < 30:
        return 2
    if pct < 50:
        return 3
    if pct < 70:
        return 4
    if pct < 85:
        return 6
    return 8


def _calc_interface_utilization(stat: dict) -> dict | None:
    """Calculate utilization percentage from two counter snapshots."""
    if not stat.get("prev_polled_at") or not stat.get("polled_at"):
        return None
    try:
        from datetime import datetime as _dt
        t1 = _dt.fromisoformat(stat["prev_polled_at"])
        t2 = _dt.fromisoformat(stat["polled_at"])
        delta_sec = (t2 - t1).total_seconds()
        if delta_sec <= 0:
            return None
        speed_bps = (stat.get("if_speed_mbps") or 0) * 1_000_000
        if speed_bps <= 0:
            return None

        # Guard against NULL previous counters (first poll has no baseline)
        if stat.get("prev_in_octets") is None or stat.get("prev_out_octets") is None:
            return None

        in_delta = stat["in_octets"] - stat["prev_in_octets"]
        out_delta = stat["out_octets"] - stat["prev_out_octets"]
        # Handle 32/64-bit counter wraps
        if in_delta < 0:
            in_delta += 2**32
        if out_delta < 0:
            out_delta += 2**32

        in_bps = (in_delta * 8) / delta_sec
        out_bps = (out_delta * 8) / delta_sec
        in_pct = min(100.0, (in_bps / speed_bps) * 100)
        out_pct = min(100.0, (out_bps / speed_bps) * 100)
        util_pct = max(in_pct, out_pct)

        return {
            "in_bps": round(in_bps),
            "out_bps": round(out_bps),
            "in_pct": round(in_pct, 1),
            "out_pct": round(out_pct, 1),
            "utilization_pct": round(util_pct, 1),
            "speed_mbps": stat.get("if_speed_mbps", 0),
            "color": _weathermap_color(util_pct),
            "width": _weathermap_width(util_pct),
        }
    except Exception:
        return None


# ── Background loops ─────────────────────────────────────────────────────────


async def _run_topology_discovery_once() -> dict:
    """Run neighbor discovery across all SNMP-enabled groups."""
    if not state.TOPOLOGY_DISCOVERY_CONFIG.get("enabled"):
        return {"enabled": False, "groups_scanned": 0, "links_discovered": 0, "errors": 0}

    groups = await db.get_all_groups()
    total_links = 0
    total_errors = 0
    groups_scanned = 0

    for group in groups:
        snmp_cfg = state._resolve_snmp_discovery_config(group["id"])
        if not snmp_cfg.get("enabled", False):
            continue
        hosts = await db.get_hosts_for_group(group["id"])
        if not hosts:
            continue

        groups_scanned += 1
        semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))

        async def _walk_host(host: dict, _cfg=snmp_cfg) -> tuple[dict, list[dict] | None, list[dict]]:
            async with semaphore:
                try:
                    neighbors, if_stats = await _discover_neighbors(
                        host["id"], host["ip_address"], _cfg, timeout_seconds=5.0,
                    )
                    return host, neighbors, if_stats
                except Exception as exc:
                    LOGGER.warning("topology scheduled: discovery failed for %s: %s",
                                   host["ip_address"], exc)
                    return host, None, []

        walk_results = await asyncio.gather(*[_walk_host(h) for h in hosts])

        for host, neighbors, if_stats in walk_results:
            if neighbors is None:
                total_errors += 1
                continue
            try:
                # Snapshot old links for change detection
                old_links = await db.get_topology_links_for_host(host["id"])
                old_link_keys = {
                    _normalize_link_key(link["source_host_id"], link["source_interface"],
                                        link["target_device_name"], link["target_interface"])
                    for link in old_links if link["source_host_id"] == host["id"]
                }
                new_link_keys = {
                    _normalize_link_key(n["source_host_id"], n["local_interface"],
                                        n["remote_device_name"], n["remote_interface"])
                    for n in neighbors
                }

                await db.delete_topology_links_for_host(host["id"])
                for n in neighbors:
                    await db.upsert_topology_link(
                        source_host_id=n["source_host_id"],
                        source_ip=n["source_ip"],
                        source_interface=n["local_interface"],
                        target_host_id=None,
                        target_ip=n.get("remote_ip", ""),
                        target_device_name=n["remote_device_name"],
                        target_interface=n["remote_interface"],
                        protocol=n["protocol"],
                        target_platform=n.get("remote_platform", ""),
                    )
                # Store interface stats
                for stat in if_stats:
                    await db.upsert_interface_stat(**stat)
                # Auto-apply interface-scope graph templates
                if if_stats:
                    try:
                        await db.apply_interface_graph_templates_to_host(host["id"], if_stats)
                    except Exception:
                        pass
                # Auto-discover SNMP data sources (interfaces, storage)
                try:
                    from netcontrol.routes.snmp import auto_discover_data_sources
                    await auto_discover_data_sources(host["id"], host["ip_address"], snmp_cfg)
                except Exception:
                    pass
                # Collect MAC/ARP tables during topology discovery
                try:
                    from netcontrol.routes.mac_tracking import collect_mac_arp_tables
                    await collect_mac_arp_tables(host["id"], host["ip_address"], snmp_cfg)
                except Exception:
                    pass
                # Record topology changes (only if there were previous links)
                if old_link_keys:
                    await _record_topology_changes(host, old_link_keys, new_link_keys, neighbors, old_links)
                total_links += len(neighbors)
            except Exception as exc:
                LOGGER.warning("topology scheduled: DB write failed for %s: %s",
                               host["ip_address"], exc)
                total_errors += 1

    if groups_scanned > 0:
        try:
            await db.resolve_topology_target_host_ids()
        except Exception:
            pass
        LOGGER.info("topology scheduled: scanned %d groups, %d links discovered, %d errors",
                     groups_scanned, total_links, total_errors)
        increment_metric("topology.discovery.scheduled.success")

    return {
        "enabled": True,
        "groups_scanned": groups_scanned,
        "links_discovered": total_links,
        "errors": total_errors,
    }


async def _topology_discovery_loop() -> None:
    while True:
        try:
            await asyncio.sleep(int(state.TOPOLOGY_DISCOVERY_CONFIG.get(
                "interval_seconds", state.TOPOLOGY_DISCOVERY_DEFAULTS["interval_seconds"])))
            await _run_topology_discovery_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("topology discovery loop failure: %s", redact_value(str(exc)))
            increment_metric("topology.discovery.scheduled.failed")
            await asyncio.sleep(state.TOPOLOGY_DISCOVERY_DEFAULTS["interval_seconds"])


# ══════════════════════════════════════════════════════════════════════════════
# Admin routes (admin_router — registered with require_admin dependency)
# ══════════════════════════════════════════════════════════════════════════════


@admin_router.get("/api/admin/topology-discovery")
async def admin_get_topology_discovery_config():
    return state.TOPOLOGY_DISCOVERY_CONFIG


@admin_router.put("/api/admin/topology-discovery")
async def admin_update_topology_discovery_config(body: dict):
    state.TOPOLOGY_DISCOVERY_CONFIG = state._sanitize_topology_discovery_config(body)
    await db.set_auth_setting("topology_discovery", state.TOPOLOGY_DISCOVERY_CONFIG)
    return state.TOPOLOGY_DISCOVERY_CONFIG


@admin_router.post("/api/admin/topology-discovery/run-now")
async def admin_run_topology_discovery_now():
    result = await _run_topology_discovery_once()
    return {"ok": True, "result": result}


# ══════════════════════════════════════════════════════════════════════════════
# Topology-feature routes (router — registered with require_auth + require_feature("topology"))
# ══════════════════════════════════════════════════════════════════════════════


@router.get("/api/topology")
async def get_topology(group_id: int | None = Query(default=None)):
    """Return topology graph data (nodes + edges) for vis-network rendering."""
    try:
        links = await db.get_topology_links(group_id)

        # Build node set from hosts in groups + external neighbors
        nodes_by_id: dict[str | int, dict] = {}
        edges: list[dict] = []

        # Gather all host IDs referenced as sources
        source_host_ids = {link["source_host_id"] for link in links}
        # Also gather resolved target host IDs
        target_host_ids = {link["target_host_id"] for link in links if link.get("target_host_id")}
        all_host_ids = source_host_ids | target_host_ids

        # Fetch all referenced inventory hosts
        if all_host_ids:
            hosts = await db.get_hosts_by_ids(list(all_host_ids))
        else:
            hosts = []

        # If filtering by group, also include all hosts in that group as nodes
        if group_id is not None:
            group_hosts = await db.get_hosts_for_group(group_id)
            for h in group_hosts:
                if h["id"] not in {hh["id"] for hh in hosts}:
                    hosts.append(h)

        # Fetch group names
        groups = await db.get_all_groups()
        group_name_map = {g["id"]: g["name"] for g in groups}

        # Build inventory nodes
        for h in hosts:
            nodes_by_id[h["id"]] = {
                "id": h["id"],
                "label": h["hostname"],
                "ip": h["ip_address"],
                "device_type": h["device_type"],
                "group_id": h["group_id"],
                "group_name": group_name_map.get(h["group_id"], ""),
                "status": h["status"],
                "in_inventory": True,
            }

        # Fetch interface stats for utilization overlay
        all_stats = await db.get_interface_stats_by_hosts(list(all_host_ids)) if all_host_ids else []
        # Build lookup: (host_id, if_name) -> utilization data
        util_map: dict[tuple[int, str], dict] = {}
        for stat in all_stats:
            util = _calc_interface_utilization(stat)
            if util:
                util_map[(stat["host_id"], stat["if_name"])] = util

        # Fetch unacknowledged change count
        change_count = await db.get_topology_changes_count(unacknowledged_only=True)

        # Build edges + external nodes
        for link in links:
            src_id = link["source_host_id"]
            tgt_host_id = link.get("target_host_id")
            tgt_name = link.get("target_device_name", "")
            tgt_ip = link.get("target_ip", "")

            if tgt_host_id and tgt_host_id in nodes_by_id:
                tgt_id = tgt_host_id
            else:
                # External neighbor -- use string ID
                ext_key = f"ext_{tgt_name}" if tgt_name else f"ext_{tgt_ip}"
                tgt_id = ext_key
                if ext_key not in nodes_by_id:
                    nodes_by_id[ext_key] = {
                        "id": ext_key,
                        "label": tgt_name or tgt_ip or "unknown",
                        "ip": tgt_ip,
                        "device_type": "unknown",
                        "group_id": None,
                        "group_name": "",
                        "status": "unknown",
                        "in_inventory": False,
                        "platform": link.get("target_platform", ""),
                    }

            src_iface = link.get("source_interface", "")
            tgt_iface = link.get("target_interface", "")
            label_parts = []
            if src_iface:
                label_parts.append(src_iface)
            if tgt_iface:
                label_parts.append(tgt_iface)
            edge_label = " -- ".join(label_parts) if label_parts else ""

            edge_data = {
                "id": link["id"],
                "from": src_id,
                "to": tgt_id,
                "label": edge_label,
                "protocol": link.get("protocol", "cdp"),
                "source_interface": src_iface,
                "target_interface": tgt_iface,
            }

            # Attach utilization + weathermap data (use source interface stats)
            util = util_map.get((src_id, src_iface))
            if util:
                edge_data["utilization"] = util
                edge_data["color"] = util.get("color", "#808080")
                edge_data["width"] = util.get("width", 1)
            else:
                edge_data["color"] = "#808080"
                edge_data["width"] = 1

            edges.append(edge_data)

        return {
            "nodes": list(nodes_by_id.values()),
            "edges": edges,
            "unacknowledged_changes": change_count,
        }
    except Exception as exc:
        LOGGER.error("topology: failed to build graph: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to build topology graph")


@router.get("/api/topology/utilization")
async def get_topology_utilization(group_id: int | None = Query(None)):
    """Return lightweight utilization data for all topology edges."""
    all_host_ids = set()
    links = await db.get_topology_links()
    for link in links:
        all_host_ids.add(link["source_host_id"])
        if link.get("target_host_id"):
            all_host_ids.add(link["target_host_id"])

    if group_id is not None:
        hosts = await db.get_hosts_for_group(group_id)
        all_host_ids = {h["id"] for h in hosts}

    all_stats = await db.get_interface_stats_by_hosts(list(all_host_ids)) if all_host_ids else []
    util_map: dict[tuple[int, str], dict] = {}
    for stat in all_stats:
        util = _calc_interface_utilization(stat)
        if util:
            util_map[(stat["host_id"], stat["if_name"])] = util

    edges = []
    for link in links:
        src_id = link["source_host_id"]
        src_iface = link.get("source_interface", "")
        util_data = util_map.get((src_id, src_iface))
        edges.append({
            "source_host_id": src_id,
            "target_host_id": link.get("target_host_id"),
            "source_interface": src_iface,
            "utilization": util_data,
        })

    return {"edges": edges}


@router.get("/api/topology/utilization/stream")
async def stream_topology_utilization(
    group_id: int | None = Query(None),
    interval: int = Query(30, ge=5, le=300),
):
    """SSE endpoint that pushes utilization updates at regular intervals."""
    async def _event_gen():
        try:
            while True:
                all_host_ids = set()
                links = await db.get_topology_links()
                for link in links:
                    all_host_ids.add(link["source_host_id"])
                    if link.get("target_host_id"):
                        all_host_ids.add(link["target_host_id"])

                if group_id is not None:
                    hosts = await db.get_hosts_for_group(group_id)
                    all_host_ids = {h["id"] for h in hosts}

                all_stats = await db.get_interface_stats_by_hosts(list(all_host_ids)) if all_host_ids else []
                util_map: dict[tuple[int, str], dict] = {}
                for stat in all_stats:
                    util = _calc_interface_utilization(stat)
                    if util:
                        util_map[(stat["host_id"], stat["if_name"])] = util

                edges = []
                for link in links:
                    src_id = link["source_host_id"]
                    src_iface = link.get("source_interface", "")
                    util_data = util_map.get((src_id, src_iface))
                    if util_data:
                        edges.append({
                            "source_host_id": src_id,
                            "target_host_id": link.get("target_host_id"),
                            "source_interface": src_iface,
                            "utilization": util_data,
                        })

                payload = json.dumps({"edges": edges})
                yield f"data: {payload}\n\n"
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            return

    return StreamingResponse(_event_gen(), media_type="text/event-stream")


@router.post("/api/topology/discover/stream")
async def discover_topology_stream():
    """Run neighbor discovery on all groups, streaming progress via SSE."""

    async def _event_generator():
        try:
            groups = await db.get_all_groups()
            # Collect all (group, hosts, snmp_cfg) tuples for enabled groups
            work: list[tuple[dict, list[dict], dict]] = []
            for group in groups:
                snmp_cfg = state._resolve_snmp_discovery_config(group["id"])
                if not snmp_cfg.get("enabled", False):
                    continue
                hosts = await db.get_hosts_for_group(group["id"])
                if hosts:
                    work.append((group, hosts, snmp_cfg))

            total_hosts = sum(len(hosts) for _, hosts, _ in work)
            yield f"data: {json.dumps({'type': 'start', 'total_hosts': total_hosts, 'total_groups': len(work)})}\n\n"

            if total_hosts == 0:
                yield f"data: {json.dumps({'type': 'done', 'hosts_scanned': 0, 'links_discovered': 0, 'errors': 0})}\n\n"
                return

            scanned = 0
            total_links = 0
            total_errors = 0
            semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))

            for group, hosts, snmp_cfg in work:
                group_name = group.get("name", f"Group {group['id']}")
                yield f"data: {json.dumps({'type': 'group_start', 'group': group_name, 'host_count': len(hosts)})}\n\n"

                # Phase 1: concurrent SNMP walks with per-host progress
                walk_results: list[tuple[dict, list[dict] | None, list[dict]]] = []

                async def _walk_host(host: dict, _cfg=snmp_cfg):
                    async with semaphore:
                        try:
                            neighbors, if_stats = await _discover_neighbors(
                                host["id"], host["ip_address"], _cfg, timeout_seconds=5.0,
                            )
                            return host, neighbors, if_stats
                        except Exception as exc:
                            LOGGER.warning("topology: neighbor discovery failed for %s: %s",
                                           host["ip_address"], exc)
                            return host, None, []

                tasks = [asyncio.create_task(_walk_host(h)) for h in hosts]
                for coro in asyncio.as_completed(tasks):
                    host, neighbors, if_stats = await coro
                    walk_results.append((host, neighbors, if_stats))
                    scanned += 1
                    neighbor_count = len(neighbors) if neighbors is not None else 0
                    yield f"data: {json.dumps({'type': 'host_walked', 'scanned': scanned, 'total_hosts': total_hosts, 'hostname': host['hostname'], 'ip': host['ip_address'], 'neighbors': neighbor_count, 'ok': neighbors is not None})}\n\n"

                # Phase 2: sequential DB writes
                yield f"data: {json.dumps({'type': 'db_write_start', 'group': group_name, 'host_count': len(walk_results)})}\n\n"

                group_links = 0
                for host, neighbors, if_stats in walk_results:
                    if neighbors is None:
                        total_errors += 1
                        continue
                    try:
                        old_links = await db.get_topology_links_for_host(host["id"])
                        old_link_keys = {
                            _normalize_link_key(link["source_host_id"], link["source_interface"],
                                                link["target_device_name"], link["target_interface"])
                            for link in old_links if link["source_host_id"] == host["id"]
                        }
                        new_link_keys = {
                            _normalize_link_key(n["source_host_id"], n["local_interface"],
                                                n["remote_device_name"], n["remote_interface"])
                            for n in neighbors
                        }
                        await db.delete_topology_links_for_host(host["id"])
                        for n in neighbors:
                            await db.upsert_topology_link(
                                source_host_id=n["source_host_id"],
                                source_ip=n["source_ip"],
                                source_interface=n["local_interface"],
                                target_host_id=None,
                                target_ip=n.get("remote_ip", ""),
                                target_device_name=n["remote_device_name"],
                                target_interface=n["remote_interface"],
                                protocol=n["protocol"],
                                target_platform=n.get("remote_platform", ""),
                            )
                        for stat in if_stats:
                            await db.upsert_interface_stat(**stat)
                        if old_link_keys:
                            await _record_topology_changes(host, old_link_keys, new_link_keys, neighbors, old_links)
                        group_links += len(neighbors)
                    except Exception as exc:
                        LOGGER.warning("topology: DB write failed for %s: %s",
                                       host["ip_address"], exc)
                        total_errors += 1

                total_links += group_links
                yield f"data: {json.dumps({'type': 'group_done', 'group': group_name, 'links': group_links})}\n\n"

            # Resolve target host IDs
            yield f"data: {json.dumps({'type': 'resolving'})}\n\n"
            resolved = await db.resolve_topology_target_host_ids()

            yield f"data: {json.dumps({'type': 'done', 'hosts_scanned': scanned, 'links_discovered': total_links, 'targets_resolved': resolved, 'errors': total_errors})}\n\n"
        except Exception as exc:
            LOGGER.error("topology: streaming discovery error: %s", exc, exc_info=True)
            yield f"data: {json.dumps({'type': 'error', 'message': 'An internal error occurred during discovery.'})}\n\n"

    return StreamingResponse(_event_generator(), media_type="text/event-stream")


@router.post("/api/topology/discover/{group_id}")
async def discover_topology_for_group(group_id: int):
    """Run CDP/LLDP neighbor discovery on all hosts in a group."""
    try:
        group = await db.get_group(group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        hosts = await db.get_hosts_for_group(group_id)
        if not hosts:
            return {"hosts_scanned": 0, "links_discovered": 0, "errors": 0}

        snmp_cfg = state._resolve_snmp_discovery_config(group_id)
        if not snmp_cfg.get("enabled", False):
            raise HTTPException(status_code=400,
                                detail="SNMP is not enabled for this group. Configure an SNMP profile first.")

        LOGGER.info("topology: starting discovery for group %d (%s) -- %d hosts",
                     group_id, group.get("name", "?"), len(hosts))

        semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))
        errors = 0
        total_links = 0

        # Phase 1: concurrent SNMP walks (no DB writes)
        async def _walk_host(host: dict) -> tuple[dict, list[dict] | None, list[dict]]:
            async with semaphore:
                try:
                    LOGGER.info("topology: walking %s (%s)...", host["hostname"], host["ip_address"])
                    neighbors, if_stats = await _discover_neighbors(
                        host["id"], host["ip_address"], snmp_cfg, timeout_seconds=5.0,
                    )
                    LOGGER.info("topology: %s done -- %d neighbors, %d if_stats",
                                host["hostname"], len(neighbors), len(if_stats))
                    return host, neighbors, if_stats
                except Exception as exc:
                    LOGGER.warning("topology: neighbor discovery failed for %s (%s): %s",
                                   host["hostname"], host["ip_address"], exc)
                    return host, None, []

        walk_results = await asyncio.gather(*[_walk_host(h) for h in hosts])
        LOGGER.info("topology: all SNMP walks complete, writing results to DB...")

        # Phase 2: sequential DB writes (avoids "database is locked")
        for host, neighbors, if_stats in walk_results:
            if neighbors is None:
                errors += 1
                continue
            try:
                # Snapshot old links for change detection
                old_links = await db.get_topology_links_for_host(host["id"])
                old_link_keys = {
                    _normalize_link_key(link["source_host_id"], link["source_interface"],
                                        link["target_device_name"], link["target_interface"])
                    for link in old_links if link["source_host_id"] == host["id"]
                }
                new_link_keys = {
                    _normalize_link_key(n["source_host_id"], n["local_interface"],
                                        n["remote_device_name"], n["remote_interface"])
                    for n in neighbors
                }

                await db.delete_topology_links_for_host(host["id"])
                for n in neighbors:
                    await db.upsert_topology_link(
                        source_host_id=n["source_host_id"],
                        source_ip=n["source_ip"],
                        source_interface=n["local_interface"],
                        target_host_id=None,
                        target_ip=n.get("remote_ip", ""),
                        target_device_name=n["remote_device_name"],
                        target_interface=n["remote_interface"],
                        protocol=n["protocol"],
                        target_platform=n.get("remote_platform", ""),
                    )
                # Store interface stats
                for stat in if_stats:
                    await db.upsert_interface_stat(**stat)
                # Auto-apply interface-scope graph templates
                if if_stats:
                    try:
                        await db.apply_interface_graph_templates_to_host(host["id"], if_stats)
                    except Exception:
                        pass
                # Record topology changes (only if there were previous links)
                if old_link_keys:
                    await _record_topology_changes(host, old_link_keys, new_link_keys, neighbors, old_links)
                total_links += len(neighbors)
            except Exception as exc:
                LOGGER.warning("topology: DB write failed for %s (%s): %s",
                               host["hostname"], host["ip_address"], exc)
                errors += 1

        # Resolve target host IDs against inventory
        resolved = await db.resolve_topology_target_host_ids()
        LOGGER.info("topology: discovered %d links from %d hosts (group %d), resolved %d targets, %d errors",
                     total_links, len(hosts), group_id, resolved, errors)

        return {
            "hosts_scanned": len(hosts),
            "links_discovered": total_links,
            "targets_resolved": resolved,
            "errors": errors,
        }
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.error("topology: discovery error for group %d: %s", group_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred during topology discovery.")


@router.post("/api/topology/discover")
async def discover_topology_all():
    """Run CDP/LLDP neighbor discovery on all groups."""
    try:
        groups = await db.get_all_groups()
        total_hosts = 0
        total_links = 0
        total_errors = 0

        for group in groups:
            snmp_cfg = state._resolve_snmp_discovery_config(group["id"])
            if not snmp_cfg.get("enabled", False):
                continue
            hosts = await db.get_hosts_for_group(group["id"])
            if not hosts:
                continue

            semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))

            # Phase 1: concurrent SNMP walks (no DB writes)
            async def _walk_host(host: dict, _cfg=snmp_cfg) -> tuple[dict, list[dict] | None, list[dict]]:
                async with semaphore:
                    try:
                        neighbors, if_stats = await _discover_neighbors(
                            host["id"], host["ip_address"], _cfg, timeout_seconds=5.0,
                        )
                        return host, neighbors, if_stats
                    except Exception as exc:
                        LOGGER.warning("topology: neighbor discovery failed for %s: %s",
                                       host["ip_address"], exc)
                        return host, None, []

            walk_results = await asyncio.gather(*[_walk_host(h) for h in hosts])

            # Phase 2: sequential DB writes (avoids "database is locked")
            for host, neighbors, if_stats in walk_results:
                if neighbors is None:
                    total_errors += 1
                    continue
                try:
                    # Snapshot old links for change detection
                    old_links = await db.get_topology_links_for_host(host["id"])
                    old_link_keys = {
                        _normalize_link_key(link["source_host_id"], link["source_interface"],
                                            link["target_device_name"], link["target_interface"])
                        for link in old_links if link["source_host_id"] == host["id"]
                    }
                    new_link_keys = {
                        _normalize_link_key(n["source_host_id"], n["local_interface"],
                                            n["remote_device_name"], n["remote_interface"])
                        for n in neighbors
                    }

                    await db.delete_topology_links_for_host(host["id"])
                    for n in neighbors:
                        await db.upsert_topology_link(
                            source_host_id=n["source_host_id"],
                            source_ip=n["source_ip"],
                            source_interface=n["local_interface"],
                            target_host_id=None,
                            target_ip=n.get("remote_ip", ""),
                            target_device_name=n["remote_device_name"],
                            target_interface=n["remote_interface"],
                            protocol=n["protocol"],
                            target_platform=n.get("remote_platform", ""),
                        )
                    # Store interface stats
                    for stat in if_stats:
                        await db.upsert_interface_stat(**stat)
                    # Auto-apply interface-scope graph templates
                    if if_stats:
                        try:
                            await db.apply_interface_graph_templates_to_host(host["id"], if_stats)
                        except Exception:
                            pass
                    # Record topology changes (only if there were previous links)
                    if old_link_keys:
                        await _record_topology_changes(host, old_link_keys, new_link_keys, neighbors, old_links)
                    total_links += len(neighbors)
                except Exception as exc:
                    LOGGER.warning("topology: DB write failed for %s: %s",
                                   host["ip_address"], exc)
                    total_errors += 1
            total_hosts += len(hosts)

        resolved = await db.resolve_topology_target_host_ids()
        return {
            "hosts_scanned": total_hosts,
            "links_discovered": total_links,
            "targets_resolved": resolved,
            "errors": total_errors,
        }
    except Exception as exc:
        LOGGER.error("topology: full discovery error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred during topology discovery.")


@router.post("/api/topology/discover/{group_id}/stream")
async def discover_topology_for_group_stream(group_id: int):
    """Run neighbor discovery on a single group, streaming progress via SSE."""

    # Validate upfront before starting the stream
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    snmp_cfg = state._resolve_snmp_discovery_config(group_id)
    if not snmp_cfg.get("enabled", False):
        raise HTTPException(status_code=400,
                            detail="SNMP is not enabled for this group. Configure an SNMP profile first.")
    hosts = await db.get_hosts_for_group(group_id)

    async def _event_generator():
        try:
            group_name = group.get("name", f"Group {group_id}")
            total_hosts = len(hosts) if hosts else 0
            yield f"data: {json.dumps({'type': 'start', 'total_hosts': total_hosts, 'total_groups': 1})}\n\n"

            if not hosts:
                yield f"data: {json.dumps({'type': 'done', 'hosts_scanned': 0, 'links_discovered': 0, 'errors': 0})}\n\n"
                return

            yield f"data: {json.dumps({'type': 'group_start', 'group': group_name, 'host_count': total_hosts})}\n\n"

            semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))
            scanned = 0
            total_links = 0
            errors = 0

            # Phase 1: concurrent SNMP walks
            walk_results: list[tuple[dict, list[dict] | None, list[dict]]] = []

            async def _walk_host(host: dict):
                async with semaphore:
                    try:
                        neighbors, if_stats = await _discover_neighbors(
                            host["id"], host["ip_address"], snmp_cfg, timeout_seconds=5.0,
                        )
                        return host, neighbors, if_stats
                    except Exception as exc:
                        LOGGER.warning("topology: neighbor discovery failed for %s (%s): %s",
                                       host["hostname"], host["ip_address"], exc)
                        return host, None, []

            tasks = [asyncio.create_task(_walk_host(h)) for h in hosts]
            for coro in asyncio.as_completed(tasks):
                host, neighbors, if_stats = await coro
                walk_results.append((host, neighbors, if_stats))
                scanned += 1
                neighbor_count = len(neighbors) if neighbors is not None else 0
                yield f"data: {json.dumps({'type': 'host_walked', 'scanned': scanned, 'total_hosts': total_hosts, 'hostname': host['hostname'], 'ip': host['ip_address'], 'neighbors': neighbor_count, 'ok': neighbors is not None})}\n\n"

            # Phase 2: sequential DB writes
            yield f"data: {json.dumps({'type': 'db_write_start', 'group': group_name, 'host_count': len(walk_results)})}\n\n"

            for host, neighbors, if_stats in walk_results:
                if neighbors is None:
                    errors += 1
                    continue
                try:
                    old_links = await db.get_topology_links_for_host(host["id"])
                    old_link_keys = {
                        _normalize_link_key(link["source_host_id"], link["source_interface"],
                                            link["target_device_name"], link["target_interface"])
                        for link in old_links if link["source_host_id"] == host["id"]
                    }
                    new_link_keys = {
                        _normalize_link_key(n["source_host_id"], n["local_interface"],
                                            n["remote_device_name"], n["remote_interface"])
                        for n in neighbors
                    }
                    await db.delete_topology_links_for_host(host["id"])
                    for n in neighbors:
                        await db.upsert_topology_link(
                            source_host_id=n["source_host_id"],
                            source_ip=n["source_ip"],
                            source_interface=n["local_interface"],
                            target_host_id=None,
                            target_ip=n.get("remote_ip", ""),
                            target_device_name=n["remote_device_name"],
                            target_interface=n["remote_interface"],
                            protocol=n["protocol"],
                            target_platform=n.get("remote_platform", ""),
                        )
                    for stat in if_stats:
                        await db.upsert_interface_stat(**stat)
                    if old_link_keys:
                        await _record_topology_changes(host, old_link_keys, new_link_keys, neighbors, old_links)
                    total_links += len(neighbors)
                except Exception as exc:
                    LOGGER.warning("topology: DB write failed for %s (%s): %s",
                                   host["hostname"], host["ip_address"], exc)
                    errors += 1

            yield f"data: {json.dumps({'type': 'group_done', 'group': group_name, 'links': total_links})}\n\n"

            # Resolve target host IDs
            yield f"data: {json.dumps({'type': 'resolving'})}\n\n"
            resolved = await db.resolve_topology_target_host_ids()

            yield f"data: {json.dumps({'type': 'done', 'hosts_scanned': scanned, 'links_discovered': total_links, 'targets_resolved': resolved, 'errors': errors})}\n\n"
        except Exception as exc:
            LOGGER.error("topology: streaming discovery error for group %d: %s", group_id, exc, exc_info=True)
            yield f"data: {json.dumps({'type': 'error', 'message': 'An internal error occurred during discovery.'})}\n\n"

    return StreamingResponse(_event_generator(), media_type="text/event-stream")


@router.get("/api/topology/host/{host_id}")
async def get_host_topology(host_id: int):
    """Return topology links for a specific host."""
    try:
        host = await db.get_host(host_id)
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        links = await db.get_topology_links_for_host(host_id)
        return {"host": host, "links": links}
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.error("topology: host topology error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred.")


@router.get("/api/topology/changes")
async def get_topology_changes(unacknowledged: bool = Query(default=True),
                               limit: int = Query(default=100, ge=1, le=10000)):
    """Return recent topology changes (added/removed links)."""
    try:
        changes = await db.get_topology_changes(
            unacknowledged_only=unacknowledged, limit=limit)
        count = await db.get_topology_changes_count(unacknowledged_only=True)
        return {"changes": changes, "unacknowledged_count": count}
    except Exception as exc:
        LOGGER.error("topology: changes error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred.")


@router.post("/api/topology/changes/acknowledge")
async def acknowledge_topology_changes():
    """Mark all topology changes as acknowledged."""
    try:
        count = await db.acknowledge_topology_changes()
        return {"acknowledged": count}
    except Exception as exc:
        LOGGER.error("topology: acknowledge error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred.")


@router.get("/api/topology/positions")
async def get_topology_positions():
    """Return saved node positions."""
    try:
        return await db.get_topology_positions()
    except Exception as exc:
        LOGGER.error("topology: get positions error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred.")


@router.put("/api/topology/positions")
async def save_topology_positions(payload: dict):
    """Save/update node positions. Body: {positions: {nodeId: {x, y}}}."""
    try:
        positions = payload.get("positions", {})
        count = await db.save_topology_positions(positions)
        return {"saved": count}
    except Exception as exc:
        LOGGER.error("topology: save positions error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred.")


@router.delete("/api/topology/positions")
async def delete_topology_positions():
    """Delete all saved node positions (reset layout)."""
    try:
        count = await db.delete_topology_positions()
        return {"deleted": count}
    except Exception as exc:
        LOGGER.error("topology: delete positions error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred.")
