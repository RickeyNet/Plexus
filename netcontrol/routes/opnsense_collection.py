"""
opnsense_collection.py -- What an OPNsense collection stores besides its snapshot.

Called by the source build (``netcontrol.routes.meraki_topology``) after an
OPNsense firewall was collected and its snapshot built, before the snapshot
is stored:

  - ``store_config_backup``: the ``config.xml`` the collection downloaded
    becomes a configuration backup of the inventory host that is this
    firewall, through the one store path every capture uses
    (``netcontrol.routes.device_config.store_device_config``: an unchanged
    configuration writes no new row, it re-checks the newest one). The
    firewall is matched to its host the way the device import matches it
    (``netcontrol.integrations.inventory_import.importable_devices``: the
    host with its address, or the one the collection matched it to). When
    the firewall is no inventory host yet, nothing is stored and the
    snapshot gets a warning that says to import it first. The XML holds
    password hashes, private keys and pre-shared keys: it is dropped from
    the raw collection here and never reaches the snapshot.
  - ``sync_audit_advisories``: the findings of the firewall's security
    audit become software advisories of the ``opnsense`` platform at the
    firewall's version (source ``opnsense-audit``), upserted by VuXML id so
    repeated collections update rather than duplicate them, and limited to
    the firewall(s) whose audit reported them (``device_keys``: the tracked
    device key of this firewall), so another firewall on the same version
    is not alerted. A finding this firewall's audit no longer reports has
    this firewall taken off its advisory (and the versions too once no
    firewall is left), so its alert resolves while another firewall's stays.
    Only an audit that verifiably completed (``completed``, see
    ``collector.parse_audit_log``) changes anything: an audit whose
    vulnerability database could not be fetched, that timed out or whose
    log is cut short says nothing about what is fixed. The software refresh
    that follows every stored collection matches the advisories to the
    tracked firewall and raises ``software_alerts`` the normal way.

  - ``sync_clients``: the ARP and NDP tables go into MAC tracking as the
    ``arp_table`` of the firewall's inventory host (matched as for the
    config backup; skipped with a warning when there is none), which also
    stamps the IP onto MAC table rows of other hosts that lack one. The
    DHCP leases (ISC, Kea, Dnsmasq) replace the leases of the firewall's
    ``dhcp_servers`` row (provider ``opnsense``, matched by the firewall's
    API address and created on first use), so they show in IPAM's DHCP
    servers, lease listing and inventory correlation. The firewall's
    "Clients" section says what was stored.
  - ``attach_rule_stats``: the filter rule counters (``rule_stats``) stay
    in the snapshot with the inventory host they belong to, for the rule
    views (``netcontrol.routes.opnsense_rules``).
  - ``store_route_capture``: the routing table and the live interface
    addresses become the route capture of the firewall's inventory host (a
    ``route_snapshots`` row in the text of
    ``netcontrol.integrations.pathtrace.opnsense_routes``, written only
    when it changed), from which the path trace takes the firewall's routes
    and the addresses DHCP or PPPoE assigned. Nothing is stored when the
    routing table was not read or the firewall is no inventory host yet.
    The firewall's "Route capture" section says what was stored.
  - ``store_alias_tables``: the pf tables of the aliases config.xml cannot
    resolve (``alias_tables``, popped from the raw collection) replace the
    ``opnsense_alias_tables`` rows of the firewall's inventory host, with
    when they were read and whether each is complete; the path trace
    resolves those aliases from them and the rule views show their size.
    Nothing is stored (the previous tables stay) when they were not read;
    the firewall's "Alias tables" section says what was stored.
  - ``opnsense_netflow.sync_flow_export``: the interface addresses become
    the host's IP aliases (the flow collector resolves the exporter by
    them) and the interface index names of the routing table are stored
    for the flow views; the firewall's "Flow export" section says whether
    Plexus receives its flows.

  - ``note_health_host``: the firewall's inventory host goes into the
    snapshot summary (``inventory_host_id``), from which the monitoring poll
    knows to read that host's health over this source's API
    (``netcontrol.routes.opnsense_health``); the "Health" section says
    whether it is stored.
  - ``opnsense_ids.store_collected``: the intrusion detection alerts
    (``ids_alerts``, popped from the raw collection) become security
    events of the source, with their alerts; the "IDS alerts" sections say
    what was stored.

All are best-effort: a failure is logged and noted in the snapshot, and
the collection is stored anyway.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import routes.database as db

from netcontrol.integrations.inventory_import import importable_devices
from netcontrol.integrations.meraki.normalize import _add, kv_section
from netcontrol.integrations.opnsense.collector import PATH_ARP, PATH_CONFIG, info_warning
from netcontrol.integrations.opnsense.normalize import (
    ADVISORY_SOURCE,
    DEVICE_NODE_PREFIX,
    PROVIDER,
    SECTION_HEALTH,
    arp_entries,
    audit_advisories,
    client_counts,
    dhcp_leases,
    interface_addresses,
    ndp_entries,
)
from netcontrol.integrations.opnsense.rules import parse_rule_stats
from netcontrol.integrations.pathtrace.opnsense_routes import LiveInterface, capture_text
from netcontrol.integrations.software.versions import canonical_version, snapshot_device_key, snapshot_devices
from netcontrol.routes.device_config import store_device_config
from netcontrol.routes.dhcp_adapters import DHCP_PROVIDER_OPNSENSE
from netcontrol.routes.route_capture import store_route_snapshot
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.opnsense")

CAPTURE_METHOD = "opnsense-api"
SECTION_CONFIG_BACKUP = "Config backup"
NOT_IMPORTED_MESSAGE = (
    "config.xml was read but not stored: this firewall is not an inventory host yet. "
    "Import it into the inventory (Map sources, Import devices) to keep its configuration backups."
)
SECTION_CLIENTS = "Clients"
CLIENTS_NOT_IMPORTED_MESSAGE = (
    "The ARP and NDP tables were read but not added to MAC tracking: this firewall is not an inventory host yet. "
    "Import it into the inventory (Map sources, Import devices) to track them."
)
SECTION_ROUTE_CAPTURE = "Route capture"
SECTION_ALIAS_TABLES = "Alias tables"
LEASE_SERVER_NOTES = (
    "Leases collected by the OPNsense topology source of this firewall; replaced on every collection. "
    "Disable this server to stop storing them."
)


def _firewall(snapshot: dict) -> dict | None:
    return next(
        (
            n
            for n in snapshot.get("nodes") or []
            if isinstance(n, dict)
            and str(n.get("id") or "").startswith(DEVICE_NODE_PREFIX)
            and n.get("kind") == "appliance"
        ),
        None,
    )


def _warn(snapshot: dict, warning: dict) -> None:
    snapshot.setdefault("collection", {}).setdefault("errors", []).append(warning)


async def matching_host(snapshot: dict, hosts: list[dict] | None = None) -> dict | None:
    """The inventory host that is the snapshot's firewall, or ``None``.
    ``hosts``: the inventory hosts when the caller already read them (it
    matches several snapshots against one read)."""
    firewall = _firewall(snapshot)
    if firewall is None:
        return None
    if hosts is None:
        hosts = await db.get_all_hosts()
    found = importable_devices(snapshot, PROVIDER, hosts)
    device = next((d for d in found["devices"] if d["key"] == firewall["id"]), None)
    existing = (device or {}).get("existing")
    if not existing or existing.get("host_id") is None:
        return None
    host_id = int(existing["host_id"])
    return next((h for h in hosts if int(h.get("id") or 0) == host_id), None)


async def store_config_backup(raw: dict, snapshot: dict) -> dict[str, Any] | None:
    """Store the collected ``config.xml`` (popped from ``raw``) as a config
    backup of the firewall's inventory host. Returns what was done, or
    ``None`` when there was nothing to store."""
    config_xml = raw.pop("config_xml", None)
    if not config_xml:
        return None
    firewall = _firewall(snapshot)
    try:
        host = await matching_host(snapshot)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: inventory lookup for the config backup failed: %s", type(exc).__name__)
        host = None
        _warn(snapshot, info_warning("config", "/" + PATH_CONFIG, "config.xml was not stored: see the server log"))
        return None
    if host is None:
        _warn(snapshot, info_warning("config", "/" + PATH_CONFIG, NOT_IMPORTED_MESSAGE))
        if firewall is not None:
            _add(
                firewall["sections"],
                kv_section(SECTION_CONFIG_BACKUP, [("Result", "Not stored: import the firewall into the inventory")]),
            )
        return {"stored": False, "host_id": None}
    try:
        stored = await store_device_config(
            int(host["id"]),
            config_xml,
            "",
            capture_method=CAPTURE_METHOD,
            device_type=str(host.get("device_type") or ""),
        )
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: config backup of host %s not stored: %s", host.get("id"), type(exc).__name__)
        _warn(snapshot, info_warning("config", "/" + PATH_CONFIG, "config.xml was not stored: see the server log"))
        return {"stored": False, "host_id": host.get("id")}
    if firewall is not None:
        _add(
            firewall["sections"],
            kv_section(
                SECTION_CONFIG_BACKUP,
                [
                    ("Result", "New backup stored" if stored.created else "Unchanged since the newest backup"),
                    ("Inventory host", host.get("hostname") or host.get("ip_address")),
                    ("Backup ID", stored.backup_id),
                    ("Source", "config.xml over the OPNsense API"),
                ],
            ),
        )
    return {"stored": True, "created": stored.created, "backup_id": stored.backup_id, "host_id": host.get("id")}


def firewall_device_key(snapshot: dict, org_ref: int) -> str:
    """The software tracker's key of the snapshot's firewall (``""`` when it
    reports no version)."""
    device = next((d for d in snapshot_devices(snapshot, PROVIDER) if d["kind"] == "appliance"), None)
    return snapshot_device_key(PROVIDER, org_ref, device) if device else ""


async def sync_audit_advisories(raw: dict, snapshot: dict, org_ref: int) -> dict[str, int] | None:
    """Bring the ``opnsense-audit`` advisories up to date with this
    firewall's audit. ``None`` when the audit did not run or did not
    verifiably complete (nothing is changed then)."""
    audit = raw.get("audit")
    version = canonical_version((snapshot.get("summary") or {}).get("version"))
    if not isinstance(audit, dict) or not audit.get("completed") or not version:
        return None
    device_key = firewall_device_key(snapshot, org_ref)
    if not device_key:
        return None
    found = audit_advisories(audit, version)
    current = {a["advisory_id"] for a in found}
    upserted = withdrawn = 0
    for advisory in found:
        existing = await db.get_software_advisory(advisory["advisory_id"])
        if existing:
            # An administrator's severity and enabled switch are kept.
            advisory["severity"] = existing.get("severity") or advisory["severity"]
        # Merged into the firewalls already on the advisory.
        await db.upsert_software_advisory({**advisory, "device_keys": [device_key]}, merge_lists=True)
        upserted += 1
    for existing in await db.list_software_advisories():
        if existing.get("source") != ADVISORY_SOURCE or existing["advisory_id"] in current:
            continue
        devices = list(existing.get("device_keys") or [])
        if devices:
            if device_key not in devices:
                continue  # found on other firewalls only
            devices.remove(device_key)
            update = {**existing, "device_keys": devices}
            if not devices:
                # No firewall reports it any more: it must match nothing (an
                # empty device list alone would mean every firewall).
                update["affected_versions"] = []
            await db.upsert_software_advisory(update)
            withdrawn += 1
            continue
        # Stored before advisories were limited to their firewalls: taken
        # off by version, as then; a firewall that still reports it adds it
        # back limited to itself.
        versions = list(existing.get("affected_versions") or [])
        if version not in versions:
            continue
        versions.remove(version)
        await db.upsert_software_advisory({**existing, "affected_versions": versions})
        withdrawn += 1
    return {"upserted": upserted, "withdrawn": withdrawn}


def _lease_server_name(snapshot: dict, raw: dict) -> str:
    name = str((snapshot.get("org") or {}).get("name") or (raw.get("firewall") or {}).get("name") or "").strip()
    return f"{name or 'OPNsense firewall'} (OPNsense)"


async def _lease_server(snapshot: dict, raw: dict) -> dict | None:
    """The ``dhcp_servers`` row (provider ``opnsense``) that holds this
    firewall's leases, matched by the firewall's API address and created on
    first use; renamed when the source is. ``None`` when the firewall has
    no address."""
    base_url = str((raw.get("firewall") or {}).get("base_url") or "").strip()
    if not base_url:
        return None
    name = _lease_server_name(snapshot, raw)
    servers = await db.list_dhcp_servers()
    server = next(
        (s for s in servers if s.get("provider") == DHCP_PROVIDER_OPNSENSE and s.get("base_url") == base_url), None
    )
    if server is None:
        return await db.create_dhcp_server(
            provider=DHCP_PROVIDER_OPNSENSE,
            name=name,
            base_url=base_url,
            auth_type="none",
            notes=LEASE_SERVER_NOTES,
            created_by="opnsense-collection",
        )
    if server.get("name") != name:
        server = await db.update_dhcp_server(int(server["id"]), name=name) or server
    return server


async def _store_neighbours(entries: list[dict], snapshot: dict) -> tuple[str, dict | None]:
    """ARP and NDP entries into MAC tracking's ``arp_table`` of the
    firewall's inventory host. Answers the section text and the host."""
    host = await matching_host(snapshot)
    if host is None:
        _warn(snapshot, info_warning("clients", "/" + PATH_ARP[0], CLIENTS_NOT_IMPORTED_MESSAGE))
        return "Not stored: import the firewall into the inventory", None
    stored = await db.upsert_arp_entries_batch(
        int(host["id"]),
        [
            {"ip_address": e["ip_address"], "mac_address": e["mac_address"], "interface_name": e["interface_name"]}
            for e in entries
        ],
    )
    return f"{stored} entries stored for {host.get('hostname') or host.get('ip_address')}", host


async def sync_clients(raw: dict, snapshot: dict) -> dict[str, Any] | None:
    """Feed the collected ARP / NDP tables into MAC tracking (the
    ``arp_table`` of the firewall's inventory host, enriching MAC table rows
    with their IP) and the DHCP leases into the firewall's ``opnsense`` DHCP
    server, whose leases are replaced by this collection's. ``None`` when
    the clients part was not collected."""
    clients = raw.get("clients")
    if not isinstance(clients, dict):
        return None
    result: dict[str, Any] = {"arp_stored": None, "leases_stored": None}
    rows: list[tuple[str, Any]] = []
    counts = client_counts(clients)
    rows += [("ARP entries", counts["arp"]), ("NDP entries", counts["ndp"])]
    rows += [(f"Leases ({name})", n) for name, n in counts["lease_backends"].items()]

    neighbours = arp_entries(clients) + ndp_entries(clients)
    if clients.get("arp") is not None or clients.get("ndp") is not None:
        try:
            text, host = await _store_neighbours(neighbours, snapshot)
            result["arp_stored"] = len(neighbours) if host else 0
        except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
            LOGGER.warning("opnsense: ARP/NDP entries not stored: %s", type(exc).__name__)
            text = "Not stored: see the server log"
        rows.append(("MAC tracking", text))

    if clients.get("leases") is not None:
        leases = dhcp_leases(clients, raw.get("interfaces"))
        try:
            server = await _lease_server(snapshot, raw)
            if server is None:
                text = "Not stored: the firewall has no address"
            elif not server.get("enabled"):
                text = f"Not stored: DHCP server '{server.get('name')}' is disabled in IPAM"
            else:
                stored = await db.replace_dhcp_server_snapshot(
                    int(server["id"]),
                    scopes=[],
                    leases=leases,
                    sync_status="success",
                    sync_message=f"OPNsense collection: {len(leases)} leases",
                )
                result["leases_stored"] = stored["leases"]
                result["dhcp_server_id"] = server["id"]
                text = f"{stored['leases']} leases in DHCP server '{server.get('name')}'"
        except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
            LOGGER.warning("opnsense: DHCP leases not stored: %s", type(exc).__name__)
            text = "Not stored: see the server log"
        rows.append(("IPAM DHCP leases", text))

    firewall = _firewall(snapshot)
    if firewall is not None:
        _add(firewall["sections"], kv_section(SECTION_CLIENTS, [*rows, ("Source", "OPNsense API")]))
    return result


async def after_collection(raw: dict, snapshot: dict, org_ref: int) -> None:
    """Store the config backup, sync the audit advisories, feed the ARP
    / NDP tables and DHCP leases into MAC tracking and IPAM and store the
    routing table as the route capture, for one collection of source
    ``org_ref``. Never raises."""
    try:
        if (raw.get("options") or {}).get("config_backup", True):
            await store_config_backup(raw, snapshot)
    finally:
        # Whatever happened above, the XML never outlives this call.
        raw.pop("config_xml", None)
    try:
        await sync_audit_advisories(raw, snapshot, org_ref)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: audit advisories not synced: %s", type(exc).__name__)
    try:
        await sync_clients(raw, snapshot)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: clients not synced: %s", type(exc).__name__)
    try:
        await attach_rule_stats(raw, snapshot)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: rule counters not kept: %s", type(exc).__name__)
    try:
        await store_route_capture(raw, snapshot)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: route capture not stored: %s", type(exc).__name__)
    try:
        await store_alias_tables(raw, snapshot)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: alias tables not stored: %s", type(exc).__name__)
    try:
        # Imported here: opnsense_netflow imports this module's helpers.
        from netcontrol.routes.opnsense_netflow import sync_flow_export

        await sync_flow_export(raw, snapshot)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: flow export state not stored: %s", type(exc).__name__)
    try:
        await note_health_host(raw, snapshot, org_ref)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: health host not noted: %s", type(exc).__name__)
    try:
        # Imported here: opnsense_ids imports this module's helpers.
        from netcontrol.routes.opnsense_ids import store_collected

        if "ids_alerts" in raw:
            await store_collected(raw, snapshot, org_ref, await matching_host(snapshot))
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: IDS alerts not stored: %s", type(exc).__name__)
    finally:
        # The alerts are stored as security events, never in the snapshot.
        raw.pop("ids_alerts", None)
        raw.pop("ids_state", None)


async def note_health_host(raw: dict, snapshot: dict, org_ref: int) -> dict | None:
    """Note the firewall's inventory host for the monitoring poll, which
    reads the health of that host over this source's API
    (``netcontrol.routes.opnsense_health``), and say in the firewall's
    "Health" section where the numbers are kept. Returns the host."""
    # Imported here: opnsense_health is imported by the monitoring routes.
    from netcontrol.routes.opnsense_health import record_inventory_host

    host = await matching_host(snapshot)
    record_inventory_host(snapshot, org_ref, host)
    firewall = _firewall(snapshot)
    section = next(
        (s for s in (firewall or {}).get("sections") or [] if s.get("title") == SECTION_HEALTH and s.get("rows")),
        None,
    )
    if section is not None and isinstance(raw.get("health"), dict):
        text = (
            f"CPU, memory, disks, temperature and state table stored with the monitoring poll of "
            f"{host.get('hostname') or host.get('ip_address')}"
            if host
            else "Shown here only: import the firewall into the inventory to store and alert on it"
        )
        section["rows"].insert(len(section["rows"]) - 1, ["History", text])
    return host


def live_interfaces(rows: Any) -> list[LiveInterface]:
    """``(key, device, addresses)`` of each collected interface row."""
    if not isinstance(rows, list):
        return []
    return [
        (str(row.get("identifier") or ""), str(row.get("device") or ""), interface_addresses(row))
        for row in rows
        if isinstance(row, dict)
    ]


async def store_route_capture(raw: dict, snapshot: dict) -> dict[str, Any] | None:
    """Store the collected routing table and the live interface addresses
    as the route capture of the firewall's inventory host (a
    ``route_snapshots`` row, written only when the text changed; see
    ``netcontrol.integrations.pathtrace.opnsense_routes``), where the path
    trace reads them. ``None`` when the routing table was not read (the
    option is off or the call failed): nothing is stored then, and the
    trace keeps the host's previous capture, or config.xml alone."""
    routes = raw.get("routes")
    if not isinstance(routes, list) or not routes:
        return None
    text, count = capture_text(routes, live_interfaces(raw.get("interfaces")))
    result: dict[str, Any] = {"stored": False, "host_id": None}
    rows: list[tuple[str, Any]] = []
    try:
        host = await matching_host(snapshot)
        if host is None:
            rows.append(("Result", "Not stored: import the firewall into the inventory"))
        else:
            written, _previous = await store_route_snapshot(int(host["id"]), text, count)
            result = {"stored": True, "created": written, "host_id": host.get("id")}
            rows += [
                ("Result", "New capture stored" if written else "Unchanged since the newest capture"),
                ("Inventory host", host.get("hostname") or host.get("ip_address")),
            ]
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: route capture not stored: %s", type(exc).__name__)
        rows.append(("Result", "Not stored: see the server log"))
    rows += [("Routes", count), ("Source", "Routing table and interface addresses over the OPNsense API")]
    firewall = _firewall(snapshot)
    if firewall is not None:
        _add(firewall["sections"], kv_section(SECTION_ROUTE_CAPTURE, rows))
    return result


async def attach_rule_stats(raw: dict, snapshot: dict) -> dict | None:
    """Keep the filter rule counters of the collection in the snapshot
    (``rule_stats``: the inventory host they belong to, when they were read
    and the counters by rule uuid), where the rule views of that host read
    them. ``None`` when the counters were not read."""
    stats = parse_rule_stats(raw.get("rule_stats")) if isinstance(raw.get("rule_stats"), dict) else None
    if stats is None:
        return None
    host = await matching_host(snapshot)
    snapshot["rule_stats"] = {
        "host_id": int(host["id"]) if host else None,
        "collected_at": raw.get("timestamp"),
        "rules": stats,
    }
    return snapshot["rule_stats"]


def _utc_text(iso: Any) -> str:
    """``YYYY-MM-DD HH:MM:SS`` (UTC) of an ISO timestamp, now when it is none."""
    try:
        moment = datetime.fromisoformat(str(iso))
    except TypeError, ValueError:
        moment = datetime.now(UTC)
    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC)
    return moment.strftime("%Y-%m-%d %H:%M:%S")


async def store_alias_tables(raw: dict, snapshot: dict) -> dict[str, Any] | None:
    """Replace the alias tables of the firewall's inventory host with the
    ones the collection read (``alias_tables``, popped from ``raw``: it is
    never part of the snapshot). ``None`` when none were read: the stored
    ones stay, as the route capture does."""
    found = raw.pop("alias_tables", None)
    if not isinstance(found, dict):
        return None
    tables = [t for t in found.get("tables") or [] if isinstance(t, dict)]
    rows: list[tuple[str, Any]] = []
    result: dict[str, Any] = {"stored": False, "host_id": None}
    try:
        host = await matching_host(snapshot)
        if host is None:
            rows.append(("Result", "Not stored: import the firewall into the inventory"))
        else:
            stored = await db.replace_opnsense_alias_tables(int(host["id"]), tables, _utc_text(found.get("read_at")))
            result = {"stored": True, "tables": stored, "host_id": host.get("id")}
            rows += [
                ("Result", f"{stored} tables stored for the path trace"),
                ("Inventory host", host.get("hostname") or host.get("ip_address")),
            ]
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: alias tables not stored: %s", type(exc).__name__)
        rows.append(("Result", "Not stored: see the server log"))
    rows.append(("Entries", sum(len(t.get("entries") or []) for t in tables)))
    cut = [str(t.get("name")) for t in tables if t.get("truncated")]
    if cut:
        rows.append(("Truncated", ", ".join(cut)))
    for key, label in (("skipped", "Never read (too large)"), ("not_read", "Not read (limit)")):
        if found.get(key):
            rows.append((label, ", ".join(str(n) for n in found[key])))
    rows.append(("Source", "pf tables over the OPNsense API (firewall/alias_util)"))
    firewall = _firewall(snapshot)
    if firewall is not None:
        _add(firewall["sections"], kv_section(SECTION_ALIAS_TABLES, rows))
    return result
