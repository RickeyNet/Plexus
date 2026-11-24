"""
opnsense_collection.py -- What an OPNsense collection stores besides its snapshot.

Called by the source build (``netcontrol.routes.meraki_topology``) after an
OPNsense firewall was collected and its snapshot built, before the snapshot
is stored:

  - ``store_config_backup``: the ``config.xml`` the collection downloaded
    becomes a configuration backup of the inventory host that is this
    firewall, through the store a backup policy run uses too
    (``netcontrol.routes.opnsense_backup.store_firewall_backup``, over
    ``device_config.store_device_config``: an unchanged configuration
    writes no new row, it re-checks the newest one). The
    firewall is matched to its host the way the device import matches it
    (``netcontrol.integrations.inventory_import.importable_devices``: the
    host with its address, or the one the collection matched it to). When
    the firewall is no inventory host yet, nothing is stored and the
    snapshot gets a warning that says to import it first. A new backup is
    compared with the one before it for rules that became any-to-any or
    shadowed, which raise alerts (``opnsense_rule_alerts``). The XML holds
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

  - ``note_software_lifecycle``: the end-of-life status of the firewall's
    release series is evaluated again with the administrator's
    end-of-life entries (an entry for ``opnsense`` and the series overrides
    the built-in estimate the snapshot was built with), so the "Series
    status" row and the end-of-life warning say what the software tracker
    says.

  - ``sync_clients``: the ARP and NDP tables go into MAC tracking as the
    ``arp_table`` of the firewall's inventory host (matched as for the
    config backup; skipped with a warning when there is none), which also
    stamps the IP onto MAC table rows of other hosts that lack one. The
    DHCP leases (ISC, Kea, Dnsmasq) replace the leases of the firewall's
    ``dhcp_servers`` row (provider ``opnsense``, matched by the firewall's
    API address and created on first use), so they show in IPAM's DHCP
    servers, lease listing and inventory correlation. The firewall's
    "Clients" section says what was stored.
  - ``store_names``: the Unbound host overrides, Dnsmasq hosts, ISC static
    mappings and Kea reservations config.xml holds (``names``, popped from
    the raw collection; see ``netcontrol.integrations.opnsense.names``)
    replace the allocations of the firewall's IPAM source (provider
    ``opnsense``, matched by the API address like the DHCP server, created
    once there is something to store), one per address under the firewall
    subnet that holds it, so they show in the subnet drill-down and are
    never handed out by next-IP allocation. The "Names and reservations"
    section says what was stored.
  - ``attach_rule_stats``: the filter rule counters (``rule_stats``) stay
    in the snapshot with the inventory host they belong to, for the rule
    views (``netcontrol.routes.opnsense_rules``), and are added to that
    host's counter history (``store_rule_counters``:
    ``opnsense_rule_counters``, which survives counter resets and tells a
    rule unused for 90 days); the "Rule counters" section says so.
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

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import routes.database as db

from netcontrol.integrations.inventory_import import importable_devices
from netcontrol.integrations.meraki.normalize import _add, kv_section
from netcontrol.integrations.meraki.subnets import subnet_index, subnets_containing
from netcontrol.integrations.opnsense.collector import PATH_ARP, PATH_CONFIG, info_warning
from netcontrol.integrations.opnsense.names import ORIGINS, STATUS_RESERVED, ipam_allocations
from netcontrol.integrations.opnsense.normalize import (
    ADVISORY_SOURCE,
    DEVICE_NODE_PREFIX,
    PROVIDER,
    SECTION_HEALTH,
    apply_series_status,
    arp_entries,
    audit_advisories,
    client_counts,
    dhcp_leases,
    interface_addresses,
    ndp_entries,
)
from netcontrol.integrations.opnsense.rules import parse_rule_stats
from netcontrol.integrations.pathtrace.opnsense_routes import LiveInterface, capture_text
from netcontrol.integrations.software.lifecycle import WARN_DAYS_SETTING, evaluate, warn_days_setting
from netcontrol.integrations.software.versions import canonical_version, snapshot_device_key, snapshot_devices
from netcontrol.routes.dhcp_adapters import DHCP_PROVIDER_OPNSENSE
from netcontrol.routes.ipam_adapters import IPAM_PROVIDER_OPNSENSE
from netcontrol.routes.opnsense_backup import store_firewall_backup
from netcontrol.routes.opnsense_masking import BACKUP_CAPTURE_METHOD, OPNSENSE_DEVICE_TYPE
from netcontrol.routes.route_capture import store_route_snapshot
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.opnsense")

CAPTURE_METHOD = BACKUP_CAPTURE_METHOD
SECTION_CONFIG_BACKUP = "Config backup"
SECTION_INVENTORY_PLATFORM = "Inventory platform"
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
SECTION_RULE_COUNTERS = "Rule counters"
LEASE_SERVER_NOTES = (
    "Leases collected by the OPNsense topology source of this firewall; replaced on every collection. "
    "Disable this server to stop storing them."
)
SECTION_NAMES = "Names and reservations"
NAMES_SOURCE_NOTES = (
    "DNS names and DHCP reservations of this firewall's config.xml (Unbound host overrides, Dnsmasq hosts, "
    "ISC DHCP static mappings, Kea reservations), collected by its OPNsense topology source with the Config "
    "backup option; replaced on every collection. Disable this source to stop storing them."
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


async def store_config_backup(raw: dict, snapshot: dict, *, org_ref: int | None = None) -> dict[str, Any] | None:
    """Store the collected ``config.xml`` (popped from ``raw``) as a config
    backup of the firewall's inventory host; a new backup is checked for
    rule changes to alert on (``opnsense_rule_alerts``; ``org_ref``: the
    collecting source, whose firewall mute covers them). Returns what was
    done, or ``None`` when there was nothing to store."""
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
        backup = await store_firewall_backup(host, config_xml, capture_method=CAPTURE_METHOD, org_ref=org_ref)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: config backup of host %s not stored: %s", host.get("id"), type(exc).__name__)
        _warn(snapshot, info_warning("config", "/" + PATH_CONFIG, "config.xml was not stored: see the server log"))
        return {"stored": False, "host_id": host.get("id")}
    stored, rule_changes = backup.stored, backup.rule_changes
    rows: list[tuple[str, Any]] = [
        ("Result", "New backup stored" if stored.created else "Unchanged since the newest backup"),
        ("Inventory host", host.get("hostname") or host.get("ip_address")),
        ("Backup ID", stored.backup_id),
    ]
    if not backup.rules_checked:
        rows.append(("Rule changes", "Not checked: see the server log"))
    elif rule_changes is not None:
        # Imported here: the alert module imports the monitoring routes.
        from netcontrol.routes.opnsense_rule_alerts import summary_text

        rows.append(("Rule changes", summary_text(rule_changes)))
    rows.append(("Source", "config.xml over the OPNsense API"))
    if firewall is not None:
        _add(firewall["sections"], kv_section(SECTION_CONFIG_BACKUP, rows))
    return {
        "stored": True,
        "created": stored.created,
        "backup_id": stored.backup_id,
        "host_id": host.get("id"),
        "rule_changes": rule_changes,
    }


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
        # Merged into the firewalls already on the advisory. The upsert keeps
        # an administrator's severity, the enabled switch, and the severity,
        # CVSS score and KEV flag CVE enrichment set (the audit has none).
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


async def note_software_lifecycle(snapshot: dict) -> dict[str, Any] | None:
    """Evaluate the firewall's release series with the administrator's
    end-of-life entries and the warning window of the software settings,
    and put the result into the snapshot (``apply_series_status``).
    ``None`` when the firewall reported no version."""
    summary = snapshot.get("summary") or {}
    version = canonical_version(summary.get("version"))
    if not version:
        return None
    settings = await db.get_software_settings()
    status = evaluate(
        PROVIDER,
        version,
        datetime.now(UTC).date(),
        await db.list_software_eol_entries(),
        reported=summary.get("major_upgrade") or "",
        warn_days=warn_days_setting(settings.get(WARN_DAYS_SETTING)),
    )
    apply_series_status(snapshot, status)
    return status


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


async def _names_source(snapshot: dict, raw: dict, base_url: str, create: bool) -> dict | None:
    """The ``ipam_sources`` row (provider ``opnsense``) that holds this
    firewall's names and reservations, matched by its API address; created
    when ``create`` (there is something to store), renamed with the source.
    ``None`` when there is none."""
    name = _lease_server_name(snapshot, raw)
    sources = await db.list_ipam_sources(provider=IPAM_PROVIDER_OPNSENSE)
    source = next((s for s in sources if s.get("base_url") == base_url), None)
    if source is None:
        if not create:
            return None
        return await db.create_ipam_source(
            provider=IPAM_PROVIDER_OPNSENSE,
            name=name,
            base_url=base_url,
            auth_type="none",
            notes=NAMES_SOURCE_NOTES,
            created_by="opnsense-collection",
        )
    if source.get("name") != name:
        source = await db.update_ipam_source(int(source["id"]), name=name) or source
    return source


def _subnet_finder(snapshot: dict) -> Callable[[str], str]:
    """``address -> the firewall's connected subnet that holds it`` (the
    most specific; ``""`` for none), from the snapshot's subnet index: the
    same rows the IPAM overview lists for the firewall, so an allocation
    keyed by it shows under that subnet and counts as taken there."""
    connected = [s for s in subnet_index(snapshot) if s.get("kind") == "connected"]

    def subnet_of(address: str) -> str:
        found = subnets_containing(connected, address)
        return str(found[0]["cidr"]) if found else ""

    return subnet_of


async def store_names(raw: dict, snapshot: dict) -> dict[str, Any] | None:
    """Replace the allocations of the firewall's ``opnsense`` IPAM source
    with the DNS names and DHCP reservations config.xml holds (``names``,
    popped from ``raw``). ``None`` when they were not read (no config.xml):
    the stored ones stay."""
    found = raw.pop("names", None)
    if not isinstance(found, dict):
        return None
    records = [r for r in found.get("records") or [] if isinstance(r, dict)]
    counts: dict[str, Any] = found["counts"] if isinstance(found.get("counts"), dict) else {}
    allocations = ipam_allocations(records, _subnet_finder(snapshot))
    result: dict[str, Any] = {"stored": None, "ipam_source_id": None}
    rows: list[tuple[str, Any]] = []
    base_url = str((raw.get("firewall") or {}).get("base_url") or "").strip()
    try:
        source = await _names_source(snapshot, raw, base_url, create=bool(allocations)) if base_url else None
        if not base_url:
            text = "Not stored: the firewall has no address"
        elif source is None:
            text = "Nothing to store"
        elif not source.get("enabled"):
            text = f"Not stored: IPAM source '{source.get('name')}' is disabled"
        else:
            stored = await db.replace_ipam_source_snapshot(
                int(source["id"]),
                prefixes=[],
                allocations=allocations,
                sync_status="success",
                sync_message=f"OPNsense collection: {len(allocations)} names and reservations",
            )
            result = {"stored": stored["allocations"], "ipam_source_id": source["id"]}
            text = f"{stored['allocations']} addresses in IPAM source '{source.get('name')}'"
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: names and reservations not stored: %s", type(exc).__name__)
        text = "Not stored: see the server log"
    rows.append(("Result", text))
    rows.append(("Addresses", len(allocations)))
    rows.append(("DHCP reservations", sum(1 for a in allocations if a["status"] == STATUS_RESERVED)))
    rows += [(label, counts[key]) for key, label in ORIGINS if counts.get(key)]
    outside = sum(1 for a in allocations if not a["prefix_subnet"])
    if outside:
        rows.append(("Outside the firewall's subnets", outside))
    rows.append(("Source", "config.xml (Config backup option)"))
    firewall = _firewall(snapshot)
    if firewall is not None:
        _add(firewall["sections"], kv_section(SECTION_NAMES, rows))
    return result


async def after_collection(raw: dict, snapshot: dict, org_ref: int) -> None:
    """Store the config backup, sync the audit advisories, feed the ARP
    / NDP tables and DHCP leases into MAC tracking and IPAM and store the
    routing table as the route capture, for one collection of source
    ``org_ref``. Never raises."""
    try:
        await adopt_firewall_host(snapshot)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: platform of the inventory host not set: %s", type(exc).__name__)
    try:
        if (raw.get("options") or {}).get("config_backup", True):
            await store_config_backup(raw, snapshot, org_ref=org_ref)
    finally:
        # Whatever happened above, the XML never outlives this call.
        raw.pop("config_xml", None)
    try:
        await sync_audit_advisories(raw, snapshot, org_ref)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: audit advisories not synced: %s", type(exc).__name__)
    try:
        await note_software_lifecycle(snapshot)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: software end of life not evaluated: %s", type(exc).__name__)
    try:
        await sync_clients(raw, snapshot)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: clients not synced: %s", type(exc).__name__)
    try:
        await store_names(raw, snapshot)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: names and reservations not stored: %s", type(exc).__name__)
    finally:
        raw.pop("names", None)
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


async def adopt_firewall_host(snapshot: dict) -> dict | None:
    """Give the inventory host that is the collected firewall the OPNsense
    platform (device type), so it is backed up over this source's API and
    never read over SSH. The collection matched it by its address (or
    another address of the firewall), so whatever platform it had was a
    guess. Returns the host when its platform was changed."""
    host = await matching_host(snapshot)
    if host is None or str(host.get("device_type") or "") == OPNSENSE_DEVICE_TYPE:
        return None
    if not await db.set_host_device_type(int(host["id"]), OPNSENSE_DEVICE_TYPE):
        return None
    LOGGER.info(
        "opnsense: inventory host %s set to platform %s (was %r)",
        host["id"],
        OPNSENSE_DEVICE_TYPE,
        host.get("device_type"),
    )
    firewall = _firewall(snapshot)
    if firewall is not None:
        _add(
            firewall["sections"],
            kv_section(
                SECTION_INVENTORY_PLATFORM,
                [
                    ("Inventory host", host.get("hostname") or host.get("ip_address")),
                    ("Platform", f"Set to OPNsense (was {host.get('device_type') or 'none'})"),
                ],
            ),
        )
    return {**host, "device_type": OPNSENSE_DEVICE_TYPE}


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
    await store_rule_counters(snapshot, host, stats, raw.get("timestamp"))
    return snapshot["rule_stats"]


async def store_rule_counters(snapshot: dict, host: dict | None, stats: dict, collected_at: Any) -> dict | None:
    """Add the read counters to the counter history of the firewall's
    inventory host (``opnsense_rule_counters``, read at the collection's
    time), from which the rule views tell a rule unused for
    ``rules.UNUSED_DAYS``. Best effort: the firewall's "Rule counters"
    section says what was stored. Returns the store's answer, or ``None``."""
    result: dict | None = None
    if host is None:
        text = "Not stored: import the firewall into the inventory"
    else:
        try:
            result = await db.record_opnsense_rule_counters(int(host["id"]), stats, _utc_text(collected_at))
            text = (
                f"{result['rules']} rules added to the counter history"
                if result["rules"]
                else "Nothing stored: the firewall reported no rule counters"
            )
        except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
            LOGGER.warning("opnsense: rule counter history not stored: %s", type(exc).__name__)
            text = "Not stored: see the server log"
    rows: list[tuple[str, Any]] = [("Result", text)]
    if host is not None:
        rows.append(("Inventory host", host.get("hostname") or host.get("ip_address")))
    if result and result.get("removed"):
        rows.append(("Removed", f"{result['removed']} rules not reported for {db.RULE_COUNTER_RETENTION_DAYS} days"))
    rows.append(("Source", "Filter rule counters over the OPNsense API (firewall/filter_util)"))
    firewall = _firewall(snapshot)
    if firewall is not None:
        _add(firewall["sections"], kv_section(SECTION_RULE_COUNTERS, rows))
    return result


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
