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

All are best-effort: a failure is logged and noted in the snapshot, and
the collection is stored anyway.
"""

from __future__ import annotations

from typing import Any

import routes.database as db

from netcontrol.integrations.inventory_import import importable_devices
from netcontrol.integrations.meraki.normalize import _add, kv_section
from netcontrol.integrations.opnsense.collector import PATH_ARP, PATH_CONFIG, info_warning
from netcontrol.integrations.opnsense.normalize import (
    ADVISORY_SOURCE,
    DEVICE_NODE_PREFIX,
    PROVIDER,
    arp_entries,
    audit_advisories,
    client_counts,
    dhcp_leases,
    ndp_entries,
)
from netcontrol.integrations.opnsense.rules import parse_rule_stats
from netcontrol.integrations.software.versions import canonical_version, snapshot_device_key, snapshot_devices
from netcontrol.routes.device_config import store_device_config
from netcontrol.routes.dhcp_adapters import DHCP_PROVIDER_OPNSENSE
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


async def matching_host(snapshot: dict) -> dict | None:
    """The inventory host that is the snapshot's firewall, or ``None``."""
    firewall = _firewall(snapshot)
    if firewall is None:
        return None
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
    """Store the config backup, sync the audit advisories and feed the ARP
    / NDP tables and DHCP leases into MAC tracking and IPAM, for one
    collection of source ``org_ref``. Never raises."""
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
