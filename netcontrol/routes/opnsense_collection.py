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
    repeated collections update rather than duplicate them. A finding the
    audit no longer reports has the version taken off its advisory, so its
    alert resolves. The software refresh that follows every stored
    collection matches them to the tracked firewall and raises
    ``software_alerts`` the normal way.

Both are best-effort: a failure is logged and noted in the snapshot, and
the collection is stored anyway.
"""

from __future__ import annotations

from typing import Any

import routes.database as db

from netcontrol.integrations.inventory_import import importable_devices
from netcontrol.integrations.meraki.normalize import _add, kv_section
from netcontrol.integrations.opnsense.collector import PATH_CONFIG, info_warning
from netcontrol.integrations.opnsense.normalize import (
    ADVISORY_SOURCE,
    DEVICE_NODE_PREFIX,
    PROVIDER,
    audit_advisories,
)
from netcontrol.integrations.software.versions import canonical_version
from netcontrol.routes.device_config import store_device_config
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.opnsense")

CAPTURE_METHOD = "opnsense-api"
SECTION_CONFIG_BACKUP = "Config backup"
NOT_IMPORTED_MESSAGE = (
    "config.xml was read but not stored: this firewall is not an inventory host yet. "
    "Import it into the inventory (Map sources, Import devices) to keep its configuration backups."
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


async def sync_audit_advisories(raw: dict, snapshot: dict) -> dict[str, int] | None:
    """Bring the ``opnsense-audit`` advisories up to date with this
    firewall's audit. ``None`` when the audit did not run (nothing is
    changed then)."""
    audit = raw.get("audit")
    version = canonical_version((snapshot.get("summary") or {}).get("version"))
    if not isinstance(audit, dict) or not version:
        return None
    found = audit_advisories(audit, version)
    current = {a["advisory_id"] for a in found}
    upserted = withdrawn = 0
    for advisory in found:
        existing = await db.get_software_advisory(advisory["advisory_id"])
        if existing:
            # An administrator's severity and enabled switch are kept.
            advisory["severity"] = existing.get("severity") or advisory["severity"]
        await db.upsert_software_advisory(advisory, merge_lists=True)
        upserted += 1
    for existing in await db.list_software_advisories():
        if existing.get("source") != ADVISORY_SOURCE or existing["advisory_id"] in current:
            continue
        versions = list(existing.get("affected_versions") or [])
        if version not in versions:
            continue
        versions.remove(version)
        await db.upsert_software_advisory({**existing, "affected_versions": versions})
        withdrawn += 1
    return {"upserted": upserted, "withdrawn": withdrawn}


async def after_collection(raw: dict, snapshot: dict) -> None:
    """Store the config backup and sync the audit advisories of one
    collection. Never raises."""
    try:
        if (raw.get("options") or {}).get("config_backup", True):
            await store_config_backup(raw, snapshot)
    finally:
        # Whatever happened above, the XML never outlives this call.
        raw.pop("config_xml", None)
    try:
        await sync_audit_advisories(raw, snapshot)
    except Exception as exc:  # noqa: BLE001 - the snapshot is stored anyway
        LOGGER.warning("opnsense: audit advisories not synced: %s", type(exc).__name__)
