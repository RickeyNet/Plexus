"""Plexus as a sync adapter.

Reads Plexus's own records into the canonical shape and writes planned
entries back through the same code paths people use, so the audit trail,
the change log, webhooks and the data validation rules apply to synced
changes too:

- VRFs, VLANs, prefixes, IP addresses and devices (hosts) go through the
  bulk import pipeline (``netcontrol.bulk_import``): its plan checks
  references, the field rules and the admin validation rules, and its
  adapters write through the ``routes.database`` facade
  (``@tracks_changes``). Prefixes and addresses are those of the built-in
  IPAM source. A device created by a sync is put in the job's host group
  (created on the first real run; default ``Synced``).
- Sites, manufacturers and device types are written with the facade
  helpers of the Organization and device catalogue APIs.
- Deletes call the facade delete of each type.

A dry run plans the bulk-import types too and puts what Plexus would refuse
in the entry's message; nothing is written. Objects the same run would
create earlier (a VRF before its prefixes) are not there yet in a dry run,
so such references show up in those messages.
"""

from __future__ import annotations

import json
from typing import Any

import routes.database as db

from netcontrol import bulk_import
from netcontrol.device_model import MANUFACTURER_NAME_MAX, MODEL_MAX, PART_NUMBER_MAX, U_HEIGHT_MAX
from netcontrol.object_scope import UNRESTRICTED
from netcontrol.organization import OrganizationValueError, clean_site_status
from netcontrol.sync.adapters.base import SyncAdapter
from netcontrol.sync.engine import Entry
from netcontrol.sync.models import OBJECT_SPECS, SyncRecord, make_record, spec_for

DEFAULT_HOST_GROUP = "Synced"
GROUP_SEPARATOR = " / "

# Canonical field -> bulk import column, per object type written through
# the bulk import pipeline; with the bulk import type and match key.
_BULK: dict[str, tuple[str, str, dict[str, str]]] = {
    "vrfs": ("vrfs", "name", {"name": "name", "rd": "rd", "description": "description"}),
    "vlans": ("vlans", "vid", {"vid": "vid", "site": "site", "name": "name", "description": "description"}),
    "prefixes": (
        "prefixes",
        "prefix",
        {"prefix": "prefix", "vrf": "vrf", "description": "description", "site": "site", "vlan": "vlan"},
    ),
    "ip_addresses": (
        "addresses",
        "address",
        {"address": "address", "prefix": "prefix", "vrf": "vrf", "dns_name": "dns_name", "description": "description"},
    ),
    "devices": (
        "hosts",
        "hostname",
        {
            "name": "hostname",
            "primary_ip": "ip_address",
            "site": "site",
            "manufacturer": "manufacturer",
            "device_type": "device_type",
            "role": "role",
            "platform": "platform",
        },
    ),
}

# Fields Plexus holds but a sync does not write (a device's serial number
# is read from the device itself).
_READ_ONLY: dict[str, set[str]] = {"devices": {"serial"}}


def _group_names(path: str) -> list[str]:
    return [part.strip() for part in path.split(GROUP_SEPARATOR.strip()) if part.strip()]


class PlexusAdapter(SyncAdapter):
    name = "plexus"
    label = "Plexus"

    def __init__(self, *, user: str, dry_run: bool, host_group: str = DEFAULT_HOST_GROUP) -> None:
        self.user = user or "system"
        self.dry_run = dry_run
        self.host_group = GROUP_SEPARATOR.join(_group_names(host_group or DEFAULT_HOST_GROUP)) or DEFAULT_HOST_GROUP

    def supports(self, object_type: str) -> bool:
        return object_type in OBJECT_SPECS

    def fields(self, object_type: str) -> tuple[str, ...]:
        return spec_for(object_type).fields

    def writable(self, object_type: str) -> set[str]:
        return set(spec_for(object_type).fields) - _READ_ONLY.get(object_type, set())

    # ── Reading ──

    async def load(self, object_type: str) -> list[SyncRecord]:
        loader = getattr(self, f"_load_{object_type}")
        rows: list[tuple[dict[str, Any], Any]] = await loader()
        return [make_record(object_type, values, ref) for values, ref in rows]

    async def _load_sites(self) -> list[tuple[dict, Any]]:
        return [
            (
                {
                    "name": s["name"],
                    "description": s.get("description"),
                    "status": s.get("status") or "active",
                    "address": s.get("address"),
                    "latitude": s.get("lat"),
                    "longitude": s.get("lng"),
                },
                int(s["id"]),
            )
            for s in await db.list_geo_sites()
        ]

    async def _load_manufacturers(self) -> list[tuple[dict, Any]]:
        return [(m, int(m["id"])) for m in await db.list_manufacturers()]

    async def _load_device_types(self) -> list[tuple[dict, Any]]:
        return [(d, int(d["id"])) for d in await db.list_device_types()]

    async def _load_vrfs(self) -> list[tuple[dict, Any]]:
        return [(v, int(v["id"])) for v in await db.list_vrfs()]

    async def _load_vlans(self) -> list[tuple[dict, Any]]:
        return [({**v, "site": (v.get("site") or {}).get("name", "")}, int(v["id"])) for v in await db.list_vlans()]

    async def _builtin_source_id(self) -> int:
        return int((await db.get_or_create_builtin_ipam_source())["id"])

    async def _load_prefixes(self) -> list[tuple[dict, Any]]:
        source_id = await self._builtin_source_id()
        return [
            ({**r, "prefix": r["subnet"]}, int(r["id"]))
            for r in await db.list_ipam_prefix_records()
            if int(r["source_id"]) == source_id
        ]

    async def _load_ip_addresses(self) -> list[tuple[dict, Any]]:
        source_id = await self._builtin_source_id()
        return [
            ({**a, "prefix": a.get("prefix_subnet"), "vrf": a.get("vrf_name")}, int(a["id"]))
            for a in await db.list_ipam_allocation_records()
            if int(a["source_id"]) == source_id
        ]

    async def _load_devices(self) -> list[tuple[dict, Any]]:
        types = {int(d["id"]): d for d in await db.list_device_types()}
        roles = {int(r["id"]): r["name"] for r in await db.list_device_roles()}
        sites = {int(s["id"]): s["name"] for s in await db.list_geo_sites()}
        out = []
        for h in await db.get_all_hosts():
            dtype = types.get(int(h["device_type_id"])) if h.get("device_type_id") is not None else None
            out.append(
                (
                    {
                        "name": h["hostname"],
                        "primary_ip": h.get("ip_address"),
                        "site": sites.get(int(h["site_id"]), "") if h.get("site_id") is not None else "",
                        "manufacturer": dtype["manufacturer"] if dtype else "",
                        "device_type": dtype["model"] if dtype else "",
                        "role": roles.get(int(h["role_id"]), "") if h.get("role_id") is not None else "",
                        "platform": h.get("device_type"),
                        "serial": h.get("serial_number"),
                    },
                    int(h["id"]),
                )
            )
        return out

    # ── Writing ──

    async def apply(self, object_type: str, entries: list[Entry]) -> None:
        writes = [e for e in entries if e.action in ("create", "update") and e.outcome == "planned"]
        deletes = [e for e in entries if e.action == "delete" and e.outcome == "planned"]
        if object_type in _BULK:
            await self._apply_bulk(object_type, writes)
        else:
            for entry in writes:
                await self._apply_catalogue(object_type, entry)
        for entry in deletes:
            await self._delete(object_type, entry)

    async def _apply_bulk(self, object_type: str, entries: list[Entry]) -> None:
        if not entries:
            return
        bulk_type, match_key, columns = _BULK[object_type]
        group_ready = True
        if object_type == "devices" and any(e.action == "create" for e in entries):
            names = _group_names(self.host_group)
            if self.dry_run:
                group_ready = any(g.get("path") == self.host_group for g in await db.get_all_groups())
            else:
                await db.get_or_create_group_path(names)
        for start in range(0, len(entries), bulk_import.MAX_IMPORT_ROWS):
            batch = entries[start : start + bulk_import.MAX_IMPORT_ROWS]
            rows = []
            for entry in batch:
                row = {columns[k]: v for k, v in entry.values.items() if k in columns}
                if object_type == "devices" and entry.action == "create" and group_ready:
                    row["group"] = self.host_group
                rows.append(row)
            text = json.dumps(rows)
            options: dict[str, Any] = {
                "mode": "upsert",
                "match_key": match_key,
                "scope": UNRESTRICTED,
                "user": self.user,
            }
            if self.dry_run:
                report, _adapter, _ctx = await bulk_import.plan_import(bulk_type, text, "json", **options)
            else:
                report = await bulk_import.commit_import(
                    bulk_type, text, "json", atomic=False, stop_at_error=False, **options
                )
            for entry, res in zip(batch, report.rows, strict=False):
                errors = [e for e in res.errors if group_ready or e.get("field") != "group"]
                problems = "; ".join(
                    f"{e['field']}: {e['message']}" if e.get("field") else str(e["message"]) for e in errors
                )
                if self.dry_run:
                    if problems:
                        entry.message = f"Plexus would refuse this now: {problems}"
                    elif not group_ready and entry.action == "create":
                        entry.message = f"Host group {self.host_group!r} is created on the first real run."
                elif res.action == "error":
                    entry.failed(problems or "Plexus refused the change.")
                else:
                    entry.applied("No change needed." if res.action == "skip" else "")

    async def _apply_catalogue(self, object_type: str, entry: Entry) -> None:
        try:
            problem = await self._check_catalogue(object_type, entry)
            if problem:
                if self.dry_run:
                    entry.message = f"Plexus would refuse this now: {problem}"
                else:
                    entry.failed(problem)
                return
            if self.dry_run:
                return
            await getattr(self, f"_write_{object_type}")(entry)
        except ValueError as exc:
            entry.failed(str(exc))
            return
        except Exception as exc:  # a database refusal is that entry's outcome
            entry.failed(f"Plexus refused the change ({type(exc).__name__}).")
            return
        entry.applied()

    async def _check_catalogue(self, object_type: str, entry: Entry) -> str:
        v = entry.values
        if object_type == "sites":
            if "status" in v and v["status"]:
                try:
                    clean_site_status(v["status"])
                except OrganizationValueError as exc:
                    return str(exc)
            for name in ("latitude", "longitude"):
                if v.get(name):
                    try:
                        float(v[name])
                    except ValueError:
                        return f"{name}: {v[name]!r} is not a number."
        if object_type == "manufacturers" and len(v.get("name", "")) > MANUFACTURER_NAME_MAX:
            return f"name: at most {MANUFACTURER_NAME_MAX} characters."
        if object_type == "device_types":
            if len(v.get("model", "")) > MODEL_MAX or len(v.get("part_number", "")) > PART_NUMBER_MAX:
                return f"model / part number: at most {MODEL_MAX} characters."
            height = v.get("u_height", "")
            if height and (not height.isdigit() or int(height) > U_HEIGHT_MAX):
                return f"u_height: a whole number up to {U_HEIGHT_MAX}."
            if entry.action == "create" and await self._manufacturer_id(v.get("manufacturer", "")) is None:
                return f"No manufacturer {v.get('manufacturer', '')!r} in Plexus; sync manufacturers first."
        return ""

    async def _manufacturer_id(self, name: str) -> int | None:
        for m in await db.list_manufacturers():
            if m["name"].lower() == name.lower():
                return int(m["id"])
        return None

    async def _write_sites(self, entry: Entry) -> None:
        v = entry.values
        fields: dict[str, Any] = {}
        for name, column in (("description", "description"), ("address", "address")):
            if name in v:
                fields[column] = v[name]
        for name, column in (("latitude", "lat"), ("longitude", "lng")):
            if name in v:
                fields[column] = float(v[name]) if v[name] else None
        if "status" in v:
            fields["status"] = clean_site_status(v["status"] or "active")
        if entry.action == "create":
            await db.create_geo_site(name=v["name"], created_by=self.user, **fields)
        elif fields:
            await db.update_geo_site(int(entry.ref), **fields)

    async def _write_manufacturers(self, entry: Entry) -> None:
        v = entry.values
        if entry.action == "create":
            await db.create_manufacturer(name=v["name"], description=v.get("description", ""))
            return
        current = await db.get_manufacturer(int(entry.ref))
        if current is None:
            raise ValueError("The manufacturer no longer exists in Plexus.")
        await db.update_manufacturer(
            int(entry.ref), name=current["name"], description=v.get("description", current["description"])
        )

    async def _write_device_types(self, entry: Entry) -> None:
        v = entry.values
        height = int(v["u_height"]) if v.get("u_height", "").isdigit() else 0
        if entry.action == "create":
            manufacturer_id = await self._manufacturer_id(v["manufacturer"])
            if manufacturer_id is None:
                raise ValueError(f"No manufacturer {v['manufacturer']!r} in Plexus.")
            await db.create_device_type(
                manufacturer_id=manufacturer_id,
                model=v["model"],
                part_number=v.get("part_number", ""),
                u_height=height,
                description=v.get("description", ""),
            )
            return
        current = await db.get_device_type(int(entry.ref))
        if current is None:
            raise ValueError("The device type no longer exists in Plexus.")
        await db.update_device_type(
            int(entry.ref),
            manufacturer_id=int(current["manufacturer_id"]),
            model=current["model"],
            part_number=v.get("part_number", current["part_number"]),
            u_height=height if "u_height" in v else int(current["u_height"]),
            description=v.get("description", current["description"]),
        )

    async def _delete(self, object_type: str, entry: Entry) -> None:
        if self.dry_run:
            return
        ref = int(entry.ref)
        try:
            if object_type == "sites":
                await db.delete_geo_site(ref)
            elif object_type == "manufacturers":
                await db.delete_catalogue_record("manufacturer", ref)
            elif object_type == "device_types":
                await db.delete_catalogue_record("device_type", ref)
            elif object_type == "vrfs":
                await db.delete_vrf(ref)
            elif object_type == "vlans":
                await db.delete_vlan(ref)
            elif object_type == "prefixes":
                await db.delete_ipam_prefix(ref)
            elif object_type == "ip_addresses":
                await db.delete_ipam_allocation(ref)
            elif object_type == "devices":
                await db.remove_host(ref)
        except Exception as exc:  # a refused delete (record in use) is that entry's outcome
            entry.failed(f"Plexus refused the delete ({type(exc).__name__}).")
            return
        entry.applied()
