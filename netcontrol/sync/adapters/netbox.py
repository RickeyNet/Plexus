"""NetBox and Nautobot adapters (REST, token auth).

The two APIs are close: ``/api/<app>/<model>/`` list endpoints paged with
``limit``/``offset``, ``POST`` to create, ``PATCH``/``DELETE`` on
``<endpoint>/<id>/``, nested references written as lookups
(``{"site": {"name": "branch-1"}}``). ``NetBoxFamilyAdapter`` holds all of
that; ``NetBoxAdapter`` and ``NautobotAdapter`` only differ in their default
endpoints and paths, status values and create defaults:

- NetBox: choice fields read at ``status.value`` and written flat; sites,
  manufacturers and device types need a ``slug`` on create (made from the
  name); devices and VLANs are created ``active``.
- Nautobot 2.x: sites are ``dcim/locations`` (created with location type
  ``Site``), statuses are records written by name (``Active``), prefixes,
  addresses and VRFs live in a namespace (``Global``), and nested records
  are read with ``depth=1``. A prefix's VRFs are a many-to-many in 2.x, so
  the prefix VRF is not mapped by default.

An address is read with its mask (``192.0.2.10/24``): the address field
drops it and the prefix field keeps the network (``/32`` / ``/128`` read
as no prefix); it is written with the prefix's length, or the host mask.
"""

from __future__ import annotations

from typing import Any

from netcontrol.sync.adapters.base import MAX_RECORDS_PER_TYPE, PAGE_SIZE, RestAdapter, slugify
from netcontrol.sync.models import network_of
from netcontrol.sync.transport import SyncError, coerce_list, host_prefix_address

_SLUGGED = {"sites": "name", "manufacturers": "name", "device_types": "model"}


class NetBoxFamilyAdapter(RestAdapter):
    LIST_PARAMS: dict[str, Any] = {}

    def ref_of(self, raw: dict) -> Any:
        return raw.get("id")

    def _path(self, object_type: str, ref: Any = None) -> str:
        base = f"api/{self.endpoint(object_type)}/"
        return base if ref is None else f"{base}{int(ref)}/"

    async def list_raw(self, object_type: str) -> list[dict]:
        rows: list[dict] = []
        offset = 0
        while True:
            params = {**self.LIST_PARAMS, "limit": PAGE_SIZE, "offset": offset}
            payload = await self.client.get(self._path(object_type), params)
            page = coerce_list(payload)
            rows.extend(page)
            if len(rows) > MAX_RECORDS_PER_TYPE:
                raise SyncError(f"{self.label} has more than {MAX_RECORDS_PER_TYPE} {object_type}; narrow the sync.")
            total = payload.get("count") if isinstance(payload, dict) else None
            offset += len(page)
            if len(page) < PAGE_SIZE or (isinstance(total, int) and offset >= total) or not page:
                return rows

    async def create_raw(self, object_type: str, body: dict) -> None:
        await self.client.request("POST", self._path(object_type), json_body=body)

    async def update_raw(self, object_type: str, ref: Any, body: dict) -> None:
        if not body:
            return
        await self.client.request("PATCH", self._path(object_type, ref), json_body=body)

    async def delete_raw(self, object_type: str, ref: Any) -> None:
        await self.client.request("DELETE", self._path(object_type, ref))

    def read_value(self, object_type: str, name: str, raw: dict, path: str) -> Any:
        value = super().read_value(object_type, name, raw, path)
        if object_type == "ip_addresses" and name == "prefix" and isinstance(value, str) and "/" in value:
            bits = value.rsplit("/", 1)[1]
            if bits in ("32", "128"):
                return ""
        return value

    def write_value(self, object_type: str, name: str, value: str, values: dict[str, str]) -> Any:
        if object_type == "ip_addresses" and name in ("address", "prefix"):
            address = values.get("address", "")
            length = network_of(address, values.get("prefix", ""))
            return f"{address}/{length}" if length is not None else host_prefix_address(address)
        if name == "u_height":
            return int(value) if value.isdigit() else 0
        if name in ("vid", "vlan") and value.isdigit():
            return int(value)
        if name in ("latitude", "longitude"):
            return float(value) if value else None
        return value


class NetBoxAdapter(NetBoxFamilyAdapter):
    name = "netbox"
    label = "NetBox"

    DEFAULTS: dict[str, dict[str, Any]] = {
        "sites": {
            "endpoint": "dcim/sites",
            "paths": {
                "name": "name",
                "description": "description",
                "status": "status.value",
                "address": "physical_address",
                "latitude": "latitude",
                "longitude": "longitude",
            },
        },
        "manufacturers": {"endpoint": "dcim/manufacturers", "paths": {"name": "name", "description": "description"}},
        "device_types": {
            "endpoint": "dcim/device-types",
            "paths": {
                "manufacturer": "manufacturer.name",
                "model": "model",
                "part_number": "part_number",
                "u_height": "u_height",
                "description": "description",
            },
        },
        "vrfs": {"endpoint": "ipam/vrfs", "paths": {"name": "name", "rd": "rd", "description": "description"}},
        "vlans": {
            "endpoint": "ipam/vlans",
            "paths": {"vid": "vid", "site": "site.name", "name": "name", "description": "description"},
            "create_defaults": {"status": "active"},
        },
        "prefixes": {
            "endpoint": "ipam/prefixes",
            "paths": {
                "prefix": "prefix",
                "vrf": "vrf.name",
                "description": "description",
                "site": "site.name",
                "vlan": "vlan.vid",
            },
            "create_defaults": {"status": "active"},
        },
        "ip_addresses": {
            "endpoint": "ipam/ip-addresses",
            "paths": {
                "address": "address",
                "prefix": "address",
                "vrf": "vrf.name",
                "dns_name": "dns_name",
                "description": "description",
            },
            "create_defaults": {"status": "active"},
        },
        "devices": {
            "endpoint": "dcim/devices",
            "paths": {
                "name": "name",
                "primary_ip": "primary_ip.address",
                "site": "site.name",
                "manufacturer": "device_type.manufacturer.name",
                "device_type": "device_type.model",
                "role": "role.name",
                "platform": "platform.name",
                "serial": "serial",
            },
            # The primary address is an assigned interface address and the
            # manufacturer comes with the device type: read, never written.
            "read_only": {"primary_ip", "manufacturer"},
            "create_defaults": {"status": "active"},
        },
    }

    def write_path(self, path: str) -> str:
        return path[: -len(".value")] if path.endswith(".value") else path

    def build_body(self, object_type: str, values: dict[str, str], *, create: bool) -> dict[str, Any]:
        body = super().build_body(object_type, values, create=create)
        source = _SLUGGED.get(object_type)
        if create and source and "slug" not in body and values.get(source):
            body["slug"] = slugify(values[source])
        return body


class NautobotAdapter(NetBoxFamilyAdapter):
    name = "nautobot"
    label = "Nautobot"
    LIST_PARAMS = {"depth": 1}

    DEFAULTS: dict[str, dict[str, Any]] = {
        "sites": {
            "endpoint": "dcim/locations",
            "paths": {
                "name": "name",
                "description": "description",
                "status": "status.name",
                "address": "physical_address",
                "latitude": "latitude",
                "longitude": "longitude",
            },
            "create_defaults": {"location_type": {"name": "Site"}, "status": {"name": "Active"}},
        },
        "manufacturers": {"endpoint": "dcim/manufacturers", "paths": {"name": "name", "description": "description"}},
        "device_types": {
            "endpoint": "dcim/device-types",
            "paths": {
                "manufacturer": "manufacturer.name",
                "model": "model",
                "part_number": "part_number",
                "u_height": "u_height",
            },
        },
        "vrfs": {
            "endpoint": "ipam/vrfs",
            "paths": {"name": "name", "rd": "rd", "description": "description"},
            "create_defaults": {"namespace": {"name": "Global"}},
        },
        "vlans": {
            "endpoint": "ipam/vlans",
            "paths": {"vid": "vid", "site": "location.name", "name": "name", "description": "description"},
            "create_defaults": {"status": {"name": "Active"}},
        },
        "prefixes": {
            "endpoint": "ipam/prefixes",
            "paths": {"prefix": "prefix", "description": "description", "site": "location.name", "vlan": "vlan.vid"},
            "create_defaults": {"status": {"name": "Active"}, "namespace": {"name": "Global"}, "type": "network"},
        },
        "ip_addresses": {
            "endpoint": "ipam/ip-addresses",
            "paths": {"address": "address", "prefix": "address", "dns_name": "dns_name", "description": "description"},
            "create_defaults": {"status": {"name": "Active"}, "namespace": {"name": "Global"}},
        },
        "devices": {
            "endpoint": "dcim/devices",
            "paths": {
                "name": "name",
                "primary_ip": "primary_ip4.address",
                "site": "location.name",
                "device_type": "device_type.model",
                "role": "role.name",
                "platform": "platform.name",
                "serial": "serial",
            },
            "read_only": {"primary_ip"},
            "create_defaults": {"status": {"name": "Active"}},
        },
    }

    def write_value(self, object_type: str, name: str, value: str, values: dict[str, str]) -> Any:
        if name == "status" and value:
            # Nautobot statuses are records looked up by name: "Active".
            return value[:1].upper() + value[1:]
        return super().write_value(object_type, name, value, values)
