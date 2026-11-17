"""ServiceNow CMDB adapter (Table API, basic auth or OAuth).

Reads ``GET /api/now/table/<table>`` with display values
(``sysparm_display_value=true``, reference links excluded), so a reference
such as a CI's location reads as the location's name; writes send display
values too (``sysparm_input_display_value=true``), so ServiceNow resolves a
reference by name. Records are paged with ``sysparm_limit`` /
``sysparm_offset`` and addressed by ``sys_id``.

OAuth uses the client-credentials grant on ``/oauth_token.do`` (the
credential's username is the client id, its password the client secret);
basic auth sends the credential's username and password.

Default tables (change any with ``_endpoint`` in the job mapping):
``cmn_location`` (sites), ``core_company`` with ``manufacturer=true``
(manufacturers), ``cmdb_hardware_product_model`` (device types),
``cmdb_ci_netgear`` (devices), ``cmdb_ci_ip_network`` (prefixes),
``cmdb_ci_ip_address`` (IP addresses) and ``cmdb_ci_vlan`` (VLANs). VRFs
have no standard CMDB class: they sync only when the mapping names a table.
"""

from __future__ import annotations

from typing import Any

from netcontrol.sync.adapters.base import MAX_RECORDS_PER_TYPE, PAGE_SIZE, RestAdapter
from netcontrol.sync.transport import HttpJsonClient, SyncError, coerce_list

TABLE_ROOT = "api/now/table"
TOKEN_PATH = "oauth_token.do"


class ServiceNowAdapter(RestAdapter):
    name = "servicenow"
    label = "ServiceNow"

    DEFAULTS: dict[str, dict[str, Any]] = {
        "sites": {
            "endpoint": "cmn_location",
            "paths": {"name": "name", "address": "street", "latitude": "latitude", "longitude": "longitude"},
        },
        "manufacturers": {
            "endpoint": "core_company",
            "paths": {"name": "name"},
            "query": "manufacturer=true",
            "create_defaults": {"manufacturer": "true"},
        },
        "device_types": {
            "endpoint": "cmdb_hardware_product_model",
            "paths": {
                "manufacturer": "manufacturer",
                "model": "name",
                "part_number": "model_number",
                "u_height": "rack_units",
                "description": "short_description",
            },
        },
        "vrfs": {"paths": {"name": "name", "description": "short_description"}},
        "vlans": {
            "endpoint": "cmdb_ci_vlan",
            "paths": {"vid": "vlan_id", "site": "location", "name": "name", "description": "short_description"},
        },
        "prefixes": {
            "endpoint": "cmdb_ci_ip_network",
            "paths": {"prefix": "name", "description": "short_description", "site": "location"},
        },
        "ip_addresses": {
            "endpoint": "cmdb_ci_ip_address",
            "paths": {"address": "ip_address", "dns_name": "fqdn", "description": "short_description"},
        },
        "devices": {
            "endpoint": "cmdb_ci_netgear",
            "paths": {
                "name": "name",
                "primary_ip": "ip_address",
                "site": "location",
                "manufacturer": "manufacturer",
                "device_type": "model_id",
                "serial": "serial_number",
            },
        },
    }

    def __init__(
        self,
        client: HttpJsonClient,
        mappings: dict[str, dict[str, Any]] | None = None,
        *,
        oauth: tuple[str, str] | None = None,
    ) -> None:
        super().__init__(client, mappings)
        self._oauth = oauth

    def supports(self, object_type: str) -> bool:
        if object_type == "vrfs":
            return bool((self.mappings.get(object_type) or {}).get("_endpoint"))
        return super().supports(object_type)

    async def __aenter__(self) -> ServiceNowAdapter:
        await super().__aenter__()
        if self._oauth is not None:
            client_id, client_secret = self._oauth
            payload = await self.client.request(
                "POST",
                TOKEN_PATH,
                data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            token = payload.get("access_token") if isinstance(payload, dict) else None
            if not token:
                await super().__aexit__(None, None, None)
                raise SyncError("ServiceNow did not return an OAuth access token; check the client id and secret.")
            self.client.headers["Authorization"] = f"Bearer {token}"
        return self

    def ref_of(self, raw: dict) -> Any:
        value = raw.get("sys_id")
        if isinstance(value, dict):
            value = value.get("value")
        return value

    def _path(self, object_type: str, ref: Any = None) -> str:
        base = f"{TABLE_ROOT}/{self.endpoint(object_type)}"
        if ref is None:
            return base
        text = str(ref)
        if not text.isalnum():
            raise SyncError("ServiceNow sys_id must be alphanumeric")
        return f"{base}/{text}"

    def _query(self, object_type: str) -> str:
        mapping = self.mapping(object_type)
        given = mapping.options.get("query")
        if isinstance(given, str):
            return given
        return str(self.DEFAULTS.get(object_type, {}).get("query", ""))

    async def list_raw(self, object_type: str) -> list[dict]:
        mapping = self.mapping(object_type)
        fields = sorted({"sys_id", *(p.split(".")[0] for p in mapping.paths.values())})
        rows: list[dict] = []
        offset = 0
        while True:
            params: dict[str, Any] = {
                "sysparm_display_value": "true",
                "sysparm_exclude_reference_link": "true",
                "sysparm_fields": ",".join(fields),
                "sysparm_limit": PAGE_SIZE,
                "sysparm_offset": offset,
            }
            query = self._query(object_type)
            if query:
                params["sysparm_query"] = query
            page = coerce_list(await self.client.get(self._path(object_type), params), "result")
            rows.extend(page)
            if len(rows) > MAX_RECORDS_PER_TYPE:
                raise SyncError(f"ServiceNow has more than {MAX_RECORDS_PER_TYPE} {object_type}; narrow the sync.")
            offset += len(page)
            if len(page) < PAGE_SIZE:
                return rows

    _WRITE_PARAMS = {"sysparm_input_display_value": "true"}

    async def create_raw(self, object_type: str, body: dict) -> None:
        await self.client.request("POST", self._path(object_type), json_body=body, params=self._WRITE_PARAMS)

    async def update_raw(self, object_type: str, ref: Any, body: dict) -> None:
        if not body:
            return
        await self.client.request("PATCH", self._path(object_type, ref), json_body=body, params=self._WRITE_PARAMS)

    async def delete_raw(self, object_type: str, ref: Any) -> None:
        await self.client.request("DELETE", self._path(object_type, ref))
