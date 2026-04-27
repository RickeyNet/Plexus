"""dhcp_adapters.py -- External DHCP server adapters for scope/lease sync.

Supports three providers:
  - kea       : ISC Kea DHCP control agent (HTTP JSON command API)
  - windows   : Windows DHCP via a REST shim that returns Get-DhcpServerv4Scope/
                Get-DhcpServerv4Lease as JSON (path: /scopes, /leases)
  - infoblox  : Infoblox WAPI (network + lease objects)
"""

from __future__ import annotations

import ipaddress
from typing import Any

import httpx

_HTTP_TIMEOUT_SECONDS = 30.0
_VALID_PROVIDERS = {"kea", "windows", "infoblox"}

_PROVIDER_INFO = {
    "kea": {
        "name": "ISC Kea DHCP",
        "auth_types": ["none", "basic"],
        "notes": "Posts JSON commands (config-get, lease4-get-all) to the Kea control agent.",
    },
    "windows": {
        "name": "Windows DHCP",
        "auth_types": ["basic", "token"],
        "notes": "Expects /scopes and /leases endpoints returning normalized JSON arrays.",
    },
    "infoblox": {
        "name": "Infoblox DHCP",
        "auth_types": ["basic", "token"],
        "notes": "Uses WAPI /network and /lease endpoints.",
    },
}


class DhcpAdapterError(RuntimeError):
    """Raised when a DHCP provider config or response is invalid."""


def normalize_dhcp_provider(raw: str | None) -> str:
    provider = str(raw or "").strip().lower()
    if provider not in _VALID_PROVIDERS:
        raise ValueError("invalid_provider")
    return provider


def get_dhcp_provider_catalog() -> list[dict]:
    return [
        {
            "id": provider,
            "name": info["name"],
            "auth_types": list(info["auth_types"]),
            "notes": info["notes"],
        }
        for provider, info in sorted(_PROVIDER_INFO.items())
    ]


async def _fetch_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | list[Any] | None = None,
    auth=None,
    verify: bool = True,
) -> Any:
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS, verify=verify) as client:
        response = await client.request(
            method.upper(),
            url,
            headers=headers,
            params=params,
            json=json_body,
            auth=auth,
        )
        response.raise_for_status()
        if not response.content:
            return {}
        return response.json()


def _normalize_subnet(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return str(ipaddress.ip_network(raw, strict=False))
    except Exception as exc:
        raise DhcpAdapterError(f"Invalid subnet returned by DHCP provider: {raw}") from exc


def _normalize_address(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        if "/" in raw:
            return str(ipaddress.ip_interface(raw).ip)
        return str(ipaddress.ip_address(raw))
    except Exception as exc:
        raise DhcpAdapterError(f"Invalid IP returned by DHCP provider: {raw}") from exc


def _normalize_mac(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    cleaned = "".join(ch for ch in raw if ch in "0123456789abcdef")
    if len(cleaned) != 12:
        return raw
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def _coerce_list(payload: Any, *keys: str) -> list[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in keys or ("results", "data", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _build_auth(server: dict, auth_config: dict) -> tuple[dict[str, str], Any]:
    headers: dict[str, str] = {}
    auth = None
    auth_type = str(server.get("auth_type") or "none").strip().lower()
    if auth_type == "basic":
        username = str(auth_config.get("username") or "").strip()
        password = str(auth_config.get("password") or "")
        if not username:
            raise DhcpAdapterError("Basic auth requires auth_config.username")
        auth = (username, password)
    elif auth_type == "token":
        token = str(auth_config.get("token") or auth_config.get("api_token") or "").strip()
        if not token:
            raise DhcpAdapterError("Token auth requires auth_config.token")
        headers["Authorization"] = f"Token {token}"
    return headers, auth


def _scope_utilization(total: int, used: int) -> tuple[int, int, int]:
    total_int = max(0, int(total or 0))
    used_int = max(0, int(used or 0))
    if used_int > total_int and total_int > 0:
        used_int = total_int
    free_int = max(0, total_int - used_int)
    return total_int, used_int, free_int


def _kea_subnet_total(subnet: str) -> int:
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return 0
    if net.prefixlen >= net.max_prefixlen - 1:
        return net.num_addresses
    return max(0, net.num_addresses - 2)


async def _collect_kea(server: dict, auth_config: dict, fetch_json) -> dict:
    base_url = str(server.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        raise DhcpAdapterError("Kea source requires a base_url")
    headers, auth = _build_auth(server, auth_config)
    verify = bool(server.get("verify_tls", 1))

    config_payload = await fetch_json(
        base_url,
        method="POST",
        headers=headers,
        json_body={"command": "config-get", "service": ["dhcp4"]},
        auth=auth,
        verify=verify,
    )
    cfg_list = config_payload if isinstance(config_payload, list) else [config_payload]
    subnets_raw: list[dict] = []
    for entry in cfg_list:
        if not isinstance(entry, dict):
            continue
        args = entry.get("arguments") or {}
        dhcp4 = args.get("Dhcp4") if isinstance(args, dict) else None
        if isinstance(dhcp4, dict):
            subs = dhcp4.get("subnet4")
            if isinstance(subs, list):
                subnets_raw.extend(s for s in subs if isinstance(s, dict))

    leases_payload = await fetch_json(
        base_url,
        method="POST",
        headers=headers,
        json_body={"command": "lease4-get-all", "service": ["dhcp4"]},
        auth=auth,
        verify=verify,
    )
    lease_list_raw: list[dict] = []
    leases_container = leases_payload if isinstance(leases_payload, list) else [leases_payload]
    for entry in leases_container:
        if not isinstance(entry, dict):
            continue
        args = entry.get("arguments") or {}
        if isinstance(args, dict):
            ll = args.get("leases")
            if isinstance(ll, list):
                lease_list_raw.extend(item for item in ll if isinstance(item, dict))

    used_by_subnet: dict[str, int] = {}
    leases: list[dict] = []
    for lease in lease_list_raw:
        addr = _normalize_address(lease.get("ip-address") or "")
        if not addr:
            continue
        subnet_id = lease.get("subnet-id")
        scope_subnet = ""
        for sub in subnets_raw:
            if sub.get("id") == subnet_id:
                scope_subnet = _normalize_subnet(str(sub.get("subnet") or ""))
                break
        if not scope_subnet:
            for sub in subnets_raw:
                subnet_text = _normalize_subnet(str(sub.get("subnet") or ""))
                if not subnet_text:
                    continue
                try:
                    if ipaddress.ip_address(addr) in ipaddress.ip_network(subnet_text, strict=False):
                        scope_subnet = subnet_text
                        break
                except ValueError:
                    continue
        used_by_subnet[scope_subnet] = used_by_subnet.get(scope_subnet, 0) + 1
        leases.append(
            {
                "address": addr,
                "scope_subnet": scope_subnet,
                "mac_address": _normalize_mac(lease.get("hw-address")),
                "hostname": str(lease.get("hostname") or "").strip(),
                "client_id": str(lease.get("client-id") or "").strip(),
                "state": "active" if int(lease.get("state") or 0) == 0 else "inactive",
                "starts_at": "",
                "ends_at": "",
                "metadata": lease,
            }
        )

    scopes: list[dict] = []
    for sub in subnets_raw:
        subnet_text = _normalize_subnet(str(sub.get("subnet") or ""))
        if not subnet_text:
            continue
        total = _kea_subnet_total(subnet_text)
        used = used_by_subnet.get(subnet_text, 0)
        total_n, used_n, free_n = _scope_utilization(total, used)
        pools = sub.get("pools") if isinstance(sub.get("pools"), list) else []
        range_start = ""
        range_end = ""
        if pools and isinstance(pools[0], dict):
            pool_text = str(pools[0].get("pool") or "")
            if "-" in pool_text:
                parts = [p.strip() for p in pool_text.split("-", 1)]
                if len(parts) == 2:
                    range_start = parts[0]
                    range_end = parts[1]
        scopes.append(
            {
                "external_id": str(sub.get("id") or subnet_text),
                "subnet": subnet_text,
                "name": str(sub.get("comment") or "").strip(),
                "range_start": range_start,
                "range_end": range_end,
                "total_addresses": total_n,
                "used_addresses": used_n,
                "free_addresses": free_n,
                "state": "active",
                "metadata": sub,
            }
        )
    return {"scopes": scopes, "leases": leases}


async def _collect_windows(server: dict, auth_config: dict, fetch_json) -> dict:
    base_url = str(server.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        raise DhcpAdapterError("Windows DHCP source requires a base_url")
    headers, auth = _build_auth(server, auth_config)
    verify = bool(server.get("verify_tls", 1))

    scopes_payload = await fetch_json(
        f"{base_url}/scopes",
        headers=headers,
        auth=auth,
        verify=verify,
    )
    leases_payload = await fetch_json(
        f"{base_url}/leases",
        headers=headers,
        auth=auth,
        verify=verify,
    )

    scopes: list[dict] = []
    for item in _coerce_list(scopes_payload):
        scope_id = str(item.get("ScopeId") or item.get("scope_id") or item.get("id") or "").strip()
        mask = str(item.get("SubnetMask") or item.get("subnet_mask") or "").strip()
        subnet_text = ""
        if scope_id and mask:
            try:
                subnet_text = str(ipaddress.ip_network(f"{scope_id}/{mask}", strict=False))
            except ValueError:
                subnet_text = ""
        if not subnet_text:
            subnet_text = _normalize_subnet(str(item.get("subnet") or ""))
        if not subnet_text:
            continue
        in_use = item.get("AddressesInUse")
        free = item.get("AddressesFree")
        if isinstance(in_use, int) and isinstance(free, int):
            total_raw = in_use + free
            used_raw = in_use
        else:
            total_raw = int(item.get("total_addresses") or 0)
            used_raw = int(item.get("used_addresses") or 0)
        total_n, used_n, free_n = _scope_utilization(total_raw, used_raw)
        scopes.append(
            {
                "external_id": scope_id or subnet_text,
                "subnet": subnet_text,
                "name": str(item.get("Name") or item.get("name") or "").strip(),
                "range_start": str(item.get("StartRange") or item.get("range_start") or "").strip(),
                "range_end": str(item.get("EndRange") or item.get("range_end") or "").strip(),
                "total_addresses": total_n,
                "used_addresses": used_n,
                "free_addresses": free_n,
                "state": str(item.get("State") or item.get("state") or "").strip(),
                "metadata": item,
            }
        )

    leases: list[dict] = []
    for item in _coerce_list(leases_payload):
        addr = _normalize_address(item.get("IPAddress") or item.get("ip_address") or item.get("address") or "")
        if not addr:
            continue
        scope_subnet = ""
        scope_id = str(item.get("ScopeId") or item.get("scope_id") or "").strip()
        if scope_id:
            for sc in scopes:
                if sc["external_id"] == scope_id or sc["subnet"].startswith(f"{scope_id}/"):
                    scope_subnet = sc["subnet"]
                    break
        if not scope_subnet:
            for sc in scopes:
                try:
                    if ipaddress.ip_address(addr) in ipaddress.ip_network(sc["subnet"], strict=False):
                        scope_subnet = sc["subnet"]
                        break
                except ValueError:
                    continue
        leases.append(
            {
                "address": addr,
                "scope_subnet": scope_subnet,
                "mac_address": _normalize_mac(item.get("ClientId") or item.get("mac_address") or item.get("MAC")),
                "hostname": str(item.get("HostName") or item.get("hostname") or "").strip(),
                "client_id": str(item.get("ClientId") or "").strip(),
                "state": str(item.get("AddressState") or item.get("state") or "").strip(),
                "starts_at": str(item.get("starts_at") or "").strip(),
                "ends_at": str(item.get("LeaseExpiryTime") or item.get("ends_at") or "").strip(),
                "metadata": item,
            }
        )
    return {"scopes": scopes, "leases": leases}


async def _collect_infoblox(server: dict, auth_config: dict, fetch_json) -> dict:
    base_url = str(server.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        raise DhcpAdapterError("Infoblox source requires a base_url")
    headers, auth = _build_auth(server, auth_config)
    verify = bool(server.get("verify_tls", 1))

    networks_payload = await fetch_json(
        f"{base_url}/network",
        headers=headers,
        params={"_return_fields": "network,comment,utilization,dhcp_utilization,total_hosts,used_hosts"},
        auth=auth,
        verify=verify,
    )
    scopes: list[dict] = []
    for item in _coerce_list(networks_payload):
        subnet_text = _normalize_subnet(str(item.get("network") or ""))
        if not subnet_text:
            continue
        total = int(item.get("total_hosts") or 0)
        used = int(item.get("used_hosts") or 0)
        if total == 0:
            try:
                net = ipaddress.ip_network(subnet_text, strict=False)
                total = max(0, net.num_addresses - 2) if net.prefixlen < net.max_prefixlen - 1 else net.num_addresses
            except ValueError:
                total = 0
        total_n, used_n, free_n = _scope_utilization(total, used)
        scopes.append(
            {
                "external_id": str(item.get("_ref") or subnet_text),
                "subnet": subnet_text,
                "name": str(item.get("comment") or "").strip(),
                "range_start": "",
                "range_end": "",
                "total_addresses": total_n,
                "used_addresses": used_n,
                "free_addresses": free_n,
                "state": "active",
                "metadata": item,
            }
        )

    leases_payload = await fetch_json(
        f"{base_url}/lease",
        headers=headers,
        params={"_return_fields": "address,binding_state,client_hostname,hardware,starts,ends,network"},
        auth=auth,
        verify=verify,
    )
    leases: list[dict] = []
    for item in _coerce_list(leases_payload):
        addr = _normalize_address(item.get("address") or "")
        if not addr:
            continue
        scope_subnet = _normalize_subnet(str(item.get("network") or ""))
        if not scope_subnet:
            for sc in scopes:
                try:
                    if ipaddress.ip_address(addr) in ipaddress.ip_network(sc["subnet"], strict=False):
                        scope_subnet = sc["subnet"]
                        break
                except ValueError:
                    continue
        leases.append(
            {
                "address": addr,
                "scope_subnet": scope_subnet,
                "mac_address": _normalize_mac(item.get("hardware")),
                "hostname": str(item.get("client_hostname") or "").strip(),
                "client_id": "",
                "state": str(item.get("binding_state") or "").strip().lower(),
                "starts_at": str(item.get("starts") or "").strip(),
                "ends_at": str(item.get("ends") or "").strip(),
                "metadata": item,
            }
        )
    return {"scopes": scopes, "leases": leases}


async def collect_dhcp_snapshot(
    server: dict,
    auth_config: dict,
    *,
    fetch_json=_fetch_json,
) -> dict:
    provider = normalize_dhcp_provider(server.get("provider"))
    if provider == "kea":
        snapshot = await _collect_kea(server, auth_config, fetch_json)
    elif provider == "windows":
        snapshot = await _collect_windows(server, auth_config, fetch_json)
    else:
        snapshot = await _collect_infoblox(server, auth_config, fetch_json)
    snapshot["summary"] = {
        "provider": provider,
        "scope_count": len(snapshot.get("scopes") or []),
        "lease_count": len(snapshot.get("leases") or []),
    }
    return snapshot
