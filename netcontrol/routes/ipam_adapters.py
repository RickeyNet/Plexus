"""ipam_adapters.py -- External IPAM provider adapters for overview sync."""

from __future__ import annotations

import ipaddress
from typing import Any

import httpx

_HTTP_TIMEOUT_SECONDS = 20.0
_VALID_PROVIDERS = {"netbox", "phpipam", "infoblox"}

_PROVIDER_INFO = {
    "netbox": {
        "name": "NetBox",
        "auth_types": ["token"],
        "notes": "Uses NetBox REST endpoints under /api/ipam/.",
    },
    "phpipam": {
        "name": "phpIPAM",
        "auth_types": ["token"],
        "notes": "Expects an app-specific API base URL ending with /api/<app-id>.",
    },
    "infoblox": {
        "name": "Infoblox",
        "auth_types": ["basic", "token"],
        "notes": "Uses WAPI endpoints such as /network and /ipv4address.",
    },
}


class IpamAdapterError(RuntimeError):
    """Raised when a provider config or API response is invalid."""


def normalize_ipam_provider(raw: str | None) -> str:
    provider = str(raw or "").strip().lower()
    if provider not in _VALID_PROVIDERS:
        raise ValueError("invalid_provider")
    return provider


def get_ipam_provider_catalog() -> list[dict]:
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
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    auth=None,
    verify: bool = True,
) -> Any:
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS, verify=verify) as client:
        response = await client.get(url, headers=headers, params=params, auth=auth)
        response.raise_for_status()
        return response.json()


async def _request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
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
        content_type = (response.headers.get("content-type") or "").lower()
        if "json" in content_type:
            return response.json()
        return {}


def _normalize_address(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        if "/" in raw:
            return str(ipaddress.ip_interface(raw).ip)
        return str(ipaddress.ip_address(raw))
    except Exception as exc:  # pragma: no cover - defensive
        raise IpamAdapterError(f"Invalid IP address returned by provider: {raw}") from exc


def _normalize_subnet(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return str(ipaddress.ip_network(raw, strict=False))
    except Exception as exc:  # pragma: no cover - defensive
        raise IpamAdapterError(f"Invalid subnet returned by provider: {raw}") from exc


def _nested_text(value: Any, *keys: str) -> str:
    current = value
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            current = None
    if isinstance(current, (dict, list)) or current is None:
        return ""
    return str(current).strip()


def _coerce_list(payload: Any) -> list[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        data = payload.get("results")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        data = payload.get("data")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
    return []


def _best_matching_prefix(address: str, prefixes: list[tuple[ipaddress._BaseNetwork, str]]) -> str:
    address_obj = ipaddress.ip_address(address)
    matches = [
        (network.prefixlen, subnet)
        for network, subnet in prefixes
        if address_obj.version == network.version and address_obj in network
    ]
    if not matches:
        return ""
    return sorted(matches, key=lambda item: item[0], reverse=True)[0][1]


def _build_auth(source: dict, auth_config: dict) -> tuple[dict[str, str], Any]:
    headers: dict[str, str] = {}
    auth = None
    provider = normalize_ipam_provider(source.get("provider"))
    auth_type = str(source.get("auth_type") or "token").strip().lower()
    if provider in {"netbox", "phpipam"} or auth_type == "token":
        token = str(auth_config.get("token") or auth_config.get("api_token") or "").strip()
        if not token:
            raise IpamAdapterError("This provider requires a token in auth_config.token")
        if provider == "netbox":
            headers["Authorization"] = f"Token {token}"
        elif provider == "phpipam":
            headers["token"] = token
        else:
            headers["Authorization"] = f"Token {token}"
    if provider == "infoblox" and auth_type == "basic":
        username = str(auth_config.get("username") or "").strip()
        password = str(auth_config.get("password") or "")
        if not username or not password:
            raise IpamAdapterError("Infoblox basic auth requires auth_config.username and auth_config.password")
        auth = (username, password)
    return headers, auth


def _extract_netbox_prefix(item: dict) -> dict | None:
    subnet = _normalize_subnet(_nested_text(item, "prefix") or _nested_text(item, "display"))
    if not subnet:
        return None
    return {
        "external_id": str(item.get("id") or subnet).strip(),
        "subnet": subnet,
        "description": str(item.get("description") or "").strip(),
        "status": _nested_text(item.get("status"), "value") or _nested_text(item.get("status"), "label"),
        "vrf": _nested_text(item.get("vrf"), "name") or _nested_text(item.get("vrf"), "display"),
        "tenant": _nested_text(item.get("tenant"), "name") or _nested_text(item.get("tenant"), "display"),
        "site": _nested_text(item.get("site"), "name") or _nested_text(item.get("site"), "display"),
        "vlan": _nested_text(item.get("vlan"), "vid") or _nested_text(item.get("vlan"), "name"),
        "metadata": item,
    }


def _netbox_address_rows(items: list[dict], prefixes: list[tuple[ipaddress._BaseNetwork, str]]) -> list[dict]:
    rows: list[dict] = []
    for item in items:
        raw_address = str(item.get("address") or "").strip()
        if not raw_address:
            continue
        address = _normalize_address(raw_address)
        rows.append(
            {
                "address": address,
                "dns_name": str(item.get("dns_name") or "").strip(),
                "status": _nested_text(item.get("status"), "value") or _nested_text(item.get("status"), "label"),
                "description": str(item.get("description") or "").strip(),
                "prefix_subnet": _nested_text(item.get("parent"), "prefix") or _best_matching_prefix(address, prefixes),
                "metadata": item,
            }
        )
    return rows


def _phpipam_network_text(item: dict) -> str:
    subnet_value = item.get("subnet")
    mask_value = item.get("mask")
    if subnet_value in (None, "") or mask_value in (None, ""):
        return ""
    subnet_text = str(subnet_value).strip()
    if subnet_text.isdigit():
        subnet_text = str(ipaddress.ip_address(int(subnet_text)))
    return _normalize_subnet(f"{subnet_text}/{mask_value}")


def _phpipam_address_text(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.isdigit():
        return str(ipaddress.ip_address(int(raw)))
    return _normalize_address(raw)


async def _collect_netbox(source: dict, auth_config: dict, fetch_json) -> dict:
    base_url = str(source.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        raise IpamAdapterError("NetBox source requires a base_url")
    headers, auth = _build_auth(source, auth_config)
    verify = bool(source.get("verify_tls", 1))
    prefix_payload = await fetch_json(
        f"{base_url}/api/ipam/prefixes/",
        headers=headers,
        params={"limit": 1000},
        auth=auth,
        verify=verify,
    )
    prefix_rows = [item for item in (_extract_netbox_prefix(row) for row in _coerce_list(prefix_payload)) if item]
    prefix_networks = [(ipaddress.ip_network(item["subnet"], strict=False), item["subnet"]) for item in prefix_rows]

    address_payload = await fetch_json(
        f"{base_url}/api/ipam/ip-addresses/",
        headers=headers,
        params={"limit": 1000},
        auth=auth,
        verify=verify,
    )
    allocation_rows = _netbox_address_rows(_coerce_list(address_payload), prefix_networks)
    return {"prefixes": prefix_rows, "allocations": allocation_rows}


async def _collect_phpipam(source: dict, auth_config: dict, fetch_json) -> dict:
    base_url = str(source.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        raise IpamAdapterError("phpIPAM source requires a base_url")
    headers, auth = _build_auth(source, auth_config)
    verify = bool(source.get("verify_tls", 1))
    prefix_payload = await fetch_json(f"{base_url}/subnets/", headers=headers, auth=auth, verify=verify)
    prefix_map: dict[str, str] = {}
    prefix_rows: list[dict] = []
    for item in _coerce_list(prefix_payload):
        subnet = _phpipam_network_text(item)
        if not subnet:
            continue
        external_id = str(item.get("id") or subnet).strip() or subnet
        prefix_map[external_id] = subnet
        prefix_rows.append(
            {
                "external_id": external_id,
                "subnet": subnet,
                "description": str(item.get("description") or item.get("name") or "").strip(),
                "status": str(item.get("state") or "").strip(),
                "vrf": str(item.get("vrfId") or "").strip(),
                "tenant": str(item.get("sectionId") or "").strip(),
                "site": str(item.get("location") or "").strip(),
                "vlan": str(item.get("vlanId") or "").strip(),
                "metadata": item,
            }
        )

    address_payload = await fetch_json(f"{base_url}/addresses/", headers=headers, auth=auth, verify=verify)
    allocation_rows: list[dict] = []
    for item in _coerce_list(address_payload):
        address = _phpipam_address_text(item.get("ip") or item.get("ip_addr"))
        if not address:
            continue
        subnet_id = str(item.get("subnetId") or item.get("subnet_id") or "").strip()
        allocation_rows.append(
            {
                "address": address,
                "dns_name": str(item.get("hostname") or "").strip(),
                "status": str(item.get("state") or "").strip(),
                "description": str(item.get("description") or "").strip(),
                "prefix_subnet": prefix_map.get(subnet_id, ""),
                "metadata": item,
            }
        )
    return {"prefixes": prefix_rows, "allocations": allocation_rows}


async def _collect_infoblox(source: dict, auth_config: dict, fetch_json) -> dict:
    base_url = str(source.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        raise IpamAdapterError("Infoblox source requires a base_url")
    headers, auth = _build_auth(source, auth_config)
    verify = bool(source.get("verify_tls", 1))
    prefix_payload = await fetch_json(
        f"{base_url}/network",
        headers=headers,
        params={"_return_fields": "network,comment,extattrs"},
        auth=auth,
        verify=verify,
    )
    prefix_rows: list[dict] = []
    prefix_networks: list[tuple[ipaddress._BaseNetwork, str]] = []
    for item in _coerce_list(prefix_payload):
        subnet = _normalize_subnet(str(item.get("network") or ""))
        if not subnet:
            continue
        prefix_rows.append(
            {
                "external_id": str(item.get("_ref") or item.get("network") or subnet).strip(),
                "subnet": subnet,
                "description": str(item.get("comment") or "").strip(),
                "status": str(item.get("status") or "").strip(),
                "vrf": _nested_text(item.get("extattrs"), "Network View", "value"),
                "tenant": "",
                "site": "",
                "vlan": "",
                "metadata": item,
            }
        )
        prefix_networks.append((ipaddress.ip_network(subnet, strict=False), subnet))

    address_payload = await fetch_json(
        f"{base_url}/ipv4address",
        headers=headers,
        params={"_return_fields": "ip_address,names,status,network,comment"},
        auth=auth,
        verify=verify,
    )
    allocation_rows: list[dict] = []
    for item in _coerce_list(address_payload):
        raw = str(item.get("ip_address") or "").strip()
        if not raw or raw.startswith("UNUSED"):
            continue
        address = _normalize_address(raw)
        prefix_subnet = ""
        network_text = str(item.get("network") or "").strip()
        if network_text:
            prefix_subnet = _normalize_subnet(network_text)
        if not prefix_subnet:
            prefix_subnet = _best_matching_prefix(address, prefix_networks)
        names = item.get("names") if isinstance(item.get("names"), list) else []
        allocation_rows.append(
            {
                "address": address,
                "dns_name": str(names[0] if names else "").strip(),
                "status": str(item.get("status") or "").strip(),
                "description": str(item.get("comment") or "").strip(),
                "prefix_subnet": prefix_subnet,
                "metadata": item,
            }
        )
    return {"prefixes": prefix_rows, "allocations": allocation_rows}


async def collect_ipam_snapshot(
    source: dict,
    auth_config: dict,
    *,
    fetch_json=_fetch_json,
) -> dict:
    provider = normalize_ipam_provider(source.get("provider"))
    if provider == "netbox":
        snapshot = await _collect_netbox(source, auth_config, fetch_json)
    elif provider == "phpipam":
        snapshot = await _collect_phpipam(source, auth_config, fetch_json)
    else:
        snapshot = await _collect_infoblox(source, auth_config, fetch_json)
    snapshot["summary"] = {
        "provider": provider,
        "prefix_count": len(snapshot.get("prefixes") or []),
        "allocation_count": len(snapshot.get("allocations") or []),
    }
    return snapshot


def _address_with_host_prefix(address: str) -> str:
    ip_obj = ipaddress.ip_address(address)
    if ip_obj.version == 6:
        return f"{address}/128"
    return f"{address}/32"


def _ip_to_int_text(address: str) -> str:
    return str(int(ipaddress.ip_address(address)))


async def _push_netbox_allocation(
    source: dict,
    headers: dict[str, str],
    auth,
    address: str,
    dns_name: str,
    description: str,
    request_json,
    fetch_json,
) -> None:
    base_url = str(source.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        raise IpamAdapterError("NetBox source requires a base_url")
    verify = bool(source.get("verify_tls", 1))
    prefixed = _address_with_host_prefix(address)

    existing_payload = await fetch_json(
        f"{base_url}/api/ipam/ip-addresses/",
        headers=headers,
        params={"address": address, "limit": 10},
        auth=auth,
        verify=verify,
    )
    existing_rows = _coerce_list(existing_payload)
    if existing_rows:
        row_id = existing_rows[0].get("id")
        if row_id is None:
            raise IpamAdapterError("NetBox returned an address row without id")
        patch_body = {
            "dns_name": dns_name,
            "description": description,
            "status": "active",
        }
        await request_json(
            "PATCH",
            f"{base_url}/api/ipam/ip-addresses/{row_id}/",
            headers=headers,
            json_body=patch_body,
            auth=auth,
            verify=verify,
        )
        return

    create_body = {
        "address": prefixed,
        "dns_name": dns_name,
        "description": description,
        "status": "active",
    }
    await request_json(
        "POST",
        f"{base_url}/api/ipam/ip-addresses/",
        headers=headers,
        json_body=create_body,
        auth=auth,
        verify=verify,
    )


async def _push_phpipam_allocation(
    source: dict,
    headers: dict[str, str],
    auth,
    address: str,
    dns_name: str,
    description: str,
    request_json,
    fetch_json,
) -> None:
    base_url = str(source.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        raise IpamAdapterError("phpIPAM source requires a base_url")
    verify = bool(source.get("verify_tls", 1))

    search_payload = await fetch_json(
        f"{base_url}/addresses/search/{address}/",
        headers=headers,
        auth=auth,
        verify=verify,
    )
    existing_rows = _coerce_list(search_payload)
    if existing_rows:
        row_id = existing_rows[0].get("id")
        if row_id is None:
            raise IpamAdapterError("phpIPAM returned an address row without id")
        await request_json(
            "PATCH",
            f"{base_url}/addresses/{row_id}/",
            headers=headers,
            json_body={"hostname": dns_name, "description": description},
            auth=auth,
            verify=verify,
        )
        return

    subnet_payload = await fetch_json(
        f"{base_url}/subnets/",
        headers=headers,
        auth=auth,
        verify=verify,
    )
    subnet_rows = _coerce_list(subnet_payload)
    target_subnet_id = ""
    target_prefix_len = -1
    addr_obj = ipaddress.ip_address(address)
    for item in subnet_rows:
        subnet_text = _phpipam_network_text(item)
        if not subnet_text:
            continue
        try:
            net = ipaddress.ip_network(subnet_text, strict=False)
        except ValueError:
            continue
        if addr_obj.version != net.version or addr_obj not in net:
            continue
        subnet_id = str(item.get("id") or "").strip()
        if not subnet_id:
            continue
        if net.prefixlen > target_prefix_len:
            target_subnet_id = subnet_id
            target_prefix_len = net.prefixlen
    if not target_subnet_id:
        raise IpamAdapterError(f"phpIPAM has no matching subnet for {address}")

    await request_json(
        "POST",
        f"{base_url}/addresses/",
        headers=headers,
        json_body={
            "subnetId": target_subnet_id,
            "ip": _ip_to_int_text(address),
            "hostname": dns_name,
            "description": description,
        },
        auth=auth,
        verify=verify,
    )


async def _push_infoblox_allocation(
    source: dict,
    headers: dict[str, str],
    auth,
    address: str,
    dns_name: str,
    description: str,
    request_json,
    fetch_json,
) -> None:
    base_url = str(source.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        raise IpamAdapterError("Infoblox source requires a base_url")
    verify = bool(source.get("verify_tls", 1))

    existing_payload = await fetch_json(
        f"{base_url}/ipv4address",
        headers=headers,
        params={
            "ip_address": address,
            "_return_fields": "_ref,ip_address,names,comment",
        },
        auth=auth,
        verify=verify,
    )
    existing_rows = _coerce_list(existing_payload)
    if existing_rows:
        row_ref = str(existing_rows[0].get("_ref") or "").strip()
        if not row_ref:
            raise IpamAdapterError("Infoblox returned an address row without _ref")
        await request_json(
            "PUT",
            f"{base_url}/{row_ref}",
            headers=headers,
            json_body={"comment": description},
            auth=auth,
            verify=verify,
        )
        return

    create_body = {
        "ipv4addr": address,
        "comment": description,
    }
    if dns_name:
        create_body["name"] = dns_name
    await request_json(
        "POST",
        f"{base_url}/fixedaddress",
        headers=headers,
        json_body=create_body,
        auth=auth,
        verify=verify,
    )


async def push_allocation_to_provider(
    source: dict,
    auth_config: dict,
    *,
    address: str,
    dns_name: str = "",
    description: str = "",
    request_json=_request_json,
    fetch_json=_fetch_json,
) -> None:
    provider = normalize_ipam_provider(source.get("provider"))
    normalized_address = _normalize_address(address)
    headers, auth = _build_auth(source, auth_config)

    if provider == "netbox":
        await _push_netbox_allocation(
            source,
            headers,
            auth,
            normalized_address,
            dns_name,
            description,
            request_json,
            fetch_json,
        )
        return
    if provider == "phpipam":
        await _push_phpipam_allocation(
            source,
            headers,
            auth,
            normalized_address,
            dns_name,
            description,
            request_json,
            fetch_json,
        )
        return
    await _push_infoblox_allocation(
        source,
        headers,
        auth,
        normalized_address,
        dns_name,
        description,
        request_json,
        fetch_json,
    )