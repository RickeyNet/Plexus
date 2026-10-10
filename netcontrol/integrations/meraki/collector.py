"""Meraki organization collector - gathers every payload a topology build needs.

``collect_organization`` walks one organization with a :class:`MerakiClient`
and returns the *raw* API payloads keyed by scope (org / network / device).
It does no interpretation - ``normalize.build_snapshot`` owns that - so the
two halves can be tested independently and a saved raw capture can be
re-normalised without touching the network.

Failure policy: a topology build over hundreds of networks must not abort
because one endpoint is unavailable. Org-wide inventory calls (networks,
devices) are required; everything else is best-effort:

  - HTTP 400/404 mean "feature not configured / not applicable here" (VLANs
    disabled, switch is not layer-3, ...) and are silently skipped
  - anything else (403 scope gap, 5xx after retries, timeout) is recorded in
    ``errors`` and surfaced in the map's collection report

Secrets (PSKs, IPsec shared secrets, RADIUS secrets) are scrubbed from every
payload before it is returned, so they never reach the database or an export.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from netcontrol.integrations.meraki.client import MerakiApiError, MerakiClient
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.meraki")

DEFAULT_OPTIONS: dict[str, Any] = {
    # Limit the build to networks carrying any of these tags / whose name
    # contains this text. Empty = whole organization.
    "network_tags": [],
    "network_name_contains": "",
    "include_lldp_cdp": True,
    "include_switch_ports": True,
    # Live per-port status (speed, errors, neighbor) costs one call per switch.
    "include_port_statuses": False,
    "include_switch_routing": True,
    "include_firewall": True,
    "include_wireless": True,
    # Clients seen in the last day (MAC, IP, VLAN, port): the MAC/ARP view.
    # One paginated call per network.
    "include_clients": True,
    # Attach data Plexus already collected over SNMP/SSH for inventory hosts
    # that match a Meraki device or one of its LLDP/CDP neighbors.
    "inventory_enrich": True,
    # Additionally SSH to matched inventory hosts for live show-command output.
    "ssh_enrich": False,
    "max_concurrency": 5,
    "requests_per_second": 8.0,
}

_BOOL_OPTIONS = (
    "include_lldp_cdp",
    "include_switch_ports",
    "include_port_statuses",
    "include_switch_routing",
    "include_firewall",
    "include_wireless",
    "include_clients",
    "inventory_enrich",
    "ssh_enrich",
)

# Key fragments that mark a value as a secret wherever it appears in a payload.
_SECRET_KEY_FRAGMENTS = ("secret", "psk", "password", "passphrase", "privatekey", "apikey", "token")

_NOT_APPLICABLE_STATUSES = {400, 404}
_CLIENT_TIMESPAN_SECONDS = 86400
_MAX_RECORDED_ERRORS = 200

ProgressCallback = Callable[[dict[str, Any]], None]


def sanitize_options(raw: object) -> dict[str, Any]:
    """Coerce stored/user-supplied build options onto the known schema."""
    src = raw if isinstance(raw, dict) else {}
    opts = dict(DEFAULT_OPTIONS)
    for key in _BOOL_OPTIONS:
        if key in src:
            opts[key] = bool(src[key])
    tags = src.get("network_tags", [])
    if isinstance(tags, str):
        tags = tags.split(",")
    if isinstance(tags, (list, tuple)):
        opts["network_tags"] = [str(t).strip() for t in tags if str(t).strip()][:50]
    opts["network_name_contains"] = str(src.get("network_name_contains") or "").strip()[:200]
    try:
        opts["max_concurrency"] = min(10, max(1, int(src.get("max_concurrency", opts["max_concurrency"]))))
    except TypeError, ValueError:
        pass
    try:
        opts["requests_per_second"] = min(10.0, max(1.0, float(src.get("requests_per_second", 8.0))))
    except TypeError, ValueError:
        pass
    return opts


def scrub_secrets(value: Any) -> Any:
    """Recursively drop secret-bearing keys from an API payload."""
    if isinstance(value, dict):
        return {
            k: scrub_secrets(v)
            for k, v in value.items()
            if not any(fragment in str(k).lower() for fragment in _SECRET_KEY_FRAGMENTS)
        }
    if isinstance(value, list):
        return [scrub_secrets(v) for v in value]
    return value


def _network_selected(network: dict, options: dict) -> bool:
    wanted_tags = {t.lower() for t in options.get("network_tags") or []}
    if wanted_tags and not wanted_tags & {str(t).lower() for t in network.get("tags") or []}:
        return False
    needle = str(options.get("network_name_contains") or "").lower()
    if needle and needle not in str(network.get("name") or "").lower():
        return False
    return True


class _Collection:
    """Mutable state shared by the concurrent collection tasks."""

    def __init__(self, client: MerakiClient, progress: ProgressCallback | None) -> None:
        self.client = client
        self.errors: list[dict[str, Any]] = []
        self._progress = progress
        self.done = 0
        self.total = 0
        self.phase = "starting"

    def report(self, **fields: Any) -> None:
        if self._progress is None:
            return
        payload = {"phase": self.phase, "calls_done": self.done, "calls_total": self.total}
        payload.update(fields)
        self._progress(payload)

    def _record_error(self, scope: str, path: str, exc: MerakiApiError) -> None:
        if len(self.errors) < _MAX_RECORDED_ERRORS:
            self.errors.append({"scope": scope, "path": path, "status": exc.status_code, "message": str(exc)})

    async def optional(
        self,
        scope: str,
        path: str,
        *,
        paginated: bool = False,
        per_page: int | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Best-effort GET: ``None`` when not applicable or failed."""
        try:
            if paginated:
                data: Any = await self.client.get_all(path, params=params, per_page=per_page)
            else:
                data = await self.client.get(path, params=params)
        except MerakiApiError as exc:
            if exc.status_code not in _NOT_APPLICABLE_STATUSES:
                self._record_error(scope, path, exc)
            return None
        finally:
            self.done += 1
            self.report()
        return scrub_secrets(data)

    async def run(self, jobs: list[tuple[dict, str, Awaitable[Any]]]) -> None:
        """Await ``(target_dict, key, awaitable)`` jobs, storing each result."""
        self.total += len(jobs)
        self.report()

        async def _one(target: dict, key: str, aw: Awaitable[Any]) -> None:
            result = await aw
            if result is not None:
                target[key] = result

        await asyncio.gather(*(_one(target, key, aw) for target, key, aw in jobs))


def _device_kind(device: dict) -> str:
    product = str(device.get("productType") or "").strip()
    if product:
        return product
    model = str(device.get("model") or "").upper()
    for prefix, kind in (
        ("MX", "appliance"),
        ("VMX", "appliance"),
        ("Z", "appliance"),
        ("MS", "switch"),
        ("C9", "switch"),
        ("MR", "wireless"),
        ("CW", "wireless"),
        ("MV", "camera"),
        ("MT", "sensor"),
        ("MG", "cellularGateway"),
    ):
        if model.startswith(prefix):
            return kind
    return "other"


async def collect_organization(
    client: MerakiClient,
    org_id: str,
    options: dict[str, Any] | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Collect one organization. Raises ``MerakiApiError`` only if the core
    inventory (organization / networks / devices) cannot be read."""
    opts = sanitize_options(options)
    col = _Collection(client, progress)
    org_path = f"organizations/{org_id}"

    # ── Phase 1: required org inventory ────────────────────────────────────
    col.phase = "inventory"
    col.total = 3
    col.report()
    organization = scrub_secrets(await client.get(org_path))
    col.done += 1
    col.report()
    all_networks = scrub_secrets(await client.get_all(f"{org_path}/networks", per_page=1000))
    col.done += 1
    col.report()
    all_devices = scrub_secrets(await client.get_all(f"{org_path}/devices", per_page=1000))
    col.done += 1

    networks = [n for n in all_networks if isinstance(n, dict) and _network_selected(n, opts)]
    network_ids = {n.get("id") for n in networks}
    devices = [d for d in all_devices if isinstance(d, dict) and d.get("networkId") in network_ids]
    col.report(networks=len(networks), devices=len(devices))

    raw: dict[str, Any] = {
        "organization": organization or {"id": org_id},
        "networks": networks,
        "devices": devices,
        "org": {},
        "networks_detail": {n["id"]: {} for n in networks if n.get("id")},
        "devices_detail": {d["serial"]: {} for d in devices if d.get("serial")},
        "options": opts,
    }

    # ── Phase 2: org-wide bulk endpoints (few calls, most of the status) ───
    col.phase = "organization"
    org_data = raw["org"]
    org_jobs: list[tuple[dict, str, Awaitable[Any]]] = [
        (
            org_data,
            "device_statuses",
            col.optional("org", f"{org_path}/devices/statuses", paginated=True, per_page=1000),
        ),
        (
            org_data,
            "uplink_statuses",
            col.optional("org", f"{org_path}/uplinks/statuses", paginated=True, per_page=1000),
        ),
        (
            org_data,
            "vpn_statuses",
            col.optional("org", f"{org_path}/appliance/vpn/statuses", paginated=True, per_page=300),
        ),
        (org_data, "third_party_vpn_peers", col.optional("org", f"{org_path}/appliance/vpn/thirdPartyVPNPeers")),
    ]
    if opts["include_firewall"]:
        # Organisation-wide: applied to traffic leaving over AutoVPN.
        org_jobs.append((org_data, "vpn_firewall", col.optional("org", f"{org_path}/appliance/vpn/vpnFirewallRules")))
    if opts["include_switch_ports"]:
        org_jobs.append(
            (
                org_data,
                "switch_ports",
                col.optional("org", f"{org_path}/switch/ports/bySwitch", paginated=True, per_page=50),
            )
        )
    await col.run(org_jobs)

    # ── Phase 3: per-network configuration ─────────────────────────────────
    col.phase = "networks"
    net_jobs: list[tuple[dict, str, Awaitable[Any]]] = []
    for net in networks:
        net_id = net.get("id")
        if not net_id:
            continue
        detail = raw["networks_detail"][net_id]
        products = set(net.get("productTypes") or [])
        base = f"networks/{net_id}"
        scope = f"network:{net.get('name') or net_id}"

        def add(key: str, suffix: str, _detail=detail, _base=base, _scope=scope) -> None:
            net_jobs.append((_detail, key, col.optional(_scope, f"{_base}/{suffix}")))

        add("link_layer", "topology/linkLayer")
        if "appliance" in products:
            add("appliance_settings", "appliance/settings")  # deploymentMode: routed / passthrough
            add("vlans", "appliance/vlans")
            add("single_lan", "appliance/singleLan")
            add("static_routes", "appliance/staticRoutes")
            add("site_to_site_vpn", "appliance/vpn/siteToSiteVpn")
            add("bgp", "appliance/vpn/bgp")
            add("appliance_ports", "appliance/ports")
            add("warm_spare", "appliance/warmSpare")
            if opts["include_firewall"]:
                add("l3_firewall", "appliance/firewall/l3FirewallRules")
                add("port_forwarding", "appliance/firewall/portForwardingRules")
                add("one_to_one_nat", "appliance/firewall/oneToOneNatRules")
                add("one_to_many_nat", "appliance/firewall/oneToManyNatRules")
                add("inbound_firewall", "appliance/firewall/inboundFirewallRules")
        if "switch" in products:
            add("stacks", "switch/stacks")
            add("stp", "switch/stp")
            if opts["include_switch_routing"]:
                add("ospf", "switch/routing/ospf")
                add("switch_acl", "switch/accessControlLists")
        if "wireless" in products and opts["include_wireless"]:
            add("ssids", "wireless/ssids")
        if opts["include_clients"]:
            net_jobs.append(
                (
                    detail,
                    "clients",
                    col.optional(
                        scope,
                        f"{base}/clients",
                        paginated=True,
                        per_page=1000,
                        params={"timespan": _CLIENT_TIMESPAN_SECONDS},
                    ),
                )
            )
    await col.run(net_jobs)

    # ── Phase 4: per-device detail ─────────────────────────────────────────
    col.phase = "devices"
    dev_jobs: list[tuple[dict, str, Awaitable[Any]]] = []
    for dev in devices:
        serial = dev.get("serial")
        if not serial:
            continue
        detail = raw["devices_detail"][serial]
        kind = _device_kind(dev)
        scope = f"device:{dev.get('name') or serial}"
        base = f"devices/{serial}"
        if opts["include_lldp_cdp"] and kind in ("appliance", "switch", "wireless", "cellularGateway"):
            dev_jobs.append((detail, "lldp_cdp", col.optional(scope, f"{base}/lldpCdp")))
        if kind == "switch":
            if opts["include_switch_routing"]:
                dev_jobs.append(
                    (detail, "routing_interfaces", col.optional(scope, f"{base}/switch/routing/interfaces"))
                )
                dev_jobs.append(
                    (detail, "routing_static_routes", col.optional(scope, f"{base}/switch/routing/staticRoutes"))
                )
            if opts["include_port_statuses"]:
                dev_jobs.append((detail, "port_statuses", col.optional(scope, f"{base}/switch/ports/statuses")))
    await col.run(dev_jobs)

    # Layer-3 interfaces of a switch stack live on the stack, not its members.
    if opts["include_switch_routing"]:
        col.phase = "stacks"
        stack_jobs: list[tuple[dict, str, Awaitable[Any]]] = []
        for net_id, detail in raw["networks_detail"].items():
            for stack in detail.get("stacks") or []:
                if not isinstance(stack, dict) or not stack.get("id"):
                    continue
                base = f"networks/{net_id}/switch/stacks/{stack['id']}/routing"
                scope = f"stack:{stack.get('name') or stack['id']}"
                stack_jobs.append((stack, "routing_interfaces", col.optional(scope, f"{base}/interfaces")))
                stack_jobs.append((stack, "routing_static_routes", col.optional(scope, f"{base}/staticRoutes")))
        await col.run(stack_jobs)

    col.phase = "collected"
    col.report()
    raw["errors"] = col.errors
    raw["stats"] = dict(client.stats)
    LOGGER.info(
        "meraki: collected org %s - %d networks, %d devices, %d calls, %d errors",
        org_id,
        len(networks),
        len(devices),
        client.stats["requests"],
        len(col.errors),
    )
    return raw
