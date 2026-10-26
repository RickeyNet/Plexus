"""
inventory_collection.py -- The "All other devices (SSH)" map source: the
inventory devices no integration (Meraki, Cato, AWS, ...) covers.

One read-only SSH session per inventory host, with the Plexus service
credential or one the caller picks, reads and stores:

  - the route table (``route_snapshots``) and the running configuration
    (``config_backups``), the two stores the path trace reads, otherwise
    written only by the monitoring poll and Config Backups policies
  - the VLANs (``vlan_definitions``; from the configuration's ``vlan``
    blocks when the VLAN command is rejected or not parsed), the ports
    (``interface_inventory``, merged from the status and switchport tables),
    the CDP / LLDP neighbors (``topology_links``) and the MAC address table,
    which otherwise only the SNMP collectors write; a successful read
    replaces what SNMP stored for that host
  - from the configuration, the IPv4 addresses of the device's interfaces
    (``host_ip_aliases``, which the map matches neighbors and integration
    records by) and its hostname, which replaces a discovery placeholder
    name (``discovered-10-74-103-1``) but never a name a user chose

The show commands and the parsing of their ntc-templates rows come from the
host's driver; a type without a driver gets the Cisco IOS ones, as the
monitoring poll and Config Backups send it. A table the driver has no
command for, or one the device rejects, is skipped. It needs no Meraki or
other integration.

  - ``POST /api/topology/inventory/collect`` starts the collection as a
    background job (kind ``inventory-collection``), polled through
    ``GET /api/sources/builds/{job_id}`` like every other source
  - ``inventory_source()`` is its entry in ``GET /api/topology/sources``

Nothing here runs a configuration command.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

import netcontrol.routes.state as state
from netcontrol.drivers import Driver, DriverCapabilityError, GenericDriver, RouteTableCommands, get_driver
from netcontrol.integrations.pathtrace.platforms import interface_addresses
from netcontrol.integrations.pathtrace.route_tables import interface_key
from netcontrol.routes import background_jobs
from netcontrol.routes.host_identity import interface_ip, is_placeholder_hostname
from netcontrol.routes.ipam_push import push_inventory_host_allocation
from netcontrol.routes.mac_tracking import mac_sightings_from_cli, store_mac_sightings
from netcontrol.routes.meraki_topology import _count_text, _source, _utc_iso
from netcontrol.routes.route_capture import (
    _is_route_table,
    _route_table_commands,
    read_route_table,
    store_route_snapshot,
)
from netcontrol.routes.shared import (
    _audit,
    _get_session,
    _open_netmiko_session,
    require_credential_access,
    service_credential,
    supervise_task,
)
from netcontrol.routes.topology import _write_links_and_stats, invalidate_topology_cache
from netcontrol.telemetry import configure_logging, redact_value

router = APIRouter()
LOGGER = configure_logging("plexus.inventory_collection")

JOB_KIND = "inventory-collection"
SOURCE_KEY = "inventory"
SOURCE_NAME = "All other devices (SSH)"
# The last run, kept so the source entry survives a restart.
SETTING_KEY = "topology_inventory_collection"

# The parts each host is read for, in the order they are read after the
# route table and the configuration, and the names a result counts them by.
TABLE_PARTS = ("vlans", "interfaces", "neighbors", "macs")
PARTS = ("routes", "configs", *TABLE_PARTS)

_SSH_TIMEOUT_SECONDS = 180
_READ_TIMEOUT_SECONDS = 60
_FALLBACK_CONFIG_COMMAND = "show running-config"
# The driver whose table commands a type without a driver gets.
_FALLBACK_TABLE_TYPE = "cisco_ios"
_MAX_MESSAGE_CHARS = 300
# What a neighbor command prints when it has no entry (a read, not a failure).
_NO_ENTRIES = re.compile(r"total\s+(?:cdp\s+)?entries\s+displayed\s*:\s*0\b", re.IGNORECASE)

# The running collection's job id. Check-then-set with no await in between.
_running: dict[str, str] = {}


def _collectable(host: dict) -> bool:
    return str(host.get("device_type") or "") != "icmp_only"


def _commands(device_type: str) -> tuple[RouteTableCommands, str]:
    """The route table commands and the configuration command of a device
    type: its driver's, or the Cisco IOS ones for a type without a driver
    (Aruba, for one), which is what the monitoring poll and Config Backups
    send such a device."""
    try:
        config = get_driver(device_type).capture_running_config_command()
    except DriverCapabilityError:
        config = _FALLBACK_CONFIG_COMMAND
    return _route_table_commands(device_type), config


def _error_text(exc: BaseException) -> str:
    """A short, redacted one-line reason for an error entry."""
    text = str(redact_value(str(exc)) or "").strip().splitlines()
    first = text[0].strip() if text else ""
    message = f"{type(exc).__name__}: {first}" if first else type(exc).__name__
    return message[:_MAX_MESSAGE_CHARS]


def _table_driver(device_type: str) -> Driver:
    """The driver whose commands read the VLAN, port, neighbor and MAC
    tables: the type's own, or Cisco IOS's for a type without a driver (the
    fallback ``_commands`` applies)."""
    driver = get_driver(device_type)
    return get_driver(_FALLBACK_TABLE_TYPE) if isinstance(driver, GenericDriver) else driver


class _NotParsed(Exception):
    """The device printed the table but no ntc-template parsed it."""


def _read_parsed(conn: Any, command: str) -> list[dict] | str | None:
    """Blocking: one show command parsed by ntc-templates. Returns its rows,
    the raw text when no template parsed it, or ``None`` when the device
    rejected the command or printed nothing."""
    output = conn.send_command(command, use_textfsm=True, read_timeout=_READ_TIMEOUT_SECONDS)
    if isinstance(output, list):
        return output
    text = str(output or "")
    if _NO_ENTRIES.search(text):
        return []
    return text if _is_route_table(text) else None


def _config_vlans(driver: Driver, config: str | None) -> list[dict]:
    try:
        return driver.parse_config_vlans(config) if config else []
    except DriverCapabilityError:
        return []


def _read_vlans(conn: Any, driver: Driver, config: str | None) -> list[dict] | None:
    """Blocking: the VLAN table, or the configuration's ``vlan`` blocks when
    the command was rejected, failed or was not parsed."""
    command = driver.vlan_show_command()
    from_config = _config_vlans(driver, config)
    try:
        parsed = _read_parsed(conn, command)
    except Exception:
        if from_config:
            return from_config
        raise
    rows = driver.parse_vlans(parsed) if isinstance(parsed, list) else []
    if rows or from_config:
        return rows or from_config
    if parsed is None:
        return None
    raise _NotParsed


def _read_interfaces(conn: Any, driver: Driver) -> list[dict] | None:
    """Blocking: the port table, merged with the switchport table when the
    platform has one (without it a trunk's allowed VLANs stay unknown)."""
    status = _read_parsed(conn, driver.interface_status_show_command())
    if status is None:
        return None
    if not isinstance(status, list):
        raise _NotParsed
    switchport: list[dict] = []
    try:
        parsed = _read_parsed(conn, driver.interface_switchport_show_command())
        switchport = parsed if isinstance(parsed, list) else []
    except DriverCapabilityError:
        pass
    except Exception as exc:  # noqa: BLE001 - the status table still gives the ports
        LOGGER.debug("inventory collection: switchport table not read: %s", type(exc).__name__)
    return driver.parse_interfaces(status, switchport)


def _read_neighbors(conn: Any, driver: Driver) -> list[dict] | None:
    """Blocking: the CDP and LLDP neighbors, merged. ``None`` when the device
    rejected every neighbor command; a command that fails or is not parsed
    fails the whole read, so the stored links are not replaced by a part."""
    entries: list[dict] = []
    read = False
    for protocol, command in driver.neighbor_show_commands():
        parsed = _read_parsed(conn, command)
        if parsed is None:
            continue
        if not isinstance(parsed, list):
            raise _NotParsed
        entries.extend(driver.parse_neighbors(protocol, parsed))
        read = True
    return _merge_neighbors(entries) if read else None


def _neighbor_key(entry: dict) -> tuple[str, str]:
    # The domain suffix is ignored for matching only; the printed name is stored.
    name = str(entry.get("remote_device_name") or "").strip().lower().split(".")[0]
    return interface_key(str(entry.get("local_interface") or "")), name


def _merge_neighbors(entries: list[dict]) -> list[dict]:
    """One link per local interface and neighbor: an LLDP entry for a
    neighbor CDP also reported is the same link (the CDP row is kept), and
    a repeated entry of one protocol is dropped."""
    merged: dict[tuple[str, str], dict] = {}
    for entry in sorted(entries, key=lambda e: e.get("protocol") != "cdp"):
        merged.setdefault(_neighbor_key(entry), entry)
    return list(merged.values())


def _read_macs(conn: Any, driver: Driver) -> list[dict] | None:
    """Blocking: the MAC address table, as the driver's ``parse_mac_table`` rows."""
    parsed = _read_parsed(conn, driver.mac_table_show_command())
    if parsed is None:
        return None
    if not isinstance(parsed, list):
        raise _NotParsed
    return driver.parse_mac_table(parsed)


def _read_part(outcome: dict[str, Any], key: str, label: str, read: Callable[[], list[dict] | None]) -> None:
    """Run one best-effort table read into ``outcome[key]``. A table the
    driver has no command for is skipped without an error entry."""
    try:
        outcome[key] = read()
    except DriverCapabilityError:
        return
    except _NotParsed:
        outcome["errors"].append(f"{label} not parsed")
    except Exception as exc:  # noqa: BLE001 - the other parts are still read
        outcome["errors"].append(f"{label} not read ({_error_text(exc)})")


def _capture_host(host: dict, credential: dict) -> dict[str, Any]:
    """Blocking: one SSH session to the host, reading its route table, its
    running configuration, then its VLAN, port, neighbor and MAC tables.
    Each part is best effort.

    Returns ``{"skipped", "routes": (text, count) | None, "config": str | None,
    "vlans" | "interfaces" | "neighbors" | "macs": [row, ...] | None,
    "device_type": the type the session resolved, "errors": [message, ...]}``
    (``None``: not read; ``skipped`` is never set: every type gets commands,
    and it is kept so a caller reads one shape).
    """
    outcome: dict[str, Any] = {"skipped": False, "routes": None, "config": None, "errors": []}
    outcome.update(dict.fromkeys(TABLE_PARTS))
    # The type may be autodetected on connect, so the commands follow the resolved one.
    conn, resolved_type = _open_netmiko_session(host, credential)
    outcome["device_type"] = resolved_type
    try:
        route_commands, config_command = _commands(resolved_type)
        try:
            text, count = read_route_table(conn, route_commands, _READ_TIMEOUT_SECONDS)
            if _is_route_table(text):
                outcome["routes"] = (text, count)
            else:
                outcome["errors"].append("Route table not read: the device printed no table")
        except Exception as exc:  # noqa: BLE001 - the configuration is still read
            outcome["errors"].append(f"Route table not read ({_error_text(exc)})")
        try:
            output = str(conn.send_command(config_command, read_timeout=_READ_TIMEOUT_SECONDS) or "")
            # The same check as a route table: output, not the error a device prints.
            if _is_route_table(output):
                outcome["config"] = output
            else:
                outcome["errors"].append("Configuration not read: the device printed no configuration")
        except Exception as exc:  # noqa: BLE001 - recorded in the collection report
            outcome["errors"].append(f"Configuration not read ({_error_text(exc)})")
        driver = _table_driver(resolved_type)
        _read_part(outcome, "vlans", "VLAN table", lambda: _read_vlans(conn, driver, outcome["config"]))
        _read_part(outcome, "interfaces", "Port table", lambda: _read_interfaces(conn, driver))
        _read_part(outcome, "neighbors", "Neighbor table", lambda: _read_neighbors(conn, driver))
        _read_part(outcome, "macs", "MAC table", lambda: _read_macs(conn, driver))
    finally:
        try:
            conn.disconnect()
        except Exception:  # noqa: BLE001 - best-effort teardown
            LOGGER.debug("inventory collection: disconnect failed for %s", host.get("ip_address"))
    return outcome


async def _store_vlans(host_id: int, vlans: list[dict]) -> None:
    """Write the host's VLANs and delete the ones this read did not list."""
    for vlan in vlans:
        await db.upsert_vlan_definition(
            host_id=host_id, vlan_id=int(vlan["vlan_id"]), name=str(vlan["name"]), state=str(vlan["state"])
        )
    await db.delete_vlan_definitions_except(host_id, [int(vlan["vlan_id"]) for vlan in vlans])


async def _store_neighbors(host: dict, neighbors: list[dict]) -> None:
    """Replace the links sourced from the host, as the SNMP discovery writes them."""
    source = {"source_host_id": int(host["id"]), "source_ip": str(host.get("ip_address") or "")}
    await _write_links_and_stats(int(host["id"]), [{**source, **entry} for entry in neighbors], [])


def _config_identity(device_type: str, config: str) -> tuple[str, list[str] | None]:
    """``(hostname, addresses)`` a running configuration sets: the device's
    own name (``""``: none found) and the IPv4 addresses of its interfaces
    (``None``: the platform's configuration is not read). Best effort: a
    configuration a parser trips on gives neither."""
    try:
        hostname = _table_driver(device_type).parse_config_hostname(config)
    except Exception as exc:  # noqa: BLE001 - the addresses are still read
        LOGGER.debug("inventory collection: hostname not parsed: %s", type(exc).__name__)
        hostname = ""
    try:
        found = interface_addresses(device_type, config)
    except Exception as exc:  # noqa: BLE001 - the stored aliases stay
        LOGGER.debug("inventory collection: interface addresses not parsed: %s", type(exc).__name__)
        found = None
    if found is None:
        return hostname, None
    return hostname, list(dict.fromkeys(ip for ip in map(interface_ip, found) if ip))


async def _store_identity(host: dict, device_type: str, config: str, rename_lock: asyncio.Lock) -> None:
    """What the configuration says the device is. Its interface addresses
    become the host's IP aliases, as the SNMP discovery records a device's
    ipAddrTable (none found: the stored aliases stay). Its hostname replaces
    the inventory name only when that is a discovery placeholder for the
    host's address (``discovered-10-74-103-1``) and no other host has the
    name: a name a user chose is never changed. ``rename_lock`` keeps two
    hosts of one run from both taking the same name."""
    host_id = int(host["id"])
    ip = str(host.get("ip_address") or "").strip()
    hostname, addresses = _config_identity(device_type, config)
    if ip and addresses:
        await db.set_host_ip_aliases(host_id, ip, [address for address in addresses if address != ip])
    current = str(host.get("hostname") or "").strip()
    if not ip or not hostname or not is_placeholder_hostname(current, ip):
        return
    async with rename_lock:
        if any(int(other["id"]) != host_id for other in await db.find_hosts_by_hostname(hostname)):
            LOGGER.info(
                "inventory collection: %s (%s) not renamed to %s: another host has that name", current, ip, hostname
            )
            return
        await db.update_host(host_id, hostname, ip, str(host.get("device_type") or ""))
    await push_inventory_host_allocation(hostname=hostname, ip_address=ip, source_hint="inventory-collection")
    LOGGER.info("inventory collection: renamed %s (%s) to %s, its configured hostname", current, ip, hostname)


async def _store_host(host: dict, outcome: dict[str, Any], rename_lock: asyncio.Lock) -> dict[str, bool]:
    """Write what was read into the stores the path trace and the map read.
    Returns, for each of ``PARTS``, whether it was read and stored."""
    host_id = int(host["id"])
    stored = dict.fromkeys(PARTS, False)
    if outcome.get("routes"):
        text, count = outcome["routes"]
        await store_route_snapshot(host_id, text, int(count))
        stored["routes"] = True
    config = outcome.get("config")
    if config:
        latest = (await db.get_latest_config_texts_for_hosts([host_id])).get(host_id)
        # An unchanged configuration writes nothing; the host still counts.
        if latest is None or latest.get("config_text") != config:
            await db.create_config_backup(
                policy_id=None, host_id=host_id, config_text=config, capture_method="topology", status="success"
            )
        stored["configs"] = True
        device_type = str(outcome.get("device_type") or host.get("device_type") or "")
        await _store_identity(host, device_type, config, rename_lock)
    # None: not read, so what SNMP or an earlier run stored stays.
    if outcome.get("vlans") is not None:
        await _store_vlans(host_id, outcome["vlans"])
        stored["vlans"] = True
    if outcome.get("interfaces") is not None:
        await db.replace_interface_inventory_by_name(host_id, outcome["interfaces"])
        stored["interfaces"] = True
    if outcome.get("neighbors") is not None:
        await _store_neighbors(host, outcome["neighbors"])
        stored["neighbors"] = True
    if outcome.get("macs") is not None:
        await store_mac_sightings(host_id, mac_sightings_from_cli(outcome["macs"]))
        stored["macs"] = True
    return stored


def _host_label(host: dict) -> str:
    return str(host.get("hostname") or host.get("ip_address") or host.get("id"))


def _error_entry(host: dict, message: str) -> dict[str, Any]:
    return {
        "host_id": host.get("id"),
        "hostname": host.get("hostname") or "",
        "ip_address": host.get("ip_address") or "",
        "message": message,
    }


def _host_result(error: str | None, *, skipped: bool = False, stored: dict[str, bool] | None = None) -> dict[str, Any]:
    """One host's result: ``skipped``, a flag per part of ``PARTS``, ``error``."""
    return {"skipped": skipped, **dict.fromkeys(PARTS, False), **(stored or {}), "error": error}


async def _collect_host(host: dict, credential: dict, rename_lock: asyncio.Lock) -> dict[str, Any]:
    """One host: capture over SSH, then store. Never raises."""
    try:
        async with state.device_op_semaphore():
            outcome = await asyncio.wait_for(
                asyncio.to_thread(_capture_host, host, credential), timeout=_SSH_TIMEOUT_SECONDS
            )
    except TimeoutError:
        return _host_result(f"Timed out after {_SSH_TIMEOUT_SECONDS} s")
    except Exception as exc:  # noqa: BLE001 - recorded in the collection report
        LOGGER.warning("inventory collection: SSH failed for %s: %s", _host_label(host), redact_value(str(exc)))
        return _host_result(f"SSH failed ({_error_text(exc)})")
    if outcome.get("skipped"):
        return _host_result(None, skipped=True)
    try:
        stored = await _store_host(host, outcome, rename_lock)
    except Exception as exc:  # noqa: BLE001 - recorded in the collection report
        LOGGER.warning("inventory collection: store failed for %s: %s", _host_label(host), redact_value(str(exc)))
        return _host_result("Capture not saved; see the server log")
    errors = outcome.get("errors") or []
    return _host_result("; ".join(errors) or None, stored=stored)


def _scope_text(group_id: int | None, host_ids: list[int] | None) -> str:
    if host_ids is not None:
        return f"hosts:{len(host_ids)}"
    if group_id is not None:
        return f"group:{group_id}"
    return "all"


async def _record(summary: dict[str, Any]) -> None:
    try:
        await db.set_auth_setting(SETTING_KEY, summary)
    except Exception as exc:  # noqa: BLE001 - the job result still carries the run
        LOGGER.warning("inventory collection: last run not saved: %s", redact_value(str(exc)))


async def _run_collection(job_id: str, hosts: list[dict], credential: dict, user: str, scope: str) -> None:
    """Background task: collect every host, store, record the run."""
    started = time.monotonic()
    total = len(hosts)
    done = 0
    errors: list[dict[str, Any]] = []
    counts = {"collected": 0, **dict.fromkeys(PARTS, 0), "skipped": 0}
    rename_lock = asyncio.Lock()

    async def _one(host: dict) -> None:
        nonlocal done
        outcome = await _collect_host(host, credential, rename_lock)
        counts["skipped"] += int(bool(outcome["skipped"]))
        for part in PARTS:
            counts[part] += int(bool(outcome[part]))
        counts["collected"] += int(any(outcome[part] for part in PARTS))
        if outcome["error"]:
            errors.append(_error_entry(host, str(outcome["error"])))
        done += 1
        background_jobs.update_progress(
            job_id, phase="collecting", hosts_done=done, hosts_total=total, host=_host_label(host)
        )

    status = "failed"
    error: str | None = "Inventory collection failed; see the server log for details"
    result: dict[str, Any] | None = None
    try:
        background_jobs.update_progress(job_id, phase="collecting", hosts_done=0, hosts_total=total, host="")
        await asyncio.gather(*(_one(host) for host in hosts))
        background_jobs.update_progress(job_id, phase="saving")
        if counts["neighbors"]:
            # Once per run, as the scheduled SNMP discovery does.
            try:
                await db.resolve_topology_target_host_ids()
            except Exception as exc:  # noqa: BLE001 - the links stay, unresolved
                LOGGER.warning("inventory collection: target host id resolution failed: %s", redact_value(str(exc)))
        if counts["collected"]:
            invalidate_topology_cache()
        errors.sort(key=lambda e: (str(e["hostname"]), str(e["ip_address"])))
        result = {
            "hosts": total,
            **counts,
            "errors": errors,
            "warning_count": len(errors),
            "duration_seconds": round(time.monotonic() - started, 2),
        }
        if not errors:
            status, error = "completed", None
        elif counts["collected"]:
            status, error = "partial", None
        else:
            error = f"No device was collected: {errors[0]['message']}"
    except Exception as exc:  # noqa: BLE001 - job must always reach a terminal state
        LOGGER.exception("inventory collection crashed: %s", type(exc).__name__)
    finally:
        _running.pop("job", None)
        await _record(
            {
                "at": datetime.now(UTC).isoformat(),
                "status": {"completed": "success"}.get(status, status),
                "message": error or "",
                "hosts": total,
                "collected": counts["collected"],
                **{part: counts[part] for part in PARTS},
                "errors": len(errors),
                "scope": scope,
            }
        )
        background_jobs.finish_job(job_id, status, result=result, error=error)
        parts_text = " ".join(f"{part}={counts[part]}" for part in PARTS)
        await _audit(
            "inventory_collection",
            "collect",
            user=user,
            detail=(
                f"scope={scope} status={status} hosts={total} collected={counts['collected']} "
                f"{parts_text} errors={len(errors)}"
            ),
        )


# How the source entry's detail names each part's count.
_PART_NOUNS = {
    "routes": "route table",
    "configs": "configuration",
    "vlans": "VLAN table",
    "interfaces": "port table",
    "neighbors": "neighbor table",
    "macs": "MAC table",
}


def _detail_text(last: dict[str, Any]) -> str:
    """``"13 of 13 devices: 13 route tables, 13 configurations, ..."`` of the last run."""
    parts = ", ".join(_count_text(last.get(part), noun) for part, noun in _PART_NOUNS.items())
    return f"{int(last.get('collected') or 0)} of {_count_text(last.get('hosts'), 'device')}: {parts}"


async def inventory_source() -> dict[str, Any]:
    """This collection as an entry of ``GET /api/topology/sources``."""
    hosts = sum(1 for host in await db.get_all_hosts() if _collectable(host))
    last = await db.get_auth_setting(SETTING_KEY) or {}
    ran = bool(last.get("at"))
    service = await service_credential()
    return _source(
        SOURCE_KEY,
        SOURCE_KEY,
        SOURCE_NAME,
        status=str(last.get("status") or "never") if ran else "never",
        last_collected_at=_utc_iso(last.get("at")) if ran else None,
        message=str(last.get("message") or "") if ran else "",
        detail=_detail_text(last) if ran else f"{_count_text(hosts, 'device')} in inventory",
        warning_count=int(last.get("errors") or 0) if ran else 0,
        collecting="job" in _running,
        can_collect=hosts > 0,
        # The service credential Settings names is the default; the dialog
        # lists the others for an administrator to pick.
        service_credential=service is not None,
        service_credential_id=int(service["id"]) if service else None,
    )


class InventoryCollectRequest(BaseModel):
    # One inventory group's direct hosts; none: every host.
    group_id: int | None = None
    # Explicit hosts; takes precedence over group_id.
    host_ids: list[int] | None = Field(default=None, max_length=10000)
    # A stored credential the caller may use; none: the Plexus service credential.
    credential_id: int | None = None


async def _hosts_in_scope(body: InventoryCollectRequest) -> list[dict]:
    if body.host_ids is not None:
        wanted = sorted(set(body.host_ids))
        hosts = await db.get_hosts_by_ids(wanted) if wanted else []
        unknown = sorted(set(wanted) - {int(h["id"]) for h in hosts})
        if unknown:
            raise HTTPException(status_code=400, detail=f"Unknown host ids: {', '.join(map(str, unknown[:20]))}")
    elif body.group_id is not None:
        if await db.get_group(body.group_id) is None:
            raise HTTPException(status_code=404, detail="Inventory group not found")
        hosts = await db.get_hosts_for_group(body.group_id)
    else:
        hosts = await db.get_all_hosts()
    return [host for host in hosts if _collectable(host)]


@router.post("/api/topology/inventory/collect", status_code=202)
async def collect_inventory_api(request: Request, body: InventoryCollectRequest | None = None):
    """Read the route table, the running configuration and the VLAN, port,
    CDP/LLDP neighbor and MAC address tables of inventory hosts over SSH into
    the stores the path trace and the map read. Poll
    ``/api/sources/builds/{job_id}`` for progress; its result counts, per
    part (``routes``, ``configs``, ``vlans``, ``interfaces``, ``neighbors``,
    ``macs``), the hosts it was read from."""
    body = body or InventoryCollectRequest()
    hosts = await _hosts_in_scope(body)
    if not hosts:
        raise HTTPException(status_code=400, detail="No collectable inventory device is in scope")
    session = _get_session(request)
    credential: dict | None
    if body.credential_id is not None:
        credential = await require_credential_access(body.credential_id, session=session, allow_service=True)
    else:
        credential = await service_credential()
    if credential is None:
        raise HTTPException(
            status_code=400, detail="No credential: set a Plexus service credential in Settings or pick a credential"
        )
    # Check-then-set with no await in between: atomic under asyncio.
    if "job" in _running:
        raise HTTPException(status_code=409, detail="An inventory collection is already running")
    job = background_jobs.create_job(
        JOB_KIND, {"phase": "starting", "hosts_done": 0, "hosts_total": len(hosts), "host": ""}
    )
    _running["job"] = job["job_id"]
    scope = _scope_text(body.group_id, body.host_ids)
    user = (session or {}).get("user", "")
    supervise_task(
        asyncio.create_task(_run_collection(job["job_id"], hosts, credential, user, scope)), "inventory-collection"
    )
    return {"job_id": job["job_id"], "status": "running"}
