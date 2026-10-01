"""Client records of a Meraki collection, for MAC tracking.

A topology snapshot carries clients only as capped display tables. MAC
tracking wants every client, as rows it can upsert and search, so this reads
them straight from the raw collection (``networks_detail[...]["clients"]``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

_STAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


def normalize_mac(raw: Any) -> str:
    """Canonical ``aa:bb:cc:dd:ee:ff``, or ``""`` when ``raw`` is not a MAC."""
    hex_only = "".join(c for c in str(raw or "").lower() if c in "0123456789abcdef")
    if len(hex_only) != 12:
        return ""
    return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))


def _stamp(raw: Any, fallback: str) -> str:
    """Meraki timestamp (ISO 8601 text or epoch seconds) as UTC text."""
    try:
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            moment = datetime.fromtimestamp(raw, UTC)
        else:
            moment = datetime.fromisoformat(str(raw or "").strip().replace("Z", "+00:00"))
            moment = moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)
    except ValueError, OverflowError, OSError:
        return fallback
    return moment.strftime(_STAMP_FORMAT)


def _vlan(raw: Any) -> int:
    try:
        vlan = int(str(raw).strip())
    except TypeError, ValueError:
        return 0
    return vlan if 1 <= vlan <= 4094 else 0


def _text(raw: Any, limit: int = 200) -> str:
    return str(raw if raw is not None else "").strip()[:limit]


def search_entry(row: dict[str, Any]) -> dict[str, Any]:
    """A stored client in the shape of a MAC tracking search result.

    ``hostname`` is the Meraki device the client was last seen on, and
    ``(org_ref, node_id)`` is that device's node on the topology map.
    """
    serial = row.get("device_serial") or ""
    return {
        "id": row.get("id"),
        "source": "meraki",
        "host_id": None,
        "hostname": row.get("device_name") or serial,
        "host_ip": "",
        "mac_address": row.get("mac_address") or "",
        "ip_address": row.get("ip_address") or "",
        "vlan": row.get("vlan") or 0,
        "port_name": row.get("port_name") or "",
        "port_index": 0,
        "entry_type": "wireless" if row.get("ssid") else "wired",
        "first_seen": row.get("first_seen") or "",
        "last_seen": row.get("last_seen") or "",
        "org_ref": row.get("org_ref"),
        "org_name": row.get("org_name") or "",
        "node_id": f"d:{serial}" if serial else "",
        "network_name": row.get("network_name") or "",
        "description": row.get("description") or "",
        "manufacturer": row.get("manufacturer") or "",
        "ssid": row.get("ssid") or "",
        "status": row.get("status") or "",
    }


def client_records(raw: dict[str, Any], collected_at: datetime | None = None) -> list[dict[str, Any]]:
    """One record per (network, MAC) of a raw collection.

    ``last_seen`` / ``first_seen`` are Meraki's own times when it reports
    them, else the time of the collection. A MAC listed twice in one network
    keeps its most recent sighting.
    """
    now = (collected_at or datetime.now(UTC)).astimezone(UTC).strftime(_STAMP_FORMAT)
    network_names = {n.get("id"): n.get("name") for n in raw.get("networks") or [] if isinstance(n, dict)}
    device_names = {d.get("serial"): d.get("name") for d in raw.get("devices") or [] if isinstance(d, dict)}
    records: dict[tuple[str, str], dict[str, Any]] = {}
    for net_id, detail in (raw.get("networks_detail") or {}).items():
        for client in (detail or {}).get("clients") or []:
            if not isinstance(client, dict):
                continue
            mac = normalize_mac(client.get("mac"))
            if not mac:
                continue
            serial = _text(client.get("recentDeviceSerial"))
            record = {
                "network_id": _text(net_id),
                "network_name": _text(network_names.get(net_id)),
                "mac_address": mac,
                "ip_address": _text(client.get("ip")),
                "vlan": _vlan(client.get("vlan")),
                "device_serial": serial,
                "device_name": _text(client.get("recentDeviceName") or device_names.get(serial)),
                "port_name": _text(client.get("switchport")),
                "description": _text(client.get("description") or client.get("user")),
                "manufacturer": _text(client.get("manufacturer")),
                "ssid": _text(client.get("ssid")),
                "status": _text(client.get("status")),
                "first_seen": _stamp(client.get("firstSeen"), now),
                "last_seen": _stamp(client.get("lastSeen"), now),
            }
            key = (record["network_id"], mac)
            if key not in records or record["last_seen"] > records[key]["last_seen"]:
                records[key] = record
    return list(records.values())
