"""Device categories: the role a host plays on the map (``hosts.device_category``).

The category picks the Topology node icon and tier, the Ansible inventory
filter and the role a host gets when a device role of the same name exists.
This is the one list of them: the category route validates against it, the
offline viewer maps it to node kinds, and SNMP discovery infers one.
"""

from __future__ import annotations

# Every category a host may carry; ``""`` (not listed) lets the map fall back
# to the device type.
DEVICE_CATEGORIES: tuple[str, ...] = (
    "router",
    "switch",
    "firewall",
    "wireless",
    "wlc",
    "phone",
    "server",
    "ups",
)

# Device types whose category is known from the type alone.
DEVICE_TYPE_CATEGORIES: dict[str, str] = {
    "apc_ups": "ups",
}


def device_type_category(device_type: str) -> str:
    """The category a device type implies, or ``""``."""
    return DEVICE_TYPE_CATEGORIES.get((device_type or "").strip(), "")
