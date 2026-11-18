"""Device type component templates: the limits and rules, with no I/O.

A device type lists the components every device of that type has. When a
host gets the device type (or on the explicit "instantiate components"
action) Plexus creates the missing ones as DCIM records of the host:

    template           DCIM record (routes.db.dcim kind)
    console_port   ->  console_port
    power_port     ->  power_port
    rear_port      ->  rear_port
    front_port     ->  front_port (mapped to the host's rear port of the
                       rear port template's name)
    module_bay     ->  module (the bay, with no module type yet, planned)
    interface      ->  no record: interfaces are what Plexus collects from
                       the device, so an interface template is compared
                       with the host's known interface names instead

A component is matched to a template by name, ignoring case; one that
exists is never changed or duplicated. Storage:
``routes.db.component_templates``; docs: ``docs/device-model.md``.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal, get_args

from netcontrol.custom_fields import clean_name

__all__ = [
    "COMPONENT_KINDS",
    "COMPONENT_TYPES",
    "INTERFACE_TYPE_MAX",
    "TEMPLATE_NAME_MAX",
    "ComponentType",
    "clean_template_name",
    "draw_error",
    "missing_interfaces",
    "plan_components",
]

ComponentType = Literal["interface", "console_port", "power_port", "rear_port", "front_port", "module_bay"]
COMPONENT_TYPES: tuple[str, ...] = get_args(ComponentType)
# Template type -> the DCIM record kind it creates (interface: none).
COMPONENT_KINDS: dict[str, str] = {
    "console_port": "console_port",
    "power_port": "power_port",
    "rear_port": "rear_port",
    "front_port": "front_port",
    "module_bay": "module",
}
TEMPLATE_NAME_MAX = 100
INTERFACE_TYPE_MAX = 50
# Rear ports first: a front port maps to one.
_ORDER = ("console_port", "power_port", "rear_port", "front_port", "module_bay")


def clean_template_name(raw: object) -> str:
    return clean_name(raw, "Component name", TEMPLATE_NAME_MAX)


def draw_error(maximum: int | None, allocated: int | None) -> str | None:
    """Why a power draw pair is refused, or ``None``."""
    if maximum is not None and allocated is not None and int(allocated) > int(maximum):
        return "The allocated draw cannot exceed the maximum draw."
    return None


def _values(template: dict, rear_names: dict[int, str]) -> dict:
    """The record values (without ``host_id``) one template creates. A front
    port carries ``rear_port_name``, resolved to the host's port on write."""
    kind = template["component_type"]
    description = template.get("description") or ""
    if kind == "module_bay":
        return {"bay": template["name"], "status": "planned", "description": description}
    values: dict = {"name": template["name"], "description": description}
    if kind in ("console_port", "rear_port", "front_port") and template.get("type"):
        values["type"] = template["type"]
    if kind == "rear_port":
        values["positions"] = int(template.get("positions") or 1)
    elif kind == "front_port":
        values["rear_port_name"] = rear_names.get(int(template.get("rear_port_template_id") or 0), "")
        values["rear_port_position"] = int(template.get("rear_port_position") or 1)
    elif kind == "power_port":
        values["maximum_draw"] = template.get("maximum_draw")
        values["allocated_draw"] = template.get("allocated_draw")
    return values


def plan_components(templates: Iterable[dict], existing: dict[str, Iterable[str]]) -> list[tuple[str, dict]]:
    """The DCIM records to create for a host: ``(kind, values)`` for each
    template whose component the host lacks (``existing``: kind -> the names
    it has, a module's by bay), rear ports before front ports."""
    rows = list(templates)
    have = {kind: {str(n).lower() for n in names} for kind, names in existing.items()}
    rear_names = {int(t["id"]): str(t["name"]) for t in rows if t["component_type"] == "rear_port"}
    plan: list[tuple[str, dict]] = []
    for component_type in _ORDER:
        kind = COMPONENT_KINDS[component_type]
        for template in rows:
            if template["component_type"] != component_type:
                continue
            if str(template["name"]).lower() in have.get(kind, set()):
                continue
            plan.append((kind, _values(template, rear_names)))
            have.setdefault(kind, set()).add(str(template["name"]).lower())
    return plan


def missing_interfaces(templates: Iterable[dict], known: Iterable[str]) -> list[str]:
    """The interface template names the host has no interface for (case
    ignored), in template order."""
    have = {str(n).lower() for n in known}
    return [
        str(t["name"]) for t in templates if t["component_type"] == "interface" and str(t["name"]).lower() not in have
    ]
