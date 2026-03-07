from __future__ import annotations

from typing import Any

from Firewall_converter.converter_v2.core.route_converter import RouteConverter

from .models import FTDStaticRouteObject


def convert_routes_v2(
    fortigate_config: dict[str, Any],
    network_objects: list[dict[str, Any]] | None = None,
    interface_name_mapping: dict[str, str] | None = None,
    converted_interfaces: dict[str, list[dict[str, Any]]] | None = None,
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Convert FortiGate static routes using a typed v2 adapter.

    This keeps legacy conversion behavior for parity while introducing typed
    v2 internals as a migration step.
    """
    legacy_output = RouteConverter(
        fortigate_config=fortigate_config,
        network_objects=network_objects,
        interface_name_mapping=interface_name_mapping,
        converted_interfaces=converted_interfaces,
        debug=debug,
    ).convert()

    typed_objects = [FTDStaticRouteObject.from_legacy(item) for item in legacy_output]
    return [item.to_legacy_dict() for item in typed_objects]
