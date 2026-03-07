#!/usr/bin/env python3
"""V2 conversion entrypoint that preserves legacy output artifacts.

This script keeps the same file contract used by importer/cleanup while routing
conversion through the typed v2 adapters.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

# Ensure package imports work when invoked as a standalone script path.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from Firewall_converter.converter_v2 import (  # noqa: E402
    convert_address_groups_v2,
    convert_addresses_v2,
    convert_interfaces_v2,
    convert_policies_v2,
    convert_routes_v2,
    convert_service_groups_v2,
    convert_services_v2,
)
from Firewall_converter.FortiGateToFTDTool.interface_converter import (  # noqa: E402
    FTD_MODELS,
    InterfaceConverter,
    print_supported_models,
)
from Firewall_converter.FortiGateToFTDTool.route_converter import RouteConverter  # noqa: E402
from Firewall_converter.FortiGateToFTDTool.service_converter import ServiceConverter  # noqa: E402


def preprocess_yaml_file(input_file: str) -> str:
    """Remove sections known to break YAML parsing before loading."""
    sections_to_skip = {
        "system_automation-trigger:",
        "dlp_filepattern:",
        "system_automation-action:",
        "dlp_sensor:",
        "dlp_settings:",
    }

    cleaned_lines: list[str] = []
    skip_section = False
    current_indent = 0

    with open(input_file, encoding="utf-8") as handle:
        for line in handle:
            stripped = line.lstrip()
            indent = len(line) - len(stripped) if stripped else 0

            if any(line.strip().startswith(section) for section in sections_to_skip):
                skip_section = True
                current_indent = indent
                continue

            if skip_section:
                if stripped and indent <= current_indent:
                    skip_section = False
                else:
                    continue

            cleaned_lines.append(line)

    return "".join(cleaned_lines)


def write_json_file(path: str, data: object, pretty: bool = False) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        if pretty:
            json.dump(data, handle, indent=2)
        else:
            json.dump(data, handle, separators=(",", ":"))


def build_conversion_metadata(args: argparse.Namespace) -> dict[str, Any]:
    default_ha = FTD_MODELS.get(args.target_model, {}).get("ha_port")
    return {
        "target_model": str(args.target_model).lower().strip(),
        "output_basename": str(args.output).strip(),
        "ha_port": args.ha_port if args.ha_port else default_ha,
        "schema_version": 1,
    }


def _dedupe_network_objects(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for obj in objects:
        name = str(obj.get("name", ""))
        if not name or name in seen:
            continue
        seen.add(name)
        deduped.append(obj)
    return deduped


def _sanitize(name: str) -> str:
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", str(name))
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")
    return sanitized


def _service_stats(port_objects: list[dict[str, Any]]) -> dict[str, int]:
    tcp = sum(1 for item in port_objects if item.get("type") == "tcpportobject")
    udp = sum(1 for item in port_objects if item.get("type") == "udpportobject")
    return {
        "total_objects": len(port_objects),
        "tcp_objects": tcp,
        "udp_objects": udp,
    }


def _policy_stats(access_rules: list[dict[str, Any]]) -> dict[str, int]:
    permit = sum(1 for rule in access_rules if str(rule.get("ruleAction", "")).upper() == "PERMIT")
    deny = sum(1 for rule in access_rules if str(rule.get("ruleAction", "")).upper() == "DENY")
    return {
        "total_rules": len(access_rules),
        "permit_rules": permit,
        "deny_rules": deny,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert FortiGate YAML configuration to Cisco FTD JSON artifacts using converter_v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input_file", nargs="?", help="Path to FortiGate YAML configuration file")
    parser.add_argument("-o", "--output", default="ftd_config", help="Base name for output JSON files")
    parser.add_argument("-p", "--pretty", action="store_true", help="Pretty-print output JSON")
    parser.add_argument("-m", "--target-model", default="ftd-3120", help="Target FTD firewall model")
    parser.add_argument(
        "--ha-port",
        type=str,
        default=None,
        metavar="ETHERNET_PORT",
        help="Custom HA port (for example: Ethernet1/5)",
    )
    parser.add_argument("--list-models", action="store_true", help="List supported FTD models and exit")

    args = parser.parse_args()

    if args.list_models:
        print_supported_models()
        return 0

    if not args.input_file:
        parser.error("input_file is required (unless using --list-models)")

    try:
        fg_config = yaml.safe_load(preprocess_yaml_file(args.input_file))
        if not isinstance(fg_config, dict):
            print("[ERROR] Parsed YAML did not produce a mapping/dictionary.")
            return 1
    except FileNotFoundError:
        print(f"[ERROR] Input file '{args.input_file}' not found")
        return 1
    except yaml.YAMLError as exc:
        print(f"[ERROR] Could not parse YAML file: {exc}")
        return 1

    try:
        interface_converter = InterfaceConverter(
            fg_config,
            target_model=args.target_model,
            custom_ha_port=args.ha_port,
        )
        # Run once to build interface mapping/stats required by policies/routes.
        interface_converter.convert()
        interface_name_mapping = interface_converter.get_interface_mapping()
        intf_stats = interface_converter.get_statistics()

        interface_results = convert_interfaces_v2(
            fortigate_config=fg_config,
            target_model=args.target_model,
            custom_ha_port=args.ha_port,
        )

        network_objects = convert_addresses_v2(fg_config)
        network_objects = _dedupe_network_objects(network_objects)
        address_object_names = {str(item.get("name", "")) for item in network_objects if item.get("name")}

        network_groups = convert_address_groups_v2(
            fortigate_config=fg_config,
            address_object_names=address_object_names,
        )
        address_groups = {
            str(group.get("name", "")) for group in network_groups if group.get("name")
        }

        service_converter = ServiceConverter(fg_config)
        service_converter.convert()
        service_name_mapping = service_converter.get_service_name_mapping()
        skipped_services = service_converter.get_skipped_services()

        split_services = {
            service_name
            for service_name, mapped in service_name_mapping.items()
            if len(mapped) > 1
        }

        port_objects = convert_services_v2(fg_config)
        service_stats = _service_stats(port_objects)

        port_groups = convert_service_groups_v2(
            fortigate_config=fg_config,
            split_services=split_services,
            service_name_mapping=service_name_mapping,
            skipped_services=skipped_services,
        )
        service_groups = {
            str(group.get("name", "")) for group in port_groups if group.get("name")
        }

        access_rules = convert_policies_v2(
            fortigate_config=fg_config,
            split_services=split_services,
            service_name_mapping=service_name_mapping,
            skipped_services=skipped_services,
            address_name_mapping={_sanitize(name): _sanitize(name) for name in address_object_names},
            address_groups=address_groups,
            service_groups=service_groups,
            interface_name_mapping=interface_name_mapping,
        )
        policy_stats = _policy_stats(access_rules)

        converted_interfaces = {
            "physical_interfaces": interface_results.get("physical_interfaces", []),
            "subinterfaces": interface_results.get("subinterfaces", []),
            "etherchannels": interface_results.get("etherchannels", []),
            "bridge_groups": interface_results.get("bridge_groups", []),
        }
        route_converter = RouteConverter(
            fortigate_config=fg_config,
            network_objects=network_objects,
            interface_name_mapping=interface_name_mapping,
            converted_interfaces=converted_interfaces,
            debug=False,
        )
        route_converter.convert()
        route_stats = route_converter.get_statistics()

        static_routes = convert_routes_v2(
            fortigate_config=fg_config,
            network_objects=network_objects,
            interface_name_mapping=interface_name_mapping,
            converted_interfaces=converted_interfaces,
            debug=False,
        )

        generated_route_objects = getattr(route_converter, "generated_network_objects", None)
        if generated_route_objects:
            existing_names = {
                str(obj.get("name", "")) for obj in network_objects if isinstance(obj, dict)
            }
            for obj in generated_route_objects:
                if not isinstance(obj, dict):
                    continue
                obj_name = str(obj.get("name", ""))
                if obj_name and obj_name not in existing_names:
                    network_objects.append(obj)
                    existing_names.add(obj_name)

        metadata = build_conversion_metadata(args)
        summary = {
            "conversion_summary": {
                "interfaces": {
                    "physical_updated": intf_stats["physical_updated"],
                    "subinterfaces_created": intf_stats["subinterfaces_created"],
                    "etherchannels_created": intf_stats["etherchannels_created"],
                    "bridge_groups_created": intf_stats["bridge_groups_created"],
                    "security_zones_created": intf_stats["security_zones_created"],
                    "skipped": intf_stats["skipped"],
                },
                "address_objects": len(network_objects),
                "address_groups": len(network_groups),
                "service_objects": {
                    "total": service_stats["total_objects"],
                    "tcp": service_stats["tcp_objects"],
                    "udp": service_stats["udp_objects"],
                    "split": len(split_services),
                },
                "service_groups": len(port_groups),
                "access_rules": {
                    "total": policy_stats["total_rules"],
                    "permit": policy_stats["permit_rules"],
                    "deny": policy_stats["deny_rules"],
                },
                "static_routes": {
                    "total": route_stats["total_routes"],
                    "converted": route_stats["converted"],
                    "blackhole_skipped": route_stats["blackhole_skipped"],
                    "other_skipped": route_stats["other_skipped"],
                },
            }
        }

        base = args.output
        write_json_file(f"{base}_metadata.json", metadata, pretty=args.pretty)
        write_json_file(f"{base}_address_objects.json", network_objects, pretty=args.pretty)
        write_json_file(f"{base}_address_groups.json", network_groups, pretty=args.pretty)
        write_json_file(f"{base}_service_objects.json", port_objects, pretty=args.pretty)
        write_json_file(f"{base}_service_groups.json", port_groups, pretty=args.pretty)
        write_json_file(f"{base}_access_rules.json", access_rules, pretty=args.pretty)
        write_json_file(f"{base}_static_routes.json", static_routes, pretty=args.pretty)
        write_json_file(f"{base}_physical_interfaces.json", interface_results.get("physical_interfaces", []), pretty=args.pretty)
        write_json_file(f"{base}_subinterfaces.json", interface_results.get("subinterfaces", []), pretty=args.pretty)
        write_json_file(f"{base}_etherchannels.json", interface_results.get("etherchannels", []), pretty=args.pretty)
        write_json_file(f"{base}_bridge_groups.json", interface_results.get("bridge_groups", []), pretty=args.pretty)
        write_json_file(f"{base}_security_zones.json", interface_results.get("security_zones", []), pretty=args.pretty)
        with open(f"{base}_summary.json", "w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2)

        print("[OK] V2 conversion complete")
        return 0
    except Exception as exc:
        print(f"[ERROR] Conversion failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
