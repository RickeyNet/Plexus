#!/usr/bin/env python3
"""Benchmark and profile converter_v2 behavior on synthetic large configs.

Focus areas:
- Address/service group flattening
- Service expansion in policy conversion
- Static route conversion
"""

from __future__ import annotations

import argparse
import cProfile
import io
import pstats
import sys
import time
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from Firewall_converter.converter_v2.core.address_group_converter import AddressGroupConverter
from Firewall_converter.converter_v2.core.policy_converter import PolicyConverter
from Firewall_converter.converter_v2.core.route_converter import RouteConverter
from Firewall_converter.converter_v2.core.service_converter import ServiceConverter
from Firewall_converter.converter_v2.core.service_group_converter import ServiceGroupConverter


def _build_large_config(
    address_objects: int,
    address_groups: int,
    service_objects: int,
    service_groups: int,
    routes: int,
    rules: int,
) -> dict[str, Any]:
    firewall_address = [
        {f"Host_{i}": {"subnet": [f"10.{(i // 254) % 255}.{i % 254 + 1}.1", "255.255.255.255"]}}
        for i in range(address_objects)
    ]

    firewall_addrgrp: list[dict[str, Any]] = []
    for i in range(address_groups):
        members: list[str] = [f"Host_{i % max(1, address_objects)}"]
        if i > 0:
            members.append(f"AddrGrp_{i-1}")
        if i > 1:
            members.append(f"AddrGrp_{i-2}")
        firewall_addrgrp.append({f"AddrGrp_{i}": {"member": members}})

    firewall_service_custom: list[dict[str, Any]] = []
    for i in range(service_objects):
        service_name = f"Svc_{i}"
        if i % 5 == 0:
            payload = {"tcp-portrange": [str(10000 + i), str(11000 + i)], "udp-portrange": str(12000 + i)}
        elif i % 2 == 0:
            payload = {"tcp-portrange": str(1000 + i)}
        else:
            payload = {"udp-portrange": str(2000 + i)}
        firewall_service_custom.append({service_name: payload})

    firewall_service_group: list[dict[str, Any]] = []
    for i in range(service_groups):
        members: list[str] = [f"Svc_{i % max(1, service_objects)}"]
        if i > 0:
            members.append(f"SvcGrp_{i-1}")
        firewall_service_group.append({f"SvcGrp_{i}": {"member": members}})

    router_static = []
    for i in range(routes):
        network_octet = i % 250
        route = {
            i + 1: {
                "dst": [f"172.16.{network_octet}.0", "255.255.255.0"],
                "gateway": f"10.0.{(i // 250) % 255}.{(i % 250) + 1}",
                "distance": (i % 10) + 1,
                "device": "port2",
                "comment": f"Route_{i}",
            }
        }
        router_static.append(route)

    firewall_policy = []
    for i in range(rules):
        src_group = f"AddrGrp_{i % max(1, address_groups)}"
        dst_group = f"AddrGrp_{(i + 7) % max(1, address_groups)}"
        svc_group = f"SvcGrp_{i % max(1, service_groups)}"
        firewall_policy.append(
            {
                i + 1000: {
                    "name": f"Rule_{i}",
                    "srcintf": ["inside"],
                    "dstintf": ["outside"],
                    "action": "accept" if i % 4 else "deny",
                    "srcaddr": [src_group],
                    "dstaddr": [dst_group],
                    "service": [svc_group],
                }
            }
        )

    return {
        "firewall_address": firewall_address,
        "firewall_addrgrp": firewall_addrgrp,
        "firewall_service_custom": firewall_service_custom,
        "firewall_service_group": firewall_service_group,
        "router_static": router_static,
        "firewall_policy": firewall_policy,
    }


def _profile(label: str, fn) -> tuple[Any, float, str]:
    profiler = cProfile.Profile()
    start = time.perf_counter()
    with redirect_stdout(io.StringIO()):
        profiler.enable()
        result = fn()
        profiler.disable()
    duration = time.perf_counter() - start

    stream = io.StringIO()
    stats = pstats.Stats(profiler, stream=stream).sort_stats("cumulative")
    stats.print_stats(15)
    return result, duration, stream.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark converter_v2 scale behavior with synthetic data")
    parser.add_argument("--objects", type=int, default=2200, help="Number of address objects (default: 2200)")
    parser.add_argument("--rules", type=int, default=2200, help="Number of policy rules (default: 2200)")
    parser.add_argument("--routes", type=int, default=1200, help="Number of routes (default: 1200)")
    parser.add_argument("--group-ratio", type=float, default=0.5, help="Groups as fraction of objects (default: 0.5)")
    args = parser.parse_args()

    addr_groups = max(1, int(args.objects * args.group_ratio))
    svc_objects = max(1, int(args.objects * 0.35))
    svc_groups = max(1, int(svc_objects * args.group_ratio))

    fg = _build_large_config(
        address_objects=args.objects,
        address_groups=addr_groups,
        service_objects=svc_objects,
        service_groups=svc_groups,
        routes=args.routes,
        rules=args.rules,
    )

    print("=== Synthetic Benchmark Input ===")
    print(f"address_objects={args.objects} address_groups={addr_groups}")
    print(f"service_objects={svc_objects} service_groups={svc_groups}")
    print(f"routes={args.routes} rules={args.rules}")

    addr_converter = AddressGroupConverter(
        fortigate_config=fg,
        address_object_names={f"Host_{i}" for i in range(args.objects)},
    )
    addr_groups_out, addr_time, addr_profile = _profile("address_groups", addr_converter.convert)

    svc_converter = ServiceConverter(fg)
    _, svc_obj_time, svc_obj_profile = _profile("service_objects", svc_converter.convert)
    service_name_mapping = svc_converter.get_service_name_mapping()
    skipped_services = svc_converter.get_skipped_services()

    svc_group_converter = ServiceGroupConverter(
        fortigate_config=fg,
        service_name_mapping=service_name_mapping,
        skipped_services=skipped_services,
    )
    svc_groups_out, svc_group_time, svc_group_profile = _profile("service_groups", svc_group_converter.convert)

    policy_converter = PolicyConverter(
        fortigate_config=fg,
        service_name_mapping=service_name_mapping,
        skipped_services=skipped_services,
        address_group_members={
            grp["name"]: [obj["name"] for obj in grp.get("objects", [])]
            for grp in addr_groups_out
        },
        address_groups={grp["name"] for grp in addr_groups_out},
        service_groups={grp["name"] for grp in svc_groups_out},
        interface_name_mapping={"inside": "inside", "outside": "outside", "port2": "inside"},
    )
    _, policy_time, policy_profile = _profile("policies", policy_converter.convert)

    route_converter = RouteConverter(
        fortigate_config=fg,
        network_objects=[
            {
                "name": f"Host_{i}",
                "description": "",
                "type": "networkobject",
                "subType": "HOST",
                "value": f"10.{(i // 254) % 255}.{i % 254 + 1}.1",
            }
            for i in range(args.objects)
        ],
        interface_name_mapping={"port2": "inside"},
        converted_interfaces={
            "physical_interfaces": [{"name": "inside", "hardwareName": "Ethernet1/2", "type": "physicalinterface"}],
            "subinterfaces": [],
            "etherchannels": [],
            "bridge_groups": [],
        },
        debug=False,
    )
    _, route_time, route_profile = _profile("routes", route_converter.convert)

    print("\n=== Stage Timings (seconds) ===")
    print(f"address_group_flatten: {addr_time:.3f}")
    print(f"service_object_expand: {svc_obj_time:.3f}")
    print(f"service_group_flatten_expand: {svc_group_time:.3f}")
    print(f"policy_service_expand: {policy_time:.3f}")
    print(f"route_conversion: {route_time:.3f}")
    print(f"total: {(addr_time + svc_obj_time + svc_group_time + policy_time + route_time):.3f}")

    print("\n=== Top Hotspots: Address Groups ===")
    print(addr_profile)
    print("\n=== Top Hotspots: Service Objects ===")
    print(svc_obj_profile)
    print("\n=== Top Hotspots: Service Groups ===")
    print(svc_group_profile)
    print("\n=== Top Hotspots: Policy Services ===")
    print(policy_profile)
    print("\n=== Top Hotspots: Routes ===")
    print(route_profile)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
