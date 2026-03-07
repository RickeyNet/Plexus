from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import netcontrol.app as app_module
from netcontrol.version import APP_VERSION


def test_fastapi_metadata_uses_shared_app_version():
    assert app_module.app.version == APP_VERSION


def _load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def test_converter_v2_entrypoint_emits_expected_artifacts(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    v2_script = repo_root / "Firewall_converter" / "converter_v2" / "fortigate_converter_v2.py"

    fortigate_config = {
        "system_interface": [
            {
                "port2": {
                    "alias": "inside",
                    "ip": "10.0.1.1/24",
                    "allowaccess": "ping",
                    "status": "up",
                }
            },
            {
                "port3": {
                    "alias": "outside",
                    "ip": "10.0.2.1/24",
                    "allowaccess": "ping",
                    "status": "up",
                }
            },
        ],
        "firewall_address": [
            {
                "LAN_NET": {
                    "subnet": ["10.0.1.0", "255.255.255.0"],
                    "comment": "LAN subnet",
                }
            },
            {
                "WAN_TARGET": {
                    "subnet": ["10.0.2.10", "255.255.255.255"],
                    "comment": "WAN host",
                }
            },
        ],
        "firewall_addrgrp": [
            {
                "LAN_GROUP": {
                    "member": ["LAN_NET"],
                }
            }
        ],
        "firewall_service_custom": [
            {
                "HTTPS": {
                    "tcp-portrange": "443",
                }
            },
            {
                "DNS": {
                    "tcp-portrange": "53",
                    "udp-portrange": "53",
                }
            },
        ],
        "firewall_service_group": [
            {
                "WEB_GROUP": {
                    "member": ["HTTPS", "DNS"],
                }
            }
        ],
        "firewall_policy": [
            {
                10: {
                    "name": "Allow_Web",
                    "srcintf": ["inside"],
                    "dstintf": ["outside"],
                    "action": "accept",
                    "srcaddr": ["LAN_GROUP"],
                    "dstaddr": ["WAN_TARGET"],
                    "service": ["WEB_GROUP"],
                }
            }
        ],
        "router_static": [
            {
                1: {
                    "dst": ["0.0.0.0", "0.0.0.0"],
                    "gateway": "10.0.2.254",
                    "distance": 1,
                    "device": "port3",
                    "comment": "Default route",
                }
            }
        ],
    }

    config_path = tmp_path / "sample_fortigate.yaml"
    config_path.write_text(json.dumps(fortigate_config, indent=2), encoding="utf-8")

    v2_result = subprocess.run(
        [sys.executable, str(v2_script), str(config_path), "--output", "v2", "--target-model", "ftd-3120"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert v2_result.returncode == 0, v2_result.stderr or v2_result.stdout

    artifact_suffixes = [
        "address_objects.json",
        "address_groups.json",
        "service_objects.json",
        "service_groups.json",
        "access_rules.json",
        "static_routes.json",
        "physical_interfaces.json",
        "subinterfaces.json",
        "etherchannels.json",
        "bridge_groups.json",
        "security_zones.json",
        "summary.json",
        "metadata.json",
    ]

    for suffix in artifact_suffixes:
        v2_path = tmp_path / f"v2_{suffix}"
        assert v2_path.exists(), f"Missing v2 artifact: {v2_path.name}"

    metadata = _load_json(tmp_path / "v2_metadata.json")
    summary = _load_json(tmp_path / "v2_summary.json")
    access_rules = _load_json(tmp_path / "v2_access_rules.json")

    assert isinstance(metadata, dict)
    assert metadata.get("target_model") == "ftd-3120"
    assert metadata.get("output_basename") == "v2"

    assert isinstance(summary, dict)
    assert "conversion_summary" in summary
    assert isinstance(summary["conversion_summary"], dict)

    assert isinstance(access_rules, list)
    assert len(access_rules) == 1
