"""Regression tests for lab-topology mgmt_subnet validation.

``mgmt_subnet`` was interpolated verbatim into a containerlab topology YAML
scalar and deployed with ``containerlab deploy``. A newline in the value could
break out of the scalar and inject arbitrary nodes/binds/exec directives — RCE
on the lab host. It is now constrained to a canonical CIDR at the model layer,
with a defensive re-check at YAML-emit time.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from netcontrol.routes.lab_topology import (
    TopologyCreate,
    _normalize_mgmt_subnet,
    build_topology_yaml,
)

_INJECTION = "172.20.20.0/24\n    binds:\n      - /:/host:rw\n    exec:\n      - rm -rf /"


def test_valid_cidr_normalizes():
    assert _normalize_mgmt_subnet("172.20.20.0/24") == "172.20.20.0/24"
    assert _normalize_mgmt_subnet(" 10.0.0.0/8 ") == "10.0.0.0/8"
    assert _normalize_mgmt_subnet("2001:db8::/64") == "2001:db8::/64"
    assert _normalize_mgmt_subnet("") == ""


def test_injection_payload_rejected_by_helper():
    with pytest.raises(ValueError):
        _normalize_mgmt_subnet(_INJECTION)
    for bad in ["not-a-subnet", "172.20.20.0/24; echo pwned", "10.0.0.0/8 extra"]:
        with pytest.raises(ValueError):
            _normalize_mgmt_subnet(bad)


def test_model_rejects_injection():
    TopologyCreate(name="ok", mgmt_subnet="172.20.20.0/24")  # valid
    with pytest.raises(ValidationError):
        TopologyCreate(name="bad", mgmt_subnet=_INJECTION)


def test_build_yaml_defends_against_stored_injection():
    """Even if a malicious row predates model validation, the YAML builder must
    not emit the injected content."""
    devices = [{"id": 1, "hostname": "r1", "runtime_node_kind": "linux", "runtime_image": "img"}]
    topo = {"id": 1, "environment_id": 1, "lab_name": "t", "mgmt_subnet": _INJECTION}
    with pytest.raises(ValueError):
        build_topology_yaml(topo, devices, [])


def test_build_yaml_valid_subnet_emitted():
    devices = [{"id": 1, "hostname": "r1", "runtime_node_kind": "linux", "runtime_image": "img"}]
    topo = {"id": 1, "environment_id": 1, "lab_name": "t", "mgmt_subnet": "172.20.20.0/24"}
    yaml_text = build_topology_yaml(topo, devices, [])
    assert "ipv4-subnet: 172.20.20.0/24" in yaml_text
    assert "binds:" not in yaml_text
    assert "exec:" not in yaml_text
