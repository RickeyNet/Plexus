"""Tests for cloud provider collectors (pagination + rule extraction helpers)."""

from __future__ import annotations

import netcontrol.routes.cloud_collectors as collectors_mod


class _FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return list(self._pages)


class _FakeClient:
    def __init__(self, pages, paginable=True):
        self._pages = pages
        self._paginable = paginable

    def can_paginate(self, operation):
        return self._paginable

    def get_paginator(self, operation):
        return _FakePaginator(self._pages)

    def describe_vpn_gateways(self, **kwargs):
        return self._pages[0]


def test_aws_list_all_concatenates_pages():
    client = _FakeClient([
        {"Vpcs": [{"VpcId": "vpc-1"}, {"VpcId": "vpc-2"}]},
        {"Vpcs": [{"VpcId": "vpc-3"}]},
    ])
    items = collectors_mod._aws_list_all(client, "describe_vpcs", "Vpcs")
    assert [i["VpcId"] for i in items] == ["vpc-1", "vpc-2", "vpc-3"]


def test_aws_list_all_falls_back_when_not_paginable():
    client = _FakeClient([{"VpnGateways": [{"VpnGatewayId": "vgw-1"}]}], paginable=False)
    items = collectors_mod._aws_list_all(client, "describe_vpn_gateways", "VpnGateways")
    assert [i["VpnGatewayId"] for i in items] == ["vgw-1"]


def test_aws_security_group_rules_extracts_ingress_and_egress():
    group = {
        "GroupId": "sg-123",
        "GroupName": "web",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    }
    rules = collectors_mod._aws_security_group_rules(group, resource_uid="aws:security_group:sg-123")
    directions = {r["direction"] for r in rules}
    assert directions == {"inbound", "outbound"}
    inbound = next(r for r in rules if r["direction"] == "inbound")
    assert "0.0.0.0/0" in str(inbound.get("source_selector") or "")


def test_metric_direction_helpers_exported():
    # The collectors module must keep raising typed errors for dispatch
    assert issubclass(collectors_mod.CloudCollectorAuthError, collectors_mod.CloudCollectorError)
    assert issubclass(collectors_mod.CloudCollectorExecutionError, collectors_mod.CloudCollectorError)
