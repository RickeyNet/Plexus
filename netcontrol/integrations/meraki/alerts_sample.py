"""Invented Meraki alerts in the shapes the two ingest paths receive.

``assurance_alert`` builds a row of ``GET /organizations/{organizationId}/
assurance/alerts``; ``webhook_payload`` builds a webhook body. Every name,
ID, serial and address here is made up (documentation ranges and
``example.com`` only), so the tests of ``netcontrol.integrations.meraki.
alerts`` and ``netcontrol.routes.meraki_alerts`` run with no network.
"""

from __future__ import annotations

from typing import Any

ORG_ID = "900001"
ORG_NAME = "Example Retail"
NETWORK_ID = "N_100000000000000001"
NETWORK_NAME = "Branch Example"
NETWORK_ID_2 = "N_100000000000000002"
NETWORK_NAME_2 = "Warehouse Example"
AP_SERIAL = "Q2XX-AAAA-0001"
AP_NAME = "ap-lobby-01"
SWITCH_SERIAL = "Q2XX-AAAA-0002"
SWITCH_NAME = "sw-core-01"
MX_SERIAL = "Q2XX-AAAA-0003"
MX_NAME = "mx-edge-01"
SHARED_SECRET = "example-shared-secret-0123456789"


def _network(network_id: str = NETWORK_ID, name: str = NETWORK_NAME) -> dict[str, str]:
    return {"id": network_id, "name": name, "url": f"https://dashboard.example.com/{name.replace(' ', '-')}/n/x"}


def _device(serial: str, name: str, product_type: str, order: int = 1) -> dict[str, Any]:
    return {
        "serial": serial,
        "name": name,
        "productType": product_type,
        "mac": "00:00:5e:00:53:01",
        "order": order,
        "url": f"https://dashboard.example.com/manage/{serial}",
    }


def assurance_alert(
    alert_id: str = "4000000001",
    *,
    alert_type: str = "unreachable",
    title: str = "Device unreachable",
    severity: str = "critical",
    category: str = "connectivity",
    serial: str = AP_SERIAL,
    name: str = AP_NAME,
    product_type: str = "wireless",
    network_id: str = NETWORK_ID,
    network_name: str = NETWORK_NAME,
    started_at: str = "2026-11-10T08:15:00Z",
    resolved_at: str | None = None,
    dismissed_at: str | None = None,
    devices: list[dict] | None = None,
) -> dict[str, Any]:
    """One assurance alert row (the documented response fields)."""
    if devices is None:
        devices = [_device(serial, name, product_type)] if serial else []
    return {
        "id": alert_id,
        "categoryType": category,
        "network": _network(network_id, network_name),
        "startedAt": started_at,
        "resolvedAt": resolved_at,
        "dismissedAt": dismissed_at,
        "deviceType": "MR" if product_type == "wireless" else "MS",
        "type": alert_type,
        "title": title,
        "description": f"{title} detected by the example sample.",
        "severity": severity,
        "scope": {"devices": devices, "applications": [], "peers": [], "others": []},
    }


def sample_assurance_alerts() -> list[dict[str, Any]]:
    """An organization's active alerts: an AP that is unreachable, CRC
    errors on a switch, and a network-wide informational alert."""
    return [
        assurance_alert(),
        assurance_alert(
            "4000000002",
            alert_type="crc_errors_error",
            title="CRC errors detected",
            severity="warning",
            serial=SWITCH_SERIAL,
            name=SWITCH_NAME,
            product_type="switch",
            devices=[
                {**_device(SWITCH_SERIAL, SWITCH_NAME, "switch", order=1), "lldp": {"port": "12"}},
                _device("Q2XX-AAAA-0004", "sw-access-02", "switch", order=2),
            ],
        ),
        assurance_alert(
            "4000000003",
            alert_type="high_channel_utilization",
            title="High channel utilization",
            severity="informational",
            category="experience_metrics",
            serial="",
            network_id=NETWORK_ID_2,
            network_name=NETWORK_NAME_2,
        ),
    ]


def webhook_payload(
    *,
    alert_type: str = "APs went down",
    alert_type_id: str = "stopped_reporting",
    alert_level: str = "critical",
    alert_id: str = "643451796765671000",
    serial: str = AP_SERIAL,
    name: str = AP_NAME,
    model: str = "MR46",
    org_id: str = ORG_ID,
    network_id: str = NETWORK_ID,
    network_name: str = NETWORK_NAME,
    occurred_at: str = "2026-11-10T08:14:30.000000Z",
    shared_secret: str = SHARED_SECRET,
    alert_data: dict | None = None,
) -> dict[str, Any]:
    """One webhook body (the documented fields of the webhook schema)."""
    return {
        "version": "0.1",
        "sharedSecret": shared_secret,
        "sentAt": "2026-11-10T08:15:31.000000Z",
        "organizationId": org_id,
        "organizationName": ORG_NAME,
        "organizationUrl": "https://dashboard.example.com/o/example/manage/organization/overview",
        "networkId": network_id,
        "networkName": network_name,
        "networkUrl": f"https://dashboard.example.com/{network_name.replace(' ', '-')}/n/x/manage/nodes/list",
        "networkTags": ["branch"],
        "deviceSerial": serial,
        "deviceMac": "00:00:5e:00:53:01",
        "deviceName": name,
        "deviceUrl": f"https://dashboard.example.com/manage/{serial}",
        "deviceTags": [],
        "deviceModel": model,
        "alertId": alert_id,
        "alertType": alert_type,
        "alertTypeId": alert_type_id,
        "alertLevel": alert_level,
        "occurredAt": occurred_at,
        "alertData": alert_data if alert_data is not None else {},
    }


def webhook_recovery(**fields: Any) -> dict[str, Any]:
    """The "came up" event that clears :func:`webhook_payload`'s alert."""
    return webhook_payload(
        alert_type="APs came up",
        alert_type_id="aps_came_up",
        alert_level="informational",
        alert_id="643451796765671001",
        occurred_at="2026-11-10T08:40:00.000000Z",
        **fields,
    )


def webhook_test(**fields: Any) -> dict[str, Any]:
    """A delivery from the Dashboard's "Send test webhook" button."""
    return webhook_payload(
        alert_type="Power supply went down",
        alert_type_id="power_supply_down",
        alert_level="critical",
        alert_id="0000000000000000",
        **fields,
    )
