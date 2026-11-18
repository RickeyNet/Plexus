"""APC Smart-UPS (Network Management Card) support: the SNMP-only ``apc_ups``
device type, its PowerNet-MIB state in the monitoring poll, the built-in
UPS alerts and the software platforms.

The SNMP answers are invented values in the shape a card returns (the
``.0`` instance of each walked scalar), so the poll is checked against the
rows it really receives without a device.
"""

from __future__ import annotations

import netcontrol.routes.state as state
import pytest
import routes.database as db
from netcontrol.drivers import (
    DriverCapabilityError,
    get_driver,
    registered_device_types,
    supports_cli,
    supports_config_capture,
)
from netcontrol.drivers.apc import ApcUpsDriver
from netcontrol.integrations.apc import snmp as apc_snmp
from netcontrol.integrations.inventory_import import capabilities
from netcontrol.integrations.software.versions import PLATFORMS, UPS_FIRMWARE_PLATFORM, classify_host
from netcontrol.routes.snmp import (
    _infer_device_category,
    _infer_vendor_os_from_text,
    _parse_model_and_version,
    parse_apc_nmc_sys_descr,
)

NMC2_DESCR = (
    "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.8.2 PN:apc_hw05_aos_682.bin AF1:v6.8.2 "
    "AN1:apc_hw05_sumx_682.bin MN:AP9631 HR:05 SN: ZA0000000001 MD:01/01/2015) "
    "(Embedded PowerNet SNMP Agent SW v2.2 compatible)"
)
NMC3_DESCR = (
    "APC Web/SNMP Management Card (MB:v1.2.0 PF:v1.4.2.1 PN:apc_hw21_aos_1.4.2.1.bin AF1:v1.4.2.1 "
    "AN1:apc_hw21_su_1.4.2.1.bin MN:AP9641 HR:B0 SN: ZA0000000002 MD:02/02/2022) "
    "(Embedded PowerNet SNMP Agent SW v2.2 compatible)"
)
PDU_DESCR = (
    "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.8.2 PN:apc_hw05_aos_682.bin AF1:v6.8.2 "
    "AN1:apc_hw05_rpdu2g_682.bin MN:AP8941 HR:05 SN: ZA0000000003 MD:03/03/2016) "
    "(Embedded PowerNet SNMP Agent SW v2.2 compatible)"
)

# upsBasicOutputStatus / upsBasicBatteryStatus codes used below.
ON_LINE, ON_BATTERY, OFF, HARDWARE_BYPASS, BATTERY_TEST = 2, 3, 7, 10, 15
NORMAL, LOW, FAULT = 2, 3, 4


def _values(**over) -> dict:
    """Walked PowerNet values of a healthy UPS (``UPS_OIDS`` key -> value)."""
    values = {
        "model": "Smart-UPS 1500",
        "firmware": "UPS 09.3 (ID18)",
        "serial": "AS0000000001",
        "battery_status": NORMAL,
        "battery_capacity": 100,
        "runtime": 282_000,  # TimeTicks (hundredths of a second): 47 minutes
        "battery_replace": 1,
        "output_status": ON_LINE,
        "output_load": 35,
    }
    values.update(over)
    return values


def _walk_rows(values: dict, sys_descr: str = NMC2_DESCR) -> dict[str, dict]:
    """What the poll's SNMP walk returns per base OID for ``values``."""
    rows = {apc_snmp.UPS_OIDS[key]: {apc_snmp.UPS_OIDS[key] + ".0": value} for key, value in values.items()}
    rows[apc_snmp.SYS_DESCR_OID] = {"1.3.6.1.2.1.1.1.0": sys_descr}
    rows["1.3.6.1.2.1.1.3"] = {"1.3.6.1.2.1.1.3.0": 360_000}  # sysUpTime: one hour
    rows["1.3.6.1.2.1.2.2.1.8"] = {"1.3.6.1.2.1.2.2.1.8.2": 1}  # ifOperStatus
    rows["1.3.6.1.2.1.2.2.1.7"] = {"1.3.6.1.2.1.2.2.1.7.2": 1}  # ifAdminStatus
    rows["1.3.6.1.2.1.31.1.1.1.1"] = {"1.3.6.1.2.1.31.1.1.1.1.2": "eth0"}  # ifName
    return rows


# ── Device type and driver ───────────────────────────────────────────────────


def test_registry_resolves_the_ups_type():
    assert isinstance(get_driver("apc_ups"), ApcUpsDriver)
    assert "apc_ups" in registered_device_types()
    driver = get_driver("apc_ups")
    assert (driver.vendor, driver.display_name) == ("apc", "APC Smart-UPS (NMC)")


def test_the_ups_is_snmp_only(monkeypatch):
    netmiko = pytest.importorskip("netmiko")
    from netcontrol.routes import inventory_collection
    from netcontrol.routes.shared import _open_netmiko_session

    assert not supports_cli("apc_ups") and not supports_config_capture("apc_ups")
    assert capabilities("apc_ups") == {"snmp_polling": True, "config_backup": False}
    assert not inventory_collection._collectable({"device_type": "apc_ups"})
    driver = get_driver("apc_ups")
    for capability in (driver.capture_running_config_command, driver.show_version_command, driver.route_table_commands):
        with pytest.raises(DriverCapabilityError):
            capability()

    def _never(**_kw):
        raise AssertionError("an SSH session was opened")

    monkeypatch.setattr(netmiko, "ConnectHandler", _never)
    with pytest.raises(DriverCapabilityError, match="no command line"):
        _open_netmiko_session(
            {"ip_address": "192.0.2.50", "device_type": "apc_ups"}, {"username": "x", "password": "x"}
        )


def test_the_manufacturer_is_apc():
    from netcontrol.device_model import manufacturer_name

    assert manufacturer_name("", "apc_ups") == "APC"
    assert manufacturer_name("apc", "unknown") == "APC"


# ── SNMP detection ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(("sys_descr", "nmc_version"), [(NMC2_DESCR, "6.8.2"), (NMC3_DESCR, "1.4.2.1")])
def test_a_ups_card_is_detected_with_the_card_firmware(sys_descr, nmc_version):
    assert _infer_vendor_os_from_text(sys_descr) == ("apc", "apc_ups", "apc-nmc")
    # The model is the UPS's, read by the poll: the sysDescr names only the card.
    assert _parse_model_and_version(sys_descr) == ("", nmc_version)
    assert _infer_device_category("", sys_descr, "apc_ups") == "ups"


def test_the_card_facts_are_parsed():
    assert parse_apc_nmc_sys_descr(NMC2_DESCR) == {
        "nmc_model": "AP9631",
        "nmc_firmware": "6.8.2",
        "nmc_application": "sumx",
        "nmc_application_firmware": "6.8.2",
        "nmc_serial": "ZA0000000001",
        "nmc_hardware": "05",
    }
    assert parse_apc_nmc_sys_descr(NMC3_DESCR)["nmc_application"] == "su"
    assert parse_apc_nmc_sys_descr("Linux host1 5.15.0") == {}


def test_a_pdu_card_is_apc_but_not_a_ups():
    assert _infer_vendor_os_from_text(PDU_DESCR)[:2] == ("apc", "unknown")
    assert _infer_vendor_os_from_text("Linux host1 5.15.0 #1 SMP x86_64") == ("unknown", "unknown", "unknown")


def _fake_snmp_agent(monkeypatch, answers: dict[str, str]) -> list[tuple[str, ...]]:
    """Stand in for pysnmp's GET in ``netcontrol.routes.snmp``: each GET
    answers ``answers`` (OID -> value, a missing OID as noSuchObject) and
    is recorded as its OID tuple."""
    pytest.importorskip("pysnmp")
    from netcontrol.routes import snmp as snmp_module

    gets: list[tuple[str, ...]] = []

    class _Engine:
        def close_dispatcher(self):
            pass

    class _Transport:
        @staticmethod
        async def create(*_a, **_kw):
            return object()

    async def _get_cmd(_engine, _auth, _transport, _context, *oids):
        gets.append(oids)
        return None, 0, 0, [(oid, answers.get(oid, "No Such Object currently exists at this OID")) for oid in oids]

    monkeypatch.setattr(snmp_module, "PYSMNP_AVAILABLE", True)
    monkeypatch.setattr(snmp_module, "SnmpEngine", _Engine)
    monkeypatch.setattr(snmp_module, "UdpTransportTarget", _Transport)
    monkeypatch.setattr(snmp_module, "ObjectIdentity", lambda oid: oid)
    monkeypatch.setattr(snmp_module, "ObjectType", lambda identity: identity)
    monkeypatch.setattr(snmp_module, "get_cmd", _get_cmd)
    return gets


_V2C = {"enabled": True, "version": "2c", "community": "example"}


async def test_discovery_reads_the_ups_model_and_serial(monkeypatch):
    """The card has no ENTITY-MIB chassis row: the discovery GET reads the
    UPS's model and serial from PowerNet-MIB."""
    from netcontrol.routes.snmp import APC_UPS_MODEL_OID, APC_UPS_SERIAL_OID, _snmp_get

    gets = _fake_snmp_agent(
        monkeypatch,
        {
            "1.3.6.1.2.1.1.1.0": NMC3_DESCR,
            "1.3.6.1.2.1.1.5.0": "ups-a",
            f"{APC_UPS_MODEL_OID}.0": "Smart-UPS SRT 10000",
            f"{APC_UPS_SERIAL_OID}.0": "AS0000000009",
        },
    )
    result = await _snmp_get("192.0.2.60", 1.0, _V2C)
    assert result is not None
    assert (result["device_type"], result["device_category"]) == ("apc_ups", "ups")
    assert (result["model"], result["serial_number"], result["software_version"]) == (
        "Smart-UPS SRT 10000",
        "AS0000000009",
        "1.4.2.1",
    )
    assert gets[1] == (f"{APC_UPS_MODEL_OID}.0", f"{APC_UPS_SERIAL_OID}.0")


async def test_discovery_of_a_ups_that_does_not_answer_powernet(monkeypatch):
    from netcontrol.routes.snmp import _snmp_get

    _fake_snmp_agent(monkeypatch, {"1.3.6.1.2.1.1.1.0": NMC2_DESCR})
    result = await _snmp_get("192.0.2.61", 1.0, _V2C)
    assert result is not None
    assert (result["device_type"], result["model"], result["serial_number"]) == ("apc_ups", "", "")


async def test_other_devices_are_not_asked_for_powernet(monkeypatch):
    from netcontrol.routes.snmp import _snmp_get

    gets = _fake_snmp_agent(monkeypatch, {"1.3.6.1.2.1.1.1.0": "Linux host1 5.15.0 #1 SMP x86_64"})
    await _snmp_get("192.0.2.62", 1.0, _V2C)
    assert len(gets) == 1


# ── PowerNet-MIB state ───────────────────────────────────────────────────────


def test_the_ups_state_is_parsed():
    status = apc_snmp.parse_ups_status(_values(), NMC2_DESCR)
    assert status["model"] == "Smart-UPS 1500"
    assert (status["firmware"], status["firmware_version"]) == ("UPS 09.3 (ID18)", "9.3")
    assert status["serial"] == "AS0000000001"
    assert (status["output_status"], status["output_status_label"]) == (ON_LINE, "On line")
    assert (status["battery_status"], status["battery_status_label"]) == (NORMAL, "Normal")
    assert status["battery_capacity_pct"] == 100
    assert status["runtime_minutes"] == 47.0
    assert status["output_load_pct"] == 35
    assert status["battery_needs_replacing"] is False
    assert (status["nmc_model"], status["nmc_firmware"]) == ("AP9631", "6.8.2")


def test_a_runtime_the_ups_does_not_report_is_empty():
    assert apc_snmp.parse_ups_status(_values(runtime=4_294_967_295))["runtime_minutes"] is None
    assert apc_snmp.parse_ups_status(_values(runtime=None))["runtime_minutes"] is None


def test_no_powernet_answer_is_no_state():
    assert apc_snmp.parse_ups_status({}, NMC2_DESCR) == {}
    assert apc_snmp.parse_ups_status(dict.fromkeys(apc_snmp.UPS_OIDS, "No Such Object currently exists")) == {}


async def test_the_state_is_read_with_the_poll_walk():
    rows = _walk_rows(_values(output_status=ON_BATTERY, battery_capacity=87, runtime=141_000))
    asked: list[str] = []

    async def walk(oid: str) -> dict:
        asked.append(oid)
        return rows.get(oid, {})

    status = await apc_snmp.read_ups_status(walk)
    assert set(asked) == {*apc_snmp.UPS_OIDS.values(), apc_snmp.SYS_DESCR_OID, apc_snmp.PROBE_TEMPERATURE_OID}
    assert status["output_status_label"] == "On battery"
    assert (status["battery_capacity_pct"], status["runtime_minutes"]) == (87, 23.5)
    assert status["nmc_firmware"] == "6.8.2"


def test_the_metric_samples():
    status = apc_snmp.parse_ups_status(_values(battery_capacity=90, output_load=40))
    rows = {metric: value for _host, metric, _labels, value in apc_snmp.ups_metric_samples(5, status)}
    assert rows == {
        "ups_battery_capacity_pct": 90.0,
        "ups_runtime_minutes": 47.0,
        "ups_output_load_pct": 40.0,
        "ups_output_status": float(ON_LINE),
        "ups_battery_status": float(NORMAL),
    }
    assert apc_snmp.ups_metric_samples(5, {}) == []
    assert apc_snmp.ups_metric_value(status, "ups_output_load_pct") == 40.0
    assert apc_snmp.ups_metric_value(None, "ups_output_load_pct") is None


# ── Built-in alerts ──────────────────────────────────────────────────────────


def _alerts(**values) -> dict[str, dict]:
    status = apc_snmp.parse_ups_status(_values(**values))
    return {check["metric"]: check for check in apc_snmp.ups_alert_checks(status)}


def test_a_healthy_ups_raises_nothing():
    assert _alerts() == {}
    assert apc_snmp.ups_alert_checks({}) == []
    # A self-test runs on battery without alerting.
    assert _alerts(output_status=BATTERY_TEST) == {}


def test_on_battery():
    alerts = _alerts(output_status=ON_BATTERY, battery_capacity=87, runtime=141_000)
    assert set(alerts) == {"ups_on_battery"}
    assert alerts["ups_on_battery"]["severity"] == "warning"
    assert alerts["ups_on_battery"]["message"] == "UPS on battery (battery 87%, 23.5 min runtime left)"
    # On battery with a low battery: critical, and the battery alert too.
    alerts = _alerts(output_status=ON_BATTERY, battery_status=LOW)
    assert alerts["ups_on_battery"]["severity"] == "critical"
    assert alerts["ups_battery"]["severity"] == "critical"


def test_battery_problems():
    alerts = _alerts(battery_replace=2)
    assert alerts["ups_battery"]["severity"] == "warning"
    assert alerts["ups_battery"]["message"].startswith("UPS battery needs replacing")
    alerts = _alerts(battery_status=FAULT, battery_replace=2)
    assert alerts["ups_battery"]["severity"] == "critical"
    assert alerts["ups_battery"]["message"].startswith("UPS battery fault, battery needs replacing")


def test_output_off_and_bypass():
    alerts = _alerts(output_status=OFF)
    assert alerts["ups_output"]["severity"] == "critical"
    assert alerts["ups_output"]["message"] == "UPS output off: Off"
    alerts = _alerts(output_status=HARDWARE_BYPASS)
    assert (alerts["ups_output"]["severity"], alerts["ups_output"]["message"]) == (
        "critical",
        "UPS output on bypass: Hardware failure bypass",
    )
    assert _alerts(output_status=9)["ups_output"]["severity"] == "warning"  # switched bypass


# ── Software platforms ───────────────────────────────────────────────────────


def test_software_platforms():
    assert {"apc-nmc", "apc-ups"} <= set(PLATFORMS)
    assert UPS_FIRMWARE_PLATFORM == "apc-ups"
    assert classify_host("apc_ups", "Smart-UPS 1500", "6.8.2") == ("apc-nmc", "6.8.2")
    assert classify_host("apc_ups", "", "1.4.2.1") == ("apc-nmc", "1.4.2.1")
    # A host whose type is not set is still recognised from the card text.
    assert classify_host("", "APC Web/SNMP Management Card", "6.8.2")[0] == "apc-nmc"


# ── The monitoring poll, end to end ──────────────────────────────────────────


async def _ups_host() -> tuple[int, int]:
    await db.init_db()
    group_id = await db.create_group("ups-test")
    host_id = await db.add_host(group_id, "ups-a", "192.0.2.60", "apc_ups")
    return group_id, host_id


async def _poll(monkeypatch, host: dict, values: dict) -> dict:
    import netcontrol.routes.monitoring as monitoring

    rows = _walk_rows(values)

    async def fake_walk(_ip, _timeout, _cfg, oid, *args, **kwargs):
        return rows.get(oid, {})

    monkeypatch.setattr(monitoring, "PYSMNP_AVAILABLE", True)
    monkeypatch.setattr(monitoring, "_snmp_walk", fake_walk)
    monkeypatch.setitem(state.MONITORING_CONFIG, "icmp_enabled", False)
    return await monitoring._poll_host_monitoring(host, None, {"enabled": True})


async def test_the_poll_reads_stores_and_alerts(monkeypatch):
    from netcontrol.routes.monitoring import _process_poll_result
    from netcontrol.routes.software import collect_software_entries

    group_id, host_id = await _ups_host()
    host = {**(await db.get_host(host_id)), "group_id": group_id}

    result = await _poll(monkeypatch, host, _values(output_status=ON_BATTERY, battery_capacity=87, runtime=141_000))
    assert result["cpu_percent"] is None and result["uptime_seconds"] == 3600
    assert result["ups"]["output_status_label"] == "On battery"
    await _process_poll_result(host, result, [])

    # The newest state, and the UPS identity on the host.
    stored = await db.get_host_vendor_status(host_id)
    assert stored["kind"] == "apc_ups" and stored["status"]["battery_capacity_pct"] == 87
    updated = await db.get_host(host_id)
    assert (updated["model"], updated["serial_number"], updated["software_version"]) == (
        "Smart-UPS 1500",
        "AS0000000001",
        "6.8.2",
    )
    # The history, as metric samples.
    samples = await db.query_metric_samples("ups_battery_capacity_pct", [host_id])
    assert [s["value"] for s in samples] == [87.0]
    # The server-side alert.
    alerts = await db.get_monitoring_alerts(host_id, acknowledged=False)
    assert [(a["metric"], a["severity"]) for a in alerts] == [("ups_on_battery", "warning")]

    # The software tracker: the card (the host) and the UPS behind it.
    entries = {e["device_key"]: e for e in await collect_software_entries() if e["host_id"] == host_id}
    assert (entries[f"host:{host_id}"]["platform"], entries[f"host:{host_id}"]["version"]) == ("apc-nmc", "6.8.2")
    ups = entries[f"host:{host_id}:ups"]
    assert (ups["platform"], ups["version"], ups["raw_version"]) == ("apc-ups", "9.3", "UPS 09.3 (ID18)")

    # Power is back: the alert is resolved.
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    result = await _poll(monkeypatch, host, _values())
    await _process_poll_result(host, result, [])
    assert await db.get_monitoring_alerts(host_id, acknowledged=False) == []
    resolved = await db.get_monitoring_alerts(host_id, acknowledged=True)
    assert [(a["metric"], a["acknowledged_by"]) for a in resolved] == [("ups_on_battery", "auto-resolved")]


async def test_a_user_rule_can_use_a_ups_metric(monkeypatch):
    from netcontrol.routes.monitoring import _evaluate_alerts_for_poll

    group_id, host_id = await _ups_host()
    poll_id = await db.create_monitoring_poll(host_id)
    res = {
        "host_id": host_id,
        "cpu_percent": None,
        "memory_percent": None,
        "if_down_count": 0,
        "if_details": [],
        "vpn_tunnels_down": 0,
        "vpn_details": [],
        "ups": apc_snmp.parse_ups_status(_values(runtime=6_000)),  # 1 minute left
    }
    rule_id = await db.create_alert_rule("short runtime", "ups_runtime_minutes", operator="<", value=10.0)
    rule = {"id": rule_id, "name": "short runtime", "metric": "ups_runtime_minutes", "operator": "<", "value": 10.0}
    created = await _evaluate_alerts_for_poll(res, poll_id, group_id, [rule])
    assert created == 1
    alerts = await db.get_monitoring_alerts(host_id)
    assert alerts[0]["metric"] == "ups_runtime_minutes" and alerts[0]["value"] == 1.0


async def test_the_vendor_status_endpoint(monkeypatch):
    from netcontrol.routes import monitoring

    _group_id, host_id = await _ups_host()

    async def _allow(*_args, **_kwargs):
        return None

    monkeypatch.setattr(monitoring, "require_object_host", _allow)
    empty = await monitoring.monitoring_vendor_status(None, host_id)
    assert empty == {"host_id": host_id, "kind": "", "status": {}, "polled_at": ""}
    await db.set_host_vendor_status(host_id, "apc_ups", {"model": "Smart-UPS 1500"})
    row = await monitoring.monitoring_vendor_status(None, host_id)
    assert row["kind"] == "apc_ups" and row["status"] == {"model": "Smart-UPS 1500"} and row["polled_at"]
