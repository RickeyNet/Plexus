"""Hardware components with serials and their history
(netcontrol/hardware_components.py, netcontrol/drivers/show_inventory.py,
routes/db/hardware_components.py).

The readers are fed invented ENTITY-MIB and JUNIPER-MIB rows and an
invented ``show inventory`` output; the change rules are pure; the storage
tests run against the test database. No device, SDK or network. Every
serial, name and address here is made up.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import netcontrol.routes.state as state
import pytest
import routes.database as db
from netcontrol import hardware_components as hc, module_health as mh, monitoring_repoll, snmp_health as sh
from netcontrol.drivers import DriverCapabilityError, get_driver
from netcontrol.drivers.show_inventory import category_of, parse_show_inventory
from netcontrol.hardware_components import Component
from netcontrol.routes.snmp import real_serial

from snmp_health_fakes import SYS_UPTIME, Agent, add_host, poll

SERIAL = sh.ENT_PHYSICAL_SERIAL_NUM


def entity(rows: list[dict]) -> tuple[dict, dict]:
    """``(walk rows, GET answers)`` of an invented entPhysicalTable: each row
    ``index``, ``cls`` and optional ``name``, ``descr``, ``model``,
    ``serial``, ``parent``, ``fru``, ``hw``, ``fw``, ``sw``."""
    walk: dict = {}
    answers: dict = {}
    for row in rows:
        i = row["index"]
        walk[f"{SERIAL}.{i}"] = row.get("serial", "")
        answers.update(
            {
                f"{sh.ENT_PHYSICAL_DESCR}.{i}": row.get("descr", ""),
                f"{sh.ENT_PHYSICAL_CONTAINED_IN}.{i}": row.get("parent", 0),
                f"{sh.ENT_PHYSICAL_CLASS}.{i}": row["cls"],
                f"{sh.ENT_PHYSICAL_PARENT_REL_POS}.{i}": row.get("pos", 0),
                f"{sh.ENT_PHYSICAL_NAME}.{i}": row.get("name", ""),
                f"{sh.ENT_PHYSICAL_HARDWARE_REV}.{i}": row.get("hw", ""),
                f"{sh.ENT_PHYSICAL_FIRMWARE_REV}.{i}": row.get("fw", ""),
                f"{sh.ENT_PHYSICAL_SOFTWARE_REV}.{i}": row.get("sw", ""),
                f"{sh.ENT_PHYSICAL_MODEL}.{i}": row.get("model", ""),
                f"{sh.ENT_PHYSICAL_IS_FRU}.{i}": row.get("fru", 1),
            }
        )
    return walk, answers


# A modular chassis: supervisor and line card in slots, a power supply, a
# fan tray, two optics (one a module in a container, one a port with its own
# serial), placeholder serials, containers and a port without one.
MODULAR = [
    {
        "index": 1,
        "cls": 3,
        "name": "Chassis",
        "descr": "Example 7 Slot Chassis",
        "model": "EX-CH7",
        "serial": "FXS0000Q0AA",
        "hw": "V01",
    },
    {"index": 2, "cls": 5, "name": "Slot 1", "parent": 1},
    {
        "index": 3,
        "cls": 9,
        "name": "Slot 1 Supervisor",
        "descr": "Example Supervisor",
        "model": "EX-SUP-1",
        "serial": "JAE0000A0AA",
        "parent": 2,
        "fw": "17.1",
        "sw": "17.9.4",
    },
    {"index": 5, "cls": 5, "name": "Slot 3", "parent": 1},
    {
        "index": 4,
        "cls": 9,
        "name": "Slot 3 Linecard",
        "descr": "Example 48-Port Line Card with SFP ports",
        "model": "EX-LC-48",
        "serial": "JAE0000B0BB",
        "parent": 5,
    },
    {
        "index": 6,
        "cls": 6,
        "name": "Power Supply Module 1",
        "descr": "Example 3200W AC",
        "model": "EX-PWR-3200",
        "serial": "ART0000C0CC",
        "parent": 1,
    },
    {
        "index": 7,
        "cls": 7,
        "name": "Fan Tray",
        "descr": "Example Fan Tray",
        "model": "EX-FAN",
        "serial": "DCH0000D0DD",
        "parent": 1,
    },
    {"index": 8, "cls": 10, "name": "Te1/1/1", "parent": 3},
    {"index": 10, "cls": 5, "name": "subslot 1/0 transceiver container 1", "parent": 3},
    {
        "index": 9,
        "cls": 9,
        "name": "",
        "descr": "SFP-10GBase-SR",
        "model": "SFP-10G-SR",
        "serial": "AVD0000E0EE",
        "parent": 10,
    },
    {
        "index": 13,
        "cls": 10,
        "name": "Te3/0/1",
        "descr": "10G optic",
        "model": "EX-OPTIC",
        "serial": "FNS0000F0FF",
        "parent": 4,
    },
    {"index": 11, "cls": 8, "name": "Temp sensor", "serial": "N/A", "parent": 3},
    {"index": 12, "cls": 9, "name": "Blank", "serial": "0000000", "parent": 1},
    {"index": 14, "cls": 1, "name": "Other", "descr": "Example clock card", "serial": "CLK0000G0GG", "parent": 1},
]

# A stack of two: the built-in module of member 1 carries the chassis serial.
STACK = [
    {"index": 1, "cls": 11, "name": "Example Stack", "serial": ""},
    {
        "index": 1000,
        "cls": 3,
        "name": "Switch 1",
        "descr": "EX-48P",
        "model": "EX-48P",
        "serial": "FOC0000X0AA",
        "parent": 1,
    },
    {
        "index": 1001,
        "cls": 9,
        "name": "Switch 1 - EX-48P - Fixed Module 0",
        "model": "EX-48P",
        "serial": "FOC0000X0AA",
        "parent": 1000,
        "fru": 2,
    },
    {
        "index": 1002,
        "cls": 6,
        "name": "Switch 1 - Power Supply A",
        "model": "PWR-EX-715",
        "serial": "LIT0000H0HH",
        "parent": 1000,
    },
    {
        "index": 2000,
        "cls": 3,
        "name": "Switch 2",
        "descr": "EX-48P",
        "model": "EX-48P",
        "serial": "FOC0000X0BB",
        "parent": 1,
    },
]

# A fixed switch: the chassis serial again on its module.
FIXED = [
    {
        "index": 1001,
        "cls": 9,
        "name": "Fixed Module",
        "model": "EX-24T",
        "serial": "FOC0000Y0YY",
        "parent": 1,
        "fru": 2,
    },
    {"index": 1, "cls": 3, "name": "Chassis", "model": "EX-24T", "serial": "FOC0000Y0YY"},
]


async def _read_entity(rows: list[dict], **kw) -> tuple[list[Component] | None, Agent]:
    walk, answers = entity(rows)
    agent = Agent(walk, answers, **kw)
    return await hc.read_entity(agent.get, agent.walk_table), agent


def _by_serial(components: list[Component]) -> dict[str, Component]:
    return {c.serial: c for c in components}


# ── Serial values ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw", ["", "  ", "N/A", "Unknown", "none", "0", "00000000", "0x0000", "No Such Instance currently exists", None]
)
def test_placeholder_serials_are_no_serial(raw):
    assert real_serial(raw) == ""


def test_a_real_serial_is_kept_trimmed():
    assert real_serial("  FOC0000X0AA ") == "FOC0000X0AA"
    assert real_serial("A0") == "A0"


# ── ENTITY-MIB ───────────────────────────────────────────────────────────────


async def test_a_modular_chassis_is_read():
    components, agent = await _read_entity(MODULAR)
    found = _by_serial(components)
    assert set(found) == {
        "FXS0000Q0AA",
        "JAE0000A0AA",
        "JAE0000B0BB",
        "ART0000C0CC",
        "DCH0000D0DD",
        "AVD0000E0EE",
        "FNS0000F0FF",
        "CLK0000G0GG",
    }
    assert [found[s].category for s in ("FXS0000Q0AA", "JAE0000A0AA", "ART0000C0CC", "DCH0000D0DD")] == [
        "chassis",
        "module",
        "power_supply",
        "fan",
    ]
    # A line card whose description names its SFP ports is a module.
    assert found["JAE0000B0BB"].category == "module"
    # An optic: a module named by its model; a port with its own serial.
    assert found["AVD0000E0EE"].category == "transceiver"
    assert found["FNS0000F0FF"].category == "transceiver"
    assert found["CLK0000G0GG"].category == "other"
    # No name: located by its parent's (the container's) name.
    assert found["AVD0000E0EE"].slot == "subslot 1/0 transceiver container 1"
    assert found["AVD0000E0EE"].name == "SFP-10GBase-SR"
    sup = found["JAE0000A0AA"]
    assert (sup.slot, sup.model, sup.firmware_rev, sup.software_rev) == (
        "Slot 1 Supervisor",
        "EX-SUP-1",
        "17.1",
        "17.9.4",
    )
    assert found["FXS0000Q0AA"].hardware_rev == "V01"
    # MIB order (by index), not walk order.
    assert [c.serial for c in components][:3] == ["FXS0000Q0AA", "JAE0000A0AA", "JAE0000B0BB"]
    # One walk of the serial column; GETs chunked; only rows with a serial
    # (and the parents not among them) asked for.
    assert agent.walks == [SERIAL]
    assert all(len(oids) <= sh.OIDS_PER_GET for oids in agent.gets)
    asked = agent.asked()
    assert f"{sh.ENT_PHYSICAL_NAME}.11" not in asked and f"{sh.ENT_PHYSICAL_DESCR}.2" not in asked
    assert f"{sh.ENT_PHYSICAL_NAME}.10" in asked  # a parent


async def test_a_stack_lists_each_member_and_one_component_per_serial():
    components, _agent = await _read_entity(STACK)
    found = _by_serial(components)
    assert set(found) == {"FOC0000X0AA", "LIT0000H0HH", "FOC0000X0BB"}
    # The built-in module carries member 1's serial: kept as the chassis.
    assert found["FOC0000X0AA"].category == "chassis" and found["FOC0000X0AA"].slot == "Switch 1"
    assert found["FOC0000X0BB"].slot == "Switch 2"


async def test_a_fixed_switch_is_one_chassis():
    components, _agent = await _read_entity(FIXED)
    assert [(c.category, c.serial, c.slot) for c in components] == [("chassis", "FOC0000Y0YY", "Chassis")]


def test_duplicate_serials_prefer_a_field_replaceable_unit_then_the_first():
    a = Component("module", "A", "A", "", "M", "SER1", fru=False)
    b = Component("module", "B", "B", "", "M", "ser1", fru=True)
    c = Component("module", "C", "C", "", "M", "SER1", fru=True)
    assert hc.dedupe([a, b, c]) == [b]


async def test_no_serial_is_an_empty_read():
    components, agent = await _read_entity([{"index": 1, "cls": 3, "name": "Chassis", "serial": "N/A"}])
    assert components == [] and agent.gets == []


async def test_a_walk_cut_short_is_not_read():
    components, agent = await _read_entity(MODULAR, cut={SERIAL})
    assert components is None and agent.gets == []


async def test_a_walk_that_reaches_its_cap_is_not_read(monkeypatch):
    monkeypatch.setattr(hc, "WALK_MAX_ROWS", 5)
    components, _agent = await _read_entity(MODULAR)
    assert components is None


async def test_too_many_serials_is_not_read(monkeypatch):
    monkeypatch.setattr(hc, "MAX_COMPONENTS", 3)
    components, agent = await _read_entity(MODULAR)
    assert components is None and agent.gets == []


async def test_an_unanswered_get_is_not_read():
    components, _agent = await _read_entity(MODULAR, silent_gets=True)
    assert components is None


async def test_an_unanswered_parent_get_keeps_the_components():
    walk, answers = entity(MODULAR)
    agent = Agent(walk, answers)
    calls = {"n": 0}

    async def get(oids):
        calls["n"] += 1
        if (
            any(oid.startswith(sh.ENT_PHYSICAL_CLASS + ".10") for oid in oids)
            and sh.ENT_PHYSICAL_DESCR + ".10" not in oids
        ):
            return {}
        return await agent.get(oids)

    components = await hc.read_entity(get, agent.walk_table)
    optic = _by_serial(components)["AVD0000E0EE"]
    assert optic.slot == "SFP-10GBase-SR"  # no parent name: its description


def test_entity_mib_oids_match_the_mib():
    # ENTITY-MIB entPhysicalEntry = 1.3.6.1.2.1.47.1.1.1.1; columns per RFC 6933.
    entry = "1.3.6.1.2.1.47.1.1.1.1."
    assert {
        sh.ENT_PHYSICAL_DESCR: 2,
        sh.ENT_PHYSICAL_CONTAINED_IN: 4,
        sh.ENT_PHYSICAL_CLASS: 5,
        sh.ENT_PHYSICAL_PARENT_REL_POS: 6,
        sh.ENT_PHYSICAL_NAME: 7,
        sh.ENT_PHYSICAL_HARDWARE_REV: 8,
        sh.ENT_PHYSICAL_FIRMWARE_REV: 9,
        sh.ENT_PHYSICAL_SOFTWARE_REV: 10,
        sh.ENT_PHYSICAL_SERIAL_NUM: 11,
        sh.ENT_PHYSICAL_MODEL: 13,
        sh.ENT_PHYSICAL_IS_FRU: 16,
    } == {
        oid: int(oid[len(entry) :])
        for oid in (
            sh.ENT_PHYSICAL_DESCR,
            sh.ENT_PHYSICAL_CONTAINED_IN,
            sh.ENT_PHYSICAL_CLASS,
            sh.ENT_PHYSICAL_PARENT_REL_POS,
            sh.ENT_PHYSICAL_NAME,
            sh.ENT_PHYSICAL_HARDWARE_REV,
            sh.ENT_PHYSICAL_FIRMWARE_REV,
            sh.ENT_PHYSICAL_SOFTWARE_REV,
            sh.ENT_PHYSICAL_SERIAL_NUM,
            sh.ENT_PHYSICAL_MODEL,
            sh.ENT_PHYSICAL_IS_FRU,
        )
    }


# ── JUNIPER-MIB ──────────────────────────────────────────────────────────────

JNX_ROWS = {
    # index: (descr, serial, fru type, part number, model)
    "7.1.0.0": ("FPC: EX-48T @ 0/*/*", "PE0000AA0001", 3, "650-000001", "EX-48T"),
    "2.1.0.0": ("PEM 0", "1EDB0000001", 7, "740-000002", ""),
    "4.1.0.0": ("Fan Tray 0", "", 13, "", ""),
    "8.1.1.0": ("Xcvr 0", "XCV00000001", None, "740-000003", ""),
    "9.1.0.0": ("Routing Engine 0", "BUILTIN", 6, "", ""),
    "1.1.0.0": ("Midplane", "JN0000AA0AA", None, "", ""),
}


def _juniper_agent(*, box_serial: str = "JN0000AA0AA", rows: dict | None = None, **kw) -> Agent:
    rows = JNX_ROWS if rows is None else rows
    walk = {f"{hc.JNX_CONTENTS_SERIAL}.{i}": r[1] for i, r in rows.items()}
    answers = {hc.JNX_BOX_DESCR: "EX-48T-CHASSIS", hc.JNX_BOX_SERIAL: box_serial, hc.JNX_BOX_REVISION: "REV 01"}
    for i, (descr, _serial, fru, part, model) in rows.items():
        answers[f"{hc.JNX_CONTENTS_DESCR}.{i}"] = descr
        answers[f"{hc.JNX_CONTENTS_REVISION}.{i}"] = "REV 02"
        answers[f"{hc.JNX_CONTENTS_PART_NO}.{i}"] = part
        answers[f"{hc.JNX_CONTENTS_CHASSIS_DESCR}.{i}"] = ""
        if model:
            answers[f"{hc.JNX_CONTENTS_MODEL}.{i}"] = model
        if fru is not None:
            answers[f"{mh.JNX_FRU_TYPE}.{i}"] = fru
    return Agent(walk, answers, **kw)


async def test_juniper_contents_table_is_read():
    agent = _juniper_agent()
    components = await hc.read_snmp("juniper_junos", agent.get, agent.walk_table)
    found = _by_serial(components)
    # The box is the chassis; the midplane row with its serial is the same one.
    assert found["JN0000AA0AA"].category == "chassis" and found["JN0000AA0AA"].model == "EX-48T-CHASSIS"
    assert found["PE0000AA0001"].category == "module" and found["PE0000AA0001"].model == "EX-48T"
    assert found["1EDB0000001"].category == "power_supply" and found["1EDB0000001"].model == "740-000002"
    assert found["XCV00000001"].category == "transceiver"
    assert found["BUILTIN"].category == "module"
    assert "" not in found  # the fan tray had no serial
    assert found["PE0000AA0001"].slot == "FPC: EX-48T @ 0/*/*"
    assert agent.walks == [hc.JNX_CONTENTS_SERIAL]


async def test_juniper_falls_back_to_entity_mib():
    walk, answers = entity(FIXED)
    agent = Agent(walk, answers)
    components = await hc.read_snmp("juniper", agent.get, agent.walk_table)
    assert [c.serial for c in components] == ["FOC0000Y0YY"]
    assert agent.walks == [hc.JNX_CONTENTS_SERIAL, SERIAL]


async def test_juniper_cut_short_does_not_fall_back():
    agent = _juniper_agent(cut={hc.JNX_CONTENTS_SERIAL})
    assert await hc.read_snmp("juniper_junos", agent.get, agent.walk_table) is None
    assert agent.walks == [hc.JNX_CONTENTS_SERIAL]


async def test_juniper_unanswered_get_is_not_read():
    agent = _juniper_agent(silent_gets=True)
    assert await hc.read_juniper(agent.get, agent.walk_table) is None


def test_juniper_category_rule():
    assert hc.juniper_category(18, "PSM 1", "") == "power_supply"
    assert hc.juniper_category(13, "Fan Tray 1", "") == "fan"
    assert hc.juniper_category(None, "Midplane", "") == "other"


def test_juniper_oids_match_the_mib():
    # JUNIPER-MIB: jnxBoxAnatomy = 1.3.6.1.4.1.2636.3.1; jnxBoxDescr 2,
    # jnxBoxSerialNo 3, jnxBoxRevision 4; jnxContentsEntry = jnxBoxAnatomy.8.1,
    # Descr 6, SerialNo 7, Revision 8, PartNo 10, ChassisDescr 12, Model 14.
    anatomy = "1.3.6.1.4.1.2636.3.1"
    assert (hc.JNX_BOX_DESCR, hc.JNX_BOX_SERIAL, hc.JNX_BOX_REVISION) == (
        f"{anatomy}.2.0",
        f"{anatomy}.3.0",
        f"{anatomy}.4.0",
    )
    entry = f"{anatomy}.8.1"
    assert [
        hc.JNX_CONTENTS_DESCR,
        hc.JNX_CONTENTS_SERIAL,
        hc.JNX_CONTENTS_REVISION,
        hc.JNX_CONTENTS_PART_NO,
        hc.JNX_CONTENTS_CHASSIS_DESCR,
        hc.JNX_CONTENTS_MODEL,
    ] == [f"{entry}.{n}" for n in (6, 7, 8, 10, 12, 14)]


@pytest.mark.parametrize(
    ("device_type", "readers"),
    [("apc_ups", 0), ("icmp_only", 0), ("cisco_xe", 1), ("arista_eos", 1), ("juniper_junos", 2), (None, 1)],
)
def test_readers_per_device_type(device_type, readers):
    assert len(hc.readers_for(device_type)) == readers
    assert hc.reads_hardware(device_type) is bool(readers)


# ── show inventory ───────────────────────────────────────────────────────────

SHOW_INVENTORY = """
NAME: "Chassis", DESCR: "Example 7 Slot Chassis"
PID: EX-CH7            , VID: V01  , SN: FXS0000Q0AA

NAME: "Slot 1 Supervisor", DESCR: "Example Supervisor 1 Module"
PID: EX-SUP-1          , VID: V02  , SN: JAE0000A0AA

NAME: "Power Supply Module 1", DESCR: "Example 3200W AC Power Supply"
PID: EX-PWR-3200       , VID: V01  , SN: ART0000C0CC

NAME: "Fan Tray", DESCR: "Example Fan Tray"
PID: EX-FAN            , VID: V01  , SN: DCH0000D0DD

NAME: "TenGigabitEthernet1/0/1", DESCR: "SFP-10GBase-SR"
PID: SFP-10G-SR          , VID: V03  , SN: AVD0000E0EE

NAME: "Slot 3 Linecard", DESCR: "Example 48-Port line card, SFP+"
PID: EX-LC-48          , VID:      , SN: JAE0000B0BB

NAME: "Switch 2", DESCR: "EX-48P"
PID: EX-48P            , VID: V01  , SN: FOC0000X0BB

NAME: "Blank", DESCR: "Example blank"
PID:                   , VID:      , SN:

NAME: "Clock", DESCR: "Example clock"
PID:                   , VID:      , SN: CLK0000G0GG
"""

ASA_INVENTORY = """Name: "Chassis", DESCR: "Example security appliance, 8GE, AC"
PID: EX-ASA-8      , VID: V05     , SN: JAD0000000A
"""

NXOS_INVENTORY = """NAME: "Chassis",  DESCR: "Example 9000 chassis"
PID: EX-9K-C48           ,  VID: V01  ,  SN: FDO0000X0AA
"""


def test_show_inventory_is_parsed():
    blocks = parse_show_inventory(SHOW_INVENTORY)
    assert [b.serial for b in blocks] == [
        "FXS0000Q0AA",
        "JAE0000A0AA",
        "ART0000C0CC",
        "DCH0000D0DD",
        "AVD0000E0EE",
        "JAE0000B0BB",
        "FOC0000X0BB",
        "CLK0000G0GG",
    ]
    assert blocks[5].vid == "" and blocks[1].pid == "EX-SUP-1"
    comps = _by_serial(hc.components_from_inventory(SHOW_INVENTORY))
    assert {s: c.category for s, c in comps.items()} == {
        "FXS0000Q0AA": "chassis",
        "JAE0000A0AA": "module",
        "ART0000C0CC": "power_supply",
        "DCH0000D0DD": "fan",
        "AVD0000E0EE": "transceiver",
        "JAE0000B0BB": "module",
        "FOC0000X0BB": "chassis",
        "CLK0000G0GG": "other",
    }
    assert comps["JAE0000A0AA"].hardware_rev == "V02" and comps["JAE0000A0AA"].slot == "Slot 1 Supervisor"


def test_show_inventory_label_case_and_spacing_vary():
    assert [b.serial for b in parse_show_inventory(ASA_INVENTORY)] == ["JAD0000000A"]
    assert [b.serial for b in parse_show_inventory(NXOS_INVENTORY)] == ["FDO0000X0AA"]
    assert parse_show_inventory("") == [] and parse_show_inventory(None) == []
    assert parse_show_inventory("PID: X , VID: V1 , SN: ABC\n") == []  # no NAME line


@pytest.mark.parametrize(
    ("name", "descr", "pid", "category"),
    [
        ("Rack 0", "Example 6 slot chassis", "EX-6", "chassis"),
        ("Chassis 1 Slot 3 Supervisor", "Supervisor for chassis", "EX-SUP", "module"),
        ("Te1/1/1", "", "EX-OPTIC", "transceiver"),
        ("0/0/0/1", "QSFP 40G SR4", "EX-Q40", "transceiver"),
        ("PS1", "Example AC power supply", "EX-PS", "power_supply"),
        ("Fan 1", "", "EX-FAN", "fan"),
    ],
)
def test_show_inventory_categories(name, descr, pid, category):
    assert category_of(name, descr, pid) == category


@pytest.mark.parametrize("device_type", ["cisco_ios", "cisco_xe", "cisco_nxos", "cisco_xr", "cisco_asa", "cisco_ftd"])
def test_cisco_drivers_have_show_inventory(device_type):
    assert get_driver(device_type).show_inventory_command() == "show inventory"


@pytest.mark.parametrize("device_type", ["juniper_junos", "arista_eos", "paloalto_panos", "fortinet"])
def test_other_drivers_have_no_show_inventory(device_type):
    with pytest.raises(DriverCapabilityError):
        get_driver(device_type).show_inventory_command()


# ── Change detection (pure) ──────────────────────────────────────────────────


def comp(serial: str, slot: str, category: str = "module", model: str = "EX-1", **kw) -> Component:
    return Component(category, slot, slot, "", model, serial, **kw)


def stored(rows: list[tuple], source: str = "snmp") -> list[dict]:
    """Stored rows from ``(id, serial, slot, status)`` (+ optional dict of fields)."""
    out = []
    for row in rows:
        rid, serial, slot, status = row[:4]
        extra = row[4] if len(row) > 4 else {}
        out.append(
            {
                "id": rid,
                "category": "module",
                "slot": slot,
                "name": slot,
                "description": "",
                "model": "EX-1",
                "serial": serial,
                "hardware_rev": "",
                "firmware_rev": "",
                "software_rev": "",
                "status": status,
                "source": source,
                "removed_at": None,
                **extra,
            }
        )
    return out


def diff(stored_rows, read, source, *, now=None, **kw) -> hc.Plan:
    return hc.diff_components(stored_rows, read, source, now=now or NOW, **kw)


def _ago(**delta) -> str:
    return (NOW - timedelta(**delta)).strftime("%Y-%m-%d %H:%M:%S")


def _kinds(plan: hc.Plan) -> list[str]:
    return [e["event"] for e in plan.events]


def _status(plan: hc.Plan) -> dict[int, str]:
    return {u["id"]: u["status"] for u in plan.updates}


def test_first_read_is_one_baseline_event():
    plan = diff([], [comp("S1", "Slot 1"), comp("S2", "Slot 2")], "snmp")
    assert plan.baseline and _kinds(plan) == ["baseline"] and len(plan.inserts) == 2
    assert plan.events[0]["detail"] == "First hardware read: 2 components with a serial."


def test_first_read_with_nothing_has_no_event():
    plan = diff([], [], "snmp")
    assert plan.events == [] and plan.inserts == []


def test_same_read_changes_nothing_but_last_seen():
    plan = diff(stored([(1, "S1", "Slot 1", "present")]), [comp("S1", "Slot 1")], "snmp")
    assert plan.events == [] and _status(plan) == {1: "present"} and plan.updates[0]["seen"]


def test_replaced_in_a_slot_at_once():
    plan = diff(
        stored([(1, "S1", "Slot 3", "present", {"model": "EX-OLD"})]), [comp("S9", "Slot 3", model="EX-NEW")], "snmp"
    )
    assert _kinds(plan) == ["replaced"]
    event = plan.events[0]
    assert (event["serial"], event["previous_serial"], event["previous_model"], event["model"]) == (
        "S9",
        "S1",
        "EX-OLD",
        "EX-NEW",
    )
    assert _status(plan) == {1: "removed"} and plan.updates[0]["removed"]
    assert [i["serial"] for i in plan.inserts] == ["S9"]


def test_a_missing_component_slot_taken_is_replaced():
    plan = diff(stored([(1, "S1", "Slot 3", "missing")]), [comp("S9", "Slot 3")], "snmp")
    assert _kinds(plan) == ["replaced"]


def test_installed_in_an_empty_slot():
    plan = diff(stored([(1, "S1", "Slot 1", "present")]), [comp("S1", "Slot 1"), comp("S2", "Slot 2")], "snmp")
    assert _kinds(plan) == ["installed"] and plan.events[0]["previous_host_id"] is None
    assert plan.events[0]["detail"] == "Installed in Slot 2."


def test_installed_from_another_host():
    elsewhere = {"S2": {"host_id": 7, "hostname": "edge-b", "slot": "Slot 4"}}
    plan = diff(
        stored([(1, "S1", "Slot 1", "present")]),
        [comp("S1", "Slot 1"), comp("s2", "Slot 2")],
        "snmp",
        elsewhere=elsewhere,
    )
    event = plan.events[0]
    assert (event["event"], event["previous_host_id"], event["previous_hostname"]) == ("installed", 7, "edge-b")
    # The detail does not name the other host: the structured fields do
    # (the API clears them for a caller who cannot read that host).
    assert "edge-b" not in event["detail"] and "another host" in event["detail"]


def test_moved_to_another_slot():
    plan = diff(stored([(1, "S1", "Slot 1", "present")]), [comp("S1", "Slot 2")], "snmp")
    assert _kinds(plan) == ["moved"] and plan.events[0]["previous_slot"] == "Slot 1"
    assert plan.updates[0]["slot"] == "Slot 2"


def test_removed_only_once_missing_for_the_confirmation_time():
    first = diff(
        stored([(1, "S1", "Slot 1", "present"), (2, "S2", "Slot 2", "present")]), [comp("S1", "Slot 1")], "snmp"
    )
    assert first.events == [] and _status(first) == {1: "present", 2: "missing"}
    assert first.updates[1]["missing_since"] == NOW.strftime("%Y-%m-%d %H:%M:%S")
    # Absent again within 30 minutes (a line card still booting): still missing.
    rows = stored([(1, "S1", "Slot 1", "present"), (2, "S2", "Slot 2", "missing", {"missing_since": _ago(minutes=29)})])
    second = diff(rows, [comp("S1", "Slot 1")], "snmp")
    assert second.events == [] and _status(second)[2] == "missing"
    assert second.updates[1]["missing_since"] == _ago(minutes=29)
    # Absent once missing for 30 minutes: removed.
    rows = stored([(1, "S1", "Slot 1", "present"), (2, "S2", "Slot 2", "missing", {"missing_since": _ago(minutes=30)})])
    third = diff(rows, [comp("S1", "Slot 1")], "snmp")
    assert _kinds(third) == ["removed"] and _status(third)[2] == "removed"
    assert third.events[0]["serial"] == "S2" and "30 minutes" in third.events[0]["detail"]
    assert third.updates[1]["missing_since"] is None and third.updates[1]["removed"]


def test_a_missing_row_without_a_time_starts_its_clock():
    rows = stored([(2, "S2", "Slot 2", "missing", {"missing_since": None}), (1, "S1", "Slot 1", "present")])
    plan = diff(rows, [comp("S1", "Slot 1")], "snmp")
    assert plan.events == [] and plan.updates[1]["missing_since"] == NOW.strftime("%Y-%m-%d %H:%M:%S")


def test_a_reload_with_a_booting_card_is_no_change():
    # Polls every few minutes after a reload: the card is missing, then back.
    rows = stored([(1, "S1", "Slot 1", "present"), (2, "LC1", "Slot 3", "present")])
    first = diff(rows, [comp("S1", "Slot 1")], "snmp")
    rows = stored([(1, "S1", "Slot 1", "present"), (2, "LC1", "Slot 3", "missing", {"missing_since": _ago(minutes=4)})])
    still = diff(rows, [comp("S1", "Slot 1")], "snmp")
    back = diff(rows, [comp("S1", "Slot 1"), comp("LC1", "Slot 3")], "snmp")
    assert first.events == still.events == back.events == []
    assert _status(back)[2] == "present" and back.updates[1]["missing_since"] is None


def test_a_swap_inside_the_confirmation_is_replaced_at_once():
    rows = stored([(1, "OLD1", "Slot 3", "missing", {"missing_since": _ago(minutes=5), "model": "EX-OLD"})])
    plan = diff(rows, [comp("NEW1", "Slot 3")], "snmp")
    assert _kinds(plan) == ["replaced"]  # no removed event
    assert (plan.events[0]["previous_serial"], plan.events[0]["previous_model"]) == ("OLD1", "EX-OLD")
    assert _status(plan) == {1: "removed"}


def test_a_swap_after_the_removal_is_a_replacement():
    rows = stored(
        [
            (1, "OLDER", "Slot 3", "removed", {"removed_at": _ago(days=20), "model": "EX-A"}),
            (2, "OLD1", "Slot 3", "removed", {"removed_at": _ago(hours=2), "model": "EX-B"}),
            (3, "S1", "Slot 1", "present"),
        ]
    )
    plan = diff(rows, [comp("S1", "Slot 1"), comp("NEW1", "Slot 3")], "snmp")
    assert _kinds(plan) == ["replaced"]
    event = plan.events[0]
    assert (event["serial"], event["previous_serial"], event["previous_model"], event["previous_slot"]) == (
        "NEW1",
        "OLD1",
        "EX-B",
        "Slot 3",
    )
    assert f"was removed at {_ago(hours=2)} UTC" in event["detail"]
    assert [i["serial"] for i in plan.inserts] == ["NEW1"]


def test_a_slot_refilled_after_the_window_is_installed():
    rows = stored([(1, "OLD1", "Slot 3", "removed", {"removed_at": _ago(days=31)}), (2, "S1", "Slot 1", "present")])
    plan = diff(rows, [comp("S1", "Slot 1"), comp("NEW1", "Slot 3")], "snmp")
    assert _kinds(plan) == ["installed"]


def test_the_same_serial_back_in_its_slot_is_installed():
    rows = stored([(1, "OLD1", "Slot 3", "removed", {"removed_at": _ago(hours=1)}), (2, "S1", "Slot 1", "present")])
    plan = diff(rows, [comp("S1", "Slot 1"), comp("OLD1", "Slot 3")], "snmp")
    assert _kinds(plan) == ["installed"] and _status(plan)[1] == "present"


def test_no_replacement_from_a_removed_row_across_sources():
    rows = stored(
        [(1, "OLD1", "Slot 3", "removed", {"removed_at": _ago(hours=1)}), (2, "S1", "Slot 1", "present")], source="snmp"
    )
    plan = diff(rows, [comp("S1", "Slot 1"), comp("NEW1", "Slot 3")], "ssh")
    assert _kinds(plan) == ["installed"]


def test_missing_then_back_is_nothing():
    plan = diff(stored([(1, "S1", "Slot 1", "missing")]), [comp("S1", "Slot 1")], "snmp")
    assert plan.events == [] and _status(plan) == {1: "present"}


def test_changed_model_or_revision():
    rows = stored([(1, "S1", "Slot 1", "present", {"firmware_rev": "1.0", "software_rev": ""})])
    plan = diff(rows, [comp("S1", "Slot 1", firmware_rev="2.0", software_rev="17.9")], "snmp")
    assert _kinds(plan) == ["changed"]
    assert plan.events[0]["changes"] == {"firmware_rev": {"before": "1.0", "after": "2.0"}}
    # A value that appeared (software_rev) is stored without an event.
    assert plan.updates[0]["software_rev"] == "17.9"


def test_a_value_gone_blank_keeps_the_stored_one():
    rows = stored([(1, "S1", "Slot 1", "present", {"hardware_rev": "V01"})])
    plan = diff(rows, [comp("S1", "Slot 1")], "snmp")
    assert plan.events == [] and plan.updates[0]["hardware_rev"] == "V01"


def test_index_renumbering_is_nothing():
    # Identity is the serial: the same components read in another order
    # (as after a reload renumbers entPhysicalIndex) change nothing.
    rows = stored([(1, "S1", "Slot 1", "present"), (2, "S2", "Slot 2", "present")])
    plan = diff(rows, [comp("S2", "Slot 2"), comp("S1", "Slot 1")], "snmp")
    assert plan.events == []


def test_a_source_switch_matches_by_serial_only():
    rows = stored(
        [(1, "S1", "Slot 1", "present", {"firmware_rev": "1"}), (2, "S2", "Slot 3", "present")], source="snmp"
    )
    read = [comp("S1", "1", firmware_rev="2"), comp("S9", "Slot 3")]
    plan = diff(rows, read, "ssh")
    # No moved (slot names differ by source), no changed, no replaced: S9 installed.
    assert _kinds(plan) == ["installed"]
    assert _status(plan) == {1: "present", 2: "missing"}
    assert plan.updates[0]["source"] == "ssh" and plan.updates[0]["slot"] == "1"


def test_a_removed_serial_back_on_the_host_is_installed_again():
    rows = stored([(1, "S1", "Slot 1", "present"), (2, "S2", "Slot 2", "removed")])
    plan = diff(rows, [comp("S1", "Slot 1"), comp("S2", "Slot 5")], "snmp")
    assert _kinds(plan) == ["installed"] and _status(plan)[2] == "present" and plan.inserts == []


def test_duplicate_serials_in_a_read_are_one_component():
    plan = diff([], [comp("S1", "Chassis", "chassis"), comp("S1", "Module", "module")], "snmp")
    assert [(i["serial"], i["category"]) for i in plan.inserts] == [("S1", "chassis")]


# ── Cadence ──────────────────────────────────────────────────────────────────

NOW = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)


def _stamp(delta: timedelta) -> str:
    return (NOW - delta).strftime("%Y-%m-%d %H:%M:%S")


def test_cadence():
    assert hc.is_due(None, NOW)
    ok = {"collected_at": _stamp(timedelta(hours=1)), "attempted_at": _stamp(timedelta(hours=1)), "result": "ok"}
    assert not hc.is_due(ok, NOW)
    assert hc.is_due(ok, NOW, stale=True)
    assert hc.is_due({**ok, "recheck": 1}, NOW)
    assert hc.is_due({**ok, "collected_at": _stamp(timedelta(hours=6))}, NOW)
    failed = {
        **ok,
        "collected_at": _stamp(timedelta(hours=7)),
        "result": "not_read",
        "attempted_at": _stamp(timedelta(minutes=5)),
    }
    assert not hc.is_due(failed, NOW)
    assert hc.is_due({**failed, "attempted_at": _stamp(timedelta(minutes=31))}, NOW)
    assert hc.is_due({"collected_at": "", "attempted_at": "garbage", "result": "not_read"}, NOW)


def test_syslog_module_and_restart_messages_mark_the_host_stale(monkeypatch):
    import asyncio

    from netcontrol import syslog_rules as sr

    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", True)
    monkeypatch.setattr(state, "EVENT_RECEIVER_CONFIG", {"repoll_trigger": True})
    monkeypatch.setattr(sr, "schedule_repoll", lambda *_a, **_k: False)
    messages = [
        (11, "%IOSXE_OIR-6-OFFLINECARD: Card (cc) offline in slot 3"),
        (12, "%SYS-5-RESTART: System restarted --"),
        (13, "%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down"),
    ]
    asyncio.run(sr.process_syslog_batch(messages))
    assert monitoring_repoll.hardware_stale(11) and monitoring_repoll.hardware_stale(12)
    assert not monitoring_repoll.hardware_stale(13)


def test_module_and_restart_traps_mark_the_host_stale(monkeypatch):
    import asyncio

    from netcontrol import syslog_rules as sr, trap_rules as tr

    from test_snmp_traps import LINK_DOWN, cefc_module, named, v2c

    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", True)
    monkeypatch.setattr(state, "EVENT_RECEIVER_CONFIG", {"repoll_trigger": True})
    monkeypatch.setattr(tr, "schedule_repoll", lambda *_a, **_k: True)
    monkeypatch.setattr(sr, "schedule_repoll", lambda *_a, **_k: False)
    rows = [(21, named(cefc_module(2))), (22, named(v2c("1.3.6.1.4.1.2636.4.1.30"))), (23, named(LINK_DOWN))]
    asyncio.run(tr.process_trap_batch(rows))
    assert monitoring_repoll.hardware_stale(21) and monitoring_repoll.hardware_stale(22)
    assert not monitoring_repoll.hardware_stale(23)
    assert not tr.hardware_may_have_changed(named(LINK_DOWN))


# ── Storage ──────────────────────────────────────────────────────────────────


async def _events(host_id: int) -> list[dict]:
    _total, rows = await db.list_hardware_events(host_id=host_id)
    return list(reversed(rows))


async def _age(host_id: int, column: str, serial: str, **delta) -> None:
    """Set a stored row's ``missing_since`` or ``removed_at`` back in time."""
    assert column in ("missing_since", "removed_at")
    stamp = (datetime.now(UTC) - timedelta(**delta)).strftime("%Y-%m-%d %H:%M:%S")
    conn = await db.get_db()
    try:
        await conn.execute(
            f"UPDATE hardware_components SET {column} = ? WHERE host_id = ? AND serial = ?",  # nosec B608 - test
            (stamp, host_id, serial),
        )
        await conn.commit()
    finally:
        await conn.close()


async def _components(host_id: int) -> dict[str, dict]:
    return {r["serial"]: r for r in await db.list_host_hardware(host_id)}


async def test_reads_are_stored_with_their_history():
    _group, host_id = await add_host("cisco_xe")
    first = await hc.apply_read(
        host_id, "snmp", [comp("S1", "Slot 1"), comp("S2", "Slot 2"), comp("CH1", "Chassis", "chassis")]
    )
    assert first["state"] == "ok" and [e["event"] for e in first["new_events"]] == ["baseline"]
    host = await db.get_host(host_id)
    assert host["serial_number"] == "CH1"  # filled from the chassis when empty
    state_row = await db.get_hardware_state(host_id)
    assert state_row["result"] == "ok" and state_row["component_count"] == 3 and state_row["source"] == "snmp"

    # S2 absent: missing (no event), and the next poll reads again.
    await hc.apply_read(host_id, "snmp", [comp("S1", "Slot 1"), comp("CH1", "Chassis", "chassis")])
    assert (await _components(host_id))["S2"]["status"] == "missing"
    assert (await db.get_hardware_state(host_id))["recheck"] == 1
    assert (await _components(host_id))["S2"]["missing_since"]
    # Absent again at once: still missing (not yet 30 minutes).
    out = await hc.apply_read(host_id, "snmp", [comp("S1", "Slot 1"), comp("CH1", "Chassis", "chassis")])
    assert out["new_events"] == [] and (await _components(host_id))["S2"]["status"] == "missing"
    # Absent once missing for 30 minutes: removed. S1 replaced in Slot 1 at once.
    await _age(host_id, "missing_since", "S2", minutes=31)
    out = await hc.apply_read(host_id, "snmp", [comp("S9", "Slot 1"), comp("CH1", "Chassis", "chassis")])
    assert sorted(e["event"] for e in out["new_events"]) == ["removed", "replaced"]
    rows = await _components(host_id)
    assert rows["S2"]["status"] == "removed" and rows["S2"]["removed_at"] and rows["S2"]["missing_since"] is None
    assert rows["S1"]["status"] == "removed" and rows["S9"]["status"] == "present"
    assert (await db.get_hardware_state(host_id))["recheck"] == 0
    assert [e["event"] for e in await _events(host_id)] == ["baseline", "replaced", "removed"]


async def test_a_slow_swap_is_stored_as_a_replacement():
    _group, host_id = await add_host("cisco_xe")
    await hc.apply_read(host_id, "snmp", [comp("S1", "Slot 1"), comp("LC1", "Slot 3", model="EX-LC")])
    await hc.apply_read(host_id, "snmp", [comp("S1", "Slot 1")])
    await _age(host_id, "missing_since", "LC1", minutes=45)
    out = await hc.apply_read(host_id, "snmp", [comp("S1", "Slot 1")])
    assert [e["event"] for e in out["new_events"]] == ["removed"]
    out = await hc.apply_read(host_id, "snmp", [comp("S1", "Slot 1"), comp("LC2", "Slot 3")])
    event = out["new_events"][0]
    assert (event["event"], event["previous_serial"], event["previous_model"]) == ("replaced", "LC1", "EX-LC")
    assert [e["event"] for e in await _events(host_id)] == ["baseline", "removed", "replaced"]


async def test_the_host_serial_is_never_overwritten():
    _group, host_id = await add_host("cisco_xe")
    await db.update_host_serial(host_id, "OLD0000SER")
    await hc.apply_read(host_id, "snmp", [comp("CH9", "Chassis", "chassis")])
    assert (await db.get_host(host_id))["serial_number"] == "OLD0000SER"


async def test_an_empty_read_is_believed_at_the_third():
    _group, host_id = await add_host("cisco_xe")
    await hc.apply_read(host_id, "snmp", [comp("S1", "Slot 1")])
    for n in (1, 2):
        out = await hc.apply_read(host_id, "snmp", [])
        assert out["state"] == "not_read" and f"{n} of 3" in out["message"]
        assert (await _components(host_id))["S1"]["status"] == "present"
        assert (await db.get_hardware_state(host_id))["recheck"] == 1
    out = await hc.apply_read(host_id, "snmp", [])
    assert out["state"] == "ok"
    assert (await _components(host_id))["S1"]["status"] == "missing"
    # A read with components resets the count.
    await hc.apply_read(host_id, "snmp", [comp("S1", "Slot 1")])
    assert (await db.get_hardware_state(host_id))["empty_reads"] == 0


async def test_not_read_keeps_the_last_complete_read():
    _group, host_id = await add_host("cisco_xe")
    await hc.apply_read(host_id, "snmp", [comp("S1", "Slot 1")])
    collected = (await db.get_hardware_state(host_id))["collected_at"]
    out = await hc.apply_read(host_id, "snmp", None)
    assert out["state"] == "not_read"
    row = await db.get_hardware_state(host_id)
    assert row["result"] == "not_read" and row["collected_at"] == collected
    assert (await _components(host_id))["S1"]["status"] == "present"


async def test_installed_from_another_host_and_history_kept_after_delete():
    group_id, host_a = await add_host("cisco_xe", "192.0.2.91")
    host_b = await db.add_host(group_id, "device-b", "192.0.2.92", "cisco_xe")
    await hc.apply_read(host_a, "snmp", [comp("S1", "Slot 1"), comp("MOVER1", "Slot 2")])
    await hc.apply_read(host_b, "snmp", [comp("B1", "Slot 1")])
    out = await hc.apply_read(host_b, "snmp", [comp("B1", "Slot 1"), comp("MOVER1", "Slot 4")])
    event = out["new_events"][0]
    assert (event["event"], event["previous_host_id"], event["previous_hostname"]) == ("installed", host_a, "device-a")
    await db.remove_host(host_a)
    _total, rows = await db.list_hardware_events()
    kept = [r for r in rows if r["hostname"] == "device-a"]
    assert kept and all(r["host_id"] is None for r in kept)
    assert await db.list_host_hardware(host_a) == []


async def test_an_unknown_host_is_not_stored():
    await db.init_db()
    assert await hc.apply_read(999999, "snmp", [comp("S1", "Slot 1")]) == {}


async def test_list_filters_and_search():
    _group, host_id = await add_host("cisco_xe")
    await hc.apply_read(
        host_id, "snmp", [comp("FOC0000X0AA", "Slot 1"), comp("ART0000C0CC", "PS1", "power_supply", "EX-PWR_1%")]
    )
    total, rows = await db.list_hardware_components(search="foc0000")
    assert total == 1 and rows[0]["serial"] == "FOC0000X0AA"
    total, _rows = await db.list_hardware_components(search="device-a")
    assert total == 2
    total, _rows = await db.list_hardware_components(search="_1%")  # LIKE wildcards are literal
    assert total == 1
    total, _rows = await db.list_hardware_components(categories=["power_supply"])
    assert total == 1
    # Object scope: an empty readable set matches no row; None (an
    # unrestricted caller) every row.
    total, _rows = await db.list_hardware_components(host_ids=[])
    assert total == 0
    assert (await db.list_hardware_components(host_ids=None))[0] == 2
    assert (await db.list_hardware_components(host_ids=[host_id]))[0] == 2
    assert (await db.list_hardware_events(host_ids=[]))[0] == 0
    assert (await db.list_hardware_events(host_ids=None))[0] == 1
    total, rows = await db.list_hardware_components(limit=1, offset=1)
    assert total == 2 and len(rows) == 1


async def test_migration_is_idempotent():
    import importlib

    await db.init_db()
    migration = importlib.import_module("routes.migrations.0136_add_hardware_components")
    conn = await db.get_db()
    try:
        await migration.up(conn)
        await migration.up(conn)
    finally:
        await conn.close()


# ── In the monitoring poll ───────────────────────────────────────────────────


def _poll_agent(rows: list[dict] = FIXED, **kw) -> Agent:
    walk, answers = entity(rows)
    walk[f"{SYS_UPTIME}.0"] = 100
    return Agent(walk, answers, **kw)


async def test_the_poll_reads_hardware_once_per_interval(monkeypatch):
    _group, host_id = await add_host("cisco_xe")
    host = {"id": host_id, "hostname": "device-a", "ip_address": "192.0.2.90", "device_type": "cisco_xe"}
    agent = _poll_agent()
    await poll(monkeypatch, host, agent)
    assert agent.walks.count(SERIAL) == 1
    assert [c["serial"] for c in (await db.list_host_hardware(host_id))] == ["FOC0000Y0YY"]
    # Not due again until the interval passes...
    agent = _poll_agent()
    await poll(monkeypatch, host, agent)
    assert agent.walks.count(SERIAL) == 0
    # ...or an event marks the host stale; a complete read clears the mark.
    monitoring_repoll.mark_hardware_stale(host_id)
    agent = _poll_agent()
    await poll(monkeypatch, host, agent)
    assert agent.walks.count(SERIAL) == 1 and not monitoring_repoll.hardware_stale(host_id)


async def test_a_stale_mark_stays_until_a_complete_read(monkeypatch):
    _group, host_id = await add_host("cisco_xe")
    host = {"id": host_id, "hostname": "device-a", "ip_address": "192.0.2.90", "device_type": "cisco_xe"}
    monitoring_repoll.mark_hardware_stale(host_id)
    await poll(monkeypatch, host, _poll_agent(cut={SERIAL}))
    assert monitoring_repoll.hardware_stale(host_id)
    assert (await db.get_hardware_state(host_id))["result"] == "not_read"


async def test_the_poll_skips_hardware_for_a_device_that_did_not_answer(monkeypatch):
    _group, host_id = await add_host("cisco_xe")
    host = {"id": host_id, "hostname": "device-a", "ip_address": "192.0.2.90", "device_type": "cisco_xe"}
    walk, answers = entity(FIXED)
    agent = Agent(walk, answers)  # no sysUpTime, no interface: not answering
    await poll(monkeypatch, host, agent)
    assert SERIAL not in agent.walks


async def test_a_failing_poll_read_is_logged_not_raised(monkeypatch):
    async def boom(*_a, **_k):
        raise RuntimeError("database down")

    monkeypatch.setattr(db, "get_hardware_state", boom)
    host = {"id": 5, "hostname": "device-z"}
    agent = _poll_agent()
    assert await hc.collect_in_poll(host, "cisco_xe", agent.get, agent.walk_table) is None
    assert await hc.collect_in_poll(host, "apc_ups", agent.get, agent.walk_table) is None


async def test_a_read_being_stored_is_not_stored_twice():
    hc._APPLYING.add(77)
    with pytest.raises(hc.HardwareReadBusy):
        await hc.refresh_over_snmp({"id": 77, "device_type": "cisco_xe"}, None, None)
    agent = _poll_agent()
    assert await hc.collect_in_poll({"id": 77}, "cisco_xe", agent.get, agent.walk_table) is None


# ── Over SSH ─────────────────────────────────────────────────────────────────


async def test_collect_over_ssh():
    _group, host_id = await add_host("cisco_xe")
    host = await db.get_host(host_id)
    commands: list[str] = []

    async def run(command: str) -> str:
        commands.append(command)
        return SHOW_INVENTORY

    assert await hc.collect_over_ssh(host, run) == 8
    assert commands == ["show inventory"]
    rows = await db.list_host_hardware(host_id)
    assert {r["source"] for r in rows} == {"ssh"}


async def test_ssh_is_not_stored_for_a_host_read_over_snmp():
    _group, host_id = await add_host("cisco_xe")
    host = await db.get_host(host_id)
    await hc.apply_read(host_id, "snmp", [comp("FXS0000Q0AA", "Chassis", "chassis")])

    async def run(_command: str) -> str:
        return SHOW_INVENTORY

    assert await hc.collect_over_ssh(host, run) == 0
    assert {r["source"] for r in await db.list_host_hardware(host_id)} == {"snmp"}
    # An SNMP read older than twice the interval: SSH is stored.
    conn = await db.get_db()
    try:
        old = (datetime.now(UTC) - timedelta(seconds=2 * hc.COLLECT_INTERVAL_SECONDS + 60)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        await conn.execute("UPDATE hardware_collection_state SET collected_at = ? WHERE host_id = ?", (old, host_id))
        await conn.commit()
    finally:
        await conn.close()
    assert await hc.collect_over_ssh(host, run) == 8


def test_snmp_read_recently():
    fresh = {"result": "ok", "source": "snmp", "collected_at": _ago(hours=11)}
    assert hc.snmp_read_recently(fresh, NOW)
    assert not hc.snmp_read_recently({**fresh, "collected_at": _ago(hours=13)}, NOW)
    assert not hc.snmp_read_recently({**fresh, "source": "ssh"}, NOW)
    assert not hc.snmp_read_recently({**fresh, "result": "not_read"}, NOW)
    assert not hc.snmp_read_recently(None, NOW)


async def test_collect_over_ssh_without_the_capability_or_on_failure():
    _group, host_id = await add_host("juniper_junos")
    host = await db.get_host(host_id)

    async def run(_command: str) -> str:
        raise AssertionError("not called")

    assert await hc.collect_over_ssh(host, run) == 0
    cisco = {**host, "device_type": "cisco_ios"}

    async def failing(_command: str) -> str:
        raise ConnectionError("refused")

    assert await hc.collect_over_ssh(cisco, failing) == 0

    async def empty(_command: str) -> str:
        return ""

    assert await hc.collect_over_ssh(cisco, empty) == 0
    assert await db.list_host_hardware(host_id) == []
