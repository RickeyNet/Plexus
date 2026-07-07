"""Unit tests for JuniperJunosDriver.parse_serial_number.

Regression coverage for the part-number confusion: on models where the
``show chassis hardware`` Chassis row carries a Part number column, the old
first-alnum-token heuristic returned the part number (e.g. "750-012345")
instead of the serial. Serials mix letters and digits; part numbers are
all-digit.
"""

from __future__ import annotations

from netcontrol.drivers.juniper_junos import JuniperJunosDriver


def _driver() -> JuniperJunosDriver:
    return JuniperJunosDriver()


def test_serial_from_chassis_row_without_part_number():
    output = (
        "Item             Version  Part number  Serial number  Description\n"
        "Chassis                                JN12345AB      EX4300-48T\n"
    )
    assert _driver().parse_serial_number(output) == "JN12345AB"


def test_serial_skips_part_number_column():
    # Chassis row DOES carry a part number; must return the serial, not it.
    output = (
        "Item             Version  Part number  Serial number  Description\n"
        "Chassis          REV 42   750-012345   JN12345AB      MX240\n"
    )
    assert _driver().parse_serial_number(output) == "JN12345AB"


def test_ignores_routing_engine_rows():
    output = (
        "Chassis                                AA9988CC       QFX5100\n"
        "Routing Engine 0  REV 01  750-000001   BB1122DD       RE-QFX5100\n"
    )
    assert _driver().parse_serial_number(output) == "AA9988CC"


def test_returns_none_when_no_serial():
    output = "Item  Version  Part number\nChassis\n"
    assert _driver().parse_serial_number(output) is None
