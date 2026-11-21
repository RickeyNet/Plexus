"""CSV exports never write a cell a spreadsheet would run as a formula."""

from __future__ import annotations

import csv
import io

import pytest
from netcontrol.csv_cells import CSV_FORMULA_PREFIXES, csv_text_cell, csv_text_row
from netcontrol.integrations.pathtrace import sweep
from netcontrol.routes import reporting

FORMULAS = ['=HYPERLINK("https://example.com")', "+1+1", "-2+3", "@SUM(A1)", "\tcmd", "\rcmd"]


@pytest.mark.parametrize("value", FORMULAS)
def test_text_cell_guards_every_formula_prefix(value):
    assert value.startswith(CSV_FORMULA_PREFIXES)
    assert csv_text_cell(value) == "'" + value


@pytest.mark.parametrize("value", ["core-sw-01", "192.0.2.10", "", "a=b", "10 - 2"])
def test_text_cell_leaves_plain_text_alone(value):
    assert csv_text_cell(value) == value


def test_text_row_guards_text_and_keeps_numbers():
    row = {"name": "=cmd", "site": "Lab", "count": -5, "ratio": -0.5, "missing": None}
    assert csv_text_row(row) == {"name": "'=cmd", "site": "Lab", "count": -5, "ratio": -0.5, "missing": None}


def test_report_csv_guards_formula_cells():
    text = reporting._rows_to_csv([{"hostname": "=cmd|' /C calc'!A0", "ip_address": "192.0.2.10", "errors": -1}])

    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows == [{"hostname": "'=cmd|' /C calc'!A0", "ip_address": "192.0.2.10", "errors": "-1"}]


def test_sweep_csv_row_guards_names_from_the_dashboard():
    row = {
        "org_name": "=Org",
        "provider": "meraki",
        "site_name": "+Site",
        "name": "@Net",
        "kind": "vlan",
        "vlan": 10,
        "cidr": "192.0.2.0/24",
        "in_vpn": True,
        "dst_site_name": "-Far",
        "dst_name": "Servers",
        "dst_cidr": "198.51.100.0/24",
        "verdict": "allowed",
        "summary": "=1+1",
    }

    cells = dict(zip(sweep.CSV_COLUMNS, sweep.csv_row(row), strict=True))

    formula_cells = {column: cell for column, cell in cells.items() if cell.startswith(CSV_FORMULA_PREFIXES)}
    assert formula_cells == {}
    assert "'=Org" in cells.values()
    assert "'=1+1" in cells.values()
    assert "192.0.2.0/24" in cells.values()
    # A spreadsheet row keeps the VLAN id as a number.
    assert 10 in sweep.sheet_row(row)
