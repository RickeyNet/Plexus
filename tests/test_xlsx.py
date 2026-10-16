"""The stdlib ``.xlsx`` writer: one tab per sheet, fitted columns, a frozen bold header."""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET  # noqa: N817
import zipfile

import pytest
from netcontrol.xlsx import MAX_WIDTH, MIN_WIDTH, PADDING, Sheet, column_name, fitted_widths, workbook, workbook_of

_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def _parts(payload: bytes) -> dict[str, str]:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        return {name: archive.read(name).decode("utf-8") for name in archive.namelist()}


def test_column_names_run_past_z():
    assert [column_name(i) for i in (0, 1, 25, 26, 27, 51, 52, 701, 702)] == [
        "A",
        "B",
        "Z",
        "AA",
        "AB",
        "AZ",
        "BA",
        "ZZ",
        "AAA",
    ]
    with pytest.raises(ValueError):
        column_name(-1)


def test_widths_fit_the_longest_text_within_bounds():
    columns = ["Id", "Name", "Summary"]
    rows = [[1, "VLAN 10 Data", "short"], [22, "VLAN 110 Users", "x" * 200], [None, "a\nmuch longer second line", ""]]
    assert fitted_widths(columns, rows) == [
        MIN_WIDTH,
        len("much longer second line") + PADDING,
        MAX_WIDTH,
    ]
    # Only the header: its own width, never under the minimum.
    assert fitted_widths(["Site", "A considerably longer heading"], []) == [MIN_WIDTH, 29 + PADDING]


def test_workbook_is_a_well_formed_package_with_the_rows_as_cells():
    rows = [
        ["Branch A", 10, "10.1.10.0/24", True, 'Rule 1 (deny any, "guest") <denies> & more'],
        ["Branch B", None, "10.1.20.0/24", False, "line one\nline two"],
        ["Bad \x00 control", 3.5, "", None, "tab\tkept"],
    ]
    parts = _parts(workbook(["Site", "VLAN", "CIDR", "In VPN", "Decided by"], rows, sheet="Reach/ability: [x]"))
    assert set(parts) == {
        "[Content_Types].xml",
        "_rels/.rels",
        "xl/workbook.xml",
        "xl/_rels/workbook.xml.rels",
        "xl/styles.xml",
        "xl/worksheets/sheet1.xml",
    }
    for text in parts.values():
        ET.fromstring(text)  # well-formed

    book = ET.fromstring(parts["xl/workbook.xml"])
    [sheet] = book.iter(f"{_NS}sheet")
    assert sheet.get("name") == "Reach ability   x"
    [name] = book.iter(f"{_NS}definedName")
    assert name.get("name") == "_xlnm._FilterDatabase" and name.text == "'Reach ability   x'!$A$1:$E$4"

    page = ET.fromstring(parts["xl/worksheets/sheet1.xml"])
    assert page.find(f"{_NS}dimension").get("ref") == "A1:E4"
    assert page.find(f"{_NS}autoFilter").get("ref") == "A1:E4"
    pane = page.find(f"{_NS}sheetViews/{_NS}sheetView/{_NS}pane")
    assert (pane.get("ySplit"), pane.get("topLeftCell"), pane.get("state")) == ("1", "A2", "frozen")
    widths = [float(col.get("width")) for col in page.iter(f"{_NS}col")]
    assert widths[0] == len("Bad  control") + PADDING and widths[2] == len("10.1.10.0/24") + PADDING
    assert all(col.get("customWidth") == "1" for col in page.iter(f"{_NS}col"))

    table = page.find(f"{_NS}sheetData")
    lines = list(table.iter(f"{_NS}row"))
    assert [line.get("r") for line in lines] == ["1", "2", "3", "4"]

    def cells(line) -> dict[str, tuple[str | None, str | None, str | None]]:
        found = {}
        for cell in line.iter(f"{_NS}c"):
            value = cell.find(f"{_NS}v")
            text = cell.find(f"{_NS}is/{_NS}t")
            found[cell.get("r")] = (
                cell.get("s"),
                value.text if value is not None else None,
                text.text if text is not None else None,
            )
        return found

    header = cells(lines[0])
    assert header["A1"] == ("1", None, "Site") and header["E1"] == ("1", None, "Decided by")
    first = cells(lines[1])
    assert first["A2"] == (None, None, "Branch A")
    assert first["B2"] == (None, "10", None)  # a number, not text
    assert first["D2"] == (None, None, "Yes")
    assert first["E2"] == (None, None, 'Rule 1 (deny any, "guest") <denies> & more')
    second = cells(lines[2])
    assert "B3" not in second  # an empty cell is left out
    assert second["D3"] == (None, None, "No") and second["E3"] == (None, None, "line one\nline two")
    third = cells(lines[3])
    assert third["A4"] == (None, None, "Bad  control") and third["B4"] == (None, "3.5", None)
    assert "C4" not in third and "D4" not in third and third["E4"] == (None, None, "tab\tkept")


def test_workbook_of_several_sheets_gives_each_its_own_tab():
    sheets = [
        Sheet("All", ["Site", "Verdict"], [["A", "Allowed"], ["B", "Blocked"]]),
        Sheet("Allowed", ["Site", "Verdict"], [["A", "Allowed"]]),
        Sheet("Blocked", ["Site", "Verdict"], [["B", "Blocked"]]),
        Sheet("Check incomplete", ["Site", "Verdict"], []),
        Sheet("blocked", ["Note"], [["a repeated title, case aside"]]),
        Sheet("", ["Note"], []),
    ]
    parts = _parts(workbook_of(sheets))
    assert [name for name in parts if name.startswith("xl/worksheets/")] == [
        f"xl/worksheets/sheet{n}.xml" for n in range(1, 7)
    ]
    for text in parts.values():
        ET.fromstring(text)
    assert parts["[Content_Types].xml"].count("/xl/worksheets/sheet") == 6

    book = ET.fromstring(parts["xl/workbook.xml"])
    tabs = [
        (
            s.get("name"),
            s.get("sheetId"),
            s.get(f"{{{'http://schemas.openxmlformats.org/officeDocument/2006/relationships'}}}id"),
        )
        for s in book.iter(f"{_NS}sheet")
    ]
    assert tabs == [
        ("All", "1", "rId1"),
        ("Allowed", "2", "rId2"),
        ("Blocked", "3", "rId3"),
        ("Check incomplete", "4", "rId4"),
        ("blocked (2)", "5", "rId5"),
        ("Sheet6", "6", "rId6"),
    ]
    names = [(n.get("localSheetId"), n.text) for n in book.iter(f"{_NS}definedName")]
    assert names[0] == ("0", "'All'!$A$1:$B$3") and names[3] == ("3", "'Check incomplete'!$A$1:$B$1")
    rels = ET.fromstring(parts["xl/_rels/workbook.xml.rels"])
    targets = {r.get("Id"): r.get("Target") for r in rels}
    assert targets["rId3"] == "worksheets/sheet3.xml" and targets["rId7"] == "styles.xml"

    blocked = ET.fromstring(parts["xl/worksheets/sheet3.xml"])
    assert [line.get("r") for line in blocked.iter(f"{_NS}row")] == ["1", "2"]
    assert "B" in {t.text for t in blocked.iter(f"{_NS}t")} and "A" not in {t.text for t in blocked.iter(f"{_NS}t")}
    empty = ET.fromstring(parts["xl/worksheets/sheet4.xml"])
    assert [line.get("r") for line in empty.iter(f"{_NS}row")] == ["1"]
    with pytest.raises(ValueError):
        workbook_of([])


def test_workbook_with_no_rows_still_has_its_header():
    parts = _parts(workbook(["Only"], []))
    page = ET.fromstring(parts["xl/worksheets/sheet1.xml"])
    assert page.find(f"{_NS}dimension").get("ref") == "A1:A1"
    assert [line.get("r") for line in page.iter(f"{_NS}row")] == ["1"]
    assert "sheet1" in ET.fromstring(parts["xl/workbook.xml"]).find(f"{_NS}sheets/{_NS}sheet").get("name").lower()
