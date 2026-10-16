"""A minimal ``.xlsx`` writer for tabular downloads, with the standard library only.

A CSV has no layout: a spreadsheet opens it with every column the same
width, so long names and summaries are cut off and short ids waste room.
``workbook`` writes one sheet of cells, ``workbook_of`` several (one tab
each), every sheet with a bold header row that stays put when scrolling, a
filter on every column and each column as wide as its longest text (within
bounds), so the file opens readable.

Text cells are written inline (no shared strings table), numbers as
numbers. The parts are the smallest set a spreadsheet application needs:
content types, the package and workbook relationships, the workbook, the
worksheets and a style sheet with the bold font.
"""

from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any
from xml.sax.saxutils import escape, quoteattr

XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
# Column widths, in characters of the default font: the bounds a fitted
# column stays within, and the room left beside the longest text.
MIN_WIDTH = 6.0
MAX_WIDTH = 80.0
PADDING = 2.0
# Characters XML 1.0 cannot carry (tab, newline and carriage return it can).
_NOT_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")
_SHEET_NAME_FORBIDDEN = re.compile(r"[\[\]:*?/\\]")
_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_XML_HEAD = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'

_WORKSHEET_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
_PACKAGE_RELS = (
    _XML_HEAD + f'<Relationships xmlns="{_PKG_REL_NS}">'
    f'<Relationship Id="rId1" Type="{_REL_NS}/officeDocument" Target="xl/workbook.xml"/>'
    "</Relationships>"
)


def _content_types(count: int) -> str:
    sheets = "".join(
        f'<Override PartName="/xl/worksheets/sheet{number}.xml" ContentType="{_WORKSHEET_TYPE}"/>'
        for number in range(1, count + 1)
    )
    return (
        _XML_HEAD + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        f"{sheets}"
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        "</Types>"
    )


def _workbook_rels(count: int) -> str:
    """Sheet ``n`` is relationship ``rIdn``; the styles come after the sheets."""
    sheets = "".join(
        f'<Relationship Id="rId{number}" Type="{_REL_NS}/worksheet" Target="worksheets/sheet{number}.xml"/>'
        for number in range(1, count + 1)
    )
    return (
        _XML_HEAD + f'<Relationships xmlns="{_PKG_REL_NS}">'
        f"{sheets}"
        f'<Relationship Id="rId{count + 1}" Type="{_REL_NS}/styles" Target="styles.xml"/>'
        "</Relationships>"
    )


# Cell style 0 is the default font, style 1 the same font in bold (the header).
_STYLES = (
    _XML_HEAD + f'<styleSheet xmlns="{_NS}">'
    '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
    '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
    '<fills count="2"><fill><patternFill patternType="none"/></fill>'
    '<fill><patternFill patternType="gray125"/></fill></fills>'
    '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
    '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
    '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
    '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
    '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
    "</styleSheet>"
)


def column_name(index: int) -> str:
    """The letters of column ``index`` (0-based): ``A``, ``Z``, ``AA``..."""
    if index < 0:
        raise ValueError("column index must be 0 or more")
    letters = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(ord("A") + remainder) + letters
    return letters


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return _NOT_XML.sub("", str(value))


def _longest_line(value: Any) -> int:
    text = str(value) if _is_number(value) else _text(value)
    return max((len(line) for line in text.splitlines()), default=0)


def fitted_widths(columns: Sequence[str], rows: Iterable[Sequence[Any]]) -> list[float]:
    """The width of each column that fits its header and its longest cell
    (the longest line of a cell with line breaks), with ``PADDING`` beside it,
    never under ``MIN_WIDTH`` nor over ``MAX_WIDTH``."""
    longest = [_longest_line(column) for column in columns]
    for row in rows:
        for index, value in enumerate(row[: len(longest)]):
            longest[index] = max(longest[index], _longest_line(value))
    return [min(MAX_WIDTH, max(MIN_WIDTH, length + PADDING)) for length in longest]


def _cell(reference: str, value: Any, style: int = 0) -> str:
    attributes = f' s="{style}"' if style else ""
    if _is_number(value):
        return f'<c r="{reference}"{attributes}><v>{value!r}</v></c>'
    text = _text(value)
    if not text:
        return ""
    return f'<c r="{reference}" t="inlineStr"{attributes}><is><t xml:space="preserve">{escape(text)}</t></is></c>'


def _row(number: int, values: Sequence[Any], style: int = 0) -> str:
    cells = "".join(_cell(f"{column_name(index)}{number}", value, style) for index, value in enumerate(values))
    return f'<row r="{number}">{cells}</row>'


def _sheet_name(name: str, fallback: str = "Sheet1") -> str:
    """``name`` as a sheet title a spreadsheet accepts: 31 characters at most,
    none of ``[]:*?/\\``, never empty."""
    cleaned = _SHEET_NAME_FORBIDDEN.sub(" ", _text(name)).strip()[:31].strip("'")
    return cleaned or fallback


def _sheet_titles(names: Sequence[str]) -> list[str]:
    """The titles of the sheets, cleaned and made distinct (a repeat gets a
    ``(2)``, ``(3)``... that still fits in 31 characters); case is ignored
    as a spreadsheet ignores it."""
    titles: list[str] = []
    for index, name in enumerate(names):
        title = _sheet_name(name, f"Sheet{index + 1}")
        candidate, attempt = title, 1
        while candidate.lower() in {t.lower() for t in titles}:
            attempt += 1
            suffix = f" ({attempt})"
            candidate = title[: 31 - len(suffix)].rstrip() + suffix
        titles.append(candidate)
    return titles


@dataclass(frozen=True)
class Sheet:
    """One tab of a workbook: its title, header and rows."""

    title: str
    columns: Sequence[str]
    rows: Iterable[Sequence[Any]]


def _worksheet(columns: Sequence[str], rows: Iterable[Sequence[Any]]) -> tuple[str, str]:
    """The worksheet part of ``columns`` over ``rows`` and its filtered range
    (``$A$1:$L$12``) for the workbook's defined name."""
    table = [list(row) for row in rows]
    widths = fitted_widths(columns, table)
    last_column = column_name(max(len(columns), 1) - 1)
    last_row = len(table) + 1
    extent = f"A1:{last_column}{last_row}"
    cols = "".join(
        f'<col min="{index + 1}" max="{index + 1}" width="{width:.2f}" customWidth="1"/>'
        for index, width in enumerate(widths)
    )
    body = [_row(1, list(columns), style=1)]
    body.extend(_row(number, row) for number, row in enumerate(table, start=2))
    worksheet = (
        _XML_HEAD + f'<worksheet xmlns="{_NS}" xmlns:r="{_REL_NS}">'
        f'<dimension ref="{extent}"/>'
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        "</sheetView></sheetViews>"
        '<sheetFormatPr defaultRowHeight="15"/>'
        f"<cols>{cols}</cols>"
        f"<sheetData>{''.join(body)}</sheetData>"
        f'<autoFilter ref="{extent}"/>'
        "</worksheet>"
    )
    return worksheet, f"$A$1:${last_column}${last_row}"


def workbook_of(sheets: Sequence[Sheet]) -> bytes:
    """An ``.xlsx`` file with one tab per sheet, in order: each its ``columns``
    as a bold, frozen header row with a filter, then its ``rows`` (strings,
    numbers, ``None`` for an empty cell, booleans as Yes/No), each column
    sized to its text. Only the first sheet's tab is selected when opened."""
    if not sheets:
        raise ValueError("a workbook needs at least one sheet")
    titles = _sheet_titles([sheet.title for sheet in sheets])
    parts: list[str] = []
    entries: list[str] = []
    names: list[str] = []
    for index, (sheet, title) in enumerate(zip(sheets, titles, strict=True)):
        worksheet, filtered = _worksheet(sheet.columns, sheet.rows)
        parts.append(worksheet)
        entries.append(f'<sheet name={quoteattr(title)} sheetId="{index + 1}" r:id="rId{index + 1}"/>')
        reference = escape("'" + title.replace("'", "''") + "'!" + filtered)
        names.append(
            f'<definedName name="_xlnm._FilterDatabase" localSheetId="{index}" hidden="1">{reference}</definedName>'
        )
    workbook_xml = (
        _XML_HEAD + f'<workbook xmlns="{_NS}" xmlns:r="{_REL_NS}">'
        f"<sheets>{''.join(entries)}</sheets>"
        f"<definedNames>{''.join(names)}</definedNames>"
        "</workbook>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _content_types(len(parts)))
        archive.writestr("_rels/.rels", _PACKAGE_RELS)
        archive.writestr("xl/workbook.xml", workbook_xml)
        archive.writestr("xl/_rels/workbook.xml.rels", _workbook_rels(len(parts)))
        archive.writestr("xl/styles.xml", _STYLES)
        for number, part in enumerate(parts, start=1):
            archive.writestr(f"xl/worksheets/sheet{number}.xml", part)
    return buffer.getvalue()


def workbook(columns: Sequence[str], rows: Iterable[Sequence[Any]], *, sheet: str = "Sheet1") -> bytes:
    """An ``.xlsx`` file of one sheet named ``sheet`` (see ``workbook_of``)."""
    return workbook_of([Sheet(sheet, columns, rows)])
