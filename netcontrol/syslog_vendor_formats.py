"""Event tags of vendor syslog formats that carry no Cisco-style
``%FACILITY-SEVERITY-MNEMONIC`` or Junos tag.

``netcontrol.syslog_rules.parse_syslog_message`` calls these for every
received message, so each parser tests a fixed substring of the message
head before any regular expression, and the expressions are anchored or
bounded (no backtracking on a long line). Pure functions; nothing here
imports ``syslog_rules``.

- **Fortinet FortiOS** (key=value): tag ``FGT-<logid>`` (``FGT-0100032002``),
  ``raw_tag`` the ``logdesc``, ``text`` the ``msg`` value (else the line
  from ``logid=`` on).
- **Palo Alto PAN-OS** (comma separated, default format): SYSTEM logs
  ``PAN-SYSTEM-<EVENT ID>`` (``PAN-SYSTEM-AUTH-FAIL``) with the description
  as ``text``; CONFIG logs ``PAN-CONFIG`` with the line from the Command
  field on as ``text``; every other log type ``PAN-<TYPE>``
  (``PAN-TRAFFIC``), so high-volume logs group into one row.
- **HPE Aruba AOS-CX** (``Event|<id>|<severity>|<role>|<slot>|<text>``):
  tag ``AOSCX-<id>`` (``AOSCX-404``).
- **HPE Aruba AOS-Switch / ProCurve** (``<5-digit event id> <facility>:
  <text>`` after the header): tag ``AOSS-<id>`` as written (``AOSS-00077``),
  program the facility (``ports``).

``docs/syslog-rules.md`` lists the forms.
"""

from __future__ import annotations

import re
from typing import NamedTuple

# The part of a message searched for a vendor marker.
HEAD_CHARS = 512


class VendorTag(NamedTuple):
    """The tag a vendor format gives a message: ``tag`` (what rules match),
    ``raw_tag`` (shown to the operator), ``text`` (what built-in patterns
    test) and, for AOS-Switch, ``program`` (its facility)."""

    tag: str
    raw_tag: str
    text: str
    program: str = ""


# ── Fortinet FortiOS ─────────────────────────────────────────────────────────

_FGT_LOGID = re.compile(r'\blogid="?(\d{10})\b')
_FGT_LOGDESC = re.compile(r'\blogdesc="([^"]{0,200})"')
_FGT_MSG = re.compile(r'\bmsg="((?:[^"\\]|\\.)*)"')


def fortios_tag(line: str) -> VendorTag | None:
    """``FGT-<logid>`` of a FortiOS key=value log line, else None."""
    head = line[:HEAD_CHARS]
    if "logid=" not in head:
        return None
    m = _FGT_LOGID.search(head)
    if m is None:
        return None
    tag = f"FGT-{m.group(1)}"
    desc = _FGT_LOGDESC.search(line)
    msg = _FGT_MSG.search(line)
    text = msg.group(1).replace('\\"', '"').strip() if msg else line[m.start() :].strip()
    return VendorTag(tag, desc.group(1) if desc else tag, text)


# ── Palo Alto PAN-OS ─────────────────────────────────────────────────────────

# FUTURE_USE, Receive Time, Serial Number, Type, ...: the start of a log in
# the default CSV format, after the syslog header.
_PAN_START = re.compile(r"(?:^|\s)\d{1,3},\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},[^,\s]*,([A-Z]{3,20}),")
# Field positions (PAN-OS "Syslog Field Descriptions").
_PAN_SUBTYPE = 4
_PAN_SYSTEM_EVENTID = 8
_PAN_SYSTEM_DESCRIPTION = 14
_PAN_CONFIG_COMMAND = 9


def _csv_fields(line: str, count: int) -> list[tuple[int, str]]:
    """The first ``count`` comma separated fields of ``line`` as
    ``(start offset, value)``; a field in double quotes may hold commas
    and doubled quotes."""
    fields: list[tuple[int, str]] = []
    i, n = 0, len(line)
    while i <= n and len(fields) < count:
        if i < n and line[i] == '"':
            parts: list[str] = []
            j = i + 1
            while True:
                q = line.find('"', j)
                if q < 0:
                    parts.append(line[j:])
                    j = n
                    break
                parts.append(line[j:q])
                if line.startswith('""', q):
                    parts.append('"')
                    j = q + 2
                    continue
                j = q + 1
                break
            fields.append((i, "".join(parts)))
            comma = line.find(",", j)
            i = n + 1 if comma < 0 else comma + 1
        else:
            comma = line.find(",", i)
            end = n if comma < 0 else comma
            fields.append((i, line[i:end]))
            i = end + 1
    return fields


def panos_tag(line: str) -> VendorTag | None:
    """``PAN-SYSTEM-<EVENT ID>``, ``PAN-CONFIG`` or ``PAN-<TYPE>`` of a
    PAN-OS log in the default CSV format, else None."""
    head = line[:HEAD_CHARS]
    if "," not in head or "/" not in head:
        return None
    m = _PAN_START.search(head)
    if m is None:
        return None
    log_type = m.group(1)
    start = m.start() if line[m.start()].isdigit() else m.start() + 1
    record = line[start:]
    if log_type == "SYSTEM":
        fields = _csv_fields(record, _PAN_SYSTEM_DESCRIPTION + 1)
        if len(fields) <= _PAN_SYSTEM_DESCRIPTION:
            return VendorTag("PAN-SYSTEM", "SYSTEM", record[fields[-1][0] :].strip())
        subtype = fields[_PAN_SUBTYPE][1].strip()
        eventid = fields[_PAN_SYSTEM_EVENTID][1].strip()
        tag = f"PAN-SYSTEM-{eventid.upper()}" if eventid else "PAN-SYSTEM"
        raw = " ".join(p for p in ("SYSTEM", subtype, eventid) if p)
        return VendorTag(tag, raw, fields[_PAN_SYSTEM_DESCRIPTION][1].strip())
    if log_type == "CONFIG":
        fields = _csv_fields(record, _PAN_CONFIG_COMMAND + 1)
        rest = record[fields[-1][0] :] if len(fields) > _PAN_CONFIG_COMMAND else ""
        return VendorTag("PAN-CONFIG", "CONFIG", rest.strip())
    fields = _csv_fields(record, _PAN_SUBTYPE + 1)
    rest = record[fields[-1][0] :] if len(fields) > _PAN_SUBTYPE else ""
    return VendorTag(f"PAN-{log_type}", log_type, rest.strip())


# ── HPE Aruba AOS-CX ─────────────────────────────────────────────────────────

_AOSCX_EVENT = re.compile(r"\bEvent\|(\d{1,6})\|(LOG_[A-Z]{2,8})\|[^|]{0,64}\|[^|]{0,64}\|")


def aoscx_tag(line: str) -> VendorTag | None:
    """``AOSCX-<event id>`` of an AOS-CX event log line, else None."""
    head = line[:HEAD_CHARS]
    if "Event|" not in head:
        return None
    m = _AOSCX_EVENT.search(head)
    if m is None:
        return None
    event_id, severity = m.groups()
    return VendorTag(f"AOSCX-{event_id}", f"Event|{event_id}|{severity}", line[m.end() :].strip())


# ── HPE Aruba AOS-Switch / ProCurve ──────────────────────────────────────────

# [host] 00077 ports: text (the event id is always five digits; facilities
# are written in either case: ports, FFI, 802.1x, dhcp-snoop).
_AOSS_EVENT = re.compile(r"(?:[^\s:]{1,255} )?(\d{5}) ([A-Za-z0-9][A-Za-z0-9_.-]{0,31}): ")


def aos_switch_tag(rest: str) -> VendorTag | None:
    """``AOSS-<event id>`` of an AOS-Switch message, else None. ``rest`` is
    the message after its priority and RFC 3164 timestamp: the event id
    must open it (after the host name), so a five-digit number later in
    another vendor's text is not taken for one."""
    if not rest[:1].isalnum():
        return None
    m = _AOSS_EVENT.match(rest)
    if m is None:
        return None
    event_id, facility = m.groups()
    return VendorTag(f"AOSS-{event_id}", f"{event_id} {facility}", rest[m.end() :].strip(), facility)


def vendor_tag(line: str) -> VendorTag | None:
    """The tag of a FortiOS, PAN-OS or AOS-CX message (``line``: the
    message after its priority, or the MSG of an RFC 5424 message), else
    None. AOS-Switch messages are told apart by their header instead
    (``aos_switch_tag``)."""
    return fortios_tag(line) or aoscx_tag(line) or panos_tag(line)
