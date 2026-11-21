"""OPNsense firewall log lines (``filterlog``) and their per-rule aggregate.

OPNsense logs one CSV line per packet a rule with "Log packets matched by
this rule" lets through or blocks, and forwards it by syslog when a remote
logging target is configured. The line format (opnsense/ports
``opnsense/filterlog/files/description.txt`` and ``print-ip.c``; the GUI's
live log parser ``src/opnsense/scripts/filter/read_log.py`` reads the same
field lists) is::

    rulenr,subrulenr,anchorname,label,interface,reason,action,dir,ipversion,
    IPv4: tos,ecn,ttl,id,offset,flags,protonum,protoname,length,src,dst,
    IPv6: class,flowlabel,hoplimit,protoname,protonum,length,src,dst,
    then UDP: srcport,dstport,datalen
         TCP: srcport,dstport,datalen,flags,seq,ack,window,urg,options
         other protocols (ICMP among them): datalength=N

The ``label`` is the pf label of the rule that decided: the rule's uuid
for an MVC rule ("Firewall: Automation" and the new rules), an MD5 hash of
the rule's fields for a legacy ``<filter><rule>``
(``opnsense_config.legacy_rule_label`` derives the same hash), and a hash
of the generated rule for the automatic ones (default deny, anti-lockout,
bogons): those match no rule of config.xml and are kept under their
label. The firewall's rule counters (``firewall/filter_util/rule_stats``)
are keyed by the same label. A release that writes ``0`` there and the
label last (before 21.1) is read too, and a line without any label is kept
under its pf rule number (``rulenr:N``).

``parse_filterlog`` never raises: a line that is not a complete filterlog
record (a short or truncated packet, another program's message) gives
``None``. ``FilterlogAggregator`` sums parsed lines in memory into
time buckets per rule and a few recent distinct flows per rule, bounded,
for a writer to flush on a timer: a busy firewall logs thousands of lines
a second, and raw lines are never stored.

Pure (no I/O).
"""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime

__all__ = [
    "BUCKET_SECONDS",
    "FilterlogAggregator",
    "FilterlogEntry",
    "bucket_start",
    "filterlog_payload",
    "is_filterlog",
    "parse_filterlog",
    "parse_record",
    "protocol_name",
]

# The tag is near the start of a syslog message: after the timestamp and
# host name (RFC 3164) or the version, timestamp and host name (RFC 5424).
_TAG = "filterlog"
_TAG_WINDOW = 320
_GENERAL = 9
_V4_FIELDS = 11
_V6_FIELDS = 8
_ACTIONS = frozenset({"pass", "block", "match", "rdr", "nat", "binat", "scrub", "synproxy-drop"})
# Actions that decide a flow: what the evidence counts.
COUNTED_ACTIONS = ("pass", "block")
_HASH = re.compile(r"[0-9a-f]{32}")
_ICMP_NUMBERS = ("1", "58")
# Timestamps are written as Plexus writes them: UTC text.
_FMT = "%Y-%m-%d %H:%M:%S"
# The width of a time bucket: an hour and a day are counted from whole buckets.
BUCKET_SECONDS = 600


@dataclass(frozen=True)
class FilterlogEntry:
    """One parsed filterlog line."""

    rule_number: int
    sub_rule: str
    anchor: str
    label: str  # the pf label as logged ("" when none)
    rule_key: str  # the label, else ``rulenr:N`` (``rulenr:anchor/N`` in an anchor)
    interface: str
    reason: str
    action: str
    direction: str
    ip_version: int
    protocol: str  # tcp, udp, icmp, icmpv6, carp... (lower case)
    protocol_number: int | None
    source: str
    destination: str
    source_port: int | None = None
    destination_port: int | None = None
    icmp_type: str = ""


def is_filterlog(message: str) -> bool:
    """Whether a syslog message (its priority already taken off) comes from
    OPNsense's filterlog. Cheap: it runs for every received message."""
    return _TAG in message[:_TAG_WINDOW]


def _skip_structured_data(text: str) -> str | None:
    """``text`` after the RFC 5424 STRUCTURED-DATA it starts with (``-`` or
    one or more ``[...]`` elements; ``]`` and ``"`` may be escaped inside)."""
    if text.startswith("-"):
        return text[1:]
    position = 0
    while position < len(text) and text[position] == "[":
        quoted = escaped = False
        end = -1
        for index in range(position + 1, len(text)):
            char = text[index]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = not quoted
            elif char == "]" and not quoted:
                end = index
                break
        if end < 0:
            return None
        position = end + 1
    return text[position:] if position else None


def filterlog_payload(message: str) -> str | None:
    """The CSV record of a filterlog message (``<PRI>`` optional), RFC 3164
    (``filterlog[pid]: record``) or RFC 5424 (``filterlog PROCID MSGID SD
    record``) framed; ``None`` when filterlog is not the program that sent
    it (a message that only mentions filterlog)."""
    if message.startswith("<"):
        end = message.find(">", 0, 6)
        if end > 0:
            message = message[end + 1 :]
    start = message.find(_TAG, 0, _TAG_WINDOW)
    if start < 0:
        return None
    rest = message[start + len(_TAG) :]
    if rest.startswith(("[", ":")):
        colon = rest.find(":")
        return rest[colon + 1 :].strip() if colon >= 0 else None
    if not rest.startswith(" "):
        return None
    parts = rest.lstrip().split(" ", 2)
    if len(parts) < 3:
        return None
    if parts[0].endswith(":"):  # "filterlog 1234: record" seen from some relays
        return " ".join(parts[1:]).strip()
    body = _skip_structured_data(parts[2].lstrip())
    return body.strip().lstrip("\ufeff") if body is not None else None


def _address(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _port(value: str) -> int | None:
    value = value.strip()
    if not value.isdigit():
        return None
    number = int(value)
    return number if 0 <= number <= 65535 else None


def protocol_name(name: str, number: str = "") -> str:
    """A logged protocol as the path trace names protocols."""
    text = name.strip().lower()
    if text in ("ipv6-icmp", "icmp6", "icmpv6") or number.strip() == "58":
        return "icmpv6"
    if not text and number.strip() == "1":
        return "icmp"
    return text or number.strip()


def parse_filterlog(message: str) -> FilterlogEntry | None:
    """One filterlog syslog message (``<PRI>`` optional) as a
    ``FilterlogEntry``; ``None`` when it is no complete filterlog record."""
    payload = filterlog_payload(message)
    return parse_record(payload) if payload else None


def parse_record(payload: str) -> FilterlogEntry | None:
    """The CSV record of a filterlog line as a ``FilterlogEntry``; ``None``
    when it is incomplete or not one. Never raises."""
    fields = payload.split(",")
    if len(fields) < _GENERAL:
        return None
    rulenr, subrule, anchor, label, interface, reason, action, direction, version = (
        f.strip() for f in fields[:_GENERAL]
    )
    action = action.lower()
    if not rulenr.isdigit() or action not in _ACTIONS or direction not in ("in", "out"):
        return None
    if version == "4" and len(fields) >= _GENERAL + _V4_FIELDS:
        number, name = fields[15], fields[16]
        source, destination = fields[18], fields[19]
        rest = fields[_GENERAL + _V4_FIELDS :]
    elif version == "6" and len(fields) >= _GENERAL + _V6_FIELDS:
        name, number = fields[12], fields[13]
        source, destination = fields[15], fields[16]
        rest = fields[_GENERAL + _V6_FIELDS :]
    else:
        return None
    src, dst = _address(source), _address(destination)
    if src is None or dst is None:
        return None
    if label in ("", "0") and fields and _HASH.fullmatch(fields[-1].strip()):
        label = fields[-1].strip()  # before 21.1 the label came last
    label = "" if label == "0" else label
    rule_key = label or f"rulenr:{anchor + '/' if anchor else ''}{rulenr}"
    protocol = protocol_name(name, number)
    src_port = dst_port = None
    icmp_type = ""
    if protocol in ("tcp", "udp") and len(rest) >= 2:
        src_port, dst_port = _port(rest[0]), _port(rest[1])
    elif number.strip() in _ICMP_NUMBERS and rest and rest[0].strip() and "=" not in rest[0]:
        icmp_type = rest[0].strip()[:32]  # pfSense-style lines name the ICMP type
    return FilterlogEntry(
        rule_number=int(rulenr),
        sub_rule=subrule,
        anchor=anchor,
        label=label,
        rule_key=rule_key[:128],
        interface=interface[:64],
        reason=reason[:32],
        action=action,
        direction=direction,
        ip_version=int(version),
        protocol=protocol[:16],
        protocol_number=int(number) if number.strip().isdigit() else None,
        source=src,
        destination=dst,
        source_port=src_port,
        destination_port=dst_port,
        icmp_type=icmp_type,
    )


# ── Aggregate ────────────────────────────────────────────────────────────────


def bucket_start(epoch: float) -> str:
    """The start of the time bucket that holds ``epoch``, as stored."""
    start = int(epoch) - int(epoch) % BUCKET_SECONDS
    return datetime.fromtimestamp(start, UTC).strftime(_FMT)


def _stamp(epoch: float) -> str:
    return datetime.fromtimestamp(int(epoch), UTC).strftime(_FMT)


class FilterlogAggregator:
    """Parsed filterlog lines summed in memory until the next flush.

    ``buckets``: ``(host_id, bucket, rule_key, action, interface,
    direction) -> [hits, last_seen]``. ``flows``: ``(host_id, rule_key,
    action, source, destination, protocol, destination_port) -> [hits,
    last_seen]`` (port 0: none). Only the deciding actions are counted
    (``pass``, ``block``). Memory is bounded: a line that needs a new
    bucket past ``max_buckets`` is dropped (counted); a flow past
    ``max_flows`` in all or ``flows_per_rule`` for its rule is left out
    while the rule's hits still count. The counters (``stats``) are kept
    since the start; ``drain`` hands over and clears the sums only.
    """

    def __init__(self, max_buckets: int = 20000, max_flows: int = 20000, flows_per_rule: int = 50) -> None:
        self.max_buckets = max_buckets
        self.max_flows = max_flows
        self.flows_per_rule = flows_per_rule
        self.buckets: dict[tuple, list] = {}
        self.flows: dict[tuple, list] = {}
        self._flow_counts: dict[tuple, int] = {}
        self.counters = {
            "lines": 0,  # counted into the evidence
            "unparsed": 0,  # filterlog lines that are no complete record
            "other_actions": 0,  # match, rdr, nat...: no decision of a rule
            "unknown_source": 0,  # from an address that is no inventory host
            "disabled": 0,  # received while the evidence was switched off
            "dropped": 0,  # past the memory bound
            "flows_left_out": 0,
        }

    def count(self, name: str, amount: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + amount

    def add(self, host_id: int, payload: str, now: float | None = None) -> bool:
        """Count the record of one filterlog message of ``host_id``
        (``filterlog_payload``). True when it counted."""
        entry = parse_record(payload)
        if entry is None:
            self.count("unparsed")
            return False
        return self.add_entry(host_id, entry, now)

    def add_entry(self, host_id: int, entry: FilterlogEntry, now: float | None = None) -> bool:
        if entry.action not in COUNTED_ACTIONS:
            self.count("other_actions")
            return False
        moment = time.time() if now is None else now
        seen = _stamp(moment)
        key = (host_id, bucket_start(moment), entry.rule_key, entry.action, entry.interface, entry.direction)
        found = self.buckets.get(key)
        if found is None:
            if len(self.buckets) >= self.max_buckets:
                self.count("dropped")
                return False
            self.buckets[key] = [1, seen]
        else:
            found[0] += 1
            found[1] = seen
        self.count("lines")
        self._add_flow(host_id, entry, seen)
        return True

    def _add_flow(self, host_id: int, entry: FilterlogEntry, seen: str) -> None:
        rule = (host_id, entry.rule_key, entry.action)
        key = (*rule, entry.source, entry.destination, entry.protocol, entry.destination_port or 0)
        found = self.flows.get(key)
        if found is not None:
            found[0] += 1
            found[1] = seen
            return
        if len(self.flows) >= self.max_flows or self._flow_counts.get(rule, 0) >= self.flows_per_rule:
            self.count("flows_left_out")
            return
        self.flows[key] = [1, seen]
        self._flow_counts[rule] = self._flow_counts.get(rule, 0) + 1

    def pending(self) -> int:
        return len(self.buckets) + len(self.flows)

    def drain(self) -> tuple[list[tuple], list[tuple]]:
        """The bucket rows ``(host_id, bucket, rule_key, action, interface,
        direction, hits, last_seen)`` and flow rows ``(host_id, rule_key,
        action, source, destination, protocol, destination_port, hits,
        last_seen)`` summed since the last drain; the sums start over."""
        buckets = [(*key, hits, seen) for key, (hits, seen) in self.buckets.items()]
        flows = [(*key, hits, seen) for key, (hits, seen) in self.flows.items()]
        self.buckets = {}
        self.flows = {}
        self._flow_counts = {}
        return buckets, flows

    def stats(self) -> dict[str, int]:
        return dict(self.counters)
