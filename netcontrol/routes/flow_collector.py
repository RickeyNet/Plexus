"""
flow_collector.py -- NetFlow v5/v9, sFlow, and IPFIX collection

Provides:
  - UDP listener for NetFlow v5 packet parsing
  - NetFlow v9/IPFIX template-based decoding
  - Flow record storage with batch inserts
  - Flow aggregation and summarization
  - Traffic analysis API endpoints (top talkers, applications, conversations)
  - Background collection and cleanup loops

Object scope: a caller limited to selected inventory groups sees the flows
and exporters of the hosts of those groups only.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request

import netcontrol.routes.state as state
from netcontrol import listener_sources
from netcontrol.bounded_map import BoundedDict
from netcontrol.flow_asn import lookup_flow_asns
from netcontrol.object_scope import group_filter, readable_host_ids, require_host, scope_exempt, scoped
from netcontrol.telemetry import configure_logging

router = APIRouter()
admin_router = APIRouter()  # /api/admin/* routes - registered with require_admin
LOGGER = configure_logging("plexus.flow_collector")


# ═════════════════════════════════════════════════════════════════════════════
# Configuration
# ═════════════════════════════════════════════════════════════════════════════

FLOW_COLLECTOR_CONFIG = {
    "enabled": False,
    "netflow_port": 2055,
    "sflow_port": 6343,
    "batch_size": 100,
    "retention_hours": 48,
    "summary_retention_days": 30,
    "aggregation_interval_seconds": 3600,
}

FLOW_AGGREGATION_MIN_INTERVAL = 60


def flow_retention_hours() -> int:
    """Hours raw flow records are kept (the ``retention_hours`` setting)."""
    return int(FLOW_COLLECTOR_CONFIG.get("retention_hours", 48))


_flow_transport = None
_flow_protocol = None
_sflow_transport = None
_sflow_protocol = None
_flow_aggregation_task: asyncio.Task | None = None

# Resolves exporter source IP -> hosts.id without per-packet DB lookups:
# each host's primary address and its recorded interface addresses
# (host_ip_aliases; the primary wins on a collision). Populated at collector
# start and refreshed via refresh_exporter_cache() whenever inventory hosts
# are added/updated/deleted or an integration recorded interface addresses.
# It is the listener allowlist's inventory address set
# (``listener_sources.INVENTORY_ADDRESSES``): one cache, one refresh.
_exporter_cache: dict[str, int] = listener_sources.INVENTORY_ADDRESSES
# The source allowlist and per-exporter rate limit of both flow sockets.
_flow_guard = listener_sources.guard("flow")

# Admitted datagrams wait in a per-listener queue and are decoded off the
# event loop, so a flood of flow packets cannot starve HTTP, WebSocket and
# background work. A datagram that does not fit is dropped and counted.
# Most datagrams one listener's queue holds while waiting to be decoded.
FLOW_DECODE_QUEUE_MAX = 4096
# Most datagram bytes one listener's queue holds (UDP datagrams reach 64 KB).
FLOW_DECODE_QUEUE_MAX_BYTES = 16 * 1024 * 1024
# Most datagrams decoded in one hand-off to the decode thread.
FLOW_DECODE_BATCH_MAX = 64
# Datagrams dropped because a decode queue was full, since Plexus started.
_decode_queue_dropped = 0
# Most decoded flow records one listener buffers for the database. One flush
# runs at a time, so while the database is slow records pile up here; past
# the cap the newest are dropped and counted (as the trap/syslog buffer does,
# metrics_engine._TRAP_EVENT_BUFFER_MAX).
FLOW_BUFFER_MAX = 50000
# Records dropped because a buffer was full: since the last warning (logged
# at most once per listener_sources.DROP_LOG_INTERVAL_SECONDS) and since
# Plexus started.
_flow_records_dropped = 0
_flow_records_dropped_total = 0
_flow_drop_logged_at = float("-inf")
# One thread decodes for both listeners, one batch at a time: the parsers'
# state (_nf9_templates, _sflow_sampling_rates) is only ever written from
# this thread, and a flood cannot occupy the shared asyncio.to_thread pool
# that SSH sessions, password hashing and other work use.
_decode_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="flow-decode")


# Well-known port to service name mapping
PORT_SERVICES = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    123: "NTP",
    161: "SNMP",
    162: "SNMP-Trap",
    514: "Syslog",
    520: "RIP",
    1433: "MSSQL",
    6379: "Redis",
    27017: "MongoDB",
}

PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
    132: "SCTP",
}


# ═════════════════════════════════════════════════════════════════════════════
# NetFlow v5 Parser
# ═════════════════════════════════════════════════════════════════════════════


def parse_netflow_v5(data: bytes, addr: tuple) -> list[dict]:
    """Parse a NetFlow v5 packet into a list of flow records.

    NetFlow v5 header: 24 bytes
    Each flow record: 48 bytes
    """
    if len(data) < 24:
        return []

    # Header
    version, count, sys_uptime, unix_secs, unix_nsecs, flow_sequence, engine_type, engine_id, sampling = struct.unpack(
        "!HHIIIIBBh", data[:24]
    )

    if version != 5:
        return []

    exporter_ip = addr[0]
    records = []

    for i in range(count):
        offset = 24 + (i * 48)
        if offset + 48 > len(data):
            break

        fields = struct.unpack("!IIIHHIIIIHHBBBBHHBBH", data[offset : offset + 48])
        (
            src_ip_raw,
            dst_ip_raw,
            nexthop,
            input_if,
            output_if,
            packets,
            octets,
            first,
            last,
            src_port,
            dst_port,
            _pad1,
            tcp_flags,
            protocol,
            tos,
            src_as,
            dst_as,
            src_mask,
            dst_mask,
            _pad2,
        ) = fields

        src_ip = socket.inet_ntoa(struct.pack("!I", src_ip_raw))
        dst_ip = socket.inet_ntoa(struct.pack("!I", dst_ip_raw))

        # Convert uptime-relative timestamps to absolute
        ts = datetime.fromtimestamp(unix_secs, tz=UTC)
        start_ms = sys_uptime - (sys_uptime - first) if first <= sys_uptime else first
        end_ms = sys_uptime - (sys_uptime - last) if last <= sys_uptime else last
        start_time = (ts - timedelta(milliseconds=sys_uptime - first)).isoformat()
        end_time = (ts - timedelta(milliseconds=sys_uptime - last)).isoformat()

        records.append(
            {
                "exporter_ip": exporter_ip,
                "flow_type": "netflow_v5",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "bytes": octets,
                "packets": packets,
                "src_as": src_as,
                "dst_as": dst_as,
                "input_if": input_if,
                "output_if": output_if,
                "tos": tos,
                "tcp_flags": tcp_flags,
                "start_time": start_time,
                "end_time": end_time,
            }
        )

    return records


# ═════════════════════════════════════════════════════════════════════════════
# NetFlow v9 / IPFIX Parser (template-based)
# ═════════════════════════════════════════════════════════════════════════════

# Hard limits on what one datagram (from any source: UDP sources can be
# spoofed and nothing here is authenticated) can make the collector keep or
# do. Real exporters send templates of tens of fields, a handful of
# templates each, and MTU-sized packets of a few dozen records, so every cap
# leaves wide headroom. With no zero-length field, a record walks at most
# record_len fields, so decoding a datagram costs at most its byte count in
# field steps, and NF9_MAX_RECORDS_PER_PACKET caps the rows it produces.
NF9_MAX_TEMPLATE_FIELDS = 128
NF9_MIN_RECORD_LEN = 4  # below this, flowset padding would decode as records
NF9_MAX_TEMPLATES_PER_EXPORTER = 32
NF9_MAX_EXPORTERS = 1024
NF9_MAX_RECORDS_PER_PACKET = 1024

# Template cache, bounded at both levels (the entry written longest ago is
# evicted first; a data flowset rewrites the template it uses):
# {exporter_ip: {template_id: raw field specs (4 bytes per field: type, length)}}
# Read and written only by the parsers; the listeners run them on the single
# decode thread (_decode_executor), so no lock is needed.
_nf9_templates: BoundedDict = BoundedDict(NF9_MAX_EXPORTERS)


def _nf9_store_template(exporter_ip: str, tpl_id: int, field_count: int, spec: bytes) -> bool:
    """Validate one template record and cache it. Returns False (and keeps
    nothing) for a template that is truncated, has a zero-length field, more
    than NF9_MAX_TEMPLATE_FIELDS fields or a record shorter than
    NF9_MIN_RECORD_LEN. A field count of 0 withdraws the template. The
    IPFIX variable-length marker (65535) is accepted as a field length."""
    templates = _nf9_templates.get(exporter_ip)
    if field_count == 0:
        if templates is not None:
            templates.pop(tpl_id, None)
        return False
    if tpl_id < 256 or field_count > NF9_MAX_TEMPLATE_FIELDS or len(spec) != 4 * field_count:
        return False
    record_len = 0
    for _f_type, f_len in struct.iter_unpack("!HH", spec):
        if f_len == 0:
            return False
        record_len += f_len
    if record_len < NF9_MIN_RECORD_LEN:
        return False
    if templates is None:
        templates = BoundedDict(NF9_MAX_TEMPLATES_PER_EXPORTER)
    templates[tpl_id] = spec
    _nf9_templates[exporter_ip] = templates
    return True


# NetFlow v9 field type IDs (subset)
NF9_FIELDS = {
    1: "in_bytes",
    2: "in_pkts",
    4: "protocol",
    5: "tos",
    6: "tcp_flags",
    7: "src_port",
    8: "src_ip",
    10: "input_if",
    11: "dst_port",
    12: "dst_ip",
    14: "output_if",
    16: "src_as",
    17: "dst_as",
    21: "last_switched",
    22: "first_switched",
}


def parse_netflow_v9(data: bytes, addr: tuple) -> list[dict]:
    """Parse NetFlow v9 / IPFIX packet. Returns flow records."""
    if len(data) < 20:
        return []

    version = struct.unpack("!H", data[:2])[0]
    if version not in (9, 10):
        return []

    exporter_ip = addr[0]
    count = struct.unpack("!H", data[2:4])[0]
    records: list[dict] = []
    offset = 20 if version == 9 else 16  # v9 header=20, IPFIX header=16

    while offset < len(data) - 4:
        flowset_id, flowset_length = struct.unpack("!HH", data[offset : offset + 4])

        if flowset_length < 4:
            break

        flowset_data = data[offset + 4 : offset + flowset_length]
        offset += flowset_length

        if flowset_id == 0:
            # Template FlowSet
            tpl_offset = 0
            while tpl_offset < len(flowset_data) - 4:
                tpl_id, field_count = struct.unpack("!HH", flowset_data[tpl_offset : tpl_offset + 4])
                tpl_offset += 4
                spec = flowset_data[tpl_offset : tpl_offset + 4 * field_count]
                tpl_offset += 4 * field_count
                _nf9_store_template(exporter_ip, tpl_id, field_count, spec)

        elif flowset_id >= 256:
            # Data FlowSet
            templates = _nf9_templates.get(exporter_ip)
            tpl_spec = templates.get(flowset_id) if templates else None
            if not templates or not tpl_spec:
                continue
            # In use: keep it ahead of templates nobody sends data for.
            templates[flowset_id] = tpl_spec
            _nf9_templates[exporter_ip] = templates
            template = list(struct.iter_unpack("!HH", tpl_spec))

            record_len = sum(f_len for _, f_len in template)
            if record_len <= 0:
                continue

            rec_offset = 0
            while rec_offset + record_len <= len(flowset_data) and len(records) < NF9_MAX_RECORDS_PER_PACKET:
                rec: dict[str, str | int] = {}
                field_offset = rec_offset
                for f_type, f_len in template:
                    raw = flowset_data[field_offset : field_offset + f_len]
                    field_offset += f_len

                    if f_type in (8, 12):  # IP addresses
                        if len(raw) == 4:
                            rec[NF9_FIELDS.get(f_type, f"f{f_type}")] = socket.inet_ntoa(raw)
                    elif f_type in (1, 2, 4, 5, 6, 7, 10, 11, 14, 16, 17):
                        val = int.from_bytes(raw, "big") if raw else 0
                        rec[NF9_FIELDS.get(f_type, f"f{f_type}")] = val

                rec_offset += record_len

                records.append(
                    {
                        "exporter_ip": exporter_ip,
                        "flow_type": f"netflow_v{version}",
                        "src_ip": rec.get("src_ip", ""),
                        "dst_ip": rec.get("dst_ip", ""),
                        "src_port": rec.get("src_port", 0),
                        "dst_port": rec.get("dst_port", 0),
                        "protocol": rec.get("protocol", 0),
                        "bytes": rec.get("in_bytes", 0),
                        "packets": rec.get("in_pkts", 0),
                        "src_as": rec.get("src_as", 0),
                        "dst_as": rec.get("dst_as", 0),
                        "input_if": rec.get("input_if", 0),
                        "output_if": rec.get("output_if", 0),
                        "tos": rec.get("tos", 0),
                        "tcp_flags": rec.get("tcp_flags", 0),
                        "start_time": datetime.now(UTC).isoformat(),
                        "end_time": datetime.now(UTC).isoformat(),
                    }
                )

    return records


# ═════════════════════════════════════════════════════════════════════════════
# sFlow v5 Parser (RFC 3176 / sflow.org spec)
# ═════════════════════════════════════════════════════════════════════════════

# Last seen sampling_rate per (exporter_ip, source_id). Surfaced to the
# flow_exporters table so the UI can show "this device is sampling 1:1024".
# Keyed {exporter_ip: {source_id: rate}} and bounded at both levels (least
# recently seen evicted first): the keys come from unauthenticated packets,
# and _latest_sflow_sampling_rate scans one exporter's entries per datagram.
# Like _nf9_templates, only the decode thread touches it (_decode_batch).
SFLOW_MAX_SOURCES_PER_EXPORTER = 1024
_sflow_sampling_rates: BoundedDict = BoundedDict(NF9_MAX_EXPORTERS)

# sFlow sample formats (low 20 bits of sample_type; enterprise=0)
_SF_FLOW_SAMPLE = 1
_SF_COUNTER_SAMPLE = 2
_SF_EXPANDED_FLOW_SAMPLE = 3
_SF_EXPANDED_COUNTER_SAMPLE = 4

# Flow record formats inside a flow_sample (low 20 bits of data_format; enterprise=0)
_SF_FLOW_RAW_PACKET_HEADER = 1

# Header protocols (sflow_record_raw_packet_header.protocol values)
_SF_HEADER_ETHERNET_ISO88023 = 1


def _decode_raw_packet_header(header: bytes) -> dict:
    """Decode the sampled raw Ethernet/IPv4 header inside a flow_sample.

    Returns the network-layer fields we want to put into flow_records:
    src_ip / dst_ip / src_port / dst_port / protocol / bytes / packets.
    Best-effort: returns {} if the packet isn't Ethernet+IPv4 or is truncated.
    """
    if len(header) < 14:
        return {}

    ethertype = int.from_bytes(header[12:14], "big")
    ip_offset = 14

    # Strip 802.1Q VLAN tag (or QinQ) if present so we can reach the IP header.
    while ethertype == 0x8100 and len(header) >= ip_offset + 4:
        ethertype = int.from_bytes(header[ip_offset + 2 : ip_offset + 4], "big")
        ip_offset += 4

    if ethertype != 0x0800:  # not IPv4 - bail (IPv6/ARP/MPLS not in flow_records schema)
        return {}
    if len(header) < ip_offset + 20:
        return {}

    ip_hdr = header[ip_offset : ip_offset + 20]
    version_ihl = ip_hdr[0]
    if (version_ihl >> 4) != 4:
        return {}
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(header) < ip_offset + ihl:
        return {}

    total_length = int.from_bytes(ip_hdr[2:4], "big")
    protocol = ip_hdr[9]
    src_ip = socket.inet_ntoa(ip_hdr[12:16])
    dst_ip = socket.inet_ntoa(ip_hdr[16:20])

    src_port = 0
    dst_port = 0
    if protocol in (6, 17):  # TCP / UDP
        l4_offset = ip_offset + ihl
        if len(header) >= l4_offset + 4:
            src_port = int.from_bytes(header[l4_offset : l4_offset + 2], "big")
            dst_port = int.from_bytes(header[l4_offset + 2 : l4_offset + 4], "big")

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "ip_total_length": total_length,
    }


def parse_sflow(data: bytes, addr: tuple) -> list[dict]:
    """Parse an sFlow v5 datagram into flow records.

    sFlow v5 datagram header (XDR, big-endian):
        u32 version (=5)
        u32 agent_address_type (1=IPv4, 2=IPv6)
        agent_address (4 or 16 bytes)
        u32 sub_agent_id
        u32 sequence_number
        u32 uptime_ms
        u32 num_samples

    Each sample:
        u32 sample_type   (enterprise<<20 | format; enterprise=0 standard)
        u32 sample_length
        bytes sample_data (length = sample_length)
    """
    if len(data) < 28:
        return []

    try:
        version = struct.unpack("!I", data[:4])[0]
    except struct.error:
        return []
    if version != 5:
        return []

    exporter_ip = addr[0]
    records: list[dict] = []

    offset = 4
    try:
        addr_type = struct.unpack("!I", data[offset : offset + 4])[0]
        offset += 4
        if addr_type == 1:  # IPv4
            offset += 4
        elif addr_type == 2:  # IPv6
            offset += 16
        else:
            return []

        if offset + 16 > len(data):
            return []
        # sub_agent_id, sequence, uptime, num_samples
        _sub_agent, _seq, _uptime, num_samples = struct.unpack("!IIII", data[offset : offset + 16])
        offset += 16
    except struct.error:
        return []

    now_iso = datetime.now(UTC).isoformat()

    for _ in range(num_samples):
        if offset + 8 > len(data):
            break
        sample_type, sample_length = struct.unpack("!II", data[offset : offset + 8])
        offset += 8
        sample_end = offset + sample_length
        if sample_length <= 0 or sample_end > len(data):
            break

        sample = data[offset:sample_end]
        offset = sample_end

        enterprise = sample_type >> 20
        fmt = sample_type & 0x000FFFFF
        if enterprise != 0:
            continue  # vendor-private; skip

        if fmt == _SF_FLOW_SAMPLE:
            decoded = _parse_sflow_flow_sample(sample, exporter_ip, expanded=False)
            for rec in decoded:
                rec.setdefault("start_time", now_iso)
                rec.setdefault("end_time", now_iso)
                records.append(rec)
        elif fmt == _SF_EXPANDED_FLOW_SAMPLE:
            decoded = _parse_sflow_flow_sample(sample, exporter_ip, expanded=True)
            for rec in decoded:
                rec.setdefault("start_time", now_iso)
                rec.setdefault("end_time", now_iso)
                records.append(rec)
        elif fmt in (_SF_COUNTER_SAMPLE, _SF_EXPANDED_COUNTER_SAMPLE):
            # Counter samples don't produce flow records, but we don't fail on them.
            # Sampling rate is captured from flow_samples; interface counters could
            # be wired into the SNMP poller path later.
            continue
        # other formats: ignore silently

    return records


def _parse_sflow_flow_sample(sample: bytes, exporter_ip: str, expanded: bool) -> list[dict]:
    """Decode the body of a flow_sample or expanded_flow_sample.

    flow_sample (format 1):
        u32 sequence_number
        u32 source_id               (type<<24 | index)   - 4 bytes
        u32 sampling_rate
        u32 sample_pool
        u32 drops
        u32 input
        u32 output
        u32 flow_records_count
        flow_record[] flow_records

    expanded_flow_sample (format 3): source_id, input, output are each two u32s.
    """
    try:
        if expanded:
            if len(sample) < 44:
                return []
            (
                _seq,
                _src_type,
                _src_index,
                sampling_rate,
                _pool,
                _drops,
                _in_fmt,
                _in_val,
                _out_fmt,
                _out_val,
                records_count,
            ) = struct.unpack("!IIIIIIIIIII", sample[:44])
            cursor = 44
        else:
            if len(sample) < 32:
                return []
            (
                _seq,
                _source_id,
                sampling_rate,
                _pool,
                _drops,
                _input,
                _output,
                records_count,
            ) = struct.unpack("!IIIIIIII", sample[:32])
            cursor = 32
    except struct.error:
        return []

    if sampling_rate > 0:
        sources = _sflow_sampling_rates.get(exporter_ip)
        if sources is None:
            sources = BoundedDict(SFLOW_MAX_SOURCES_PER_EXPORTER)
        sources[_src_index if expanded else (_source_id & 0x00FFFFFF)] = sampling_rate
        _sflow_sampling_rates[exporter_ip] = sources

    out: list[dict] = []
    rate = sampling_rate if sampling_rate > 0 else 1

    for _ in range(records_count):
        if cursor + 8 > len(sample):
            break
        try:
            data_format, flow_data_length = struct.unpack("!II", sample[cursor : cursor + 8])
        except struct.error:
            break
        cursor += 8
        body_end = cursor + flow_data_length
        if flow_data_length <= 0 or body_end > len(sample):
            break

        body = sample[cursor:body_end]
        cursor = body_end

        enterprise = data_format >> 20
        fmt = data_format & 0x000FFFFF
        if enterprise != 0 or fmt != _SF_FLOW_RAW_PACKET_HEADER:
            continue
        if len(body) < 16:
            continue

        try:
            protocol_kind, frame_length, _stripped, header_length = struct.unpack("!IIII", body[:16])
        except struct.error:
            continue
        if protocol_kind != _SF_HEADER_ETHERNET_ISO88023:
            continue
        header_bytes = body[16 : 16 + header_length]

        decoded = _decode_raw_packet_header(header_bytes)
        if not decoded:
            continue

        # Each sampled packet represents `rate` packets on the wire.
        # frame_length is the original Ethernet frame size, used to estimate bytes.
        bytes_estimate = frame_length * rate
        packets_estimate = rate

        out.append(
            {
                "exporter_ip": exporter_ip,
                "flow_type": "sflow_v5",
                "src_ip": decoded["src_ip"],
                "dst_ip": decoded["dst_ip"],
                "src_port": decoded["src_port"],
                "dst_port": decoded["dst_port"],
                "protocol": decoded["protocol"],
                "bytes": bytes_estimate,
                "packets": packets_estimate,
                "src_as": 0,
                "dst_as": 0,
                "input_if": 0,
                "output_if": 0,
                "tos": 0,
                "tcp_flags": 0,
                # start_time / end_time filled in by parse_sflow()
            }
        )

    return out


def _latest_sflow_sampling_rate(exporter_ip: str) -> int:
    """Return the most recently observed sampling rate for an exporter, or 0."""
    return max(_sflow_sampling_rates.get(exporter_ip, {}).values(), default=0)


def _decode_batch(mode: str, batch: list[tuple[bytes, tuple]]) -> list[tuple[tuple, list[dict], int]]:
    """Decode queued datagrams of one listener; runs on the decode thread.

    Returns ``(addr, records, sampling_rate)`` for each datagram that gave
    records. A datagram the parser fails on is logged and skipped, so it
    cannot cost the rest of the batch. The sFlow sampling rate is read here,
    on the thread that writes it.
    """
    decoded: list[tuple[tuple, list[dict], int]] = []
    for data, addr in batch:
        try:
            if mode == "sflow":
                records = parse_sflow(data, addr)
                sampling_rate = _latest_sflow_sampling_rate(addr[0])
            elif struct.unpack("!H", data[:2])[0] == 5:
                records = parse_netflow_v5(data, addr)
                sampling_rate = 0
            else:
                records = parse_netflow_v9(data, addr)
                sampling_rate = 0
        except Exception as exc:
            LOGGER.debug("flow_collector: decode of a datagram from %s failed: %s", addr[0], type(exc).__name__)
            continue
        if records:
            decoded.append((addr, records, sampling_rate))
    return decoded


# ═════════════════════════════════════════════════════════════════════════════
# UDP Flow Receiver Protocol
# ═════════════════════════════════════════════════════════════════════════════


class _FlowCollectorProtocol(asyncio.DatagramProtocol):
    """UDP listener that receives NetFlow/IPFIX/sFlow packets.

    The collector binds two sockets (NetFlow on 2055, sFlow on 6343) and
    each protocol instance is told which format to expect via `mode`:
    `mode="netflow"` parses v5/v9/IPFIX off the version byte; `mode="sflow"`
    routes everything through parse_sflow(). Both modes share the same
    buffer/flush path so flow_records end up in one table.

    The event loop only admits a datagram (source allowlist, rate limit,
    length and version) and queues it. A drain worker hands the queue to
    the decode thread in batches and stores the records it returns.
    """

    def __init__(self, mode: str = "netflow"):
        self.mode = mode
        self._buffer: list[tuple] = []
        # True while a flush runs: it loops until the buffer is empty, so a
        # batch stored meanwhile waits for it instead of a second writer.
        self._flushing = False
        self._flush_task: asyncio.Task | None = None
        # (datagram, source address) waiting to be decoded; bounded in count
        # (FLOW_DECODE_QUEUE_MAX) and in bytes (FLOW_DECODE_QUEUE_MAX_BYTES).
        self._queue: asyncio.Queue[tuple[bytes, tuple]] = asyncio.Queue()
        self._queued_bytes = 0
        self._drain_task: asyncio.Task | None = None
        self._closing: asyncio.Task | None = None
        # Hold strong references to fire-and-forget tasks spawned from the hot
        # UDP path. The event loop only keeps a weak reference, so without this
        # a task can be garbage-collected before it runs, silently dropping an
        # exporter-stat update or a buffer flush under load.
        self._bg_tasks: set[asyncio.Task] = set()

    def connection_made(self, transport):
        self.transport = transport
        self._flush_task = asyncio.create_task(self._periodic_flush())
        self._drain_task = asyncio.create_task(self._drain_loop())
        LOGGER.info("flow_collector: UDP listener started (mode=%s)", self.mode)

    def datagram_received(self, data: bytes, addr: tuple):
        global _decode_queue_dropped
        # An exporter that is not an inventory host address (nor in an
        # allowed network), or over its rate limit, is dropped unparsed.
        if not _flow_guard.admit(addr[0]):
            return
        if len(data) < 4:
            return
        if self.mode != "sflow" and struct.unpack("!H", data[:2])[0] not in (5, 9, 10):
            return  # Unknown format
        if (
            self._closing is not None
            or self._queue.qsize() >= FLOW_DECODE_QUEUE_MAX
            or self._queued_bytes + len(data) > FLOW_DECODE_QUEUE_MAX_BYTES
        ):
            _decode_queue_dropped += 1
            return
        self._queued_bytes += len(data)
        self._queue.put_nowait((data, addr))

    async def drain(self) -> None:
        """Wait until every queued datagram is decoded and its records are in
        the buffer. Returns at once when the drain worker is not running."""
        worker = self._drain_task
        if worker is None or worker.done():
            return
        joined = asyncio.ensure_future(self._queue.join())
        try:
            await asyncio.wait({joined, worker}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            joined.cancel()

    async def _drain_loop(self) -> None:
        """Take up to FLOW_DECODE_BATCH_MAX datagrams at a time, decode them
        on the decode thread (one batch at a time) and store the records."""
        loop = asyncio.get_running_loop()
        while True:
            batch = [await self._queue.get()]
            while len(batch) < FLOW_DECODE_BATCH_MAX and not self._queue.empty():
                batch.append(self._queue.get_nowait())
            try:
                decoded = await loop.run_in_executor(_decode_executor, _decode_batch, self.mode, batch)
                self._store(decoded)
            except Exception as exc:
                LOGGER.warning("flow_collector: decoding %d datagrams failed: %s", len(batch), type(exc).__name__)
            finally:
                self._queued_bytes -= sum(len(data) for data, _addr in batch)
                for _ in batch:
                    self._queue.task_done()

    def _store(self, decoded: list[tuple[tuple, list[dict], int]]) -> None:
        """Buffer the decoded records and count each packet for its exporter
        (on the event loop: the exporter cache and the pending stats are
        only touched here). A record that does not fit (``FLOW_BUFFER_MAX``)
        is dropped and counted."""
        global _flow_records_dropped, _flow_records_dropped_total
        for addr, records, sampling_rate in decoded:
            exporter_ip = addr[0]
            host_id = _exporter_cache.get(exporter_ip)
            flow_type = records[0]["flow_type"]
            last_record_at = records[-1].get("end_time")

            for rec in records:
                if len(self._buffer) >= FLOW_BUFFER_MAX:
                    _flow_records_dropped += 1
                    _flow_records_dropped_total += 1
                    continue
                self._buffer.append(
                    (
                        rec["exporter_ip"],
                        host_id,
                        rec["flow_type"],
                        rec["src_ip"],
                        rec["dst_ip"],
                        rec["src_port"],
                        rec["dst_port"],
                        rec["protocol"],
                        rec["bytes"],
                        rec["packets"],
                        rec["src_as"],
                        rec["dst_as"],
                        rec["input_if"],
                        rec["output_if"],
                        rec["tos"],
                        rec["tcp_flags"],
                        rec["start_time"],
                        rec["end_time"],
                    )
                )

            # Per-exporter telemetry: count this packet (not per-record) so the
            # number matches what the device actually sent over the wire. Pure
            # in-memory accumulate — flushed to the DB on the periodic tick, so
            # the hot UDP path never touches the writer lock.
            _note_exporter_packet(exporter_ip, flow_type, host_id, last_record_at, sampling_rate)

        # A flush already running picks these records up before it ends.
        if not self._flushing and len(self._buffer) >= FLOW_COLLECTOR_CONFIG.get("batch_size", 100):
            self._spawn(self._flush_buffer())

    def _spawn(self, coro) -> None:
        """Fire off a background coroutine, holding a strong reference until it
        finishes so the loop's weak reference can't let it be GC'd mid-flight."""
        task = asyncio.create_task(coro)
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)

    async def _flush_buffer(self):
        """Write the buffer to the database. One flush at a time per
        listener: a call while one runs returns at once, and the running one
        keeps taking the buffer until it is empty, so no record is left
        behind and a slow database never has a pile of writers queued on it."""
        if self._flushing:
            return
        self._flushing = True
        try:
            while self._buffer:
                batch = self._buffer[:]
                self._buffer.clear()
                try:
                    count = await db.create_flow_records_batch(batch)
                    if count > 0:
                        LOGGER.debug("flow_collector: flushed %d flow records", count)
                except Exception as exc:
                    LOGGER.warning("flow_collector: flush error: %s", str(exc))
        finally:
            self._flushing = False
        _log_flow_records_dropped()

    async def _periodic_flush(self):
        """Flush buffer and pending exporter stats periodically (every 10 seconds)."""
        while True:
            await asyncio.sleep(10)
            await self._flush_buffer()
            await _flush_exporter_stats()

    async def close(self) -> None:
        """Stop the listener's work: decode and store every datagram already
        queued, stop the drain worker and the periodic flush, wait for
        flushes in flight, then flush the buffer. Datagrams that arrive
        while closing are dropped and counted. Safe to call more than once;
        every call waits for the same close."""
        if self._closing is None:
            self._closing = asyncio.create_task(self._close())
        await asyncio.shield(self._closing)

    async def _close(self) -> None:
        global _decode_queue_dropped
        await self.drain()
        tasks = [t for t in (self._drain_task, self._flush_task) if t is not None]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # Left only when the worker was not running (never connected, or
        # cancelled from outside): nothing will decode these.
        while not self._queue.empty():
            data, _addr = self._queue.get_nowait()
            self._queued_bytes -= len(data)
            _decode_queue_dropped += 1
        if self._bg_tasks:
            await asyncio.gather(*list(self._bg_tasks), return_exceptions=True)
        await self._flush_buffer()

    def connection_lost(self, exc):
        # A socket that closed without stop_flow_collector (an error) still
        # gets its queue decoded and its buffer flushed; the task is held in
        # self._closing, and stop_flow_collector waits for it.
        if self._closing is None:
            self._closing = asyncio.create_task(self._close())
        LOGGER.info("flow_collector: UDP listener stopped")


# ═════════════════════════════════════════════════════════════════════════════
# Exporter Cache & Telemetry
# ═════════════════════════════════════════════════════════════════════════════


async def refresh_exporter_cache() -> int:
    """Reload _exporter_cache from the hosts table and the hosts' recorded
    interface addresses (``db.get_exporter_host_map``).

    Called at collector startup and from host CRUD paths so the in-memory
    map stays consistent with inventory without per-packet DB lookups.
    The map is the listener allowlist's (``listener_sources.refresh_inventory``),
    so a host change reaches the trap and syslog allowlist too. Returns the
    number of entries loaded.
    """
    return await listener_sources.refresh_inventory()


async def on_host_changed(
    old_ip: str | None = None,
    new_ip: str | None = None,
    host_id: int | None = None,
) -> None:
    """Hook called from host add/update/remove to keep state consistent.

    Refreshes the in-memory exporter cache and propagates host_id changes
    to any existing flow_exporters rows for the affected IPs so the
    exporter table doesn't lag inventory edits.
    """
    await sync_exporter_hosts()
    try:
        if old_ip and old_ip != new_ip:
            await db.update_flow_exporter_host_id(old_ip, None)
        if new_ip and host_id is not None:
            await db.update_flow_exporter_host_id(new_ip, host_id)
    except Exception as exc:
        LOGGER.warning("flow_collector: exporter host_id sync failed: %s", type(exc).__name__)


async def sync_exporter_hosts() -> int:
    """Refresh the exporter cache, then link every ``flow_exporters`` row to
    the host its address now resolves to (an interface address recorded
    after the exporter was first seen links it; an address no host has any
    more unlinks it). Called after host edits and after an integration
    recorded a host's interface addresses (the OPNsense collection). Returns
    the number of exporter rows changed; never raises."""
    await refresh_exporter_cache()
    try:
        return await db.relink_flow_exporters(dict(_exporter_cache))
    except Exception as exc:
        LOGGER.warning("flow_collector: exporter host_id relink failed: %s", type(exc).__name__)
        return 0


# Pending per-exporter packet counters, keyed by (exporter_ip, flow_type).
# Written by the drain worker on the event loop after a batch is decoded (one
# thread, so no lock needed) and drained by _flush_exporter_stats. Bounded: with
# the "any" source policy the keys follow whatever reaches the socket.
_pending_exporter_stats: BoundedDict = BoundedDict(4 * NF9_MAX_EXPORTERS)


def _note_exporter_packet(
    exporter_ip: str,
    flow_type: str,
    host_id: int | None,
    last_record_at: str | None,
    sampling_rate: int = 0,
) -> None:
    """Accumulate per-exporter packet telemetry in memory (no DB access)."""
    entry = _pending_exporter_stats.get((exporter_ip, flow_type))
    if entry is None:
        _pending_exporter_stats[(exporter_ip, flow_type)] = {
            "host_id": host_id,
            "packets": 1,
            "sampling_rate": int(sampling_rate or 0),
            "last_record_at": last_record_at,
        }
        return
    entry["packets"] += 1
    entry["host_id"] = host_id
    if sampling_rate:
        entry["sampling_rate"] = int(sampling_rate)
    if last_record_at:
        entry["last_record_at"] = last_record_at


async def _flush_exporter_stats() -> None:
    """Persist accumulated exporter counters. Best-effort: never raises.

    One upsert per active (exporter, flow_type) pair per flush tick instead
    of one per received packet.
    """
    if not _pending_exporter_stats:
        return
    pending = dict(_pending_exporter_stats)
    _pending_exporter_stats.clear()
    for (exporter_ip, flow_type), stats in pending.items():
        try:
            await db.upsert_flow_exporter(
                exporter_ip=exporter_ip,
                flow_type=flow_type,
                host_id=stats["host_id"],
                packets_delta=stats["packets"],
                sampling_rate=stats["sampling_rate"],
                last_record_at=stats["last_record_at"],
            )
        except Exception as exc:
            LOGGER.debug("flow_collector: exporter upsert failed for %s: %s", exporter_ip, type(exc).__name__)


# ═════════════════════════════════════════════════════════════════════════════
# Collector Lifecycle
# ═════════════════════════════════════════════════════════════════════════════


async def start_flow_collector(port: int = 2055, sflow_port: int | None = None) -> bool:
    """Start the UDP flow collector.

    Always opens the NetFlow/IPFIX listener on ``port``. If ``sflow_port``
    is provided and non-zero, also opens a second listener for sFlow v5 on
    that port. The sFlow socket failing to bind is logged but doesn't
    abort startup - NetFlow still works on its own.
    """
    global _flow_transport, _flow_protocol, _sflow_transport, _sflow_protocol
    if _flow_transport is not None:
        return False  # Already running

    try:
        loop = asyncio.get_event_loop()
        _flow_transport, _flow_protocol = await loop.create_datagram_endpoint(
            lambda: _FlowCollectorProtocol(mode="netflow"),
            local_addr=("0.0.0.0", port),  # nosec B104 - NetFlow/IPFIX listener must accept exporters on any interface
        )
        FLOW_COLLECTOR_CONFIG["enabled"] = True
        FLOW_COLLECTOR_CONFIG["netflow_port"] = port
        await refresh_exporter_cache()
        LOGGER.info("flow_collector: NetFlow listener started on UDP port %d", port)
    except Exception as exc:
        LOGGER.error("flow_collector: failed to start NetFlow listener on port %d: %s", port, str(exc))
        return False

    if sflow_port:
        try:
            _sflow_transport, _sflow_protocol = await loop.create_datagram_endpoint(
                lambda: _FlowCollectorProtocol(mode="sflow"),
                local_addr=("0.0.0.0", sflow_port),  # nosec B104 - sFlow listener must accept exporters on any interface
            )
            FLOW_COLLECTOR_CONFIG["sflow_port"] = sflow_port
            LOGGER.info("flow_collector: sFlow listener started on UDP port %d", sflow_port)
        except Exception as exc:
            LOGGER.warning(
                "flow_collector: sFlow listener on port %d failed (continuing without it): %s",
                sflow_port,
                str(exc),
            )
            _sflow_transport = None
            _sflow_protocol = None

    return True


async def stop_flow_collector() -> bool:
    """Stop the UDP flow collector (both NetFlow and sFlow sockets)."""
    global _flow_transport, _flow_protocol, _sflow_transport, _sflow_protocol
    if _flow_transport is None and _sflow_transport is None:
        return False

    # Each socket is closed first so nothing more is queued; close() then
    # decodes what is already queued and flushes the rows.
    if _sflow_transport is not None:
        try:
            _sflow_transport.close()
            if _sflow_protocol:
                await _sflow_protocol.close()
        except Exception as exc:
            LOGGER.debug("flow_collector: sFlow transport close failed: %s", exc)
        _sflow_transport = None
        _sflow_protocol = None

    if _flow_transport is not None:
        try:
            _flow_transport.close()
            if _flow_protocol:
                await _flow_protocol.close()
        except Exception as exc:
            LOGGER.debug("flow_collector: NetFlow transport close failed: %s", exc)
        _flow_transport = None
        _flow_protocol = None

    await _flush_exporter_stats()
    FLOW_COLLECTOR_CONFIG["enabled"] = False
    LOGGER.info("flow_collector: stopped")
    return True


async def flow_aggregation_loop() -> None:
    """Background loop: periodically aggregate flows and prune old records.

    Interval is taken from FLOW_COLLECTOR_CONFIG['aggregation_interval_seconds']
    on each iteration, with a floor of FLOW_AGGREGATION_MIN_INTERVAL.
    """
    while True:
        interval = max(
            FLOW_AGGREGATION_MIN_INTERVAL,
            int(FLOW_COLLECTOR_CONFIG.get("aggregation_interval_seconds", 3600)),
        )
        await asyncio.sleep(interval)
        if not FLOW_COLLECTOR_CONFIG.get("enabled"):
            continue
        try:
            await flow_aggregation_cycle()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("flow_collector: aggregation cycle failed: %s", type(exc).__name__)


async def flow_aggregation_cycle():
    """Hourly upkeep: re-read the exporter cache, so interface addresses a
    discovery recorded without a host edit resolve their exporters within
    the hour, and prune old records. The flow views aggregate the raw
    records (one scan per view, ``db.get_flow_overview``); no summaries are
    written, and the ones an older release wrote age out at
    ``summary_retention_days``."""
    await sync_exporter_hosts()

    # Cleanup old raw records
    cleaned = await db.cleanup_old_flow_records(flow_retention_hours())
    if cleaned > 0:
        LOGGER.info("flow_collector: cleaned up %d old flow records", cleaned)
    summary_days = int(FLOW_COLLECTOR_CONFIG.get("summary_retention_days", 30))
    cleaned = await db.cleanup_old_flow_summaries(summary_days)
    if cleaned > 0:
        LOGGER.info("flow_collector: cleaned up %d old flow summaries", cleaned)


# ═════════════════════════════════════════════════════════════════════════════
# API Endpoints
# ═════════════════════════════════════════════════════════════════════════════


async def _flow_scope(request: Request | None, host_id: int | None) -> dict:
    """The ``group_ids`` keyword of the flow readers for the caller (``{}``
    when unrestricted); 404 for a scoped caller's unreadable ``host_id``."""
    scope_kwargs = await group_filter(request)
    if scope_kwargs and host_id is not None:
        await require_host(request, host_id)
    return scope_kwargs


@router.get("/api/flows/top-talkers")
@scoped("list")
async def api_top_talkers(
    host_id: int | None = Query(None),
    hours: int = Query(1, ge=1, le=168),
    direction: str = Query("src"),
    limit: int = Query(20, ge=1, le=100),
    request: Request = None,  # type: ignore[assignment]
):
    scope_kwargs = await _flow_scope(request, host_id)
    results = await db.get_flow_top_talkers(host_id, hours, direction, limit, **scope_kwargs)
    return await _with_talker_networks(results)


async def _with_talker_networks(*talker_lists: list[dict]) -> list[dict]:
    """Each talker row (``ip``) of ``talker_lists`` with its ASN details when
    known, from one lookup; returns the first list."""
    asns = await lookup_flow_asns([r["ip"] for rows in talker_lists for r in rows])
    for rows in talker_lists:
        for r in rows:
            r["protocol_name"] = ""  # flows are aggregated, no single protocol
            if (network := asns.get(r["ip"])) is not None:
                r.update(network)
    return talker_lists[0]


def _with_service_names(rows: list[dict]) -> list[dict]:
    """Application rows (``port``, ``protocol``) with ``service_name`` and
    ``protocol_name``."""
    for r in rows:
        port = r.get("port", 0)
        proto = r.get("protocol", 0)
        r["service_name"] = PORT_SERVICES.get(port, f"port-{port}")
        r["protocol_name"] = PROTOCOL_NAMES.get(proto, f"proto-{proto}")
    return rows


@router.get("/api/flows/top-applications")
@scoped("list")
async def api_top_applications(
    host_id: int | None = Query(None),
    hours: int = Query(1, ge=1, le=168),
    limit: int = Query(20, ge=1, le=100),
    request: Request = None,  # type: ignore[assignment]
):
    scope_kwargs = await _flow_scope(request, host_id)
    return _with_service_names(await db.get_flow_top_applications(host_id, hours, limit, **scope_kwargs))


@router.get("/api/flows/top-conversations")
@scoped("list")
async def api_top_conversations(
    host_id: int | None = Query(None),
    hours: int = Query(1, ge=1, le=168),
    limit: int = Query(20, ge=1, le=100),
    request: Request = None,  # type: ignore[assignment]
):
    scope_kwargs = await _flow_scope(request, host_id)
    return await db.get_flow_top_conversations(host_id, hours, limit, **scope_kwargs)


@router.get("/api/flows/top-interfaces")
@scoped("list")
async def api_top_interfaces(
    host_id: int | None = Query(None),
    hours: int = Query(1, ge=1, le=168),
    limit: int = Query(20, ge=1, le=100),
    request: Request = None,  # type: ignore[assignment]
):
    """The exporters' interfaces ranked by traffic: the index the flow
    records carry (``if_index``) with its name (``if_name``, ``if_device``;
    ``None`` when the host has no name for it) and the bytes that entered
    and left on it."""
    scope_kwargs = await _flow_scope(request, host_id)
    rows = await db.get_flow_top_interfaces(host_id, hours, limit, **scope_kwargs)
    return await db.with_interface_names(rows)


@router.get("/api/flows/timeline")
@scoped("list")
async def api_flow_timeline(
    host_id: int | None = Query(None),
    hours: int = Query(6, ge=1, le=168),
    bucket_minutes: int = Query(5, ge=1, le=60),
    request: Request = None,  # type: ignore[assignment]
):
    scope_kwargs = await _flow_scope(request, host_id)
    return await db.get_flow_timeline(host_id, hours, bucket_minutes, **scope_kwargs)


@router.get("/api/flows/overview")
@scoped("list")
async def api_flow_overview(
    host_id: int | None = Query(None),
    hours: int = Query(1, ge=1, le=168),
    limit: int = Query(20, ge=1, le=100),
    bucket_minutes: int = Query(5, ge=1, le=60),
    parts: str = Query("", max_length=200),
    request: Request = None,  # type: ignore[assignment]
) -> dict:
    """Flow views from one scan of the records: ``top_src``, ``top_dst``,
    ``top_applications``, ``top_conversations``, ``top_interfaces`` and
    ``timeline``, each as the endpoint of that name returns it for the same
    arguments. ``parts``: a comma-separated choice of those (empty: all), so
    a page shows what one tab needs without computing the rest."""
    chosen = [p.strip() for p in parts.split(",") if p.strip()]
    if set(chosen) - set(db.FLOW_OVERVIEW_PARTS):
        raise HTTPException(400, f"parts must be among: {', '.join(db.FLOW_OVERVIEW_PARTS)}")
    scope_kwargs = await _flow_scope(request, host_id)
    found = await db.get_flow_overview(
        host_id, hours, limit, bucket_minutes, parts=chosen or None, **scope_kwargs
    )
    if "top_src" in found or "top_dst" in found:
        await _with_talker_networks(found.get("top_src", []), found.get("top_dst", []))
    _with_service_names(found.get("top_applications", []))
    if "top_interfaces" in found:
        found["top_interfaces"] = await db.with_interface_names(found["top_interfaces"])
    return {**found, "hours": hours, "bucket_minutes": bucket_minutes}


@router.get("/api/flows/status")
@scope_exempt("the collector's own settings and state: no host or inventory group data")
async def api_flow_status():
    return {
        "enabled": FLOW_COLLECTOR_CONFIG.get("enabled", False),
        "netflow_port": FLOW_COLLECTOR_CONFIG.get("netflow_port", 2055),
        "sflow_port": FLOW_COLLECTOR_CONFIG.get("sflow_port", 6343),
        "running": _flow_transport is not None,
        "sflow_running": _sflow_transport is not None,
        **_drop_counters(),
    }


def _drop_counters() -> dict[str, int]:
    """Datagrams the listener allowlist and rate limit dropped, and those
    dropped because a decode queue was full, and the flow records dropped
    because a buffer was full, since start."""
    stats = _flow_guard.stats()
    return {
        "dropped_source": stats["dropped_source"],
        "dropped_rate": stats["dropped_rate"],
        "dropped_queue": _decode_queue_dropped,
        "dropped_buffer": _flow_records_dropped_total,
    }


def _log_flow_records_dropped() -> None:
    """Warn about records dropped at a full buffer, at most once per
    ``listener_sources.DROP_LOG_INTERVAL_SECONDS`` (a flood would otherwise
    log on every flush)."""
    global _flow_records_dropped, _flow_drop_logged_at
    if not _flow_records_dropped:
        return
    now = time.monotonic()
    if now - _flow_drop_logged_at < listener_sources.DROP_LOG_INTERVAL_SECONDS:
        return
    LOGGER.warning("flow_collector: flow record buffer full - dropped %d records", _flow_records_dropped)
    _flow_records_dropped = 0
    _flow_drop_logged_at = now


@router.get("/api/flows/exporters")
@scoped("list")
async def api_flow_exporters(request: Request = None):  # type: ignore[assignment]
    """List devices that have exported flows, with per-protocol packet
    counters (a scoped caller: those that are hosts it can read, and the
    cache size is their count)."""
    rows = await db.list_flow_exporters()
    hosts = await readable_host_ids(request)
    if hosts is not None:
        rows = [row for row in rows if row.get("host_id") is not None and int(row["host_id"]) in hosts]
        return {"exporters": rows, "cache_size": len(rows)}
    return {"exporters": rows, "cache_size": len(_exporter_cache)}


@admin_router.post("/api/admin/flows/start")
async def api_start_collector(
    port: int = Query(2055, ge=1, le=65535),
    sflow_port: int | None = Query(None, ge=1, le=65535),
):
    ok = await start_flow_collector(port, sflow_port=sflow_port)
    if not ok:
        raise HTTPException(400, "Collector already running or port unavailable")
    return {
        "started": True,
        "port": port,
        "sflow_port": sflow_port,
        "sflow_running": _sflow_transport is not None,
    }


@admin_router.post("/api/admin/flows/stop")
async def api_stop_collector():
    ok = await stop_flow_collector()
    if not ok:
        raise HTTPException(400, "Collector not running")
    return {"stopped": True}


# ═════════════════════════════════════════════════════════════════════════════
# Persisted Config (Phase D)
# ═════════════════════════════════════════════════════════════════════════════
#
# Port / retention / toggle state lives in auth_settings("flow_collector").
# These endpoints let admins change it from the Settings UI without an env-var
# restart; `apply_flow_collector_config()` runs the diff (start/stop/rebind
# listeners only when the relevant fields actually changed).


def _ensure_aggregation_task() -> None:
    """Start the aggregation loop if it isn't already running."""
    global _flow_aggregation_task
    if _flow_aggregation_task is None or _flow_aggregation_task.done():
        _flow_aggregation_task = asyncio.create_task(flow_aggregation_loop())


async def _cancel_aggregation_task() -> None:
    global _flow_aggregation_task
    if _flow_aggregation_task is None:
        return
    _flow_aggregation_task.cancel()
    try:
        await _flow_aggregation_task
    except (asyncio.CancelledError, Exception) as exc:
        LOGGER.debug("flow_collector: aggregation task cancel wait raised: %s", exc)
    _flow_aggregation_task = None


async def apply_flow_collector_config(new_cfg: dict) -> dict:
    """Apply a new persisted config, hot-restarting listeners on port changes.

    Returns the final FLOW_COLLECTOR_CONFIG snapshot after reconciliation.
    Callers are expected to have already validated/sanitized `new_cfg`.
    """
    old_enabled = bool(FLOW_COLLECTOR_CONFIG.get("enabled"))
    old_netflow = int(FLOW_COLLECTOR_CONFIG.get("netflow_port", 2055))
    old_sflow = int(FLOW_COLLECTOR_CONFIG.get("sflow_port", 6343))

    FLOW_COLLECTOR_CONFIG.update(new_cfg)

    new_enabled = bool(FLOW_COLLECTOR_CONFIG.get("enabled"))
    new_netflow = int(FLOW_COLLECTOR_CONFIG.get("netflow_port", 2055))
    new_sflow = int(FLOW_COLLECTOR_CONFIG.get("sflow_port", 6343))

    listener_change = old_netflow != new_netflow or old_sflow != new_sflow or old_enabled != new_enabled

    if new_enabled:
        if listener_change:
            # Stop first so the rebind doesn't hit EADDRINUSE on the old port.
            if _flow_transport is not None or _sflow_transport is not None:
                await stop_flow_collector()
            await start_flow_collector(
                new_netflow,
                sflow_port=new_sflow if new_sflow else None,
            )
        elif _flow_transport is None:
            # Was enabled in config but somehow not running - start it.
            await start_flow_collector(
                new_netflow,
                sflow_port=new_sflow if new_sflow else None,
            )
        _ensure_aggregation_task()
    else:
        # Disabled: ensure both the listener and the aggregation loop are gone.
        if _flow_transport is not None or _sflow_transport is not None:
            await stop_flow_collector()
        await _cancel_aggregation_task()

    # FLOW_COLLECTOR_CONFIG["enabled"] gets flipped to False by stop_flow_collector(),
    # but the persisted intent is what the admin chose. Restore it.
    FLOW_COLLECTOR_CONFIG["enabled"] = new_enabled

    return _config_snapshot()


def _config_snapshot() -> dict:
    """Return the publishable config view (omits batch_size internal knob)."""
    return {
        "enabled": bool(FLOW_COLLECTOR_CONFIG.get("enabled", False)),
        "netflow_port": int(FLOW_COLLECTOR_CONFIG.get("netflow_port", 2055)),
        "sflow_port": int(FLOW_COLLECTOR_CONFIG.get("sflow_port", 6343)),
        "retention_hours": int(FLOW_COLLECTOR_CONFIG.get("retention_hours", 48)),
        "summary_retention_days": int(FLOW_COLLECTOR_CONFIG.get("summary_retention_days", 30)),
        "aggregation_interval_seconds": int(FLOW_COLLECTOR_CONFIG.get("aggregation_interval_seconds", 3600)),
        "netflow_running": _flow_transport is not None,
        "sflow_running": _sflow_transport is not None,
        **_drop_counters(),
    }


@admin_router.get("/api/admin/flows/config")
async def api_get_flow_config():
    return _config_snapshot()


@admin_router.put("/api/admin/flows/config")
async def api_update_flow_config(body: dict):
    sanitized = state._sanitize_flow_collector_config(body)
    await db.set_auth_setting("flow_collector", sanitized)
    snapshot = await apply_flow_collector_config(sanitized)
    return snapshot
