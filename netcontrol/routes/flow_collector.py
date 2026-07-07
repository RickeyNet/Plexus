"""
flow_collector.py -- NetFlow v5/v9, sFlow, and IPFIX collection

Provides:
  - UDP listener for NetFlow v5 packet parsing
  - NetFlow v9/IPFIX template-based decoding
  - Flow record storage with batch inserts
  - Flow aggregation and summarization
  - Traffic analysis API endpoints (top talkers, applications, conversations)
  - Background collection and cleanup loops
"""
from __future__ import annotations

import asyncio
import json
import socket
import struct
from datetime import UTC, datetime, timedelta

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request

import netcontrol.routes.state as state
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

_flow_transport = None
_flow_protocol = None
_sflow_transport = None
_sflow_protocol = None
_flow_aggregation_task: asyncio.Task | None = None

# Resolves exporter source IP -> hosts.id without per-packet DB lookups.
# Populated at collector start and refreshed via refresh_exporter_cache()
# whenever inventory hosts are added/updated/deleted.
_exporter_cache: dict[str, int] = {}
_exporter_cache_lock = asyncio.Lock()


# Well-known port to service name mapping
PORT_SERVICES = {
    22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 123: "NTP", 161: "SNMP", 162: "SNMP-Trap",
    514: "Syslog", 520: "RIP", 1433: "MSSQL", 6379: "Redis",
    27017: "MongoDB",
}

PROTOCOL_NAMES = {
    1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP",
    51: "AH", 89: "OSPF", 132: "SCTP",
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

        fields = struct.unpack("!IIIHHIIIIHHBBBBHHBBH", data[offset:offset + 48])
        (src_ip_raw, dst_ip_raw, nexthop, input_if, output_if,
         packets, octets, first, last,
         src_port, dst_port, _pad1, tcp_flags, protocol, tos,
         src_as, dst_as, src_mask, dst_mask, _pad2) = fields

        src_ip = socket.inet_ntoa(struct.pack("!I", src_ip_raw))
        dst_ip = socket.inet_ntoa(struct.pack("!I", dst_ip_raw))

        # Convert uptime-relative timestamps to absolute
        ts = datetime.fromtimestamp(unix_secs, tz=UTC)
        start_ms = sys_uptime - (sys_uptime - first) if first <= sys_uptime else first
        end_ms = sys_uptime - (sys_uptime - last) if last <= sys_uptime else last
        start_time = (ts - timedelta(milliseconds=sys_uptime - first)).isoformat()
        end_time = (ts - timedelta(milliseconds=sys_uptime - last)).isoformat()

        records.append({
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
        })

    return records


# ═════════════════════════════════════════════════════════════════════════════
# NetFlow v9 / IPFIX Parser (template-based)
# ═════════════════════════════════════════════════════════════════════════════

# Template cache: {(exporter_ip, template_id): [(field_type, field_length), ...]}
_nf9_templates: dict[tuple[str, int], list[tuple[int, int]]] = {}

# NetFlow v9 field type IDs (subset)
NF9_FIELDS = {
    1: "in_bytes", 2: "in_pkts", 4: "protocol", 5: "tos",
    6: "tcp_flags", 7: "src_port", 8: "src_ip", 10: "input_if",
    11: "dst_port", 12: "dst_ip", 14: "output_if",
    16: "src_as", 17: "dst_as", 21: "last_switched", 22: "first_switched",
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
    records = []
    offset = 20 if version == 9 else 16  # v9 header=20, IPFIX header=16

    while offset < len(data) - 4:
        flowset_id, flowset_length = struct.unpack("!HH", data[offset:offset + 4])

        if flowset_length < 4:
            break

        flowset_data = data[offset + 4:offset + flowset_length]
        offset += flowset_length

        if flowset_id == 0:
            # Template FlowSet
            tpl_offset = 0
            while tpl_offset < len(flowset_data) - 4:
                tpl_id, field_count = struct.unpack("!HH", flowset_data[tpl_offset:tpl_offset + 4])
                tpl_offset += 4
                fields = []
                for _ in range(field_count):
                    if tpl_offset + 4 > len(flowset_data):
                        break
                    f_type, f_len = struct.unpack("!HH", flowset_data[tpl_offset:tpl_offset + 4])
                    tpl_offset += 4
                    fields.append((f_type, f_len))
                _nf9_templates[(exporter_ip, tpl_id)] = fields

        elif flowset_id >= 256:
            # Data FlowSet
            template = _nf9_templates.get((exporter_ip, flowset_id))
            if not template:
                continue

            record_len = sum(f_len for _, f_len in template)
            if record_len <= 0:
                continue

            rec_offset = 0
            while rec_offset + record_len <= len(flowset_data):
                rec = {}
                field_offset = rec_offset
                for f_type, f_len in template:
                    raw = flowset_data[field_offset:field_offset + f_len]
                    field_offset += f_len

                    if f_type in (8, 12):  # IP addresses
                        if len(raw) == 4:
                            rec[NF9_FIELDS.get(f_type, f"f{f_type}")] = socket.inet_ntoa(raw)
                    elif f_type in (1, 2, 4, 5, 6, 7, 10, 11, 14, 16, 17):
                        val = int.from_bytes(raw, "big") if raw else 0
                        rec[NF9_FIELDS.get(f_type, f"f{f_type}")] = val

                rec_offset += record_len

                records.append({
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
                })

    return records


# ═════════════════════════════════════════════════════════════════════════════
# sFlow v5 Parser (RFC 3176 / sflow.org spec)
# ═════════════════════════════════════════════════════════════════════════════

# Last seen sampling_rate per (exporter_ip, source_id). Surfaced to the
# flow_exporters table so the UI can show "this device is sampling 1:1024".
_sflow_sampling_rates: dict[tuple[str, int], int] = {}

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
        ethertype = int.from_bytes(header[ip_offset + 2:ip_offset + 4], "big")
        ip_offset += 4

    if ethertype != 0x0800:  # not IPv4 - bail (IPv6/ARP/MPLS not in flow_records schema)
        return {}
    if len(header) < ip_offset + 20:
        return {}

    ip_hdr = header[ip_offset:ip_offset + 20]
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
            src_port = int.from_bytes(header[l4_offset:l4_offset + 2], "big")
            dst_port = int.from_bytes(header[l4_offset + 2:l4_offset + 4], "big")

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
        addr_type = struct.unpack("!I", data[offset:offset + 4])[0]
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
        _sub_agent, _seq, _uptime, num_samples = struct.unpack("!IIII", data[offset:offset + 16])
        offset += 16
    except struct.error:
        return []

    now_iso = datetime.now(UTC).isoformat()

    for _ in range(num_samples):
        if offset + 8 > len(data):
            break
        sample_type, sample_length = struct.unpack("!II", data[offset:offset + 8])
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
                _seq, _src_type, _src_index, sampling_rate, _pool, _drops,
                _in_fmt, _in_val, _out_fmt, _out_val, records_count,
            ) = struct.unpack("!IIIIIIIIIII", sample[:44])
            cursor = 44
        else:
            if len(sample) < 32:
                return []
            (
                _seq, _source_id, sampling_rate, _pool, _drops,
                _input, _output, records_count,
            ) = struct.unpack("!IIIIIIII", sample[:32])
            cursor = 32
    except struct.error:
        return []

    if sampling_rate > 0:
        _sflow_sampling_rates[(exporter_ip, _src_index if expanded else (_source_id & 0x00FFFFFF))] = sampling_rate

    out: list[dict] = []
    rate = sampling_rate if sampling_rate > 0 else 1

    for _ in range(records_count):
        if cursor + 8 > len(sample):
            break
        try:
            data_format, flow_data_length = struct.unpack("!II", sample[cursor:cursor + 8])
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
            protocol_kind, frame_length, _stripped, header_length = struct.unpack(
                "!IIII", body[:16]
            )
        except struct.error:
            continue
        if protocol_kind != _SF_HEADER_ETHERNET_ISO88023:
            continue
        header_bytes = body[16:16 + header_length]

        decoded = _decode_raw_packet_header(header_bytes)
        if not decoded:
            continue

        # Each sampled packet represents `rate` packets on the wire.
        # frame_length is the original Ethernet frame size, used to estimate bytes.
        bytes_estimate = frame_length * rate
        packets_estimate = rate

        out.append({
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
        })

    return out


def _latest_sflow_sampling_rate(exporter_ip: str) -> int:
    """Return the most recently observed sampling rate for an exporter, or 0."""
    best = 0
    for (ip, _src), rate in _sflow_sampling_rates.items():
        if ip == exporter_ip and rate > best:
            best = rate
    return best


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
    """

    def __init__(self, mode: str = "netflow"):
        self.mode = mode
        self._buffer: list[tuple] = []
        self._flush_task: asyncio.Task | None = None
        # Hold strong references to fire-and-forget tasks spawned from the hot
        # UDP path. The event loop only keeps a weak reference, so without this
        # a task can be garbage-collected before it runs, silently dropping an
        # exporter-stat update or a buffer flush under load.
        self._bg_tasks: set[asyncio.Task] = set()

    def connection_made(self, transport):
        self.transport = transport
        self._flush_task = asyncio.create_task(self._periodic_flush())
        LOGGER.info("flow_collector: UDP listener started (mode=%s)", self.mode)

    def datagram_received(self, data: bytes, addr: tuple):
        if len(data) < 4:
            return

        if self.mode == "sflow":
            records = parse_sflow(data, addr)
            sampling_rate = _latest_sflow_sampling_rate(addr[0])
        else:
            version = struct.unpack("!H", data[:2])[0]
            if version == 5:
                records = parse_netflow_v5(data, addr)
            elif version in (9, 10):
                records = parse_netflow_v9(data, addr)
            else:
                return  # Unknown format
            sampling_rate = 0

        if not records:
            return

        exporter_ip = addr[0]
        host_id = _exporter_cache.get(exporter_ip)
        flow_type = records[0]["flow_type"]
        last_record_at = records[-1].get("end_time")

        for rec in records:
            self._buffer.append((
                rec["exporter_ip"], host_id, rec["flow_type"],
                rec["src_ip"], rec["dst_ip"], rec["src_port"], rec["dst_port"],
                rec["protocol"], rec["bytes"], rec["packets"],
                rec["src_as"], rec["dst_as"], rec["input_if"], rec["output_if"],
                rec["tos"], rec["tcp_flags"], rec["start_time"], rec["end_time"],
            ))

        # Per-exporter telemetry: count this packet (not per-record) so the
        # number matches what the device actually sent over the wire.
        self._spawn(_record_exporter_packet(
            exporter_ip, flow_type, host_id, last_record_at, sampling_rate
        ))

        if len(self._buffer) >= FLOW_COLLECTOR_CONFIG.get("batch_size", 100):
            self._spawn(self._flush_buffer())

    def _spawn(self, coro) -> None:
        """Fire off a background coroutine, holding a strong reference until it
        finishes so the loop's weak reference can't let it be GC'd mid-flight."""
        task = asyncio.create_task(coro)
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)

    async def _flush_buffer(self):
        if not self._buffer:
            return
        batch = self._buffer[:]
        self._buffer.clear()
        try:
            count = await db.create_flow_records_batch(batch)
            if count > 0:
                LOGGER.debug("flow_collector: flushed %d flow records", count)
        except Exception as exc:
            LOGGER.warning("flow_collector: flush error: %s", str(exc))

    async def _periodic_flush(self):
        """Flush buffer periodically (every 10 seconds)."""
        while True:
            await asyncio.sleep(10)
            await self._flush_buffer()

    def connection_lost(self, exc):
        if self._flush_task:
            self._flush_task.cancel()
        LOGGER.info("flow_collector: UDP listener stopped")


# ═════════════════════════════════════════════════════════════════════════════
# Exporter Cache & Telemetry
# ═════════════════════════════════════════════════════════════════════════════


async def refresh_exporter_cache() -> int:
    """Reload _exporter_cache from the hosts table.

    Called at collector startup and from host CRUD paths so the in-memory
    map stays consistent with inventory without per-packet DB lookups.
    Returns the number of entries loaded.
    """
    async with _exporter_cache_lock:
        try:
            mapping = await db.get_exporter_host_map()
        except Exception as exc:
            LOGGER.warning("flow_collector: exporter cache refresh failed: %s", type(exc).__name__)
            return len(_exporter_cache)
        _exporter_cache.clear()
        _exporter_cache.update(mapping)
        return len(_exporter_cache)


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
    await refresh_exporter_cache()
    try:
        if old_ip and old_ip != new_ip:
            await db.update_flow_exporter_host_id(old_ip, None)
        if new_ip and host_id is not None:
            await db.update_flow_exporter_host_id(new_ip, host_id)
    except Exception as exc:
        LOGGER.warning("flow_collector: exporter host_id sync failed: %s", type(exc).__name__)


async def _record_exporter_packet(
    exporter_ip: str,
    flow_type: str,
    host_id: int | None,
    last_record_at: str | None,
    sampling_rate: int = 0,
) -> None:
    """Persist per-exporter packet telemetry. Best-effort: never raises."""
    try:
        await db.upsert_flow_exporter(
            exporter_ip=exporter_ip,
            flow_type=flow_type,
            host_id=host_id,
            packets_delta=1,
            sampling_rate=sampling_rate,
            last_record_at=last_record_at,
        )
    except Exception as exc:
        LOGGER.debug("flow_collector: exporter upsert failed for %s: %s",
                     exporter_ip, type(exc).__name__)


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
            local_addr=("0.0.0.0", port),
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
                local_addr=("0.0.0.0", sflow_port),
            )
            FLOW_COLLECTOR_CONFIG["sflow_port"] = sflow_port
            LOGGER.info("flow_collector: sFlow listener started on UDP port %d", sflow_port)
        except Exception as exc:
            LOGGER.warning(
                "flow_collector: sFlow listener on port %d failed (continuing without it): %s",
                sflow_port, str(exc),
            )
            _sflow_transport = None
            _sflow_protocol = None

    return True


async def stop_flow_collector() -> bool:
    """Stop the UDP flow collector (both NetFlow and sFlow sockets)."""
    global _flow_transport, _flow_protocol, _sflow_transport, _sflow_protocol
    if _flow_transport is None and _sflow_transport is None:
        return False

    if _sflow_transport is not None:
        try:
            if _sflow_protocol:
                await _sflow_protocol._flush_buffer()
            _sflow_transport.close()
        except Exception as exc:
            LOGGER.debug("flow_collector: sFlow transport close failed: %s", exc)
        _sflow_transport = None
        _sflow_protocol = None

    if _flow_transport is not None:
        try:
            if _flow_protocol:
                await _flow_protocol._flush_buffer()
            _flow_transport.close()
        except Exception as exc:
            LOGGER.debug("flow_collector: NetFlow transport close failed: %s", exc)
        _flow_transport = None
        _flow_protocol = None

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
    """Aggregate raw flow records into hourly summaries."""
    now = datetime.now(UTC)
    period_end = now.replace(minute=0, second=0, microsecond=0)
    period_start = period_end - timedelta(hours=1)

    # Top talkers
    top_src = await db.get_flow_top_talkers(hours=1, direction="src", limit=50)
    top_dst = await db.get_flow_top_talkers(hours=1, direction="dst", limit=50)
    top_apps = await db.get_flow_top_applications(hours=1, limit=50)
    top_convos = await db.get_flow_top_conversations(hours=1, limit=50)

    for summary_type, data in [
        ("top_src", top_src), ("top_dst", top_dst),
        ("top_applications", top_apps), ("top_conversations", top_convos),
    ]:
        if data:
            await db.create_flow_summary(
                host_id=None,
                summary_type=summary_type,
                time_window="hourly",
                period_start=period_start.isoformat(),
                period_end=period_end.isoformat(),
                data_json=json.dumps(data),
            )

    # Cleanup old raw records
    retention_hours = FLOW_COLLECTOR_CONFIG.get("retention_hours", 48)
    cleaned = await db.cleanup_old_flow_records(retention_hours)
    if cleaned > 0:
        LOGGER.info("flow_collector: cleaned up %d old flow records", cleaned)


# ═════════════════════════════════════════════════════════════════════════════
# API Endpoints
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/api/flows/top-talkers")
async def api_top_talkers(
    host_id: int | None = Query(None),
    hours: int = Query(1, ge=1, le=168),
    direction: str = Query("src"),
    limit: int = Query(20, ge=1, le=100),
):
    results = await db.get_flow_top_talkers(host_id, hours, direction, limit)
    for r in results:
        r["protocol_name"] = ""  # flows are aggregated, no single protocol
    return results


@router.get("/api/flows/top-applications")
async def api_top_applications(
    host_id: int | None = Query(None),
    hours: int = Query(1, ge=1, le=168),
    limit: int = Query(20, ge=1, le=100),
):
    results = await db.get_flow_top_applications(host_id, hours, limit)
    for r in results:
        port = r.get("port", 0)
        proto = r.get("protocol", 0)
        r["service_name"] = PORT_SERVICES.get(port, f"port-{port}")
        r["protocol_name"] = PROTOCOL_NAMES.get(proto, f"proto-{proto}")
    return results


@router.get("/api/flows/top-conversations")
async def api_top_conversations(
    host_id: int | None = Query(None),
    hours: int = Query(1, ge=1, le=168),
    limit: int = Query(20, ge=1, le=100),
):
    return await db.get_flow_top_conversations(host_id, hours, limit)


@router.get("/api/flows/timeline")
async def api_flow_timeline(
    host_id: int | None = Query(None),
    hours: int = Query(6, ge=1, le=168),
    bucket_minutes: int = Query(5, ge=1, le=60),
):
    return await db.get_flow_timeline(host_id, hours, bucket_minutes)


@router.get("/api/flows/status")
async def api_flow_status():
    return {
        "enabled": FLOW_COLLECTOR_CONFIG.get("enabled", False),
        "netflow_port": FLOW_COLLECTOR_CONFIG.get("netflow_port", 2055),
        "sflow_port": FLOW_COLLECTOR_CONFIG.get("sflow_port", 6343),
        "running": _flow_transport is not None,
        "sflow_running": _sflow_transport is not None,
    }


@router.get("/api/flows/exporters")
async def api_flow_exporters():
    """List devices that have exported flows, with per-protocol packet counters."""
    rows = await db.list_flow_exporters()
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

    listener_change = (
        old_netflow != new_netflow
        or old_sflow != new_sflow
        or old_enabled != new_enabled
    )

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
        "aggregation_interval_seconds": int(
            FLOW_COLLECTOR_CONFIG.get("aggregation_interval_seconds", 3600)
        ),
        "netflow_running": _flow_transport is not None,
        "sflow_running": _sflow_transport is not None,
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
