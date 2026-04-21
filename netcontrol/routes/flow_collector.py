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
}

_flow_transport = None
_flow_protocol = None


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
# UDP Flow Receiver Protocol
# ═════════════════════════════════════════════════════════════════════════════

class _FlowCollectorProtocol(asyncio.DatagramProtocol):
    """UDP listener that receives NetFlow/IPFIX/sFlow packets."""

    def __init__(self):
        self._buffer: list[tuple] = []
        self._flush_task: asyncio.Task | None = None

    def connection_made(self, transport):
        self.transport = transport
        self._flush_task = asyncio.create_task(self._periodic_flush())
        LOGGER.info("flow_collector: UDP listener started")

    def datagram_received(self, data: bytes, addr: tuple):
        if len(data) < 4:
            return

        version = struct.unpack("!H", data[:2])[0]

        if version == 5:
            records = parse_netflow_v5(data, addr)
        elif version in (9, 10):
            records = parse_netflow_v9(data, addr)
        else:
            return  # Unknown format

        # Resolve exporter to host_id
        exporter_ip = addr[0]

        for rec in records:
            self._buffer.append((
                rec["exporter_ip"], None, rec["flow_type"],
                rec["src_ip"], rec["dst_ip"], rec["src_port"], rec["dst_port"],
                rec["protocol"], rec["bytes"], rec["packets"],
                rec["src_as"], rec["dst_as"], rec["input_if"], rec["output_if"],
                rec["tos"], rec["tcp_flags"], rec["start_time"], rec["end_time"],
            ))

        if len(self._buffer) >= FLOW_COLLECTOR_CONFIG.get("batch_size", 100):
            asyncio.create_task(self._flush_buffer())

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
# Collector Lifecycle
# ═════════════════════════════════════════════════════════════════════════════


async def start_flow_collector(port: int = 2055) -> bool:
    """Start the UDP flow collector on the specified port."""
    global _flow_transport, _flow_protocol
    if _flow_transport is not None:
        return False  # Already running

    try:
        loop = asyncio.get_event_loop()
        _flow_transport, _flow_protocol = await loop.create_datagram_endpoint(
            lambda: _FlowCollectorProtocol(),
            local_addr=("0.0.0.0", port),
        )
        FLOW_COLLECTOR_CONFIG["enabled"] = True
        LOGGER.info("flow_collector: started on UDP port %d", port)
        return True
    except Exception as exc:
        LOGGER.error("flow_collector: failed to start on port %d: %s", port, str(exc))
        return False


async def stop_flow_collector() -> bool:
    """Stop the UDP flow collector."""
    global _flow_transport, _flow_protocol
    if _flow_transport is None:
        return False
    try:
        if _flow_protocol:
            await _flow_protocol._flush_buffer()
        _flow_transport.close()
    except Exception:
        pass
    _flow_transport = None
    _flow_protocol = None
    FLOW_COLLECTOR_CONFIG["enabled"] = False
    LOGGER.info("flow_collector: stopped")
    return True


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
    limit: int = Query(20, le=100),
):
    results = await db.get_flow_top_talkers(host_id, hours, direction, limit)
    for r in results:
        r["protocol_name"] = ""  # flows are aggregated, no single protocol
    return results


@router.get("/api/flows/top-applications")
async def api_top_applications(
    host_id: int | None = Query(None),
    hours: int = Query(1, ge=1, le=168),
    limit: int = Query(20, le=100),
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
    limit: int = Query(20, le=100),
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
        "running": _flow_transport is not None,
    }


@router.post("/api/admin/flows/start")
async def api_start_collector(port: int = Query(2055, ge=1, le=65535)):
    ok = await start_flow_collector(port)
    if not ok:
        raise HTTPException(400, "Collector already running or port unavailable")
    return {"started": True, "port": port}


@router.post("/api/admin/flows/stop")
async def api_stop_collector():
    ok = await stop_flow_collector()
    if not ok:
        raise HTTPException(400, "Collector not running")
    return {"stopped": True}
