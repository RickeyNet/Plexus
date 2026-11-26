"""Tests for the NetFlow/sFlow/IPFIX collector.

Covers:
  - NetFlow v5 hex-encoded packet -> parser round-trip
  - NetFlow v9 template flowset followed by a data flowset
  - sFlow v5 flow_sample with a raw Ethernet/IPv4/UDP packet header
  - DB batch insert + top-talker query
  - Collector lifecycle start/stop idempotency (binds to an ephemeral port
    so the tests don't fight 2055 in CI)
  - Exporter cache refresh hooks (on_host_changed) keep the in-memory
    map in sync with inventory CRUD without per-packet DB lookups
"""

from __future__ import annotations

import asyncio
import socket
import struct
import threading

import pytest
import routes.database as db_module
from netcontrol import listener_sources
from netcontrol.routes import flow_collector

# ── shared fixture helpers ──────────────────────────────────────────────────


async def receive(proto: flow_collector._FlowCollectorProtocol, data: bytes, *addrs: tuple) -> None:
    """Hand ``data`` to the listener once per source address, then wait until
    the drain worker has decoded everything queued (no fixed sleep)."""
    for addr in addrs:
        proto.datagram_received(data, addr)
    await proto.drain()


async def _init_db():
    """Run init_db() on the per-test database."""
    await db_module.init_db()


async def _add_host(hostname: str = "exporter1", ip: str = "10.1.2.3") -> int:
    """Insert one host row + its inventory group; return host_id."""
    db = await db_module.get_db()
    try:
        cur = await db.execute(
            "INSERT OR IGNORE INTO inventory_groups (name) VALUES (?)",
            ("default",),
        )
        if cur.lastrowid:
            gid = cur.lastrowid
        else:
            cur2 = await db.execute("SELECT id FROM inventory_groups WHERE name = ?", ("default",))
            gid = (await cur2.fetchone())[0]
        cur = await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address) VALUES (?, ?, ?)",
            (gid, hostname, ip),
        )
        await db.commit()
        return cur.lastrowid
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# NetFlow v5 parser
# ═════════════════════════════════════════════════════════════════════════════


def _build_nf5_packet(records: list[dict]) -> bytes:
    """Hand-build a NetFlow v5 datagram so the test owns every byte.

    Header (24 bytes): version=5, count, sys_uptime, unix_secs, unix_nsecs,
                       flow_sequence, engine_type, engine_id, sampling.
    Record (48 bytes): src, dst, nexthop, in_if, out_if, packets, octets,
                       first, last, sport, dport, pad, tcp_flags, proto,
                       tos, src_as, dst_as, src_mask, dst_mask, pad.
    """
    header = struct.pack(
        "!HHIIIIBBh",
        5,  # version
        len(records),  # count
        1_000_000,  # sys_uptime ms
        1_700_000_000,  # unix_secs
        0,  # unix_nsecs
        0,  # flow_sequence
        0,
        0,  # engine_type, engine_id
        0,  # sampling
    )
    body = b""
    for r in records:
        body += struct.pack(
            "!IIIHHIIIIHHBBBBHHBBH",
            struct.unpack("!I", socket.inet_aton(r["src_ip"]))[0],
            struct.unpack("!I", socket.inet_aton(r["dst_ip"]))[0],
            0,  # nexthop
            r.get("input_if", 1),
            r.get("output_if", 2),
            r.get("packets", 1),
            r.get("bytes", 100),
            900_000,  # first switched (ms)
            999_000,  # last switched (ms)
            r.get("src_port", 12345),
            r.get("dst_port", 80),
            0,  # pad1
            r.get("tcp_flags", 0),
            r.get("protocol", 6),
            0,  # tos
            0,  # src_as
            0,  # dst_as
            0,  # src_mask
            0,  # dst_mask
            0,  # pad2
        )
    return header + body


def test_parse_netflow_v5_roundtrip():
    pkt = _build_nf5_packet(
        [
            {
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 5555,
                "dst_port": 443,
                "protocol": 6,
                "bytes": 2048,
                "packets": 4,
            },
            {
                "src_ip": "192.168.1.10",
                "dst_ip": "8.8.8.8",
                "src_port": 33333,
                "dst_port": 53,
                "protocol": 17,
                "bytes": 128,
                "packets": 1,
            },
        ]
    )

    recs = flow_collector.parse_netflow_v5(pkt, ("203.0.113.1", 2055))

    assert len(recs) == 2
    assert recs[0]["exporter_ip"] == "203.0.113.1"
    assert recs[0]["flow_type"] == "netflow_v5"
    assert recs[0]["src_ip"] == "10.0.0.1"
    assert recs[0]["dst_ip"] == "10.0.0.2"
    assert recs[0]["src_port"] == 5555
    assert recs[0]["dst_port"] == 443
    assert recs[0]["protocol"] == 6
    assert recs[0]["bytes"] == 2048
    assert recs[0]["packets"] == 4

    assert recs[1]["src_ip"] == "192.168.1.10"
    assert recs[1]["dst_port"] == 53
    assert recs[1]["protocol"] == 17


def test_parse_netflow_v5_rejects_wrong_version():
    # version=9 in a v5 parser must return no records, not crash.
    junk = struct.pack("!HHIIIIBBh", 9, 0, 0, 0, 0, 0, 0, 0, 0)
    assert flow_collector.parse_netflow_v5(junk, ("1.2.3.4", 2055)) == []


def test_parse_netflow_v5_too_short():
    assert flow_collector.parse_netflow_v5(b"\x00" * 10, ("1.2.3.4", 2055)) == []


# ═════════════════════════════════════════════════════════════════════════════
# NetFlow v9 parser (template + data)
# ═════════════════════════════════════════════════════════════════════════════


def _build_nf9_template_and_data() -> bytes:
    """Build a v9 packet with one Template flowset and one matching Data flowset.

    Template id 256 with these fields (type, length):
        8  src_ip      4
        12 dst_ip      4
        7  src_port    2
        11 dst_port    2
        4  protocol    1
        1  in_bytes    4
        2  in_pkts     4
    Total record length = 21 bytes per data record.
    """
    # ─ v9 header (20 bytes)
    header = struct.pack(
        "!HHIIII",
        9,  # version
        2,  # count of flowsets (template + data)
        12_345,  # sys_uptime
        1_700_000_000,  # unix_secs
        0,  # sequence_number
        1,  # source_id
    )

    # ─ Template flowset (id=0)
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4)]
    tpl_body = struct.pack("!HH", 256, len(fields))  # tpl_id, field_count
    for f_type, f_len in fields:
        tpl_body += struct.pack("!HH", f_type, f_len)
    tpl_flowset_len = 4 + len(tpl_body)
    if tpl_flowset_len % 4:  # pad to 4-byte boundary
        tpl_body += b"\x00" * (4 - tpl_flowset_len % 4)
        tpl_flowset_len = 4 + len(tpl_body)
    tpl_flowset = struct.pack("!HH", 0, tpl_flowset_len) + tpl_body

    # ─ Data flowset (id=template id)
    rec1 = (
        socket.inet_aton("10.0.0.1")
        + socket.inet_aton("10.0.0.2")
        + struct.pack("!H", 1111)  # src_port
        + struct.pack("!H", 443)  # dst_port
        + struct.pack("!B", 6)  # protocol = TCP
        + struct.pack("!I", 5000)  # in_bytes
        + struct.pack("!I", 7)  # in_pkts
    )
    rec2 = (
        socket.inet_aton("10.0.0.3")
        + socket.inet_aton("8.8.8.8")
        + struct.pack("!H", 2222)
        + struct.pack("!H", 53)
        + struct.pack("!B", 17)  # UDP
        + struct.pack("!I", 256)
        + struct.pack("!I", 2)
    )
    data_body = rec1 + rec2
    data_flowset_len = 4 + len(data_body)
    if data_flowset_len % 4:
        data_body += b"\x00" * (4 - data_flowset_len % 4)
        data_flowset_len = 4 + len(data_body)
    data_flowset = struct.pack("!HH", 256, data_flowset_len) + data_body

    return header + tpl_flowset + data_flowset


def test_parse_netflow_v9_template_then_data():
    # Reset the template cache so prior tests can't leak in.
    flow_collector._nf9_templates.clear()

    pkt = _build_nf9_template_and_data()
    recs = flow_collector.parse_netflow_v9(pkt, ("198.51.100.7", 2055))

    assert len(recs) == 2
    assert all(r["flow_type"] == "netflow_v9" for r in recs)
    assert all(r["exporter_ip"] == "198.51.100.7" for r in recs)

    assert recs[0]["src_ip"] == "10.0.0.1"
    assert recs[0]["dst_ip"] == "10.0.0.2"
    assert recs[0]["src_port"] == 1111
    assert recs[0]["dst_port"] == 443
    assert recs[0]["protocol"] == 6
    assert recs[0]["bytes"] == 5000
    assert recs[0]["packets"] == 7

    assert recs[1]["src_ip"] == "10.0.0.3"
    assert recs[1]["dst_port"] == 53
    assert recs[1]["protocol"] == 17


def test_parse_netflow_v9_data_without_template_is_ignored():
    # Data flowset arriving before its template should be skipped silently,
    # not raise. This is the common case after a collector restart.
    flow_collector._nf9_templates.clear()

    header = struct.pack("!HHIIII", 9, 1, 0, 1_700_000_000, 0, 1)
    bogus_data = struct.pack("!HH", 999, 8) + b"\x00\x00\x00\x00"
    pkt = header + bogus_data

    assert flow_collector.parse_netflow_v9(pkt, ("198.51.100.8", 2055)) == []


# ═════════════════════════════════════════════════════════════════════════════
# sFlow v5 parser
# ═════════════════════════════════════════════════════════════════════════════


def _build_sflow_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, sampling_rate: int = 1024) -> bytes:
    """Build an sFlow v5 datagram carrying one flow_sample with one
    raw_packet_header (Ethernet/IPv4/UDP).

    Layout:
        v5 header (28 bytes):
            u32 version=5, u32 addr_type=1, 4-byte agent_ipv4,
            u32 sub_agent, u32 seq, u32 uptime, u32 num_samples
        sample header (8 bytes):
            u32 sample_type=1 (flow_sample), u32 sample_length
        flow_sample body (32 bytes):
            u32 seq, u32 source_id, u32 sampling_rate, u32 sample_pool,
            u32 drops, u32 input, u32 output, u32 flow_records_count
        flow_record (variable):
            u32 data_format=1 (raw_packet_header), u32 flow_data_length
            u32 protocol_kind=1 (Ethernet), u32 frame_length,
            u32 stripped, u32 header_length, bytes header (padded to 4)
    """
    # Build the Ethernet + IPv4 + UDP header that sFlow will sample.
    eth = (
        b"\xaa\xbb\xcc\xdd\xee\xff"  # dst mac
        + b"\x11\x22\x33\x44\x55\x66"  # src mac
        + b"\x08\x00"  # ethertype = IPv4
    )
    # IPv4: ihl=5, total_length=28 (20 IP + 8 UDP), proto=17 (UDP)
    ipv4 = (
        b"\x45\x00"  # version=4, ihl=5, dscp=0
        + struct.pack("!H", 20 + 8)  # total_length
        + b"\x00\x00\x00\x00"  # id+flags+frag
        + b"\x40\x11"  # ttl=64, proto=UDP
        + b"\x00\x00"  # checksum (ignored by parser)
        + socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
    )
    udp = (
        struct.pack("!H", src_port)
        + struct.pack("!H", dst_port)
        + b"\x00\x08"  # udp length
        + b"\x00\x00"  # udp checksum
    )
    header_bytes = eth + ipv4 + udp  # 14 + 20 + 8 = 42 bytes
    header_len = len(header_bytes)
    # XDR opaque pads to a 4-byte boundary.
    pad = (-header_len) % 4
    header_padded = header_bytes + b"\x00" * pad

    raw_pkt_record_body = (
        struct.pack("!I", 1)  # protocol_kind = Ethernet
        + struct.pack("!I", 60)  # original frame length on the wire
        + struct.pack("!I", 0)  # stripped
        + struct.pack("!I", header_len)  # header_length
        + header_padded
    )
    flow_record = (
        struct.pack("!I", 1)  # data_format = raw_packet_header
        + struct.pack("!I", len(raw_pkt_record_body))
        + raw_pkt_record_body
    )

    flow_sample_body = (
        struct.pack(
            "!IIIIIIII",
            99,  # seq
            0,  # source_id (type<<24 | index)
            sampling_rate,
            0,  # sample_pool
            0,  # drops
            1,  # input if
            2,  # output if
            1,  # flow_records_count
        )
        + flow_record
    )

    sample = (
        struct.pack("!I", 1)  # sample_type = flow_sample
        + struct.pack("!I", len(flow_sample_body))
        + flow_sample_body
    )

    datagram_header = (
        struct.pack("!I", 5)  # version
        + struct.pack("!I", 1)  # agent_addr_type IPv4
        + socket.inet_aton("10.0.0.99")  # agent address
        + struct.pack("!I", 0)  # sub_agent_id
        + struct.pack("!I", 1)  # sequence_number
        + struct.pack("!I", 0)  # uptime_ms
        + struct.pack("!I", 1)  # num_samples
    )
    return datagram_header + sample


def test_parse_sflow_flow_sample_extracts_udp_5tuple():
    pkt = _build_sflow_packet(
        src_ip="10.5.5.1",
        dst_ip="10.5.5.2",
        src_port=44444,
        dst_port=53,
        sampling_rate=512,
    )

    recs = flow_collector.parse_sflow(pkt, ("198.51.100.20", 6343))

    assert len(recs) == 1
    rec = recs[0]
    assert rec["flow_type"] == "sflow_v5"
    assert rec["exporter_ip"] == "198.51.100.20"
    assert rec["src_ip"] == "10.5.5.1"
    assert rec["dst_ip"] == "10.5.5.2"
    assert rec["src_port"] == 44444
    assert rec["dst_port"] == 53
    assert rec["protocol"] == 17  # UDP
    # bytes_estimate = frame_length * sampling_rate
    assert rec["bytes"] == 60 * 512
    assert rec["packets"] == 512

    # And the sampling rate should have been captured for the API surface.
    assert flow_collector._latest_sflow_sampling_rate("198.51.100.20") == 512


def test_parse_sflow_rejects_wrong_version():
    bad = struct.pack("!I", 4) + b"\x00" * 32
    assert flow_collector.parse_sflow(bad, ("1.2.3.4", 6343)) == []


# ═════════════════════════════════════════════════════════════════════════════
# DB batch insert + top-talker query
# ═════════════════════════════════════════════════════════════════════════════


async def test_create_flow_records_batch_and_top_talkers():
    await _init_db()
    host_id = await _add_host(ip="10.10.10.1")

    rows = [
        # 10.0.0.1 wins on src_ip total bytes (1000 + 2000 = 3000).
        (
            "10.10.10.1",
            host_id,
            "netflow_v5",
            "10.0.0.1",
            "8.8.8.8",
            1111,
            53,
            17,
            1000,
            2,
            0,
            0,
            1,
            2,
            0,
            0,
            "2026-05-12T00:00:00+00:00",
            "2026-05-12T00:00:01+00:00",
        ),
        (
            "10.10.10.1",
            host_id,
            "netflow_v5",
            "10.0.0.1",
            "1.1.1.1",
            2222,
            443,
            6,
            2000,
            4,
            0,
            0,
            1,
            2,
            0,
            0,
            "2026-05-12T00:00:02+00:00",
            "2026-05-12T00:00:03+00:00",
        ),
        # 10.0.0.2 has fewer bytes - should sort second.
        (
            "10.10.10.1",
            host_id,
            "netflow_v5",
            "10.0.0.2",
            "8.8.8.8",
            3333,
            53,
            17,
            500,
            1,
            0,
            0,
            1,
            2,
            0,
            0,
            "2026-05-12T00:00:04+00:00",
            "2026-05-12T00:00:05+00:00",
        ),
    ]
    inserted = await db_module.create_flow_records_batch(rows)
    assert inserted == 3

    top_src = await db_module.get_flow_top_talkers(host_id=host_id, hours=1, direction="src", limit=10)
    # 10.0.0.1 with 3000 bytes / 2 flows; 10.0.0.2 with 500 bytes / 1 flow.
    assert len(top_src) == 2
    assert top_src[0]["ip"] == "10.0.0.1"
    assert top_src[0]["total_bytes"] == 3000
    assert top_src[0]["flow_count"] == 2
    assert top_src[1]["ip"] == "10.0.0.2"
    assert top_src[1]["total_bytes"] == 500

    # And the destination view: 8.8.8.8 should win since it's hit twice.
    top_dst = await db_module.get_flow_top_talkers(host_id=host_id, hours=1, direction="dst", limit=10)
    dst_ips = [r["ip"] for r in top_dst]
    assert "8.8.8.8" in dst_ips
    # 8.8.8.8 = 1000 + 500 = 1500 vs 1.1.1.1 = 2000, so 1.1.1.1 wins.
    assert top_dst[0]["ip"] == "1.1.1.1"


async def test_create_flow_records_batch_empty_is_noop():
    await _init_db()
    assert await db_module.create_flow_records_batch([]) == 0


# ═════════════════════════════════════════════════════════════════════════════
# Collector lifecycle (start/stop idempotency)
# ═════════════════════════════════════════════════════════════════════════════


def _pick_free_udp_port() -> int:
    """Bind to port 0 to let the OS pick a free UDP port, then release it.

    Race-prone in theory; in practice the asyncio rebind happens immediately
    and the test process is the only thing reaching for the port.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


async def test_collector_start_stop_idempotent():
    await _init_db()

    netflow_port = _pick_free_udp_port()
    sflow_port = _pick_free_udp_port()

    try:
        ok = await flow_collector.start_flow_collector(netflow_port, sflow_port)
        assert ok is True
        assert flow_collector._flow_transport is not None
        assert flow_collector._sflow_transport is not None
        assert flow_collector.FLOW_COLLECTOR_CONFIG["enabled"] is True
        assert flow_collector.FLOW_COLLECTOR_CONFIG["netflow_port"] == netflow_port
        assert flow_collector.FLOW_COLLECTOR_CONFIG["sflow_port"] == sflow_port

        # Second start while already running should be a no-op (False), not
        # an EADDRINUSE crash.
        again = await flow_collector.start_flow_collector(netflow_port, sflow_port)
        assert again is False

        protocols = (flow_collector._flow_protocol, flow_collector._sflow_protocol)
        stopped = await flow_collector.stop_flow_collector()
        assert stopped is True
        for proto in protocols:
            assert proto._drain_task.done() and proto._flush_task.done() and not proto._bg_tasks
        assert flow_collector._flow_transport is None
        assert flow_collector._sflow_transport is None
        assert flow_collector.FLOW_COLLECTOR_CONFIG["enabled"] is False

        # Second stop while already stopped should also be a no-op.
        stopped_again = await flow_collector.stop_flow_collector()
        assert stopped_again is False
    finally:
        # Belt-and-braces: never leak a socket out of the test.
        if flow_collector._flow_transport is not None or flow_collector._sflow_transport is not None:
            await flow_collector.stop_flow_collector()


# ═════════════════════════════════════════════════════════════════════════════
# Decode queue: datagrams are decoded off the event loop
# ═════════════════════════════════════════════════════════════════════════════

EXPORTER_IP = "192.0.2.60"
EXPORTER_HOST_ID = 4242
NF5_PACKET = _build_nf5_packet(
    [
        {"src_ip": "198.51.100.1", "dst_ip": "203.0.113.9", "src_port": 5555, "dst_port": 443, "bytes": 2048},
        {"src_ip": "198.51.100.2", "dst_ip": "203.0.113.9", "dst_port": 53, "protocol": 17, "packets": 3},
    ]
)


@pytest.fixture
def flushed(monkeypatch):
    """An inventory of one exporter host, fresh listener counters and no
    pending exporter stats; the rows the collector flushes are collected
    here instead of written to the database."""
    saved = dict(listener_sources.INVENTORY_ADDRESSES)
    listener_sources.INVENTORY_ADDRESSES.clear()
    listener_sources.INVENTORY_ADDRESSES[EXPORTER_IP] = EXPORTER_HOST_ID
    monkeypatch.setattr(listener_sources, "_inventory_loaded_at", float("inf"))
    for guard in listener_sources.GUARDS.values():
        guard.reset()
    flow_collector._pending_exporter_stats.clear()
    rows: list[tuple] = []

    async def fake_batch(batch):
        rows.extend(batch)
        return len(batch)

    monkeypatch.setattr(flow_collector.db, "create_flow_records_batch", fake_batch)
    yield rows
    flow_collector._pending_exporter_stats.clear()
    listener_sources.INVENTORY_ADDRESSES.clear()
    listener_sources.INVENTORY_ADDRESSES.update(saved)
    for guard in listener_sources.GUARDS.values():
        guard.reset()


@pytest.fixture
async def proto(flushed):
    """A NetFlow listener with its drain worker running (no socket)."""
    p = flow_collector._FlowCollectorProtocol(mode="netflow")
    p.connection_made(None)
    yield p
    await p.close()


async def test_datagrams_are_decoded_on_a_thread_other_than_the_loop(proto, monkeypatch):
    real = flow_collector.parse_netflow_v5
    threads: list[int] = []

    def spy(data, addr):
        threads.append(threading.get_ident())
        return real(data, addr)

    monkeypatch.setattr(flow_collector, "parse_netflow_v5", spy)
    proto.datagram_received(NF5_PACKET, (EXPORTER_IP, 2055))
    assert threads == []  # queued, not decoded inline
    await proto.drain()
    assert len(threads) == 1 and threads[0] != threading.get_ident()
    assert len(proto._buffer) == 2


async def test_a_full_queue_drops_and_counts(proto, monkeypatch):
    monkeypatch.setattr(flow_collector, "FLOW_DECODE_QUEUE_MAX", 3)
    before = flow_collector._drop_counters()["dropped_queue"]
    # No await between datagrams: the worker cannot take any off the queue.
    await receive(proto, NF5_PACKET, *[(EXPORTER_IP, 2055)] * 5)
    assert flow_collector._drop_counters()["dropped_queue"] == before + 2
    assert (await flow_collector.api_flow_status())["dropped_queue"] == before + 2
    assert flow_collector._config_snapshot()["dropped_queue"] == before + 2
    assert len(proto._buffer) == 3 * 2


async def test_the_queue_is_bounded_in_bytes(proto, monkeypatch):
    monkeypatch.setattr(flow_collector, "FLOW_DECODE_QUEUE_MAX_BYTES", 2 * len(NF5_PACKET))
    before = flow_collector._drop_counters()["dropped_queue"]
    await receive(proto, NF5_PACKET, *[(EXPORTER_IP, 2055)] * 3)
    assert flow_collector._drop_counters()["dropped_queue"] == before + 1
    assert len(proto._buffer) == 2 * 2


async def test_a_datagram_the_parser_fails_on_does_not_stop_the_others(proto, monkeypatch):
    real = flow_collector.parse_netflow_v5
    calls = 0

    def flaky(data, addr):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError("bad datagram")
        return real(data, addr)

    monkeypatch.setattr(flow_collector, "parse_netflow_v5", flaky)
    await receive(proto, NF5_PACKET, *[(EXPORTER_IP, 2055)] * 3)
    assert calls == 3
    assert len(proto._buffer) == 2 * 2
    # The worker is still alive and decodes later datagrams.
    await receive(proto, NF5_PACKET, (EXPORTER_IP, 2055))
    assert len(proto._buffer) == 3 * 2
    assert not proto._drain_task.done()


async def test_rows_and_exporter_stats_of_a_v5_packet(flushed):
    p = flow_collector._FlowCollectorProtocol(mode="netflow")
    p.connection_made(None)
    await receive(p, NF5_PACKET, (EXPORTER_IP, 2055))
    # (exporter, host, type, src, dst, sport, dport, proto, bytes, packets,
    # src_as, dst_as, in_if, out_if, tos, tcp_flags, start, end): the times
    # are unix_secs 1_700_000_000 less (uptime - first) and (uptime - last).
    start, end = "2023-11-14T22:11:40+00:00", "2023-11-14T22:13:19+00:00"
    head = (EXPORTER_IP, EXPORTER_HOST_ID, "netflow_v5")
    expected = [
        (*head, "198.51.100.1", "203.0.113.9", 5555, 443, 6, 2048, 1, 0, 0, 1, 2, 0, 0, start, end),
        (*head, "198.51.100.2", "203.0.113.9", 12345, 53, 17, 100, 3, 0, 0, 1, 2, 0, 0, start, end),
    ]
    assert p._buffer == expected
    assert dict(flow_collector._pending_exporter_stats) == {
        (EXPORTER_IP, "netflow_v5"): {
            "host_id": EXPORTER_HOST_ID,
            "packets": 1,
            "sampling_rate": 0,
            "last_record_at": "2023-11-14T22:13:19+00:00",
        }
    }
    await p.close()
    assert flushed == expected


async def test_sflow_packets_carry_their_sampling_rate(flushed):
    p = flow_collector._FlowCollectorProtocol(mode="sflow")
    p.connection_made(None)
    await receive(p, _build_sflow_packet("198.51.100.5", "203.0.113.5", 40000, 53, 2048), (EXPORTER_IP, 6343))
    assert flow_collector._pending_exporter_stats[(EXPORTER_IP, "sflow_v5")]["sampling_rate"] == 2048
    assert len(p._buffer) == 1
    await p.close()


async def test_close_decodes_what_is_queued_and_leaves_no_task(flushed):
    p = flow_collector._FlowCollectorProtocol(mode="netflow")
    p.connection_made(None)
    for _ in range(3):
        p.datagram_received(NF5_PACKET, (EXPORTER_IP, 2055))
    await p.close()
    assert len(flushed) == 3 * 2
    assert p._buffer == []
    assert p._drain_task.done() and p._flush_task.done() and not p._bg_tasks
    # connection_lost after close (the transport's callback) starts nothing.
    p.connection_lost(None)
    await p.close()
    assert len(flushed) == 3 * 2


async def test_connection_lost_alone_drains_and_stops_the_worker(flushed):
    p = flow_collector._FlowCollectorProtocol(mode="netflow")
    p.connection_made(None)
    p.datagram_received(NF5_PACKET, (EXPORTER_IP, 2055))
    p.connection_lost(OSError("socket gone"))
    await p.close()
    assert len(flushed) == 2
    assert p._drain_task.done()


async def test_stop_flow_collector_decodes_queued_datagrams(flushed):
    await _init_db()
    netflow_port = _pick_free_udp_port()
    try:
        assert await flow_collector.start_flow_collector(netflow_port)
        listener_sources.INVENTORY_ADDRESSES[EXPORTER_IP] = EXPORTER_HOST_ID
        p = flow_collector._flow_protocol
        p.datagram_received(NF5_PACKET, (EXPORTER_IP, 2055))
        assert await flow_collector.stop_flow_collector()
    finally:
        if flow_collector._flow_transport is not None:
            await flow_collector.stop_flow_collector()
    assert [row[3] for row in flushed] == ["198.51.100.1", "198.51.100.2"]
    leftover = [
        t
        for t in asyncio.all_tasks()
        if t is not asyncio.current_task() and getattr(t.get_coro(), "__qualname__", "").startswith("_FlowCollector")
    ]
    assert leftover == []


# ═════════════════════════════════════════════════════════════════════════════
# Exporter cache refresh on host CRUD
# ═════════════════════════════════════════════════════════════════════════════


async def test_refresh_exporter_cache_loads_inventory():
    await _init_db()
    flow_collector._exporter_cache.clear()

    h1 = await _add_host(hostname="sw-a", ip="10.20.30.1")
    h2 = await _add_host(hostname="sw-b", ip="10.20.30.2")

    loaded = await flow_collector.refresh_exporter_cache()
    assert loaded == 2
    assert flow_collector._exporter_cache.get("10.20.30.1") == h1
    assert flow_collector._exporter_cache.get("10.20.30.2") == h2


async def test_on_host_changed_updates_cache_and_exporter_rows():
    await _init_db()
    flow_collector._exporter_cache.clear()

    # Seed an exporter row for an IP that *will* later be associated
    # with a new inventory host.
    await db_module.upsert_flow_exporter(
        exporter_ip="10.99.0.1",
        flow_type="netflow_v5",
        host_id=None,
        packets_delta=1,
    )
    rows = await db_module.list_flow_exporters()
    assert rows[0]["host_id"] is None

    # Add the host and notify the collector - both the cache and the
    # exporter row should pick up the new host_id without a restart.
    host_id = await _add_host(hostname="sw-c", ip="10.99.0.1")
    await flow_collector.on_host_changed(old_ip=None, new_ip="10.99.0.1", host_id=host_id)

    assert flow_collector._exporter_cache.get("10.99.0.1") == host_id

    rows = await db_module.list_flow_exporters()
    assert rows[0]["host_id"] == host_id
    assert rows[0]["hostname"] == "sw-c"

    # Now simulate the host being deleted: old_ip set, new_ip None.
    await flow_collector.on_host_changed(old_ip="10.99.0.1", new_ip=None, host_id=None)
    rows = await db_module.list_flow_exporters()
    assert rows[0]["host_id"] is None


async def test_one_flush_at_a_time_and_nothing_is_left_behind(proto, flushed, monkeypatch):
    monkeypatch.setitem(flow_collector.FLOW_COLLECTOR_CONFIG, "batch_size", 1)
    release = asyncio.Event()
    running = 0
    most = 0

    async def slow_batch(batch):
        nonlocal running, most
        running += 1
        most = max(most, running)
        await release.wait()
        flushed.extend(batch)
        running -= 1
        return len(batch)

    monkeypatch.setattr(flow_collector.db, "create_flow_records_batch", slow_batch)
    # Each datagram's records reach the buffer while the first flush waits.
    for _ in range(4):
        await receive(proto, NF5_PACKET, (EXPORTER_IP, 2055))
    await proto._flush_buffer()  # the periodic flush: returns while one runs
    assert most == 1 and proto._flushing
    release.set()
    await asyncio.gather(*list(proto._bg_tasks))
    assert most == 1 and not proto._flushing
    assert len(flushed) == 4 * 2 and proto._buffer == []


async def test_a_full_buffer_drops_the_newest_records_and_counts_them(proto, flushed, monkeypatch):
    monkeypatch.setattr(flow_collector, "FLOW_BUFFER_MAX", 3)
    monkeypatch.setitem(flow_collector.FLOW_COLLECTOR_CONFIG, "batch_size", 1000)
    before = flow_collector._drop_counters()["dropped_buffer"]
    await receive(proto, NF5_PACKET, *[(EXPORTER_IP, 2055)] * 3)
    assert len(proto._buffer) == 3
    assert flow_collector._drop_counters()["dropped_buffer"] == before + 3
    kept = list(proto._buffer)
    await proto._flush_buffer()
    assert flushed == kept
