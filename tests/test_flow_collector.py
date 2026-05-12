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

import socket
import struct
import pytest

import routes.database as db_module
from netcontrol.routes import flow_collector


# ── shared fixture helpers ──────────────────────────────────────────────────

async def _init_db(tmp_path, monkeypatch) -> str:
    """Point routes.database at a fresh sqlite file and run init_db()."""
    db_path = str(tmp_path / "flow.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    return db_path


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
            cur2 = await db.execute(
                "SELECT id FROM inventory_groups WHERE name = ?", ("default",)
            )
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
        5,                # version
        len(records),     # count
        1_000_000,        # sys_uptime ms
        1_700_000_000,    # unix_secs
        0,                # unix_nsecs
        0,                # flow_sequence
        0, 0,             # engine_type, engine_id
        0,                # sampling
    )
    body = b""
    for r in records:
        body += struct.pack(
            "!IIIHHIIIIHHBBBBHHBBH",
            struct.unpack("!I", socket.inet_aton(r["src_ip"]))[0],
            struct.unpack("!I", socket.inet_aton(r["dst_ip"]))[0],
            0,                          # nexthop
            r.get("input_if", 1),
            r.get("output_if", 2),
            r.get("packets", 1),
            r.get("bytes", 100),
            900_000,                    # first switched (ms)
            999_000,                    # last switched (ms)
            r.get("src_port", 12345),
            r.get("dst_port", 80),
            0,                          # pad1
            r.get("tcp_flags", 0),
            r.get("protocol", 6),
            0,                          # tos
            0,                          # src_as
            0,                          # dst_as
            0,                          # src_mask
            0,                          # dst_mask
            0,                          # pad2
        )
    return header + body


def test_parse_netflow_v5_roundtrip():
    pkt = _build_nf5_packet([
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
         "src_port": 5555, "dst_port": 443, "protocol": 6,
         "bytes": 2048, "packets": 4},
        {"src_ip": "192.168.1.10", "dst_ip": "8.8.8.8",
         "src_port": 33333, "dst_port": 53, "protocol": 17,
         "bytes": 128, "packets": 1},
    ])

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
        9,             # version
        2,             # count of flowsets (template + data)
        12_345,        # sys_uptime
        1_700_000_000, # unix_secs
        0,             # sequence_number
        1,             # source_id
    )

    # ─ Template flowset (id=0)
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4)]
    tpl_body = struct.pack("!HH", 256, len(fields))  # tpl_id, field_count
    for f_type, f_len in fields:
        tpl_body += struct.pack("!HH", f_type, f_len)
    tpl_flowset_len = 4 + len(tpl_body)
    if tpl_flowset_len % 4:                     # pad to 4-byte boundary
        tpl_body += b"\x00" * (4 - tpl_flowset_len % 4)
        tpl_flowset_len = 4 + len(tpl_body)
    tpl_flowset = struct.pack("!HH", 0, tpl_flowset_len) + tpl_body

    # ─ Data flowset (id=template id)
    rec1 = (
        socket.inet_aton("10.0.0.1")
        + socket.inet_aton("10.0.0.2")
        + struct.pack("!H", 1111)        # src_port
        + struct.pack("!H", 443)         # dst_port
        + struct.pack("!B", 6)           # protocol = TCP
        + struct.pack("!I", 5000)        # in_bytes
        + struct.pack("!I", 7)           # in_pkts
    )
    rec2 = (
        socket.inet_aton("10.0.0.3")
        + socket.inet_aton("8.8.8.8")
        + struct.pack("!H", 2222)
        + struct.pack("!H", 53)
        + struct.pack("!B", 17)          # UDP
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


def _build_sflow_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                       sampling_rate: int = 1024) -> bytes:
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
        b"\xaa\xbb\xcc\xdd\xee\xff"          # dst mac
        + b"\x11\x22\x33\x44\x55\x66"        # src mac
        + b"\x08\x00"                        # ethertype = IPv4
    )
    # IPv4: ihl=5, total_length=28 (20 IP + 8 UDP), proto=17 (UDP)
    ipv4 = (
        b"\x45\x00"                          # version=4, ihl=5, dscp=0
        + struct.pack("!H", 20 + 8)          # total_length
        + b"\x00\x00\x00\x00"                # id+flags+frag
        + b"\x40\x11"                        # ttl=64, proto=UDP
        + b"\x00\x00"                        # checksum (ignored by parser)
        + socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
    )
    udp = (
        struct.pack("!H", src_port)
        + struct.pack("!H", dst_port)
        + b"\x00\x08"                        # udp length
        + b"\x00\x00"                        # udp checksum
    )
    header_bytes = eth + ipv4 + udp          # 14 + 20 + 8 = 42 bytes
    header_len = len(header_bytes)
    # XDR opaque pads to a 4-byte boundary.
    pad = (-header_len) % 4
    header_padded = header_bytes + b"\x00" * pad

    raw_pkt_record_body = (
        struct.pack("!I", 1)                 # protocol_kind = Ethernet
        + struct.pack("!I", 60)              # original frame length on the wire
        + struct.pack("!I", 0)               # stripped
        + struct.pack("!I", header_len)      # header_length
        + header_padded
    )
    flow_record = (
        struct.pack("!I", 1)                 # data_format = raw_packet_header
        + struct.pack("!I", len(raw_pkt_record_body))
        + raw_pkt_record_body
    )

    flow_sample_body = struct.pack(
        "!IIIIIIII",
        99,                                  # seq
        0,                                   # source_id (type<<24 | index)
        sampling_rate,
        0,                                   # sample_pool
        0,                                   # drops
        1,                                   # input if
        2,                                   # output if
        1,                                   # flow_records_count
    ) + flow_record

    sample = (
        struct.pack("!I", 1)                 # sample_type = flow_sample
        + struct.pack("!I", len(flow_sample_body))
        + flow_sample_body
    )

    datagram_header = (
        struct.pack("!I", 5)                 # version
        + struct.pack("!I", 1)               # agent_addr_type IPv4
        + socket.inet_aton("10.0.0.99")      # agent address
        + struct.pack("!I", 0)               # sub_agent_id
        + struct.pack("!I", 1)               # sequence_number
        + struct.pack("!I", 0)               # uptime_ms
        + struct.pack("!I", 1)               # num_samples
    )
    return datagram_header + sample


def test_parse_sflow_flow_sample_extracts_udp_5tuple():
    pkt = _build_sflow_packet(
        src_ip="10.5.5.1", dst_ip="10.5.5.2",
        src_port=44444, dst_port=53,
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
    assert rec["protocol"] == 17                 # UDP
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


async def test_create_flow_records_batch_and_top_talkers(tmp_path, monkeypatch):
    await _init_db(tmp_path, monkeypatch)
    host_id = await _add_host(ip="10.10.10.1")

    rows = [
        # 10.0.0.1 wins on src_ip total bytes (1000 + 2000 = 3000).
        ("10.10.10.1", host_id, "netflow_v5",
         "10.0.0.1", "8.8.8.8", 1111, 53, 17, 1000, 2, 0, 0, 1, 2, 0, 0,
         "2026-05-12T00:00:00+00:00", "2026-05-12T00:00:01+00:00"),
        ("10.10.10.1", host_id, "netflow_v5",
         "10.0.0.1", "1.1.1.1", 2222, 443, 6, 2000, 4, 0, 0, 1, 2, 0, 0,
         "2026-05-12T00:00:02+00:00", "2026-05-12T00:00:03+00:00"),
        # 10.0.0.2 has fewer bytes — should sort second.
        ("10.10.10.1", host_id, "netflow_v5",
         "10.0.0.2", "8.8.8.8", 3333, 53, 17, 500, 1, 0, 0, 1, 2, 0, 0,
         "2026-05-12T00:00:04+00:00", "2026-05-12T00:00:05+00:00"),
    ]
    inserted = await db_module.create_flow_records_batch(rows)
    assert inserted == 3

    top_src = await db_module.get_flow_top_talkers(
        host_id=host_id, hours=1, direction="src", limit=10
    )
    # 10.0.0.1 with 3000 bytes / 2 flows; 10.0.0.2 with 500 bytes / 1 flow.
    assert len(top_src) == 2
    assert top_src[0]["ip"] == "10.0.0.1"
    assert top_src[0]["total_bytes"] == 3000
    assert top_src[0]["flow_count"] == 2
    assert top_src[1]["ip"] == "10.0.0.2"
    assert top_src[1]["total_bytes"] == 500

    # And the destination view: 8.8.8.8 should win since it's hit twice.
    top_dst = await db_module.get_flow_top_talkers(
        host_id=host_id, hours=1, direction="dst", limit=10
    )
    dst_ips = [r["ip"] for r in top_dst]
    assert "8.8.8.8" in dst_ips
    # 8.8.8.8 = 1000 + 500 = 1500 vs 1.1.1.1 = 2000, so 1.1.1.1 wins.
    assert top_dst[0]["ip"] == "1.1.1.1"


async def test_create_flow_records_batch_empty_is_noop(tmp_path, monkeypatch):
    await _init_db(tmp_path, monkeypatch)
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


async def test_collector_start_stop_idempotent(tmp_path, monkeypatch):
    await _init_db(tmp_path, monkeypatch)

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

        stopped = await flow_collector.stop_flow_collector()
        assert stopped is True
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
# Exporter cache refresh on host CRUD
# ═════════════════════════════════════════════════════════════════════════════


async def test_refresh_exporter_cache_loads_inventory(tmp_path, monkeypatch):
    await _init_db(tmp_path, monkeypatch)
    flow_collector._exporter_cache.clear()

    h1 = await _add_host(hostname="sw-a", ip="10.20.30.1")
    h2 = await _add_host(hostname="sw-b", ip="10.20.30.2")

    loaded = await flow_collector.refresh_exporter_cache()
    assert loaded == 2
    assert flow_collector._exporter_cache.get("10.20.30.1") == h1
    assert flow_collector._exporter_cache.get("10.20.30.2") == h2


async def test_on_host_changed_updates_cache_and_exporter_rows(tmp_path, monkeypatch):
    await _init_db(tmp_path, monkeypatch)
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

    # Add the host and notify the collector — both the cache and the
    # exporter row should pick up the new host_id without a restart.
    host_id = await _add_host(hostname="sw-c", ip="10.99.0.1")
    await flow_collector.on_host_changed(
        old_ip=None, new_ip="10.99.0.1", host_id=host_id
    )

    assert flow_collector._exporter_cache.get("10.99.0.1") == host_id

    rows = await db_module.list_flow_exporters()
    assert rows[0]["host_id"] == host_id
    assert rows[0]["hostname"] == "sw-c"

    # Now simulate the host being deleted: old_ip set, new_ip None.
    await flow_collector.on_host_changed(
        old_ip="10.99.0.1", new_ip=None, host_id=None
    )
    rows = await db_module.list_flow_exporters()
    assert rows[0]["host_id"] is None
