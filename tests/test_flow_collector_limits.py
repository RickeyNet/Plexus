"""Hard limits on the NetFlow v9/IPFIX template cache and decoder, and on the
sFlow sampling-rate map (SECURITY_AUDIT finding 11 / INB-1).

A hostile exporter (UDP sources are unauthenticated and spoofable) must not
be able to make one datagram cost more than its own size in decode work, nor
grow the collector's in-memory state without bound. Work is measured in
traced Python lines inside the parser, not wall-clock time.
"""

from __future__ import annotations

import socket
import struct
import sys

import pytest
from netcontrol.bounded_map import BoundedDict
from netcontrol.routes import flow_collector as fc

from test_flow_collector import _build_nf9_template_and_data, _build_sflow_packet

EXPORTER = ("192.0.2.10", 2055)


@pytest.fixture(autouse=True)
def _clean_caches():
    fc._nf9_templates.clear()
    fc._sflow_sampling_rates.clear()
    yield
    fc._nf9_templates.clear()
    fc._sflow_sampling_rates.clear()


def _v9_header() -> bytes:
    return struct.pack("!HHIIII", 9, 1, 0, 1_700_000_000, 0, 1)


def _template_flowset(tpl_id: int, fields: list[tuple[int, int]]) -> bytes:
    body = struct.pack("!HH", tpl_id, len(fields)) + b"".join(struct.pack("!HH", t, n) for t, n in fields)
    return struct.pack("!HH", 0, 4 + len(body)) + body


def _data_flowset(tpl_id: int, payload: bytes) -> bytes:
    return struct.pack("!HH", tpl_id, 4 + len(payload)) + payload


def _traced_lines(fn, *args):
    """Run ``fn`` and count the Python lines it executes (the parser and
    everything it calls): a deterministic measure of work done."""
    count = 0

    def tracer(frame, event, arg):
        nonlocal count
        if event == "line":
            count += 1
        return tracer

    sys.settrace(tracer)
    try:
        result = fn(*args)
    finally:
        sys.settrace(None)
    return result, count


# ── template validation ─────────────────────────────────────────────────────


def test_audit_template_with_zero_length_fields_is_rejected_and_data_is_cheap():
    # The audit's packet pair: ~16,000 zero-length fields plus one 1-byte
    # field (record_len 1), then ~64 KB of data for that template.
    fields = [(1, 0)] * 15_999 + [(1, 1)]
    fc.parse_netflow_v9(_v9_header() + _template_flowset(300, fields), EXPORTER)
    assert 300 not in fc._nf9_templates.get(EXPORTER[0], {})

    data_pkt = _v9_header() + _data_flowset(300, b"\x01" * 65_000)
    recs, lines = _traced_lines(fc.parse_netflow_v9, data_pkt, EXPORTER)
    assert recs == []
    assert lines < 200


@pytest.mark.parametrize(
    "fields",
    [
        [(8, 4), (1, 0), (12, 4)],  # a zero-length field among real ones
        [(1, 1)] * (fc.NF9_MAX_TEMPLATE_FIELDS + 1),  # too many fields
        [(4, 1), (5, 1), (6, 1)],  # record shorter than NF9_MIN_RECORD_LEN
    ],
)
def test_bad_templates_are_not_stored(fields):
    fc.parse_netflow_v9(_v9_header() + _template_flowset(400, fields), EXPORTER)
    assert 400 not in fc._nf9_templates.get(EXPORTER[0], {})


def test_truncated_template_is_not_stored():
    fields = [(8, 4), (12, 4), (7, 2), (11, 2)]
    flowset = _template_flowset(401, fields)
    # Claim the full field count but cut the last field off the flowset.
    truncated = struct.pack("!HH", 0, len(flowset) - 4) + flowset[4:-4]
    fc.parse_netflow_v9(_v9_header() + truncated, EXPORTER)
    assert 401 not in fc._nf9_templates.get(EXPORTER[0], {})


def test_template_at_field_cap_is_stored():
    fields = [(1, 1)] * fc.NF9_MAX_TEMPLATE_FIELDS
    fc.parse_netflow_v9(_v9_header() + _template_flowset(402, fields), EXPORTER)
    assert 402 in fc._nf9_templates[EXPORTER[0]]


def test_zero_field_count_withdraws_template():
    fc.parse_netflow_v9(_v9_header() + _template_flowset(403, [(8, 4), (12, 4)]), EXPORTER)
    assert 403 in fc._nf9_templates[EXPORTER[0]]
    assert fc._nf9_store_template(EXPORTER[0], 403, 0, b"") is False
    assert 403 not in fc._nf9_templates[EXPORTER[0]]


def test_variable_length_field_template_is_accepted_and_parse_is_safe():
    # IPFIX marks variable-length fields with length 65535; such a template
    # is valid and must be kept, and data for it must not raise.
    fields = [(8, 4), (12, 4), (82, 65535)]
    fc.parse_netflow_v9(_v9_header() + _template_flowset(404, fields), EXPORTER)
    assert 404 in fc._nf9_templates[EXPORTER[0]]
    payload = socket.inet_aton("192.0.2.1") + socket.inet_aton("198.51.100.2") + b"\x03eth"
    recs, lines = _traced_lines(fc.parse_netflow_v9, _v9_header() + _data_flowset(404, payload), EXPORTER)
    assert recs == []
    assert lines < 200


# ── work and row bounds on data flowsets ────────────────────────────────────


def test_widest_template_costs_at_most_packet_bytes_in_field_steps():
    # 128 one-byte fields: the most fields a stored template may have.
    fields = [(1, 1)] * fc.NF9_MAX_TEMPLATE_FIELDS
    fc.parse_netflow_v9(_v9_header() + _template_flowset(500, fields), EXPORTER)
    payload = b"\x01" * 65_000
    recs, lines = _traced_lines(fc.parse_netflow_v9, _v9_header() + _data_flowset(500, payload), EXPORTER)
    assert len(recs) == len(payload) // fc.NF9_MAX_TEMPLATE_FIELDS
    # A field step is a handful of lines; allow 8 per payload byte.
    assert lines < 8 * len(payload)


def test_records_per_packet_are_capped():
    fc.parse_netflow_v9(_v9_header() + _template_flowset(501, [(1, 4)]), EXPORTER)
    recs = fc.parse_netflow_v9(_v9_header() + _data_flowset(501, b"\x00\x00\x00\x01" * 16_000), EXPORTER)
    assert len(recs) == fc.NF9_MAX_RECORDS_PER_PACKET


# ── cache bounds ────────────────────────────────────────────────────────────


def test_templates_per_exporter_are_bounded_lru():
    for tpl_id in range(256, 256 + fc.NF9_MAX_TEMPLATES_PER_EXPORTER + 10):
        fc.parse_netflow_v9(_v9_header() + _template_flowset(tpl_id, [(8, 4), (12, 4)]), EXPORTER)
    kept = fc._nf9_templates[EXPORTER[0]]
    assert len(kept) == fc.NF9_MAX_TEMPLATES_PER_EXPORTER
    assert 256 not in kept
    assert 256 + fc.NF9_MAX_TEMPLATES_PER_EXPORTER + 9 in kept


def test_exporters_are_bounded_and_active_ones_survive(monkeypatch):
    monkeypatch.setattr(fc, "_nf9_templates", BoundedDict(4))
    pkt = _build_nf9_template_and_data()
    fc.parse_netflow_v9(pkt, ("192.0.2.1", 2055))
    for i in range(2, 10):
        # The first exporter keeps sending data, so it stays most recent.
        fc.parse_netflow_v9(pkt[:20] + pkt[20 + 36 :], ("192.0.2.1", 2055))
        fc.parse_netflow_v9(pkt, (f"192.0.2.{i}", 2055))
    assert len(fc._nf9_templates) == 4
    assert "192.0.2.1" in fc._nf9_templates


def test_valid_v9_packet_still_decodes_the_same():
    recs = fc.parse_netflow_v9(_build_nf9_template_and_data(), ("198.51.100.7", 2055))
    assert [
        (r["src_ip"], r["dst_ip"], r["src_port"], r["dst_port"], r["protocol"], r["bytes"], r["packets"]) for r in recs
    ] == [
        ("10.0.0.1", "10.0.0.2", 1111, 443, 6, 5000, 7),
        ("10.0.0.3", "8.8.8.8", 2222, 53, 17, 256, 2),
    ]


# ── sFlow ───────────────────────────────────────────────────────────────────


def test_sflow_sampling_rate_map_is_bounded(monkeypatch):
    monkeypatch.setattr(fc, "SFLOW_MAX_SOURCES_PER_EXPORTER", 3)
    monkeypatch.setattr(fc, "_sflow_sampling_rates", BoundedDict(2))
    for rate in (100, 200, 300, 400):
        fc._parse_sflow_flow_sample(struct.pack("!IIIIIIII", 0, rate, rate, 0, 0, 0, 0, 0), "192.0.2.5", expanded=False)
    assert len(fc._sflow_sampling_rates["192.0.2.5"]) == 3
    assert fc._latest_sflow_sampling_rate("192.0.2.5") == 400
    for ip in ("192.0.2.6", "192.0.2.7"):
        fc._parse_sflow_flow_sample(struct.pack("!IIIIIIII", 0, 1, 64, 0, 0, 0, 0, 0), ip, expanded=False)
    assert len(fc._sflow_sampling_rates) == 2
    assert fc._latest_sflow_sampling_rate("192.0.2.5") == 0


def test_sflow_huge_counts_cost_at_most_packet_bytes():
    # num_samples and flow_records_count are read from the packet; claim
    # billions and give almost nothing: the loops stop at the data.
    header = struct.pack("!II", 5, 1) + socket.inet_aton("192.0.2.9") + struct.pack("!IIII", 0, 1, 0, 0xFFFFFFFF)
    body = struct.pack("!IIIIIIII", 0, 0, 1, 0, 0, 0, 0, 0xFFFFFFFF)
    sample = struct.pack("!II", 1, len(body)) + body
    recs, lines = _traced_lines(fc.parse_sflow, header + sample, ("192.0.2.9", 6343))
    assert recs == []
    assert lines < 200


def test_valid_sflow_packet_still_decodes_the_same():
    recs = fc.parse_sflow(_build_sflow_packet("192.0.2.1", "198.51.100.2", 40000, 53, 256), ("192.0.2.20", 6343))
    assert [
        (r["src_ip"], r["dst_ip"], r["src_port"], r["dst_port"], r["protocol"], r["bytes"], r["packets"]) for r in recs
    ] == [("192.0.2.1", "198.51.100.2", 40000, 53, 17, 60 * 256, 256)]
    assert fc._latest_sflow_sampling_rate("192.0.2.20") == 256
