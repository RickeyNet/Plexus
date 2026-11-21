"""OPNsense firewall log (filterlog) evidence of the filter rules.

The parser of the filterlog CSV line (both syslog framings, IPv4 / IPv6,
TCP / UDP / ICMP, malformed lines), the pf label of a legacy rule, the
in-memory aggregate, the diversion out of the syslog receiver's batch
writer (filterlog lines are never stored raw), the rules endpoint with the
evidence, the path trace hop evidence and the retention. Every line is
written for these tests from the upstream format with invented values:
documentation ranges and example.com only.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import time

import netcontrol.routes.metrics_engine as me
import netcontrol.routes.opnsense_filterlog as evidence
import netcontrol.routes.state as state
import pytest
import routes.database as db
from netcontrol.integrations.opnsense.filterlog import (
    BUCKET_SECONDS,
    FilterlogAggregator,
    bucket_start,
    filterlog_payload,
    is_filterlog,
    parse_filterlog,
    parse_record,
)
from netcontrol.integrations.pathtrace.model import net
from netcontrol.integrations.pathtrace.opnsense_config import legacy_rule_label, parse_document, parse_xml

from test_meraki_topology import api  # noqa: F401 - the fixture is used by name
from test_opnsense_rules import _E2E_CONFIG, CONFIG, RULE_SSH_DMZ, RULE_WEB, _firewall_and_router

UUID = "11111111-1111-4111-8111-000000000001"
HASH = "0123456789abcdef0123456789abcdef"
# RFC 5424, IPv4 TCP SYN passed by an MVC rule (its uuid is the label).
V4_TCP_5424 = (
    '<134>1 2026-11-20T10:00:00+00:00 fw-lab-1.example.com filterlog 81234 - [meta sequenceId="17"] '
    f"82,,,{UUID},igb1,match,pass,in,4,0x0,,64,51234,0,DF,6,tcp,60,192.0.2.10,192.0.2.140,"
    "50123,443,0,S,1234567890,,64240,,mss;sackOK;TS;nop;wscale"
)
# RFC 3164, IPv4 UDP blocked by an automatic rule (a hash label).
V4_UDP_3164 = (
    f"<134>Nov 20 10:00:01 fw-lab-1 filterlog[81234]: 5,,,{HASH},igb0,match,block,in,4,0x0,,240,12345,0,none,"
    "17,udp,40,203.0.113.50,203.0.113.2,5353,161,20"
)
# RFC 5424 without structured data, IPv6 ICMP (OPNsense prints datalength=).
V6_ICMP = (
    "<134>1 2026-11-20T10:00:02+00:00 fw-lab-1.example.com filterlog 81234 - - "
    f"90,,,{UUID},igb1,match,pass,out,6,0x00,0x00000,64,ipv6-icmp,58,16,2001:db8:1::10,2001:db8:2::20,"
    "datalength=16"
)
# IPv6 TCP block.
V6_TCP = (
    f"<134>Nov 20 10:00:03 fw-lab-1 filterlog[81234]: 12,,,{HASH},igb0,match,block,in,6,0x00,0x00000,57,tcp,6,"
    "40,2001:db8:ff::5,2001:db8:1::10,40000,22,0,S,1,,1024,,"
)
# A pfSense-style ICMP line naming the type.
V4_ICMP_TYPED = (
    f"filterlog[1]: 7,,,{HASH},igb1,match,block,in,4,0x0,,64,0,0,none,1,icmp,84,192.0.2.10,198.51.100.10,request,1234,1"
)


# ── Parser ───────────────────────────────────────────────────────────────────


def test_ipv4_tcp_pass_rfc5424():
    entry = parse_filterlog(V4_TCP_5424)
    assert entry is not None
    assert (entry.rule_number, entry.label, entry.rule_key) == (82, UUID, UUID)
    assert (entry.interface, entry.reason, entry.action, entry.direction) == ("igb1", "match", "pass", "in")
    assert (entry.ip_version, entry.protocol, entry.protocol_number) == (4, "tcp", 6)
    assert (entry.source, entry.destination, entry.source_port, entry.destination_port) == (
        "192.0.2.10",
        "192.0.2.140",
        50123,
        443,
    )


def test_ipv4_udp_block_rfc3164():
    entry = parse_filterlog(V4_UDP_3164)
    assert entry is not None
    assert (entry.action, entry.protocol, entry.rule_key) == ("block", "udp", HASH)
    assert (entry.source, entry.destination, entry.destination_port) == ("203.0.113.50", "203.0.113.2", 161)


def test_ipv6_icmp_and_tcp():
    icmp = parse_filterlog(V6_ICMP)
    assert icmp is not None
    assert (icmp.ip_version, icmp.protocol, icmp.direction) == (6, "icmpv6", "out")
    assert (icmp.source, icmp.destination, icmp.destination_port, icmp.icmp_type) == (
        "2001:db8:1::10",
        "2001:db8:2::20",
        None,
        "",
    )
    tcp = parse_filterlog(V6_TCP)
    assert tcp is not None
    assert (tcp.protocol, tcp.action, tcp.destination_port, tcp.source) == ("tcp", "block", 22, "2001:db8:ff::5")


def test_icmp_type_of_a_typed_line_and_priority_optional():
    entry = parse_filterlog(V4_ICMP_TYPED)
    assert entry is not None and entry.protocol == "icmp" and entry.icmp_type == "request"


def test_labels_old_layout_and_none():
    # Before 21.1 the label field was 0 and the label came last.
    old = parse_record(
        f"82,,,0,igb1,match,pass,in,4,0x0,,64,1,0,DF,17,udp,40,192.0.2.10,198.51.100.53,5000,53,20,{HASH}"
    )
    assert old is not None and old.rule_key == HASH
    bare = parse_record("82,,,0,igb1,match,pass,in,4,0x0,,64,1,0,DF,17,udp,40,192.0.2.10,198.51.100.53,5000,53,20")
    assert bare is not None and bare.label == "" and bare.rule_key == "rulenr:82"
    anchored = parse_record("3,,openvpn,0,ovpns1,match,pass,in,4,0x0,,64,1,0,DF,17,udp,40,192.0.2.10,192.0.2.1,1,2,3")
    assert anchored is not None and anchored.rule_key == "rulenr:openvpn/3"


@pytest.mark.parametrize(
    "message",
    [
        "",
        "<134>Nov 20 10:00:00 fw-lab-1 configd.py: restarting filterlog",
        "<134>Nov 20 10:00:00 fw-lab-1 filterlog[1]: garbage",
        "<134>Nov 20 10:00:00 fw-lab-1 filterlog[1]: 82,,,abc,igb1,match,pass,in,4,0x0",
        # A truncated packet: no addresses.
        "<134>Nov 20 10:00:00 fw-lab-1 filterlog[1]: 82,,,abc,igb1,match,pass,in,4,truncated-ip=40,",
        "<134>Nov 20 10:00:00 fw-lab-1 filterlog[1]: 82,,,abc,igb1,match,pass,in,4,0x0,,64,1,0,DF,6,tcp,60,x,y,1,2",
        "<134>Nov 20 10:00:00 fw-lab-1 filterlog[1]: x,,,abc,igb1,match,pass,in,4,0x0,,64,1,0,DF,6,tcp,60,"
        "192.0.2.1,192.0.2.2,1,2",
        "<134>Nov 20 10:00:00 fw-lab-1 filterlog[1]: 1,,,abc,igb1,match,fly,in,4,0x0,,64,1,0,DF,6,tcp,60,"
        "192.0.2.1,192.0.2.2,1,2",
        "<134>Nov 20 10:00:00 fw-lab-1 filterlog[1]: 1,,,abc,igb1,match,pass,in,5,0x0,,64,1,0,DF,6,tcp,60,"
        "192.0.2.1,192.0.2.2,1,2",
        '<134>1 2026-11-20T10:00:00Z fw-lab-1.example.com filterlog 1 - [meta x="unterminated 1,,,a',
        "<134>1 2026-11-20T10:00:00Z fw-lab-1.example.com filterlog 1",
        "<134>Nov 20 10:00:00 fw-lab-1 filterlogd: 1,2",
    ],
)
def test_malformed_lines_give_none(message):
    assert parse_filterlog(message) is None


def test_framing_helpers():
    assert is_filterlog(V4_UDP_3164) and not is_filterlog("<13>Nov 20 10:00:00 sw-lab-1 %LINK-3-UPDOWN: down")
    # Only filterlog as the sending program counts: a message that names it does not.
    assert filterlog_payload("Nov 20 10:00:00 fw-lab-1 configd.py: filterlog started on pid 5 now") is None
    escaped = '1 2026-11-20T10:00:00Z fw.example.com filterlog 1 - [a b="x\\]y"][c d="]"] 82,,,'
    assert filterlog_payload(escaped) == "82,,,"


def test_legacy_rule_label_matches_opnsense_calc_rule_hash():
    """``Util::calcRuleHash``: updated/created/descr dropped, keys sorted (one
    level), json_encode (escaped slashes, no spaces), MD5."""
    element = parse_xml(
        '<opnsense><filter><rule uuid="11111111-1111-4111-8111-0000000000aa">'
        "<type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><descr>Users/servers</descr>"
        "<source><port>443</port><address>192.0.2.10</address></source>"
        "<destination><network>192.0.2.0/24</network></destination><log/>"
        "<updated><username>admin@192.0.2.5</username><time>1700000000</time></updated>"
        "</rule></filter></opnsense>"
    )
    assert element is not None
    rule = element.find("filter/rule")
    assert rule is not None
    expected = (
        '{"@attributes":{"uuid":"11111111-1111-4111-8111-0000000000aa"},'
        '"destination":{"network":"192.0.2.0\\/24"},"interface":"lan","ipprotocol":"inet","log":"",'
        '"source":{"address":"192.0.2.10","port":"443"},"type":"pass"}'
    )
    assert legacy_rule_label(rule) == hashlib.md5(expected.encode(), usedforsecurity=False).hexdigest()


def test_rules_carry_their_pf_label():
    config = parse_document(CONFIG)
    assert config is not None
    mvc = next(r for r in config.rules if r.tier == "automation")
    assert mvc.label == mvc.uuid
    legacy = [r for r in config.rules if r.tier != "automation"]
    assert all(len(r.label) == 32 and r.label != r.uuid for r in legacy)
    # The label does not change with the description (calcRuleHash drops descr).
    renamed = parse_document(CONFIG.replace("<descr>Users to DMZ web</descr>", "<descr>Renamed</descr>"))
    assert renamed is not None
    assert {r.uuid: r.label for r in renamed.rules} == {r.uuid: r.label for r in config.rules}


# ── Aggregate ────────────────────────────────────────────────────────────────

NOW = 1_800_000_000.0  # aligned to a bucket boundary below


def _payload(line: str) -> str:
    found = filterlog_payload(line)
    assert found is not None
    return found


def test_aggregate_buckets_flows_and_drain():
    agg = FilterlogAggregator()
    start = NOW - NOW % BUCKET_SECONDS
    assert agg.add(7, _payload(V4_TCP_5424), start + 1)
    assert agg.add(7, _payload(V4_TCP_5424), start + 2)
    assert agg.add(7, _payload(V4_TCP_5424), start + BUCKET_SECONDS)  # the next bucket
    assert agg.add(7, _payload(V4_UDP_3164), start + 3)
    assert not agg.add(7, "garbage", start)
    assert not agg.add(7, _payload(V4_TCP_5424).replace(",pass,", ",rdr,"), start)
    hits, flows = agg.drain()
    by = {(r[1], r[2], r[3]): (r[6], r[7]) for r in hits}
    assert by[(bucket_start(start), UUID, "pass")] == (2, bucket_start(start + 2)[:-2] + "02")
    assert by[(bucket_start(start + BUCKET_SECONDS), UUID, "pass")][0] == 1
    assert by[(bucket_start(start), HASH, "block")][0] == 1
    flow = next(f for f in flows if f[1] == UUID)
    assert flow[:7] == (7, UUID, "pass", "192.0.2.10", "192.0.2.140", "tcp", 443) and flow[7] == 3
    stats = agg.stats()
    assert (stats["lines"], stats["unparsed"], stats["other_actions"]) == (4, 1, 1)
    assert agg.drain() == ([], []) and agg.pending() == 0


def test_aggregate_is_bounded():
    agg = FilterlogAggregator(max_buckets=1, max_flows=10, flows_per_rule=1)
    assert agg.add(1, _payload(V4_TCP_5424), NOW)
    assert not agg.add(2, _payload(V4_TCP_5424), NOW)  # a second bucket: dropped
    assert agg.stats()["dropped"] == 1
    other = _payload(V4_TCP_5424).replace("192.0.2.10", "192.0.2.11")
    assert agg.add(1, other, NOW)  # counted, its flow left out (one flow per rule)
    hits, flows = agg.drain()
    assert hits[0][6] == 2 and len(flows) == 1 and agg.stats()["flows_left_out"] == 1


# ── Diversion out of the receiver ────────────────────────────────────────────


@pytest.fixture
def fresh(monkeypatch):
    agg = FilterlogAggregator()
    monkeypatch.setattr(evidence, "AGGREGATOR", agg)
    monkeypatch.setattr(evidence, "_ensure_flusher", lambda: None)
    monkeypatch.setitem(state.EVENT_RECEIVER_CONFIG, "filterlog_evidence", True)
    return agg


def _row(host_id, message, event_type="syslog"):
    return ("192.0.2.1", host_id, event_type, "16", "info", "", message, message)


def test_divert_takes_out_filterlog_lines(fresh):
    other = _row(5, "Nov 20 10:00:00 fw-lab-1 configd.py: filterlog restarted")
    kept = evidence.divert([_row(5, V4_TCP_5424[5:]), _row(None, V4_UDP_3164[5:]), other, _row(5, V4_TCP_5424, "trap")])
    assert kept == [other, _row(5, V4_TCP_5424, "trap")]
    stats = fresh.stats()
    assert (stats["lines"], stats["unknown_source"]) == (1, 1)
    assert evidence.receiver_stats()["filterlog_received"] == 1
    assert evidence.receiver_stats()["filterlog_dropped"] == 1


def test_switch_off_drops_the_lines(fresh, monkeypatch):
    monkeypatch.setitem(state.EVENT_RECEIVER_CONFIG, "filterlog_evidence", False)
    assert evidence.divert([_row(5, V4_TCP_5424[5:])]) == []
    assert fresh.stats()["disabled"] == 1 and fresh.pending() == 0
    assert state._sanitize_event_receiver_config({"filterlog_evidence": False})["filterlog_evidence"] is False
    assert state._sanitize_event_receiver_config({})["filterlog_evidence"] is True


async def _host(name: str = "fw-lab-1", address: str = "192.0.2.1") -> int:
    group_id = await db.create_group(f"Firewalls {name}")
    return await db.add_host(group_id, name, address, device_type="opnsense")


async def test_writer_stores_other_messages_but_never_filterlog_lines(fresh, monkeypatch):
    host_id = await _host()
    monkeypatch.setattr(me, "_TRAP_EVENT_FLUSH_SECONDS", 0.01)
    me._host_ip_cache.clear()
    me._queue_trap_syslog_event("192.0.2.1", "syslog", "16", "info", "", V4_TCP_5424[5:], V4_TCP_5424)
    me._queue_trap_syslog_event("198.51.100.99", "syslog", "16", "info", "", V4_UDP_3164[5:], V4_UDP_3164)
    me._queue_trap_syslog_event("192.0.2.1", "syslog", "16", "info", "", "sshd[1]: login ok", "sshd[1]: login ok")
    try:
        for _ in range(200):
            if not me._trap_event_buffer and fresh.stats()["lines"] and fresh.stats()["unknown_source"]:
                break
            await asyncio.sleep(0.02)
        events = await db.get_trap_syslog_events(event_type="syslog", limit=50)
        for _ in range(100):
            if events:
                break
            await asyncio.sleep(0.02)
            events = await db.get_trap_syslog_events(event_type="syslog", limit=50)
    finally:
        if me._trap_event_writer_task is not None:
            me._trap_event_writer_task.cancel()
            me._trap_event_writer_task = None
    assert [e["message"] for e in events] == ["sshd[1]: login ok"]
    assert fresh.stats()["lines"] == 1 and fresh.stats()["unknown_source"] == 1
    assert await evidence.flush() == 2  # one bucket, one flow
    rows = await db.get_opnsense_filterlog_rule_summary(host_id, "2000-01-01 00:00:00", "2000-01-01 00:00:00")
    assert [(r["rule_key"], r["action"], r["hits"]) for r in rows] == [(UUID, "pass", 1)]
    assert me.event_receiver_snapshot()["filterlog_received"] == 1


async def test_flusher_runs_on_a_timer(monkeypatch):
    agg = FilterlogAggregator()
    monkeypatch.setattr(evidence, "AGGREGATOR", agg)
    monkeypatch.setattr(evidence, "FLUSH_SECONDS", 0.01)
    monkeypatch.setitem(state.EVENT_RECEIVER_CONFIG, "filterlog_evidence", True)
    host_id = await _host()
    evidence.divert([_row(host_id, V4_TCP_5424[5:])])
    written = ""
    try:
        for _ in range(200):
            written = await db.get_opnsense_filterlog_last_seen(host_id)
            if written:
                break
            await asyncio.sleep(0.02)
    finally:
        if evidence._flush_task is not None:
            evidence._flush_task.cancel()
            evidence._flush_task = None
    assert written and agg.pending() == 0


async def test_a_failed_write_is_counted_and_dropped(fresh, monkeypatch):
    async def boom(*_a, **_k):
        raise RuntimeError("database down")

    fresh.add(1, _payload(V4_TCP_5424), NOW)
    monkeypatch.setattr(db, "upsert_opnsense_filterlog", boom)
    assert await evidence.flush() == 0 and fresh.stats()["dropped"] == 1 and fresh.pending() == 0


# ── Storage, retention ───────────────────────────────────────────────────────


def _stamp(epoch: float) -> str:
    return bucket_start(epoch)[:-5] + time.strftime("%M:%S", time.gmtime(epoch))


async def _seed_evidence(host_id: int, rows: list[tuple], flows: list[tuple]) -> None:
    await db.upsert_opnsense_filterlog(
        [(host_id, *r) for r in rows], [(host_id, *f) for f in flows], flows_per_rule=evidence.FLOWS_PER_RULE
    )


async def test_upsert_sums_and_trims_flows_and_retention_removes_old_rows():
    host_id = await _host()
    now = time.time()
    seen = _stamp(now)
    bucket = bucket_start(now)
    await _seed_evidence(host_id, [(bucket, UUID, "pass", "igb1", "in", 3, seen)], [])
    await _seed_evidence(host_id, [(bucket, UUID, "pass", "igb1", "in", 2, seen)], [])
    flows = [(UUID, "pass", f"192.0.2.{i}", "192.0.2.140", "tcp", 443, 1, _stamp(now - i)) for i in range(1, 4)]
    await db.upsert_opnsense_filterlog([], [(host_id, *f) for f in flows], flows_per_rule=2)
    rows = await db.get_opnsense_filterlog_rule_summary(host_id, bucket, bucket)
    assert rows[0]["hits"] == 5 and rows[0]["recent_hits"] == 5
    kept = await db.get_opnsense_filterlog_flows(host_id, "2000-01-01 00:00:00")
    assert [f["source"] for f in kept] == ["192.0.2.1", "192.0.2.2"]  # the newest two
    assert await db.hosts_with_opnsense_filterlog([host_id, host_id + 1000], bucket) == {host_id}
    assert await db.get_opnsense_filterlog_flows(host_id, "2000-01-01 00:00:00", []) == []

    old = "2020-01-01 00:00:00"
    await _seed_evidence(
        host_id,
        [(old, HASH, "block", "igb0", "in", 9, old)],
        [(HASH, "block", "203.0.113.5", "203.0.113.2", "udp", 161, 9, old)],
    )
    deleted = await me.run_retention_cleanup()
    assert deleted["filterlog_evidence_deleted"] == 2
    remaining = await db.get_opnsense_filterlog_rule_summary(host_id, "2000-01-01 00:00:00", bucket)
    assert {r["rule_key"] for r in remaining} == {UUID}
    assert await db.upsert_opnsense_filterlog([], []) == 0


# ── Rules endpoint ───────────────────────────────────────────────────────────


def test_rules_endpoint_carries_the_evidence(api):  # noqa: F811 - the imported fixture
    from test_opnsense_rules import _seed

    ids = _seed(CONFIG, CONFIG)
    config = parse_document(CONFIG)
    assert config is not None
    web = next(r for r in config.rules if r.uuid == RULE_WEB)
    now = time.time()
    seen = _stamp(now)
    day_old = now - 5 * 3600

    async def seed() -> None:
        await _seed_evidence(
            ids["host"],
            [
                (bucket_start(now), web.label, "pass", "igb1", "in", 4, seen),
                (bucket_start(day_old), web.label, "pass", "igb1", "in", 6, _stamp(day_old)),
                (bucket_start(now), web.label, "block", "igb1", "in", 1, seen),
                (bucket_start(now), HASH, "block", "igb0", "in", 7, seen),
                (bucket_start(now), "rulenr:3", "pass", "igb0", "out", 1, seen),
            ],
            [(web.label, "pass", "192.0.2.10", "192.0.2.140", "tcp", 443, 4, seen)],
        )

    asyncio.run(seed())
    body = api.get(f"/api/opnsense/hosts/{ids['host']}/rules").json()
    rules = {r["uuid"]: r for r in body["rules"] if r["uuid"]}
    found = rules[RULE_WEB]["log_evidence"]
    assert rules[RULE_WEB]["label"] == web.label
    assert (found["passes"], found["passes_recent"], found["blocks"], found["blocks_recent"]) == (10, 4, 1, 1)
    assert found["last_seen"] == seen and found["seen_on"] == ["igb1 in"]
    assert found["flows"][0]["source"] == "192.0.2.10" and found["flows"][0]["destination_port"] == 443
    assert rules[RULE_SSH_DMZ]["log_evidence"] is None
    log = body["log_evidence"]
    assert log["enabled"] and log["received_at"] == seen and log["window_hours"] == 24
    unmatched = {u["rule_key"]: u for u in log["unmatched"]}
    assert set(unmatched) == {HASH, "rulenr:3"}
    assert "automatic" in unmatched[HASH]["name"] and unmatched[HASH]["blocks"] == 7
    assert "pf rule 3" in unmatched["rulenr:3"]["name"]
    # The counters collected by uuid still reach the rule (the label first, the uuid as fallback).
    assert rules[RULE_WEB]["stats"] == {"packets": 4}


def test_rules_endpoint_without_evidence(api):  # noqa: F811 - the imported fixture
    from test_opnsense_rules import _seed

    ids = _seed(CONFIG, CONFIG)
    body = api.get(f"/api/opnsense/hosts/{ids['host']}/rules").json()
    assert all(r["log_evidence"] is None for r in body["rules"])
    assert body["log_evidence"]["received_at"] is None and body["log_evidence"]["unmatched"] == []


# ── Path trace hop evidence ──────────────────────────────────────────────────


def _trace_to_dmz_web() -> dict:
    _block, tracer = _firewall_and_router()
    result = tracer.trace("192.0.2.0/25", "192.0.2.140", source_node=31, protocol="tcp", port=443)
    assert result["verdict"] == "allowed", result["summary"]
    return result


async def _firewall_with_backup() -> int:
    host_id = await _host()
    await db.create_config_backup(None, host_id, _E2E_CONFIG, capture_method="opnsense-api")
    return host_id


def _on(result: dict, host_id: int) -> dict:
    for hop in result["request"]["hops"]:
        if hop["node"] == 31:
            hop["node"] = host_id
    return result


async def test_trace_without_evidence_is_unchanged():
    host_id = await _firewall_with_backup()
    result = _on(_trace_to_dmz_web(), host_id)
    before = copy.deepcopy(result)
    assert await evidence.attach_trace_evidence(result, "192.0.2.0/25", "192.0.2.140", "tcp", 443) == before


async def test_trace_hop_shows_rule_evidence_and_a_contradiction():
    host_id = await _firewall_with_backup()
    config = parse_document(_E2E_CONFIG)
    assert config is not None
    web = next(r for r in config.rules if r.uuid == RULE_WEB)
    now = time.time()
    seen = _stamp(now)
    await _seed_evidence(
        host_id,
        [
            (bucket_start(now), web.label, "pass", "igb1", "in", 3, seen),
            (bucket_start(now), HASH, "block", "igb1", "in", 5, seen),
        ],
        [
            (web.label, "pass", "192.0.2.20", "192.0.2.141", "tcp", 443, 3, seen),  # another destination
            (HASH, "block", "192.0.2.10", "192.0.2.140", "tcp", 443, 5, seen),  # the traced flow, blocked
        ],
    )
    result = await evidence.attach_trace_evidence(
        _on(_trace_to_dmz_web(), host_id), "192.0.2.0/25", "192.0.2.140", "tcp", 443
    )
    [hop] = result["request"]["hops"]
    found = hop["log_evidence"]
    assert found["trace_says"] == "allowed"
    named = {r["number"]: r for r in found["rules"]}
    assert named[web.number]["passes"] == 3 and named[web.number]["description"] == "Users to DMZ web"
    assert found["flow"]["matched"] and (found["flow"]["passes"], found["flow"]["blocks"]) == (0, 5)
    assert "automatic" in found["flow"]["rules"][0]
    assert found["contradiction"].startswith("The trace allows this flow here, but the firewall log shows it blocked")
    # The replies are left as they were.
    assert all("log_evidence" not in h for h in result["reply"]["hops"])


async def test_trace_evidence_never_breaks_the_trace(monkeypatch):
    async def boom(*_a, **_k):
        raise RuntimeError("database down")

    monkeypatch.setattr(db, "hosts_with_opnsense_filterlog", boom)
    result = {"request": {"hops": [{"node": 1, "items": []}]}}
    assert await evidence.attach_trace_evidence(result, "192.0.2.1", "192.0.2.2") == result


def test_flow_matching_and_contradictions():
    flow = {"source": "192.0.2.10", "destination": "198.51.100.5", "protocol": "udp", "destination_port": 53}
    src, dst = net("192.0.2.0/24"), net("198.51.100.5")
    assert evidence.flow_matches(flow, src, dst, "", None)
    assert evidence.flow_matches(flow, src, dst, "udp", 53)
    assert not evidence.flow_matches(flow, src, dst, "tcp", 53)
    assert not evidence.flow_matches(flow, src, dst, "udp", 443)
    assert not evidence.flow_matches(flow, net("203.0.113.0/24"), dst, "", None)
    assert not evidence.flow_matches(flow, None, dst, "", None)
    icmp6 = {"source": "2001:db8::1", "destination": "2001:db8::2", "protocol": "icmpv6", "destination_port": None}
    assert evidence.flow_matches(icmp6, net("2001:db8::/32"), net("2001:db8::2"), "icmp6", None)
    assert evidence.contradiction("blocked", 2, 0).startswith("The trace blocks this flow here")
    assert "both passed (2) and blocked (1)" in evidence.contradiction("allowed", 2, 1)
    assert evidence.contradiction("allowed", 2, 0) == "" and evidence.contradiction("", 0, 3) == ""
    assert evidence.describe_key("11111111-1111-4111-8111-0000000000ff").startswith("A rule that is not")


def test_server_side_only():
    from netcontrol.integrations.pathtrace.offline import MODULES

    assert not any("filterlog" in module for module in MODULES)
