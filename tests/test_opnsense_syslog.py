"""OPNsense syslog into the receiver (``netcontrol.syslog_rules`` re-collect
triggers, ``netcontrol.source_recollect``): which messages start a
re-collection of the firewall's topology source and why, how the source
address is mapped to the source, the debounce / cooldown / trailing run,
the switch and the explanation of the rule tester.

Every message here is written from the upstream log formats (OPNsense
gateway watcher, FreeBSD ip_carp.c, strongSwan, OpenVPN, OPNsense
Config.php / AuthenticationFactory) with invented names and documentation
addresses.
"""

from __future__ import annotations

import asyncio

import netcontrol.routes.state as state
import pytest
import routes.database as db
from netcontrol import source_recollect as rc, syslog_rules as sr
from netcontrol.integrations.opnsense.normalize import build_snapshot, snapshot_addresses
from netcontrol.integrations.opnsense.sample import SAMPLE_URL, build_sample_raw
from netcontrol.routes import meraki_topology as topology, metrics_engine

HDR = "<134>1 2026-01-10T10:00:00+00:00 fw-a.example.com"

# (message, reason)
TRIGGERS = [
    # Gateway watcher (ident dpinger), RFC 5424 and RFC 3164.
    (
        f"{HDR} dpinger 4242 - - MONITOR: WAN_GW (Addr: 192.0.2.254 Alarm: none -> down RTT: 0.0 ms "
        "RTTd: 0.0 ms Loss: 100.0 %)",
        "gateway",
    ),
    (
        "<165>Jan 10 10:00:00 fw-a dpinger[4242]: ALERT: WAN2_GW (Addr: 198.51.100.1 Alarm: down -> none "
        "RTT: 12.3 ms RTTd: 1.1 ms Loss: 0.0 %)",
        "gateway",
    ),
    # dpinger itself.
    ("dpinger[311]: WAN_GW 192.0.2.254: Alarm latency 523000us stddev 1200us loss 21%", "gateway"),
    ("dpinger[311]: WAN_GW 192.0.2.254: Clear latency 9000us stddev 400us loss 0%", "gateway"),
    # CARP (kernel).
    ("<6>Jan 10 10:00:00 fw-a kernel: carp: 3@vtnet1: BACKUP -> MASTER (master timed out)", "carp"),
    (f"{HDR} kernel - - - carp: 3@vtnet1: MASTER -> BACKUP (more frequent advertisement received)", "carp"),
    ("kernel: carp: 5@igb0: INIT -> BACKUP (initialization complete)", "carp"),
    ("kernel: carp: demoted by 240 to 240 (sysctl)", "carp"),
    # IPsec (strongSwan charon).
    (
        "charon[812]: 12[IKE] <con1|7> IKE_SA con1[7] established between 192.0.2.1[fw-a]...203.0.113.9[203.0.113.9]",
        "vpn",
    ),
    ("charon[812]: 05[IKE] <con1|7> deleting IKE_SA con1[7] between 192.0.2.1[fw-a]...203.0.113.9[203.0.113.9]", "vpn"),
    ("charon[812]: 05[IKE] <con1|7> IKE_SA deleted", "vpn"),
    ("charon[812]: 09[IKE] <con1|7> CHILD_SA con1-net{12} closed", "vpn"),
    # OpenVPN instances.
    ("openvpn_client2[5511]: Initialization Sequence Completed", "vpn"),
    (f"{HDR} openvpn_client2 5511 - - SIGUSR1[soft,ping-restart] received, process restarting", "vpn"),
    ("openvpn_server1[61]: SIGTERM[hard,] received, process exiting", "vpn"),
    # Configuration save.
    ("config[1234]: config-event: new_config /conf/backup/config-1767000000.1234.xml", "config"),
    (
        f"{HDR} audit 3101 - - user ops@198.51.100.7 changed configuration to /conf/backup/config-1767000000.1234.xml "
        "in /api/routes/gateway/set ops@198.51.100.7 made changes",
        "config",
    ),
    # Suricata alerts (IDS "syslog alerts", IPS drop, eve over syslog): a read of the IDS alerts only.
    (
        "suricata[4711]: [1:9100002:1] PLEXUS SAMPLE Port scan from outside [Classification: Attempted "
        "Information Leak] [Priority: 2] {TCP} 198.51.100.99:40000 -> 203.0.113.10:22",
        "ids",
    ),
    (
        "suricata[4711]: [Drop] [1:9100001:3] PLEXUS SAMPLE Trojan beacon [Classification: A Network Trojan "
        "was detected] [Priority: 1] {TCP} 192.0.2.50:51234 -> 203.0.113.66:80",
        "ids",
    ),
    (
        f'{HDR} suricata 4711 - - {{"timestamp":"2026-11-20T10:15:30.512301+0000","event_type":"alert",'
        '"src_ip":"192.0.2.50","alert":{"signature_id":9100001,"severity":1}}',
        "ids",
    ),
]

NOT_TRIGGERS = [
    # The watcher reloading, a pending gateway with no data.
    "dpinger[4242]: Reloaded gateway watcher configuration on SIGHUP",
    # Kernel lines other than CARP transitions.
    "kernel: vtnet1: link state changed to UP",
    # strongSwan rekeys: CHILD_SA established / closing repeat on every rekey.
    "charon[812]: 12[IKE] <con1|7> CHILD_SA con1-net{13} established with SPIs c1a2b3c4_i c5d6e7f8_o and TS "
    "192.0.2.0/25 === 198.51.100.0/24",
    "charon[812]: 12[IKE] <con1|7> closing CHILD_SA con1-net{12} with SPIs c1a2b3c4_i (0 bytes) c5d6e7f8_o (0 bytes) "
    "and TS 192.0.2.0/25 === 198.51.100.0/24",
    # One road-warrior client of a server instance.
    "openvpn_server1[61]: alice/198.51.100.7:1194 SIGUSR1[soft,ping-restart] received, client-instance restarting",
    "openvpn_server1[61]: alice/198.51.100.7:1194 Peer Connection Initiated with [AF_INET]198.51.100.7:1194",
    "openvpn_server1[61]: alice/198.51.100.7:1194 Initialization Sequence Completed",
    # Logins, and the IOS XR configuration commit (its process is "config" too).
    "audit[3101]: user ops authenticated successfully for WebGui [using A + B] at 198.51.100.7",
    "config[65]: %MGBL-CONFIG-6-DB_COMMIT : Configuration committed by user 'ops'.",
    # Cisco and plain messages.
    "%LINK-3-UPDOWN: Interface GigabitEthernet0/7, changed state to down",
    "cron[99]: (root) CMD (/usr/local/sbin/configctl -d syslog archive)",
    # Suricata's own status lines and its other eve records are no alert.
    "suricata[4711]: [100171] <Notice> -- rule reload complete",
    'suricata[4711]: {"timestamp":"2026-11-20T10:15:30+0000","event_type":"stats"}',
]


@pytest.mark.parametrize(("message", "reason"), TRIGGERS)
def test_each_opnsense_state_change_is_a_recollect_trigger(message, reason):
    parsed = sr.parse_syslog_message(message)
    assert sr.recollect_reason(parsed) == reason
    # Never a built-in alert as well: the availability tracker owns these.
    assert [r.key for r in sr.merge_rules([]) if sr._evaluate(r, parsed)] == []
    # Nor a trigger of the inventory-host engine.
    assert (sr.is_config_change(parsed), sr.repoll_reason(parsed)) == (False, "")


@pytest.mark.parametrize("message", NOT_TRIGGERS)
def test_other_messages_start_no_recollect(message):
    assert sr.recollect_reason(sr.parse_syslog_message(message)) == ""


def test_every_reason_is_covered():
    assert {reason for _m, reason in TRIGGERS} == set(sr.RECOLLECT_REASONS)


# ── The firewall's addresses ─────────────────────────────────────────────────


@pytest.fixture(scope="module")
def snapshot() -> dict:
    return build_snapshot(build_sample_raw())


def test_snapshot_addresses_cover_the_api_interfaces_and_carp_vips(snapshot):
    found = snapshot_addresses(snapshot)
    assert found[0] == "192.0.2.1"  # the API address
    assert len(found) == len(set(found))
    assert "2001:db8:10::1" in found  # an interface's IPv6 address
    for vip in snapshot["ha"]["vips"]:
        for address in vip["addresses"]:
            assert address.split("/")[0] in found
    assert not any(a.startswith("fe80") for a in found)


def test_snapshot_addresses_of_an_empty_snapshot():
    assert snapshot_addresses({}) == []


# ── Source resolution ────────────────────────────────────────────────────────


@pytest.fixture
def clean():
    rc.reset_state()
    topology._SNAPSHOT_CACHE.clear()
    yield
    rc.reset_state()
    topology._SNAPSHOT_CACHE.clear()


async def _source(name: str = "fw-a", *, provider: str = "opnsense", key: str = "k:s", snap: dict | None = None) -> int:
    await db.init_db()
    org = await db.create_meraki_org(name, provider=provider, base_url=SAMPLE_URL, api_key=key)
    assert org
    if snap is not None:
        await db.create_meraki_snapshot(int(org["id"]), snap, built_by="test", duration_seconds=1.0)
    return int(org["id"])


async def test_a_firewall_that_is_no_inventory_host_is_found_by_its_addresses(clean, snapshot):
    org_ref = await _source(snap=snapshot)
    # Another provider and an OPNsense source without a key are left out.
    await _source("meraki-org", provider="meraki")
    await _source("fw-nokey", key="")
    mapping = await rc.build_source_map()
    assert mapping.sources_for("192.0.2.1", None) == {org_ref}
    assert mapping.sources_for("203.0.113.10", None) == {org_ref}
    assert mapping.sources_for("2001:db8:10:0::1", None) == {org_ref}
    assert mapping.sources_for("203.0.113.250", None) == frozenset()
    assert mapping.by_host == {}


async def test_an_inventory_host_maps_to_its_firewall(clean, snapshot):
    org_ref = await _source(snap=snapshot)
    group_id = await db.create_group("fw")
    host_id = await db.add_host(group_id, "fw-edge-1", "192.0.2.1", "opnsense")
    mapping = await rc.build_source_map()
    # A message from an address the snapshot does not list, resolved to the host.
    assert mapping.sources_for("198.51.100.200", host_id) == {org_ref}
    assert mapping.sources_for("198.51.100.200", host_id + 1) == frozenset()


async def test_a_source_without_a_snapshot_is_found_by_its_api_address(clean):
    org_ref = await _source()
    mapping = await rc.build_source_map()
    assert mapping.sources_for("192.0.2.1", None) == {org_ref}


async def test_the_map_is_cached(clean, monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(rc, "_clock", clock)
    builds: list[int] = []

    async def fake_build():
        builds.append(1)
        return rc.SourceMap(by_ip={"192.0.2.1": frozenset({7})})

    monkeypatch.setattr(rc, "build_source_map", fake_build)
    await rc.source_map()
    clock.t += rc.MAP_TTL_SECONDS - 1
    await rc.source_map()
    assert len(builds) == 1
    clock.t += 2
    await rc.source_map()
    assert len(builds) == 2


async def test_a_failed_map_build_keeps_the_receiver_going(clean, monkeypatch):
    async def broken():
        raise RuntimeError("db down")

    monkeypatch.setattr(rc, "build_source_map", broken)
    assert (await rc.source_map()).sources_for("192.0.2.1", None) == frozenset()


# ── Scheduling ───────────────────────────────────────────────────────────────


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def scheduler(monkeypatch, clean):
    """A fake clock whose sleep advances it, and runs recorded instead of
    collected (``outcomes`` says what each run returns)."""
    clock = _Clock()
    runs: list[tuple[int, float, list[str]]] = []
    outcomes: list[str | Exception] = []

    async def fake_sleep(seconds: float) -> None:
        clock.t += seconds
        await asyncio.sleep(0)

    async def fake_run(org_ref: int, reasons: set[str]) -> str:
        runs.append((org_ref, clock.t, sorted(reasons)))
        outcome = outcomes.pop(0) if outcomes else "completed"
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(rc, "_clock", clock)
    monkeypatch.setattr(rc, "_sleep", fake_sleep)
    monkeypatch.setattr(rc, "run_recollect", fake_run)
    return clock, runs, outcomes


async def _settle() -> None:
    while rc._tasks:
        await asyncio.gather(*list(rc._tasks.values()), return_exceptions=True)


async def test_a_burst_is_one_run_after_the_delay(scheduler):
    clock, runs, _outcomes = scheduler
    assert rc.note_recollect(1, "gateway") is True
    assert rc.note_recollect(1, "carp") is False
    assert rc.note_recollect(2, "vpn") is True
    assert rc.pending() == {1: ["carp", "gateway"], 2: ["vpn"]}
    await _settle()
    assert sorted(runs) == [(1, 1000.0 + rc.DELAY_SECONDS, ["carp", "gateway"]), (2, 1005.0, ["vpn"])]
    assert rc.pending() == {}


async def test_messages_in_the_cooldown_leave_one_trailing_run(scheduler):
    clock, runs, _outcomes = scheduler
    rc.note_recollect(1, "gateway")
    await _settle()
    started = runs[0][1]
    clock.t += 10
    assert rc.note_recollect(1, "gateway") is True
    assert rc.note_recollect(1, "config") is False
    await _settle()
    assert [r[1] for r in runs] == [started, started + rc.MIN_INTERVAL_SECONDS]
    assert runs[1][2] == ["config", "gateway"]
    # Long after: the delay again.
    clock.t += 1000
    rc.note_recollect(1, "vpn")
    before = clock.t
    await _settle()
    assert runs[2][1] == before + rc.DELAY_SECONDS


async def test_a_message_during_a_run_waits_out_the_interval(scheduler, monkeypatch):
    clock, runs, _outcomes = scheduler
    noted: list[bool] = []

    async def run_that_logs(org_ref: int, reasons: set[str]) -> str:
        runs.append((org_ref, clock.t, sorted(reasons)))
        if len(runs) == 1:
            clock.t += 30  # the collection takes a while; the firewall logs again meanwhile
            noted.append(rc.note_recollect(org_ref, "carp"))
        return "completed"

    monkeypatch.setattr(rc, "run_recollect", run_that_logs)
    rc.note_recollect(3, "carp")
    await _settle()
    assert noted == [True]
    assert [r[1] - runs[0][1] for r in runs] == [0.0, rc.MIN_INTERVAL_SECONDS]


async def test_a_busy_source_is_retried_and_a_failure_is_logged(scheduler, caplog):
    clock, runs, outcomes = scheduler
    outcomes.extend(["busy", RuntimeError("boom")])
    rc.note_recollect(4, "config")
    await _settle()
    assert [r[1] for r in runs] == [1005.0, 1005.0 + rc.BUSY_RETRY_SECONDS]
    assert runs[1][2] == ["config"]
    assert "failed" in caplog.text
    # The failed run counts for the interval; the next message still runs.
    clock.t += 1
    rc.note_recollect(4, "config")
    await _settle()
    assert runs[2][1] == runs[1][1] + rc.MIN_INTERVAL_SECONDS


async def test_a_source_is_collected_at_most_so_often_in_an_hour(scheduler):
    clock, runs, _outcomes = scheduler
    for _ in range(rc.MAX_RUNS_PER_HOUR + 1):
        rc.note_recollect(5, "gateway")
        await _settle()
    starts = [r[1] for r in runs]
    # One a minute up to the cap, then the next waits out the first one's hour.
    assert starts[: rc.MAX_RUNS_PER_HOUR] == [
        starts[0] + i * rc.MIN_INTERVAL_SECONDS for i in range(rc.MAX_RUNS_PER_HOUR)
    ]
    assert starts[-1] == starts[0] + rc.HOUR_SECONDS
    # A busy source collected nothing: that attempt is not one of the hour's runs.
    assert len(rc._run_times[5]) == rc.MAX_RUNS_PER_HOUR


async def test_events_are_scheduled_per_mapped_source(scheduler, monkeypatch):
    _clock, runs, _outcomes = scheduler

    async def fake_map():
        return rc.SourceMap(by_ip={"192.0.2.1": frozenset({5})}, by_host={9: frozenset({5, 6})})

    monkeypatch.setattr(rc, "source_map", fake_map)
    scheduled = await rc.schedule_for_events(
        [("192.0.2.1", None, "gateway"), ("198.51.100.9", 9, "carp"), ("203.0.113.1", None, "vpn")]
    )
    assert scheduled == 2
    assert rc.pending() == {5: ["carp", "gateway"], 6: ["carp"]}


# ── The collection itself ────────────────────────────────────────────────────


async def test_a_run_collects_through_the_build_path(clean, monkeypatch):
    org_ref = await _source()
    calls: list[tuple[int, str]] = []

    async def fake_collect(org: dict, user: str) -> str | None:
        calls.append((int(org["id"]), user))
        return "completed"

    monkeypatch.setattr(topology, "collect_source_now", fake_collect)
    assert await rc.run_recollect(org_ref, {"gateway"}) == "completed"
    assert calls == [(org_ref, rc.RECOLLECT_USER)]

    async def busy(org: dict, user: str) -> str | None:
        return None

    monkeypatch.setattr(topology, "collect_source_now", busy)
    assert await rc.run_recollect(org_ref, {"gateway"}) == "busy"
    other = await _source("meraki-org", provider="meraki")
    assert await rc.run_recollect(other, {"gateway"}) == "skipped"
    assert await rc.run_recollect(999999, {"gateway"}) == "skipped"


async def test_collect_source_now_never_runs_two_collections_of_a_source(monkeypatch):
    builds: list[str] = []

    async def fake_build(job_id: str, org: dict, user: str) -> None:
        builds.append(user)
        topology._running_builds.pop(org["id"], None)

    monkeypatch.setattr(topology, "_run_build", fake_build)
    org = {"id": 424242, "name": "fw-x"}
    topology._running_builds[424242] = "job-running"
    try:
        assert await topology.collect_source_now(org, "syslog") is None
        assert builds == []
    finally:
        topology._running_builds.pop(424242, None)
    await topology.collect_source_now(org, "syslog")
    assert builds == ["syslog"]


# ── The receiver and the switch ──────────────────────────────────────────────


@pytest.fixture
def recorded(monkeypatch, clean):
    events: list[list] = []

    async def fake_schedule(found):
        events.append(list(found))
        return len(events[-1])

    monkeypatch.setattr(rc, "schedule_for_events", fake_schedule)
    monkeypatch.setattr(state, "EVENT_RECEIVER_CONFIG", {})
    return events


GW_DOWN = TRIGGERS[0][0]
CARP_DEMOTED = "kernel: carp: demoted by 240 to 240 (sysctl)"
LINK_DOWN = "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down"


async def test_the_writer_hands_hostless_opnsense_messages_to_the_trigger(recorded, monkeypatch):
    seen: list[list] = []

    async def fake_batch(rows):
        seen.append(list(rows))
        return {}

    monkeypatch.setattr(sr, "process_syslog_batch", fake_batch)
    await metrics_engine._evaluate_syslog_rules(
        [
            ("203.0.113.10", None, "syslog", "16", "info", "", GW_DOWN, ""),
            ("192.0.2.10", 7, "syslog", "16", "info", "", CARP_DEMOTED, ""),
            ("192.0.2.10", 7, "syslog", "23", "info", "", LINK_DOWN, ""),
            ("192.0.2.10", 7, "trap", "", "info", "1.3.6", "trap", ""),
        ]
    )
    # The rule engine still sees only inventory hosts' messages.
    assert seen == [[(7, CARP_DEMOTED), (7, LINK_DOWN)]]
    assert recorded == [[("203.0.113.10", None, "gateway"), ("192.0.2.10", 7, "carp")]]


async def test_a_trigger_failure_is_logged_not_raised(monkeypatch, caplog):
    async def broken(rows):
        raise RuntimeError("trigger failure")

    monkeypatch.setattr(sr, "process_recollect_batch", broken)
    await metrics_engine._evaluate_syslog_rules([("203.0.113.10", None, "syslog", "16", "info", "", GW_DOWN, "")])
    assert "re-collect trigger failed" in caplog.text


async def test_the_switch_turns_the_trigger_off(recorded):
    state.EVENT_RECEIVER_CONFIG["recollect_trigger"] = False
    assert await sr.process_recollect_batch([("203.0.113.10", None, GW_DOWN)]) == 0
    assert recorded == []
    state.EVENT_RECEIVER_CONFIG["recollect_trigger"] = True
    assert await sr.process_recollect_batch([("203.0.113.10", None, GW_DOWN)]) == 1


def test_the_switch_is_on_by_default():
    assert state.EVENT_RECEIVER_DEFAULTS["recollect_trigger"] is True
    assert state._sanitize_event_receiver_config({"recollect_trigger": 0})["recollect_trigger"] is False


async def test_explain_says_why_a_message_starts_a_recollect():
    await db.init_db()
    sr.invalidate_rules_cache()
    found = await sr.explain_message(GW_DOWN)
    assert (found["program"], found["recollect"], found["matches"]) == ("dpinger", "gateway", [])
    found = await sr.explain_message("config[1234]: config-event: new_config /conf/backup/config-1.xml")
    assert found["recollect"] == "config"
    found = await sr.explain_message("%LINK-3-UPDOWN: Interface Gi0/1, changed state to down")
    assert (found["program"], found["recollect"]) == ("", "")
