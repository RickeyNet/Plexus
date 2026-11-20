"""Syslog rule state restored at startup (``syslog_rules.restore_state``) and
the rule activity analysis (``netcontrol.syslog_activity``, ``GET
/api/monitoring/syslog-rules/activity``).

Every message is invented; hostnames and addresses are made up
(documentation ranges).
"""

from __future__ import annotations

import asyncio
import logging

import netcontrol.routes.state as state
import pytest
import routes.database as db
from netcontrol import syslog_activity as activity, syslog_rules as sr

from mcp_helpers import admin_client
from test_object_changes import _scoped_client
from test_syslog_rules import DOWN, PREFIX, _Clock, _host, _open

ACTIVITY = PREFIX + "/activity"
CONFIG = "%SYS-5-CONFIG_I: Configured from console by ops on vty0 (192.0.2.50)"


async def _sql(statement: str, params: tuple = ()) -> None:
    conn = await db.get_db()
    try:
        await conn.execute(statement, params)
        await conn.commit()
    finally:
        await conn.close()


async def _store(message: str, host_id: int | None, ago: int = 0, source_ip: str = "192.0.2.10") -> None:
    """A stored syslog message received ``ago`` seconds before now."""
    await _sql(
        "INSERT INTO trap_syslog_events (source_ip, host_id, event_type, message, received_at) "
        "VALUES (?, ?, 'syslog', ?, datetime('now', ?))",
        (source_ip, host_id, message, f"-{int(ago)} seconds"),
    )


@pytest.fixture
def restore(monkeypatch):
    """Monitoring and every switch on, a fake clock, re-polls and config
    changes recorded instead of run."""
    sr.reset_state()
    clock = _Clock()
    monkeypatch.setattr(sr, "_clock", clock)
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", True)
    monkeypatch.setattr(
        state,
        "EVENT_RECEIVER_CONFIG",
        {"syslog_alerts": True, "config_change_trigger": True, "repoll_trigger": True},
    )
    repolls: list[int] = []
    changes: list[int] = []
    monkeypatch.setattr(sr, "schedule_repoll", lambda host_id, *_a, **_k: repolls.append(host_id) or True)
    monkeypatch.setattr(sr, "note_config_change", changes.append)
    yield clock, repolls, changes
    sr.reset_state()


# ── Restore at startup ───────────────────────────────────────────────────────


async def test_restored_counters_make_the_next_down_raise(restore):
    clock, repolls, changes = restore
    _gid, host_id = await _host()
    await _store(DOWN, host_id, ago=240)
    await _store(DOWN, host_id, ago=120)
    out = await sr.restore_state()
    assert out == {"messages": 2, "counters": 1, "config_changes": 0}
    assert list(sr._counters) == [("link_flap", host_id, "GigabitEthernet0/7")]
    # Counted at their age before now.
    assert list(sr._counters[("link_flap", host_id, "GigabitEthernet0/7")]) == pytest.approx(
        [clock.t - 240, clock.t - 120], abs=5
    )
    assert (await sr.process_syslog_batch([(host_id, DOWN)]))["raised"] == 1
    assert f"syslog:link_flap:{host_id}:GigabitEthernet0/7" in await _open(host_id)


async def test_restore_raises_nothing_and_schedules_nothing(restore, caplog):
    _clock, repolls, changes = restore
    _gid, host_id = await _host()
    for ago in (300, 200, 100):
        await _store(DOWN, host_id, ago=ago)
    await _store("%BGP-5-NBR_RESET: Neighbor 203.0.113.2 reset", host_id, ago=50)
    with caplog.at_level(logging.INFO, logger="plexus.syslog_rules"):
        out = await sr.restore_state()
    assert out["messages"] == 4
    assert await _open(host_id) == {}
    assert repolls == [] and changes == []
    assert "restored 1 threshold counters from 4 stored messages" in caplog.text


async def test_messages_older_than_the_window_are_ignored(restore, monkeypatch):
    _gid, host_id = await _host()
    # The longest enabled threshold window is 600 s (link_flap).
    await _store(DOWN, host_id, ago=900)
    await _store(DOWN, host_id, ago=700)
    assert (await sr.restore_state())["messages"] == 0
    # The window is capped.
    monkeypatch.setattr(sr, "RESTORE_WINDOW_MAX_SECONDS", 100)
    await _store(DOWN, host_id, ago=200)
    await _store(DOWN, host_id, ago=10)
    assert (await sr.restore_state())["messages"] == 1
    # Messages of unknown sources are not replayed.
    await _store(DOWN, None, ago=20, source_ip="203.0.113.9")
    sr.reset_state()
    assert (await sr.restore_state())["messages"] == 1


async def test_a_stored_clear_message_drops_the_counter(restore):
    _gid, host_id = await _host()
    await db.create_syslog_alert_rule(
        sr.clean_custom_rule(
            {
                "name": "Boom",
                "match_type": "contains",
                "pattern": "boom",
                "clear_pattern": "calm",
                "threshold_count": 2,
                "threshold_window_seconds": 600,
            }
        )
    )
    sr.invalidate_rules_cache()
    await _store("%X-1-Y: boom", host_id, ago=100)
    await _store("%X-1-Y: calm", host_id, ago=50)
    await sr.restore_state()
    assert not [k for k in sr._counters if k[0].startswith("custom_")]
    assert (await sr.process_syslog_batch([(host_id, "%X-1-Y: boom")]))["raised"] == 0


async def test_no_threshold_rule_enabled_skips_the_counters(restore):
    _gid, host_id = await _host()
    await db.set_syslog_builtin_override("link_flap", False, "warning")
    await db.set_syslog_builtin_override("auth_failure", False, "warning")
    sr.invalidate_rules_cache()
    await _store(DOWN, host_id, ago=60)
    assert await sr.restore_state() == {"messages": 0, "counters": 0, "config_changes": 0}


@pytest.mark.parametrize("switch", ["monitoring", "syslog_alerts"])
async def test_counters_need_monitoring_and_the_alert_switch(restore, monkeypatch, switch):
    _gid, host_id = await _host()
    if switch == "monitoring":
        monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", False)
    else:
        state.EVENT_RECEIVER_CONFIG["syslog_alerts"] = False
    await _store(DOWN, host_id, ago=60)
    assert await sr.restore_state() == {"messages": 0, "counters": 0, "config_changes": 0}


async def test_a_pending_config_change_is_rearmed(restore):
    _clock, _repolls, changes = restore
    _g1, pending = await _host("sw-1", "192.0.2.11")
    _g2, backed_up = await _host("sw-2", "192.0.2.12")
    _g3, stale = await _host("sw-3", "192.0.2.13")
    _g4, old = await _host("sw-4", "192.0.2.14")
    await _store(CONFIG, pending, ago=40)
    await _store(DOWN, pending, ago=20)  # newer, but no configuration change
    # Backed up after its message: nothing to do.
    await _store(CONFIG, backed_up, ago=60)
    await db.create_config_backup(None, backed_up, "hostname sw-2\n", capture_method="syslog")
    # Backed up before its message: re-armed.
    await _store(CONFIG, stale, ago=30)
    backup_id = await db.create_config_backup(None, stale, "hostname sw-3\n")
    await _sql(
        "UPDATE config_backups SET captured_at = datetime('now', '-200 seconds'), "
        "checked_at = datetime('now', '-200 seconds') WHERE id = ?",
        (backup_id,),
    )
    # Older than the cooldown: its run would have started already.
    await _store(CONFIG, old, ago=int(sr.CONFIG_COOLDOWN_SECONDS) + 60)
    out = await sr.restore_state()
    assert out["config_changes"] == 2
    assert sorted(changes) == sorted([pending, stale])


async def test_config_changes_follow_their_switch(restore, monkeypatch):
    _clock, _repolls, changes = restore
    _gid, host_id = await _host()
    await _store(CONFIG, host_id, ago=30)
    state.EVENT_RECEIVER_CONFIG["config_change_trigger"] = False
    assert (await sr.restore_state())["config_changes"] == 0 and changes == []
    # The configuration trigger does not need monitoring.
    state.EVENT_RECEIVER_CONFIG["config_change_trigger"] = True
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", False)
    assert (await sr.restore_state())["config_changes"] == 1 and changes == [host_id]


async def test_restore_never_raises(restore, monkeypatch, caplog):
    async def broken(*_args, **_kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(db, "list_syslog_messages_since", broken)
    out = await sr.restore_state()
    assert out == {"messages": 0, "counters": 0, "config_changes": 0}
    assert "state restore failed: database unavailable" in caplog.text


async def test_the_restore_rearms_a_real_config_run(monkeypatch):
    """Without the fixture's stub: the run is scheduled one debounce out."""
    sr.reset_state()
    monkeypatch.setattr(state, "EVENT_RECEIVER_CONFIG", {"config_change_trigger": True})
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", False)
    runs: list[int] = []

    async def fake_run(host_id: int) -> dict:
        runs.append(host_id)
        return {}

    monkeypatch.setattr(sr, "run_config_change", fake_run)
    monkeypatch.setattr(sr, "CONFIG_DEBOUNCE_SECONDS", 0.01)
    _gid, host_id = await _host()
    await _store(CONFIG, host_id, ago=10)
    assert (await sr.restore_state())["config_changes"] == 1
    while sr._config_tasks:
        await asyncio.gather(*list(sr._config_tasks.values()), return_exceptions=True)
    assert runs == [host_id]
    sr.reset_state()


# ── Activity analysis ────────────────────────────────────────────────────────


@pytest.fixture
def fresh_rules():
    sr.reset_state()
    yield
    sr.reset_state()


async def test_matches_per_rule_and_trigger(fresh_rules):
    _g1, ios = await _host("sw-1", "192.0.2.11", "cisco_ios")
    _g2, nxos = await _host("sw-2", "192.0.2.12", "cisco_nxos")
    await _store(DOWN, ios, ago=300)
    await _store(DOWN, nxos, ago=200)
    await _store("%OSPF-5-ADJCHG: Process 1, Nbr 198.51.100.2 on Gi0/1 from LOADING to FULL, Loading Done", ios, 150)
    await _store(CONFIG, ios, ago=100)
    await _store("%SYS-5-RELOAD: Reload requested by ops on vty0 (192.0.2.50).", nxos, ago=90)
    await _store("<6>Jan 10 10:00:00 fw-a kernel: carp: 3@vtnet1: BACKUP -> MASTER", nxos, ago=80)
    out = await activity.analyze(24)
    assert (out["scanned"], out["matched"], out["unmatched"], out["unknown_source"]) == (6, 6, 0, 0)
    assert out["truncated"] is False and out["limit"] == activity.SCAN_LIMIT and out["hours"] == 24
    rules = {r["key"]: r for r in out["rules"]}
    assert set(rules) == {"link_flap", "ospf_neighbor"}
    assert (rules["link_flap"]["raised"], rules["link_flap"]["cleared"], rules["link_flap"]["hosts"]) == (2, 0, 2)
    assert (rules["ospf_neighbor"]["raised"], rules["ospf_neighbor"]["cleared"]) == (0, 1)
    # The newest down (200 s ago) is older than the OSPF clear (150 s ago).
    assert "" < rules["link_flap"]["last_at"] < rules["ospf_neighbor"]["last_at"]
    # The link downs are re-polls too.
    assert out["triggers"] == {"config_change": 1, "repoll": 3, "recollect": 1}
    assert out["oldest_at"] and out["oldest_at"] <= rules["link_flap"]["last_at"]
    assert out["unmatched_tags"] == [] and out["unknown_sources"] == []


async def test_unmatched_messages_are_grouped(fresh_rules):
    _g1, ios = await _host("sw-1", "192.0.2.11", "cisco_ios")
    _g2, nxos = await _host("sw-2", "192.0.2.12", "cisco_nxos")
    acl = "%SEC-6-IPACCESSLOGP: list 101 denied tcp 198.51.100.7(5000) -> 192.0.2.1(22), 1 packet"
    await _store(acl, ios, ago=300)
    await _store(acl, nxos, ago=200)
    newest_acl = "%SEC-6-IPACCESSLOGP: list 102 denied udp 198.51.100.8(53) -> 192.0.2.1(53), 1 packet " + "x" * 400
    await _store(newest_acl, ios, ago=100)
    await _store("<14>Jan 10 10:00:00 sw-1 cron[99]: job started", ios, ago=90)
    await _store("<14>Jan 10 10:00:00 sw-1 CRON[99]: job done", ios, ago=80)
    await _store("just some text", ios, ago=70)
    await _store("%PLATFORM-2-FAN_REMOVED: Fan module 2 removed", nxos, ago=60)
    out = await activity.analyze(24)
    assert (out["matched"], out["unmatched"], out["scanned"]) == (0, 7, 7)
    groups = {(g["tag"], g["program"]): g for g in out["unmatched_tags"]}
    assert [(g["tag"], g["program"], g["count"]) for g in out["unmatched_tags"]] == [
        ("SEC-IPACCESSLOGP", "", 3),
        ("", "cron", 2),
        ("", "", 1),
        ("PLATFORM-FAN_REMOVED", "", 1),
    ]
    acl_group = groups[("SEC-IPACCESSLOGP", "")]
    assert acl_group["raw_tag"] == "SEC-6-IPACCESSLOGP"
    assert acl_group["hosts"] == 2 and acl_group["device_types"] == ["cisco_ios", "cisco_nxos"]
    assert acl_group["sample"] == newest_acl[: activity.SAMPLE_MAX]
    assert acl_group["related"] == ""
    cron = groups[("", "cron")]
    assert (cron["raw_tag"], cron["hosts"], cron["sample"]) == ("", 1, "<14>Jan 10 10:00:00 sw-1 CRON[99]: job done")
    assert cron["last_at"] >= acl_group["last_at"]
    assert groups[("", "")]["sample"] == "just some text"
    assert groups[("PLATFORM-FAN_REMOVED", "")]["related"] == "fan"
    assert not any(g["known_tag"] for g in out["unmatched_tags"])


async def test_a_tag_a_builtin_handles_is_marked_known(fresh_rules):
    _g, ios = await _host("sw-1", "192.0.2.11", "cisco_ios")
    # The up message carries the tag of the link_flap rule, whose pattern
    # wants "to down"; the copy message that of the configuration trigger.
    await _store("%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up", ios, ago=60)
    await _store("%ASA-5-111010: User 'ops', running 'CLI' from IP 192.0.2.50, executed 'show version'", ios, ago=50)
    await _store("%BGP-6-NEXTHOP_CHANGE: next hop changed for 198.51.100.0/24", ios, ago=40)
    out = await activity.analyze(24)
    assert out["matched"] == 0
    groups = {g["tag"]: (g["related"], g["known_tag"]) for g in out["unmatched_tags"]}
    assert groups == {
        "LINK-UPDOWN": ("link_flap", True),
        "ASA-111010": ("config_change", True),
        "BGP-NEXTHOP_CHANGE": ("bgp_neighbor", False),
    }
    assert sr.tag_owner("SYS-RESTART") == "repoll" and sr.tag_owner("CHASSISD_SNMP_TRAP6") == "power_supply"
    assert sr.tag_owner("") == "" and sr.tag_owner("SEC-IPACCESSLOGP") == ""


async def test_unknown_sources_and_the_top_lists(fresh_rules, monkeypatch):
    _gid, host_id = await _host()
    for n in range(3):
        await _store(DOWN, None, ago=100 + n, source_ip="203.0.113.9")
    await _store(DOWN, None, ago=50, source_ip="203.0.113.8")
    await _store("%A-1-ONE: x", host_id, ago=40)
    await _store("%B-1-TWO: x", host_id, ago=30)
    await _store("%B-1-TWO: y", host_id, ago=20)
    monkeypatch.setattr(activity, "UNMATCHED_TOP", 1)
    monkeypatch.setattr(activity, "UNKNOWN_SOURCES_TOP", 1)
    out = await activity.analyze(24)
    assert out["unknown_source"] == 4 and out["scanned"] == 7
    assert [(s["source_ip"], s["count"]) for s in out["unknown_sources"]] == [("203.0.113.9", 3)]
    assert out["unknown_sources"][0]["last_at"]
    assert [g["tag"] for g in out["unmatched_tags"]] == ["B-TWO"]
    # Messages of unknown sources are not run through the rules.
    assert out["rules"] == [] and out["triggers"]["repoll"] == 0


async def test_the_scan_stops_at_its_limit(fresh_rules, monkeypatch):
    _gid, host_id = await _host()
    monkeypatch.setattr(activity, "SCAN_LIMIT", 3)
    monkeypatch.setattr(activity, "PAGE_SIZE", 2)
    for n in range(3):
        await _store(f"%A-1-N{n}: x", host_id, ago=100 - n)
    out = await activity.analyze(24)
    assert (out["scanned"], out["truncated"], out["limit"]) == (3, False, 3)
    for n in range(2):
        await _store(f"%A-1-M{n}: x", host_id, ago=10 - n)
    out = await activity.analyze(24)
    assert (out["scanned"], out["truncated"]) == (3, True)
    # Newest first: the two oldest were left out.
    assert {g["tag"] for g in out["unmatched_tags"]} == {"A-M0", "A-M1", "A-N2"}


async def test_the_window(fresh_rules):
    _gid, host_id = await _host()
    await _store("%A-1-OLD: x", host_id, ago=2 * 3600)
    await _store("%A-1-NEW: x", host_id, ago=60)
    assert [g["tag"] for g in (await activity.analyze(1))["unmatched_tags"]] == ["A-NEW"]
    assert (await activity.analyze(3))["scanned"] == 2
    assert (await activity.analyze(1))["oldest_at"] > ""


@pytest.mark.parametrize(
    ("tag", "program", "sample", "related"),
    [
        ("OSPFV3-NBRSTATE", "", "", "ospf_neighbor"),
        ("ROUTING-BGP-NOTIFICATION", "", "", "bgp_neighbor"),
        ("LINK-CHANGED", "", "", "link_flap"),
        ("LINEPROTO-UPDOWN", "", "", "link_flap"),
        ("ETHPORT-IF_DOWN_ADMIN_DOWN", "", "", "link_flap"),
        ("PM-PORT_STATE_CHANGE", "", "", "link_flap"),
        ("PLATFORM-PS_FAIL_X", "", "", "power_supply"),
        ("ENVMON-POWER_SUPPLY_X", "", "", "power_supply"),
        ("IOSXE_PEM-PEMCHASFSERR", "", "", "power_supply"),
        ("IOSXE_PEM-FANFAIL_X", "", "", "fan"),
        ("ENVMON-FAN_FAIL", "", "", "fan"),
        ("SEC_LOGIN-LOGIN_SUCCESS", "", "", "auth_failure"),
        ("AAA-AUTHEN_FAIL", "", "", "auth_failure"),
        ("", "sshd", "sshd[12]: Failed password for ops from 198.51.100.7 port 4022 ssh2", "auth_failure"),
        ("PARSER-CFGLOG_LOGGEDCMD", "", "", ""),
        ("SYS-CONFIG_R", "", "", "config_change"),
        ("UI_COMMIT_PROGRESS", "", "", "config_change"),
        ("SYS-RESTART_X", "", "", "repoll"),
        ("UI_REBOOT_X", "", "", "repoll"),
        ("", "kernel", "kernel: ix0: link state changed to DOWN", "link_flap"),
        # Word boundaries: no accidental hits inside other words.
        ("MCAST-FANOUT_LIMIT", "", "", ""),
        ("SEC-IPACCESSLOGP", "", "", ""),
        ("", "", "", ""),
    ],
)
def test_related_hints(tag, program, sample, related):
    assert activity.related_rule(tag, program, sample) == related


# ── API ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def admin(monkeypatch, request):
    sr.reset_state()
    return admin_client(monkeypatch, request)


def test_the_route_validates_hours(admin):
    assert admin.get(ACTIVITY, params={"hours": 0}).status_code == 422
    assert admin.get(ACTIVITY, params={"hours": 169}).status_code == 422
    resp = admin.get(ACTIVITY)
    assert resp.status_code == 200, resp.text
    assert resp.json()["hours"] == 24
    assert admin.get(ACTIVITY, params={"hours": 168}).json()["hours"] == 168


def test_a_group_limited_caller_sees_only_their_groups(admin, monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})
    mine, mine_host = asyncio.run(_host("sw-mine", "192.0.2.21"))
    _other, other_host = asyncio.run(_host("sw-other", "192.0.2.22"))
    asyncio.run(_store("%A-1-MINE: x", mine_host, ago=60))
    asyncio.run(_store("%A-1-OTHER: x", other_host, ago=50))
    asyncio.run(_store("%A-1-STRANGER: x", None, ago=40, source_ip="203.0.113.9"))
    everything = admin.get(ACTIVITY).json()
    assert (everything["scanned"], everything["unknown_source"]) == (3, 1)
    scoped = _scoped_client(admin, "syslog-scoped", mine, ["monitoring"])
    resp = scoped.get(ACTIVITY)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body["scanned"], body["unknown_source"], body["unknown_sources"]) == (1, 0, [])
    assert [g["tag"] for g in body["unmatched_tags"]] == ["A-MINE"]
