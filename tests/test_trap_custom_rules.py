"""Custom SNMP trap rules, the CISCO-SYSLOG-MIB ``clogMessageGenerated``
bridge to the syslog rules, and the trap threshold counters restored at
startup (``netcontrol.trap_rules``, ``/api/monitoring/trap-rules``,
migration 0138).

Every trap datagram is invented and built with pysnmp the way an agent
builds it; the enterprise OID 1.3.6.1.4.1.32473 is the documentation
enterprise number (RFC 5612), names and addresses are made up
(documentation ranges).
"""

from __future__ import annotations

import logging

import netcontrol.routes.state as state
import pytest
import routes.database as db
from netcontrol import syslog_rules as sr, trap_rules as tr
from netcontrol.routes.snmp import decode_snmp_trap
from netcontrol.snmp_traps import name_trap

from mcp_helpers import user_client
from test_snmp_traps import (  # noqa: F401 - admin and engine are fixtures
    IF,
    LINK_DOWN,
    LINK_UP,
    PREFIX,
    _host,
    _open,
    _receive,
    admin,
    engine,
    named,
    v1,
    v2c,
)

EXAMPLE = "1.3.6.1.4.1.32473"
DISK_TRAP = f"{EXAMPLE}.2.0.5"
DISK_OK_TRAP = f"{EXAMPLE}.2.0.6"
VOLUME = f"{EXAMPLE}.1.3.1.2"
LEVEL = f"{EXAMPLE}.1.3.1.3"
AUTH = v2c("1.3.6.1.6.3.1.1.5.5")

# CISCO-SYSLOG-MIB clogMessageGenerated and its clogHistTable columns.
CLOG = "1.3.6.1.4.1.9.9.41.1.2.3.1"
CLOG_TRAP = "1.3.6.1.4.1.9.9.41.2.0.1"


def disk(trap: str = DISK_TRAP, volume: str = "/var", level: str = "high", index: int = 4) -> bytes:
    return v2c(trap, [(f"{VOLUME}.{index}", volume), (f"{LEVEL}.{index}", level)])


def clog(facility: str, severity: int, mnemonic: str, text: str, *, index: int = 17) -> bytes:
    return v2c(
        CLOG_TRAP,
        [
            (f"{CLOG}.2.{index}", facility),
            (f"{CLOG}.3.{index}", severity),
            (f"{CLOG}.4.{index}", mnemonic),
            (f"{CLOG}.5.{index}", text),
            (f"{CLOG}.6.{index}", 4242),
        ],
    )


def rule(**body) -> sr.Rule:
    return tr.draft_rule({"name": "r", "pattern": DISK_TRAP, **body})


# ── Validation ───────────────────────────────────────────────────────────────


def test_a_rule_is_cleaned_to_its_stored_form():
    values = tr.clean_custom_trap_rule(
        {
            "name": " Disk ",
            "pattern": "linkdown, .1.3.6.1.4.1.32473.2.*, linkDown",
            "clear_pattern": "LINKUP",
            "severity": "critical",
            "threshold_count": 2,
            "trap_match": {
                "conditions": [{"object": "ifdescr", "op": "contains", "value": " Gi "}],
                "clear_conditions": [{"object": f".{IF}.7", "value": "up"}],
                "instance": {"object": "ifIndex", "part": "index"},
            },
        }
    )
    assert values == {
        "name": "Disk",
        "enabled": True,
        "severity": "critical",
        "threshold_count": 2,
        "threshold_window_seconds": 300,
        "auto_resolve_minutes": 0,
        "match_type": "trap",
        "pattern": f"linkDown, {EXAMPLE}.2.*",
        "clear_pattern": "linkUp",
        "trap_match": {
            "conditions": [{"object": "ifDescr", "op": "contains", "value": "Gi"}],
            "clear_conditions": [{"object": f"{IF}.7", "op": "equals", "value": "up"}],
            "instance": {"object": "ifIndex", "part": "index"},
        },
    }
    # No instance: one alert per device.
    assert tr.clean_custom_trap_rule({"name": "x", "pattern": DISK_TRAP})["trap_match"]["instance"] == {
        "object": "",
        "part": "value",
    }


@pytest.mark.parametrize(
    ("body", "error"),
    [
        ({"pattern": DISK_TRAP}, "needs a name"),
        ({"name": "x"}, "needs a trap"),
        ({"name": "x", "pattern": " , "}, "needs a trap"),
        ({"name": "x", "pattern": "noSuchTrap"}, "registry does not know: noSuchTrap"),
        ({"name": "x", "pattern": "1.3.6..1"}, "not a dotted OID"),
        ({"name": "x", "pattern": "1.3.x.*"}, "OID prefix that is not a dotted OID"),
        ({"name": "x", "pattern": "1.3.٦"}, "not a dotted OID"),  # an Arabic-Indic digit
        ({"name": "x", "pattern": "1.3." + "1" * 400 + "!"}, "not a dotted OID"),
        ({"name": "x", "pattern": "1" * 501}, "longer than 500"),
        ({"name": "x", "pattern": DISK_TRAP, "clear_pattern": "nope"}, "clearing trap names a trap"),
        ({"name": "x", "pattern": DISK_TRAP, "severity": "loud"}, "severity must be"),
        ({"name": "x", "pattern": DISK_TRAP, "threshold_count": 0}, "threshold_count must be"),
        ({"name": "x", "pattern": DISK_TRAP, "trap_match": []}, "trap_match must be an object"),
        ({"name": "x", "pattern": DISK_TRAP, "trap_match": {"conditions": {}}}, "must be a list"),
        ({"name": "x", "pattern": DISK_TRAP, "trap_match": {"conditions": ["a"]}}, "must be an object"),
        (
            {"name": "x", "pattern": DISK_TRAP, "trap_match": {"conditions": [{"object": VOLUME}] * 11}},
            "at most 10",
        ),
        (
            {"name": "x", "pattern": DISK_TRAP, "trap_match": {"conditions": [{"object": VOLUME, "op": "like"}]}},
            "op must be one of",
        ),
        (
            {"name": "x", "pattern": DISK_TRAP, "trap_match": {"conditions": [{"object": VOLUME, "value": ""}]}},
            "needs a value",
        ),
        (
            {"name": "x", "pattern": DISK_TRAP, "trap_match": {"conditions": [{"object": VOLUME, "value": "v" * 201}]}},
            "longer than 200",
        ),
        (
            {
                "name": "x",
                "pattern": DISK_TRAP,
                "trap_match": {"conditions": [{"object": VOLUME, "op": "regex", "value": "(?<=a)b"}]},
            },
            "not a valid regular expression",
        ),
        (
            {
                "name": "x",
                "pattern": DISK_TRAP,
                "trap_match": {"conditions": [{"object": "noSuchObject", "value": "1"}]},
            },
            "object the registry does not know: noSuchObject",
        ),
        (
            {"name": "x", "pattern": DISK_TRAP, "trap_match": {"conditions": [{"object": "1.3..6", "value": "1"}]}},
            "is not a dotted OID",
        ),
        (
            {"name": "x", "pattern": DISK_TRAP, "trap_match": {"clear_conditions": [{"object": VOLUME, "value": "1"}]}},
            "need a clearing trap",
        ),
        ({"name": "x", "pattern": DISK_TRAP, "trap_match": {"instance": "ifIndex"}}, "instance must be an object"),
        (
            {"name": "x", "pattern": DISK_TRAP, "trap_match": {"instance": {"object": VOLUME, "part": "oid"}}},
            "instance part must be one of",
        ),
    ],
)
def test_invalid_rules_are_refused(body, error):
    with pytest.raises(sr.RuleError, match=error):
        tr.clean_custom_trap_rule(body)


# ── Matching ─────────────────────────────────────────────────────────────────


def test_a_rule_matches_by_name_oid_or_prefix():
    down = named(LINK_DOWN)
    assert sr.evaluate_rule(rule(pattern="linkDown"), down) == {"action": "raise", "instance": ""}
    assert sr.evaluate_rule(rule(pattern="1.3.6.1.6.3.1.1.5.3"), down) == {"action": "raise", "instance": ""}
    assert sr.evaluate_rule(rule(pattern="1.3.6.1.6.3.1.1.5.*"), down) == {"action": "raise", "instance": ""}
    assert sr.evaluate_rule(rule(pattern="1.3.6.1.6.3.1.1.4.*"), down) is None
    assert sr.evaluate_rule(rule(pattern="linkUp"), down) is None
    # A trap the registry does not name: by its OID only.
    unknown = named(disk())
    assert unknown.name == ""
    assert sr.evaluate_rule(rule(), unknown) == {"action": "raise", "instance": ""}
    assert sr.evaluate_rule(rule(pattern=f"{EXAMPLE}.*"), unknown) is not None
    # A v1 trap's enterprise.0.specific also matches the notification OID.
    v1_trap = named(v1(f"{EXAMPLE}.2", 5, [(f"{VOLUME}.4", "/var")]))
    assert v1_trap.trap_oid == f"{EXAMPLE}.2.0.5"
    assert sr.evaluate_rule(rule(pattern=f"{EXAMPLE}.2.5"), v1_trap) is not None


def test_conditions_and_instances():
    trap = named(disk(volume="/var/log", level="critical"))
    equals = {"conditions": [{"object": LEVEL, "op": "equals", "value": "CRITICAL"}]}
    assert sr.evaluate_rule(rule(trap_match=equals), trap) is not None
    assert sr.evaluate_rule(rule(trap_match={"conditions": [{"object": LEVEL, "value": "crit"}]}), trap) is None
    contains = {"conditions": [{"object": VOLUME, "op": "contains", "value": "/LOG"}]}
    assert sr.evaluate_rule(rule(trap_match=contains), trap) is not None
    regex = {"conditions": [{"object": VOLUME, "op": "regex", "value": "^/var/(log|tmp)$"}]}
    assert sr.evaluate_rule(rule(trap_match=regex), trap) is not None
    # Every condition must hold; a varbind the trap lacks fails its condition.
    both = {"conditions": [*equals["conditions"], {"object": f"{EXAMPLE}.1.9", "value": "x"}]}
    assert sr.evaluate_rule(rule(trap_match=both), trap) is None
    # The instance: the value, or the index after the object.
    by_value = rule(trap_match={"instance": {"object": VOLUME}})
    assert sr.evaluate_rule(by_value, trap) == {"action": "raise", "instance": "/var/log"}
    by_index = rule(trap_match={"instance": {"object": VOLUME, "part": "index"}})
    assert sr.evaluate_rule(by_index, trap) == {"action": "raise", "instance": f"{VOLUME} 4"}
    absent = rule(trap_match={"instance": {"object": f"{EXAMPLE}.1.9"}})
    assert sr.evaluate_rule(absent, trap) == {"action": "raise", "instance": ""}
    # Registry objects: an enumerated value by its label or its number.
    down = named(LINK_DOWN)
    admin_up = {"conditions": [{"object": "ifAdminStatus", "value": "up"}], "instance": {"object": "ifDescr"}}
    assert sr.evaluate_rule(rule(pattern="linkDown", trap_match=admin_up), down) == {
        "action": "raise",
        "instance": "GigabitEthernet1/0/12",
    }
    by_number = {
        "conditions": [{"object": "ifOperStatus", "value": "2"}],
        "instance": {"object": "ifIndex", "part": "index"},
    }
    assert sr.evaluate_rule(rule(pattern="linkDown", trap_match=by_number), down) == {
        "action": "raise",
        "instance": "ifIndex 12",
    }


def test_a_clearing_trap_names_the_same_instance():
    custom = rule(clear_pattern=DISK_OK_TRAP, trap_match={"instance": {"object": VOLUME}})
    assert sr.evaluate_rule(custom, named(disk(DISK_OK_TRAP))) == {"action": "clear", "instance": "/var"}
    guarded = rule(clear_pattern=DISK_OK_TRAP, trap_match={"clear_conditions": [{"object": LEVEL, "value": "normal"}]})
    assert sr.evaluate_rule(guarded, named(disk(DISK_OK_TRAP))) is None
    assert sr.evaluate_rule(guarded, named(disk(DISK_OK_TRAP, level="normal"))) == {"action": "clear", "instance": ""}


def test_trap_rows_and_syslog_rows_stay_apart():
    syslog_row = {
        **sr.clean_custom_rule({"name": "s", "match_type": "contains", "pattern": "boom"}),
        "id": 1,
        "builtin_key": "",
        "source": "syslog",
    }
    trap_row = {
        **tr.clean_custom_trap_rule({"name": "t", "pattern": DISK_TRAP}),
        "id": 2,
        "builtin_key": "",
        "source": "trap",
    }
    broken = {**trap_row, "id": 3, "trap_match": {"conditions": [{"object": VOLUME, "op": "regex", "value": "("}]}}
    syslog_keys = [r.key for r in sr.merge_rules([syslog_row, trap_row]) if not r.builtin]
    trap_rules = [r for r in tr.merge_rules([syslog_row, trap_row, broken]) if not r.builtin]
    assert syslog_keys == ["custom_1"]
    assert [(r.key, r.metric, r.source) for r in trap_rules] == [("custom_2", "trap_custom_2", "trap")]
    payload = trap_rules[0].payload()
    assert payload["trap_match"]["instance"] == {"object": "", "part": "value"} and payload["match_type"] == "trap"
    assert "trap_match" not in sr.merge_rules([syslog_row])[-1].payload()


# ── The engine ───────────────────────────────────────────────────────────────


async def _purge() -> None:
    """Delete the custom trap rules (the database is shared by the session)."""
    conn = await db.get_db()
    try:
        await conn.execute("DELETE FROM syslog_alert_rules WHERE source = 'trap' AND builtin_key = ''")
        await conn.commit()
    finally:
        await conn.close()
    sr.invalidate_rules_cache()


async def _custom(**body) -> int:
    await _purge()
    row = await db.create_syslog_alert_rule(
        tr.clean_custom_trap_rule({"name": "Disk filling", "pattern": DISK_TRAP, **body}), source="trap"
    )
    sr.invalidate_rules_cache()
    return int(row["id"])


async def test_a_custom_rule_raises_on_an_unnamed_trap_and_its_clearing_trap_resolves(engine):  # noqa: F811
    host_id = await _host("trap-c1", "192.0.2.80", "linux")
    rule_id = await _custom(
        clear_pattern=DISK_OK_TRAP, severity="critical", trap_match={"instance": {"object": VOLUME}}
    )
    await _receive("192.0.2.80", disk(), disk(volume="/home", index=5))
    opened = await _open(host_id)
    key = f"trap:custom_{rule_id}:{host_id}:/var"
    assert set(opened) == {key, f"trap:custom_{rule_id}:{host_id}:/home"}
    alert = opened[key]
    assert (alert["alert_type"], alert["metric"], alert["severity"]) == ("trap", f"trap_custom_{rule_id}", "critical")
    assert alert["message"].startswith(f"Disk filling on /var: {DISK_TRAP}: {VOLUME}.4 = /var")
    await _receive("192.0.2.80", disk(DISK_OK_TRAP))
    assert list(await _open(host_id)) == [f"trap:custom_{rule_id}:{host_id}:/home"]
    # A suppression of the rule's metric holds it back.
    await db.create_alert_suppression("maint", "2099-01-01 00:00:00", host_id=host_id, metric=f"trap_custom_{rule_id}")
    await _receive("192.0.2.80", disk(volume="/srv", index=6))
    assert f"trap:custom_{rule_id}:{host_id}:/srv" not in await _open(host_id)
    await _purge()


async def test_a_custom_threshold_rule_counts_like_the_builtin_ones(engine):  # noqa: F811
    clock, _repolls, _changes = engine
    host_id = await _host("trap-c2", "192.0.2.81", "linux")
    await _custom(threshold_count=3, threshold_window_seconds=120)
    for _ in range(2):
        await _receive("192.0.2.81", disk())
        clock.t += 30
    assert await _open(host_id) == {}
    await _receive("192.0.2.81", disk())
    assert len(await _open(host_id)) == 1
    await _purge()


async def test_a_disabled_custom_rule_raises_nothing(engine):  # noqa: F811
    host_id = await _host("trap-c3", "192.0.2.82", "linux")
    await _custom(enabled=False)
    await _receive("192.0.2.82", disk())
    assert await _open(host_id) == {}
    await _purge()


# ── clogMessageGenerated through the syslog rules ────────────────────────────


def test_the_syslog_line_of_a_clog_trap():
    assert tr.clog_syslog_line(named(clog("SYS", 6, "CONFIG_I", "Configured from console by admin on vty0"))) == (
        "%SYS-5-CONFIG_I: Configured from console by admin on vty0"
    )
    assert tr.clog_syslog_line(named(clog("ROUTING-BGP", 6, "ADJCHANGE", "neighbor  203.0.113.2  Up"))) == (
        "%ROUTING-BGP-5-ADJCHANGE: neighbor 203.0.113.2 Up"
    )
    parsed = sr.parse_syslog_message(tr.clog_syslog_line(named(clog("LINK", 4, "UPDOWN", "Interface Gi0/1, x"))) or "")
    assert (parsed.tag, parsed.raw_tag) == ("LINK-UPDOWN", "LINK-3-UPDOWN")
    # Not a clog trap, or varbinds that make no tag.
    assert tr.clog_syslog_line(named(LINK_DOWN)) is None
    assert tr.clog_syslog_line(named(clog("SYS", 9, "CONFIG_I", "x"))) is None
    assert tr.clog_syslog_line(named(clog("SYS VTY", 6, "CONFIG_I", "x"))) is None
    assert tr.clog_syslog_line(named(clog("SYS", 6, "CONFIG I", "x"))) is None
    # An octet string that is not text: its printable label.
    trap = name_trap(
        {
            "trap_oid": CLOG_TRAP,
            "varbinds": [
                (f"{CLOG}.2.1", "SYS"),
                (f"{CLOG}.3.1", "6"),
                (f"{CLOG}.4.1", "CONFIG_I"),
                (f"{CLOG}.5.1", "0x" + b"done".hex()),
            ],
        }
    )
    assert tr.clog_syslog_line(trap) == "%SYS-5-CONFIG_I: done"


BGP_DOWN_TEXT = "neighbor 203.0.113.2 Down BGP Notification sent"


async def test_a_clog_trap_raises_the_syslog_alert_and_meets_the_syslog_message(engine):  # noqa: F811
    clock, _repolls, changes = engine
    host_id = await _host("trap-c4", "192.0.2.83")
    await _receive("192.0.2.83", clog("BGP", 6, "ADJCHANGE", BGP_DOWN_TEXT))
    key = f"syslog:bgp_neighbor:{host_id}:203.0.113.2"
    alert = (await _open(host_id))[key]
    assert (alert["alert_type"], alert["metric"]) == ("syslog", "syslog_bgp_neighbor")
    assert alert["message"] == f"BGP neighbor down on 203.0.113.2: BGP-5-ADJCHANGE: {BGP_DOWN_TEXT}"
    # The same message as syslog a moment later is the same event: one alert, not bumped.
    clock.t += 2
    await sr.process_syslog_batch([(host_id, f"<189>%BGP-5-ADJCHANGE: {BGP_DOWN_TEXT}")])
    assert (await _open(host_id))[key]["occurrence_count"] == 1
    # The configuration-change trigger takes it too, and the Up resolves.
    await _receive("192.0.2.83", clog("SYS", 6, "CONFIG_I", "Configured from console by admin on vty0"))
    assert changes == [host_id]
    await _receive("192.0.2.83", clog("BGP", 6, "ADJCHANGE", "neighbor 203.0.113.2 Up"))
    assert await _open(host_id) == {}


async def test_a_clog_trap_follows_the_syslog_switches(engine, monkeypatch):  # noqa: F811
    _clock, _repolls, changes = engine
    host_id = await _host("trap-c5", "192.0.2.84")
    # Trap alerts off: the syslog alert is still raised.
    monkeypatch.setattr(state, "EVENT_RECEIVER_CONFIG", {"trap_alerts": False})
    await _receive("192.0.2.84", clog("BGP", 6, "ADJCHANGE", BGP_DOWN_TEXT))
    assert [a["alert_type"] for a in (await _open(host_id)).values()] == ["syslog"]
    # Syslog alerts and the configuration trigger off: nothing.
    monkeypatch.setattr(state, "EVENT_RECEIVER_CONFIG", {"syslog_alerts": False, "config_change_trigger": False})
    await _receive("192.0.2.84", clog("BGP", 6, "ADJCHANGE", "neighbor 203.0.113.9 Down Hold Timer Expired"))
    await _receive("192.0.2.84", clog("SYS", 6, "CONFIG_I", "Configured from console"))
    assert len(await _open(host_id)) == 1 and changes == []


async def test_a_clog_trap_with_the_wrong_community_does_nothing(engine):  # noqa: F811
    host_id = await _host("trap-c6", "192.0.2.85")
    data = clog("BGP", 6, "ADJCHANGE", BGP_DOWN_TEXT)
    await _receive("192.0.2.85", data.replace(b"trap-community", b"wrong-communit"))
    assert await _open(host_id) == {}


# ── Restore at startup ───────────────────────────────────────────────────────


async def _store_trap(data: bytes, host_id: int | None, ago: int, source_ip: str = "192.0.2.86") -> None:
    """A stored trap received ``ago`` seconds before now, as the receiver stores it."""
    severity, oid, message = tr.event_fields(named(data))
    conn = await db.get_db()
    try:
        await conn.execute(
            "INSERT INTO trap_syslog_events (source_ip, host_id, event_type, severity, oid, message, raw_data, "
            "received_at) VALUES (?, ?, 'trap', ?, ?, ?, ?, datetime('now', ?))",
            (source_ip, host_id, severity, oid, message, data[:1000].hex(), f"-{int(ago)} seconds"),
        )
        await conn.commit()
    finally:
        await conn.close()


AUTH_KEY = "trap_snmp_auth_failure"


async def test_restore_rebuilds_the_trap_counters_from_believed_traps(engine):  # noqa: F811
    clock, repolls, changes = engine
    host_id = await _host("trap-c7", "192.0.2.86")
    for ago in (200, 150, 100):
        await _store_trap(AUTH, host_id, ago)
    # Not counted: the wrong community now, an undecodable (SNMPv3) datagram,
    # a source that is no inventory host, an event older than the window.
    await _store_trap(AUTH.replace(b"trap-community", b"wrong-communit"), host_id, 90)
    conn = await db.get_db()
    try:
        await conn.execute(
            "INSERT INTO trap_syslog_events (source_ip, host_id, event_type, message, raw_data, received_at) "
            "VALUES ('192.0.2.86', ?, 'trap', 'SNMP trap from 192.0.2.86 (90 bytes)', '3081', datetime('now', '-80 seconds'))",
            (host_id,),
        )
        await conn.commit()
    finally:
        await conn.close()
    await _store_trap(AUTH, None, 70, source_ip="203.0.113.86")
    await _store_trap(AUTH, host_id, 700)
    out = await tr.restore_state()
    assert out == {"traps": 3}
    assert list(sr._counters[(AUTH_KEY, host_id, "")]) == pytest.approx(
        [clock.t - 200, clock.t - 150, clock.t - 100], abs=5
    )
    assert await _open(host_id) == {} and repolls == [] and changes == []
    # Two live failures make five within the window: raised.
    await _receive("192.0.2.86", AUTH)
    clock.t += 10
    await _receive("192.0.2.86", AUTH)
    assert list(await _open(host_id)) == [f"trap:snmp_auth_failure:{host_id}:"]


async def test_restore_counts_custom_rules_and_clog_lines(engine):  # noqa: F811
    clock, _repolls, _changes = engine
    host_id = await _host("trap-c8", "192.0.2.87")
    rule_id = await _custom(threshold_count=3, threshold_window_seconds=600)
    login = clog("SEC_LOGIN", 5, "LOGIN_FAILED", "Login failed [user: x] [Source: 198.51.100.4]")
    for ago in (400, 300):
        await _store_trap(disk(), host_id, ago, source_ip="192.0.2.87")
    for ago in (250, 200, 150, 100):
        await _store_trap(login, host_id, ago, source_ip="192.0.2.87")
    assert (await tr.restore_state())["traps"] == 6
    assert len(sr._counters[(f"trap_custom_{rule_id}", host_id, "")]) == 2
    assert len(sr._counters[("auth_failure", host_id, "")]) == 4
    await _receive("192.0.2.87", disk())
    clock.t += 10
    await _receive("192.0.2.87", login)
    assert set(await _open(host_id)) == {
        f"trap:custom_{rule_id}:{host_id}:",
        f"syslog:auth_failure:{host_id}:",
    }
    await _purge()


async def test_restore_follows_the_switches_and_never_raises(engine, monkeypatch, caplog):  # noqa: F811
    host_id = await _host("trap-c9", "192.0.2.88")
    await _store_trap(AUTH, host_id, 100, source_ip="192.0.2.88")
    monkeypatch.setattr(state, "EVENT_RECEIVER_CONFIG", {"trap_alerts": False, "syslog_alerts": False})
    assert await tr.restore_state() == {"traps": 0}
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", False)
    monkeypatch.setattr(state, "EVENT_RECEIVER_CONFIG", {})
    assert await tr.restore_state() == {"traps": 0}
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", True)

    async def broken(*_a, **_k):
        raise RuntimeError("database gone")

    monkeypatch.setattr(db, "list_syslog_messages_since", broken)
    with caplog.at_level(logging.WARNING, logger="plexus.trap_rules"):
        assert await tr.restore_state() == {"traps": 0}
    assert "state restore failed: database gone" in caplog.text


def test_a_stored_trap_is_decoded_again_only_when_it_can_be():
    assert tr.decode_stored_trap(AUTH.hex()) == decode_snmp_trap(AUTH)
    assert tr.decode_stored_trap("zz") is None
    assert tr.decode_stored_trap("") is None
    assert tr.decode_stored_trap(AUTH[:20].hex()) is None


# ── API ──────────────────────────────────────────────────────────────────────


def _event_id(client, source_ip: str) -> int:
    events = client.get("/api/metrics/events", params={"event_type": "trap", "limit": 200}).json()
    return next(int(e["id"]) for e in events if e["source_ip"] == source_ip)


def test_custom_trap_rule_crud(admin):  # noqa: F811
    body = {
        "name": "Disk filling",
        "pattern": DISK_TRAP,
        "clear_pattern": DISK_OK_TRAP,
        "severity": "critical",
        "trap_match": {"conditions": [{"object": LEVEL, "value": "high"}], "instance": {"object": VOLUME}},
    }
    created = admin.post(PREFIX, json=body)
    assert created.status_code == 201, created.text
    rule_ = created.json()
    rule_id = rule_["id"]
    assert (rule_["key"], rule_["metric"], rule_["source"], rule_["builtin"], rule_["match_type"]) == (
        f"custom_{rule_id}",
        f"trap_custom_{rule_id}",
        "trap",
        False,
        "trap",
    )
    assert rule_["trap_match"]["conditions"] == [{"object": LEVEL, "op": "equals", "value": "high"}]
    listed = admin.get(PREFIX).json()
    assert [r["key"] for r in listed][: len(tr.TRAP_RULES)] == [r.key for r in tr.TRAP_RULES]
    assert listed[-1]["id"] == rule_id
    # Not a syslog rule: the syslog list and routes do not see it.
    assert rule_id not in [r["id"] for r in admin.get("/api/monitoring/syslog-rules").json()]
    assert admin.put(f"/api/monitoring/syslog-rules/{rule_id}", json={"name": "y"}).status_code == 404
    assert admin.delete(f"/api/monitoring/syslog-rules/{rule_id}").status_code == 404
    syslog_rule = admin.post(
        "/api/monitoring/syslog-rules", json={"name": "s", "match_type": "contains", "pattern": "boom"}
    ).json()
    assert admin.put(f"{PREFIX}/{syslog_rule['id']}", json={"name": "y"}).status_code == 404
    assert admin.delete(f"{PREFIX}/{syslog_rule['id']}").status_code == 404
    assert admin.patch(f"{PREFIX}/builtin/custom_{rule_id}", json={"enabled": False}).status_code == 404

    updated = admin.put(f"{PREFIX}/{rule_id}", json={"name": "Disk full", "threshold_count": 2})
    assert updated.status_code == 200, updated.text
    assert (updated.json()["name"], updated.json()["threshold_count"], updated.json()["pattern"]) == (
        "Disk full",
        2,
        DISK_TRAP,
    )
    assert admin.put(f"{PREFIX}/{rule_id}", json={"pattern": "noSuchTrap"}).status_code == 400
    assert admin.post(PREFIX, json={"name": "x"}).status_code == 400
    assert admin.put(f"{PREFIX}/999999", json={"name": "y"}).status_code == 404
    deleted = admin.delete(f"{PREFIX}/{rule_id}")
    assert deleted.status_code == 200 and deleted.json() == {"ok": True, "alerts_resolved": 0}
    assert admin.delete(f"{PREFIX}/{rule_id}").status_code == 404
    admin.delete(f"/api/monitoring/syslog-rules/{syslog_rule['id']}")


def test_disabling_or_deleting_a_custom_rule_resolves_its_alerts(admin):  # noqa: F811
    portal = admin.raw.portal
    host_id = portal.call(_host, "trap-c10", "192.0.2.89", "linux")
    rule_id = admin.post(PREFIX, json={"name": "Disk", "pattern": DISK_TRAP}).json()["id"]
    metric = f"trap_custom_{rule_id}"

    async def raise_alert() -> None:
        await db.create_monitoring_alert(
            host_id=host_id,
            poll_id=None,
            alert_type="trap",
            metric=metric,
            message="Disk",
            severity="warning",
            dedup_key=f"trap:custom_{rule_id}:{host_id}:",
            hostname="trap-c10",
        )

    portal.call(raise_alert)
    disabled = admin.put(f"{PREFIX}/{rule_id}", json={"enabled": False})
    assert disabled.status_code == 200 and disabled.json()["enabled"] is False
    assert portal.call(_open, host_id) == {}
    assert admin.put(f"{PREFIX}/{rule_id}", json={"enabled": True}).status_code == 200
    portal.call(raise_alert)
    assert admin.delete(f"{PREFIX}/{rule_id}").json()["alerts_resolved"] == 1


def test_the_trap_rule_test_route(admin):  # noqa: F811
    portal = admin.raw.portal
    portal.call(
        db.create_trap_syslog_events_batch,
        [
            ("198.51.100.90", None, "trap", "", "warning", "1.3.6.1.6.3.1.1.5.3", "linkDown", LINK_DOWN.hex(), "udp"),
            ("198.51.100.91", None, "trap", "", "info", "", "SNMP trap (90 bytes)", "3081", "udp"),
        ],
    )
    result = admin.post(f"{PREFIX}/test", json={"event_id": _event_id(admin, "198.51.100.90")})
    assert result.status_code == 200, result.text
    body = result.json()
    assert (body["name"], body["trap_oid"], body["repoll"], body["config_change"]) == (
        "linkDown",
        "1.3.6.1.6.3.1.1.5.3",
        True,
        False,
    )
    assert [m["key"] for m in body["matches"]] == ["link_down"] and body["draft"] is None
    descr = next(v for v in body["varbinds"] if v["name"] == "ifDescr")
    assert (descr["oid"], descr["index"], descr["label"]) == (f"{IF}.2.12", "12", "GigabitEthernet1/0/12")
    # A draft rule, against an OID with varbinds.
    tried = admin.post(
        f"{PREFIX}/test",
        json={
            "trap_oid": DISK_TRAP,
            "varbinds": [[f"{VOLUME}.4", "/var"]],
            "rule": {"name": "d", "pattern": DISK_TRAP, "trap_match": {"instance": {"object": VOLUME}}},
        },
    ).json()
    assert tried["name"] == "" and tried["draft"] == {"action": "raise", "instance": "/var"}
    no_match = admin.post(
        f"{PREFIX}/test", json={"trap_oid": "1.3.6.1.4.1.32473.9", "rule": {"name": "d", "pattern": DISK_TRAP}}
    )
    assert no_match.json()["draft"] == {"action": "", "instance": ""}
    # A clog trap shows its syslog line and what the syslog rules do with it.
    clogged = admin.post(
        f"{PREFIX}/test",
        json={
            "trap_oid": CLOG_TRAP,
            "varbinds": [
                [f"{CLOG}.2.1", "SYS"],
                [f"{CLOG}.3.1", "6"],
                [f"{CLOG}.4.1", "CONFIG_I"],
                [f"{CLOG}.5.1", "x"],
            ],
        },
    ).json()
    assert clogged["syslog_line"] == "%SYS-5-CONFIG_I: x" and clogged["syslog"]["config_change"] is True
    # Errors.
    assert admin.post(f"{PREFIX}/test", json={"event_id": _event_id(admin, "198.51.100.91")}).status_code == 400
    assert admin.post(f"{PREFIX}/test", json={"event_id": 99999999}).status_code == 404
    assert admin.post(f"{PREFIX}/test", json={}).status_code == 400
    assert admin.post(f"{PREFIX}/test", json={"trap_oid": DISK_TRAP, "rule": {"name": "d"}}).status_code == 400
    assert admin.post(f"{PREFIX}/test", json={"trap_oid": DISK_TRAP, "varbinds": [["1"]]}).status_code == 422


def test_trap_rule_permissions(admin):  # noqa: F811
    reader = user_client(admin, "trap-c-reader", features=["monitoring"])
    assert reader.get(PREFIX).status_code == 200
    assert reader.post(PREFIX, json={"name": "x", "pattern": DISK_TRAP}).status_code == 403
    # The test route is a POST: it needs monitoring.write, like the syslog one.
    assert reader.post(f"{PREFIX}/test", json={"trap_oid": DISK_TRAP}).status_code == 403
    writer = user_client(admin, "trap-c-writer", features=["monitoring", "monitoring.write"])
    created = writer.post(PREFIX, json={"name": "x", "pattern": DISK_TRAP})
    assert created.status_code == 201
    assert writer.post(f"{PREFIX}/test", json={"trap_oid": DISK_TRAP}).status_code == 200
    assert writer.delete(f"{PREFIX}/{created.json()['id']}").status_code == 200


# ── Migration ────────────────────────────────────────────────────────────────


async def test_the_migration_adds_the_source_columns():
    await db.init_db()
    conn = await db.get_db(read_only=True)
    try:
        cursor = await conn.execute("SELECT version FROM schema_migrations WHERE version = 138")
        assert await cursor.fetchone() is not None
    finally:
        await conn.close()
    row = await db.set_syslog_builtin_override("trap_fan", True, "warning", source="trap")
    assert (row["source"], row["trap_match"]) == ("trap", {})
    assert (await db.set_syslog_builtin_override("fan", True, "warning"))["source"] == "syslog"
