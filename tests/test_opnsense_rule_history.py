"""OPNsense rule counter history: the filter rule counters kept across
collections and counter resets, and the "unused for 90 days" flag.

pf resets its rule counters at a reboot and at every filter reload, so the
collection adds each read to a per host, per label history
(``opnsense_rule_counters``); ``rules.analyze`` turns that history into each
rule's ``history`` block and the ``unused_90d`` flag. Every name and
address is invented (documentation ranges); no firewall is contacted.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from netcontrol.integrations.opnsense.normalize import build_snapshot
from netcontrol.integrations.opnsense.rules import FLAGS, UNUSED_DAYS, analyze, rule_history
from netcontrol.integrations.opnsense.sample import build_sample_raw
from netcontrol.integrations.pathtrace.opnsense_config import parse_document

from test_meraki_topology import api  # noqa: F401 - the fixture is used by name
from test_opnsense_rules import CONFIG, RULE_DISABLED, RULE_SSH_DMZ, RULE_WEB

LABEL_A = "a0000000-0000-4000-8000-000000000001"
LABEL_B = "a0000000-0000-4000-8000-000000000002"
LABEL_C = "a0000000-0000-4000-8000-000000000003"
SAMPLE_PASSING = "d0000000-0000-4000-8000-000000000001"
SAMPLE_IDLE = "d0000000-0000-4000-8000-000000000002"
NOW = datetime(2026, 11, 15, 8, 0, 0, tzinfo=UTC)


def _text(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")


def _ago(days: float, now: datetime = NOW) -> str:
    return _text(now - timedelta(days=days))


async def _host(address: str = "192.0.2.1") -> int:
    import routes.database as db

    group_id = await db.create_group(f"Firewalls {address}")
    return await db.add_host(group_id, f"fw-{address}", address, device_type="opnsense")


# ── Store ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_first_read_growth_and_reset():
    import routes.database as db

    host_id = await _host()
    first = await db.record_opnsense_rule_counters(
        host_id,
        {
            LABEL_A: {"evaluations": 40, "packets": 5, "bytes": 100, "states": 1, "pf_rules": 1},
            LABEL_B: {"evaluations": 40, "packets": 0, "bytes": 0},
        },
        "2026-11-01 08:00:00",
    )
    assert first == {"rules": 2, "removed": 0}
    rows = await db.get_opnsense_rule_counters(host_id)
    # First seen with packets already counted: hit at that read.
    assert rows[LABEL_A] == {
        "first_seen_at": "2026-11-01 08:00:00",
        "last_seen_at": "2026-11-01 08:00:00",
        "last_hit_at": "2026-11-01 08:00:00",
        "total_packets": 5,
        "total_bytes": 100,
        "counters": {"evaluations": 40, "packets": 5, "bytes": 100, "states": 1, "pf_rules": 1},
    }
    assert rows[LABEL_B]["last_hit_at"] == "" and rows[LABEL_B]["total_packets"] == 0
    assert rows[LABEL_B]["counters"] == {"evaluations": 40, "packets": 0, "bytes": 0}

    # Growth: the difference is added and the hit moves; an idle rule stays unhit.
    await db.record_opnsense_rule_counters(
        host_id, {LABEL_A: {"packets": 8, "bytes": 160}, LABEL_B: {"packets": 0, "bytes": 0}}, "2026-11-02 08:00:00"
    )
    rows = await db.get_opnsense_rule_counters(host_id)
    assert (rows[LABEL_A]["total_packets"], rows[LABEL_A]["total_bytes"]) == (8, 160)
    assert rows[LABEL_A]["last_hit_at"] == "2026-11-02 08:00:00"
    assert rows[LABEL_B]["last_hit_at"] == "" and rows[LABEL_B]["last_seen_at"] == "2026-11-02 08:00:00"
    assert rows[LABEL_B]["first_seen_at"] == "2026-11-01 08:00:00"

    # A reset (reboot, filter reload): the counter went down, all of it is new.
    await db.record_opnsense_rule_counters(host_id, {LABEL_A: {"packets": 2, "bytes": 30}}, "2026-11-03 08:00:00")
    rows = await db.get_opnsense_rule_counters(host_id)
    assert (rows[LABEL_A]["total_packets"], rows[LABEL_A]["total_bytes"]) == (10, 190)
    assert rows[LABEL_A]["last_hit_at"] == "2026-11-03 08:00:00"
    assert rows[LABEL_A]["counters"] == {"packets": 2, "bytes": 30}

    # Unchanged after the reset: no hit, nothing added.
    await db.record_opnsense_rule_counters(host_id, {LABEL_A: {"packets": 2, "bytes": 30}}, "2026-11-04 08:00:00")
    rows = await db.get_opnsense_rule_counters(host_id)
    assert rows[LABEL_A]["total_packets"] == 10 and rows[LABEL_A]["last_hit_at"] == "2026-11-03 08:00:00"
    assert rows[LABEL_A]["last_seen_at"] == "2026-11-04 08:00:00"

    # A reset to zero is no hit either.
    await db.record_opnsense_rule_counters(host_id, {LABEL_A: {"packets": 0, "bytes": 0}}, "2026-11-05 08:00:00")
    rows = await db.get_opnsense_rule_counters(host_id)
    assert rows[LABEL_A]["total_packets"] == 10 and rows[LABEL_A]["last_hit_at"] == "2026-11-03 08:00:00"

    # A read older than the stored one changes nothing; an empty read nothing at all.
    await db.record_opnsense_rule_counters(host_id, {LABEL_A: {"packets": 999}}, "2026-11-04 09:00:00")
    assert (await db.get_opnsense_rule_counters(host_id))[LABEL_A]["total_packets"] == 10
    assert await db.record_opnsense_rule_counters(host_id, {}, "2026-11-06 08:00:00") == {"rules": 0, "removed": 0}

    # Rows go with their host.
    await db.remove_host(host_id)
    assert await db.get_opnsense_rule_counters(host_id) == {}


@pytest.mark.asyncio
async def test_a_label_no_longer_reported_is_kept_for_the_retention_then_removed():
    import routes.database as db

    assert db.RULE_COUNTER_RETENTION_DAYS == 30
    host_id = await _host()
    other_id = await _host("192.0.2.2")
    await db.record_opnsense_rule_counters(host_id, {LABEL_A: {"packets": 1}, LABEL_C: {"packets": 0}}, _ago(40))
    await db.record_opnsense_rule_counters(other_id, {LABEL_C: {"packets": 0}}, _ago(40))
    # The rule was deleted (or edited into a new label): only LABEL_A is reported.
    found = await db.record_opnsense_rule_counters(host_id, {LABEL_A: {"packets": 1}}, _ago(11))
    assert found == {"rules": 1, "removed": 0}
    assert sorted(await db.get_opnsense_rule_counters(host_id)) == [LABEL_A, LABEL_C]
    found = await db.record_opnsense_rule_counters(host_id, {LABEL_A: {"packets": 1}}, _ago(9))
    assert found == {"rules": 1, "removed": 1}
    assert sorted(await db.get_opnsense_rule_counters(host_id)) == [LABEL_A]
    # Another host's rows are its own.
    assert sorted(await db.get_opnsense_rule_counters(other_id)) == [LABEL_C]


# ── Analysis ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def document():
    found = parse_document(CONFIG)
    assert found is not None
    return found


def _row(first_days: float, hit_days: float | None, last_days: float = 0, packets: int = 0) -> dict:
    return {
        "first_seen_at": _ago(first_days),
        "last_seen_at": _ago(last_days),
        "last_hit_at": _ago(hit_days) if hit_days is not None else "",
        "total_packets": packets,
        "total_bytes": packets * 100,
        "counters": {"packets": 0},
    }


def test_the_flag_needs_90_days_of_tracking_without_a_hit(document):
    assert "unused_90d" in FLAGS and UNUSED_DAYS == 90
    history = {
        RULE_WEB: _row(90, None),
        RULE_SSH_DMZ: _row(89, None),
        RULE_DISABLED: _row(200, None),
    }
    view = analyze(document, history=history, now=NOW)
    rules = {r["uuid"]: r for r in view["rules"] if r["uuid"]}
    assert "unused_90d" in rules[RULE_WEB]["flags"]
    assert rules[RULE_WEB]["history"] == {
        "first_seen_at": _ago(90),
        "last_seen_at": _ago(0),
        "last_hit_at": None,
        "tracked_days": 90,
        "idle_days": 90,
        "total_packets": 0,
        "total_bytes": 0,
    }
    # Tracked for less than 90 days: not flagged, and its history says how long.
    assert "unused_90d" not in rules[RULE_SSH_DMZ]["flags"]
    assert rules[RULE_SSH_DMZ]["history"]["tracked_days"] == 89
    # A disabled rule is never unused.
    assert rules[RULE_DISABLED]["flags"] == ["disabled"]
    # No history: no block, no flag.
    others = [r for r in view["rules"] if r["uuid"] not in history]
    assert others and all(r["history"] is None and "unused_90d" not in r["flags"] for r in others)
    assert view["summary"]["unused_90d"] == 1
    assert view["unused_days"] == UNUSED_DAYS and view["history_available"] is True
    # The positional call the other callers make still works.
    plain = analyze(document)
    assert plain["history_available"] is False and plain["summary"]["unused_90d"] == 0


def test_a_hit_inside_the_window_or_a_pause_in_collecting_keeps_the_flag_off(document):
    history = {
        # Tracked 200 days, hit 89 days ago.
        RULE_WEB: _row(200, 89, packets=12),
        # Tracked 200 days, hit 91 days ago (first read with packets counted works the same).
        RULE_SSH_DMZ: _row(200, 91, packets=3),
    }
    rules = {r["uuid"]: r for r in analyze(document, history=history, now=NOW)["rules"] if r["uuid"]}
    assert "unused_90d" not in rules[RULE_WEB]["flags"] and rules[RULE_WEB]["history"]["idle_days"] == 89
    assert rules[RULE_WEB]["history"]["last_hit_at"] == _ago(89)
    assert "unused_90d" in rules[RULE_SSH_DMZ]["flags"] and rules[RULE_SSH_DMZ]["history"]["total_packets"] == 3

    # Collections stopped 60 days ago: only the 60 observed days count.
    paused = {RULE_WEB: _row(120, None, last_days=60)}
    found = rule_history(paused[RULE_WEB], NOW)
    assert found is not None and (found["tracked_days"], found["idle_days"]) == (60, 60)
    rules = {r["uuid"]: r for r in analyze(document, history=paused, now=NOW)["rules"] if r["uuid"]}
    assert "unused_90d" not in rules[RULE_WEB]["flags"]
    assert rule_history(None, NOW) is None and rule_history({"first_seen_at": ""}, NOW) is None


def test_the_unused_flag_keeps_its_meaning(document):
    stats = {RULE_WEB: {"packets": 0}}
    history = {RULE_WEB: _row(10, None)}
    rules = {r["uuid"]: r for r in analyze(document, stats, history=history, now=NOW)["rules"] if r["uuid"]}
    assert "unused" in rules[RULE_WEB]["flags"] and "unused_90d" not in rules[RULE_WEB]["flags"]


# ── Collection ───────────────────────────────────────────────────────────────


def _firewall_section(snapshot: dict) -> dict:
    from netcontrol.routes.opnsense_collection import SECTION_RULE_COUNTERS

    firewall = next(n for n in snapshot["nodes"] if n.get("kind") == "appliance" and n["id"].startswith("d:"))
    return dict(next(s for s in firewall["sections"] if s["title"] == SECTION_RULE_COUNTERS)["rows"])


@pytest.mark.asyncio
async def test_the_collection_stores_the_counters_of_its_host():
    import routes.database as db
    from netcontrol.routes.opnsense_collection import attach_rule_stats

    raw = build_sample_raw()
    snapshot = build_snapshot(raw)
    # Not an inventory host yet: nothing stored, and the section says why.
    await attach_rule_stats(raw, snapshot)
    assert _firewall_section(snapshot)["Result"] == "Not stored: import the firewall into the inventory"

    host_id = await _host()
    raw = build_sample_raw()
    snapshot = build_snapshot(raw)
    kept = await attach_rule_stats(raw, snapshot)
    assert kept is not None and kept["host_id"] == host_id
    section = _firewall_section(snapshot)
    assert section["Result"] == "2 rules added to the counter history"
    rows = await db.get_opnsense_rule_counters(host_id)
    # Read at the collection's time.
    assert rows[SAMPLE_PASSING]["last_hit_at"] == "2026-11-14 09:00:00"
    assert rows[SAMPLE_PASSING]["total_packets"] == 9120
    assert rows[SAMPLE_IDLE]["last_hit_at"] == "" and rows[SAMPLE_IDLE]["first_seen_at"] == "2026-11-14 09:00:00"


@pytest.mark.asyncio
async def test_a_failing_store_is_noted_and_the_collection_goes_on(monkeypatch):
    import routes.database as db
    from netcontrol.routes.opnsense_collection import attach_rule_stats

    async def broken(*_args, **_kwargs):
        raise RuntimeError("store down")

    await _host()
    monkeypatch.setattr(db, "record_opnsense_rule_counters", broken)
    raw = build_sample_raw()
    snapshot = build_snapshot(raw)
    assert await attach_rule_stats(raw, snapshot) is not None
    assert _firewall_section(snapshot)["Result"] == "Not stored: see the server log"


# ── API ──────────────────────────────────────────────────────────────────────


def test_the_rules_view_serves_the_history(api):  # noqa: F811 - the imported fixture
    import routes.database as db

    now = datetime.now(UTC)

    async def seed() -> int:
        host_id = await _host()
        await db.create_config_backup(None, host_id, CONFIG, capture_method="opnsense-api")
        await db.record_opnsense_rule_counters(
            host_id, {RULE_WEB: {"packets": 0}, RULE_SSH_DMZ: {"packets": 4}}, _ago(100, now)
        )
        await db.record_opnsense_rule_counters(
            host_id, {RULE_WEB: {"packets": 0}, RULE_SSH_DMZ: {"packets": 9}}, _ago(1, now)
        )
        return host_id

    host_id = asyncio.run(seed())
    found = api.get(f"/api/opnsense/hosts/{host_id}/rules")
    assert found.status_code == 200, found.text
    body = found.json()
    assert body["unused_days"] == 90 and body["history_available"] is True
    assert body["summary"]["unused_90d"] == 1
    rules = {r["uuid"]: r for r in body["rules"] if r["uuid"]}
    assert "unused_90d" in rules[RULE_WEB]["flags"]
    assert rules[RULE_WEB]["history"]["last_hit_at"] is None
    assert rules[RULE_WEB]["history"]["tracked_days"] == 99
    web = rules[RULE_SSH_DMZ]["history"]
    assert "unused_90d" not in rules[RULE_SSH_DMZ]["flags"]
    assert web["total_packets"] == 9 and web["last_hit_at"] == _ago(1, now) and web["idle_days"] == 0
    other = [r for r in body["rules"] if r["uuid"] not in (RULE_WEB, RULE_SSH_DMZ)]
    assert all(r["history"] is None for r in other)
