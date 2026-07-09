"""Tests for the job queue machinery in netcontrol/routes/jobs.py.

Covers:
  * _validate_ad_hoc_ip reserved-range blocking
  * _template_lines comment/blank stripping
  * _coerce_parameters schema validation and type coercion
  * queue ordering (priority desc, FIFO within priority)
  * dependency gating (check_job_dependencies_met)
  * cancel / priority-update lifecycle rules
  * _JobEventWriter batched event persistence

The job *runner* (_run_job and the queue loop) drives real SSH sessions and
is exercised via integration paths; this file covers everything around it.
"""

from __future__ import annotations

import pytest
import routes.database as db_module
from fastapi import HTTPException
from netcontrol.routes.jobs import (
    _coerce_parameters,
    _JobEventWriter,
    _template_lines,
    _validate_ad_hoc_ip,
)
from routes.runner import LogEvent

# ── _validate_ad_hoc_ip ──────────────────────────────────────────────────────


def test_ad_hoc_ip_accepts_unicast():
    assert _validate_ad_hoc_ip("192.168.1.10") == "192.168.1.10"
    assert _validate_ad_hoc_ip("10.0.0.1") == "10.0.0.1"


def test_ad_hoc_ip_rejects_garbage():
    with pytest.raises(HTTPException) as exc:
        _validate_ad_hoc_ip("not-an-ip")
    assert exc.value.status_code == 400


@pytest.mark.parametrize("blocked", ["127.0.0.1", "169.254.10.10", "::1"])
def test_ad_hoc_ip_rejects_reserved_ranges(blocked):
    with pytest.raises(HTTPException) as exc:
        _validate_ad_hoc_ip(blocked)
    assert exc.value.status_code == 400
    assert "reserved" in exc.value.detail


# ── _template_lines ──────────────────────────────────────────────────────────


def test_template_lines_strips_comments_and_blanks():
    content = "show version\n\n# a comment\n  show ip route  \n\t\n"
    assert _template_lines(content) == ["show version", "  show ip route"]


def test_template_lines_empty_input():
    assert _template_lines("") == []
    assert _template_lines(None) == []


# ── _coerce_parameters ───────────────────────────────────────────────────────


def test_coerce_empty_schema_returns_empty():
    assert _coerce_parameters([], {"anything": 1}) == {}


def test_coerce_required_missing_raises_400():
    schema = [{"name": "vlan", "type": "int", "required": True}]
    with pytest.raises(HTTPException) as exc:
        _coerce_parameters(schema, {})
    assert exc.value.status_code == 400
    assert "vlan" in exc.value.detail


def test_coerce_default_applies_when_missing():
    schema = [{"name": "vlan", "type": "int", "default": "100"}]
    assert _coerce_parameters(schema, {}) == {"vlan": 100}


def test_coerce_empty_string_treated_as_missing():
    schema = [{"name": "vlan", "type": "int", "default": "7"}]
    assert _coerce_parameters(schema, {"vlan": ""}) == {"vlan": 7}


def test_coerce_int_rejects_unparseable():
    schema = [{"name": "vlan", "type": "int"}]
    with pytest.raises(HTTPException) as exc:
        _coerce_parameters(schema, {"vlan": "ten"})
    assert exc.value.status_code == 400


@pytest.mark.parametrize("raw,expected", [
    (True, True),
    ("true", True),
    ("YES", True),
    ("1", True),
    ("on", True),
    ("false", False),
    ("0", False),
    ("anything-else", False),
])
def test_coerce_bool_variants(raw, expected):
    schema = [{"name": "enabled", "type": "bool"}]
    assert _coerce_parameters(schema, {"enabled": raw}) == {"enabled": expected}


def test_coerce_list_from_csv_and_list():
    schema = [{"name": "vlans", "type": "list"}]
    assert _coerce_parameters(schema, {"vlans": "10, 20 ,30"}) == {"vlans": ["10", "20", "30"]}
    assert _coerce_parameters(schema, {"vlans": [1, " 2 ", ""]}) == {"vlans": ["1", "2"]}


def test_coerce_ignores_keys_not_in_schema():
    schema = [{"name": "vlan", "type": "int", "default": "1"}]
    out = _coerce_parameters(schema, {"vlan": 5, "rogue": "x"})
    assert out == {"vlan": 5}


# ── DB-backed queue behavior ─────────────────────────────────────────────────


async def _init_clean_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "jobs.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    playbook_id = await db_module.create_playbook("test-pb", "test_pb.txt")
    return playbook_id


async def test_queue_orders_by_priority_then_fifo(tmp_path, monkeypatch):
    pb = await _init_clean_db(tmp_path, monkeypatch)
    normal_first = await db_module.create_job(pb, None, priority=2)
    normal_second = await db_module.create_job(pb, None, priority=2)
    critical = await db_module.create_job(pb, None, priority=4)

    nxt = await db_module.get_next_queued_job()
    assert nxt["id"] == critical

    await db_module.cancel_job(critical)
    nxt = await db_module.get_next_queued_job()
    assert nxt["id"] == normal_first

    await db_module.cancel_job(normal_first)
    nxt = await db_module.get_next_queued_job()
    assert nxt["id"] == normal_second


async def test_start_job_wins_transition_only_once(tmp_path, monkeypatch):
    """start_job must report whether it won queued→running: a second caller
    (concurrent queue kick, or a cancel racing the launch) gets False and
    must not launch a duplicate runner."""
    pb = await _init_clean_db(tmp_path, monkeypatch)
    job = await db_module.create_job(pb, None)

    assert await db_module.start_job(job) is True
    assert await db_module.start_job(job) is False  # already running

    cancelled = await db_module.create_job(pb, None)
    await db_module.cancel_job(cancelled)
    assert await db_module.start_job(cancelled) is False  # cancel won first


async def test_dependencies_gate_until_success(tmp_path, monkeypatch):
    pb = await _init_clean_db(tmp_path, monkeypatch)
    dep = await db_module.create_job(pb, None)
    dependent = await db_module.create_job(pb, None, depends_on=[dep])

    # Dependency still queued → not met.
    assert await db_module.check_job_dependencies_met(dependent) is False

    await db_module.start_job(dep)
    await db_module.finish_job(dep, "success", hosts_ok=1)
    assert await db_module.check_job_dependencies_met(dependent) is True


async def test_failed_dependency_keeps_gate_closed(tmp_path, monkeypatch):
    pb = await _init_clean_db(tmp_path, monkeypatch)
    dep = await db_module.create_job(pb, None)
    dependent = await db_module.create_job(pb, None, depends_on=[dep])

    await db_module.start_job(dep)
    await db_module.finish_job(dep, "failed", hosts_failed=1)
    assert await db_module.check_job_dependencies_met(dependent) is False


async def test_no_dependencies_is_always_met(tmp_path, monkeypatch):
    pb = await _init_clean_db(tmp_path, monkeypatch)
    job = await db_module.create_job(pb, None)
    assert await db_module.check_job_dependencies_met(job) is True


async def test_cancel_only_hits_queued_or_running(tmp_path, monkeypatch):
    pb = await _init_clean_db(tmp_path, monkeypatch)
    job = await db_module.create_job(pb, None)

    assert await db_module.cancel_job(job, "tester") is True
    # Already cancelled → no row matches.
    assert await db_module.cancel_job(job, "tester") is False

    done = await db_module.create_job(pb, None)
    await db_module.start_job(done)
    await db_module.finish_job(done, "success")
    assert await db_module.cancel_job(done, "tester") is False


async def test_priority_update_only_while_queued_and_clamped(tmp_path, monkeypatch):
    pb = await _init_clean_db(tmp_path, monkeypatch)
    job = await db_module.create_job(pb, None, priority=2)

    assert await db_module.update_job_priority(job, 99) is True
    fetched = await db_module.get_job(job)
    assert fetched["priority"] == 4  # clamped to max

    await db_module.start_job(job)
    assert await db_module.update_job_priority(job, 1) is False


# ── _JobEventWriter ──────────────────────────────────────────────────────────


async def test_event_writer_persists_in_order(tmp_path, monkeypatch):
    pb = await _init_clean_db(tmp_path, monkeypatch)
    job = await db_module.create_job(pb, None)

    writer = _JobEventWriter(job, batch_size=2, flush_seconds=0.05)
    for i in range(5):
        writer.enqueue(LogEvent(level="info", message=f"line {i}", host="sw1"))
    await writer.close()

    events = await db_module.get_job_events(job)
    assert [e["message"] for e in events] == [f"line {i}" for i in range(5)]
    assert all(e["level"] == "info" and e["host"] == "sw1" for e in events)


async def test_event_writer_rejects_enqueue_after_close(tmp_path, monkeypatch):
    pb = await _init_clean_db(tmp_path, monkeypatch)
    job = await db_module.create_job(pb, None)

    writer = _JobEventWriter(job)
    await writer.close()
    with pytest.raises(RuntimeError):
        writer.enqueue(LogEvent(level="info", message="too late"))
