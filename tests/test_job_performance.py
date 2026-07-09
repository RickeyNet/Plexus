from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
import routes.database as db_module
from netcontrol.routes import jobs
from routes.runner import BasePlaybook, LogEvent


@pytest.mark.asyncio
async def test_job_event_writer_batches_and_preserves_order(monkeypatch):
    calls: list[tuple[int, list[tuple[str, str, str]]]] = []

    async def add_job_events(job_id, events):
        calls.append((job_id, list(events)))

    monkeypatch.setattr(jobs.db, "add_job_events", add_job_events)

    writer = jobs._JobEventWriter(42, batch_size=3, flush_seconds=10)
    for i in range(5):
        writer.enqueue(LogEvent(level="info", message=f"event-{i}", host="sw1"))
    await writer.close()

    assert [len(events) for _, events in calls] == [3, 2]
    assert [event[1] for _, events in calls for event in events] == [
        "event-0",
        "event-1",
        "event-2",
        "event-3",
        "event-4",
    ]


@pytest.mark.asyncio
async def test_add_job_events_uses_one_ordered_transaction(monkeypatch):
    calls = []

    class FakeDb:
        async def executemany(self, query, params):
            calls.append(("executemany", query, list(params)))

        async def commit(self):
            calls.append(("commit",))

        async def close(self):
            calls.append(("close",))

    async def get_db():
        return FakeDb()

    monkeypatch.setattr(db_module, "get_db", get_db)

    await db_module.add_job_events(
        17,
        [
            ("info", "first", "sw1"),
            ("success", "second", "sw1"),
            ("warning", "third", "sw2"),
        ],
    )

    assert calls[0][0] == "executemany"
    assert calls[0][2] == [
        (17, "info", "sw1", "first"),
        (17, "success", "sw1", "second"),
        (17, "warning", "sw2", "third"),
    ]
    assert calls[1:] == [("commit",), ("close",)]


@pytest.mark.asyncio
async def test_postgres_compat_executemany_converts_parameters():
    calls = []

    class FakeTx:
        async def start(self):
            pass

        async def commit(self):
            pass

        async def rollback(self):
            pass

    class FakePgConnection:
        def transaction(self):
            # executemany is a write, so the compat layer opens an implicit
            # transaction (and a per-statement savepoint) around it.
            return FakeTx()

        async def executemany(self, query, params):
            calls.append((query, params))

    compat = db_module._PostgresConnectionCompat(FakePgConnection())
    cursor = await compat.executemany(
        "INSERT INTO job_events (job_id, level, message) VALUES (?,?,?)",
        [(1, "info", "first"), (1, "info", "second")],
    )

    assert calls == [
        (
            "INSERT INTO job_events (job_id, level, message) VALUES ($1,$2,$3)",
            [(1, "info", "first"), (1, "info", "second")],
        )
    ]
    assert cursor.rowcount == 2


@pytest.mark.asyncio
async def test_run_job_flushes_events_before_marking_complete(monkeypatch):
    timeline = []

    async def add_job_events(job_id, events):
        timeline.append(("persist", job_id, [event[1] for event in events]))

    async def finish_job(job_id, **kwargs):
        timeline.append(("finish", job_id, kwargs["status"]))

    async def execute_playbook(*args, **kwargs):
        callback = args[5]
        await callback(LogEvent(level="info", message="first", host="sw1"))
        await callback(
            LogEvent(
                level="success",
                message="Finished processing sw1.",
                host="sw1",
            )
        )
        return SimpleNamespace(status="success", hosts_skipped=0)

    monkeypatch.setattr(jobs.db, "add_job_events", add_job_events)
    monkeypatch.setattr(jobs.db, "finish_job", finish_job)
    monkeypatch.setattr(jobs, "execute_playbook", execute_playbook)

    await jobs._run_job(
        23,
        object,
        [{"hostname": "sw1"}],
        {},
        [],
        True,
    )

    assert timeline == [
        ("persist", 23, ["first", "Finished processing sw1."]),
        ("finish", 23, "success"),
    ]


@pytest.mark.asyncio
async def test_run_job_records_cancellation_after_writer_already_closed(monkeypatch):
    timeline = []

    async def execute_playbook(*args, **kwargs):
        return SimpleNamespace(status="success", hosts_skipped=0)

    async def finish_job(job_id, **kwargs):
        raise asyncio.CancelledError

    async def add_job_event(job_id, level, message, host):
        timeline.append(("event", job_id, level, message))

    async def cancel_job(job_id, cancelled_by):
        timeline.append(("cancel", job_id, cancelled_by))

    monkeypatch.setattr(jobs, "execute_playbook", execute_playbook)
    monkeypatch.setattr(jobs.db, "finish_job", finish_job)
    monkeypatch.setattr(jobs.db, "add_job_event", add_job_event)
    monkeypatch.setattr(jobs.db, "cancel_job", cancel_job)

    await jobs._run_job(24, object, [], {}, [], True)

    assert timeline == [
        ("event", 24, "warning", "Job cancelled by user"),
        ("cancel", 24, "system"),
    ]


@pytest.mark.asyncio
async def test_host_runner_bounds_concurrency_and_preserves_host_order():
    playbook = BasePlaybook()
    playbook.host_concurrency = 2
    active = 0
    max_active = 0

    async def worker(host):
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        try:
            yield LogEvent(level="info", message="start", host=host["hostname"])
            await asyncio.sleep(0.02)
            yield LogEvent(level="success", message="finish", host=host["hostname"])
        finally:
            active -= 1

    hosts = [{"hostname": f"sw{i}"} for i in range(5)]
    events = [
        event
        async for event in playbook.run_hosts_concurrently(hosts, worker)
    ]

    assert max_active == 2
    for host in hosts:
        messages = [
            event.message for event in events if event.host == host["hostname"]
        ]
        assert messages == ["start", "finish"]
