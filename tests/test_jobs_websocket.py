"""/ws/jobs/{id}: a queued job streams instead of reporting itself complete."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from netcontrol.routes import jobs


def _event(event_id: int, message: str) -> dict:
    return {"id": event_id, "level": "info", "message": message, "host": "", "timestamp": "2026-11-04T17:53:41Z"}


@pytest.fixture
def ws_client(monkeypatch: pytest.MonkeyPatch):
    """App with only the jobs WS router; auth and job storage stubbed.

    ``state["statuses"]`` is consumed one per ``get_job`` call (the last
    repeats); ``state["events"]`` is a list of event lists, one per
    ``get_job_events`` call (the last repeats).
    """
    state: dict = {"statuses": ["success"], "events": [[]]}

    async def verify(token):
        return {"user_id": 1, "user": "admin"}

    async def get_user(user_id):
        return {"id": 1, "role": "admin"}

    async def features(user):
        return ["jobs"]

    async def get_job(job_id):
        status = state["statuses"].pop(0) if len(state["statuses"]) > 1 else state["statuses"][0]
        return {"id": job_id, "status": status, "launched_by": "admin"}

    async def get_events(job_id, limit=10000):
        return state["events"].pop(0) if len(state["events"]) > 1 else state["events"][0]

    monkeypatch.setattr(jobs, "verify_ws_session", verify)
    monkeypatch.setattr(jobs, "_get_user_features", features)
    monkeypatch.setattr(jobs.db, "get_user_by_id", get_user)
    monkeypatch.setattr(jobs.db, "get_job", get_job)
    monkeypatch.setattr(jobs.db, "get_job_events", get_events)

    app = FastAPI()
    app.include_router(jobs.ws_router)
    with TestClient(app) as client:
        client.cookies.set("session", "x")
        yield client, state


def test_finished_job_replays_and_completes(ws_client) -> None:
    client, state = ws_client
    state["statuses"] = ["success"]
    state["events"] = [[_event(1, "PLAY [all]")]]
    with client.websocket_connect("/ws/jobs/7") as ws:
        assert ws.receive_json()["message"] == "PLAY [all]"
        assert ws.receive_json() == {"type": "job_complete", "job_id": 7, "status": "success"}


def test_queued_job_is_not_reported_complete(ws_client) -> None:
    """A queued job subscribes; when it then finishes before the subscription
    took effect, the viewer still gets the late lines and the real status."""
    client, state = ws_client
    # Status read on connect: queued. Re-check after subscribing: success.
    state["statuses"] = ["queued", "success"]
    state["events"] = [[_event(1, "Job queued")], [_event(1, "Job queued"), _event(2, "ok: [sw1]")]]
    with client.websocket_connect("/ws/jobs/7") as ws:
        assert ws.receive_json()["message"] == "Job queued"
        # Only the line logged after the replay - no duplicate of event 1.
        assert ws.receive_json()["message"] == "ok: [sw1]"
        done = ws.receive_json()
    assert done == {"type": "job_complete", "job_id": 7, "status": "success"}
    assert 7 not in jobs._job_sockets or not jobs._job_sockets[7]
