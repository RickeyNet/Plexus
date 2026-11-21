"""Object-level permissions in the configuration modules: Config Backups,
Config Drift (HTTP and both WebSockets) and Intended Configuration.

A scoped user may read group A, read and write group B, and has nothing on
group C. Lists, summaries, searches and exports show only A and B; every
by-id read of a C record answers exactly like an unknown id; writes on A
records answer 403 and on B succeed; "all hosts" actions touch only
writable hosts. Device sessions are mocked."""

from __future__ import annotations

import asyncio
import io
import sys
import types
import zipfile
from unittest.mock import AsyncMock

import netcontrol.routes.config_backups as config_backups
import netcontrol.routes.config_drift as config_drift
import pytest
import routes.database as db
from netcontrol import object_scope
from netcontrol.routes import state
from netcontrol.routes.device_config import DeviceConfig

from mcp_helpers import CsrfClient, admin_client, user_client
from test_object_scope_api import _error, _group, _host, _scoped

READ_ONLY = _error(object_scope.READ_ONLY_DETAIL)
FEATURES = sorted(object_scope.SCOPE_ENFORCED_FEATURES)
CONFIG = "hostname {name}\nsnmp-server community public RO\n"
UNKNOWN = 999999


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


@pytest.fixture
def abc(admin) -> dict[str, int]:
    """Groups A, B and C with one host each."""
    t = {"A": _group(admin, "site-a"), "B": _group(admin, "site-b"), "C": _group(admin, "site-c")}
    t["hA"] = _host(admin, t["A"], "edge-a", "192.0.2.10")
    t["hB"] = _host(admin, t["B"], "edge-b", "198.51.100.20")
    t["hC"] = _host(admin, t["C"], "edge-c", "203.0.113.30")
    return t


@pytest.fixture
def scoped(admin, abc) -> CsrfClient:
    grants = [{"inventory_group_id": abc["A"]}, {"inventory_group_id": abc["B"], "can_write": True}]
    return _scoped(admin, "config-ops", grants, FEATURES)


@pytest.fixture
def devices(monkeypatch):
    """No device sessions: captures return a fixed config, credentials pass."""
    cred = AsyncMock(return_value={"username": "u", "password": "", "secret": ""})
    monkeypatch.setattr(config_backups, "require_credential_access", cred)
    monkeypatch.setattr(config_drift, "require_credential_access", cred)

    async def _capture(host, _cred, **_kw):
        return DeviceConfig(int(host["id"]), CONFIG.format(name=host["hostname"]), "", created=True, reused=False)

    monkeypatch.setattr(config_backups, "get_device_config", _capture)
    monkeypatch.setattr(config_drift, "get_device_config", _capture)


def _run(coro):
    return asyncio.run(coro)


def _not_found_alike(client: CsrfClient, url: str, hidden_id: int) -> None:
    """The hidden record answers exactly like an unknown id."""
    hidden = client.get(url.format(hidden_id))
    unknown = client.get(url.format(UNKNOWN))
    assert hidden.status_code == 404, (url, hidden.text)
    assert (hidden.status_code, hidden.json()) == (unknown.status_code, unknown.json()), url


# ── Config Backups ───────────────────────────────────────────────────────────


@pytest.fixture
def backups(abc) -> dict[str, int]:
    out = {"cred": _run(db.create_credential("lab", "operator", "", is_service=True))}
    for key, name in (("A", "edge-a"), ("B", "edge-b"), ("C", "edge-c")):
        host = abc[f"h{key}"]
        _run(db.create_config_backup(None, host, CONFIG.format(name=f"{name}-old"), "manual"))
        out[key] = _run(db.create_config_backup(None, host, CONFIG.format(name=name), "manual"))
        out[f"p{key}"] = _run(db.create_config_backup_policy(f"policy-{key}", abc[key], credential_id=out["cred"]))
    return out


def test_backup_lists_summary_search_and_export_show_readable_hosts(admin, abc, scoped, backups):
    mine = {abc["hA"], abc["hB"]}
    rows = scoped.get("/api/config-backups").json()
    assert {r["host_id"] for r in rows} == mine
    assert len(rows) == 4
    assert scoped.get(f"/api/config-backups?host_id={abc['hC']}").json() == []
    assert {r["host_id"] for r in scoped.get("/api/config-backups/latest-per-host").json()} == mine

    summary = scoped.get("/api/config-backups/summary").json()
    assert (summary["total_policies"], summary["total_backups"], summary["hosts_backed_up"]) == (2, 4, 2)
    everything = admin.get("/api/config-backups/summary").json()
    assert everything["total_backups"] >= 6 and everything["total_policies"] >= 3

    for mode in ("substring", "fulltext"):
        found = scoped.get(f"/api/config-backups/search?q=hostname&mode={mode}").json()
        assert {r["host_id"] for r in found["results"]} == mine, mode
        assert found["count"] == 4
        # A search for a secret (the SNMP community) finds it only on the
        # host the user may change: A is read only, so its lines are masked
        # and a hit that matched nothing but the secret is dropped.
        secret = scoped.get(f"/api/config-backups/search?q=public&mode={mode}").json()
        assert {r["host_id"] for r in secret["results"]} == {abc["hB"]}, mode
        assert secret["count"] == 2
        assert not any(r.get("secrets_masked") for r in secret["results"])
    assert {
        r["host_id"] for r in admin.get("/api/config-backups/search?q=public&mode=substring").json()["results"]
    } >= (mine | {abc["hC"]})

    # The archive holds raw configs: only those of hosts the user may change.
    archive = scoped.get("/api/config-backups/download")
    assert archive.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(archive.content)).namelist()
    assert len(names) == 2
    assert all(n.startswith("edge-b") for n in names)
    for hidden in ("hA", "hC"):
        assert scoped.get(f"/api/config-backups/download?host_id={abc[hidden]}").status_code == 404

    policies = scoped.get("/api/config-backups/policies").json()
    assert {p["group_id"] for p in policies} == {abc["A"], abc["B"]}
    assert scoped.get(f"/api/config-backups/policies?group_id={abc['C']}").json() == []


def test_backup_records_by_id_and_writes(abc, scoped, backups):
    for url in (
        "/api/config-backups/{}",
        "/api/config-backups/{}/diff",
        "/api/config-backups/{}/download",
    ):
        _not_found_alike(scoped, url, backups["C"])
        assert scoped.get(url.format(backups["B"])).status_code == 200, url
    # Read only on A: the view and diff come with the secrets masked, and
    # the raw download is refused. Writable B is shown as captured.
    for url in ("/api/config-backups/{}", "/api/config-backups/{}/diff"):
        masked = scoped.get(url.format(backups["A"]))
        assert masked.status_code == 200, url
        assert masked.json()["secrets_masked"] is True, url
        assert "public" not in masked.text, url
    assert scoped.get(f"/api/config-backups/{backups['A']}/download").status_code == 403
    raw = scoped.get(f"/api/config-backups/{backups['B']}").json()
    assert "community public" in raw["config_text"] and not raw.get("secrets_masked")
    assert "community public" in scoped.get(f"/api/config-backups/{backups['B']}/download").text
    _not_found_alike(scoped, "/api/config-backups/policies/{}", backups["pC"])
    assert scoped.get(f"/api/config-backups/policies/{backups['pA']}").status_code == 200

    # Delete: read only on A, hidden C, writable B.
    resp = scoped.delete(f"/api/config-backups/{backups['A']}")
    assert (resp.status_code, resp.json()) == (403, READ_ONLY)
    assert scoped.delete(f"/api/config-backups/{backups['C']}").json() == _error("Backup not found")
    assert scoped.delete(f"/api/config-backups/{backups['B']}").status_code == 200


def test_backup_policies_follow_their_group(abc, scoped, backups, devices):
    body = {"name": "nightly", "credential_id": backups["cred"]}
    resp = scoped.post("/api/config-backups/policies", json={**body, "group_id": abc["C"]})
    assert (resp.status_code, resp.json()) == (404, _error("Inventory group not found"))
    assert scoped.post("/api/config-backups/policies", json={**body, "group_id": abc["A"]}).json() == READ_ONLY
    created = scoped.post("/api/config-backups/policies", json={**body, "group_id": abc["B"]})
    assert created.status_code == 201, created.text

    for pid, status in ((backups["pA"], 403), (backups["pC"], 404), (backups["pB"], 200)):
        assert scoped.put(f"/api/config-backups/policies/{pid}", json={"name": "renamed"}).status_code == status
    run = scoped.post(f"/api/config-backups/policies/{backups['pC']}/run-now")
    assert (run.status_code, run.json()) == (404, _error("Policy not found"))
    assert scoped.post(f"/api/config-backups/policies/{backups['pA']}/run-now").status_code == 403
    run = scoped.post(f"/api/config-backups/policies/{backups['pB']}/run-now")
    assert run.status_code == 200, run.text
    assert run.json()["backed_up"] == 1
    assert scoped.delete(f"/api/config-backups/policies/{backups['pA']}").status_code == 403
    assert scoped.delete(f"/api/config-backups/policies/{backups['pC']}").status_code == 404
    assert scoped.delete(f"/api/config-backups/policies/{backups['pB']}").status_code == 200


def test_restore_needs_write_on_the_backup_host(monkeypatch, abc, scoped, backups, devices):
    pushed: list[str] = []

    class _Session:
        def __init__(self, **device):
            pushed.append(device["host"])

        def enable(self):
            pass

        def send_config_set(self, lines):
            return ""

        def disconnect(self):
            pass

    monkeypatch.setitem(sys.modules, "netmiko", types.SimpleNamespace(ConnectHandler=_Session))
    monkeypatch.setattr("routes.crypto.decrypt", lambda text: text)
    body = {"credential_id": 1}
    resp = scoped.post("/api/config-backups/restore", json={**body, "backup_id": backups["C"]})
    assert (resp.status_code, resp.json()) == (404, _error("Backup not found"))
    resp = scoped.post("/api/config-backups/restore", json={**body, "backup_id": backups["A"]})
    assert (resp.status_code, resp.json()) == (403, READ_ONLY)
    assert pushed == []
    resp = scoped.post("/api/config-backups/restore", json={**body, "backup_id": backups["B"]})
    assert resp.status_code == 200, resp.text
    assert pushed == ["198.51.100.20"]


def test_unrestricted_user_sees_every_backup(admin, abc, backups):
    everyone = user_client(admin, "all-backups", features=["config-backups", "config-backups.write"])
    hosts = {r["host_id"] for r in everyone.get("/api/config-backups").json()}
    assert {abc["hA"], abc["hB"], abc["hC"]} <= hosts
    assert everyone.get(f"/api/config-backups/{backups['C']}").status_code == 200
    assert everyone.get(f"/api/config-backups/policies/{backups['pC']}").status_code == 200


# ── Config Drift ─────────────────────────────────────────────────────────────


@pytest.fixture
def drift(abc) -> dict[str, int]:
    out = {}
    for key in ("A", "B", "C"):
        host = abc[f"h{key}"]
        out[f"bl{key}"] = _run(db.create_config_baseline(host, f"base-{key}", "hostname x\n"))
        out[f"s{key}"] = _run(db.create_config_snapshot(host, "hostname y\n"))
        out[f"e{key}"] = _run(db.create_config_drift_event(host, out[f"s{key}"], out[f"bl{key}"], "-x\n+y\n", 1, 1))
        _run(db.create_config_drift_event_history(out[f"e{key}"], host, "detected", "", "open", "system"))
    return out


def test_drift_lists_and_summary_show_readable_hosts(admin, abc, scoped, drift):
    mine = {abc["hA"], abc["hB"]}
    assert {e["host_id"] for e in scoped.get("/api/config-drift/events").json()} == mine
    assert scoped.get(f"/api/config-drift/events?host_id={abc['hC']}").json() == []
    assert {b["host_id"] for b in scoped.get("/api/config-drift/baselines").json()} == mine
    assert scoped.get(f"/api/config-drift/snapshots?host_id={abc['hC']}").json() == []
    assert scoped.get(f"/api/config-drift/snapshots?host_id={UNKNOWN}").json() == []
    assert len(scoped.get(f"/api/config-drift/snapshots?host_id={abc['hA']}").json()) == 1
    summary = scoped.get("/api/config-drift/summary").json()
    assert summary == {"total_baselined": 2, "compliant": 0, "drifted": 2, "open_events": 2, "accepted_events": 0}
    assert admin.get("/api/config-drift/summary").json()["open_events"] >= 3


def test_drift_records_by_id_answer_like_unknown_ids(scoped, drift):
    for url, key in (
        ("/api/config-drift/baselines/{}", "bl"),
        ("/api/config-drift/snapshots/{}", "s"),
        ("/api/config-drift/events/{}", "e"),
        ("/api/config-drift/events/{}/history", "e"),
    ):
        _not_found_alike(scoped, url, drift[f"{key}C"])
        assert scoped.get(url.format(drift[f"{key}A"])).status_code == 200, url


def test_drift_writes(abc, scoped, drift, devices, monkeypatch):
    monkeypatch.setattr(config_drift, "_run_revert_job", AsyncMock())
    status = {"status": "accepted"}
    assert scoped.put(f"/api/config-drift/events/{drift['eA']}/status", json=status).json() == READ_ONLY
    assert scoped.put(f"/api/config-drift/events/{drift['eC']}/status", json=status).status_code == 404
    assert scoped.put(f"/api/config-drift/events/{drift['eB']}/status", json=status).status_code == 200

    # Bulk: every event must be writable, else nothing changes.
    new_b = _run(db.create_config_drift_event(abc["hB"], drift["sB"], drift["blB"], "-a\n+b\n"))
    for ids, code in (([new_b, drift["eA"]], 403), ([new_b, drift["eC"]], 404), ([new_b, UNKNOWN], 404)):
        assert scoped.post("/api/config-drift/events/bulk-resolve", json={"event_ids": ids}).status_code == code
    assert _run(db.get_config_drift_event(new_b))["status"] == "open"
    resolved = scoped.post("/api/config-drift/events/bulk-resolve", json={"event_ids": [new_b]})
    assert resolved.json() == {"ok": True, "resolved": 1}

    for url, field in (
        ("/api/config-drift/baselines/{}", "bl"),
        ("/api/config-drift/snapshots/{}", "s"),
    ):
        assert scoped.delete(url.format(drift[f"{field}A"])).json() == READ_ONLY
        assert scoped.delete(url.format(drift[f"{field}C"])).status_code == 404
    assert scoped.put(f"/api/config-drift/baselines/{drift['blA']}", json={"name": "x"}).status_code == 403
    assert scoped.put(f"/api/config-drift/baselines/{drift['blB']}", json={"name": "x"}).status_code == 200
    new_baseline = {"name": "n", "config_text": "hostname n\n"}
    assert scoped.post("/api/config-drift/baselines", json={**new_baseline, "host_id": abc["hA"]}).status_code == 403
    assert scoped.post("/api/config-drift/baselines", json={**new_baseline, "host_id": abc["hC"]}).status_code == 404
    assert scoped.post("/api/config-drift/baselines", json={**new_baseline, "host_id": abc["hB"]}).status_code == 201

    # Device actions: capture, check, analyze, revert.
    for url in ("/api/config-drift/snapshots/capture", "/api/config-drift/check", "/api/config-drift/analyze"):
        body = {"host_id": abc["hA"], "credential_id": 1}
        assert scoped.post(url, json=body).json() == READ_ONLY, url
        assert scoped.post(url, json={**body, "host_id": abc["hC"]}).json() == _error("Host not found"), url
        assert scoped.post(url, json={**body, "host_id": abc["hB"]}).status_code == 200, url
    for url in ("/api/config-drift/snapshots/capture-group", "/api/config-drift/analyze-group"):
        body = {"group_id": abc["A"], "credential_id": 1}
        assert scoped.post(url, json=body).json() == READ_ONLY, url
        assert scoped.post(url, json={**body, "group_id": abc["C"]}).json() == _error("No hosts found in group")
        assert scoped.post(url, json={**body, "group_id": abc["B"]}).status_code == 200, url
    revert = {"credential_id": 1}
    assert scoped.post("/api/config-drift/events/revert", json={**revert, "event_id": drift["eA"]}).status_code == 403
    assert scoped.post("/api/config-drift/events/revert", json={**revert, "event_id": drift["eC"]}).status_code == 404
    assert scoped.post("/api/config-drift/events/revert", json={**revert, "event_id": drift["eB"]}).status_code == 200


def test_capture_jobs_and_websockets_hide_out_of_scope_hosts(abc, scoped, drift, devices, monkeypatch):
    monkeypatch.setattr(config_drift, "_run_config_capture_job", AsyncMock())
    assert (
        scoped.post(
            "/api/config-drift/snapshots/capture-single-job", json={"host_id": abc["hA"], "credential_id": 1}
        ).json()
        == READ_ONLY
    )
    assert (
        scoped.post(
            "/api/config-drift/snapshots/capture-job", json={"group_id": abc["C"], "credential_id": 1}
        ).status_code
        == 404
    )
    started = scoped.post("/api/config-drift/snapshots/capture-job", json={"group_id": abc["B"], "credential_id": 1})
    assert started.status_code == 200, started.text
    job_id = started.json()["job_id"]
    assert config_drift._capture_jobs[job_id]["group_ids"] == [abc["B"]]
    assert scoped.get(f"/api/config-drift/capture-job/{job_id}").status_code == 200

    def _job(group_id: int) -> dict:
        return {
            "job_id": "x",
            "status": "completed",
            "started_at": "",
            "finished_at": "",
            "output_lines": ["edge\n"],
            "output": "edge\n",
            "launched_by": "config-ops",
            "group_ids": [group_id],
        }

    monkeypatch.setitem(config_drift._capture_jobs, "hidden-capture", _job(abc["C"]))
    monkeypatch.setitem(config_drift._capture_jobs, "mine-capture", _job(abc["A"]))
    monkeypatch.setitem(config_drift._revert_jobs, "hidden-revert", _job(abc["C"]))
    monkeypatch.setitem(config_drift._revert_jobs, "mine-revert", _job(abc["B"]))
    hidden = scoped.get("/api/config-drift/capture-job/hidden-capture")
    assert (hidden.status_code, hidden.json()) == (404, _error("Capture job not found"))

    with scoped.raw.websocket_connect("/ws/config-capture/hidden-capture") as ws:
        assert ws.receive_json() == {"type": "error", "message": "Job not found"}
    with scoped.raw.websocket_connect("/ws/config-capture/mine-capture") as ws:
        assert ws.receive_json() == {"type": "line", "text": "edge\n"}
        assert ws.receive_json()["type"] == "job_complete"
    with scoped.raw.websocket_connect("/ws/config-revert/hidden-revert") as ws:
        assert ws.receive_json() == {"type": "error", "data": "Job not found"}
    with scoped.raw.websocket_connect("/ws/config-revert/mine-revert") as ws:
        assert ws.receive_json() == {"type": "line", "data": "edge\n"}


def test_capture_job_status_is_for_its_launcher_or_an_admin(admin, abc, monkeypatch):
    """The HTTP twin of /ws/config-capture checks the launcher like the
    socket does; another user's job answers like an unknown one."""
    job = {
        "job_id": "other-capture",
        "status": "completed",
        "started_at": "",
        "finished_at": "",
        "output_lines": ["hostname edge-1\n"],
        "launched_by": "someone-else",
        "group_ids": [abc["B"]],
    }
    monkeypatch.setitem(config_drift._capture_jobs, "other-capture", job)
    everyone = user_client(admin, "all-capture", features=["config-drift"])
    other = everyone.get("/api/config-drift/capture-job/other-capture")
    unknown = everyone.get("/api/config-drift/capture-job/no-such-capture")
    expected = (404, _error("Capture job not found"))
    assert (other.status_code, other.json()) == (unknown.status_code, unknown.json()) == expected
    monkeypatch.setitem(config_drift._capture_jobs, "own-capture", {**job, "launched_by": "all-capture"})
    assert everyone.get("/api/config-drift/capture-job/own-capture").status_code == 200
    assert admin.get("/api/config-drift/capture-job/other-capture").json()["output"] == "hostname edge-1\n"


def test_unrestricted_user_sees_every_drift_record(admin, abc, drift):
    everyone = user_client(admin, "all-drift", features=["config-drift"])
    hosts = {e["host_id"] for e in everyone.get("/api/config-drift/events").json()}
    assert {abc["hA"], abc["hB"], abc["hC"]} <= hosts
    assert everyone.get(f"/api/config-drift/events/{drift['eC']}").status_code == 200
    assert everyone.get("/api/config-drift/summary").json()["open_events"] >= 3


# ── Intended configuration ───────────────────────────────────────────────────


@pytest.fixture
def intended(admin, abc) -> dict:
    template = {"name": "all", "kind": "device", "template_text": "hostname {{ host.name }}\n"}
    out = {"template": admin.post("/api/intended-config/templates", json=template).json()["id"]}
    hidden = {"name": "site-c", "kind": "device", "group_id": abc["C"], "template_text": "hostname c\n"}
    out["hidden_template"] = admin.post("/api/intended-config/templates", json=hidden).json()["id"]
    for name, extra in (("for-c", {"group_id": abc["C"]}), ("for-edge-c", {"host_id": abc["hC"]}), ("for-a", {})):
        resp = admin.post("/api/intended-config/contexts", json={"name": name, "data": {"x": 1}, **extra})
        assert resp.status_code == 201, resp.text
        out[name] = resp.json()["id"]
    generated = admin.post("/api/intended-config/generate", json={"host_ids": [abc["hA"], abc["hB"], abc["hC"]]})
    assert generated.json()["generated"] == 3, generated.text
    return out


def test_intended_rows_counts_and_records(admin, abc, scoped, intended):
    listed = scoped.get("/api/intended-config/hosts").json()
    assert {r["host_id"] for r in listed["rows"]} == {abc["hA"], abc["hB"]}
    assert listed["counts"]["hosts"] == 2
    assert listed["counts"]["generated"] == 2
    assert admin.get("/api/intended-config/hosts").json()["counts"]["generated"] >= 3

    templates = {t["id"]: t for t in scoped.get("/api/intended-config/templates").json()["templates"]}
    assert set(templates) == {intended["template"]}
    # Counted over the readable hosts only (edge-c rendered from site-c).
    assert templates[intended["template"]]["host_count"] == 2
    assert scoped.get(f"/api/intended-config/templates/{intended['template']}").json()["host_count"] == 2
    _not_found_alike(scoped, "/api/intended-config/templates/{}", intended["hidden_template"])
    assert {c["id"] for c in scoped.get("/api/intended-config/contexts").json()["contexts"]} == {intended["for-a"]}
    _not_found_alike(scoped, "/api/intended-config/contexts/{}", intended["for-c"])
    _not_found_alike(scoped, "/api/intended-config/contexts/{}", intended["for-edge-c"])

    _not_found_alike(scoped, "/api/intended-config/hosts/{}", abc["hC"])
    _not_found_alike(scoped, "/api/intended-config/hosts/{}/variables", abc["hC"])
    assert scoped.get(f"/api/intended-config/hosts/{abc['hA']}").status_code == 200
    assert scoped.get(f"/api/intended-config/hosts/{abc['hA']}/variables").status_code == 200


def test_generate_needs_write(admin, abc, scoped, intended):
    generate = "/api/intended-config/generate"
    assert scoped.post(generate, json={"host_ids": [abc["hA"]]}).json() == READ_ONLY
    assert scoped.post(generate, json={"host_ids": [abc["hB"], abc["hC"]]}).status_code == 404
    assert scoped.post(generate, json={"group_id": abc["A"]}).json() == READ_ONLY
    assert scoped.post(generate, json={"group_id": abc["C"]}).json() == _error("Group not found")
    assert scoped.post(generate, json={"group_id": abc["B"]}).json()["hosts"] == 1
    assert scoped.post(generate, json={"host_ids": [abc["hB"]]}).json()["hosts"] == 1
    # "Every host" is every writable host for a scoped caller.
    assert scoped.post(generate, json={}).json()["hosts"] == 1
    everyone = admin.post(generate, json={}).json()
    assert everyone["hosts"] >= 3


def test_unrestricted_user_sees_every_intended_row(admin, abc, intended):
    everyone = user_client(admin, "all-intended", features=["config-drift"])
    rows = everyone.get("/api/intended-config/hosts").json()["rows"]
    assert {abc["hA"], abc["hB"], abc["hC"]} <= {r["host_id"] for r in rows}
    templates = {t["id"] for t in everyone.get("/api/intended-config/templates").json()["templates"]}
    assert {intended["template"], intended["hidden_template"]} <= templates
    assert everyone.get(f"/api/intended-config/contexts/{intended['for-c']}").status_code == 200
