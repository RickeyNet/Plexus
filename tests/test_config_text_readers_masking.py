"""Device configuration text is read under one rule on every page.

A running configuration holds the device's secrets (enable and user
secrets, SNMP communities, TACACS+/RADIUS keys). An admin, the API token, or
a user holding ``config-backups.write`` with write access to the device's
group reads it as captured; every other reader gets the secrets masked. The
rule lives in ``netcontrol.routes.config_visibility`` and covers each copy
of the configuration: config backups, drift snapshots, baselines and drift
diffs, compliance scan snippets, audit drift evidence, lab twins and their
runs, intended-config comparisons and remediation, risk analyses and the
drift events shown beside alerts.

Every secret and address below is invented.
"""

from __future__ import annotations

import functools

import pytest
import routes.database as db_module
from netcontrol.routes.config_visibility import mask_commands, mask_lines, restore_masked_lines

from mcp_helpers import admin_client, user_client

ENABLE_SECRET = "example-secret-value-0001"
COMMUNITY = "example-secret-value-0002"
TACACS_KEY = "example-secret-value-0003"
SECRETS = (ENABLE_SECRET, COMMUNITY, TACACS_KEY)
CONFIG = (
    "hostname edge-sw1\n"
    f"enable secret 0 {ENABLE_SECRET}\n"
    f"snmp-server community {COMMUNITY} RO\n"
    "tacacs server tac-a\n"
    " address ipv4 192.0.2.50\n"
    f" key 0 {TACACS_KEY}\n"
    "interface GigabitEthernet0/1\n"
    " description uplink\n"
)
# A user who reads device configuration as captured.
RAW_FEATURES = ["config-backups", "config-backups.write"]


def _leaked(text: str) -> list[str]:
    return [s for s in SECRETS if s in text]


@pytest.fixture
def env(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    call = admin.raw.portal.call
    group = admin.post("/api/inventory", json={"name": "masking-lab"})
    assert group.status_code == 201, group.text
    gid = int(group.json()["id"])
    host = admin.post(
        f"/api/inventory/{gid}/hosts",
        json={"hostname": "edge-sw1", "ip_address": "192.0.2.21", "device_type": "cisco_ios"},
    )
    assert host.status_code == 201, host.text
    host_id = int(host.json()["id"])
    return {"admin": admin, "call": call, "gid": gid, "host_id": host_id}


# ── Config drift ─────────────────────────────────────────────────────────────


def test_config_drift_snapshot_masks_secrets_for_read_only_users(env):
    call, host_id = env["call"], env["host_id"]
    snapshot_id = call(functools.partial(db_module.create_config_snapshot, host_id, CONFIG, "manual"))
    reader = user_client(env["admin"], "drift-reader", features=["config-drift"])

    resp = reader.get(f"/api/config-drift/snapshots/{snapshot_id}")
    assert resp.status_code == 200, resp.text
    assert _leaked(resp.text) == [], "drift snapshot returned device secrets to a read-only config-drift user"
    assert resp.json()["secrets_masked"] is True
    # The structure stays readable: the masked line keeps its keyword.
    assert "snmp-server community" in resp.json()["config_text"]


def test_config_drift_snapshot_is_raw_for_callers_with_the_raw_right(env):
    call, host_id = env["call"], env["host_id"]
    snapshot_id = call(functools.partial(db_module.create_config_snapshot, host_id, CONFIG, "manual"))
    writer = user_client(env["admin"], "drift-raw", features=["config-drift", *RAW_FEATURES])

    for client in (env["admin"], writer):
        resp = client.get(f"/api/config-drift/snapshots/{snapshot_id}")
        assert resp.status_code == 200, resp.text
        assert resp.json()["config_text"] == CONFIG
        assert not resp.json().get("secrets_masked")


def test_config_drift_baseline_masks_secrets_for_read_only_users(env):
    call, host_id = env["call"], env["host_id"]
    baseline_id = call(
        functools.partial(db_module.create_config_baseline, host_id, name="golden", config_text=CONFIG)
    )
    reader = user_client(env["admin"], "baseline-reader", features=["config-drift"])

    detail = reader.get(f"/api/config-drift/baselines/{baseline_id}")
    listing = reader.get("/api/config-drift/baselines")
    assert detail.status_code == 200 and listing.status_code == 200
    assert _leaked(detail.text) == [], "baseline detail returned device secrets to a read-only config-drift user"
    assert _leaked(listing.text) == [], "baseline list returned device secrets to a read-only config-drift user"

    writer = user_client(env["admin"], "baseline-raw", features=["config-drift", *RAW_FEATURES])
    assert writer.get(f"/api/config-drift/baselines/{baseline_id}").json()["config_text"] == CONFIG
    assert [b["config_text"] for b in writer.get("/api/config-drift/baselines").json()] == [CONFIG]


def test_config_drift_event_diff_masks_secrets_for_read_only_users(env):
    call, host_id = env["call"], env["host_id"]
    snapshot_id = call(functools.partial(db_module.create_config_snapshot, host_id, CONFIG, "manual"))
    diff = f"--- baseline\n+++ actual\n-snmp-server community old RO\n+snmp-server community {COMMUNITY} RO\n"
    event_id = call(functools.partial(db_module.create_config_drift_event, host_id, snapshot_id, None, diff, 1, 1))
    reader = user_client(env["admin"], "event-reader", features=["config-drift"])

    resp = reader.get(f"/api/config-drift/events/{event_id}")
    listing = reader.get("/api/config-drift/events")
    assert resp.status_code == 200 and listing.status_code == 200, resp.text
    assert COMMUNITY not in resp.text, "drift event diff returned an SNMP community to a read-only config-drift user"
    assert COMMUNITY not in listing.text, "drift event list returned an SNMP community to a read-only user"
    # The masked diff keeps one line per line.
    assert len(resp.json()["diff_text"].splitlines()) == len(diff.splitlines())

    writer = user_client(env["admin"], "event-raw", features=["config-drift", *RAW_FEATURES])
    assert writer.get(f"/api/config-drift/events/{event_id}").json()["diff_text"] == diff


def test_baseline_saved_from_a_masked_snapshot_stores_the_configuration(env):
    """A drift writer without the raw right takes the newest snapshot (masked
    for them) as the baseline: the stored baseline holds the captured lines,
    not the mask, so drift detection keeps comparing like with like."""
    call, host_id = env["call"], env["host_id"]
    snapshot_id = call(functools.partial(db_module.create_config_snapshot, host_id, CONFIG, "manual"))
    writer = user_client(env["admin"], "drift-writer", features=["config-drift", "config-drift.write"])

    masked = writer.get(f"/api/config-drift/snapshots/{snapshot_id}").json()["config_text"]
    assert _leaked(masked) == []
    created = writer.post("/api/config-drift/baselines", json={"host_id": host_id, "config_text": masked})
    assert created.status_code == 201, created.text

    stored = env["admin"].get(f"/api/config-drift/baselines/{created.json()['id']}").json()["config_text"]
    assert stored == CONFIG


def test_restore_masked_lines_keeps_equal_lines_in_source_order():
    source = "snmp-server community first-0001 RO\nsnmp-server community second-0002 RO\nhostname a\n"
    masked = "\n".join(mask_lines(source.splitlines())) + "\n"
    assert "first-0001" not in masked
    assert restore_masked_lines(masked, source) == source
    # A line with no source stays masked; text with no mask is untouched.
    assert restore_masked_lines("enable secret 0 ********\n", source) == "enable secret 0 ********\n"
    assert restore_masked_lines("hostname b\n", source) == "hostname b\n"


# ── Compliance ───────────────────────────────────────────────────────────────


def test_compliance_result_snippet_masks_secrets_for_every_reader(env):
    """The snippet has no reader in the application; it is masked for every
    caller, rows stored before the scan masked it included."""
    call, host_id = env["call"], env["host_id"]
    profile_id = call(functools.partial(db_module.create_compliance_profile, "masking-profile"))
    result_id = call(
        functools.partial(
            db_module.create_compliance_scan_result, None, profile_id, host_id, config_snippet=CONFIG[:2000]
        )
    )
    reader = user_client(env["admin"], "compliance-reader", features=["compliance"])

    for client in (reader, env["admin"]):
        detail = client.get(f"/api/compliance/results/{result_id}")
        listing = client.get("/api/compliance/results")
        assert detail.status_code == 200 and listing.status_code == 200
        assert _leaked(detail.text) == [], "compliance result detail returned device secrets"
        assert _leaked(listing.text) == [], "compliance result list returned device secrets"
        assert detail.json()["config_snippet"].startswith("hostname edge-sw1\n")


async def test_compliance_scan_stores_a_masked_snippet(monkeypatch):
    from types import SimpleNamespace

    from netcontrol.routes import compliance

    async def fake_config(*_args, **_kwargs):
        return SimpleNamespace(config_text=CONFIG)

    monkeypatch.setattr(compliance, "get_device_config", fake_config)
    profile = {"rules": [{"name": "community set", "type": "must_contain", "pattern": "snmp-server community"}]}
    result = await compliance._evaluate_host_compliance({"id": 1, "ip_address": "192.0.2.21"}, profile, {})

    assert result["passed_rules"] == 1  # rules still see the captured text
    assert _leaked(result["config_snippet"]) == []


# ── Audit ────────────────────────────────────────────────────────────────────


def test_audit_drift_finding_masks_secrets_for_reports_users(env):
    call, host_id = env["call"], env["host_id"]
    baseline = CONFIG.replace(COMMUNITY, "old-community-placeholder")
    call(functools.partial(db_module.create_config_baseline, host_id, name="golden", config_text=baseline))
    call(functools.partial(db_module.create_config_snapshot, host_id, CONFIG, "manual"))
    reporter = user_client(env["admin"], "reports-only", features=["reports"])

    run = env["admin"].post("/api/audit/runs")  # starting a run needs reports.write
    assert run.status_code == 201, run.text
    findings = reporter.get(f"/api/audit/runs/{run.json()['id']}/findings")
    assert findings.status_code == 200, findings.text
    drift = [f for f in findings.json()["findings"] if f["rule_id"] == "config.drift"]
    assert drift, findings.text
    assert drift[0]["evidence"]["lines_added"] == 1  # evaluated on the captured text
    assert COMMUNITY not in findings.text, "audit drift evidence returned an SNMP community to a reports-only user"
    assert _leaked(env["admin"].get(f"/api/hosts/{host_id}/audit-findings").text) == []

    # Stored masked, not only masked on the way out.
    stored = call(functools.partial(_evidence_rows, int(run.json()["id"])))
    assert stored and all(_leaked(text) == [] for text in stored)


async def _evidence_rows(run_id: int) -> list[str]:
    conn = await db_module.get_db()
    try:
        cursor = await conn.execute("SELECT evidence_json FROM audit_findings WHERE run_id = ?", (run_id,))
        return [str(row[0]) for row in await cursor.fetchall()]
    finally:
        await conn.close()


# ── Lab ──────────────────────────────────────────────────────────────────────


def _clone(client, host_id: int) -> dict:
    lab_env = client.post("/api/lab/environments", json={"name": "masking-env"})
    assert lab_env.status_code in (200, 201), lab_env.text
    cloned = client.post(f"/api/lab/environments/{lab_env.json()['id']}/clone-host", json={"host_id": host_id})
    assert cloned.status_code in (200, 201), cloned.text
    return cloned.json()


def test_lab_clone_does_not_unmask_config_for_read_only_backup_users(env):
    """A caller whose backup view is masked gets a twin of the masked text."""
    call, host_id = env["call"], env["host_id"]
    call(functools.partial(db_module.create_config_snapshot, host_id, CONFIG, "manual"))
    user = user_client(env["admin"], "lab-user", features=["lab", "lab.write", "config-backups"])

    cloned = _clone(user, host_id)
    assert cloned["secrets_masked"] is True
    device = user.get(f"/api/lab/devices/{cloned['id']}")
    assert device.status_code == 200, device.text
    assert _leaked(device.text) == [], "lab twin returned the raw running config to a read-only config-backups user"
    # Stored masked: even an admin reading the twin sees no secret.
    assert _leaked(env["admin"].get(f"/api/lab/devices/{cloned['id']}").text) == []

    simulated = user.post(f"/api/lab/devices/{cloned['id']}/simulate", json={"proposed_commands": ["ntp server 192.0.2.9"]})
    assert simulated.status_code == 200, simulated.text
    assert _leaked(simulated.text) == []


def test_lab_clone_is_raw_for_callers_with_the_raw_right(env):
    call, host_id = env["call"], env["host_id"]
    call(functools.partial(db_module.create_config_snapshot, host_id, CONFIG, "manual"))
    user = user_client(env["admin"], "lab-raw", features=["lab", "lab.write", *RAW_FEATURES])

    cloned = _clone(user, host_id)
    assert cloned["secrets_masked"] is False
    assert user.get(f"/api/lab/devices/{cloned['id']}").json()["running_config"] == CONFIG


def test_lab_twin_and_runs_of_a_raw_clone_are_masked_for_other_readers(env):
    """A twin an admin cloned as captured, in a shared environment, is read
    masked by a user who may not read the host's configuration."""
    call, host_id, admin = env["call"], env["host_id"], env["admin"]
    call(functools.partial(db_module.create_config_snapshot, host_id, CONFIG, "manual"))
    lab_env = admin.post("/api/lab/environments", json={"name": "shared-env", "shared": True})
    assert lab_env.status_code in (200, 201), lab_env.text
    cloned = admin.post(f"/api/lab/environments/{lab_env.json()['id']}/clone-host", json={"host_id": host_id})
    device_id = cloned.json()["id"]
    run = admin.post(f"/api/lab/devices/{device_id}/simulate", json={"proposed_commands": ["no enable secret"]})
    assert run.status_code == 200, run.text
    drift_run_id = call(
        functools.partial(
            db_module.create_lab_drift_run,
            device_id,
            host_id,
            "drifted",
            diff_text=f"--- twin\n+++ production\n-snmp-server community {COMMUNITY} RO\n",
            diff_removed=1,
        )
    )
    reader = user_client(env["admin"], "lab-reader", features=["lab"])

    for path in (
        f"/api/lab/devices/{device_id}",
        f"/api/lab/runs/{run.json()['run_id']}",
        f"/api/lab/drift/runs/{drift_run_id}",
    ):
        resp = reader.get(path)
        assert resp.status_code == 200, (path, resp.text)
        assert _leaked(resp.text) == [], path
        assert _leaked(admin.get(path).text) != [], path  # the admin still reads it as captured


# ── Intended config ──────────────────────────────────────────────────────────


def _intended_with_backup(env) -> None:
    call, host_id = env["call"], env["host_id"]
    backup_id = call(
        functools.partial(db_module.create_config_backup, policy_id=None, host_id=host_id, config_text=CONFIG)
    )
    values = {
        "template_id": None,
        "template_name": "masking-template",
        "status": "ok",
        "error": "",
        # A section the template manages: the backup's other lines under it
        # (here the TACACS+ key) are "extra".
        "config_text": "hostname edge-sw1\ntacacs server tac-a\n address ipv4 192.0.2.50\n",
        "compliance": "non-compliant",
        "backup_id": backup_id,
        "missing_count": 0,
        "extra_count": 7,
    }
    call(db_module.save_intended_config, host_id, values)


def test_intended_config_detail_masks_backup_lines_for_read_only_users(env):
    _intended_with_backup(env)
    host_id = env["host_id"]
    reader = user_client(env["admin"], "intended-reader", features=["config-drift"])

    resp = reader.get(f"/api/intended-config/hosts/{host_id}")
    assert resp.status_code == 200, resp.text
    assert _leaked(resp.text) == [], "intended config detail returned backup secret lines to a read-only user"
    assert resp.json()["extra"], resp.text  # the lines are still listed, masked

    writer = user_client(env["admin"], "intended-raw", features=["config-drift", *RAW_FEATURES])
    assert TACACS_KEY in writer.get(f"/api/intended-config/hosts/{host_id}").text


def test_intended_config_remediation_masks_backup_lines_for_read_only_users(env):
    _intended_with_backup(env)
    host_id = env["host_id"]
    reader = user_client(env["admin"], "remediation-reader", features=["config-drift"])

    single = reader.get(f"/api/intended-config/hosts/{host_id}/remediation")
    bulk = reader.post("/api/intended-config/remediation", json={"host_ids": [host_id]})
    assert single.status_code == 200 and bulk.status_code == 200, (single.text, bulk.text)
    assert _leaked(single.text) == [] and _leaked(bulk.text) == []
    assert single.json()["secrets_masked"] is True
    assert "tacacs server tac-a" in single.json()["commands"]  # intended lines stay readable
    raw = env["admin"].get(f"/api/intended-config/hosts/{host_id}/remediation").json()
    assert TACACS_KEY in " ".join(raw["commands"]) and not raw.get("secrets_masked")


def test_masked_commands_hide_the_value_a_no_command_removes():
    commands = ["tacacs server tac-a", f" no key 0 {TACACS_KEY}", f"no snmp-server community {COMMUNITY} RO"]
    masked = mask_commands(commands)
    assert _leaked(" ".join(masked)) == []
    assert masked[0] == "tacacs server tac-a"
    assert masked[1].startswith(" no key 0 ") and masked[2].startswith("no snmp-server community ")


# ── Risk analysis, alert correlation ─────────────────────────────────────────


def test_risk_analysis_masks_the_captured_config_for_read_only_users(env):
    call, host_id = env["call"], env["host_id"]
    analysis_id = call(
        functools.partial(
            db_module.create_risk_analysis,
            host_id=host_id,
            group_id=env["gid"],
            current_config=CONFIG,
            simulated_config=CONFIG,
            proposed_diff=f"--- current\n+++ after-change\n+snmp-server community {COMMUNITY} RO\n",
        )
    )
    reader = user_client(env["admin"], "risk-reader", features=["risk-analysis"])

    for path in (f"/api/risk-analysis/{analysis_id}", "/api/risk-analysis"):
        resp = reader.get(path)
        assert resp.status_code == 200, resp.text
        assert _leaked(resp.text) == [], path
    assert env["admin"].get(f"/api/risk-analysis/{analysis_id}").json()["current_config"] == CONFIG


def test_alert_correlation_masks_drift_diffs_for_read_only_users(env, monkeypatch):
    call, host_id = env["call"], env["host_id"]
    diff = f"--- baseline\n+++ actual\n+snmp-server community {COMMUNITY} RO\n"

    async def drift_in_window(host_ids, _start, _end):
        # The drift event the correlation window selects (the window itself
        # is not what this test is about).
        return [{"id": 1, "host_id": host_ids[0], "diff_text": diff, "device_type": "cisco_ios"}]

    monkeypatch.setattr(db_module, "get_config_drift_events_in_range", drift_in_window)
    alert_id = call(
        functools.partial(db_module.create_monitoring_alert, host_id, None, "threshold", "cpu", "CPU high")
    )
    reader = user_client(env["admin"], "monitoring-reader", features=["monitoring"])

    resp = reader.get(f"/api/monitoring/alerts/{alert_id}/correlation")
    assert resp.status_code == 200, resp.text
    assert resp.json()["related_drift_events"], resp.text
    assert COMMUNITY not in resp.text
    assert COMMUNITY in env["admin"].get(f"/api/monitoring/alerts/{alert_id}/correlation").text


# ── Control ──────────────────────────────────────────────────────────────────


def test_config_backup_view_is_masked_for_read_only_users(env):
    call, host_id = env["call"], env["host_id"]
    backup_id = call(
        functools.partial(db_module.create_config_backup, policy_id=None, host_id=host_id, config_text=CONFIG)
    )
    reader = user_client(env["admin"], "backup-reader", features=["config-backups"])
    resp = reader.get(f"/api/config-backups/{backup_id}")
    assert resp.status_code == 200, resp.text
    assert _leaked(resp.text) == []
    assert resp.json().get("secrets_masked") is True
    writer = user_client(env["admin"], "backup-raw", features=RAW_FEATURES)
    assert writer.get(f"/api/config-backups/{backup_id}").json()["config_text"] == CONFIG
