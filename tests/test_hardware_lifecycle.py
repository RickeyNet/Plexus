"""Hardware lifecycle (``netcontrol.routes.hardware_lifecycle``,
``routes.db.hardware_lifecycle``, ``netcontrol.hardware_lifecycle``):
end-of-life notices on device types and part numbers (also matched through
DCIM modules), support contracts with their devices, the per-device and
fleet status, the CSV report, the server-side alert check into
``monitoring_alerts`` (raised once per condition, resolved when it clears),
access, change log and audit."""

from __future__ import annotations

import asyncio
import csv
import io
from datetime import UTC, date, datetime, timedelta

import netcontrol.app as app_module
import pytest
import routes.database as db
from netcontrol.custom_fields import CustomFieldError
from netcontrol.hardware_lifecycle import (
    alert_conditions,
    clean_cost,
    clean_currency,
    clean_part_number,
    clean_warn_days,
    contract_state,
    days_until,
    fleet_summary,
    host_status,
    milestone_order_errors,
    notice_state,
)
from netcontrol.routes import state
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

BASE = "/api/lifecycle"
NOTICES = f"{BASE}/notices"
CONTRACTS = f"{BASE}/contracts"
STATUS = f"{BASE}/status"

TODAY = date(2026, 6, 1)


def _day(offset: int) -> str:
    """A date ``offset`` days from the real today, as the API sees it."""
    return (datetime.now(UTC).date() + timedelta(days=offset)).isoformat()


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200):
    assert resp.status_code == status, resp.text
    return resp.json()


def _fields(resp) -> dict:
    assert resp.status_code == 422, resp.text
    return resp.json()["detail"]["fields"]


def _host(admin: CsrfClient, name: str, ip: str) -> int:
    gid = int(_ok(admin.post("/api/inventory", json={"name": f"group-{name}"}), 201)["id"])
    body = {"hostname": name, "ip_address": ip, "device_type": "cisco_ios"}
    return int(_ok(admin.post(f"/api/inventory/{gid}/hosts", json=body), 201)["id"])


def _device_type(model: str, part_number: str = "", maker: str = "Example Networks") -> int:
    async def make() -> int:
        found = [m for m in await db.list_manufacturers() if m["name"] == maker]
        mid = found[0]["id"] if found else (await db.create_manufacturer(name=maker))["id"]
        return int((await db.create_device_type(manufacturer_id=mid, model=model, part_number=part_number))["id"])

    return asyncio.run(make())


def _assign(host_id: int, device_type_id: int) -> None:
    asyncio.run(db.set_host_device_fields(host_id, {"device_type_id": device_type_id}))


# ── Rules ────────────────────────────────────────────────────────────────────


def test_field_rules():
    assert clean_part_number(" WS-EX-48 ") == "WS-EX-48" and clean_part_number(None) == ""
    for bad in ("A B", "X" * 101):
        with pytest.raises(CustomFieldError):
            clean_part_number(bad)
    assert clean_currency(" usd ") == "USD" and clean_currency("") == ""
    with pytest.raises(CustomFieldError):
        clean_currency("dollars")
    assert clean_cost(None) is None and clean_cost("") is None
    assert clean_cost(1200) == "1200.00" and clean_cost("99.5") == "99.50"
    for bad in (-1, "1.234", "abc", True, "NaN", 10**13, [1]):
        with pytest.raises(CustomFieldError):
            clean_cost(bad)
    assert clean_warn_days(30, "W") == 30
    for bad in (0, 3651, True, "30"):
        with pytest.raises(CustomFieldError):
            clean_warn_days(bad, "W")
    assert milestone_order_errors({"end_of_sale": "2026-01-01", "end_of_support": "2030-01-01"}) == {}
    errors = milestone_order_errors(
        {"end_of_sale": "2027-01-01", "end_of_sw_maintenance": "2026-01-01", "end_of_support": "2028-01-01"}
    )
    assert set(errors) == {"end_of_sw_maintenance"}
    assert days_until("", TODAY) is None and days_until("bad", TODAY) is None
    assert days_until("2026-06-11", TODAY) == 10


def test_notice_and_contract_states():
    notice = {"end_of_sale": "2026-01-01", "end_of_sw_maintenance": "2026-06-01", "end_of_support": "2027-06-01"}
    st = notice_state(notice, TODAY)
    assert st["stage"] == "end_of_sw_maintenance"  # passed on its date
    assert st["next"] == {
        "milestone": "end_of_support",
        "label": "Last date of support",
        "date": "2027-06-01",
        "days": 365,
    }
    assert notice_state({}, TODAY) == {"stage": "supported", "next": None}
    assert notice_state({"end_of_support": "2026-05-01"}, TODAY)["stage"] == "end_of_support"

    assert contract_state({"start_date": "2026-07-01", "end_date": "2027-01-01"}, TODAY, 30) == "not_started"
    assert contract_state({"end_date": "2026-05-31"}, TODAY, 30) == "expired"
    assert contract_state({"end_date": "2026-06-01"}, TODAY, 30) == "expiring"  # last day covered
    assert contract_state({"end_date": "2026-12-01"}, TODAY, 30) == "covered"
    assert contract_state({"end_date": ""}, TODAY, 30) == "covered"


def test_host_status_and_alert_conditions():
    empty = host_status([], [], TODAY)
    assert empty["stage"] == "none" and empty["coverage"] == "none" and empty["next"] is None
    assert alert_conditions(empty, support_warn_days=90) == []

    notices = [
        {"id": 1, "end_of_sale": "2026-03-01", "end_of_support": "2026-08-01"},
        {"id": 2, "end_of_sale": "2025-01-01", "end_of_support": "2029-01-01"},
    ]
    contracts = [
        {"id": 7, "provider": "Example Support", "contract_id": "C-1", "end_date": "2026-05-01"},
        {"id": 8, "provider": "Example Support", "contract_id": "C-2", "end_date": "2026-06-20"},
    ]
    st = host_status(notices, contracts, TODAY, contract_warn_days=30)
    assert st["stage"] == "end_of_sale"
    assert st["end_of_sale"] == "2025-01-01" and st["end_of_support"] == "2026-08-01"
    assert st["days_to_end_of_support"] == 61 and st["next"]["notice_id"] == 1
    assert st["coverage"] == "expiring" and st["coverage_end"] == "2026-06-20" and st["coverage_days"] == 19
    assert [c["state"] for c in st["contracts"]] == ["expired", "expiring"]
    kinds = {c["kind"]: c["severity"] for c in alert_conditions(st, support_warn_days=90)}
    assert kinds == {"end_of_support_soon": "info", "contract_expiring": "info"}
    assert {c["kind"] for c in alert_conditions(st, support_warn_days=30)} == {"contract_expiring"}

    past = host_status([{"id": 3, "end_of_support": "2026-01-01"}], contracts[:1], TODAY)
    assert past["coverage"] == "expired" and past["coverage_end"] == "2026-05-01"
    kinds = {c["kind"]: c["severity"] for c in alert_conditions(past, support_warn_days=90)}
    assert kinds == {"end_of_support": "warning", "contract_expired": "warning"}

    open_ended = host_status([], [{"end_date": ""}, {"end_date": "2026-06-05"}], TODAY, contract_warn_days=30)
    assert open_ended["coverage"] == "covered" and open_ended["coverage_end"] is None
    future = host_status([], [{"start_date": "2026-07-01", "end_date": "2027-07-01"}], TODAY)
    assert future["coverage"] == "not_started" and future["coverage_days"] == 30

    summary = fleet_summary([empty, st, past])
    assert summary["devices"] == 3 and summary["with_notice"] == 2 and summary["past_end_of_support"] == 1
    assert summary["by_coverage"]["expiring"] == 1 and summary["by_stage"]["none"] == 1


# ── Access ───────────────────────────────────────────────────────────────────


def test_anonymous_is_rejected(admin):
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    for path in (NOTICES, CONTRACTS, STATUS, f"{BASE}/hosts/1", f"{BASE}/settings"):
        assert anon.get(path).status_code == 401, path


def test_reads_need_lifecycle_and_writes_need_lifecycle_write(admin):
    plain = user_client(admin, "plain-user")
    assert plain.get(NOTICES).status_code == 403
    reader = user_client(admin, "lifecycle-reader", features=["lifecycle"])
    for path in (NOTICES, CONTRACTS, STATUS, f"{BASE}/choices", f"{BASE}/settings", f"{STATUS}/export"):
        assert reader.get(path).status_code == 200, path
    assert reader.post(NOTICES, json={"part_number": "PN-EX-1"}).status_code == 403
    assert reader.post(f"{BASE}/check").status_code == 403
    writer = user_client(admin, "lifecycle-writer", features=["lifecycle", "lifecycle.write"])
    assert writer.post(NOTICES, json={"part_number": "PN-EX-1"}).status_code == 201
    assert "lifecycle" in state.FEATURE_FLAGS and "lifecycle.write" in state.FEATURE_FLAGS


# ── Notices ──────────────────────────────────────────────────────────────────


def test_notice_crud_and_validation(admin):
    dt = _device_type("EX-1000", "EX-1000-AC")
    notice = _ok(
        admin.post(
            NOTICES,
            json={
                "device_type_id": dt,
                "end_of_sale": "2026-01-31",
                "end_of_support": "2031-01-31",
                "documentation_url": "https://docs.example.com/eol/ex-1000",
            },
        ),
        201,
    )
    assert notice["device_type_model"] == "EX-1000" and notice["manufacturer_name"] == "Example Networks"
    assert notice["created_by"] == "admin" and notice["stage"] in ("end_of_sale", "supported")
    assert admin.post(NOTICES, json={"device_type_id": dt}).status_code == 409

    part = _ok(admin.post(NOTICES, json={"part_number": "PN-EX-9", "comments": "Line card"}), 201)
    assert admin.post(NOTICES, json={"part_number": "pn-ex-9"}).status_code == 409

    assert set(_fields(admin.post(NOTICES, json={}))) == {"device_type_id", "part_number"}
    assert set(_fields(admin.post(NOTICES, json={"device_type_id": dt, "part_number": "X"}))) == {
        "device_type_id",
        "part_number",
    }
    assert set(_fields(admin.post(NOTICES, json={"device_type_id": 99999}))) == {"device_type_id"}
    bad = _fields(
        admin.post(
            NOTICES,
            json={
                "part_number": "PN-BAD",
                "end_of_sale": "2026-13-01",
                "end_of_security_fixes": "2030-01-01",
                "end_of_support": "2029-01-01",
                "documentation_url": "docs.example.com",
            },
        )
    )
    assert set(bad) == {"end_of_sale", "end_of_support", "documentation_url"}

    updated = _ok(admin.put(f"{NOTICES}/{part['id']}", json={"end_of_sale": "2027-02-01"}))
    assert updated["end_of_sale"] == "2027-02-01" and updated["comments"] == "Line card"
    moved = _ok(admin.put(f"{NOTICES}/{part['id']}", json={"part_number": "", "device_type_id": _device_type("EX-2")}))
    assert moved["part_number"] == "" and moved["device_type_model"] == "EX-2"
    assert admin.put(f"{NOTICES}/{part['id']}", json={"device_type_id": dt}).status_code == 409
    assert admin.put(f"{NOTICES}/99999", json={}).status_code == 404

    listed = _ok(admin.get(NOTICES))["notices"]
    assert [n["device_type_model"] for n in listed] == ["EX-1000", "EX-2"]
    assert [n["id"] for n in _ok(admin.get(NOTICES, params={"q": "1000"}))["notices"]] == [notice["id"]]
    assert [n["id"] for n in _ok(admin.get(NOTICES, params={"device_type_id": dt}))["notices"]] == [notice["id"]]

    assert _ok(admin.delete(f"{NOTICES}/{part['id']}")) == {"ok": True}
    assert admin.delete(f"{NOTICES}/{part['id']}").status_code == 404
    assert admin.get(f"{NOTICES}/{part['id']}").status_code == 404

    # A notice goes with its device type.
    asyncio.run(db.delete_catalogue_record("device_type", dt))
    assert admin.get(f"{NOTICES}/{notice['id']}").status_code == 404


def test_notices_apply_by_device_type_part_number_and_module(admin):
    by_type = _host(admin, "core-sw1", "192.0.2.11")
    by_part = _host(admin, "core-sw2", "192.0.2.12")
    by_model = _host(admin, "core-sw3", "192.0.2.13")
    by_module = _host(admin, "core-sw4", "192.0.2.14")
    _host(admin, "spare-sw5", "192.0.2.15")
    dt_a = _device_type("EX-3000", "EX-3000-48P")
    dt_b = _device_type("EX-3000-B", "EX-3000-48P")
    dt_c = _device_type("EX-LC-8")
    for host, dt in ((by_type, dt_a), (by_part, dt_b), (by_model, dt_c)):
        _assign(host, dt)
    _ok(admin.post("/api/dcim/modules", json={"host_id": by_module, "bay": "Slot 1", "part_number": "ex-lc-8"}), 201)

    type_notice = _ok(admin.post(NOTICES, json={"device_type_id": dt_a, "end_of_support": "2020-01-01"}), 201)
    part_notice = _ok(admin.post(NOTICES, json={"part_number": "EX-3000-48P", "end_of_sale": "2020-01-01"}), 201)
    module_notice = _ok(admin.post(NOTICES, json={"part_number": "EX-LC-8"}), 201)
    assert type_notice["host_count"] == 1 and part_notice["host_count"] == 2 and module_notice["host_count"] == 2

    hosts = _ok(admin.get(f"{NOTICES}/{part_notice['id']}"))["hosts"]
    assert [(h["hostname"], h["via"]) for h in hosts] == [("core-sw1", ["part_number"]), ("core-sw2", ["part_number"])]
    hosts = _ok(admin.get(f"{NOTICES}/{module_notice['id']}"))["hosts"]
    assert {h["hostname"]: h["via"] for h in hosts} == {"core-sw3": ["part_number"], "core-sw4": ["module"]}

    detail = _ok(admin.get(f"{BASE}/hosts/{by_type}"))
    assert {n["id"]: n["via"] for n in detail["notices"]} == {
        type_notice["id"]: ["device_type"],
        part_notice["id"]: ["part_number"],
    }
    assert detail["status"]["stage"] == "end_of_support" and detail["status"]["hostname"] == "core-sw1"
    assert admin.get(f"{BASE}/hosts/99999").status_code == 404


# ── Contracts ────────────────────────────────────────────────────────────────


def test_contract_crud_hosts_and_validation(admin):
    h1 = _host(admin, "edge-r1", "192.0.2.21")
    h2 = _host(admin, "edge-r2", "192.0.2.22")
    contract = _ok(
        admin.post(
            CONTRACTS,
            json={
                "provider": "Example Support Co",
                "contract_id": "SC-1001",
                "start_date": _day(-300),
                "end_date": _day(400),
                "cost": "1500.5",
                "currency": "usd",
                "support_level": "24x7x4",
                "host_ids": [h2, h1, h1],
            },
        ),
        201,
    )
    assert contract["cost"] == "1500.50" and contract["currency"] == "USD" and contract["state"] == "covered"
    assert [h["hostname"] for h in contract["hosts"]] == ["edge-r1", "edge-r2"] and contract["host_count"] == 2
    assert admin.post(CONTRACTS, json={"provider": "example support co", "contract_id": "sc-1001"}).status_code == 409

    fields = _fields(
        admin.post(
            CONTRACTS,
            json={"provider": "", "contract_id": "X", "start_date": "2026-05-01", "end_date": "2026-04-01", "cost": -3},
        )
    )
    assert set(fields) == {"provider", "end_date", "cost"}
    assert set(_fields(admin.post(CONTRACTS, json={"provider": "P", "contract_id": "C", "host_ids": [99999]}))) == {
        "host_ids"
    }

    cid = contract["id"]
    kept = _ok(admin.put(f"{CONTRACTS}/{cid}", json={"end_date": _day(10)}))
    assert kept["state"] == "expiring" and kept["host_count"] == 2 and kept["cost"] == "1500.50"
    replaced = _ok(admin.put(f"{CONTRACTS}/{cid}", json={"host_ids": [h1], "cost": None}))
    assert [h["id"] for h in replaced["hosts"]] == [h1] and replaced["cost"] is None
    assert admin.put(f"{CONTRACTS}/99999", json={}).status_code == 404

    other = _ok(
        admin.post(CONTRACTS, json={"provider": "Another Reseller", "contract_id": "AR-7", "end_date": _day(-5)}), 201
    )
    assert other["state"] == "expired"
    assert (
        admin.put(
            f"{CONTRACTS}/{other['id']}", json={"provider": "Example Support Co", "contract_id": "SC-1001"}
        ).status_code
        == 409
    )
    assert [c["contract_id"] for c in _ok(admin.get(CONTRACTS))["contracts"]] == ["AR-7", "SC-1001"]
    assert [c["id"] for c in _ok(admin.get(CONTRACTS, params={"host_id": h1}))["contracts"]] == [cid]
    assert [c["id"] for c in _ok(admin.get(CONTRACTS, params={"state": "expired"}))["contracts"]] == [other["id"]]
    assert [c["id"] for c in _ok(admin.get(CONTRACTS, params={"q": "reseller"}))["contracts"]] == [other["id"]]
    assert _ok(admin.get(f"{CONTRACTS}/{cid}"))["support_level"] == "24x7x4"

    assert _ok(admin.delete(f"{CONTRACTS}/{cid}")) == {"ok": True}
    assert admin.delete(f"{CONTRACTS}/{cid}").status_code == 404
    assert _ok(admin.get(f"{BASE}/hosts/{h1}"))["contracts"] == []


# ── Status, report, choices ──────────────────────────────────────────────────


def test_fleet_status_filters_and_csv(admin):
    old = _host(admin, "=old-sw", "192.0.2.31")
    new = _host(admin, "new-sw", "192.0.2.32")
    dt = _device_type("EX-OLD")
    _assign(old, dt)
    _ok(admin.post(NOTICES, json={"device_type_id": dt, "end_of_sale": _day(-400), "end_of_support": _day(-1)}), 201)
    _ok(
        admin.post(
            CONTRACTS,
            json={
                "provider": "Example Support Co",
                "contract_id": "SC-9",
                "end_date": _day(20),
                "host_ids": [old, new],
            },
        ),
        201,
    )

    body = _ok(admin.get(STATUS))
    # Other hosts may exist (seeded); only these two have a notice or contract.
    assert body["summary"]["devices"] == len(body["devices"]) and body["summary"]["past_end_of_support"] == 1
    assert body["summary"]["by_coverage"]["expiring"] == 2
    rows = {r["hostname"]: r for r in body["devices"]}
    assert rows["=old-sw"]["stage"] == "end_of_support" and rows["=old-sw"]["days_to_end_of_support"] == -1
    assert rows["new-sw"]["stage"] == "none" and rows["new-sw"]["coverage_end"] == _day(20)
    assert [r["hostname"] for r in _ok(admin.get(STATUS, params={"stage": "end_of_support"}))["devices"]] == ["=old-sw"]
    assert [r["hostname"] for r in _ok(admin.get(STATUS, params={"q": "new"}))["devices"]] == ["new-sw"]
    assert [r["hostname"] for r in _ok(admin.get(STATUS, params={"coverage": "expiring"}))["devices"]] == [
        "=old-sw",
        "new-sw",
    ]
    assert admin.get(STATUS, params={"stage": "bogus"}).status_code == 422

    resp = admin.get(f"{STATUS}/export", params={"stage": "end_of_support"})
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/csv")
    table = list(csv.reader(io.StringIO(resp.text)))
    assert table[0][:3] == ["Hostname", "IP Address", "Manufacturer"] and len(table) == 2
    assert table[1][0] == "'=old-sw"  # formula guarded
    assert table[1][table[0].index("Contracts")] == "Example Support Co SC-9"
    assert admin.get(f"{STATUS}/export", params={"coverage": "bogus"}).status_code == 422

    choices = _ok(admin.get(f"{BASE}/choices"))
    assert {"id": old, "hostname": "=old-sw", "ip_address": "192.0.2.31"} in choices["hosts"]
    assert {"id": dt, "manufacturer": "Example Networks", "model": "EX-OLD", "part_number": ""} in choices[
        "device_types"
    ]
    assert [m["key"] for m in choices["milestones"]][-1] == "end_of_support"


# ── Settings and alerts ──────────────────────────────────────────────────────


def test_settings(admin):
    defaults = _ok(admin.get(f"{BASE}/settings"))
    assert defaults["alerts_enabled"] is True and defaults["contract_warn_days"] == 60
    updated = _ok(admin.put(f"{BASE}/settings", json={"contract_warn_days": 30, "alerts_enabled": False}))
    assert updated["contract_warn_days"] == 30 and updated["alerts_enabled"] is False
    assert updated["support_warn_days"] == 180
    assert set(_fields(admin.put(f"{BASE}/settings", json={"support_warn_days": 0}))) == {"support_warn_days"}


def _alerts(host_id: int) -> list[dict]:
    rows = asyncio.run(db.get_monitoring_alerts(host_id=host_id))
    return [r for r in rows if r["alert_type"] == "hardware_lifecycle"]


def test_alert_check_raises_once_and_resolves(admin):
    eos = _host(admin, "legacy-r1", "192.0.2.41")
    covered = _host(admin, "branch-r1", "192.0.2.42")
    dt = _device_type("EX-LEGACY")
    _assign(eos, dt)
    _ok(admin.post(NOTICES, json={"device_type_id": dt, "end_of_support": _day(-10)}), 201)
    contract = _ok(
        admin.post(
            CONTRACTS,
            json={"provider": "Example Support Co", "contract_id": "SC-50", "end_date": _day(5), "host_ids": [covered]},
        ),
        201,
    )

    first = _ok(admin.post(f"{BASE}/check"))
    assert first["ok"] and first["conditions"] == 2 and first["raised"] == 2
    (eos_alert,) = _alerts(eos)
    assert eos_alert["severity"] == "warning" and eos_alert["dedup_key"] == f"lifecycle:end_of_support:{eos}"
    assert eos_alert["message"].startswith("legacy-r1 passed its last date of support")
    (exp_alert,) = _alerts(covered)
    assert exp_alert["severity"] == "info" and "SC-50" not in exp_alert["message"]

    # Acknowledged or not, a lasting condition does not alert again.
    asyncio.run(db.acknowledge_monitoring_alert(int(eos_alert["id"]), "admin"))
    again = _ok(admin.post(f"{BASE}/check"))
    assert again["raised"] == 0 and again["conditions"] == 2
    assert len(_alerts(eos)) == 1 and len(_alerts(covered)) == 1

    # The contract renewed: its alert is resolved and its state forgotten.
    _ok(admin.put(f"{CONTRACTS}/{contract['id']}", json={"end_date": _day(365)}))
    cleared = _ok(admin.post(f"{BASE}/check"))
    assert cleared["cleared"] == 1 and cleared["resolved"] == 1
    (exp_alert,) = _alerts(covered)
    assert exp_alert["acknowledged"] == 1 and exp_alert["acknowledged_by"] == "auto-resolved"
    assert set(asyncio.run(db.list_lifecycle_alert_states())) == {f"lifecycle:end_of_support:{eos}"}

    # The contract lapses: the expired condition is raised as a new alert.
    _ok(admin.put(f"{CONTRACTS}/{contract['id']}", json={"end_date": _day(-1)}))
    lapsed = _ok(admin.post(f"{BASE}/check"))
    assert lapsed["raised"] == 1
    assert [a["severity"] for a in _alerts(covered) if not a["acknowledged"]] == ["warning"]

    # Alerts off: every condition clears.
    _ok(admin.put(f"{BASE}/settings", json={"alerts_enabled": False}))
    off = _ok(admin.post(f"{BASE}/check"))
    assert off["conditions"] == 0 and off["cleared"] == 2
    assert asyncio.run(db.list_lifecycle_alert_states()) == {}
    settings = _ok(admin.get(f"{BASE}/settings"))
    assert settings["last_check_at"] and settings["last_check_alerts"] == 0

    events = asyncio.run(db.get_audit_events(limit=100))
    assert "check" in {e["action"] for e in events if e.get("category") == "lifecycle"}


def test_check_failure_is_reported(admin, monkeypatch):
    from netcontrol.routes import hardware_lifecycle as hl

    async def boom(**_kwargs):
        raise RuntimeError("database down")

    monkeypatch.setattr(hl, "device_statuses", boom)
    resp = admin.post(f"{BASE}/check")
    assert resp.status_code == 500 and "database down" not in resp.text


# ── Change log and audit ─────────────────────────────────────────────────────


def test_changes_are_recorded_and_audited(admin):
    notice = _ok(admin.post(NOTICES, json={"part_number": "PN-EX-77"}), 201)
    _ok(admin.put(f"{NOTICES}/{notice['id']}", json={"end_of_sale": "2027-01-01"}))
    contract = _ok(admin.post(CONTRACTS, json={"provider": "Example Support Co", "contract_id": "SC-77"}), 201)
    _ok(admin.delete(f"{CONTRACTS}/{contract['id']}"))

    history = _ok(admin.get(f"/api/changes/hardware_notice/{notice['id']}"))["changes"]
    assert [c["action"] for c in history] == ["update", "create"]
    assert history[0]["changes"]["end_of_sale"] == {"before": "", "after": "2027-01-01"}
    assert history[1]["object_label"] == "PN-EX-77" and history[1]["user"] == "admin"
    contract_history = _ok(admin.get(f"/api/changes/support_contract/{contract['id']}"))["changes"]
    assert [c["action"] for c in contract_history] == ["delete", "create"]
    assert contract_history[1]["object_label"] == "SC-77"

    reader = user_client(admin, "lifecycle-reader", features=["lifecycle"])
    assert _ok(reader.get(f"/api/changes/hardware_notice/{notice['id']}"))["total"] == 2
    other = user_client(admin, "dcim-reader", features=["dcim"])
    assert other.get(f"/api/changes/hardware_notice/{notice['id']}").status_code == 403

    actions = {e["action"] for e in asyncio.run(db.get_audit_events(limit=50)) if e.get("category") == "lifecycle"}
    assert {"notice_create", "notice_update", "contract_create", "contract_delete"} <= actions
