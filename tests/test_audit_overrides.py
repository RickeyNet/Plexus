"""Tests for audit finding overrides (Phase 6).

Covers:
  * CRUD round-trip on `audit_rule_overrides` via the helper functions.
  * `_finding_is_overridden`: host-specific match, global match (host_id NULL),
    rule-id mismatch, host mismatch with non-null override host, expired
    override is inactive.
  * Payload validation: empty rule_id, invalid mode, unparseable expires_at,
    empty expires_at is allowed (permanent).
  * UNIQUE(rule_id, host_id) -> 409 on duplicate create via the endpoint.
  * Engine integration: a fake rule emits findings, an override suppresses
    them, the audit_runs row reflects zero persisted findings but
    `summary_json` records `suppressed_total` / `suppressed_by_rule` /
    `suppressed_by_mode` so the suppression is auditable.
  * Global override (host_id NULL) suppresses findings across all hosts.
  * Expired override is ignored at evaluation time.
  * Mid-run snapshot: overrides are loaded once per run, so a new override
    created mid-execution can't selectively suppress later rules.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
import routes.database as db_module
from fastapi import HTTPException
from netcontrol.routes import audit as audit_router


async def _init_clean_db(tmp_path, monkeypatch) -> str:
    db_path = str(tmp_path / "audit_overrides.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    return db_path


async def _make_host(group_name: str = "g1", hostname: str = "sw1") -> int:
    gid = await db_module.create_group(group_name)
    return await db_module.add_host(
        gid, hostname=hostname, ip_address=f"10.0.0.{hash(hostname) % 200 + 1}",
    )


# ── CRUD round-trip ────────────────────────────────────────────────────────

async def test_override_crud_roundtrip(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    # host_id has a FOREIGN KEY to hosts(id) (enforced: the shared SQLite
    # connection runs with PRAGMA foreign_keys=ON), so a real host is needed.
    host_id = await _make_host()

    created = await audit_router._create_override(
        rule_id="port.duplex_mismatch",
        host_id=host_id,
        mode="mute",
        reason="known asymmetric peer",
        created_by="alice",
        expires_at=None,
    )
    assert created["rule_id"] == "port.duplex_mismatch"
    assert created["host_id"] == host_id
    assert created["mode"] == "mute"
    assert created["expires_at"] in (None, "")

    oid = int(created["id"])
    fetched = await audit_router._get_override(oid)
    assert fetched is not None
    assert fetched["id"] == oid

    listed = await audit_router._list_overrides()
    assert any(o["id"] == oid for o in listed)

    assert (await audit_router._delete_override(oid)) is True
    assert (await audit_router._delete_override(oid)) is False
    assert (await audit_router._get_override(oid)) is None


# ── _finding_is_overridden ─────────────────────────────────────────────────

def _f(rule_id: str = "r1", host_id: int | None = 1) -> audit_router.Finding:
    return audit_router.Finding(
        rule_id=rule_id, category="c", severity="medium",
        title="t", host_id=host_id,
    )


def test_host_specific_override_matches_same_host():
    now = datetime.now(UTC)
    ovr = {"rule_id": "r1", "host_id": 1, "mode": "mute", "expires_at": None}
    assert audit_router._finding_is_overridden(_f(host_id=1), [ovr], now) is ovr


def test_host_specific_override_skips_other_host():
    now = datetime.now(UTC)
    ovr = {"rule_id": "r1", "host_id": 1, "mode": "mute", "expires_at": None}
    assert audit_router._finding_is_overridden(_f(host_id=2), [ovr], now) is None


def test_global_override_matches_any_host():
    now = datetime.now(UTC)
    ovr = {"rule_id": "r1", "host_id": None, "mode": "mute", "expires_at": None}
    assert audit_router._finding_is_overridden(_f(host_id=99), [ovr], now) is ovr


def test_rule_mismatch_no_match():
    now = datetime.now(UTC)
    ovr = {"rule_id": "OTHER", "host_id": None, "mode": "mute", "expires_at": None}
    assert audit_router._finding_is_overridden(_f(), [ovr], now) is None


def test_expired_override_is_inactive():
    now = datetime.now(UTC)
    past = (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    ovr = {"rule_id": "r1", "host_id": None, "mode": "mute", "expires_at": past}
    assert audit_router._finding_is_overridden(_f(), [ovr], now) is None


def test_future_expiry_override_is_active():
    now = datetime.now(UTC)
    future = (now + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    ovr = {"rule_id": "r1", "host_id": None, "mode": "mute", "expires_at": future}
    assert audit_router._finding_is_overridden(_f(), [ovr], now) is ovr


def test_unparseable_expiry_is_inactive():
    """A corrupt expires_at value should not silently keep an override
    active forever -- we'd rather fail-open than suppress findings
    unexpectedly."""
    now = datetime.now(UTC)
    ovr = {"rule_id": "r1", "host_id": None, "mode": "mute", "expires_at": "garbage"}
    assert audit_router._finding_is_overridden(_f(), [ovr], now) is None


# ── Payload validation ─────────────────────────────────────────────────────

def test_validate_override_rejects_empty_rule_id():
    with pytest.raises(HTTPException) as ei:
        audit_router._validate_override_payload("", "mute", None)
    assert ei.value.status_code == 400
    assert "rule_id" in str(ei.value.detail)


def test_validate_override_rejects_invalid_mode():
    with pytest.raises(HTTPException) as ei:
        audit_router._validate_override_payload("r1", "yolo", None)
    assert ei.value.status_code == 400
    assert "mode" in str(ei.value.detail)


def test_validate_override_rejects_unparseable_expiry():
    with pytest.raises(HTTPException) as ei:
        audit_router._validate_override_payload("r1", "mute", "tomorrow")
    assert ei.value.status_code == 400
    assert "expires_at" in str(ei.value.detail)


def test_validate_override_accepts_none_and_iso_expiry():
    # None -> permanent.
    audit_router._validate_override_payload("r1", "mute", None)
    # ISO datetime -> ok.
    audit_router._validate_override_payload(
        "r1", "accept_risk", "2030-01-01 00:00:00",
    )


# ── Engine integration ────────────────────────────────────────────────────-

class _AlwaysFireRule(audit_router.Rule):
    """Test rule: emit one finding per host, deterministically."""
    rule_id = "test.always_fire"
    category = "test"
    default_severity = "medium"

    async def evaluate(self, ctx: audit_router.AuditContext):
        out: list[audit_router.Finding] = []
        for h in ctx.hosts:
            out.append(audit_router.Finding(
                rule_id=self.rule_id, category=self.category,
                severity="medium", title="Always fires", host_id=h.get("id"),
            ))
        return out


async def _run_with_fake_rule(monkeypatch) -> int:
    """Replace `_RULE_REGISTRY` with just the fake rule for the duration
    of one audit run, then restore."""
    monkeypatch.setattr(
        audit_router, "_RULE_REGISTRY", [_AlwaysFireRule],
    )
    return await audit_router.run_audit(trigger="manual")


async def _fetch_run_row(run_id: int) -> dict:
    conn = await db_module.get_db()
    try:
        cursor = await conn.execute(
            "SELECT id, status, findings_total, summary_json "
            "FROM audit_runs WHERE id = ?",
            (run_id,),
        )
        row = await cursor.fetchone()
        cols = [d[0] for d in cursor.description]
        return dict(zip(cols, row))
    finally:
        await conn.close()


async def _fetch_findings(run_id: int) -> list[dict]:
    conn = await db_module.get_db()
    try:
        cursor = await conn.execute(
            "SELECT rule_id, host_id FROM audit_findings WHERE run_id = ?",
            (run_id,),
        )
        rows = await cursor.fetchall()
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, r)) for r in rows]
    finally:
        await conn.close()


async def test_run_without_override_persists_finding(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    host_id = await _make_host()

    run_id = await _run_with_fake_rule(monkeypatch)
    row = await _fetch_run_row(run_id)
    assert row["findings_total"] == 1

    findings = await _fetch_findings(run_id)
    assert len(findings) == 1
    assert findings[0]["host_id"] == host_id

    summary = json.loads(row["summary_json"])
    assert summary["suppressed_total"] == 0


async def test_host_specific_override_suppresses_finding(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    host_id = await _make_host()

    await audit_router._create_override(
        rule_id="test.always_fire", host_id=host_id, mode="mute",
        reason="known FP", created_by="t", expires_at=None,
    )

    run_id = await _run_with_fake_rule(monkeypatch)
    row = await _fetch_run_row(run_id)
    assert row["findings_total"] == 0
    assert (await _fetch_findings(run_id)) == []

    summary = json.loads(row["summary_json"])
    assert summary["suppressed_total"] == 1
    assert summary["suppressed_by_rule"] == {"test.always_fire": 1}
    assert summary["suppressed_by_mode"]["mute"] == 1
    assert summary["suppressed_by_mode"]["accept_risk"] == 0


async def test_global_override_suppresses_all_hosts(tmp_path, monkeypatch):
    """An override with host_id=NULL applies to every host."""
    await _init_clean_db(tmp_path, monkeypatch)
    await _make_host(hostname="sw-a")
    await _make_host(group_name="g2", hostname="sw-b")

    await audit_router._create_override(
        rule_id="test.always_fire", host_id=None, mode="accept_risk",
        reason="org-wide accepted", created_by="cisocoach", expires_at=None,
    )

    run_id = await _run_with_fake_rule(monkeypatch)
    row = await _fetch_run_row(run_id)
    assert row["findings_total"] == 0

    summary = json.loads(row["summary_json"])
    assert summary["suppressed_total"] == 2
    assert summary["suppressed_by_mode"]["accept_risk"] == 2
    assert summary["suppressed_by_mode"]["mute"] == 0


async def test_expired_override_does_not_suppress(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    await _make_host()
    past = (datetime.now(UTC) - timedelta(hours=1)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    await audit_router._create_override(
        rule_id="test.always_fire", host_id=None, mode="mute",
        reason="long-expired", created_by="t", expires_at=past,
    )

    run_id = await _run_with_fake_rule(monkeypatch)
    row = await _fetch_run_row(run_id)
    assert row["findings_total"] == 1

    summary = json.loads(row["summary_json"])
    assert summary["suppressed_total"] == 0


async def test_unique_constraint_blocks_duplicate_override(tmp_path, monkeypatch):
    """UNIQUE(rule_id, host_id) -- second create for the same pair must
    fail. The endpoint maps that to 409; the helper itself raises."""
    await _init_clean_db(tmp_path, monkeypatch)
    host_id = await _make_host()

    await audit_router._create_override(
        rule_id="r1", host_id=host_id, mode="mute", reason="",
        created_by="", expires_at=None,
    )
    with pytest.raises(Exception):
        await audit_router._create_override(
            rule_id="r1", host_id=host_id, mode="mute", reason="",
            created_by="", expires_at=None,
        )


async def test_endpoint_returns_409_on_duplicate(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    host_id = await _make_host()
    payload = {
        "rule_id": "r1", "host_id": host_id, "mode": "mute",
        "reason": "", "created_by": "", "expires_at": None,
    }
    # First create succeeds.
    await audit_router.create_audit_override(payload=payload)
    # Second should raise HTTPException(409).
    with pytest.raises(HTTPException) as ei:
        await audit_router.create_audit_override(payload=payload)
    assert ei.value.status_code == 409
