"""Regression guard for the activate-phase commit/verify contract.

A scheduled IOS-XE activate once reported success while the device
silently rolled back to the old version.  Two defects combined:

  1. A failed ``install commit`` was logged as a *warning*, then the
     device was marked ``verify_status="completed"`` / ``phase="verified"``
     anyway.  On IOS-XE an uncommitted activate auto-rolls-back, so the
     "verified" device was actually back on the old image.
  2. The post-reboot version check was trusted blindly - even a
     "successful" commit was never re-confirmed.

These tests pin the corrected contract: a commit failure is a hard
failure, and the version is re-read *after* commit before the device
may be marked verified.  They stub every device/DB dependency so the
only thing under test is the commit/verify branch of
``_device_activate``.
"""

from __future__ import annotations

import pytest
from netcontrol.routes import upgrades


class _FakeConn:
    """Netmiko stand-in. ``show version`` returns a scripted version."""

    def __init__(
        self,
        versions: list[str],
        commit_raises: bool = False,
        commit_output: str = "SUCCESS: install_commit",
        redundancy: str = "",
    ) -> None:
        # One version string per ``show version`` call, consumed in order.
        self._versions = list(versions)
        self._commit_raises = commit_raises
        self._commit_output = commit_output
        # ``show redundancy`` output; empty = standalone (no peer).
        self._redundancy = redundancy
        self.commands: list[str] = []

    def send_command(self, command: str, **_: object) -> str:
        self.commands.append(command)
        if command == "show version":
            # Consume one scripted version per call; once exhausted keep
            # reporting the last one (a real device doesn't change version
            # between back-to-back show-version calls).
            if len(self._versions) > 1:
                v = self._versions.pop(0)
            else:
                v = self._versions[0]
            return f"Cisco IOS XE Software, Version {v}\n"
        if command == "show redundancy":
            return self._redundancy
        if command == "install commit":
            if self._commit_raises:
                raise OSError("The process for the command is not responding or is otherwise unavailable")
            return self._commit_output
        return ""

    def disconnect(self) -> None:  # pragma: no cover - trivial
        pass


@pytest.fixture
def _patched(monkeypatch: pytest.MonkeyPatch):
    """Stub _emit, the DB writes, and the reboot-wait helpers.

    Returns the dict of recorded ``db.update_upgrade_device`` kwargs
    (last-write-wins per call list) so tests can assert the final
    persisted ``verify_status`` / ``error_message``.
    """
    emits: list[tuple] = []
    db_writes: list[dict] = []
    status_emits: list[dict] = []
    # Mutable holder so the closures below resolve the conn the test
    # installs *after* the fixture returns.
    holder: dict = {"conn": None}

    async def fake_emit(cid, did, level, message, host=""):
        emits.append((level, message))

    async def fake_emit_device_status(cid, did, **kw):
        status_emits.append(kw)

    async def fake_update(dev_id, **kw):
        db_writes.append(kw)

    shared: list[str] = []

    async def fake_share(cid, did, running_version):
        shared.append(running_version)

    monkeypatch.setattr(upgrades, "_emit", fake_emit)
    monkeypatch.setattr(upgrades, "_emit_device_status", fake_emit_device_status)
    monkeypatch.setattr(upgrades.db, "update_upgrade_device", fake_update)
    monkeypatch.setattr(upgrades, "_share_running_version", fake_share)

    async def fake_resolve_device_type(_dev):
        return "cisco_xe"

    async def fake_connect(*_a, **_k):
        return holder["conn"]

    async def fake_wait_for_down(*_a, **_k):
        return True

    async def fake_wait_for_reboot(*_a, **_k):
        return holder["conn"]

    # The image-presence gate (`dir flash:<image>`) is not what these
    # tests exercise - assume the pre-staged image is on flash.
    def fake_check_image_exists(_conn, _image, _dest):
        return True

    monkeypatch.setattr(upgrades, "_resolve_device_type", fake_resolve_device_type)
    monkeypatch.setattr(upgrades, "_connect_device", fake_connect)
    monkeypatch.setattr(upgrades, "_wait_for_down", fake_wait_for_down)
    monkeypatch.setattr(upgrades, "_wait_for_reboot", fake_wait_for_reboot)
    monkeypatch.setattr(upgrades, "_check_image_exists", fake_check_image_exists)
    # The post-reload chassis wait never sleeps for real, and gives up at
    # once unless a test passes ``chassis_health_wait``.
    monkeypatch.setattr(upgrades, "CHASSIS_HEALTH_CHECK_INTERVAL", 0)
    monkeypatch.setattr(upgrades, "CHASSIS_HEALTH_WAIT", 0)
    monkeypatch.setattr(upgrades, "REDUNDANT_CHASSIS_HEALTH_WAIT", 0)

    return {"emits": emits, "db": db_writes, "status": status_emits, "holder": holder, "shared": shared}


def _final_verify_state(db_writes: list[dict]) -> tuple[str | None, str | None]:
    """Return (verify_status, error_message) from the last write that set them."""
    verify = err = None
    for w in db_writes:
        if "verify_status" in w:
            verify = w["verify_status"]
        if "error_message" in w:
            err = w["error_message"]
    return verify, err


def _final_status(db_writes: list[dict], key: str) -> str | None:
    """Return the last written value for a device status key."""
    status = None
    for w in db_writes:
        if key in w:
            status = w[key]
    return status


@pytest.mark.asyncio
async def test_commit_failure_marks_device_failed_not_verified(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    """A raising ``install commit`` must NOT leave the device verified."""
    # show version calls, in order: pre-activate "already running?" check
    # (must be the OLD version or activate is skipped), then post-reboot
    # (NEW). The commit command then throws.
    conn = _FakeConn(versions=["17.15.04", "17.15.05"], commit_raises=True)
    _patched["holder"]["conn"] = conn

    dev = {"id": 42, "ip_address": "10.0.0.1", "target_image": "cat9k_lite_iosxe.17.15.05.SPA.bin"}
    await upgrades._device_activate(campaign_id=1, dev=dev, credentials={}, image_map={}, options={})

    verify, err = _final_verify_state(_patched["db"])
    assert verify == "failed", f"commit failure must fail verify, got {verify!r}"
    assert _final_status(_patched["db"], "activate_status") == "failed"
    assert err and "commit failed" in err.lower()
    # It must never have been stamped verified/completed.
    assert all(w.get("verify_status") != "completed" for w in _patched["db"]), (
        "device was marked completed despite a failed commit"
    )
    assert _patched["shared"] == [], "an unverified version must not reach the inventory host"
    assert not any(w.get("phase") == "verified" for w in _patched["db"]), (
        "device phase set to verified despite a failed commit"
    )


@pytest.mark.asyncio
async def test_post_commit_rollback_is_detected(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    """Commit 'succeeds' but the device is back on the old version."""
    # show version order: pre-activate check = OLD (so activate runs),
    # post-reboot = NEW, post-commit re-verify = OLD -> silent rollback.
    conn = _FakeConn(versions=["17.15.04", "17.15.05", "17.15.04"], commit_raises=False)
    _patched["holder"]["conn"] = conn

    dev = {"id": 42, "ip_address": "10.0.0.1", "target_image": "cat9k_lite_iosxe.17.15.05.SPA.bin"}
    await upgrades._device_activate(campaign_id=1, dev=dev, credentials={}, image_map={}, options={})

    verify, err = _final_verify_state(_patched["db"])
    assert verify == "failed", f"post-commit rollback must fail verify, got {verify!r}"
    assert _final_status(_patched["db"], "activate_status") == "failed"
    assert err and "post-commit" in err.lower()
    assert all(w.get("verify_status") != "completed" for w in _patched["db"])
    assert _patched["shared"] == []


@pytest.mark.asyncio
async def test_commit_error_text_marks_device_failed(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    """Netmiko can return commit failure text without raising."""
    conn = _FakeConn(
        versions=["17.15.04", "17.15.05"],
        commit_output=("The process for the command is not responding or is otherwise unavailable"),
    )
    _patched["holder"]["conn"] = conn

    dev = {"id": 42, "ip_address": "10.0.0.1", "target_image": "cat9k_lite_iosxe.17.15.05.SPA.bin"}
    await upgrades._device_activate(campaign_id=1, dev=dev, credentials={}, image_map={}, options={})

    verify, err = _final_verify_state(_patched["db"])
    assert verify == "failed"
    assert _final_status(_patched["db"], "activate_status") == "failed"
    assert err and "commit failed" in err.lower()
    assert "not responding" in err.lower()
    assert not any(w.get("verify_status") == "completed" for w in _patched["db"])


@pytest.mark.asyncio
async def test_successful_commit_and_reverify_marks_verified(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    """Happy path: reboot OK, commit OK, post-commit version still new."""
    # pre-activate check = OLD (activate runs), post-reboot = NEW,
    # post-commit re-verify = NEW (commit stuck).
    conn = _FakeConn(versions=["17.15.04", "17.15.05", "17.15.05"], commit_raises=False)
    _patched["holder"]["conn"] = conn

    dev = {"id": 42, "ip_address": "10.0.0.1", "target_image": "cat9k_lite_iosxe.17.15.05.SPA.bin"}
    await upgrades._device_activate(campaign_id=1, dev=dev, credentials={}, image_map={}, options={})

    verify, err = _final_verify_state(_patched["db"])
    assert verify == "completed", f"clean upgrade must verify, got {verify!r}"
    assert err == "", f"verified device must clear error_message, got {err!r}"
    assert any(w.get("phase") == "verified" for w in _patched["db"])
    # The verified version goes to the inventory host, once.
    assert _patched["shared"] == ["17.15.05"]


@pytest.mark.asyncio
async def test_verify_mismatch_marks_activate_failed(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    """Verify Upgrade must clear the activate green check on version mismatch."""
    conn = _FakeConn(versions=["17.15.04"])
    _patched["holder"]["conn"] = conn

    dev = {
        "id": 42,
        "ip_address": "10.0.0.1",
        "target_image": "cat9k_lite_iosxe.17.15.05.SPA.bin",
    }
    await upgrades._device_verify(campaign_id=1, dev=dev, credentials={}, image_map={}, options={})

    verify, err = _final_verify_state(_patched["db"])
    assert verify == "failed"
    assert _final_status(_patched["db"], "activate_status") == "failed"
    assert err and "version mismatch" in err.lower()
    assert any(w.get("activate_status") == "failed" and w.get("verify_status") == "failed" for w in _patched["status"])


# ── Redundancy gate + ISSU ──────────────────────────────────────────────────

_DUPLEX_HOT = """\
                 Hardware Mode = Duplex
     Operating Redundancy Mode = sso
Current Processor Information :
        Current Software state = ACTIVE
Peer Processor Information :
        Current Software state = STANDBY HOT
"""
_DUPLEX_COLD = _DUPLEX_HOT.replace("STANDBY HOT", "STANDBY COLD")
_DUPLEX_RPR = _DUPLEX_HOT.replace("= sso", "= rpr")
_SIMPLEX = """\
                 Hardware Mode = Simplex
     Operating Redundancy Mode = Non-redundant
Current Processor Information :
        Current Software state = ACTIVE
Peer (slot: 2) information is not available because it is in 'DISABLED' state
"""

_DEV = {"id": 42, "ip_address": "10.0.0.1", "target_image": "cat9k_iosxe.17.15.05.SPA.bin"}


def _activate_cmds(conn: _FakeConn) -> list[str]:
    return [c for c in conn.commands if c.startswith("install activate")]


@pytest.mark.asyncio
async def test_issu_sends_issu_verb_when_standby_hot(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    conn = _FakeConn(versions=["17.15.04", "17.15.05", "17.15.05"], redundancy=_DUPLEX_HOT)
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={"issu": True})
    assert _activate_cmds(conn) == ["install activate issu prompt-level none"]
    assert _final_status(_patched["db"], "activate_status") == "completed"
    assert "show redundancy" in conn.commands


@pytest.mark.asyncio
async def test_issu_refused_on_standalone(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    conn = _FakeConn(versions=["17.15.04"], redundancy=_SIMPLEX)
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={"issu": True})
    assert _activate_cmds(conn) == [], "must not send any activate when ISSU gate fails"
    assert _final_status(_patched["db"], "activate_status") == "failed"
    _, err = _final_verify_state(_patched["db"])
    assert "not redundant" in (err or "")


@pytest.mark.asyncio
async def test_issu_refused_without_sso(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    conn = _FakeConn(versions=["17.15.04"], redundancy=_DUPLEX_RPR)
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={"issu": True})
    assert _activate_cmds(conn) == []
    _, err = _final_verify_state(_patched["db"])
    assert "requires SSO" in (err or "")


@pytest.mark.asyncio
async def test_issu_ignores_skip_health_check(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    # ISSU on a cold standby fails on-box anyway; skip_health_check must
    # not let it through to a confusing mid-install error.
    conn = _FakeConn(versions=["17.15.04"], redundancy=_DUPLEX_COLD)
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(
        campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={"issu": True, "skip_health_check": True}
    )
    assert _activate_cmds(conn) == []
    assert _final_status(_patched["db"], "activate_status") == "failed"


@pytest.mark.asyncio
async def test_issu_refused_on_platform_without_support(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    async def fake_resolve_device_type(_dev):
        return "cisco_nxos"

    monkeypatch.setattr(upgrades, "_resolve_device_type", fake_resolve_device_type)
    conn = _FakeConn(versions=["10.3.4a"])
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={"issu": True})
    assert not [c for c in conn.commands if c.startswith("install")]
    _, err = _final_verify_state(_patched["db"])
    assert "ISSU not supported on cisco_nxos" in (err or "")


@pytest.mark.asyncio
async def test_cold_standby_blocks_plain_activate(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    conn = _FakeConn(versions=["17.15.04"], redundancy=_DUPLEX_COLD)
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert _activate_cmds(conn) == []
    assert _final_status(_patched["db"], "activate_status") == "failed"
    _, err = _final_verify_state(_patched["db"])
    assert "STANDBY COLD" in (err or "")


@pytest.mark.asyncio
async def test_cold_standby_plain_activate_overridable(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    conn = _FakeConn(versions=["17.15.04", "17.15.05", "17.15.05"], redundancy=_DUPLEX_COLD)
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(
        campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={"allow_degraded_chassis": True}
    )
    assert _activate_cmds(conn) == ["install activate prompt-level none"]
    assert any(
        lvl == "warn" and "Proceeding despite" in msg and "allow_degraded_chassis" in msg
        for lvl, msg in _patched["emits"]
    )
    # It was not HOT before the reload, so the commit does not wait for it.
    assert _final_status(_patched["db"], "verify_status") == "completed"


@pytest.mark.asyncio
async def test_skip_health_check_no_longer_overrides_cold_standby(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    conn = _FakeConn(versions=["17.15.04"], redundancy=_DUPLEX_COLD)
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(
        campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={"skip_health_check": True}
    )
    assert _activate_cmds(conn) == []
    _, err = _final_verify_state(_patched["db"])
    assert "STANDBY COLD" in (err or "")


@pytest.mark.asyncio
async def test_hot_standby_plain_activate_uses_disruptive_verb(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    # Redundant chassis without the ISSU option → normal full reload,
    # never auto-upgraded to ISSU.
    conn = _FakeConn(versions=["17.15.04", "17.15.05", "17.15.05"], redundancy=_DUPLEX_HOT)
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert _activate_cmds(conn) == ["install activate prompt-level none"]


@pytest.mark.asyncio
async def test_health_check_flags_cold_standby() -> None:
    conn = _FakeConn(versions=["17.15.04"], redundancy=_DUPLEX_COLD)
    passed, warnings = await upgrades._health_check(conn, "10.0.0.1", device_type="cisco_xe")
    assert passed is False
    assert any("STANDBY COLD" in w for w in warnings)


@pytest.mark.asyncio
async def test_health_check_issu_requires_redundancy() -> None:
    conn = _FakeConn(versions=["17.15.04"], redundancy=_SIMPLEX)
    passed, warnings = await upgrades._health_check(conn, "10.0.0.1", device_type="cisco_xe", issu=True)
    assert passed is False
    assert any("not redundant" in w for w in warnings)
    # Same box, no ISSU: standalone is fine.
    passed, warnings = await upgrades._health_check(conn, "10.0.0.1", device_type="cisco_xe")
    assert passed is True


# ── Boot-mode gate, chassis-aware reboot windows, ISSU commit timing ────────

_BUNDLE_LINE = "*    1 52    C9410R          17.12.04          CAT9K_IOSXE           BUNDLE\n"


class _SeqConn(_FakeConn):
    """``_FakeConn`` whose ``show redundancy`` output is scripted per call.

    Lets a test model the ISSU timeline: STANDBY HOT at the pre-flight
    gate, then STANDBY COLD after switchover while the old active is
    reloading, then HOT again once it's back.  Once the list is
    exhausted the last entry repeats.  ``boot_mode`` is returned for
    the ``show version | include ...`` gate.
    """

    def __init__(self, versions: list[str], redundancy_seq: list[str], boot_mode: str = "") -> None:
        super().__init__(versions)
        self._red_seq = list(redundancy_seq)
        self._boot_mode = boot_mode

    def send_command(self, command: str, **kw: object) -> str:
        if command == "show redundancy":
            self.commands.append(command)
            if len(self._red_seq) > 1:
                return self._red_seq.pop(0)
            return self._red_seq[0]
        if command.startswith("show version | include"):
            self.commands.append(command)
            return self._boot_mode
        return super().send_command(command, **kw)


@pytest.mark.asyncio
async def test_bundle_mode_blocks_activate(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    conn = _SeqConn(versions=["17.15.04"], redundancy_seq=[_SIMPLEX], boot_mode=_BUNDLE_LINE)
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert _activate_cmds(conn) == [], "must not send activate on a BUNDLE-mode box"
    assert _final_status(_patched["db"], "activate_status") == "failed"
    _, err = _final_verify_state(_patched["db"])
    assert "BUNDLE" in (err or "")


@pytest.mark.asyncio
async def test_unknown_boot_mode_does_not_block(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    # ``_FakeConn`` returns "" for the mode query - a box whose ``show
    # version`` table couldn't be parsed must still be upgradeable.
    conn = _FakeConn(versions=["17.15.04", "17.15.05", "17.15.05"], redundancy=_SIMPLEX)
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert _activate_cmds(conn) == ["install activate prompt-level none"]
    assert _final_status(_patched["db"], "activate_status") == "completed"


@pytest.mark.asyncio
async def test_redundant_chassis_widens_reboot_window(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    """A dual-sup chassis reloads both sups + all linecards; give it longer."""
    seen: dict = {}

    async def fake_wait_for_reboot(ip, credentials, options, max_wait, check_interval, *a, **k):
        seen["max_wait"] = max_wait
        return _patched["holder"]["conn"]

    monkeypatch.setattr(upgrades, "_wait_for_reboot", fake_wait_for_reboot)

    conn = _FakeConn(versions=["17.15.04", "17.15.05", "17.15.05"], redundancy=_DUPLEX_HOT)
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert seen["max_wait"] == upgrades.REDUNDANT_VERIFY_WAIT

    conn = _FakeConn(versions=["17.15.04", "17.15.05", "17.15.05"], redundancy=_SIMPLEX)
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert seen["max_wait"] == upgrades.DEFAULT_VERIFY_WAIT

    # Operator override still wins.
    conn = _FakeConn(versions=["17.15.04", "17.15.05", "17.15.05"], redundancy=_DUPLEX_HOT)
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={"verify_wait": 777})
    assert seen["max_wait"] == 777


@pytest.mark.asyncio
async def test_issu_waits_for_standby_hot_before_commit(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    """After the ISSU switchover the old active is still reloading.

    ``install commit`` sent while the peer is STANDBY COLD aborts the
    ISSU.  The activate phase must poll ``show redundancy`` until HOT
    and only then commit.
    """
    monkeypatch.setattr(upgrades, "ISSU_STANDBY_CHECK_INTERVAL", 0)
    # gate: HOT -> post-switchover: COLD, COLD -> back: HOT
    conn = _SeqConn(
        versions=["17.15.04", "17.15.05", "17.15.05"],
        redundancy_seq=[_DUPLEX_HOT, _DUPLEX_COLD, _DUPLEX_COLD, _DUPLEX_HOT],
    )
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={"issu": True})
    assert _activate_cmds(conn) == ["install activate issu prompt-level none"]
    assert "install commit" in conn.commands
    assert _final_status(_patched["db"], "activate_status") == "completed"
    assert _final_status(_patched["db"], "verify_status") == "completed"
    # Commit must come after the *last* redundancy poll (the one that
    # reported HOT), and there must have been polls after the activate.
    activate_idx = conn.commands.index("install activate issu prompt-level none")
    commit_idx = conn.commands.index("install commit")
    polls_after_activate = [i for i, c in enumerate(conn.commands) if c == "show redundancy" and i > activate_idx]
    assert len(polls_after_activate) >= 3, conn.commands
    assert commit_idx > max(polls_after_activate)


@pytest.mark.asyncio
async def test_issu_standby_timeout_skips_commit_and_fails(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    monkeypatch.setattr(upgrades, "ISSU_STANDBY_CHECK_INTERVAL", 0)
    conn = _SeqConn(
        versions=["17.15.04", "17.15.05", "17.15.05"],
        redundancy_seq=[_DUPLEX_HOT, _DUPLEX_COLD],
    )
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(
        campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={"issu": True, "standby_wait": 0}
    )
    assert "install commit" not in conn.commands, "must never commit with a cold standby mid-ISSU"
    assert _final_status(_patched["db"], "activate_status") == "failed"
    assert _final_status(_patched["db"], "verify_status") == "failed"
    _, err = _final_verify_state(_patched["db"])
    assert "STANDBY HOT" in (err or "")
    assert "install commit" in (err or "")


@pytest.mark.asyncio
async def test_plain_activate_waits_for_standby_before_commit(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    """Non-ISSU full reload: a standby that was HOT before must be HOT again
    before ``install commit`` (it can come up minutes after the active)."""
    conn = _SeqConn(
        versions=["17.15.04", "17.15.05", "17.15.05"],
        redundancy_seq=[_DUPLEX_HOT, _DUPLEX_COLD, _SIMPLEX, _DUPLEX_HOT],
    )
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(
        campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={"chassis_health_wait": 600}
    )
    assert "install commit" in conn.commands
    assert _final_status(_patched["db"], "verify_status") == "completed"
    commit_idx = conn.commands.index("install commit")
    polls = [i for i, c in enumerate(conn.commands) if c == "show redundancy"]
    assert len(polls) == 4 and commit_idx > polls[-1]
    assert any(lvl == "dim" and "STANDBY COLD" in msg for lvl, msg in _patched["emits"])


@pytest.mark.asyncio
async def test_plain_activate_standby_never_hot_skips_commit(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    conn = _SeqConn(
        versions=["17.15.04", "17.15.05", "17.15.05"],
        redundancy_seq=[_DUPLEX_HOT, _SIMPLEX],
    )
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert "install commit" not in conn.commands
    assert _final_status(_patched["db"], "activate_status") == "failed"
    assert _final_status(_patched["db"], "verify_status") == "failed"
    _, err = _final_verify_state(_patched["db"])
    assert "standby supervisor is DISABLED, not STANDBY HOT" in err
    assert "install commit was NOT sent" in err
    assert "auto-abort timer state unknown" in err


# ── Install state gate, activate reply, diagnosis ───────────────────────────
#
# An install left uncommitted by an earlier upgrade makes IOS-XE refuse the
# next activate.  Plexus used to send the activate anyway, report the
# prompt timeout as "connection closed", wait for a reload that never came
# and stop at "Version mismatch" with no reason.

_SUMMARY_HEAD = """\
[ Switch 1 ] Installed Package(s) Information:
State (St): I - Inactive, U - Activated & Uncommitted,
            C - Activated & Committed, D - Deactivated & Uncommitted
--------------------------------------------------------------------------------
Type  St   Filename/Version
--------------------------------------------------------------------------------
"""


def _summary(packages: str, timer: str = "inactive") -> str:
    return f"{_SUMMARY_HEAD}{packages}{'-' * 80}\nAuto abort timer: {timer}\n{'-' * 80}\n"


# Old version committed, target added and inactive: ready to activate.
_READY = _summary("IMG   I    17.15.05.0.2\nIMG   C    17.15.04.0.1\n")
# The incident: the running old version activated but never committed.
_OLD_UNCOMMITTED = _summary("IMG   I    17.15.05.0.2\nIMG   U    17.15.04.0.1\n")
# After a commit of the running old version.
_OLD_COMMITTED = _READY
# Target running and committed: the end state of a good upgrade.
_TARGET_COMMITTED = _summary("IMG   C    17.15.05.0.2\n")
_TARGET_UNCOMMITTED = _summary(
    "IMG   U    17.15.05.0.2\n", "active on install_activate, time before rollback - 01:12:30"
)

_ACTIVATE = "install activate prompt-level none"


class ReadTimeout(Exception):
    """Stands in for ``netmiko.exceptions.ReadTimeout`` (matched by name)."""


class _InstallConn(_FakeConn):
    """``_FakeConn`` that also answers the install commands.

    ``summaries`` is consumed one per ``show install summary`` (the last
    repeats).  ``activate`` is the reply to the activate command, or an
    exception to raise; ``chunks`` is what ``read_channel`` returns
    afterwards; ``alive`` is the ``is_alive`` sequence (last repeats).
    """

    def __init__(
        self,
        versions: list[str],
        summaries: list[str],
        *,
        activate: str | Exception = "",
        chunks: list[str] | None = None,
        alive: list[bool] | None = None,
        install_log: str = "",
        commit_output: str = "SUCCESS: install_commit",
    ) -> None:
        super().__init__(versions, commit_output=commit_output, redundancy="")
        self._summaries = list(summaries)
        self._activate = activate
        self._chunks = list(chunks or [])
        self._alive = list(alive or [True])
        self._install_log = install_log
        self.base_prompt = "lab-sw-1"

    def send_command(self, command: str, **kw: object) -> str:
        if command == "show install summary":
            self.commands.append(command)
            return self._summaries.pop(0) if len(self._summaries) > 1 else self._summaries[0]
        if command == "show install log":
            self.commands.append(command)
            return self._install_log
        if command.startswith("install activate"):
            self.commands.append(command)
            if isinstance(self._activate, Exception):
                raise self._activate
            return self._activate
        return super().send_command(command, **kw)

    def read_channel(self) -> str:
        return self._chunks.pop(0) if self._chunks else ""

    def is_alive(self) -> bool:
        return self._alive.pop(0) if len(self._alive) > 1 else self._alive[0]


def _errors(patched) -> list[str]:
    return [msg for lvl, msg in patched["emits"] if lvl == "error"]


@pytest.mark.asyncio
async def test_pending_install_refuses_activate(_patched) -> None:
    conn = _InstallConn(["17.15.04"], [_OLD_UNCOMMITTED])
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert _activate_cmds(conn) == [], "must not send activate with an install left open"
    assert "install commit" not in conn.commands
    assert _final_status(_patched["db"], "activate_status") == "failed"
    _, err = _final_verify_state(_patched["db"])
    assert "17.15.04.0.1 (the running version) is activated but not committed" in err
    assert "auto-abort timer inactive" in err
    assert "'install commit'" in err and "'install abort'" in err
    assert "Commit a pending install before activating" in err


@pytest.mark.asyncio
async def test_pending_install_message_names_active_timer(_patched) -> None:
    summary = _summary("IMG   I    17.15.05.0.2\nIMG   U    17.15.04.0.1\n", "active , time before rollback - 00:42:10")
    conn = _InstallConn(["17.15.04"], [summary])
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    _, err = _final_verify_state(_patched["db"])
    assert "auto-abort timer active (00:42:10 before rollback)" in err


@pytest.mark.asyncio
async def test_commit_pending_install_option_commits_then_activates(_patched) -> None:
    conn = _InstallConn(
        ["17.15.04", "17.15.05", "17.15.05"],
        [_OLD_UNCOMMITTED, _OLD_COMMITTED, _TARGET_COMMITTED],
    )
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(
        campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={"commit_pending_install": True}
    )
    assert _activate_cmds(conn) == [_ACTIVATE]
    assert conn.commands.index("install commit") < conn.commands.index(_ACTIVATE)
    assert _final_status(_patched["db"], "activate_status") == "completed"
    assert _final_status(_patched["db"], "verify_status") == "completed"
    assert any("running install commit" in msg for _lvl, msg in _patched["emits"])


@pytest.mark.asyncio
async def test_commit_pending_install_refuses_a_version_not_running(_patched) -> None:
    # The uncommitted version is the target, which is not running: a
    # commit would lock in a version the switch is not on.
    conn = _InstallConn(["17.15.04"], [_summary("IMG   U    17.15.05.0.2\nIMG   C    17.15.04.0.1\n")])
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(
        campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={"commit_pending_install": True}
    )
    assert "install commit" not in conn.commands
    assert _activate_cmds(conn) == []
    _, err = _final_verify_state(_patched["db"])
    assert "17.15.05.0.2 is activated but not committed" in err


@pytest.mark.asyncio
async def test_commit_pending_install_still_open_fails(_patched) -> None:
    conn = _InstallConn(["17.15.04"], [_OLD_UNCOMMITTED])
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(
        campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={"commit_pending_install": True}
    )
    assert "install commit" in conn.commands
    assert _activate_cmds(conn) == []
    _, err = _final_verify_state(_patched["db"])
    assert "still lists an open install" in err


@pytest.mark.asyncio
async def test_on_target_but_uncommitted_is_committed(_patched) -> None:
    conn = _InstallConn(["17.15.05"], [_TARGET_UNCOMMITTED, _TARGET_COMMITTED])
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert "install commit" in conn.commands
    assert _activate_cmds(conn) == []
    assert _final_status(_patched["db"], "activate_status") == "completed"
    assert _final_status(_patched["db"], "verify_status") == "completed"
    assert any("01:12:30 before rollback" in msg for _lvl, msg in _patched["emits"])


@pytest.mark.asyncio
async def test_on_target_and_committed_skips_as_before(_patched) -> None:
    conn = _InstallConn(["17.15.05"], [_TARGET_COMMITTED])
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert "install commit" not in conn.commands
    assert _final_status(_patched["db"], "verify_status") == "completed"


@pytest.mark.asyncio
async def test_on_target_commit_failure_fails_with_switch_text(_patched) -> None:
    conn = _InstallConn(
        ["17.15.05"],
        [_TARGET_UNCOMMITTED],
        commit_output="FAILED: install_commit : commit not allowed",
    )
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert _final_status(_patched["db"], "activate_status") == "failed"
    _, err = _final_verify_state(_patched["db"])
    assert "commit not allowed" in err
    assert not any(w.get("verify_status") == "completed" for w in _patched["db"])


@pytest.mark.asyncio
async def test_target_not_added_refuses_activate(_patched) -> None:
    conn = _InstallConn(["17.15.04"], [_summary("IMG   C    17.15.04.0.1\n")])
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert _activate_cmds(conn) == []
    _, err = _final_verify_state(_patched["db"])
    assert "Target 17.15.05 is not added on the switch" in err
    assert "17.15.04.0.1 (C)" in err
    assert "Transfer" in err


@pytest.mark.asyncio
async def test_target_match_ignores_leading_zeros(_patched) -> None:
    dev = {**_DEV, "target_image": "cat9k_iosxe.17.09.04a.SPA.bin"}
    conn = _InstallConn(
        ["17.06.05", "17.09.04a", "17.09.04a"],
        [_summary("IMG   I    17.9.4a.0.6\nIMG   C    17.6.5.0.5797\n"), _summary("IMG   C    17.9.4a.0.6\n")],
    )
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=dev, credentials={}, image_map={}, options={})
    assert _activate_cmds(conn) == [_ACTIVATE]
    assert _final_status(_patched["db"], "verify_status") == "completed"


@pytest.mark.asyncio
async def test_unrecognised_install_state_proceeds(_patched) -> None:
    conn = _InstallConn(["17.15.04", "17.15.05", "17.15.05"], ["% Invalid input detected at '^' marker.\n"])
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert _activate_cmds(conn) == [_ACTIVATE]
    assert _final_status(_patched["db"], "verify_status") == "completed"
    assert any(lvl == "warn" and "Install state check skipped" in msg for lvl, msg in _patched["emits"])


@pytest.mark.asyncio
async def test_activate_reply_failed_fails_fast(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    waited: list = []

    async def fake_wait_for_down(*_a, **_k):
        waited.append(1)
        return True

    monkeypatch.setattr(upgrades, "_wait_for_down", fake_wait_for_down)
    conn = _InstallConn(
        ["17.15.04"],
        [_READY],
        activate="install_activate: START Mon Jan  5 11:00:00 UTC 2026\n"
        "FAILED: install_activate : No inactive package to activate\n",
    )
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert waited == [], "must not wait for a reload the switch refused"
    assert _final_status(_patched["db"], "activate_status") == "failed"
    _, err = _final_verify_state(_patched["db"])
    assert err.startswith("Activate failed on the switch:")
    assert "No inactive package to activate" in err


@pytest.mark.asyncio
async def test_read_timeout_with_live_session_is_not_connection_closed(
    monkeypatch: pytest.MonkeyPatch, _patched
) -> None:
    monkeypatch.setattr(upgrades, "ACTIVATE_REPLY_POLL_INTERVAL", 0)
    conn = _InstallConn(
        ["17.15.04"],
        [_READY],
        activate=ReadTimeout("Pattern not detected: 'lab\\-sw\\-1' in output."),
        chunks=["", "install_activate: START x\n", "FAILED: install_activate : Install in progress\n"],
        alive=[True],
    )
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    messages = [msg for _lvl, msg in _patched["emits"]]
    assert not any("Connection closed" in m or "SSH session closed" in m for m in messages)
    assert any("has not finished the activate yet" in m for m in messages)
    _, err = _final_verify_state(_patched["db"])
    assert "Install in progress" in err
    assert _final_status(_patched["db"], "activate_status") == "failed"


@pytest.mark.asyncio
async def test_read_timeout_then_prompt_returns_waits_for_reload(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    monkeypatch.setattr(upgrades, "ACTIVATE_REPLY_POLL_INTERVAL", 0)
    conn = _InstallConn(
        ["17.15.04", "17.15.05", "17.15.05"],
        [_READY, _TARGET_COMMITTED],
        activate=ReadTimeout("Pattern not detected"),
        chunks=["install_activate: START x\nSUCCESS: install_activate x\nlab-sw-1#"],
    )
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert any("waiting for the switch to reload" in msg for _lvl, msg in _patched["emits"])
    assert _final_status(_patched["db"], "verify_status") == "completed"


@pytest.mark.asyncio
async def test_read_timeout_then_session_drop_is_a_reload(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    monkeypatch.setattr(upgrades, "ACTIVATE_REPLY_POLL_INTERVAL", 0)
    seen: dict = {}

    async def fake_wait_for_down(ip, **kw):
        seen["timeout"] = kw["timeout"]
        return True

    monkeypatch.setattr(upgrades, "_wait_for_down", fake_wait_for_down)
    conn = _InstallConn(
        ["17.15.04", "17.15.05", "17.15.05"],
        [_READY, _TARGET_COMMITTED],
        activate=ReadTimeout("Pattern not detected"),
        chunks=["Install will reload the system now!\n"],
        alive=[True, True, False],
    )
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert any("SSH session closed - the switch is reloading" in msg for _lvl, msg in _patched["emits"])
    assert _final_status(_patched["db"], "verify_status") == "completed"
    # The time spent reading counts against the same offline budget.
    assert 60 <= seen["timeout"] <= upgrades.DEFAULT_DOWN_TIMEOUT


@pytest.mark.asyncio
async def test_read_timeout_budget_is_shared_with_offline_wait(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    """Reading a silent, still-open session uses up the offline budget."""
    monkeypatch.setattr(upgrades, "ACTIVATE_REPLY_POLL_INTERVAL", 0)
    monkeypatch.setattr(upgrades, "DEFAULT_DOWN_TIMEOUT", 0)
    seen: dict = {}

    async def fake_wait_for_down(ip, **kw):
        seen["timeout"] = kw["timeout"]
        return False

    monkeypatch.setattr(upgrades, "_wait_for_down", fake_wait_for_down)
    conn = _InstallConn(["17.15.04"], [_READY], activate=ReadTimeout("Pattern not detected"))
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert seen["timeout"] == 0
    assert any("neither finished nor dropped" in msg for _lvl, msg in _patched["emits"])


@pytest.mark.asyncio
async def test_dropped_session_is_still_a_reload(_patched) -> None:
    conn = _InstallConn(
        ["17.15.04", "17.15.05", "17.15.05"],
        [_READY, _TARGET_COMMITTED],
        activate=OSError("Socket is closed"),
    )
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert any("SSH session closed (expected during reload)" in msg for _lvl, msg in _patched["emits"])
    assert _final_status(_patched["db"], "verify_status") == "completed"


@pytest.mark.asyncio
async def test_never_went_offline_carries_diagnosis(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    async def fake_wait_for_down(*_a, **_k):
        return False

    monkeypatch.setattr(upgrades, "_wait_for_down", fake_wait_for_down)
    install_log = (
        "[4|install_activate]: START Mon Jan  5 11:00:00 UTC 2026\n"
        "[4|install_activate(ERROR, )]: Install operation not allowed while an install is in progress\n"
        "[4|install_activate]: END FAILED exit(1) Mon Jan  5 11:00:05 UTC 2026\n"
    )
    conn = _InstallConn(["17.15.04"], [_READY, _OLD_UNCOMMITTED], install_log=install_log)
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    _, err = _final_verify_state(_patched["db"])
    assert err.startswith("Version mismatch: 17.15.04. Switch did not reload.")
    assert "17.15.04.0.1 (running) activated but not committed" in err
    assert "auto-abort timer inactive" in err
    assert "Last install operation: install_activate FAILED" in err
    assert "not allowed while an install is in progress" in err
    assert any("Switch did not reload" in msg for msg in _errors(_patched))
    assert len(err) < 900


@pytest.mark.asyncio
async def test_version_mismatch_without_install_hooks_keeps_plain_message(_patched) -> None:
    # Rolled back after the reboot, on a fake that knows no install commands.
    conn = _FakeConn(versions=["17.15.04"])
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    _, err = _final_verify_state(_patched["db"])
    assert err == "Version mismatch: 17.15.04"


@pytest.mark.asyncio
async def test_post_commit_install_state_must_be_committed(_patched) -> None:
    conn = _InstallConn(["17.15.04", "17.15.05", "17.15.05"], [_READY, _TARGET_UNCOMMITTED])
    _patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert _final_status(_patched["db"], "verify_status") == "failed"
    assert _final_status(_patched["db"], "activate_status") == "failed"
    _, err = _final_verify_state(_patched["db"])
    assert "still lists an open install" in err
    assert not any(w.get("verify_status") == "completed" for w in _patched["db"])


@pytest.mark.asyncio
async def test_prestage_warns_about_pending_install(monkeypatch: pytest.MonkeyPatch) -> None:
    emits: list[tuple] = []

    async def fake_emit(cid, did, level, message, host=""):
        emits.append((level, message))

    async def unpacked(*_a, **_k):
        return True, None

    monkeypatch.setattr(upgrades, "_emit", fake_emit)
    monkeypatch.setattr(upgrades, "_verify_install_add_unpacked_files", unpacked)
    conn = _InstallConn(["17.15.04"], [_OLD_UNCOMMITTED])
    ok, _ = await upgrades._run_install_add_prestage(
        conn, 1, 42, "192.0.2.10", "cat9k_iosxe.17.15.05.SPA.bin", "flash:", device_type="cisco_xe"
    )
    assert ok is True
    assert any(c.startswith("install add file") for c in conn.commands), "a pending install must not block install add"
    assert any(lvl == "warn" and "Activate will be refused until it is closed" in msg for lvl, msg in emits)
