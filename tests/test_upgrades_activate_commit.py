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
    ) -> None:
        # One version string per ``show version`` call, consumed in order.
        self._versions = list(versions)
        self._commit_raises = commit_raises
        self._commit_output = commit_output
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
        if command == "install commit":
            if self._commit_raises:
                raise OSError(
                    "The process for the command is not responding "
                    "or is otherwise unavailable")
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

    monkeypatch.setattr(upgrades, "_emit", fake_emit)
    monkeypatch.setattr(upgrades, "_emit_device_status", fake_emit_device_status)
    monkeypatch.setattr(upgrades.db, "update_upgrade_device", fake_update)

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

    return {"emits": emits, "db": db_writes, "status": status_emits,
            "holder": holder}


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
async def test_commit_failure_marks_device_failed_not_verified(
    monkeypatch: pytest.MonkeyPatch, _patched
) -> None:
    """A raising ``install commit`` must NOT leave the device verified."""
    # show version calls, in order: pre-activate "already running?" check
    # (must be the OLD version or activate is skipped), then post-reboot
    # (NEW). The commit command then throws.
    conn = _FakeConn(versions=["17.15.04", "17.15.05"], commit_raises=True)
    _patched["holder"]["conn"] = conn

    dev = {"id": 42, "ip_address": "10.0.0.1", "target_image": "cat9k_lite_iosxe.17.15.05.SPA.bin"}
    await upgrades._device_activate(
        campaign_id=1, dev=dev, credentials={}, image_map={}, options={})

    verify, err = _final_verify_state(_patched["db"])
    assert verify == "failed", f"commit failure must fail verify, got {verify!r}"
    assert _final_status(_patched["db"], "activate_status") == "failed"
    assert err and "commit failed" in err.lower()
    # It must never have been stamped verified/completed.
    assert all(
        w.get("verify_status") != "completed" for w in _patched["db"]
    ), "device was marked completed despite a failed commit"
    assert not any(
        w.get("phase") == "verified" for w in _patched["db"]
    ), "device phase set to verified despite a failed commit"


@pytest.mark.asyncio
async def test_post_commit_rollback_is_detected(
    monkeypatch: pytest.MonkeyPatch, _patched
) -> None:
    """Commit 'succeeds' but the device is back on the old version."""
    # show version order: pre-activate check = OLD (so activate runs),
    # post-reboot = NEW, post-commit re-verify = OLD -> silent rollback.
    conn = _FakeConn(versions=["17.15.04", "17.15.05", "17.15.04"],
                     commit_raises=False)
    _patched["holder"]["conn"] = conn

    dev = {"id": 42, "ip_address": "10.0.0.1", "target_image": "cat9k_lite_iosxe.17.15.05.SPA.bin"}
    await upgrades._device_activate(
        campaign_id=1, dev=dev, credentials={}, image_map={}, options={})

    verify, err = _final_verify_state(_patched["db"])
    assert verify == "failed", f"post-commit rollback must fail verify, got {verify!r}"
    assert _final_status(_patched["db"], "activate_status") == "failed"
    assert err and "post-commit" in err.lower()
    assert all(w.get("verify_status") != "completed" for w in _patched["db"])


@pytest.mark.asyncio
async def test_commit_error_text_marks_device_failed(
    monkeypatch: pytest.MonkeyPatch, _patched
) -> None:
    """Netmiko can return commit failure text without raising."""
    conn = _FakeConn(
        versions=["17.15.04", "17.15.05"],
        commit_output=(
            "The process for the command is not responding "
            "or is otherwise unavailable"
        ),
    )
    _patched["holder"]["conn"] = conn

    dev = {"id": 42, "ip_address": "10.0.0.1", "target_image": "cat9k_lite_iosxe.17.15.05.SPA.bin"}
    await upgrades._device_activate(
        campaign_id=1, dev=dev, credentials={}, image_map={}, options={})

    verify, err = _final_verify_state(_patched["db"])
    assert verify == "failed"
    assert _final_status(_patched["db"], "activate_status") == "failed"
    assert err and "commit failed" in err.lower()
    assert "not responding" in err.lower()
    assert not any(w.get("verify_status") == "completed" for w in _patched["db"])


@pytest.mark.asyncio
async def test_successful_commit_and_reverify_marks_verified(
    monkeypatch: pytest.MonkeyPatch, _patched
) -> None:
    """Happy path: reboot OK, commit OK, post-commit version still new."""
    # pre-activate check = OLD (activate runs), post-reboot = NEW,
    # post-commit re-verify = NEW (commit stuck).
    conn = _FakeConn(versions=["17.15.04", "17.15.05", "17.15.05"],
                     commit_raises=False)
    _patched["holder"]["conn"] = conn

    dev = {"id": 42, "ip_address": "10.0.0.1", "target_image": "cat9k_lite_iosxe.17.15.05.SPA.bin"}
    await upgrades._device_activate(
        campaign_id=1, dev=dev, credentials={}, image_map={}, options={})

    verify, err = _final_verify_state(_patched["db"])
    assert verify == "completed", f"clean upgrade must verify, got {verify!r}"
    assert err == "", f"verified device must clear error_message, got {err!r}"
    assert any(w.get("phase") == "verified" for w in _patched["db"])


@pytest.mark.asyncio
async def test_verify_mismatch_marks_activate_failed(
    monkeypatch: pytest.MonkeyPatch, _patched
) -> None:
    """Verify Upgrade must clear the activate green check on version mismatch."""
    conn = _FakeConn(versions=["17.15.04"])
    _patched["holder"]["conn"] = conn

    dev = {
        "id": 42,
        "ip_address": "10.0.0.1",
        "target_image": "cat9k_lite_iosxe.17.15.05.SPA.bin",
    }
    await upgrades._device_verify(
        campaign_id=1, dev=dev, credentials={}, image_map={}, options={})

    verify, err = _final_verify_state(_patched["db"])
    assert verify == "failed"
    assert _final_status(_patched["db"], "activate_status") == "failed"
    assert err and "version mismatch" in err.lower()
    assert any(
        w.get("activate_status") == "failed" and w.get("verify_status") == "failed"
        for w in _patched["status"]
    )
