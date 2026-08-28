"""Transfer-phase standby gate for dual-sup chassis (Catalyst 9400/9600).

``install add`` in IOS-XE install mode copies every unpacked package to
the standby supervisor's bootflash.  If the peer is STANDBY COLD or
absent that sync silently doesn't happen: the transfer phase reports
success and the activate phase's redundancy gate refuses the box an
hour later.  ``_transfer_standby_gate`` catches it before the SCP.
"""

from __future__ import annotations

import pytest
from netcontrol.routes import upgrades

_HOT = {"redundant": True, "standby_hot": True, "peer_state": "STANDBY HOT"}
_COLD = {"redundant": True, "standby_hot": False, "peer_state": "STANDBY COLD"}
_STANDALONE = {"redundant": False, "standby_hot": False, "peer_state": "DISABLED"}


@pytest.fixture
def _emits(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    events: list[tuple] = []

    async def fake_emit(campaign_id, device_id, level, message, host=""):
        events.append((level, message))

    monkeypatch.setattr(upgrades, "_emit", fake_emit)
    return events


@pytest.mark.asyncio
async def test_cold_standby_blocks_transfer(_emits) -> None:
    err = await upgrades._transfer_standby_gate(1, 42, "10.0.0.1", "cisco_xe", _COLD, {})
    assert err is not None
    assert "STANDBY COLD" in err
    assert "install add" in err


@pytest.mark.asyncio
async def test_hot_standby_passes(_emits) -> None:
    assert await upgrades._transfer_standby_gate(1, 42, "10.0.0.1", "cisco_xe", _HOT, {}) is None


@pytest.mark.asyncio
async def test_standalone_and_unknown_pass(_emits) -> None:
    assert await upgrades._transfer_standby_gate(1, 42, "10.0.0.1", "cisco_xe", _STANDALONE, {}) is None
    # ``_probe_redundancy`` returns None on a failed/unsupported read -
    # a flaky ``show redundancy`` must never block a transfer.
    assert await upgrades._transfer_standby_gate(1, 42, "10.0.0.1", "cisco_xe", None, {}) is None


@pytest.mark.asyncio
async def test_skip_health_check_downgrades_to_warning(_emits) -> None:
    err = await upgrades._transfer_standby_gate(1, 42, "10.0.0.1", "cisco_xe", _COLD, {"skip_health_check": True})
    assert err is None
    assert any(lvl == "warn" and "STANDBY COLD" in msg for (lvl, msg) in _emits)


@pytest.mark.asyncio
async def test_single_phase_platforms_are_not_gated(_emits) -> None:
    # NX-OS / Junos have no discrete install-add, so a "cold" peer has
    # nothing to sync and the gate must stay out of the way.
    for dt in ("cisco_nxos", "juniper_junos"):
        assert await upgrades._transfer_standby_gate(1, 42, "10.0.0.1", dt, _COLD, {}) is None, dt


@pytest.mark.asyncio
async def test_probe_redundancy_never_raises() -> None:
    class _Boom:
        def send_command(self, *_a, **_k):
            raise OSError("socket closed")

    assert await upgrades._probe_redundancy(_Boom(), "cisco_xe") is None
    # Platform with no redundancy concept -> None too.
    assert await upgrades._probe_redundancy(_Boom(), "juniper_junos") is None
