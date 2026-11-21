"""Upgrade safety gates for modular and stacked IOS-XE chassis.

Boot variables, ``show module`` before and after the reload, the wait for
the chassis to settle before ``install commit``, the Verify phase, the
reboot window and power-cycle warnings, flash space on both supervisors,
power supplies and fans, and the ``allow_degraded_chassis`` override.
All device data is invented.
"""

from __future__ import annotations

import pytest
from netcontrol.routes import upgrades

import test_upgrades_activate_commit as activate_tests
import test_upgrades_transfer as transfer_tests
from test_upgrades_activate_commit import (
    _DUPLEX_COLD,
    _DUPLEX_HOT,
    _SIMPLEX,
    _activate_cmds,
    _final_status,
    _final_verify_state,
    _SeqConn,
)

# The activate tests' fixture (stubbed db, emits and reboot waits),
# registered here under the same name.
_patched = activate_tests._patched

_DEV = {"id": 42, "ip_address": "192.0.2.10", "target_image": "cat9k_iosxe.17.15.05.SPA.bin"}
_TARGET = "17.15.05"


class _ChassisConn(_SeqConn):
    """``_SeqConn`` that also answers scripted chassis commands.

    ``scripts`` maps a command to its replies, consumed one per call (the
    last repeats); an Exception entry is raised.
    """

    def __init__(
        self, versions: list[str], redundancy_seq: list[str] | None = None, scripts: dict | None = None
    ) -> None:
        super().__init__(versions, redundancy_seq or [""])
        self._scripts = {k: list(v) for k, v in (scripts or {}).items()}

    def send_command(self, command: str, **kw: object) -> str:
        if command in self._scripts:
            self.commands.append(command)
            replies = self._scripts[command]
            reply = replies.pop(0) if len(replies) > 1 else replies[0]
            if isinstance(reply, Exception):
                raise reply
            return reply
        return super().send_command(command, **kw)


def _boot(active: str = "bootflash:packages.conf", creg: str = "0x2102", manual: str = "no") -> str:
    return f"BOOT variable = {active};\nConfiguration Register is {creg}\nMANUAL_BOOT variable = {manual}\n"


def _module_table(rows: list[tuple[int, str, str, str, str]], roles: dict[int, str] | None = None) -> str:
    """Rows of (slot, card type, model, sw, status) as a 9400 ``show module``."""
    cards = "\n".join(f"{s}   48   {card}   {model}   JAE0000000{s}" for s, card, model, _sw, _st in rows)
    status = "\n".join(
        f"{s}   0000.5E00.53{s}0 to 0000.5E00.53{s}F 1.0  17.15.1r     {sw}           {st}"
        for s, _card, _model, sw, st in rows
    )
    text = (
        "Chassis Type: C9407R\n\n"
        "Mod Ports Card Type                              Model          Serial No.\n"
        f"---+-----+------\n{cards}\n\n"
        "Mod MAC addresses                    Hw   Fw           Sw                 Status\n"
        f"---+------\n{status}\n"
    )
    if roles:
        text += "\nMod Redundancy Role     Operating Redundancy Mode Configured Redundancy Mode\n---+------\n"
        text += "\n".join(f"{s}   {role}   sso   sso" for s, role in roles.items()) + "\n"
    return text


_LC = "48-Port UPOE 10/100/1000 (RJ-45)"
_SUP = "Supervisor 1 Module"


def _chassis(
    sw: str = "17.15.04",
    lc_status: str = "ok",
    lc2_sw: str | None = None,
    standby: str | None = "Standby",
    with_lc2: bool = True,
) -> str:
    rows = [(1, _LC, "C9400-LC-48U", sw, lc_status)]
    if with_lc2:
        rows.append((2, _LC, "C9400-LC-48U", lc2_sw or sw, "ok"))
    rows += [(3, _SUP, "C9400-SUP-1", sw, "ok"), (4, _SUP, "C9400-SUP-1", sw, "ok")]
    roles = {3: "Active"}
    if standby:
        roles[4] = standby
    return _module_table(rows, roles)


def _single_sup(sw: str = "17.15.04") -> str:
    return _module_table([(1, _LC, "C9400-LC-48U", sw, "ok"), (3, _SUP, "C9400-SUP-1", sw, "ok")], {3: "Active"})


async def _activate(patched, conn, options: dict | None = None, dev: dict | None = None) -> None:
    patched["holder"]["conn"] = conn
    await upgrades._device_activate(campaign_id=1, dev=dev or _DEV, credentials={}, image_map={}, options=options or {})


def _messages(patched, level: str) -> list[str]:
    return [msg for lvl, msg in patched["emits"] if lvl == level]


# ── Boot variables ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("boot", "fragment"),
    [
        (_boot(active="bootflash:cat9k_iosxe.17.15.04.SPA.bin"), "not a .conf file"),
        ("BOOT variable = \nConfiguration Register is 0x2102\n", "BOOT variable is empty"),
        (_boot(manual="yes"), "manual boot is enabled"),
        (_boot(creg="0x2142"), "ignores the startup configuration"),
        (_boot(creg="0x2100"), "boots to ROMMON"),
        (_boot() + "Standby BOOT variable = bootflash:old.bin;\n", "Standby supervisor: BOOT variable is"),
    ],
)
async def test_boot_vars_block_activate(_patched, boot: str, fragment: str) -> None:
    conn = _ChassisConn(["17.15.04"], scripts={"show boot": [boot]})
    # Neither override applies to the boot variables.
    await _activate(_patched, conn, {"skip_health_check": True, "allow_degraded_chassis": True})
    assert _activate_cmds(conn) == []
    assert _final_status(_patched["db"], "activate_status") == "failed"
    _, err = _final_verify_state(_patched["db"])
    assert err.startswith("Boot variables would not boot the new release:")
    assert fragment in err


@pytest.mark.asyncio
async def test_boot_vars_ok_logs_and_proceeds(_patched) -> None:
    conn = _ChassisConn(["17.15.04", _TARGET, _TARGET], scripts={"show boot": [_boot(creg="0x102")]})
    await _activate(_patched, conn)
    assert _activate_cmds(conn) == ["install activate prompt-level none"]
    assert "Boot variables OK (Active supervisor bootflash:packages.conf)" in _messages(_patched, "info")
    # The boot variables are read before the redundancy gate.
    assert conn.commands.index("show boot") < conn.commands.index("show redundancy")


@pytest.mark.asyncio
async def test_boot_vars_other_conf_only_warns(_patched) -> None:
    conn = _ChassisConn(["17.15.04", _TARGET, _TARGET], scripts={"show boot": [_boot(active="bootflash:lab.conf")]})
    await _activate(_patched, conn)
    assert _activate_cmds(conn) == ["install activate prompt-level none"]
    assert any("not packages.conf" in m for m in _messages(_patched, "warn"))


@pytest.mark.asyncio
async def test_boot_vars_read_failure_proceeds(_patched) -> None:
    conn = _ChassisConn(["17.15.04", _TARGET, _TARGET], scripts={"show boot": [OSError("channel closed")]})
    await _activate(_patched, conn)
    assert _activate_cmds(conn) == ["install activate prompt-level none"]
    assert any(m.startswith("Boot variable check skipped: show boot failed") for m in _messages(_patched, "warn"))


@pytest.mark.asyncio
async def test_boot_vars_block_prestage(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    async def health_check(*_a, **_k):
        raise AssertionError("health check must not run")

    async def detect_model(_conn, _ip):
        return "C9407R", "17.15.04"

    monkeypatch.setattr(upgrades, "_health_check", health_check)
    monkeypatch.setattr(upgrades, "_detect_model", detect_model)
    conn = _ChassisConn(["17.15.04"], scripts={"show boot": [_boot(manual="yes")]})
    _patched["holder"]["conn"] = conn
    await upgrades._device_prestage(1, {"id": 42, "ip_address": "192.0.2.10"}, {}, [], {"skip_health_check": True})
    assert _final_status(_patched["db"], "prestage_status") == "failed"
    _, err = _final_verify_state(_patched["db"])
    assert "manual boot is enabled" in err


# ── Module problems (pure) ──────────────────────────────────────────────────


def _parsed(text: str) -> dict:
    return upgrades.get_driver("cisco_xe").parse_module_state(text)


def test_module_problems_status_and_dead_standby() -> None:
    problems = upgrades._module_problems(_parsed(_chassis(lc_status="faulty", standby=None)))
    assert "Slot 1 (C9400-LC-48U) is faulty" in problems
    assert "2 supervisors installed but none is in the standby role" in problems
    assert upgrades._module_problems(_parsed(_chassis())) == []
    assert upgrades._module_problems(None) == []


def test_module_problems_version_and_missing_slot() -> None:
    baseline = _parsed(_chassis())
    now = _parsed(_chassis(sw=_TARGET, lc2_sw="17.15.04", with_lc2=True))
    assert upgrades._module_problems(now, _TARGET, baseline) == ["Slot 2 (C9400-LC-48U) runs 17.15.04, not 17.15.05"]
    now = _parsed(_chassis(sw=_TARGET, with_lc2=False))
    assert upgrades._module_problems(now, _TARGET, baseline) == [
        "Slot 2 (C9400-LC-48U) was present before the reload and is missing now"
    ]
    # Leading zeros do not matter.
    assert upgrades._module_problems(_parsed(_chassis(sw="17.15.5")), _TARGET) == []


def test_module_problems_baseline_fault_is_exempt() -> None:
    baseline = _parsed(_chassis(lc_status="faulty"))
    now = _parsed(_chassis(sw=_TARGET, lc_status="faulty"))
    assert upgrades._module_problems(now, _TARGET, baseline) == []
    # Without the baseline it is reported.
    assert upgrades._module_problems(now, _TARGET) == ["Slot 1 (C9400-LC-48U) is faulty"]


def test_module_problems_baseline_without_standby_is_exempt() -> None:
    # Activated knowingly with a dead second supervisor: the same fault
    # after the reload must not withhold the commit.
    baseline = _parsed(_chassis(standby=None))
    now = _parsed(_chassis(sw=_TARGET, standby=None))
    assert upgrades._module_problems(now, _TARGET, baseline) == []
    # A standby that was there before and is not now is still a problem.
    assert upgrades._module_problems(now, _TARGET, _parsed(_chassis())) == [
        "2 supervisors installed but none is in the standby role"
    ]


def test_module_problems_provisioned_in_chassis_standby_is_healthy() -> None:
    state = {
        "modular": True,
        "modules": [
            {"chassis": 1, "slot": 3, "status": "ok", "supervisor": True, "role": "active", "sw": _TARGET},
            {"chassis": 1, "slot": 4, "status": "Provisioned", "supervisor": True, "role": "inchassis-standby"},
            {"chassis": 2, "slot": 3, "status": "ok", "supervisor": True, "role": "standby", "sw": _TARGET},
        ],
    }
    assert upgrades._module_problems(state, _TARGET) == []


# ── Pre-activate module gate ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_module_gate_blocks_activate(_patched) -> None:
    conn = _ChassisConn(["17.15.04"], [_DUPLEX_HOT], {"show module": [_chassis(lc_status="out of service")]})
    await _activate(_patched, conn)
    assert _activate_cmds(conn) == []
    _, err = _final_verify_state(_patched["db"])
    assert err.startswith("Module check failed: Slot 1 (C9400-LC-48U) is out of service")
    # The override is named the way the campaign form labels it.
    assert "'Allow a degraded chassis'" in err


@pytest.mark.asyncio
async def test_module_gate_dead_second_supervisor_blocks_simplex_chassis(_patched) -> None:
    # A dead second supervisor makes show redundancy say Simplex.
    conn = _ChassisConn(["17.15.04"], [_SIMPLEX], {"show module": [_chassis(standby=None)]})
    await _activate(_patched, conn)
    assert _activate_cmds(conn) == []
    _, err = _final_verify_state(_patched["db"])
    assert "2 supervisors installed but none is in the standby role" in err


@pytest.mark.asyncio
async def test_allow_degraded_chassis_activates_and_exempts_known_fault(_patched) -> None:
    conn = _ChassisConn(
        ["17.15.04", _TARGET, _TARGET],
        [_DUPLEX_HOT],
        {"show module": [_chassis(lc_status="faulty"), _chassis(sw=_TARGET, lc_status="faulty")]},
    )
    await _activate(_patched, conn, {"allow_degraded_chassis": True})
    assert _activate_cmds(conn) == ["install activate prompt-level none"]
    assert any("Proceeding despite" in m and "faulty" in m for m in _messages(_patched, "warn"))
    assert "install commit" in conn.commands
    assert _final_status(_patched["db"], "verify_status") == "completed"


@pytest.mark.asyncio
async def test_issu_ignores_allow_degraded_chassis_for_modules(_patched) -> None:
    conn = _ChassisConn(["17.15.04"], [_DUPLEX_HOT], {"show module": [_chassis(lc_status="faulty")]})
    await _activate(_patched, conn, {"issu": True, "allow_degraded_chassis": True})
    assert _activate_cmds(conn) == []
    _, err = _final_verify_state(_patched["db"])
    assert "Module check failed" in err


@pytest.mark.asyncio
async def test_issu_ignores_allow_degraded_chassis_for_cold_standby(_patched) -> None:
    conn = _ChassisConn(["17.15.04"], [_DUPLEX_COLD])
    await _activate(_patched, conn, {"issu": True, "allow_degraded_chassis": True})
    assert _activate_cmds(conn) == []


# ── Post-reload chassis health before commit ────────────────────────────────


@pytest.mark.asyncio
async def test_commit_waits_for_line_card(_patched) -> None:
    conn = _ChassisConn(
        ["17.15.04", _TARGET, _TARGET],
        [_DUPLEX_HOT],
        {
            "show module": [
                _chassis(),
                _chassis(sw=_TARGET, lc_status="booting"),
                _chassis(sw=_TARGET, lc_status="booting"),
                _chassis(sw=_TARGET),
            ]
        },
    )
    await _activate(_patched, conn, {"chassis_health_wait": 600})
    assert "install commit" in conn.commands
    module_reads = [i for i, c in enumerate(conn.commands) if c == "show module"]
    assert len(module_reads) == 4
    assert conn.commands.index("install commit") > module_reads[-1]
    assert any("Slot 1 (C9400-LC-48U) is booting" in m for m in _messages(_patched, "dim"))
    assert any(
        m.startswith("Chassis healthy after the reload - Modules: 4 ok, all on 17.15.05; standby supervisor")
        for m in _messages(_patched, "success")
    )
    assert _final_status(_patched["db"], "verify_status") == "completed"


@pytest.mark.asyncio
async def test_chassis_never_settles_skips_commit_and_names_timer(_patched) -> None:
    summary = (
        "[ R0 R1 ] Installed Package(s) Information:\n"
        "Type  St   Filename/Version\n"
        "IMG   C    17.15.04.0.1\n"
        "IMG   U    17.15.05.0.2\n"
        "Auto abort timer: active on install_activate, time before rollback - 01:40:00\n"
    )
    conn = _ChassisConn(
        ["17.15.04", _TARGET, _TARGET],
        [_DUPLEX_HOT],
        {
            "show module": [_chassis(), _chassis(sw=_TARGET, lc2_sw="17.15.04", with_lc2=True)],
            # Unrecognised at the pre-activate gate, then the open install.
            "show install summary": ["", summary],
        },
    )
    await _activate(_patched, conn)
    assert "install commit" not in conn.commands
    assert _final_status(_patched["db"], "activate_status") == "failed"
    assert _final_status(_patched["db"], "verify_status") == "failed"
    _, err = _final_verify_state(_patched["db"])
    assert err.startswith("Chassis not healthy 0 min after the reload: Slot 2 (C9400-LC-48U) runs 17.15.04")
    assert "install commit was NOT sent (auto-abort timer active (01:40:00 before rollback))" in err
    assert "'install commit'" in err and "'install abort'" in err
    assert _patched["shared"] == []


@pytest.mark.asyncio
async def test_missing_line_card_after_reload_blocks_commit(_patched) -> None:
    conn = _ChassisConn(
        ["17.15.04", _TARGET, _TARGET],
        [_DUPLEX_HOT],
        {"show module": [_chassis(), _chassis(sw=_TARGET, with_lc2=False)]},
    )
    await _activate(_patched, conn)
    assert "install commit" not in conn.commands
    _, err = _final_verify_state(_patched["db"])
    assert "Slot 2 (C9400-LC-48U) was present before the reload and is missing now" in err


@pytest.mark.asyncio
async def test_stack_member_must_return_ready(_patched) -> None:
    header = (
        "Switch#   Role    Mac Address     Priority Version  State\n"
        "-------------------------------------------------------------\n"
        "*1       Active   0000.5e00.5344     15     V02     Ready\n"
    )
    before = header + " 2       Standby  0000.5e00.5345     14     V02     Ready\n"
    after = header + " 2       Member   0000.5e00.5345     14     V02     Progressing\n"
    conn = _ChassisConn(["17.15.04", _TARGET, _TARGET], scripts={"show switch": [before, after]})
    await _activate(_patched, conn)
    assert "install commit" not in conn.commands
    _, err = _final_verify_state(_patched["db"])
    assert "stack member 2 is Progressing" in err
    assert "stack member 1" not in err


@pytest.mark.asyncio
async def test_stack_with_standby_member_is_not_called_supervisors(_patched) -> None:
    # A stack with a standby member answers show redundancy as Duplex, like
    # a dual-supervisor chassis; the reload line must still say "stack".
    stack = (
        "Switch#   Role    Mac Address     Priority Version  State\n"
        "*1       Active   0000.5e00.5344     15     V02     Ready\n"
        " 2       Standby  0000.5e00.5345     14     V02     Ready\n"
    )
    conn = _ChassisConn(["17.15.04", _TARGET, _TARGET], [_DUPLEX_HOT], {"show switch": [stack]})
    await _activate(_patched, conn)
    reload_lines = [m for m in _messages(_patched, "info") if m.startswith("This will trigger a reload")]
    assert len(reload_lines) == 1
    assert "all 2 stack members reload" in reload_lines[0]
    assert "supervisors" not in reload_lines[0]


@pytest.mark.asyncio
async def test_unrecognised_module_output_keeps_todays_flow(_patched) -> None:
    conn = _ChassisConn(["17.15.04", _TARGET, _TARGET], scripts={"show module": ["% Invalid input\n"]})
    await _activate(_patched, conn)
    assert "install commit" in conn.commands
    assert any(
        m.startswith("Module check skipped: show module reply not recognised") for m in _messages(_patched, "warn")
    )


# ── Reboot windows and power-cycle messages ─────────────────────────────────


@pytest.mark.asyncio
async def test_single_sup_modular_chassis_gets_wide_windows(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    seen: dict = {}

    async def fake_wait_for_reboot(ip, credentials, options, max_wait, *a, **k):
        seen["max_wait"] = max_wait
        return _patched["holder"]["conn"]

    monkeypatch.setattr(upgrades, "_wait_for_reboot", fake_wait_for_reboot)
    conn = _ChassisConn(
        ["17.15.04", _TARGET, _TARGET], [_SIMPLEX], {"show module": [_single_sup(), _single_sup(_TARGET)]}
    )
    await _activate(_patched, conn)
    assert seen["max_wait"] == upgrades.REDUNDANT_VERIFY_WAIT
    infos = _messages(_patched, "info")
    assert (
        "This will trigger a reload: the supervisor and every line card reload. "
        f"Allowing up to {upgrades.REDUNDANT_VERIFY_WAIT // 60} minutes for SSH to answer again..."
    ) in infos
    assert upgrades._DO_NOT_POWER_CYCLE in _messages(_patched, "warn")
    assert "Do not power cycle" in upgrades._DO_NOT_POWER_CYCLE


@pytest.mark.asyncio
async def test_unreachable_after_reboot_says_do_not_power_cycle(monkeypatch: pytest.MonkeyPatch, _patched) -> None:
    async def never_back(*_a, **_k):
        return None

    monkeypatch.setattr(upgrades, "_wait_for_reboot", never_back)
    conn = _ChassisConn(["17.15.04"], [_DUPLEX_HOT])
    await _activate(_patched, conn)
    _, err = _final_verify_state(_patched["db"])
    assert err.startswith("Switch unreachable after reboot")
    assert "Do not power cycle it - check the console first" in err
    assert _final_status(_patched["db"], "verify_status") == "failed"
    assert err in _messages(_patched, "error")


# ── Verify phase ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_fails_on_line_card_down(_patched) -> None:
    conn = _ChassisConn([_TARGET], [_DUPLEX_HOT], {"show module": [_chassis(sw=_TARGET, lc_status="offline")]})
    _patched["holder"]["conn"] = conn
    await upgrades._device_verify(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert _final_status(_patched["db"], "verify_status") == "failed"
    _, err = _final_verify_state(_patched["db"])
    assert err == "Running 17.15.05, but the chassis is not healthy: Slot 1 (C9400-LC-48U) is offline"


@pytest.mark.asyncio
async def test_verify_fails_on_cold_standby_and_other_release(_patched) -> None:
    conn = _ChassisConn(
        [_TARGET], [_DUPLEX_COLD], {"show module": [_chassis(sw=_TARGET, lc2_sw="17.12.04", with_lc2=True)]}
    )
    _patched["holder"]["conn"] = conn
    await upgrades._device_verify(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    _, err = _final_verify_state(_patched["db"])
    assert "standby supervisor is STANDBY COLD, not STANDBY HOT" in err
    assert "Slot 2 (C9400-LC-48U) runs 17.12.04, not 17.15.05" in err


@pytest.mark.asyncio
async def test_verify_logs_chassis_summary(_patched) -> None:
    conn = _ChassisConn([_TARGET], [_DUPLEX_HOT], {"show module": [_chassis(sw=_TARGET)]})
    _patched["holder"]["conn"] = conn
    await upgrades._device_verify(campaign_id=1, dev=_DEV, credentials={}, image_map={}, options={})
    assert _final_status(_patched["db"], "verify_status") == "completed"
    assert "Modules: 4 ok, all on 17.15.05; standby supervisor STANDBY HOT" in _messages(_patched, "info")


# ── Health check (Prestage) ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_check_flags_modules_and_power() -> None:
    conn = _ChassisConn(
        ["17.15.04"],
        [_DUPLEX_HOT],
        {
            "show module": [_chassis(lc_status="faulty")],
            "show environment status": ["PS2     C9400-PWR-3200AC      ac    3200 W    faulty        bad   good\n"],
            "show environment all": ["% Invalid input detected\n"],
        },
    )
    passed, warnings = await upgrades._health_check(conn, "192.0.2.10", device_type="cisco_xe")
    assert passed is False
    assert "Slot 1 (C9400-LC-48U) is faulty" in warnings
    assert any(w.startswith("Power/fan: PS2 C9400-PWR-3200AC") for w in warnings)


@pytest.mark.asyncio
async def test_health_check_passes_healthy_chassis() -> None:
    conn = _ChassisConn(["17.15.04"], [_DUPLEX_HOT], {"show module": [_chassis()]})
    passed, warnings = await upgrades._health_check(conn, "192.0.2.10", device_type="cisco_xe")
    assert passed is True and warnings == []


# ── Flash space ─────────────────────────────────────────────────────────────


class _DirConn:
    def __init__(self, replies: dict[str, str | Exception]) -> None:
        self.replies = replies
        self.commands: list[str] = []

    def send_command(self, command: str, **_: object) -> str:
        self.commands.append(command)
        reply = self.replies.get(command, "")
        if isinstance(reply, Exception):
            raise reply
        return reply


def _free(n: int) -> str:
    return f"11353194496 bytes total ({n} bytes free)\n"


@pytest.mark.asyncio
async def test_active_flash_needs_room_for_unpacked_packages(tmp_path) -> None:
    image = tmp_path / "img.bin"
    image.write_bytes(b"x" * 1000)
    conn = _DirConn({"dir flash: | include bytes": _free(2000)})
    ok, free = await upgrades._check_flash_space(conn, str(image), "flash:")
    assert (ok, free) == (False, 2000)
    ok, _ = await upgrades._check_flash_space(conn, str(image), "flash:", image_on_flash=True)
    assert ok is True
    # A platform that installs straight from the file needs the copy only.
    ok, _ = await upgrades._check_flash_space(conn, str(image), "flash:", unpacks=False)
    assert ok is True
    conn = _DirConn({"dir flash: | include bytes": _free(2300)})
    ok, _ = await upgrades._check_flash_space(conn, str(image), "flash:")
    assert ok is True


@pytest.fixture
def _emits(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    events: list[tuple] = []

    async def fake_emit(campaign_id, device_id, level, message, host=""):
        events.append((level, message))

    monkeypatch.setattr(upgrades, "_emit", fake_emit)
    return events


@pytest.mark.asyncio
async def test_standby_flash_gate(tmp_path, _emits) -> None:
    image = tmp_path / "img.bin"
    image.write_bytes(b"x" * 1000)
    # First filesystem does not answer; the second is too full.
    conn = _DirConn(
        {
            "dir stby-bootflash: | include bytes": "%Error opening stby-bootflash: (No such device)\n",
            "dir stby-flash: | include bytes": _free(1500),
            "dir stby-flash:img.bin": "%Error opening stby-flash:img.bin (No such file or directory)\n",
        }
    )
    err = await upgrades._standby_flash_gate(conn, 1, 42, "192.0.2.10", "cisco_xe", str(image), "img.bin")
    assert err and err.startswith("Not enough free space on the standby supervisor (stby-flash:)")
    # Image already on the standby: only 1.1x is needed.
    conn.replies["dir stby-flash:img.bin"] = "  12  -rw-  1000  img.bin\n"
    assert await upgrades._standby_flash_gate(conn, 1, 42, "192.0.2.10", "cisco_xe", str(image), "img.bin") is None
    assert any(m.startswith("Standby flash space OK (stby-flash:") for _lvl, m in _emits)


@pytest.mark.asyncio
async def test_standby_flash_gate_unreadable_proceeds(tmp_path, _emits) -> None:
    image = tmp_path / "img.bin"
    image.write_bytes(b"x" * 1000)
    conn = _DirConn({"dir stby-bootflash: | include bytes": OSError("closed")})
    assert await upgrades._standby_flash_gate(conn, 1, 42, "192.0.2.10", "cisco_xe", str(image), "img.bin") is None
    assert any(lvl == "warn" and "Standby flash space could not be read" in m for lvl, m in _emits)
    # No standby filesystem concept: nothing is read.
    conn = _DirConn({})
    assert await upgrades._standby_flash_gate(conn, 1, 42, "192.0.2.10", "cisco_nxos", str(image), "img.bin") is None
    assert conn.commands == []


@pytest.mark.asyncio
async def test_transfer_blocks_on_full_standby(monkeypatch: pytest.MonkeyPatch, tmp_path, _patched) -> None:
    image = tmp_path / "cat9k_iosxe.17.15.05.SPA.bin"
    image.write_bytes(b"x" * 1000)
    transfers: list = []

    async def transfer_image(*_a, **_k):
        transfers.append(1)
        return True, None

    monkeypatch.setattr(upgrades, "_local_image_path", lambda name: str(image))
    monkeypatch.setattr(upgrades, "_transfer_image", transfer_image)
    monkeypatch.setattr(upgrades, "_check_image_exists", lambda conn, name, dest: False)
    conn = _ChassisConn(
        ["17.15.04"],
        [_DUPLEX_HOT],
        {
            "dir flash: | include bytes": [_free(10**6)],
            "dir stby-bootflash: | include bytes": [_free(1500)],
        },
    )
    _patched["holder"]["conn"] = conn
    await upgrades._device_transfer(1, _DEV, {}, [], {"skip_md5": True})
    assert transfers == []
    assert _final_status(_patched["db"], "transfer_status") == "failed"
    _, err = _final_verify_state(_patched["db"])
    assert "standby supervisor (stby-bootflash:)" in err


# ── Check status ────────────────────────────────────────────────────────────


class _CheckConn(transfer_tests._FakeConn):
    def send_command(self, cmd: str, **kwargs) -> str:
        if cmd == "show boot":
            self.commands.append(cmd)
            return _boot(manual="yes")
        if cmd == "show module":
            self.commands.append(cmd)
            return _chassis(lc_status="faulty")
        return super().send_command(cmd, **kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize(("running", "status"), [("17.12.04", "failed"), (_TARGET, "completed")])
async def test_check_status_boot_vars_block_and_modules_warn(
    monkeypatch: pytest.MonkeyPatch, running: str, status: str
) -> None:
    rec = transfer_tests._patch_check(monkeypatch, running=running)

    async def connect(*_a, **_k):
        return _CheckConn()

    monkeypatch.setattr(upgrades, "_connect_device", connect)
    await transfer_tests._run_check(transfer_status="completed")
    assert rec["updates"]["transfer_status"] == status
    assert ("warn", "Module check: Slot 1 (C9400-LC-48U) is faulty") in rec["emits"]
    if status == "failed":
        # Same treatment as a BUNDLE boot mode: blocks only when not on the target.
        assert "manual boot is enabled" in rec["updates"]["error_message"]
        assert rec["updates"]["phase_detail"] == "Boot variables"
        assert rec["md5_checked"] is False
