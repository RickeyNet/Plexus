"""Regression tests for _validate_cli_inputs (upgrades.py).

image_name and dest_path are interpolated into IOS-XE CLI commands (dir,
verify /md5, install add), so unsafe characters must be rejected to prevent
command injection through Netmiko. This locks the allow-list guard against
reintroduction.
"""

from __future__ import annotations

from netcontrol.routes.upgrades import _validate_cli_inputs


def test_valid_inputs_pass():
    assert _validate_cli_inputs("cat9k_iosxe.17.09.04a.SPA.bin", "flash:") is None
    assert _validate_cli_inputs("image-1.0_final.bin", "bootflash:/") is None


def test_image_name_injection_rejected():
    for bad in [
        "img.bin; reload",
        "img.bin && erase",
        "img.bin | tftp",
        "../../etc/passwd",
        "img.bin`whoami`",
        "img.bin$(id)",
        "img name.bin",  # space
        "img.bin\nreload",
    ]:
        assert _validate_cli_inputs(bad, "flash:") is not None, bad


def test_dest_path_injection_rejected():
    for bad in [
        "flash:; reload",
        "flash:/../secret",
        "flash: rm",
        "flash:|tftp",
        "/etc/",
    ]:
        assert _validate_cli_inputs("img.bin", bad) is not None, bad


def test_empty_inputs_rejected():
    assert _validate_cli_inputs("", "flash:") is not None
    assert _validate_cli_inputs("img.bin", "") is not None
