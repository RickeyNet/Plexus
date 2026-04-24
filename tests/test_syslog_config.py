import logging.handlers
from types import SimpleNamespace
from unittest.mock import AsyncMock

import netcontrol.routes.admin as admin_module
import netcontrol.routes.state as state
import pytest
from netcontrol.telemetry import (
    configure_logging,
    configure_syslog_logging,
    syslog_logging_enabled,
)


def test_sanitize_syslog_config_normalizes_values():
    cfg = state._sanitize_syslog_config(
        {
            "enabled": True,
            "host": "  syslog.example.local ",
            "port": 70000,
            "protocol": "TCP",
            "facility": "LOCAL7",
            "level": "debug",
            "app_name": "Plexus Prod",
        }
    )

    assert cfg == {
        "enabled": True,
        "host": "syslog.example.local",
        "port": 65535,
        "protocol": "tcp",
        "facility": "local7",
        "level": "DEBUG",
        "app_name": "PlexusProd",
    }


def test_configure_syslog_logging_attaches_and_removes_handler():
    logger = configure_logging("plexus.test_syslog_unit")
    configure_syslog_logging(
        {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 5514,
            "protocol": "udp",
            "facility": "local0",
            "level": "INFO",
            "app_name": "plexus-test",
        }
    )

    try:
        assert syslog_logging_enabled() is True
        assert any(
            isinstance(handler, logging.handlers.SysLogHandler)
            for handler in logger.handlers
        )
    finally:
        configure_syslog_logging({"enabled": False})

    assert syslog_logging_enabled() is False
    assert not any(
        isinstance(handler, logging.handlers.SysLogHandler)
        for handler in logger.handlers
    )


@pytest.mark.asyncio
async def test_admin_update_syslog_config_persists_and_applies(monkeypatch):
    monkeypatch.setattr(admin_module.db, "set_auth_setting", AsyncMock())
    monkeypatch.setattr(admin_module, "_audit", AsyncMock())

    body = admin_module.SyslogConfigRequest(
        enabled=True,
        host="127.0.0.1",
        port=5514,
        protocol="udp",
        facility="local1",
        level="WARNING",
        app_name="plexus-test",
    )
    request = SimpleNamespace(cookies={})

    try:
        result = await admin_module.admin_update_syslog_config(body, request)

        assert result["enabled"] is True
        assert result["active"] is True
        assert state.SYSLOG_CONFIG["host"] == "127.0.0.1"
        admin_module.db.set_auth_setting.assert_awaited_once_with(
            "syslog_config",
            state.SYSLOG_CONFIG,
        )
    finally:
        configure_syslog_logging({"enabled": False})
        state.SYSLOG_CONFIG = state._sanitize_syslog_config(None)
