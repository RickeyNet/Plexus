"""API-level behavior tests for config backup search and diff routes."""

from __future__ import annotations

from unittest.mock import AsyncMock

import netcontrol.routes.config_backups as config_backups_module
import pytest
from fastapi import HTTPException


@pytest.mark.asyncio
async def test_search_config_backup_records_success(monkeypatch):
    """Search route should pass through query params to DB helper."""
    expected = {"query": "public", "count": 1, "results": [{"backup_id": 1}]}
    search_mock = AsyncMock(return_value=expected)
    monkeypatch.setattr(config_backups_module.db, "search_config_backups", search_mock)

    result = await config_backups_module.search_config_backup_records(
        q="public",
        mode="fulltext",
        limit=25,
        context_lines=2,
    )
    assert result == expected
    search_mock.assert_awaited_once_with(
        "public",
        mode="fulltext",
        limit=25,
        context_lines=2,
    )


@pytest.mark.asyncio
async def test_search_config_backup_records_invalid_regex_maps_to_400(monkeypatch):
    """Invalid regex ValueError should map to HTTP 400 for the API."""
    search_mock = AsyncMock(side_effect=ValueError("invalid_regex"))
    monkeypatch.setattr(config_backups_module.db, "search_config_backups", search_mock)

    with pytest.raises(HTTPException) as exc_info:
        await config_backups_module.search_config_backup_records(
            q="(",
            mode="regex",
            limit=50,
            context_lines=1,
        )
    assert exc_info.value.status_code == 400
    assert "Invalid regex pattern" in exc_info.value.detail


@pytest.mark.asyncio
async def test_search_config_backup_records_invalid_mode_maps_to_400(monkeypatch):
    """Unsupported mode ValueError should map to HTTP 400 for the API."""
    search_mock = AsyncMock(side_effect=ValueError("invalid_mode"))
    monkeypatch.setattr(config_backups_module.db, "search_config_backups", search_mock)

    with pytest.raises(HTTPException) as exc_info:
        await config_backups_module.search_config_backup_records(
            q="public",
            mode="not-a-mode",
            limit=50,
            context_lines=1,
        )
    assert exc_info.value.status_code == 400
    assert "Unsupported search mode" in exc_info.value.detail


@pytest.mark.asyncio
async def test_search_config_backup_records_generic_value_error_maps_to_400(monkeypatch):
    """Unexpected ValueError should map to a generic invalid query HTTP 400."""
    search_mock = AsyncMock(side_effect=ValueError("something_else"))
    monkeypatch.setattr(config_backups_module.db, "search_config_backups", search_mock)

    with pytest.raises(HTTPException) as exc_info:
        await config_backups_module.search_config_backup_records(
            q="public",
            mode="fulltext",
            limit=50,
            context_lines=1,
        )
    assert exc_info.value.status_code == 400
    assert "Invalid search query" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_config_backup_diff_success(monkeypatch):
    """Diff route should return computed diff against previous successful backup."""
    current = {
        "id": 10,
        "host_id": 100,
        "status": "success",
        "config_text": "hostname sw-core-01\nsnmp-server community secure RO\n",
        "hostname": "sw-core-01",
        "ip_address": "10.0.1.1",
        "captured_at": "2026-01-02 10:00:00",
    }
    previous = {
        "id": 9,
        "host_id": 100,
        "status": "success",
        "config_text": "hostname sw-core-01\nsnmp-server community public RO\n",
        "captured_at": "2026-01-01 10:00:00",
    }
    monkeypatch.setattr(config_backups_module.db, "get_config_backup", AsyncMock(return_value=current))
    monkeypatch.setattr(
        config_backups_module.db, "get_previous_successful_config_backup", AsyncMock(return_value=previous)
    )

    captured = {}

    def _fake_diff(before, after, baseline_label, actual_label):
        captured["before"] = before
        captured["after"] = after
        captured["baseline_label"] = baseline_label
        captured["actual_label"] = actual_label
        return ("@@ diff @@\n-public\n+secure\n", 1, 1)

    monkeypatch.setattr(config_backups_module, "_compute_config_diff", _fake_diff)

    result = await config_backups_module.get_config_backup_diff(10)
    assert result["backup_id"] == 10
    assert result["previous_backup_id"] == 9
    assert result["diff_lines_added"] == 1
    assert result["diff_lines_removed"] == 1
    assert captured["baseline_label"] == "backup-9"
    assert captured["actual_label"] == "backup-10"


@pytest.mark.asyncio
async def test_get_config_backup_diff_failed_backup_raises_400(monkeypatch):
    """Diff route should reject backups that are not successful captures."""
    current = {
        "id": 10,
        "host_id": 100,
        "status": "error",
        "config_text": "",
    }
    monkeypatch.setattr(config_backups_module.db, "get_config_backup", AsyncMock(return_value=current))

    with pytest.raises(HTTPException) as exc_info:
        await config_backups_module.get_config_backup_diff(10)
    assert exc_info.value.status_code == 400
    assert "successful config capture" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_config_backup_diff_missing_previous_raises_404(monkeypatch):
    """Diff route should return 404 when no previous successful backup exists."""
    current = {
        "id": 10,
        "host_id": 100,
        "status": "success",
        "config_text": "hostname sw-core-01\n",
    }
    monkeypatch.setattr(config_backups_module.db, "get_config_backup", AsyncMock(return_value=current))
    monkeypatch.setattr(config_backups_module.db, "get_previous_successful_config_backup", AsyncMock(return_value=None))

    with pytest.raises(HTTPException) as exc_info:
        await config_backups_module.get_config_backup_diff(10)
    assert exc_info.value.status_code == 404
    assert "No previous successful backup" in exc_info.value.detail


@pytest.mark.asyncio
async def test_scheduled_backup_goes_through_the_shared_capture(monkeypatch):
    """A policy run reads the device (no reuse window) through the capture
    every feature shares, tagged with its policy; an unchanged config counts
    as skipped, not backed up."""
    from netcontrol.routes.device_config import DeviceConfig

    db = config_backups_module.db
    policy = {"id": 3, "group_id": 7, "credential_id": 5, "created_by": "admin", "retention_days": 30}
    hosts = [
        {"id": 11, "ip_address": "192.0.2.11", "device_type": "cisco_xe"},
        {"id": 12, "ip_address": "192.0.2.12", "device_type": "cisco_xe"},
    ]
    monkeypatch.setattr(db, "get_config_backup_policies_due", AsyncMock(return_value=[policy]))
    monkeypatch.setattr(db, "get_hosts_for_group", AsyncMock(return_value=hosts))
    monkeypatch.setattr(db, "update_config_backup_policy_last_run", AsyncMock())
    monkeypatch.setattr(db, "delete_old_config_backups", AsyncMock(return_value=0))
    monkeypatch.setattr(config_backups_module, "require_credential_access", AsyncMock(return_value={"username": "u"}))

    calls: list[tuple[int, dict]] = []

    async def _fake_get(host, cred, **kwargs):
        calls.append((host["id"], kwargs))
        changed = host["id"] == 11
        return DeviceConfig(host["id"], "hostname sw", "", created=changed, reused=False)

    monkeypatch.setattr(config_backups_module, "get_device_config", _fake_get)

    result = await config_backups_module._run_config_backups_once()

    assert result == {"policies_run": 1, "hosts_backed_up": 1, "errors": 0}
    assert sorted(calls, key=lambda c: c[0]) == [
        (11, {"capture_method": "scheduled", "policy_id": 3}),
        (12, {"capture_method": "scheduled", "policy_id": 3}),
    ]
