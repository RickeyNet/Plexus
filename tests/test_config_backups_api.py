"""API-level behavior tests for config backup search, diff and policy runs (OPNsense hosts over the API, policies without a credential)."""

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


# ── Policies without a credential, OPNsense hosts over the API ───────────────

_FIREWALL = {"id": 21, "ip_address": "192.0.2.21", "device_type": "opnsense", "group_id": 7}
_SWITCH = {"id": 22, "ip_address": "192.0.2.22", "device_type": "cisco_xe", "group_id": 7}


def _stored(host_id: int, created: bool = True):
    from netcontrol.routes.device_config import DeviceConfig

    return DeviceConfig(host_id, "text", "", created=created, reused=False)


@pytest.fixture
def capture(monkeypatch):
    """Record the SSH captures, the API backups and the error rows."""
    calls: dict[str, list] = {"ssh": [], "api": [], "errors": []}

    async def _ssh(host, cred, **kwargs):
        calls["ssh"].append((host["id"], cred, kwargs))
        return _stored(host["id"])

    async def _api(host, **kwargs):
        calls["api"].append((host["id"], kwargs))
        return _stored(host["id"])

    async def _error_row(**kwargs):
        calls["errors"].append(kwargs)
        return 1

    monkeypatch.setattr(config_backups_module, "get_device_config", _ssh)
    monkeypatch.setattr(config_backups_module, "backup_firewall", _api)
    monkeypatch.setattr(config_backups_module.db, "create_config_backup", _error_row)
    return calls


@pytest.mark.asyncio
async def test_backup_host_reads_an_opnsense_host_over_the_api_and_needs_no_credential(capture):
    result = await config_backups_module.backup_host(_FIREWALL, None, policy_id=3, capture_method="manual")
    assert result is True
    assert capture["api"] == [(21, {"policy_id": 3, "capture_method": "manual"})]
    assert capture["ssh"] == [] and capture["errors"] == []


@pytest.mark.asyncio
async def test_backup_host_without_a_credential_writes_an_error_row_for_an_ssh_host(capture):
    result = await config_backups_module.backup_host(_SWITCH, None, policy_id=3, capture_method="scheduled")
    assert result is False and capture["ssh"] == []
    (row,) = capture["errors"]
    assert row["status"] == "error" and row["host_id"] == 22 and row["policy_id"] == 3
    assert row["error_message"] == config_backups_module.NO_CREDENTIAL_MESSAGE


@pytest.mark.asyncio
async def test_backup_host_turns_a_failed_api_backup_into_an_error_row(capture, monkeypatch):
    from netcontrol.routes.opnsense_backup import NO_SOURCE_MESSAGE, FirewallBackupError

    async def _fail(host, **kwargs):
        raise FirewallBackupError(NO_SOURCE_MESSAGE)

    monkeypatch.setattr(config_backups_module, "backup_firewall", _fail)
    assert await config_backups_module.backup_host(_FIREWALL, None, policy_id=3, capture_method="manual") is False
    assert capture["errors"][0]["error_message"] == NO_SOURCE_MESSAGE


@pytest.mark.asyncio
async def test_backup_host_outcome_gives_the_reason_stored_on_the_error_row(capture):
    """Run Now names why a host failed: the text of its error row."""
    outcome = await config_backups_module.backup_host_outcome(_SWITCH, None, policy_id=3, capture_method="manual")
    assert outcome == (False, config_backups_module.NO_CREDENTIAL_MESSAGE)
    assert capture["errors"][0]["error_message"] == outcome[1]

    outcome = await config_backups_module.backup_host_outcome(_FIREWALL, None, policy_id=3, capture_method="manual")
    assert outcome == (True, "")


def _due(monkeypatch, policy: dict, hosts: list[dict]) -> AsyncMock:
    db = config_backups_module.db
    last_run = AsyncMock()
    monkeypatch.setattr(db, "get_config_backup_policies_due", AsyncMock(return_value=[policy]))
    monkeypatch.setattr(db, "get_hosts_for_group", AsyncMock(return_value=hosts))
    monkeypatch.setattr(db, "update_config_backup_policy_last_run", last_run)
    monkeypatch.setattr(db, "delete_old_config_backups", AsyncMock(return_value=0))
    return last_run


@pytest.mark.asyncio
async def test_a_scheduled_policy_without_a_credential_backs_up_its_firewall(capture, monkeypatch):
    policy = {"id": 4, "group_id": 7, "credential_id": None, "created_by": "admin", "retention_days": 30}
    last_run = _due(monkeypatch, policy, [_FIREWALL, _SWITCH])
    check = AsyncMock()
    monkeypatch.setattr(config_backups_module, "require_credential_access", check)

    result = await config_backups_module._run_config_backups_once()

    assert result == {"policies_run": 1, "hosts_backed_up": 1, "errors": 1}
    assert capture["api"] == [(21, {"policy_id": 4, "capture_method": "scheduled"})] and capture["ssh"] == []
    assert [r["host_id"] for r in capture["errors"]] == [22]
    check.assert_not_awaited()
    last_run.assert_awaited_once_with(4)


@pytest.mark.asyncio
async def test_a_rejected_credential_still_backs_up_the_firewall(capture, monkeypatch):
    """The SSH hosts keep today's behaviour (no row, one error, retried at
    the next wake-up when nothing else ran); the firewall is backed up."""
    policy = {"id": 5, "group_id": 7, "credential_id": 9, "created_by": "gone", "retention_days": 30}
    monkeypatch.setattr(
        config_backups_module, "require_credential_access", AsyncMock(side_effect=HTTPException(403, "no"))
    )
    last_run = _due(monkeypatch, policy, [_FIREWALL, _SWITCH])
    result = await config_backups_module._run_config_backups_once()
    assert result == {"policies_run": 1, "hosts_backed_up": 1, "errors": 1}
    assert [h for h, _ in capture["api"]] == [21] and capture["ssh"] == [] and capture["errors"] == []
    last_run.assert_awaited_once_with(5)

    capture["api"].clear()
    last_run = _due(monkeypatch, policy, [_SWITCH])
    result = await config_backups_module._run_config_backups_once()
    assert result == {"policies_run": 0, "hosts_backed_up": 0, "errors": 1}
    assert capture["api"] == [] and capture["ssh"] == []
    last_run.assert_not_awaited()


@pytest.mark.asyncio
async def test_host_backup_policy_needs_a_credential_only_for_an_ssh_host(monkeypatch):
    policy = {"id": 6, "name": "a", "group_id": 7, "credential_id": None, "enabled": 1}
    monkeypatch.setattr(config_backups_module.db, "get_config_backup_policies", AsyncMock(return_value=[policy]))
    assert await config_backups_module.host_backup_policy(_FIREWALL) == (policy, None)
    assert await config_backups_module.host_backup_policy(_SWITCH) is None


# ── opnsense_backup.backup_firewall: the error messages ─────────────────────


@pytest.fixture
def firewall_source(monkeypatch):
    import netcontrol.routes.opnsense_health as health

    org = {"id": 41, "name": "Edge firewall", "provider": "opnsense", "base_url": "https://fw1.example.com"}
    source = AsyncMock(return_value=org)
    monkeypatch.setattr(health, "source_of_host", source)
    monkeypatch.setattr(config_backups_module.db, "get_meraki_org_api_key", AsyncMock(return_value="key-1:secret-1"))
    return source


@pytest.mark.asyncio
async def test_backup_firewall_needs_the_host_to_be_a_collected_firewall(firewall_source):
    from netcontrol.routes.opnsense_backup import NO_SOURCE_MESSAGE, FirewallBackupError, backup_firewall

    firewall_source.return_value = None
    with pytest.raises(FirewallBackupError) as raised:
        await backup_firewall(_FIREWALL, policy_id=1, capture_method="manual")
    assert str(raised.value) == NO_SOURCE_MESSAGE and "import the firewall" in NO_SOURCE_MESSAGE


@pytest.mark.asyncio
async def test_backup_firewall_needs_the_source_key(firewall_source, monkeypatch):
    from netcontrol.routes.opnsense_backup import FirewallBackupError, backup_firewall

    monkeypatch.setattr(config_backups_module.db, "get_meraki_org_api_key", AsyncMock(return_value=""))
    with pytest.raises(FirewallBackupError, match="OPNsense source 'Edge firewall' has no API key"):
        await backup_firewall(_FIREWALL, policy_id=1, capture_method="manual")

    monkeypatch.setattr(config_backups_module.db, "get_meraki_org_api_key", AsyncMock(return_value="no-colon"))
    with pytest.raises(FirewallBackupError, match="key:secret") as raised:
        await backup_firewall(_FIREWALL, policy_id=1, capture_method="manual")
    assert "no-colon" not in str(raised.value)


def _answering(monkeypatch, handler) -> None:
    import httpx
    import netcontrol.routes.meraki_topology as topology_routes

    real = topology_routes.OpnsenseClient

    def _client(base_url, key, secret, **kwargs):
        kwargs.update(transport=httpx.MockTransport(handler), requests_per_second=1000)
        return real(base_url, key, secret, **kwargs)

    monkeypatch.setattr(topology_routes, "OpnsenseClient", _client)


@pytest.mark.asyncio
async def test_backup_firewall_names_the_privilege_of_a_refused_download(firewall_source, monkeypatch):
    import httpx
    from netcontrol.routes.opnsense_backup import FirewallBackupError, backup_firewall

    _answering(monkeypatch, lambda request: httpx.Response(403, json={"message": "Forbidden"}))
    with pytest.raises(FirewallBackupError) as raised:
        await backup_firewall(_FIREWALL, policy_id=1, capture_method="manual")
    message = str(raised.value)
    assert "HTTP 403" in message and "Diagnostics: Configuration History" in message
    assert "secret-1" not in message and "key-1" not in message


@pytest.mark.asyncio
async def test_backup_firewall_refuses_an_answer_that_is_no_config_xml(firewall_source, monkeypatch):
    import httpx
    from netcontrol.routes.opnsense_backup import FirewallBackupError, backup_firewall

    _answering(monkeypatch, lambda request: httpx.Response(200, text="<html>login</html>"))
    with pytest.raises(FirewallBackupError, match="did not answer with an OPNsense config.xml"):
        await backup_firewall(_FIREWALL, policy_id=1, capture_method="manual")
