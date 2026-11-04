"""Discovery reads model, serial, version, hostname and device type over SSH
``show version`` (no SNMP needed), with the service credential by default."""

from __future__ import annotations

import asyncio

import netcontrol.routes.inventory as inventory
import pytest
from fastapi import HTTPException
from netcontrol.routes import background_jobs
from netcontrol.routes.inventory import DiscoveryScanRequest

from test_show_version_parser import IOS_XE_C9300, UNRECOGNIZED

SERVICE = {"id": 3, "name": "plexus-svc", "username": "svc", "password": "x", "is_service": 1}
MINE = {"id": 9, "name": "my-cred", "username": "me", "password": "x", "is_service": 0}


def _body(**overrides) -> DiscoveryScanRequest:
    values = {
        "cidrs": ["10.0.0.0/30"],
        "timeout_seconds": 0.1,
        "max_hosts": 16,
        "use_snmp": False,
        "use_icmp": False,
    }
    values.update(overrides)
    return DiscoveryScanRequest(**values)


def _ssh_probe_hit(ip: str = "10.0.0.1") -> dict:
    """What the TCP probe returns for a Catalyst: the banner names only Cisco."""
    return {
        "hostname": f"discovered-{ip.replace('.', '-')}",
        "ip_address": ip,
        "device_type": "cisco_ios",
        "status": "online",
        "discovery": {"protocol": "ssh", "port": 22, "banner": "SSH-2.0-Cisco-1.25", "vendor": "cisco", "os": "ios"},
    }


class _FakeShow:
    """Stands in for the shared SSH helper ``_run_show_command``."""

    def __init__(self, output: str | Exception) -> None:
        self.output = output
        self.calls: list[tuple[dict, dict, str, dict]] = []

    async def __call__(self, host, credentials, command, **kwargs):
        self.calls.append((host, credentials, command, kwargs))
        if isinstance(self.output, Exception):
            raise self.output
        return self.output


# ── Credential resolution ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_explicit_credential_is_access_checked(monkeypatch):
    seen = {}

    async def fake_access(credential_id, *, session=None, allow_service=False):
        seen.update(credential_id=credential_id, session=session, allow_service=allow_service)
        return MINE

    async def no_service():
        raise AssertionError("the service credential must not be looked up for an explicit pick")

    monkeypatch.setattr(inventory, "require_credential_access", fake_access)
    monkeypatch.setattr(inventory, "service_credential", no_service)

    cred, summary = await inventory._resolve_discovery_ssh(_body(credential_id=9), {"user": "alice", "user_id": 1})
    assert cred is MINE
    assert seen == {"credential_id": 9, "session": {"user": "alice", "user_id": 1}, "allow_service": True}
    assert summary["credential"] == "my-cred"
    assert summary["credential_source"] == "explicit"
    assert summary["skipped_reason"] == ""


@pytest.mark.asyncio
async def test_explicit_credential_denied_raises(monkeypatch):
    async def deny(credential_id, *, session=None, allow_service=False):
        raise HTTPException(403, "You can only use your own credentials")

    monkeypatch.setattr(inventory, "require_credential_access", deny)
    with pytest.raises(HTTPException) as exc:
        await inventory._resolve_discovery_ssh(_body(credential_id=9), {"user": "bob", "user_id": 2})
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_service_credential_is_the_default(monkeypatch):
    async def service():
        return SERVICE

    monkeypatch.setattr(inventory, "service_credential", service)
    cred, summary = await inventory._resolve_discovery_ssh(_body(), None)
    assert cred is SERVICE
    assert summary["credential"] == "plexus-svc"
    assert summary["credential_source"] == "service"


@pytest.mark.asyncio
async def test_no_credential_skips_ssh_without_failing(monkeypatch):
    async def none():
        return None

    monkeypatch.setattr(inventory, "service_credential", none)
    cred, summary = await inventory._resolve_discovery_ssh(_body(), None)
    assert cred is None
    assert summary["enabled"] is True
    assert "service credential" in summary["skipped_reason"]


@pytest.mark.asyncio
async def test_use_ssh_off_skips_credential_lookup(monkeypatch):
    async def no_service():
        raise AssertionError("not looked up when SSH is off")

    monkeypatch.setattr(inventory, "service_credential", no_service)
    cred, summary = await inventory._resolve_discovery_ssh(_body(use_ssh=False), None)
    assert cred is None
    assert summary["enabled"] is False
    assert summary["skipped_reason"]


@pytest.mark.asyncio
async def test_scan_job_without_credential_still_discovers(monkeypatch):
    async def fake_get_group(group_id):
        return {"id": group_id, "name": "lab"}

    async def fake_probe(ip_address, **kwargs):
        return _ssh_probe_hit(ip_address) if ip_address == "10.0.0.2" else None

    async def none():
        return None

    class _Req:
        cookies: dict = {}

    show = _FakeShow(IOS_XE_C9300)
    monkeypatch.setattr(inventory.db, "get_group", fake_get_group)
    monkeypatch.setattr(inventory, "_probe_discovery_target", fake_probe)
    monkeypatch.setattr(inventory, "service_credential", none)
    monkeypatch.setattr(inventory, "_run_show_command", show)
    monkeypatch.setattr(inventory.state, "_resolve_snmp_discovery_config", lambda _gid: {"enabled": False})

    launched = await inventory.discovery_scan(1, _body(), _Req())
    deadline = asyncio.get_event_loop().time() + 5
    while (job := background_jobs.get_job(launched["job_id"]))["status"] == "running":
        assert asyncio.get_event_loop().time() < deadline
        await asyncio.sleep(0.01)
    assert job["status"] == "completed"
    result = job["result"]
    assert result["discovered_count"] == 1
    assert show.calls == []  # no credential: no SSH login
    assert result["ssh_enrichment"]["attempted"] == 0
    assert "service credential" in result["ssh_enrichment"]["skipped_reason"]


# ── Probe enrichment ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_show_version_corrects_banner_guess(monkeypatch):
    show = _FakeShow(IOS_XE_C9300)
    monkeypatch.setattr(inventory, "_run_show_command", show)
    host = _ssh_probe_hit()

    await inventory._enrich_with_show_version(host, SERVICE)

    # One session, no SSHDetect second login, generic Cisco handler.
    assert len(show.calls) == 1
    target, cred, command, kwargs = show.calls[0]
    assert target == {"ip_address": "10.0.0.1", "device_type": "cisco_ios"}
    assert cred is SERVICE
    assert command == "show version"
    assert kwargs["autodetect"] is False

    assert host["device_type"] == "cisco_xe"
    assert host["model"] == "C9300-48P"
    assert host["software_version"] == "17.09.04a"
    assert host["serial_number"] == "FOC2345X0AB"
    assert host["hostname"] == "HQ-CORE-SW1"
    assert host["sys_name"] == "HQ-CORE-SW1"
    assert host["device_category"] == "switch"
    assert host["discovery"]["device_type_source"] == "ssh"
    assert host["discovery"]["os"] == "ios-xe"
    assert host["discovery"]["ssh"]["ok"] is True


@pytest.mark.asyncio
async def test_snmp_hit_keeps_snmp_facts_ssh_lacks(monkeypatch):
    show = _FakeShow("Cisco IOS XE Software, Version 17.12.3\n")
    monkeypatch.setattr(inventory, "_run_show_command", show)
    host = {
        "hostname": "core-sw",
        "ip_address": "10.0.0.5",
        "device_type": "cisco_ios",
        "model": "C9300-24T",
        "serial_number": "FOC999",
        "sys_name": "core-sw",
        "discovery": {"protocol": "snmpv2c"},
    }

    await inventory._enrich_with_show_version(host, SERVICE)

    assert host["device_type"] == "cisco_xe"
    assert host["software_version"] == "17.12.3"
    # Not in the output: the SNMP values stay.
    assert host["model"] == "C9300-24T"
    assert host["serial_number"] == "FOC999"
    assert host["hostname"] == "core-sw"


@pytest.mark.asyncio
async def test_ssh_failure_is_recorded_on_the_host(monkeypatch):
    monkeypatch.setattr(inventory, "_run_show_command", _FakeShow(RuntimeError("Authentication failed.")))
    host = _ssh_probe_hit()

    await inventory._enrich_with_show_version(host, SERVICE)

    assert host["device_type"] == "cisco_ios"  # banner guess untouched
    assert host["discovery"]["ssh"] == {"ok": False, "error": "RuntimeError: Authentication failed."}
    assert "device_type_source" not in host["discovery"]


@pytest.mark.asyncio
async def test_unrecognized_output_is_a_failure_not_facts(monkeypatch):
    monkeypatch.setattr(inventory, "_run_show_command", _FakeShow(UNRECOGNIZED))
    host = _ssh_probe_hit()
    await inventory._enrich_with_show_version(host, SERVICE)
    assert host["discovery"]["ssh"]["ok"] is False
    assert host["device_type"] == "cisco_ios"
    assert "model" not in host


@pytest.mark.asyncio
async def test_ssh_timeout_is_recorded(monkeypatch):
    async def hang(*_a, **_k):
        await asyncio.sleep(5)

    monkeypatch.setattr(inventory, "_run_show_command", hang)
    monkeypatch.setattr(inventory, "DISCOVERY_SSH_TIMEOUT_SECONDS", 0.05)
    host = _ssh_probe_hit()
    await inventory._enrich_with_show_version(host, SERVICE)
    assert host["discovery"]["ssh"]["ok"] is False
    assert "timed out" in host["discovery"]["ssh"]["error"]


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["icmp", "https"])
async def test_hosts_without_ssh_surface_are_not_logged_into(monkeypatch, protocol):
    show = _FakeShow(IOS_XE_C9300)
    monkeypatch.setattr(inventory, "_run_show_command", show)
    host = {"hostname": "x", "ip_address": "10.0.0.7", "device_type": "unknown", "discovery": {"protocol": protocol}}
    await inventory._enrich_with_show_version(host, SERVICE)
    assert show.calls == []
    assert "ssh" not in host["discovery"]


@pytest.mark.asyncio
async def test_scan_target_passes_icmp_flag_and_enriches(monkeypatch):
    seen = {}

    async def fake_probe(**kwargs):
        seen.update(kwargs)
        return _ssh_probe_hit(kwargs["ip_address"])

    show = _FakeShow(IOS_XE_C9300)
    monkeypatch.setattr(inventory, "_probe_discovery_target", fake_probe)
    monkeypatch.setattr(inventory, "_run_show_command", show)

    host = await inventory._scan_target("10.0.0.1", _body(use_icmp=False), {}, asyncio.Semaphore(1), SERVICE)
    assert seen["use_icmp"] is False
    assert host is not None and host["device_type"] == "cisco_xe"

    show.calls.clear()
    host = await inventory._scan_target("10.0.0.1", _body(), {}, asyncio.Semaphore(1), None)
    assert show.calls == []
    assert host is not None and host["device_type"] == "cisco_ios"


def test_enrichment_summary_counts_and_failures():
    base = {"enabled": True, "credential": "plexus-svc", "credential_source": "service", "skipped_reason": ""}
    hosts = [
        {"ip_address": "10.0.0.1", "discovery": {"ssh": {"ok": True}}},
        {"ip_address": "10.0.0.2", "discovery": {"ssh": {"ok": False, "error": "RuntimeError: boom"}}},
        {"ip_address": "10.0.0.3", "discovery": {"protocol": "icmp"}},
    ]
    summary = inventory._ssh_enrichment_summary(base, hosts)
    assert summary["credential"] == "plexus-svc"
    assert (summary["attempted"], summary["enriched"], summary["failed"]) == (2, 1, 1)
    assert summary["failures"] == [{"ip_address": "10.0.0.2", "error": "RuntimeError: boom"}]


# ── Planner authority ────────────────────────────────────────────────────────


def _norm(raw: dict) -> dict:
    entry = inventory._normalize_discovered_entry(raw)
    assert entry is not None
    return entry


def test_ssh_show_version_type_replaces_established_cisco_ios():
    """The inventory bug: every Catalyst typed cisco_ios by the banner.
    show version over SSH is authoritative and corrects it to cisco_xe."""
    host = _ssh_probe_hit("10.2.2.1")
    host.update(device_type="cisco_xe", model="C9300-48P", software_version="17.09.04a", serial_number="FOC1")
    host["discovery"]["device_type_source"] = "ssh"
    existing = [{"id": 1, "hostname": "sw1", "ip_address": "10.2.2.1", "serial_number": "", "device_type": "cisco_ios"}]

    plan = inventory._build_discovery_plan([_norm(host)], existing, {"10.2.2.1": 1}, {})

    update = plan["update"][0]
    assert update["device_type"] == "cisco_xe"
    assert (update["model"], update["software_version"], update["serial_number"]) == (
        "C9300-48P",
        "17.09.04a",
        "FOC1",
    )


def test_banner_guess_still_cannot_overwrite_established_type():
    host = _ssh_probe_hit("10.2.2.1")  # no show version facts
    existing = [{"id": 1, "hostname": "sw1", "ip_address": "10.2.2.1", "serial_number": "", "device_type": "cisco_xe"}]
    plan = inventory._build_discovery_plan([_norm(host)], existing, {"10.2.2.1": 1}, {})
    assert plan["update"][0]["device_type"] == "cisco_xe"


def test_ssh_type_wins_over_snmp_type_on_the_same_device():
    snmp = {
        "hostname": "core",
        "ip_address": "10.3.3.1",
        "sys_name": "core",
        "device_type": "cisco_ios",
        "discovery": {"protocol": "snmpv2c"},
    }
    ssh = _ssh_probe_hit("10.3.3.2")
    ssh.update(device_type="cisco_xe", sys_name="core", hostname="core")
    ssh["discovery"]["device_type_source"] = "ssh"

    plan = inventory._build_discovery_plan([_norm(snmp), _norm(ssh)], [], {}, {})
    assert len(plan["add"]) == 1
    assert plan["add"][0]["device_type"] == "cisco_xe"


@pytest.mark.asyncio
async def test_onboard_persists_ssh_facts(monkeypatch):
    """Onboarding scan results writes the SSH-read device type, model,
    version and serial."""
    calls: dict[str, list] = {"add": [], "info": [], "serial": []}

    async def fake_hosts(_gid):
        return []

    async def fake_index(_gid):
        return {}

    async def fake_add(gid, hostname, ip, device_type):
        calls["add"].append((hostname, ip, device_type))
        return 50

    async def fake_info(host_id, model, sw, category):
        calls["info"].append((host_id, model, sw, category))

    async def fake_serial(host_id, serial):
        calls["serial"].append((host_id, serial))

    async def noop(*_a, **_k):
        return None

    monkeypatch.setattr(inventory.db, "get_hosts_for_group", fake_hosts)
    monkeypatch.setattr(inventory.db, "get_host_ip_index", fake_index)
    monkeypatch.setattr(inventory.db, "add_host", fake_add)
    monkeypatch.setattr(inventory.db, "update_host_device_info", fake_info)
    monkeypatch.setattr(inventory.db, "update_host_serial", fake_serial)
    monkeypatch.setattr(inventory.db, "update_host_status", noop)
    monkeypatch.setattr(inventory.db, "set_host_ip_aliases", noop)
    monkeypatch.setattr(inventory.db, "apply_graph_templates_to_host", noop)
    monkeypatch.setattr(inventory, "push_inventory_host_allocation", noop)
    monkeypatch.setattr(inventory, "_notify_flow_collector_host_changed", noop)
    monkeypatch.setattr(inventory.state, "_resolve_snmp_discovery_config", lambda _g: {"enabled": False})

    show = _FakeShow(IOS_XE_C9300)
    monkeypatch.setattr(inventory, "_run_show_command", show)
    host = _ssh_probe_hit("10.4.4.1")
    await inventory._enrich_with_show_version(host, SERVICE)

    result = await inventory._sync_group_hosts(7, [host])

    assert result["added"] == 1
    assert calls["add"] == [("HQ-CORE-SW1", "10.4.4.1", "cisco_xe")]
    assert calls["info"] == [(50, "C9300-48P", "17.09.04a", "switch")]
    assert calls["serial"] == [(50, "FOC2345X0AB")]
