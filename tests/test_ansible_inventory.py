"""Tests for the Ansible dynamic inventory provider."""

from __future__ import annotations

import json
import subprocess
import sys

import netcontrol.app as app_module
import netcontrol.routes.state as state_module
import pytest
import routes.database as db_module
from fastapi.testclient import TestClient

from netcontrol.routes.ansible_inventory import (
    _ansible_connection,
    _map_network_os,
    _sanitize_group_name,
)


# ── Unit tests for helper functions ──────────────────────────────────────────


class TestSanitizeGroupName:
    def test_simple_name(self):
        assert _sanitize_group_name("core_switches") == "core_switches"

    def test_spaces_replaced(self):
        assert _sanitize_group_name("my group") == "my_group"

    def test_special_chars_replaced(self):
        assert _sanitize_group_name("DC-1 (prod)") == "DC_1__prod_"

    def test_dots_replaced(self):
        assert _sanitize_group_name("site.east") == "site_east"

    def test_empty_string(self):
        assert _sanitize_group_name("") == ""


class TestMapNetworkOs:
    def test_cisco_ios(self):
        assert _map_network_os("cisco_ios") == "cisco.ios.ios"

    def test_arista_eos(self):
        assert _map_network_os("arista_eos") == "arista.eos.eos"

    def test_unknown_passes_through(self):
        assert _map_network_os("custom_vendor") == "custom_vendor"


class TestAnsibleConnection:
    def test_linux_uses_ssh(self):
        assert _ansible_connection("linux") == "ssh"
        assert _ansible_connection("linux_ssh") == "ssh"

    def test_network_device_uses_network_cli(self):
        assert _ansible_connection("cisco_ios") == "ansible.netcommon.network_cli"


# ── Integration tests via TestClient ─────────────────────────────────────────


@pytest.fixture
def ansible_client(monkeypatch, tmp_path):
    """Create a test client with API token auth and seeded inventory data."""
    db_path = tmp_path / "ansible-inv-test.db"
    monkeypatch.setattr(db_module, "DB_PATH", str(db_path))
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "test-ansible-token")
    # Disable rate limiting for test fixture setup
    monkeypatch.setitem(state_module.API_RATE_LIMIT, "enabled", False)

    with TestClient(app_module.app) as client:
        # Seed inventory data — use unique names to avoid collision with seed data
        headers = {"X-Api-Token": "test-ansible-token"}

        # Delete any seeded groups first to start from a clean state
        resp = client.get("/api/inventory", headers=headers)
        for grp in resp.json():
            client.delete(f"/api/inventory/{grp['id']}", headers=headers)

        # Create groups
        resp = client.post("/api/inventory", json={"name": "TestCore", "description": "Core network"}, headers=headers)
        assert resp.status_code == 201
        core_id = resp.json()["id"]

        resp = client.post("/api/inventory", json={"name": "TestAccess", "description": "Access switches"}, headers=headers)
        assert resp.status_code == 201
        access_id = resp.json()["id"]

        # Add hosts to core group
        client.post(f"/api/inventory/{core_id}/hosts", json={
            "hostname": "core-sw01", "ip_address": "10.0.0.1", "device_type": "cisco_ios",
        }, headers=headers)
        client.post(f"/api/inventory/{core_id}/hosts", json={
            "hostname": "core-sw02", "ip_address": "10.0.0.2", "device_type": "arista_eos",
        }, headers=headers)

        # Add hosts to access group
        client.post(f"/api/inventory/{access_id}/hosts", json={
            "hostname": "access-sw01", "ip_address": "10.1.0.1", "device_type": "cisco_ios",
        }, headers=headers)
        client.post(f"/api/inventory/{access_id}/hosts", json={
            "hostname": "linux-server01", "ip_address": "10.2.0.1", "device_type": "linux",
        }, headers=headers)

        yield client, headers


class TestAnsibleInventoryListEndpoint:
    def test_returns_all_groups_and_hosts(self, ansible_client):
        client, headers = ansible_client
        resp = client.get("/api/ansible/inventory", headers=headers)
        assert resp.status_code == 200
        data = resp.json()

        # Check _meta.hostvars exists
        assert "_meta" in data
        assert "hostvars" in data["_meta"]
        hostvars = data["_meta"]["hostvars"]

        # All 4 hosts should be present
        assert len(hostvars) == 4
        assert "core-sw01" in hostvars
        assert "core-sw02" in hostvars
        assert "access-sw01" in hostvars
        assert "linux-server01" in hostvars

        # Check host variables
        core_sw01 = hostvars["core-sw01"]
        assert core_sw01["ansible_host"] == "10.0.0.1"
        assert core_sw01["ansible_network_os"] == "cisco.ios.ios"
        assert core_sw01["ansible_connection"] == "ansible.netcommon.network_cli"
        assert core_sw01["plexus_device_type"] == "cisco_ios"
        assert core_sw01["plexus_group"] == "TestCore"

        # Linux host should use ssh connection
        linux_host = hostvars["linux-server01"]
        assert linux_host["ansible_connection"] == "ssh"
        assert linux_host["ansible_network_os"] == "linux"

        # Check "all" group contains all hosts
        assert "all" in data
        assert len(data["all"]["hosts"]) == 4

    def test_groups_are_sanitized(self, ansible_client):
        client, headers = ansible_client
        resp = client.get("/api/ansible/inventory", headers=headers)
        data = resp.json()

        # "TestCore" should become "TestCore" (already valid)
        assert "TestCore" in data
        assert "TestAccess" in data

    def test_filter_by_group(self, ansible_client):
        client, headers = ansible_client
        resp = client.get("/api/ansible/inventory?group=TestCore", headers=headers)
        data = resp.json()

        hostvars = data["_meta"]["hostvars"]
        assert len(hostvars) == 2
        assert "core-sw01" in hostvars
        assert "core-sw02" in hostvars
        assert "access-sw01" not in hostvars

    def test_filter_by_device_type(self, ansible_client):
        client, headers = ansible_client
        resp = client.get("/api/ansible/inventory?device_type=cisco_ios", headers=headers)
        data = resp.json()

        hostvars = data["_meta"]["hostvars"]
        assert len(hostvars) == 2
        assert "core-sw01" in hostvars
        assert "access-sw01" in hostvars
        # arista and linux hosts excluded
        assert "core-sw02" not in hostvars
        assert "linux-server01" not in hostvars

    def test_filter_nonexistent_group_returns_empty(self, ansible_client):
        client, headers = ansible_client
        resp = client.get("/api/ansible/inventory?group=nonexistent", headers=headers)
        data = resp.json()

        hostvars = data["_meta"]["hostvars"]
        assert len(hostvars) == 0
        assert data["all"]["hosts"] == []

    def test_requires_auth(self, ansible_client):
        client, _ = ansible_client
        resp = client.get("/api/ansible/inventory")
        assert resp.status_code == 401


class TestAnsibleInventoryHostEndpoint:
    def test_returns_host_vars(self, ansible_client):
        client, headers = ansible_client
        resp = client.get("/api/ansible/inventory/host/core-sw01", headers=headers)
        assert resp.status_code == 200
        data = resp.json()

        assert data["ansible_host"] == "10.0.0.1"
        assert data["ansible_network_os"] == "cisco.ios.ios"
        assert data["plexus_device_type"] == "cisco_ios"

    def test_host_not_found_returns_404(self, ansible_client):
        client, headers = ansible_client
        resp = client.get("/api/ansible/inventory/host/nonexistent", headers=headers)
        assert resp.status_code == 404


# ── CLI script tests ─────────────────────────────────────────────────────────


class TestCLIScript:
    def test_missing_token_exits_with_error(self, tmp_path, monkeypatch):
        """CLI should fail when PLEXUS_API_TOKEN is not set."""
        env = {k: v for k, v in __import__("os").environ.items()}
        env.pop("PLEXUS_API_TOKEN", None)
        result = subprocess.run(
            [sys.executable, "scripts/plexus_ansible_inventory.py", "--list"],
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode != 0
        assert "PLEXUS_API_TOKEN" in result.stderr

    def test_help_flag(self):
        result = subprocess.run(
            [sys.executable, "scripts/plexus_ansible_inventory.py", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Ansible dynamic inventory" in result.stdout
