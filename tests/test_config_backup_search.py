"""Config backup search and diff helper tests."""

from __future__ import annotations

import pytest
import routes.database as db_module


@pytest.fixture
async def backup_search_db(tmp_path, monkeypatch):
    """Initialize a temporary SQLite DB with config backup sample data."""
    db_path = str(tmp_path / "backup_search_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setattr(db_module, "DB_ENGINE", "sqlite")
    await db_module.init_db()

    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (1, 'core')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, status) "
            "VALUES (100, 1, 'sw-core-01', '10.0.1.1', 'cisco_ios', 'online')"
        )
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, status) "
            "VALUES (200, 1, 'r-edge-01', '10.0.2.1', 'cisco_ios', 'online')"
        )
        await db.commit()
    finally:
        await db.close()

    first_id = await db_module.create_config_backup(
        policy_id=None,
        host_id=100,
        config_text=(
            "hostname sw-core-01\n"
            "snmp-server community public RO\n"
            "line vty 0 4\n"
            " transport input ssh\n"
        ),
    )
    second_id = await db_module.create_config_backup(
        policy_id=None,
        host_id=200,
        config_text=(
            "hostname r-edge-01\n"
            "ip access-list standard MGMT\n"
            " permit 10.0.0.0 0.0.0.255\n"
            " deny any\n"
        ),
    )
    third_id = await db_module.create_config_backup(
        policy_id=None,
        host_id=100,
        config_text=(
            "hostname sw-core-01\n"
            "snmp-server community public RO\n"
            "snmp-server community secure RW\n"
        ),
    )
    return {"first_id": first_id, "second_id": second_id, "third_id": third_id}


@pytest.mark.asyncio
async def test_search_config_backups_fulltext_returns_context(backup_search_db):
    """Full-text mode should find backups and include contextual match metadata."""
    result = await db_module.search_config_backups("snmp community public", mode="fulltext", limit=10)
    assert result["count"] >= 1
    assert result["mode"] in {"fulltext", "substring"}  # sqlite fallback-safe
    top = result["results"][0]
    assert top["hostname"] == "sw-core-01"
    assert top["match_line_number"] > 0
    assert "public" in top["match_context"].lower()
    assert isinstance(top["context_before_lines"], list)
    assert isinstance(top["context_after_lines"], list)


@pytest.mark.asyncio
async def test_search_config_backups_substring_has_more(backup_search_db):
    """Substring mode should support result limiting and has_more flag."""
    result = await db_module.search_config_backups("snmp-server community", mode="substring", limit=1)
    assert result["count"] == 1
    assert result["has_more"] is True
    assert result["results"][0]["backup_id"] in {backup_search_db["first_id"], backup_search_db["third_id"]}


@pytest.mark.asyncio
async def test_search_config_backups_regex(backup_search_db):
    """Regex mode should match case-insensitively and return line context."""
    result = await db_module.search_config_backups(r"snmp-server community\s+public", mode="regex", limit=10)
    assert result["count"] >= 1
    assert any("public" in row["match_line"].lower() for row in result["results"])


@pytest.mark.asyncio
async def test_search_config_backups_invalid_regex_raises(backup_search_db):
    """Invalid regex should raise ValueError with invalid_regex marker."""
    with pytest.raises(ValueError) as exc:
        await db_module.search_config_backups(r"(unclosed", mode="regex", limit=10)
    assert (exc.value.args[0] if exc.value.args else "") == "invalid_regex"


@pytest.mark.asyncio
async def test_get_previous_successful_config_backup(backup_search_db):
    """Previous-backup helper should return the prior successful backup for host."""
    previous = await db_module.get_previous_successful_config_backup(backup_search_db["third_id"])
    assert previous is not None
    assert previous["id"] == backup_search_db["first_id"]
    assert previous["hostname"] == "sw-core-01"
