"""Config backup search and diff helper tests."""

from __future__ import annotations

import pytest
import routes.database as db_module


@pytest.fixture
async def backup_search_db():
    """Initialize the test DB with config backup sample data."""
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
        config_text=("hostname sw-core-01\nsnmp-server community public RO\nline vty 0 4\n transport input ssh\n"),
    )
    second_id = await db_module.create_config_backup(
        policy_id=None,
        host_id=200,
        config_text=("hostname r-edge-01\nip access-list standard MGMT\n permit 10.0.0.0 0.0.0.255\n deny any\n"),
    )
    third_id = await db_module.create_config_backup(
        policy_id=None,
        host_id=100,
        config_text=("hostname sw-core-01\nsnmp-server community public RO\nsnmp-server community secure RW\n"),
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
async def test_search_config_backups_regex_without_literal_rejected(backup_search_db):
    """Regex patterns with no required literal must be rejected (no full scan)."""
    for pattern in (r"\d+\.\d+", r".*", r"foo|bar", r"ab"):
        with pytest.raises(ValueError) as exc:
            await db_module.search_config_backups(pattern, mode="regex", limit=10)
        assert (exc.value.args[0] if exc.value.args else "") == "regex_needs_literal"


def test_regex_required_literal_extraction():
    """The pre-filter literal must be a substring every match contains."""
    from routes.db.topology import _regex_required_literal as lit

    assert lit(r"snmp-server community\s+public") == "snmp-server community"
    assert lit(r"interface Gig.*shutdown") == "interface Gig"
    assert lit(r"ab+c") == "ab"  # 'c' run is shorter; 'b' required once
    assert lit(r"ab?cdef") == "cdef"  # optional 'b' breaks the run
    assert lit(r"a{0,3}bcd") == "bcd"  # min-0 repeat drops its atom
    assert lit(r"a{2}bc") == "bc"  # 'a' kept but shorter than 'bc'
    assert lit(r"foo|bar") == ""  # top-level alternation: nothing required
    assert lit(r"(foo|bar)baz") == "baz"  # group contents skipped conservatively
    assert lit(r"\d+\.\d+\.\d+") == "."  # only escaped dots are literal
    assert lit(r"escaped\.dot") == "escaped.dot"
    assert lit(r"^hostname sw-") == "hostname sw-"
    assert lit(r"[Pp]ermit any") == "ermit any"


def test_config_backup_regex_is_linear_time():
    """Patterns run through RE2: a polynomial-backtracking shape that the
    shape screen does not catch finishes immediately, matching is
    case-insensitive, and RE2-unsupported syntax is rejected as invalid."""
    import time

    from routes.db.topology import _compile_config_backup_regex as compile_regex

    evil = compile_regex("a*a*a*a*a*a*b")
    start = time.monotonic()
    assert evil.search("a" * 5000) is None
    assert time.monotonic() - start < 1.0

    assert compile_regex(r"snmp-server .*PUBLIC").search("snmp-server community public RO")
    for unsupported in (r"(?=x)abc", r"(abc)\1"):
        with pytest.raises(ValueError, match="invalid_regex"):
            compile_regex(unsupported)


@pytest.mark.asyncio
async def test_get_previous_successful_config_backup(backup_search_db):
    """Previous-backup helper should return the prior successful backup for host."""
    previous = await db_module.get_previous_successful_config_backup(backup_search_db["third_id"])
    assert previous is not None
    assert previous["id"] == backup_search_db["first_id"]
    assert previous["hostname"] == "sw-core-01"


@pytest.mark.asyncio
async def test_search_reads_the_config_with_defaults(backup_search_db):
    """A setting left at its default is only in the config with defaults
    included, and search finds it there; a row without one is searched by
    its plain config."""
    full_id = await db_module.create_config_backup(
        policy_id=None,
        host_id=200,
        config_text="hostname r-edge-01\n",
        config_text_full="hostname r-edge-01\nip ssh window-size 8192\n",
    )
    result = await db_module.search_config_backups("ip ssh window-size", mode="substring", limit=10)
    assert [row["backup_id"] for row in result["results"]] == [full_id]
    assert result["results"][0]["match_line"] == "ip ssh window-size 8192"

    fulltext = await db_module.search_config_backups("window-size", mode="fulltext", limit=10)
    assert [row["backup_id"] for row in fulltext["results"]] == [full_id]

    plain = await db_module.search_config_backups("transport input ssh", mode="substring", limit=10)
    assert [row["backup_id"] for row in plain["results"]] == [backup_search_db["first_id"]]


@pytest.mark.asyncio
async def test_newest_host_backup_honours_the_age_limit(backup_search_db):
    """The newest successful backup of a host, optionally only when the
    device confirmed it within the age limit (``checked_at``)."""
    newest = await db_module.get_newest_host_config_backup(100)
    assert newest["id"] == backup_search_db["third_id"]
    assert await db_module.get_newest_host_config_backup(100, max_age_seconds=900) is not None

    db = await db_module.get_db()
    try:
        await db.execute(
            "UPDATE config_backups SET checked_at = datetime('now', '-1 hours') WHERE id = ?",
            (backup_search_db["third_id"],),
        )
        await db.commit()
    finally:
        await db.close()
    assert await db_module.get_newest_host_config_backup(100, max_age_seconds=900) is None

    await db_module.mark_config_backup_checked(backup_search_db["third_id"])
    fresh = await db_module.get_newest_host_config_backup(100, max_age_seconds=900)
    assert fresh["id"] == backup_search_db["third_id"]


@pytest.mark.asyncio
async def test_retention_keeps_each_hosts_newest_backup(backup_search_db):
    """Retention never deletes the configuration a host still has, however old."""
    db = await db_module.get_db()
    try:
        await db.execute("UPDATE config_backups SET captured_at = datetime('now', '-90 days')")
        await db.commit()
    finally:
        await db.close()
    deleted = await db_module.delete_old_config_backups(30)
    assert deleted == 1  # first_id: host 100 has a newer one
    assert (await db_module.get_newest_host_config_backup(100))["id"] == backup_search_db["third_id"]
    assert (await db_module.get_newest_host_config_backup(200))["id"] == backup_search_db["second_id"]
    assert await db_module.get_config_backup(backup_search_db["first_id"]) is None
