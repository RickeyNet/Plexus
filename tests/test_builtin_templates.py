"""Tests for the config templates that ship with Plexus.

``routes.builtin_templates.BUILTIN_TEMPLATES`` holds the SNMPv3 template
for Cisco and Aruba platforms; ``seed_builtin_templates`` inserts them
once per install at startup.  The contract under test:

  * every built-in lands as a ``(name, device_type)`` row, once;
  * a user's edit, rename or delete of a seeded row survives a re-seed;
  * a built-in added later (not yet recorded) is still seeded;
  * the shipped bodies reference secrets rather than literal strings,
    and the vendor variants resolve per host device_type.
"""

from __future__ import annotations

import pytest
import routes.database as db_module
from routes.builtin_templates import (
    BUILTIN_TEMPLATES,
    SECRET_SNMPV3_AUTH_KEY,
    SECRET_SNMPV3_PRIV_KEY,
    SNMPV3_TEMPLATE_NAME,
    builtin_template_key,
)
from routes.db.playbooks import BUILTIN_TEMPLATES_SETTING
from routes.secret_resolver import extract_secret_names, has_secret_references

KNOWN_DEVICE_TYPES = {"cisco_ios", "cisco_xe", "cisco_nxos", "aruba_aoscx", "aruba_osswitch"}


@pytest.fixture
async def db():
    await db_module.init_db()
    return db_module


def _rows_by_key(rows: list[dict]) -> dict[str, dict]:
    return {builtin_template_key(r["name"], r["device_type"]): r for r in rows}


# ── Static shape of the shipped list ───────────────────────────────────────


def test_builtin_list_has_unique_name_device_type_pairs():
    keys = [builtin_template_key(t["name"], t["device_type"]) for t in BUILTIN_TEMPLATES]
    assert len(keys) == len(set(keys))


def test_builtin_list_is_snmpv3_only_and_covers_cisco_and_aruba():
    by_name: dict[str, set[str]] = {}
    for t in BUILTIN_TEMPLATES:
        by_name.setdefault(t["name"], set()).add(t["device_type"])
    assert set(by_name) == {SNMPV3_TEMPLATE_NAME}
    assert by_name[SNMPV3_TEMPLATE_NAME] == KNOWN_DEVICE_TYPES


def test_builtin_bodies_are_vendor_specific_and_use_secrets():
    for t in BUILTIN_TEMPLATES:
        assert t["device_type"], f"{t['name']} must not ship a generic body"
        assert t["content"].strip(), f"{t['name']} [{t['device_type']}] has no content"
        assert t["description"].strip()
        assert has_secret_references(t["content"]), f"{t['name']} [{t['device_type']}] has no secret reference"
        names = extract_secret_names(t["content"].split("\n"))
        assert names == {SECRET_SNMPV3_AUTH_KEY, SECRET_SNMPV3_PRIV_KEY}
        # No community strings: SNMPv3 only.
        assert "community" not in t["content"]
        # The description tells the operator which secrets to define.
        for name in names:
            assert name in t["description"]


def test_builtin_bodies_render_secret_placeholders_literally():
    """The f-string brace escaping must produce ``{{secret.NAME}}`` verbatim."""
    ios_v3 = next(t for t in BUILTIN_TEMPLATES if t["device_type"] == "cisco_ios" and t["name"] == SNMPV3_TEMPLATE_NAME)
    assert f"auth sha {{{{secret.{SECRET_SNMPV3_AUTH_KEY}}}}} priv aes 128 {{{{secret.{SECRET_SNMPV3_PRIV_KEY}}}}}" in ios_v3["content"]
    assert "{{secret.snmp_v3_auth_key}}" in ios_v3["content"]
    assert "{{{" not in ios_v3["content"] and "}}}" not in ios_v3["content"]


# ── Seeding behaviour ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_seed_creates_every_builtin_once(db):
    created = await db.seed_builtin_templates()
    assert created == len(BUILTIN_TEMPLATES)

    rows = _rows_by_key(await db.get_all_templates())
    for t in BUILTIN_TEMPLATES:
        row = rows[builtin_template_key(t["name"], t["device_type"])]
        assert row["content"] == t["content"]
        assert row["description"] == t["description"]

    recorded = await db.get_auth_setting(BUILTIN_TEMPLATES_SETTING)
    assert set(recorded["keys"]) == set(rows)

    # Second start: nothing new, no duplicates.
    assert await db.seed_builtin_templates() == 0
    assert len(await db.get_all_templates()) == len(BUILTIN_TEMPLATES)


@pytest.mark.asyncio
async def test_seed_respects_user_edit_rename_and_delete(db):
    await db.seed_builtin_templates()
    rows = _rows_by_key(await db.get_all_templates())
    edited = rows[builtin_template_key(SNMPV3_TEMPLATE_NAME, "cisco_ios")]
    renamed = rows[builtin_template_key(SNMPV3_TEMPLATE_NAME, "aruba_aoscx")]
    deleted = rows[builtin_template_key(SNMPV3_TEMPLATE_NAME, "cisco_nxos")]

    await db.update_template(edited["id"], edited["name"], "snmp-server community mine RO", "mine", "cisco_ios")
    await db.update_template(renamed["id"], "Corp SNMPv3", renamed["content"], renamed["description"], "aruba_aoscx")
    await db.delete_template(deleted["id"])

    assert await db.seed_builtin_templates() == 0

    after = await db.get_all_templates()
    assert len(after) == len(BUILTIN_TEMPLATES) - 1
    by_id = {r["id"]: r for r in after}
    assert by_id[edited["id"]]["content"] == "snmp-server community mine RO"
    assert by_id[renamed["id"]]["name"] == "Corp SNMPv3"
    assert deleted["id"] not in by_id
    # The renamed built-in's original slot is not re-filled either.
    assert builtin_template_key(SNMPV3_TEMPLATE_NAME, "aruba_aoscx") not in _rows_by_key(after)


@pytest.mark.asyncio
async def test_seed_adds_builtins_that_were_not_recorded_yet(db):
    """A later release's new built-in is seeded on an install that already ran."""
    await db.seed_builtin_templates()
    recorded = await db.get_auth_setting(BUILTIN_TEMPLATES_SETTING)
    dropped = builtin_template_key(SNMPV3_TEMPLATE_NAME, "aruba_osswitch")
    await db.set_auth_setting(BUILTIN_TEMPLATES_SETTING, {"keys": [k for k in recorded["keys"] if k != dropped]})
    row = _rows_by_key(await db.get_all_templates())[dropped]
    await db.delete_template(row["id"])

    assert await db.seed_builtin_templates() == 1
    assert dropped in _rows_by_key(await db.get_all_templates())
    assert dropped in (await db.get_auth_setting(BUILTIN_TEMPLATES_SETTING))["keys"]


@pytest.mark.asyncio
async def test_seed_keeps_a_user_row_that_already_uses_a_builtin_slot(db):
    """An install that made its own (name, device_type) row keeps it."""
    tid = await db.create_template(SNMPV3_TEMPLATE_NAME, "my own body", "mine", "cisco_ios")

    created = await db.seed_builtin_templates()
    assert created == len(BUILTIN_TEMPLATES) - 1

    row = await db.get_template(tid)
    assert row["content"] == "my own body"
    recorded = await db.get_auth_setting(BUILTIN_TEMPLATES_SETTING)
    assert builtin_template_key(SNMPV3_TEMPLATE_NAME, "cisco_ios") in recorded["keys"]


# ── Job-time resolution across the shipped variants ────────────────────────


@pytest.mark.asyncio
async def test_selected_cisco_variant_resolves_aruba_body_for_aruba_host(db):
    await db.seed_builtin_templates()
    rows = _rows_by_key(await db.get_all_templates())
    selected = rows[builtin_template_key(SNMPV3_TEMPLATE_NAME, "cisco_ios")]

    for device_type in KNOWN_DEVICE_TYPES:
        resolved = await db.resolve_template_for_device_type(selected["id"], device_type)
        assert resolved is not None
        assert resolved["device_type"] == device_type
        assert resolved["content"] == rows[builtin_template_key(SNMPV3_TEMPLATE_NAME, device_type)]["content"]

    aruba = await db.resolve_template_for_device_type(selected["id"], "aruba_aoscx")
    assert "snmpv3 user plexus" in aruba["content"]
    assert "snmp-server group" not in aruba["content"]
