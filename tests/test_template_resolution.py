"""Tests for Phase 12 - per-device_type template resolution.

A job binds a single ``template_id``, but Phase 12 lets one logical
template (keyed by ``name``) carry vendor-specific command bodies
(keyed by ``device_type``).  ``resolve_template_for_device_type``
picks the right body for a host's platform:

  1. exact ``(name, device_type)`` match - the vendor-specific body
  2. else the ``(name, '')`` generic sibling
  3. else the originally-selected row (operator picked a vendor row
     directly and there is no generic sibling)

These tests also lock in the migrated uniqueness contract: two rows
may share a ``name`` as long as their ``device_type`` differs, but a
duplicate ``(name, device_type)`` pair is rejected - so the migration
genuinely replaced the old column-level ``UNIQUE(name)``.
"""

from __future__ import annotations

import pytest
import routes.database as db_module


@pytest.fixture
async def db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "template_resolution.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    return db_module


# ── Schema / uniqueness contract ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_same_name_different_device_type_allowed(db):
    """The old column-level UNIQUE(name) must be gone.

    Two templates can share a name as long as device_type differs -
    that is the whole point of "by template name across vendors".
    """
    base = await db.create_template("SNMPv3 Std", "generic body", "", "")
    pa = await db.create_template(
        "SNMPv3 Std", "set deviceconfig system snmp-setting", "", "paloalto_panos"
    )
    assert base != pa
    rows = await db.get_template_variants("SNMPv3 Std")
    assert {r["device_type"] for r in rows} == {"", "paloalto_panos"}


@pytest.mark.asyncio
async def test_duplicate_name_and_device_type_rejected(db):
    """The composite UNIQUE(name, device_type) must still reject dupes.

    Replacing one constraint with a looser one would silently allow two
    'cisco_ios' bodies for the same name - the resolver would then pick
    an arbitrary one.  The composite key must forbid that.
    """
    await db.create_template("SNMPv3 Std", "body A", "", "cisco_ios")
    with pytest.raises(Exception):  # noqa: B017 - sqlite IntegrityError shape
        await db.create_template("SNMPv3 Std", "body B", "", "cisco_ios")


# ── Resolution order ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_resolve_prefers_exact_vendor_match(db):
    generic = await db.create_template("T", "GENERIC", "", "")
    await db.create_template("T", "PANOS-BODY", "", "paloalto_panos")
    resolved = await db.resolve_template_for_device_type(generic, "paloalto_panos")
    assert resolved is not None
    assert resolved["content"] == "PANOS-BODY"
    assert resolved["device_type"] == "paloalto_panos"


@pytest.mark.asyncio
async def test_resolve_falls_back_to_generic_sibling(db):
    generic = await db.create_template("T", "GENERIC", "", "")
    await db.create_template("T", "PANOS-BODY", "", "paloalto_panos")
    # arista_eos has no variant → generic body.
    resolved = await db.resolve_template_for_device_type(generic, "arista_eos")
    assert resolved is not None
    assert resolved["content"] == "GENERIC"
    assert resolved["device_type"] == ""


@pytest.mark.asyncio
async def test_resolve_uses_selected_row_when_no_generic(db):
    """Operator picked a vendor row directly and there is no generic.

    With only a 'fortinet' row, resolving for 'fortinet' yields it, and
    resolving for an unrelated vendor still yields it (the selected
    row) rather than None - the playbook then decides per-host whether
    that body is acceptable.
    """
    forti = await db.create_template("T", "FORTI-BODY", "", "fortinet")
    same = await db.resolve_template_for_device_type(forti, "fortinet")
    assert same is not None and same["content"] == "FORTI-BODY"
    other = await db.resolve_template_for_device_type(forti, "cisco_ios")
    assert other is not None and other["content"] == "FORTI-BODY"


@pytest.mark.asyncio
async def test_resolve_unknown_template_id_returns_none(db):
    assert await db.resolve_template_for_device_type(9999, "cisco_ios") is None


@pytest.mark.asyncio
async def test_resolve_starting_from_vendor_row_finds_sibling(db):
    """Resolution keys on name, not on the selected row's device_type.

    If the operator selected the PAN-OS variant but the host is
    FortiGate, resolution must still find the 'fortinet' sibling by
    name - it doesn't matter which variant was clicked in the UI.
    """
    await db.create_template("T", "GENERIC", "", "")
    pa = await db.create_template("T", "PANOS-BODY", "", "paloalto_panos")
    await db.create_template("T", "FORTI-BODY", "", "fortinet")
    resolved = await db.resolve_template_for_device_type(pa, "fortinet")
    assert resolved is not None
    assert resolved["content"] == "FORTI-BODY"


@pytest.mark.asyncio
async def test_update_template_can_set_device_type(db):
    tid = await db.create_template("T", "body", "desc", "")
    await db.update_template(tid, "T", "body2", "desc2", "cisco_nxos")
    row = await db.get_template(tid)
    assert row["device_type"] == "cisco_nxos"
    assert row["content"] == "body2"
