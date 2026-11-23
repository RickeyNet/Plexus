"""OPNsense config backups are encrypted at rest
(``netcontrol.routes.opnsense_backup_encryption``): ``config_backups.config_text``
holds the masked ``config.xml``, ``config_text_enc`` the raw file encrypted
and ``config_text_digest`` its keyed digest. Only the raw download decrypts
it. Invented data only."""

from __future__ import annotations

import asyncio
import base64
import io
import os
import re
import zipfile

import pytest
import routes.database as db
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from netcontrol.integrations.opnsense import secrets
from netcontrol.integrations.pathtrace.opnsense_config import parse_document, parse_xml
from netcontrol.mcp import redact
from netcontrol.routes import device_config, opnsense_backup_encryption as encryption, opnsense_masking
from routes.crypto import decrypt

from mcp_helpers import admin_client, user_client
from test_opnsense_drift import SECRETS, _assert_no_secret, _sample

# ═════════════════════════════════════════════════════════════════════════════
# 1. The masked form: idempotent, drift-stable, still the same XML
# ═════════════════════════════════════════════════════════════════════════════

_PROSE = "Allow office VLAN 30 to the 4 build servers in rack 12 and the 2 test labs next door"
_WRAPPED_BLOB = (
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5QUJDREVGR0hJSktMTU5PUFFS\r\n"
    "U1RVVldYWVowMTIzNDU2Nzg5QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIz\r\nNDU2"
)
CASES = {
    "sample": _sample(),
    "sample with CRLF line breaks": _sample().replace("\n", "\r\n"),
    "wrapped blob with CRLF": f"<opnsense>\r\n  <cert><crt>{_WRAPPED_BLOB}</crt></cert>\r\n</opnsense>\r\n",
    "secret over several lines": "<opnsense>\n  <password>  invented-line-1\n  invented-line-2  </password>\n</opnsense>\n",
    "entities": "<opnsense><password>inv&amp;ented&#38;&lt;</password><descr>a &amp; b</descr></opnsense>",
    "carriage return reference": "<opnsense><password>invented&#13;value</password><descr>x&#13;y</descr></opnsense>",
    "attributes": '<opnsense><password b="2" a="1">invented-attr-pass</password></opnsense>',
    "cdata": "<opnsense><secret><![CDATA[invented&cdata<value>]]></secret></opnsense>",
    "url password": "<opnsense><mirror>https://u:invented-p&amp;w@mirror.example.com/x</mirror></opnsense>",
    "crypt hash in text": "<opnsense><descr>hash $6$inventedsalt$inventedhash here</descr></opnsense>",
    "empty secrets": "<opnsense><password></password><password/><key> </key></opnsense>",
    "prose description": f"<opnsense><filter><rule><descr>{_PROSE}</descr></rule></filter></opnsense>",
}


@pytest.mark.parametrize("raw", list(CASES.values()), ids=list(CASES))
def test_masking_is_idempotent_and_drift_stable(raw):
    masked = opnsense_masking.mask_text(raw)
    # Masking the stored (masked) text again changes nothing, so a view that
    # masks on the way out shows the same fingerprints as before.
    assert opnsense_masking.mask_text(masked) == masked
    # Drift of the stored masked text equals drift of the raw file: existing
    # baselines and snapshots show no false drift.
    assert opnsense_masking.drift_form(masked) == opnsense_masking.drift_form(raw)
    assert opnsense_masking.drift_form(opnsense_masking.drift_form(raw)) == opnsense_masking.drift_form(raw)


def test_masked_text_parses_like_the_raw_file():
    raw = _sample()
    masked = opnsense_masking.mask_text(raw)
    _assert_no_secret(masked)
    assert secrets.looks_like_config_xml(masked)
    assert parse_xml(masked) is not None
    assert parse_document(masked) is not None
    assert secrets.config_revision(masked) == secrets.config_revision(raw)


def test_text_of_short_words_is_not_a_blob():
    # A rule description is kept, however long; a wrapped base64 value is not.
    assert secrets.mask_config_xml(CASES["prose description"]) == CASES["prose description"]
    assert _WRAPPED_BLOB.split()[0] not in secrets.mask_config_xml(CASES["wrapped blob with CRLF"])


def test_ai_access_gets_bare_markers_from_the_stored_text():
    masked = opnsense_masking.mask_text(_sample())
    assert re.search(r"\[masked(?: blob)?:[0-9a-f]{8}\]", masked)
    for keep_lines in (False, True):
        out = redact.redact_config_text(masked, keep_lines=keep_lines)
        _assert_no_secret(out)
        assert "[masked]" in out and not re.search(r"\[masked(?: blob)?:", out)


def test_digest_is_keyed_and_exact():
    raw = _sample()
    digest = encryption.backup_digest(raw)
    assert re.fullmatch(r"[0-9a-f]{64}", digest) and encryption.backup_digest(raw) == digest
    changed = _sample(**{"ipsec psk": "invented-ipsec-psk-CHANGED"})
    assert encryption.backup_digest(changed) != digest
    assert encryption.same_digest(digest, digest)
    assert not encryption.same_digest("", digest) and not encryption.same_digest(None, digest)


# ═════════════════════════════════════════════════════════════════════════════
# 2. The store: masked text, encrypted copy, exact change detection
# ═════════════════════════════════════════════════════════════════════════════


async def _hosts() -> tuple[int, int]:
    await db.init_db()
    group = await db.create_group("opn-backup-encryption")
    firewall = await db.add_host(group, "fw-enc-1", "192.0.2.61", "opnsense")
    switch = await db.add_host(group, "sw-enc-1", "192.0.2.62", "cisco_ios")
    return int(firewall), int(switch)


async def _rows(host_id: int) -> list[dict]:
    conn = await db.get_db(read_only=True)
    try:
        cursor = await conn.execute("SELECT * FROM config_backups WHERE host_id = ? ORDER BY id", (host_id,))
        return db.rows_to_list(await cursor.fetchall())
    finally:
        await conn.close()


async def _store(host_id: int, raw: str, method: str = "opnsense-api") -> device_config.DeviceConfig:
    return await device_config.store_device_config(host_id, raw, "", capture_method=method, device_type="opnsense")


@pytest.mark.asyncio
async def test_stored_row_holds_no_secret_in_any_plain_column():
    firewall, _switch = await _hosts()
    raw = _sample()
    stored = await _store(firewall, raw)
    assert stored.created
    [row] = await _rows(firewall)
    # Every column, the encrypted copy and the digest included.
    _assert_no_secret(*(str(v) for v in row.values()))
    assert row["config_text"] == stored.config_text == opnsense_masking.mask_text(raw)
    assert decrypt(row["config_text_enc"]) == raw
    assert row["config_text_digest"] == encryption.backup_digest(raw)
    # Readers of a backup never get the encrypted copy or the digest.
    detail = await db.get_config_backup(stored.backup_id)
    assert detail is not None and "config_text_enc" not in detail and "config_text_digest" not in detail


@pytest.mark.asyncio
async def test_unchanged_file_is_no_new_row_and_a_changed_secret_is():
    firewall, _switch = await _hosts()
    raw = _sample()
    first = await _store(firewall, raw)
    again = await _store(firewall, raw, method="scheduled")
    assert not again.created and again.backup_id == first.backup_id
    assert again.config_text == first.config_text
    # Only a secret changed (same <revision>): a new backup.
    changed = await _store(firewall, _sample(**{"radius secret": "invented-radius-CHANGED"}))
    assert changed.created and changed.backup_id != first.backup_id
    rows = await _rows(firewall)
    assert len(rows) == 2
    _assert_no_secret(*(str(v) for r in rows for v in r.values()))
    assert "invented-radius-CHANGED" not in str(rows)


@pytest.mark.asyncio
async def test_a_plain_text_row_without_a_digest_never_counts_as_unchanged():
    firewall, _switch = await _hosts()
    raw = _sample()
    legacy = await db.create_config_backup(None, firewall, raw, capture_method="opnsense-api")
    stored = await _store(firewall, raw)
    assert stored.created and stored.backup_id != legacy


@pytest.mark.asyncio
async def test_other_devices_backups_are_stored_as_captured():
    _firewall, switch = await _hosts()
    text = "hostname sw-enc-1\nsnmp-server community invented-community RO\n"
    stored = await device_config.store_device_config(switch, text, "", capture_method="manual", device_type="cisco_ios")
    [row] = await _rows(switch)
    assert row["config_text"] == stored.config_text == text
    assert row["config_text_enc"] == "" and row["config_text_digest"] == ""
    again = await device_config.store_device_config(switch, text, "", capture_method="manual", device_type="cisco_ios")
    assert not again.created


# ═════════════════════════════════════════════════════════════════════════════
# 3. Backups stored in plain text by an older release
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_legacy_rows_are_converted_once_and_nothing_is_lost():
    firewall, switch = await _hosts()
    other = await db.add_host(await db.create_group("opn-enc-other"), "edge-enc-1", "192.0.2.63", "")
    raws = {
        # By capture method, by the host's device type, by content.
        await db.create_config_backup(None, firewall, _sample(), capture_method="opnsense-api"): _sample(),
        await db.create_config_backup(
            None, firewall, _sample(revision_time="1700000100.0"), capture_method="manual"
        ): _sample(revision_time="1700000100.0"),
        await db.create_config_backup(
            None, int(other), _sample(revision_time="1700000200.0"), capture_method="scheduled"
        ): _sample(revision_time="1700000200.0"),
    }
    cisco = "hostname sw-enc-1\nusername netops secret 0 invented-pass\n"
    cisco_id = await db.create_config_backup(None, switch, cisco, capture_method="scheduled")
    failed = await db.create_config_backup(None, firewall, "", capture_method="opnsense-api", status="error")

    # Two processes at once, two rows per query: every row converted once.
    results = await asyncio.gather(
        encryption.encrypt_legacy_backups(batch_size=2), encryption.encrypt_legacy_backups(batch_size=2)
    )
    assert sum(r["sealed"] for r in results) == 3
    assert await encryption.encrypt_legacy_backups(batch_size=2) == {"sealed": 0, "skipped": 0}

    rows = {r["id"]: r for h in (firewall, switch, int(other)) for r in await _rows(h)}
    assert set(rows) == {*raws, cisco_id, failed}
    for backup_id, raw in raws.items():
        row = rows[backup_id]
        _assert_no_secret(*(str(v) for v in row.values()))
        assert row["config_text"] == opnsense_masking.mask_text(raw)
        assert decrypt(row["config_text_enc"]) == raw
        assert row["config_text_digest"] == encryption.backup_digest(raw)
    assert rows[cisco_id]["config_text"] == cisco and rows[cisco_id]["config_text_enc"] == ""
    assert rows[failed]["config_text_enc"] == "" and rows[failed]["status"] == "error"


# ═════════════════════════════════════════════════════════════════════════════
# 4. The API: raw download decrypts, everything else reads the masked text
# ═════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def clients(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    group = admin.post("/api/inventory", json={"name": "firewalls"})
    assert group.status_code == 201, group.text
    host = admin.post(
        f"/api/inventory/{group.json()['id']}/hosts",
        json={"hostname": "fw-enc-api", "ip_address": "192.0.2.64", "device_type": "opnsense"},
    )
    assert host.status_code == 201, host.text
    reader = user_client(admin, "fw-backup-reader", features=["config-backups"])
    writer = user_client(admin, "fw-backup-writer", features=["config-backups", "config-backups.write"])
    return admin, reader, writer, int(host.json()["id"])


def _zip_files(content: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


@pytest.mark.asyncio
async def test_raw_download_returns_the_exact_file_and_views_stay_masked(clients):
    admin, reader, writer, host_id = clients
    first_raw = _sample()
    # Bytes exactly as collected: CRLF line breaks and a non-ASCII name.
    raw = _sample(revision_time="1700000300.0").replace("fw-lab-01", "fw-läb-01").replace("\n", "\r\n")
    await _store(host_id, first_raw)
    second = (await _store(host_id, raw)).backup_id

    for client in (writer, admin):
        single = client.get(f"/api/config-backups/{second}/download")
        assert single.status_code == 200, single.text
        assert single.content == raw.encode("utf-8")
        files = _zip_files(client.get("/api/config-backups/download").content)
        assert sorted(files.values()) == sorted([first_raw.encode("utf-8"), raw.encode("utf-8")])

    for client in (reader, writer, admin):
        detail = client.get(f"/api/config-backups/{second}")
        assert detail.status_code == 200 and detail.json()["secrets_masked"] is True
        assert "config_text_enc" not in detail.json() and "config_text_digest" not in detail.json()
        assert detail.json()["revision"]["time"] == "1700000300.0"
        _assert_no_secret(detail.text)
        diff = client.get(f"/api/config-backups/{second}/diff")
        assert diff.status_code == 200 and diff.json()["secrets_masked"] is True
        _assert_no_secret(diff.text)
        hits = client.get("/api/config-backups/search", params={"q": SECRETS["ipsec psk"], "mode": "substring"})
        assert hits.json()["results"] == []
        found = client.get("/api/config-backups/search", params={"q": "rocommunity", "mode": "substring"})
        assert found.json()["results"]
        _assert_no_secret(found.text)
        listed = client.get("/api/config-backups", params={"host_id": host_id}).json()
        assert {b["id"] for b in listed} >= {second}

    for url in (f"/api/config-backups/{second}/download", "/api/config-backups/download"):
        denied = reader.get(url)
        assert denied.status_code == 403
        _assert_no_secret(denied.text)


def _foreign_ciphertext(plaintext: str) -> str:
    """A ciphertext in this install's format under some other key."""
    nonce = os.urandom(12)
    sealed = AESGCM(AESGCM.generate_key(bit_length=256)).encrypt(nonce, plaintext.encode(), None)
    return base64.urlsafe_b64encode(b"\x02" + nonce + sealed).decode()


@pytest.mark.asyncio
async def test_a_copy_encrypted_under_another_key_is_refused_clearly(clients):
    admin, _reader, writer, host_id = clients
    backup_id = (await _store(host_id, _sample())).backup_id
    conn = await db.get_db()
    try:
        await conn.execute(
            "UPDATE config_backups SET config_text_enc = ? WHERE id = ?", (_foreign_ciphertext(_sample()), backup_id)
        )
        await conn.commit()
    finally:
        await conn.close()

    for client in (writer, admin):
        single = client.get(f"/api/config-backups/{backup_id}/download")
        assert single.status_code == 409
        message = single.json()["error"]["message"]
        assert "encryption key" in message and "masked" in message
        _assert_no_secret(single.text)
        files = _zip_files(client.get("/api/config-backups/download").content)
        assert list(files) == ["NOT-INCLUDED.txt"]
        assert str(backup_id) in files["NOT-INCLUDED.txt"].decode()
        _assert_no_secret(*(v.decode() for v in files.values()))
        # The masked text is still there.
        detail = client.get(f"/api/config-backups/{backup_id}")
        assert detail.status_code == 200 and "<opnsense>" in detail.json()["config_text"]
