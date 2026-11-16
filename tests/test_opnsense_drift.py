"""OPNsense config drift with masked secrets.

Covers ``netcontrol.integrations.opnsense.secrets`` (masking,
normalization, revision), its use by config drift (snapshots from the
stored config.xml backup, baselines, analysis, events, scheduled check,
revert refused), by the config backup view, diff, search and restore, and
by AI access (``netcontrol.mcp.redact``).

The sample config.xml is invented: documentation addresses and made-up
names and values only.
"""

from __future__ import annotations

import json
import re
from unittest.mock import AsyncMock

import netcontrol.routes.config_backups as backups_routes
import netcontrol.routes.config_drift as drift_routes
import netcontrol.routes.state as state
import pytest
import routes.database as db_module
from fastapi import HTTPException
from netcontrol.integrations.opnsense import secrets
from netcontrol.mcp import redact
from netcontrol.routes import opnsense_masking
from netcontrol.routes.shared import _compute_config_diff

# Every secret value of the sample, by kind. None may appear in any output.
SECRETS: dict[str, str] = {
    "user bcrypt hash": "$2y$11$InventedBcryptHashValueForTestsOnly0123456789abcdefghi",
    "user otp seed": "INVENTEDOTPSEEDJBSWY3DPEHPK3PXP",
    "api key": "InventedApiKeyId7f3c2a91b8d4e6f0a1b2c3d4e5f60718293a4b5c6d7e8f90",
    "api secret": "InventedApiSecretQ9w8e7r6t5y4u3i2o1p0",
    "cert private key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCkludmVudGVkQ2VydFByaXZhdGVLZXk=",
    "ca private key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCkludmVudGVkQ2FQcml2YXRlS2V5Cg==",
    "openvpn tls key": "IyBJbnZlbnRlZCBPcGVuVlBOIHN0YXRpYyBrZXkgVjEgdGxzLWF1dGgga2V5IGJsb2I=",
    "openvpn shared key": "IyBJbnZlbnRlZCBPcGVuVlBOIHNoYXJlZCBrZXkgZm9yIHRlc3RzIG9ubHk=",
    "ipsec psk": "invented-ipsec-psk-4471",
    "ipsec mobile psk": "invented-mobile-psk-5582",
    "ipsec mvc psk": "invented-swanctl-psk-6693",
    "wireguard private key": "aW52ZW50ZWQtd2lyZWd1YXJkLXByaXZrZXktMDAx",
    "wireguard psk": "aW52ZW50ZWQtd2lyZWd1YXJkLXBzay0wMDI=",
    "snmp community": "invented-community-ro",
    "radius secret": "invented-radius-secret-77",
    "ldap bind password": "invented-ldap-bindpw-88",
    "dhcp ddns key": "aW52ZW50ZWQtZGRucy1rZXk=",
    "dns tsig secret": "aW52ZW50ZWQtdHNpZy1zZWNyZXQ=",
    "carp password": "invented-carp-pass-1",
    "pppoe password": "invented-pppoe-pass-2",
    "dyndns password": "invented-dyndns-pass-3",
    "acme dns token": "invented-acme-dns-token-4",
    "smtp password": "invented-smtp-pass-5",
    "ha sync password": "invented-hasync-pass-6",
    "url password": "invented-url-pass-7",
    "wireless passphrase": "invented-wpa-passphrase-8",
    "snmpv3 auth key": "invented-snmpv3-authkey-9",
    "snmpv3 privacy key": "invented-snmpv3-enckey-10",
    "monit password": "invented-monit-pass-11",
    "cdata secret": "invented&cdata<secret>12",
    "authorized keys blob": "c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUludmVudGVkS2V5Rm9yVGVzdHMgdXNlckBleGFtcGxlLmNvbQ==",
}

# Values that are not secrets and stay readable.
PLAIN = (
    "fw-lab-01",
    "example.com",
    "192.0.2.1",
    "203.0.113.10",
    "aW52ZW50ZWQtd2lyZWd1YXJkLXB1YmtleS0wMDM=",  # a WireGuard public key
    "<keytype>RSA</keytype>",
    "<passwordauth>1</passwordauth>",
    "<certref>6500aa0000001</certref>",
    "<descr>Invented web GUI certificate</descr>",
)


def _sample(*, revision_time: str = "1700000000.1", **overrides: str) -> str:
    v = {**SECRETS, **overrides}
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<opnsense>
  <revision>
    <username>root@192.0.2.50</username>
    <time>{revision_time}</time>
    <description>/system_advanced_admin.php made changes</description>
  </revision>
  <system>
    <hostname>fw-lab-01</hostname>
    <domain>example.com</domain>
    <user>
      <name>root</name>
      <bcrypt-hash>{v["user bcrypt hash"]}</bcrypt-hash>
      <otp_seed>{v["user otp seed"]}</otp_seed>
      <authorizedkeys>{v["authorized keys blob"]}</authorizedkeys>
      <apikeys>
        <item>
          <key>{v["api key"]}</key>
          <secret>{v["api secret"]}</secret>
        </item>
      </apikeys>
    </user>
    <ssh><passwordauth>1</passwordauth></ssh>
    <webgui><certref>6500aa0000001</certref></webgui>
  </system>
  <cert uuid="c1" refid="6500aa0000001">
    <descr>Invented web GUI certificate</descr>
    <keytype>RSA</keytype>
    <prv>{v["cert private key"]}</prv>
  </cert>
  <ca refid="6500aa0000002"><descr>Invented CA</descr><prv>{v["ca private key"]}</prv></ca>
  <openvpn>
    <openvpn-server>
      <vpnid>1</vpnid>
      <tls>{v["openvpn tls key"]}</tls>
      <shared_key>{v["openvpn shared key"]}</shared_key>
    </openvpn-server>
  </openvpn>
  <ipsec>
    <phase1>
      <remote-gateway>203.0.113.10</remote-gateway>
      <pre-shared-key>{v["ipsec psk"]}</pre-shared-key>
    </phase1>
    <mobilekey><ident>road@example.com</ident><pre-shared-key>{v["ipsec mobile psk"]}</pre-shared-key></mobilekey>
  </ipsec>
  <OPNsense>
    <IPsec version="1.0.1">
      <preSharedKeys>
        <preSharedKey uuid="p1"><ident>192.0.2.1</ident><keyType>PSK</keyType><Key>{v["ipsec mvc psk"]}</Key></preSharedKey>
      </preSharedKeys>
    </IPsec>
    <wireguard>
      <server><servers><server uuid="w1">
        <name>wg-lab</name>
        <privkey>{v["wireguard private key"]}</privkey>
        <pubkey>aW52ZW50ZWQtd2lyZWd1YXJkLXB1YmtleS0wMDM=</pubkey>
      </server></servers></server>
      <client><clients><client uuid="w2"><psk>{v["wireguard psk"]}</psk></client></clients></client>
    </wireguard>
    <AcmeClient><validations><validation><dns_cf_token>{v["acme dns token"]}</dns_cf_token></validation></validations></AcmeClient>
    <monit><general><httpdPassword>{v["monit password"]}</httpdPassword></general></monit>
    <netsnmp><users><user><authkey>{v["snmpv3 auth key"]}</authkey><enckey>{v["snmpv3 privacy key"]}</enckey></user></users></netsnmp>
  </OPNsense>
  <snmpd><rocommunity>{v["snmp community"]}</rocommunity></snmpd>
  <system_authserver>
    <authserver><type>radius</type><radius_secret>{v["radius secret"]}</radius_secret></authserver>
    <authserver><type>ldap</type><ldap_bindpw>{v["ldap bind password"]}</ldap_bindpw></authserver>
  </system_authserver>
  <dhcpd><lan><ddnsdomainkey>{v["dhcp ddns key"]}</ddnsdomainkey></lan></dhcpd>
  <unbound><tsig_secret>{v["dns tsig secret"]}</tsig_secret></unbound>
  <virtualip><vip mode="carp" interface="lan"><subnet>192.0.2.1</subnet><password>{v["carp password"]}</password></vip></virtualip>
  <ppps><ppp><type>pppoe</type><password>{v["pppoe password"]}</password></ppp></ppps>
  <dyndnses><dyndns><host>fw.example.com</host><password>{v["dyndns password"]}</password></dyndns></dyndnses>
  <notifications><smtp><smtppassword>{v["smtp password"]}</smtppassword></smtp></notifications>
  <hasync><pfsyncpeerip>192.0.2.2</pfsyncpeerip><password>{v["ha sync password"]}</password></hasync>
  <firmware><mirror>https://mirror-user:{v["url password"]}@mirror.example.com/opnsense</mirror></firmware>
  <wireless><wpa><passphrase>{v["wireless passphrase"]}</passphrase></wpa></wireless>
  <custom><secret><![CDATA[{v["cdata secret"]}]]></secret></custom>
</opnsense>
"""


def _assert_no_secret(*outputs: object) -> None:
    blob = "\n".join(o if isinstance(o, str) else json.dumps(o, default=str) for o in outputs)
    leaked = [kind for kind, value in SECRETS.items() if value in blob]
    # A CDATA value is also searched for in its escaped form.
    if "invented&amp;cdata&lt;secret&gt;12" in blob:
        leaked.append("cdata secret (escaped)")
    assert not leaked, f"secret values leaked: {leaked}"


# ═════════════════════════════════════════════════════════════════════════════
# 1. The pure rules
# ═════════════════════════════════════════════════════════════════════════════


def test_mask_config_xml_hides_every_secret_and_keeps_the_rest():
    masked = secrets.mask_config_xml(_sample())
    _assert_no_secret(masked)
    for value in PLAIN:
        assert value in masked
    # One marker per secret element (the URL password included).
    assert len(re.findall(r"\[masked(?: blob)?:[0-9a-f]{8}\]", masked)) == len(SECRETS)


def test_bare_marker_without_fingerprint():
    masked = secrets.mask_config_xml(_sample(), fingerprint=False)
    _assert_no_secret(masked)
    assert "[masked]" in masked
    assert not re.search(r"\[masked:[0-9a-f]{8}\]", masked)


def test_keep_lines_keeps_the_line_count():
    text = "<opnsense>\n  <prv>line-one-secret\nline-two-secret</prv>\n</opnsense>\n"
    masked = secrets.mask_config_xml(text, keep_lines=True)
    assert masked.count("\n") == text.count("\n")
    assert "line-one-secret" not in masked and "line-two-secret" not in masked


@pytest.mark.parametrize(
    "tag",
    [
        "password",
        "bcrypt-hash",
        "otp_seed",
        "key",
        "Key",
        "secret",
        "prv",
        "privkey",
        "privateKey",
        "tls",
        "shared_key",
        "psk",
        "pre-shared-key",
        "rocommunity",
        "radius_secret",
        "ldap_bindpw",
        "ddnsdomainkey",
        "tsig_secret",
        "dns_cf_token",
        "httpdPassword",
        "authkey",
        "enckey",
        "passphrase",
        "api_secret",
    ],
)
def test_secret_tag_names(tag):
    assert secrets.is_secret_tag(tag)


@pytest.mark.parametrize(
    "tag",
    ["pubkey", "publicKey", "keytype", "keylen", "keyid", "certref", "passwordauth", "password_policy", "descr"],
)
def test_descriptive_tag_names_are_not_secrets(tag):
    assert not secrets.is_secret_tag(tag)


def test_fingerprint_is_keyed_and_stable():
    assert secrets.fingerprint("x") == secrets.fingerprint("x")
    assert secrets.fingerprint("x", b"k1") == secrets.fingerprint("x", b"k1")
    assert secrets.fingerprint("x", b"k1") != secrets.fingerprint("x", b"k2")
    assert secrets.fingerprint("x", b"k1") != secrets.fingerprint("x")
    assert re.fullmatch(r"[0-9a-f]{8}", secrets.fingerprint("x"))


def test_drift_text_is_stable_masked_and_idempotent():
    first = secrets.drift_text(_sample(), key=b"k")
    _assert_no_secret(first)
    # Every save rewrites <revision>: not drift.
    assert secrets.drift_text(_sample(revision_time="1800000000.9"), key=b"k") == first
    assert "<revision>" not in first and "root@192.0.2.50" not in first
    # Attribute order and comments are not drift either.
    reordered = _sample().replace('uuid="c1" refid="6500aa0000001"', 'refid="6500aa0000001" uuid="c1"')
    reordered = reordered.replace("<system>", "<!-- invented comment --><system>", 1)
    assert secrets.drift_text(reordered, key=b"k") == first
    # Masking and normalizing their own output change nothing.
    assert secrets.drift_text(first, key=b"k") == first
    assert secrets.mask_config_xml(first, key=b"k") == first


def test_changed_secret_still_shows_as_drift():
    before = secrets.drift_text(_sample(), key=b"k")
    after = secrets.drift_text(_sample(**{"ipsec psk": "invented-ipsec-psk-CHANGED"}), key=b"k")
    diff_text, added, removed = _compute_config_diff(before, after)
    assert (added, removed) == (1, 1)
    assert re.search(r"^-\s*<pre-shared-key>\[masked:[0-9a-f]{8}\]</pre-shared-key>$", diff_text, re.M)
    assert re.search(r"^\+\s*<pre-shared-key>\[masked:[0-9a-f]{8}\]</pre-shared-key>$", diff_text, re.M)
    _assert_no_secret(diff_text)
    assert "invented-ipsec-psk-CHANGED" not in diff_text


def test_config_revision_and_non_config_text():
    assert secrets.config_revision(_sample()) == {
        "time": "1700000000.1",
        "username": "root@192.0.2.50",
        "description": "/system_advanced_admin.php made changes",
    }
    assert secrets.config_revision("hostname sw1\n") == {}
    assert secrets.normalize_config_xml("hostname sw1\n") == "hostname sw1\n"
    assert secrets.looks_like_config_xml(_sample())
    assert not secrets.looks_like_config_xml("<response status='success'/>")


def test_unparsable_config_is_still_masked_and_loses_its_revision():
    broken = _sample().replace("</opnsense>", "")  # cut short
    out = secrets.drift_text(broken, key=b"k")
    _assert_no_secret(out)
    assert "<revision>" not in out


def test_doctype_is_refused_not_parsed():
    text = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "boom">]><opnsense><a>&e;</a></opnsense>'
    assert secrets.normalize_config_xml(text) == text  # left as text, never expanded


def test_mcp_redaction_covers_config_xml():
    out = redact.redact_config_text(_sample())
    _assert_no_secret(out)
    lines = redact.redact_config_text(_sample(), keep_lines=True)
    _assert_no_secret(lines)
    assert lines.count("\n") == _sample().count("\n")


# ═════════════════════════════════════════════════════════════════════════════
# 2. Config drift and config backups of an OPNsense host
# ═════════════════════════════════════════════════════════════════════════════

FW = 300


class DummyRequest:
    def __init__(self):
        self.cookies = {}
        self.state = type("S", (), {"correlation_id": "test-corr"})()


@pytest.fixture
async def fw_db(monkeypatch):
    await db_module.init_db()
    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (1, 'edge')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, status) "
            f"VALUES ({FW}, 1, 'fw-lab-01', '192.0.2.1', 'opnsense', 'online')"
        )
        await db.commit()
    finally:
        await db.close()
    monkeypatch.setattr(drift_routes, "require_credential_access", AsyncMock(return_value={}))
    # Nothing may open a session to the firewall.
    no_ssh = AsyncMock(side_effect=AssertionError("an OPNsense host must not be read over SSH"))
    monkeypatch.setattr(drift_routes, "get_device_config", no_ssh)


async def _store_backup(text: str) -> int:
    return await db_module.create_config_backup(
        policy_id=None,
        host_id=FW,
        config_text=text,
        config_text_full="",
        capture_method="opnsense-api",
        status="success",
        error_message="",
    )


async def _drift_tables() -> list:
    return [
        await db_module.get_config_baselines(),
        [await db_module.get_config_snapshot(s["id"]) for s in await db_module.get_config_snapshots_for_host(FW)],
        await db_module.get_config_drift_events(),
    ]


@pytest.mark.asyncio
async def test_capture_without_backup_is_409(fw_db):
    body = drift_routes.ConfigSnapshotCaptureRequest(host_id=FW, credential_id=1)
    with pytest.raises(HTTPException) as exc_info:
        await drift_routes.capture_config_snapshot(body, DummyRequest())
    assert exc_info.value.status_code == 409
    assert "OPNsense" in exc_info.value.detail


@pytest.mark.asyncio
async def test_drift_cycle_masks_everything_and_detects_a_secret_change(fw_db):
    raw = _sample()
    await _store_backup(raw)
    req = DummyRequest()

    # Baseline from the raw config.xml (pasted): stored in drift form.
    created = await drift_routes.create_config_baseline(
        drift_routes.ConfigBaselineCreate(host_id=FW, name="fw baseline", config_text=raw), req
    )
    baseline = await db_module.get_config_baseline(created["id"])
    assert "<revision>" not in baseline["config_text"]

    # Capture takes the stored backup, not the firewall.
    captured = await drift_routes.capture_config_snapshot(
        drift_routes.ConfigSnapshotCaptureRequest(host_id=FW, credential_id=1), req
    )
    snapshot = await db_module.get_config_snapshot(captured["snapshot_id"])
    assert snapshot["config_text"] == baseline["config_text"]
    assert (await drift_routes._analyze_drift_for_host(FW))["drifted"] is False

    # A save that changes only <revision>: still compliant.
    await _store_backup(_sample(revision_time="1700000999.5"))
    check = drift_routes.ConfigDriftCheckRequest(host_id=FW, credential_id=1)
    assert (await drift_routes.full_config_drift_check(check, req))["drifted"] is False

    # A changed secret is drift, shown by its fingerprint only.
    await _store_backup(_sample(revision_time="1700001000.0", **{"radius secret": "invented-radius-NEW"}))
    result = await drift_routes.full_config_drift_check(check, req)
    assert result["drifted"] is True
    event = await drift_routes.get_config_drift_event(result["event_id"], req)
    assert re.search(r"^\+\s*<radius_secret>\[masked:[0-9a-f]{8}\]</radius_secret>$", event["diff_text"], re.M)
    assert (event["diff_lines_added"], event["diff_lines_removed"]) == (1, 1)

    outputs = [
        event,
        await drift_routes.list_config_drift_events(req, status=None, host_id=None, limit=100),
        await drift_routes.get_config_baseline(created["id"], req),
        await drift_routes.list_config_baselines(req, host_id=None),
        await drift_routes.get_config_snapshot(captured["snapshot_id"], req),
        *await _drift_tables(),
    ]
    _assert_no_secret(*outputs)
    assert "invented-radius-NEW" not in json.dumps(outputs, default=str)

    # Raw backups are stored as collected (a restore needs them).
    newest = await db_module.get_newest_host_config_backup(FW)
    assert "invented-radius-NEW" in newest["config_text"]


@pytest.mark.asyncio
async def test_scheduled_check_snapshots_new_backups(fw_db, monkeypatch):
    monkeypatch.setitem(state.CONFIG_DRIFT_CHECK_CONFIG, "enabled", True)
    await _store_backup(_sample())
    await drift_routes.create_config_baseline(
        drift_routes.ConfigBaselineCreate(host_id=FW, name="fw", config_text=_sample()), DummyRequest()
    )
    first = await drift_routes._run_config_drift_check_once()
    assert (first["hosts_checked"], first["drifted"]) == (1, 0)
    # Nothing new: no further snapshot.
    await drift_routes._run_config_drift_check_once()
    assert len(await db_module.get_config_snapshots_for_host(FW)) == 1

    await _store_backup(_sample(**{"carp password": "invented-carp-NEW"}))
    second = await drift_routes._run_config_drift_check_once()
    assert second["drifted"] == 1
    assert len(await db_module.get_config_snapshots_for_host(FW)) == 2
    tables = await _drift_tables()
    _assert_no_secret(*tables)
    assert "invented-carp-NEW" not in json.dumps(tables, default=str)


@pytest.mark.asyncio
async def test_revert_is_refused(fw_db):
    await _store_backup(_sample())
    req = DummyRequest()
    await drift_routes.create_config_baseline(
        drift_routes.ConfigBaselineCreate(host_id=FW, name="fw", config_text=_sample()), req
    )
    await _store_backup(_sample(**{"snmp community": "invented-community-NEW"}))
    result = await drift_routes.full_config_drift_check(
        drift_routes.ConfigDriftCheckRequest(host_id=FW, credential_id=1), req
    )
    with pytest.raises(HTTPException) as exc_info:
        await drift_routes.revert_drift_event(
            drift_routes.ConfigDriftRevertRequest(event_id=result["event_id"], credential_id=1), req
        )
    assert exc_info.value.status_code == 400
    assert "OPNsense" in exc_info.value.detail
    assert drift_routes._revert_jobs == {} or all(j.get("host_id") != FW for j in drift_routes._revert_jobs.values())


@pytest.mark.asyncio
async def test_backup_view_diff_search_and_restore(fw_db, monkeypatch):
    first = await _store_backup(_sample())
    second = await _store_backup(_sample(revision_time="1700000500.0", **{"wireguard psk": "aW52ZW50ZWQtTkVX"}))
    req = DummyRequest()

    detail = await backups_routes.get_config_backup_detail(second, req)
    assert detail["secrets_masked"] is True
    assert detail["revision"]["time"] == "1700000500.0"
    assert "<revision>" in detail["config_text"]  # the view is the file as stored, masked
    _assert_no_secret(detail)
    assert "aW52ZW50ZWQtTkVX" not in json.dumps(detail)

    diff = await backups_routes.get_config_backup_diff(second, req)
    assert diff["secrets_masked"] is True
    assert diff["previous_backup_id"] == first
    assert (diff["diff_lines_added"], diff["diff_lines_removed"]) == (1, 1)  # the psk, not <revision>
    assert re.search(r"^\+\s*<psk>\[masked:[0-9a-f]{8}\]</psk>$", diff["diff_text"], re.M)
    assert diff["previous_revision"]["time"] == "1700000000.1"
    _assert_no_secret(diff)

    # A search for a secret value cannot confirm it; other hits are masked.
    hit_on_secret = await backups_routes.search_config_backup_records(
        q=SECRETS["ipsec psk"], mode="substring", limit=50, context_lines=2, request=req
    )
    assert hit_on_secret["results"] == []
    hits = await backups_routes.search_config_backup_records(
        q="rocommunity", mode="substring", limit=50, context_lines=2, request=req
    )
    assert hits["results"] and all(r["secrets_masked"] for r in hits["results"])
    _assert_no_secret(hits)

    with pytest.raises(HTTPException) as exc_info:
        await backups_routes.restore_config_from_backup(
            backups_routes.ConfigBackupRestoreRequest(backup_id=second, credential_id=1), req
        )
    assert exc_info.value.status_code == 400
    assert "OPNsense" in exc_info.value.detail


def test_mask_record_leaves_other_vendors_alone():
    record = {"device_type": "cisco_ios", "config_text": "snmp-server community invented RO\n"}
    assert opnsense_masking.mask_record(dict(record), "config_text") == record
    xml = {"device_type": "", "config_text": _sample()}
    masked = opnsense_masking.mask_record(xml, "config_text")
    assert masked["secrets_masked"] is True
    _assert_no_secret(masked)
