"""Secret masking for MCP tool results (``netcontrol.mcp.redact``).

Every config below is invented: hostnames such as ``edge-rtr-01`` and
addresses from the documentation ranges.
"""

from __future__ import annotations

import pytest
from netcontrol.mcp import redact
from netcontrol.mcp.redact import MASK

IOS = """\
hostname edge-rtr-01
service password-encryption
enable secret 9 $9$IosEnableHash1$abcdefghijk
enable password 7 0822455D0A16IosEnable
username netops privilege 15 secret 5 $1$IosUser$HashValue111
username backup password 0 IosPlainUserPw
snmp-server community IosRoComm RO
snmp-server community IosRwComm RW 10
snmp-server user monitor NETGROUP v3 auth sha IosSnmpAuthPw priv aes 128 IosSnmpPrivPw
snmp-server host 192.0.2.50 version 2c IosTrapComm
tacacs-server key 7 IosTacacsGlobalKey
tacacs server TAC-1
 address ipv4 192.0.2.10
 key 7 IosTacacsKey
radius server RAD-1
 address ipv4 192.0.2.11 auth-port 1812 acct-port 1813
 key IosRadiusKey
interface GigabitEthernet0/0
 ip address 192.0.2.1 255.255.255.0
 ip ospf message-digest-key 1 md5 7 IosOspfMd5Key
 ip ospf authentication-key IosOspfAuthKey
 standby 1 authentication md5 key-string IosHsrpKey
 standby 2 authentication IosHsrpText
 vrrp 3 authentication text IosVrrpText
router bgp 65001
 neighbor 192.0.2.2 remote-as 65002
 neighbor 192.0.2.2 password 7 IosBgpPw
key chain OSPF-KEYS
 key 1
  key-string 7 IosKeyString
crypto isakmp key IosIsakmpKey address 192.0.2.99
crypto keyring KR-1
 pre-shared-key address 192.0.2.98 key IosKeyringKey
ntp authentication-key 5 md5 IosNtpKey 7
line vty 0 4
 password 7 IosVtyPw
"""
IOS_SECRETS = [
    "$9$IosEnableHash1$abcdefghijk",
    "0822455D0A16IosEnable",
    "$1$IosUser$HashValue111",
    "IosPlainUserPw",
    "IosRoComm",
    "IosRwComm",
    "IosSnmpAuthPw",
    "IosSnmpPrivPw",
    "IosTrapComm",
    "IosTacacsGlobalKey",
    "IosTacacsKey",
    "IosRadiusKey",
    "IosOspfMd5Key",
    "IosOspfAuthKey",
    "IosHsrpKey",
    "IosHsrpText",
    "IosVrrpText",
    "IosBgpPw",
    "IosKeyString",
    "IosIsakmpKey",
    "IosKeyringKey",
    "IosNtpKey",
    "IosVtyPw",
]
IOS_KEEP = [
    "hostname edge-rtr-01",
    "service password-encryption",
    f"snmp-server community {MASK} RO",
    f"snmp-server community {MASK} RW 10",
    "snmp-server user monitor NETGROUP v3 auth sha",
    "priv aes 128",
    "address ipv4 192.0.2.10",
    "neighbor 192.0.2.2 password",
    f"crypto isakmp key {MASK} address 192.0.2.99",
    " key 1\n",
    "ip ospf message-digest-key 1 md5",
]

NXOS = """\
hostname dc-nxos-01
username admin password 5 $5$NxosAdminHash$zzzz role network-admin
snmp-server user nms network-operator auth sha 0xNxosAuthHex priv aes-128 0xNxosPrivHex localizedkey
snmp-server community NxosComm group network-operator
tacacs-server host 192.0.2.20 key 7 "NxosTacacsKey"
radius-server host 192.0.2.21 key 7 "NxosRadiusKey" authentication accounting
"""
NXOS_SECRETS = ["$5$NxosAdminHash$zzzz", "0xNxosAuthHex", "0xNxosPrivHex", "NxosComm", "NxosTacacsKey", "NxosRadiusKey"]
NXOS_KEEP = [
    "role network-admin",
    "snmp-server community",
    "group network-operator",
    "tacacs-server host 192.0.2.20 key",
]

ASA = """\
hostname fw-asa-01
enable password AsaEnablePw encrypted
passwd AsaPasswd encrypted
username ops password AsaUserPw encrypted privilege 15
snmp-server host inside 192.0.2.30 community AsaComm version 2c
tunnel-group 203.0.113.9 type ipsec-l2l
tunnel-group 203.0.113.9 ipsec-attributes
 ikev1 pre-shared-key AsaIkev1Psk
 ikev2 remote-authentication pre-shared-key AsaIkev2Remote
 ikev2 local-authentication pre-shared-key AsaIkev2Local
aaa-server TAC (inside) host 192.0.2.31
 key AsaAaaKey
"""
ASA_SECRETS = [
    "AsaEnablePw",
    "AsaPasswd",
    "AsaUserPw",
    "AsaComm",
    "AsaIkev1Psk",
    "AsaIkev2Remote",
    "AsaIkev2Local",
    "AsaAaaKey",
]
ASA_KEEP = [
    "tunnel-group 203.0.113.9 ipsec-attributes",
    "ikev1 pre-shared-key",
    "encrypted privilege 15",
    "version 2c",
]

JUNOS = """\
system {
    host-name core-mx-01;
    root-authentication {
        encrypted-password "$6$JunosRootHash$abcdefg";
    }
    login {
        user ops {
            authentication {
                encrypted-password "$1$JunosUserHash$hij";
            }
        }
    }
    radius-server {
        192.0.2.40 secret "$9$JunosRadiusSecret";
    }
    tacplus-server {
        192.0.2.41 secret "JunosPlainTacSecret";
    }
}
snmp {
    community JunosComm {
        authorization read-only;
    }
}
protocols {
    bgp {
        group ebgp {
            authentication-key "$9$JunosBgpKey";
        }
    }
}
security {
    ike {
        policy p1 {
            pre-shared-key ascii-text "$9$JunosIkePsk";
        }
    }
}
set snmp community JunosSetComm authorization read-only
"""
JUNOS_SECRETS = [
    "$6$JunosRootHash$abcdefg",
    "$1$JunosUserHash$hij",
    "$9$JunosRadiusSecret",
    "JunosPlainTacSecret",
    "JunosComm",
    "$9$JunosBgpKey",
    "$9$JunosIkePsk",
    "JunosSetComm",
]
JUNOS_KEEP = [
    "host-name core-mx-01;",
    "encrypted-password",
    "192.0.2.40 secret",
    "authorization read-only",
    "pre-shared-key ascii-text",
]

PANOS = """\
<config>
  <mgt-config>
    <users>
      <entry name="admin">
        <phash>$5$PanAdminPhash$xyz</phash>
      </entry>
    </users>
  </mgt-config>
  <ike>
    <gateway>
      <entry name="gw-branch">
        <pre-shared-key>
          <key>-AQ==PanIkeKeyValue</key>
        </pre-shared-key>
      </entry>
    </gateway>
  </ike>
  <server-profile>
    <ldap>
      <entry name="corp-ldap">
        <bind-dn>cn=svc,dc=example,dc=com</bind-dn>
        <bind-password>-AQ==PanBindPw</bind-password>
      </entry>
    </ldap>
    <radius>
      <entry name="rad">
        <secret>-AQ==PanRadiusSecret</secret>
      </entry>
    </radius>
  </server-profile>
  <password>PanPlainPassword</password>
</config>
"""
PANOS_SECRETS = ["$5$PanAdminPhash$xyz", "PanIkeKeyValue", "PanBindPw", "PanRadiusSecret", "PanPlainPassword"]
PANOS_KEEP = ["<phash>", "</phash>", "<bind-dn>cn=svc,dc=example,dc=com</bind-dn>", '<entry name="gw-branch">', "<key>"]

FORTINET = """\
config system admin
    edit "admin"
        set password ENC SH2FortiAdminHash==
    next
end
config vpn ipsec phase1-interface
    edit "to-branch"
        set remote-gw 203.0.113.20
        set psksecret ENC FortiPskEnc==
    next
    edit "to-lab"
        set psksecret FortiPlainPsk
    next
end
config user radius
    edit "rad1"
        set server "192.0.2.60"
        set secret ENC FortiRadiusEnc==
    next
end
config wireless-controller vap
    edit "corp"
        set passphrase ENC FortiWifiEnc==
    next
end
"""
FORTINET_SECRETS = ["SH2FortiAdminHash==", "FortiPskEnc==", "FortiPlainPsk", "FortiRadiusEnc==", "FortiWifiEnc=="]
FORTINET_KEEP = ["set remote-gw 203.0.113.20", "set psksecret", 'set server "192.0.2.60"', "set password"]

ARISTA = """\
hostname leaf-eos-01
username admin privilege 15 role network-admin secret sha512 $6$AristaAdminHash$qrs
enable password sha512 $6$AristaEnable$tuv
snmp-server community AristaComm ro
router bgp 65010
   neighbor 192.0.2.70 password 7 AristaBgpPw
radius-server host 192.0.2.71 key 7 AristaRadiusKey
management api http-commands
   no shutdown
"""
ARISTA_SECRETS = ["$6$AristaAdminHash$qrs", "$6$AristaEnable$tuv", "AristaComm", "AristaBgpPw", "AristaRadiusKey"]
ARISTA_KEEP = ["role network-admin secret sha512", "snmp-server community", " ro", "neighbor 192.0.2.70 password"]

WIRELESS = """\
dot11 ssid corp-wifi
 authentication key-management wpa version 2
 wpa-psk ascii 0 WifiPskPlain
wlan guest
 wpa-passphrase WifiGuestPassphrase
 passphrase 7 WifiOtherPassphrase
crypto pki certificate chain TP-self-signed-1
 certificate self-signed 01
  30820330 30820218 A0030201 02020101 300D0609 2A864886 F70D0101 05050030
  1D06035D 0E041604 14CAFEBA BEDEADBE EF001122 33445566 778899AA BBCCDDEE
  quit
"""
WIRELESS_SECRETS = ["WifiPskPlain", "WifiGuestPassphrase", "WifiOtherPassphrase", "30820330", "14CAFEBA"]
WIRELESS_KEEP = ["dot11 ssid corp-wifi", "wpa-psk ascii", "certificate self-signed 01", "  quit"]

FAMILIES = {
    "ios": (IOS, IOS_SECRETS, IOS_KEEP),
    "nxos": (NXOS, NXOS_SECRETS, NXOS_KEEP),
    "asa": (ASA, ASA_SECRETS, ASA_KEEP),
    "junos": (JUNOS, JUNOS_SECRETS, JUNOS_KEEP),
    "panos": (PANOS, PANOS_SECRETS, PANOS_KEEP),
    "fortinet": (FORTINET, FORTINET_SECRETS, FORTINET_KEEP),
    "arista": (ARISTA, ARISTA_SECRETS, ARISTA_KEEP),
    "wireless": (WIRELESS, WIRELESS_SECRETS, WIRELESS_KEEP),
}


@pytest.mark.parametrize("family", sorted(FAMILIES))
def test_masks_each_family(family):
    text, secrets, keep = FAMILIES[family]
    out = redact.redact_config_text(text)
    leaked = [s for s in secrets if s in out]
    assert leaked == []
    missing = [k for k in keep if k not in out]
    assert missing == []
    assert MASK in out


@pytest.mark.parametrize("family", ["ios", "nxos", "asa", "junos", "panos", "fortinet", "arista"])
def test_line_count_and_other_lines_unchanged(family):
    text, _, _ = FAMILIES[family]
    out = redact.redact_config_text(text)
    before, after = text.splitlines(keepends=True), out.splitlines(keepends=True)
    assert len(before) == len(after)
    for old, new in zip(before, after, strict=True):
        if MASK not in new:
            assert old == new


def test_redaction_is_idempotent():
    once = redact.redact_config_text(IOS)
    assert redact.redact_config_text(once) == once


def test_crlf_preserved():
    text = IOS.replace("\n", "\r\n")
    out = redact.redact_config_text(text)
    assert out.count("\r\n") == text.count("\r\n")
    assert out.count("\n") == text.count("\n")
    assert [s for s in IOS_SECRETS if s in out] == []
    assert f"snmp-server community {MASK} RO\r\n" in out


def test_keyword_in_description_not_mangled():
    text = (
        "interface GigabitEthernet0/1\n"
        " description uplink password reset pending\n"
        "ip access-list extended MGMT\n"
        " remark allow the secret server key exchange\n"
        " 20 remark the password vault\n"
        "access-list 101 remark secret zone\n"
        "snmp-server community DescTestComm RO\n"
    )
    out = redact.redact_config_text(text)
    assert " description uplink password reset pending\n" in out
    assert " remark allow the secret server key exchange\n" in out
    assert " 20 remark the password vault\n" in out
    assert "access-list 101 remark secret zone\n" in out
    assert "DescTestComm" not in out


def test_unterminated_banner_does_not_stop_masking():
    text = "banner motd ^C\nWelcome\nsnmp-server community AfterBannerComm RO\n"
    assert "AfterBannerComm" not in redact.redact_config_text(text)


# One entry per form: the secret is always S3cr3tVal (or S3cr3tVal2).
REVIEWED_FORMS = [
    # A banner never switches masking off for the lines after it.
    "banner login ! Authorized only\nenable password S3cr3tVal encrypted\n!",
    "banner motd [WARNING] Authorized access only\nsnmp-server community S3cr3tVal RO\n"
    "username a password S3cr3tVal encrypted\nnat (inside,outside) source dynamic any interface [x]",
    "banner motd * Notice\npasswd S3cr3tVal encrypted\naaa-server X (inside) host 192.0.2.1\n key *****",
    "banner motd #\nWelcome\nsnmp-server community S3cr3tVal RO\n#",
    # "description" or "remark" later in a line does not exempt it.
    "snmp-server community S3cr3tVal view V RO description foo",
    "snmp-server community S3cr3tVal RO  ! remark old",
    "username x privilege 15 password 0 S3cr3tVal description admin user",
    '<entry name="x"><description>a description of box</description><secret>S3cr3tVal</secret></entry>',
    # A command quoted inside other text.
    "Missing: snmp-server community S3cr3tVal RO",
    "Missing: tacacs-server key 7 S3cr3tVal",
    "12: snmp-server community S3cr3tVal RO",
    "config: key 7 S3cr3tVal",
    "expected 'tacacs-server key 7 S3cr3tVal'",
    "no snmp-server community S3cr3tVal RO",
    # Aruba AOS-CX.
    "user admin group administrators password ciphertext S3cr3tVal",
    "user admin group administrators password plaintext S3cr3tVal",
    "radius-server host 192.0.2.1 key ciphertext S3cr3tVal",
    "tacacs-server host 192.0.2.1 key plaintext S3cr3tVal",
    "snmpv3 user x auth sha auth-pass ciphertext S3cr3tVal priv aes priv-pass ciphertext S3cr3tVal2",
    # Cisco IOS and IOS-XE.
    " ip nhrp authentication S3cr3tVal",
    " client 192.0.2.1 server-key 7 S3cr3tVal",
    " pac key 7 S3cr3tVal",
    "  pre-shared-key hostname peer.example.com key S3cr3tVal",
    " pre-shared-key address ipv6 2001:db8::1/128 key S3cr3tVal",
    "ntp authentication-key 1 hmac-sha2-256 S3cr3tVal 7",
    "ntp authentication-key 1 sha1 S3cr3tVal 7",
    "ntp authentication-key 1 cmac-aes-128 S3cr3tVal 7",
    "ip msdp password peer 192.0.2.1 7 S3cr3tVal",
    " ipv6 ospf authentication ipsec spi 500 md5 S3cr3tVal",
    " ospfv3 authentication ipsec spi 256 sha1 S3cr3tVal",
    " ip rsvp authentication key S3cr3tVal",
    # NX-OS and Arista.
    "  hsrp 1\n    authentication text S3cr3tVal",
    "  hsrp 1\n    authentication S3cr3tVal",
    "   vrrp 10 peer authentication text S3cr3tVal",
    "   isis authentication key 7 S3cr3tVal",
    "   authentication key 7 S3cr3tVal",
    "  key-octet-string 7 S3cr3tVal cryptographic-algorithm AES_128_CMAC",
    "   key 0102 7 S3cr3tVal",
    " bfd authentication keyed-sha1 keyid 1 key S3cr3tVal",
    # IOS-XR.
    " message-digest-key 1 md5 encrypted S3cr3tVal",
    " authentication-key encrypted S3cr3tVal",
    " hello-password hmac-md5 encrypted S3cr3tVal",
    " lsp-password hmac-md5 encrypted S3cr3tVal",
    # ASA.
    "failover key S3cr3tVal",
    # PAN-OS.
    "<authpwd>S3cr3tVal</authpwd>",
    "<privpwd>S3cr3tVal</privpwd>",
    "set network ike gateway GW authentication pre-shared-key key S3cr3tVal",
    # Fortinet: the community string is the entry's name.
    'config system snmp community\n    edit 1\n        set name "S3cr3tVal"\n        config hosts\n'
    "            edit 1\n                set ip 192.0.2.9 255.255.255.255\n            next\n        end\n"
    "    next\nend",
    # HP Comware and ProCurve.
    "snmp-agent community read cipher S3cr3tVal",
    "snmp-agent community write S3cr3tVal",
    "radius-server shared-key cipher S3cr3tVal",
    " local-user admin password irreversible-cipher S3cr3tVal",
    'password manager user-name "admin" sha1 "S3cr3tVal"',
]


@pytest.mark.parametrize("text", REVIEWED_FORMS)
def test_masks_reviewed_forms(text):
    out = redact.redact_config_text(text + "\n")
    assert "S3cr3tVal" not in out
    assert MASK in out
    assert len(out.splitlines()) == len(text.splitlines())


# Lines that look like the forms above and carry no secret: returned as written.
NOT_SECRETS = [
    " authentication pre-share",
    " authentication message-digest",
    " authentication open",
    " authentication mode md5",
    " authentication key-chain CORE-CHAIN",
    " ip ospf authentication message-digest",
    "aaa authentication login default group tacacs+ local",
    " key 1",
    'config system global\n    set hostname "edge-fw-01"\nend\nconfig system interface\n    edit "port1"\n'
    '        set name "uplink"\n    next\nend',
    "banner motd ^C Authorised users only ^C",
]


@pytest.mark.parametrize("text", NOT_SECRETS)
def test_leaves_lookalike_lines_alone(text):
    assert redact.redact_config_text(text + "\n") == text + "\n"


def test_algorithm_name_is_kept_beside_a_masked_ntp_key():
    assert redact.redact_config_text("ntp authentication-key 1 md5 S3cr3tVal 7\n") == (
        f"ntp authentication-key 1 md5 {MASK} 7\n"
    )
    assert redact.redact_config_text("ntp authentication-key 1 sha1 S3cr3tVal 7\n") == (
        f"ntp authentication-key 1 sha1 {MASK} 7\n"
    )


def test_fortinet_name_is_masked_only_inside_snmp_community():
    text = (
        'config system snmp community\n    edit 1\n        set name "S3cr3tVal"\n    next\nend\n'
        'config firewall address\n    edit 1\n        set name "branch-net"\n    next\nend\n'
    )
    out = redact.redact_config_text(text)
    assert "S3cr3tVal" not in out
    assert 'set name "branch-net"' in out


def test_compliance_finding_detail_is_masked():
    finding = {
        "name": "snmp-server community S3cr3tVal RO",
        "pattern": "snmp-server community S3cr3tVal RO",
        "detail": "Missing: snmp-server community S3cr3tVal RO",
        "passed": False,
    }
    assert "S3cr3tVal" not in str(redact.redact_value({"findings": [finding]}))


def test_single_hex_dump_line_is_masked():
    assert redact.redact_config_text("  30820330 308202A8 A0030201 02020101") == f"  {MASK}"


def test_keep_lines_masks_blocks_line_for_line():
    text = (
        'set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----\n'
        "MIIFHzInventedBodyLine1\n"
        "InventedBodyLine2==\n"
        '-----END ENCRYPTED PRIVATE KEY-----"\n'
        " 30820330 308202A8 A0030201 02020101\n"
        " 14CAFEBA 0D06092A 864886F7 0D010105\n"
        "ntp server 192.0.2.9\n"
    )
    out = redact.redact_config_text(text, keep_lines=True)
    assert out.splitlines() == [MASK] * 4 + [f" {MASK}"] * 2 + ["ntp server 192.0.2.9"]


def test_long_hyphenated_line_is_masked_quickly():
    import time

    line = "a-" * 20_000 + " key x passphrase S3cr3tVal\n"
    started = time.perf_counter()
    out = redact.redact_config_text(line)
    assert time.perf_counter() - started < 1.0
    assert "S3cr3tVal" not in out


def test_diff_lines_are_masked():
    diff = (
        "--- a/config\n+++ b/config\n@@ -1,3 +1,3 @@\n"
        " hostname edge-rtr-01\n"
        "-snmp-server community OldDiffComm RO\n"
        "+snmp-server community NewDiffComm RO\n"
        "+ key 7 DiffTacacsKey\n"
    )
    out = redact.redact_config_text(diff)
    assert "OldDiffComm" not in out and "NewDiffComm" not in out and "DiffTacacsKey" not in out
    assert f"-snmp-server community {MASK} RO\n" in out
    assert " hostname edge-rtr-01\n" in out


def test_pem_block_collapsed():
    text = (
        "crypto key import\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEAinventedkeymaterialline1\n"
        "inventedkeymaterialline2==\n"
        "-----END RSA PRIVATE KEY-----\n"
        "hostname edge-rtr-01\n"
    )
    out = redact.redact_config_text(text)
    assert out == f"crypto key import\n{MASK}\nhostname edge-rtr-01\n"


def test_unterminated_pem_block_masks_the_rest():
    text = "-----BEGIN PRIVATE KEY-----\ninventedkeymaterial\nmore\n"
    out = redact.redact_config_text(text)
    assert "inventedkeymaterial" not in out and "more" not in out


def test_plain_strings_pass_through():
    for value in ["edge-rtr-01", "192.0.2.1", "", "GigabitEthernet1/0/1 is up", "Cisco IOS XE 17.9.4"]:
        assert redact.redact_config_text(value) == value


def test_redact_value_nested():
    value = {
        "a": [{"api_key": "x", "name": "n", "apiKey": "y", "SNMP_Community": "z", "privateKey": "k"}],
        "config": "snmp-server community NestedComm RO\n",
        "count": 3,
        "has_password": True,
        "note": None,
        "pair": ("enable secret NestedEnable", 5),
    }
    out = redact.redact_value(value)
    row = out["a"][0]
    assert row == {"api_key": MASK, "name": "n", "apiKey": MASK, "SNMP_Community": MASK, "privateKey": MASK}
    assert "NestedComm" not in out["config"] and "snmp-server community" in out["config"]
    assert out["count"] == 3 and out["has_password"] is True and out["note"] is None
    assert "NestedEnable" not in out["pair"][0] and out["pair"][1] == 5
    assert value["a"][0]["api_key"] == "x"  # input not modified


def test_redact_result_fails_closed(monkeypatch):
    def _boom(value):
        raise RuntimeError("pattern exploded")

    monkeypatch.setattr(redact, "redact_value", _boom)
    with pytest.raises(redact.RedactionError):
        redact.redact_result({"line": "anything"})


def test_redact_result_masks():
    assert "hunter2" not in str(redact.redact_result({"line": "snmp-server community hunter2 RO"}))
