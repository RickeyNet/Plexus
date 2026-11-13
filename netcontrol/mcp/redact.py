"""Secret masking for everything an MCP tool returns.

Always on: the dispatcher passes every tool result through ``redact_result``
before it is serialised, and there is no setting that turns it off. A
failure here withholds the result (``RedactionError``); it never falls back
to the unmasked value.

Two layers:

* ``redact_config_text`` works line by line on device configuration text
  (and on diffs and search matches of it). A rule masks the secret value and
  keeps the rest of the line, so a reader still sees that the feature is
  configured: ``snmp-server community ******** RO``. Line endings and every
  line without a secret are returned byte for byte.
* ``redact_value`` walks structured results. A value under a key on the
  deny-list is replaced whole; every string goes through
  ``redact_config_text``.

Pattern matching cannot promise to catch every secret in every vendor
syntax. That limit is stated in ``docs/ai-access.md``; where it is not
acceptable, the ``configs`` category is left off the token.

To cover another vendor form, add one line to ``_RULES``.
"""

from __future__ import annotations

import re
from typing import Any

from netcontrol.integrations.meraki.collector import _SECRET_KEY_FRAGMENTS as _MERAKI_SECRET_KEY_FRAGMENTS

MASK = "********"


class RedactionError(Exception):
    """Masking failed, so the result must not be returned."""


# ── Config text ──────────────────────────────────────────────────────────────

# Where a command may start: at the start of a line (after a diff marker and
# indentation) or anywhere it is not the tail of another word, so a command
# quoted inside other text ("Missing: snmp-server community ...") is covered.
_LEAD = r"(?:^[+\-<> \t]*|(?<![\w-]))"
# A secret value: a quoted string or one token.
_V = r'(?P<v>"[^"]*"|\S+)'
# Words platforms put between a keyword and its value: an encryption-type
# digit (0, 5, 7, 8, 9) or a type name.
_T = r"(?:(?:[0-9]|ciphertext|plaintext|encrypted|irreversible-cipher|cipher|simple|hmac-\S+) )*"
# Digest names that precede an NTP or routing key.
_ALG = r"(?:md5|sha\S*|hmac-\S+|cmac-\S+)"
# The one word after a bare "authentication" that is a setting, not a secret.
_AUTH_WORDS = (
    r"(?:md5|text|open|shared|pre-share|rsa-sig|rsa-encr|ecdsa-sig|message-digest|null|none|periodic|mode|"
    r"key-chain|local|remote|simple|enable|disable|required|optional|dot1x|mab|pap|chap|"
    r"sha\S*|hmac\S*|keyed\S*|mschap\S*|eap\S*|wpa\S*)"
)


def _mask(match: re.Match[str]) -> str:
    value = match.group("v")
    quoted = len(value) >= 2 and value.startswith('"') and value.endswith('"')
    return match.group("p") + (f'"{MASK}"' if quoted else MASK)


def _rule(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Ordered. Each pattern has a prefix group ``p`` that is kept and a value
# group ``v`` that is masked.
_RULES: tuple[re.Pattern[str], ...] = (
    # XML (PAN-OS): <phash>, <key>, <password>, <secret>, <bind-password>, ...
    _rule(
        r"(?P<p><(?P<tag>(?:[\w.-]*-)?"
        r"(?:phash|key|password|passwd|secret|passphrase|community-string|authpwd|privpwd))>)"
        r"(?P<v>[^<]+)(?=</(?P=tag)>)"
    ),
    # Password hashes anywhere: $1$ $5$ $6$ $8$ $9$ (IOS, NX-OS, Junos, EOS).
    _rule(r"(?P<p>)(?P<v>\$(?:1|5|6|8|9|2[aby])\$[^\s\"';<]+)"),
    # Fortinet encrypted values.
    _rule(r"(?P<p>\bENC )" + _V),
    # SNMP communities and SNMPv3 keys.
    _rule(rf"(?P<p>{_LEAD}snmp-server community )" + _V),
    _rule(rf"(?P<p>{_LEAD}snmp-server host .*?\bcommunity )" + _V),
    _rule(
        rf"(?P<p>{_LEAD}snmp-server host \S+(?: vrf \S+)?(?: (?:traps|informs))?"
        r"(?: version (?:1|2c|3(?: (?:auth|noauth|priv))?))? )"
        r"(?!vrf\b|traps\b|informs\b|version\b|community\b)" + _V
    ),
    _rule(rf"(?P<p>{_LEAD}snmp-server user .*?\bauth (?:md5|sha\S*) )" + _V),
    _rule(rf"(?P<p>{_LEAD}snmp-server user .*?\bpriv (?:(?:des|3des|aes\S*)(?: \d+)? )?)" + _V),
    _rule(rf"(?P<p>{_LEAD}community )" + _V + r"(?= \{)"),
    _rule(r"(?P<p>\bsnmp community )" + _V),
    _rule(r"(?P<p>\bsnmp-agent community (?:(?:read|write) )?(?:(?:cipher|simple) )?)" + _V),
    _rule(rf"(?P<p>\b(?:auth|priv)-pass(?:word)? {_T})" + _V),
    # TACACS+ and RADIUS keys.
    _rule(rf"(?P<p>{_LEAD}(?:tacacs|radius)-server .*?\bkey {_T})" + _V),
    _rule(rf"(?P<p>\bserver-private \S+ .*?\bkey {_T})" + _V),
    _rule(rf"(?P<p>(?<![\w-])(?:shared-key|server-key|pac key|key-octet-string|failover key(?: hex)?) {_T})" + _V),
    # A "key <value>" line of its own (tacacs server, radius server,
    # aaa-server), indented or quoted in other text. "key 1" alone is a
    # key-chain id and is left as it is.
    _rule(rf"(?P<p>(?:^[+\-<>]?[ \t]+|[:'\"(]\s*)key {_T})(?!\d+\s*$)" + _V + r"(?=\s*$)"),
    # MACsec: key <hex id> <type> <value>.
    _rule(r"(?P<p>^[+\-<>]?[ \t]+key [0-9a-f]{2,} [0-9] )" + _V + r"(?=\s*$)"),
    # Routing and first-hop protocol authentication.
    _rule(rf"(?P<p>\bmessage-digest-key \d+ md5 {_T})" + _V),
    _rule(rf"(?P<p>\bauthentication-key \d+ {_ALG} )" + _V),
    _rule(rf"(?P<p>\bauthentication-key (?!\d+ {_ALG} ){_T})" + _V),
    _rule(rf"(?P<p>\bkey-string {_T})(?P<v>\S.*)"),
    _rule(rf"(?P<p>{_LEAD}(?:standby|vrrp|glbp)(?: \d+)? authentication (?:text )?)(?!md5\b|text\b)" + _V),
    _rule(r"(?P<p>\bnhrp authentication )" + _V),
    _rule(rf"(?P<p>\bauthentication ipsec spi \d+ \S+ {_T})" + _V),
    _rule(rf"(?P<p>\bauthentication \S+ keyid \d+ key {_T})" + _V),
    _rule(rf"(?P<p>\bauthentication key {_T})" + _V),
    _rule(r"(?P<p>\bauthentication text )" + _V),
    # A bare "authentication <value>" line (HSRP on NX-OS).
    _rule(rf"(?P<p>^[+\-<>]?[ \t]+authentication )(?!{_AUTH_WORDS}\s*$)" + _V + r"(?=\s*$)"),
    _rule(rf"(?P<p>\bmsdp password peer \S+ {_T})" + _V),
    # IPsec and IKE pre-shared keys.
    _rule(rf"(?P<p>\bcrypto isakmp key {_T})" + _V),
    _rule(rf"(?P<p>\bpre-shared-key (?:address|hostname)(?: ipv6)? \S+(?: \d+\.\S+)? key {_T})" + _V),
    _rule(
        r"(?P<p>\bpre-shared-key (?:(?:local|remote|ascii-text|hexadecimal|hex|key|[0-9]) )*)"
        r"(?!address\b|hostname\b)" + _V
    ),
    # Wireless.
    _rule(rf"(?P<p>\bwpa-psk (?:(?:ascii|hex) )?{_T})" + _V),
    _rule(rf"(?P<p>\bset-key (?:(?:ascii|hex) )?{_T})" + _V),
    _rule(r"(?P<p>passphrase (?:(?:[0-9]|ENC) )?)" + _V),
    # Fortinet "set <secret-ish name> <value>".
    _rule(
        rf"(?P<p>{_LEAD}set (?:[\w-]*(?:password|passwd|secret|psk|pwd)[\w-]*|(?:[\w-]+-)?key) (?:ENC )?)"
        r"(?P<v>\S.*)"
    ),
    # ProCurve "password manager user-name <name> sha1 <value>".
    _rule(r"(?P<p>\bpassword (?:manager|operator)(?: user-name \S+)? (?:(?:sha1|sha256|plaintext) )?)" + _V),
    # Any "password"/"passwd"/"secret" followed by its value, with the
    # encryption-type words platforms put in between.
    _rule(
        r"(?P<p>\b(?:password|passwd|secret)"
        r"(?: (?:[0-9]|ENC|encrypted|sha512|sha256|sha1|pbkdf2|scrypt|md5|cipher|hash|simple|ciphertext|plaintext|"
        r"irreversible-cipher|hmac-\S+|level \d+))* )(?!(?:peer|manager|operator) )" + _V
    ),
)

# A line with none of these has nothing the rules above could match.
_TRIGGER = re.compile(
    r"pass|secret|key|community|snmp|authentication|psk|ENC |\$\d|\$2[aby]\$|pwd|phash", re.IGNORECASE
)
# A description or remark command is free text an operator wrote and is never
# rewritten. Only the command itself: the word later in a line exempts nothing.
_FREE_TEXT = re.compile(
    r"^[+\-<> \t]*(?:(?:ip(?:v6)? )?access-list \S+ (?:line \d+ )?)?(?:\d+ )?(?:description|remark)\s",
    re.IGNORECASE,
)
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]+-----")
_PEM_INLINE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----")
# A certificate or key hex dump line: four or more groups of eight hex digits.
_HEX_DUMP = re.compile(r"^(?P<lead>[+\-<> \t]*)(?:[0-9A-Fa-f]{8}[ \t]+){3,}[0-9A-Fa-f]{1,8}[ \t]*$")
# Fortinet keeps an SNMP community string as the name of its entry.
_FORTI_SNMP = "config system snmp community"
_FORTI_NAME = re.compile(r"(?P<p>^[+\-<> \t]*set name )" + _V, re.IGNORECASE)
_MARKERS = "+-<> \t"
_LINE_ENDINGS = "\r\n\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"


def _split(line: str) -> tuple[str, str]:
    body = line.rstrip(_LINE_ENDINGS)
    return body, line[len(body) :]


def _mask_line(body: str) -> str:
    if not _TRIGGER.search(body) or _FREE_TEXT.search(body):
        return body
    for rule in _RULES:
        body = rule.sub(_mask, body)
    return body


def redact_config_text(text: str, *, keep_lines: bool = False) -> str:
    """Mask the secrets in configuration text; keep everything else as it is.

    A key or certificate block becomes one mask line. With ``keep_lines``
    every line of the block is masked in place instead, so line numbers in
    the result are those of the original text.
    """
    if not text:
        return text
    if (
        "\n" not in text
        and "\r" not in text
        and not _TRIGGER.search(text)
        and "-----BEGIN" not in text
        and not _HEX_DUMP.match(text)
    ):
        return text

    lines = text.splitlines(keepends=True)
    out: list[str] = []
    index = 0
    snmp_depth = 0  # nesting inside a Fortinet "config system snmp community"
    while index < len(lines):
        body, ending = _split(lines[index])

        if _PEM_BEGIN.search(body):
            if _PEM_INLINE.search(body):
                out.append(_mask_line(_PEM_INLINE.sub(MASK, body)) + ending)
                index += 1
                continue
            # A key or certificate block. Without an END line, everything
            # that follows is withheld.
            first = index
            while index < len(lines) - 1 and not _PEM_END.search(lines[index]):
                index += 1
            if keep_lines:
                out.extend(MASK + _split(line)[1] for line in lines[first : index + 1])
            else:
                out.append(MASK + _split(lines[index])[1])
            index += 1
            continue

        hex_match = _HEX_DUMP.match(body)
        if hex_match:
            first = index
            while index + 1 < len(lines) and _HEX_DUMP.match(_split(lines[index + 1])[0]):
                index += 1
            masked = hex_match.group("lead") + MASK
            if keep_lines:
                out.extend(masked + _split(line)[1] for line in lines[first : index + 1])
            else:
                out.append(masked + _split(lines[index])[1])
            index += 1
            continue

        command = body.lstrip(_MARKERS).rstrip().lower()
        if snmp_depth == 0:
            if command == _FORTI_SNMP:
                snmp_depth = 1
        elif command.startswith("config "):
            snmp_depth += 1
        elif command == "end":
            snmp_depth -= 1
        elif snmp_depth == 1:
            body = _FORTI_NAME.sub(_mask, body)

        out.append(_mask_line(body) + ending)
        index += 1
    return "".join(out)


# ── Structured values ────────────────────────────────────────────────────────

# Compared against the key lower-cased with "_", "-" and spaces removed.
_DENY_KEY_FRAGMENTS: tuple[str, ...] = tuple(
    dict.fromkeys(
        (
            "password",
            "passwd",
            "secret",
            "token",
            "apikey",
            "community",
            "psk",
            "privatekey",
            "passphrase",
            "authkey",
            "privkey",
            *_MERAKI_SECRET_KEY_FRAGMENTS,
        )
    )
)
_KEY_SEPARATORS = str.maketrans("", "", "_- ")


def _is_secret_key(key: object) -> bool:
    compact = str(key).lower().translate(_KEY_SEPARATORS)
    return any(fragment in compact for fragment in _DENY_KEY_FRAGMENTS)


def redact_value(value: Any) -> Any:
    """A masked copy of ``value``. Dicts, lists and tuples are walked; a
    value under a secret-bearing key is replaced whole (booleans and nulls
    stay, so ``has_password: true`` still reads); every string is passed
    through ``redact_config_text``."""
    if isinstance(value, str):
        return redact_config_text(value)
    if isinstance(value, dict):
        masked: dict[Any, Any] = {}
        for key, item in value.items():
            if _is_secret_key(key) and item is not None and not isinstance(item, bool) and item != "":
                masked[key] = MASK
            else:
                masked[key] = redact_value(item)
        return masked
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact_value(item) for item in value]
    if isinstance(value, bytes):
        return MASK
    return value


def redact_result(value: Any) -> Any:
    """``redact_value`` for the dispatcher: any failure becomes
    ``RedactionError`` so the caller withholds the result."""
    try:
        return redact_value(value)
    except Exception as exc:
        raise RedactionError("redaction failed") from exc
