"""Secret masking and normalization of an OPNsense ``config.xml``.

Pure (standard library only) so every place that shows or stores a form of
the configuration uses the same rules: config drift (snapshots, baselines,
diffs and drift events), the config backup view, diff and search, the
backup rule diff and AI access (``netcontrol.mcp.redact``).

``mask_config_xml`` replaces the value of every element that holds a
secret with a fixed marker plus a short fingerprint of the value::

    <password>[masked:1a2b3c4d]</password>

The fingerprint is the first 8 hex digits of an HMAC-SHA256 of the value
(``key``: a per-install key the caller derives; without one a plain
SHA-256). Equal values give equal markers, so a changed secret still shows
as a changed line in a diff while the value itself never appears. The
keyed form keeps a short, guessable value (an SNMP community ``public``)
from being confirmed by hashing candidates. ``fingerprint=False`` gives a
bare ``[masked]`` for views that need no change tracking.

Which elements are secrets: the curated ``SECRET_TAGS`` (the names
``config.xml`` uses for passwords and their hashes, API key secrets,
private keys, pre-shared keys, SNMP communities, RADIUS/LDAP secrets, TSIG
keys, OTP seeds, tokens), plus any element whose name says it holds one
(``*password*``, ``*secret*``, ``*passphrase*``, ``*token*``,
``*privkey*``, ``*psk*``, ``*community*``, a name ending in ``key``, ...),
except names that describe one (``keytype``, ``keylen``, ``certref``,
``pubkey``, ``password_policy``, ...). Independently of the name, any
long base64 or hex value (a certificate, a key, an encoded blob) becomes
``[masked blob:...]``, a bcrypt/crypt hash anywhere becomes a marker and
the password of a URL with credentials (``https://user:pw@host``) too.

``normalize_config_xml`` gives a form that is stable across saves of an
unchanged configuration: the XML pretty-printed with two-space indents,
attributes in name order, comments dropped, and the top-level
``<revision>`` (who saved it, when and why: it changes on every save) left
out. ``config_revision`` reads that block for showing it separately.
``drift_text`` is both: what config drift stores and diffs.

All functions are idempotent: masking or normalizing their own output
returns it unchanged, so a stored masked form can be masked again on read.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import re
import xml.etree.ElementTree as ElementTree  # nosec B405 - types and ParseError only; parsing goes through safe_xml

from netcontrol.integrations.safe_xml import DoctypeRefused, parse_xml

MASKED = "[masked]"
_MARKER = re.compile(r"\[masked(?: blob)?(?::[0-9a-f]{8})?\]")

# Element names (compared lower-cased) whose value is always a secret.
SECRET_TAGS: frozenset[str] = frozenset(
    {
        # Local users, CARP/HA sync, PPPoE/PPTP/L2TP, dynamic DNS, monit,
        # SMTP notifications and every other plain password field.
        "password",
        "passwd",
        "pass",
        "pw",
        "pwd",
        "authpass",
        "privpass",
        "smtppassword",
        # Password hashes of the local users.
        "bcrypt-hash",
        "md5-hash",
        "sha512-hash",
        "nt-hash",
        "lm-hash",
        # TOTP seed of a user.
        "otp_seed",
        # API keys (<apikeys><item><key/><secret/>), IPsec MVC PSKs
        # (<preSharedKey><Key/>), OpenVPN static keys, ACME account keys.
        "key",
        "secret",
        "apikey",
        "api_key",
        "api_secret",
        "token",
        "auth_token",
        "access_token",
        # Certificate and CA private keys, WireGuard and IPsec key pairs.
        "prv",
        "privkey",
        "privatekey",
        "private-key",
        "private_key",
        # OpenVPN TLS auth/crypt key and shared (static) key.
        "tls",
        "tlsauth",
        "shared_key",
        "sharedkey",
        "static_key",
        "statickey",
        # IPsec and WireGuard pre-shared keys.
        "psk",
        "pre-shared-key",
        "presharedkey",
        # SNMP communities and SNMPv3 keys.
        "rocommunity",
        "rwcommunity",
        "community",
        "trapcommunity",
        "authkey",
        "enckey",
        # RADIUS and LDAP server secrets.
        "radius_secret",
        "radiussecret",
        "ldap_bindpw",
        "bindpw",
        # DHCP dynamic DNS and DNS TSIG keys.
        "ddnsdomainkey",
        "tsig_secret",
        "tsigkey",
        # Wireless.
        "passphrase",
        "wpa_passphrase",
    }
)

# A name containing one of these holds a secret (unless it describes one).
_SECRET_FRAGMENTS: tuple[str, ...] = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "privkey",
    "privatekey",
    "private_key",
    "private-key",
    "presharedkey",
    "pre-shared-key",
    "pre_shared_key",
    "sharedkey",
    "shared_key",
    "shared-key",
    "psk",
    "community",
    "bindpw",
    "apikey",
    "api_key",
    "api-key",
    "otp_seed",
    "tsig",
)
# A name ending in one of these holds a secret (unless it describes one).
_SECRET_SUFFIXES: tuple[str, ...] = ("key", "-hash", "_hash", "_pass", "-pass", "_pw", "_pwd")
# A name ending in one of these describes a secret rather than holding it.
_DESCRIPTIVE_SUFFIXES: tuple[str, ...] = (
    "type",
    "len",
    "length",
    "size",
    "bits",
    "algo",
    "algorithm",
    "ref",
    "id",
    "name",
    "mode",
    "enable",
    "enabled",
    "expire",
    "expires",
    "expiry",
    "policy",
    "hint",
    "file",
    "format",
    "lifetime",
    "rounds",
    "strength",
    "method",
    "usage",
    "count",
    "interval",
    "timeout",
    "descr",
    "description",
    "url",
    "uri",
    "server",
    "host",
    "port",
    "user",
    "username",
    "login",
    "email",
    "ident",
    # Settings about passwords: <ssh><passwordauth>, a maximum age.
    "auth",
    "age",
    "min",
    "max",
)


def is_secret_tag(tag: str) -> bool:
    """Whether an element of this name holds a secret value."""
    name = tag.rsplit("}", 1)[-1].lower()
    if name in SECRET_TAGS:
        return True
    if "pub" in name or name.endswith(_DESCRIPTIVE_SUFFIXES):
        return False
    return any(f in name for f in _SECRET_FRAGMENTS) or name.endswith(_SECRET_SUFFIXES)


def fingerprint(value: str, key: bytes | None = None) -> str:
    """First 8 hex digits of HMAC-SHA256(key, value), SHA-256 without a key."""
    data = value.encode("utf-8")
    digest = hmac.new(key, data, hashlib.sha256).hexdigest() if key else hashlib.sha256(data).hexdigest()
    return digest[:8]


def _marker(value: str, key: bytes | None, use_fingerprint: bool, *, blob: bool = False) -> str:
    if not use_fingerprint:
        return MASKED
    kind = "masked blob" if blob else "masked"
    return f"[{kind}:{fingerprint(value, key)}]"


# A leaf element: no child elements, its text (CDATA sections allowed) up to
# its own end tag. One character or one CDATA section per step: linear.
_LEAF = re.compile(
    r"<(?P<tag>[A-Za-z_][\w.\-]*)(?P<attrs>\s[^<>]*?)?(?<!/)>"
    r"(?P<value>(?:[^<]|<!\[CDATA\[.*?\]\]>)*)"
    r"</(?P=tag)\s*>",
    re.DOTALL,
)
_CDATA = re.compile(r"<!\[CDATA\[(.*?)\]\]>", re.DOTALL)
# A long base64 or hex value: a certificate, a key, an encoded blob.
_BLOB = re.compile(r"[A-Za-z0-9+/=\s]+")
_BLOB_MIN_CHARS = 64
# bcrypt / crypt(3) hashes anywhere.
_CRYPT_HASH = re.compile(r"\$(?:2[abxy]|1|5|6|y|argon2(?:id|i|d))\$[^\s<\"'&]+")
# The password of a URL with credentials.
_URL_PASSWORD = re.compile(r"(?P<p>\b[a-z][a-z0-9+.\-]*://[^/\s:@<>\"']+:)(?P<v>[^@\s<>\"'/]+)(?=@)", re.IGNORECASE)


def _plain(value: str) -> str:
    """The value as the configuration means it: CDATA unwrapped, entities
    resolved, surrounding whitespace dropped."""
    return html.unescape(_CDATA.sub(lambda m: m.group(1), value)).strip()


def _is_blob(plain: str) -> bool:
    compact = "".join(plain.split())
    return (
        len(compact) >= _BLOB_MIN_CHARS
        and _BLOB.fullmatch(plain) is not None
        and any(c.isdigit() or c in "+/" for c in compact)
        and not compact.isdigit()
    )


def mask_config_xml(
    text: str,
    *,
    key: bytes | None = None,
    fingerprint: bool = True,
    keep_lines: bool = False,
) -> str:
    """Mask every secret in OPNsense ``config.xml`` text (raw, normalized, a
    fragment, or a unified diff of either) and keep everything else as it is.

    ``keep_lines`` keeps the line count: a value spanning several lines
    becomes the marker followed by as many line breaks."""
    if not text:
        return text
    use_fingerprint = fingerprint

    def _leaf(match: re.Match[str]) -> str:
        value = match.group("value")
        plain = _plain(value)
        if not plain or _MARKER.fullmatch(plain):
            return match.group(0)
        if is_secret_tag(match.group("tag")):
            replacement = _marker(plain, key, use_fingerprint)
        elif _is_blob(plain):
            replacement = _marker(plain, key, use_fingerprint, blob=True)
        else:
            return match.group(0)
        if keep_lines:
            replacement += "\n" * value.count("\n")
        tag = match.group("tag")
        return f"<{tag}{match.group('attrs') or ''}>{replacement}</{tag}>"

    out = _LEAF.sub(_leaf, text)
    out = _CRYPT_HASH.sub(lambda m: _marker(m.group(0), key, use_fingerprint), out)
    return _URL_PASSWORD.sub(
        lambda m: (
            m.group(0)
            if _MARKER.fullmatch(m.group("v"))
            else m.group("p") + _marker(m.group("v"), key, use_fingerprint)
        ),
        out,
    )


# ── Normalization ────────────────────────────────────────────────────────────

_ROOTS = ("opnsense", "pfsense")
_LOOKS_LIKE = re.compile(
    r"\A﻿?\s*(?:<\?xml[^>]*\?>\s*)?(?:<!--.*?-->\s*)*<(?:" + "|".join(_ROOTS) + r")[\s>/]",
    re.DOTALL | re.IGNORECASE,
)
_SNIFF_CHARS = 4096


def looks_like_config_xml(text: str | None) -> bool:
    """Whether the text is an OPNsense (or pfSense) ``config.xml``."""
    return bool(text) and _LOOKS_LIKE.match(str(text)[:_SNIFF_CHARS]) is not None


def _top_revision(root: ElementTree.Element) -> ElementTree.Element | None:
    return next((child for child in root if child.tag == "revision"), None)


def _without_revision_text(text: str) -> str:
    """``text`` with its first ``<revision>`` block, the blanks before it and
    the line break after it taken out (for a config that does not parse)."""
    start = text.find("<revision>")
    end = text.find("</revision>", start) if start >= 0 else -1
    if end < 0:
        return text
    end += len("</revision>")
    while start and text[start - 1] in " \t":
        start -= 1
    while end < len(text) and text[end] in " \t":
        end += 1
    if text.startswith("\r", end):
        end += 1
    if text.startswith("\n", end):
        end += 1
    return text[:start] + text[end:]


def _parse(text: str) -> ElementTree.Element | None:
    body = text.lstrip("﻿")
    # A str with an encoding declaration is parsed as the str it is.
    body = re.sub(r"\A\s*<\?xml[^>]*\?>", "", body, count=1)
    try:
        return parse_xml(body)
    except DoctypeRefused, ElementTree.ParseError:
        return None


def normalize_config_xml(text: str) -> str:
    """The stable form of a ``config.xml`` (see the module docstring). Text
    that is not one is returned unchanged; one that does not parse has only
    its ``<revision>`` block taken out."""
    if not looks_like_config_xml(text):
        return text
    root = _parse(text)
    if root is None:
        return _without_revision_text(text)
    revision = _top_revision(root)
    if revision is not None:
        root.remove(revision)
    for element in root.iter():
        if len(element.attrib) > 1:
            items = sorted(element.attrib.items())
            element.attrib.clear()
            element.attrib.update(items)
    ElementTree.indent(root, space="  ")
    return '<?xml version="1.0"?>\n' + ElementTree.tostring(root, encoding="unicode") + "\n"


def config_revision(text: str) -> dict[str, str]:
    """The top-level ``<revision>`` of a ``config.xml``: ``time`` (epoch
    seconds as written), ``username`` and ``description``; empty when the
    text has none."""
    if not looks_like_config_xml(text):
        return {}
    root = _parse(text)
    revision = _top_revision(root) if root is not None else None
    if revision is None:
        return {}
    return {
        field: (revision.findtext(field) or "").strip()
        for field in ("time", "username", "description")
        if (revision.findtext(field) or "").strip()
    }


def drift_text(text: str, *, key: bytes | None = None) -> str:
    """Normalized and masked: what config drift stores and compares."""
    return mask_config_xml(normalize_config_xml(text), key=key)
