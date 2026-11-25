"""What counts as a secret-bearing key name: one definition for the log
redaction (``netcontrol.telemetry``) and the masking of MCP tool results
(``netcontrol.mcp.redact``).

A key is secret-bearing when, lower-cased with ``_``, ``-`` and spaces
removed, it holds one of ``SECRET_KEY_FRAGMENTS`` (``api_key``,
``SNMP_Community``, ``privateKey``, ``routing_key``, ``credentials``).

A key whose last word only names or references a secret is not:
``credential_id``, ``token_count``, ``community_list``,
``secret_variables``, ``password_enabled``. Those values are ids, counts,
names of a feature or flags, and the reader needs them. Two exceptions:
``secret_id`` is a secret itself (the Vault AppRole credential), and a
stored credential's ``credential_name`` and ``credential_source`` are
references although ``community_name`` is the community.

``should_mask`` adds the value rules both callers share: a boolean, ``None``
or an empty string is kept (``has_password: true`` still reads), and a list
or mapping under a name that ends in a collection word is masked whole
(``community_list: [...]`` may hold the communities themselves, while
``credential_id: {"before": 1, "after": 2}`` is still a pair of ids).

This module imports nothing from Plexus: the logging setup imports it,
and almost everything imports the logging setup.
"""

from __future__ import annotations

import re
from typing import Any

# The words of a secret key name; a space marks where a separator may stand
# (``api key`` matches ``api_key``, ``api-key``, ``apikey`` and ``apiKey``).
SECRET_KEY_WORDS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "secret key",
    "token",
    "api key",
    "authorization",
    "community",
    "psk",
    "private key",
    "priv key",
    "auth key",
    "passphrase",
    "routing key",
    "credential",
    # The LDAP bind password and a webhook's auth header value.
    "bind pw",
    "auth value",
)

# Compared against the key lower-cased with "_", "-" and spaces removed.
SECRET_KEY_FRAGMENTS: tuple[str, ...] = tuple(word.replace(" ", "") for word in SECRET_KEY_WORDS)

# The fragments as one regular expression for free text, with an optional
# "_" or "-" where the words allow a separator (``api[_-]?key``).
SECRET_KEY_REGEX = "(?:" + "|".join(word.replace(" ", "[_-]?") for word in SECRET_KEY_WORDS) + ")"

# Last words that make a key a reference to a secret, not the secret.
REFERENCE_WORDS: frozenset[str] = frozenset(
    {
        "id",
        "ids",
        "uuid",
        "ref",
        "refs",
        "count",
        "length",
        "list",
        "lists",
        "variables",
        "enabled",
        "configured",
        "set",
        "type",
        "file",
        "path",
    }
)

# Last words that make a "credential" key a reference to a stored credential
# (``credential_name``). Not for the other names: ``community_name`` is the
# community itself.
CREDENTIAL_REFERENCE_WORDS: frozenset[str] = frozenset({"name", "names", "source"})

# Keys that end in a reference word and are secrets all the same, compared
# compact: the Vault AppRole ``secret_id`` is the credential, not an id of one.
SECRET_DESPITE_REFERENCE: tuple[str, ...] = ("secretid",)

# Reference words that name a collection: a list or mapping stored under
# such a key can be the secrets themselves, so it gets no exception.
COLLECTION_WORDS: frozenset[str] = frozenset({"list", "lists", "variables"})

_CONTAINERS = (dict, list, tuple, set, frozenset)

_KEY_SEPARATORS = str.maketrans("", "", "_- ")
# Words of a key: snake, kebab and camel case ("credentialId" -> credential, Id).
_KEY_WORDS = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")


def compact_key(key: object) -> str:
    """``key`` lower-cased with ``_``, ``-`` and spaces removed."""
    return str(key).lower().translate(_KEY_SEPARATORS)


def is_secret_key(key: object, fragments: tuple[str, ...] = SECRET_KEY_FRAGMENTS) -> bool:
    """Whether a value stored under ``key`` is a secret (see the module
    docstring). ``fragments`` lets a caller add names of its own."""
    text = str(key)
    compact = compact_key(text)
    matched = [fragment for fragment in fragments if fragment in compact]
    if not matched:
        return False
    if compact.endswith(SECRET_DESPITE_REFERENCE):
        return True
    words = _KEY_WORDS.findall(text)
    if len(words) < 2:
        return True
    last = words[-1].lower()
    if last in REFERENCE_WORDS:
        return False
    return not (last in CREDENTIAL_REFERENCE_WORDS and matched == ["credential"])


def should_mask(key: object, value: Any, fragments: tuple[str, ...] = SECRET_KEY_FRAGMENTS) -> bool:
    """Whether ``value`` under ``key`` is replaced whole: a secret key name
    with a value other than a boolean, ``None`` or an empty string. A list
    or mapping under a collection word (``community_list``) gets no
    reference-word exception."""
    if value is None or isinstance(value, bool) or value == "":
        return False
    if isinstance(value, _CONTAINERS):
        words = _KEY_WORDS.findall(str(key))
        if words and words[-1].lower() in COLLECTION_WORDS:
            compact = compact_key(key)
            return any(fragment in compact for fragment in fragments)
    return is_secret_key(key, fragments)
