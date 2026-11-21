"""Write-only secret fields in API payloads: masking on read, keep-on-mask
on write, and the rule that a stored secret is not reused for a new
destination.

``mask_secret_fields`` and ``merge_secret_fields`` work on dotted paths
(``"v3.auth_password"``) into nested dicts, so one call covers a settings
object whatever its shape. The mask is the same ``••••••••`` the auth
config and notification channel APIs show.

``refuse_secret_reuse`` is the "address changed, re-enter the credential"
rule: when a field that decides where a secret is sent (host, URL, port,
scheme, TLS verification, CA bundle) changes, a stored secret may not be
kept unless the same request sends it again. Without it, a caller who may
edit the settings but not read the secret can point the integration at a
host they control and have Plexus present the secret there. Every
"blank keeps the stored secret" update path calls it (federation peers,
topology sources, notification channels, SIEM sinks, event webhooks, the
RADIUS/TACACS+/LDAP/OIDC settings, secrets providers); ``url_origin`` turns
a URL into the scheme/host/port it is compared by, so a path change alone
does not count.

``seal_secret_paths`` / ``open_secret_paths`` encrypt and decrypt the
secrets at dotted paths (``*`` matches every item of a list or every value
of a dict) of a settings object stored as JSON; ``routes.db.users`` uses
them for ``auth_settings`` rows.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit

SECRET_MASK = "••••••••"

# The secret fields of the settings objects kept in ``auth_settings`` rows,
# named once: the API modules mask and merge by them, and ``routes.db.users``
# encrypts them at rest (``AUTH_SETTING_SECRET_PATHS``).
#: An SNMP profile (named, a group's discovery profile, or the global one).
SNMP_SECRET_FIELDS = ("community", "v3.auth_password", "v3.priv_password")
#: A SIEM sink.
SIEM_SINK_SECRET_FIELDS = ("bearer_token", "tls_client_key_pem")
#: A notification channel.
NOTIFICATION_CHANNEL_SECRET_FIELDS = ("smtp_password", "routing_key", "webhook_auth_value")


def _get(obj: Mapping, path: str) -> Any:
    node: Any = obj
    for part in path.split("."):
        if not isinstance(node, Mapping):
            return None
        node = node.get(part)
    return node


def _set(obj: dict, path: str, value: Any) -> None:
    *parents, leaf = path.split(".")
    node = obj
    for part in parents:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[leaf] = value


def mask_secret_fields(obj: Mapping, paths: Iterable[str]) -> dict:
    """A deep copy of ``obj`` with each set secret at ``paths`` replaced by
    ``SECRET_MASK`` (an empty one stays empty, so the form shows it unset)."""
    out = copy.deepcopy(dict(obj))
    for path in paths:
        if _get(out, path):
            _set(out, path, SECRET_MASK)
    return out


def merge_secret_fields(new: Mapping, stored: Mapping | None, paths: Iterable[str]) -> dict:
    """A deep copy of ``new`` where each secret at ``paths`` that is the mask
    or left out takes the ``stored`` value. An explicit ``""`` clears it."""
    out = copy.deepcopy(dict(new))
    for path in paths:
        value = _get(out, path)
        if value is None or value == SECRET_MASK:
            _set(out, path, _get(stored or {}, path) or "")
    return out


def destination_changes(old: Mapping | None, new: Mapping, fields: Iterable[str]) -> list[str]:
    """The ``fields`` (dotted paths) whose value differs between the stored
    settings ``old`` and the submitted ``new``. With no ``old`` (a create),
    nothing changed: there is no stored secret to protect."""
    if old is None:
        return []
    return [f for f in fields if _get(old, f) != _get(new, f)]


def refuse_secret_reuse(
    old: Mapping | None,
    new: Mapping,
    destination_fields: Iterable[str],
    *,
    stored: Iterable[str],
    resent: Iterable[str],
) -> None:
    """Raise ``ValueError`` when a destination field changed and a stored
    secret (names in ``stored``) is not in ``resent`` (the secrets this
    request sends again). The message names the changed fields and the
    secrets to enter again, never a value."""
    changed = destination_changes(old, new, destination_fields)
    if not changed:
        return
    resent_set = set(resent)
    missing = sorted(s for s in stored if s not in resent_set)
    if missing:
        raise ValueError(
            f"{', '.join(changed)} changed, so the stored {', '.join(missing)} cannot be reused: "
            f"enter {', '.join(missing)} again"
        )


_DEFAULT_PORTS = {"http": 80, "https": 443, "ldap": 389, "ldaps": 636}


def url_origin(url: Any) -> str:
    """``scheme://host:port`` of ``url``, lower-cased, with the default port
    filled in: what decides where a request goes. ``""`` for no URL."""
    text = str(url or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return text.lower()
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    return f"{scheme}://{host}:{port or _DEFAULT_PORTS.get(scheme, '')}"


def compared_tls_verify(old: Any, new: Any) -> bool:
    """The TLS-verification value of the submitted settings as
    ``refuse_secret_reuse`` should compare it: turning verification off
    counts as a change, turning it on does not (it only makes the secret
    safer), so the new value is taken as the old one then."""
    return bool(old) if new else False


# ── Secrets at rest inside a JSON settings object ────────────────────────────

# A sealed secret is stored as {SEALED_KEY: "<ciphertext>"}: a plain legacy
# value is always a string, so the two can never be confused.
SEALED_KEY = "__enc__"


def _walk(node: Any, parts: list[str], fn: Callable[[Any], Any]) -> None:
    head, rest = parts[0], parts[1:]
    if head == "*":
        if isinstance(node, list):
            keys: Iterable[Any] = range(len(node))
        elif isinstance(node, dict):
            keys = list(node.keys())
        else:
            return
    elif isinstance(node, dict) and head in node:
        keys = [head]
    else:
        return
    for key in keys:
        if rest:
            _walk(node[key], rest, fn)
        else:
            node[key] = fn(node[key])


def map_secret_paths(obj: Any, paths: Iterable[str], fn: Callable[[Any], Any]) -> Any:
    """A deep copy of ``obj`` with ``fn`` applied to the value at each dotted
    path (``*`` = every list item or dict value). Missing paths are skipped."""
    out = copy.deepcopy(obj)
    for path in paths:
        _walk(out, path.split("."), fn)
    return out


def is_sealed(value: Any) -> bool:
    return isinstance(value, dict) and set(value) == {SEALED_KEY} and isinstance(value[SEALED_KEY], str)


def seal_secret_paths(obj: Any, paths: Iterable[str], encrypt: Callable[[str], str]) -> Any:
    """``obj`` with each non-empty string secret at ``paths`` encrypted into
    ``{SEALED_KEY: ciphertext}``. Already sealed values are kept."""

    def seal(value: Any) -> Any:
        if isinstance(value, str) and value:
            return {SEALED_KEY: encrypt(value)}
        return value

    return map_secret_paths(obj, paths, seal)


def open_secret_paths(obj: Any, paths: Iterable[str], decrypt: Callable[[str], str]) -> Any:
    """``obj`` with each sealed secret at ``paths`` decrypted. A legacy plain
    string is returned as it is. A value that cannot be decrypted (the key
    changed) becomes ``""``: the secret is unusable, and the ciphertext is
    never handed on as if it were the secret."""

    def unseal(value: Any) -> Any:
        if not is_sealed(value):
            return value
        try:
            return decrypt(value[SEALED_KEY])
        except Exception:  # noqa: BLE001 - any failure means the secret is gone
            return ""

    return map_secret_paths(obj, paths, unseal)


def has_plain_secret(obj: Any, paths: Iterable[str]) -> bool:
    """Whether a non-empty secret at ``paths`` is still stored in plain text."""
    found = False

    def check(value: Any) -> Any:
        nonlocal found
        if isinstance(value, str) and value:
            found = True
        return value

    map_secret_paths(obj, paths, check)
    return found
