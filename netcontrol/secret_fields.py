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
host they control and have Plexus present the secret there.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping
from typing import Any

SECRET_MASK = "••••••••"


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
