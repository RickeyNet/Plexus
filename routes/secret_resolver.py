"""
secret_resolver.py - Resolve {{secret.NAME}} placeholders in template commands.

Fetches encrypted values from the secret_variables table, decrypts them
(or resolves their external reference through a secrets provider, see
netcontrol/secrets_providers), and substitutes into command strings at job
execution time.  Plaintext values are never stored in templates, job
events, or logs.
"""

import base64
import json
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote, quote_plus

from fastapi import HTTPException

import routes.database as db

# Matches {{secret.variable_name}} - name allows alphanumeric, underscore, hyphen
_SECRET_RE = re.compile(r"\{\{\s*secret\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}")

# Matches any {{secret.*}} reference (used for validation / detection).
# Bounded quantifiers prevent regex DoS on attacker-controlled input.
_SECRET_ANY_RE = re.compile(r"\{\{ {0,8}secret\.[^}\s]{1,128} {0,8}\}\}")

# Inputs longer than this are not scanned (defense in depth against ReDoS).
_MAX_SCAN_LEN = 1_000_000


class SecretResolutionError(Exception):
    """Raised when one or more secret references cannot be resolved."""

    def __init__(self, missing: list[str]):
        self.missing = missing
        super().__init__(f"Unresolved secret variable(s): {', '.join(missing)}")


async def _plaintext(row: dict) -> str | None:
    """The value of a secret variable row, or None when its external
    reference cannot be resolved (the failure is audited by the provider
    service)."""
    from netcontrol.secrets_providers.service import SecretsProviderError, secret_variable_plaintext

    try:
        return await secret_variable_plaintext(row)
    except SecretsProviderError:
        return None


# Role and access group ids of the user a secret is resolved for; ``None``
# is a system caller (unattended polling), to which no rule applies.
SecretUser = tuple[str, list[int]] | None


def secret_rule(raw: object) -> dict:
    """A secret variable's stored ``usable_by`` as a ``{"roles", "groups"}``
    rule (``netcontrol.job_inputs.normalize_rule``); empty is open (every
    user who may run the job). A stored value that no longer validates
    reads as admins only, so a damaged rule never opens a secret up."""
    from netcontrol.job_inputs import JobInputError, normalize_rule

    try:
        return normalize_rule(raw, "usable_by")
    except JobInputError:
        return {"roles": ["admin"], "groups": []}


def may_use_secret(row: dict, user: SecretUser) -> bool:
    """Whether ``user`` may have the secret variable ``row`` resolved: always
    for a system caller (``None``), else by its ``usable_by`` rule (admins
    always pass)."""
    if user is None:
        return True
    from netcontrol.job_inputs import rule_allows

    role, group_ids = user
    return rule_allows(secret_rule(row.get("usable_by")), role=role, group_ids=group_ids)


async def saving_user(request: Any) -> SecretUser:
    """The (role, access group ids) of the user saving text through
    ``request``, for ``require_usable_secret_references``. The server API
    token is admin-equivalent; a request without a session passes open
    rules only. ``None`` (no rule) only when there is no request at all,
    which is an internal call."""
    if request is None:
        return None
    from netcontrol.job_inputs import user_permissions
    from netcontrol.routes.shared import request_session

    session = request_session(request)
    if session is None:
        return ("", [])
    if session.get("auth_mode") == "token":
        return ("admin", [])
    return await user_permissions(session)


async def refused_secret_references(texts: Iterable[str], user: SecretUser, *, names: Iterable[str] = ()) -> list[str]:
    """The secret variables referenced in ``texts`` as ``{{secret.NAME}}``
    (the parser ``resolve_secrets`` substitutes with), plus the bare
    ``names``, that ``user`` cannot have resolved; sorted. As when a job is
    launched, a name that does not exist and one whose ``usable_by`` rule
    refuses ``user`` read the same, so the answer does not tell which
    restricted names exist. An admin (and a system caller) passes every
    rule and may name a secret that is yet to be created."""
    if user is None or user[0] == "admin":
        return []
    wanted = extract_secret_names([t for t in texts if isinstance(t, str)])
    wanted |= {n for n in names if isinstance(n, str) and n}
    refused: list[str] = []
    for name in sorted(wanted):
        row = await db.get_secret_variable_by_name(name)
        if row is None or not may_use_secret(row, user):
            refused.append(name)
    return refused


async def require_usable_secret_references(request: Any, texts: Iterable[str], *, names: Iterable[str] = ()) -> None:
    """Refuse (403) saving text that references a secret variable the saving
    user may not use. Templates, input defaults and SNMP profiles are later
    resolved for whoever runs them (an admin passes every rule), so the
    author of the text must be allowed to use each secret it names too.
    Admins and the API token pass. The names in the message are the ones
    the caller sent; it does not say whether they exist."""
    refused = await refused_secret_references(texts, await saving_user(request), names=names)
    if refused:
        raise HTTPException(
            403,
            f"Secret variable(s) {', '.join(refused)} do not exist or are not usable by you: "
            "text that references a secret can be saved only by a user who may use it",
        )


def normalize_secret_name(name: str) -> str:
    """Reduce a pasted reference to the bare secret name.

    Users often paste the template reference (``{{secret.NAME}}``) or the
    dotted form (``secret.NAME``) into the name field. Both are reduced to
    ``NAME``; anything else is returned stripped and unchanged so the caller's
    validation can reject it.
    """
    name = (name or "").strip()
    if name.startswith("{{") and name.endswith("}}"):
        name = name[2:-2].strip()
    if name.startswith("secret."):
        name = name[len("secret.") :]
    return name.strip()


def has_secret_references(text: str) -> bool:
    """Return True if *text* contains any {{secret.*}} placeholders."""
    if not text or len(text) > _MAX_SCAN_LEN:
        return False
    return bool(_SECRET_ANY_RE.search(text))


def extract_secret_names(lines: list[str]) -> set[str]:
    """Return the set of secret variable names referenced in *lines*."""
    names: set[str] = set()
    for line in lines:
        names.update(_SECRET_RE.findall(line))
    return names


async def resolve_secrets(
    template_commands: list[str],
    *,
    redact: bool = False,
    user: SecretUser = None,
) -> list[str]:
    """Replace ``{{secret.NAME}}`` placeholders with decrypted values.

    Parameters
    ----------
    template_commands:
        Raw command lines (may contain ``{{secret.NAME}}`` tokens).
    redact:
        If True, replace values with ``********`` instead of the real
        plaintext.  Used for dry-run / audit display.
    user:
        The (role, access group ids) the secrets are resolved for. A secret
        whose ``usable_by`` rule does not allow them is reported as missing,
        so a caller cannot tell it from one that does not exist. ``None``
        (the default) is a system caller and applies no rule.

    Returns
    -------
    list[str]
        Commands with secrets substituted (or redacted).

    Raises
    ------
    SecretResolutionError
        If any referenced secret variable does not exist in the store (or
        may not be used by ``user``).
    """
    # Fast path - nothing to resolve
    names = extract_secret_names(template_commands)
    if not names:
        return list(template_commands)
    secrets_map = await _usable_values(names, user, redact=redact)
    return _substitute(template_commands, secrets_map)


async def _usable_values(names: set[str], user: SecretUser, *, redact: bool = False) -> dict[str, str]:
    """Each of ``names`` mapped to its value (``********`` with ``redact``),
    fetched once. Raises ``SecretResolutionError`` naming those that do not
    exist, that ``user`` may not use, or whose external reference failed."""
    secrets_map: dict[str, str] = {}
    for name in names:
        row = await db.get_secret_variable_by_name(name)
        if row is None or not may_use_secret(row, user):
            continue
        if redact:
            secrets_map[name] = "********"
            continue
        value = await _plaintext(row)
        if value is not None:
            secrets_map[name] = value
    missing = sorted(names - set(secrets_map.keys()))
    if missing:
        raise SecretResolutionError(missing)
    return secrets_map


def _substitute(lines: list[str], secrets_map: dict[str, str]) -> list[str]:
    def _replace(m: re.Match) -> str:
        return secrets_map[m.group(1)]

    return [_SECRET_RE.sub(_replace, line) for line in lines]


async def resolve_secret_bodies(
    bodies: list[list[str]], *, user: SecretUser = None
) -> tuple[list[list[str]], set[str]]:
    """``resolve_secrets`` for several command bodies at once, returning the
    resolved bodies (same order) and the values to scrub from the job log.

    Each secret is fetched once and the values to scrub are exactly the ones
    substituted, so a provider value that changes between two fetches can
    never be pushed without also being scrubbed. Raises
    ``SecretResolutionError`` as ``resolve_secrets`` does."""
    names: set[str] = set()
    for body in bodies:
        names |= extract_secret_names(body)
    if not names:
        return [list(body) for body in bodies], set()
    secrets_map = await _usable_values(names, user)
    return [_substitute(body, secrets_map) for body in bodies], {v for v in secrets_map.values() if v}


def redact_secrets_in_text(text: str) -> str:
    """Replace any {{secret.*}} tokens with ******** for safe logging."""
    return _SECRET_ANY_RE.sub("********", text)


async def build_redaction_set(template_commands: list[str], *, user: SecretUser = None) -> set[str]:
    """Return the set of decrypted secret values referenced in *template_commands*.

    Used to scrub output so plaintext secrets never reach the DB or
    WebSocket subscribers. A caller that also substitutes the values uses
    ``resolve_secret_bodies`` instead (one fetch for both). Raises ``SecretResolutionError`` for an
    external secret that cannot be resolved: a value missing here would
    not be scrubbed if a later resolution succeeded. A secret ``user`` may
    not use (``resolve_secrets``) is skipped like a missing one: it is not
    decrypted, and ``resolve_secrets`` refuses it.
    """
    names = extract_secret_names(template_commands)
    if not names:
        return set()
    values: set[str] = set()
    failed: list[str] = []
    for name in names:
        row = await db.get_secret_variable_by_name(name)
        if row and may_use_secret(row, user):
            val = await _plaintext(row)
            if val is None:
                failed.append(name)
            elif val:  # don't add empty strings to the redaction set
                values.add(val)
    if failed:
        raise SecretResolutionError(sorted(failed))
    return values


# Secret values shorter than this are not scrubbed from job output: masking a
# one to three character string would blank every "1", "ab" or "on" in the
# log while protecting nothing (a value that short is guessable anyway).
MIN_REDACT_LENGTH = 4


REDACTION_MASK = "********"


def redaction_forms(value: str) -> set[str]:
    """``value`` and the common encodings a device or command may print it
    in: base64 (standard and URL-safe, with and without padding), URL
    encoding (``%20`` and ``+`` for spaces), hex, JSON string escaping
    (ASCII-only and not) and backslash escaping. A multi-line value (a key
    or certificate) also gives each of its lines, as a device echoes it one
    line at a time. Forms shorter than ``MIN_REDACT_LENGTH`` are left out;
    empty for a value that short. Matching ignores letter case
    (``SecretScrubber``)."""
    if len(value) < MIN_REDACT_LENGTH:
        return set()
    raw = value.encode("utf-8")
    forms = {value, quote(value, safe=""), quote(value), quote_plus(value), raw.hex(), raw.hex().upper()}
    for encoded in (base64.b64encode(raw).decode("ascii"), base64.urlsafe_b64encode(raw).decode("ascii")):
        forms.update((encoded, encoded.rstrip("=")))
    forms.add(json.dumps(value)[1:-1])
    forms.add(json.dumps(value, ensure_ascii=False)[1:-1])
    forms.add(value.replace("\\", "\\\\").replace('"', '\\"'))
    if "\n" in value or "\r" in value:
        forms.update(line.strip() for line in value.splitlines())
    return {form for form in forms if len(form) >= MIN_REDACT_LENGTH}


class SecretScrubber:
    """Masks secret values (``redaction_forms``, any letter case) in the
    output of one job. Best effort: a value the device transforms otherwise
    (wrapped, re-encoded inside a longer blob, hashed) is not recognized.

    Build one per job, so the forms are computed once. ``scrub`` masks one
    text on its own. ``feed`` masks a stream of event messages in order: a
    message that ends in the first characters of a form (one or more, fewer
    than the whole form) has that trailing fragment held back and put in
    front of the next message, so no part of a value split across two
    events is shown; ``flush`` returns what is held when the job ends.
    Output that ends in no such fragment is returned whole."""

    def __init__(self, secret_values: Iterable[str]):
        forms: set[str] = set()
        for val in secret_values:
            if val:
                forms |= redaction_forms(val)
        # Longest first, so a form that contains another is masked whole.
        lowered = sorted({form.lower() for form in forms}, key=len, reverse=True)
        self._pattern = re.compile("|".join(re.escape(f) for f in lowered), re.IGNORECASE) if lowered else None
        self._by_first: dict[str, list[str]] = {}
        for form in lowered:
            self._by_first.setdefault(form[0], []).append(form)
        self._longest = len(lowered[0]) if lowered else 0
        self._held = ""

    def scrub(self, text: str) -> str:
        if self._pattern is None or not text:
            return text
        return self._pattern.sub(REDACTION_MASK, text)

    def feed(self, text: str) -> str:
        """The part of ``text`` (after what was held) that can be shown now."""
        if self._pattern is None:
            return text
        # Every trailing fragment that may begin a form was held, so no form
        # can start in text already returned: scrubbing held + text is enough.
        scrubbed = self.scrub(self._held + text)
        cut = self._partial_start(scrubbed)
        self._held = scrubbed[cut:]
        return scrubbed[:cut]

    def flush(self) -> str:
        """What ``feed`` holds back (the start of a form that never
        completed); empty when nothing is held."""
        held, self._held = self._held, ""
        return held

    def _partial_start(self, text: str) -> int:
        """Where the longest trailing fragment of ``text`` that starts a
        form (and is not the whole form) begins; ``len(text)`` when there is
        none. At most ``longest form - 1`` characters are held."""
        end = len(text)
        for start in range(max(0, end - self._longest + 1), end):
            candidates = self._by_first.get(text[start].lower())
            if not candidates:
                continue
            fragment = text[start:].lower()
            if any(len(form) > len(fragment) and form.startswith(fragment) for form in candidates):
                return start
        return end


def redact_values(text: str, secret_values: set[str]) -> str:
    """Replace each secret value, and its common encodings
    (``redaction_forms``, any letter case), with ********. Best effort, one
    text on its own; job output goes through one ``SecretScrubber`` per job,
    which also catches a value split across two events."""
    return SecretScrubber(secret_values).scrub(text)
