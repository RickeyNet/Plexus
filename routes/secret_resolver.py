"""
secret_resolver.py - Resolve {{secret.NAME}} placeholders in template commands.

Fetches encrypted values from the secret_variables table, decrypts them
(or resolves their external reference through a secrets provider, see
netcontrol/secrets_providers), and substitutes into command strings at job
execution time.  Plaintext values are never stored in templates, job
events, or logs.
"""

import base64
import re
from urllib.parse import quote, quote_plus

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
) -> list[str]:
    """Replace ``{{secret.NAME}}`` placeholders with decrypted values.

    Parameters
    ----------
    template_commands:
        Raw command lines (may contain ``{{secret.NAME}}`` tokens).
    redact:
        If True, replace values with ``********`` instead of the real
        plaintext.  Used for dry-run / audit display.

    Returns
    -------
    list[str]
        Commands with secrets substituted (or redacted).

    Raises
    ------
    SecretResolutionError
        If any referenced secret variable does not exist in the store.
    """
    # Fast path - nothing to resolve
    names = extract_secret_names(template_commands)
    if not names:
        return list(template_commands)

    # Bulk-fetch all referenced secrets in one query
    secrets_map: dict[str, str] = {}
    for name in names:
        row = await db.get_secret_variable_by_name(name)
        if row is None:
            continue
        if redact:
            secrets_map[name] = "********"
            continue
        value = await _plaintext(row)
        if value is not None:
            secrets_map[name] = value

    # Check for missing references
    missing = sorted(names - set(secrets_map.keys()))
    if missing:
        raise SecretResolutionError(missing)

    # Perform substitution
    resolved: list[str] = []
    for line in template_commands:

        def _replace(m: re.Match) -> str:
            return secrets_map[m.group(1)]

        resolved.append(_SECRET_RE.sub(_replace, line))
    return resolved


def redact_secrets_in_text(text: str) -> str:
    """Replace any {{secret.*}} tokens with ******** for safe logging."""
    return _SECRET_ANY_RE.sub("********", text)


async def build_redaction_set(template_commands: list[str]) -> set[str]:
    """Return the set of decrypted secret values referenced in *template_commands*.

    Used to scrub job output logs so plaintext secrets never reach the DB
    or WebSocket subscribers. Raises ``SecretResolutionError`` for an
    external secret that cannot be resolved: a value missing here would
    not be scrubbed if a later resolution succeeded.
    """
    names = extract_secret_names(template_commands)
    if not names:
        return set()
    values: set[str] = set()
    failed: list[str] = []
    for name in names:
        row = await db.get_secret_variable_by_name(name)
        if row:
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


def redaction_forms(value: str) -> set[str]:
    """``value`` and the common encodings a device or command may print it
    in: base64 (standard and URL-safe, with and without padding), URL
    encoding (``%20`` and ``+`` for spaces) and hex. Forms shorter than
    ``MIN_REDACT_LENGTH`` are left out; empty for a value that short."""
    if len(value) < MIN_REDACT_LENGTH:
        return set()
    raw = value.encode("utf-8")
    forms = {value, quote(value, safe=""), quote(value), quote_plus(value), raw.hex(), raw.hex().upper()}
    for encoded in (base64.b64encode(raw).decode("ascii"), base64.urlsafe_b64encode(raw).decode("ascii")):
        forms.update((encoded, encoded.rstrip("=")))
    return {form for form in forms if len(form) >= MIN_REDACT_LENGTH}


def redact_values(text: str, secret_values: set[str]) -> str:
    """Replace each secret value, and its common encodings
    (``redaction_forms``), with ********. Best effort: a value the device
    transforms otherwise (wrapped, re-encoded inside a longer blob, hashed)
    is not recognized."""
    forms: set[str] = set()
    for val in secret_values:
        forms |= redaction_forms(val)
    # Longest first, so a form that contains another is masked whole.
    for form in sorted(forms, key=len, reverse=True):
        text = text.replace(form, "********")
    return text
