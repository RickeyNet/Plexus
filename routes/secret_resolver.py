"""
secret_resolver.py — Resolve {{secret.NAME}} placeholders in template commands.

Fetches encrypted values from the secret_variables table, decrypts them,
and substitutes into command strings at job execution time.  Plaintext
values are never stored in templates, job events, or logs.
"""

import re

import routes.database as db
from routes.crypto import decrypt

# Matches {{secret.variable_name}} — name allows alphanumeric, underscore, hyphen
_SECRET_RE = re.compile(r"\{\{\s*secret\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}")

# Matches any {{secret.*}} reference (used for validation / detection)
_SECRET_ANY_RE = re.compile(r"\{\{\s*secret\.[^}]*\}\}")


class SecretResolutionError(Exception):
    """Raised when one or more secret references cannot be resolved."""

    def __init__(self, missing: list[str]):
        self.missing = missing
        super().__init__(f"Unresolved secret variable(s): {', '.join(missing)}")


def has_secret_references(text: str) -> bool:
    """Return True if *text* contains any {{secret.*}} placeholders."""
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
    # Fast path — nothing to resolve
    names = extract_secret_names(template_commands)
    if not names:
        return list(template_commands)

    # Bulk-fetch all referenced secrets in one query
    secrets_map: dict[str, str] = {}
    for name in names:
        row = await db.get_secret_variable_by_name(name)
        if row is not None:
            secrets_map[name] = "********" if redact else decrypt(row["enc_value"])

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
    or WebSocket subscribers.
    """
    names = extract_secret_names(template_commands)
    if not names:
        return set()
    values: set[str] = set()
    for name in names:
        row = await db.get_secret_variable_by_name(name)
        if row:
            val = decrypt(row["enc_value"])
            if val:  # don't add empty strings to the redaction set
                values.add(val)
    return values


def redact_values(text: str, secret_values: set[str]) -> str:
    """Replace any occurrence of known secret values with ********."""
    for val in secret_values:
        text = text.replace(val, "********")
    return text
