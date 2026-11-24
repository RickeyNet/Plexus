"""Rules for account names and local passwords.

One place for every path that creates or renames an account or sets a local
password: admin user management, self-registration, the change-password
form and the accounts an external sign-in creates.
"""

from __future__ import annotations

from netcontrol.sso import CONTROL_CHARS, USERNAME_MAX_LENGTH

# Username the server API token acts as (``require_auth``). Objects it
# creates are stored under this owner name, so no account may carry it.
API_TOKEN_USER = "api-token"

# Names no account may take, compared without regard to case.
RESERVED_USERNAMES = frozenset({API_TOKEN_USER})

USERNAME_MIN_LENGTH = 3
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 256


def is_reserved_username(username: str) -> bool:
    return username.strip().lower() in RESERVED_USERNAMES


def username_problem(username: str) -> str | None:
    """Why ``username`` (already trimmed) cannot be an account name, or
    ``None``. Uniqueness is the caller's check (it needs the database)."""
    if len(username) < USERNAME_MIN_LENGTH:
        return f"Username must be at least {USERNAME_MIN_LENGTH} characters"
    if len(username) > USERNAME_MAX_LENGTH:
        return f"Username must be at most {USERNAME_MAX_LENGTH} characters"
    if CONTROL_CHARS.search(username):
        return "Username must not contain control characters or line breaks"
    if is_reserved_username(username):
        return "This username is reserved"
    return None


def password_problem(password: str, username: str = "") -> str | None:
    """Why ``password`` cannot be the local password of ``username``, or
    ``None``."""
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters"
    if len(password) > PASSWORD_MAX_LENGTH:
        return f"Password must be at most {PASSWORD_MAX_LENGTH} characters"
    if username and password.strip().lower() == username.strip().lower():
        return "Password must differ from the username"
    return None
